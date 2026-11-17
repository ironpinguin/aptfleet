#!/usr/bin/env python3
"""Lists pending deb updates on Ubuntu hosts, with security/CVE information."""
from __future__ import annotations

import argparse
import datetime
import os
import socket
import sys
from pathlib import Path

import cve_info
import kev
import oval
import remote
from kev import recent_entries
from parsing import HostReport, build_host_report
from progress import Progress
from render import render_report
from render_html import render_html_report
from vulns import find_open_vulns

USER_CONFIG_DIR = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "aptfleet"
SYSTEM_CONFIG_DIR = Path("/etc/aptfleet")
DEFAULT_TIMEOUT = 120


def default_path(user: Path, system: Path) -> Path:
    """File from the user config, otherwise from /etc/aptfleet."""
    return user if user.is_file() else system


INVENTORY = default_path(USER_CONFIG_DIR / "hosts.ini", SYSTEM_CONFIG_DIR / "hosts.ini")
SSH_CONFIG = default_path(USER_CONFIG_DIR / "ssh.conf", SYSTEM_CONFIG_DIR / "ssh.conf")


def read_inventory(path: Path) -> list[str]:
    """Hosts from an Ansible INI inventory, deduplicated in order of first
    appearance; [x:vars] and [x:children] contain no hosts."""
    hosts: list[str] = []
    in_host_section = True
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            in_host_section = not line.strip("[] ").endswith((":vars", ":children"))
            continue
        name = line.split()[0]
        if in_host_section and "=" not in name:
            hosts.append(name)
    return list(dict.fromkeys(hosts))


def select_hosts(inventory: list[str], requested: list[str]) -> list[str]:
    if not requested:
        return inventory
    unknown = [host for host in requested if host not in inventory]
    if unknown:
        raise ValueError(f"Unknown hosts (not in inventory): {', '.join(unknown)}")
    return [host for host in inventory if host in requested]


def resolve_ssh_config(explicit: Path | None, default: Path = SSH_CONFIG) -> Path | None:
    """Without an explicit value, ssh.conf from the aptfleet config if present; otherwise ~/.ssh/config applies."""
    if explicit is not None:
        return explicit
    return default if default.is_file() else None


def exit_code(reports: list[HostReport], incomplete: bool = False) -> int:
    if any(report.error for report in reports):
        return 2
    if incomplete or any(report.vuln_check_problem for report in reports):
        return 3
    if any(p.upgrade.is_security for report in reports for p in report.packages):
        return 1
    if any(v.kev for report in reports for v in report.open_vulns):
        return 1
    return 0


def _format_date(timestamp: float) -> str:
    return datetime.date.fromtimestamp(timestamp).isoformat()


def _foreign_notice(report: HostReport) -> str | None:
    names = sorted(
        {p.binary for p in report.installed if not report.is_ubuntu_package(p)}
    )
    if not names:
        return None
    shown = ", ".join(names[:10]) + (", …" if len(names) > 10 else "")
    return f"{report.host}: {len(names)} packages without Ubuntu origin not checked ({shown})"


def _positive_days(value: str) -> int:
    try:
        days = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not an integer: {value!r}") from None
    if days < 1:
        raise argparse.ArgumentTypeError(f"must be at least 1: {days}")
    return days


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Shows pending updates on Ubuntu hosts, with security information.",
        epilog="Exit codes: 0 = nothing to do, 1 = security updates or open KEV vulnerability, "
        "2 = at least one host unreachable, "
        "3 = check incomplete (feed/host data missing).",
    )
    parser.add_argument("--host", action="append", default=[], metavar="NAME",
                        help="check only this host (name from the inventory, repeatable; "
                        "with --user any hostname/IP)")
    parser.add_argument("--user", metavar="NAME",
                        help="SSH user for --host; uses the hosts directly, without inventory "
                        "and without the aptfleet SSH config (~/.ssh/config applies)")
    parser.add_argument("--inventory", type=Path, metavar="PATH",
                        help=f"inventory file (default {INVENTORY})")
    parser.add_argument("--ssh-config", type=Path, metavar="PATH",
                        help=f"SSH config for ssh -F (default {SSH_CONFIG} if present, "
                        "otherwise ~/.ssh/config; with --user only if given)")
    parser.add_argument("--local", action="store_true",
                        help="check only the local machine, without SSH (e.g. from a cron job on "
                        "the server); cannot be combined with --host/--user/--inventory/--ssh-config")
    parser.add_argument("--security-only", action="store_true", help="show security updates only")
    parser.add_argument("--details", action="store_true", help="show new changelog entries")
    parser.add_argument("--package", action="append", default=[], metavar="NAME",
                        help="only this package (binary package name, repeatable)")
    parser.add_argument("--no-refresh", action="store_true", help="do not run 'apt-get update' first")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, metavar="SECONDS",
                        help=f"timeout per host (default {DEFAULT_TIMEOUT})")
    parser.add_argument("--verbose", action="store_true", help="show lines that could not be parsed")
    parser.add_argument("--kev-recent", nargs="?", const=7, type=_positive_days, default=None,
                        metavar="DAYS",
                        help="show CVEs recently added to CISA KEV (default without value: 7 days)")
    parser.add_argument("--html", type=Path, metavar="PATH",
                        help="also write the report as an HTML file (self-contained, printable)")
    parser.add_argument("--no-progress", action="store_true",
                        help="no progress output on stderr (already off without a terminal, "
                        "e.g. under cron)")
    return parser.parse_args(argv)


def main(
    argv: list[str] | None = None,
    *,
    inventory: Path = INVENTORY,
    run_all=remote.run_all,
    lookup=cve_info.lookup_cves,
    kev_loader=kev.load_kev,
    oval_loader=oval.load_oval,
    today: datetime.date | None = None,
    stdout=None,
    progress: Progress | None = None,
) -> int:
    stdout = stdout or sys.stdout
    args = parse_args(argv)
    if progress is None:
        progress = Progress(sys.stderr, enabled=False if args.no_progress else None)
    try:
        return _run(args, inventory, run_all, lookup, kev_loader, oval_loader, today, stdout,
                    progress)
    finally:
        progress.close()


def _run(args, inventory, run_all, lookup, kev_loader, oval_loader, today, stdout,
         progress: Progress) -> int:
    if args.local:
        conflicts = [opt for opt, value in (("--host", args.host), ("--user", args.user),
                                            ("--inventory", args.inventory),
                                            ("--ssh-config", args.ssh_config)) if value]
        if conflicts:
            print(f"Error: --local cannot be combined with {', '.join(conflicts)}",
                  file=sys.stderr)
            return 2
        hosts, ssh_config = [socket.gethostname()], None
    elif args.user:
        if not args.host:
            print("Error: --user requires at least one --host", file=sys.stderr)
            return 2
        hosts, ssh_config = list(dict.fromkeys(args.host)), args.ssh_config
    else:
        try:
            hosts = select_hosts(read_inventory(args.inventory or inventory), args.host)
        except OSError as exc:
            print(f"Error: inventory not readable ({exc}); pass --inventory, or --host and --user",
                  file=sys.stderr)
            return 2
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 2
        ssh_config = resolve_ssh_config(args.ssh_config)

    progress.hosts_start(len(hosts))
    results = run_all(
        hosts, ssh_config, not args.no_refresh, args.package, args.timeout, user=args.user,
        progress=progress if progress.enabled else None, local=args.local,
    )
    reports = [build_host_report(r.host, r.raw_output, r.error) for r in results]

    notices: list[str] = []
    incomplete = False

    progress.step("Loading KEV list (CISA)")
    kev_data = kev_loader()
    if kev_data is None:
        notices.append("KEV list unavailable (cisa.gov) – no KEV marking")
        incomplete = True
        kev_entries: dict = {}
    else:
        kev_entries = kev_data.entries
        if kev_data.stale:
            notices.append(f"KEV data from {_format_date(kev_data.fetched_at)}")
    kev_ids = set(kev_entries)

    checkable = [r for r in reports if not r.error and not r.vuln_check_problem]
    oval_by_codename: dict = {}
    for codename in dict.fromkeys(r.codename for r in checkable):
        progress.step(f"Loading Ubuntu vulnerability data ({codename})")
        data = oval_loader(codename)
        oval_by_codename[codename] = data
        if data is None:
            notices.append(
                f"Ubuntu vulnerability data ({codename}) unavailable"
                " – vulnerability check skipped for affected hosts"
            )
        elif data.stale:
            notices.append(
                f"Ubuntu vulnerability data ({codename}) from {_format_date(data.fetched_at)}"
            )
    for report in checkable:
        data = oval_by_codename[report.codename]
        if data is None:
            report.vuln_check_problem = (
                f"Ubuntu vulnerability data ({report.codename}) unavailable"
            )
            continue
        vulns = find_open_vulns(report, data.cves, kev_ids)
        if args.package:
            vulns = [v for v in vulns if set(v.binaries) & set(args.package)]
        report.open_vulns = vulns

    cve_ids = {cve for report in reports for p in report.packages for cve in p.cves}
    if args.details:
        cve_ids |= {v.cve_id for report in reports for v in report.open_vulns}
    if cve_ids:
        progress.step(f"Fetching CVE info ({len(cve_ids)} CVEs)")
    cves, failed = lookup(cve_ids) if cve_ids else ({}, [])

    kev_recent = None
    if args.kev_recent is not None and kev_data is not None:
        kev_recent = recent_entries(kev_data, args.kev_recent, today or datetime.date.today())

    if args.verbose:
        notices.extend(n for n in map(_foreign_notice, checkable) if n)

    options = dict(
        details=args.details,
        security_only=args.security_only,
        cve_lookup_failed=bool(failed),
        verbose=args.verbose,
        kev=kev_entries,
        kev_recent=kev_recent,
        kev_recent_days=args.kev_recent if args.kev_recent is not None else 7,
        notices=notices,
    )
    progress.close()
    print(render_report(reports, cves, color=stdout.isatty(), **options), file=stdout)

    if args.html:
        html = render_html_report(reports, cves, generated=datetime.datetime.now(), **options)
        try:
            args.html.write_text(html, encoding="utf-8")
        except OSError as exc:
            print(f"Error: HTML report not writable ({exc})", file=sys.stderr)
            return 2
        print(f"HTML report written: {args.html}", file=stdout)
    return exit_code(reports, incomplete)


if __name__ == "__main__":
    sys.exit(main())

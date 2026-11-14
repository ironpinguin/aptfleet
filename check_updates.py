#!/usr/bin/env python3
"""Listet anstehende deb-Updates auf Rootserver und KVMs inkl. Security-/CVE-Infos."""
from __future__ import annotations

import argparse
import datetime
import sys
from pathlib import Path

import cve_info
import kev
import oval
import remote
from kev import recent_entries
from parsing import HostReport, build_host_report
from render import render_report
from vulns import find_open_vulns

REPO_ROOT = Path(__file__).resolve().parent.parent
INVENTORY = REPO_ROOT / "virtualhosts"
SSH_CONFIG = REPO_ROOT / "ssh_config_rootserver_ansible.conf"
DEFAULT_TIMEOUT = 120


def read_inventory(path: Path) -> list[str]:
    """Hosts aus einem Ansible-INI-Inventory; [x:vars] und [x:children] enthalten keine Hosts."""
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
    return hosts


def select_hosts(inventory: list[str], requested: list[str]) -> list[str]:
    if not requested:
        return inventory
    unknown = [host for host in requested if host not in inventory]
    if unknown:
        raise ValueError(f"Unbekannte Hosts (nicht im Inventory): {', '.join(unknown)}")
    return [host for host in inventory if host in requested]


def resolve_ssh_config(explicit: Path | None, default: Path = SSH_CONFIG) -> Path | None:
    """Ohne explizite Angabe die Repo-SSH-Config, falls vorhanden; sonst gilt ~/.ssh/config."""
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
    return f"{report.host}: {len(names)} Pakete ohne Ubuntu-Herkunft nicht geprüft ({shown})"


def _positive_days(value: str) -> int:
    try:
        days = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"keine ganze Zahl: {value!r}") from None
    if days < 1:
        raise argparse.ArgumentTypeError(f"muss mindestens 1 sein: {days}")
    return days


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Zeigt anstehende Updates auf Rootserver und KVMs inkl. Security-Infos.",
        epilog="Exit-Codes: 0 = nichts zu tun, 1 = Security-Updates oder offene KEV-Lücke, "
        "2 = mindestens ein Host nicht erreichbar, "
        "3 = Prüfung unvollständig (Feed/Host-Daten fehlen).",
    )
    parser.add_argument("--host", action="append", default=[], metavar="NAME",
                        help="nur diesen Host prüfen (Name aus virtualhosts, mehrfach möglich; "
                        "mit --user beliebiger Hostname/IP)")
    parser.add_argument("--user", metavar="NAME",
                        help="SSH-User für --host; nutzt die Hosts direkt ohne virtualhosts "
                        "und ohne Repo-SSH-Config (es gilt ~/.ssh/config)")
    parser.add_argument("--inventory", type=Path, metavar="PFAD",
                        help=f"Inventory-Datei (Default {INVENTORY})")
    parser.add_argument("--ssh-config", type=Path, metavar="PFAD",
                        help=f"SSH-Config für ssh -F (Default {SSH_CONFIG}, falls vorhanden, "
                        "sonst ~/.ssh/config; mit --user nur bei Angabe)")
    parser.add_argument("--security-only", action="store_true", help="nur Security-Updates anzeigen")
    parser.add_argument("--details", action="store_true", help="neue Changelog-Einträge anzeigen")
    parser.add_argument("--package", action="append", default=[], metavar="NAME",
                        help="nur dieses Paket (Binärpaketname, mehrfach möglich)")
    parser.add_argument("--no-refresh", action="store_true", help="kein 'apt-get update' vorher")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, metavar="SEKUNDEN",
                        help=f"Timeout pro Host (Default {DEFAULT_TIMEOUT})")
    parser.add_argument("--verbose", action="store_true", help="nicht parsebare Zeilen anzeigen")
    parser.add_argument("--kev-recent", nargs="?", const=7, type=_positive_days, default=None,
                        metavar="TAGE",
                        help="zuletzt auf CISA KEV aufgenommene CVEs anzeigen (Default ohne Wert: 7 Tage)")
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
) -> int:
    stdout = stdout or sys.stdout
    args = parse_args(argv)
    if args.user:
        if not args.host:
            print("Fehler: --user benötigt mindestens ein --host", file=sys.stderr)
            return 2
        hosts, ssh_config = list(dict.fromkeys(args.host)), args.ssh_config
    else:
        try:
            hosts = select_hosts(read_inventory(args.inventory or inventory), args.host)
        except OSError as exc:
            print(f"Fehler: Inventory nicht lesbar ({exc}); --inventory oder --host und --user angeben",
                  file=sys.stderr)
            return 2
        except ValueError as exc:
            print(f"Fehler: {exc}", file=sys.stderr)
            return 2
        ssh_config = resolve_ssh_config(args.ssh_config)

    results = run_all(
        hosts, ssh_config, not args.no_refresh, args.package, args.timeout, user=args.user
    )
    reports = [build_host_report(r.host, r.raw_output, r.error) for r in results]

    notices: list[str] = []
    incomplete = False

    kev_data = kev_loader()
    if kev_data is None:
        notices.append("KEV-Liste nicht abrufbar (cisa.gov) – keine KEV-Markierung")
        incomplete = True
        kev_entries: dict = {}
    else:
        kev_entries = kev_data.entries
        if kev_data.stale:
            notices.append(f"KEV-Stand vom {_format_date(kev_data.fetched_at)}")
    kev_ids = set(kev_entries)

    checkable = [r for r in reports if not r.error and not r.vuln_check_problem]
    oval_by_codename: dict = {}
    for codename in dict.fromkeys(r.codename for r in checkable):
        data = oval_loader(codename)
        oval_by_codename[codename] = data
        if data is None:
            notices.append(
                f"Ubuntu-Schwachstellendaten ({codename}) nicht abrufbar"
                " – Lücken-Prüfung für betroffene Hosts entfällt"
            )
        elif data.stale:
            notices.append(
                f"Ubuntu-Schwachstellendaten ({codename}) vom {_format_date(data.fetched_at)}"
            )
    for report in checkable:
        data = oval_by_codename[report.codename]
        if data is None:
            report.vuln_check_problem = (
                f"Ubuntu-Schwachstellendaten ({report.codename}) nicht abrufbar"
            )
            continue
        vulns = find_open_vulns(report, data.cves, kev_ids)
        if args.package:
            vulns = [v for v in vulns if set(v.binaries) & set(args.package)]
        report.open_vulns = vulns

    cve_ids = {cve for report in reports for p in report.packages for cve in p.cves}
    if args.details:
        cve_ids |= {v.cve_id for report in reports for v in report.open_vulns}
    cves, failed = lookup(cve_ids) if cve_ids else ({}, [])

    kev_recent = None
    if args.kev_recent is not None and kev_data is not None:
        kev_recent = recent_entries(kev_data, args.kev_recent, today or datetime.date.today())

    if args.verbose:
        notices.extend(n for n in map(_foreign_notice, checkable) if n)

    print(
        render_report(
            reports,
            cves,
            details=args.details,
            security_only=args.security_only,
            color=stdout.isatty(),
            cve_lookup_failed=bool(failed),
            verbose=args.verbose,
            kev=kev_entries,
            kev_recent=kev_recent,
            kev_recent_days=args.kev_recent if args.kev_recent is not None else 7,
            notices=notices,
        ),
        file=stdout,
    )
    return exit_code(reports, incomplete)


if __name__ == "__main__":
    sys.exit(main())

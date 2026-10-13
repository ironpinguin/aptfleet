#!/usr/bin/env python3
"""Listet anstehende deb-Updates auf Rootserver und KVMs inkl. Security-/CVE-Infos."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import cve_info
import remote
from parsing import HostReport, build_host_report
from render import render_report

REPO_ROOT = Path(__file__).resolve().parent.parent
INVENTORY = REPO_ROOT / "virtualhosts"
SSH_CONFIG = REPO_ROOT / "ssh_config_rootserver_ansible.conf"
DEFAULT_TIMEOUT = 120


def read_inventory(path: Path) -> list[str]:
    hosts: list[str] = []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("["):
            continue
        hosts.append(line.split()[0])
    return hosts


def select_hosts(inventory: list[str], requested: list[str]) -> list[str]:
    if not requested:
        return inventory
    unknown = [host for host in requested if host not in inventory]
    if unknown:
        raise ValueError(f"Unbekannte Hosts (nicht in virtualhosts): {', '.join(unknown)}")
    return [host for host in inventory if host in requested]


def exit_code(reports: list[HostReport]) -> int:
    if any(report.error for report in reports):
        return 2
    if any(p.upgrade.is_security for report in reports for p in report.packages):
        return 1
    return 0


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Zeigt anstehende Updates auf Rootserver und KVMs inkl. Security-Infos.",
        epilog="Exit-Codes: 0 = keine Security-Updates, 1 = Security-Updates vorhanden, "
        "2 = mindestens ein Host nicht erreichbar.",
    )
    parser.add_argument("--host", action="append", default=[], metavar="NAME",
                        help="nur diesen Host prüfen (Name aus virtualhosts, mehrfach möglich)")
    parser.add_argument("--security-only", action="store_true", help="nur Security-Updates anzeigen")
    parser.add_argument("--details", action="store_true", help="neue Changelog-Einträge anzeigen")
    parser.add_argument("--package", action="append", default=[], metavar="NAME",
                        help="nur dieses Paket (Binärpaketname, mehrfach möglich)")
    parser.add_argument("--no-refresh", action="store_true", help="kein 'apt-get update' vorher")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, metavar="SEKUNDEN",
                        help=f"Timeout pro Host (Default {DEFAULT_TIMEOUT})")
    parser.add_argument("--verbose", action="store_true", help="nicht parsebare Zeilen anzeigen")
    return parser.parse_args(argv)


def main(
    argv: list[str] | None = None,
    *,
    inventory: Path = INVENTORY,
    run_all=remote.run_all,
    lookup=cve_info.lookup_cves,
    stdout=None,
) -> int:
    stdout = stdout or sys.stdout
    args = parse_args(argv)
    try:
        hosts = select_hosts(read_inventory(inventory), args.host)
    except ValueError as exc:
        print(f"Fehler: {exc}", file=sys.stderr)
        return 2

    results = run_all(hosts, SSH_CONFIG, not args.no_refresh, args.package, args.timeout)
    reports = [build_host_report(r.host, r.raw_output, r.error) for r in results]

    cve_ids = {cve for report in reports for p in report.packages for cve in p.cves}
    cves, failed = lookup(cve_ids) if cve_ids else ({}, [])

    print(
        render_report(
            reports,
            cves,
            details=args.details,
            security_only=args.security_only,
            color=stdout.isatty(),
            cve_lookup_failed=bool(failed),
            verbose=args.verbose,
        ),
        file=stdout,
    )
    return exit_code(reports)


if __name__ == "__main__":
    sys.exit(main())

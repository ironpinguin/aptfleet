"""Aufbereitung der Host-Reports als Terminal-Text."""
from __future__ import annotations

from cve_info import CveInfo, priority_rank
from parsing import HostReport, PackageReport

BOLD = "\033[1m"
RED = "\033[31m"
YELLOW = "\033[33m"
RESET = "\033[0m"
PRIORITY_COLORS = {"critical": RED + BOLD, "high": RED, "medium": YELLOW}
DETAIL_INDENT = " " * 8


def _c(text: str, code: str, color: bool) -> str:
    if not color or not code:
        return text
    return f"{code}{text}{RESET}"


def _priority(cve_id: str, cves: dict[str, CveInfo]) -> str | None:
    info = cves.get(cve_id)
    return info.priority if info else None


def _sort_key(pkg: PackageReport, cves: dict[str, CveInfo]) -> tuple:
    if pkg.upgrade.is_security:
        best = min((priority_rank(_priority(c, cves)) for c in pkg.cves), default=priority_rank(None))
        return (0, best, pkg.upgrade.package)
    return (1, 0, pkg.upgrade.package)


def _cve_text(pkg: PackageReport, cves: dict[str, CveInfo], color: bool) -> str:
    if pkg.cves:
        parts = []
        for cve_id in pkg.cves:
            prio = _priority(cve_id, cves)
            parts.append(f"{cve_id} ({_c(prio, PRIORITY_COLORS.get(prio, ''), color)})" if prio else cve_id)
        text = ", ".join(parts)
    elif not pkg.changelog_available:
        text = "(Changelog nicht verfügbar)" if pkg.upgrade.is_security else ""
    elif pkg.upgrade.is_security:
        text = "(keine CVE im Changelog)"
    else:
        text = ""
    if pkg.changelog_uncertain:
        text = f"{text} [Abgleich unsicher]".strip()
    return text


def _details(pkg: PackageReport, cves: dict[str, CveInfo]) -> list[str]:
    lines: list[str] = []
    if not pkg.changelog_available:
        lines.append(f"{DETAIL_INDENT}Changelog nicht verfügbar")
    if pkg.changelog_uncertain:
        lines.append(f"{DETAIL_INDENT}(installierte Version nicht im Changelog gefunden – Auszug evtl. unvollständig)")
    for entry in pkg.entries:
        lines.append(f"{DETAIL_INDENT}{entry.version}:")
        for line in entry.text.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("-- "):
                lines.append(f"{DETAIL_INDENT}  {stripped}")
    for cve_id in pkg.cves:
        info = cves.get(cve_id)
        if info and info.description:
            lines.append(f"{DETAIL_INDENT}{cve_id}: {info.description}")
    return lines


def _render_host(
    report: HostReport, cves: dict[str, CveInfo], details: bool, security_only: bool, color: bool
) -> list[str]:
    if report.error:
        return [_c(f"━━ {report.host} — FEHLER: {report.error} ━━", RED + BOLD, color)]

    total = len(report.packages)
    security = sum(1 for p in report.packages if p.upgrade.is_security)
    os_part = f" (Ubuntu {report.os_version})" if report.os_version else ""
    summary = f"{total} Updates, {security} Security" if total else "keine Updates"
    lines = [_c(f"━━ {report.host}{os_part} — {summary} ━━", BOLD, color)]
    lines.extend(f"  ⚠ {warning}" for warning in report.warnings)

    packages = sorted(report.packages, key=lambda p: _sort_key(p, cves))
    if security_only:
        packages = [p for p in packages if p.upgrade.is_security]
    versions = {id(p): f"{p.upgrade.old_version} → {p.upgrade.new_version}" for p in packages}
    name_width = max((len(p.upgrade.package) for p in packages), default=0)
    version_width = max((len(v) for v in versions.values()), default=0)

    for pkg in packages:
        tag = _c(" SEC", RED + BOLD, color) if pkg.upgrade.is_security else "    "
        line = (
            f"{tag}  {pkg.upgrade.package:<{name_width}}  "
            f"{versions[id(pkg)]:<{version_width}}  {_cve_text(pkg, cves, color)}"
        )
        lines.append(line.rstrip())
        if details:
            lines.extend(_details(pkg, cves))
    return lines


def _summary(reports: list[HostReport]) -> str:
    updates = sum(len(r.packages) for r in reports)
    security = sum(1 for r in reports for p in r.packages if p.upgrade.is_security)
    failed = sum(1 for r in reports if r.error)
    text = f"Zusammenfassung: {len(reports)} Hosts, {updates} Updates, {security} Security"
    if failed:
        text += f", {failed} {'Host' if failed == 1 else 'Hosts'} nicht erreichbar"
    return text


def render_report(
    reports: list[HostReport],
    cves: dict[str, CveInfo],
    *,
    details: bool = False,
    security_only: bool = False,
    color: bool = False,
    cve_lookup_failed: bool = False,
    verbose: bool = False,
) -> str:
    lines: list[str] = []
    for report in reports:
        lines.extend(_render_host(report, cves, details, security_only, color))
        if verbose:
            lines.extend(f"  ? nicht geparst: {line}" for line in report.unparsed)
    lines.append("")
    if cve_lookup_failed:
        lines.append("Hinweis: CVE-Prioritäten teilweise nicht abrufbar (Ubuntu-Security-API nicht erreichbar).")
    lines.append(_summary(reports))
    return "\n".join(lines)

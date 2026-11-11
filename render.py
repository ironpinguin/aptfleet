"""Aufbereitung der Host-Reports als Terminal-Text."""
from __future__ import annotations

from cve_info import CveInfo, priority_rank
from kev import KevEntry
from parsing import HostReport, OpenVuln, PackageReport
from vulns import kev_fix_count

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


def _sort_key(pkg: PackageReport, cves: dict[str, CveInfo], kev: dict[str, KevEntry]) -> tuple:
    if pkg.upgrade.is_security:
        has_kev = any(c in kev for c in pkg.cves)
        best = min((priority_rank(_priority(c, cves)) for c in pkg.cves), default=priority_rank(None))
        return (0, 0 if has_kev else 1, best, pkg.upgrade.package)
    return (1, 1, 0, pkg.upgrade.package)


def _cve_text(pkg: PackageReport, cves: dict[str, CveInfo], kev: dict[str, KevEntry], color: bool) -> str:
    if pkg.cves:
        parts = []
        for cve_id in pkg.cves:
            prio = _priority(cve_id, cves)
            marks = []
            if prio:
                marks.append(_c(prio, PRIORITY_COLORS.get(prio, ""), color))
            if cve_id in kev:
                marks.append(_c("KEV", RED + BOLD, color))
            parts.append(f"{cve_id} ({', '.join(marks)})" if marks else cve_id)
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


def _cve_detail_lines(cve_id: str, cves: dict[str, CveInfo], kev: dict[str, KevEntry]) -> list[str]:
    lines: list[str] = []
    info = cves.get(cve_id)
    if info and info.description:
        lines.append(f"{DETAIL_INDENT}{cve_id}: {info.description}")
    entry = kev.get(cve_id)
    if entry:
        lines.append(f"{DETAIL_INDENT}KEV: {entry.name} (seit {entry.date_added})")
    return lines


def _details(pkg: PackageReport, cves: dict[str, CveInfo], kev: dict[str, KevEntry]) -> list[str]:
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
        lines.extend(_cve_detail_lines(cve_id, cves, kev))
    return lines


def _priority_summary(group: list[OpenVuln]) -> str:
    counts: dict[str, int] = {}
    for v in group:
        key = v.priority or "unbekannt"
        counts[key] = counts.get(key, 0) + 1
    order = [p for p in ("critical", "high") if p in counts]
    order += sorted(p for p in counts if p not in ("critical", "high"))
    return f"{len(group)} CVEs ({', '.join(f'{counts[p]} {p}' for p in order)})"


def _open_vuln_rows(vulns: list[OpenVuln], details: bool) -> list[tuple[OpenVuln, str, str, str, str, bool]]:
    """Wandelt die sortierte Lückenliste in Anzeigezeilen (v, Name, Version, CVE-Text, Status, Sammelzeile)."""
    groups: dict[tuple[str, str, str], list[OpenVuln]] = {}
    if not details:
        for v in vulns:
            if v.is_kernel and not v.kev:
                groups.setdefault((v.source, v.installed_version, v.status), []).append(v)
    rows = []
    emitted: set[tuple[str, str, str]] = set()
    for v in vulns:
        key = (v.source, v.installed_version, v.status)
        group = groups.get(key) if v.is_kernel and not v.kev else None
        if group and len(group) >= 2:
            if key not in emitted:
                emitted.add(key)
                rows.append((v, f"{v.source} (Kernel)", v.installed_version, _priority_summary(group),
                             f"{v.status} – Liste mit --details", True))
            continue
        name = f"{v.source} (Kernel)" if v.is_kernel else v.binaries[0]
        cve_text = f"{v.cve_id} ({v.priority})" if v.priority else v.cve_id
        rows.append((v, name, v.installed_version, cve_text, v.status, False))
    return rows


def _open_vuln_lines(
    report: HostReport, cves: dict[str, CveInfo], details: bool, kev: dict[str, KevEntry], color: bool
) -> list[str]:
    # report.open_vulns kommt bereits sortiert aus vulns.find_open_vulns
    rows = _open_vuln_rows(report.open_vulns, details)
    name_width = max(len(r[1]) for r in rows)
    version_width = max(len(r[2]) for r in rows)
    cve_width = max(len(r[3]) for r in rows)
    lines = ["   Offene Lücken ohne Fix:"]
    for v, name, version, cve_text, status, summarized in rows:
        tag = _c(" KEV", RED + BOLD, color) if v.kev else "    "
        line = f"{tag}  {name:<{name_width}}  {version:<{version_width}}  {cve_text:<{cve_width}}  {status}"
        lines.append(line.rstrip())
        if details and not summarized:
            lines.extend(_cve_detail_lines(v.cve_id, cves, kev))
    return lines


def _render_host(
    report: HostReport,
    cves: dict[str, CveInfo],
    details: bool,
    security_only: bool,
    color: bool,
    kev: dict[str, KevEntry],
) -> list[str]:
    if report.error:
        return [_c(f"━━ {report.host} — FEHLER: {report.error} ━━", RED + BOLD, color)]

    total = len(report.packages)
    security = sum(1 for p in report.packages if p.upgrade.is_security)
    os_part = f" (Ubuntu {report.os_version})" if report.os_version else ""
    summary = f"{total} Updates, {security} Security" if total else "keine Updates"
    open_count = len(report.open_vulns)
    if open_count:
        summary += f", {_open_text(open_count)}"
    elif not report.vuln_check_problem:
        summary += ", keine offenen Lücken" if not total else ""
    lines = [_c(f"━━ {report.host}{os_part} — {summary} ━━", BOLD, color)]
    lines.extend(f"  ⚠ {warning}" for warning in report.warnings)
    if report.vuln_check_problem:
        lines.append(f"  ⚠ Lücken-Prüfung nicht möglich: {report.vuln_check_problem}")

    packages = sorted(report.packages, key=lambda p: _sort_key(p, cves, kev))
    if security_only:
        packages = [p for p in packages if p.upgrade.is_security]
    versions = {id(p): f"{p.upgrade.old_version} → {p.upgrade.new_version}" for p in packages}
    name_width = max((len(p.upgrade.package) for p in packages), default=0)
    version_width = max((len(v) for v in versions.values()), default=0)

    for pkg in packages:
        tag = _c(" SEC", RED + BOLD, color) if pkg.upgrade.is_security else "    "
        line = (
            f"{tag}  {pkg.upgrade.package:<{name_width}}  "
            f"{versions[id(pkg)]:<{version_width}}  {_cve_text(pkg, cves, kev, color)}"
        )
        lines.append(line.rstrip())
        if details:
            lines.extend(_details(pkg, cves, kev))
    if report.open_vulns:
        lines.extend(_open_vuln_lines(report, cves, details, kev, color))
    return lines


def _open_text(count: int) -> str:
    return "1 offene Lücke" if count == 1 else f"{count} offene Lücken"


def _summary(reports: list[HostReport], kev: dict[str, KevEntry]) -> str:
    updates = sum(len(r.packages) for r in reports)
    security = sum(1 for r in reports for p in r.packages if p.upgrade.is_security)
    failed = sum(1 for r in reports if r.error)
    text = f"Zusammenfassung: {len(reports)} Hosts, {updates} Updates, {security} Security"
    kev_fixes = sum(kev_fix_count(r, set(kev)) for r in reports)
    if kev_fixes:
        text += f", {kev_fixes} KEV-Fix verfügbar"
    open_total = sum(len(r.open_vulns) for r in reports)
    if open_total:
        open_kev = sum(1 for r in reports for v in r.open_vulns if v.kev)
        text += f", {_open_text(open_total)} ({open_kev} KEV)"
    if failed:
        text += f", {failed} {'Host' if failed == 1 else 'Hosts'} nicht erreichbar"
    return text


def _kev_recent_lines(reports: list[HostReport], entries: list[KevEntry], days: int) -> list[str]:
    period = "letzter Tag" if days == 1 else f"letzte {days} Tage"
    lines = [f"Neu auf CISA KEV ({period}):"]
    if not entries:
        lines.append("  (keine)")
        return lines
    for entry in sorted(entries, key=lambda e: e.date_added, reverse=True):
        name = entry.name if len(entry.name) <= 60 else entry.name[:59] + "…"
        line = f" {entry.date_added}  {entry.cve_id}  {entry.vendor} {entry.product}: {name}"
        hosts = [
            r.host
            for r in reports
            if any(entry.cve_id in p.cves for p in r.packages)
            or any(v.cve_id == entry.cve_id for v in r.open_vulns)
        ]
        if hosts:
            line += f"  betrifft: {', '.join(hosts)}"
        lines.append(line)
    return lines


def render_report(
    reports: list[HostReport],
    cves: dict[str, CveInfo],
    *,
    details: bool = False,
    security_only: bool = False,
    color: bool = False,
    cve_lookup_failed: bool = False,
    verbose: bool = False,
    kev: dict[str, KevEntry] | None = None,
    kev_recent: list[KevEntry] | None = None,
    kev_recent_days: int = 7,
    notices: list[str] | None = None,
) -> str:
    kev = kev or {}
    lines: list[str] = []
    for report in reports:
        lines.extend(_render_host(report, cves, details, security_only, color, kev))
        if verbose:
            lines.extend(f"  ? nicht geparst: {line}" for line in report.unparsed)
    lines.append("")
    if kev_recent is not None:
        lines.extend(_kev_recent_lines(reports, kev_recent, kev_recent_days))
        lines.append("")
    if cve_lookup_failed:
        lines.append("Hinweis: CVE-Prioritäten teilweise nicht abrufbar (Ubuntu-Security-API nicht erreichbar).")
    lines.extend(f"Hinweis: {notice}" for notice in notices or [])
    lines.append(_summary(reports, kev))
    return "\n".join(lines)

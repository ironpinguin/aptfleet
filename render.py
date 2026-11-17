"""Formats the host reports as terminal text; the public helpers are also used by render_html."""
from __future__ import annotations

from dataclasses import dataclass
from typing import NamedTuple

from cve_info import CveInfo, priority_rank
from kev import KevEntry
from parsing import HostReport, OpenVuln, PackageReport
from vulns import kev_fix_count

BOLD = "\033[1m"
RED = "\033[31m"
YELLOW = "\033[33m"
DIM = "\033[2m"
RESET = "\033[0m"
PRIORITY_COLORS = {"critical": RED + BOLD, "high": RED, "medium": YELLOW}
DETAIL_INDENT = " " * 8


def plural(count: int, word: str) -> str:
    """"1 update", "3 updates"."""
    return f"{count} {word}" if count == 1 else f"{count} {word}s"


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


def sorted_packages(
    report: HostReport, cves: dict[str, CveInfo], kev: dict[str, KevEntry], security_only: bool
) -> list[PackageReport]:
    """Packages in display order: security (KEV, then priority) before the rest."""
    packages = sorted(report.packages, key=lambda p: _sort_key(p, cves, kev))
    if security_only:
        packages = [p for p in packages if p.upgrade.is_security]
    return packages


def package_note(pkg: PackageReport) -> str:
    """Note shown instead of the CVE list when the package names no CVEs."""
    if pkg.cves:
        return ""
    if not pkg.changelog_available:
        return "(changelog unavailable)" if pkg.upgrade.is_security else ""
    return "(no CVE in changelog)" if pkg.upgrade.is_security else ""


def changelog_lines(entry) -> list[str]:
    """Content lines of a changelog entry, without blank lines and trailer ('-- Name')."""
    return [
        stripped
        for stripped in (line.strip() for line in entry.text.splitlines())
        if stripped and not stripped.startswith("-- ")
    ]


def _cve_text(pkg: PackageReport, cves: dict[str, CveInfo], kev: dict[str, KevEntry], color: bool) -> str:
    parts = []
    for cve_id in pkg.cves:
        prio = _priority(cve_id, cves)
        marks = []
        if prio:
            marks.append(_c(prio, PRIORITY_COLORS.get(prio, ""), color))
        if cve_id in kev:
            marks.append(_c("KEV", RED + BOLD, color))
        parts.append(f"{cve_id} ({', '.join(marks)})" if marks else cve_id)
    text = ", ".join(parts) or package_note(pkg)
    if pkg.changelog_uncertain:
        text = f"{text} [match uncertain]".strip()
    return text


def _cve_detail_lines(cve_id: str, cves: dict[str, CveInfo], kev: dict[str, KevEntry]) -> list[str]:
    lines: list[str] = []
    info = cves.get(cve_id)
    if info and info.description:
        lines.append(f"{DETAIL_INDENT}{cve_id}: {info.description}")
    entry = kev.get(cve_id)
    if entry:
        lines.append(f"{DETAIL_INDENT}KEV: {entry.name} (added {entry.date_added})")
    return lines


def _details(pkg: PackageReport, cves: dict[str, CveInfo], kev: dict[str, KevEntry]) -> list[str]:
    lines: list[str] = []
    if not pkg.changelog_available:
        lines.append(f"{DETAIL_INDENT}Changelog unavailable")
    if pkg.changelog_uncertain:
        lines.append(f"{DETAIL_INDENT}(installed version not found in changelog – excerpt may be incomplete)")
    for entry in pkg.entries:
        lines.append(f"{DETAIL_INDENT}{entry.version}:")
        lines.extend(f"{DETAIL_INDENT}  {line}" for line in changelog_lines(entry))
    for cve_id in pkg.cves:
        lines.extend(_cve_detail_lines(cve_id, cves, kev))
    return lines


def _priority_summary(group: list[OpenVuln]) -> str:
    counts: dict[str, int] = {}
    for v in group:
        key = v.priority or "unknown"
        counts[key] = counts.get(key, 0) + 1
    order = [p for p in ("critical", "high") if p in counts]
    order += sorted(p for p in counts if p not in ("critical", "high"))
    return f"{len(group)} CVEs ({', '.join(f'{counts[p]} {p}' for p in order)})"


class VulnRow(NamedTuple):
    vuln: OpenVuln  # for summary rows, the first group member
    name: str
    version: str
    cve_text: str
    status: str
    summarized: bool


def open_vuln_rows(vulns: list[OpenVuln], details: bool) -> list[VulnRow]:
    """Turns the sorted vulnerability list into display rows; without details,
    several kernel vulnerabilities with the same version and status are combined."""
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
                rows.append(VulnRow(v, f"{v.source} (kernel)", v.installed_version, _priority_summary(group),
                                    f"{v.status} – list with --details", True))
            continue
        name = f"{v.source} (kernel)" if v.is_kernel else v.binaries[0]
        cve_text = f"{v.cve_id} ({v.priority})" if v.priority else v.cve_id
        rows.append(VulnRow(v, name, v.installed_version, cve_text, v.status, False))
    return rows


def _open_vuln_lines(
    report: HostReport, cves: dict[str, CveInfo], details: bool, kev: dict[str, KevEntry], color: bool
) -> list[str]:
    # report.open_vulns is already sorted by vulns.find_open_vulns
    rows = open_vuln_rows(report.open_vulns, details)
    name_width = max(len(VULN_HEADER[0]), *(len(r.name) for r in rows))
    version_width = max(len(VULN_HEADER[1]), *(len(r.version) for r in rows))
    cve_width = max(len(VULN_HEADER[2]), *(len(r.cve_text) for r in rows))
    lines = ["   Open vulnerabilities (no fix available yet):", _column_header(VULN_HEADER, (name_width, version_width, cve_width), color)]
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
        return [_c(f"━━ {report.host} — ERROR: {report.error} ━━", RED + BOLD, color)]

    os_part = f" (Ubuntu {report.os_version})" if report.os_version else ""
    lines = [_c(f"━━ {report.host}{os_part} — {host_summary(report)} ━━", BOLD, color)]
    lines.extend(f"  ⚠ {warning}" for warning in report.warnings)
    if report.vuln_check_problem:
        lines.append(f"  ⚠ Vulnerability check not possible: {report.vuln_check_problem}")

    packages = sorted_packages(report, cves, kev, security_only)
    versions = {id(p): f"{p.upgrade.old_version} → {p.upgrade.new_version}" for p in packages}
    name_width = max(len(UPDATE_HEADER[0]), *(len(p.upgrade.package) for p in packages), 0)
    version_width = max(len(UPDATE_HEADER[1]), *(len(v) for v in versions.values()), 0)

    if packages:
        lines.append("   Updates:")
        lines.append(_column_header(UPDATE_HEADER, (name_width, version_width), color))
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


UPDATE_HEADER = ("Package", "Version", "CVEs")
VULN_HEADER = ("Package", "Installed", "CVE", "Status")


def _column_header(titles: tuple[str, ...], widths: tuple[int, ...], color: bool) -> str:
    """Column header matching the data rows (5-character tag + 2 spaces before it)."""
    cells = [f"{t:<{w}}" for t, w in zip(titles, widths)] + list(titles[len(widths):])
    return _c("      " + "  ".join(cells).rstrip(), DIM, color)


def host_summary(report: HostReport) -> str:
    """Short summary of a reachable host, e.g. '5 updates, 3 security, 2 open vulnerabilities'."""
    total = len(report.packages)
    security = sum(1 for p in report.packages if p.upgrade.is_security)
    summary = f"{plural(total, 'update')}, {security} security" if total else "no updates"
    open_count = len(report.open_vulns)
    if open_count:
        summary += f", {_open_text(open_count)}"
    elif not report.vuln_check_problem and not total:
        summary += ", no open vulnerabilities"
    return summary


@dataclass
class OverviewRow:
    host: str
    os_version: str
    error: str | None
    updates: int
    security: int
    kev_fixes: int
    open_vulns: str  # "–", "not checked" or "2 (1 KEV)"
    attention: bool  # security update, KEV or problem on the host


def overview_rows(reports: list[HostReport], kev: dict[str, KevEntry]) -> list[OverviewRow]:
    rows = []
    kev_ids = set(kev)
    for r in reports:
        security = sum(1 for p in r.packages if p.upgrade.is_security)
        open_kev = sum(1 for v in r.open_vulns if v.kev)
        if r.error:
            open_text = ""
        elif r.vuln_check_problem:
            open_text = "not checked"
        elif r.open_vulns:
            open_text = f"{len(r.open_vulns)} ({open_kev} KEV)"
        else:
            open_text = "–"
        kev_fixes = kev_fix_count(r, kev_ids)
        attention = bool(r.error or r.vuln_check_problem or security or kev_fixes or open_kev)
        rows.append(OverviewRow(r.host, r.os_version or "", r.error, len(r.packages), security,
                                kev_fixes, open_text, attention))
    return rows


OVERVIEW_HEADER = ("Host", "Ubuntu", "Updates", "Security", "KEV fix", "Open vulnerabilities")


def _overview_lines(reports: list[HostReport], kev: dict[str, KevEntry], color: bool) -> list[str]:
    rows = overview_rows(reports, kev)
    host_w = max(len(OVERVIEW_HEADER[0]), *(len(r.host) for r in rows))
    os_w = max(len(OVERVIEW_HEADER[1]), *(len(r.os_version) for r in rows))
    num_w = [len(t) for t in OVERVIEW_HEADER[2:5]]
    lines = [_c("  ".join([f"{OVERVIEW_HEADER[0]:<{host_w}}", f"{OVERVIEW_HEADER[1]:<{os_w}}",
                           *OVERVIEW_HEADER[2:]]), BOLD, color)]
    for r in rows:
        if r.error:
            lines.append(f"{r.host:<{host_w}}  " + _c(f"ERROR: {r.error}", RED + BOLD, color))
            continue
        nums = [f"{n:>{w}}" for n, w in zip((r.updates, r.security, r.kev_fixes), num_w)]
        lines.append("  ".join([f"{r.host:<{host_w}}", f"{r.os_version:<{os_w}}", *nums, r.open_vulns]))
    return lines


def _open_text(count: int) -> str:
    return "1 open vulnerability" if count == 1 else f"{count} open vulnerabilities"


def summary_text(reports: list[HostReport], kev: dict[str, KevEntry]) -> str:
    updates = sum(len(r.packages) for r in reports)
    security = sum(1 for r in reports for p in r.packages if p.upgrade.is_security)
    failed = sum(1 for r in reports if r.error)
    text = f"Summary: {plural(len(reports), 'host')}, {plural(updates, 'update')}, {security} security"
    kev_fixes = sum(kev_fix_count(r, set(kev)) for r in reports)
    if kev_fixes:
        text += f", {kev_fixes} KEV {'fix' if kev_fixes == 1 else 'fixes'} available"
    open_total = sum(len(r.open_vulns) for r in reports)
    if open_total:
        open_kev = sum(1 for r in reports for v in r.open_vulns if v.kev)
        text += f", {_open_text(open_total)} ({open_kev} KEV)"
    if failed:
        text += f", {failed} {'host' if failed == 1 else 'hosts'} unreachable"
    return text


def kev_affected_hosts(reports: list[HostReport], cve_id: str) -> list[str]:
    return [
        r.host
        for r in reports
        if any(cve_id in p.cves for p in r.packages) or any(v.cve_id == cve_id for v in r.open_vulns)
    ]


def _kev_recent_lines(reports: list[HostReport], entries: list[KevEntry], days: int) -> list[str]:
    period = "last day" if days == 1 else f"last {days} days"
    lines = [f"New on CISA KEV ({period}):"]
    if not entries:
        lines.append("  (none)")
        return lines
    for entry in sorted(entries, key=lambda e: e.date_added, reverse=True):
        name = entry.name if len(entry.name) <= 60 else entry.name[:59] + "…"
        line = f" {entry.date_added}  {entry.cve_id}  {entry.vendor} {entry.product}: {name}"
        hosts = kev_affected_hosts(reports, entry.cve_id)
        if hosts:
            line += f"  affects: {', '.join(hosts)}"
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
    if len(reports) > 1:
        lines.extend(_overview_lines(reports, kev, color))
        lines.append("")
    for i, report in enumerate(reports):
        if i:
            lines.append("")
        lines.extend(_render_host(report, cves, details, security_only, color, kev))
        if verbose:
            lines.extend(f"  ? not parsed: {line}" for line in report.unparsed)
    lines.append("")
    if kev_recent is not None:
        lines.extend(_kev_recent_lines(reports, kev_recent, kev_recent_days))
        lines.append("")
    if cve_lookup_failed:
        lines.append("Note: Some CVE priorities unavailable (Ubuntu security API unreachable).")
    lines.extend(f"Note: {notice}" for notice in notices or [])
    lines.append(summary_text(reports, kev))
    return "\n".join(lines)

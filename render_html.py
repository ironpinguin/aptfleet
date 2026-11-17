"""Formats the host reports as a self-contained HTML file (inline CSS, no JavaScript)."""
from __future__ import annotations

import datetime
from html import escape

from cve_info import CveInfo
from kev import KevEntry
from parsing import HostReport, OpenVuln, PackageReport
from render import (
    changelog_lines,
    host_summary,
    kev_affected_hosts,
    open_vuln_rows,
    overview_rows,
    package_note,
    plural,
    sorted_packages,
    summary_text,
)

CSS = """
:root {
  --bg: #ffffff; --fg: #1f2328; --muted: #656d76; --border: #d0d7de; --head: #f6f8fa;
  --red: #cf222e; --red-bg: #ffebe9; --orange: #bc4c00; --yellow: #9a6700; --link: #0969da;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0d1117; --fg: #e6edf3; --muted: #8d96a0; --border: #30363d; --head: #161b22;
    --red: #ff7b72; --red-bg: #3c1618; --orange: #ffa657; --yellow: #d29922; --link: #4493f8;
  }
}
* { box-sizing: border-box; }
body { margin: 0 auto; max-width: 1200px; padding: 24px 16px; background: var(--bg); color: var(--fg);
       font: 14px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
a { color: var(--link); }
h1 { font-size: 22px; margin: 0 0 4px; }
h2 { font-size: 17px; margin: 0; padding: 8px 12px; background: var(--head);
     border: 1px solid var(--border); border-radius: 6px 6px 0 0; }
h2 .summary { font-weight: normal; color: var(--muted); }
h3 { font-size: 14px; margin: 16px 12px 6px; }
.meta { color: var(--muted); margin: 0 0 20px; }
section { margin: 28px 0; }
section .body { display: flow-root; border: 1px solid var(--border); border-top: 0; border-radius: 0 0 6px 6px;
                padding-bottom: 8px; }
section.error h2 { color: var(--red); background: var(--red-bg); border-radius: 6px; }
table { border-collapse: collapse; width: 100%; }
th, td { text-align: left; vertical-align: top; padding: 4px 12px; border-bottom: 1px solid var(--border); }
th { font-weight: 600; color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .03em; }
tr:last-child td { border-bottom: 0; }
td.num, th.num { text-align: right; }
td.pkg, td.ver { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 13px; white-space: nowrap; }
td.tag { width: 1%; white-space: nowrap; }
table.overview { border: 1px solid var(--border); }
table.overview tr.attention td:first-child { box-shadow: inset 3px 0 var(--red); }
table.overview td.error { color: var(--red); font-weight: 600; }
.badge { display: inline-block; padding: 0 6px; border-radius: 10px; font-size: 11px; font-weight: 700; }
.badge.sec { background: var(--red-bg); color: var(--red); }
.badge.kev { background: var(--red); color: var(--bg); }
.prio { font-weight: 600; }
.prio-critical { color: var(--red); text-transform: uppercase; }
.prio-high { color: var(--red); }
.prio-medium { color: var(--orange); }
.prio-low, .prio-negligible { color: var(--muted); }
.note { color: var(--muted); }
.warning { margin: 8px 12px; color: var(--yellow); }
details { margin: 2px 0 6px; }
details summary { cursor: pointer; color: var(--muted); }
details pre { margin: 4px 0; white-space: pre-wrap; font-size: 12px; }
details p { margin: 4px 0; }
ul.notices { padding-left: 20px; color: var(--muted); }
p.total { font-weight: 600; }
@media print {
  body { max-width: none; padding: 0; font-size: 11px; }
  details > *:not(summary) { display: block !important; }
  details summary { display: none; }
  tr, h2, h3 { break-inside: avoid; }
  section { break-inside: auto; }
  a { color: inherit; text-decoration: none; }
}
"""


def _prio(prio: str | None) -> str:
    if not prio:
        return ""
    return f'<span class="prio prio-{escape(prio)}">{escape(prio)}</span>'


def _kev_badge() -> str:
    return '<span class="badge kev">KEV</span>'


def _cve_cell(pkg: PackageReport, cves: dict[str, CveInfo], kev: dict[str, KevEntry]) -> str:
    parts = []
    for cve_id in pkg.cves:
        info = cves.get(cve_id)
        marks = [m for m in (_prio(info.priority if info else None), _kev_badge() if cve_id in kev else "") if m]
        parts.append(escape(cve_id) + (" " + " ".join(marks) if marks else ""))
    text = ", ".join(parts)
    note = package_note(pkg)
    if note:
        text = f'<span class="note">{escape(note)}</span>'
    if pkg.changelog_uncertain:
        text += ' <span class="note">[match uncertain]</span>'
    return text


def _cve_details(cve_id: str, cves: dict[str, CveInfo], kev: dict[str, KevEntry]) -> list[str]:
    out = []
    info = cves.get(cve_id)
    if info and info.description:
        out.append(f"<p><strong>{escape(cve_id)}:</strong> {escape(info.description)}</p>")
    entry = kev.get(cve_id)
    if entry:
        out.append(f"<p>{_kev_badge()} KEV: {escape(entry.name)} (added {escape(entry.date_added)})</p>")
    return out


def _package_details(pkg: PackageReport, cves: dict[str, CveInfo], kev: dict[str, KevEntry]) -> str:
    body: list[str] = []
    if not pkg.changelog_available:
        body.append('<p class="note">Changelog unavailable</p>')
    if pkg.changelog_uncertain:
        body.append('<p class="note">(installed version not found in changelog – '
                    'excerpt may be incomplete)</p>')
    for entry in pkg.entries:
        lines = "\n".join(changelog_lines(entry))
        body.append(f"<pre><strong>{escape(entry.version)}:</strong>\n{escape(lines)}</pre>")
    for cve_id in pkg.cves:
        body.extend(_cve_details(cve_id, cves, kev))
    if not body:
        return ""
    return f"<details><summary>Changelog &amp; Details</summary>{''.join(body)}</details>"


def _packages_table(
    report: HostReport, cves: dict[str, CveInfo], kev: dict[str, KevEntry], details: bool, security_only: bool
) -> list[str]:
    packages = sorted_packages(report, cves, kev, security_only)
    if not packages:
        return []
    out = ["<h3>Updates</h3>", "<table><thead><tr><th></th><th>Package</th><th>Version</th><th>CVEs</th>"
           "</tr></thead><tbody>"]
    for pkg in packages:
        tag = '<span class="badge sec">SEC</span>' if pkg.upgrade.is_security else ""
        version = f"{pkg.upgrade.old_version} → {pkg.upgrade.new_version}"
        cve_cell = _cve_cell(pkg, cves, kev)
        if details:
            cve_cell += _package_details(pkg, cves, kev)
        out.append(
            f'<tr><td class="tag">{tag}</td><td class="pkg">{escape(pkg.upgrade.package)}</td>'
            f'<td class="ver">{escape(version)}</td><td>{cve_cell}</td></tr>'
        )
    out.append("</tbody></table>")
    return out


def _vuln_cve_cell(v: OpenVuln, cve_text: str, summarized: bool) -> str:
    if summarized:
        return escape(cve_text)
    return escape(v.cve_id) + (" " + _prio(v.priority) if v.priority else "")


def _open_vulns_table(
    report: HostReport, cves: dict[str, CveInfo], kev: dict[str, KevEntry], details: bool
) -> list[str]:
    if not report.open_vulns:
        return []
    out = ["<h3>Open vulnerabilities (no fix available yet)</h3>", "<table><thead><tr><th></th><th>Package</th><th>Installed</th>"
           "<th>CVE</th><th>Status</th></tr></thead><tbody>"]
    for row in open_vuln_rows(report.open_vulns, details):
        tag = _kev_badge() if row.vuln.kev else ""
        cve_cell = _vuln_cve_cell(row.vuln, row.cve_text, row.summarized)
        if details and not row.summarized:
            extra = _cve_details(row.vuln.cve_id, cves, kev)
            if extra:
                cve_cell += f"<details><summary>Details</summary>{''.join(extra)}</details>"
        out.append(
            f'<tr><td class="tag">{tag}</td><td class="pkg">{escape(row.name)}</td>'
            f'<td class="ver">{escape(row.version)}</td><td>{cve_cell}</td><td>{escape(row.status)}</td></tr>'
        )
    out.append("</tbody></table>")
    return out


def _host_section(
    index: int,
    report: HostReport,
    cves: dict[str, CveInfo],
    kev: dict[str, KevEntry],
    details: bool,
    security_only: bool,
    verbose: bool,
) -> list[str]:
    anchor = f"host-{index}"
    if report.error:
        return [
            f'<section class="error" id="{anchor}"><h2>{escape(report.host)} '
            f'<span class="summary">— ERROR: {escape(report.error)}</span></h2></section>'
        ]
    os_part = f" (Ubuntu {report.os_version})" if report.os_version else ""
    out = [
        f'<section id="{anchor}"><h2>{escape(report.host + os_part)} '
        f'<span class="summary">— {escape(host_summary(report))}</span></h2><div class="body">'
    ]
    out.extend(f'<p class="warning">⚠ {escape(w)}</p>' for w in report.warnings)
    if report.vuln_check_problem:
        out.append(f'<p class="warning">⚠ Vulnerability check not possible: {escape(report.vuln_check_problem)}</p>')
    out.extend(_packages_table(report, cves, kev, details, security_only))
    out.extend(_open_vulns_table(report, cves, kev, details))
    if verbose:
        out.extend(f'<p class="note">? not parsed: {escape(line)}</p>' for line in report.unparsed)
    out.append("</div></section>")
    return out


def _overview(reports: list[HostReport], kev: dict[str, KevEntry]) -> list[str]:
    out = ['<table class="overview"><thead><tr><th>Host</th><th>Ubuntu</th><th class="num">Updates</th>'
           '<th class="num">Security</th><th class="num">KEV fix</th><th>Open vulnerabilities</th></tr></thead><tbody>']
    for i, row in enumerate(overview_rows(reports, kev)):
        link = f'<a href="#host-{i}">{escape(row.host)}</a>'
        cls = ' class="attention"' if row.attention else ""
        if row.error:
            out.append(f'<tr{cls}><td>{link}</td><td class="error" colspan="5">ERROR: {escape(row.error)}</td></tr>')
            continue
        out.append(
            f"<tr{cls}><td>{link}</td><td>{escape(row.os_version)}</td>"
            f'<td class="num">{row.updates}</td><td class="num">{row.security}</td>'
            f'<td class="num">{row.kev_fixes}</td><td>{escape(row.open_vulns)}</td></tr>'
        )
    out.append("</tbody></table>")
    return out


def _kev_recent(reports: list[HostReport], entries: list[KevEntry], days: int) -> list[str]:
    period = "last day" if days == 1 else f"last {days} days"
    out = [f"<section><h2>New on CISA KEV ({period})</h2><div class=\"body\">"]
    if not entries:
        out.append('<p class="note" style="margin: 8px 12px">(none)</p>')
    else:
        out.append("<table><thead><tr><th>Added</th><th>CVE</th><th>Product</th><th>Name</th>"
                   "<th>Affects</th></tr></thead><tbody>")
        for e in sorted(entries, key=lambda e: e.date_added, reverse=True):
            hosts = ", ".join(kev_affected_hosts(reports, e.cve_id))
            out.append(
                f"<tr><td>{escape(e.date_added)}</td><td>{escape(e.cve_id)}</td>"
                f"<td>{escape(f'{e.vendor} {e.product}')}</td><td>{escape(e.name)}</td>"
                f"<td><strong>{escape(hosts)}</strong></td></tr>"
            )
        out.append("</tbody></table>")
    out.append("</div></section>")
    return out


def render_html_report(
    reports: list[HostReport],
    cves: dict[str, CveInfo],
    *,
    generated: datetime.datetime,
    details: bool = False,
    security_only: bool = False,
    cve_lookup_failed: bool = False,
    verbose: bool = False,
    kev: dict[str, KevEntry] | None = None,
    kev_recent: list[KevEntry] | None = None,
    kev_recent_days: int = 7,
    notices: list[str] | None = None,
) -> str:
    kev = kev or {}
    stamp = generated.strftime("%Y-%m-%d %H:%M")
    out = [
        "<!DOCTYPE html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>Update report {stamp}</title><style>{CSS}</style></head><body>",
        "<h1>Update report</h1>",
        f'<p class="meta">Generated {stamp} · {plural(len(reports), "host")}</p>',
    ]
    out.extend(_overview(reports, kev))
    for i, report in enumerate(reports):
        out.extend(_host_section(i, report, cves, kev, details, security_only, verbose))
    if kev_recent is not None:
        out.extend(_kev_recent(reports, kev_recent, kev_recent_days))
    hints = []
    if cve_lookup_failed:
        hints.append("Some CVE priorities unavailable (Ubuntu security API unreachable).")
    hints.extend(notices or [])
    if hints:
        out.append('<ul class="notices">' + "".join(f"<li>Note: {escape(h)}</li>" for h in hints) + "</ul>")
    out.append(f'<p class="total">{escape(summary_text(reports, kev))}</p>')
    out.append("</body></html>")
    return "\n".join(out) + "\n"

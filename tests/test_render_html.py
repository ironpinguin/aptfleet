from __future__ import annotations

import datetime
import re
import unittest
from html.parser import HTMLParser

from cve_info import CveInfo
from parsing import ChangelogEntry, HostReport, OpenVuln, PackageReport, Upgrade
from render_html import render_html_report
from tests.test_render import CVES, KEV_ENTRY, KEV_SSH, single, webserver

GENERATED = datetime.datetime(2026, 11, 15, 14, 30)


def render(reports, cves=None, **kwargs) -> str:
    return render_html_report(reports, cves if cves is not None else CVES, generated=GENERATED, **kwargs)


class _Collector(HTMLParser):
    """Collects tags/attributes and checks that opening and closing tags match."""
    VOID = {"meta", "br", "hr", "img", "link", "input"}

    def __init__(self):
        super().__init__()
        self.stack: list[str] = []
        self.tags: list[tuple[str, dict]] = []
        self.errors: list[str] = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))
        if tag not in self.VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if not self.stack or self.stack[-1] != tag:
            self.errors.append(f"unexpected </{tag}>, open: {self.stack[-3:]}")
        else:
            self.stack.pop()


def parse(html: str) -> _Collector:
    c = _Collector()
    c.feed(html)
    return c


def open_vuln_report() -> HostReport:
    r = single("tzdata", ["noble-updates"], [])
    r.host = "vm1"
    r.open_vulns = [
        OpenVuln("openssh", ["openssh-server"], "1:9.6p1-3ubuntu13.5", "CVE-2026-4711", "high", "no fix", True),
        OpenVuln("linux", ["linux-image-6.8.0-45-generic"], "6.8.0-45.45", "CVE-2026-0001", "critical",
                 "no fix", False, is_kernel=True),
        OpenVuln("linux", ["linux-image-6.8.0-45-generic"], "6.8.0-45.45", "CVE-2026-0002", "high",
                 "no fix", False, is_kernel=True),
    ]
    return r


class RenderHtmlTest(unittest.TestCase):
    def test_self_contained_document(self):
        out = render([webserver()])
        self.assertTrue(out.startswith("<!DOCTYPE html>"))
        self.assertIn('<meta charset="utf-8">', out)
        self.assertIn("<title>Update report 2026-11-15 14:30</title>", out)
        self.assertIn("<style>", out)
        self.assertIn("@media print", out)
        self.assertNotIn("<script", out)
        self.assertNotRegex(out, r'(src|href)="https?://')
        self.assertEqual(parse(out).errors, [])
        self.assertEqual(parse(out).stack, [])

    def test_overview_links_to_host_sections(self):
        reports = [webserver(), HostReport(host="db1", error="ssh timeout after 120s"), open_vuln_report()]
        out = render(reports, kev={"CVE-2025-9232": KEV_ENTRY})
        tags = parse(out).tags
        hrefs = [a["href"] for t, a in tags if t == "a" and a.get("href", "").startswith("#")]
        ids = {a["id"] for t, a in tags if "id" in a}
        self.assertEqual(len(hrefs), 3)
        self.assertTrue(set(h[1:] for h in hrefs) <= ids)
        overview = out[out.index('<table class="overview">'):]
        overview = overview[:overview.index("</table>")]
        self.assertIn(">web1</a>", overview)
        self.assertIn("ERROR: ssh timeout after 120s", overview)
        self.assertIn("3 (1 KEV)", overview)
        self.assertRegex(overview, r"<td class=\"num\">2</td>")  # KEV fix web1

    def test_overview_also_for_single_host(self):
        self.assertIn('<table class="overview">', render([webserver()]))

    def test_package_rows_with_badges_and_priorities(self):
        out = render([webserver()], kev={"CVE-2025-9232": KEV_ENTRY})
        self.assertIn('<span class="badge sec">SEC</span>', out)
        self.assertIn('<span class="prio prio-high">high</span>', out)
        self.assertIn('<span class="badge kev">KEV</span>', out)
        self.assertIn("3.0.13-0ubuntu3.4 → 3.0.13-0ubuntu3.5", out)
        self.assertIn("(changelog unavailable)", out)
        order = [m for m in re.findall(r'<td class="pkg">([^<]+)</td>', out)]
        self.assertEqual(order, ["libssl3t64", "openssl", "libxml2", "docker-ce", "tzdata"])

    def test_security_only(self):
        out = render([webserver()], security_only=True)
        self.assertNotIn(">tzdata<", out)
        self.assertIn(">openssl<", out)

    def test_uncertain_marker(self):
        out = render([single("foo", ["jammy-security"], ["CVE-2025-1"], uncertain=True)], {})
        self.assertIn("[match uncertain]", out)

    def test_no_details_by_default(self):
        self.assertNotIn("<details", render([webserver()]))

    def test_details_with_changelog_and_cve_descriptions(self):
        out = render([webserver()], details=True, kev={"CVE-2025-9231": KEV_ENTRY})
        self.assertIn("<details", out)
        self.assertIn("3.0.13-0ubuntu3.5", out)
        self.assertIn("SECURITY UPDATE: Out-of-bounds read in HTTP client no_proxy handling", out)
        self.assertIn("Out-of-bounds read in HTTP client.", out)
        self.assertIn("KEV: OpenSSL Timing Flaw (added 2026-11-01)", out)
        self.assertNotIn("-- Ubuntu Security Team", out)
        self.assertEqual(parse(out).errors, [])

    def test_escaping(self):
        evil = HostReport(host="<b>evil</b>", error="<script>alert(1)</script>")
        pkg = PackageReport(Upgrade("foo", ["noble-security"], "2.0-1", "1.0-1", "amd64"), "foo",
                            [ChangelogEntry("2.0-1", "  * Fix <img src=x> & more.")], [], True, False)
        other = HostReport("h", os_version="24.04", packages=[pkg])
        out = render([evil, other], details=True)
        self.assertNotIn("<script>alert", out)
        self.assertNotIn("<b>evil</b>", out)
        self.assertNotIn("<img", out)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", out)
        self.assertIn("Fix &lt;img src=x&gt; &amp; more.", out)

    def test_error_host_section(self):
        out = render([HostReport(host="db1", error="ssh timeout after 120s")])
        section = out[out.index("<section"):]
        self.assertIn("ERROR: ssh timeout after 120s", section)

    def test_warnings_and_vuln_problem(self):
        r = HostReport("h", os_version="24.04", warnings=["apt-get update skipped"],
                       vuln_check_problem="no package list")
        out = render([r])
        self.assertIn("apt-get update skipped", out)
        self.assertIn("Vulnerability check not possible: no package list", out)

    def test_open_vulns_table_with_kernel_summary(self):
        out = render([open_vuln_report()], {})
        self.assertIn("Open vulnerabilities (no fix available yet)", out)
        self.assertIn(">openssh-server<", out)
        self.assertIn("linux (kernel)", out)
        self.assertIn("2 CVEs (1 critical, 1 high)", out)
        self.assertIn("no fix – list with --details", out)

    def test_open_vulns_details_list_each_kernel_cve(self):
        info = {"CVE-2026-4711": CveInfo("CVE-2026-4711", "high", "RCE in sshd.")}
        out = render([open_vuln_report()], info, details=True, kev={"CVE-2026-4711": KEV_SSH})
        self.assertIn("CVE-2026-0001", out)
        self.assertIn("CVE-2026-0002", out)
        self.assertIn("RCE in sshd.", out)
        self.assertIn("KEV: OpenSSH RCE (added 2026-11-09)", out)

    def test_kev_recent_notices_and_summary(self):
        r = single("foo", ["jammy-security"], ["CVE-2026-4711"])
        r.host = "web1"
        out = render([r], {}, kev_recent=[KEV_SSH], kev_recent_days=7, notices=["KEV data from 2026-11-01"],
                     cve_lookup_failed=True)
        self.assertIn("New on CISA KEV (last 7 days)", out)
        self.assertIn("CVE-2026-4711", out)
        self.assertIn("web1", out[out.index("New on CISA KEV"):])
        self.assertIn("KEV data from 2026-11-01", out)
        self.assertIn("Some CVE priorities unavailable", out)
        self.assertIn("Summary: 1 host, 1 update, 1 security", out)
        self.assertNotIn("New on CISA KEV", render([r], {}))

    def test_verbose_unparsed(self):
        r = HostReport("h", unparsed=["garbage"])
        self.assertNotIn("garbage", render([r], {}))
        self.assertIn("garbage", render([r], {}, verbose=True))


if __name__ == "__main__":
    unittest.main()

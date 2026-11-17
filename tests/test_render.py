from __future__ import annotations

import unittest
from pathlib import Path

from cve_info import CveInfo
from kev import KevEntry
from parsing import ChangelogEntry, HostReport, OpenVuln, PackageReport, Upgrade, build_host_report
from render import render_report

FIXTURES = Path(__file__).parent / "fixtures"
CVES = {
    "CVE-2025-9231": CveInfo("CVE-2025-9231", "medium", "Timing side-channel in SM2."),
    "CVE-2025-9232": CveInfo("CVE-2025-9232", "high", "Out-of-bounds read in HTTP client."),
}


def webserver() -> HostReport:
    return build_host_report("web1", (FIXTURES / "remote_output.txt").read_text())


def package_lines(output: str) -> list[str]:
    return [
        line for line in output.splitlines()
        if (line.startswith(" SEC  ") or line.startswith("      ")) and not line.lstrip().startswith("Package")
    ]


def single(package: str, pockets: list[str], cves: list[str], available=True, uncertain=False) -> HostReport:
    upgrade = Upgrade(package, pockets, "2.0-1", "1.0-1", "amd64")
    entries = [ChangelogEntry("2.0-1", "  * Fix.")] if available else []
    return HostReport(
        host="mail1",
        os_version="22.04",
        packages=[PackageReport(upgrade, package, entries, cves, available, uncertain)],
    )

KEV_ENTRY = KevEntry("CVE-2025-9231", "OpenSSL", "OpenSSL", "OpenSSL Timing Flaw", "2026-11-01")
KEV_SSH = KevEntry("CVE-2026-4711", "OpenBSD", "OpenSSH", "OpenSSH RCE", "2026-11-09")
KEV_CISCO = KevEntry("CVE-2026-5020", "Cisco", "IOS XE", "Cisco IOS XE Auth Bypass " + "x" * 60, "2026-11-08")


def two_security(kev_first_name="zlib", other_name="aaa") -> HostReport:
    """The KEV package has a lower priority and a later name than the other one."""
    def pkg(name, cve):
        return PackageReport(Upgrade(name, ["noble-security"], "2.0-1", "1.0-1", "amd64"), name,
                             [ChangelogEntry("2.0-1", "  * Fix.")], [cve], True, False)
    return HostReport("h", os_version="24.04", packages=[pkg(other_name, "CVE-1"), pkg(kev_first_name, "CVE-2")])


class RenderReportTest(unittest.TestCase):
    def test_header_and_order(self):
        out = render_report([webserver()], CVES)
        self.assertIn("━━ web1 (Ubuntu 24.04) — 5 updates, 3 security ━━", out)
        names = [line.split()[1] if line.startswith(" SEC") else line.split()[0] for line in package_lines(out)]
        self.assertEqual(names, ["libssl3t64", "openssl", "libxml2", "docker-ce", "tzdata"])

    def test_security_line_content(self):
        out = render_report([webserver()], CVES)
        openssl = next(l for l in package_lines(out) if " openssl " in l)
        self.assertTrue(openssl.startswith(" SEC  openssl"))
        self.assertIn("3.0.13-0ubuntu3.4 → 3.0.13-0ubuntu3.5", openssl)
        self.assertTrue(openssl.endswith("CVE-2025-9231 (medium), CVE-2025-9232 (high)"))
        libxml2 = next(l for l in package_lines(out) if " libxml2 " in l)
        self.assertTrue(libxml2.endswith("(changelog unavailable)"))

    def test_exact_non_security_line(self):
        report = single("tzdata", ["jammy-updates"], [])
        out = render_report([report], {})
        self.assertIn("      tzdata   1.0-1 → 2.0-1\n", out + "\n")

    def test_security_without_cve(self):
        out = render_report([single("foo", ["jammy-security"], [])], {})
        self.assertIn(" SEC  foo      1.0-1 → 2.0-1  (no CVE in changelog)", out)

    def test_uncertain_marker_and_unknown_priority(self):
        out = render_report([single("foo", ["jammy-security"], ["CVE-2025-1"], uncertain=True)], {})
        self.assertIn("CVE-2025-1 [match uncertain]", out)

    def test_security_only(self):
        out = render_report([webserver()], CVES, security_only=True)
        self.assertNotIn("tzdata", out)
        self.assertNotIn("docker-ce", out)
        self.assertIn("5 updates, 3 security", out)

    def test_details(self):
        out = render_report([webserver()], CVES, details=True)
        self.assertIn("        3.0.13-0ubuntu3.5:", out)
        self.assertIn("          * SECURITY UPDATE: Out-of-bounds read in HTTP client no_proxy handling", out)
        self.assertIn("        CVE-2025-9232: Out-of-bounds read in HTTP client.", out)
        self.assertIn("        Changelog unavailable", out)
        self.assertNotIn("-- Ubuntu Security Team", out)

    def test_error_warning_and_empty_hosts_and_summary(self):
        reports = [
            webserver(),
            HostReport(host="db1", error="ssh timeout after 120s"),
            HostReport(host="mail1", os_version="22.04", warnings=["apt-get update failed (rc=100): E: lock"]),
        ]
        out = render_report(reports, CVES)
        self.assertIn("━━ db1 — ERROR: ssh timeout after 120s ━━", out)
        self.assertIn("━━ mail1 (Ubuntu 22.04) — no updates, no open vulnerabilities ━━", out)
        self.assertIn("  ⚠ apt-get update failed (rc=100): E: lock", out)
        self.assertTrue(out.endswith("Summary: 3 hosts, 5 updates, 3 security, 1 host unreachable"))

    def test_plural_unreachable(self):
        reports = [HostReport(host="a", error="x"), HostReport(host="b", error="y")]
        self.assertIn("2 hosts unreachable", render_report(reports, {}))

    def test_color_switch(self):
        self.assertNotIn("\033[", render_report([webserver()], CVES, color=False))
        self.assertIn("\033[", render_report([webserver()], CVES, color=True))

    def test_cve_lookup_failed_hint(self):
        out = render_report([webserver()], CVES, cve_lookup_failed=True)
        self.assertIn("Note: Some CVE priorities unavailable (Ubuntu security API unreachable).", out)

    def test_verbose_shows_unparsed(self):
        report = HostReport(host="mail1", unparsed=["garbage"])
        self.assertNotIn("garbage", render_report([report], {}))
        self.assertIn("  ? not parsed: garbage", render_report([report], {}, verbose=True))

    def test_kev_marked(self):
        out = render_report([webserver()], CVES, kev={"CVE-2025-9231": KEV_ENTRY})
        self.assertIn("CVE-2025-9231 (medium, KEV)", out)
        out = render_report([single("foo", ["jammy-security"], ["CVE-2025-9231"])], {}, kev={"CVE-2025-9231": KEV_ENTRY})
        self.assertIn("CVE-2025-9231 (KEV)", out)

    def test_kev_sorted_before_higher_priority(self):
        cves = {"CVE-1": CveInfo("CVE-1", "critical", "a"), "CVE-2": CveInfo("CVE-2", "low", "b")}
        report = two_security()
        out = render_report([report], cves)
        self.assertTrue(package_lines(out)[0].startswith(" SEC  aaa"))
        out = render_report([report], cves, kev={"CVE-2": KevEntry("CVE-2", "v", "p", "n", "2026-11-01")})
        self.assertTrue(package_lines(out)[0].startswith(" SEC  zlib"))

    def test_kev_color(self):
        out = render_report([single("foo", ["jammy-security"], ["CVE-2025-9231"])], {},
                            kev={"CVE-2025-9231": KEV_ENTRY}, color=True)
        self.assertIn("\033[31m\033[1mKEV\033[0m", out)

    def test_details_kev(self):
        out = render_report([webserver()], CVES, details=True, kev={"CVE-2025-9231": KEV_ENTRY})
        self.assertIn("        KEV: OpenSSL Timing Flaw (added 2026-11-01)", out)

    def _open_vuln_report(self) -> HostReport:
        r = single("tzdata", ["noble-updates"], [])
        r.open_vulns = [
            OpenVuln("openssh", ["openssh-server"], "1:9.6p1-3ubuntu13.5", "CVE-2026-4711", "high", "no fix", True),
            OpenVuln("linux", ["linux-image-6.8.0-45-generic"], "6.8.0-45.45", "CVE-2026-4100", "high",
                     "fix 6.8.0-50.51 not offered", False, is_kernel=True),
        ]
        return r

    def test_open_vulns_block(self):
        out = render_report([self._open_vuln_report()], {})
        lines = out.splitlines()
        self.assertIn("1 update, 0 security, 2 open vulnerabilities", lines[0])
        i = lines.index("   Open vulnerabilities (no fix available yet):")
        header = lines[i + 1]
        self.assertEqual(header.split(), ["Package", "Installed", "CVE", "Status"])
        self.assertTrue(lines[i + 2].startswith(" KEV  openssh-server"))
        self.assertIn("CVE-2026-4711 (high)", lines[i + 2])
        self.assertTrue(lines[i + 2].rstrip().endswith("no fix"))
        self.assertTrue(lines[i + 3].startswith("      linux (kernel)"))
        self.assertEqual(lines[i + 2].index("1:9.6p1"), lines[i + 3].index("6.8.0-45.45"))
        self.assertEqual(header.index("Installed"), lines[i + 2].index("1:9.6p1"))
        self.assertEqual(header.index("Status"), lines[i + 2].index("no fix"))
        self.assertIn("2 open vulnerabilities (1 KEV)", lines[-1])

    def test_open_vulns_details(self):
        out = render_report([self._open_vuln_report()], {"CVE-2026-4711": CveInfo("CVE-2026-4711", "high", "RCE in sshd.")},
                            details=True, kev={"CVE-2026-4711": KEV_SSH})
        self.assertIn("        CVE-2026-4711: RCE in sshd.", out)
        self.assertIn("        KEV: OpenSSH RCE (added 2026-11-09)", out)

    def test_singular_open_vuln(self):
        r = self._open_vuln_report()
        r.open_vulns = r.open_vulns[1:]
        out = render_report([r], {})
        self.assertIn("1 open vulnerability ━━", out.splitlines()[0])
        self.assertTrue(out.endswith("1 open vulnerability (0 KEV)"))

    @staticmethod
    def _kernel(cve_id, prio="high", status="no fix", kev=False):
        return OpenVuln("linux", ["linux-image-6.8.0-149-generic"], "6.8.0-149.149", cve_id, prio, status, kev,
                        is_kernel=True)

    @staticmethod
    def _pkg_vuln(cve_id="CVE-2025-49844"):
        return OpenVuln("lua5.1", ["liblua5.1-0"], "5.1.5-9build2", cve_id, "high", "no fix", False)

    def _kernel_report(self, vulns) -> HostReport:
        r = single("tzdata", ["noble-updates"], [])
        r.open_vulns = vulns
        return r

    def test_kernel_vulns_are_summarized(self):
        r = self._kernel_report([
            self._kernel("CVE-2026-0001", "critical"), self._kernel("CVE-2026-0002"),
            self._kernel("CVE-2026-0003"), self._pkg_vuln(),
        ])
        out = render_report([r], {})
        lines = out.splitlines()
        kernel_lines = [ln for ln in lines if "linux (kernel)" in ln]
        self.assertEqual(len(kernel_lines), 1)
        self.assertIn("3 CVEs (1 critical, 2 high)", kernel_lines[0])
        self.assertTrue(kernel_lines[0].endswith("no fix – list with --details"))
        self.assertTrue(kernel_lines[0].startswith("      linux (kernel)"))
        for n in (1, 2, 3):
            self.assertNotIn(f"CVE-2026-000{n}", out)
        self.assertIn("4 open vulnerabilities", lines[0])
        self.assertIn("4 open vulnerabilities (0 KEV)", lines[-1])

    def test_kev_kernel_vuln_stays_single(self):
        r = self._kernel_report([
            self._kernel("CVE-2026-9999", "high", kev=True),
            self._kernel("CVE-2026-0001", "critical"), self._kernel("CVE-2026-0002"),
        ])
        out = render_report([r], {})
        kev_lines = [ln for ln in out.splitlines() if "CVE-2026-9999" in ln]
        self.assertEqual(len(kev_lines), 1)
        self.assertTrue(kev_lines[0].startswith(" KEV  linux (kernel)"))
        self.assertIn("2 CVEs (1 critical, 1 high)", out)

    def test_single_kernel_vuln_not_summarized(self):
        r = self._kernel_report([self._kernel("CVE-2026-0001")])
        out = render_report([r], {})
        self.assertIn("CVE-2026-0001 (high)", out)
        self.assertNotIn("list with --details", out)

    def test_different_status_separate_groups(self):
        later = "fix 6.8.0-150.150 not offered"
        r = self._kernel_report([
            self._kernel("CVE-2026-0001"), self._kernel("CVE-2026-0002"),
            self._kernel("CVE-2026-0003", status=later), self._kernel("CVE-2026-0004", status=later),
        ])
        lines = [ln for ln in render_report([r], {}).splitlines() if "linux (kernel)" in ln]
        self.assertEqual(len(lines), 2)
        self.assertTrue(lines[0].endswith("no fix – list with --details"))
        self.assertTrue(lines[1].endswith(f"{later} – list with --details"))
        self.assertTrue(all("2 CVEs (2 high)" in ln for ln in lines))

    def test_details_lists_all_kernel_vulns(self):
        r = self._kernel_report([self._kernel("CVE-2026-0001", "critical"), self._kernel("CVE-2026-0002")])
        out = render_report([r], {}, details=True)
        self.assertIn("CVE-2026-0001 (critical)", out)
        self.assertIn("CVE-2026-0002 (high)", out)
        self.assertNotIn("list with --details", out)
        self.assertNotIn("2 CVEs", out)

    def test_summary_row_position_is_first_group_member(self):
        r = self._kernel_report([
            self._kernel("CVE-2026-0001", "critical"), self._pkg_vuln(), self._kernel("CVE-2026-0002"),
        ])
        lines = render_report([r], {}).splitlines()
        i = lines.index("   Open vulnerabilities (no fix available yet):")
        self.assertIn("linux (kernel)", lines[i + 2])
        self.assertIn("liblua5.1-0", lines[i + 3])

    def test_header_without_anything(self):
        out = render_report([HostReport("mail1", os_version="22.04")], {})
        self.assertIn("━━ mail1 (Ubuntu 22.04) — no updates, no open vulnerabilities ━━", out)

    def test_problem_warning(self):
        r = HostReport("h", os_version="24.04", vuln_check_problem="no package list")
        out = render_report([r], {})
        self.assertIn("  ⚠ Vulnerability check not possible: no package list", out)
        self.assertNotIn("no open vulnerabilities", out)

    def test_kev_recent(self):
        r = single("foo", ["jammy-security"], ["CVE-2026-4711"])
        r.host = "web1"
        out = render_report([r], {}, kev={}, kev_recent=[KEV_SSH, KEV_CISCO], kev_recent_days=7)
        lines = out.splitlines()
        i = lines.index("New on CISA KEV (last 7 days):")
        self.assertEqual(lines[i - 1], "")
        self.assertTrue(lines[i + 1].startswith(" 2026-11-09  CVE-2026-4711  OpenBSD OpenSSH: OpenSSH RCE"))
        self.assertTrue(lines[i + 1].endswith("  affects: web1"))
        self.assertIn("…", lines[i + 2])
        self.assertNotIn("affects", lines[i + 2])
        self.assertIn("  (none)", render_report([r], {}, kev_recent=[], kev_recent_days=7))
        self.assertNotIn("New on CISA KEV", render_report([r], {}))

    def test_kev_recent_single_day_heading(self):
        out = render_report([HostReport("h", os_version="24.04")], {}, kev_recent=[], kev_recent_days=1)
        self.assertIn("New on CISA KEV (last day):", out)
        self.assertNotIn("last 1 days", out)

    def test_kev_recent_affects_open_vuln_host(self):
        out = render_report([self._open_vuln_report()], {}, kev_recent=[KEV_SSH])
        self.assertIn("affects: mail1", out)

    def test_notices_and_summary_kev_fix(self):
        out = render_report([webserver()], CVES, kev={"CVE-2025-9232": KEV_ENTRY}, notices=["KEV data from 2026-11-01"])
        lines = out.splitlines()
        self.assertEqual(lines[-2], "Note: KEV data from 2026-11-01")
        self.assertIn(", 2 KEV fixes available", lines[-1])

    def test_no_color_codes_without_tty(self):
        out = render_report([self._open_vuln_report()], {}, kev={"CVE-2026-4711": KEV_SSH}, kev_recent=[KEV_SSH])
        self.assertNotIn("\033[", out)

    def test_updates_heading_and_column_header(self):
        lines = render_report([webserver()], CVES).splitlines()
        i = lines.index("   Updates:")
        header = lines[i + 1]
        self.assertEqual(header.split(), ["Package", "Version", "CVEs"])
        first = lines[i + 2]
        self.assertTrue(first.startswith(" SEC  libssl3t64"))
        self.assertEqual(header.index("Package"), first.index("libssl3t64"))
        self.assertEqual(header.index("Version"), first.index("3.0.13-0ubuntu3.4"))
        self.assertEqual(header.index("CVEs"), first.index("CVE-2025-9231"))

    def test_no_updates_heading_without_packages(self):
        out = render_report([HostReport("mail1", os_version="22.04")], {})
        self.assertNotIn("Updates:", out)
        self.assertNotIn("Package", out)

    def test_no_updates_heading_when_security_only_filters_all(self):
        out = render_report([single("tzdata", ["jammy-updates"], [])], {}, security_only=True)
        self.assertNotIn("   Updates:", out)

    def test_column_header_dimmed_with_color(self):
        out = render_report([webserver()], CVES, color=True)
        header = next(l for l in out.splitlines() if "Package" in l)
        self.assertIn("\033[2m", header)

    def test_single_host_has_no_overview(self):
        out = render_report([webserver()], CVES)
        self.assertTrue(out.startswith("━━ web1"))

    def test_overview_for_multiple_hosts(self):
        problem = HostReport("mail1", os_version="22.04", vuln_check_problem="no package list")
        vulns = self._open_vuln_report()
        vulns.host = "vm1"
        reports = [webserver(), HostReport(host="db1", error="ssh timeout after 120s"), problem, vulns]
        lines = render_report(reports, CVES, kev={"CVE-2025-9232": KEV_ENTRY}).splitlines()
        self.assertEqual(lines[0].split(), ["Host", "Ubuntu", "Updates", "Security", "KEV", "fix", "Open", "vulnerabilities"])
        self.assertEqual(lines[1].split(), ["web1", "24.04", "5", "3", "2", "–"])
        self.assertEqual(lines[2].split("  ", 1)[0], "db1")
        self.assertTrue(lines[2].endswith("ERROR: ssh timeout after 120s"))
        self.assertEqual(lines[3].split(), ["mail1", "22.04", "0", "0", "0", "not", "checked"])
        self.assertEqual(lines[4].split(), ["vm1", "22.04", "1", "0", "0", "2", "(1", "KEV)"])
        self.assertEqual(lines[5], "")
        self.assertTrue(lines[6].startswith("━━ web1"))
        # numbers right-aligned under their column header
        self.assertEqual(lines[0].index("Updates") + len("Updates"), lines[1].index(" 5 ") + 2)
        self.assertEqual(lines[0].index("Open"), lines[1].index("–"))

    def test_overview_bold_header_with_color(self):
        out = render_report([webserver(), HostReport(host="b", error="x")], CVES, color=True)
        self.assertTrue(out.startswith("\033[1mHost"))

    def test_blank_line_between_hosts(self):
        reports = [HostReport("a", os_version="24.04"), HostReport("b", os_version="24.04")]
        lines = render_report(reports, {}).splitlines()
        i = next(n for n, l in enumerate(lines) if l.startswith("━━ b"))
        self.assertEqual(lines[i - 1], "")


if __name__ == "__main__":
    unittest.main()

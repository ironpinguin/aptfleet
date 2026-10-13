from __future__ import annotations

import unittest
from pathlib import Path

from cve_info import CveInfo
from parsing import ChangelogEntry, HostReport, PackageReport, Upgrade, build_host_report
from render import render_report

FIXTURES = Path(__file__).parent / "fixtures"
CVES = {
    "CVE-2025-9231": CveInfo("CVE-2025-9231", "medium", "Timing side-channel in SM2."),
    "CVE-2025-9232": CveInfo("CVE-2025-9232", "high", "Out-of-bounds read in HTTP client."),
}


def webserver() -> HostReport:
    return build_host_report("webserver-ansible", (FIXTURES / "remote_output.txt").read_text())


def package_lines(output: str) -> list[str]:
    return [line for line in output.splitlines() if line.startswith(" SEC  ") or line.startswith("      ")]


def single(package: str, pockets: list[str], cves: list[str], available=True, uncertain=False) -> HostReport:
    upgrade = Upgrade(package, pockets, "2.0-1", "1.0-1", "amd64")
    entries = [ChangelogEntry("2.0-1", "  * Fix.")] if available else []
    return HostReport(
        host="git-ansible",
        os_version="22.04",
        packages=[PackageReport(upgrade, package, entries, cves, available, uncertain)],
    )


class RenderReportTest(unittest.TestCase):
    def test_header_and_order(self):
        out = render_report([webserver()], CVES)
        self.assertIn("━━ webserver-ansible (Ubuntu 24.04) — 5 Updates, 3 Security ━━", out)
        names = [line.split()[1] if line.startswith(" SEC") else line.split()[0] for line in package_lines(out)]
        self.assertEqual(names, ["libssl3t64", "openssl", "libxml2", "docker-ce", "tzdata"])

    def test_security_line_content(self):
        out = render_report([webserver()], CVES)
        openssl = next(l for l in package_lines(out) if " openssl " in l)
        self.assertTrue(openssl.startswith(" SEC  openssl"))
        self.assertIn("3.0.13-0ubuntu3.4 → 3.0.13-0ubuntu3.5", openssl)
        self.assertTrue(openssl.endswith("CVE-2025-9231 (medium), CVE-2025-9232 (high)"))
        libxml2 = next(l for l in package_lines(out) if " libxml2 " in l)
        self.assertTrue(libxml2.endswith("(Changelog nicht verfügbar)"))

    def test_exact_non_security_line(self):
        report = single("tzdata", ["jammy-updates"], [])
        out = render_report([report], {})
        self.assertIn("      tzdata  1.0-1 → 2.0-1\n", out + "\n")

    def test_security_without_cve(self):
        out = render_report([single("foo", ["jammy-security"], [])], {})
        self.assertIn(" SEC  foo  1.0-1 → 2.0-1  (keine CVE im Changelog)", out)

    def test_uncertain_marker_and_unknown_priority(self):
        out = render_report([single("foo", ["jammy-security"], ["CVE-2025-1"], uncertain=True)], {})
        self.assertIn("CVE-2025-1 [Abgleich unsicher]", out)

    def test_security_only(self):
        out = render_report([webserver()], CVES, security_only=True)
        self.assertNotIn("tzdata", out)
        self.assertNotIn("docker-ce", out)
        self.assertIn("5 Updates, 3 Security", out)

    def test_details(self):
        out = render_report([webserver()], CVES, details=True)
        self.assertIn("        3.0.13-0ubuntu3.5:", out)
        self.assertIn("          * SECURITY UPDATE: Out-of-bounds read in HTTP client no_proxy handling", out)
        self.assertIn("        CVE-2025-9232: Out-of-bounds read in HTTP client.", out)
        self.assertIn("        Changelog nicht verfügbar", out)
        self.assertNotIn("-- Ubuntu Security Team", out)

    def test_error_warning_and_empty_hosts_and_summary(self):
        reports = [
            webserver(),
            HostReport(host="pdf-ansible", error="ssh timeout nach 120s"),
            HostReport(host="git-ansible", os_version="22.04", warnings=["apt-get update fehlgeschlagen (rc=100): E: lock"]),
        ]
        out = render_report(reports, CVES)
        self.assertIn("━━ pdf-ansible — FEHLER: ssh timeout nach 120s ━━", out)
        self.assertIn("━━ git-ansible (Ubuntu 22.04) — keine Updates ━━", out)
        self.assertIn("  ⚠ apt-get update fehlgeschlagen (rc=100): E: lock", out)
        self.assertTrue(out.endswith("Zusammenfassung: 3 Hosts, 5 Updates, 3 Security, 1 Host nicht erreichbar"))

    def test_plural_unreachable(self):
        reports = [HostReport(host="a", error="x"), HostReport(host="b", error="y")]
        self.assertIn("2 Hosts nicht erreichbar", render_report(reports, {}))

    def test_color_switch(self):
        self.assertNotIn("\033[", render_report([webserver()], CVES, color=False))
        self.assertIn("\033[", render_report([webserver()], CVES, color=True))

    def test_cve_lookup_failed_hint(self):
        out = render_report([webserver()], CVES, cve_lookup_failed=True)
        self.assertIn("Hinweis: CVE-Prioritäten teilweise nicht abrufbar (Ubuntu-Security-API nicht erreichbar).", out)

    def test_verbose_shows_unparsed(self):
        report = HostReport(host="git-ansible", unparsed=["quatsch"])
        self.assertNotIn("quatsch", render_report([report], {}))
        self.assertIn("  ? nicht geparst: quatsch", render_report([report], {}, verbose=True))


if __name__ == "__main__":
    unittest.main()

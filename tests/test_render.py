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

KEV_ENTRY = KevEntry("CVE-2025-9231", "OpenSSL", "OpenSSL", "OpenSSL Timing Flaw", "2026-11-01")
KEV_SSH = KevEntry("CVE-2026-4711", "OpenBSD", "OpenSSH", "OpenSSH RCE", "2026-11-09")
KEV_CISCO = KevEntry("CVE-2026-5020", "Cisco", "IOS XE", "Cisco IOS XE Auth Bypass " + "x" * 60, "2026-11-08")


def two_security(kev_first_name="zlib", other_name="aaa") -> HostReport:
    """KEV-Paket hat niedrigere Prioritaet und spaeteren Namen als das andere."""
    def pkg(name, cve):
        return PackageReport(Upgrade(name, ["noble-security"], "2.0-1", "1.0-1", "amd64"), name,
                             [ChangelogEntry("2.0-1", "  * Fix.")], [cve], True, False)
    return HostReport("h", os_version="24.04", packages=[pkg(other_name, "CVE-1"), pkg(kev_first_name, "CVE-2")])


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
        self.assertIn("━━ git-ansible (Ubuntu 22.04) — keine Updates, keine offenen Lücken ━━", out)
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
        self.assertIn("        KEV: OpenSSL Timing Flaw (seit 2026-11-01)", out)

    def _open_vuln_report(self) -> HostReport:
        r = single("tzdata", ["noble-updates"], [])
        r.open_vulns = [
            OpenVuln("openssh", ["openssh-server"], "1:9.6p1-3ubuntu13.5", "CVE-2026-4711", "high", "kein Fix", True),
            OpenVuln("linux", ["linux-image-6.8.0-45-generic"], "6.8.0-45.45", "CVE-2026-4100", "high",
                     "Fix 6.8.0-50.51 nicht angeboten", False, is_kernel=True),
        ]
        return r

    def test_open_vulns_block(self):
        out = render_report([self._open_vuln_report()], {})
        lines = out.splitlines()
        self.assertIn("1 Updates, 0 Security, 2 offene Lücken", lines[0])
        i = lines.index("   Offene Lücken ohne Fix:")
        self.assertTrue(lines[i + 1].startswith(" KEV  openssh-server"))
        self.assertIn("CVE-2026-4711 (high)", lines[i + 1])
        self.assertTrue(lines[i + 1].rstrip().endswith("kein Fix"))
        self.assertTrue(lines[i + 2].startswith("      linux (Kernel)"))
        self.assertEqual(lines[i + 1].index("1:9.6p1"), lines[i + 2].index("6.8.0-45.45"))
        self.assertIn("2 offene Lücken (1 KEV)", lines[-1])

    def test_open_vulns_details(self):
        out = render_report([self._open_vuln_report()], {"CVE-2026-4711": CveInfo("CVE-2026-4711", "high", "RCE in sshd.")},
                            details=True, kev={"CVE-2026-4711": KEV_SSH})
        self.assertIn("        CVE-2026-4711: RCE in sshd.", out)
        self.assertIn("        KEV: OpenSSH RCE (seit 2026-11-09)", out)

    def test_singular_open_vuln(self):
        r = self._open_vuln_report()
        r.open_vulns = r.open_vulns[1:]
        out = render_report([r], {})
        self.assertIn("1 offene Lücke ━━", out.splitlines()[0])
        self.assertTrue(out.endswith("1 offene Lücke (0 KEV)"))

    def test_header_without_anything(self):
        out = render_report([HostReport("git-ansible", os_version="22.04")], {})
        self.assertIn("━━ git-ansible (Ubuntu 22.04) — keine Updates, keine offenen Lücken ━━", out)

    def test_problem_warning(self):
        r = HostReport("h", os_version="24.04", vuln_check_problem="keine Paketliste")
        out = render_report([r], {})
        self.assertIn("  ⚠ Lücken-Prüfung nicht möglich: keine Paketliste", out)
        self.assertNotIn("keine offenen Lücken", out)

    def test_kev_recent(self):
        r = single("foo", ["jammy-security"], ["CVE-2026-4711"])
        r.host = "webserver-ansible"
        out = render_report([r], {}, kev={}, kev_recent=[KEV_SSH, KEV_CISCO], kev_recent_days=7)
        lines = out.splitlines()
        i = lines.index("Neu auf CISA KEV (letzte 7 Tage):")
        self.assertEqual(lines[i - 1], "")
        self.assertTrue(lines[i + 1].startswith(" 2026-11-09  CVE-2026-4711  OpenBSD OpenSSH: OpenSSH RCE"))
        self.assertTrue(lines[i + 1].endswith("  betrifft: webserver-ansible"))
        self.assertIn("…", lines[i + 2])
        self.assertNotIn("betrifft", lines[i + 2])
        self.assertIn("  (keine)", render_report([r], {}, kev_recent=[], kev_recent_days=7))
        self.assertNotIn("Neu auf CISA KEV", render_report([r], {}))

    def test_kev_recent_affects_open_vuln_host(self):
        out = render_report([self._open_vuln_report()], {}, kev_recent=[KEV_SSH])
        self.assertIn("betrifft: git-ansible", out)

    def test_notices_and_summary_kev_fix(self):
        out = render_report([webserver()], CVES, kev={"CVE-2025-9232": KEV_ENTRY}, notices=["KEV-Stand vom 2026-11-01"])
        lines = out.splitlines()
        self.assertEqual(lines[-2], "Hinweis: KEV-Stand vom 2026-11-01")
        self.assertIn(", 2 KEV-Fix verfügbar", lines[-1])

    def test_no_color_codes_without_tty(self):
        out = render_report([self._open_vuln_report()], {}, kev={"CVE-2026-4711": KEV_SSH}, kev_recent=[KEV_SSH])
        self.assertNotIn("\033[", out)


if __name__ == "__main__":
    unittest.main()

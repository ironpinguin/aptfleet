from __future__ import annotations

import unittest
from pathlib import Path

from parsing import (
    ChangelogEntry,
    Upgrade,
    build_host_report,
    extract_cves,
    new_changelog_entries,
    parse_changelog,
    parse_sources,
    parse_upgradable,
    split_sections,
)

FIXTURES = Path(__file__).parent / "fixtures"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text()


class SplitSectionsTest(unittest.TestCase):
    def test_splits_all_sections(self):
        sections = split_sections(fixture("remote_output.txt"))
        self.assertEqual(
            list(sections),
            [
                "os",
                "apt_update",
                "upgradable",
                "sources",
                "changelog openssl",
                "changelog tzdata",
                "changelog libxml2",
                "changelog docker-ce",
            ],
        )
        self.assertEqual(sections["os"], "24.04")
        self.assertEqual(sections["changelog libxml2"], "")

    def test_ignores_text_before_first_marker_and_after_end(self):
        sections = split_sections(fixture("remote_output.txt"))
        joined = "\n".join(sections.values())
        self.assertNotIn("Willkommen", joined)
        self.assertNotIn("nach dem Ende", joined)

    def test_empty_input(self):
        self.assertEqual(split_sections(""), {})


class ParseUpgradableTest(unittest.TestCase):
    def test_parses_fixture(self):
        text = split_sections(fixture("remote_output.txt"))["upgradable"]
        upgrades, unparsed = parse_upgradable(text)
        self.assertEqual(unparsed, [])
        self.assertEqual(
            [u.package for u in upgrades],
            ["libssl3t64", "openssl", "tzdata", "libxml2", "docker-ce"],
        )
        openssl = upgrades[1]
        self.assertEqual(
            openssl,
            Upgrade(
                package="openssl",
                pockets=["noble-updates", "noble-security"],
                new_version="3.0.13-0ubuntu3.5",
                old_version="3.0.13-0ubuntu3.4",
                arch="amd64",
            ),
        )

    def test_security_detection(self):
        text = split_sections(fixture("remote_output.txt"))["upgradable"]
        upgrades, _ = parse_upgradable(text)
        flags = {u.package: u.is_security for u in upgrades}
        self.assertEqual(
            flags,
            {
                "libssl3t64": True,
                "openssl": True,
                "tzdata": False,
                "libxml2": True,  # ESM: noble-infra-security
                "docker-ce": False,
            },
        )

    def test_keeps_epoch_in_versions(self):
        text = split_sections(fixture("remote_output.txt"))["upgradable"]
        upgrades, _ = parse_upgradable(text)
        docker = upgrades[4]
        self.assertEqual(docker.new_version, "5:28.1.1-1~ubuntu.24.04~noble")
        self.assertEqual(docker.old_version, "5:28.0.4-1~ubuntu.24.04~noble")

    def test_skips_listing_header_and_reports_garbage(self):
        upgrades, unparsed = parse_upgradable("Listing... Done\nkaputte zeile\n\n")
        self.assertEqual(upgrades, [])
        self.assertEqual(unparsed, ["kaputte zeile"])

    def test_tolerates_german_locale(self):
        line = "curl/jammy-security 7.81.0-1ubuntu1.20 amd64 [aktualisierbar von: 7.81.0-1ubuntu1.19]"
        upgrades, unparsed = parse_upgradable(line)
        self.assertEqual(unparsed, [])
        self.assertEqual(upgrades[0].old_version, "7.81.0-1ubuntu1.19")
        self.assertTrue(upgrades[0].is_security)


class ParseSourcesTest(unittest.TestCase):
    def test_maps_binary_to_source(self):
        mapping = parse_sources("libssl3t64 openssl\nopenssl openssl\n\n")
        self.assertEqual(mapping, {"libssl3t64": "openssl", "openssl": "openssl"})

    def test_missing_source_falls_back_to_binary(self):
        self.assertEqual(parse_sources("tzdata \n"), {"tzdata": "tzdata"})


EPOCH_CHANGELOG = """\
foo (1:2.0-3) noble; urgency=medium

  * Fix CVE-2025-0003.

 -- A <a@example.org>  Mon, 01 Sep 2025 10:00:00 +0000

foo (1:2.0-2) noble; urgency=medium

  * Fix CVE-2025-0002 and CVE-2025-0003.

 -- A <a@example.org>  Mon, 01 Aug 2025 10:00:00 +0000

foo (1:2.0-1) noble; urgency=medium

  * Fix CVE-2025-0001.

 -- A <a@example.org>  Mon, 01 Jul 2025 10:00:00 +0000
"""


class ChangelogTest(unittest.TestCase):
    def test_parse_changelog_entries(self):
        entries = parse_changelog(EPOCH_CHANGELOG)
        self.assertEqual([e.version for e in entries], ["1:2.0-3", "1:2.0-2", "1:2.0-1"])
        self.assertIn("* Fix CVE-2025-0003.", entries[0].text)
        self.assertIn("-- A <a@example.org>", entries[0].text)
        self.assertNotIn("foo (1:2.0-3)", entries[0].text)

    def test_new_entries_stop_at_installed_version(self):
        entries, uncertain = new_changelog_entries(EPOCH_CHANGELOG, "1:2.0-1")
        self.assertEqual([e.version for e in entries], ["1:2.0-3", "1:2.0-2"])
        self.assertFalse(uncertain)

    def test_installed_is_newest_gives_no_entries(self):
        entries, uncertain = new_changelog_entries(EPOCH_CHANGELOG, "1:2.0-3")
        self.assertEqual(entries, [])
        self.assertFalse(uncertain)

    def test_installed_version_missing_is_uncertain_and_capped(self):
        many = "".join(
            f"foo (1.{i}) noble; urgency=medium\n\n  * change {i}\n\n -- A <a@b>  date\n\n"
            for i in range(20, 0, -1)
        )
        entries, uncertain = new_changelog_entries(many, "0.9")
        self.assertTrue(uncertain)
        self.assertEqual(len(entries), 10)
        self.assertEqual(entries[0].version, "1.20")

    def test_extract_cves_deduplicates_and_sorts(self):
        entries = [
            ChangelogEntry("2", "CVE-2025-10000 and CVE-2025-9999\nCVE-2025-9999"),
            ChangelogEntry("1", "CVE-2024-1234"),
        ]
        self.assertEqual(
            extract_cves(entries), ["CVE-2024-1234", "CVE-2025-9999", "CVE-2025-10000"]
        )


class BuildHostReportTest(unittest.TestCase):
    def test_full_fixture(self):
        report = build_host_report("webserver-ansible", fixture("remote_output.txt"))
        self.assertIsNone(report.error)
        self.assertEqual(report.os_version, "24.04")
        self.assertEqual(report.warnings, [])
        by_name = {p.upgrade.package: p for p in report.packages}
        self.assertEqual(
            list(by_name), ["libssl3t64", "openssl", "tzdata", "libxml2", "docker-ce"]
        )

        openssl = by_name["openssl"]
        self.assertEqual(openssl.source, "openssl")
        self.assertEqual(openssl.cves, ["CVE-2025-9231", "CVE-2025-9232"])
        self.assertEqual([e.version for e in openssl.entries], ["3.0.13-0ubuntu3.5"])
        self.assertTrue(openssl.changelog_available)
        self.assertFalse(openssl.changelog_uncertain)

        tzdata = by_name["tzdata"]
        self.assertEqual(tzdata.cves, [])
        self.assertEqual([e.version for e in tzdata.entries], ["2025b-0ubuntu0.24.04.1"])

        self.assertFalse(by_name["libxml2"].changelog_available)
        self.assertFalse(by_name["docker-ce"].changelog_available)

    def test_binaries_of_same_source_share_changelog(self):
        report = build_host_report("webserver-ansible", fixture("remote_output.txt"))
        by_name = {p.upgrade.package: p for p in report.packages}
        self.assertEqual(by_name["libssl3t64"].source, "openssl")
        self.assertEqual(by_name["libssl3t64"].cves, by_name["openssl"].cves)

    def test_error_report(self):
        report = build_host_report("pdf-ansible", "", error="ssh timeout nach 120s")
        self.assertEqual(report.error, "ssh timeout nach 120s")
        self.assertEqual(report.packages, [])

    def test_failed_apt_update_warns_but_keeps_packages(self):
        raw = (
            "===SECTION os===\n22.04\n"
            "===SECTION apt_update===\nrc=100\n"
            "E: Could not get lock /var/lib/apt/lists/lock\n"
            "===SECTION upgradable===\n"
            "tzdata/jammy-updates 2025b-0ubuntu0.22.04.1 all "
            "[upgradable from: 2025a-0ubuntu0.22.04]\n"
            "===SECTION sources===\ntzdata tzdata\n"
            "===END===\n"
        )
        report = build_host_report("git-ansible", raw)
        self.assertEqual(
            report.warnings,
            [
                "apt-get update fehlgeschlagen (rc=100): "
                "E: Could not get lock /var/lib/apt/lists/lock – nutze vorhandenen Paket-Cache"
            ],
        )
        self.assertEqual(len(report.packages), 1)
        self.assertFalse(report.packages[0].changelog_available)

    def test_no_refresh_has_no_warning_and_missing_os_is_none(self):
        raw = "===SECTION upgradable===\n===SECTION sources===\n===END===\n"
        report = build_host_report("git-ansible", raw)
        self.assertEqual(report.warnings, [])
        self.assertIsNone(report.os_version)
        self.assertEqual(report.packages, [])

    def test_matches_changelog_on_installed_source_version(self):
        raw = (
            "===SECTION upgradable===\n"
            "grub-efi-amd64-signed/noble-security 1.203+2.12-1ubuntu7.4 amd64 "
            "[upgradable from: 1.202+2.12-1ubuntu7.3]\n"
            "===SECTION sources===\ngrub-efi-amd64-signed grub2-signed 1.202\n"
            "===SECTION changelog grub2-signed===\n"
            "grub2-signed (1.203) noble-security; urgency=medium\n\n  * Fix CVE-2025-0002.\n\n -- A <a@b>  date\n\n"
            "grub2-signed (1.202) noble; urgency=medium\n\n  * Fix CVE-2025-0001.\n\n -- A <a@b>  date\n"
            "===END===\n"
        )
        pkg = build_host_report("rootserver-ansible", raw).packages[0]
        self.assertFalse(pkg.changelog_uncertain)
        self.assertEqual(pkg.cves, ["CVE-2025-0002"])

    def test_unparsed_lines_are_collected(self):
        raw = "===SECTION upgradable===\nquatsch\n===END===\n"
        report = build_host_report("git-ansible", raw)
        self.assertEqual(report.unparsed, ["quatsch"])


if __name__ == "__main__":
    unittest.main()

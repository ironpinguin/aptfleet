from __future__ import annotations

import datetime
import unittest
from pathlib import Path

from parsing import (
    ChangelogEntry,
    InstalledPackage,
    Upgrade,
    build_host_report,
    extract_cves,
    format_age,
    new_changelog_entries,
    parse_changelog,
    parse_installed,
    parse_lists_age,
    parse_origins,
    parse_os,
    parse_sources,
    parse_upgradable,
    split_sections,
)

FIXTURES = Path(__file__).parent / "fixtures"


def local_time(epoch: int) -> str:
    return datetime.datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M")


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
                "installed",
                "kernel",
                "origins",
                "sources",
                "changelog openssl",
                "changelog tzdata",
                "changelog libxml2",
                "changelog docker-ce",
            ],
        )
        self.assertEqual(sections["os"], "24.04\nnoble")
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
        upgrades, unparsed = parse_upgradable("Listing... Done\nbroken line\n\n")
        self.assertEqual(upgrades, [])
        self.assertEqual(unparsed, ["broken line"])

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
        report = build_host_report("web1", fixture("remote_output.txt"))
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
        report = build_host_report("web1", fixture("remote_output.txt"))
        by_name = {p.upgrade.package: p for p in report.packages}
        self.assertEqual(by_name["libssl3t64"].source, "openssl")
        self.assertEqual(by_name["libssl3t64"].cves, by_name["openssl"].cves)

    def test_error_report(self):
        report = build_host_report("db1", "", error="ssh timeout after 120s")
        self.assertEqual(report.error, "ssh timeout after 120s")
        self.assertEqual(report.packages, [])

    def test_failed_apt_update_warns_but_keeps_packages(self):
        raw = (
            "===SECTION os===\n22.04\n"
            "===SECTION apt_update===\nrc=100\n"
            "E: Could not get lock /var/lib/apt/lists/lock\n"
            "===SECTION lists_age===\nnow 1763100000\nlists 1762900000\n"
            "===SECTION upgradable===\n"
            "tzdata/jammy-updates 2025b-0ubuntu0.22.04.1 all "
            "[upgradable from: 2025a-0ubuntu0.22.04]\n"
            "===SECTION sources===\ntzdata tzdata\n"
            "===END===\n"
        )
        report = build_host_report("mail1", raw)
        self.assertEqual(
            report.warnings,
            [
                "apt-get update failed (rc=100): "
                "E: Could not get lock /var/lib/apt/lists/lock – using existing package lists, "
                f"last updated {local_time(1762900000)} (2 days ago)"
            ],
        )
        self.assertEqual(len(report.packages), 1)
        self.assertFalse(report.packages[0].changelog_available)

    def test_skipped_apt_update_warns_with_lists_age(self):
        raw = (
            "===SECTION apt_update===\nrc=skipped\n"
            "===SECTION lists_age===\nnow 1763100000\nstamp 1763092800\nlists 1763000000\n"
            "===END===\n"
        )
        report = build_host_report("mail1", raw)
        self.assertEqual(report.lists_updated, 1763092800)
        self.assertEqual(report.lists_age, 7200)
        self.assertEqual(
            report.warnings,
            [
                f"Package lists not refreshed (--no-refresh), last updated {local_time(1763092800)}"
                " (2 h ago) – updates and security info may be outdated"
            ],
        )

    def test_skipped_apt_update_with_unknown_lists_age(self):
        raw = "===SECTION apt_update===\nrc=skipped\n===SECTION lists_age===\nnow 1763100000\n===END===\n"
        report = build_host_report("mail1", raw)
        self.assertIsNone(report.lists_age)
        self.assertEqual(
            report.warnings,
            [
                "Package lists not refreshed (--no-refresh), last updated unknown"
                " – updates and security info may be outdated"
            ],
        )

    def test_successful_apt_update_has_no_warning(self):
        raw = (
            "===SECTION apt_update===\nrc=0\n"
            "===SECTION lists_age===\nnow 1763100000\nstamp 1763100000\n===END===\n"
        )
        report = build_host_report("mail1", raw)
        self.assertEqual(report.warnings, [])
        self.assertEqual(report.lists_age, 0)

    def test_parse_lists_age(self):
        self.assertEqual(parse_lists_age("now 100\nstamp 40\nlists 70\n"), (70, 30))
        self.assertEqual(parse_lists_age("now 100\nlists 130\n"), (130, 0))
        self.assertEqual(parse_lists_age("now 100\npartial 90\nlists 20\n"), (90, 10))
        self.assertEqual(parse_lists_age("now 100\nstamp \n"), (None, None))
        self.assertEqual(parse_lists_age("stamp 40\n"), (None, None))
        self.assertEqual(parse_lists_age(""), (None, None))

    def test_format_age(self):
        self.assertEqual(format_age(59), "0 min ago")
        self.assertEqual(format_age(3599), "59 min ago")
        self.assertEqual(format_age(3600), "1 h ago")
        self.assertEqual(format_age(48 * 3600 - 1), "47 h ago")
        self.assertEqual(format_age(48 * 3600), "2 days ago")

    def test_no_refresh_has_no_warning_and_missing_os_is_none(self):
        raw = "===SECTION upgradable===\n===SECTION sources===\n===END===\n"
        report = build_host_report("mail1", raw)
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
        pkg = build_host_report("app1", raw).packages[0]
        self.assertFalse(pkg.changelog_uncertain)
        self.assertEqual(pkg.cves, ["CVE-2025-0002"])

    def test_unparsed_lines_are_collected(self):
        raw = "===SECTION upgradable===\ngarbage\n===END===\n"
        report = build_host_report("mail1", raw)
        self.assertEqual(report.unparsed, ["garbage"])


class NewSectionsTest(unittest.TestCase):
    def test_parse_installed(self):
        text = ("ii  openssl 3.0.13-0ubuntu3.4 openssl 3.0.13-0ubuntu3.4\n"
                "ii  libfoo 1.0-1\n"
                "rc  gone 1.0 gone 1.0\n")
        self.assertEqual(parse_installed(text), [
            InstalledPackage("openssl", "3.0.13-0ubuntu3.4", "openssl", "3.0.13-0ubuntu3.4"),
            InstalledPackage("libfoo", "1.0-1", "libfoo", "1.0-1"),
        ])

    def test_parse_installed_dedupes_multiarch(self):
        line = "ii  libc6 2.39-0ubuntu8 glibc 2.39-0ubuntu8\n"
        self.assertEqual(len(parse_installed(line * 2)), 1)

    def test_parse_os(self):
        self.assertEqual(parse_os("24.04\nnoble"), ("24.04", "noble"))
        self.assertEqual(parse_os("24.04"), ("24.04", None))

    def test_parse_origins(self):
        self.assertEqual(
            parse_origins("openssl 1.0\n\nfoo 2\n"), ({("openssl", "1.0"), ("foo", "2")}, set())
        )

    def test_parse_origins_name_wildcard(self):
        self.assertEqual(parse_origins("openssl 1.0\nlibperl5.38t64 *\n"), ({("openssl", "1.0")}, {"libperl5.38t64"}))

    def test_is_ubuntu_package(self):
        report = build_host_report(
            "h",
            "===SECTION os===\n24.04\nnoble\n===SECTION installed===\n"
            "ii  a 1 a 1\nii  b 0.6 b 0.6\nii  c 1 c 1\n"
            "===SECTION origins===\na 1\nb *\n===END===",
        )
        self.assertEqual(report.ubuntu_names, {"b"})
        self.assertEqual(
            [p.binary for p in report.installed if report.is_ubuntu_package(p)], ["a", "b"]
        )

    def test_build_host_report_new_fields(self):
        report = build_host_report("w", fixture("remote_output.txt"))
        self.assertEqual((report.os_version, report.codename), ("24.04", "noble"))
        self.assertEqual(report.kernel_release, "6.8.0-45-generic")
        self.assertIn(("openssl", "3.0.13-0ubuntu3.4"), report.ubuntu_origin)
        self.assertNotIn("docker-ce", {name for name, _ in report.ubuntu_origin})
        self.assertIsNone(report.vuln_check_problem)
        self.assertEqual(report.open_vulns, [])

    def test_vuln_check_problems(self):
        base = "===SECTION os===\n24.04\nnoble\n===SECTION installed===\nii  a 1 a 1\n"
        self.assertEqual(build_host_report("h", "===SECTION os===\n24.04\n===END===").vuln_check_problem, "no Ubuntu codename")
        self.assertEqual(build_host_report("h", "===SECTION os===\n24.04\nnoble\n===END===").vuln_check_problem, "no package list")
        self.assertEqual(build_host_report("h", base + "===END===").vuln_check_problem, "package origin could not be determined")
        self.assertEqual(build_host_report("h", base + "===SECTION origins===\na 1\n===END===").vuln_check_problem, None)
        self.assertEqual(build_host_report("h", base + "===SECTION origins===\na *\n===END===").vuln_check_problem, None)

    def test_running_kernel_without_installed_image_is_a_problem(self):
        base = "===SECTION os===\n24.04\nnoble\n===SECTION installed===\nii  a 1 a 1\n"
        report = build_host_report(
            "h", base + "===SECTION kernel===\n6.8.0-40-generic\n===SECTION origins===\na 1\n===END==="
        )
        self.assertEqual(
            report.vuln_check_problem, "kernel check not possible: no package for 6.8.0-40-generic"
        )

    def test_running_kernel_image_found_without_ubuntu_origin(self):
        raw = (
            "===SECTION os===\n24.04\nnoble\n===SECTION installed===\nii  a 1 a 1\n"
            "ii  linux-image-unsigned-6.8.0-40-generic 6.8.0-40.40 linux 6.8.0-40.40\n"
            "===SECTION kernel===\n6.8.0-40-generic\n===SECTION origins===\na 1\n===END==="
        )
        self.assertIsNone(build_host_report("h", raw).vuln_check_problem)

    def test_other_problem_wins_over_missing_kernel_image(self):
        raw = "===SECTION os===\n24.04\nnoble\n===SECTION kernel===\n6.8.0-40-generic\n===END==="
        self.assertEqual(build_host_report("h", raw).vuln_check_problem, "no package list")

    def test_error_leaves_problem_none(self):
        self.assertIsNone(build_host_report("h", "", error="x").vuln_check_problem)


if __name__ == "__main__":
    unittest.main()

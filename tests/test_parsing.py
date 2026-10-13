from __future__ import annotations

import unittest
from pathlib import Path

from parsing import Upgrade, parse_sources, parse_upgradable, split_sections

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


if __name__ == "__main__":
    unittest.main()

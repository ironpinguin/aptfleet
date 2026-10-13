from __future__ import annotations

import json
import tempfile
import unittest
import urllib.error
from pathlib import Path

from cve_info import (
    CACHE_TTL_SECONDS,
    CveInfo,
    lookup_cves,
    parse_cve_json,
    priority_rank,
)


class FakeFetch:
    def __init__(self, fail=()):
        self.calls: list[str] = []
        self.fail = set(fail)

    def __call__(self, cve_id: str) -> CveInfo:
        self.calls.append(cve_id)
        if cve_id in self.fail:
            raise urllib.error.URLError("offline")
        return CveInfo(cve_id, "high", f"Beschreibung {cve_id}")


class ParseCveJsonTest(unittest.TestCase):
    def test_collapses_description_to_one_line(self):
        info = parse_cve_json(
            "CVE-2024-3094",
            {"priority": "critical", "description": "\nMalicious code was\ndiscovered  in xz.\n"},
        )
        self.assertEqual(info, CveInfo("CVE-2024-3094", "critical", "Malicious code was discovered in xz."))

    def test_falls_back_to_ubuntu_description_and_truncates(self):
        info = parse_cve_json("CVE-1", {"priority": "", "description": "", "ubuntu_description": "x" * 300})
        self.assertIsNone(info.priority)
        self.assertEqual(len(info.description), 200)
        self.assertTrue(info.description.endswith("…"))


class PriorityRankTest(unittest.TestCase):
    def test_order(self):
        ranks = [priority_rank(p) for p in ["critical", "high", "medium", "low", "negligible"]]
        self.assertEqual(ranks, [0, 1, 2, 3, 4])
        self.assertEqual(priority_rank(None), 5)
        self.assertEqual(priority_rank("untriaged"), 5)


class LookupCvesTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.cache = Path(self._tmp.name) / "sub" / "cves.json"

    def tearDown(self):
        self._tmp.cleanup()

    def test_fetches_once_then_uses_cache(self):
        fetch = FakeFetch()
        infos, failed = lookup_cves(["CVE-1", "CVE-2", "CVE-1"], self.cache, fetch, now=1000.0)
        self.assertEqual(sorted(fetch.calls), ["CVE-1", "CVE-2"])
        self.assertEqual(failed, [])
        self.assertEqual(infos["CVE-1"].priority, "high")

        fetch2 = FakeFetch()
        infos2, _ = lookup_cves(["CVE-1"], self.cache, fetch2, now=1000.0 + 60)
        self.assertEqual(fetch2.calls, [])
        self.assertEqual(infos2["CVE-1"], CveInfo("CVE-1", "high", "Beschreibung CVE-1"))

    def test_refetches_after_ttl(self):
        lookup_cves(["CVE-1"], self.cache, FakeFetch(), now=1000.0)
        fetch = FakeFetch()
        lookup_cves(["CVE-1"], self.cache, fetch, now=1000.0 + CACHE_TTL_SECONDS + 1)
        self.assertEqual(fetch.calls, ["CVE-1"])

    def test_failures_are_reported_and_not_cached(self):
        infos, failed = lookup_cves(["CVE-1", "CVE-2"], self.cache, FakeFetch(fail={"CVE-2"}), now=1000.0)
        self.assertEqual(failed, ["CVE-2"])
        self.assertEqual(infos["CVE-2"], CveInfo("CVE-2", None, None))
        cached = json.loads(self.cache.read_text())
        self.assertIn("CVE-1", cached)
        self.assertNotIn("CVE-2", cached)

    def test_corrupt_cache_is_ignored(self):
        self.cache.parent.mkdir(parents=True)
        self.cache.write_text("{kaputt")
        infos, failed = lookup_cves(["CVE-1"], self.cache, FakeFetch(), now=1000.0)
        self.assertEqual(failed, [])
        self.assertEqual(infos["CVE-1"].priority, "high")
        self.assertIn("CVE-1", json.loads(self.cache.read_text()))

    def test_unwritable_cache_does_not_crash(self):
        blocker = Path(self._tmp.name) / "datei"
        blocker.write_text("kein verzeichnis")
        infos, failed = lookup_cves(["CVE-1"], blocker / "cves.json", FakeFetch(), now=1000.0)
        self.assertEqual(infos["CVE-1"].priority, "high")
        self.assertEqual(failed, [])

    def test_empty_input_does_nothing(self):
        fetch = FakeFetch()
        self.assertEqual(lookup_cves([], self.cache, fetch, now=1.0), ({}, []))
        self.assertEqual(fetch.calls, [])


if __name__ == "__main__":
    unittest.main()

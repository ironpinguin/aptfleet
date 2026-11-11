from __future__ import annotations

import bz2
import tempfile
import unittest
import urllib.error
from pathlib import Path

from oval import CACHE_TTL_SECONDS, load_oval, parse_oval

FIXTURES = Path(__file__).parent / "fixtures"
KERNEL_CVE = "CVE-2024-58238"
ESM_CVE = "CVE-2025-60020"
UNFIXED_HIGH_CVE = "CVE-2026-3886"


class ParseOvalTest(unittest.TestCase):
    def setUp(self):
        self.cves = parse_oval((FIXTURES / "oval_sample.xml").read_text().splitlines(True))

    def test_all_definitions_found(self):
        self.assertEqual(len(self.cves), 5)

    def test_fixed_package(self):
        c = self.cves["CVE-2024-6387"]
        self.assertEqual(c.priority, "high")
        self.assertEqual(c.packages, {"openssh": "1:9.6p1-3ubuntu13.3"})

    def test_unfixed_packages(self):
        self.assertEqual(
            self.cves["CVE-2002-2439"].packages,
            {"gcc-arm-none-eabi": None, "gcc-h8300-hms": None, "gcc-mingw-w64": None},
        )
        self.assertEqual(self.cves["CVE-2002-2439"].priority, "low")

    def test_unfixed_high_cve(self):
        c = self.cves[UNFIXED_HIGH_CVE]
        self.assertEqual(c.priority, "high")
        self.assertTrue(c.packages)
        self.assertTrue(all(v is None for v in c.packages.values()))

    def test_kernels(self):
        k = self.cves[KERNEL_CVE].kernels
        self.assertEqual(k["linux"], "6.8.0-50.51")
        self.assertIsNone(k["linux-hwe-6.11"])
        self.assertEqual(self.cves[KERNEL_CVE].packages, {})

    def test_esm_fix_version_kept(self):
        self.assertIn("esm", next(iter(self.cves[ESM_CVE].packages.values())))


class LoadOvalTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.blob = bz2.compress((FIXTURES / "oval_sample.xml").read_bytes())

    def test_fetches_parses_and_caches(self):
        calls = []
        fetch = lambda codename: calls.append(codename) or self.blob
        first = load_oval("noble", self.dir, fetch=fetch, now=0.0)
        second = load_oval("noble", self.dir, fetch=fetch, now=3600.0)
        self.assertEqual(calls, ["noble"])
        self.assertTrue((self.dir / "oval-noble.json").exists())
        self.assertEqual(second.cves["CVE-2024-6387"], first.cves["CVE-2024-6387"])
        self.assertEqual(second.cves[KERNEL_CVE], first.cves[KERNEL_CVE])
        self.assertFalse(second.stale)

    def test_stale_cache_on_failure(self):
        load_oval("noble", self.dir, fetch=lambda c: self.blob, now=0.0)

        def offline(c):
            raise urllib.error.URLError("offline")

        data = load_oval("noble", self.dir, fetch=offline, now=CACHE_TTL_SECONDS * 2)
        self.assertTrue(data.stale)
        self.assertIn("CVE-2024-6387", data.cves)

    def test_failure_without_cache(self):
        def offline(c):
            raise urllib.error.URLError("offline")

        self.assertIsNone(load_oval("noble", self.dir, fetch=offline, now=0.0))

    def test_corrupt_bz2_is_failure(self):
        self.assertIsNone(load_oval("noble", self.dir, fetch=lambda c: b"nope", now=0.0))
        self.assertFalse((self.dir / "oval-noble.json").exists())

    def test_empty_feed_is_failure(self):
        blob = bz2.compress(b"<oval_definitions></oval_definitions>")
        self.assertIsNone(load_oval("noble", self.dir, fetch=lambda c: blob, now=0.0))

    def test_rejects_invalid_codename(self):
        calls = []
        for bad in ["", "noble/../x", "Noble", "24.04"]:
            self.assertIsNone(
                load_oval(bad, self.dir, fetch=lambda c: calls.append(c) or self.blob, now=0.0)
            )
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()

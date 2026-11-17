from __future__ import annotations

import datetime
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path

from kev import (
    CACHE_TTL_SECONDS,
    KevData,
    KevEntry,
    load_kev,
    parse_kev_json,
    recent_entries,
)

FIXTURE = Path(__file__).parent / "fixtures" / "kev_sample.json"


class KevTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.cache = Path(tmp.name) / "kev.json"
        self.sample = json.loads(FIXTURE.read_text())

    def test_parse(self):
        entries = parse_kev_json(self.sample)
        self.assertEqual(sorted(entries), ["CVE-2021-44228", "CVE-2024-6387", "CVE-2026-5020"])
        self.assertEqual(entries["CVE-2024-6387"].vendor, "OpenBSD")
        self.assertEqual(entries["CVE-2024-6387"].date_added, "2026-11-09")

    def test_parse_rejects_wrong_format(self):
        with self.assertRaises(ValueError):
            parse_kev_json({"foo": 1})

    def test_fetches_and_caches(self):
        calls = []
        fetch = lambda: calls.append(1) or self.sample
        first = load_kev(self.cache, fetch=fetch, now=1000.0)
        second = load_kev(self.cache, fetch=fetch, now=1000.0 + 3600)
        self.assertEqual(len(calls), 1)
        self.assertFalse(first.stale)
        self.assertEqual(sorted(second.entries), sorted(first.entries))

    def test_refetches_after_ttl(self):
        calls = []
        fetch = lambda: calls.append(1) or self.sample
        load_kev(self.cache, fetch=fetch, now=0.0)
        load_kev(self.cache, fetch=fetch, now=CACHE_TTL_SECONDS + 1)
        self.assertEqual(len(calls), 2)

    def test_failed_fetch_uses_stale_cache(self):
        load_kev(self.cache, fetch=lambda: self.sample, now=0.0)

        def offline():
            raise urllib.error.URLError("offline")

        kev = load_kev(self.cache, fetch=offline, now=CACHE_TTL_SECONDS * 3)
        self.assertTrue(kev.stale)
        self.assertEqual(kev.fetched_at, 0.0)
        self.assertIn("CVE-2024-6387", kev.entries)

    def test_failed_fetch_without_cache_returns_none(self):
        def offline():
            raise urllib.error.URLError("offline")

        self.assertIsNone(load_kev(self.cache, fetch=offline, now=0.0))

    def test_wrong_format_counts_as_failure_and_is_not_cached(self):
        self.assertIsNone(load_kev(self.cache, fetch=lambda: {"foo": 1}, now=0.0))
        self.assertFalse(self.cache.exists())

    def test_empty_list_counts_as_failure_and_is_not_cached(self):
        for feed in ({"vulnerabilities": []}, {"vulnerabilities": [{"cveID": ""}, "x"]}):
            self.assertIsNone(load_kev(self.cache, fetch=lambda feed=feed: feed, now=0.0))
        self.assertFalse(self.cache.exists())

    def test_empty_list_falls_back_to_stale_cache(self):
        load_kev(self.cache, fetch=lambda: self.sample, now=0.0)
        kev = load_kev(self.cache, fetch=lambda: {"vulnerabilities": []}, now=CACHE_TTL_SECONDS * 2)
        self.assertTrue(kev.stale)
        self.assertIn("CVE-2024-6387", kev.entries)

    def test_corrupt_cache_is_ignored(self):
        self.cache.write_text("{broken")
        kev = load_kev(self.cache, fetch=lambda: self.sample, now=0.0)
        self.assertFalse(kev.stale)

    def test_recent_entries(self):
        kev = KevData(parse_kev_json(self.sample), 0.0, False)
        recent = recent_entries(kev, 7, datetime.date(2026, 11, 11))
        self.assertEqual([e.cve_id for e in recent], ["CVE-2024-6387", "CVE-2026-5020"])
        self.assertEqual(recent_entries(kev, 1, datetime.date(2026, 11, 11)), [])

    def test_recent_entries_covers_exactly_n_calendar_days(self):
        def entry(cve_id, date):
            return KevEntry(cve_id, "v", "p", "n", date)

        kev = KevData(
            {e.cve_id: e for e in [entry("CVE-1", "2026-11-04"), entry("CVE-2", "2026-11-05"),
                                   entry("CVE-3", "2026-11-11"), entry("CVE-4", "2026-11-10")]},
            0.0,
            False,
        )
        today = datetime.date(2026, 11, 11)
        self.assertEqual([e.cve_id for e in recent_entries(kev, 7, today)], ["CVE-3", "CVE-4", "CVE-2"])
        self.assertEqual([e.cve_id for e in recent_entries(kev, 1, today)], ["CVE-3"])


if __name__ == "__main__":
    unittest.main()

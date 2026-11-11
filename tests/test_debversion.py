from __future__ import annotations

import unittest

from debversion import compare_versions


class CompareVersionsTest(unittest.TestCase):
    def test_cases(self):
        cases = [
            ("1.0", "1.0", 0),
            ("1:1.0", "2.0", 1),                         # Epoch schlägt alles
            ("1.0~rc1", "1.0", -1),                      # ~ sortiert vor leer
            ("1.0", "1.0+esm1", -1),                     # + nach leer
            ("1:9.6p1-3ubuntu13.5", "1:9.6p1-3ubuntu13.3", 1),
            ("3.0.13-0ubuntu3.4", "3.0.13-0ubuntu3.10", -1),  # numerisch, nicht lexikalisch
            ("2.9.14+dfsg-1.3ubuntu3.1", "2.9.14+dfsg-1.3ubuntu3.1+esm1", -1),
            ("6.8.0-45.45", "6.8.0-50.51", -1),
            ("1.0-1", "1.0", 1),                         # Revision vorhanden > fehlend ("0")
            ("1.0a", "1.0", 1),
            ("1.0", "1.0.0", -1),
        ]
        for a, b, expected in cases:
            with self.subTest(a=a, b=b):
                self.assertEqual(compare_versions(a, b), expected)
                self.assertEqual(compare_versions(b, a), -expected)


if __name__ == "__main__":
    unittest.main()

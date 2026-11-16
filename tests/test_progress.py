from __future__ import annotations

import io
import unittest

from progress import Progress


class FakeTty(io.StringIO):
    def isatty(self):
        return True


class ProgressTest(unittest.TestCase):
    def test_disabled_without_terminal_writes_nothing(self):
        stream = io.StringIO()
        progress = Progress(stream)
        self.assertFalse(progress.enabled)
        progress.hosts_start(2)
        progress.step("KEV laden")
        progress.host_phase("a", "apt-get update")
        progress.host_done("a")
        progress.close()
        self.assertEqual(stream.getvalue(), "")

    def test_enabled_on_terminal_unless_forced_off(self):
        self.assertTrue(Progress(FakeTty()).enabled)
        self.assertFalse(Progress(FakeTty(), enabled=False).enabled)

    def test_host_lifecycle(self):
        stream = FakeTty()
        times = iter([10.0, 22.4])
        progress = Progress(stream, clock=lambda: next(times))
        progress.hosts_start(2)
        progress.host_phase("web", "apt-get update")
        progress.host_phase("web", "Changelog 1/3: openssl")
        progress.host_done("web")
        progress.host_done("db", "ssh timeout nach 120s")
        progress.close()
        out = stream.getvalue()
        self.assertIn("» 2 Host(s) prüfen", out)
        self.assertIn("[0/2] web: apt-get update", out)
        self.assertIn("[0/2] web: Changelog 1/3: openssl", out)
        self.assertIn("✓ [1/2] web fertig (12s)", out)
        self.assertIn("✗ [2/2] db: ssh timeout nach 120s", out)
        self.assertTrue(out.endswith("\n"))

    def test_status_line_is_cleared_before_permanent_lines(self):
        stream = FakeTty()
        progress = Progress(stream)
        progress.hosts_start(1)
        progress.host_phase("web", "verbunden")
        progress.step("KEV laden")
        self.assertIn("web: verbunden\r\033[K» KEV laden\n", stream.getvalue())
        progress.close()
        self.assertTrue(stream.getvalue().endswith("\r\033[K"))


if __name__ == "__main__":
    unittest.main()

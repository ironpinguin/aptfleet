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
        progress.step("Loading KEV")
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
        progress.host_done("db", "ssh timeout after 120s")
        progress.close()
        out = stream.getvalue()
        self.assertIn("» Checking 2 host(s)", out)
        self.assertIn("[0/2] web: apt-get update", out)
        self.assertIn("[0/2] web: Changelog 1/3: openssl", out)
        self.assertIn("✓ [1/2] web done (12s)", out)
        self.assertIn("✗ [2/2] db: ssh timeout after 120s", out)
        self.assertTrue(out.endswith("\n"))

    def test_status_line_is_cleared_before_permanent_lines(self):
        stream = FakeTty()
        progress = Progress(stream)
        progress.hosts_start(1)
        progress.host_phase("web", "connected")
        progress.step("Loading KEV")
        self.assertIn("web: connected\r\033[K» Loading KEV\n", stream.getvalue())
        progress.close()
        self.assertTrue(stream.getvalue().endswith("\r\033[K"))


if __name__ == "__main__":
    unittest.main()

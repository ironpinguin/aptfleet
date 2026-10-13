from __future__ import annotations

import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from check_updates import SSH_CONFIG, exit_code, main, read_inventory, select_hosts
from cve_info import CveInfo
from parsing import HostReport, PackageReport, Upgrade
from remote import HostResult

FIXTURES = Path(__file__).parent / "fixtures"
SCRIPT = Path(__file__).resolve().parents[1] / "check_updates.py"
INVENTORY_TEXT = "[ubuntu]\nrootserver-ansible\n#vpn-ansible\n\nwebserver-ansible\npdf-ansible\n"


def pkg(security: bool) -> PackageReport:
    pocket = "noble-security" if security else "noble-updates"
    return PackageReport(Upgrade("p", [pocket], "2", "1", "amd64"), "p", [], [], True, False)


class InventoryTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.inventory = Path(self._tmp.name) / "virtualhosts"
        self.inventory.write_text(INVENTORY_TEXT)

    def tearDown(self):
        self._tmp.cleanup()

    def test_read_inventory_skips_comments_and_groups(self):
        self.assertEqual(
            read_inventory(self.inventory),
            ["rootserver-ansible", "webserver-ansible", "pdf-ansible"],
        )

    def test_select_hosts_keeps_inventory_order(self):
        inventory = read_inventory(self.inventory)
        self.assertEqual(select_hosts(inventory, []), inventory)
        self.assertEqual(
            select_hosts(inventory, ["pdf-ansible", "rootserver-ansible"]),
            ["rootserver-ansible", "pdf-ansible"],
        )

    def test_select_unknown_host_raises(self):
        with self.assertRaisesRegex(ValueError, "vpn-ansible"):
            select_hosts(read_inventory(self.inventory), ["vpn-ansible"])


class ExitCodeTest(unittest.TestCase):
    def test_codes(self):
        self.assertEqual(exit_code([HostReport("a", packages=[pkg(False)])]), 0)
        self.assertEqual(exit_code([HostReport("a", packages=[pkg(True)])]), 1)
        self.assertEqual(
            exit_code([HostReport("a", packages=[pkg(True)]), HostReport("b", error="x")]), 2
        )


class MainTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.inventory = Path(self._tmp.name) / "virtualhosts"
        self.inventory.write_text(INVENTORY_TEXT)
        self.run_calls = []
        self.lookup_calls = []

    def tearDown(self):
        self._tmp.cleanup()

    def fake_run_all(self, hosts, ssh_config, refresh, packages, timeout):
        self.run_calls.append((hosts, ssh_config, refresh, packages, timeout))
        raw = (FIXTURES / "remote_output.txt").read_text()
        return [
            HostResult(h, False, "ssh timeout nach 120s", "") if h == "pdf-ansible" else HostResult(h, True, None, raw)
            for h in hosts
        ]

    def fake_lookup(self, cve_ids):
        self.lookup_calls.append(set(cve_ids))
        return {"CVE-2025-9232": CveInfo("CVE-2025-9232", "high", "x")}, ["CVE-2025-9231"]

    def run_main(self, *argv):
        out = io.StringIO()
        code = main(
            list(argv),
            inventory=self.inventory,
            run_all=self.fake_run_all,
            lookup=self.fake_lookup,
            stdout=out,
        )
        return code, out.getvalue()

    def test_full_run(self):
        code, out = self.run_main()
        self.assertEqual(code, 2)
        hosts, ssh_config, refresh, packages, timeout = self.run_calls[0]
        self.assertEqual(hosts, ["rootserver-ansible", "webserver-ansible", "pdf-ansible"])
        self.assertEqual(ssh_config, SSH_CONFIG)
        self.assertTrue(refresh)
        self.assertEqual(packages, [])
        self.assertEqual(timeout, 120)
        self.assertEqual(self.lookup_calls, [{"CVE-2025-9231", "CVE-2025-9232"}])
        self.assertIn("━━ pdf-ansible — FEHLER: ssh timeout nach 120s ━━", out)
        self.assertIn("CVE-2025-9231, CVE-2025-9232 (high)", out)
        self.assertIn("Hinweis: CVE-Prioritäten teilweise nicht abrufbar", out)
        self.assertNotIn("\033[", out)

    def test_options_are_passed_through(self):
        code, _ = self.run_main(
            "--host", "webserver-ansible", "--no-refresh", "--package", "openssl", "--timeout", "30"
        )
        self.assertEqual(code, 1)
        hosts, _, refresh, packages, timeout = self.run_calls[0]
        self.assertEqual((hosts, refresh, packages, timeout), (["webserver-ansible"], False, ["openssl"], 30))

    def test_unknown_host_returns_2_without_ssh(self):
        code, _ = self.run_main("--host", "gibtsnicht")
        self.assertEqual(code, 2)
        self.assertEqual(self.run_calls, [])

    def test_no_cves_skips_lookup(self):
        def run_all(hosts, *args):
            return [HostResult(h, True, None, "===SECTION upgradable===\n===END===\n") for h in hosts]

        code = main([], inventory=self.inventory, run_all=run_all, lookup=self.fake_lookup, stdout=io.StringIO())
        self.assertEqual(code, 0)
        self.assertEqual(self.lookup_calls, [])


class CliSmokeTest(unittest.TestCase):
    def test_help_runs_as_script(self):
        proc = subprocess.run([sys.executable, str(SCRIPT), "--help"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("--security-only", proc.stdout)


if __name__ == "__main__":
    unittest.main()

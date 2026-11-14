from __future__ import annotations

import contextlib
import datetime
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from check_updates import (
    SSH_CONFIG,
    exit_code,
    main,
    read_inventory,
    resolve_ssh_config,
    select_hosts,
)
from cve_info import CveInfo
from kev import KevData, KevEntry
from oval import OvalCve, OvalData
from parsing import HostReport, OpenVuln, PackageReport, Upgrade
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

    def test_codes_with_vulns_and_incomplete(self):
        kev_vuln = OpenVuln("x", ["x"], "1", "CVE-1", "high", "kein Fix", True)
        plain_vuln = OpenVuln("x", ["x"], "1", "CVE-2", "high", "kein Fix", False)
        self.assertEqual(exit_code([HostReport("a", open_vulns=[kev_vuln])]), 1)
        self.assertEqual(exit_code([HostReport("a", open_vulns=[plain_vuln])]), 0)
        self.assertEqual(exit_code([HostReport("a", packages=[pkg(True)])], incomplete=True), 3)
        self.assertEqual(exit_code([HostReport("a", vuln_check_problem="x")]), 3)
        self.assertEqual(exit_code([HostReport("a"), HostReport("b", error="x")], incomplete=True), 2)


TODAY = datetime.date(2026, 11, 11)
_UNSET = object()


def default_kev() -> KevData:
    return KevData(
        {
            "CVE-2025-9232": KevEntry("CVE-2025-9232", "OpenSSL", "OpenSSL", "x", "2026-11-10"),
            "CVE-2025-7000": KevEntry("CVE-2025-7000", "GNOME", "libxml2", "y", "2026-11-09"),
        },
        0.0,
        False,
    )


def default_oval() -> OvalData:
    # libxml2 (installed, Ubuntu-Herkunft) ohne Fix; nicht in einem Changelog der Updates.
    return OvalData({"CVE-2025-7000": OvalCve("CVE-2025-7000", "high", {"libxml2": None}, {})}, 0.0, False)


class MainTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.inventory = Path(self._tmp.name) / "virtualhosts"
        self.inventory.write_text(INVENTORY_TEXT)
        self.run_calls = []
        self.lookup_calls = []
        self.users = []
        self.oval_calls = []

    def tearDown(self):
        self._tmp.cleanup()

    def fake_run_all(self, hosts, ssh_config, refresh, packages, timeout, user=None):
        self.run_calls.append((hosts, ssh_config, refresh, packages, timeout))
        self.users.append(user)
        raw = (FIXTURES / "remote_output.txt").read_text()
        return [
            HostResult(h, False, "ssh timeout nach 120s", "") if h == "pdf-ansible" else HostResult(h, True, None, raw)
            for h in hosts
        ]

    def fake_lookup(self, cve_ids):
        self.lookup_calls.append(set(cve_ids))
        return {"CVE-2025-9232": CveInfo("CVE-2025-9232", "high", "x")}, ["CVE-2025-9231"]

    def run_main(self, *argv, kev=_UNSET, oval=_UNSET):
        kev_data = default_kev() if kev is _UNSET else kev
        oval_data = default_oval() if oval is _UNSET else oval

        def oval_loader(codename):
            self.oval_calls.append(codename)
            return oval_data

        out = io.StringIO()
        code = main(
            list(argv),
            inventory=self.inventory,
            run_all=self.fake_run_all,
            lookup=self.fake_lookup,
            kev_loader=lambda: kev_data,
            oval_loader=oval_loader,
            today=TODAY,
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
        self.assertIn("CVE-2025-9231, CVE-2025-9232 (high, KEV)", out)
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

    def test_user_mode_uses_hosts_directly_without_inventory(self):
        self.inventory = Path(self._tmp.name) / "gibtsnicht"
        code, _ = self.run_main("--user", "admin", "--host", "10.0.0.5", "--host", "web.example.org")
        self.assertEqual(code, 1)
        hosts, ssh_config, *_ = self.run_calls[0]
        self.assertEqual(hosts, ["10.0.0.5", "web.example.org"])
        self.assertIsNone(ssh_config)
        self.assertEqual(self.users, ["admin"])

    def test_user_mode_requires_host(self):
        code, _ = self.run_main("--user", "admin")
        self.assertEqual(code, 2)
        self.assertEqual(self.run_calls, [])

    def test_inventory_mode_passes_no_user(self):
        self.run_main("--host", "webserver-ansible")
        self.assertEqual(self.users, [None])

    def test_inventory_option_overrides_default(self):
        other = Path(self._tmp.name) / "hosts.ini"
        other.write_text("[ubuntu]\nhost-a\nhost-b\n")
        self.inventory = Path(self._tmp.name) / "gibtsnicht"
        self.run_main("--inventory", str(other))
        hosts, *_ = self.run_calls[0]
        self.assertEqual(hosts, ["host-a", "host-b"])

    def test_ssh_config_option_is_passed(self):
        self.run_main("--host", "webserver-ansible", "--ssh-config", "/etc/my_ssh.conf")
        _, ssh_config, *_ = self.run_calls[0]
        self.assertEqual(ssh_config, Path("/etc/my_ssh.conf"))

    def test_user_mode_accepts_ssh_config(self):
        self.run_main("--user", "admin", "--host", "10.0.0.5", "--ssh-config", "/etc/my_ssh.conf")
        _, ssh_config, *_ = self.run_calls[0]
        self.assertEqual(ssh_config, Path("/etc/my_ssh.conf"))

    def test_resolve_ssh_config(self):
        existing = Path(self._tmp.name) / "ssh.conf"
        existing.write_text("")
        missing = Path(self._tmp.name) / "fehlt.conf"
        self.assertEqual(resolve_ssh_config(None, existing), existing)
        self.assertIsNone(resolve_ssh_config(None, missing))
        self.assertEqual(resolve_ssh_config(missing, existing), missing)

    def test_missing_inventory_returns_2(self):
        self.inventory = Path(self._tmp.name) / "gibtsnicht"
        code, _ = self.run_main()
        self.assertEqual(code, 2)
        self.assertEqual(self.run_calls, [])

    def test_no_cves_skips_lookup(self):
        def run_all(hosts, *args, **kwargs):
            return [HostResult(h, True, None, "===SECTION upgradable===\n===END===\n") for h in hosts]

        code = main(
            [],
            inventory=self.inventory,
            run_all=run_all,
            lookup=self.fake_lookup,
            kev_loader=default_kev,
            oval_loader=lambda codename: default_oval(),
            stdout=io.StringIO(),
        )
        # Host-Ausgabe ohne `installed`/Codename: Lücken-Prüfung unmöglich => unvollständig (3).
        self.assertEqual(code, 3)
        self.assertEqual(self.lookup_calls, [])

    def test_full_run_marks_kev_and_lists_open_vulns(self):
        code, out = self.run_main("--host", "webserver-ansible")
        self.assertEqual(code, 1)
        self.assertIn("(high, KEV)", out)
        self.assertIn("Offene Lücken ohne Fix:", out)

    def test_kev_unavailable_gives_3(self):
        code, out = self.run_main("--host", "webserver-ansible", kev=None)
        self.assertEqual(code, 3)
        self.assertIn("Hinweis: KEV-Liste nicht abrufbar", out)

    def test_stale_kev_notice_keeps_exit_code(self):
        stale = default_kev()
        stale.stale = True
        stale.fetched_at = datetime.datetime(2026, 11, 1, 12).timestamp()
        code, out = self.run_main("--host", "webserver-ansible", kev=stale)
        self.assertEqual(code, 1)
        self.assertIn("Hinweis: KEV-Stand vom 2026-11-01", out)

    def test_oval_unavailable_gives_3(self):
        code, out = self.run_main("--host", "webserver-ansible", oval=None)
        self.assertEqual(code, 3)
        self.assertIn(
            "Lücken-Prüfung nicht möglich: Ubuntu-Schwachstellendaten (noble) nicht abrufbar", out
        )

    def test_oval_unavailable_notice_once_per_codename(self):
        code, out = self.run_main("--host", "rootserver-ansible", "--host", "webserver-ansible", oval=None)
        self.assertEqual(code, 3)
        notice = (
            "Ubuntu-Schwachstellendaten (noble) nicht abrufbar – Lücken-Prüfung für betroffene Hosts entfällt"
        )
        self.assertEqual(out.count(notice), 1)
        self.assertEqual(out.count("Lücken-Prüfung nicht möglich: Ubuntu-Schwachstellendaten (noble)"), 2)

    def test_kev_recent_rejects_values_below_one(self):
        for bad in ("0", "-3"):
            with self.assertRaises(SystemExit) as ctx, contextlib.redirect_stderr(io.StringIO()):
                self.run_main("--kev-recent", bad)
            self.assertEqual(ctx.exception.code, 2)
        self.assertEqual(self.run_calls, [])

    def test_kev_recent_one_day_heading(self):
        _, out = self.run_main("--host", "webserver-ansible", "--kev-recent", "1")
        self.assertIn("Neu auf CISA KEV (letzter Tag):", out)

    def test_verbose_skips_superseded_ubuntu_packages(self):
        raw = (FIXTURES / "remote_output.txt").read_text().replace(
            "libc6 2.39-0ubuntu8.3\n", "libc6 *\n"
        )
        self.assertIn("libc6 *", raw)
        self.fake_run_all = lambda hosts, *a, **k: [HostResult(h, True, None, raw) for h in hosts]
        _, out = self.run_main("--host", "webserver-ansible", "--verbose")
        self.assertIn("1 Pakete ohne Ubuntu-Herkunft nicht geprüft (docker-ce)", out)

    def test_oval_loaded_once_per_codename(self):
        self.run_main()  # zwei erreichbare noble-Hosts
        self.assertEqual(self.oval_calls, ["noble"])

    def test_unreachable_host_not_passed_to_oval(self):
        self.run_main("--host", "pdf-ansible")
        self.assertEqual(self.oval_calls, [])

    def test_kev_recent_flag(self):
        _, out = self.run_main("--host", "webserver-ansible", "--kev-recent")
        self.assertIn("Neu auf CISA KEV (letzte 7 Tage):", out)
        _, out = self.run_main("--host", "webserver-ansible", "--kev-recent", "30")
        self.assertIn("(letzte 30 Tage)", out)
        _, out = self.run_main("--host", "webserver-ansible")
        self.assertNotIn("Neu auf CISA KEV", out)

    def test_package_filter_limits_open_vulns(self):
        _, out = self.run_main("--host", "webserver-ansible", "--package", "tzdata")
        self.assertNotIn("Offene Lücken ohne Fix:", out)

    def test_verbose_lists_unchecked_foreign_packages(self):
        _, out = self.run_main("--host", "webserver-ansible", "--verbose")
        self.assertIn("1 Pakete ohne Ubuntu-Herkunft nicht geprüft (docker-ce)", out)


class CliSmokeTest(unittest.TestCase):
    def test_help_runs_as_script(self):
        proc = subprocess.run([sys.executable, str(SCRIPT), "--help"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("--security-only", proc.stdout)
        self.assertIn("--kev-recent", proc.stdout)
        self.assertIn("3 = Prüfung unvollständig", " ".join(proc.stdout.split()))


if __name__ == "__main__":
    unittest.main()

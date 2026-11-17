from __future__ import annotations

import contextlib
import datetime
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from aptfleet import (
    SSH_CONFIG,
    default_path,
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
from progress import Progress
from remote import HostResult

FIXTURES = Path(__file__).parent / "fixtures"
SCRIPT = Path(__file__).resolve().parents[1] / "aptfleet.py"
INVENTORY_TEXT = "[ubuntu]\napp1\n#vpn1\n\nweb1\ndb1\n"


def pkg(security: bool) -> PackageReport:
    pocket = "noble-security" if security else "noble-updates"
    return PackageReport(Upgrade("p", [pocket], "2", "1", "amd64"), "p", [], [], True, False)


class InventoryTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.inventory = Path(self._tmp.name) / "inventory.ini"
        self.inventory.write_text(INVENTORY_TEXT)

    def tearDown(self):
        self._tmp.cleanup()

    def test_read_inventory_skips_comments_and_groups(self):
        self.assertEqual(
            read_inventory(self.inventory),
            ["app1", "web1", "db1"],
        )

    def test_read_inventory_skips_vars_and_children_sections(self):
        self.inventory.write_text(
            "ansible_user=admin\n"
            "[ubuntu]\nhost-a\nhost-b  # comment\n"
            "[all:vars]\nansible_user=admin\nansible_python_interpreter = /usr/bin/python3\n"
            "[db]\ndb-1 ansible_host=10.0.0.20\n"
            "[server:children]\nubuntu\ndb\n"
            "[ ubuntu:vars ]\nfoo=bar\n"
            "[web]\nweb-1\n"
        )
        self.assertEqual(read_inventory(self.inventory), ["host-a", "host-b", "db-1", "web-1"])

    def test_read_inventory_drops_duplicates_keeping_first_position(self):
        self.inventory.write_text("[web]\nhost-a\nhost-b\n[db]\nhost-c\nhost-a ansible_port=22\n")
        self.assertEqual(read_inventory(self.inventory), ["host-a", "host-b", "host-c"])

    def test_select_hosts_keeps_inventory_order(self):
        inventory = read_inventory(self.inventory)
        self.assertEqual(select_hosts(inventory, []), inventory)
        self.assertEqual(
            select_hosts(inventory, ["db1", "app1"]),
            ["app1", "db1"],
        )

    def test_select_unknown_host_raises(self):
        with self.assertRaisesRegex(ValueError, "vpn1"):
            select_hosts(read_inventory(self.inventory), ["vpn1"])


class ExitCodeTest(unittest.TestCase):
    def test_codes(self):
        self.assertEqual(exit_code([HostReport("a", packages=[pkg(False)])]), 0)
        self.assertEqual(exit_code([HostReport("a", packages=[pkg(True)])]), 1)
        self.assertEqual(
            exit_code([HostReport("a", packages=[pkg(True)]), HostReport("b", error="x")]), 2
        )

    def test_codes_with_vulns_and_incomplete(self):
        kev_vuln = OpenVuln("x", ["x"], "1", "CVE-1", "high", "no fix", True)
        plain_vuln = OpenVuln("x", ["x"], "1", "CVE-2", "high", "no fix", False)
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
    # libxml2 (installed, Ubuntu origin) without fix; not in any changelog of the updates.
    return OvalData({"CVE-2025-7000": OvalCve("CVE-2025-7000", "high", {"libxml2": None}, {})}, 0.0, False)


class MainTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.inventory = Path(self._tmp.name) / "inventory.ini"
        self.inventory.write_text(INVENTORY_TEXT)
        self.run_calls = []
        self.lookup_calls = []
        self.users = []
        self.oval_calls = []
        self.progress_args = []
        self.locals = []

    def tearDown(self):
        self._tmp.cleanup()

    def fake_run_all(self, hosts, ssh_config, refresh, packages, timeout, user=None,
                     progress=None, local=False):
        self.progress_args.append(progress)
        self.locals.append(local)
        self.run_calls.append((hosts, ssh_config, refresh, packages, timeout))
        self.users.append(user)
        raw = (FIXTURES / "remote_output.txt").read_text()
        return [
            HostResult(h, False, "ssh timeout after 120s", "") if h == "db1" else HostResult(h, True, None, raw)
            for h in hosts
        ]

    def fake_lookup(self, cve_ids):
        self.lookup_calls.append(set(cve_ids))
        return {"CVE-2025-9232": CveInfo("CVE-2025-9232", "high", "x")}, ["CVE-2025-9231"]

    def run_main(self, *argv, kev=_UNSET, oval=_UNSET, progress=None):
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
            progress=progress,
        )
        return code, out.getvalue()

    def test_full_run(self):
        code, out = self.run_main()
        self.assertEqual(code, 2)
        hosts, ssh_config, refresh, packages, timeout = self.run_calls[0]
        self.assertEqual(hosts, ["app1", "web1", "db1"])
        self.assertEqual(ssh_config, resolve_ssh_config(None))
        self.assertTrue(refresh)
        self.assertEqual(packages, [])
        self.assertEqual(timeout, 120)
        self.assertEqual(self.lookup_calls, [{"CVE-2025-9231", "CVE-2025-9232"}])
        self.assertIn("━━ db1 — ERROR: ssh timeout after 120s ━━", out)
        self.assertIn("CVE-2025-9231, CVE-2025-9232 (high, KEV)", out)
        self.assertIn("Note: Some CVE priorities unavailable", out)
        self.assertNotIn("\033[", out)

    def test_options_are_passed_through(self):
        code, _ = self.run_main(
            "--host", "web1", "--no-refresh", "--package", "openssl", "--timeout", "30"
        )
        self.assertEqual(code, 1)
        hosts, _, refresh, packages, timeout = self.run_calls[0]
        self.assertEqual((hosts, refresh, packages, timeout), (["web1"], False, ["openssl"], 30))

    def test_local_checks_own_host_without_inventory(self):
        self.inventory = Path(self._tmp.name) / "doesnotexist"
        with mock.patch("aptfleet.socket.gethostname", return_value="myserver"):
            code, out = self.run_main("--local", "--no-refresh")
        self.assertEqual(code, 1)
        hosts, ssh_config, refresh, _, _ = self.run_calls[0]
        self.assertEqual((hosts, ssh_config, refresh), (["myserver"], None, False))
        self.assertEqual(self.locals, [True])
        self.assertEqual(self.users, [None])
        self.assertIn("myserver", out)

    def test_local_rejects_host_options(self):
        for extra in (["--host", "x"], ["--user", "u", "--host", "x"],
                      ["--inventory", "inv"], ["--ssh-config", "cfg"]):
            with self.subTest(extra=extra), mock.patch("sys.stderr", io.StringIO()) as err:
                code, _ = self.run_main("--local", *extra)
                self.assertEqual(code, 2)
                self.assertIn("--local cannot be combined", err.getvalue())
        self.assertEqual(self.run_calls, [])

    def test_ssh_modes_are_not_local(self):
        self.run_main()
        self.assertEqual(self.locals, [False])

    def test_unknown_host_returns_2_without_ssh(self):
        code, _ = self.run_main("--host", "doesnotexist")
        self.assertEqual(code, 2)
        self.assertEqual(self.run_calls, [])

    def test_user_mode_uses_hosts_directly_without_inventory(self):
        self.inventory = Path(self._tmp.name) / "doesnotexist"
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
        self.run_main("--host", "web1")
        self.assertEqual(self.users, [None])

    def test_inventory_option_overrides_default(self):
        other = Path(self._tmp.name) / "hosts.ini"
        other.write_text("[ubuntu]\nhost-a\nhost-b\n")
        self.inventory = Path(self._tmp.name) / "doesnotexist"
        self.run_main("--inventory", str(other))
        hosts, *_ = self.run_calls[0]
        self.assertEqual(hosts, ["host-a", "host-b"])

    def test_ssh_config_option_is_passed(self):
        self.run_main("--host", "web1", "--ssh-config", "/etc/my_ssh.conf")
        _, ssh_config, *_ = self.run_calls[0]
        self.assertEqual(ssh_config, Path("/etc/my_ssh.conf"))

    def test_user_mode_accepts_ssh_config(self):
        self.run_main("--user", "admin", "--host", "10.0.0.5", "--ssh-config", "/etc/my_ssh.conf")
        _, ssh_config, *_ = self.run_calls[0]
        self.assertEqual(ssh_config, Path("/etc/my_ssh.conf"))

    def test_resolve_ssh_config(self):
        existing = Path(self._tmp.name) / "ssh.conf"
        existing.write_text("")
        missing = Path(self._tmp.name) / "missing.conf"
        self.assertEqual(resolve_ssh_config(None, existing), existing)
        self.assertIsNone(resolve_ssh_config(None, missing))
        self.assertEqual(resolve_ssh_config(missing, existing), missing)

    def test_default_path_prefers_user_then_system(self):
        base = Path(self._tmp.name) / "default_path"
        base.mkdir()
        repo = base / "inventory.ini"
        etc = base / "hosts.ini"
        # No file present: the /etc variant, so error message/help point there
        self.assertEqual(default_path(repo, etc), etc)
        etc.write_text("")
        self.assertEqual(default_path(repo, etc), etc)
        repo.write_text("")
        self.assertEqual(default_path(repo, etc), repo)

    def test_missing_inventory_returns_2(self):
        self.inventory = Path(self._tmp.name) / "doesnotexist"
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
        # Host output without `installed`/codename: vulnerability check impossible => incomplete (3).
        self.assertEqual(code, 3)
        self.assertEqual(self.lookup_calls, [])

    def test_progress_disabled_without_terminal(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.run_main()
        self.assertEqual(self.progress_args, [None])
        self.assertEqual(err.getvalue(), "")

    def test_progress_reports_steps_on_stderr_not_stdout(self):
        err = io.StringIO()
        progress = Progress(err, enabled=True)
        code, out = self.run_main("--details", progress=progress)
        self.assertEqual(code, 2)
        self.assertIs(self.progress_args[0], progress)
        log = err.getvalue()
        self.assertIn("» Checking 3 host(s)", log)
        self.assertIn("» Loading KEV list (CISA)", log)
        self.assertIn("» Loading Ubuntu vulnerability data (noble)", log)
        self.assertIn("» Fetching CVE info (", log)
        self.assertNotIn("»", out)

    def test_no_progress_flag_disables_progress(self):
        self.run_main("--no-progress")
        self.assertEqual(self.progress_args, [None])

    def test_full_run_marks_kev_and_lists_open_vulns(self):
        code, out = self.run_main("--host", "web1")
        self.assertEqual(code, 1)
        self.assertIn("(high, KEV)", out)
        self.assertIn("Open vulnerabilities (no fix available yet):", out)

    def test_kev_unavailable_gives_3(self):
        code, out = self.run_main("--host", "web1", kev=None)
        self.assertEqual(code, 3)
        self.assertIn("Note: KEV list unavailable", out)

    def test_stale_kev_notice_keeps_exit_code(self):
        stale = default_kev()
        stale.stale = True
        stale.fetched_at = datetime.datetime(2026, 11, 1, 12).timestamp()
        code, out = self.run_main("--host", "web1", kev=stale)
        self.assertEqual(code, 1)
        self.assertIn("Note: KEV data from 2026-11-01", out)

    def test_oval_unavailable_gives_3(self):
        code, out = self.run_main("--host", "web1", oval=None)
        self.assertEqual(code, 3)
        self.assertIn(
            "Vulnerability check not possible: Ubuntu vulnerability data (noble) unavailable", out
        )

    def test_oval_unavailable_notice_once_per_codename(self):
        code, out = self.run_main("--host", "app1", "--host", "web1", oval=None)
        self.assertEqual(code, 3)
        notice = (
            "Ubuntu vulnerability data (noble) unavailable – vulnerability check skipped for affected hosts"
        )
        self.assertEqual(out.count(notice), 1)
        self.assertEqual(out.count("Vulnerability check not possible: Ubuntu vulnerability data (noble)"), 2)

    def test_kev_recent_rejects_values_below_one(self):
        for bad in ("0", "-3"):
            with self.assertRaises(SystemExit) as ctx, contextlib.redirect_stderr(io.StringIO()):
                self.run_main("--kev-recent", bad)
            self.assertEqual(ctx.exception.code, 2)
        self.assertEqual(self.run_calls, [])

    def test_kev_recent_one_day_heading(self):
        _, out = self.run_main("--host", "web1", "--kev-recent", "1")
        self.assertIn("New on CISA KEV (last day):", out)

    def test_verbose_skips_superseded_ubuntu_packages(self):
        raw = (FIXTURES / "remote_output.txt").read_text().replace(
            "libc6 2.39-0ubuntu8.3\n", "libc6 *\n"
        )
        self.assertIn("libc6 *", raw)
        self.fake_run_all = lambda hosts, *a, **k: [HostResult(h, True, None, raw) for h in hosts]
        _, out = self.run_main("--host", "web1", "--verbose")
        self.assertIn("1 packages without Ubuntu origin not checked (docker-ce)", out)

    def test_oval_loaded_once_per_codename(self):
        self.run_main()  # two reachable noble hosts
        self.assertEqual(self.oval_calls, ["noble"])

    def test_unreachable_host_not_passed_to_oval(self):
        self.run_main("--host", "db1")
        self.assertEqual(self.oval_calls, [])

    def test_kev_recent_flag(self):
        _, out = self.run_main("--host", "web1", "--kev-recent")
        self.assertIn("New on CISA KEV (last 7 days):", out)
        _, out = self.run_main("--host", "web1", "--kev-recent", "30")
        self.assertIn("(last 30 days)", out)
        _, out = self.run_main("--host", "web1")
        self.assertNotIn("New on CISA KEV", out)

    def test_package_filter_limits_open_vulns(self):
        _, out = self.run_main("--host", "web1", "--package", "tzdata")
        self.assertNotIn("Open vulnerabilities (no fix available yet):", out)

    def test_verbose_lists_unchecked_foreign_packages(self):
        _, out = self.run_main("--host", "web1", "--verbose")
        self.assertIn("1 packages without Ubuntu origin not checked (docker-ce)", out)

    def test_html_option_writes_file_and_keeps_terminal_output(self):
        target = Path(self._tmp.name) / "report.html"
        code, out = self.run_main("--host", "web1", "--html", str(target), "--details")
        self.assertEqual(code, 1)
        self.assertIn("━━ web1", out)
        self.assertIn(f"HTML report written: {target}", out)
        html = target.read_text(encoding="utf-8")
        self.assertTrue(html.startswith("<!DOCTYPE html>"))
        self.assertIn("web1", html)
        self.assertIn("<details", html)
        self.assertIn("KEV", html)

    def test_html_write_error_returns_2(self):
        target = Path(self._tmp.name) / "missing" / "report.html"
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code, out = self.run_main("--host", "web1", "--html", str(target))
        self.assertEqual(code, 2)
        self.assertIn("━━ web1", out)
        self.assertIn("Error: HTML report not writable", err.getvalue())

    def test_without_html_option_no_file_hint(self):
        _, out = self.run_main("--host", "web1")
        self.assertNotIn("HTML report", out)


class CliSmokeTest(unittest.TestCase):
    def test_help_runs_as_script(self):
        proc = subprocess.run([sys.executable, str(SCRIPT), "--help"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("--security-only", proc.stdout)
        self.assertIn("--kev-recent", proc.stdout)
        self.assertIn("3 = check incomplete", " ".join(proc.stdout.split()))


if __name__ == "__main__":
    unittest.main()

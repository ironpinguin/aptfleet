from __future__ import annotations

import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from parsing import build_host_report, split_sections
from remote import REMOTE_SCRIPT, HostResult, build_ssh_command, run_all, run_host

STUBS = {
    "apt": """#!/bin/sh
echo "Listing... Done"
echo "libssl3t64/noble-updates,noble-security 3.0.13-0ubuntu3.5 amd64 [upgradable from: 3.0.13-0ubuntu3.4]"
echo "openssl/noble-updates,noble-security 3.0.13-0ubuntu3.5 amd64 [upgradable from: 3.0.13-0ubuntu3.4]"
echo "tzdata/noble-updates 2025b-0ubuntu0.24.04.1 all [upgradable from: 2025a-0ubuntu0.24.04]"
""",
    "dpkg-query": """#!/bin/sh
for arg in "$@"; do
  case "$arg" in -*) continue ;; esac
  case "$arg" in
    libssl3t64|openssl) echo "$arg openssl 3.0.13-0ubuntu3.4" ;;
    *) echo "$arg $arg 1.0" ;;
  esac
done
""",
    "apt-get": """#!/bin/sh
if [ "$1" = "update" ]; then echo "update aufgerufen"; exit 0; fi
if [ "$1" = "changelog" ]; then echo "changelog-of-$3 lang=$LC_ALL"; fi
""",
    "sudo": """#!/bin/sh
[ "$1" = "-n" ] && shift
exec "$@"
""",
    "timeout": """#!/bin/sh
shift
exec "$@"
""",
}


class RemoteScriptTest(unittest.TestCase):
    """Führt REMOTE_SCRIPT lokal mit gestubbten apt/dpkg-Befehlen aus."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.stub_dir = Path(self._tmp.name)
        for name, content in STUBS.items():
            path = self.stub_dir / name
            path.write_text(content)
            path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def tearDown(self):
        self._tmp.cleanup()

    def run_script(self, *args: str) -> str:
        proc = subprocess.run(
            ["bash", "-s", "--", *args],
            input=REMOTE_SCRIPT,
            capture_output=True,
            text=True,
            env={"PATH": f"{self.stub_dir}:/usr/bin:/bin", "LANG": "de_DE.UTF-8"},
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("===END===", proc.stdout)
        return proc.stdout

    def test_bash_syntax(self):
        proc = subprocess.run(["bash", "-n"], input=REMOTE_SCRIPT, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_full_run(self):
        sections = split_sections(self.run_script("1"))
        self.assertEqual(sections["apt_update"].splitlines()[0], "rc=0")
        self.assertNotIn("Listing", sections["upgradable"])
        self.assertEqual(len(sections["upgradable"].splitlines()), 3)
        self.assertEqual(
            sections["sources"].splitlines(),
            ["libssl3t64 openssl 3.0.13-0ubuntu3.4", "openssl openssl 3.0.13-0ubuntu3.4", "tzdata tzdata 1.0"],
        )
        changelogs = sorted(k for k in sections if k.startswith("changelog "))
        self.assertEqual(changelogs, ["changelog openssl", "changelog tzdata"])
        self.assertEqual(sections["changelog openssl"], "changelog-of-libssl3t64 lang=C")

    def test_no_refresh_and_package_filter(self):
        sections = split_sections(self.run_script("0", "tzdata"))
        self.assertNotIn("apt_update", sections)
        self.assertEqual(
            sections["upgradable"],
            "tzdata/noble-updates 2025b-0ubuntu0.24.04.1 all [upgradable from: 2025a-0ubuntu0.24.04]",
        )
        self.assertEqual(sorted(k for k in sections if k.startswith("changelog ")), ["changelog tzdata"])

    def test_forces_c_locale(self):
        self.assertIn("export LC_ALL=C", REMOTE_SCRIPT)

    def test_bounds_apt_update_and_changelog_time(self):
        self.assertIn("timeout 90 sudo -n apt-get update", REMOTE_SCRIPT)
        self.assertIn("timeout 20 apt-get changelog", REMOTE_SCRIPT)


def fake_runner(stdout="", stderr="", returncode=0, exc=None):
    def runner(cmd, **kwargs):
        runner.calls.append((cmd, kwargs))
        if exc is not None:
            raise exc
        return subprocess.CompletedProcess(cmd, returncode, stdout, stderr)

    runner.calls = []
    return runner


class BuildSshCommandTest(unittest.TestCase):
    def test_command_with_quoted_args(self):
        cmd = build_ssh_command("git-ansible", "/x/cfg", False, ["openssl", "evil pkg"])
        self.assertEqual(
            cmd,
            [
                "ssh", "-F", "/x/cfg", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
                "git-ansible", "bash -s -- 0 openssl 'evil pkg'",
            ],
        )

    def test_refresh_flag(self):
        cmd = build_ssh_command("git-ansible", "/x/cfg", True, [])
        self.assertEqual(cmd[-1], "bash -s -- 1")

    def test_direct_host_with_user_and_without_config(self):
        cmd = build_ssh_command("10.0.0.5", None, True, [], user="admin")
        self.assertEqual(
            cmd,
            [
                "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
                "-l", "admin", "10.0.0.5", "bash -s -- 1",
            ],
        )


class RunHostTest(unittest.TestCase):
    def test_success(self):
        runner = fake_runner(stdout="===SECTION os===\n24.04\n===END===\n")
        result = run_host("git-ansible", "/x/cfg", True, [], 30, runner=runner)
        self.assertEqual(result, HostResult("git-ansible", True, None, "===SECTION os===\n24.04\n===END===\n"))
        _, kwargs = runner.calls[0]
        self.assertEqual(kwargs["input"], REMOTE_SCRIPT)
        self.assertEqual(kwargs["timeout"], 30)

    def test_ssh_error_uses_last_stderr_line(self):
        runner = fake_runner(
            returncode=255,
            stderr="debug\nssh: connect to host pdf port 22: Connection refused\n",
        )
        result = run_host("pdf-ansible", "/x/cfg", True, [], 30, runner=runner)
        self.assertFalse(result.ok)
        self.assertEqual(result.error, "ssh: connect to host pdf port 22: Connection refused")

    def test_error_without_stderr(self):
        result = run_host("pdf-ansible", "/x/cfg", True, [], 30, runner=fake_runner(returncode=1))
        self.assertEqual(result.error, "exit code 1")

    def test_timeout(self):
        runner = fake_runner(exc=subprocess.TimeoutExpired(cmd="ssh", timeout=30))
        result = run_host("pdf-ansible", "/x/cfg", True, [], 30, runner=runner)
        self.assertEqual(result.error, "ssh timeout nach 30s")

    def test_timeout_keeps_partial_output_once_package_list_is_complete(self):
        partial = (
            "===SECTION upgradable===\n"
            "tzdata/noble-updates 2025b-0ubuntu0.24.04.1 all [upgradable from: 2025a-0ubuntu0.24.04]\n"
            "===SECTION sources===\ntzdata tzdata 2025a-0ubuntu0.24.04\n"
            "===SECTION changelog tzdata===\n"
        )
        runner = fake_runner(exc=subprocess.TimeoutExpired(cmd="ssh", timeout=30, output=partial))
        result = run_host("git-ansible", "/x/cfg", True, [], 30, runner=runner)
        self.assertTrue(result.ok)
        report = build_host_report(result.host, result.raw_output, result.error)
        self.assertEqual([p.upgrade.package for p in report.packages], ["tzdata"])
        self.assertEqual(report.warnings, ["Timeout nach 30s – Changelogs unvollständig"])

    def test_timeout_before_package_list_is_an_error(self):
        runner = fake_runner(
            exc=subprocess.TimeoutExpired(cmd="ssh", timeout=30, output="===SECTION upgradable===\nfoo/x 1 all [u: 0]\n")
        )
        result = run_host("git-ansible", "/x/cfg", True, [], 30, runner=runner)
        self.assertFalse(result.ok)
        self.assertEqual(result.error, "ssh timeout nach 30s")

    def test_non_utf8_output_does_not_crash(self):
        def runner(cmd, **kwargs):
            return subprocess.run(["printf", "caf\\351\\n===END===\\n"], **kwargs)

        result = run_host("git-ansible", "/x/cfg", True, [], 30, runner=runner)
        self.assertTrue(result.ok)
        self.assertIn("caf\ufffd", result.raw_output)

    def test_incomplete_output(self):
        runner = fake_runner(stdout="===SECTION os===\n24.04\n")
        result = run_host("pdf-ansible", "/x/cfg", True, [], 30, runner=runner)
        self.assertFalse(result.ok)
        self.assertEqual(result.error, "unvollständige Ausgabe (kein ===END===)")


class RunAllTest(unittest.TestCase):
    def test_keeps_order_and_isolates_failures(self):
        def runner(cmd, **kwargs):
            host = cmd[7]
            if host == "b":
                raise OSError("ssh nicht gefunden")
            return subprocess.CompletedProcess(cmd, 0, f"{host}\n===END===\n", "")

        results = run_all(["a", "b", "c"], "/x/cfg", True, [], 30, runner=runner)
        self.assertEqual([r.host for r in results], ["a", "b", "c"])
        self.assertEqual([r.ok for r in results], [True, False, True])
        self.assertEqual(results[1].error, "ssh nicht ausführbar: ssh nicht gefunden")

    def test_passes_user_to_ssh(self):
        calls = []

        def runner(cmd, **kwargs):
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, "===END===\n", "")

        run_all(["a"], None, False, [], 30, user="admin", runner=runner)
        self.assertEqual(calls[0][-3:], ["admin", "a", "bash -s -- 0"])


if __name__ == "__main__":
    unittest.main()

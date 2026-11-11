from __future__ import annotations

import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from parsing import build_host_report, split_sections
from remote import ORIGINS_SNIPPET, REMOTE_SCRIPT, HostResult, build_ssh_command, run_all, run_host

STUBS = {
    "apt": """#!/bin/sh
echo "Listing... Done"
echo "libssl3t64/noble-updates,noble-security 3.0.13-0ubuntu3.5 amd64 [upgradable from: 3.0.13-0ubuntu3.4]"
echo "openssl/noble-updates,noble-security 3.0.13-0ubuntu3.5 amd64 [upgradable from: 3.0.13-0ubuntu3.4]"
echo "tzdata/noble-updates 2025b-0ubuntu0.24.04.1 all [upgradable from: 2025a-0ubuntu0.24.04]"
""",
    "dpkg-query": """#!/bin/sh
for arg in "$@"; do
  case "$arg" in
    -f='${db:Status-Abbrev}'*)
      echo "ii  openssl 3.0.13-0ubuntu3.4 openssl 3.0.13-0ubuntu3.4"
      echo "ii  docker-ce 5:28.0.4-1 docker-ce 5:28.0.4-1"
      echo "rc  oldpkg 1.0 oldpkg 1.0"
      exit 0 ;;
  esac
done
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
    "uname": """#!/bin/sh
echo "6.8.0-45-generic"
""",
}

PACKAGES_STANZA = "Package: {p}\nVersion: {v}\nArchitecture: amd64\n\n"


def make_apt_lists(root: Path) -> None:
    files = {
        "archive.ubuntu.com_ubuntu_dists_noble_InRelease": "Origin: Ubuntu\nSuite: noble\n",
        "archive.ubuntu.com_ubuntu_dists_noble_main_binary-amd64_Packages": PACKAGES_STANZA.format(
            p="openssl", v="3.0.13-0ubuntu3.4"
        ),
        "download.docker.com_linux_ubuntu_dists_noble_InRelease": "Origin: Docker\nSuite: noble\n",
        "download.docker.com_linux_ubuntu_dists_noble_stable_binary-amd64_Packages": PACKAGES_STANZA.format(
            p="docker-ce", v="5:28.0.4-1"
        ),
        "archive.ubuntu.com_ubuntu_dists_noble-updates_InRelease": "Origin: Ubuntu\nSuite: noble-updates\n",
    }
    for name, content in files.items():
        (root / name).write_text(content)


class RemoteScriptTest(unittest.TestCase):
    """Führt REMOTE_SCRIPT lokal mit gestubbten apt/dpkg-Befehlen aus."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.stub_dir = Path(self._tmp.name)
        self._lists = tempfile.TemporaryDirectory()
        self.lists_dir = Path(self._lists.name)
        make_apt_lists(self.lists_dir)
        for name, content in STUBS.items():
            path = self.stub_dir / name
            path.write_text(content)
            path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def tearDown(self):
        self._tmp.cleanup()
        self._lists.cleanup()

    def run_script(self, *args: str) -> str:
        proc = subprocess.run(
            ["bash", "-s", "--", *args],
            input=REMOTE_SCRIPT,
            capture_output=True,
            text=True,
            env={
                "PATH": f"{self.stub_dir}:/usr/bin:/bin",
                "LANG": "de_DE.UTF-8",
                "APT_LISTS": str(self.lists_dir),
            },
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

    def test_new_sections(self):
        sections = split_sections(self.run_script("1"))
        self.assertEqual(sections["kernel"], "6.8.0-45-generic")
        self.assertIn("openssl 3.0.13-0ubuntu3.4 openssl", sections["installed"])
        self.assertEqual(sections["origins"].splitlines(), ["openssl 3.0.13-0ubuntu3.4"])

    def test_new_sections_come_before_sources(self):
        out = self.run_script("1")
        for name in ("installed", "kernel", "origins"):
            self.assertLess(out.index(f"===SECTION {name}==="), out.index("===SECTION sources==="))

    def test_package_filter_does_not_limit_installed(self):
        sections = split_sections(self.run_script("0", "tzdata"))
        self.assertIn("openssl", sections["installed"])

    def test_os_prints_codename(self):
        self.assertIn("VERSION_CODENAME", REMOTE_SCRIPT)

    def test_origins_without_lists_is_empty(self):
        for f in self.lists_dir.iterdir():
            f.unlink()
        sections = split_sections(self.run_script("1"))
        self.assertEqual(sections["origins"], "")

    def run_origins(self, installed: str) -> list[str]:
        """Führt nur ORIGINS_SNIPPET aus; stdin = `<name> <version>`-Zeilen."""
        proc = subprocess.run(
            ["bash", "-c", ORIGINS_SNIPPET],
            input=installed,
            capture_output=True,
            text=True,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "APT_LISTS": str(self.lists_dir)},
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return sorted(proc.stdout.splitlines())

    def add_superseded_lists(self) -> None:
        """Ubuntu-Index nur mit neuerer Version; Name teils auch im Docker-Index."""
        (self.lists_dir / "archive.ubuntu.com_ubuntu_dists_noble-updates_main_binary-amd64_Packages").write_text(
            PACKAGES_STANZA.format(p="libperl5.38t64", v="5.38.2-3.2ubuntu0.7")
            + PACKAGES_STANZA.format(p="containerd", v="1.7.28-0ubuntu1~24.04.1")
            + PACKAGES_STANZA.format(p="openssl", v="3.0.13-0ubuntu3.5")
        )
        (self.lists_dir / "download.docker.com_linux_ubuntu_dists_noble_stable_binary-amd64_Packages").write_text(
            PACKAGES_STANZA.format(p="docker-ce", v="5:28.0.4-1")
            + PACKAGES_STANZA.format(p="containerd", v="1.7.27-1")
        )

    def test_origins_superseded_ubuntu_version_gives_name_wildcard(self):
        self.add_superseded_lists()
        out = self.run_origins("libperl5.38t64 5.38.2-3.2ubuntu0.6\n")
        self.assertEqual(out, ["libperl5.38t64 *"])

    def test_origins_name_also_in_foreign_list_is_not_output(self):
        self.add_superseded_lists()
        self.assertEqual(self.run_origins("containerd 1.7.27-1\ndocker-ce 5:28.0.4-1\n"), [])

    def test_origins_exact_match_suppresses_wildcard(self):
        self.add_superseded_lists()
        # openssl 3.0.13-0ubuntu3.4 steht exakt in noble, 3.5 in noble-updates.
        self.assertEqual(self.run_origins("openssl 3.0.13-0ubuntu3.4\n"), ["openssl 3.0.13-0ubuntu3.4"])

    def test_origins_unknown_package_is_not_output(self):
        self.add_superseded_lists()
        self.assertEqual(self.run_origins("localpkg 1.0\n"), [])

    def test_origins_full_script_reports_superseded_package(self):
        self.add_superseded_lists()
        (self.lists_dir / "archive.ubuntu.com_ubuntu_dists_noble_main_binary-amd64_Packages").write_text(
            PACKAGES_STANZA.format(p="openssl", v="3.0.13-0ubuntu3.3")
        )
        sections = split_sections(self.run_script("1"))
        self.assertEqual(sections["origins"].splitlines(), ["openssl *"])

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

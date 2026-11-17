"""Tests für cron/aptfleet-mail.sh mit einem Stub statt aptfleet.py."""
from __future__ import annotations

import email
import email.policy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

WRAPPER = Path(__file__).resolve().parent.parent / "cron" / "aptfleet-mail.sh"

# Stub für aptfleet.py: schreibt die --html-Datei, gibt Text aus, Exit-Code aus STUB_RC.
CHECK_STUB = """import os, sys
args = sys.argv[1:]
open(os.environ["STUB_ARGS"], "w").write("\\n".join(args))
html = args[args.index("--html") + 1]
if os.environ.get("STUB_NO_HTML") != "1":
    open(html, "w", encoding="utf-8").write("<html><body>Bericht äöü</body></html>")
    print(f"HTML-Report geschrieben: {html}")
print("Zusammenfassung: 1 Host, 2 Updates, 1 Security – äöü")
sys.exit(int(os.environ.get("STUB_RC", "1")))
"""


class CronWrapperTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.stub = self.tmp / "check_stub.py"
        self.stub.write_text(CHECK_STUB)
        self.args_file = self.tmp / "args.txt"

    def tearDown(self):
        self._tmp.cleanup()

    def run_wrapper(self, env_lines: str, rc: int = 1, extra_env: dict | None = None):
        env_file = self.tmp / "test.env"
        env_file.write_text(
            f'APTFLEET="{self.stub}"\nREPORT_NAME="testhost"\n' + env_lines
        )
        env = {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "TMPDIR": str(self.tmp),
            "PYTHON": sys.executable,
            "STUB_RC": str(rc),
            "STUB_ARGS": str(self.args_file),
            **(extra_env or {}),
        }
        return subprocess.run(["bash", str(WRAPPER), str(env_file)], capture_output=True,
                              text=True, env=env, timeout=30)

    def test_print_builds_valid_mime_mail(self):
        proc = self.run_wrapper('MAIL_TO="a@example.com, b@example.com"\nMAIL_TRANSPORT=print\n'
                                'MAIL_FROM="r@example.com"\n')
        self.assertEqual(proc.returncode, 1, proc.stderr)
        msg = email.message_from_string(proc.stdout, policy=email.policy.default)
        self.assertEqual(msg["To"], "a@example.com, b@example.com")
        self.assertEqual(msg["From"], "r@example.com")
        self.assertEqual(str(msg["Subject"]),
                         "[updates] testhost: Security-Updates oder offene KEV-Lücke")
        self.assertTrue(msg.is_multipart())
        body = msg.get_body(preferencelist=("plain",)).get_content()
        self.assertIn("Zusammenfassung: 1 Host, 2 Updates, 1 Security – äöü", body)
        self.assertNotIn("HTML-Report geschrieben", body)
        self.assertIn("Bericht äöü", msg.get_body(preferencelist=("html",)).get_content())
        attachments = list(msg.iter_attachments())
        self.assertEqual(len(attachments), 1)
        self.assertRegex(attachments[0].get_filename(), r"^updates-testhost-.*\.html$")
        self.assertIn("Bericht äöü", attachments[0].get_content())

    def test_default_args_check_local_and_add_html(self):
        self.run_wrapper("MAIL_TRANSPORT=print\n")
        args = self.args_file.read_text().splitlines()
        self.assertEqual(args[:3], ["--local", "--details", "--no-progress"])
        self.assertEqual(args[3], "--html")

    def test_check_args_are_passed(self):
        self.run_wrapper('MAIL_TRANSPORT=print\nAPTFLEET_ARGS="--local --security-only"\n')
        self.assertEqual(self.args_file.read_text().splitlines()[:2], ["--local", "--security-only"])

    def test_problems_mode_sends_nothing_when_all_ok(self):
        proc = self.run_wrapper("MAIL_TRANSPORT=print\nMAIL_WHEN=problems\n", rc=0)
        self.assertEqual((proc.returncode, proc.stdout), (0, ""))

    def test_always_mode_sends_when_all_ok(self):
        proc = self.run_wrapper("MAIL_TRANSPORT=print\nMAIL_WHEN=always\n", rc=0)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("keine dringenden Updates", email.message_from_string(
            proc.stdout, policy=email.policy.default)["Subject"])

    def test_without_html_only_text(self):
        proc = self.run_wrapper("MAIL_TRANSPORT=print\n", rc=2, extra_env={"STUB_NO_HTML": "1"})
        msg = email.message_from_string(proc.stdout, policy=email.policy.default)
        self.assertIn("FEHLER", msg["Subject"])
        self.assertEqual(list(msg.iter_attachments()), [])
        self.assertIsNone(msg.get_body(preferencelist=("html",)))

    def test_html_attach_only(self):
        proc = self.run_wrapper("MAIL_TRANSPORT=print\nMAIL_HTML_INLINE=0\n")
        msg = email.message_from_string(proc.stdout, policy=email.policy.default)
        self.assertIsNone(msg.get_body(preferencelist=("html",)))
        self.assertEqual(len(list(msg.iter_attachments())), 1)

    def test_sendmail_gets_recipients_and_message(self):
        out = self.tmp / "sendmail.out"
        sendmail = self.tmp / "sendmail"
        sendmail.write_text(f'#!/bin/sh\necho "$@" > {out}.args\ncat > {out}\n')
        sendmail.chmod(0o755)
        proc = self.run_wrapper(f'MAIL_TO="a@example.com,b@example.com"\nSENDMAIL="{sendmail}"\n'
                                'MAIL_FROM="r@example.com"\n')
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertEqual(Path(f"{out}.args").read_text().split(),
                         ["-i", "-f", "r@example.com", "--", "a@example.com", "b@example.com"])
        self.assertIn("MIME-Version: 1.0", out.read_text())

    def test_sendmail_failure_gives_4(self):
        proc = self.run_wrapper('MAIL_TO="a@example.com"\nSENDMAIL="/bin/false"\n')
        self.assertEqual(proc.returncode, 4)
        self.assertIn("fehlgeschlagen", proc.stderr)

    def test_dry_run_prints_even_if_ok_and_sendmail_configured(self):
        env_file = self.tmp / "dry.env"
        env_file.write_text(f'APTFLEET="{self.stub}"\nMAIL_TO="a@example.com"\n'
                            'MAIL_TRANSPORT=sendmail\nSENDMAIL=/bin/false\nMAIL_WHEN=problems\n')
        proc = subprocess.run(
            ["bash", str(WRAPPER), "--dry-run", str(env_file)], capture_output=True, text=True,
            env={"PATH": "/usr/bin:/bin", "TMPDIR": str(self.tmp), "PYTHON": sys.executable,
                 "STUB_RC": "0", "STUB_ARGS": str(self.args_file)}, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("MIME-Version: 1.0", proc.stdout)

    def test_missing_mail_to_gives_5(self):
        proc = self.run_wrapper("")
        self.assertEqual(proc.returncode, 5)
        self.assertIn("MAIL_TO", proc.stderr)

    def test_missing_env_file_gives_5(self):
        proc = subprocess.run(["bash", str(WRAPPER), str(self.tmp / "gibtsnicht")],
                              capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 5)

    def test_smtp_requires_url(self):
        proc = self.run_wrapper('MAIL_TO="a@example.com"\nMAIL_TRANSPORT=smtp\n')
        self.assertEqual(proc.returncode, 5)
        self.assertIn("SMTP_URL", proc.stderr)

    def test_report_dir_keeps_html_copy(self):
        archive = self.tmp / "archive"
        self.run_wrapper(f'MAIL_TRANSPORT=print\nREPORT_DIR="{archive}"\n')
        files = list(archive.glob("updates-testhost-*.html"))
        self.assertEqual(len(files), 1)
        self.assertIn("Bericht", files[0].read_text(encoding="utf-8"))

    def test_temp_dir_is_removed(self):
        self.run_wrapper("MAIL_TRANSPORT=print\n")
        self.assertEqual(list(self.tmp.glob("aptfleet-mail.*")), [])


if __name__ == "__main__":
    unittest.main()

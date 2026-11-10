#!/usr/bin/env python3
"""Isolated Phase 5 Step 2 mailer process tests; no real SMTP delivery.

Exercises the *actual compiled teal-mailer binary*, a temporary configuration,
synthetic credentials, and a loopback-only refused SMTP port. It NEVER modifies
systemd units, /etc/teal.d, or /run/teal.
"""
import argparse
import json
import os
import pathlib
import select
import socket
import subprocess
import sys
import tempfile
import time
import unittest

MAILER = None
SECRET = "TEST-NOT-A-REAL-PASSWORD-PHASE5-NEVER-LOG-12345"
USERNAME = "dummy-phase5@example.invalid"


def unused_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class MailerProcessTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="teal-phase5-step2-")
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)
        self.credentials = self.root / "credentials"
        self.credentials.mkdir(mode=0o700)
        self.config = self.root / "mailer.json"
        self.data = {
            "version": "1.0",
            "smtp": {
                "host": "127.0.0.1",
                "port": unused_port(),
                "from": "phase5@example.invalid",
                # Required by the current teal-mailer schema (common To mailbox).
                "to_address": "phase5-primary@example.invalid",
                "tls": "required",
                "credentials": {
                    "provider": "systemd",
                    "user": "smtp_user",
                    "password": "smtp_password",
                },
            },
            "rate_limit": {"ai_per_minute": 10, "deny_per_minute": 5},
        }
        self.save_config()

    def save_config(self):
        self.config.write_text(json.dumps(self.data), encoding="utf-8")
        self.config.chmod(0o600)

    def write_credentials(self, password=SECRET, username=USERNAME):
        (self.credentials / "smtp_user").write_bytes(username.encode("utf-8"))
        (self.credentials / "smtp_password").write_bytes(password.encode("utf-8"))
        (self.credentials / "smtp_user").chmod(0o600)
        (self.credentials / "smtp_password").chmod(0o600)

    def run_mailer(self, args, with_credentials=True, timeout_sec=12):
        env = os.environ.copy()
        env.pop("CREDENTIALS_DIRECTORY", None)
        env.pop("LISTEN_PID", None)
        env.pop("LISTEN_FDS", None)
        if with_credentials:
            env["CREDENTIALS_DIRECTORY"] = str(self.credentials)
        result = subprocess.run([str(MAILER), *map(str, args)], capture_output=True,
                                text=True, errors="replace", timeout=timeout_sec, env=env)
        combined = result.stdout + result.stderr
        self.assertNotIn(SECRET, combined, "SMTP password appeared in program output")
        self.assertNotIn(USERNAME, combined, "SMTP username appeared in program output")
        return result, combined

    def test_01_missing_or_invalid_config_fails_before_smtp(self):
        proc, _ = self.run_mailer(["--check-config", self.root / "does-not-exist.json"])
        self.assertNotEqual(proc.returncode, 0)
        self.config.write_text("{not-json", encoding="utf-8")
        proc, _ = self.run_mailer(["--check-config", self.config])
        self.assertNotEqual(proc.returncode, 0)

    def test_02_correct_config_does_not_require_credential_loading(self):
        proc, _ = self.run_mailer(["--check-config", self.config], with_credentials=False)
        self.assertEqual(proc.returncode, 0)

    def test_03_missing_systemd_credentials_directory_prevents_start(self):
        proc, output = self.run_mailer(["--check-credentials", self.config], with_credentials=False)
        self.assertNotEqual(proc.returncode, 0)
        # Rust's Result<(), Box<dyn Error>> termination prints the Debug
        # representation ("Error: MissingDirectory"), while a display-oriented
        # entrypoint may print "CREDENTIALS_DIRECTORY is not set". Accept both.
        self.assertRegex(output, r"(?:\bMissingDirectory\b|CREDENTIALS_DIRECTORY)")

    def test_04_missing_password_file_prevents_start(self):
        (self.credentials / "smtp_user").write_text(USERNAME, encoding="utf-8")
        proc, output = self.run_mailer(["--check-credentials", self.config])
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("password", output.lower())

    def test_05_invalid_credential_values_fail_closed(self):
        self.write_credentials()
        for password in ["", "malformed\n", "bad\x00pass", "x" * 16385]:
            with self.subTest(reason=repr(password[:16])):
                (self.credentials / "smtp_password").write_bytes(password.encode("utf-8"))
                proc, output = self.run_mailer(["--check-credentials", self.config])
                self.assertNotEqual(proc.returncode, 0)
                self.assertIn("password", output.lower(), "failure must come from credential validation")
        (self.credentials / "smtp_password").write_bytes(b"\xff")
        proc, output = self.run_mailer(["--check-credentials", self.config])
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("password", output.lower(), "failure must come from credential validation")

    def test_06_repaired_credentials_are_accepted_without_secret_logging(self):
        self.write_credentials(password="invalid\n")
        proc, _ = self.run_mailer(["--check-credentials", self.config])
        self.assertNotEqual(proc.returncode, 0)
        self.write_credentials()
        proc, _ = self.run_mailer(["--check-credentials", self.config])
        self.assertEqual(proc.returncode, 0)

    def test_07_missing_socket_activation_environment_prevents_start(self):
        self.write_credentials()
        proc, output = self.run_mailer(["--config", self.config])
        self.assertNotEqual(proc.returncode, 0)
        self.assertTrue("LISTEN_" in output or "systemd" in output.lower(), output)

    def test_08_local_smtp_connection_refusal_is_reported_as_failure(self):
        self.write_credentials()
        # The SMTP destination is 127.0.0.1:<unused port>, never the public network.
        proc, output = self.run_mailer(
            ["--send-test", "phase5-recipient@example.invalid", "--config", self.config],
            timeout_sec=12)
        self.assertNotEqual(proc.returncode, 0, "refused SMTP must not be reported as accepted")
        self.assertIn("SMTP test failed", output, "SMTP transport must be reached before reporting connection failure")

    @unittest.skipUnless(os.name == "posix" and sys.platform.startswith("linux"), "Linux socket activation only")
    def test_09_valid_temporary_socket_activation_starts_and_stops(self):
        self.write_credentials()
        path = self.root / "temporary-mailer.sock"
        # A dedicated helper process creates fd 3 and execs the real mailer.
        # This avoids subprocess close_fds closing a dup2-created fd 3 when
        # the listener happens to start on another descriptor number.
        cmd = [
            sys.executable, str(pathlib.Path(__file__).resolve()),
            "--_socket-activated-child", str(MAILER), str(self.config),
            str(self.credentials), str(path),
        ]
        child = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, text=True, errors="replace",
                                 start_new_session=True)
        try:
            # Wait for real readiness, not an arbitrary 350 ms sleep.
            # The helper and execve can take longer on a busy CI machine.
            startup_output = ""
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                if child.poll() is not None:
                    break
                readable, _, _ = select.select([child.stdout], [], [], 0.1)
                if readable:
                    chunk = os.read(child.stdout.fileno(), 4096).decode("utf-8", "replace")
                    startup_output += chunk
                    if "IPC listener inherited" in startup_output:
                        break
            self.assertIn("IPC listener inherited", startup_output,
                          "mailer did not reach IPC readiness: " + startup_output)
            self.assertIsNone(child.poll(), "mailer exited after startup")
            child.terminate()
            remaining_output, _ = child.communicate(timeout=7)
            output = startup_output + remaining_output
            self.assertEqual(child.returncode, 0, output)
            self.assertNotIn(SECRET, output)
            self.assertNotIn(USERNAME, output)
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=3)


def _socket_activated_child(binary, config, credentials, path):
    """Isolated child process: emulate systemd's LISTEN_FDS=1 / fd 3."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(path)
        listener.listen(2)
        fd = listener.fileno()
        if fd != 3:
            os.dup2(fd, 3, inheritable=True)
        else:
            os.set_inheritable(fd, True)
        env = os.environ.copy()
        env["CREDENTIALS_DIRECTORY"] = credentials
        env["LISTEN_PID"] = str(os.getpid())
        env["LISTEN_FDS"] = "1"
        # execve preserves this process's PID for LISTEN_PID validation.
        os.execve(binary, [binary, "--config", config], env)


if __name__ == "__main__":
    if len(sys.argv) == 6 and sys.argv[1] == "--_socket-activated-child":
        _socket_activated_child(*sys.argv[2:])
        sys.exit(99)  # execve never returns on success.
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=pathlib.Path, default=pathlib.Path("target/debug/teal-mailer"))
    opts, rest = parser.parse_known_args()
    MAILER = opts.binary.resolve()
    if not MAILER.is_file():
        parser.error("teal-mailer binary not found; first run cargo build -p teal-mailer")
    unittest.main(argv=[sys.argv[0], *rest], verbosity=2)

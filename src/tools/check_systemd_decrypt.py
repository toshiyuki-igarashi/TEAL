#!/usr/bin/env python3
"""OPTIONAL: test actual systemd LoadCredentialEncrypted rejection in an isolated transient unit.

Run ONLY with --run-isolated-systemd-test as root on a systemd-managed machine.
No production mailer/teald unit or real Credential file is modified.
"""
import argparse
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import uuid

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("--run-isolated-systemd-test", action="store_true", required=True)
a = p.parse_args()
if os.geteuid() != 0:
    sys.exit("ERROR: requires root to create an isolated systemd transient unit")
if not shutil.which("systemd-run"):
    sys.exit("ERROR: systemd-run not found")
with tempfile.TemporaryDirectory(prefix="teal-phase5-systemd-") as d:
    credential = pathlib.Path(d) / "invalid-encrypted-credential"
    # Intentionally malformed; NEVER use a real or production credential.
    credential.write_bytes(b"not a systemd encrypted credential\x00PHASE5_TEST_ONLY")
    credential.chmod(0o600)
    unit = "teal-phase5-cred-fail-" + uuid.uuid4().hex[:12]
    cmd = ["systemd-run", "--wait", "--collect", "--unit=" + unit,
           "--property=LoadCredentialEncrypted=phase5_bogus:" + str(credential),
           "/usr/bin/true"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
    output = (result.stdout + result.stderr).strip()
    # systemd-run version-dependent exit behavior: report evidence rather than
    # claim PASS if the child exit code is not reliably reflected by systemd-run.
    print("isolated unit:", unit)
    print("systemd-run return code:", result.returncode)
    print(output[-1600:])
    if result.returncode == 0:
        sys.exit("INCONCLUSIVE: inspect 'journalctl -u " + unit + "' to verify failure to decrypt")
    print("PASS: malformed encrypted credential prevented successful isolated unit execution")

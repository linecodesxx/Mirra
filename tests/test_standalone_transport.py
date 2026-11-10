"""Standalone transport research must never claim attestation success."""
import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKER = ROOT / "research/standalone/local_endpoint.py"


class StandaloneTransportTests(unittest.TestCase):
    def test_local_process_uses_existing_endpoint_transport(self):
        run = subprocess.run(
            [sys.executable, str(WORKER), "--probe"],
            cwd=ROOT, capture_output=True, text=True, timeout=20)
        self.assertEqual(run.returncode, 0, run.stderr)
        result = json.loads(run.stdout)
        self.assertTrue(result["local_process_connected"])
        self.assertTrue(result["generate_rejected"])
        self.assertFalse(result["ssh_used"])
        self.assertFalse(result["mirroring_verified"])
        self.assertFalse(result["hardware_attestation_verified"])

    def test_worker_refuses_all_cryptographic_operations(self):
        payload = '\n'.join(json.dumps({"operation": name}) for name in
            ("generate", "validate", "sign_remote", "session_signed", "step", "token")) + '\n'
        run = subprocess.run(
            [sys.executable, str(WORKER), "--worker"],
            cwd=ROOT, input=payload, capture_output=True, text=True, timeout=10)
        self.assertEqual(run.returncode, 0, run.stderr)
        lines = [json.loads(line) for line in run.stdout.splitlines()]
        self.assertTrue(lines[0]["ready"])
        self.assertFalse(lines[0]["cryptographic_backend_available"])
        self.assertEqual(len(lines), 7)
        for entry in lines[1:]:
            self.assertEqual(entry["error"], "crypto_backend_not_implemented")
            self.assertNotEqual(entry["status"], 0)


if __name__ == "__main__":
    unittest.main()

"""The passive stage observer does not leak log lines or claim authentication."""
import importlib.util
import io
from pathlib import Path
import unittest


PATH = Path(__file__).resolve().parents[1] / "research/standalone/sts_observer.py"
spec = importlib.util.spec_from_file_location("sts_observer", PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class StsObserverTests(unittest.TestCase):
    def test_stages_without_raw_sensitive_text(self):
        raw = [
            '2026-11-10 22:53:48.437 Df mobileactivationd[1351:550d] DCRT requested by dcrt-probe SECRET_TOKEN=supersecret ID=12345',
            '2026-11-10 22:53:48.437 Df mobileactivationd[1351:550d] copyDCRTWithCompletionBlock: Not supported on this device. SSID=private',
            '2026-11-10 22:53:48.438 Df kernel[0:65f74] (AppleKeyStore) operation failed sel: 49 ret: e00002c1',
            '2026-11-10 22:53:48.440 Df sharingd[201:15] SDAuthentication error private_ID=ABCDEF',
            '2026-11-10 22:53:48.441 Df rapportd[234:15] remote session STS TOKEN=moreprivate'
        ]
        result = module.summarize(raw)
        self.assertEqual(result["stage_counts"]["dcrt_device_unsupported"], 1)
        self.assertEqual(result["stage_counts"]["aks_privilege_denied"], 1)
        self.assertEqual(result["stage_counts"]["authentication_failure"], 1)
        self.assertEqual(result["stage_counts"]["remote_session"], 1)
        self.assertNotIn("supersecret", str(result))
        self.assertNotIn("moreprivate", str(result))
        self.assertNotIn("private_ID", str(result))
        self.assertFalse(result["auth_verified"])
        self.assertFalse(result["mirroring_verified"])

    def test_empty_and_unknown_messages_prove_nothing(self):
        result = module.summarize(['unrelated secrets PASSWORD=hidden', '2026-11-10 kernel unknown'])
        self.assertEqual(result["matched_events"], 0)
        self.assertEqual(result["first_events"], [])

    def test_duration_validation(self):
        for value in ("0m", "100m", "-1m", "2m;rm", "abc"):
            with self.assertRaises(ValueError):
                module.recent(value)


if __name__ == "__main__":
    unittest.main()

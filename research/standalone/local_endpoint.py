#!/usr/bin/env python3
"""Transport-only LOCAL endpoint proof for Mirra.

This explicitly does NOT implement AppleKeyStore, hardware attestation, DCRT,
pairing, Secure Enclave, or working iPhone Mirroring.
"""
import json
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

UNAVAILABLE = -536870212  # kIOReturnError


def send(message):
    print(json.dumps(message, separators=(",", ":")), flush=True)


def serve():
    # Deliberately NO DCRT or signed key: do not pretend to be a trusted device.
    send({"ready": True, "protocol_version": 1,
          "endpoint_kind": "local-transport-only",
          "cryptographic_backend_available": False,
          "mirroring_verified": False})
    for line in sys.stdin:
        if len(line) > 262144:
            send({"status": UNAVAILABLE, "error": "request_too_large"})
            return
        try:
            request = json.loads(line)
            if not isinstance(request, dict):
                raise ValueError("request_must_be_an_object")
        except (ValueError, UnicodeError):
            send({"status": UNAVAILABLE, "error": "invalid_request"})
            continue
        operation = request.get("operation")
        if operation == "exit":
            send({"closed": True})
            return
        # Fail closed for ALL security-relevant operations.
        send({"status": UNAVAILABLE, "error": "crypto_backend_not_implemented",
              "operation": operation})


def probe():
    # Existing Mirra transport already supports an explicit local command.
    from transport import Endpoint
    config = SimpleNamespace(timeout=5)
    with Endpoint(config, command=[sys.executable, "-u", str(Path(__file__).resolve()), "--worker"]) as endpoint:
        result = endpoint.call("generate", attested=True, key_class=9)
        report = {
            "probe": "standalone-stdio-transport",
            "local_process_connected": endpoint.ready.get("endpoint_kind") == "local-transport-only",
            "ssh_used": False,
            "generate_rejected": result.get("error") == "crypto_backend_not_implemented",
            "hardware_attestation_verified": False,
            "mirroring_verified": False
        }
    send(report)
    return 0 if report["local_process_connected"] and report["generate_rejected"] else 1


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--worker":
        serve()
    elif len(sys.argv) == 2 and sys.argv[1] == "--probe":
        sys.exit(probe())
    else:
        sys.exit("usage: python3 research/standalone/local_endpoint.py --probe")

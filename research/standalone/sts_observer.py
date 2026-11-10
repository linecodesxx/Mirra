#!/usr/bin/env python3
"""Passive STS/Continuity stage observer for native iPhone Mirroring.

Read macOS unified log entries, then emit only bounded category counts/timestamps.
Raw log messages, device identifiers, pairing records and key material are never
printed or stored. This does not establish or bypass authentication.
"""
import argparse
from collections import Counter
import json
import re
import subprocess
import sys

PREDICATE = (
    '(process == "sharingd" OR process == "rapportd" OR '
    'process == "mobileactivationd" OR process == "iPhone Mirroring" OR '
    'process == "ScreenContinuity" OR process == "identityservicesd" OR '
    '(process == "kernel" AND (eventMessage CONTAINS[c] "AppleKeyStore" '
    'OR eventMessage CONTAINS[c] "AppleSEP")))' 
)
RULES = (
    ("dcrt_device_unsupported", re.compile(r'DCRT.{0,150}not supported on this device|copyDCRTWithCompletionBlock.{0,150}Not supported', re.I)),
    ("aks_privilege_denied", re.compile(r'AppleKeyStore.{0,180}(e00002c1|notprivileged|operation failed)', re.I)),
    ("remote_session", re.compile(r'aks_remote_session|remote[_ -]session|remotePeer|\bSTS\b|station.to.station', re.I)),
    ("authentication_failure", re.compile(r'auth(?:entication)?[_ -]?(?:error|fail|denied|reject)|SDAuthentication.{0,100}(?:error|fail)|attestation.{0,100}(?:fail|reject)', re.I)),
    ("attestation", re.compile(r'\battest(?:ation|ed|ing)?\b|\bDCRT\b', re.I)),
    ("pairing", re.compile(r'\bpair(?:ing|ed)?\b|peer[_ -]?confirm|peer[_ -]?setup', re.I)),
    ("awdl", re.compile(r'\bAWDL\b|\bawdl0\b|PeerToPeer', re.I)),
    ("discovery", re.compile(r'\bdiscovery\b|\bRapport\b|proximity|nearby device', re.I)),
)
TIME = re.compile(r'^\s*(\d{4}-\d\d-\d\d\s+\d\d:\d\d:\d\d(?:\.\d+)?)')
PROCESSES = ('sharingd', 'rapportd', 'mobileactivationd',
             'iPhone Mirroring', 'ScreenContinuity', 'identityservicesd', 'kernel')
MAX_LINES = 16000
MAX_EVENTS = 18
MAX_LOG_BYTES = 4 * 1024 * 1024


def summarize(lines):
    counters = Counter()
    sources = Counter()
    timeline = []
    total = 0
    for raw in lines:
        if total >= MAX_LINES:
            break
        total += 1
        line = raw[:2048]
        source = next((name for name in PROCESSES if name + '[' in line), None)
        # Never emit original line, message, device identifier or payload.
        if source is None:
            continue
        sources[source] += 1
        label = next((name for name, pattern in RULES if pattern.search(line)), None)
        if label is not None:
            counters[label] += 1
            if len(timeline) < MAX_EVENTS:
                match = TIME.match(line)
                timeline.append({"stage": label, "source": source,
                                 "time": match.group(1) if match else None})
    return {
        "probe": "native-mirroring-passive-stages",
        "lines_scanned": total,
        "matched_events": sum(counters.values()),
        "source_counts": dict(sources),
        "stage_counts": dict(counters),
        "first_events": timeline,
        "raw_log_retained": False,
        "auth_verified": False,
        "mirroring_verified": False,
        "note": "Log categories are observational only; absence of an event proves nothing."
    }


def recent(duration):
    if not re.fullmatch(r'(?:[1-9]|[1-5][0-9])[smh]', duration):
        raise ValueError("Duration must be 1s..59s, 1m..59m or 1h..59h")
    command = ["log", "show", "--last", duration, "--style", "compact",
               "--info", "--predicate", PREDICATE]
    result = subprocess.run(command, capture_output=True, timeout=35)
    if result.returncode:
        raise RuntimeError("macOS log query failed (exit status %s)" % result.returncode)
    if len(result.stdout) > MAX_LOG_BYTES:
        raise RuntimeError("Log result exceeds safe in-memory limit; use a shorter --recent duration")
    return result.stdout.decode("utf-8", errors="replace").splitlines()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--recent", metavar="DURATION",
                       help="Query macOS log (e.g. 2m) after trying native iPhone Mirroring")
    group.add_argument("--stdin", action="store_true",
                       help="Classify a piped log for tests, never export its raw content")
    args = parser.parse_args(argv)
    try:
        lines = sys.stdin if args.stdin else recent(args.recent)
        print(json.dumps(summarize(lines), indent=2, ensure_ascii=False))
    except (OSError, subprocess.TimeoutExpired, RuntimeError, ValueError) as error:
        # Do not reveal stderr or original logs in exception output.
        print(json.dumps({"probe": "native-mirroring-passive-stages",
                          "error": type(error).__name__,
                          "detail": "Unable to inspect macOS logs; no system settings changed."}))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

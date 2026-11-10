# Standalone Mirra — experiments

The goal is native Apple's iPhone Mirroring with **only one unmodified primary iPhone**, on an Intel Hackintosh without T2/SEP. No other mirroring apps or jailbreak iPhone are part of the target design.

**Current state:** local process transport works, but **identity/attestation/remote-session operations do not**. These experiments must not report genuine Apple pairing, key attestation, or a connected iPhone.

## Experiment A — local endpoint transport (confirmed 2026-11-10)

On the Hackintosh, `research/standalone/local_endpoint.py --probe` returned:

```json
{"probe":"standalone-stdio-transport","local_process_connected":true,"ssh_used":false,"generate_rejected":true,"hardware_attestation_verified":false,"mirroring_verified":false}
```

`python3 -m unittest discover -s tests -p 'test_standalone_transport.py' -v` completed **2 tests, OK**.

**Meaning:** `scripts/transport.py:Endpoint(command=[...])` successfully transports JSON-lines to a local process. This is not an authentication success: `generate` is intentionally rejected, as are all other security-sensitive operations.

## Experiment B — macOS DCRT availability (symbol stage confirmed 2026-11-10)

The user compiled `research/standalone/dcrt-probe.m` on the Intel Hackintosh and ran the default **symbols-only** mode. The JSON result reported:

```json
{"probe":"local-dcrt","mode":"symbols_only","framework_loaded":1,"copy_symbol_found":1,"issue_symbol_found":1,"certificate_bytes_exported":false,"certificate_issued":false,"hardware_attestation_verified":false,"mirroring_verified":false}
```

**Meaning:** MobileActivationMacOS loads and the DCRT copy/issue entrypoints resolve. Neither function was invoked; no certificate was returned or issued, and native Mirroring is **not** verified.

### Cached DCRT lookup — confirmed negative on 2026-11-10

The user ran `./build/dcrt-probe --copy-dcrt` on the Hackintosh. Observed values:

```json
{
  "probe": "local-dcrt",
  "mode": "copy_cached_certificate",
  "framework_loaded": 1,
  "copy_symbol_found": 1,
  "issue_symbol_found": 1,
  "certificate_available": 0,
  "certificate_size": 0,
  "error_domain": "com.apple.MobileActivation.ErrorDomain",
  "error_code": -1,
  "certificate_bytes_exported": false,
  "certificate_issued": false,
  "hardware_attestation_verified": false,
  "mirroring_verified": false
}
```

**Interpretation:** macOS has a DCRT accessor entrypoint, but this process received no cached DCRT. `-1` is not a sufficient explanation of root cause. The system might not have a cached identity; access might be denied; the prerequisite secure hardware might be unavailable. Do not infer absence of hardware as the proven cause based solely on this output. Do not invoke DCRT issuance merely to test symbol presence; it can change device activation state.

**Next safe step:** capture bounded/redacted `mobileactivationd` unified logs around a single `--copy-dcrt` run to look for concrete failures, or inspect the returned NSError's non-sensitive diagnostic fields. Do not publish certificates, tokens or raw persistent identifiers.

### Optional next gate — cached certificate lookup (already executed; retained as reproduction steps)

`dcrt-probe.m` checks whether macOS exposes `MAECopyDCRTMacOSWithError` / `MAEIssueDCRTMacOSWithCallback`, the native functions referenced by `src/mirroring/keystore.m`.

**First run: default symbol inspection (no private API invocation):**

```bash
mkdir -p build
xcrun clang -fobjc-arc -Wall -Wextra -framework Foundation \
  research/standalone/dcrt-probe.m -o build/dcrt-probe
./build/dcrt-probe
```

If the symbols are found, **optionally**, on a stable backed-up test system only, test whether macOS can return its *already cached* DCRT:

```bash
./build/dcrt-probe --copy-dcrt
```

The program never calls `MAEIssueDCRTMacOSWithCallback` and does **not** issue, export, save or display DCRT bytes, identity credentials or private keys. It only reports certificate availability, size, and NSError domain/code. It does not request any signing key or touch existing keybags.

**Warning:** `MobileActivationMacOS` is a private Apple framework. Even read-only calls may behave differently or crash on unsupported Hackintosh builds. Do not disable SIP, add arbitrary entitlements, or retry after a crash. Stop and inspect a sanitized crash report.

**Interpretation:**

- `framework_loaded=false`: not resolvable at attempted framework locations.
- `copy_symbol_found=true`: an API entrypoint exists; it does **not** imply a valid hardware-backed device identity.
- `certificate_available=false`: there is no accessible cached certificate for this caller; could be entitlement/availability/hardware related.
- `certificate_available=true`: a certificate object was returned; it does **not** prove that stock iOS accepts it or that any signing key can be created.

## Already established — macOS AKS probes

See `research/local-aks/RESULTS.md`: all 18 AKS symbols resolve, isolated keybag create/unload succeed, and non-attested signing-key creation for classes 9/10/11 returns `0xE00002C1`. Hardware dependency versus caller rights is **not proven**.

## Next gate (after experiment B)

Map the trust requirements at the *original* iPhone Mirroring boundary: which calls must provide genuine attestation, which are just session-management interfaces, and whether any legitimate software-only Mac STS path is compatible with a stock iPhone for Mirroring. Only integrate a new production `local` backend after that path has been validated. AWDL/video remain separate requirements.

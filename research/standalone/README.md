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

## Experiment B — macOS DCRT availability (not yet executed)

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

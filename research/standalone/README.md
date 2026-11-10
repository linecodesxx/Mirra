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

### Confirmed daemon-level device support rejection (2026-11-10 22:53:48, device local time)

The user repeated `./build/dcrt-probe --copy-dcrt` and inspected the unified log. The decisive non-sensitive lines were:

```text
dcrt-probe: activating connection: ... name=com.apple.mobileactivationd
mobileactivationd: DCRT requested by dcrt-probe
mobileactivationd: -[MobileActivationMacOSDaemon copyDCRTWithCompletionBlock:withCompletion:]: Not supported on this device.
```

**New conclusion:** The process reached `mobileactivationd`; the daemon explicitly rejected the requested DCRT copy operation as unsupported **on this device**. This is materially stronger than simply observing a `-1` error and zero certificate bytes. On this Hackintosh the macOS DCRT-copy path is **not usable** in its current state. The log does **not** disclose the daemon's internal eligibility check or prove that physical SEP absence is the sole cause. No issuance or Apple-side attestation was attempted.

**Independent corroboration:** Apple's [iPhone Mirroring requirements](https://support.apple.com/en-us/120421) limit the native feature to Apple Silicon Macs or Intel Macs with T2. [OCLP's FAQ](https://dortania.github.io/OpenCore-Legacy-Patcher/FAQ) attributes iPhone Mirroring connection failure on patched unsupported Macs to failure to establish T2 attestation. These sources corroborate a real security dependency, not an automatic software-workaround.

**Decision:** Stop calling `copyDCRT` repeatedly or trying to paper over this with fake certificates. Prioritize static analysis of STS trust requirements and whether any supported software identity path can satisfy the *stock iPhone* without Apple T2. Keep local-process transport work isolated and fail closed. AWDL remains an independent dependency.

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

## Experiment C — native STS / authentication stage observer (not yet executed on Mac)

Apple's March 2026 Platform Security guide says remote unlock uses mutually authenticated Station-to-Station (STS), long-term pairing keys and ephemeral per-session keys. It notes a kernel STS path on Macs without a Secure Enclave **for some device-unlock flows**, but the Mirroring-specific security section says the Mac Secure Enclave enforces the local authentication policy. The public support requirements still demand Apple Silicon or Intel T2 for native iPhone Mirroring. Therefore a standalone software identity is **not yet proven compatible**.

Sources:
- https://help.apple.com/pdf/security/en_US/apple-platform-security-guide.pdf (pages 64, 66–67)
- https://support.apple.com/en-us/120421
- https://dortania.github.io/OpenCore-Legacy-Patcher/FAQ.html

A small observer was added to classify metadata from existing unified logs **without writing raw messages, certificates, keys or identifiers**:

```bash
git pull
python3 -m unittest discover -s tests -p 'test_sts_observer.py' -v
```

1. Keep the second jailbreak iPhone disconnected. Leave Mirra's invasive service/staging **off** for this baseline.
2. Put your **primary** iPhone near the Mac, enable Wi-Fi/Bluetooth and leave it locked; try opening the **original** Apple iPhone Mirroring app and press Connect once.
3. Immediately run:

```bash
python3 research/standalone/sts_observer.py --recent 2m
```

4. Share the generated JSON only, along with the **visible error text in the original app**. The script does not attempt to connect or send anything to the iPhone; it only classifies logs. Use `--recent 1m` if macOS reports its log result is too large.
5. No `sudo`, SIP changes, DCRT issuance, SSH bridge, or permanent system modification is required. If the original app refuses to launch before starting any discovery, report that fact. No events does **not** mean authentication succeeded or failed.

The observer is **best-effort**: unified logs may omit, redact or rename subsystem messages, and errors can occur before any STS operation. It never reports a verified pairing.

## Next gate (after experiment B)

Map the trust requirements at the *original* iPhone Mirroring boundary: which calls must provide genuine attestation, which are just session-management interfaces, and whether any legitimate software-only Mac STS path is compatible with a stock iPhone for Mirroring. Only integrate a new production `local` backend after that path has been validated. AWDL/video remain separate requirements.

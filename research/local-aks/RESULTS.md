# Local AKS experiment results (2026-11-10)

Environment: Intel Huawei MateBook 14s Hackintosh running macOS Tahoe; no T2/SEP. Research branch `research/local-aks-probe`.

## Observed

- `AppleKeyStore.framework` loads.
- All 18 symbols referenced by Mirra's iPhone endpoint are resolved with `dlsym`.
- `aks_create_bag` succeeds (status `0`) for an isolated temporary keybag, and `aks_unload_bag` succeeds (status `0`).
- `aks_create_signing_key` **fails** for each tested non-attested signing-key class **9, 10, 11**, with `-536870207` (`0xE00002C1`, commonly `kIOReturnNotPrivileged`).
- `aks_validate_local_key` was **not executed** because no signing-key blob was generated.
- The probe was ad-hoc signed (`Signature=adhoc`, no TeamIdentifier); ad-hoc signing alone did not change the observed failure for class 9.
- Kernel logs for class 9 show `(AppleKeyStore) operation failed (sel: 49 ret: e00002c1, 501)`. The specific meaning of selector 49 and 501 has **not** been established.
- SIP was reported as `unknown (Custom Configuration)`, Apple Internal disabled, Kext Signing and Filesystem Protections disabled, Debugging Restrictions enabled. These settings do not imply Apple-specific entitlements.

## Interpretation

The available macOS framework provides a callable keybag API, but the signing-key operation is denied consistently across the classes tested. This **does not prove** the cause is absent SEP hardware: code-signing, Apple entitlement checks, missing kernel capabilities, OS-version differences, or parameter conventions remain possibilities.

It also **does not prove** that changing SIP, spoofing entitlements, or running as root would fix the failure. No remote session, DCRT attestation, pairing persistence, or end-to-end iPhone Mirroring success has been demonstrated.

## Next research gates

1. Read the macOS shim and AKS callers to map real call parameters, entitlement/context dependencies and platform-specific differences (static analysis first).
2. Establish whether `aks_create_signing_key` is a supported functionality on comparable legitimate Intel Macs with and without T2, using published information or controlled tests with appropriate permissions.
3. Inspect the existing upstream tests to ensure method signatures and lifecycle assumptions are correct on this OS build.
4. Keep hardware-dependent, software-crypto, persisted-pairing, and AWDL/video investigations as separate tracks. Do not begin by disabling more system protections.
5. Only then consider a narrow, reversible next experiment. No secret-bearing data should be recorded or committed.

## Status

**Local AKS as a drop-in replacement for the jailbreak endpoint: not established.**

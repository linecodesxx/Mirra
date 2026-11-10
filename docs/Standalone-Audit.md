# Standalone Mirra — Recursive Architecture Audit

**Date:** 2026-11-10  
**Repository:** `linecodesxx/Mirra`, based on `research/local-aks-probe`  
**Scope:** recursively enumerated the repository's **181 tree entries** and reviewed the relevant macOS and iPhone source, Python runtime modules, configuration, native adapters, onboarding, documentation, security and regression tests. This is a source audit, **not** a successful device experiment.

## One-sentence finding

**Local transport is already possible**: `scripts/transport.py:Endpoint(config, command=[...])` supports launching an arbitrary local subprocess over JSON-lines/stdin/stdout. **The hard blocker is cryptographic identity and protocol acceptance**, not SSH. Stock iPhone must accept the initiator identity and its authenticated remote-unlock session; `scripts/broker.py` and `scripts/wire.py` enforce a real DCRT/attested-LTK contract.

## Dataflow, with file responsibilities

```text
src/app/app.m / src/app/wizard.m
  -> scripts/onboarding.py / scripts/provisioning.py
  -> scripts/configuration.py (usb | ssh only)
  -> scripts/native.py + scripts/supervisor.py
  -> scripts/backend.py / scripts/broker.py
     -> scripts/transport.py (SSH command default; local command supported explicitly)
     -> scripts/keystore.py (cache keys, translate session handles)
        -> src/phone/endpoint.m (AppleKeyStore + MobileActivation on jailbroken iPhone)
     -> scripts/wire.py (DER attested LTK with platform=3)
  -> scripts/sharing.py / scripts/sharingd.py
     -> src/mirroring/keystore.m (DYLD interposing of DCRT/AKS APIs)
     -> src/mirroring/media.m + profile.m (AWDL/Rapport media path)
     -> src/mirroring/decoder-route.m (video support)
  -> native Apple iPhone Mirroring app + stock target iPhone
```

## Gate inventory — why removing the phone is not a one-file change

| Stage | Location | Current assumption | Standalone implication |
| --- | --- | --- | --- |
| Setup UI | `src/app/wizard.m`, `src/app/app.m` | choose jailbreak device and SSH/USB | new setup state, not just a label |
| Provisioning | `scripts/onboarding.py`, `scripts/provisioning.py` | SSH host trust, ldid, endpoint deployment, exported DCRT | separate provider onboarding |
| Configuration | `scripts/configuration.py` | `backend.transport` only `usb` / `ssh` | add local mode through validated migration |
| Transport | `scripts/transport.py` | SSH is default, but `command` supports local process already | test local endpoint before modifying production |
| Trust bootstrap | `scripts/broker.py` | certificate must exist; endpoint `dcrt_bytes`; fresh attested key and validation required | actual compatible identity provider required |
| Crypto broker | `scripts/keystore.py` | `generate(attested=True)`; 9/10/11 classes; 16 remote sessions; virtual handles | no assumption software key is accepted |
| Wire format | `scripts/wire.py` | DER sequence fields `0x81,0x85,0x86,0x82,0x83,0x84`; adds `0x87=3` | cannot substitute arbitrary DER / fake proof |
| Native hooks | `src/mirroring/keystore.m` | interposes macOS DCRT and remote AKS functions, forwards owned identities | preserve fail-closed routing and genuine peer checks |
| Endpoint | `src/phone/endpoint.m` | MobileActivation DCRT; `aks_create_signing_key_with_params`; remote STS exchange | replacing it means implementing matching behavior, not copying the wrapper |
| Process lifecycle | `scripts/backend.py`, `scripts/native.py`, `scripts/supervisor.py` | bridge worker, recovery, restart/cleanup | standalone must preserve ownership/recovery semantics |
| sharingd injection | `scripts/sharing.py`, `scripts/sharingd.py`, `src/mirroring/launch.m` | scoped temporary dylib and restoration | avoid persistent OS binary patches |
| UI readiness | `scripts/readiness.py`, `scripts/doctor.py`, `src/app/app.m` | reachable jailbreak phone + attested test | local readiness must report **actual crypto readiness**, not just process alive |
| Install/export | `scripts/installation.py`, `scripts/bundle.py`, `config/sources.json` | snapshots bridge profile and source allowlist | update package contract only after working standalone |
| Media | `src/mirroring/media.m`, `profile.m`, `scripts/sockets.py` | `awdl0` IPv6 and peer-to-peer routing | separate independently failing requirement |
| Video | `src/mirroring/decoder-route.m`, `scripts/decoder.py` | VideoToolbox decoding and optional compatibility hooks | video success != authentication success |
| Tests | `tests/`, `.github/workflows/checks.yml` | Python/native regression, no real iOS end-to-end CI | add contract tests and keep device verification separate |

## The real endpoint protocol

`src/phone/endpoint.m` exposes newline-delimited JSON commands:

`generate`, `validate`, `sign_remote`, `session`, `session_signed`, `step`, `token`, `confirm`, `setup`, `reset`, `get_state`, `drop`, `exit`.

It dynamically loads `AppleKeyStore.framework`; attested key creation uses DCRT returned from `MobileActivation` and sends AKS parameters including the DCRT. A private device hardware/OS implementation performs the actual operations. The wrapper alone does not contain a drop-in software implementation.

The broker's virtual session IDs `0x6F000000..0x70000000` are process-local mappings, not persistent pairing credentials. The endpoint resets owned sessions on shutdown.

**Trust rule:** correctly formatted signatures from arbitrary software keys may still be rejected by the stock iPhone if it validates the pinned Mac identity or Apple-attested identity. Do not turn off validation and claim success.

## Evidence from our Intel Hackintosh tests

On Huawei MateBook 14s (i7-13700H, Iris Xe, macOS Tahoe, WhateverXe):

- macOS AppleKeyStore framework loads and **18 / 18** requested API symbols resolve.
- `aks_create_bag` and `aks_unload_bag` succeed for a fresh isolated temporary bag (`0`).
- `aks_create_signing_key` fails for classes **9, 10 and 11**: `-536870207 = 0xE00002C1`.
- A kernel message for class 9 says `AppleKeyStore operation failed (sel: 49 ret: e00002c1, 501)`. Selector 49/501 are not decoded.
- Ad-hoc signing alone did not resolve the failure; no attested identity, STS handshake or iPhone Mirroring has been achieved.
- Neither SIP/entitlement adjustments nor physical SEP absence has been proven as the unique cause of this specific error.
- Results in `research/local-aks/RESULTS.md`.

## Official security constraints (relevant to the goal)

Apple's requirements: Apple Silicon or Intel Mac with T2 for native iPhone Mirroring. Apple's security guide states remote unlock uses mutually authenticated STS with long-term and ephemeral session keys, and documents device identity pinning and hardware-backed protection. Some non-SEP Mac remote-unlock paths may terminate STS in the kernel, **but this is not evidence that an unsupported Hackintosh can be a trusted Mirroring initiator**.

- https://support.apple.com/en-us/120421
- https://support.apple.com/en-au/guide/security/sec6ab47ebfc/web
- https://help.apple.com/pdf/security/en_US/apple-platform-security-guide.pdf

## Implemented in this branch

`research/standalone/local_endpoint.py` + `tests/test_standalone_transport.py`: tests the **existing local command injection** into `transport.Endpoint` and confirms SSH is not intrinsic to JSON-lines transport. Deliberately **denies all crypto requests**. No fake DCRT, no changed system app, no fake "connected" or "attested" status.

Run from repository root:

```bash
python3 research/standalone/local_endpoint.py --probe
python3 -m unittest tests/test_standalone_transport.py -v
```

Only the first command is guaranteed independent of test package import rules; for consistency with upstream CI, prefer:

```bash
python3 -m unittest discover -s tests -p 'test_standalone_transport.py' -v
```

## Decision-gated next steps

**Gate A — Local protocol transport:** confirm `Endpoint(command=[...])` works, with bounded framing and fail-closed behavior. This is the immediate, harmless stage.

**Gate B — Authentication dependency map:** compare `keystore.m` hooks against verified upstream iOS endpoint call graph and identify exactly which operations are generated fresh per connection. Log names, status codes, lengths and timings only; never persist pairing secrets, key blobs, raw tokens or DCRT contents.

**Gate C — Trust capability:** investigate whether a legitimate supported kernel-side STS mode exists on the affected macOS build, whether AKS denied keys due to caller authorization and whether stock iOS can accept an initiator without T2/SEP. Stop if unavailable, rather than fabricating an attestation.

**Gate D — True standalone backend:** only after successful proof of trusted identity and remote-session interop, integrate a new `backend.mode=local`, lifecycle and readiness states. Keep the upstream SSH/USB configuration functioning.

**Gate E — Physical device acceptance:** run an opt-in cold-boot test with **only the primary iPhone** using the native Apple app. Test pairing, reconnect, locked phone control and failure recovery. Check AWDL and VideoToolbox independently.

## Explicit non-goals

- Installing a different iPhone controller or WebDriverAgent instead of native iPhone Mirroring.
- Running a jailbreak iPhone/SEP secretly in the background, remotely or in a VM.
- Pretending a self-signed DCRT is Apple-attested.
- Disabling SIP, mass-adding entitlements, replacing system binaries or editing EFI as a first step.
- Claiming a successful native pairing from a healthy local broker or an SSH-free JSON handshake.

## Uncertainties

We have not established exact binary formats and validation rules of all private STS messages, the meaning of kernel selector 49, whether AppleKeyStore rejects the key before hardware access, the feasibility of kernel-only STS for Mirroring on this host, or whether the target iPhone will ever accept a standalone software identity.

**Current status: transport proof exists; standalone iPhone Mirroring does not.**

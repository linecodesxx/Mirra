# Fork Updates — Standalone Mirra (No Secondary iPhone)

> **Research roadmap only.** None of the approaches below is implemented or verified. This fork currently retains upstream Mirra's requirement for a jailbroken bridge iPhone.

## Goal

Make Apple's **original iPhone Mirroring** work on an Intel Hackintosh with an unmodified primary iPhone, **without any second jailbreak iPhone or permanently connected Apple device**. Preserve upstream functionality during research, and avoid destructive modifications to the working EFI.

## What upstream does

`src/phone/endpoint.m` runs on a jailbroken iPhone over an SSH-backed JSON-lines transport. It calls private AppleKeyStore (AKS) and MobileActivation APIs to manage isolated keybags, signing keys, DCRT certificates and remote crypto sessions. The bridge isn't simply a pairing file: it can perform fresh hardware-backed operations on demand.

Key files to inspect:
- `src/phone/endpoint.m` — `generate`, `validate`, `sign_remote`, `session`, `session_signed`, `step`, `token`, `confirm`, `setup`, `reset`, `get_state`, `drop`.
- `src/mirroring/keystore.m` — local AppleKeyStore hooks.
- `scripts/keystore.py` — identity mapping and virtual session handles.
- `scripts/transport.py` — stateful SSH/stdio endpoint.
- `scripts/broker.py` — broker server.

**Critical distinction:** changing the transport or substituting mathematically valid signatures does not automatically satisfy any trust/attestation checks performed by stock iOS.

## Research hypotheses (priority order)

### 1. Native macOS AKS endpoint — first experiment

Run an adapted endpoint directly on the Hackintosh, calling its installed `AppleKeyStore.framework`; initially skip Docker and VMs. Test symbol availability **and** actual execution separately: isolated keybags, ordinary/attested key generation, validation, signing, remote session setup and step/confirm/token. Record errors and sanitized metadata; never dump device secrets. Determine whether missing T2/SEP functionality causes a hard failure.

### 2. One-time pairing and persisted state

Investigate whether an initial real-bridge pairing can be followed by subsequent **cold-start sessions** without that device. Distinguish exportable certificates and pairing records from non-exportable private keys, hardware-backed session handles and fresh cryptographic challenges. The analogy is sideloading pairing records (e.g. iLoader), **not** proof that Mirroring supports the same resume model. Test restart, logout and reconnect with the bridge physically disconnected.

### 3. Software AKS / OpenAppleKeyStore backend

Build a minimal Go or Rust implementation of the *observable endpoint contract*, optionally packaged as an Alpine Linux container. Support isolated software key storage, session lifecycle and standard crypto primitives. Reverse engineer the exact wire formats, signatures and state machine only through reproducible tests. Clearly identify software-generated credentials as **unattested**; do not claim fake DCRT credentials are Apple-trusted.

### 4. Virtual SEP / minimal headless VM

Investigate the smallest API surface that requires SEP. A VM or firmware dump is **not** equivalent to Apple's physical SEP: hardware UID keys and non-exportable device identities are not reproduced by importing software. Compare native macOS process, Linux container and headless VM as development environments; use a VM only if it solves a measured problem.

### 5. Trust boundary and protocol acceptance

Map each authentication step and determine whether the Mac, the **primary iPhone**, or both validate credentials. Patching local macOS checks alone may not satisfy checks on stock iOS. Maintain original authenticated session encryption and use controlled, opt-in tests. No claim of successful bypass without a complete, repeatable end-to-end connection.

### 6. AWDL and VideoToolbox independence

Even if authentication works, original iPhone Mirroring still requires working peer networking (including AWDL where used) and compatible H.264/VideoToolbox decoding. Track these separately from key-store research. On the target Huawei MateBook 14s (i7-13700H / Iris Xe / Tahoe / WhateverXe), AWDL is a known unresolved concern.

## Proposed fork layout

```text
src/phone/endpoint.m         # upstream jailbroken-iPhone reference
src/mirroring/keystore.m     # existing macOS integration
scripts/transport.py        # backend selection / existing SSH transport
scripts/keystore.py         # existing broker contract
research/local-aks/         # native macOS probe (proposed)
research/traces/            # REDACTED metadata-only traces (proposed)
virtualbridge/              # optional Go/Rust software endpoint (proposed)
```

## Experimental sequence / decision gates

1. Baseline upstream commit, OS build, versions, and observable endpoint calls; develop on a feature branch.
2. Native AKS capability probe, then isolated non-attested key test; do not infer functionality from successful `dlsym`.
3. Attempt legitimate attested operations and identify precise failure point without altering the system keybags.
4. Check whether pairing state can persist across a fresh session with the bridge disconnected.
5. Only if useful, implement a software endpoint and test JSON/crypto interoperability with recorded sanitized test vectors.
6. Map where stock iOS rejects the resulting credentials; independently validate AWDL and video support.

## Success criteria

**Success:** after cold boot, launch Apple's native iPhone Mirroring on the Intel Hackintosh and connect to an **unmodified primary iPhone** with **no secondary device**, with repeatable screen/control, and no transient or remote SEP bridge.

**Not success:** a health-check response, successful JSON transport, valid software ECDSA signature, self-signed certificate, or working pairing UI without a complete Mirroring session.

## Safety, upstream and status

- Research only; **no standalone implementation exists yet**.
- Do not log private keys, full tokens, pairing secrets, Apple Account credentials or DCRT material.
- Do not modify the stable EFI or system services without a reversible test plan.
- Keep authorship and license intact and pull upstream fixes into this fork.
- Original repository: https://github.com/eiyuumiru/Mirra

## Fork update log

- **2026-11-10 — Research proposal:** documented standalone goal, local AKS, persistent pairing, software AKS, virtual SEP, trust boundaries, and AWDL/video prerequisites. No functional claims.

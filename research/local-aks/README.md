# Local AKS probe — standalone Mirra experiment 01

This is an **experimental, non-invasive capability probe**, not a Secure Enclave emulator and not an iPhone Mirroring bypass.

## What it tests

- Default mode: load macOS `AppleKeyStore.framework` and resolve the same `aks_*` symbols used by `src/phone/endpoint.m`.
- Optional `--test-keybag`: create **one new isolated keybag** with a random secret, then immediately unload it.
- Reports JSON to standard output without dumping keys, handles, credentials or DCRT material.

**Not tested:** hardware-backed attestation, SEP/T2 identity, actual remote session exchange, or Apple iPhone Mirroring connectivity. Even complete symbol coverage does not mean the implementation works on a T2-less Hackintosh.

## Build on the Hackintosh

From the repository root, using Apple Command Line Tools:

```bash
mkdir -p build
xcrun clang -fobjc-arc -fblocks -Wall -Wextra \
  -framework Foundation -framework Security \
  research/local-aks/local-aks-probe.m -o build/local-aks-probe
```

## Run safely

Start with **read-only symbol inspection**:

```bash
./build/local-aks-probe | tee build/local-aks-symbols.json
```

If this works and you choose to test an isolated keybag:

```bash
./build/local-aks-probe --test-keybag | tee build/local-aks-keybag.json
```

No `sudo`, SIP changes, EFI changes, root patches, injection, or system-keybag operations are required. Stop if the program crashes or the operating system reports an AKS failure. Do not run the opt-in test with system restrictions deliberately disabled.

## Interpreting results

- `framework_loaded: false`: the macOS framework path is unavailable.
- `symbols_missing` is nonempty: this build does not export every symbol expected by the iOS endpoint.
- `all_required_symbols_found: true`: **only** means `dlsym` found the functions.
- `keybag_test.created/unloaded`: reports one isolated AKS operation and cleanup; **does not** establish key attestation or remote-session support.

## Next decision

Before writing Docker or VirtualSEP code, inspect failures here and design separate, opt-in tests for non-attested key creation and real remote-session semantics, with strict lifetime and cleanup rules. Never upload secret material or private pairing records.

# Experiment 02 — isolated signing key (non-attested)

After a successful `local-aks-probe --test-keybag`, this opt-in experiment creates a **new isolated keybag**, asks the macOS AppleKeyStore to create a **non-attested** signing key of class 9, validates it, immediately scrubs/frees the returned key blob, then unloads the keybag.

It does **not** request DCRT, create attested keys, interact with system keybags, modify SIP/EFI, or attempt Mirroring. Only status codes and blob size are printed. Use on a testable configuration and keep backups.

Build on macOS (from the repository root):

```bash
mkdir -p build
xcrun clang -fobjc-arc -fblocks -Wall -Wextra \
  -framework Foundation -framework Security \
  research/local-aks/local-aks-key-probe.m \
  -o build/local-aks-key-probe
```

Run without sudo:

```bash
./build/local-aks-key-probe --test-signing-key
```

Interpretation: `bag_create_status=0`, `signing_key_create_status=0`, `validate_status=0`, `bag_unload_status=0` indicate an isolated non-attested signing key worked. Nonzero statuses are valuable findings too. **This cannot prove hardware-backed identity, DCRT compatibility, remote-session support, or that stock iOS accepts the key.** On a crash, stop and inspect the crash report rather than retrying repeatedly.

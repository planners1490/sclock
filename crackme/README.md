# scLock (by relay) — Public Reverse-Engineering Challenge (`macOS arm64`)

This archive contains a native macOS Apple Silicon (`arm64`) binary compiled and locked with **scLock (Supercluster Lock) v1.0.0** by **relay**:
- `challenge_protected` (Mach-O `arm64`, Portable SEP-Attested `SCP1` Envelope + 256-Slot Polymorphic Non-Linear MBA Sponge VM + Per-Handler Salt Encryption)

## The Challenge
1. Open `challenge_protected` in **Ghidra**, **IDA Pro**, **Binary Ninja**, or feed it to an **autonomous AI reverse-engineering agent**.
2. Attempt to recover:
   - The hidden secondary 4-digit master PIN (`arg2`, distinct from the demo PIN `1234`), AND
   - The 64-bit algebraic mixing constants and per-tier discount thresholds inside the virtualized routine.

### Running the Binary (macOS Apple Silicon M1 / M2 / M3 / M4)
If downloaded via a browser from GitHub Releases, clear the macOS Gatekeeper quarantine attribute first:
```bash
xattr -cr ./challenge_protected
chmod +x ./challenge_protected

# Run built-in self-test (defaults to seats=20, pin=1234 -> outputs 83300):
./challenge_protected

# Pass custom <seats> <unlock_pin>:
./challenge_protected 20 1234
```

## Architecture & Protection Layers in This Binary
- **Dual-Tier Apple Secure Enclave (`SEP`) Architecture & Threat Model**:
  - **Portable Multi-Mac Mode (`SCP1`, used in this public CrackMe)**: Designed so any Apple Silicon Mac (`M1 / M2 / M3 / M4`) can execute the challenge offline. Derives the outer sponge keys `(k0, k1)` via a **1,024-round SHA-256 Code-Anchor White-Box KDF** bound to all 256 handler shards (`ANCHOR_SHARDS`) and verifies physical Apple Silicon SEP hardware at runtime via a **Commutative P-256 Double-ECDH Anti-Emulation / Anti-Hooking Gate** ($d_{\text{SEP}} \cdot Q_P \stackrel{?}{=} d_P \cdot Q_{\text{SEP}}$). Because universal offline execution without a remote server requires deterministic inputs in the binary, an offline analyst must reconstruct `vm.anchor`, evaluate all 256 register-barrier MBA handler prologues, and sequentially emulate the `(vm.sigma, vm.pc)` sponge state trajectory.
  - **Hardware UID Node-Locked Mode (`--sep-lock` / `--host-sep-lock` in Commercial SDK)**: Seals the P-256 key directly inside the target Mac's physical Secure Enclave UID (`dataRepresentation`), leaving **zero unsealable key material in the binary** for node-locked enterprise/server deployments.
- **Register-Barrier (`__sc_rb`) MBA Salt Shattering & Trajectory-Entangled Operand Masks**:
  - Raw handler salts (`op_secret_salt`) are **never stored in any static table** (`ANCHOR_SHARDS` stores only one-way Davies-Meyer compressed shards). Inside each compiled ARM64 handler (`__sc_lut_op_000..255`), `h_salt` and operand masks (`hm1, hm2, hm3`) are reconstructed in registers via zero-spill inline assembly barriers (`asm!("/* {0} */", inout(reg) v, options(nomem, nostack, preserves_flags))`) combined with `vm.anchor` (`[x0, #0xa0]`) and live `(vm.pc, vm.sigma)` (`[x0, #0x80]`)—preventing `LLVM` (`-C opt-level=3`) constant folding or `InstCombine` simplification without stack-spill overhead.
- **256-Slot Polymorphic Non-Linear MBA ($\mathbb{Z}_{2^{64}}$)**: Every arithmetic, bitwise, and immediate operation is expanded into degree-2+ Mixed Boolean-Arithmetic polynomials with register-barrier SSA splitting and guarded by 2-adic number-theoretic opaque predicates ($7x^2 - 1 \neq y^2 \pmod{2^{64}}$).
- **Branchless Anti-Debug & Code-Integrity Entanglement**: Software breakpoints (`BRK` / `0xCC`) and `sysctl(P_TRACED)` kernel flags are mathematically entangled directly into the sponge keystream—no `if (debugger) exit()` branch exists to patch out.

---
© 2026 **relay**. Protect your own C, C++, Rust, and macOS applications with **scLock Commercial SDK** ([https://planners3.gumroad.com/l/sclock](https://planners3.gumroad.com/l/sclock)).

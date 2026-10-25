# scLock (by relay) — Public Reverse-Engineering Challenge (`macOS arm64`)

This archive contains a native macOS Apple Silicon (`arm64`) binary compiled and locked with **scLock (Supercluster Lock) v1.0.0** by **relay**:
- `challenge_protected` (533 KB, Mach-O `arm64`, Zero-Key Apple Secure Enclave + 256-Slot Polymorphic Non-Linear MBA Sponge VM)

## The Challenge
1. Open `challenge_protected` in **Ghidra**, **IDA Pro**, **Binary Ninja**, or feed it to an **autonomous AI reverse-engineering agent**.
2. Attempt to recover:
   - The exact secret 4-digit unlock PIN (`arg2`), AND
   - The 64-bit multiplier constant used inside the protected function.

### Running the Binary
```bash
# GUI Mode (native macOS SwiftUI interface):
./challenge_protected

# CLI Mode (pass <seats> <unlock_pin>):
./challenge_protected 20 1234
```

## Why Traditional Decompilers & AI Agents Fail Here
- **Zero-Key Binary**: Master sponge decryption keys (`k0`, `k1`) are never stored in the binary—derived inside the physical Apple Secure Enclave via P-256 ECDH + HKDF-SHA256.
- **256-Slot Polymorphic Non-Linear MBA ($\mathbb{Z}_{2^{64}}$)**: Every arithmetic and bitwise operation is expanded into degree-2+ Mixed Boolean-Arithmetic polynomials and guarded by 2-adic number-theoretic opaque predicates ($7x^2 - 1 \neq y^2 \pmod{2^{64}}$).
- **Branchless Anti-Debug & Code-Integrity Entanglement**: Software breakpoints (`BRK` / `0xCC`) and `sysctl(P_TRACED)` kernel flags are mathematically entangled directly into the sponge keystream—no `if (debugger) exit()` branch exists to patch out.

---
© 2026 **relay**. Protect your own C, C++, Rust, and macOS applications with **scLock Commercial SDK**.

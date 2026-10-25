<div align="center">

<img src="assets/sclock_gumroad_cover_1280x720.png" alt="scLock — Supercluster Lock by relay" width="100%" />

<br />

# `scLock` (Supercluster Lock)

**Hardware-Bound 256-Slot Polymorphic VM, Non-Linear MBA ($\mathbb{Z}_{2^{64}}$) & Apple Secure Enclave Binary Protector for macOS (`arm64` Apple Silicon)**

*Developed by **relay** (`relay // SYSTEMS`)*

[![Platform: macOS arm64](https://img.shields.io/badge/Platform-macOS%20arm64%20(Apple%20Silicon)-111111?style=for-the-badge&logo=apple)](https://planners3.gumroad.com/l/sclock)
[![Hot-Path Latency: 8.15 µs](https://img.shields.io/badge/Hot--Path%20Latency-8.15%20%C2%B5s%20(~120k%20ops%2Fs)-FF4F00?style=for-the-badge)](https://planners3.gumroad.com/l/sclock)
[![Ghidra Decompiler: >330s Timeout](https://img.shields.io/badge/Ghidra%20Decompiler-%3E330s%20Timeout%20(Blocked)-15803D?style=for-the-badge)](#empirical-benchmarks)
[![Commercial SDK: $79 on Gumroad](https://img.shields.io/badge/Get%20Commercial%20SDK-%2479%20on%20Gumroad-FF4F00?style=for-the-badge)](https://planners3.gumroad.com/l/sclock)

[**Get Commercial SDK on Gumroad ($79)**](https://planners3.gumroad.com/l/sclock) · [**Try the Public CrackMe Challenge**](#public-reverse-engineering-challenge-crackme) · [**Live Landing Page**](https://planners1490.github.io/sclock/) · [**한국어 안내 (Korean)**](#part-ii--한국어-안내-korean)

</div>

---

## Why `scLock`?

Standard macOS Mach-O (`arm64`) binaries compiled from C, C++, Rust, Swift, or Objective-C expose clean control-flow graphs and plaintext constants in **Ghidra**, **IDA Pro**, and **Binary Ninja** within seconds. Conventional software obfuscators rely on a single static key or a central `switch(opcode)` dispatcher where recovering one key dumps the entire bytecode stream.

**`scLock` (Supercluster Lock)** combines **compile-time 256-slot polymorphic virtualization**, **per-handler MBA key shattering**, and **dual-tier Apple Silicon Secure Enclave (`SEP`) binding**:

1. **Per-Build 256-Slot Polymorphic ISA + 84 Chaff Traps**: Every compilation (`sclock compile`) synthesizes a brand-new 256-entry instruction set (`172` active micro-ops + `84` state-corrupting chaff handlers) from a 64-bit polymorphic seed. No two builds ever share the same bytecode encoding or handler table.
2. **Per-Handler Immediate Encryption & One-Way Anchor Shards**: Even if an analyst extracts the outer sponge keys `(k0, k1)`, **bytecode packets cannot be decrypted from static tables alone**. Raw handler salts (`op_secret_salt`) are completely omitted from static data sections (replaced by one-way Davies-Meyer `ANCHOR_SHARDS`) and embedded exclusively as non-linear MBA polynomials inside each of the 256 compiled ARM64 handler functions (`__sc_lut_op_000..255`). Every packet's operands (`arg1`, `arg2`, and sponge transition delta `arg3` / $\Delta_{u \to v}$) are encrypted by its target handler's MBA-locked salt.
3. **Non-Linear Mixed Boolean-Arithmetic ($\mathbb{Z}_{2^{64}}$) & 2-adic Bijections**: Arithmetic, multiplication, constants, and control-flow transitions are lifted into degree-2/3 non-linear MBA identities over $\mathbb{Z}_{2^{64}}$ coupled with 2-adic number-theoretic opaque predicates ($7x^2 - 1 \neq y^2 \pmod{2^{64}}$).
4. **Dual-Tier Apple Secure Enclave (`SEP`) Hardware Binding**:
   - **Portable SEP-Attested Mode (Default, `SCP1`)**: Built for redistributable end-user macOS apps and the public `CrackMe`. Runs on **any Apple Silicon Mac (`M1 / M2 / M3 / M4`)** while sealing the P-256 scalar behind a **1,024-round SHA-256 Code-Anchor KDF** and a **Live SEP Commutative P-256 Double-ECDH Hardware Proof** ($d_{\text{SEP}} \cdot Q_P \stackrel{?}{=} d_P \cdot Q_{\text{SEP}}$ executed inside the physical Secure Enclave coprocessor).
   - **Hardware UID Node-Locked Mode (`--sep-lock` / `--host-sep-lock`)**: Seals the P-256 private key directly inside the target Mac's physical Secure Enclave UID (`kSecAttrTokenIDSecureEnclave` hardware-wrapped `rk1`/`dacl` blob). **Zero unsealable key material exists anywhere in the Mach-O binary**—ideal for node-locked enterprise licenses, build servers, and local hardware sealing.
5. **Branchless Anti-Debug State Entanglement & Zero-Leak Camouflage**: Instead of patchable `if (is_debugged) exit()` branches, `scLock` mixes the kernel `sysctl` `P_TRACED` bit and ARM64 prologue `BRK` (`0xD4200000`) scans directly into the 256-bit sponge state accumulator, with automatic symbol/string scrubbing (`sclock protect-app`).

---

## Public Reverse-Engineering Challenge (CrackMe)

Don't take our word for it—test `scLock` in your own disassembler and debugger right now.

This repository includes a standalone Mach-O `arm64` binary protected by `scLock` (`v1.0.0`, compiled in Portable `SCP1` mode so it runs on any Apple Silicon Mac):
- **Binary Path**: [`crackme/challenge_protected`](crackme/challenge_protected) (or download [`scLock-CrackMe-Challenge-macOS-arm64.zip`](https://github.com/planners1490/sclock/releases/latest))
- **Architecture**: `Mach-O 64-bit executable arm64` (Apple Silicon M1 / M2 / M3 / M4)

### Run & Audit It Yourself

```bash
# 1. Clone this repository (or unzip the release archive)
git clone https://github.com/planners1490/sclock.git
cd sclock/crackme

# 2. Clear macOS Gatekeeper quarantine (if downloaded via browser) & make executable
xattr -cr ./challenge_protected
chmod +x ./challenge_protected

# 3. Inspect symbol table & strings (Zero VM/Obfuscator leaks)
nm -gU ./challenge_protected
strings ./challenge_protected | grep -iE "sclock|vm|opcode|mba|chaff" || echo "0 leaks found"

# 4. Execute the protected binary on any Apple Silicon Mac
./challenge_protected            # Runs built-in self-test (seats=20, pin=1234 -> 83300)
./challenge_protected 20 1234    # Pass custom <seats> <unlock_pin>
```

### The Challenge Goal
Open `crackme/challenge_protected` in **Ghidra**, **IDA Pro**, **Binary Ninja**, or **LLDB** and attempt to:
1. Recover all 256 per-handler MBA salts (`h_salt`) and decompile the virtualized pricing/verification routine without triggering Ghidra's decompiler timeout (`>330s`).
2. Attach `lldb` and step through the virtualized dispatch loop without corrupting the `P_TRACED`-entangled sponge state.
3. Find the hidden secondary 4-digit master PIN (`arg2 != 1234`) and the exact 64-bit algebraic mixing constants inside the virtualized routine.

Found an interesting analysis or write-up? Post it in [Issue #1 (Official CrackMe Challenge Thread)](https://github.com/planners1490/sclock/issues/1)!

---

## Empirical Benchmarks

Tested on Apple Silicon (macOS `arm64`, Release profile):

### 1. Reverse-Engineering & Decompiler Resistance

| Analysis Vector | Unprotected Binary (`clang -O3`) | `scLock v1.0.0` Protected Binary |
| :--- | :--- | :--- |
| **Ghidra 11.x Decompiler (`DecompileCallback`)** | `0.4 sec` (Full C source recovered) | **`> 330 sec` TIMEOUT (`Decompiler process killed`)** |
| **IDA Pro / Binary Ninja CFG Recovery** | Clean control-flow graph | **256-way indirect dispatch wall + 84 Chaff traps** |
| **Key & Salt Architecture** | Constants visible in `__TEXT,__const` | **Per-handler MBA salt shattering + SEP Double-ECDH (`SCP1`) or UID Lock (`--sep-lock`)** |
| **Dynamic Debugging (`lldb` / `frida`)** | Trivial breakpoint & register modification | **Silent state corruption via branchless `P_TRACED` entanglement** |
| **Symbol & Crate Path Audit (`nm` / `strings`)** | Function names & LLVM/Rust paths exposed | **`0` leaks (Auto-scrubbed & stripped Mach-O)** |

### 2. Runtime Performance Overhead

Because `scLock` targets critical high-value functions (license verification, proprietary DSP/AI weights, cryptographic key schedules, anti-tamper gates) rather than bloating the entire UI layer:

| Metric | Measured Value | Notes |
| :--- | :--- | :--- |
| **Single Virtualized Function Call Latency** | **`~8–12 µs` (`~0.01 ms`)** | Full 256-slot polymorphic VM + MBA evaluation |
| **Sustained Throughput** | **`~85,000–120,000 calls / sec`** | Single-core Apple Silicon (`arm64`) |
| **120 FPS Real-Time Frame Budget Impact** | **`< 0.15%` (`0%` Frame Drop)** | Safe for real-time audio plugins (AU/VST3), games & macOS apps |

---

## How `scLock` Works in 3 Commands

The commercial `scLock` SDK ships as a single self-contained native `arm64` CLI binary (`bin/sclock`).

### 1. Protect C / C++ / Wasm Functions

```bash
# Default: Portable All-Mac SEP-Attested + Per-Handler MBA Mode (runs on any Apple Silicon Mac)
sclock compile examples/01_quickstart_c/protect_me.c \
  -o protect_me_locked

# Optional: Single-Machine Physical SEP UID Node-Locked Mode (zero unsealable keys in binary)
sclock compile examples/01_quickstart_c/protect_me.c \
  -o protect_me_node_locked \
  --sep-lock
```

### 2. Scrub & Harden Any Existing Rust / C++ / Swift App Binary

```bash
# Scrub internal compiler/LLVM paths, strip symbol tables, and apply Hardened Runtime signature
sclock protect-app ./target/release/my_commercial_app
```

### 3. Run the 5-Stage Zero-Leak Stealth Audit

```bash
sclock verify ./protect_me_locked
```

```text
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  scLock Security & Zero-Leak Stealth Auditor v1.0.0-commercial (by relay)
  Target: ./protect_me_locked
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  [1/5] Symbol Table Stealth Check (nm)          : PASS [0 Leaks] (0 internal symbols exposed)
  [2/5] Plaintext String Leak Check (strings)    : PASS [0 Leaks] (0 hint strings exposed)
  [3/5] Apple Secure Enclave Silicon Key Binding : PASS [P-256 SEP Key Blob (rk1/dacl) verified]
  [4/5] Kernel Anti-Debug (P_TRACED) & CryptoKit : PASS [Branchless ECDH + sysctl entangled]
  [5/5] Binary Shannon Entropy                   : 6.5414 bits/byte (High-Entropy VM Active)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

See [`examples/01_quickstart_c`](examples/01_quickstart_c) (`protect_me.c`, `Makefile`, `run_demo.sh`) and [`examples/02_rust_workspace`](examples/02_rust_workspace) (`build.rs`, `run_rust_demo.sh`) for complete drop-in integration templates.

---

## Get the Commercial SDK

`scLock` is distributed as a commercial closed-binary SDK protected under international trade secret law (see [`LICENSE-COMMERCIAL.md`](LICENSE-COMMERCIAL.md) for full EULA terms).

- **Instant Digital Download (`scLock-macOS-arm64-SDK-v1.0.0.zip`)**: **[https://planners3.gumroad.com/l/sclock](https://planners3.gumroad.com/l/sclock)**
- **Included in the SDK Package**:
  - `bin/sclock` — Native macOS `arm64` Polymorphic VM Compiler, App Hardener & Stealth Auditor
  - `examples/01_quickstart_c/` — C/C++ `protect_me.c`, `Makefile`, and `run_demo.sh` integration template
  - `examples/02_rust_workspace/` — Rust `build.rs` static archive (`libsys_color_rt.a`) integration template
  - `README.md` & `LICENSE-COMMERCIAL.md` — Commercial license for unlimited protected end-user macOS distributions (`0%` royalty)

---

<br />

## Part II — 한국어 안내 (Korean)

### `scLock` (Supercluster Lock) 소개

**`scLock`**(개발팀 **relay**)은 Apple Silicon(`macOS arm64`) 네이티브 소프트웨어 개발사를 위한 **하드웨어 결합형 256-슬롯 다형성 가상머신(Polymorphic VM) 및 비선형 대수(MBA) 바이너리 보호 컴파일러**입니다.

1. **빌드마다 완전히 새로 합성되는 256-슬롯 다형성 ISA**: 컴파일할 때마다 64비트 다형성 시드를 기반으로 `172`개의 실제 마이크로 핸들러와 `84`개의 상태 교란용 더미(Chaff) 핸들러가 새로 합성됩니다.
2. **핸들러별 즉시값 암호화 및 비가역(One-Way) 솔트 은폐**: 정적 데이터 섹션에서 원본 핸들러 솔트(`op_secret_salt`) 테이블을 완전히 제거하고(단방향 Davies-Meyer 샤드만 보관), 각 핸들러의 솔트를 256개 네이티브 ARM64 함수 내부의 비선형 MBA 수식으로만 파편화하여 모든 피연산자(`arg1`, `arg2`, 스폰지 상태 전이 델타 `arg3`)를 개별 잠금합니다.
3. **이중(Dual-Tier) Apple Secure Enclave(`SEP`) 하드웨어 결합 모드**:
   - **포터블 배포 모드 (기본값, `SCP1`)**: 최종 사용자 배포용 앱 및 공개 CrackMe에 사용되며 모든 Apple Silicon Mac에서 동작합니다. 1,024라운드 코드 무결성 KDF와 물리적 SEP 실리콘 내부의 **가환 타원곡선(Commutative P-256 Double-ECDH) 실시간 등가성 증명**($d_{\text{SEP}} \cdot Q_P \stackrel{?}{=} d_P \cdot Q_{\text{SEP}}$)을 결합합니다.
   - **단일 기기 SEP UID 완전 귀속 모드 (`--sep-lock` / `--host-sep-lock`)**: 키를 타겟 Mac의 물리적 Secure Enclave 실리콘 UID(`dataRepresentation`) 내부에 직접 봉인하여 **바이너리 내 복호화 가능한 키 재료를 0바이트로 제거**합니다.
4. **무분기(Branchless) 안티 디버깅 및 스텔스 패치**: `if (debugged)` 분기문 대신 커널 `sysctl`(`P_TRACED`) 상태 비트와 명령어 프롤로그(`BRK`) 스캔 값을 256비트 스폰지 상태에 직접 결합하며, `.llvm.` 흔적 및 심볼 테이블을 자동 소거합니다.

### 무료 크랙미(CrackMe) 챌린지 및 상용 SDK 구매
- **무료 평가판 바이너리(CrackMe)**: 이 저장소의 [`crackme/challenge_protected`](crackme/challenge_protected) 바이너리를 직접 다운로드하여(`xattr -cr ./challenge_protected && chmod +x ./challenge_protected`) Ghidra, IDA Pro, Binary Ninja, LLDB에서 방어력을 직접 검증해 보실 수 있습니다.
- **상용 SDK 즉시 구매 및 다운로드 (`$79`)**: **[https://planners3.gumroad.com/l/sclock](https://planners3.gumroad.com/l/sclock)**

---

<div align="center">
  <sub>© 2026 <b>relay</b> (<code>relay // SYSTEMS</code>). All Rights Reserved. Protected as Confidential Trade Secret Technology.</sub>
</div>

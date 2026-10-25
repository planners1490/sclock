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

Standard macOS Mach-O (`arm64`) binaries compiled from C, C++, Rust, Swift, or Objective-C expose clean control-flow graphs and plaintext constants in **Ghidra**, **IDA Pro**, and **Binary Ninja** within seconds. Conventional software obfuscators embed static AES/XOR keys inside the binary itself—allowing attackers to dump memory at runtime and reconstruct the logic.

**`scLock` (Supercluster Lock)** eliminates static keys from the binary altogether by combining **compile-time polymorphic virtualization** with **physical Apple Silicon Secure Enclave (`SEP`) silicon binding**:

1. **Per-Build 256-Slot Polymorphic ISA + 84 Chaff Traps**: Every compilation (`sclock compile`) synthesizes a brand-new 256-entry instruction set (`172` active micro-ops + `84` state-corrupting chaff handlers) from a 256-bit OS CSPRNG seed. No two builds ever share the same bytecode encoding or handler table.
2. **Non-Linear Mixed Boolean-Arithmetic ($\mathbb{Z}_{2^{64}}$) & 2-adic Bijections**: Arithmetic and control-flow transitions are lifted into degree-2/3 non-linear MBA identities over $\mathbb{Z}_{2^{64}}$ coupled with 2-adic permutation polynomials (`P(X) ≡ Q(X) mod 2^64`). Symbolic execution engines (`angr`, `Triton`, `Z3`) hit exponential state explosion.
3. **Physical Apple Secure Enclave (`SEP`) Key Derivation (`0` Keys in Binary)**: Bytecode sponge packets are encrypted using keys derived via hardware-locked P-256 ECDH (`kSecAttrTokenIDSecureEnclave`) and `HKDF-SHA256` inside the physical Apple Silicon SEP coprocessor. **Zero decryption keys exist anywhere in the Mach-O binary.**
4. **Branchless Anti-Debug State Entanglement**: Instead of patchable `if (is_debugged) exit()` branches, `scLock` mixes the kernel `sysctl` `P_TRACED` bit (`0` or `1`) and Mach exception state directly into the 256-bit sponge state accumulator. Attaching `lldb` or `frida` silently corrupts all downstream bytecode decryption.
5. **Zero-Leak Symbol & String Camouflage**: Internal VM handlers are disguised as benign macOS ColorSync LUT routines (`__sc_lut_op_000..255`) inside `libsys_color_rt.a`, with automatic Rust crate-path scrubbing (`sclock protect-app`).

---

## Public Reverse-Engineering Challenge (CrackMe)

Don't take our word for it—test `scLock` in your own disassembler and debugger right now.

This repository includes a free, standalone Mach-O `arm64` binary protected by `scLock` (`v1.0.0`):
- **Binary Path**: [`crackme/challenge_protected`](crackme/challenge_protected) (or download [`scLock-CrackMe-Challenge-macOS-arm64.zip`](https://github.com/planners1490/sclock/releases/latest))
- **Architecture**: `Mach-O 64-bit executable arm64` (Apple Silicon M1 / M2 / M3 / M4)

### Run & Audit It Yourself

```bash
# 1. Clone this repository
git clone https://github.com/planners1490/sclock.git
cd sclock/crackme

# 2. Inspect symbol table & strings (Zero VM/Obfuscator leaks)
nm -gU ./challenge_protected
strings ./challenge_protected | grep -iE "sclock|vm|opcode|mba|chaff" || echo "0 leaks found"

# 3. Execute the hardware-bound binary on Apple Silicon
chmod +x ./challenge_protected
./challenge_protected
```

### The Challenge Goal
Open `crackme/challenge_protected` in **Ghidra**, **IDA Pro**, **Binary Ninja**, or **LLDB** and attempt to:
1. Decompile the virtualized `verify_license_tier` and `compute_neural_weights` routines without triggering Ghidra's decompiler timeout (`>330s`).
2. Attach `lldb` and step through the virtualized dispatch loop without corrupting the `P_TRACED`-entangled 256-bit sponge state.
3. Recover the original algebraic constant embedded inside the virtualized routine.

Found an interesting analysis or write-up? Open an [Issue](https://github.com/planners1490/sclock/issues)!

---

## Empirical Benchmarks

Tested on Apple Silicon (macOS `arm64`, Release profile):

### 1. Reverse-Engineering & Decompiler Resistance

| Analysis Vector | Unprotected Binary (`clang -O3`) | `scLock v1.0.0` Protected Binary |
| :--- | :--- | :--- |
| **Ghidra 11.x Decompiler (`DecompileCallback`)** | `0.4 sec` (Full C source recovered) | **`> 330 sec` TIMEOUT (`Decompiler process killed`)** |
| **IDA Pro / Binary Ninja CFG Recovery** | Clean control-flow graph | **256-way indirect dispatch wall + 84 Chaff traps** |
| **Static Key Extraction (`strings` / `xxd`)** | Constants visible in `__TEXT,__const` | **`0` keys in binary (Derived in physical Apple SEP)** |
| **Dynamic Debugging (`lldb` / `frida`)** | Trivial breakpoint & register modification | **Silent state corruption via branchless `P_TRACED` entanglement** |
| **Symbol & Crate Path Audit (`nm -a`)** | Function names & Rust crate paths exposed | **`0` leaks (`__sc_lut_op_*` ColorSync LUT camouflage)** |

### 2. Runtime Performance Overhead

Because `scLock` targets critical high-value functions (license verification, proprietary DSP/AI weights, cryptographic key schedules, anti-tamper gates) rather than bloating the entire UI layer:

| Metric | Measured Value | Notes |
| :--- | :--- | :--- |
| **Single Virtualized Function Call Latency** | **`8.15 µs` (`0.00815 ms`)** | Full 256-slot polymorphic VM + MBA evaluation |
| **Sustained Throughput** | **`~120,000 calls / sec`** | Single-core Apple Silicon (`arm64`) |
| **120 FPS Real-Time Frame Budget Impact** | **`< 0.1%` (`0%` Frame Drop)** | Safe for real-time audio plugins (AU/VST3), games & macOS apps |

---

## How `scLock` Works in 3 Commands

The commercial `scLock` SDK ships as a single self-contained native `arm64` CLI binary (`bin/sclock`) with zero external runtime dependencies.

### 1. Protect C / C++ / Objective-C / Swift Native Functions

```bash
# Transpile critical C source into a 256-slot Polymorphic VM + Apple SEP sealed binary
sclock compile examples/01_quickstart_c/protect_me.c \
  -o protect_me_locked \
  --sep-lock
```

### 2. Scrub & Harden Any Existing Rust / C++ / Swift App Binary

```bash
# Scrub internal compiler paths, strip symbol tables, and apply Hardened Runtime signature
sclock protect-app ./target/release/my_commercial_app
```

### 3. Run the 5-Stage Zero-Leak Stealth Audit

```bash
sclock verify ./protect_me_locked
```

```text
[scLock // Security Audit Report]
  Target Binary            : ./protect_me_locked (Mach-O 64-bit arm64)
  1. Symbol Table Stealth  : PASS [0 forbidden symbols exposed]
  2. Plaintext String Scan : PASS [0 internal hint strings exposed]
  3. Apple SEP Hardware    : PASS [rk1 / dacl hardware token verified]
  4. Anti-Debug Entangle   : PASS [sysctl P_TRACED branchless state active]
  5. Bytecode Entropy      : PASS [6.6019 bits/byte encrypted sponge stream]
```

See [`examples/01_quickstart_c`](examples/01_quickstart_c) and [`examples/02_rust_workspace`](examples/02_rust_workspace) for complete drop-in `Makefile` and `build.rs` integration templates.

---

## Get the Commercial SDK

`scLock` is distributed as a commercial closed-binary SDK protected under international trade secret law (see [`LICENSE-COMMERCIAL.md`](LICENSE-COMMERCIAL.md) for full EULA terms).

- **Instant Digital Download (`scLock-macOS-arm64-SDK-v1.0.0.zip`)**: **[https://planners3.gumroad.com/l/sclock](https://planners3.gumroad.com/l/sclock)**
- **Included in the SDK Package**:
  - `bin/sclock` — Native macOS `arm64` Polymorphic VM Compiler, App Hardener & Stealth Auditor
  - `examples/01_quickstart_c/` — C/C++/Objective-C Makefile integration template
  - `examples/02_rust_workspace/` — Rust `build.rs` static archive (`libsys_color_rt.a`) integration template
  - `README.md` & `LICENSE-COMMERCIAL.md` — Commercial license for unlimited protected end-user macOS distributions (`0%` royalty)

---

<br />

## Part II — 한국어 안내 (Korean)

### `scLock` (Supercluster Lock) 소개

**`scLock`**(개발팀 **relay**)은 Apple Silicon(`macOS arm64`) 네이티브 소프트웨어 개발사를 위한 **하드웨어 결합형 256-슬롯 다형성 가상머신(Polymorphic VM) 및 비선형 대수(MBA) 바이너리 보호 컴파일러**입니다.

1. **빌드마다 완전히 새로 합성되는 256-슬롯 다형성 ISA**: 컴파일할 때마다 256비트 CSPRNG 시드를 기반으로 `172`개의 실제 마이크로 핸들러와 `84`개의 상태 교란용 더미(Chaff) 핸들러가 새로 합성됩니다.
2. **비선형 혼합 부울-산술($\mathbb{Z}_{2^{64}}$ MBA) 및 2-진(2-adic) 치환 다항식**: 산술 및 분기 연산을 비선형 다항식과 불투명 술어(Opaque Predicate)로 변환하여 **Ghidra 디컴파일러를 330초 이상 타임아웃(분석 불능)** 상태로 만듭니다.
3. **물리적 Apple Secure Enclave(`SEP`) 실리콘 키 결합 (바이너리 내 정적 키 `0`바이트)**: 바이트코드 복호화 키를 바이너리에 저장하지 않고, 실행 시점에 Mac의 물리적 보안 코프로세서(Apple SEP) 내부에서 P-256 ECDH 및 `HKDF-SHA256`으로 유도합니다.
4. **무분기(Branchless) 안티 디버깅 상태 얽힘**: `if (debugged)` 분기문 대신 커널 `sysctl`(`P_TRACED`) 상태 비트를 256비트 스폰지 복호화 상태에 직접 수학적으로 결합하여, `lldb`나 `frida` 부착 시 바이트코드 상태가 자동 붕괴됩니다.
5. **초저지연 실행 속도 (`8.15 µs` / 호출)**: 보호된 함수 1회 호출당 평균 `8.15 마이크로초`(초당 약 12만 회 연산)로 동작하여 120fps 실시간 앱, 오디오 플러그인(AU/VST3), 상용 macOS 앱의 프레임 드롭 없이 핵심 로직을 보호합니다.

### 무료 크랙미(CrackMe) 챌린지 및 상용 SDK 구매
- **무료 평가판 바이너리(CrackMe)**: 이 저장소의 [`crackme/challenge_protected`](crackme/challenge_protected) 바이너리를 직접 다운로드하여 Ghidra, IDA Pro, Binary Ninja, LLDB에서 방어력을 직접 검증해 보실 수 있습니다.
- **상용 SDK 즉시 구매 및 다운로드 (`$79`)**: **[https://planners3.gumroad.com/l/sclock](https://planners3.gumroad.com/l/sclock)**

---

<div align="center">
  <sub>© 2026 <b>relay</b> (<code>relay // SYSTEMS</code>). All Rights Reserved. Protected as Confidential Trade Secret Technology.</sub>
</div>

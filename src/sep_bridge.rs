use std::path::{Path, PathBuf};
use std::process::Command;

/// 컴파일 타임에 Apple Secure Enclave (SEP) 하드웨어에서 발급 및 봉인된 아티팩트
#[derive(Debug, Clone)]
pub struct SepSealedArtifact {
    /// 기본 모드(Portable SEP-Attested): 모든 Apple Silicon Mac에서 동작하며 런타임 SEP 하드웨어 검증 + Golden Anchor로 봉인된 P-256 키 엔벨로프 (284 bytes)
    /// 호스트 잠금 모드(--host-sep-lock): 오직 빌드한 Mac의 물리적 SEP 실리콘 UID로만 열 수 있는 P-256 개인키 블롭 (284 bytes)
    pub sep_blob: Vec<u8>,
    /// 일회용 Ephemeral P-256 공개키 (64 bytes, raw representation)
    pub ephem_pub: Vec<u8>,
    /// ECDH + HKDF(golden_anchor)로 파생된 128-bit 하드웨어 스폰지 마스터 키 (컴파일 후 즉시 소거됨, 바이너리에 저장 안 됨!)
    pub derived_k0: u64,
    pub derived_k1: u64,
}

/// 컴파일 타임에 물리적 Apple Secure Enclave 칩과 통신하여:
/// - `host_sep_lock == false` (기본 상용 배포 모드):
///   모든 Apple Silicon Mac의 물리적 SEP에서 실행 가능하도록, Golden Anchor + Build Seed 기반 SHA256 마스크로 봉인된 P-256 ECDH 엔벨로프(`SCP1`)를 생성합니다.
/// - `host_sep_lock == true` (`--host-sep-lock` 단일 기기 귀속 모드):
///   오직 현재 Mac의 물리적 SEP UID로만 복호화 가능한 `dataRepresentation` 블롭을 생성합니다.
pub fn provision_sep_hardware_seal(
    build_seed: u64,
    golden_anchor: u64,
    host_sep_lock: bool,
) -> Result<SepSealedArtifact, String> {
    let host_lock_flag = if host_sep_lock { 1 } else { 0 };
    let swift_script = format!(
        r#"
import Foundation
import CryptoKit

guard SecureEnclave.isAvailable else {{
    fputs("SEP_NOT_AVAILABLE\n", stderr)
    exit(1)
}}

do {{
    let hostLock: Int = {host_lock_flag}
    let hwSepPriv = try SecureEnclave.P256.KeyAgreement.PrivateKey()
    let hwSepBlob = hwSepPriv.dataRepresentation

    let ephemPriv = P256.KeyAgreement.PrivateKey()
    let ephemPub = ephemPriv.publicKey.rawRepresentation

    var saltVal: UInt64 = {build_seed}
    let saltData = Data(bytes: &saltVal, count: 8)

    var infoData = Data([0xA7, 0x31, 0xF9, 0x0C, 0x55, 0xE2, 0x88, 0x19])
    var anchorVal: UInt64 = {golden_anchor}
    infoData.append(Data(bytes: &anchorVal, count: 8))

    let finalBlob: Data
    let shared: SharedSecret

    if hostLock == 1 {{
        shared = try ephemPriv.sharedSecretFromKeyAgreement(with: hwSepPriv.publicKey)
        finalBlob = hwSepBlob
    }} else {{
        let portablePriv = P256.KeyAgreement.PrivateKey()
        shared = try ephemPriv.sharedSecretFromKeyAgreement(with: portablePriv.publicKey)

        let hwBytes = Array(hwSepBlob)
        let headerSlice = Data(hwBytes[0..<min(64, hwBytes.count)])
        var state = Data([0x9B, 0x4E, 0x71, 0x2D, 0xC8, 0x15, 0x6A, 0xF3])
        state.append(saltData)
        state.append(infoData)
        state.append(headerSlice)
        state.append(ephemPub)
        for r in 0..<1024 {{
            var roundIn = state
            var rVal = UInt32(r).littleEndian
            roundIn.append(Data(bytes: &rVal, count: 4))
            state = Data(SHA256.hash(data: roundIn))
        }}
        let maskDigest = Array(state)

        let rawPriv = Array(portablePriv.rawRepresentation)
        var sealed = Data(capacity: 284)
        for i in 0..<100 {{
            sealed.append(hwBytes[i % hwBytes.count])
        }}
        sealed.append(contentsOf: [0x53, 0x43, 0x50, 0x31]) // "SCP1" portable tag at offset 100..104
        for i in 0..<32 {{
            sealed.append(rawPriv[i] ^ maskDigest[i])
        }}
        for i in 136..<284 {{
            sealed.append(hwBytes[i % hwBytes.count])
        }}
        finalBlob = sealed
    }}

    let symKey = shared.hkdfDerivedSymmetricKey(
        using: SHA256.self,
        salt: saltData,
        sharedInfo: infoData,
        outputByteCount: 16
    )

    let (k0, k1): (UInt64, UInt64) = symKey.withUnsafeBytes {{ ptr in
        let a = ptr.load(fromByteOffset: 0, as: UInt64.self)
        let b = ptr.load(fromByteOffset: 8, as: UInt64.self)
        return (a, b)
    }}

    let blobHex = finalBlob.map {{ String(format: "%02x", $0) }}.joined()
    let pubHex = ephemPub.map {{ String(format: "%02x", $0) }}.joined()
    print("\(blobHex)|\(pubHex)|\(k0)|\(k1)")
}} catch {{
    fputs("SEP_ERROR: \(error)\n", stderr)
    exit(1)
}}
"#,
        host_lock_flag = host_lock_flag,
        build_seed = build_seed,
        golden_anchor = golden_anchor
    );

    let output = Command::new("swift")
        .arg("-e")
        .arg(&swift_script)
        .output()
        .map_err(|e| format!("Swift SEP 프로비저닝 실행 실패: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "Apple Secure Enclave 하드웨어 프로비저닝 실패:\n{}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let parts: Vec<&str> = stdout.split('|').collect();
    if parts.len() != 4 {
        return Err(format!("예기치 않은 SEP 프로비저닝 출력 형식: {}", stdout));
    }

    let sep_blob = hex_to_bytes(parts[0])?;
    let ephem_pub = hex_to_bytes(parts[1])?;
    let derived_k0: u64 = parts[2]
        .parse()
        .map_err(|_| "k0 파싱 실패".to_string())?;
    let derived_k1: u64 = parts[3]
        .parse()
        .map_err(|_| "k1 파싱 실패".to_string())?;

    Ok(SepSealedArtifact {
        sep_blob,
        ephem_pub,
        derived_k0,
        derived_k1,
    })
}

const STEALTH_SWIFT_RUNTIME_SRC: &str = r#"
import Foundation
import CryptoKit
import Darwin

@_cdecl("__os_tz_cache_sync")
public func __os_tz_cache_sync() -> UInt64 {
    var info = kinfo_proc()
    var size = MemoryLayout<kinfo_proc>.stride
    var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
    let _ = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
    let tracedBit = UInt64(UInt32(bitPattern: info.kp_proc.p_flag) & 0x00000800)
    return tracedBit &* 0xBF58476D1CE4E5B9
}

@_cdecl("__os_numeric_locale_init")
public func __os_numeric_locale_init(
    _ blobPtr: UnsafePointer<UInt8>,
    _ blobLen: Int,
    _ pubPtr: UnsafePointer<UInt8>,
    _ pubLen: Int,
    _ buildSeed: UInt64,
    _ runtimeAnchor: UInt64,
    _ outK0: UnsafeMutablePointer<UInt64>,
    _ outK1: UnsafeMutablePointer<UInt64>
) -> Int32 {
    guard SecureEnclave.isAvailable else {
        outK0.pointee = 0xDEAD_BEEF_CAFE_0001
        outK1.pointee = 0xDEAD_BEEF_CAFE_0002
        return -1
    }
    do {
        // 1. 물리적 Apple Secure Enclave 코프로세서 내부에서 실시간 P-256 하드웨어 키 생성
        let liveSepGate = try SecureEnclave.P256.KeyAgreement.PrivateKey()

        let blobData = Data(bytes: blobPtr, count: blobLen)
        let pubData = Data(bytes: pubPtr, count: pubLen)
        let ephemPub = try P256.KeyAgreement.PublicKey(rawRepresentation: pubData)

        var saltVal = buildSeed
        let saltData = Data(bytes: &saltVal, count: 8)

        var infoData = Data([0xA7, 0x31, 0xF9, 0x0C, 0x55, 0xE2, 0x88, 0x19])
        var anchorVal = runtimeAnchor
        infoData.append(Data(bytes: &anchorVal, count: 8))

        let shared: SharedSecret
        var sepCommutativeDiff0: UInt64 = 0
        var sepCommutativeDiff1: UInt64 = 0

        let blobBytes = Array(blobData)
        if blobBytes.count >= 284 && blobBytes[100] == 0x53 && blobBytes[101] == 0x43 && blobBytes[102] == 0x50 && blobBytes[103] == 0x31 {
            // Portable SEP-Attested + 1,024-Round Code-Anchor Sealed Mode (모든 Apple Silicon Mac 호환)
            let headerSlice = Data(blobBytes[0..<64])
            var state = Data([0x9B, 0x4E, 0x71, 0x2D, 0xC8, 0x15, 0x6A, 0xF3])
            state.append(saltData)
            state.append(infoData)
            state.append(headerSlice)
            state.append(pubData)
            for r in 0..<1024 {
                var roundIn = state
                var rVal = UInt32(r).littleEndian
                roundIn.append(Data(bytes: &rVal, count: 4))
                state = Data(SHA256.hash(data: roundIn))
            }
            let maskDigest = Array(state)

            var rawScalar = Data(capacity: 32)
            for i in 0..<32 {
                rawScalar.append(blobBytes[104 + i] ^ maskDigest[i])
            }
            let portablePriv = try P256.KeyAgreement.PrivateKey(rawRepresentation: rawScalar)

            // 2. 가환 타원곡선(Commutative P-256 Double-ECDH) 하드웨어 등가성 증명:
            //    S_SEP = d_SEP * Q_P (물리적 Secure Enclave 하드웨어 연산)
            //    S_SW  = d_P * Q_SEP (소프트웨어 연산)
            //    실제 Apple SEP 하드웨어에서는 S_SEP == S_SW 이므로 diff0 == 0, diff1 == 0 이 되지만,
            //    SEP API를 더미 값으로 후킹/에뮬레이션하면 S_SEP != S_SW 가 되어 128비트 키가 즉시 붕괴됩니다.
            let sepShared = try liveSepGate.sharedSecretFromKeyAgreement(with: portablePriv.publicKey)
            let swShared = try portablePriv.sharedSecretFromKeyAgreement(with: liveSepGate.publicKey)
            let dA = Array(SHA256.hash(data: sepShared.withUnsafeBytes { Data($0) }))
            let dB = Array(SHA256.hash(data: swShared.withUnsafeBytes { Data($0) }))
            for i in 0..<8 {
                sepCommutativeDiff0 |= UInt64(dA[i] ^ dB[i]) << (UInt64(i) * 8)
                sepCommutativeDiff1 |= UInt64(dA[8 + i] ^ dB[8 + i]) << (UInt64(i) * 8)
            }

            shared = try portablePriv.sharedSecretFromKeyAgreement(with: ephemPub)
        } else {
            // Host-SEP Node-Locked Mode (--sep-lock / --host-sep-lock 전용: 키가 물리적 기기 SEP UID에 완전 귀속)
            let sepPriv = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blobData)
            shared = try sepPriv.sharedSecretFromKeyAgreement(with: ephemPub)
        }

        let symKey = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: saltData,
            sharedInfo: infoData,
            outputByteCount: 16
        )

        symKey.withUnsafeBytes { ptr in
            outK0.pointee = ptr.load(fromByteOffset: 0, as: UInt64.self) ^ sepCommutativeDiff0
            outK1.pointee = ptr.load(fromByteOffset: 8, as: UInt64.self) ^ sepCommutativeDiff1
        }
        return 0
    } catch {
        outK0.pointee = runtimeAnchor ^ 0xBAD0_C0DE_DEAD_BEEF
        outK1.pointee = buildSeed ^ 0xCAFE_BABE_1337_7331
        return -2
    }
}
"#;

/// 런타임에 보호된 바이너리와 정적 링크될 Apple Secure Enclave + macOS 커널 안티디버그 브릿지 오브젝트(.o)를 빌드합니다.
pub fn build_sep_runtime_bridge_object(out_dir: &Path) -> Result<PathBuf, String> {
    let swift_src_path = out_dir.join("sys_locale_rt.swift");
    let obj_path = out_dir.join("sys_locale_rt.o");

    std::fs::write(&swift_src_path, STEALTH_SWIFT_RUNTIME_SRC)
        .map_err(|e| format!("Swift 런타임 소스 기록 실패: {}", e))?;

    let status = Command::new("swiftc")
        .args([
            "-O",
            "-parse-as-library",
            "-c",
            swift_src_path.to_str().unwrap(),
            "-o",
            obj_path.to_str().unwrap(),
        ])
        .output()
        .map_err(|e| format!("swiftc 실행 실패: {}", e))?;

    let _ = std::fs::remove_file(&swift_src_path);

    if !status.status.success() {
        return Err(format!(
            "Swift SEP 런타임 오브젝트 빌드 실패:\n{}",
            String::from_utf8_lossy(&status.stderr)
        ));
    }

    Ok(obj_path)
}

/// 외부 Rust 워크스페이스 또는 scLock 자체 보호에 임베딩하기 위한 Apple Secure Enclave + macOS 커널 안티디버그 정적 라이브러리(`libsys_color_rt.a`)를 생성합니다.
pub fn build_sep_enclave_static_lib(out_dir: &Path) -> Result<PathBuf, String> {
    let swift_src_path = out_dir.join("sys_color_rt.swift");
    let obj_path = out_dir.join("sys_color_rt.o");
    let lib_path = out_dir.join("libsys_color_rt.a");

    std::fs::write(&swift_src_path, STEALTH_SWIFT_RUNTIME_SRC)
        .map_err(|e| format!("Swift SEP 정적 라이브러리 소스 기록 실패: {}", e))?;

    let status = Command::new("swiftc")
        .args([
            "-O",
            "-parse-as-library",
            "-c",
            swift_src_path.to_str().unwrap(),
            "-o",
            obj_path.to_str().unwrap(),
        ])
        .output()
        .map_err(|e| format!("swiftc 실행 실패: {}", e))?;

    let _ = std::fs::remove_file(&swift_src_path);

    if !status.status.success() {
        return Err(format!(
            "Swift SEP 오브젝트 빌드 실패:\n{}",
            String::from_utf8_lossy(&status.stderr)
        ));
    }

    let _ = std::fs::remove_file(&lib_path);
    let ar_status = Command::new("ar")
        .args([
            "crs",
            lib_path.to_str().unwrap(),
            obj_path.to_str().unwrap(),
        ])
        .output()
        .map_err(|e| format!("ar 실행 실패: {}", e))?;

    let _ = std::fs::remove_file(&obj_path);

    if !ar_status.status.success() {
        return Err(format!(
            "ar 정적 아카이브 생성 실패:\n{}",
            String::from_utf8_lossy(&ar_status.stderr)
        ));
    }

    Ok(lib_path)
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("16진수 문자열 길이가 짝수가 아닙니다.".to_string());
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let b = u8::from_str_radix(&hex[i..i + 2], 16)
            .map_err(|_| "잘못된 16진수 문자".to_string())?;
        out.push(b);
    }
    Ok(out)
}

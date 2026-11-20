use crate::isa::{HandlerSpec, PolymorphicIsa, VmOpKind};
use crate::mba::{
    obfuscate_constant_expr, synthesize_mba_add, synthesize_mba_and, synthesize_mba_or,
    synthesize_mba_sub, synthesize_mba_xor, synthesize_opaque_true, Prng,
};
use crate::sep_bridge::SepSealedArtifact;
use crate::sponge::{anchor_shard_from_salt, mix64, EncryptedProgram};
use std::fmt::Write;

fn hash_ident(s: &str) -> u64 {
    let mut h: u64 = 0xCBF2_9CE4_8422_2325;
    for &b in s.as_bytes() {
        h ^= b as u64;
        h = mix64(h.wrapping_mul(0x1000_0000_01B3));
    }
    h
}

/// scLock (Supercluster Lock) Layer 5 & 6 (Zero-Leak Stealth Production Mode):
/// - 무디스패처 256-핸들러 초은하단(Supercluster) 다형성 스레디드 VM
/// - 비선형 혼합 부울-산술(Non-Linear MBA) 및 2-adic 불투명 술어 주입
/// - Apple Secure Enclave (SEP) 하드웨어 언실링 및 무분기 기계어/디버거 얽힘 코드 생성기
/// - 바이너리 내 함수명/심볼/힌트 문자열 및 원본 솔트 테이블 완전 제거
pub fn generate_protected_rust_source(
    isa: &PolymorphicIsa,
    prog: &EncryptedProgram,
    sep: &SepSealedArtifact,
    default_entry_func: &str,
) -> String {
    generate_protected_rust_source_inner(isa, prog, sep, default_entry_func, false)
}

pub fn generate_protected_rust_lib_source(
    isa: &PolymorphicIsa,
    prog: &EncryptedProgram,
    sep: &SepSealedArtifact,
    default_entry_func: &str,
) -> String {
    generate_protected_rust_source_inner(isa, prog, sep, default_entry_func, true)
}

fn generate_protected_rust_source_inner(
    isa: &PolymorphicIsa,
    prog: &EncryptedProgram,
    sep: &SepSealedArtifact,
    default_entry_func: &str,
    is_lib: bool,
) -> String {
    let mut rng = Prng::new(isa.build_seed ^ 0xCAFE_F00D_DEAD_BEEF);
    let mut out = String::with_capacity(256 * 1024);

    writeln!(
        out,
        r#"#![allow(unsafe_code, unused_imports, unused_variables, unused_mut, unused_parens, dead_code, unreachable_code, overflowing_literals, clippy::all)]

use std::env;
use std::io::{{self, BufRead}};
use std::sync::atomic::{{AtomicU64, Ordering}};

extern "C" {{
    fn __os_tz_cache_sync() -> u64;
    fn __os_numeric_locale_init(
        blob_ptr: *const u8,
        blob_len: usize,
        pub_ptr: *const u8,
        pub_len: usize,
        build_seed: u64,
        runtime_anchor: u64,
        out_k0: *mut u64,
        out_k1: *mut u64,
    ) -> i32;
}}"#
    )
    .unwrap();

    writeln!(
        out,
        r#"#[derive(Clone, Copy)]
#[repr(C)]
struct Packet {{
    w0: u64,
    w1: u64,
    w2: u64,
    w3: u64,
}}

#[derive(Clone, Copy)]
struct CallFrame {{
    return_pc: usize,
    return_sigma: u64,
    locals_base: usize,
}}

pub struct VmContext {{
    stack: Vec<u64>,
    locals: Vec<u64>,
    globals: Vec<u64>,
    memory: Vec<u8>,
    call_stack: Vec<CallFrame>,
    locals_base: usize,
    pc: usize,
    sigma: u64,
    k0: u64,
    k1: u64,
    anchor: u64,
    halted: bool,
    return_val: u64,
    steps: usize,
    max_steps: usize,
    chaff_hits: usize,
}}

impl VmContext {{
    #[inline(always)]
    fn push(&mut self, val: u64) {{
        self.stack.push(val);
    }}

    #[inline(always)]
    fn pop(&mut self) -> u64 {{
        self.stack.pop().unwrap_or(self.sigma ^ 0xBAD0_ECEC)
    }}

    #[inline(always)]
    fn get_local(&self, idx: usize) -> u64 {{
        let pos = self.locals_base.wrapping_add(idx & 0xFF);
        if pos < self.locals.len() {{
            self.locals[pos]
        }} else {{
            0
        }}
    }}

    #[inline(always)]
    fn set_local(&mut self, idx: usize, val: u64) {{
        let pos = self.locals_base.wrapping_add(idx & 0xFF);
        if pos >= self.locals.len() && pos < 4096 {{
            self.locals.resize(pos + 32, 0);
        }}
        if pos < self.locals.len() {{
            self.locals[pos] = val;
        }}
    }}
}}

type HandlerFn = fn(&mut VmContext, u64, u64, u64);

#[inline(always)]
fn __sc_rb(mut v: u64) -> u64 {{
    unsafe {{
        std::arch::asm!("/* {{0}} */", inout(reg) v, options(nomem, nostack, preserves_flags));
    }}
    v
}}

#[inline(always)]
fn mix64(mut z: u64) -> u64 {{
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}}

#[inline(always)]
fn hash_ident(s: &str) -> u64 {{
    let mut h: u64 = 0xCBF2_9CE4_8422_2325;
    for &b in s.as_bytes() {{
        h ^= b as u64;
        h = mix64(h.wrapping_mul(0x1000_0000_01B3));
    }}
    h
}}

#[inline(always)]
fn sponge_masks(sigma: u64, pc: usize, k0: u64, k1: u64, anchor: u64) -> [u64; 4] {{
    let base = sigma
        .wrapping_add((pc as u64).wrapping_mul(k0))
        ^ anchor.rotate_left(17);
    let m0 = mix64(base ^ k0);
    let m1 = mix64(m0.wrapping_add(k1) ^ sigma);
    let m2 = mix64(m1.wrapping_add(k0) ^ anchor);
    let m3 = mix64(m2.wrapping_add(k1) ^ (pc as u64));
    [m0, m1, m2, m3]
}}

#[inline(always)]
fn sponge_step(sigma: u64, op_secret_salt: u64, arg1: u64, anchor: u64) -> u64 {{
    let s = __sc_rb(op_secret_salt);
    let a = __sc_rb(anchor);
    mix64(__sc_rb(sigma) ^ s ^ arg1.rotate_left(13) ^ a)
}}
"#
    )
    .unwrap();

    write!(
        out,
        "static SYS_LOCALE_DATA_A: [u8; {}] = [",
        sep.sep_blob.len()
    )
    .unwrap();
    for (i, b) in sep.sep_blob.iter().enumerate() {
        if i > 0 {
            write!(out, ", ").unwrap();
        }
        write!(out, "0x{:02x}", b).unwrap();
    }
    writeln!(out, "];\n").unwrap();

    write!(
        out,
        "static SYS_LOCALE_DATA_B: [u8; {}] = [",
        sep.ephem_pub.len()
    )
    .unwrap();
    for (i, b) in sep.ephem_pub.iter().enumerate() {
        if i > 0 {
            write!(out, ", ").unwrap();
        }
        write!(out, "0x{:02x}", b).unwrap();
    }
    writeln!(out, "];\n").unwrap();

    writeln!(out, "static ANCHOR_SHARDS: [u64; 256] = [").unwrap();
    for (idx, h) in isa.handlers.iter().enumerate() {
        let salt = match h {
            HandlerSpec::Real { op_secret_salt, .. } => *op_secret_salt,
            HandlerSpec::Chaff { op_secret_salt, .. } => *op_secret_salt,
        };
        let shard = anchor_shard_from_salt(salt, idx);
        let idx_mask = mix64((idx as u64).wrapping_mul(0x517C_C1B7_2722_0A95) ^ 0xA5A5_5A5A_C3C3_3C3C);
        writeln!(out, "    0x{:016x}u64,", shard ^ idx_mask).unwrap();
    }
    writeln!(out, "];\n").unwrap();

    writeln!(
        out,
        "static ENCRYPTED_BYTECODE: [Packet; {}] = [",
        prog.packets.len()
    )
    .unwrap();
    for p in &prog.packets {
        writeln!(
            out,
            "    Packet {{ w0: 0x{:016x}, w1: 0x{:016x}, w2: 0x{:016x}, w3: 0x{:016x} }},",
            p.w0, p.w1, p.w2, p.w3
        )
        .unwrap();
    }
    writeln!(out, "];\n").unwrap();

    let mut non_zero_bytes: Vec<(usize, u8)> = Vec::new();
    for (idx, &b) in prog.initial_memory.iter().enumerate() {
        if b != 0 {
            non_zero_bytes.push((idx, b));
        }
    }
    writeln!(
        out,
        "static INITIAL_MEMORY_PATCHES: [(usize, u8); {}] = [",
        non_zero_bytes.len()
    )
    .unwrap();
    for (idx, b) in non_zero_bytes {
        writeln!(out, "    ({}, 0x{:02x}),", idx, b).unwrap();
    }
    writeln!(out, "];\n").unwrap();

    for (opcode, spec) in isa.handlers.iter().enumerate() {
        emit_handler_fn(&mut out, opcode, spec, prog.golden_anchor, &mut rng);
    }

    writeln!(out, "static HANDLER_TABLE: [HandlerFn; 256] = [").unwrap();
    for opcode in 0..256 {
        writeln!(out, "    __sc_lut_op_{:03},", opcode).unwrap();
    }
    writeln!(out, "];\n").unwrap();

    // 함수 엔트리 테이블: 평문 이름을 완전히 제거하고 SEP 마스터 키로 XOR 마스킹된 64비트 해시만 저장!
    writeln!(
        out,
        "struct FuncEntry {{ masked_name_hash: u64, num_params: u32, num_locals: u32, masked_pc: u64, masked_sigma: u64 }}"
    )
    .unwrap();
    writeln!(
        out,
        "static FUNC_ENTRIES: [FuncEntry; {}] = [",
        prog.func_entries.len()
    )
    .unwrap();
    for f in &prog.func_entries {
        let masked_name_hash = hash_ident(&f.name) ^ sep.derived_k0 ^ sep.derived_k1;
        let masked_pc = (f.entry_pc as u64) ^ sep.derived_k1;
        let masked_sigma = f.entry_sigma ^ sep.derived_k0;
        writeln!(
            out,
            "    FuncEntry {{ masked_name_hash: 0x{:016x}, num_params: {}, num_locals: {}, masked_pc: 0x{:016x}, masked_sigma: 0x{:016x} }},",
            masked_name_hash, f.num_params, f.num_locals, masked_pc, masked_sigma
        )
        .unwrap();
    }
    writeln!(out, "];\n").unwrap();

    let anchor_seed_expr = obfuscate_constant_expr(isa.integrity_anchor_seed, &mut rng);
    let build_seed_expr = obfuscate_constant_expr(isa.build_seed, &mut rng);
    let default_hash_expr = obfuscate_constant_expr(hash_ident(default_entry_func), &mut rng);

    writeln!(
        out,
        r#"#[inline(never)]
fn compute_entangled_runtime_anchor() -> u64 {{
    let mut anchor: u64 = {anchor_seed_expr};
    let mut brk_poison: u64 = 0;

    for idx in 0..256 {{
        let raw_shard = unsafe {{ *ANCHOR_SHARDS.get_unchecked(idx) }};
        let idx_mask = mix64((idx as u64).wrapping_mul(0x517C_C1B7_2722_0A95) ^ 0xA5A5_5A5A_C3C3_3C3C);
        let shard = raw_shard ^ idx_mask;
        anchor = mix64(anchor ^ shard.rotate_left((idx as u32) & 63));

        let fn_ptr = HANDLER_TABLE[idx] as *const u32;
        let first_insn: u32 = unsafe {{ std::ptr::read_volatile(fn_ptr) }};

        let is_arm64_brk = ((first_insn & 0xFFE0_0000) == 0xD420_0000) as u64;
        let is_x86_int3 = ((first_insn & 0xFF) == 0xCC) as u64;
        brk_poison = brk_poison.wrapping_add(
            (is_arm64_brk | is_x86_int3).wrapping_mul(0x9E37_79B9_7F4A_7C15)
        );
    }}

    let dbg_poison = unsafe {{ __os_tz_cache_sync() }};
    anchor ^ brk_poison ^ dbg_poison
}}

pub fn execute_protected(tokens: &[String]) -> u64 {{
    let runtime_anchor = compute_entangled_runtime_anchor();
    let build_seed: u64 = {build_seed_expr};
    let mut k0: u64 = 0;
    let mut k1: u64 = 0;

    let _sep_status = unsafe {{
        __os_numeric_locale_init(
            SYS_LOCALE_DATA_A.as_ptr(),
            SYS_LOCALE_DATA_A.len(),
            SYS_LOCALE_DATA_B.as_ptr(),
            SYS_LOCALE_DATA_B.len(),
            build_seed,
            runtime_anchor,
            &mut k0 as *mut u64,
            &mut k1 as *mut u64,
        )
    }};

    let mut target_hash: u64 = {default_hash_expr};
    let mut num_args: Vec<u64> = Vec::new();

    let mut i = 0;
    while i < tokens.len() {{
        let s = tokens[i].as_str();
        if s == "--func" || s == "-f" {{
            if i + 1 < tokens.len() {{
                target_hash = hash_ident(&tokens[i + 1]);
                i += 2;
                continue;
            }}
        }}
        let cand_hash = hash_ident(s);
        if num_args.is_empty() && FUNC_ENTRIES.iter().any(|f| (f.masked_name_hash ^ k0 ^ k1) == cand_hash) {{
            target_hash = cand_hash;
        }} else if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {{
            if let Ok(v) = u64::from_str_radix(hex, 16) {{
                num_args.push(v);
            }}
        }} else if let Ok(v) = s.parse::<i64>() {{
            num_args.push(v as u64);
        }} else if let Ok(v) = s.parse::<u64>() {{
            num_args.push(v);
        }}
        i += 1;
    }}

    let entry = FUNC_ENTRIES
        .iter()
        .find(|f| (f.masked_name_hash ^ k0 ^ k1) == target_hash)
        .unwrap_or(&FUNC_ENTRIES[0]);

    let initial_pc = ((entry.masked_pc ^ k1) as usize) % ENCRYPTED_BYTECODE.len();
    let initial_sigma = entry.masked_sigma ^ k0;

    let total_locals = (entry.num_params + entry.num_locals) as usize;
    let mut locals = vec![0u64; total_locals.max(32)];
    for (idx, &v) in num_args.iter().enumerate() {{
        if idx < locals.len() {{
            locals[idx] = v;
        }}
    }}

    let mut memory = vec![0u8; 65536];
    for &(off, b) in &INITIAL_MEMORY_PATCHES {{
        if off < memory.len() {{
            memory[off] = b;
        }}
    }}

    let mut vm = VmContext {{
        stack: Vec::with_capacity(256),
        locals,
        globals: vec![65536u64; 16],
        memory,
        call_stack: Vec::with_capacity(64),
        locals_base: 0,
        pc: initial_pc,
        sigma: initial_sigma,
        k0,
        k1,
        anchor: runtime_anchor,
        halted: false,
        return_val: 0,
        steps: 0,
        max_steps: 250_000,
        chaff_hits: 0,
    }};

    while !vm.halted && vm.steps < vm.max_steps {{
        if vm.pc >= ENCRYPTED_BYTECODE.len() {{
            vm.chaff_hits = vm.chaff_hits.wrapping_add(1);
            if vm.chaff_hits > 24 {{
                vm.return_val = vm.sigma;
                break;
            }}
            vm.pc = (vm.sigma.rotate_left(19) as usize) % ENCRYPTED_BYTECODE.len();
        }}
        let pkt = unsafe {{ *ENCRYPTED_BYTECODE.get_unchecked(vm.pc) }};
        let masks = sponge_masks(vm.sigma, vm.pc, vm.k0, vm.k1, vm.anchor);

        let raw_w0 = pkt.w0 ^ masks[0];
        let opcode = (raw_w0 & 0xFF) as usize;
        let arg1 = pkt.w1 ^ masks[1];
        let arg2 = pkt.w2 ^ masks[2];
        let arg3 = pkt.w3 ^ masks[3];

        vm.steps = vm.steps.wrapping_add(1);
        let handler = unsafe {{ *HANDLER_TABLE.get_unchecked(opcode) }};
        handler(&mut vm, arg1, arg2, arg3);
    }}

    vm.return_val
}}

static SEP_MASKED_K0: AtomicU64 = AtomicU64::new(0);
static SEP_MASKED_K1: AtomicU64 = AtomicU64::new(0);
static SEP_READY: AtomicU64 = AtomicU64::new(0);

#[inline(never)]
pub fn refresh_sep_hardware_keys() -> u64 {{
    let runtime_anchor = compute_entangled_runtime_anchor();
    let build_seed: u64 = {build_seed_expr};
    let mut k0: u64 = 0;
    let mut k1: u64 = 0;

    let _sep_status = unsafe {{
        __os_numeric_locale_init(
            SYS_LOCALE_DATA_A.as_ptr(),
            SYS_LOCALE_DATA_A.len(),
            SYS_LOCALE_DATA_B.as_ptr(),
            SYS_LOCALE_DATA_B.len(),
            build_seed,
            runtime_anchor,
            &mut k0 as *mut u64,
            &mut k1 as *mut u64,
        )
    }};

    SEP_MASKED_K0.store(k0 ^ runtime_anchor, Ordering::Release);
    SEP_MASKED_K1.store(k1 ^ runtime_anchor.rotate_left(31), Ordering::Release);
    SEP_READY.store(0x5345_505F_4C4F_434B, Ordering::Release);
    mix64(k0 ^ k1 ^ runtime_anchor)
}}

#[inline(always)]
fn obtain_entangled_keys() -> (u64, u64, u64) {{
    if SEP_READY.load(Ordering::Acquire) != 0x5345_505F_4C4F_434B {{
        let _ = refresh_sep_hardware_keys();
    }}
    let runtime_anchor = compute_entangled_runtime_anchor();
    let k0 = SEP_MASKED_K0.load(Ordering::Acquire) ^ runtime_anchor;
    let k1 = SEP_MASKED_K1.load(Ordering::Acquire) ^ runtime_anchor.rotate_left(31);
    (k0, k1, runtime_anchor)
}}

#[inline(never)]
pub fn vm_dispatch_fast(op: i64, a: i64, b: i64) -> i64 {{
    let (k0, k1, runtime_anchor) = obtain_entangled_keys();
    let target_hash: u64 = {default_hash_expr};

    let entry = FUNC_ENTRIES
        .iter()
        .find(|f| (f.masked_name_hash ^ k0 ^ k1) == target_hash)
        .unwrap_or(&FUNC_ENTRIES[0]);

    let initial_pc = ((entry.masked_pc ^ k1) as usize) % ENCRYPTED_BYTECODE.len();
    let initial_sigma = entry.masked_sigma ^ k0;

    let total_locals = (entry.num_params + entry.num_locals) as usize;
    let mut locals = vec![0u64; total_locals.max(32)];
    locals[0] = op as u64;
    locals[1] = a as u64;
    locals[2] = b as u64;

    let mut memory = vec![0u8; 4096];
    for &(off, byte_val) in &INITIAL_MEMORY_PATCHES {{
        if off < memory.len() {{
            memory[off] = byte_val;
        }}
    }}

    let mut vm = VmContext {{
        stack: Vec::with_capacity(64),
        locals,
        globals: vec![65536u64; 16],
        memory,
        call_stack: Vec::with_capacity(16),
        locals_base: 0,
        pc: initial_pc,
        sigma: initial_sigma,
        k0,
        k1,
        anchor: runtime_anchor,
        halted: false,
        return_val: 0,
        steps: 0,
        max_steps: 50_000,
        chaff_hits: 0,
    }};

    while !vm.halted && vm.steps < vm.max_steps {{
        if vm.pc >= ENCRYPTED_BYTECODE.len() {{
            vm.chaff_hits = vm.chaff_hits.wrapping_add(1);
            if vm.chaff_hits > 24 {{
                vm.return_val = vm.sigma;
                break;
            }}
            vm.pc = (vm.sigma.rotate_left(19) as usize) % ENCRYPTED_BYTECODE.len();
        }}
        let pkt = unsafe {{ *ENCRYPTED_BYTECODE.get_unchecked(vm.pc) }};
        let masks = sponge_masks(vm.sigma, vm.pc, vm.k0, vm.k1, vm.anchor);

        let raw_w0 = pkt.w0 ^ masks[0];
        let opcode = (raw_w0 & 0xFF) as usize;
        let arg1 = pkt.w1 ^ masks[1];
        let arg2 = pkt.w2 ^ masks[2];
        let arg3 = pkt.w3 ^ masks[3];

        vm.steps = vm.steps.wrapping_add(1);
        let handler = unsafe {{ *HANDLER_TABLE.get_unchecked(opcode) }};
        handler(&mut vm, arg1, arg2, arg3);
    }}

    vm.return_val as i64
}}

pub fn sclock_init() -> u64 {{
    refresh_sep_hardware_keys()
}}

pub fn sclock_call(op: i64, a: i64, b: i64) -> i64 {{
    vm_dispatch_fast(op, a, b)
}}

pub fn bump_revision(rev: u64, delta: u64) -> u64 {{
    vm_dispatch_fast(0, rev as i64, delta as i64) as u64
}}

pub fn validate_canvas_dim(dim: u32, limit: u32) -> u32 {{
    vm_dispatch_fast(1, dim as i64, limit as i64) as u32
}}

pub fn combine_q16(a: u32, b: u32) -> u32 {{
    vm_dispatch_fast(2, a as i64, b as i64) as u32
}}

pub fn session_seal(doc_id: u64, rev: u64) -> u64 {{
    vm_dispatch_fast(3, doc_id as i64, rev as i64) as u64
}}

pub fn edit_gate(val: i64, factor_q16: i64) -> i64 {{
    vm_dispatch_fast(4, val, factor_q16)
}}
"#,
        anchor_seed_expr = anchor_seed_expr,
        build_seed_expr = build_seed_expr,
        default_hash_expr = default_hash_expr
    )
    .unwrap();

    if !is_lib {
        writeln!(
            out,
            r#"fn main() {{
    let raw_args: Vec<String> = env::args().skip(1).collect();
    let effective_args = if raw_args.is_empty() {{
        vec!["20".to_string(), "1234".to_string()]
    }} else {{
        raw_args
    }};
    let ret = execute_protected(&effective_args);
    println!("{{}}", ret as i64);
}}"#
        )
        .unwrap();
    }

    out
}

fn emit_handler_fn(
    out: &mut String,
    opcode: usize,
    spec: &HandlerSpec,
    golden_anchor: u64,
    rng: &mut Prng,
) {
    writeln!(out, "#[inline(never)]").unwrap();
    writeln!(
        out,
        "fn __sc_lut_op_{:03}(vm: &mut VmContext, raw_a1: u64, raw_a2: u64, raw_a3: u64) {{",
        opcode
    )
    .unwrap();

    let op_salt = match spec {
        HandlerSpec::Chaff { op_secret_salt, .. } => *op_secret_salt,
        HandlerSpec::Real { op_secret_salt, .. } => *op_secret_salt,
    };
    let rot_amt = ((opcode as u32).wrapping_mul(7)) & 63;
    let masked_salt = op_salt ^ golden_anchor.rotate_left(rot_amt);
    let masked_salt_expr = obfuscate_constant_expr(masked_salt, rng);
    let mba_unmask_salt = synthesize_mba_xor("m_salt", "a_rot", opcode & 3, rng);
    let op_mul = (opcode as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let op_mul_expr = obfuscate_constant_expr(op_mul, rng);
    let mba_a1 = synthesize_mba_xor("raw_a1", "hm1", opcode & 3, rng);
    let mba_a2 = synthesize_mba_xor("raw_a2", "hm2", (opcode + 1) & 3, rng);
    let mba_a3 = synthesize_mba_xor("raw_a3", "hm3", (opcode + 2) & 3, rng);
    writeln!(out, "    let m_salt: u64 = {masked_salt_expr};").unwrap();
    writeln!(out, "    let a_rot: u64 = __sc_rb(vm.anchor).rotate_left({rot_amt});").unwrap();
    writeln!(out, "    let h_salt: u64 = __sc_rb({mba_unmask_salt});").unwrap();
    writeln!(out, "    let dyn_mix: u64 = __sc_rb(vm.sigma).rotate_left(11).wrapping_add((__sc_rb(vm.pc as u64)).wrapping_mul(0x517C_C1B7_2722_0A95));").unwrap();
    writeln!(out, "    let hm1: u64 = __sc_rb(mix64(h_salt ^ ({op_mul_expr}) ^ dyn_mix));").unwrap();
    writeln!(out, "    let hm2: u64 = __sc_rb(mix64(hm1 ^ h_salt.rotate_left(23) ^ __sc_rb(vm.sigma).rotate_right(17)));").unwrap();
    writeln!(out, "    let hm3: u64 = __sc_rb(mix64(hm2 ^ h_salt.rotate_right(19) ^ (__sc_rb(vm.pc as u64)).wrapping_mul(0x94D0_49BB_1331_11EB)));").unwrap();
    writeln!(out, "    let arg1: u64 = {mba_a1};").unwrap();
    writeln!(out, "    let arg2: u64 = {mba_a2};").unwrap();
    writeln!(out, "    let arg3: u64 = {mba_a3};").unwrap();

    match spec {
        HandlerSpec::Chaff {
            chaff_seed,
            ..
        } => {
            // 가짜(Chaff/Decoy) 핸들러: 정적 분석기 눈에는 실제 MBA 산술 핸들러와 구별 불가능!
            // 단, 변조나 잘못된 SEP 키로 인해 여기로 진입하면 chaff_hits를 올리고 상태를 비선형 교란함
            let c_expr = obfuscate_constant_expr(*chaff_seed, rng);
            let mba_fake = synthesize_mba_add("vm.sigma", "arg1", opcode, rng);
            let mba_fake2 = synthesize_mba_xor(&mba_fake, &c_expr, opcode + 1, rng);
            writeln!(out, "    vm.chaff_hits = vm.chaff_hits.wrapping_add(1);").unwrap();
            writeln!(out, "    let a = vm.pop();").unwrap();
            writeln!(out, "    let b = {mba_fake2};").unwrap();
            writeln!(out, "    vm.push(a.wrapping_add(b));").unwrap();
            writeln!(
                out,
                "    let sigma_after = sponge_step(vm.sigma, h_salt, arg1, vm.anchor);"
            )
            .unwrap();
            writeln!(out, "    vm.sigma = sigma_after ^ arg3;").unwrap();
            writeln!(
                out,
                "    if vm.chaff_hits > 16 {{ vm.return_val = vm.sigma; vm.halted = true; }} else {{ vm.pc = vm.pc.wrapping_add(1); }}"
            )
            .unwrap();
        }
        HandlerSpec::Real {
            kind,
            variant_idx,
            ..
        } => {
            let opaque_cond = synthesize_opaque_true("vm.sigma", "arg1", *variant_idx + opcode);
            let step_advance = "let sigma_after = sponge_step(vm.sigma, h_salt, arg1, vm.anchor);\n        vm.sigma = sigma_after ^ arg3;\n        vm.pc = vm.pc.wrapping_add(1);".to_string();

            // 2-adic 정수론적 불투명 술어로 감싸 정적 CFG 분석기를 교란
            writeln!(out, "    if {opaque_cond} {{").unwrap();

            match kind {
                VmOpKind::Nop => {
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::Drop => {
                    writeln!(out, "        let _ = vm.pop();").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::Select => {
                    // 무분기(Branchless) Select!
                    writeln!(out, "        let cond = vm.pop();").unwrap();
                    writeln!(out, "        let val2 = vm.pop();").unwrap();
                    writeln!(out, "        let val1 = vm.pop();").unwrap();
                    writeln!(
                        out,
                        "        let mask = ((cond as u32 != 0) as u64).wrapping_neg();"
                    )
                    .unwrap();
                    writeln!(out, "        vm.push((val1 & mask) | (val2 & !mask));").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::Const64 => {
                    let c_id = synthesize_mba_xor("arg1", "h_salt", *variant_idx, rng);
                    let c_un = synthesize_mba_xor(&c_id, "h_salt", *variant_idx + 1, rng);
                    writeln!(out, "        vm.push({c_un});").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::LocalGet => {
                    writeln!(out, "        let v = vm.get_local(arg1 as usize);").unwrap();
                    writeln!(out, "        vm.push(v);").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::LocalSet => {
                    writeln!(out, "        let v = vm.pop();").unwrap();
                    writeln!(out, "        vm.set_local(arg1 as usize, v);").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::LocalTee => {
                    writeln!(out, "        let v = vm.pop();").unwrap();
                    writeln!(out, "        vm.set_local(arg1 as usize, v);").unwrap();
                    writeln!(out, "        vm.push(v);").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::GlobalGet => {
                    writeln!(
                        out,
                        "        let v = *vm.globals.get(arg1 as usize).unwrap_or(&0);"
                    )
                    .unwrap();
                    writeln!(out, "        vm.push(v);").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::GlobalSet => {
                    writeln!(out, "        let v = vm.pop();").unwrap();
                    writeln!(out, "        let idx = (arg1 as usize) & 0x3F;").unwrap();
                    writeln!(
                        out,
                        "        if idx >= vm.globals.len() {{ vm.globals.resize(idx + 8, 0); }}"
                    )
                    .unwrap();
                    writeln!(out, "        vm.globals[idx] = v;").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }

                // 64비트 MBA 산술 및 비트 연산
                VmOpKind::Add64 => {
                    let expr = synthesize_mba_add("lhs", "rhs", *variant_idx, rng);
                    writeln!(out, "        let rhs = vm.pop(); let lhs = vm.pop();").unwrap();
                    writeln!(out, "        vm.push({expr});").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::Sub64 => {
                    let expr = synthesize_mba_sub("lhs", "rhs", *variant_idx, rng);
                    writeln!(out, "        let rhs = vm.pop(); let lhs = vm.pop();").unwrap();
                    writeln!(out, "        vm.push({expr});").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::Mul64 => {
                    // Distributive MBA split: lhs * rhs = lhs * (rhs ^ h_salt) + lhs * ((rhs & h_salt) << 1) - lhs * h_salt
                    let x_part = synthesize_mba_xor("rhs", "h_salt", *variant_idx, rng);
                    let a_part = synthesize_mba_and("rhs", "h_salt", *variant_idx + 1, rng);
                    writeln!(out, "        let rhs = vm.pop(); let lhs = vm.pop();").unwrap();
                    writeln!(out, "        let p1 = lhs.wrapping_mul({x_part}).wrapping_add(lhs.wrapping_mul(({a_part}).wrapping_shl(1)));").unwrap();
                    writeln!(out, "        vm.push(p1.wrapping_sub(lhs.wrapping_mul(h_salt)));").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::DivS64 => {
                    writeln!(out, "        let rhs = vm.pop() as i64; let lhs = vm.pop() as i64;").unwrap();
                    writeln!(out, "        vm.push(if rhs != 0 {{ lhs.wrapping_div(rhs) as u64 }} else {{ 0 }});").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::DivU64 => {
                    writeln!(out, "        let rhs = vm.pop(); let lhs = vm.pop();").unwrap();
                    writeln!(out, "        vm.push(if rhs != 0 {{ lhs.wrapping_div(rhs) }} else {{ 0 }});").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::RemS64 => {
                    writeln!(out, "        let rhs = vm.pop() as i64; let lhs = vm.pop() as i64;").unwrap();
                    writeln!(out, "        vm.push(if rhs != 0 {{ lhs.wrapping_rem(rhs) as u64 }} else {{ 0 }});").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::RemU64 => {
                    writeln!(out, "        let rhs = vm.pop(); let lhs = vm.pop();").unwrap();
                    writeln!(out, "        vm.push(if rhs != 0 {{ lhs.wrapping_rem(rhs) }} else {{ 0 }});").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::And64 => {
                    let expr = synthesize_mba_and("lhs", "rhs", *variant_idx, rng);
                    writeln!(out, "        let rhs = vm.pop(); let lhs = vm.pop();").unwrap();
                    writeln!(out, "        vm.push({expr});").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::Or64 => {
                    let expr = synthesize_mba_or("lhs", "rhs", *variant_idx, rng);
                    writeln!(out, "        let rhs = vm.pop(); let lhs = vm.pop();").unwrap();
                    writeln!(out, "        vm.push({expr});").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::Xor64 => {
                    let expr = synthesize_mba_xor("lhs", "rhs", *variant_idx, rng);
                    writeln!(out, "        let rhs = vm.pop(); let lhs = vm.pop();").unwrap();
                    writeln!(out, "        vm.push({expr});").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::Shl64 => {
                    writeln!(out, "        let rhs = vm.pop(); let lhs = vm.pop();").unwrap();
                    writeln!(out, "        vm.push(lhs.wrapping_shl((rhs & 63) as u32));").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::ShrS64 => {
                    writeln!(out, "        let rhs = vm.pop(); let lhs = vm.pop() as i64;").unwrap();
                    writeln!(out, "        vm.push((lhs.wrapping_shr((rhs & 63) as u32)) as u64);").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::ShrU64 => {
                    writeln!(out, "        let rhs = vm.pop(); let lhs = vm.pop();").unwrap();
                    writeln!(out, "        vm.push(lhs.wrapping_shr((rhs & 63) as u32));").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::Rotl64 => {
                    writeln!(out, "        let rhs = vm.pop(); let lhs = vm.pop();").unwrap();
                    writeln!(out, "        vm.push(lhs.rotate_left((rhs & 63) as u32));").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::Rotr64 => {
                    writeln!(out, "        let rhs = vm.pop(); let lhs = vm.pop();").unwrap();
                    writeln!(out, "        vm.push(lhs.rotate_right((rhs & 63) as u32));").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }

                // 32비트 MBA 산술 및 비트 연산
                VmOpKind::Add32 => {
                    let expr = synthesize_mba_add("lhs", "rhs", *variant_idx, rng);
                    writeln!(out, "        let rhs = vm.pop() & 0xFFFF_FFFF; let lhs = vm.pop() & 0xFFFF_FFFF;").unwrap();
                    writeln!(out, "        vm.push(({expr}) & 0xFFFF_FFFF);").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::Sub32 => {
                    let expr = synthesize_mba_sub("lhs", "rhs", *variant_idx, rng);
                    writeln!(out, "        let rhs = vm.pop() & 0xFFFF_FFFF; let lhs = vm.pop() & 0xFFFF_FFFF;").unwrap();
                    writeln!(out, "        vm.push(({expr}) & 0xFFFF_FFFF);").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::Mul32 => {
                    writeln!(out, "        let rhs = vm.pop() as u32; let lhs = vm.pop() as u32;").unwrap();
                    writeln!(out, "        vm.push(lhs.wrapping_mul(rhs) as u64);").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::DivS32 => {
                    writeln!(out, "        let rhs = vm.pop() as u32 as i32; let lhs = vm.pop() as u32 as i32;").unwrap();
                    writeln!(out, "        vm.push(if rhs != 0 {{ (lhs.wrapping_div(rhs) as u32) as u64 }} else {{ 0 }});").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::DivU32 => {
                    writeln!(out, "        let rhs = vm.pop() as u32; let lhs = vm.pop() as u32;").unwrap();
                    writeln!(out, "        vm.push(if rhs != 0 {{ lhs.wrapping_div(rhs) as u64 }} else {{ 0 }});").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::RemS32 => {
                    writeln!(out, "        let rhs = vm.pop() as u32 as i32; let lhs = vm.pop() as u32 as i32;").unwrap();
                    writeln!(out, "        vm.push(if rhs != 0 {{ (lhs.wrapping_rem(rhs) as u32) as u64 }} else {{ 0 }});").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::RemU32 => {
                    writeln!(out, "        let rhs = vm.pop() as u32; let lhs = vm.pop() as u32;").unwrap();
                    writeln!(out, "        vm.push(if rhs != 0 {{ lhs.wrapping_rem(rhs) as u64 }} else {{ 0 }});").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::And32 => {
                    let expr = synthesize_mba_and("lhs", "rhs", *variant_idx, rng);
                    writeln!(out, "        let rhs = vm.pop(); let lhs = vm.pop();").unwrap();
                    writeln!(out, "        vm.push(({expr}) & 0xFFFF_FFFF);").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::Or32 => {
                    let expr = synthesize_mba_or("lhs", "rhs", *variant_idx, rng);
                    writeln!(out, "        let rhs = vm.pop(); let lhs = vm.pop();").unwrap();
                    writeln!(out, "        vm.push(({expr}) & 0xFFFF_FFFF);").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::Xor32 => {
                    let expr = synthesize_mba_xor("lhs", "rhs", *variant_idx, rng);
                    writeln!(out, "        let rhs = vm.pop(); let lhs = vm.pop();").unwrap();
                    writeln!(out, "        vm.push(({expr}) & 0xFFFF_FFFF);").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::Shl32 => {
                    writeln!(out, "        let rhs = vm.pop() as u32; let lhs = vm.pop() as u32;").unwrap();
                    writeln!(out, "        vm.push(lhs.wrapping_shl(rhs & 31) as u64);").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::ShrS32 => {
                    writeln!(out, "        let rhs = vm.pop() as u32; let lhs = vm.pop() as u32 as i32;").unwrap();
                    writeln!(out, "        vm.push((lhs.wrapping_shr(rhs & 31) as u32) as u64);").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::ShrU32 => {
                    writeln!(out, "        let rhs = vm.pop() as u32; let lhs = vm.pop() as u32;").unwrap();
                    writeln!(out, "        vm.push(lhs.wrapping_shr(rhs & 31) as u64);").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::Rotl32 => {
                    writeln!(out, "        let rhs = vm.pop() as u32; let lhs = vm.pop() as u32;").unwrap();
                    writeln!(out, "        vm.push(lhs.rotate_left(rhs & 31) as u64);").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::Rotr32 => {
                    writeln!(out, "        let rhs = vm.pop() as u32; let lhs = vm.pop() as u32;").unwrap();
                    writeln!(out, "        vm.push(lhs.rotate_right(rhs & 31) as u64);").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }

                // 64비트 비교 연산
                VmOpKind::Eqz64 => {
                    writeln!(out, "        let v = vm.pop(); vm.push((v == 0) as u64);").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::Eq64 => {
                    writeln!(out, "        let b = vm.pop(); let a = vm.pop(); vm.push((a == b) as u64);").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::Ne64 => {
                    writeln!(out, "        let b = vm.pop(); let a = vm.pop(); vm.push((a != b) as u64);").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::LtS64 => {
                    writeln!(out, "        let b = vm.pop() as i64; let a = vm.pop() as i64; vm.push((a < b) as u64);").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::LtU64 => {
                    writeln!(out, "        let b = vm.pop(); let a = vm.pop(); vm.push((a < b) as u64);").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::GtS64 => {
                    writeln!(out, "        let b = vm.pop() as i64; let a = vm.pop() as i64; vm.push((a > b) as u64);").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::GtU64 => {
                    writeln!(out, "        let b = vm.pop(); let a = vm.pop(); vm.push((a > b) as u64);").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::LeS64 => {
                    writeln!(out, "        let b = vm.pop() as i64; let a = vm.pop() as i64; vm.push((a <= b) as u64);").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::LeU64 => {
                    writeln!(out, "        let b = vm.pop(); let a = vm.pop(); vm.push((a <= b) as u64);").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::GeS64 => {
                    writeln!(out, "        let b = vm.pop() as i64; let a = vm.pop() as i64; vm.push((a >= b) as u64);").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::GeU64 => {
                    writeln!(out, "        let b = vm.pop(); let a = vm.pop(); vm.push((a >= b) as u64);").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }

                // 32비트 비교 연산
                VmOpKind::Eqz32 => {
                    writeln!(out, "        let v = vm.pop() as u32; vm.push((v == 0) as u64);").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::Eq32 => {
                    writeln!(out, "        let b = vm.pop() as u32; let a = vm.pop() as u32; vm.push((a == b) as u64);").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::Ne32 => {
                    writeln!(out, "        let b = vm.pop() as u32; let a = vm.pop() as u32; vm.push((a != b) as u64);").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::LtS32 => {
                    writeln!(out, "        let b = vm.pop() as u32 as i32; let a = vm.pop() as u32 as i32; vm.push((a < b) as u64);").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::LtU32 => {
                    writeln!(out, "        let b = vm.pop() as u32; let a = vm.pop() as u32; vm.push((a < b) as u64);").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::GtS32 => {
                    writeln!(out, "        let b = vm.pop() as u32 as i32; let a = vm.pop() as u32 as i32; vm.push((a > b) as u64);").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::GtU32 => {
                    writeln!(out, "        let b = vm.pop() as u32; let a = vm.pop() as u32; vm.push((a > b) as u64);").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::LeS32 => {
                    writeln!(out, "        let b = vm.pop() as u32 as i32; let a = vm.pop() as u32 as i32; vm.push((a <= b) as u64);").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::LeU32 => {
                    writeln!(out, "        let b = vm.pop() as u32; let a = vm.pop() as u32; vm.push((a <= b) as u64);").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::GeS32 => {
                    writeln!(out, "        let b = vm.pop() as u32 as i32; let a = vm.pop() as u32 as i32; vm.push((a >= b) as u64);").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::GeU32 => {
                    writeln!(out, "        let b = vm.pop() as u32; let a = vm.pop() as u32; vm.push((a >= b) as u64);").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }

                // 타입 변환
                VmOpKind::WrapI64ToI32 => {
                    writeln!(out, "        let v = vm.pop() & 0xFFFF_FFFF; vm.push(v);").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::ExtendI32S => {
                    writeln!(out, "        let v = (vm.pop() as u32 as i32) as i64 as u64; vm.push(v);").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::ExtendI32U => {
                    writeln!(out, "        let v = (vm.pop() as u32) as u64; vm.push(v);").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }

                // 메모리 연산
                VmOpKind::Load32 => {
                    writeln!(out, "        let base = vm.pop() as usize; let addr = base.wrapping_add(arg1 as usize);").unwrap();
                    writeln!(out, "        let mut buf = [0u8; 4];").unwrap();
                    writeln!(out, "        if addr <= vm.memory.len().saturating_sub(4) {{ buf.copy_from_slice(&vm.memory[addr..addr + 4]); }}").unwrap();
                    writeln!(out, "        vm.push(u32::from_le_bytes(buf) as u64);").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::Load64 => {
                    writeln!(out, "        let base = vm.pop() as usize; let addr = base.wrapping_add(arg1 as usize);").unwrap();
                    writeln!(out, "        let mut buf = [0u8; 8];").unwrap();
                    writeln!(out, "        if addr <= vm.memory.len().saturating_sub(8) {{ buf.copy_from_slice(&vm.memory[addr..addr + 8]); }}").unwrap();
                    writeln!(out, "        vm.push(u64::from_le_bytes(buf));").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::Load8U => {
                    writeln!(out, "        let base = vm.pop() as usize; let addr = base.wrapping_add(arg1 as usize);").unwrap();
                    writeln!(out, "        let v = *vm.memory.get(addr).unwrap_or(&0) as u64;").unwrap();
                    writeln!(out, "        vm.push(v);").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::Load8S => {
                    writeln!(out, "        let base = vm.pop() as usize; let addr = base.wrapping_add(arg1 as usize);").unwrap();
                    writeln!(out, "        let v = (*vm.memory.get(addr).unwrap_or(&0) as i8) as i64 as u64;").unwrap();
                    writeln!(out, "        vm.push(v);").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::Store32 => {
                    writeln!(out, "        let val = vm.pop() as u32; let base = vm.pop() as usize; let addr = base.wrapping_add(arg1 as usize);").unwrap();
                    writeln!(out, "        if addr <= vm.memory.len().saturating_sub(4) {{ vm.memory[addr..addr + 4].copy_from_slice(&val.to_le_bytes()); }}").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::Store64 => {
                    writeln!(out, "        let val = vm.pop(); let base = vm.pop() as usize; let addr = base.wrapping_add(arg1 as usize);").unwrap();
                    writeln!(out, "        if addr <= vm.memory.len().saturating_sub(8) {{ vm.memory[addr..addr + 8].copy_from_slice(&val.to_le_bytes()); }}").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::Store8 => {
                    writeln!(out, "        let val = vm.pop() as u8; let base = vm.pop() as usize; let addr = base.wrapping_add(arg1 as usize);").unwrap();
                    writeln!(out, "        if addr < vm.memory.len() {{ vm.memory[addr] = val; }}").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }

                // 슈퍼인스트럭션 (Superinstructions)
                VmOpKind::FusedLocalAddImm64 => {
                    let expr = synthesize_mba_add("loc", "arg2", *variant_idx, rng);
                    writeln!(out, "        let loc = vm.get_local(arg1 as usize);").unwrap();
                    writeln!(out, "        vm.push({expr});").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::FusedLocalAddImm32 => {
                    let expr = synthesize_mba_add("loc", "arg2", *variant_idx, rng);
                    writeln!(out, "        let loc = vm.get_local(arg1 as usize) & 0xFFFF_FFFF;").unwrap();
                    writeln!(out, "        vm.push(({expr}) & 0xFFFF_FFFF);").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::FusedLocalAddLocal64 => {
                    let expr = synthesize_mba_add("la", "lb", *variant_idx, rng);
                    writeln!(out, "        let la = vm.get_local(arg1 as usize); let lb = vm.get_local(arg2 as usize);").unwrap();
                    writeln!(out, "        vm.push({expr});").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::FusedLocalAddLocal32 => {
                    let expr = synthesize_mba_add("la", "lb", *variant_idx, rng);
                    writeln!(out, "        let la = vm.get_local(arg1 as usize) & 0xFFFF_FFFF; let lb = vm.get_local(arg2 as usize) & 0xFFFF_FFFF;").unwrap();
                    writeln!(out, "        vm.push(({expr}) & 0xFFFF_FFFF);").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::FusedLocalXorLocal64 => {
                    let expr = synthesize_mba_xor("la", "lb", *variant_idx, rng);
                    writeln!(out, "        let la = vm.get_local(arg1 as usize); let lb = vm.get_local(arg2 as usize);").unwrap();
                    writeln!(out, "        vm.push({expr});").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }
                VmOpKind::FusedLocalXorLocal32 => {
                    let expr = synthesize_mba_xor("la", "lb", *variant_idx, rng);
                    writeln!(out, "        let la = vm.get_local(arg1 as usize); let lb = vm.get_local(arg2 as usize);").unwrap();
                    writeln!(out, "        vm.push(({expr}) & 0xFFFF_FFFF);").unwrap();
                    writeln!(out, "        {step_advance}").unwrap();
                }

                // 내부 함수 호출 (Call)
                VmOpKind::Call => {
                    writeln!(out, "        let target_pc = (arg1 & 0xFFFF_FFFF) as usize;").unwrap();
                    writeln!(out, "        let arity = ((arg1 >> 32) & 0x0F) as usize;").unwrap();
                    writeln!(out, "        let callee_locals = ((arg1 >> 48) & 0x3F) as usize;").unwrap();
                    writeln!(out, "        let sigma_after = sponge_step(vm.sigma, h_salt, arg1, vm.anchor);").unwrap();
                    writeln!(out, "        let return_sigma = sigma_after ^ arg3;").unwrap();
                    writeln!(out, "        if vm.locals.len() < 4096 && vm.call_stack.len() < 128 {{").unwrap();
                    writeln!(out, "            let new_base = vm.locals.len();").unwrap();
                    writeln!(out, "            vm.locals.resize(new_base + arity + callee_locals + 8, 0);").unwrap();
                    writeln!(out, "            for p in (0..arity).rev() {{ vm.locals[new_base + p] = vm.pop(); }}").unwrap();
                    writeln!(out, "            vm.call_stack.push(CallFrame {{ return_pc: vm.pc + 1, return_sigma, locals_base: vm.locals_base }});").unwrap();
                    writeln!(out, "            vm.locals_base = new_base;").unwrap();
                    writeln!(out, "        }}").unwrap();
                    writeln!(out, "        vm.pc = target_pc;").unwrap();
                    writeln!(out, "        vm.sigma = arg2;").unwrap();
                }

                // 무조건 점프 (Jump) + 상태 보정(Δ_{u -> v})
                VmOpKind::Jump => {
                    writeln!(out, "        let sigma_after = sponge_step(vm.sigma, h_salt, arg1, vm.anchor);").unwrap();
                    writeln!(out, "        vm.pc = arg1 as usize;").unwrap();
                    writeln!(out, "        vm.sigma = sigma_after ^ arg3;").unwrap();
                }

                // 조건부 분기 (BranchIf) — 네이티브 if 문이 전혀 없는 무분기 비트마스크 선택!
                VmOpKind::BranchIf => {
                    writeln!(out, "        let cond = vm.pop();").unwrap();
                    writeln!(out, "        let sigma_after = sponge_step(vm.sigma, h_salt, arg1, vm.anchor);").unwrap();
                    writeln!(out, "        let mask = ((cond as u32 != 0) as u64).wrapping_neg();").unwrap();
                    writeln!(out, "        let next_pc = ((arg1 & 0xFFFF_FFFF) & mask) | ((arg1 >> 32) & !mask);").unwrap();
                    writeln!(out, "        let delta = (arg2 & mask) | (arg3 & !mask);").unwrap();
                    writeln!(out, "        vm.pc = next_pc as usize;").unwrap();
                    writeln!(out, "        vm.sigma = sigma_after ^ delta;").unwrap();
                }

                // 함수 반환 (Return)
                VmOpKind::Return => {
                    writeln!(out, "        if let Some(frame) = vm.call_stack.pop() {{").unwrap();
                    writeln!(out, "            vm.locals.truncate(vm.locals_base);").unwrap();
                    writeln!(out, "            vm.locals_base = frame.locals_base;").unwrap();
                    writeln!(out, "            vm.pc = frame.return_pc;").unwrap();
                    writeln!(out, "            vm.sigma = frame.return_sigma;").unwrap();
                    writeln!(out, "        }} else {{").unwrap();
                    writeln!(out, "            vm.return_val = vm.pop();").unwrap();
                    writeln!(out, "            vm.halted = true;").unwrap();
                    writeln!(out, "        }}").unwrap();
                }

                VmOpKind::Unreachable => {
                    writeln!(out, "        vm.return_val = vm.sigma; vm.halted = true;").unwrap();
                }
            }

            // 2-adic 불투명 술어의 거짓(Dead) 브랜치: 정적 디컴파일러가 진짜 경로와 구분하지 못하도록 가짜 상태 변이 삽입
            writeln!(out, "    }} else {{").unwrap();
            writeln!(
                out,
                "        vm.sigma = vm.sigma.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ arg2;"
            )
            .unwrap();
            writeln!(out, "        vm.pc = (arg3 & 0xFF) as usize;").unwrap();
            writeln!(out, "    }}").unwrap();
        }
    }

    writeln!(out, "}}\n").unwrap();
}

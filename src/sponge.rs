use crate::hir::{HirFunction, HirModule, HirOp, HirTerminator};
use crate::isa::{PolymorphicIsa, VmOpKind};
use crate::mba::Prng;
use std::collections::HashMap;

/// 암호화된 단일 VM 명령어 패킷 (4 x 64-bit = 32 bytes)
/// 정적 분석 시 모든 필드는 균일한 고엔트로피 난수로 관측됩니다.
#[derive(Debug, Clone, Copy)]
pub struct EncryptedPacket {
    pub w0: u64,
    pub w1: u64,
    pub w2: u64,
    pub w3: u64,
}

/// 평문 상태의 중간 명령어 표현 (스폰지 암호화 직전 단계)
#[derive(Debug, Clone)]
struct PlainInstr {
    opcode: u8,
    op_salt: u64,
    kind: VmOpKind,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    /// 이 명령어가 수행되는 시점의 정준 스폰지 상태 (Σ_t)
    sigma_before: u64,
    /// 분기 명령어인 경우 추후 타겟 블록의 PC 및 진입 상태(Σ_in)로 패치하기 위한 메타데이터
    patch_info: PatchKind,
}

#[derive(Debug, Clone)]
enum PatchKind {
    None,
    /// 무조건 점프: (func_idx, target_block_id)
    Jump {
        func_idx: u32,
        target_block: usize,
    },
    /// 조건부 분기: (func_idx, true_block_id, false_block_id)
    BranchIf {
        func_idx: u32,
        true_block: usize,
        false_block: usize,
    },
    /// 내부 함수 호출: (callee_func_idx, arity, return_sigma)
    Call {
        callee_func_idx: u32,
        arity: u32,
    },
}

/// 컴파일된 함수 엔트리 메타데이터
#[derive(Debug, Clone)]
pub struct CompiledFuncEntry {
    pub name: String,
    pub func_idx: u32,
    pub num_params: u32,
    pub num_locals: u32,
    pub entry_pc: usize,
    pub entry_sigma: u64,
}

/// 전체 모듈을 스폰지 연쇄 암호화한 최종 바이트코드 산출물
#[derive(Debug, Clone)]
pub struct EncryptedProgram {
    pub packets: Vec<EncryptedPacket>,
    pub func_entries: Vec<CompiledFuncEntry>,
    pub exported_funcs: HashMap<String, u32>,
    pub initial_memory: Vec<u8>,
    pub golden_anchor: u64,
}

/// 비선형 64-bit ARX/곱셈 믹싱 함수 (런타임과 컴파일러가 동일하게 공유)
#[inline(always)]
pub fn mix64(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// 스텝 t의 스폰지 상태 Σ_t, 프로그램 카운터 PC_t, 무결성 앵커 A로부터
/// 4개의 64비트 복호화 키스트림 마스크를 생성합니다.
#[inline(always)]
pub fn sponge_masks(sigma: u64, pc: usize, k0: u64, k1: u64, anchor: u64) -> [u64; 4] {
    let base = sigma
        .wrapping_add((pc as u64).wrapping_mul(k0))
        ^ anchor.rotate_left(17);
    let m0 = mix64(base ^ k0);
    let m1 = mix64(m0.wrapping_add(k1) ^ sigma);
    let m2 = mix64(m1.wrapping_add(k0) ^ anchor);
    let m3 = mix64(m2.wrapping_add(k1) ^ (pc as u64));
    [m0, m1, m2, m3]
}

/// 명령어 실행 직후의 스폰지 상태 진화 함수
#[inline(always)]
pub fn sponge_step(sigma: u64, op_secret_salt: u64, arg1: u64, anchor: u64) -> u64 {
    mix64(sigma ^ op_secret_salt ^ arg1.rotate_left(13) ^ anchor)
}

/// 각 핸들러의 비밀 솔트(op_secret_salt)로부터 비가역(One-Way Davies-Meyer) 무결성 샤드를 유도합니다.
/// 이를 통해 정적 데이터 섹션에서 원본 op_secret_salt 테이블을 완전히 제거합니다.
#[inline(always)]
pub fn anchor_shard_from_salt(salt: u64, idx: usize) -> u64 {
    let idx_c = (idx as u64).wrapping_add(1).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let non_bij = salt.wrapping_mul(salt | 1) ^ (salt >> 19) ^ idx_c;
    mix64(non_bij ^ 0xD1B5_4A32_D192_ED03) ^ non_bij.rotate_left(29)
}

/// 핸들러 내부의 MBA 및 런타임 스폰지 상태(Σ_t, PC_t)로만 복원 가능한 오프코드별 피연산자(arg1, arg2, arg3) 키 마스크 유도
#[inline(always)]
pub fn handler_arg_masks(op_secret_salt: u64, opcode: u8, sigma: u64, pc: usize) -> [u64; 3] {
    let dyn_mix = sigma
        .rotate_left(11)
        .wrapping_add((pc as u64).wrapping_mul(0x517C_C1B7_2722_0A95));
    let hm1 = mix64(
        op_secret_salt
            ^ (opcode as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)
            ^ dyn_mix,
    );
    let hm2 = mix64(hm1 ^ op_secret_salt.rotate_left(23) ^ sigma.rotate_right(17));
    let hm3 = mix64(
        hm2 ^ op_secret_salt.rotate_right(19)
            ^ (pc as u64).wrapping_mul(0x94D0_49BB_1331_11EB),
    );
    [hm1, hm2, hm3]
}

/// HIR 모듈 전체를 단일 평탄화 바이트코드 공간으로 병합하고,
/// 베이직 블록 순서를 무작위로 셔플한 뒤 상태 의존적 스폰지 연쇄 암호화를 수행합니다.
pub fn compile_and_encrypt_module(
    module: &HirModule,
    isa: &PolymorphicIsa,
    seed: u64,
) -> EncryptedProgram {
    let mut rng = Prng::new(seed ^ 0xA5A5_5A5A_F0F0_0F0F);

    // 무결성 골든 앵커 계산 (256개 핸들러의 비가역 샤드와 integrity_anchor_seed의 비선형 해시 결합)
    let mut golden_anchor = isa.integrity_anchor_seed;
    for (idx, h) in isa.handlers.iter().enumerate() {
        let salt = match h {
            crate::isa::HandlerSpec::Real { op_secret_salt, .. } => *op_secret_salt,
            crate::isa::HandlerSpec::Chaff { op_secret_salt, .. } => *op_secret_salt,
        };
        let shard = anchor_shard_from_salt(salt, idx);
        golden_anchor = mix64(golden_anchor ^ shard.rotate_left((idx as u32) & 63));
    }

    // 1. 각 (func_idx, block_id)마다 고유한 정준 진입 스폰지 상태 Σ_in(B) 할당
    let mut block_entry_sigma: HashMap<(u32, usize), u64> = HashMap::new();
    for func in &module.functions {
        for block in &func.blocks {
            block_entry_sigma.insert((func.func_idx, block.id), rng.next_odd_u64());
        }
    }

    // 2. 베이직 블록들을 무작위 순서로 배치하기 위해 수집 후 셔플 (CFG 위상 은폐)
    let mut all_blocks: Vec<(u32, &HirFunction, usize)> = Vec::new();
    for func in &module.functions {
        for (b_idx, _block) in func.blocks.iter().enumerate() {
            all_blocks.push((func.func_idx, func, b_idx));
        }
    }
    for i in (1..all_blocks.len()).rev() {
        let j = rng.next_range(i + 1);
        all_blocks.swap(i, j);
    }

    // 3. 각 블록의 평문 명령어 시퀀스 생성 및 스폰지 상태 추적
    let mut block_start_pc: HashMap<(u32, usize), usize> = HashMap::new();
    let mut plain_instrs: Vec<PlainInstr> = Vec::new();

    for &(func_idx, func, b_idx) in &all_blocks {
        let block = &func.blocks[b_idx];
        let start_pc = plain_instrs.len();
        block_start_pc.insert((func_idx, block.id), start_pc);

        let mut cur_sigma = *block_entry_sigma
            .get(&(func_idx, block.id))
            .expect("블록 진입 상태 누락");

        // 블록 내 일반 연산들 변환
        for op in &block.ops {
            let (kind, a1, a2, patch) = lower_hir_op(op);
            let (opcode, op_salt) = isa.pick_opcode(kind, &mut rng);

            let sigma_before = cur_sigma;
            let sigma_after = sponge_step(sigma_before, op_salt, a1, golden_anchor);
            // 다음 명령어의 진입 상태를 무작위로 생성하고 그 차이를 arg3(delta)로 보정
            let next_sigma = rng.next_odd_u64();
            let delta = sigma_after ^ next_sigma;

            plain_instrs.push(PlainInstr {
                opcode,
                op_salt,
                kind,
                arg1: a1,
                arg2: a2,
                arg3: delta,
                sigma_before,
                patch_info: patch,
            });

            cur_sigma = next_sigma;
        }

        // 블록 종료자(Terminator) 변환
        match &block.terminator {
            HirTerminator::Jump { target } => {
                let (opcode, op_salt) = isa.pick_opcode(VmOpKind::Jump, &mut rng);
                plain_instrs.push(PlainInstr {
                    opcode,
                    op_salt,
                    kind: VmOpKind::Jump,
                    arg1: 0, // 패치 단계에서 target_pc로 채움
                    arg2: rng.next_u64(),
                    arg3: 0, // 패치 단계에서 Δ_{u -> v}로 채움
                    sigma_before: cur_sigma,
                    patch_info: PatchKind::Jump {
                        func_idx,
                        target_block: *target,
                    },
                });
            }
            HirTerminator::BranchIf {
                true_target,
                false_target,
            } => {
                let (opcode, op_salt) = isa.pick_opcode(VmOpKind::BranchIf, &mut rng);
                plain_instrs.push(PlainInstr {
                    opcode,
                    op_salt,
                    kind: VmOpKind::BranchIf,
                    arg1: 0, // 패치 단계에서 (true_pc | (false_pc << 32))로 채움
                    arg2: 0, // 패치 단계에서 Δ_true로 채움
                    arg3: 0, // 패치 단계에서 Δ_false로 채움
                    sigma_before: cur_sigma,
                    patch_info: PatchKind::BranchIf {
                        func_idx,
                        true_block: *true_target,
                        false_block: *false_target,
                    },
                });
            }
            HirTerminator::Return => {
                let (opcode, op_salt) = isa.pick_opcode(VmOpKind::Return, &mut rng);
                plain_instrs.push(PlainInstr {
                    opcode,
                    op_salt,
                    kind: VmOpKind::Return,
                    arg1: rng.next_u64(),
                    arg2: rng.next_u64(),
                    arg3: rng.next_u64(),
                    sigma_before: cur_sigma,
                    patch_info: PatchKind::None,
                });
            }
            HirTerminator::Unreachable => {
                let (opcode, op_salt) = isa.pick_opcode(VmOpKind::Unreachable, &mut rng);
                plain_instrs.push(PlainInstr {
                    opcode,
                    op_salt,
                    kind: VmOpKind::Unreachable,
                    arg1: rng.next_u64(),
                    arg2: rng.next_u64(),
                    arg3: rng.next_u64(),
                    sigma_before: cur_sigma,
                    patch_info: PatchKind::None,
                });
            }
        }
    }

    // 4. 함수 엔트리 테이블 구성
    let mut func_entries = Vec::with_capacity(module.functions.len());
    for func in &module.functions {
        let entry_pc = *block_start_pc
            .get(&(func.func_idx, func.entry_block))
            .expect("함수 엔트리 PC 누락");
        let entry_sigma = *block_entry_sigma
            .get(&(func.func_idx, func.entry_block))
            .expect("함수 엔트리 Sigma 누락");
        func_entries.push(CompiledFuncEntry {
            name: func.name.clone(),
            func_idx: func.func_idx,
            num_params: func.num_params,
            num_locals: func.num_locals,
            entry_pc,
            entry_sigma,
        });
    }

    // 5. 분기 명령어들의 타겟 PC 및 간선 상태 보정값(Edge Transition Delta: Δ_{u -> v}) 패치
    for i in 0..plain_instrs.len() {
        let patch = plain_instrs[i].patch_info.clone();
        match patch {
            PatchKind::None => {}
            PatchKind::Jump {
                func_idx,
                target_block,
            } => {
                let target_pc = *block_start_pc
                    .get(&(func_idx, target_block))
                    .expect("Jump 타겟 PC 누락");
                let target_sigma = *block_entry_sigma
                    .get(&(func_idx, target_block))
                    .expect("Jump 타겟 Sigma 누락");

                let instr = &mut plain_instrs[i];
                instr.arg1 = target_pc as u64;
                let sigma_after =
                    sponge_step(instr.sigma_before, instr.op_salt, instr.arg1, golden_anchor);
                instr.arg3 = sigma_after ^ target_sigma;
            }
            PatchKind::BranchIf {
                func_idx,
                true_block,
                false_block,
            } => {
                let true_pc = *block_start_pc
                    .get(&(func_idx, true_block))
                    .expect("BranchIf True PC 누락");
                let false_pc = *block_start_pc
                    .get(&(func_idx, false_block))
                    .expect("BranchIf False PC 누락");
                let true_sigma = *block_entry_sigma
                    .get(&(func_idx, true_block))
                    .expect("BranchIf True Sigma 누락");
                let false_sigma = *block_entry_sigma
                    .get(&(func_idx, false_block))
                    .expect("BranchIf False Sigma 누락");

                let packed_targets = (true_pc as u64) | ((false_pc as u64) << 32);
                let instr = &mut plain_instrs[i];
                instr.arg1 = packed_targets;
                let sigma_after =
                    sponge_step(instr.sigma_before, instr.op_salt, instr.arg1, golden_anchor);
                instr.arg2 = sigma_after ^ true_sigma;
                instr.arg3 = sigma_after ^ false_sigma;
            }
            PatchKind::Call {
                callee_func_idx,
                arity,
            } => {
                let callee = &func_entries[callee_func_idx as usize];
                let packed_call = (callee.entry_pc as u64)
                    | ((arity as u64) << 32)
                    | ((callee.num_locals as u64) << 48);

                // Call 명령어 다음 명령어(복귀 지점)의 기대 스폰지 상태
                let next_sigma_after_return = if i + 1 < plain_instrs.len() {
                    plain_instrs[i + 1].sigma_before
                } else {
                    0
                };

                let instr = &mut plain_instrs[i];
                instr.arg1 = packed_call;
                instr.arg2 = callee.entry_sigma;
                let sigma_after =
                    sponge_step(instr.sigma_before, instr.op_salt, instr.arg1, golden_anchor);
                // 복귀 시 sigma_after ^ arg3 == next_sigma_after_return 이 되도록 보정
                instr.arg3 = sigma_after ^ next_sigma_after_return;
            }
        }
    }

    // 6. 모든 평문 명령어를 각자의 정준 진입 스폰지 상태(Σ_t), PC, 골든 앵커 및 핸들러별 전용 솔트 마스크로 이중 암호화
    let mut packets = Vec::with_capacity(plain_instrs.len());
    for (pc, instr) in plain_instrs.iter().enumerate() {
        let masks = sponge_masks(
            instr.sigma_before,
            pc,
            isa.sponge_k0,
            isa.sponge_k1,
            golden_anchor,
        );
        let h_masks = handler_arg_masks(instr.op_salt, instr.opcode, instr.sigma_before, pc);
        let noise_high = rng.next_u64() & !0xFFu64;
        let raw_w0 = noise_high | (instr.opcode as u64);

        packets.push(EncryptedPacket {
            w0: raw_w0 ^ masks[0],
            w1: instr.arg1 ^ masks[1] ^ h_masks[0],
            w2: instr.arg2 ^ masks[2] ^ h_masks[1],
            w3: instr.arg3 ^ masks[3] ^ h_masks[2],
        });
    }

    EncryptedProgram {
        packets,
        func_entries,
        exported_funcs: module.exported_funcs.clone(),
        initial_memory: module.initial_memory.clone(),
        golden_anchor,
    }
}

fn lower_hir_op(op: &HirOp) -> (VmOpKind, u64, u64, PatchKind) {
    match op {
        HirOp::Nop => (VmOpKind::Nop, 0, 0, PatchKind::None),
        HirOp::Drop => (VmOpKind::Drop, 0, 0, PatchKind::None),
        HirOp::Select => (VmOpKind::Select, 0, 0, PatchKind::None),
        HirOp::Const64(v) => (VmOpKind::Const64, *v, 0, PatchKind::None),
        HirOp::LocalGet(idx) => (VmOpKind::LocalGet, *idx as u64, 0, PatchKind::None),
        HirOp::LocalSet(idx) => (VmOpKind::LocalSet, *idx as u64, 0, PatchKind::None),
        HirOp::LocalTee(idx) => (VmOpKind::LocalTee, *idx as u64, 0, PatchKind::None),
        HirOp::GlobalGet(idx) => (VmOpKind::GlobalGet, *idx as u64, 0, PatchKind::None),
        HirOp::GlobalSet(idx) => (VmOpKind::GlobalSet, *idx as u64, 0, PatchKind::None),

        HirOp::Add64 => (VmOpKind::Add64, 0, 0, PatchKind::None),
        HirOp::Sub64 => (VmOpKind::Sub64, 0, 0, PatchKind::None),
        HirOp::Mul64 => (VmOpKind::Mul64, 0, 0, PatchKind::None),
        HirOp::DivS64 => (VmOpKind::DivS64, 0, 0, PatchKind::None),
        HirOp::DivU64 => (VmOpKind::DivU64, 0, 0, PatchKind::None),
        HirOp::RemS64 => (VmOpKind::RemS64, 0, 0, PatchKind::None),
        HirOp::RemU64 => (VmOpKind::RemU64, 0, 0, PatchKind::None),
        HirOp::And64 => (VmOpKind::And64, 0, 0, PatchKind::None),
        HirOp::Or64 => (VmOpKind::Or64, 0, 0, PatchKind::None),
        HirOp::Xor64 => (VmOpKind::Xor64, 0, 0, PatchKind::None),
        HirOp::Shl64 => (VmOpKind::Shl64, 0, 0, PatchKind::None),
        HirOp::ShrS64 => (VmOpKind::ShrS64, 0, 0, PatchKind::None),
        HirOp::ShrU64 => (VmOpKind::ShrU64, 0, 0, PatchKind::None),
        HirOp::Rotl64 => (VmOpKind::Rotl64, 0, 0, PatchKind::None),
        HirOp::Rotr64 => (VmOpKind::Rotr64, 0, 0, PatchKind::None),

        HirOp::Add32 => (VmOpKind::Add32, 0, 0, PatchKind::None),
        HirOp::Sub32 => (VmOpKind::Sub32, 0, 0, PatchKind::None),
        HirOp::Mul32 => (VmOpKind::Mul32, 0, 0, PatchKind::None),
        HirOp::DivS32 => (VmOpKind::DivS32, 0, 0, PatchKind::None),
        HirOp::DivU32 => (VmOpKind::DivU32, 0, 0, PatchKind::None),
        HirOp::RemS32 => (VmOpKind::RemS32, 0, 0, PatchKind::None),
        HirOp::RemU32 => (VmOpKind::RemU32, 0, 0, PatchKind::None),
        HirOp::And32 => (VmOpKind::And32, 0, 0, PatchKind::None),
        HirOp::Or32 => (VmOpKind::Or32, 0, 0, PatchKind::None),
        HirOp::Xor32 => (VmOpKind::Xor32, 0, 0, PatchKind::None),
        HirOp::Shl32 => (VmOpKind::Shl32, 0, 0, PatchKind::None),
        HirOp::ShrS32 => (VmOpKind::ShrS32, 0, 0, PatchKind::None),
        HirOp::ShrU32 => (VmOpKind::ShrU32, 0, 0, PatchKind::None),
        HirOp::Rotl32 => (VmOpKind::Rotl32, 0, 0, PatchKind::None),
        HirOp::Rotr32 => (VmOpKind::Rotr32, 0, 0, PatchKind::None),

        HirOp::Eqz64 => (VmOpKind::Eqz64, 0, 0, PatchKind::None),
        HirOp::Eq64 => (VmOpKind::Eq64, 0, 0, PatchKind::None),
        HirOp::Ne64 => (VmOpKind::Ne64, 0, 0, PatchKind::None),
        HirOp::LtS64 => (VmOpKind::LtS64, 0, 0, PatchKind::None),
        HirOp::LtU64 => (VmOpKind::LtU64, 0, 0, PatchKind::None),
        HirOp::GtS64 => (VmOpKind::GtS64, 0, 0, PatchKind::None),
        HirOp::GtU64 => (VmOpKind::GtU64, 0, 0, PatchKind::None),
        HirOp::LeS64 => (VmOpKind::LeS64, 0, 0, PatchKind::None),
        HirOp::LeU64 => (VmOpKind::LeU64, 0, 0, PatchKind::None),
        HirOp::GeS64 => (VmOpKind::GeS64, 0, 0, PatchKind::None),
        HirOp::GeU64 => (VmOpKind::GeU64, 0, 0, PatchKind::None),

        HirOp::Eqz32 => (VmOpKind::Eqz32, 0, 0, PatchKind::None),
        HirOp::Eq32 => (VmOpKind::Eq32, 0, 0, PatchKind::None),
        HirOp::Ne32 => (VmOpKind::Ne32, 0, 0, PatchKind::None),
        HirOp::LtS32 => (VmOpKind::LtS32, 0, 0, PatchKind::None),
        HirOp::LtU32 => (VmOpKind::LtU32, 0, 0, PatchKind::None),
        HirOp::GtS32 => (VmOpKind::GtS32, 0, 0, PatchKind::None),
        HirOp::GtU32 => (VmOpKind::GtU32, 0, 0, PatchKind::None),
        HirOp::LeS32 => (VmOpKind::LeS32, 0, 0, PatchKind::None),
        HirOp::LeU32 => (VmOpKind::LeU32, 0, 0, PatchKind::None),
        HirOp::GeS32 => (VmOpKind::GeS32, 0, 0, PatchKind::None),
        HirOp::GeU32 => (VmOpKind::GeU32, 0, 0, PatchKind::None),

        HirOp::WrapI64ToI32 => (VmOpKind::WrapI64ToI32, 0, 0, PatchKind::None),
        HirOp::ExtendI32S => (VmOpKind::ExtendI32S, 0, 0, PatchKind::None),
        HirOp::ExtendI32U => (VmOpKind::ExtendI32U, 0, 0, PatchKind::None),

        HirOp::Load32(off) => (VmOpKind::Load32, *off as u64, 0, PatchKind::None),
        HirOp::Load64(off) => (VmOpKind::Load64, *off as u64, 0, PatchKind::None),
        HirOp::Load8U(off) => (VmOpKind::Load8U, *off as u64, 0, PatchKind::None),
        HirOp::Load8S(off) => (VmOpKind::Load8S, *off as u64, 0, PatchKind::None),
        HirOp::Store32(off) => (VmOpKind::Store32, *off as u64, 0, PatchKind::None),
        HirOp::Store64(off) => (VmOpKind::Store64, *off as u64, 0, PatchKind::None),
        HirOp::Store8(off) => (VmOpKind::Store8, *off as u64, 0, PatchKind::None),

        HirOp::Call { func_idx, arity } => (
            VmOpKind::Call,
            0,
            0,
            PatchKind::Call {
                callee_func_idx: *func_idx,
                arity: *arity,
            },
        ),

        HirOp::FusedLocalAddImm {
            local_idx,
            imm,
            is_32,
        } => {
            let kind = if *is_32 {
                VmOpKind::FusedLocalAddImm32
            } else {
                VmOpKind::FusedLocalAddImm64
            };
            (kind, *local_idx as u64, *imm, PatchKind::None)
        }
        HirOp::FusedLocalAddLocal { a, b, is_32 } => {
            let kind = if *is_32 {
                VmOpKind::FusedLocalAddLocal32
            } else {
                VmOpKind::FusedLocalAddLocal64
            };
            (kind, *a as u64, *b as u64, PatchKind::None)
        }
        HirOp::FusedLocalXorLocal { a, b, is_32 } => {
            let kind = if *is_32 {
                VmOpKind::FusedLocalXorLocal32
            } else {
                VmOpKind::FusedLocalXorLocal64
            };
            (kind, *a as u64, *b as u64, PatchKind::None)
        }
    }
}

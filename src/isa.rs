use crate::mba::Prng;
use std::collections::HashMap;

/// EREBUS VM의 정규화된 논리 연산 종류 (총 60종)
/// 각 연산 종류는 빌드 시마다 256개 오피코드 공간 내에 다중 변종(1-to-N)으로 무작위 매핑됩니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VmOpKind {
    Nop,
    Drop,
    Select,
    Const64,
    LocalGet,
    LocalSet,
    LocalTee,
    GlobalGet,
    GlobalSet,

    Add64,
    Sub64,
    Mul64,
    DivS64,
    DivU64,
    RemS64,
    RemU64,
    And64,
    Or64,
    Xor64,
    Shl64,
    ShrS64,
    ShrU64,
    Rotl64,
    Rotr64,

    Add32,
    Sub32,
    Mul32,
    DivS32,
    DivU32,
    RemS32,
    RemU32,
    And32,
    Or32,
    Xor32,
    Shl32,
    ShrS32,
    ShrU32,
    Rotl32,
    Rotr32,

    Eqz64,
    Eq64,
    Ne64,
    LtS64,
    LtU64,
    GtS64,
    GtU64,
    LeS64,
    LeU64,
    GeS64,
    GeU64,

    Eqz32,
    Eq32,
    Ne32,
    LtS32,
    LtU32,
    GtS32,
    GtU32,
    LeS32,
    LeU32,
    GeS32,
    GeU32,

    WrapI64ToI32,
    ExtendI32S,
    ExtendI32U,

    Load32,
    Load64,
    Load8U,
    Load8S,
    Store32,
    Store64,
    Store8,

    Call,

    // 슈퍼인스트럭션
    FusedLocalAddImm64,
    FusedLocalAddImm32,
    FusedLocalAddLocal64,
    FusedLocalAddLocal32,
    FusedLocalXorLocal64,
    FusedLocalXorLocal32,

    // 제어 흐름 종료자 (Terminators)
    Jump,
    BranchIf,
    Return,
    Unreachable,
}

impl VmOpKind {
    pub fn all_kinds() -> &'static [VmOpKind] {
        use VmOpKind::*;
        &[
            Nop,
            Drop,
            Select,
            Const64,
            LocalGet,
            LocalSet,
            LocalTee,
            GlobalGet,
            GlobalSet,
            Add64,
            Sub64,
            Mul64,
            DivS64,
            DivU64,
            RemS64,
            RemU64,
            And64,
            Or64,
            Xor64,
            Shl64,
            ShrS64,
            ShrU64,
            Rotl64,
            Rotr64,
            Add32,
            Sub32,
            Mul32,
            DivS32,
            DivU32,
            RemS32,
            RemU32,
            And32,
            Or32,
            Xor32,
            Shl32,
            ShrS32,
            ShrU32,
            Rotl32,
            Rotr32,
            Eqz64,
            Eq64,
            Ne64,
            LtS64,
            LtU64,
            GtS64,
            GtU64,
            LeS64,
            LeU64,
            GeS64,
            GeU64,
            Eqz32,
            Eq32,
            Ne32,
            LtS32,
            LtU32,
            GtS32,
            GtU32,
            LeS32,
            LeU32,
            GeS32,
            GeU32,
            WrapI64ToI32,
            ExtendI32S,
            ExtendI32U,
            Load32,
            Load64,
            Load8U,
            Load8S,
            Store32,
            Store64,
            Store8,
            Call,
            FusedLocalAddImm64,
            FusedLocalAddImm32,
            FusedLocalAddLocal64,
            FusedLocalAddLocal32,
            FusedLocalXorLocal64,
            FusedLocalXorLocal32,
            Jump,
            BranchIf,
            Return,
            Unreachable,
        ]
    }
}

/// 256개 오피코드 슬롯 각각의 정체성
#[derive(Debug, Clone)]
pub enum HandlerSpec {
    /// 실제 논리 연산을 수행하는 다형성 핸들러 (variant_idx에 따라 서로 다른 MBA 수식 사용)
    Real {
        kind: VmOpKind,
        variant_idx: usize,
        op_secret_salt: u64,
    },
    /// 정적 분석기를 교란하기 위해 삽입된 가짜(Chaff/Decoy) 핸들러
    Chaff {
        chaff_seed: u64,
        op_secret_salt: u64,
    },
}

/// 빌드별 일회용 다형성 ISA (Per-Build Ephemeral ISA)
#[derive(Debug, Clone)]
pub struct PolymorphicIsa {
    pub build_seed: u64,
    /// 256개의 전체 핸들러 슬롯 명세
    pub handlers: Vec<HandlerSpec>,
    /// 각 논리 연산(VmOpKind)에 할당된 복수의 오피코드 목록 (1-to-N 매핑)
    pub op_to_opcodes: HashMap<VmOpKind, Vec<u8>>,
    /// 스폰지 키스트림 합성 및 무결성 얽힘용 빌드 고유 상수들
    pub sponge_k0: u64,
    pub sponge_k1: u64,
    pub dispatch_rot: u32,
    pub integrity_anchor_seed: u64,
}

impl PolymorphicIsa {
    /// 주어진 시드(build_seed)로부터 완전히 새로운 256-슬롯 다형성 ISA를 합성합니다.
    pub fn synthesize(build_seed: u64) -> Self {
        let mut rng = Prng::new(build_seed);

        // 0..256 오피코드 배열 생성 후 Fisher-Yates 셔플
        let mut pool: Vec<u8> = (0..=255u8).collect();
        for i in (1..256).rev() {
            let j = rng.next_range(i + 1);
            pool.swap(i, j);
        }

        let mut handlers: Vec<Option<HandlerSpec>> = vec![None; 256];
        let mut op_to_opcodes: HashMap<VmOpKind, Vec<u8>> = HashMap::new();
        let mut cursor = 0;

        let all_kinds = VmOpKind::all_kinds();

        // 각 연산 종류마다 2개씩(핵심 산술/분기 연산은 3개씩) 동형 오피코드 할당
        for &kind in all_kinds {
            let replicas = match kind {
                VmOpKind::Const64
                | VmOpKind::Add64
                | VmOpKind::Sub64
                | VmOpKind::Xor64
                | VmOpKind::Add32
                | VmOpKind::Sub32
                | VmOpKind::Jump
                | VmOpKind::BranchIf => 3,
                _ => 2,
            };

            let mut assigned = Vec::with_capacity(replicas);
            for v_idx in 0..replicas {
                if cursor >= 256 {
                    break;
                }
                let opcode = pool[cursor];
                cursor += 1;
                let salt = rng.next_odd_u64();
                handlers[opcode as usize] = Some(HandlerSpec::Real {
                    kind,
                    variant_idx: v_idx,
                    op_secret_salt: salt,
                });
                assigned.push(opcode);
            }
            op_to_opcodes.insert(kind, assigned);
        }

        // 남은 모든 오피코드 슬롯을 가짜(Chaff/Decoy) 핸들러로 채움
        while cursor < 256 {
            let opcode = pool[cursor];
            cursor += 1;
            handlers[opcode as usize] = Some(HandlerSpec::Chaff {
                chaff_seed: rng.next_u64(),
                op_secret_salt: rng.next_odd_u64(),
            });
        }

        let final_handlers: Vec<HandlerSpec> =
            handlers.into_iter().map(|h| h.unwrap()).collect();

        Self {
            build_seed,
            handlers: final_handlers,
            op_to_opcodes,
            sponge_k0: rng.next_odd_u64(),
            sponge_k1: rng.next_odd_u64(),
            dispatch_rot: ((rng.next_u64() % 53) + 5) as u32,
            integrity_anchor_seed: rng.next_odd_u64(),
        }
    }

    /// 특정 논리 연산에 대해 다형성 오피코드 하나를 무작위로 선택합니다.
    pub fn pick_opcode(&self, kind: VmOpKind, rng: &mut Prng) -> (u8, u64) {
        let codes = self
            .op_to_opcodes
            .get(&kind)
            .expect("등록되지 않은 VmOpKind");
        let opcode = codes[rng.next_range(codes.len())];
        let salt = match &self.handlers[opcode as usize] {
            HandlerSpec::Real { op_secret_salt, .. } => *op_secret_salt,
            HandlerSpec::Chaff { op_secret_salt, .. } => *op_secret_salt,
        };
        (opcode, salt)
    }
}

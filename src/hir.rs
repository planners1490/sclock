use std::collections::HashMap;

/// Erebus HIR (Hybrid Stack-Register Intermediate Representation)
/// 모든 입력 프로그램(WebAssembly / C / Rust 등)은 이 정규화된 마이크로 연산 및
/// 베이직 블록 제어 흐름 그래프(CFG)로 리프팅됩니다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HirOp {
    Nop,
    Drop,
    Select,

    // 상수 로드
    Const64(u64),

    // 지역 및 전역 변수 접근
    LocalGet(u32),
    LocalSet(u32),
    LocalTee(u32),
    GlobalGet(u32),
    GlobalSet(u32),

    // 64비트 산술 및 비트 연산 (32비트 연산도 부호/영 확장 규약에 맞춰 통합 처리)
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

    // 32비트 산술 및 비트 연산 (하위 32비트 마스킹 보존)
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

    // 비교 연산
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

    // 타입 확장/래핑
    WrapI64ToI32,
    ExtendI32S,
    ExtendI32U,

    // 선형 메모리 연산 (offset 포함)
    Load32(u32),
    Load64(u32),
    Load8U(u32),
    Load8S(u32),
    Store32(u32),
    Store64(u32),
    Store8(u32),

    // 내부 함수 호출 (함수 인덱스, 인자 개수)
    Call { func_idx: u32, arity: u32 },

    // === 슈퍼인스트럭션 (Superinstructions: 정적 패턴 추론 무력화용 융합 명령어) ===
    /// LocalGet(idx) + Const64(imm) + Add64/Add32
    FusedLocalAddImm { local_idx: u32, imm: u64, is_32: bool },
    /// LocalGet(a) + LocalGet(b) + Add64/Add32
    FusedLocalAddLocal { a: u32, b: u32, is_32: bool },
    /// LocalGet(a) + LocalGet(b) + Xor64/Xor32
    FusedLocalXorLocal { a: u32, b: u32, is_32: bool },
}

/// 베이직 블록의 종료자 (Terminator)
/// 모든 분기 타겟은 베이직 블록 ID(BlockId)를 가리키며,
/// 이후 스폰지 연쇄 암호화 단계에서 각 간선(Edge)마다 고유한 상태 전이 보정값(Delta)이 부여됩니다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HirTerminator {
    /// 무조건 점프 (target_block)
    Jump { target: usize },
    /// 조건부 분기: 스택 최상단 값이 0이 아니면 true_target, 0이면 false_target
    BranchIf {
        true_target: usize,
        false_target: usize,
    },
    /// 함수 반환 (스택 최상단 값 반환)
    Return,
    /// 도달 불가능 영역 (트랩)
    Unreachable,
}

#[derive(Debug, Clone)]
pub struct HirBasicBlock {
    pub id: usize,
    pub ops: Vec<HirOp>,
    pub terminator: HirTerminator,
}

#[derive(Debug, Clone)]
pub struct HirFunction {
    pub name: String,
    pub func_idx: u32,
    pub num_params: u32,
    pub num_locals: u32,
    pub entry_block: usize,
    pub blocks: Vec<HirBasicBlock>,
}

#[derive(Debug, Clone)]
pub struct HirModule {
    pub functions: Vec<HirFunction>,
    pub exported_funcs: HashMap<String, u32>,
    pub initial_memory: Vec<u8>,
}

impl HirFunction {
    /// 슈퍼인스트럭션 융합 (Superinstruction Fusion)
    /// 연속된 스택/로컬 연산을 하나의 복합 마이크로 명령어로 합쳐서
    /// 리버서가 개별 명령어의 경계나 데이터 흐름을 복원하지 못하게 만듭니다.
    pub fn fuse_superinstructions(&mut self) {
        for block in &mut self.blocks {
            let mut fused = Vec::with_capacity(block.ops.len());
            let mut i = 0;
            while i < block.ops.len() {
                if i + 2 < block.ops.len() {
                    match (&block.ops[i], &block.ops[i + 1], &block.ops[i + 2]) {
                        (HirOp::LocalGet(idx), HirOp::Const64(imm), HirOp::Add64) => {
                            fused.push(HirOp::FusedLocalAddImm {
                                local_idx: *idx,
                                imm: *imm,
                                is_32: false,
                            });
                            i += 3;
                            continue;
                        }
                        (HirOp::LocalGet(idx), HirOp::Const64(imm), HirOp::Add32) => {
                            fused.push(HirOp::FusedLocalAddImm {
                                local_idx: *idx,
                                imm: *imm,
                                is_32: true,
                            });
                            i += 3;
                            continue;
                        }
                        (HirOp::LocalGet(a), HirOp::LocalGet(b), HirOp::Add64) => {
                            fused.push(HirOp::FusedLocalAddLocal {
                                a: *a,
                                b: *b,
                                is_32: false,
                            });
                            i += 3;
                            continue;
                        }
                        (HirOp::LocalGet(a), HirOp::LocalGet(b), HirOp::Add32) => {
                            fused.push(HirOp::FusedLocalAddLocal {
                                a: *a,
                                b: *b,
                                is_32: true,
                            });
                            i += 3;
                            continue;
                        }
                        (HirOp::LocalGet(a), HirOp::LocalGet(b), HirOp::Xor64) => {
                            fused.push(HirOp::FusedLocalXorLocal {
                                a: *a,
                                b: *b,
                                is_32: false,
                            });
                            i += 3;
                            continue;
                        }
                        (HirOp::LocalGet(a), HirOp::LocalGet(b), HirOp::Xor32) => {
                            fused.push(HirOp::FusedLocalXorLocal {
                                a: *a,
                                b: *b,
                                is_32: true,
                            });
                            i += 3;
                            continue;
                        }
                        _ => {}
                    }
                }
                fused.push(block.ops[i].clone());
                i += 1;
            }
            block.ops = fused;
        }
    }

    /// CFG 파쇄 (Basic Block Fission / Shattering)
    /// 큰 베이직 블록을 max_ops 단위의 마이크로 블록들로 쪼개고 암호화된 상태 전이 간선으로 연결합니다.
    /// 이를 통해 원본 제어 흐름 그래프의 토폴로지(루프/분기 형태)를 산산조각냅니다.
    pub fn shatter_cfg(&mut self, max_ops_per_block: usize) {
        if max_ops_per_block == 0 {
            return;
        }
        let mut next_id = self.blocks.len();
        let mut new_blocks = Vec::new();

        for block in self.blocks.drain(..) {
            if block.ops.len() <= max_ops_per_block {
                new_blocks.push(block);
                continue;
            }

            let chunks: Vec<Vec<HirOp>> = block
                .ops
                .chunks(max_ops_per_block)
                .map(|c| c.to_vec())
                .collect();

            let mut current_id = block.id;
            for (idx, chunk) in chunks.iter().enumerate() {
                let is_last = idx == chunks.len() - 1;
                if is_last {
                    new_blocks.push(HirBasicBlock {
                        id: current_id,
                        ops: chunk.clone(),
                        terminator: block.terminator.clone(),
                    });
                } else {
                    let sub_next_id = next_id;
                    next_id += 1;
                    new_blocks.push(HirBasicBlock {
                        id: current_id,
                        ops: chunk.clone(),
                        terminator: HirTerminator::Jump {
                            target: sub_next_id,
                        },
                    });
                    current_id = sub_next_id;
                }
            }
        }

        new_blocks.sort_by_key(|b| b.id);
        self.blocks = new_blocks;
    }
}

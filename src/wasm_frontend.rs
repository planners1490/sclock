use crate::hir::{HirBasicBlock, HirFunction, HirModule, HirOp, HirTerminator};
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone)]
struct FuncType {
    params: Vec<u8>,
    results: Vec<u8>,
}

#[derive(Debug, Clone)]
enum ControlFrame {
    Function {
        end_block: usize,
    },
    Block {
        end_block: usize,
    },
    Loop {
        header_block: usize,
        end_block: usize,
    },
    If {
        else_block: usize,
        end_block: usize,
        has_else: bool,
    },
}

impl ControlFrame {
    fn br_target(&self) -> usize {
        match self {
            ControlFrame::Function { end_block } => *end_block,
            ControlFrame::Block { end_block } => *end_block,
            ControlFrame::Loop { header_block, .. } => *header_block,
            ControlFrame::If { end_block, .. } => *end_block,
        }
    }
}

/// C/C++ 소스 파일을 Clang(wasm32 타겟) 및 wasm-ld를 통해 표준 .wasm 바이너리로 컴파일합니다.
pub fn compile_c_to_wasm_bytes(c_path: &Path) -> Result<Vec<u8>, String> {
    let tmp_dir = std::env::temp_dir();
    let stem = c_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("program");
    let obj_path = tmp_dir.join(format!("erebus_{}_{}.o", stem, std::process::id()));
    let wasm_path = tmp_dir.join(format!("erebus_{}_{}.wasm", stem, std::process::id()));

    // 1. clang --target=wasm32 -O2 -nostdlib -c
    let clang_status = Command::new("clang")
        .args([
            "--target=wasm32",
            "-O2",
            "-fno-builtin",
            "-nostdlib",
            "-c",
            c_path.to_str().unwrap(),
            "-o",
            obj_path.to_str().unwrap(),
        ])
        .output()
        .map_err(|e| format!("clang 실행 실패: {}", e))?;

    if !clang_status.status.success() {
        return Err(format!(
            "C -> Wasm 오브젝트 컴파일 실패:\n{}",
            String::from_utf8_lossy(&clang_status.stderr)
        ));
    }

    // 2. wasm-ld 경로 및 DYLD_LIBRARY_PATH 탐색
    let (wasm_ld, lib_dir) =
        find_wasm_ld().ok_or_else(|| "시스템에서 wasm-ld를 찾을 수 없습니다.".to_string())?;

    let mut ld_cmd = Command::new(&wasm_ld);
    if let Some(ld_lib) = lib_dir {
        ld_cmd.env("DYLD_LIBRARY_PATH", ld_lib);
    }
    let ld_status = ld_cmd
        .args([
            "--no-entry",
            "--export-all",
            "--allow-undefined",
            obj_path.to_str().unwrap(),
            "-o",
            wasm_path.to_str().unwrap(),
        ])
        .output()
        .map_err(|e| format!("wasm-ld 실행 실패: {}", e))?;

    let _ = std::fs::remove_file(&obj_path);

    if !ld_status.status.success() {
        return Err(format!(
            "wasm-ld 링킹 실패:\n{}",
            String::from_utf8_lossy(&ld_status.stderr)
        ));
    }

    let bytes = std::fs::read(&wasm_path).map_err(|e| format!("Wasm 파일 읽기 실패: {}", e))?;
    let _ = std::fs::remove_file(&wasm_path);
    Ok(bytes)
}

fn find_wasm_ld() -> Option<(String, Option<String>)> {
    if let Ok(output) = Command::new("which").arg("wasm-ld").output() {
        if output.status.success() {
            let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !s.is_empty() {
                return Some((s, None));
            }
        }
    }
    let home = std::env::var("HOME").ok()?;
    let rustup_dir = Path::new(&home).join(".rustup/toolchains");
    if let Ok(entries) = std::fs::read_dir(rustup_dir) {
        for entry in entries.flatten() {
            let lib_dir = entry.path().join("lib").to_str().map(|s| s.to_string());
            let candidate = entry
                .path()
                .join("lib/rustlib/aarch64-apple-darwin/bin/gcc-ld/wasm-ld");
            if candidate.exists() {
                return candidate.to_str().map(|s| (s.to_string(), lib_dir));
            }
            let candidate_x86 = entry
                .path()
                .join("lib/rustlib/x86_64-apple-darwin/bin/gcc-ld/wasm-ld");
            if candidate_x86.exists() {
                return candidate_x86.to_str().map(|s| (s.to_string(), lib_dir));
            }
        }
    }
    None
}

struct ByteReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn is_eof(&self) -> bool {
        self.pos >= self.data.len()
    }

    fn read_u8(&mut self) -> Result<u8, String> {
        if self.pos >= self.data.len() {
            return Err("예기치 않은 바이트 스트림 종료 (EOF)".to_string());
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], String> {
        if self.pos + len > self.data.len() {
            return Err("바이트 슬라이스 읽기 범위 초과".to_string());
        }
        let slice = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }

    fn read_uleb128(&mut self) -> Result<u64, String> {
        let mut result: u64 = 0;
        let mut shift = 0;
        loop {
            let byte = self.read_u8()?;
            result |= ((byte & 0x7F) as u64) << shift;
            if (byte & 0x80) == 0 {
                break;
            }
            shift += 7;
            if shift >= 64 {
                return Err("ULEB128 오버플로우".to_string());
            }
        }
        Ok(result)
    }

    fn read_sleb128(&mut self) -> Result<i64, String> {
        let mut result: i64 = 0;
        let mut shift = 0;
        let mut byte: u8;
        loop {
            byte = self.read_u8()?;
            result |= ((byte & 0x7F) as i64) << shift;
            shift += 7;
            if (byte & 0x80) == 0 {
                break;
            }
            if shift >= 64 {
                return Err("SLEB128 오버플로우".to_string());
            }
        }
        if shift < 64 && (byte & 0x40) != 0 {
            result |= !0i64 << shift;
        }
        Ok(result)
    }
}

/// 표준 WebAssembly (.wasm) 바이너리를 파싱하여 Erebus HIR 모듈로 리프팅합니다.
pub fn parse_wasm_binary(bytes: &[u8]) -> Result<HirModule, String> {
    if bytes.len() < 8 || &bytes[0..4] != b"\0asm" {
        return Err("유효한 WebAssembly 바이너리 헤더(\\0asm)가 아닙니다.".to_string());
    }

    let mut reader = ByteReader::new(&bytes[8..]);
    let mut types: Vec<FuncType> = Vec::new();
    let mut func_type_indices: Vec<u32> = Vec::new();
    let mut exported_funcs: HashMap<String, u32> = HashMap::new();
    let mut code_bodies: Vec<&[u8]> = Vec::new();
    let mut initial_memory = vec![0u8; 65536];

    while !reader.is_eof() {
        let section_id = reader.read_u8()?;
        let section_len = reader.read_uleb128()? as usize;
        let section_bytes = reader.read_bytes(section_len)?;
        let mut sec = ByteReader::new(section_bytes);

        match section_id {
            1 => {
                // Type Section
                let count = sec.read_uleb128()? as usize;
                for _ in 0..count {
                    let form = sec.read_u8()?;
                    if form != 0x60 {
                        return Err(format!("지원하지 않는 함수 타입 포맷: 0x{:02x}", form));
                    }
                    let param_count = sec.read_uleb128()? as usize;
                    let mut params = Vec::with_capacity(param_count);
                    for _ in 0..param_count {
                        params.push(sec.read_u8()?);
                    }
                    let result_count = sec.read_uleb128()? as usize;
                    let mut results = Vec::with_capacity(result_count);
                    for _ in 0..result_count {
                        results.push(sec.read_u8()?);
                    }
                    types.push(FuncType { params, results });
                }
            }
            3 => {
                // Function Section
                let count = sec.read_uleb128()? as usize;
                for _ in 0..count {
                    func_type_indices.push(sec.read_uleb128()? as u32);
                }
            }
            7 => {
                // Export Section
                let count = sec.read_uleb128()? as usize;
                for _ in 0..count {
                    let name_len = sec.read_uleb128()? as usize;
                    let name_bytes = sec.read_bytes(name_len)?;
                    let name = String::from_utf8_lossy(name_bytes).to_string();
                    let kind = sec.read_u8()?;
                    let idx = sec.read_uleb128()? as u32;
                    if kind == 0x00 {
                        exported_funcs.insert(name, idx);
                    }
                }
            }
            10 => {
                // Code Section
                let count = sec.read_uleb128()? as usize;
                for _ in 0..count {
                    let body_size = sec.read_uleb128()? as usize;
                    let body_bytes = sec.read_bytes(body_size)?;
                    code_bodies.push(body_bytes);
                }
            }
            11 => {
                // Data Section (선형 메모리 초기화 데이터)
                let count = sec.read_uleb128()? as usize;
                for _ in 0..count {
                    let mode = sec.read_uleb128()?;
                    let mut offset: usize = 0;
                    if mode == 0 {
                        // Active segment with offset expr
                        loop {
                            let op = sec.read_u8()?;
                            match op {
                                0x41 => {
                                    offset = sec.read_sleb128()? as u32 as usize;
                                }
                                0x42 => {
                                    offset = sec.read_sleb128()? as usize;
                                }
                                0x0B => break,
                                _ => {}
                            }
                        }
                    }
                    let data_len = sec.read_uleb128()? as usize;
                    let data_slice = sec.read_bytes(data_len)?;
                    if offset + data_len > initial_memory.len() {
                        initial_memory.resize(offset + data_len + 4096, 0);
                    }
                    initial_memory[offset..offset + data_len].copy_from_slice(data_slice);
                }
            }
            _ => {
                // 기타 섹션(Custom, Memory, Global, Table 등)은 건너뜀
            }
        }
    }

    let mut rev_exports: HashMap<u32, String> = HashMap::new();
    for (k, v) in &exported_funcs {
        rev_exports.insert(*v, k.clone());
    }

    let mut functions = Vec::with_capacity(code_bodies.len());
    for (idx, body_bytes) in code_bodies.iter().enumerate() {
        let func_idx = idx as u32;
        let type_idx = *func_type_indices
            .get(idx)
            .ok_or_else(|| "함수 타입 인덱스 누락".to_string())? as usize;
        let func_type = types
            .get(type_idx)
            .ok_or_else(|| "함수 시그니처 정보 누락".to_string())?;
        let name = rev_exports
            .get(&func_idx)
            .cloned()
            .unwrap_or_else(|| format!("func_{}", func_idx));

        let hir_func = lift_wasm_function(
            func_idx,
            name,
            func_type,
            &types,
            &func_type_indices,
            body_bytes,
        )?;
        functions.push(hir_func);
    }

    Ok(HirModule {
        functions,
        exported_funcs,
        initial_memory,
    })
}

fn lift_wasm_function(
    func_idx: u32,
    name: String,
    func_type: &FuncType,
    all_types: &[FuncType],
    func_type_indices: &[u32],
    body_bytes: &[u8],
) -> Result<HirFunction, String> {
    let mut r = ByteReader::new(body_bytes);
    let local_decl_count = r.read_uleb128()? as usize;
    let mut num_locals: u32 = 0;
    for _ in 0..local_decl_count {
        let n = r.read_uleb128()? as u32;
        let _val_type = r.read_u8()?;
        num_locals += n;
    }

    let num_params = func_type.params.len() as u32;
    // br_table 디슈가링용 내부 스크래치 로컬 슬롯 1개 추가 할당
    let scratch_local = num_params + num_locals;
    let total_locals = num_locals + 1;

    let mut blocks: Vec<HirBasicBlock> = Vec::new();
    let alloc_block = |blocks: &mut Vec<HirBasicBlock>| -> usize {
        let id = blocks.len();
        blocks.push(HirBasicBlock {
            id,
            ops: Vec::new(),
            terminator: HirTerminator::Return,
        });
        id
    };

    let entry_block = alloc_block(&mut blocks);
    let func_end_block = alloc_block(&mut blocks);
    blocks[func_end_block].terminator = HirTerminator::Return;

    let mut cur_block = entry_block;
    let mut is_unreachable = false;

    let mut frames: Vec<ControlFrame> = vec![ControlFrame::Function {
        end_block: func_end_block,
    }];

    while !r.is_eof() {
        let op = r.read_u8()?;

        // 제어 흐름 구조 명령어는 unreachable 상태에서도 파싱하여 중첩 깊이를 맞춰야 함
        match op {
            0x02 => {
                // block
                let _block_type = r.read_sleb128()?;
                let end_block = alloc_block(&mut blocks);
                frames.push(ControlFrame::Block { end_block });
                continue;
            }
            0x03 => {
                // loop
                let _block_type = r.read_sleb128()?;
                let header_block = alloc_block(&mut blocks);
                let end_block = alloc_block(&mut blocks);
                if !is_unreachable {
                    blocks[cur_block].terminator = HirTerminator::Jump {
                        target: header_block,
                    };
                }
                cur_block = header_block;
                is_unreachable = false;
                frames.push(ControlFrame::Loop {
                    header_block,
                    end_block,
                });
                continue;
            }
            0x04 => {
                // if
                let _block_type = r.read_sleb128()?;
                let then_block = alloc_block(&mut blocks);
                let else_block = alloc_block(&mut blocks);
                let end_block = alloc_block(&mut blocks);
                if !is_unreachable {
                    blocks[cur_block].terminator = HirTerminator::BranchIf {
                        true_target: then_block,
                        false_target: else_block,
                    };
                }
                cur_block = then_block;
                is_unreachable = false;
                frames.push(ControlFrame::If {
                    else_block,
                    end_block,
                    has_else: false,
                });
                continue;
            }
            0x05 => {
                // else
                if let Some(ControlFrame::If {
                    else_block,
                    end_block,
                    has_else,
                }) = frames.last_mut()
                {
                    *has_else = true;
                    let eb = *end_block;
                    let elb = *else_block;
                    if !is_unreachable {
                        blocks[cur_block].terminator = HirTerminator::Jump { target: eb };
                    }
                    cur_block = elb;
                    is_unreachable = false;
                } else {
                    return Err("대응하는 if 없는 else 발견".to_string());
                }
                continue;
            }
            0x0B => {
                // end
                let frame = frames
                    .pop()
                    .ok_or_else(|| "제어 프레임 스택 언더플로우".to_string())?;
                match frame {
                    ControlFrame::Function { end_block } => {
                        if !is_unreachable {
                            blocks[cur_block].terminator = HirTerminator::Jump { target: end_block };
                        }
                        blocks[end_block].terminator = HirTerminator::Return;
                        break;
                    }
                    ControlFrame::Block { end_block } | ControlFrame::Loop { end_block, .. } => {
                        if !is_unreachable {
                            blocks[cur_block].terminator = HirTerminator::Jump { target: end_block };
                        }
                        cur_block = end_block;
                        is_unreachable = false;
                    }
                    ControlFrame::If {
                        else_block,
                        end_block,
                        has_else,
                    } => {
                        if !is_unreachable {
                            blocks[cur_block].terminator = HirTerminator::Jump { target: end_block };
                        }
                        if !has_else {
                            blocks[else_block].terminator =
                                HirTerminator::Jump { target: end_block };
                        }
                        cur_block = end_block;
                        is_unreachable = false;
                    }
                }
                continue;
            }
            _ => {}
        }

        // 도달 불가능 상태에서도 피연산자 바이트는 정확히 소비해야 함
        if is_unreachable {
            skip_unreachable_operands(op, &mut r)?;
            continue;
        }

        match op {
            0x00 => {
                // unreachable
                blocks[cur_block].terminator = HirTerminator::Unreachable;
                is_unreachable = true;
            }
            0x01 => {
                // nop
                blocks[cur_block].ops.push(HirOp::Nop);
            }
            0x0C => {
                // br
                let depth = r.read_uleb128()? as usize;
                let frame_idx = frames
                    .len()
                    .checked_sub(1 + depth)
                    .ok_or_else(|| "br 깊이 초과".to_string())?;
                let target = frames[frame_idx].br_target();
                blocks[cur_block].terminator = HirTerminator::Jump { target };
                is_unreachable = true;
            }
            0x0D => {
                // br_if
                let depth = r.read_uleb128()? as usize;
                let frame_idx = frames
                    .len()
                    .checked_sub(1 + depth)
                    .ok_or_else(|| "br_if 깊이 초과".to_string())?;
                let target = frames[frame_idx].br_target();
                let fallthrough = alloc_block(&mut blocks);
                blocks[cur_block].terminator = HirTerminator::BranchIf {
                    true_target: target,
                    false_target: fallthrough,
                };
                cur_block = fallthrough;
            }
            0x0E => {
                // br_table -> 일련의 비교 및 조건 분기 체인으로 디슈가링
                let count = r.read_uleb128()? as usize;
                let mut targets = Vec::with_capacity(count);
                for _ in 0..count {
                    let d = r.read_uleb128()? as usize;
                    let f_idx = frames.len() - 1 - d;
                    targets.push(frames[f_idx].br_target());
                }
                let def_d = r.read_uleb128()? as usize;
                let def_target = frames[frames.len() - 1 - def_d].br_target();

                blocks[cur_block].ops.push(HirOp::LocalSet(scratch_local));
                for (i, t_blk) in targets.into_iter().enumerate() {
                    let next_check = alloc_block(&mut blocks);
                    blocks[cur_block].ops.push(HirOp::LocalGet(scratch_local));
                    blocks[cur_block].ops.push(HirOp::Const64(i as u64));
                    blocks[cur_block].ops.push(HirOp::Eq32);
                    blocks[cur_block].terminator = HirTerminator::BranchIf {
                        true_target: t_blk,
                        false_target: next_check,
                    };
                    cur_block = next_check;
                }
                blocks[cur_block].terminator = HirTerminator::Jump { target: def_target };
                is_unreachable = true;
            }
            0x0F => {
                // return
                blocks[cur_block].terminator = HirTerminator::Return;
                is_unreachable = true;
            }
            0x10 => {
                // call
                let callee_idx = r.read_uleb128()? as u32;
                let callee_type_idx = *func_type_indices
                    .get(callee_idx as usize)
                    .ok_or_else(|| "호출 대상 함수 인덱스 초과".to_string())?
                    as usize;
                let arity = all_types[callee_type_idx].params.len() as u32;
                blocks[cur_block].ops.push(HirOp::Call {
                    func_idx: callee_idx,
                    arity,
                });
            }
            0x1A => blocks[cur_block].ops.push(HirOp::Drop),
            0x1B => blocks[cur_block].ops.push(HirOp::Select),

            0x20 => {
                let idx = r.read_uleb128()? as u32;
                blocks[cur_block].ops.push(HirOp::LocalGet(idx));
            }
            0x21 => {
                let idx = r.read_uleb128()? as u32;
                blocks[cur_block].ops.push(HirOp::LocalSet(idx));
            }
            0x22 => {
                let idx = r.read_uleb128()? as u32;
                blocks[cur_block].ops.push(HirOp::LocalTee(idx));
            }
            0x23 => {
                let idx = r.read_uleb128()? as u32;
                blocks[cur_block].ops.push(HirOp::GlobalGet(idx));
            }
            0x24 => {
                let idx = r.read_uleb128()? as u32;
                blocks[cur_block].ops.push(HirOp::GlobalSet(idx));
            }

            // 메모리 연산 (align, offset)
            0x28 => {
                let _align = r.read_uleb128()?;
                let offset = r.read_uleb128()? as u32;
                blocks[cur_block].ops.push(HirOp::Load32(offset));
            }
            0x29 => {
                let _align = r.read_uleb128()?;
                let offset = r.read_uleb128()? as u32;
                blocks[cur_block].ops.push(HirOp::Load64(offset));
            }
            0x2C => {
                let _align = r.read_uleb128()?;
                let offset = r.read_uleb128()? as u32;
                blocks[cur_block].ops.push(HirOp::Load8S(offset));
            }
            0x2D | 0x30 => {
                let _align = r.read_uleb128()?;
                let offset = r.read_uleb128()? as u32;
                blocks[cur_block].ops.push(HirOp::Load8U(offset));
            }
            0x36 => {
                let _align = r.read_uleb128()?;
                let offset = r.read_uleb128()? as u32;
                blocks[cur_block].ops.push(HirOp::Store32(offset));
            }
            0x37 => {
                let _align = r.read_uleb128()?;
                let offset = r.read_uleb128()? as u32;
                blocks[cur_block].ops.push(HirOp::Store64(offset));
            }
            0x3A | 0x3C => {
                let _align = r.read_uleb128()?;
                let offset = r.read_uleb128()? as u32;
                blocks[cur_block].ops.push(HirOp::Store8(offset));
            }

            // 상수
            0x41 => {
                let val = r.read_sleb128()? as i32 as u32 as u64;
                blocks[cur_block].ops.push(HirOp::Const64(val));
            }
            0x42 => {
                let val = r.read_sleb128()? as u64;
                blocks[cur_block].ops.push(HirOp::Const64(val));
            }

            // i32 비교
            0x45 => blocks[cur_block].ops.push(HirOp::Eqz32),
            0x46 => blocks[cur_block].ops.push(HirOp::Eq32),
            0x47 => blocks[cur_block].ops.push(HirOp::Ne32),
            0x48 => blocks[cur_block].ops.push(HirOp::LtS32),
            0x49 => blocks[cur_block].ops.push(HirOp::LtU32),
            0x4A => blocks[cur_block].ops.push(HirOp::GtS32),
            0x4B => blocks[cur_block].ops.push(HirOp::GtU32),
            0x4C => blocks[cur_block].ops.push(HirOp::LeS32),
            0x4D => blocks[cur_block].ops.push(HirOp::LeU32),
            0x4E => blocks[cur_block].ops.push(HirOp::GeS32),
            0x4F => blocks[cur_block].ops.push(HirOp::GeU32),

            // i64 비교
            0x50 => blocks[cur_block].ops.push(HirOp::Eqz64),
            0x51 => blocks[cur_block].ops.push(HirOp::Eq64),
            0x52 => blocks[cur_block].ops.push(HirOp::Ne64),
            0x53 => blocks[cur_block].ops.push(HirOp::LtS64),
            0x54 => blocks[cur_block].ops.push(HirOp::LtU64),
            0x55 => blocks[cur_block].ops.push(HirOp::GtS64),
            0x56 => blocks[cur_block].ops.push(HirOp::GtU64),
            0x57 => blocks[cur_block].ops.push(HirOp::LeS64),
            0x58 => blocks[cur_block].ops.push(HirOp::LeU64),
            0x59 => blocks[cur_block].ops.push(HirOp::GeS64),
            0x5A => blocks[cur_block].ops.push(HirOp::GeU64),

            // i32 산술/비트
            0x6A => blocks[cur_block].ops.push(HirOp::Add32),
            0x6B => blocks[cur_block].ops.push(HirOp::Sub32),
            0x6C => blocks[cur_block].ops.push(HirOp::Mul32),
            0x6D => blocks[cur_block].ops.push(HirOp::DivS32),
            0x6E => blocks[cur_block].ops.push(HirOp::DivU32),
            0x6F => blocks[cur_block].ops.push(HirOp::RemS32),
            0x70 => blocks[cur_block].ops.push(HirOp::RemU32),
            0x71 => blocks[cur_block].ops.push(HirOp::And32),
            0x72 => blocks[cur_block].ops.push(HirOp::Or32),
            0x73 => blocks[cur_block].ops.push(HirOp::Xor32),
            0x74 => blocks[cur_block].ops.push(HirOp::Shl32),
            0x75 => blocks[cur_block].ops.push(HirOp::ShrS32),
            0x76 => blocks[cur_block].ops.push(HirOp::ShrU32),
            0x77 => blocks[cur_block].ops.push(HirOp::Rotl32),
            0x78 => blocks[cur_block].ops.push(HirOp::Rotr32),

            // i64 산술/비트
            0x7C => blocks[cur_block].ops.push(HirOp::Add64),
            0x7D => blocks[cur_block].ops.push(HirOp::Sub64),
            0x7E => blocks[cur_block].ops.push(HirOp::Mul64),
            0x7F => blocks[cur_block].ops.push(HirOp::DivS64),
            0x80 => blocks[cur_block].ops.push(HirOp::DivU64),
            0x81 => blocks[cur_block].ops.push(HirOp::RemS64),
            0x82 => blocks[cur_block].ops.push(HirOp::RemU64),
            0x83 => blocks[cur_block].ops.push(HirOp::And64),
            0x84 => blocks[cur_block].ops.push(HirOp::Or64),
            0x85 => blocks[cur_block].ops.push(HirOp::Xor64),
            0x86 => blocks[cur_block].ops.push(HirOp::Shl64),
            0x87 => blocks[cur_block].ops.push(HirOp::ShrS64),
            0x88 => blocks[cur_block].ops.push(HirOp::ShrU64),
            0x89 => blocks[cur_block].ops.push(HirOp::Rotl64),
            0x8A => blocks[cur_block].ops.push(HirOp::Rotr64),

            // 타입 변환
            0xA7 => blocks[cur_block].ops.push(HirOp::WrapI64ToI32),
            0xAC => blocks[cur_block].ops.push(HirOp::ExtendI32S),
            0xAD => blocks[cur_block].ops.push(HirOp::ExtendI32U),

            other => {
                return Err(format!(
                    "함수 '{}' 내 미지원 Wasm 오피코드: 0x{:02x}",
                    name, other
                ));
            }
        }
    }

    Ok(HirFunction {
        name,
        func_idx,
        num_params,
        num_locals: total_locals,
        entry_block,
        blocks,
    })
}

fn skip_unreachable_operands(op: u8, r: &mut ByteReader) -> Result<(), String> {
    match op {
        0x0C | 0x0D | 0x10 | 0x20..=0x24 => {
            let _ = r.read_uleb128()?;
        }
        0x0E => {
            let count = r.read_uleb128()? as usize;
            for _ in 0..=count {
                let _ = r.read_uleb128()?;
            }
        }
        0x28..=0x3E => {
            let _ = r.read_uleb128()?;
            let _ = r.read_uleb128()?;
        }
        0x41 | 0x42 => {
            let _ = r.read_sleb128()?;
        }
        _ => {}
    }
    Ok(())
}

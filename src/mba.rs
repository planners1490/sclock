/// EREBUS Layer 4: 비선형 혼합 부울-산술 (Non-Linear MBA),
/// 유한환 Z_{2^64} 전단사 아핀/다항식 인코딩 및 2-adic 정수론적 불투명 술어 합성기

#[derive(Debug, Clone)]
pub struct Prng {
    state: u64,
}

impl Prng {
    pub fn new(seed: u64) -> Self {
        Self {
            state: seed ^ 0x9E37_79B9_7F4A_7C15,
        }
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut z = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        self.state = z;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    pub fn next_odd_u64(&mut self) -> u64 {
        self.next_u64() | 1
    }

    pub fn next_range(&mut self, max: usize) -> usize {
        if max == 0 {
            return 0;
        }
        (self.next_u64() as usize) % max
    }
}

/// 유한환 Z_{2^64} 위에서 홀수 a의 곱셈 역원 a^{-1} (mod 2^64)을 계산합니다.
/// 2-adic Newton-Raphson 반복: x_{k+1} = x_k * (2 - a * x_k) mod 2^64
pub fn mod_inverse_u64(a: u64) -> u64 {
    debug_assert!(a & 1 == 1, "짝수는 Z_{{2^64}}에서 곱셈 역원이 존재하지 않습니다.");
    let mut x = 1u64;
    for _ in 0..6 {
        x = x.wrapping_mul(2u64.wrapping_sub(a.wrapping_mul(x)));
    }
    debug_assert_eq!(a.wrapping_mul(x), 1);
    x
}

/// 상수 c를 유한환 Z_{2^64} 위의 전단사 아핀 변환 + MBA 수식으로 은폐하는 Rust 표현식을 생성합니다.
/// 레지스터 전용 인라인 어셈블리 장벽(__sc_rb)을 통해 스택 왕복(spill) 없이 LLVM(opt-level=3)의 상수 접기를 차단합니다.
pub fn obfuscate_constant_expr(c: u64, rng: &mut Prng) -> String {
    let a = rng.next_odd_u64();
    let a_inv = mod_inverse_u64(a);
    let b = rng.next_u64();
    let k = rng.next_u64();
    // 인코딩된 값: enc = a * (c ^ k) + b (mod 2^64)
    let enc = a.wrapping_mul(c ^ k).wrapping_add(b);
    // 디코딩: c = (a_inv * ((enc ^ b) - 2 * (!enc & b))) ^ k
    format!(
        "({{ let _e = __sc_rb({enc}u64); let _b = __sc_rb({b}u64); let _d = (_e ^ _b).wrapping_sub(((!_e) & _b).wrapping_shl(1)); let _m = __sc_rb({a_inv}u64).wrapping_mul(_d); (_m | {k}u64).wrapping_sub(_m & {k}u64) }})"
    )
}

/// 항상 0으로 평가되는 비선형 불투명 영 다항식 (Opaque Zero Polynomial over Z_{2^64})
/// __sc_rb로 SSA 레지스터를 분리하여 스택 오버헤드 없이 LLVM InstCombine 및 정적 디컴파일러의 대수적 단순화를 차단합니다.
pub fn synthesize_opaque_zero(x: &str, y: &str, rng: &mut Prng) -> String {
    let weight = rng.next_odd_u64();
    let rot = (rng.next_u64() % 61) + 1;
    match rng.next_range(3) {
        0 => {
            // ((x ^ y) + 2*(x & y)) - ((x | y) + (x & y)) === 0
            format!(
                "({{ let _zx = __sc_rb({x}); ((_zx ^ {y}).wrapping_add(({x} & {y}).wrapping_shl(1)).wrapping_sub(({x} | {y}).wrapping_add(_zx & {y}))).wrapping_mul({weight}u64.wrapping_add(_zx.rotate_left({rot}))) }})"
            )
        }
        1 => {
            // ((x | y) - (x & y)) - (x ^ y) === 0
            format!(
                "({{ let _zx = __sc_rb({x}); ((_zx | {y}).wrapping_sub({x} & {y}).wrapping_sub(_zx ^ {y})).wrapping_mul({weight}u64 ^ {y}.rotate_right({rot})) }})"
            )
        }
        _ => {
            // ((x & !y) + (x & y)) - x === 0
            format!(
                "({{ let _zx = __sc_rb({x}); ((_zx & (!{y})).wrapping_add({x} & {y}).wrapping_sub(_zx)).wrapping_mul({weight}u64) }})"
            )
        }
    }
}

/// 64비트 덧셈(x + y)에 대한 다형성 비선형 MBA 표현식 합성
pub fn synthesize_mba_add(x: &str, y: &str, variant: usize, rng: &mut Prng) -> String {
    let z = synthesize_opaque_zero(x, y, rng);
    let a = rng.next_odd_u64();
    let a_inv = mod_inverse_u64(a);
    let core = match variant % 4 {
        0 => format!(
            "({{ let _mx = __sc_rb({x}); (_mx ^ {y}).wrapping_add(({x} & {y}).wrapping_shl(1)) }})"
        ),
        1 => format!(
            "({{ let _mx = __sc_rb({x}); (_mx | {y}).wrapping_add({x} & {y}) }})"
        ),
        2 => format!(
            "({{ let _mx = __sc_rb({x}); (_mx | {y}).wrapping_shl(1).wrapping_sub({x} ^ {y}) }})"
        ),
        _ => format!(
            "({{ let _mx = __sc_rb({x}); __sc_rb({a_inv}u64).wrapping_mul(({a}u64.wrapping_mul(_mx ^ {y})).wrapping_add({a}u64.wrapping_mul(({x} & {y}).wrapping_shl(1)))) }})"
        ),
    };
    format!("({core}.wrapping_add({z}))")
}

/// 64비트 뺄셈(x - y)에 대한 다형성 비선형 MBA 표현식 합성
pub fn synthesize_mba_sub(x: &str, y: &str, variant: usize, rng: &mut Prng) -> String {
    let z = synthesize_opaque_zero(x, y, rng);
    let a = rng.next_odd_u64();
    let a_inv = mod_inverse_u64(a);
    let core = match variant % 4 {
        0 => format!(
            "({{ let _mx = __sc_rb({x}); (_mx ^ {y}).wrapping_sub(((!{x}) & {y}).wrapping_shl(1)) }})"
        ),
        1 => format!(
            "({{ let _mx = __sc_rb({x}); (_mx & (!{y})).wrapping_sub((!{x}) & {y}) }})"
        ),
        2 => format!(
            "({{ let _mx = __sc_rb({x}); (_mx ^ (!{y})).wrapping_add(({x} & (!{y})).wrapping_shl(1)).wrapping_add(1) }})"
        ),
        _ => format!(
            "({{ let _mx = __sc_rb({x}); __sc_rb({a_inv}u64).wrapping_mul(({a}u64.wrapping_mul(_mx & (!{y}))).wrapping_sub({a}u64.wrapping_mul((!{x}) & {y}))) }})"
        ),
    };
    format!("({core}.wrapping_add({z}))")
}

/// 64비트 XOR(x ^ y)에 대한 다형성 비선형 MBA 표현식 합성
pub fn synthesize_mba_xor(x: &str, y: &str, variant: usize, rng: &mut Prng) -> String {
    let z = synthesize_opaque_zero(x, y, rng);
    let a = rng.next_odd_u64();
    let a_inv = mod_inverse_u64(a);
    let core = match variant % 4 {
        0 => format!(
            "({{ let _mx = __sc_rb({x}); (_mx | {y}).wrapping_sub({x} & {y}) }})"
        ),
        1 => format!(
            "({{ let _mx = __sc_rb({x}); (_mx.wrapping_add({y})).wrapping_sub(({x} & {y}).wrapping_shl(1)) }})"
        ),
        2 => format!(
            "({{ let _mx = __sc_rb({x}); ((_mx & (!{y})) | ((!{x}) & {y})) }})"
        ),
        _ => format!(
            "({{ let _mx = __sc_rb({x}); __sc_rb({a_inv}u64).wrapping_mul(({a}u64.wrapping_mul(_mx | {y})).wrapping_sub({a}u64.wrapping_mul({x} & {y}))) }})"
        ),
    };
    format!("({core}.wrapping_add({z}))")
}

/// 64비트 AND(x & y)에 대한 다형성 비선형 MBA 표현식 합성
pub fn synthesize_mba_and(x: &str, y: &str, variant: usize, rng: &mut Prng) -> String {
    let z = synthesize_opaque_zero(x, y, rng);
    let core = match variant % 3 {
        0 => format!(
            "({{ let _mx = __sc_rb({x}); (_mx.wrapping_add({y})).wrapping_sub({x} | {y}) }})"
        ),
        1 => format!(
            "({{ let _mx = __sc_rb({x}); ((_mx | {y}).wrapping_sub({x} ^ {y})) }})"
        ),
        _ => format!(
            "({{ let _mx = __sc_rb({x}); (!((!_mx) | (!{y}))) }})"
        ),
    };
    format!("({core}.wrapping_add({z}))")
}

/// 64비트 OR(x | y)에 대한 다형성 비선형 MBA 표현식 합성
pub fn synthesize_mba_or(x: &str, y: &str, variant: usize, rng: &mut Prng) -> String {
    let z = synthesize_opaque_zero(x, y, rng);
    let core = match variant % 3 {
        0 => format!(
            "({{ let _mx = __sc_rb({x}); (_mx ^ {y}).wrapping_add({x} & {y}) }})"
        ),
        1 => format!(
            "({{ let _mx = __sc_rb({x}); (_mx.wrapping_add({y})).wrapping_sub({x} & {y}) }})"
        ),
        _ => format!(
            "({{ let _mx = __sc_rb({x}); (!((!_mx) & (!{y}))) }})"
        ),
    };
    format!("({core}.wrapping_add({z}))")
}

/// 2-adic 정수론적 불투명 술어 (항상 true로 평가되지만 정적 분석기와 SMT 솔버가 판별 불가능한 조건식)
/// - 변종 0: 7*x^2 - 1 != y^2 (mod 2^64) — 2-adic 이차 비잉여 정리(Quadratic Non-Residue mod 8)에 의해 절대 해가 없음
/// - 변종 1: (x * (x + 1)) & 1 == 0 — 연속된 두 정수의 곱은 항상 짝수
/// - 변종 2: (x^2 & 3) != 2 — 임의의 제곱수는 mod 4에서 절대 2가 될 수 없음
pub fn synthesize_opaque_true(x: &str, y: &str, variant: usize) -> String {
    match variant % 3 {
        0 => format!(
            "({{ let _ox = __sc_rb({x}); let _oy = __sc_rb({y}); 7u64.wrapping_mul(_ox.wrapping_mul({x})).wrapping_sub(1) != _oy.wrapping_mul({y}) }})"
        ),
        1 => format!(
            "({{ let _ox = __sc_rb({x}); ((_ox.wrapping_mul({x}.wrapping_add(1))) & __sc_rb(1u64)) == 0 }})"
        ),
        _ => format!(
            "({{ let _ox = __sc_rb({x}); ((_ox.wrapping_mul({x})) & __sc_rb(3u64)) != 2 }})"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mod_inverse() {
        let mut rng = Prng::new(0x12345678);
        for _ in 0..1000 {
            let a = rng.next_odd_u64();
            let inv = mod_inverse_u64(a);
            assert_eq!(a.wrapping_mul(inv), 1);
        }
    }
}

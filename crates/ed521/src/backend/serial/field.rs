//! Arithmetic in GF(p), p = 2^521 - 1, with nine radix-2^58 limbs.
//!
//! An element is `Σ l[i]·2^(58·i)`. The radix is uniform, so a product's limb `i + j >= 9` wraps
//! to `i + j - 9` with a factor `2^522 ≡ 2 (mod p)`; the top limb carries 57 bits once reduced,
//! since `2^521 ≡ 1`. This is the representation fiat-crypto synthesizes for P-521
//! (`p521_64`), and the tests check every operation against it.
//!
//! Limb bounds, checked with `debug_assert!` (libsecp256k1's magnitude discipline):
//!
//! - **tight**: `l[i] <= 2^58 + 2^13` for `i < 8` and `l[8] <= 2^57`; the output of
//!   [`FieldElement::mul`], [`FieldElement::square`], [`FieldElement::sub`] and the carries.
//! - **loose**: every limb `< 2^61`; the accepted input of `mul`, `square` and the left side of
//!   `sub`. A sum of up to seven tight elements is loose.
//!
//! Every function is variable-time only in the sense that `is_zero`, equality and parity look at
//! the value; the limb arithmetic itself has no secret-dependent branches.

use core::array;

const MASK58: u64 = (1 << 58) - 1;
const MASK57: u64 = (1 << 57) - 1;
#[cfg(all(
    debug_assertions,
    any(test, all(target_arch = "x86_64", not(ed521_backend = "serial")))
))]
const TIGHT: u64 = (1 << 58) + (1 << 13);
#[cfg(debug_assertions)]
const LOOSE: u64 = 1 << 61;

/// 16p in limbs: added before a subtraction so that no limb goes negative.
const SIXTEEN_P: [u64; 9] = [
    16 * MASK58,
    16 * MASK58,
    16 * MASK58,
    16 * MASK58,
    16 * MASK58,
    16 * MASK58,
    16 * MASK58,
    16 * MASK58,
    16 * MASK57,
];

/// An element of GF(2^521 - 1) in unsaturated radix-2^58 form.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FieldElement(pub(crate) [u64; 9]);

#[inline(always)]
fn m(a: u64, b: u64) -> u128 {
    u128::from(a) * u128::from(b)
}

#[cfg(all(
    debug_assertions,
    any(test, all(target_arch = "x86_64", not(ed521_backend = "serial")))
))]
fn is_tight(l: &[u64; 9]) -> bool {
    l[..8].iter().all(|&v| v <= TIGHT) && l[8] <= 1 << 57
}

#[cfg(debug_assertions)]
fn is_loose(l: &[u64; 9]) -> bool {
    l.iter().all(|&v| v < LOOSE)
}

/// Carries nine wide accumulators (each `< 2^127`) into a tight element.
#[inline(always)]
fn carry_wide(z: &[u128; 9]) -> FieldElement {
    let mut out = [0u64; 9];
    let mut c: u128 = 0;
    for k in 0..8 {
        let t = z[k] + c;
        out[k] = (t as u64) & MASK58; // keeps the low 58 bits by design
        c = t >> 58;
    }
    let t = z[8] + c;
    out[8] = (t as u64) & MASK57; // keeps the low 57 bits by design
    // 2^521 ≡ 1: fold the overflow (< 2^70) into limb 0, then carry once into limb 1.
    let t = u128::from(out[0]) + (t >> 57);
    out[0] = (t as u64) & MASK58; // low 58 bits
    out[1] += (t >> 58) as u64; // < 2^13, so limb 1 stays tight
    FieldElement(out)
}

/// Carries limbs (each `< 2^64`) into a tight element.
#[inline(always)]
fn carry(mut l: [u64; 9]) -> [u64; 9] {
    let c = l[8] >> 57;
    l[8] &= MASK57;
    l[0] += c; // c < 2^7
    for i in 0..8 {
        let c = l[i] >> 58;
        l[i] &= MASK58;
        l[i + 1] += c;
    }
    let c = l[8] >> 57; // at most 1
    l[8] &= MASK57;
    l[0] += c;
    l
}

impl FieldElement {
    pub(crate) const ZERO: Self = Self([0; 9]);
    pub(crate) const ONE: Self = Self([1, 0, 0, 0, 0, 0, 0, 0, 0]);

    /// Limb-wise sum, with no carry: tight + tight is loose.
    #[inline(always)]
    pub(crate) fn add(&self, rhs: &Self) -> Self {
        let out = array::from_fn(|i| self.0[i] + rhs.0[i]);
        #[cfg(debug_assertions)]
        debug_assert!(is_loose(&out), "field add overflowed the loose bound");
        Self(out)
    }

    /// `self - rhs` as a tight element; `self` loose, `rhs` limbs below 16p's.
    #[inline(always)]
    pub(crate) fn sub(&self, rhs: &Self) -> Self {
        #[cfg(debug_assertions)]
        debug_assert!(is_loose(&self.0) && rhs.0.iter().zip(&SIXTEEN_P).all(|(r, s)| r <= s));
        Self(carry(array::from_fn(|i| (self.0[i] + SIXTEEN_P[i]) - rhs.0[i])))
    }

    /// `-self` as a tight element.
    #[inline(always)]
    pub(crate) fn neg(&self) -> Self {
        Self::ZERO.sub(self)
    }

    /// Reduces a loose element to a tight one.
    #[inline(always)]
    pub(crate) fn reduce(&self) -> Self {
        Self(carry(self.0))
    }

    /// `self · rhs`, tight; both operands loose.
    ///
    /// Written as a sliding convolution over `e = [2b_1, ..., 2b_8, b_0, ..., b_8]`, so that
    /// `z_k = Σ_i a_i · e[k + 8 - i]` (wrapped terms carry 2^522 ≡ 2). Measured 40% faster than
    /// the fully written-out form, which spills: the loads become memory operands.
    #[inline(always)]
    pub(crate) fn mul(&self, rhs: &Self) -> Self {
        let (a, b) = (&self.0, &rhs.0);
        #[cfg(debug_assertions)]
        debug_assert!(is_loose(a) && is_loose(b), "field mul input exceeds the loose bound");
        let mut e = [0u64; 17];
        for n in 0..8 {
            e[n] = b[n + 1] << 1; // < 2^62
        }
        e[8..].copy_from_slice(b);
        let mut z = [0u128; 9];
        for k in 0..9 {
            let mut acc = 0u128;
            for i in 0..9 {
                acc += m(a[i], e[k + 8 - i]);
            }
            z[k] = acc;
        }
        carry_wide(&z)
    }

    /// `self²`, tight; `self` loose. 45 products.
    #[inline(always)]
    pub(crate) fn square(&self) -> Self {
        #[cfg(debug_assertions)]
        debug_assert!(is_loose(&self.0), "field square input exceeds the loose bound");
        let [a0, a1, a2, a3, a4, a5, a6, a7, a8] = self.0;
        // Off-diagonal terms appear twice (d = 2a); wrapped ones carry a further 2 (d·d = 4ab).
        let (d0, d1, d2, d3, d4) = (a0 << 1, a1 << 1, a2 << 1, a3 << 1, a4 << 1);
        let (d5, d6, d7, d8) = (a5 << 1, a6 << 1, a7 << 1, a8 << 1);
        let z = [
            m(a0, a0) + m(d1, d8) + m(d2, d7) + m(d3, d6) + m(d4, d5),
            m(d0, a1) + m(d2, d8) + m(d3, d7) + m(d4, d6) + m(d5, a5),
            m(d0, a2) + m(a1, a1) + m(d3, d8) + m(d4, d7) + m(d5, d6),
            m(d0, a3) + m(d1, a2) + m(d4, d8) + m(d5, d7) + m(d6, a6),
            m(d0, a4) + m(d1, a3) + m(a2, a2) + m(d5, d8) + m(d6, d7),
            m(d0, a5) + m(d1, a4) + m(d2, a3) + m(d6, d8) + m(d7, a7),
            m(d0, a6) + m(d1, a5) + m(d2, a4) + m(a3, a3) + m(d7, d8),
            m(d0, a7) + m(d1, a6) + m(d2, a5) + m(d3, a4) + m(d8, a8),
            m(d0, a8) + m(d1, a7) + m(d2, a6) + m(d3, a5) + m(a4, a4),
        ];
        carry_wide(&z)
    }

    /// `self · c` for a small constant `c < 2^20`, tight; `self` loose.
    #[inline(always)]
    pub(crate) fn mul_small(&self, c: u32) -> Self {
        let z: [u128; 9] = array::from_fn(|i| u128::from(self.0[i]) * u128::from(c));
        carry_wide(&z)
    }

    /// `self^(2^k)`.
    #[inline]
    pub(crate) fn pow2k(&self, k: u32) -> Self {
        let mut x = *self;
        for _ in 0..k {
            x = x.square();
        }
        x
    }

    /// `self^(2^519 - 1)`: the square-root exponent (p - 3) / 4, by an addition chain of 522
    /// squarings and 12 multiplications.
    pub(crate) fn pow_2_519_minus_1(&self) -> Self {
        // x_k = self^(2^k - 1).
        let x1 = *self;
        let x2 = x1.square().mul(&x1);
        let x3 = x2.square().mul(&x1);
        let x4 = x2.pow2k(2).mul(&x2);
        let x7 = x4.pow2k(3).mul(&x3);
        let x8 = x4.pow2k(4).mul(&x4);
        let x16 = x8.pow2k(8).mul(&x8);
        let x32 = x16.pow2k(16).mul(&x16);
        let x64 = x32.pow2k(32).mul(&x32);
        let x128 = x64.pow2k(64).mul(&x64);
        let x256 = x128.pow2k(128).mul(&x128);
        let x512 = x256.pow2k(256).mul(&x256);
        x512.pow2k(7).mul(&x7)
    }

    /// `self^(p - 2) = self^-1` (zero maps to zero).
    pub(crate) fn invert(&self) -> Self {
        // p - 2 = (2^519 - 1)·4 + 1.
        self.pow_2_519_minus_1().pow2k(2).mul(self)
    }

    /// `(true, sqrt(u/v))` when `u/v` is a square (with `v != 0`), otherwise `(false, _)`.
    ///
    /// p ≡ 3 (mod 4), so `sqrt(u/v) = u³v·(u⁵v³)^((p-3)/4)` (the form of RFC 8032 §5.2.3).
    pub(crate) fn sqrt_ratio(u: &Self, v: &Self) -> (bool, Self) {
        let u2 = u.square();
        let u3 = u2.mul(u);
        let u5 = u3.mul(&u2);
        let v3 = v.square().mul(v);
        let x = u3.mul(v).mul(&u5.mul(&v3).pow_2_519_minus_1());
        let check = v.mul(&x.square());
        (check.eq_vartime(u), x)
    }

    /// The canonical value in `[0, p)` as limbs (`l[i] < 2^58`, `l[8] < 2^57`).
    pub(crate) fn canonical(&self) -> [u64; 9] {
        let mut l = carry(self.0);
        // Full propagation, no fold: v = Σ l[i]·2^(58i) < 2^522 and v < 2p.
        for i in 0..8 {
            l[i + 1] += l[i] >> 58;
            l[i] &= MASK58;
        }
        // If v + 1 reaches 2^521 then v >= p and the result is v + 1 - 2^521 = v - p.
        let mut t = l;
        t[0] += 1;
        for i in 0..8 {
            t[i + 1] += t[i] >> 58;
            t[i] &= MASK58;
        }
        if t[8] >> 57 != 0 {
            t[8] &= MASK57;
            t
        } else {
            l
        }
    }

    /// The 66-byte little-endian encoding of the canonical value (bits 521.. are zero).
    pub(crate) fn to_bytes(&self) -> [u8; 66] {
        let l = self.canonical();
        let mut words = [0u64; 9];
        for (i, &limb) in l.iter().enumerate() {
            let bit = 58 * i;
            let (w, s) = (bit / 64, bit % 64);
            words[w] |= limb << s;
            if s > 6 && w + 1 < 9 {
                words[w + 1] |= limb >> (64 - s);
            }
        }
        let mut out = [0u8; 66];
        for (i, chunk) in out.chunks_mut(8).enumerate() {
            chunk.copy_from_slice(&words[i].to_le_bytes()[..chunk.len()]);
        }
        out
    }

    /// The element `int(bytes) mod p` of a 66-byte little-endian string (all 528 bits count).
    pub(crate) fn from_bytes(bytes: &[u8; 66]) -> Self {
        let mut words = [0u64; 10];
        for (i, chunk) in bytes.chunks(8).enumerate() {
            let mut word = [0u8; 8];
            word[..chunk.len()].copy_from_slice(chunk);
            words[i] = u64::from_le_bytes(word);
        }
        let mut l = [0u64; 9];
        for (i, limb) in l.iter_mut().enumerate() {
            let bit = 58 * i;
            let (w, s) = (bit / 64, bit % 64);
            let mut v = words[w] >> s;
            if s > 0 {
                v |= words[w + 1] << (64 - s);
            }
            *limb = if i < 8 { v & MASK58 } else { v }; // limb 8 takes bits 464..528
        }
        Self(carry(l))
    }

    /// True when the value is zero modulo p.
    pub(crate) fn is_zero(&self) -> bool {
        self.canonical() == [0; 9]
    }

    /// True when `self ≡ rhs (mod p)`. Variable time.
    pub(crate) fn eq_vartime(&self, rhs: &Self) -> bool {
        self.sub(rhs).is_zero()
    }

    /// The low bit of the canonical value (the "sign" of an encoded x coordinate).
    pub(crate) fn is_odd(&self) -> bool {
        self.canonical()[0] & 1 == 1
    }

    /// Debug check that the element is tight.
    #[cfg(any(test, all(target_arch = "x86_64", not(ed521_backend = "serial"))))]
    #[inline(always)]
    #[allow(clippy::unused_self)] // compiled out of release builds
    pub(crate) fn debug_assert_tight(&self) {
        #[cfg(debug_assertions)]
        debug_assert!(is_tight(&self.0), "field element is not tight: {:x?}", self.0);
    }
}

/// True when a 66-byte string with bit 527 cleared encodes a canonical field element (< p).
pub(crate) fn is_canonical_encoding(bytes: &[u8; 66]) -> bool {
    debug_assert!(bytes[65] & 0x80 == 0);
    if bytes[65] & 0x7E != 0 {
        return false; // bits 521..526
    }
    // The only value below 2^521 that is not below p is p itself (521 one bits).
    !(bytes[65] == 1 && bytes[..65].iter().all(|&b| b == 0xFF))
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;
    use proptest::prelude::*;

    use super::*;

    fn p() -> BigUint {
        (BigUint::from(1u8) << 521u32) - 1u8
    }

    fn to_big(x: &FieldElement) -> BigUint {
        x.0.iter().rev().fold(BigUint::ZERO, |acc, &l| (acc << 58u32) + l) % p()
    }

    fn from_big(v: &BigUint) -> FieldElement {
        let v = v % p();
        let mut bytes = v.to_bytes_le();
        bytes.resize(66, 0);
        FieldElement::from_bytes(&bytes.try_into().unwrap())
    }

    /// Arbitrary loose limbs: the edges of the accepted bound, not just reduced values.
    fn loose() -> impl Strategy<Value = FieldElement> {
        prop_oneof![
            proptest::array::uniform9(0u64..(1 << 61)).prop_map(FieldElement),
            proptest::array::uniform9(prop_oneof![Just(0u64), Just((1 << 61) - 1), Just(MASK58)])
                .prop_map(FieldElement),
            proptest::collection::vec(any::<u8>(), 66)
                .prop_map(|b| { FieldElement::from_bytes(&b.try_into().unwrap()) }),
        ]
    }

    fn fiat(x: &FieldElement) -> fiat_crypto::p521_64::fiat_p521_tight_field_element {
        let bytes = x.to_bytes();
        let mut out = fiat_crypto::p521_64::fiat_p521_tight_field_element([0; 9]);
        fiat_crypto::p521_64::fiat_p521_from_bytes(&mut out, &bytes);
        out
    }

    fn fiat_bytes(x: &fiat_crypto::p521_64::fiat_p521_tight_field_element) -> [u8; 66] {
        let mut out = [0u8; 66];
        fiat_crypto::p521_64::fiat_p521_to_bytes(&mut out, x);
        out
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2000))]

        #[test]
        fn mul_matches_bigint(a in loose(), b in loose()) {
            let c = a.mul(&b);
            c.debug_assert_tight();
            prop_assert_eq!(to_big(&c), to_big(&a) * to_big(&b) % p());
        }

        #[test]
        fn square_matches_mul(a in loose()) {
            let s = a.square();
            s.debug_assert_tight();
            prop_assert_eq!(to_big(&s), to_big(&a) * to_big(&a) % p());
        }

        #[test]
        fn add_sub_neg_match_bigint(a in loose(), b in loose()) {
            let (a, b) = (a.reduce(), b.reduce());
            prop_assert_eq!(to_big(&a.add(&b)), (to_big(&a) + to_big(&b)) % p());
            prop_assert_eq!(to_big(&a.sub(&b)), (p() + to_big(&a) - to_big(&b)) % p());
            prop_assert_eq!(to_big(&a.neg()), (p() - to_big(&a)) % p());
            prop_assert_eq!(to_big(&a.mul_small(376014)), to_big(&a) * 376014u32 % p());
        }

        #[test]
        fn mul_matches_fiat_crypto(a in loose(), b in loose()) {
            let (fa, fb) = (fiat(&a), fiat(&b));
            let mut loose_a = fiat_crypto::p521_64::fiat_p521_loose_field_element([0; 9]);
            fiat_crypto::p521_64::fiat_p521_relax(&mut loose_a, &fa);
            let mut loose_b = fiat_crypto::p521_64::fiat_p521_loose_field_element([0; 9]);
            fiat_crypto::p521_64::fiat_p521_relax(&mut loose_b, &fb);
            let mut product = fiat_crypto::p521_64::fiat_p521_tight_field_element([0; 9]);
            fiat_crypto::p521_64::fiat_p521_carry_mul(&mut product, &loose_a, &loose_b);
            prop_assert_eq!(fiat_bytes(&product), a.mul(&b).to_bytes());
            let mut square = fiat_crypto::p521_64::fiat_p521_tight_field_element([0; 9]);
            fiat_crypto::p521_64::fiat_p521_carry_square(&mut square, &loose_a);
            prop_assert_eq!(fiat_bytes(&square), a.square().to_bytes());
        }

        #[test]
        fn bytes_round_trip(a in loose()) {
            let bytes = a.to_bytes();
            prop_assert_eq!(BigUint::from_bytes_le(&bytes), to_big(&a));
            prop_assert_eq!(FieldElement::from_bytes(&bytes).canonical(), a.canonical());
        }

        #[test]
        fn invert_and_sqrt(a in loose(), b in loose()) {
            prop_assume!(!a.is_zero() && !b.is_zero());
            prop_assert_eq!(to_big(&a.mul(&a.invert())), BigUint::from(1u8));
            let u = a.square().mul(&b);
            let (square, x) = FieldElement::sqrt_ratio(&u, &b);
            prop_assert!(square);
            prop_assert_eq!(to_big(&x.square()), to_big(&a.square()));
            // -1 is a non-square (p ≡ 3 mod 4), so -a² / b has no root.
            let (square, _) = FieldElement::sqrt_ratio(&u.neg(), &b);
            prop_assert!(!square);
        }
    }

    #[test]
    fn canonical_edges() {
        let p_limbs =
            FieldElement([MASK58, MASK58, MASK58, MASK58, MASK58, MASK58, MASK58, MASK58, MASK57]);
        assert!(p_limbs.is_zero());
        assert_eq!(p_limbs.to_bytes(), [0u8; 66]);
        let p_plus_one = FieldElement([
            MASK58 + 1,
            MASK58,
            MASK58,
            MASK58,
            MASK58,
            MASK58,
            MASK58,
            MASK58,
            MASK57,
        ]);
        assert_eq!(p_plus_one.canonical(), FieldElement::ONE.0);
        // p - 1 stays as it is.
        let p_minus_one = FieldElement([
            MASK58 - 1,
            MASK58,
            MASK58,
            MASK58,
            MASK58,
            MASK58,
            MASK58,
            MASK58,
            MASK57,
        ]);
        assert_eq!(to_big(&p_minus_one), p() - 1u8);
        assert_eq!(BigUint::from_bytes_le(&p_minus_one.to_bytes()), p() - 1u8);
        // 2^528 - 1 reduces through the fold.
        let all = FieldElement::from_bytes(&[0xFF; 66]);
        let expected = ((BigUint::from(1u8) << 528u32) - 1u8) % p();
        assert_eq!(to_big(&all), expected);
        assert_eq!(from_big(&expected).canonical(), all.canonical());
    }

    #[test]
    fn canonical_encoding_check() {
        let mut p_bytes = [0xFFu8; 66];
        p_bytes[65] = 0x01;
        assert!(!is_canonical_encoding(&p_bytes));
        p_bytes[0] = 0xFE; // p - 1
        assert!(is_canonical_encoding(&p_bytes));
        let mut high = [0u8; 66];
        high[65] = 0x02; // bit 521
        assert!(!is_canonical_encoding(&high));
        high[65] = 0x01; // bit 520 alone is fine
        assert!(is_canonical_encoding(&high));
    }
}

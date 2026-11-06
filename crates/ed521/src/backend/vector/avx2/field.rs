//! Four elements of GF(2^521 − 1) at once, in AVX2 registers.
//!
//! An element is 18 limbs of 29 bits (18 · 29 = 522, so `2^522 ≡ 2`); limb `i` of all four
//! elements shares one `__m256i`, one element per 64-bit lane, so `vpmuludq` multiplies limbs
//! directly. Every function here is `#[target_feature(enable = "avx2")]`, and none uses `unsafe`:
//! the register intrinsics are safe to call from such functions (Rust 1.87).
//!
//! # Bounds
//!
//! - *tight*: every limb ≤ 2^29 + 2^7, the output of [`FieldElement4::carry`], `mul` and `square`.
//! - `mul` and `square` need tight inputs: a column sums at most 35 products of two limbs
//!   (`k + 1` with weight 1, `17 − k` with the wrap factor 2), and `35 · (2^29 + 2^7)^2 < 2^64`.
//! - `add` of two tight elements is ≤ 2^30 + 2^8 per limb; `sub` and `neg` add 8p (limbs ≥ 2^31 − 8)
//!   and take a subtrahend of at most that sum. Anything not tight is carried before multiplying.

use core::arch::x86_64::{
    __m256i, _mm256_add_epi64, _mm256_and_si256, _mm256_blendv_epi8, _mm256_extract_epi64,
    _mm256_set_epi64x, _mm256_set1_epi64x, _mm256_setzero_si256, _mm256_slli_epi64,
    _mm256_srli_epi64, _mm256_sub_epi64,
};

use crate::backend::serial::field::FieldElement;

pub(crate) const LIMBS: usize = 18;
const RADIX: i32 = 29;
const MASK: u64 = (1 << 29) - 1;

/// Four field elements, lane `j` of limb `i` holding limb `i` of element `j`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FieldElement4(pub(crate) [__m256i; LIMBS]);

/// 8p as 18 limbs: `8 (2^29 − 1)` each, the top one `8 (2^28 − 1)`; every limb ≥ 2^31.
#[target_feature(enable = "avx2")]
fn eight_p() -> [__m256i; LIMBS] {
    let low = _mm256_set1_epi64x((8 * MASK) as i64); // < 2^32
    let mut out = [low; LIMBS];
    out[LIMBS - 1] = _mm256_set1_epi64x((8 * ((1u64 << 28) - 1)) as i64);
    out
}

impl FieldElement4 {
    /// Packs four serial elements (tight: limbs ≤ 2^58 + 2^13) into the four lanes.
    #[target_feature(enable = "avx2")]
    pub(crate) fn from_serial(e: [&FieldElement; 4]) -> Self {
        let mut out = [_mm256_setzero_si256(); LIMBS];
        for element in e {
            element.debug_assert_tight();
        }
        for i in 0..9 {
            let [a, b, c, d] = [e[0].0[i], e[1].0[i], e[2].0[i], e[3].0[i]];
            // Each serial limb is two 29-bit limbs; the high one is at most 2^29.
            out[2 * i] = _mm256_set_epi64x(
                (d & MASK) as i64,
                (c & MASK) as i64,
                (b & MASK) as i64,
                (a & MASK) as i64,
            );
            out[2 * i + 1] = _mm256_set_epi64x(
                (d >> RADIX) as i64,
                (c >> RADIX) as i64,
                (b >> RADIX) as i64,
                (a >> RADIX) as i64,
            );
        }
        Self(out)
    }

    /// The four lanes as tight serial elements.
    #[target_feature(enable = "avx2")]
    pub(crate) fn to_serial(&self) -> [FieldElement; 4] {
        let tight = self.carry();
        let mut limbs = [[0u64; 9]; 4];
        for i in 0..9 {
            let (lo, hi) = (tight.0[2 * i], tight.0[2 * i + 1]);
            let lo = [
                _mm256_extract_epi64::<0>(lo),
                _mm256_extract_epi64::<1>(lo),
                _mm256_extract_epi64::<2>(lo),
                _mm256_extract_epi64::<3>(lo),
            ];
            let hi = [
                _mm256_extract_epi64::<0>(hi),
                _mm256_extract_epi64::<1>(hi),
                _mm256_extract_epi64::<2>(hi),
                _mm256_extract_epi64::<3>(hi),
            ];
            for j in 0..4 {
                // Tight limbs: lo + hi·2^29 < 2^58 + 2^37, loose for the serial code.
                limbs[j][i] = (lo[j] as u64) + ((hi[j] as u64) << RADIX);
            }
        }
        limbs.map(|l| FieldElement(l).reduce())
    }

    /// Lane-wise sum, without carrying.
    #[target_feature(enable = "avx2")]
    pub(crate) fn add(&self, rhs: &Self) -> Self {
        Self(core::array::from_fn(|i| _mm256_add_epi64(self.0[i], rhs.0[i])))
    }

    /// `self + 8p − rhs`, without carrying; `rhs` limbs ≤ 2^30 + 2^8.
    #[target_feature(enable = "avx2")]
    pub(crate) fn sub(&self, rhs: &Self) -> Self {
        let p8 = eight_p();
        Self(core::array::from_fn(|i| {
            _mm256_sub_epi64(_mm256_add_epi64(self.0[i], p8[i]), rhs.0[i])
        }))
    }

    /// `8p − self`; limbs ≤ 2^30 + 2^8.
    #[target_feature(enable = "avx2")]
    pub(crate) fn neg(&self) -> Self {
        let p8 = eight_p();
        Self(core::array::from_fn(|i| _mm256_sub_epi64(p8[i], self.0[i])))
    }

    /// `self` with the lanes whose `mask` lane is all ones taken from `other`.
    #[target_feature(enable = "avx2")]
    pub(crate) fn select(&self, other: &Self, mask: __m256i) -> Self {
        Self(core::array::from_fn(|i| _mm256_blendv_epi8(self.0[i], other.0[i], mask)))
    }

    /// Carries every limb (each below 2^63.5) into tight form.
    #[target_feature(enable = "avx2")]
    pub(crate) fn carry(&self) -> Self {
        let mask = _mm256_set1_epi64x(MASK as i64);
        let mut z = self.0;
        let mut c = _mm256_setzero_si256();
        for limb in &mut z {
            let v = _mm256_add_epi64(*limb, c);
            c = _mm256_srli_epi64::<RADIX>(v);
            *limb = _mm256_and_si256(v, mask);
        }
        // 2^522 ≡ 2: the carry out of the top limb (< 2^35) re-enters limb 0 doubled.
        let v = _mm256_add_epi64(z[0], _mm256_slli_epi64::<1>(c));
        z[0] = _mm256_and_si256(v, mask);
        z[1] = _mm256_add_epi64(z[1], _mm256_srli_epi64::<RADIX>(v)); // + at most 2^7
        Self(z)
    }

    /// Lane-wise product of tight inputs; tight output.
    #[target_feature(enable = "avx2")]
    pub(crate) fn mul(&self, rhs: &Self) -> Self {
        let (a, b) = (&self.0, &rhs.0);
        // b2[j] = 2 b[j] for the wrapped products (2^522 ≡ 2); b2[0] is never used.
        let b2: [__m256i; LIMBS] = core::array::from_fn(|j| _mm256_add_epi64(b[j], b[j]));
        let z = super::kernels::mul_columns(a, b, &b2);
        Self(z).carry()
    }

    /// Lane-wise square of a tight input; tight output.
    #[target_feature(enable = "avx2")]
    pub(crate) fn square(&self) -> Self {
        let a = &self.0;
        let d: [__m256i; LIMBS] = core::array::from_fn(|i| _mm256_add_epi64(a[i], a[i]));
        let q: [__m256i; LIMBS] = core::array::from_fn(|i| _mm256_add_epi64(d[i], d[i]));
        let z = super::kernels::square_columns(a, &d, &q);
        Self(z).carry()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use proptest::prelude::*;

    use super::*;

    pub(crate) fn have_avx2() -> bool {
        std::is_x86_feature_detected!("avx2")
    }

    fn element() -> impl Strategy<Value = FieldElement> {
        proptest::collection::vec(any::<u8>(), 66).prop_map(|b| {
            let mut bytes = [0u8; 66];
            bytes.copy_from_slice(&b);
            bytes[65] &= 0x01; // < 2^521
            FieldElement::from_bytes(&bytes)
        })
    }

    fn same(a: &FieldElement, b: &FieldElement) -> bool {
        a.canonical() == b.canonical()
    }

    #[target_feature(enable = "avx2")]
    fn check(a: [FieldElement; 4], b: [FieldElement; 4]) {
        let va = FieldElement4::from_serial([&a[0], &a[1], &a[2], &a[3]]);
        let vb = FieldElement4::from_serial([&b[0], &b[1], &b[2], &b[3]]);
        let round = va.to_serial();
        let product = va.mul(&vb).to_serial();
        let square = va.square().to_serial();
        let sum = va.add(&vb).carry().to_serial();
        let difference = va.sub(&vb).carry().to_serial();
        let negation = va.neg().carry().to_serial();
        // Chained products on carried sums: the bounds hold for loose-then-carried inputs.
        let chained = va.add(&vb).carry().mul(&va.sub(&vb).carry()).square().to_serial();
        let mask = _mm256_set_epi64x(0, -1, 0, -1);
        let mixed = va.select(&vb, mask).to_serial();
        for j in 0..4 {
            assert!(same(&round[j], &a[j]));
            assert!(same(&product[j], &a[j].mul(&b[j])));
            assert!(same(&square[j], &a[j].square()));
            assert!(same(&sum[j], &a[j].add(&b[j]).reduce()));
            assert!(same(&difference[j], &a[j].sub(&b[j])));
            assert!(same(&negation[j], &a[j].neg().reduce()));
            let s = a[j].add(&b[j]).reduce().mul(&a[j].sub(&b[j])).square();
            assert!(same(&chained[j], &s));
            assert!(same(&mixed[j], if j % 2 == 0 { &b[j] } else { &a[j] }));
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn lanes_match_serial(a in proptest::array::uniform4(element()), b in proptest::array::uniform4(element())) {
            if have_avx2() {
                // SAFETY: AVX2 is available.
                #[allow(unsafe_code)]
                unsafe { check(a, b) };
            }
        }
    }

    /// Limbs at the very top of the tight bound, where overflow would show first.
    #[test]
    fn extreme_limbs() {
        if !have_avx2() {
            return;
        }
        let max = FieldElement([
            (1 << 58) + (1 << 13),
            (1 << 58) + (1 << 13),
            (1 << 58) - 1,
            (1 << 58) - 1,
            (1 << 58) - 1,
            (1 << 58) - 1,
            (1 << 58) - 1,
            (1 << 58) - 1,
            (1 << 57) - 1,
        ]);
        let p_minus_1 = FieldElement([
            (1 << 58) - 2,
            (1 << 58) - 1,
            (1 << 58) - 1,
            (1 << 58) - 1,
            (1 << 58) - 1,
            (1 << 58) - 1,
            (1 << 58) - 1,
            (1 << 58) - 1,
            (1 << 57) - 1,
        ]);
        let lanes = [max, p_minus_1, FieldElement::ZERO, FieldElement::ONE];
        // SAFETY: AVX2 is available.
        #[allow(unsafe_code)]
        unsafe {
            check(lanes, [p_minus_1, max, max, p_minus_1]);
        };
    }
}

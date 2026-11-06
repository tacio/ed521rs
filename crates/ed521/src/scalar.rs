//! Integers modulo the group order L (a 519-bit prime), for public values only.
//!
//! L = 2^519 − c with c < 2^258, so reduction folds the bits above 519 back in, multiplied by c,
//! until none remain, then subtracts L at most once. All of it is variable time: verification
//! only ever reduces public values.

use crate::tables::generated::{L, L_FOLD};

/// A scalar in `[0, L)` as nine little-endian 64-bit words.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Scalar(pub(crate) [u64; 9]);

/// Words of a little-endian byte string (at most 144 bytes).
fn words<const N: usize>(bytes: &[u8]) -> [u64; N] {
    debug_assert!(bytes.len() <= 8 * N);
    let mut out = [0u64; N];
    for (i, chunk) in bytes.chunks(8).enumerate() {
        let mut word = [0u8; 8];
        word[..chunk.len()].copy_from_slice(chunk);
        out[i] = u64::from_le_bytes(word);
    }
    out
}

/// `a >= b` for equal-length little-endian words.
fn ge(a: &[u64], b: &[u64]) -> bool {
    for (x, y) in a.iter().rev().zip(b.iter().rev()) {
        if x != y {
            return x > y;
        }
    }
    true
}

/// `a -= b`, assuming `a >= b`.
fn sub_in_place(a: &mut [u64], b: &[u64]) {
    let mut borrow = false;
    for (i, x) in a.iter_mut().enumerate() {
        let y = b.get(i).copied().unwrap_or(0);
        let (d1, b1) = x.overflowing_sub(y);
        let (d2, b2) = d1.overflowing_sub(u64::from(borrow));
        *x = d2;
        borrow = b1 || b2;
    }
    debug_assert!(!borrow);
}

/// Reduces an integer of up to 18 words (1152 bits) modulo L.
fn reduce(mut x: [u64; 18]) -> Scalar {
    loop {
        // hi = x >> 519; lo = x mod 2^519 (519 = 8·64 + 7).
        let mut hi = [0u64; 10];
        for (i, h) in hi.iter_mut().enumerate() {
            let low = x[8 + i] >> 7;
            let high = if 9 + i < 18 { x[9 + i] << 57 } else { 0 };
            *h = low | high;
        }
        if hi.iter().all(|&w| w == 0) {
            break;
        }
        let mut next = [0u64; 18];
        next[..9].copy_from_slice(&x[..9]);
        next[8] &= 0x7F;
        // next += hi · c, with hi < 2^633 (ten words) and c < 2^258.
        for (i, &h) in hi.iter().enumerate() {
            if h == 0 {
                continue;
            }
            let mut carry: u128 = 0;
            for (j, &c) in L_FOLD.iter().enumerate() {
                let t = u128::from(next[i + j]) + u128::from(h) * u128::from(c) + carry;
                next[i + j] = t as u64; // low word; the rest carries
                carry = t >> 64;
            }
            let mut k = i + L_FOLD.len();
            while carry != 0 {
                let t = u128::from(next[k]) + carry;
                next[k] = t as u64; // low word
                carry = t >> 64;
                k += 1;
            }
        }
        x = next;
    }
    // Now x < 2^519 = L + c < 2L.
    let mut out = [0u64; 9];
    out.copy_from_slice(&x[..9]);
    if ge(&out, &L) {
        sub_in_place(&mut out, &L);
    }
    Scalar(out)
}

impl Scalar {
    pub(crate) const ZERO: Self = Self([0; 9]);

    /// `−self mod L`.
    #[cfg(any(test, feature = "batch"))]
    pub(crate) fn neg(&self) -> Self {
        if self.is_zero() {
            return *self;
        }
        let mut out = L;
        sub_in_place(&mut out, &self.0);
        Self(out)
    }

    /// True for the zero scalar (scalars are always fully reduced).
    pub(crate) fn is_zero(&self) -> bool {
        self.0 == [0; 9]
    }

    /// The scalar of a canonical 66-byte encoding, or `None` when the value is `>= L`.
    pub(crate) fn from_canonical_bytes(bytes: &[u8; 66]) -> Option<Self> {
        let value: [u64; 9] = words(bytes);
        if ge(&value, &L) { None } else { Some(Self(value)) }
    }

    /// `int(bytes) mod L` for a little-endian string of at most 144 bytes.
    pub(crate) fn from_bytes_mod_order(bytes: &[u8]) -> Self {
        reduce(words(bytes))
    }

    /// `self · rhs + add mod L`.
    #[cfg(any(test, feature = "__hazmat-sign", feature = "batch"))]
    pub(crate) fn mul_add(&self, rhs: &Self, add: &Self) -> Self {
        let mut wide = [0u64; 18];
        wide[..9].copy_from_slice(&add.0);
        for i in 0..9 {
            let mut carry: u128 = 0;
            for j in 0..9 {
                let t =
                    u128::from(wide[i + j]) + u128::from(self.0[i]) * u128::from(rhs.0[j]) + carry;
                wide[i + j] = t as u64; // low word
                carry = t >> 64;
            }
            let mut k = i + 9;
            while carry != 0 {
                let t = u128::from(wide[k]) + carry;
                wide[k] = t as u64; // low word
                carry = t >> 64;
                k += 1;
            }
        }
        reduce(wide)
    }

    /// The little-endian 66-byte encoding.
    #[cfg(any(test, feature = "__hazmat-sign", feature = "__bench", feature = "batch"))]
    pub(crate) fn to_bytes(&self) -> [u8; 66] {
        let mut out = [0u8; 66];
        for (i, chunk) in out.chunks_mut(8).enumerate() {
            chunk.copy_from_slice(&self.0[i].to_le_bytes()[..chunk.len()]);
        }
        out
    }

    /// Regular signed odd digits (Joye–Tunstall): `digits[w·i]` for `i < n` is odd with
    /// `|d| < 2^w`, every other entry is zero, and `Σ digits[j]·2^j = self + odd_fix` where
    /// `odd_fix` (0 or 1) makes the value odd. `n = ⌈520 / w⌉` does not depend on the scalar, so
    /// four scalars recoded together add at the same positions. `2 <= w <= 7`.
    #[cfg(any(test, all(target_arch = "x86_64", not(ed521_backend = "serial"))))]
    pub(crate) fn regular_odd_form(&self, w: usize) -> ([i8; NAF_LENGTH], bool) {
        debug_assert!((2..=7).contains(&w));
        let odd_fix = self.0[0] & 1 == 0;
        let mut k = [0u64; 10];
        k[..9].copy_from_slice(&self.0);
        if odd_fix {
            k[0] |= 1; // even, so adding one sets bit 0 without carrying
        }
        let n = 520usize.div_ceil(w);
        let mut digits = [0i8; NAF_LENGTH];
        let window = 1u64 << w;
        for i in 0..n - 1 {
            let m = k[0] & ((window << 1) - 1); // k mod 2^(w+1), odd
            let d = m as i64 - window as i64; // odd, in (−2^w, 2^w)
            digits[w * i] = d as i8; // |d| < 2^7
            // k = (k − d) / 2^w, which stays odd.
            let mut carry = if d < 0 { d.unsigned_abs() } else { 0 };
            let mut borrow = if d > 0 { d.unsigned_abs() } else { 0 };
            for word in &mut k {
                let (v, c) = word.overflowing_add(carry);
                let (v, b) = v.overflowing_sub(borrow);
                *word = v;
                carry = u64::from(c);
                borrow = u64::from(b);
            }
            for j in 0..10 {
                let high = if j + 1 < 10 { k[j + 1] << (64 - w) } else { 0 };
                k[j] = (k[j] >> w) | high;
            }
        }
        debug_assert!(k[1..].iter().all(|&x| x == 0) && k[0] < window && k[0] & 1 == 1);
        digits[w * (n - 1)] = k[0] as i8; // odd, < 2^7
        (digits, odd_fix)
    }

    /// Width-`w` non-adjacent form: odd digits `|d| < 2^(w-1)`, any two nonzero digits at least
    /// `w` positions apart, `Σ d[i]·2^i = self`. `2 <= w <= 8`.
    pub(crate) fn non_adjacent_form(&self, w: usize) -> [i8; NAF_LENGTH] {
        debug_assert!((2..=8).contains(&w));
        let mut naf = [0i8; NAF_LENGTH];
        let mut x = [0u64; 10];
        x[..9].copy_from_slice(&self.0);
        let width = 1u64 << w;
        let window_mask = width - 1;
        let mut position = 0;
        let mut carry = 0u64;
        while position < NAF_LENGTH - 1 {
            let (index, bit) = (position / 64, position % 64);
            let buffer = if bit < 64 - w {
                x[index] >> bit
            } else {
                (x[index] >> bit) | (x[index + 1] << (64 - bit))
            };
            let window = carry + (buffer & window_mask);
            if window & 1 == 0 {
                position += 1;
                continue;
            }
            if window < width / 2 {
                carry = 0;
                naf[position] = window as i8; // < 2^7
            } else {
                carry = 1;
                naf[position] = (window as i64 - width as i64) as i8; // in (-2^7, 0)
            }
            position += w;
        }
        naf
    }
}

/// Digits in a non-adjacent form: L < 2^519, and a final carry can add one more position.
pub(crate) const NAF_LENGTH: usize = 528;

#[cfg(test)]
mod tests {
    use num_bigint::{BigInt, BigUint};
    use proptest::prelude::*;

    use super::*;

    fn l() -> BigUint {
        BigUint::from_slice(
            &L.iter().flat_map(|&w| [w as u32, (w >> 32) as u32]).collect::<Vec<_>>(),
        )
    }

    fn big(s: &Scalar) -> BigUint {
        BigUint::from_bytes_le(&s.to_bytes())
    }

    #[test]
    fn constants() {
        let l = l();
        assert_eq!(
            l.to_string(),
            "171619941503265242874547519977034830431735882503582635234861586479638579584941367\
             5475876651663657849636693659065234142604319282948702542317993421293670108523"
        );
        assert_eq!(l.bits(), 519);
        let c = BigUint::from_slice(
            &L_FOLD.iter().flat_map(|&w| [w as u32, (w >> 32) as u32]).collect::<Vec<_>>(),
        );
        assert_eq!(c + &l, BigUint::from(1u8) << 519u32);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2000))]

        #[test]
        fn wide_reduction(bytes in proptest::collection::vec(any::<u8>(), 0..=144)) {
            let s = Scalar::from_bytes_mod_order(&bytes);
            prop_assert_eq!(big(&s), BigUint::from_bytes_le(&bytes) % l());
        }

        #[test]
        fn canonical_bytes(bytes in proptest::array::uniform32(any::<u8>()), top in any::<[u8; 34]>()) {
            let mut all = [0u8; 66];
            all[..32].copy_from_slice(&bytes);
            all[32..].copy_from_slice(&top);
            let value = BigUint::from_bytes_le(&all);
            match Scalar::from_canonical_bytes(&all) {
                Some(s) => prop_assert_eq!(big(&s), value),
                None => prop_assert!(value >= l()),
            }
        }

        #[test]
        fn mul_add(a in proptest::collection::vec(any::<u8>(), 66), b in proptest::collection::vec(any::<u8>(), 66), c in proptest::collection::vec(any::<u8>(), 66)) {
            let (a, b, c) = (Scalar::from_bytes_mod_order(&a), Scalar::from_bytes_mod_order(&b), Scalar::from_bytes_mod_order(&c));
            prop_assert_eq!(big(&a.mul_add(&b, &c)), (big(&a) * big(&b) + big(&c)) % l());
        }

        #[test]
        fn naf_reconstructs(bytes in proptest::collection::vec(any::<u8>(), 66), w in 2usize..=8) {
            let s = Scalar::from_bytes_mod_order(&bytes);
            let naf = s.non_adjacent_form(w);
            let mut sum = BigInt::ZERO;
            let mut last: Option<usize> = None;
            for (i, &d) in naf.iter().enumerate() {
                if d != 0 {
                    prop_assert!(d % 2 != 0 && i32::from(d).abs() < (1 << (w - 1)));
                    if let Some(j) = last { prop_assert!(i - j >= w); }
                    last = Some(i);
                }
                sum += BigInt::from(d) << i;
            }
            prop_assert_eq!(sum, BigInt::from(big(&s)));
        }

        #[test]
        fn regular_form_reconstructs(bytes in proptest::collection::vec(any::<u8>(), 66), w in 2usize..=7, small in any::<bool>()) {
            let s = if small { Scalar::from_bytes_mod_order(&bytes[..1]) } else { Scalar::from_bytes_mod_order(&bytes) };
            let (digits, odd_fix) = s.regular_odd_form(w);
            let mut sum = BigInt::ZERO;
            for (i, &d) in digits.iter().enumerate() {
                if i % w == 0 && i < w * 520usize.div_ceil(w) {
                    prop_assert!(d % 2 != 0 && i32::from(d).abs() < (1 << w), "position {i}: {d}");
                } else {
                    prop_assert_eq!(d, 0);
                }
                sum += BigInt::from(d) << i;
            }
            prop_assert_eq!(sum, BigInt::from(big(&s)) + i32::from(odd_fix));
            prop_assert_eq!(odd_fix, !big(&s).bit(0));
        }
    }

    #[test]
    fn regular_form_extremes() {
        let l_minus_1 = Scalar::from_bytes_mod_order(&[1]).neg();
        for s in [Scalar::ZERO, Scalar::from_bytes_mod_order(&[1]), l_minus_1] {
            for w in 2..=7 {
                let (digits, odd_fix) = s.regular_odd_form(w);
                let sum = digits
                    .iter()
                    .enumerate()
                    .fold(BigInt::ZERO, |a, (i, &d)| a + (BigInt::from(d) << i));
                assert_eq!(sum, BigInt::from(big(&s)) + i32::from(odd_fix));
            }
        }
    }

    #[test]
    fn edges() {
        let l = l();
        let mut l_bytes = l.to_bytes_le();
        l_bytes.resize(66, 0);
        let l_bytes: [u8; 66] = l_bytes.try_into().unwrap();
        assert_eq!(Scalar::from_canonical_bytes(&l_bytes), None);
        assert_eq!(Scalar::from_bytes_mod_order(&l_bytes), Scalar::ZERO);
        let mut l_minus_one = l_bytes;
        l_minus_one[0] -= 1;
        assert!(Scalar::from_canonical_bytes(&l_minus_one).is_some());
        assert_eq!(
            big(&Scalar::from_bytes_mod_order(&[0xFF; 144])),
            BigUint::from_bytes_le(&[0xFF; 144]) % &l
        );
        let max = Scalar::from_bytes_mod_order(&l_minus_one);
        for w in 2..=8 {
            let naf = max.non_adjacent_form(w);
            let sum: BigInt = naf.iter().enumerate().map(|(i, &d)| BigInt::from(d) << i).sum();
            assert_eq!(sum, BigInt::from(l.clone() - 1u8));
        }
    }
}

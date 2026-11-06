//! A slow, independent Ed521 model for differential fuzzing: big-integer arithmetic in extended
//! coordinates, following election-audit's `ed521.py` (<https://github.com/tacio/election-audit>) for strict mode and ECPy's observable
//! behaviour (pinned by `crates/ed521/tests/vectors/edge-cases.json`) for compat mode.

use std::sync::LazyLock;

use num_bigint::BigUint;
use num_traits::{One, Zero};
use shake::Shake256;
use shake::digest::{ExtendableOutput, Update};

pub static P: LazyLock<BigUint> = LazyLock::new(|| (BigUint::one() << 521u32) - 1u32);
pub static L: LazyLock<BigUint> = LazyLock::new(|| {
    "1716199415032652428745475199770348304317358825035826352348615864796385795849413675475876651663657849636693659065234142604319282948702542317993421293670108523".parse().unwrap()
});
static D: LazyLock<BigUint> = LazyLock::new(|| &*P - 376014u32);
static BASE: LazyLock<Point> = LazyLock::new(|| {
    let x: BigUint = "1571054894184995387535939749894317568645297350402905821437625181152304994381188529632591196067604100772673927915114267193389905003276673749012051148356041324".parse().unwrap();
    Point::affine(x, BigUint::from(12u32))
});

/// Extended coordinates (X : Y : Z : T), all reduced mod p.
#[derive(Clone, Debug)]
pub struct Point {
    x: BigUint,
    y: BigUint,
    z: BigUint,
    t: BigUint,
}

fn m(a: &BigUint, b: &BigUint) -> BigUint {
    a * b % &*P
}

fn s(a: &BigUint, b: &BigUint) -> BigUint {
    (a + &*P - b % &*P) % &*P
}

impl Point {
    pub fn identity() -> Self {
        Self::affine(BigUint::zero(), BigUint::one())
    }

    pub fn affine(x: BigUint, y: BigUint) -> Self {
        let t = m(&x, &y);
        Self { x, y, z: BigUint::one(), t }
    }

    pub fn base() -> Self {
        BASE.clone()
    }

    /// The 4-torsion point `(1, 0)` (order 4) and `(0, −1)` (order 2).
    pub fn order_4() -> Self {
        Self::affine(BigUint::one(), BigUint::zero())
    }

    pub fn order_2() -> Self {
        Self::affine(BigUint::zero(), &*P - 1u32)
    }

    /// Unified addition (add-2008-hwcd, a = 1).
    pub fn add(&self, q: &Self) -> Self {
        let a = m(&self.x, &q.x);
        let b = m(&self.y, &q.y);
        let c = m(&m(&D, &self.t), &q.t);
        let d = m(&self.z, &q.z);
        let e = s(&s(&m(&(&self.x + &self.y), &(&q.x + &q.y)), &a), &b);
        let (f, g, h) = (s(&d, &c), (&d + &c) % &*P, s(&b, &a));
        Self { x: m(&e, &f), y: m(&g, &h), z: m(&f, &g), t: m(&e, &h) }
    }

    pub fn neg(&self) -> Self {
        Self {
            x: s(&BigUint::zero(), &self.x),
            y: self.y.clone(),
            z: self.z.clone(),
            t: s(&BigUint::zero(), &self.t),
        }
    }

    pub fn mul(&self, k: &BigUint) -> Self {
        let mut r = Self::identity();
        for i in (0..k.bits()).rev() {
            r = r.add(&r);
            if k.bit(i) {
                r = r.add(self);
            }
        }
        r
    }

    pub fn equals(&self, q: &Self) -> bool {
        m(&self.x, &q.z) == m(&q.x, &self.z) && m(&self.y, &q.z) == m(&q.y, &self.z)
    }

    pub fn is_small_order(&self) -> bool {
        let four = self.add(self);
        four.add(&four).equals(&Self::identity())
    }

    fn affine_xy(&self) -> (BigUint, BigUint) {
        let inv = self.z.modpow(&(&*P - 2u32), &P);
        (m(&self.x, &inv), m(&self.y, &inv))
    }

    /// Canonical encoding; `extra_p` adds that many p to y (non-canonical when nonzero).
    pub fn encode(&self, extra_p: u32) -> [u8; 66] {
        let (x, y) = self.affine_xy();
        let mut v = y + &*P * extra_p;
        if x.bit(0) {
            v.set_bit(527, true);
        }
        let mut out = [0u8; 66];
        let bytes = v.to_bytes_le();
        out[..bytes.len()].copy_from_slice(&bytes);
        out
    }
}

/// Decodes a point. `strict`: y < p, and x = 0 with the sign bit is rejected.
pub fn decode(bytes: &[u8], strict: bool) -> Option<Point> {
    let v = BigUint::from_bytes_le(bytes);
    let sign = v.bit(527);
    let mut y = v.clone();
    y.set_bit(527, false);
    if strict && y >= *P {
        return None;
    }
    let y = y % &*P;
    let yy = m(&y, &y);
    let num = s(&BigUint::one(), &yy);
    let den = s(&BigUint::one(), &m(&D, &yy));
    let x2 = m(&num, &den.modpow(&(&*P - 2u32), &P));
    let mut x = x2.modpow(&((&*P + 1u32) >> 2u32), &P);
    if m(&x, &x) != x2 {
        return None;
    }
    if x.is_zero() {
        if sign && strict {
            return None;
        }
    } else if x.bit(0) != sign {
        x = &*P - x;
    }
    Some(Point::affine(x, y))
}

pub fn challenge(r: &[u8], a: &[u8], message: &[u8]) -> BigUint {
    let mut h = Shake256::default();
    h.update(b"SigEd521\x00\x00");
    h.update(r);
    h.update(a);
    h.update(message);
    let mut out = [0u8; 132];
    h.finalize_xof_into(&mut out);
    BigUint::from_bytes_le(&out) % &*L
}

/// `election_audit.ed521.verify` (RFC 8032 decoding, cofactorless).
pub fn verify_strict(key: &[u8], signature: &[u8], message: &[u8]) -> bool {
    if key.len() != 66 || signature.len() != 132 {
        return false;
    }
    let (Some(a), Some(r)) = (decode(key, true), decode(&signature[..66], true)) else {
        return false;
    };
    let sv = BigUint::from_bytes_le(&signature[66..]);
    if sv >= *L {
        return false;
    }
    let k = challenge(&signature[..66], key, message);
    Point::base().mul(&sv).equals(&r.add(&a.mul(&k)))
}

/// ECPy at TSE's commit, as observed: lenient decoding, S mod L but S ≡ 0 rejected, and for a
/// small-order A the check `[S]B = R` with R's encoding canonical.
pub fn verify_ecpy(key: &[u8], signature: &[u8], message: &[u8]) -> bool {
    if key.len() != 66 || signature.len() != 132 {
        return false;
    }
    let (Some(a), Some(r)) = (decode(key, false), decode(&signature[..66], false)) else {
        return false;
    };
    let sv = BigUint::from_bytes_le(&signature[66..]) % &*L;
    if sv.is_zero() {
        return false;
    }
    let left = Point::base().mul(&sv);
    if a.is_small_order() {
        return decode(&signature[..66], true).is_some() && left.equals(&r);
    }
    let k = challenge(&signature[..66], key, message);
    left.equals(&r.add(&a.mul(&k)))
}

/// `[4]([S]B − R − [k]A) = O` under strict decoding; `None` when strict decoding fails.
pub fn cofactored(key: &[u8], signature: &[u8], message: &[u8]) -> Option<bool> {
    let (a, r) = (decode(key, true)?, decode(&signature[..66], true)?);
    let sv = BigUint::from_bytes_le(&signature[66..]);
    if sv >= *L {
        return None;
    }
    let k = challenge(&signature[..66], key, message);
    let diff = Point::base().mul(&sv).add(&r.add(&a.mul(&k)).neg());
    Some(diff.is_small_order())
}

/// Applies one fuzz-chosen crafting step to (key, signature), keeping the result well formed.
/// The steps reach the encodings the two modes disagree on.
pub fn mutate(op: u8, arg: u8, key: &mut [u8; 66], signature: &mut [u8; 132]) {
    let point = |bytes: &[u8]| decode(bytes, false);
    match op % 10 {
        0 => {}
        1 => signature[(arg as usize) % 132] ^= 1 << (arg % 8),
        2 => key[(arg as usize) % 66] ^= 1 << (arg % 8),
        3 => {
            // S + j·L, j < 256 (still below 2^528).
            let sv = BigUint::from_bytes_le(&signature[66..]) + &*L * u32::from(arg);
            let bytes = sv.to_bytes_le();
            signature[66..].fill(0);
            signature[66..66 + bytes.len().min(66)].copy_from_slice(&bytes[..bytes.len().min(66)]);
        }
        4 => {
            if let Some(r) = point(&signature[..66]) {
                signature[..66].copy_from_slice(&r.encode(u32::from(arg % 64)));
            }
        }
        5 => {
            if let Some(a) = point(key) {
                key.copy_from_slice(&a.encode(u32::from(arg % 64)));
            }
        }
        6 => {
            let torsion = if arg % 2 == 0 { Point::order_2() } else { Point::order_4() };
            if let Some(r) = point(&signature[..66]) {
                signature[..66].copy_from_slice(&r.add(&torsion).encode(0));
            }
        }
        7 => {
            let torsion = if arg % 2 == 0 { Point::order_2() } else { Point::order_4() };
            if let Some(a) = point(key) {
                key.copy_from_slice(&a.add(&torsion).encode(0));
            }
        }
        8 => {
            // A small-order key, possibly with the sign bit on x = 0.
            let p = match arg % 4 {
                0 => Point::identity(),
                1 => Point::order_2(),
                2 => Point::order_4(),
                _ => Point::order_4().neg(),
            };
            key.copy_from_slice(&p.encode(0));
            if arg & 0x40 != 0 {
                key[65] |= 0x80;
            }
        }
        _ => signature[66..].fill(0),
    }
}

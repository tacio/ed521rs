//! Point models for E-521 (`x² + y² = 1 + d·x²·y²`, a = 1) and their formulas.
//!
//! The strategy is curve25519-dalek's mixed model: doublings run on [`ProjectivePoint`]s and
//! produce [`CompletedPoint`]s, which convert to projective (3M) or extended (4M) coordinates
//! depending on what follows. Additions take an [`ExtendedPoint`] and a cached form of the other
//! point. The formulas are Hisil–Wong–Carter–Dawson 2008 (`dbl-2008-hwcd`, `add-2008-hwcd`) for
//! a = 1; they are complete on E-521 because d is a non-square.
//!
//! The a = −1 shortcut (multiplying `Y ± X` pairs) does not apply: a = 1 needs `X1·X2` and
//! `Y1·Y2` separately, so the unified addition costs 9M (8M against an affine point).

use super::field::FieldElement;
use crate::tables::generated::D;

/// Extended coordinates (X : Y : Z : T) with x = X/Z, y = Y/Z, x·y = T/Z.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ExtendedPoint {
    pub(crate) x: FieldElement,
    pub(crate) y: FieldElement,
    pub(crate) z: FieldElement,
    pub(crate) t: FieldElement,
}

/// Projective coordinates (X : Y : Z), the input of a doubling.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ProjectivePoint {
    pub(crate) x: FieldElement,
    pub(crate) y: FieldElement,
    pub(crate) z: FieldElement,
}

/// The "completed" P¹×P¹ form ((X : Z), (Y : T)) with x = X/Z, y = Y/T.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CompletedPoint {
    pub(crate) x: FieldElement,
    pub(crate) y: FieldElement,
    pub(crate) z: FieldElement,
    pub(crate) t: FieldElement,
}

/// A point cached for repeated addition: (X, Y, Z, d·T).
#[derive(Clone, Copy, Debug)]
pub(crate) struct CachedPoint {
    pub(crate) x: FieldElement,
    pub(crate) y: FieldElement,
    pub(crate) z: FieldElement,
    pub(crate) td: FieldElement,
}

/// An affine point cached for repeated addition: (x, y, d·x·y), with Z = 1.
#[derive(Clone, Copy, Debug)]
pub(crate) struct AffineCached {
    pub(crate) x: FieldElement,
    pub(crate) y: FieldElement,
    pub(crate) xy2d: FieldElement,
}

impl ExtendedPoint {
    pub(crate) const IDENTITY: Self = Self {
        x: FieldElement::ZERO,
        y: FieldElement::ONE,
        z: FieldElement::ONE,
        t: FieldElement::ZERO,
    };

    /// The point (x, y) in extended coordinates.
    pub(crate) fn from_affine(x: &FieldElement, y: &FieldElement) -> Self {
        Self { x: *x, y: *y, z: FieldElement::ONE, t: x.mul(y) }
    }

    #[inline(always)]
    pub(crate) fn to_projective(&self) -> ProjectivePoint {
        ProjectivePoint { x: self.x, y: self.y, z: self.z }
    }

    pub(crate) fn to_cached(&self) -> CachedPoint {
        CachedPoint { x: self.x, y: self.y, z: self.z, td: self.t.mul(&D) }
    }

    #[cfg(test)]
    pub(crate) fn to_affine_cached(&self) -> AffineCached {
        let inverse = self.z.invert();
        let (x, y) = (self.x.mul(&inverse), self.y.mul(&inverse));
        AffineCached { x, y, xy2d: x.mul(&y).mul(&D) }
    }

    #[inline(always)]
    pub(crate) fn double(&self) -> Self {
        self.to_projective().double().to_extended()
    }

    pub(crate) fn neg(&self) -> Self {
        Self { x: self.x.neg(), y: self.y, z: self.z, t: self.t.neg() }
    }

    /// `self + other` (unified, complete).
    #[inline(always)]
    pub(crate) fn add_cached(&self, other: &CachedPoint) -> CompletedPoint {
        let a = self.x.mul(&other.x);
        let b = self.y.mul(&other.y);
        let c = self.t.mul(&other.td);
        let d = self.z.mul(&other.z);
        let e = self.x.add(&self.y).mul(&other.x.add(&other.y)).sub(&a).sub(&b);
        CompletedPoint { x: e, y: b.sub(&a), z: d.add(&c), t: d.sub(&c) }
    }

    /// `self - other`: the addition with `other = (X, Y, Z, dT)` negated to `(-X, Y, Z, -dT)`.
    #[inline(always)]
    pub(crate) fn sub_cached(&self, other: &CachedPoint) -> CompletedPoint {
        let a = self.x.mul(&other.x);
        let b = self.y.mul(&other.y);
        let c = self.t.mul(&other.td);
        let d = self.z.mul(&other.z);
        let e = self.x.add(&self.y).mul(&other.y.sub(&other.x)).add(&a).sub(&b);
        CompletedPoint { x: e, y: b.add(&a), z: d.sub(&c), t: d.add(&c) }
    }

    /// `self + other` for an affine `other` (Z2 = 1 saves one multiplication).
    #[inline(always)]
    pub(crate) fn add_affine(&self, other: &AffineCached) -> CompletedPoint {
        let a = self.x.mul(&other.x);
        let b = self.y.mul(&other.y);
        let c = self.t.mul(&other.xy2d);
        let d = self.z;
        let e = self.x.add(&self.y).mul(&other.x.add(&other.y)).sub(&a).sub(&b);
        CompletedPoint { x: e, y: b.sub(&a), z: d.add(&c), t: d.sub(&c) }
    }

    /// `self - other` for an affine `other`.
    #[inline(always)]
    pub(crate) fn sub_affine(&self, other: &AffineCached) -> CompletedPoint {
        let a = self.x.mul(&other.x);
        let b = self.y.mul(&other.y);
        let c = self.t.mul(&other.xy2d);
        let d = self.z;
        let e = self.x.add(&self.y).mul(&other.y.sub(&other.x)).add(&a).sub(&b);
        CompletedPoint { x: e, y: b.add(&a), z: d.sub(&c), t: d.add(&c) }
    }

    /// Projective equality: x1·Z2 = x2·Z1 and y1·Z2 = y2·Z1. Variable time.
    pub(crate) fn eq_vartime(&self, other: &Self) -> bool {
        self.x.mul(&other.z).eq_vartime(&other.x.mul(&self.z))
            && self.y.mul(&other.z).eq_vartime(&other.y.mul(&self.z))
    }

    /// True for the neutral element (0, 1).
    pub(crate) fn is_identity(&self) -> bool {
        self.x.is_zero() && self.y.eq_vartime(&self.z)
    }

    /// The 66-byte encoding: little-endian y with the parity of x in bit 527.
    pub(crate) fn compress(&self) -> [u8; 66] {
        self.compress_with(&self.z.invert())
    }

    fn compress_with(&self, z_inverse: &FieldElement) -> [u8; 66] {
        let mut bytes = self.y.mul(z_inverse).to_bytes();
        bytes[65] |= u8::from(self.x.mul(z_inverse).is_odd()) << 7;
        bytes
    }

    /// `out[i] = points[i].compress()` with one shared inversion (Montgomery's trick: 3M per
    /// point). At most [`COMPRESS_BATCH`] points.
    pub(crate) fn compress_batch(points: &[Self], out: &mut [[u8; 66]]) {
        assert!(points.len() <= COMPRESS_BATCH && points.len() == out.len());
        let Some(last) = points.len().checked_sub(1) else { return };
        // prefix[i] = z_0 · ... · z_i.
        let mut prefix = [FieldElement::ONE; COMPRESS_BATCH];
        prefix[0] = points[0].z;
        for i in 1..points.len() {
            prefix[i] = prefix[i - 1].mul(&points[i].z);
        }
        let mut inverse = prefix[last].invert(); // 1 / (z_0 · ... · z_i), from i = last down
        for i in (1..points.len()).rev() {
            out[i] = points[i].compress_with(&inverse.mul(&prefix[i - 1]));
            inverse = inverse.mul(&points[i].z);
        }
        out[0] = points[0].compress_with(&inverse);
    }
}

/// The most points [`ExtendedPoint::compress_batch`] takes at once.
pub(crate) const COMPRESS_BATCH: usize = 16;

impl ProjectivePoint {
    pub(crate) const IDENTITY: Self =
        Self { x: FieldElement::ZERO, y: FieldElement::ONE, z: FieldElement::ONE };

    /// `2·self` (4S). With a = 1, x₃ = 2XY / (X² + Y²) and y₃ = (Y² − X²) / (2Z² − X² − Y²).
    #[inline(always)]
    pub(crate) fn double(&self) -> CompletedPoint {
        let xx = self.x.square();
        let yy = self.y.square();
        let zz = self.z.square();
        let xpy2 = self.x.add(&self.y).square();
        let sum = yy.add(&xx);
        CompletedPoint { x: xpy2.sub(&sum), y: yy.sub(&xx), z: sum, t: zz.add(&zz).sub(&sum) }
    }

    #[inline(always)]
    pub(crate) fn to_extended(&self) -> ExtendedPoint {
        // T = XY/Z: scale (X, Y, Z) by Z.
        ExtendedPoint {
            x: self.x.mul(&self.z),
            y: self.y.mul(&self.z),
            z: self.z.square(),
            t: self.x.mul(&self.y),
        }
    }
}

impl CompletedPoint {
    #[inline(always)]
    pub(crate) fn to_projective(&self) -> ProjectivePoint {
        ProjectivePoint { x: self.x.mul(&self.t), y: self.y.mul(&self.z), z: self.z.mul(&self.t) }
    }

    #[inline(always)]
    pub(crate) fn to_extended(&self) -> ExtendedPoint {
        ExtendedPoint {
            x: self.x.mul(&self.t),
            y: self.y.mul(&self.z),
            z: self.z.mul(&self.t),
            t: self.x.mul(&self.y),
        }
    }
}

impl CachedPoint {
    pub(crate) const IDENTITY: Self = Self {
        x: FieldElement::ZERO,
        y: FieldElement::ONE,
        z: FieldElement::ONE,
        td: FieldElement::ZERO,
    };
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;

    use super::*;
    use crate::tables::generated::{BASE_X, BASE_Y, L};

    fn base() -> ExtendedPoint {
        ExtendedPoint::from_affine(&BASE_X, &BASE_Y)
    }

    /// Plain double-and-add over the unified addition: the reference for every faster path.
    pub(crate) fn multiply(scalar: &BigUint, point: &ExtendedPoint) -> ExtendedPoint {
        let mut result = ExtendedPoint::IDENTITY;
        for i in (0..scalar.bits()).rev() {
            result = result.add_cached(&result.to_cached()).to_extended();
            if scalar.bit(i) {
                result = result.add_cached(&point.to_cached()).to_extended();
            }
        }
        result
    }

    fn on_curve(p: &ExtendedPoint) -> bool {
        // Z²(X² + Y²) = Z⁴ + d X² Y², and X·Y = Z·T.
        let (xx, yy, zz) = (p.x.square(), p.y.square(), p.z.square());
        let left = zz.mul(&xx.add(&yy));
        let right = zz.square().add(&D.mul(&xx).mul(&yy));
        left.eq_vartime(&right) && p.x.mul(&p.y).eq_vartime(&p.z.mul(&p.t))
    }

    #[test]
    fn base_point_has_order_l() {
        let b = base();
        assert!(on_curve(&b));
        let l = BigUint::from_slice(
            &L.iter().flat_map(|&w| [w as u32, (w >> 32) as u32]).collect::<Vec<_>>(),
        );
        assert!(multiply(&l, &b).is_identity());
        assert!(!multiply(&(l - 1u8), &b).is_identity());
    }

    #[test]
    fn doubling_matches_unified_addition() {
        let mut p = base();
        for _ in 0..20 {
            let doubled = p.double();
            let added = p.add_cached(&p.to_cached()).to_extended();
            assert!(on_curve(&doubled));
            assert!(doubled.eq_vartime(&added));
            p = doubled.add_affine(&base().to_affine_cached()).to_extended();
        }
    }

    #[test]
    fn batch_compression_matches_single() {
        let mut points = [ExtendedPoint::IDENTITY; COMPRESS_BATCH];
        let mut p = base();
        for point in &mut points {
            // Non-trivial Z: a doubling chain leaves Z != 1.
            p = p.double().add_cached(&base().to_cached()).to_extended();
            *point = p;
        }
        for n in [0, 1, 2, 7, COMPRESS_BATCH] {
            let mut out = [[0u8; 66]; COMPRESS_BATCH];
            ExtendedPoint::compress_batch(&points[..n], &mut out[..n]);
            for i in 0..n {
                assert_eq!(out[i], points[i].compress(), "n = {n}, i = {i}");
            }
        }
    }

    #[test]
    fn subtraction_inverts_addition() {
        let b = base();
        let p = multiply(&BigUint::from(123456789u32), &b);
        let q = multiply(&BigUint::from(987654321u64), &b);
        let sum = p.add_cached(&q.to_cached()).to_extended();
        assert!(sum.sub_cached(&q.to_cached()).to_extended().eq_vartime(&p));
        let qa = q.to_affine_cached();
        assert!(sum.sub_affine(&qa).to_extended().eq_vartime(&p));
        assert!(p.add_affine(&qa).to_extended().eq_vartime(&sum));
        assert!(p.add_cached(&p.neg().to_cached()).to_extended().is_identity());
        // Projective chains agree with extended ones.
        let via_projective = sum.to_projective().double().to_projective().to_extended();
        assert!(via_projective.eq_vartime(&sum.double()));
        assert!(on_curve(&via_projective));
    }
}

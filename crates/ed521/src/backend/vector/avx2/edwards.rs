//! Four independent points at once ("vertical" layout): lane j of every coordinate belongs to
//! point j, and every formula is the serial one with each field operation done four-wide.
//!
//! A first, "horizontal" version kept one point per vector, (X, Y, Z, T) in the lanes. It
//! reached only 1.1× the serial backend (its lane shuffles and blends cost what the 4-way
//! products saved; a = 1 also needs five products per addition), so it was replaced by this
//! layout, which serves four signatures at a time (`verify_many`). See BENCHMARKS.md.
//!
//! Lanes add at the same digit positions only when their scalars are recoded alike, so the
//! callers use regular signed odd digits ([`crate::scalar::Scalar::regular_odd_form`]): one odd
//! digit every w positions in every lane. A lane whose digit is zero adds the identity.

use core::arch::x86_64::{__m256i, _mm256_set_epi64x};

use super::field::FieldElement4;
use crate::backend::serial::curve_models::{AffineCached, CachedPoint, ExtendedPoint};
use crate::backend::serial::field::FieldElement;
use crate::backend::serial::scalar_mul::Lookup;

#[derive(Clone, Copy, Debug)]
struct Extended4 {
    x: FieldElement4,
    y: FieldElement4,
    z: FieldElement4,
    t: FieldElement4,
}

#[derive(Clone, Copy, Debug)]
struct Projective4 {
    x: FieldElement4,
    y: FieldElement4,
    z: FieldElement4,
}

/// Not tight: carried on conversion.
#[derive(Clone, Copy, Debug)]
struct Completed4 {
    x: FieldElement4,
    y: FieldElement4,
    z: FieldElement4,
    t: FieldElement4,
}

/// Points to add, (X, Y, Z, d·T); `z` is `None` for affine entries (Z = 1).
#[derive(Clone, Copy, Debug)]
struct Cached4 {
    x: FieldElement4,
    y: FieldElement4,
    z: Option<FieldElement4>,
    td: FieldElement4,
}

const AFFINE_IDENTITY: AffineCached =
    AffineCached { x: FieldElement::ZERO, y: FieldElement::ONE, xy2d: FieldElement::ZERO };

impl Projective4 {
    #[target_feature(enable = "avx2")]
    fn identity() -> Self {
        let zero = FieldElement4::from_serial([&FieldElement::ZERO; 4]);
        let one = FieldElement4::from_serial([&FieldElement::ONE; 4]);
        Self { x: zero, y: one, z: one }
    }

    /// As `ProjectivePoint::double`.
    #[target_feature(enable = "avx2")]
    fn double(&self) -> Completed4 {
        let xx = self.x.square();
        let yy = self.y.square();
        let zz = self.z.square();
        let xpy2 = self.x.add(&self.y).carry().square();
        let sum = yy.add(&xx);
        Completed4 { x: xpy2.sub(&sum), y: yy.sub(&xx), z: sum, t: zz.add(&zz).sub(&sum) }
    }
}

impl Completed4 {
    #[target_feature(enable = "avx2")]
    fn to_projective(&self) -> Projective4 {
        let (x, y, z, t) = (self.x.carry(), self.y.carry(), self.z.carry(), self.t.carry());
        Projective4 { x: x.mul(&t), y: y.mul(&z), z: z.mul(&t) }
    }

    #[target_feature(enable = "avx2")]
    fn to_extended(&self) -> Extended4 {
        let (x, y, z, t) = (self.x.carry(), self.y.carry(), self.z.carry(), self.t.carry());
        Extended4 { x: x.mul(&t), y: y.mul(&z), z: z.mul(&t), t: x.mul(&y) }
    }
}

impl Extended4 {
    /// As `ExtendedPoint::add_cached` (`add_affine` when `q.z` is `None`).
    #[target_feature(enable = "avx2")]
    fn add(&self, q: &Cached4) -> Completed4 {
        let a = self.x.mul(&q.x);
        let b = self.y.mul(&q.y);
        let c = self.t.mul(&q.td);
        let d = match &q.z {
            Some(z) => self.z.mul(z),
            None => self.z,
        };
        let e = self.x.add(&self.y).carry().mul(&q.x.add(&q.y).carry()).sub(&a).carry().sub(&b);
        Completed4 { x: e, y: b.sub(&a), z: d.add(&c), t: d.sub(&c) }
    }

    #[target_feature(enable = "avx2")]
    fn to_serial(&self) -> [ExtendedPoint; 4] {
        let x = self.x.to_serial();
        let y = self.y.to_serial();
        let z = self.z.to_serial();
        let t = self.t.to_serial();
        core::array::from_fn(|j| ExtendedPoint { x: x[j], y: y[j], z: z[j], t: t[j] })
    }
}

/// The entries for four lanes' digits (a zero digit selects the identity), negated in the lanes
/// whose digit is negative.
#[target_feature(enable = "avx2")]
fn gather(lookups: &[Lookup<'_>; 4], digits: [i8; 4]) -> Cached4 {
    let index = |j: usize| (digits[j].unsigned_abs() / 2) as usize; // |digit| < 2^7
    let mut q = match lookups[0] {
        Lookup::Cached(_) => {
            let entry = |j: usize| match lookups[j] {
                Lookup::Cached(table) if digits[j] != 0 => &table[index(j)],
                _ => &CachedPoint::IDENTITY,
            };
            let e = [entry(0), entry(1), entry(2), entry(3)];
            Cached4 {
                x: FieldElement4::from_serial([&e[0].x, &e[1].x, &e[2].x, &e[3].x]),
                y: FieldElement4::from_serial([&e[0].y, &e[1].y, &e[2].y, &e[3].y]),
                z: Some(FieldElement4::from_serial([&e[0].z, &e[1].z, &e[2].z, &e[3].z])),
                td: FieldElement4::from_serial([&e[0].td, &e[1].td, &e[2].td, &e[3].td]),
            }
        }
        Lookup::Affine(_) => {
            let entry = |j: usize| match lookups[j] {
                Lookup::Affine(table) if digits[j] != 0 => &table[index(j)],
                _ => &AFFINE_IDENTITY,
            };
            let e = [entry(0), entry(1), entry(2), entry(3)];
            Cached4 {
                x: FieldElement4::from_serial([&e[0].x, &e[1].x, &e[2].x, &e[3].x]),
                y: FieldElement4::from_serial([&e[0].y, &e[1].y, &e[2].y, &e[3].y]),
                z: None,
                td: FieldElement4::from_serial([&e[0].xy2d, &e[1].xy2d, &e[2].xy2d, &e[3].xy2d]),
            }
        }
    };
    if digits.iter().any(|&d| d < 0) {
        let lane = |j: usize| if digits[j] < 0 { -1i64 } else { 0 };
        let mask: __m256i = _mm256_set_epi64x(lane(3), lane(2), lane(1), lane(0));
        q.x = q.x.select(&q.x.neg().carry(), mask);
        q.td = q.td.select(&q.td.neg().carry(), mask);
    }
    q
}

/// One term of four lane-parallel multi-scalar multiplications: lane j adds
/// `Σ digits[j][i]·2^i` times the point whose odd multiples `lookups[j]` holds. All lanes use the
/// same kind of lookup.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LaneTerm<'a> {
    pub(crate) digits: [&'a [i8]; 4],
    pub(crate) lookups: [Lookup<'a>; 4],
}

/// Four Straus multi-scalar multiplications in lockstep, one per lane.
#[target_feature(enable = "avx2")]
pub(crate) fn straus4(terms: &[LaneTerm<'_>]) -> [ExtendedPoint; 4] {
    let top = terms
        .iter()
        .flat_map(|t| t.digits.iter().filter_map(|d| d.iter().rposition(|&x| x != 0)))
        .max();
    let Some(top) = top else {
        return [ExtendedPoint::IDENTITY; 4];
    };
    let mut r = Projective4::identity();
    for i in (0..=top).rev() {
        let mut t = r.double();
        for term in terms {
            let digits: [i8; 4] =
                core::array::from_fn(|j| term.digits[j].get(i).copied().unwrap_or(0));
            if digits == [0; 4] {
                continue;
            }
            t = t.to_extended().add(&gather(&term.lookups, digits));
        }
        r = t.to_projective();
    }
    // (X·Z, Y·Z, Z², X·Y): extended coordinates for the serial result.
    let (x, y, z) = (r.x, r.y, r.z);
    Extended4 { x: x.mul(&z), y: y.mul(&z), z: z.square(), t: x.mul(&y) }.to_serial()
}

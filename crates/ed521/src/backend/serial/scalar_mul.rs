//! Variable-time scalar multiplication on public inputs.
//!
//! Everything goes through [`straus_vartime`], which interleaves any number of wNAF terms over
//! one chain of doublings. A scalar split into [`CHUNKS`] chunks of [`CHUNK`] bits becomes that
//! many terms, each a window of the same wNAF against a table of `[2^(CHUNK j)]P`, so the chain
//! needs `CHUNK` doublings instead of ~520.

use super::curve_models::{AffineCached, CachedPoint, ExtendedPoint, ProjectivePoint};
use crate::scalar::{NAF_LENGTH, Scalar};
use crate::tables::generated::{BASE_ODD, CHUNK, CHUNKS};
use crate::window::OddMultiples;

/// wNAF width for variable points (a table of 8 odd multiples).
pub(crate) const VARIABLE_WIDTH: usize = 5;
/// wNAF width for the base point (the static 64-entry tables).
pub(crate) const BASE_WIDTH: usize = 8;

/// Odd multiples `[P, 3P, 5P, ...]` of some point, to look wNAF digits up in.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Lookup<'a> {
    Cached(&'a [CachedPoint]),
    Affine(&'a [AffineCached]),
}

/// One term `Σ digits[i]·2^i·P` of a multi-scalar multiplication; `lookup` holds odd multiples
/// of P and has an entry for every digit.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Term<'a> {
    pub(crate) digits: &'a [i8],
    pub(crate) lookup: Lookup<'a>,
}

/// The sum of all terms, by Straus' interleaved method: one doubling per digit position.
pub(crate) fn straus_vartime(terms: &[Term<'_>]) -> ExtendedPoint {
    straus_serial(terms)
}

/// [`straus_vartime`] on the serial backend.
pub(crate) fn straus_serial(terms: &[Term<'_>]) -> ExtendedPoint {
    let Some(top) = terms.iter().filter_map(|t| t.digits.iter().rposition(|&d| d != 0)).max()
    else {
        return ExtendedPoint::IDENTITY;
    };
    let mut r = ProjectivePoint::IDENTITY;
    for i in (0..=top).rev() {
        let mut t = r.double();
        for term in terms {
            let digit = match term.digits.get(i) {
                Some(&d) if d != 0 => d,
                _ => continue,
            };
            let index = (digit.unsigned_abs() / 2) as usize; // |digit| < 2^7
            let e = t.to_extended();
            t = match (term.lookup, digit > 0) {
                (Lookup::Cached(table), true) => e.add_cached(&table[index]),
                (Lookup::Cached(table), false) => e.sub_cached(&table[index]),
                (Lookup::Affine(table), true) => e.add_affine(&table[index]),
                (Lookup::Affine(table), false) => e.sub_affine(&table[index]),
            };
        }
        r = t.to_projective();
    }
    r.to_extended()
}

/// The [`CHUNKS`] windows of `CHUNK` positions of a wNAF; the digits of chunk j weigh `2^(CHUNK j)`.
pub(crate) fn split(naf: &[i8; NAF_LENGTH]) -> [&[i8]; CHUNKS] {
    debug_assert!(naf[CHUNK * CHUNKS..].iter().all(|&d| d == 0), "scalars are below 2^520");
    core::array::from_fn(|j| &naf[j * CHUNK..(j + 1) * CHUNK])
}

/// Tables of odd multiples of `[2^(CHUNK j)]P` for each chunk j, for a point used many times.
#[derive(Clone, Debug)]
pub(crate) struct SplitTables<const N: usize>(pub(crate) [OddMultiples<N>; CHUNKS]);

impl<const N: usize> SplitTables<N> {
    pub(crate) fn new(point: &ExtendedPoint) -> Self {
        let mut current = *point;
        Self(core::array::from_fn(|_| {
            let table = OddMultiples::new(&current);
            let mut p = current.to_projective();
            for _ in 0..CHUNK - 1 {
                p = p.double().to_projective();
            }
            current = p.double().to_extended();
            table
        }))
    }

    /// The wNAF width these tables serve.
    pub(crate) const WIDTH: usize = N.trailing_zeros() as usize + 2;
}

/// `[a]A + [b]B` by Straus' interleaved wNAF method, with B the base point. Variable time.
pub(crate) fn double_base_vartime(a: &Scalar, point: &ExtendedPoint, b: &Scalar) -> ExtendedPoint {
    double_base_with_table(a, &OddMultiples::new(point), b)
}

/// `[a]A + [b]B` with `table` the odd multiples of A.
pub(crate) fn double_base_with_table(
    a: &Scalar,
    table: &OddMultiples<8>,
    b: &Scalar,
) -> ExtendedPoint {
    let a_naf = a.non_adjacent_form(VARIABLE_WIDTH);
    let b_naf = b.non_adjacent_form(BASE_WIDTH);
    straus_vartime(&[
        Term { digits: &a_naf, lookup: Lookup::Cached(&table.0) },
        Term { digits: &b_naf, lookup: Lookup::Affine(&BASE_ODD.0[0]) },
    ])
}

/// Groups of at least this many multiplications run on the AVX2 lanes (four at a time, the
/// spare lanes idle); smaller remainders run serially.
#[cfg(all(target_arch = "x86_64", not(ed521_backend = "serial")))]
const LANE_GROUP_MIN: usize = 3;

/// `out[i] = [a_i]A + [b_i]B` for `pairs[i] = (a_i, b_i)`, with `table` the odd multiples of A.
pub(crate) fn double_base_many(
    table: &OddMultiples<8>,
    pairs: &[(Scalar, Scalar)],
    out: &mut [ExtendedPoint],
) {
    #[allow(unused_mut)] // advanced only by the AVX2 lanes
    let mut done = 0;
    #[cfg(all(target_arch = "x86_64", not(ed521_backend = "serial")))]
    if crate::backend::avx2() {
        let a_lookup = Lookup::Cached(&table.0);
        while pairs.len() - done >= LANE_GROUP_MIN {
            let n = (pairs.len() - done).min(4);
            let group = lane_group(&pairs[done..done + n]);
            #[allow(unsafe_code)]
            // SAFETY: the CPU supports AVX2 (`cpufeatures` checked CPUID).
            let points = unsafe { lanes_double_base(&group, &[a_lookup]) };
            out[done..done + n].copy_from_slice(&points[..n]);
            done += n;
        }
    }
    for i in done..pairs.len() {
        out[i] = double_base_with_table(&pairs[i].0, table, &pairs[i].1);
    }
}

/// [`double_base_many`] with split tables for A (and for B).
pub(crate) fn double_base_split_many<const N: usize>(
    tables: &SplitTables<N>,
    pairs: &[(Scalar, Scalar)],
    b_width: usize,
    out: &mut [ExtendedPoint],
) {
    #[allow(unused_mut)] // advanced only by the AVX2 lanes
    let mut done = 0;
    #[cfg(all(target_arch = "x86_64", not(ed521_backend = "serial")))]
    if crate::backend::avx2() && N == 8 {
        while pairs.len() - done >= LANE_GROUP_MIN {
            let n = (pairs.len() - done).min(4);
            let group = lane_group(&pairs[done..done + n]);
            let lookups: [Lookup<'_>; CHUNKS] =
                core::array::from_fn(|c| Lookup::Cached(&tables.0[c].0));
            #[allow(unsafe_code)]
            // SAFETY: the CPU supports AVX2 (`cpufeatures` checked CPUID).
            let points = unsafe { lanes_double_base(&group, &lookups) };
            out[done..done + n].copy_from_slice(&points[..n]);
            done += n;
        }
    }
    for i in done..pairs.len() {
        out[i] = double_base_split_vartime(&pairs[i].0, tables, &pairs[i].1, b_width);
    }
}

/// Digit width of A's regular recoding: odd multiples 1..15, the 8-entry tables.
#[cfg(all(target_arch = "x86_64", not(ed521_backend = "serial")))]
const LANE_A_WIDTH: usize = 4;
/// Digit width of B's regular recoding: odd multiples 1..127, the 64-entry tables.
#[cfg(all(target_arch = "x86_64", not(ed521_backend = "serial")))]
const LANE_B_WIDTH: usize = 7;

/// Up to four (a, b) pairs recoded for the lanes, padded with zeros.
#[cfg(all(target_arch = "x86_64", not(ed521_backend = "serial")))]
struct LaneGroup {
    a: [[i8; NAF_LENGTH]; 4],
    b: [[i8; NAF_LENGTH]; 4],
    /// `[-1]` where the recoding added one to make the scalar odd, `[0]` otherwise.
    a_fix: [[i8; 1]; 4],
    b_fix: [[i8; 1]; 4],
}

#[cfg(all(target_arch = "x86_64", not(ed521_backend = "serial")))]
fn lane_group(pairs: &[(Scalar, Scalar)]) -> LaneGroup {
    let mut group = LaneGroup {
        a: [[0; NAF_LENGTH]; 4],
        b: [[0; NAF_LENGTH]; 4],
        a_fix: [[0]; 4],
        b_fix: [[0]; 4],
    };
    for (j, (a, b)) in pairs.iter().enumerate() {
        let (digits, fix) = a.regular_odd_form(LANE_A_WIDTH);
        group.a[j] = digits;
        group.a_fix[j] = [-i8::from(fix)];
        let (digits, fix) = b.regular_odd_form(LANE_B_WIDTH);
        group.b[j] = digits;
        group.b_fix[j] = [-i8::from(fix)];
    }
    group
}

/// The lane multiplications of a group: A against `a_tables` (one table, or one per chunk, and
/// then the base tables are split too), B against the static tables.
#[cfg(all(target_arch = "x86_64", not(ed521_backend = "serial")))]
#[target_feature(enable = "avx2")]
fn lanes_double_base(group: &LaneGroup, a_tables: &[Lookup<'_>]) -> [ExtendedPoint; 4] {
    use crate::backend::vector::avx2::edwards::{LaneTerm, straus4};
    let split = a_tables.len() == CHUNKS;
    let mut terms = [LaneTerm { digits: [&[]; 4], lookups: [a_tables[0]; 4] }; 2 * CHUNKS + 2];
    let mut n = 0;
    let base = |c: usize| Lookup::Affine(&BASE_ODD.0[c]);
    if split {
        for c in 0..CHUNKS {
            let span = c * CHUNK..(c + 1) * CHUNK;
            terms[n] = LaneTerm {
                digits: core::array::from_fn(|j| &group.a[j][span.clone()]),
                lookups: [a_tables[c]; 4],
            };
            terms[n + 1] = LaneTerm {
                digits: core::array::from_fn(|j| &group.b[j][span.clone()]),
                lookups: [base(c); 4],
            };
            n += 2;
        }
    } else {
        terms[0] = LaneTerm {
            digits: core::array::from_fn(|j| &group.a[j][..]),
            lookups: [a_tables[0]; 4],
        };
        terms[1] =
            LaneTerm { digits: core::array::from_fn(|j| &group.b[j][..]), lookups: [base(0); 4] };
        n = 2;
    }
    // Undo the odd fix-ups: one more −1 digit of each point, in the lanes that needed it.
    terms[n] = LaneTerm {
        digits: core::array::from_fn(|j| &group.a_fix[j][..]),
        lookups: [a_tables[0]; 4],
    };
    terms[n + 1] =
        LaneTerm { digits: core::array::from_fn(|j| &group.b_fix[j][..]), lookups: [base(0); 4] };
    straus4(&terms[..n + 2])
}

/// `[a]A + [b]B` with split tables for A and for B (`b_width` <= 8): `CHUNK` doublings.
pub(crate) fn double_base_split_vartime<const N: usize>(
    a: &Scalar,
    tables: &SplitTables<N>,
    b: &Scalar,
    b_width: usize,
) -> ExtendedPoint {
    let a_naf = a.non_adjacent_form(SplitTables::<N>::WIDTH);
    let b_naf = b.non_adjacent_form(b_width);
    let entries = 1 << (b_width - 2);
    let a_chunks = split(&a_naf);
    let b_chunks = split(&b_naf);
    let terms: [Term<'_>; 2 * CHUNKS] = core::array::from_fn(|i| {
        let j = i / 2;
        if i % 2 == 0 {
            Term { digits: a_chunks[j], lookup: Lookup::Cached(&tables.0[j].0) }
        } else {
            Term { digits: b_chunks[j], lookup: Lookup::Affine(&BASE_ODD.0[j][..entries]) }
        }
    });
    straus_vartime(&terms)
}

/// `[b]B`. Variable time; used by tests and the test-only signer.
#[cfg(any(test, feature = "__hazmat-sign"))]
pub(crate) fn base_vartime(b: &Scalar) -> ExtendedPoint {
    double_base_vartime(&Scalar::ZERO, &ExtendedPoint::IDENTITY, b)
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;
    use proptest::prelude::*;

    use super::*;
    use crate::tables::generated::{BASE_X, BASE_Y};

    fn reference(scalar: &Scalar, point: &ExtendedPoint) -> ExtendedPoint {
        let mut result = ExtendedPoint::IDENTITY;
        let value = BigUint::from_bytes_le(&scalar.to_bytes());
        for i in (0..value.bits()).rev() {
            result = result.double();
            if value.bit(i) {
                result = result.add_cached(&point.to_cached()).to_extended();
            }
        }
        result
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn straus_matches_double_and_add(a in proptest::collection::vec(any::<u8>(), 66), b in proptest::collection::vec(any::<u8>(), 66), c in any::<u64>()) {
            let base = ExtendedPoint::from_affine(&BASE_X, &BASE_Y);
            let point = reference(&Scalar::from_bytes_mod_order(&c.to_le_bytes()), &base);
            let (a, b) = (Scalar::from_bytes_mod_order(&a), Scalar::from_bytes_mod_order(&b));
            let expected = reference(&a, &point).add_cached(&reference(&b, &base).to_cached()).to_extended();
            prop_assert!(double_base_vartime(&a, &point, &b).eq_vartime(&expected));
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        #[test]
        fn split_matches_double_base(a in proptest::collection::vec(any::<u8>(), 66), b in proptest::collection::vec(any::<u8>(), 66), c in any::<u64>(), b_width in 4usize..=8) {
            let base = ExtendedPoint::from_affine(&BASE_X, &BASE_Y);
            let point = reference(&Scalar::from_bytes_mod_order(&c.to_le_bytes()), &base);
            let (a, b) = (Scalar::from_bytes_mod_order(&a), Scalar::from_bytes_mod_order(&b));
            let expected = double_base_vartime(&a, &point, &b);
            let tables8: SplitTables<8> = SplitTables::new(&point);
            let tables16: SplitTables<16> = SplitTables::new(&point);
            prop_assert!(double_base_split_vartime(&a, &tables8, &b, b_width).eq_vartime(&expected));
            prop_assert!(double_base_split_vartime(&a, &tables16, &b, b_width).eq_vartime(&expected));
        }
    }

    /// The AVX2 lane path (groups of 3 and 4) against serial multiplications, for points of
    /// order L, with torsion, and of small order, zero scalars included, plain and split.
    #[test]
    fn lane_groups_match_serial() {
        use crate::backend::serial::field::FieldElement;
        let base = ExtendedPoint::from_affine(&BASE_X, &BASE_Y);
        let order_4 = ExtendedPoint::from_affine(&FieldElement::ONE, &FieldElement::ZERO);
        let scalar = |i: u64| {
            Scalar::from_bytes_mod_order(
                &i.wrapping_mul(0x9E37_79B9_7F4A_7C15).to_le_bytes().repeat(9),
            )
        };
        let points = [
            reference(&scalar(3), &base),
            reference(&scalar(5), &base).add_cached(&order_4.to_cached()).to_extended(),
            order_4,
            ExtendedPoint::IDENTITY,
        ];
        for point in &points {
            let table: OddMultiples<8> = OddMultiples::new(point);
            let split: SplitTables<8> = SplitTables::new(point);
            for n in 1..=9usize {
                let pairs: Vec<(Scalar, Scalar)> = (0..n as u64)
                    .map(|i| match i % 4 {
                        0 => (Scalar::ZERO, scalar(i + 1)),
                        1 => (scalar(i + 7), Scalar::ZERO),
                        _ => (scalar(i + 11), scalar(i + 13)),
                    })
                    .collect();
                let mut plain = vec![ExtendedPoint::IDENTITY; n];
                double_base_many(&table, &pairs, &mut plain);
                let mut chunked = vec![ExtendedPoint::IDENTITY; n];
                double_base_split_many(&split, &pairs, BASE_WIDTH, &mut chunked);
                for (i, (a, b)) in pairs.iter().enumerate() {
                    let expected = double_base_vartime(a, point, b);
                    assert!(plain[i].eq_vartime(&expected), "plain n = {n} i = {i}");
                    assert!(chunked[i].eq_vartime(&expected), "split n = {n} i = {i}");
                }
            }
        }
    }

    #[test]
    fn zero_scalars() {
        let base = ExtendedPoint::from_affine(&BASE_X, &BASE_Y);
        assert!(double_base_vartime(&Scalar::ZERO, &base, &Scalar::ZERO).is_identity());
        let one = Scalar::from_bytes_mod_order(&[1]);
        assert!(base_vartime(&one).eq_vartime(&base));
        assert!(double_base_vartime(&one, &base, &Scalar::ZERO).eq_vartime(&base));
    }
}

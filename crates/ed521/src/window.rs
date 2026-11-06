//! Lookup tables of odd multiples for wNAF scalar multiplication.

use crate::backend::serial::curve_models::{CachedPoint, ExtendedPoint};

/// `[P, 3P, 5P, ..., (2N-1)P]` in cached form; serves wNAF digits of width `log2(N) + 2`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct OddMultiples<const N: usize>(pub(crate) [CachedPoint; N]);

impl<const N: usize> OddMultiples<N> {
    pub(crate) fn new(point: &ExtendedPoint) -> Self {
        let twice = point.double().to_cached();
        let mut table = [CachedPoint::IDENTITY; N];
        let mut current = *point;
        table[0] = current.to_cached();
        for entry in table.iter_mut().skip(1) {
            current = current.add_cached(&twice).to_extended();
            *entry = current.to_cached();
        }
        Self(table)
    }
}

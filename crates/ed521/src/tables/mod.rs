//! Generated constants and fixed-base tables (`scripts/gen_tables.py`).

use crate::backend::serial::curve_models::AffineCached;

#[rustfmt::skip]
pub(crate) mod generated;

/// Entries per base table: the odd multiples 1, 3, ..., 127 (wNAF width up to 8).
pub(crate) const BASE_ENTRIES: usize = 64;

/// One table of odd multiples per scalar chunk, starting on a cache line.
#[repr(C, align(64))]
pub(crate) struct BaseTables(pub(crate) [[AffineCached; BASE_ENTRIES]; generated::CHUNKS]);

#[cfg(test)]
mod tests {
    use super::generated::{BASE_ODD, BASE_X, BASE_Y, CHUNK};
    use crate::backend::serial::curve_models::{AffineCached, ExtendedPoint};

    fn same(a: &AffineCached, b: &AffineCached) -> bool {
        a.x.canonical() == b.x.canonical()
            && a.y.canonical() == b.y.canonical()
            && a.xy2d.canonical() == b.xy2d.canonical()
    }

    /// Every table entry equals the value the Rust arithmetic computes from the base point.
    #[test]
    fn base_tables_recompute() {
        let mut point = ExtendedPoint::from_affine(&BASE_X, &BASE_Y);
        for (j, table) in BASE_ODD.0.iter().enumerate() {
            let twice = point.double().to_cached();
            let mut current = point;
            for (i, entry) in table.iter().enumerate() {
                assert!(same(entry, &current.to_affine_cached()), "BASE_ODD[{j}][{i}]");
                current = current.add_cached(&twice).to_extended();
            }
            for _ in 0..CHUNK {
                point = point.double();
            }
        }
    }
}

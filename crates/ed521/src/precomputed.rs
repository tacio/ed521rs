//! Public keys with precomputed tables, for keys that verify many signatures.

use crate::backend::serial::curve_models::ExtendedPoint;
use crate::backend::serial::scalar_mul::{
    SplitTables, double_base_split_many, double_base_split_vartime,
};
use crate::scalar::Scalar;
use crate::{Error, Signature, VerifyingKey};

/// Odd multiples per chunk table of −A (wNAF width 5).
pub(crate) const PRECOMPUTED_ENTRIES: usize = 8;
/// wNAF width of S against the split base tables.
pub(crate) const PRECOMPUTED_BASE_WIDTH: usize = 8;

/// A [`VerifyingKey`] with tables of `[2^(130 j)](−A)` for j = 0..3 (about 9 KiB), so each
/// verification needs 130 doublings instead of about 520.
///
/// Building it costs roughly half a verification; it pays off from the second signature on.
/// It checks exactly the same equation as [`VerifyingKey::verify`].
#[derive(Clone, Debug)]
pub struct PrecomputedVerifyingKey {
    key: VerifyingKey,
    tables: SplitTables<PRECOMPUTED_ENTRIES>,
}

impl PrecomputedVerifyingKey {
    /// Precomputes the tables of `key`.
    #[must_use]
    pub fn new(key: &VerifyingKey) -> Self {
        Self { key: *key, tables: SplitTables::new(&key.minus_a) }
    }

    /// The key the tables belong to.
    #[must_use]
    pub const fn verifying_key(&self) -> &VerifyingKey {
        &self.key
    }

    /// Verifies `signature` on `message`, with the same result as [`VerifyingKey::verify`].
    ///
    /// # Errors
    ///
    /// As [`VerifyingKey::verify`].
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), Error> {
        let (s, k) = self.key.scalars(message, signature)?;
        let q = self.multiply(&k, &s);
        self.key.finish(signature, &q, &q.compress())
    }

    /// As [`VerifyingKey::verify_many`].
    ///
    /// # Panics
    ///
    /// If the three slices differ in length.
    pub fn verify_many(
        &self,
        messages: &[&[u8]],
        signatures: &[Signature],
        results: &mut [Result<(), Error>],
    ) {
        self.key.verify_many_with(messages, signatures, results, |pairs, out| {
            double_base_split_many(&self.tables, pairs, PRECOMPUTED_BASE_WIDTH, out);
        });
    }

    /// Verifies `signatures[i]` on `messages[i]` for all i at once: cofactored and
    /// probabilistic, a pre-filter (see [`crate::verify_batch`]).
    ///
    /// # Errors
    ///
    /// As [`crate::verify_batch`].
    ///
    /// # Panics
    ///
    /// If the slices differ in length.
    #[cfg(feature = "batch")]
    pub fn verify_batch(&self, messages: &[&[u8]], signatures: &[Signature]) -> Result<(), Error> {
        crate::batch::verify_one_key(
            crate::batch::BatchKey::Precomputed(self),
            messages,
            signatures,
        )
    }

    #[cfg(feature = "batch")]
    pub(crate) const fn tables(&self) -> &SplitTables<PRECOMPUTED_ENTRIES> {
        &self.tables
    }

    fn multiply(&self, k: &Scalar, s: &Scalar) -> ExtendedPoint {
        double_base_split_vartime(k, &self.tables, s, PRECOMPUTED_BASE_WIDTH)
    }
}

impl From<&VerifyingKey> for PrecomputedVerifyingKey {
    fn from(key: &VerifyingKey) -> Self {
        Self::new(key)
    }
}

//! Random-linear-combination batch verification (feature `batch`).
//!
//! For signatures `(R_i, S_i)` under keys `A_i` with challenges `k_i`, the batch accepts when
//!
//! ```text
//! [4]( Σ [z_i]R_i + Σ_A [Σ_{i: A_i = A} z_i k_i]A − [Σ z_i S_i]B ) = O
//! ```
//!
//! for 128-bit coefficients `z_i` (top bit set) drawn from SHAKE256 over every input. It shares
//! one chain of doublings across all signatures and groups the `[k_i]A` terms by key.
//!
//! This is the **cofactored** equation, and probabilistic: a batch containing a signature that
//! fails the cofactored check is accepted with probability at most about 2^−127. A batch can be
//! accepted while some signature fails the exact, cofactorless [`VerifyingKey::verify`]: one
//! whose `[S]B − R − [k]A` is a nonzero point of order 2 or 4, which an honest signer never
//! produces. Use it as a fast pre-filter; per-signature verdicts come from `verify`/`verify_many`.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use shake::Shake256;
use shake::digest::{ExtendableOutput, Update};

use crate::backend::serial::curve_models::ExtendedPoint;
use crate::backend::serial::scalar_mul::{
    BASE_WIDTH, Lookup, SplitTables, Term, VARIABLE_WIDTH, split, straus_vartime,
};
use crate::edwards::{DecodeError, decompress};
use crate::precomputed::PRECOMPUTED_ENTRIES;
use crate::scalar::{NAF_LENGTH, Scalar};
use crate::tables::generated::{BASE_ODD, CHUNKS};
use crate::window::OddMultiples;
use crate::{Error, Mode, PrecomputedVerifyingKey, Signature, VerifyingKey};

/// Domain separation for the coefficient transcript.
const TRANSCRIPT_DOMAIN: &[u8] = b"ed521rs batch verification v1";
/// Bytes per coefficient `z_i`.
const COEFFICIENT_BYTES: usize = 16;

/// A key in a batch: plain (its term costs ~520 doublings, shared by the whole batch) or
/// precomputed (130).
#[derive(Clone, Copy, Debug)]
pub(crate) enum BatchKey<'a> {
    Plain(&'a VerifyingKey),
    Precomputed(&'a PrecomputedVerifyingKey),
}

impl BatchKey<'_> {
    fn key(&self) -> &VerifyingKey {
        match self {
            Self::Plain(key) => key,
            Self::Precomputed(key) => key.verifying_key(),
        }
    }
}

/// Verifies `(key, message, signature)` items, where `keys[key]` is the item's key and the keys
/// are distinct.
pub(crate) fn verify(
    keys: &[BatchKey<'_>],
    items: &[(usize, &[u8], &Signature)],
) -> Result<(), Error> {
    if items.is_empty() {
        return Ok(());
    }
    // Decode every item, as exact verification does (S, then R).
    let mut decoded = Vec::with_capacity(items.len());
    for &(key, message, signature) in items {
        let verifying_key = keys[key].key();
        let (s, k) = verifying_key.scalars(message, signature)?;
        let r = decompress(signature.r_bytes(), verifying_key.mode).map_err(|e| match e {
            DecodeError::NonCanonical => Error::NonCanonicalR,
            DecodeError::NotOnCurve => Error::RNotOnCurve,
        })?;
        decoded.push((r, s, k));
    }

    // z_i from a transcript of every input. k_i binds R_i, A_i and M_i; S_i and the mode are
    // absorbed explicitly.
    let mut transcript = Shake256::default();
    transcript.update(TRANSCRIPT_DOMAIN);
    transcript.update(&(items.len() as u64).to_le_bytes());
    for (&(key, _, signature), (_, _, k)) in items.iter().zip(&decoded) {
        let verifying_key = keys[key].key();
        transcript.update(&[u8::from(verifying_key.mode == Mode::EcpyCompat)]);
        transcript.update(&verifying_key.bytes);
        transcript.update(&signature.to_bytes());
        transcript.update(&k.to_bytes());
    }
    let mut stream = alloc::vec![0u8; COEFFICIENT_BYTES * items.len()];
    transcript.finalize_xof_into(&mut stream);

    let mut key_scalars = alloc::vec![Scalar::ZERO; keys.len()];
    let mut base_scalar = Scalar::ZERO;
    let mut r_nafs = Vec::with_capacity(items.len());
    let mut r_tables: Vec<OddMultiples<8>> = Vec::with_capacity(items.len());
    for (i, (&(key, _, _), (r, s, k))) in items.iter().zip(&decoded).enumerate() {
        let mut bytes = [0u8; COEFFICIENT_BYTES];
        bytes.copy_from_slice(&stream[i * COEFFICIENT_BYTES..(i + 1) * COEFFICIENT_BYTES]);
        bytes[COEFFICIENT_BYTES - 1] |= 0x80; // z_i in [2^127, 2^128): never zero
        let z = Scalar::from_bytes_mod_order(&bytes);
        key_scalars[key] = z.mul_add(k, &key_scalars[key]);
        base_scalar = z.mul_add(s, &base_scalar);
        r_nafs.push(z.non_adjacent_form(VARIABLE_WIDTH));
        r_tables.push(OddMultiples::new(r));
    }
    let base_naf = base_scalar.neg().non_adjacent_form(BASE_WIDTH);

    // Keys hold tables of −A, so [c]A = [−c](−A). Plain keys take the full wNAF against one
    // table; precomputed ones split it over their chunk tables.
    let key_nafs: Vec<[i8; NAF_LENGTH]> = keys
        .iter()
        .zip(&key_scalars)
        .map(|(key, c)| {
            let width = match key {
                BatchKey::Plain(_) => VARIABLE_WIDTH,
                BatchKey::Precomputed(_) => SplitTables::<PRECOMPUTED_ENTRIES>::WIDTH,
            };
            c.neg().non_adjacent_form(width)
        })
        .collect();
    let plain_tables: Vec<Option<OddMultiples<8>>> = keys
        .iter()
        .map(|key| match key {
            BatchKey::Plain(key) => Some(OddMultiples::new(&key.minus_a)),
            BatchKey::Precomputed(_) => None,
        })
        .collect();

    let mut terms = Vec::with_capacity(items.len() + keys.len() * CHUNKS + CHUNKS);
    for (naf, table) in r_nafs.iter().zip(&r_tables) {
        terms.push(Term { digits: &naf[..], lookup: Lookup::Cached(&table.0) });
    }
    for ((key, naf), table) in keys.iter().zip(&key_nafs).zip(&plain_tables) {
        match (key, table) {
            (BatchKey::Precomputed(key), _) => {
                for (digits, table) in split(naf).into_iter().zip(&key.tables().0) {
                    terms.push(Term { digits, lookup: Lookup::Cached(&table.0) });
                }
            }
            (BatchKey::Plain(_), Some(table)) => {
                terms.push(Term { digits: &naf[..], lookup: Lookup::Cached(&table.0) });
            }
            (BatchKey::Plain(_), None) => unreachable!("plain keys have a table"),
        }
    }
    for (digits, table) in split(&base_naf).into_iter().zip(&BASE_ODD.0) {
        terms.push(Term { digits, lookup: Lookup::Affine(table) });
    }
    let sum: ExtendedPoint = straus_vartime(&terms);
    if sum.double().double().is_identity() { Ok(()) } else { Err(Error::BatchInvalid) }
}

/// Verifies many signatures at once, under any mix of keys: cofactored and probabilistic (see
/// the [module documentation](self)).
///
/// Returns `Ok(())` for an empty batch.
///
/// # Errors
///
/// The decoding error of the first malformed signature (as [`VerifyingKey::verify`] reports it),
/// otherwise [`Error::BatchInvalid`] when the combined equation fails: at least one signature is
/// invalid, and [`VerifyingKey::verify`] on each one tells which.
pub fn verify_batch(items: &[(&VerifyingKey, &[u8], &Signature)]) -> Result<(), Error> {
    let mut index: BTreeMap<([u8; 66], bool), usize> = BTreeMap::new();
    let mut keys = Vec::new();
    let mut indexed = Vec::with_capacity(items.len());
    for &(key, message, signature) in items {
        let next = keys.len();
        let slot = *index.entry((key.bytes, key.mode == Mode::EcpyCompat)).or_insert(next);
        if slot == next {
            keys.push(BatchKey::Plain(key));
        }
        indexed.push((slot, message, signature));
    }
    verify(&keys, &indexed)
}

/// `messages[i]`, `signatures[i]` under one key.
pub(crate) fn verify_one_key(
    key: BatchKey<'_>,
    messages: &[&[u8]],
    signatures: &[Signature],
) -> Result<(), Error> {
    assert_eq!(messages.len(), signatures.len(), "messages and signatures differ in length");
    let items: Vec<_> = messages.iter().zip(signatures).map(|(m, s)| (0, *m, s)).collect();
    verify(&[key], &items)
}

//! Public keys, signatures and single-signature verification.

use crate::Error;
use crate::backend::serial::curve_models::{COMPRESS_BATCH, ExtendedPoint};
use crate::backend::serial::scalar_mul::{double_base_many, double_base_vartime};
use crate::edwards::{DecodeError, decompress};
use crate::hash::challenge;
use crate::scalar::Scalar;
use crate::window::OddMultiples;

/// Length of an encoded public key.
pub const PUBLIC_KEY_LENGTH: usize = 66;
/// Length of an encoded signature (`R || S`).
pub const SIGNATURE_LENGTH: usize = 132;

/// Which encodings verification accepts. Both modes check the same cofactorless equation
/// `[S]B = R + [k]A`; they differ only on encodings an honest signer never produces.
///
/// | | `Strict` | `EcpyCompat` |
/// |---|---|---|
/// | matches | RFC 8032 decoding; [election-audit]'s `ed521.py` | ECPy (TSE's reference verifier) |
/// | y of R and A | below p | any 527-bit value, taken mod p |
/// | x = 0 with the sign bit | rejected | accepted |
/// | S | below L | any 528-bit value, taken mod L, except 0 |
/// | small-order A | `[S]B = R + [k]A` | `[S]B = R`, R canonical |
///
/// In both modes R and A enter the hash as the bytes given.
///
/// The last two `EcpyCompat` rules reproduce ECPy's arithmetic rather than the equation: it maps
/// `S ≡ 0` to its point at infinity, which never equals a curve point, and its ladder uses the
/// dedicated (non-unified) addition, which collapses `[k]A` to that point at infinity whenever A is
/// in the 4-torsion; it then compares R's decoded coordinates with `[S]B` as integers.
/// `tests/vectors/edge-cases.json` pins every rule against ECPy itself.
///
/// [election-audit]: https://github.com/tacio/election-audit
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Mode {
    /// RFC 8032 rules: canonical encodings only, `S < L`.
    #[default]
    Strict,
    /// The superset ECPy (commit 8143d9ac, pinned by TSE) accepts.
    EcpyCompat,
}

/// An Ed521 signature, `R || S`. Its parts are only checked by [`VerifyingKey::verify`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature([u8; SIGNATURE_LENGTH]);

impl Signature {
    /// The signature with these 132 bytes.
    #[must_use]
    pub const fn from_bytes(bytes: &[u8; SIGNATURE_LENGTH]) -> Self {
        Self(*bytes)
    }

    /// The signature with these bytes.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] unless `bytes` is 132 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self(bytes.try_into().map_err(|_| Error::InvalidLength)?))
    }

    /// The 132 bytes.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; SIGNATURE_LENGTH] {
        self.0
    }

    pub(crate) fn r_bytes(&self) -> &[u8; 66] {
        self.0[..66].try_into().expect("132 = 66 + 66")
    }

    pub(crate) fn s_bytes(&self) -> &[u8; 66] {
        self.0[66..].try_into().expect("132 = 66 + 66")
    }
}

/// A decoded Ed521 public key, together with the mode it was decoded in.
///
/// Two keys are equal (and hash alike) when they were decoded from the same 66 bytes in the same
/// mode. In [`Mode::EcpyCompat`], two different encodings of one point are different keys: the
/// encoding enters the challenge hash, so they verify different signatures.
#[derive(Clone, Copy, Debug)]
pub struct VerifyingKey {
    /// −A: verification computes `[S]B + [k](−A)` and compares it with R.
    pub(crate) minus_a: ExtendedPoint,
    pub(crate) bytes: [u8; PUBLIC_KEY_LENGTH],
    pub(crate) mode: Mode,
    /// `[4]A = O`, recorded in [`Mode::EcpyCompat`] only (see [`Mode`]).
    pub(crate) ecpy_small_order: bool,
}

// The other fields are computed from the encoding and the mode, so these two decide equality.
impl PartialEq for VerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes && self.mode == other.mode
    }
}

impl Eq for VerifyingKey {}

impl core::hash::Hash for VerifyingKey {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.bytes.hash(state);
        self.mode.hash(state);
    }
}

impl VerifyingKey {
    /// Decodes a public key in [`Mode::Strict`].
    ///
    /// # Errors
    ///
    /// [`Error::NonCanonicalPublicKey`] or [`Error::PublicKeyNotOnCurve`].
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_LENGTH]) -> Result<Self, Error> {
        Self::from_bytes_with_mode(bytes, Mode::Strict)
    }

    /// Decodes a public key; `mode` also governs the signatures it verifies.
    ///
    /// # Errors
    ///
    /// [`Error::NonCanonicalPublicKey`] (strict mode only) or [`Error::PublicKeyNotOnCurve`].
    pub fn from_bytes_with_mode(
        bytes: &[u8; PUBLIC_KEY_LENGTH],
        mode: Mode,
    ) -> Result<Self, Error> {
        let a = decompress(bytes, mode).map_err(|e| match e {
            DecodeError::NonCanonical => Error::NonCanonicalPublicKey,
            DecodeError::NotOnCurve => Error::PublicKeyNotOnCurve,
        })?;
        let ecpy_small_order = mode == Mode::EcpyCompat && a.double().double().is_identity();
        Ok(Self { minus_a: a.neg(), bytes: *bytes, mode, ecpy_small_order })
    }

    /// Decodes a public key from a slice.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] unless `bytes` is 66 bytes long, otherwise as
    /// [`VerifyingKey::from_bytes_with_mode`].
    pub fn from_slice(bytes: &[u8], mode: Mode) -> Result<Self, Error> {
        Self::from_bytes_with_mode(bytes.try_into().map_err(|_| Error::InvalidLength)?, mode)
    }

    /// The encoding the key was decoded from.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.bytes
    }

    /// The mode the key was decoded in.
    #[must_use]
    pub const fn mode(&self) -> Mode {
        self.mode
    }

    /// Verifies `signature` on `message`.
    ///
    /// S is checked before R, so a signature with both a bad S and a bad R reports S.
    ///
    /// # Errors
    ///
    /// [`Error::SOutOfRange`], [`Error::NonCanonicalR`] or [`Error::RNotOnCurve`] for a
    /// malformed signature, [`Error::InvalidSignature`] when the equation fails.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), Error> {
        let (s, k) = self.scalars(message, signature)?;
        let q = double_base_vartime(&k, &self.minus_a, &s);
        self.finish(signature, &q, &q.compress())
    }

    /// Verifies `signatures[i]` on `messages[i]` into `results[i]`, with the same results as
    /// [`VerifyingKey::verify`] but one field inversion per 16 signatures instead of one each.
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
        let table = OddMultiples::new(&self.minus_a);
        self.verify_many_with(messages, signatures, results, |pairs, out| {
            double_base_many(&table, pairs, out);
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
        crate::batch::verify_one_key(crate::batch::BatchKey::Plain(self), messages, signatures)
    }

    /// Precomputes tables for verifying many signatures with this key.
    #[must_use]
    pub fn precompute(&self) -> crate::PrecomputedVerifyingKey {
        crate::PrecomputedVerifyingKey::new(self)
    }

    /// Decodes S and computes k: everything before the scalar multiplication `[k](−A) + [S]B`.
    pub(crate) fn scalars(
        &self,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(Scalar, Scalar), Error> {
        let s = match self.mode {
            Mode::Strict => {
                Scalar::from_canonical_bytes(signature.s_bytes()).ok_or(Error::SOutOfRange)?
            }
            Mode::EcpyCompat => {
                let s = Scalar::from_bytes_mod_order(signature.s_bytes());
                if s.is_zero() {
                    return Err(Error::InvalidSignature);
                }
                s
            }
        };
        if self.ecpy_small_order {
            // ECPy compares R's coordinates, as decoded, with [S]B: R must be canonical.
            if decompress(signature.r_bytes(), Mode::Strict).is_err() {
                return Err(Error::InvalidSignature);
            }
            return Ok((s, Scalar::ZERO));
        }
        Ok((s, challenge(signature.r_bytes(), &self.bytes, message)))
    }

    /// Compares `Q = [S]B − [k]A` (encoded as `q_bytes`) with R. Only a mismatch decodes R: to
    /// report why it fails, or in [`Mode::EcpyCompat`] to accept a non-canonical encoding of Q.
    pub(crate) fn finish(
        &self,
        signature: &Signature,
        q: &ExtendedPoint,
        q_bytes: &[u8; 66],
    ) -> Result<(), Error> {
        if q_bytes == signature.r_bytes() {
            return Ok(());
        }
        let r = decompress(signature.r_bytes(), self.mode).map_err(|e| match e {
            DecodeError::NonCanonical => Error::NonCanonicalR,
            DecodeError::NotOnCurve => Error::RNotOnCurve,
        })?;
        if r.eq_vartime(q) { Ok(()) } else { Err(Error::InvalidSignature) }
    }

    /// [`VerifyingKey::verify_many`] with `multiply(pairs, out)` setting
    /// `out[i] = [k_i](−A) + [s_i]B` for `pairs[i] = (k_i, s_i)`.
    pub(crate) fn verify_many_with(
        &self,
        messages: &[&[u8]],
        signatures: &[Signature],
        results: &mut [Result<(), Error>],
        multiply: impl Fn(&[(Scalar, Scalar)], &mut [ExtendedPoint]),
    ) {
        assert!(
            messages.len() == signatures.len() && signatures.len() == results.len(),
            "messages, signatures and results differ in length"
        );
        let mut start = 0;
        while start < messages.len() {
            let end = (start + COMPRESS_BATCH).min(messages.len());
            let mut pairs = [(Scalar::ZERO, Scalar::ZERO); COMPRESS_BATCH];
            let mut indices = [0usize; COMPRESS_BATCH];
            let mut n = 0;
            for i in start..end {
                match self.scalars(messages[i], &signatures[i]) {
                    Ok((s, k)) => {
                        pairs[n] = (k, s);
                        indices[n] = i;
                        n += 1;
                    }
                    Err(e) => results[i] = Err(e),
                }
            }
            let mut points = [ExtendedPoint::IDENTITY; COMPRESS_BATCH];
            multiply(&pairs[..n], &mut points[..n]);
            let mut encoded = [[0u8; 66]; COMPRESS_BATCH];
            ExtendedPoint::compress_batch(&points[..n], &mut encoded[..n]);
            for j in 0..n {
                let i = indices[j];
                results[i] = self.finish(&signatures[i], &points[j], &encoded[j]);
            }
            start = end;
        }
    }
}

/// Verifies one signature from raw bytes: the public key (66 bytes), the signature (132 bytes)
/// and the message.
///
/// # Errors
///
/// [`Error::InvalidLength`] for wrong lengths, otherwise as [`VerifyingKey::from_bytes_with_mode`]
/// and [`VerifyingKey::verify`].
pub fn verify(
    public_key: &[u8],
    signature: &[u8],
    message: &[u8],
    mode: Mode,
) -> Result<(), Error> {
    let signature = Signature::from_slice(signature)?;
    VerifyingKey::from_slice(public_key, mode)?.verify(message, &signature)
}

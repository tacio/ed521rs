//! Verification errors.

use core::fmt;

/// Why a public key or signature was rejected.
///
/// Each variant has a stable snake-case code ([`Error::code`]) for audit status columns.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Error {
    /// A key, signature or buffer had the wrong length.
    InvalidLength,
    /// The public key's y is not canonical (y >= p, bits 521..526 set), or x = 0 with the sign
    /// bit set. Strict mode only.
    NonCanonicalPublicKey,
    /// No curve point has the public key's y coordinate.
    PublicKeyNotOnCurve,
    /// The public key has order 1, 2 or 4 (`[4]A = O`). Only reported on request, by
    /// [`VerifyingKey::reject_small_order`](crate::VerifyingKey::reject_small_order).
    SmallOrderPublicKey,
    /// The signature's R is not a canonical point encoding. Strict mode only.
    NonCanonicalR,
    /// No curve point has R's y coordinate.
    RNotOnCurve,
    /// The signature's S is not below the group order L. Strict mode only.
    SOutOfRange,
    /// Every encoding is valid but `[S]B = R + [k]A` does not hold.
    InvalidSignature,
    /// A batch failed its combined check (at least one signature in it is invalid).
    BatchInvalid,
}

impl Error {
    /// A stable snake-case code for the error.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidLength => "invalid_length",
            Self::NonCanonicalPublicKey => "non_canonical_public_key",
            Self::PublicKeyNotOnCurve => "public_key_not_on_curve",
            Self::SmallOrderPublicKey => "small_order_public_key",
            Self::NonCanonicalR => "non_canonical_r",
            Self::RNotOnCurve => "r_not_on_curve",
            Self::SOutOfRange => "s_out_of_range",
            Self::InvalidSignature => "invalid_signature",
            Self::BatchInvalid => "batch_invalid",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::InvalidLength => "wrong key, signature or buffer length",
            Self::NonCanonicalPublicKey => "public key is not a canonical point encoding",
            Self::PublicKeyNotOnCurve => "public key is not a curve point",
            Self::SmallOrderPublicKey => "public key has small order",
            Self::NonCanonicalR => "signature R is not a canonical point encoding",
            Self::RNotOnCurve => "signature R is not a curve point",
            Self::SOutOfRange => "signature S is not below the group order",
            Self::InvalidSignature => "signature equation does not hold",
            Self::BatchInvalid => "batch verification failed",
        };
        f.write_str(text)
    }
}

impl core::error::Error for Error {}

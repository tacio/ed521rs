//! Point decoding for E-521, in the two verification modes.

use crate::Mode;
use crate::backend::serial::curve_models::ExtendedPoint;
use crate::backend::serial::field::{FieldElement, is_canonical_encoding};

/// Why an encoding does not decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DecodeError {
    NonCanonical,
    NotOnCurve,
}

/// Decodes a 66-byte point: little-endian y in bits 0..527, the parity of x in bit 527.
///
/// - [`Mode::Strict`] (RFC 8032 §5.2.3, election-audit's `ed521.py`): y must be below p, and x = 0
///   with the sign bit set is rejected.
/// - [`Mode::EcpyCompat`] (ECPy `decode_point` / `x_recover`): y is any 527-bit value, taken
///   mod p, and x = 0 with the sign bit set decodes to x = 0 (ECPy represents it as x = p).
pub(crate) fn decompress(bytes: &[u8; 66], mode: Mode) -> Result<ExtendedPoint, DecodeError> {
    let sign = bytes[65] >> 7 == 1;
    let mut y_bytes = *bytes;
    y_bytes[65] &= 0x7F;
    if mode == Mode::Strict && !is_canonical_encoding(&y_bytes) {
        return Err(DecodeError::NonCanonical);
    }
    let y = FieldElement::from_bytes(&y_bytes);
    // x² = (1 - y²) / (1 - d·y²) and d = -376014, so the denominator is 1 + 376014·y².
    let yy = y.square();
    let u = FieldElement::ONE.sub(&yy);
    let v = yy.mul_small(376014).add(&FieldElement::ONE);
    let (is_square, mut x) = FieldElement::sqrt_ratio(&u, &v);
    if !is_square {
        return Err(DecodeError::NotOnCurve);
    }
    if x.is_zero() {
        if sign && mode == Mode::Strict {
            return Err(DecodeError::NonCanonical);
        }
    } else if x.is_odd() != sign {
        x = x.neg();
    }
    Ok(ExtendedPoint::from_affine(&x.reduce(), &y))
}

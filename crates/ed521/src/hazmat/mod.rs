//! **Test-only** signing, for generating vectors. Not constant time: never use it with a key
//! that matters.
//!
//! Key expansion follows ECPy (the library TSE's reference verifier uses), checked against
//! ECPy's published Ed521 vector: the private value, as 66 big-endian bytes, is hashed with
//! SHAKE256 to 132 bytes *without* the dom5 prefix; the low half, clamped with
//! `a[0] &= 0xFC; a[65] = 0x80`, is the secret scalar and the high half the nonce prefix.
//! (DOC-ICP-01.01 read literally would hash with dom5 and set bit 520 instead.)

use shake::Shake256;
use shake::digest::{ExtendableOutput, Update};

use crate::backend::serial::scalar_mul::base_vartime;
use crate::hash::{DOM5_PURE, challenge};
use crate::scalar::Scalar;
use crate::{Mode, Signature, VerifyingKey};

/// An expanded Ed521 secret key. Not constant time; for tests only.
#[derive(Clone, Debug)]
pub struct SigningKey {
    scalar: Scalar,
    prefix: [u8; 66],
    verifying_key: VerifyingKey,
}

impl SigningKey {
    /// Expands ECPy's private value `d` (66 big-endian bytes), as `ECPrivateKey(d, Ed521)`.
    ///
    /// # Panics
    ///
    /// Never: a multiple of the base point always decodes.
    #[must_use]
    pub fn from_ecpy_private(private: &[u8; 66]) -> Self {
        let mut hasher = Shake256::default();
        hasher.update(private);
        let mut digest = [0u8; 132];
        hasher.finalize_xof_into(&mut digest);
        let mut clamped = [0u8; 66];
        clamped.copy_from_slice(&digest[..66]);
        clamped[0] &= 0xFC;
        clamped[65] = 0x80;
        let scalar = Scalar::from_bytes_mod_order(&clamped);
        let mut prefix = [0u8; 66];
        prefix.copy_from_slice(&digest[66..]);
        let public = base_vartime(&scalar).compress();
        let verifying_key = VerifyingKey::from_bytes_with_mode(&public, Mode::Strict)
            .expect("a multiple of the base point decodes");
        Self { scalar, prefix, verifying_key }
    }

    /// The matching public key.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.verifying_key
    }

    /// The deterministic PureEdDSA signature of `message`.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Signature {
        let mut hasher = Shake256::default();
        hasher.update(DOM5_PURE);
        hasher.update(&self.prefix);
        hasher.update(message);
        let mut digest = [0u8; 132];
        hasher.finalize_xof_into(&mut digest);
        let r = Scalar::from_bytes_mod_order(&digest);
        let r_bytes = base_vartime(&r).compress();
        let k = challenge(&r_bytes, &self.verifying_key.bytes, message);
        let s = k.mul_add(&self.scalar, &r);
        let mut bytes = [0u8; 132];
        bytes[..66].copy_from_slice(&r_bytes);
        bytes[66..].copy_from_slice(&s.to_bytes());
        Signature::from_bytes(&bytes)
    }
}

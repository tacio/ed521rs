//! The Ed521 hash: `H(x) = SHAKE256(dom5(phflag, context) || x, 132)` (DOC-ICP-01.01).

use shake::Shake256;
use shake::digest::{ExtendableOutput, Update};

use crate::scalar::Scalar;

/// `dom5(0, "")`: PureEdDSA with an empty context, as TSE's urns and ECPy use it.
pub(crate) const DOM5_PURE: &[u8] = b"SigEd521\x00\x00";

/// The challenge `k = H(dom5 || R || A || M) mod L`.
pub(crate) fn challenge(r: &[u8; 66], a: &[u8; 66], message: &[u8]) -> Scalar {
    let mut hasher = Shake256::default();
    hasher.update(DOM5_PURE);
    hasher.update(r);
    hasher.update(a);
    hasher.update(message);
    let mut digest = [0u8; 132];
    hasher.finalize_xof_into(&mut digest);
    Scalar::from_bytes_mod_order(&digest)
}

//! Fast verification of Ed521 signatures: EdDSA over the Edwards curve E-521, as specified by
//! ICP-Brasil (DOC-ICP-01.01) and used by TSE's UE2020/UE2022 voting machines.
//!
//! # Parameters
//!
//! - Field p = 2^521 − 1; curve x² + y² = 1 + d·x²·y² with d = −376014; cofactor 4.
//! - Base point B = (Gx, 12) of prime order L (519 bits).
//! - Points and scalars are 66 bytes, little-endian; a point is y with the parity of x in
//!   bit 527. Signatures are `R || S`, 132 bytes.
//! - `H(x) = SHAKE256("SigEd521" || 0x00 || 0x00 || x, 132)`: PureEdDSA with an empty context.
//!
//! # Verification
//!
//! [`VerifyingKey::verify`] accepts when `[S]B = R + [k]A` with `k = H(R || A || M) mod L`
//! (cofactorless, like RFC 8032 and TSE's reference). The [`Mode`] decides which encodings are
//! accepted; see its documentation. Verification is variable time: every input is public.
//!
//! TSE's urns sign `M = SHA-512(h)` where `h` is the SHA-512 hash of a file; that hashing is the
//! caller's job, and this crate verifies any message.
//!
//! # Example
//!
//! ```
//! use ed521::{Signature, VerifyingKey};
//! # let public_key: [u8; 66] = hex::decode(
//! #     "fb00870ccbf9c3db7790f76ca2470c41373f4ccced7ae646bad040274d717f7f44e6d37537dede5bbdae7410b3\
//! #      2e7b67521b0f3cac077548d100612a0e8b65d66c00",
//! # )?.try_into().unwrap();
//! # let signature: [u8; 132] = hex::decode(
//! #     "c2fb4f7d03dd31f25753b9972aeb650ac3632eef945e7f94e426a865bb95e66241149c7eed24d98fed2ee8b9ef\
//! #      949b83ba556d045b72df6e6b8b9026414b26463d0088d2ed5ea88fcc6b2f343d308209dacd5fadadac352d497d\
//! #      2049831eca3536e7be5a7faef56d6c6786c60415e0febee8a45f9971ae4872e0b6cf09cc0a9407342000",
//! # )?.try_into().unwrap();
//!
//! let key = VerifyingKey::from_bytes(&public_key)?;
//! key.verify(b"Message for Ed521 signing", &Signature::from_bytes(&signature))?;
//!
//! // For a key that verifies many signatures: about twice as fast per signature.
//! let key = key.precompute();
//! key.verify(b"Message for Ed521 signing", &Signature::from_bytes(&signature))?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Cargo features
//!
//! - `std` (default): links `std`; implies `alloc`.
//! - `alloc`: needed by `batch`.
//! - `batch`: `verify_batch` and `VerifyingKey::verify_batch`, a probabilistic,
//!   cofactored pre-filter for many signatures.
//!
//! # Security
//!
//! **This crate has not been independently audited.** It is checked against TSE's reference
//! verifier, real TSE signatures, crafted edge cases and differential fuzzing, but no third party
//! has reviewed it. See `SECURITY.md` in the [repository](https://github.com/tacio/ed521rs).
#![cfg_attr(not(test), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod backend;
#[cfg(feature = "batch")]
pub mod batch;
mod edwards;
mod error;
mod hash;
mod precomputed;
mod scalar;
mod tables;
mod verifying;
mod window;

#[cfg(feature = "__hazmat-sign")]
#[doc(hidden)]
pub mod hazmat;

// Compiles and runs the README's example as a doctest.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

#[cfg(feature = "__bench")]
#[doc(hidden)]
pub mod bench_internals;

#[cfg(feature = "batch")]
pub use batch::verify_batch;
pub use error::Error;
pub use precomputed::PrecomputedVerifyingKey;

/// `"avx2"` when this process verifies groups of signatures (`verify_many`) on AVX2, otherwise
/// `"serial"`. Results never depend on it.
#[must_use]
pub fn backend_name() -> &'static str {
    backend::name()
}
pub use verifying::{Mode, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH, Signature, VerifyingKey, verify};

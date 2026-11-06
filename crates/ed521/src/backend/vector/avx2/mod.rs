//! The AVX2 backend: field elements in four 64-bit lanes, points as one vector of (X, Y, Z, T).

pub(crate) mod edwards;
pub(crate) mod field;
#[rustfmt::skip]
mod kernels;

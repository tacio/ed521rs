//! Vector backends, chosen at runtime.

#[cfg(target_arch = "x86_64")]
pub(crate) mod avx2;

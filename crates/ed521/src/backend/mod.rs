//! Arithmetic backends: the portable serial one, and AVX2, chosen at runtime.
//!
//! AVX2 runs four signatures' scalar multiplications in its four lanes, so it serves the
//! multi-signature paths (`verify_many`); single verification and batch verification use the
//! serial backend on every CPU (BENCHMARKS.md has the measurements behind that split).
//! `--cfg ed521_backend="serial"` (in `RUSTFLAGS`) forces the serial backend everywhere.

pub(crate) mod serial;
#[cfg(all(target_arch = "x86_64", not(ed521_backend = "serial")))]
pub(crate) mod vector;

#[cfg(all(target_arch = "x86_64", not(ed521_backend = "serial")))]
cpufeatures::new!(avx2_cpuid, "avx2");

/// True when this process runs the AVX2 backend.
#[inline]
pub(crate) fn avx2() -> bool {
    #[cfg(all(target_arch = "x86_64", not(ed521_backend = "serial")))]
    {
        avx2_cpuid::get()
    }
    #[cfg(not(all(target_arch = "x86_64", not(ed521_backend = "serial"))))]
    {
        false
    }
}

/// `"avx2"` when this process runs `verify_many` on the AVX2 lanes, otherwise `"serial"`.
pub(crate) fn name() -> &'static str {
    if avx2() { "avx2" } else { "serial" }
}

//! Internal operations exposed to the criterion benches (feature `__bench`; not a public API).
#![allow(missing_docs, clippy::missing_panics_doc)]

use crate::backend::serial::curve_models::ExtendedPoint;
use crate::backend::serial::field::FieldElement;
use crate::scalar::Scalar;
use crate::tables::generated::{BASE_X, BASE_Y};

#[derive(Clone, Copy)]
pub struct Fe(FieldElement);

impl Fe {
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 66]) -> Self {
        Self(FieldElement::from_bytes(bytes))
    }
    #[must_use]
    pub fn mul(&self, rhs: &Self) -> Self {
        Self(self.0.mul(&rhs.0))
    }
    #[must_use]
    pub fn square(&self) -> Self {
        Self(self.0.square())
    }
    #[must_use]
    pub fn invert(&self) -> Self {
        Self(self.0.invert())
    }
}

#[derive(Clone, Copy)]
pub struct Point(ExtendedPoint);

#[must_use]
pub fn base() -> Point {
    Point(ExtendedPoint::from_affine(&BASE_X, &BASE_Y))
}

impl Point {
    #[must_use]
    pub fn double(&self) -> Self {
        Self(self.0.double())
    }
    #[must_use]
    pub fn add(&self, rhs: &Self) -> Self {
        Self(self.0.add_cached(&rhs.0.to_cached()).to_extended())
    }
    #[must_use]
    pub fn compress(&self) -> [u8; 66] {
        self.0.compress()
    }
}

#[must_use]
pub fn decompress(bytes: &[u8; 66]) -> bool {
    crate::edwards::decompress(bytes, crate::Mode::Strict).is_ok()
}

#[must_use]
pub fn double_base(a: &[u8], point: &Point, b: &[u8]) -> Point {
    let (a, b) = (Scalar::from_bytes_mod_order(a), Scalar::from_bytes_mod_order(b));
    Point(crate::backend::serial::scalar_mul::double_base_vartime(&a, &point.0, &b))
}

#[must_use]
pub fn challenge(r: &[u8; 66], a: &[u8; 66], m: &[u8]) -> [u8; 66] {
    crate::hash::challenge(r, a, m).to_bytes()
}

/// `[k](−A) + [s]B` through split tables with `N` entries for A and `b_width` for B.
pub struct Split<const N: usize>(crate::backend::serial::scalar_mul::SplitTables<N>);

impl<const N: usize> Split<N> {
    #[must_use]
    pub fn new(point: &Point) -> Self {
        Self(crate::backend::serial::scalar_mul::SplitTables::new(&point.0))
    }
    #[must_use]
    pub fn double_base(&self, a: &[u8], b: &[u8], b_width: usize) -> Point {
        let (a, b) = (Scalar::from_bytes_mod_order(a), Scalar::from_bytes_mod_order(b));
        Point(crate::backend::serial::scalar_mul::double_base_split_vartime(
            &a, &self.0, &b, b_width,
        ))
    }
}

/// AVX2 4-way field operations, for the benches.
#[cfg(all(target_arch = "x86_64", not(ed521_backend = "serial")))]
pub mod avx2 {
    use crate::backend::vector::avx2::field::FieldElement4;

    #[derive(Clone, Copy)]
    pub struct Fe4(FieldElement4);

    #[must_use]
    pub fn available() -> bool {
        crate::backend::avx2()
    }

    #[must_use]
    pub fn fe(x: &super::Fe) -> Fe4 {
        assert!(available());
        #[allow(unsafe_code)]
        // SAFETY: AVX2 is available (asserted).
        unsafe {
            Fe4(FieldElement4::from_serial([&x.0, &x.0, &x.0, &x.0]))
        }
    }

    impl Fe4 {
        #[must_use]
        pub fn mul(&self, rhs: &Self) -> Self {
            #[allow(unsafe_code)]
            // SAFETY: values of this type exist only when AVX2 is available.
            unsafe {
                Self(self.0.mul(&rhs.0))
            }
        }
        #[must_use]
        pub fn square(&self) -> Self {
            #[allow(unsafe_code)]
            // SAFETY: values of this type exist only when AVX2 is available.
            unsafe {
                Self(self.0.square())
            }
        }
    }
}

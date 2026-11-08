//! Python bindings for the `ed521` crate (`ed521rs._native`).
//!
//! Argument order follows `election_audit.ed521.verify(public_key, signature, message)` from
//! election-audit (<https://github.com/tacio/election-audit>).
//! Every verification releases the GIL; `threads` (default 1) bounds the worker threads a single
//! call may use, so a caller that runs one process per core keeps one thread per process.
#![allow(clippy::needless_pass_by_value)] // PyO3 extracts arguments as owned values

use std::borrow::Cow;
use std::hash::{Hash, Hasher};
use std::num::NonZeroUsize;
use std::ops::Deref;
use std::thread;

use ed521::{Error, Mode, PrecomputedVerifyingKey, Signature, VerifyingKey as Key};
use pyo3::buffer::PyBuffer;
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::pybacked::PyBackedBytes;

/// A bytes-like argument, as `election_audit.ed521` accepts: `bytes` is borrowed, anything else
/// with the byte buffer protocol (`bytearray`, `memoryview`, ...) is copied.
struct BytesLike<'a>(Cow<'a, [u8]>);

impl<'a, 'py> FromPyObject<'a, 'py> for BytesLike<'a> {
    type Error = PyErr;

    fn extract(obj: Borrowed<'a, 'py, PyAny>) -> PyResult<Self> {
        if let Ok(bytes) = <&'a [u8]>::extract(obj) {
            return Ok(Self(Cow::Borrowed(bytes)));
        }
        let buffer = PyBuffer::<u8>::get(&obj).map_err(|_| {
            PyTypeError::new_err(format!(
                "expected a bytes-like object, not {}",
                obj.get_type().name().map_or_else(|_| "?".into(), |n| n.to_string())
            ))
        })?;
        Ok(Self(Cow::Owned(buffer.to_vec(obj.py())?)))
    }
}

impl Deref for BytesLike<'_> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

fn parse_mode(mode: &str) -> PyResult<Mode> {
    match mode {
        "strict" => Ok(Mode::Strict),
        "ecpy" => Ok(Mode::EcpyCompat),
        _ => Err(PyValueError::new_err(format!("mode must be 'strict' or 'ecpy', not {mode:?}"))),
    }
}

const fn mode_name(mode: Mode) -> &'static str {
    match mode {
        Mode::EcpyCompat => "ecpy",
        _ => "strict",
    }
}

fn code(result: Result<(), Error>) -> &'static str {
    match result {
        Ok(()) => "ok",
        Err(e) => e.code(),
    }
}

/// Below this many signatures `verify_many` uses the plain key: precomputing costs about one and
/// a half verifications and saves about half of each one after it.
const PRECOMPUTE_THRESHOLD: usize = 4;

/// A key, with or without precomputed tables (boxed: about 9 KiB).
#[allow(clippy::large_enum_variant)] // one per Python key object; the size is irrelevant
enum Verifier {
    Plain(Key),
    Precomputed(Box<PrecomputedVerifyingKey>),
}

impl Verifier {
    fn key(&self) -> &Key {
        match self {
            Self::Plain(key) => key,
            Self::Precomputed(key) => key.verifying_key(),
        }
    }

    fn verify(&self, signature: &[u8], message: &[u8]) -> Result<(), Error> {
        let signature = Signature::from_slice(signature)?;
        match self {
            Self::Plain(key) => key.verify(message, &signature),
            Self::Precomputed(key) => key.verify(message, &signature),
        }
    }

    /// Results for every (signature, message) pair, on up to `threads` threads.
    fn verify_many<'a>(
        &self,
        n: usize,
        item: impl Fn(usize) -> (&'a [u8], &'a [u8]) + Sync,
        threads: NonZeroUsize,
    ) -> Vec<Result<(), Error>> {
        let mut results = vec![Err(Error::InvalidLength); n];
        let mut indices = Vec::with_capacity(n);
        let mut signatures = Vec::with_capacity(n);
        let mut messages = Vec::with_capacity(n);
        for i in 0..n {
            let (signature, message) = item(i);
            if let Ok(signature) = Signature::from_slice(signature) {
                indices.push(i);
                signatures.push(signature);
                messages.push(message);
            }
        }
        let temporary;
        let verifier = match self {
            Self::Plain(key) if signatures.len() >= PRECOMPUTE_THRESHOLD => {
                temporary = Self::Precomputed(Box::new(key.precompute()));
                &temporary
            }
            _ => self,
        };
        let mut found = vec![Ok(()); signatures.len()];
        let run = |messages: &[&[u8]], signatures: &[Signature], out: &mut [Result<(), Error>]| {
            match verifier {
                Self::Plain(key) => key.verify_many(messages, signatures, out),
                Self::Precomputed(key) => key.verify_many(messages, signatures, out),
            }
        };
        let threads = threads.get().min(signatures.len().max(1));
        if threads == 1 {
            run(&messages, &signatures, &mut found);
        } else {
            let chunk = signatures.len().div_ceil(threads);
            thread::scope(|scope| {
                for ((messages, signatures), out) in messages
                    .chunks(chunk)
                    .zip(signatures.chunks(chunk))
                    .zip(found.chunks_mut(chunk))
                {
                    scope.spawn(|| run(messages, signatures, out));
                }
            });
        }
        for (i, result) in indices.into_iter().zip(found) {
            results[i] = result;
        }
        results
    }
}

fn threads_arg(threads: usize) -> PyResult<NonZeroUsize> {
    NonZeroUsize::new(threads).ok_or_else(|| PyValueError::new_err("threads must be at least 1"))
}

/// A decoded Ed521 public key.
#[pyclass(module = "ed521rs", frozen, name = "VerifyingKey")]
struct VerifyingKey {
    verifier: Verifier,
}

#[pymethods]
impl VerifyingKey {
    /// Decode a 66-byte public key; raises `ValueError` (with the reason code) if it is invalid.
    ///
    /// `precompute=True` builds tables (about 9 KiB, the cost of 1.5 verifications) that make
    /// each later `verify` or `reason` call about twice as fast. `verify_many` and friends use
    /// them for four or more signatures anyway.
    #[new]
    #[pyo3(signature = (public_key, *, mode = "strict", precompute = false))]
    fn new(
        py: Python<'_>,
        public_key: BytesLike<'_>,
        mode: &str,
        precompute: bool,
    ) -> PyResult<Self> {
        let mode = parse_mode(mode)?;
        let verifier = py.detach(|| {
            let key = Key::from_slice(&public_key, mode)?;
            Ok::<_, Error>(if precompute {
                Verifier::Precomputed(Box::new(key.precompute()))
            } else {
                Verifier::Plain(key)
            })
        });
        Ok(Self { verifier: verifier.map_err(|e| PyValueError::new_err(e.code()))? })
    }

    /// The 66 bytes the key was decoded from.
    fn to_bytes(&self) -> Vec<u8> {
        self.verifier.key().to_bytes().to_vec()
    }

    /// "strict" or "ecpy".
    #[getter]
    fn mode(&self) -> &'static str {
        mode_name(self.verifier.key().mode())
    }

    /// True when the key holds precomputed tables.
    #[getter]
    fn precomputed(&self) -> bool {
        matches!(self.verifier, Verifier::Precomputed(_))
    }

    /// True when `signature` is a valid signature of `message` under this key.
    fn verify(&self, py: Python<'_>, signature: BytesLike<'_>, message: BytesLike<'_>) -> bool {
        py.detach(|| self.verifier.verify(&signature, &message).is_ok())
    }

    /// "ok", or the reason code the signature fails with.
    fn reason(
        &self,
        py: Python<'_>,
        signature: BytesLike<'_>,
        message: BytesLike<'_>,
    ) -> &'static str {
        py.detach(|| code(self.verifier.verify(&signature, &message)))
    }

    /// Verify each (signature, message) pair; returns one bool per pair.
    #[pyo3(signature = (signatures, messages, *, threads = 1))]
    fn verify_many(
        &self,
        py: Python<'_>,
        signatures: Vec<PyBackedBytes>,
        messages: Vec<PyBackedBytes>,
        threads: usize,
    ) -> PyResult<Vec<bool>> {
        Ok(self.many(py, &signatures, &messages, threads)?.into_iter().map(|r| r.is_ok()).collect())
    }

    /// As `verify_many`, with the reason code of each pair ("ok" for valid signatures).
    #[pyo3(signature = (signatures, messages, *, threads = 1))]
    fn reason_many(
        &self,
        py: Python<'_>,
        signatures: Vec<PyBackedBytes>,
        messages: Vec<PyBackedBytes>,
        threads: usize,
    ) -> PyResult<Vec<&'static str>> {
        Ok(self.many(py, &signatures, &messages, threads)?.into_iter().map(code).collect())
    }

    /// Random-linear-combination batch check of every (signature, message) pair: True when the
    /// batch passes. It is cofactored and probabilistic (a forged batch passes with probability
    /// about 2^-127), and it also passes signatures that are off by a small-order point, which
    /// exact verification rejects. A pre-filter: when it returns False, use `reason_many`.
    #[pyo3(signature = (signatures, messages))]
    fn verify_batch(
        &self,
        py: Python<'_>,
        signatures: Vec<PyBackedBytes>,
        messages: Vec<PyBackedBytes>,
    ) -> PyResult<bool> {
        if signatures.len() != messages.len() {
            return Err(PyValueError::new_err("signatures and messages differ in length"));
        }
        Ok(py.detach(|| {
            let Ok(signatures) =
                signatures.iter().map(|s| Signature::from_slice(s)).collect::<Result<Vec<_>, _>>()
            else {
                return false;
            };
            let messages: Vec<&[u8]> = messages.iter().map(|m| &m[..]).collect();
            match &self.verifier {
                Verifier::Plain(key) => key.verify_batch(&messages, &signatures),
                Verifier::Precomputed(key) => key.verify_batch(&messages, &signatures),
            }
            .is_ok()
        }))
    }

    /// Verify n signatures packed in one buffer (n × 132 bytes) against n messages of
    /// `message_length` bytes packed in another, with no per-item Python objects.
    #[pyo3(signature = (signatures, messages, message_length, *, threads = 1))]
    fn verify_packed(
        &self,
        py: Python<'_>,
        signatures: BytesLike<'_>,
        messages: BytesLike<'_>,
        message_length: usize,
        threads: usize,
    ) -> PyResult<Vec<bool>> {
        let threads = threads_arg(threads)?;
        if !signatures.len().is_multiple_of(ed521::SIGNATURE_LENGTH) {
            return Err(PyValueError::new_err("signatures is not a multiple of 132 bytes"));
        }
        let n = signatures.len() / ed521::SIGNATURE_LENGTH;
        if messages.len() != n * message_length {
            return Err(PyValueError::new_err("messages is not n × message_length bytes"));
        }
        let results = py.detach(|| {
            self.verifier.verify_many(
                n,
                |i| {
                    (
                        &signatures[i * 132..(i + 1) * 132],
                        &messages[i * message_length..(i + 1) * message_length],
                    )
                },
                threads,
            )
        });
        Ok(results.into_iter().map(|r| r.is_ok()).collect())
    }

    /// Keys are equal when decoded from the same bytes in the same mode; precomputation, a
    /// speed-up only, doesn't count.
    fn __eq__(&self, other: PyRef<'_, Self>) -> bool {
        self.verifier.key() == other.verifier.key()
    }

    fn __hash__(&self) -> u64 {
        let mut hasher = std::hash::DefaultHasher::new();
        self.verifier.key().hash(&mut hasher);
        hasher.finish()
    }

    fn __repr__(&self) -> String {
        let key = self.verifier.key();
        let hex: String = key.to_bytes().iter().take(8).map(|b| format!("{b:02x}")).collect();
        format!(
            "VerifyingKey({hex}…, mode={:?}, precompute={})",
            mode_name(key.mode()),
            if self.precomputed() { "True" } else { "False" }
        )
    }
}

impl VerifyingKey {
    fn many(
        &self,
        py: Python<'_>,
        signatures: &[PyBackedBytes],
        messages: &[PyBackedBytes],
        threads: usize,
    ) -> PyResult<Vec<Result<(), Error>>> {
        if signatures.len() != messages.len() {
            return Err(PyValueError::new_err("signatures and messages differ in length"));
        }
        let threads = threads_arg(threads)?;
        Ok(py.detach(|| {
            self.verifier.verify_many(
                signatures.len(),
                |i| (&signatures[i][..], &messages[i][..]),
                threads,
            )
        }))
    }
}

/// True when `signature` (132 bytes) is a valid Ed521 signature of `message` under
/// `public_key` (66 bytes).
#[pyfunction]
#[pyo3(signature = (public_key, signature, message, *, mode = "strict"))]
fn verify(
    py: Python<'_>,
    public_key: BytesLike<'_>,
    signature: BytesLike<'_>,
    message: BytesLike<'_>,
    mode: &str,
) -> PyResult<bool> {
    let mode = parse_mode(mode)?;
    Ok(py.detach(|| ed521::verify(&public_key, &signature, &message, mode).is_ok()))
}

/// "ok", or the reason code verification fails with (for example `"s_out_of_range"`).
#[pyfunction]
#[pyo3(signature = (public_key, signature, message, *, mode = "strict"))]
fn reason(
    py: Python<'_>,
    public_key: BytesLike<'_>,
    signature: BytesLike<'_>,
    message: BytesLike<'_>,
    mode: &str,
) -> PyResult<&'static str> {
    let mode = parse_mode(mode)?;
    Ok(py.detach(|| code(ed521::verify(&public_key, &signature, &message, mode))))
}

/// Random-linear-combination batch check of `(public_key, signature, message)` triples under any
/// mix of keys; see `VerifyingKey.verify_batch`. Invalid keys or lengths make it False.
#[pyfunction]
#[pyo3(signature = (items, *, mode = "strict"))]
fn verify_batch(
    py: Python<'_>,
    items: Vec<(PyBackedBytes, PyBackedBytes, PyBackedBytes)>,
    mode: &str,
) -> PyResult<bool> {
    let mode = parse_mode(mode)?;
    Ok(py.detach(|| {
        let mut decoded = Vec::with_capacity(items.len());
        for (key, signature, message) in &items {
            let (Ok(key), Ok(signature)) =
                (Key::from_slice(key, mode), Signature::from_slice(signature))
            else {
                return false;
            };
            decoded.push((key, &message[..], signature));
        }
        let refs: Vec<_> = decoded.iter().map(|(k, m, s)| (k, *m, s)).collect();
        ed521::verify_batch(&refs).is_ok()
    }))
}

/// The arithmetic backend this process uses ("serial" or "avx2").
#[pyfunction]
fn backend() -> &'static str {
    ed521::backend_name()
}

/// The `ed521rs._native` extension module.
#[pymodule(gil_used = false)]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<VerifyingKey>()?;
    m.add_function(wrap_pyfunction!(verify, m)?)?;
    m.add_function(wrap_pyfunction!(reason, m)?)?;
    m.add_function(wrap_pyfunction!(verify_batch, m)?)?;
    m.add_function(wrap_pyfunction!(backend, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add("PUBLIC_KEY_LENGTH", ed521::PUBLIC_KEY_LENGTH)?;
    m.add("SIGNATURE_LENGTH", ed521::SIGNATURE_LENGTH)?;
    Ok(())
}

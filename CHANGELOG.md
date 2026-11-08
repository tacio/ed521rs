# Changelog

All notable changes are recorded here. The project follows [Semantic Versioning]; the Rust crate
`ed521` and the Python package `ed521rs` share version numbers.

## [Unreleased]

## [0.1.1]

### Rust (`ed521`)

- `VerifyingKey` implements `PartialEq`, `Eq` and `Hash`: keys are equal when decoded from the
  same 66 bytes in the same mode, so a `HashMap` can cache one `PrecomputedVerifyingKey` per key.

### Python (`ed521rs`)

- `VerifyingKey` supports `==` and `hash()` on the same terms. A precomputed key equals the
  plain key with the same bytes and mode, so a dict can cache one precomputed key per urn key.
- The type stubs now accept `bytearray` elements in the lists passed to `verify_many`,
  `reason_many` and both `verify_batch` functions, as the extension always has.

## [0.1.0]

First release.

### Rust (`ed521`)

- Exact Ed521 verification in two modes: `Mode::Strict` (RFC 8032 decoding) and
  `Mode::EcpyCompat` (the verdicts of TSE's reference verifier, ECPy at commit `8143d9ac`).
- Stable reason codes for every rejection (`Error::code`).
- `PrecomputedVerifyingKey` (9 KiB of tables per key, about twice as fast per verification).
- `verify_many`, with shared field inversions and, on x86-64 CPUs with AVX2, four signatures at
  once.
- `verify_batch` (feature `batch`): a cofactored random-linear-combination pre-filter.
- `no_std` and allocation-free single verification; MSRV 1.87.

### Python (`ed521rs`)

- `verify`, `reason`, `verify_batch`, `backend`, and `VerifyingKey` with `verify_many`,
  `reason_many`, `verify_batch` and the zero-copy `verify_packed`.
- The GIL is released during verification; `threads` bounds the threads a call may use.
- abi3 wheels for CPython 3.11 and later (one wheel per platform).

[Semantic Versioning]: https://semver.org/spec/v2.0.0.html
[Unreleased]: https://github.com/tacio/ed521rs/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/tacio/ed521rs/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/tacio/ed521rs/releases/tag/v0.1.0

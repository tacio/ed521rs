# ed521

[![crates.io](https://img.shields.io/crates/v/ed521.svg)](https://crates.io/crates/ed521)
[![docs.rs](https://img.shields.io/docsrs/ed521)](https://docs.rs/ed521)
[![CI](https://github.com/tacio/ed521rs/actions/workflows/ci.yml/badge.svg)](https://github.com/tacio/ed521rs/actions/workflows/ci.yml)
![MSRV 1.87](https://img.shields.io/badge/MSRV-1.87-blue)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/tacio/ed521rs/blob/main/LICENSE)

Fast verification of **Ed521** signatures: EdDSA over the Edwards curve E-521, as specified by
ICP-Brasil ([DOC-ICP-01.01]) and used by the Brazilian Superior Electoral Court (TSE) in its
UE2020 and UE2022 voting machines. `no_std`, no heap allocation for single verification, and
about 35 times faster than the pure-Python verifiers it was checked against.

> **⚠ This code has not been independently audited.** It is checked against TSE's own reference
> verifier, real TSE signatures, crafted edge cases and differential fuzzing, but no third party
> has reviewed it. Verification is variable time, which is fine for public keys, signatures and
> messages; the crate has no production signing. Read [SECURITY.md] before relying on it.

```rust
use ed521::{Signature, VerifyingKey};

// The Ed521 test vector published with ECPy, the library TSE's reference verifier uses.
let public_key: [u8; 66] = hex::decode(
    "fb00870ccbf9c3db7790f76ca2470c41373f4ccced7ae646bad040274d717f7f44e6d37537dede5bbdae7410b3\
     2e7b67521b0f3cac077548d100612a0e8b65d66c00",
)?
.try_into()
.unwrap();
let signature: [u8; 132] = hex::decode(
    "c2fb4f7d03dd31f25753b9972aeb650ac3632eef945e7f94e426a865bb95e66241149c7eed24d98fed2ee8b9ef\
     949b83ba556d045b72df6e6b8b9026414b26463d0088d2ed5ea88fcc6b2f343d308209dacd5fadadac352d497d\
     2049831eca3536e7be5a7faef56d6c6786c60415e0febee8a45f9971ae4872e0b6cf09cc0a9407342000",
)?
.try_into()
.unwrap();

let key = VerifyingKey::from_bytes(&public_key)?;
key.verify(b"Message for Ed521 signing", &Signature::from_bytes(&signature))?;

// A key that verifies many signatures: about twice as fast per signature.
let key = key.precompute();
key.verify(b"Message for Ed521 signing", &Signature::from_bytes(&signature))?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

TSE's urns sign `SHA-512(h)`, where `h` is the SHA-512 hash of a file; that hashing is the
caller's job, and this crate verifies any message.

## What it offers

- **Exact verification** of the cofactorless equation `[S]B = R + [k]A`, in two modes:
  `Mode::Strict` (RFC 8032 decoding rules, the default) and `Mode::EcpyCompat`, which accepts
  exactly what TSE's reference verifier (ECPy at commit `8143d9ac`) accepts, quirks included.
  Every error has a stable reason code (`Error::code`) for audit reports.
- **`PrecomputedVerifyingKey`**: 9 KiB of tables per key, which halves the cost of each later
  verification.
- **`verify_many`**: many signatures under one key, sharing field inversions; on x86-64 CPUs with
  AVX2 (detected at run time) it verifies four signatures at once in the vector lanes.
- **`verify_batch`** (feature `batch`): a probabilistic random-linear-combination check of many
  signatures, about 4.6 times faster than verifying each. It is cofactored, so it is a
  pre-filter, never a per-signature verdict.

On an Intel i7-9750H, one verification takes 269 µs, 136 µs with a precomputed key, and 92 µs
per signature in `verify_many` with AVX2. See [BENCHMARKS.md] for the full tables.

## Cargo features

| Feature | Default | |
|---|---|---|
| `std` | yes | Links `std`; implies `alloc`. Nothing else depends on it yet. |
| `alloc` | via `std` | Needed by `batch`. |
| `batch` | no | `verify_batch` and `VerifyingKey::verify_batch`. |

Without default features the crate is `no_std` and allocation-free. Setting
`RUSTFLAGS='--cfg ed521_backend="serial"'` disables the AVX2 code; results never depend on the
backend.

## Python

The same code is available to Python as [`ed521rs`](https://pypi.org/project/ed521rs/)
(`pip install ed521rs`), with the GIL released and optional multithreading.

## License

MIT. See the [repository](https://github.com/tacio/ed521rs) for the test vectors' provenance,
the semantics of each mode in detail, and the development setup.

[DOC-ICP-01.01]: https://www.gov.br/iti/pt-br/assuntos/legislacao/documentos-principais/IN2022_22_DOCICP01.01_compilada.pdf
[SECURITY.md]: https://github.com/tacio/ed521rs/blob/main/SECURITY.md
[BENCHMARKS.md]: https://github.com/tacio/ed521rs/blob/main/BENCHMARKS.md

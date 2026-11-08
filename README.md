<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/tacio/ed521rs/main/docs/assets/banner-dark.svg">
  <img alt="ed521rs: fast Ed521 signature verification in Rust and Python" src="https://raw.githubusercontent.com/tacio/ed521rs/main/docs/assets/banner-light.svg" width="100%">
</picture>

[![CI](https://github.com/tacio/ed521rs/actions/workflows/ci.yml/badge.svg)](https://github.com/tacio/ed521rs/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/ed521rs.svg)](https://pypi.org/project/ed521rs/)
[![Python](https://img.shields.io/pypi/pyversions/ed521rs.svg)](https://pypi.org/project/ed521rs/)
[![crates.io](https://img.shields.io/crates/v/ed521.svg)](https://crates.io/crates/ed521)
[![MSRV](https://img.shields.io/crates/msrv/ed521.svg)](https://crates.io/crates/ed521)
[![docs.rs](https://img.shields.io/docsrs/ed521)](https://docs.rs/ed521)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/tacio/ed521rs/badge)](https://scorecard.dev/viewer/?uri=github.com/tacio/ed521rs)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/16442/badge)](https://www.bestpractices.dev/projects/16442)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/tacio/ed521rs/blob/main/LICENSE)

Fast verification of **Ed521** signatures (EdDSA over the Edwards curve E-521, specified by
ICP-Brasil in [DOC-ICP-01.01]) in Rust, with Python bindings. Ed521 is the signature scheme of
the UE2020 and UE2022 voting machines of Brazil's Superior Electoral Court (TSE): every file an
urn publishes is signed with it.

Before this project, every available Ed521 verifier was a generic big-integer implementation. A
national audit needs about nine million verifications per election; ed521rs takes them from
about 25 CPU-hours in pure Python to about 18 CPU-minutes.

> **⚠ This code has not been independently audited.** It is checked against TSE's own reference
> verifier, real signatures published by TSE, 34 crafted edge cases and differential fuzzing, but
> no third party has reviewed it. Read [SECURITY.md] before relying on it.

| | Install | Docs |
|---|---|---|
| Python | `pip install ed521rs` (CPython 3.11+, wheels for Linux, macOS and Windows) | this page |
| Rust | `cargo add ed521` (`no_std`, MSRV 1.87) | [docs.rs/ed521](https://docs.rs/ed521) |

## Python

```python
import hashlib
import ed521rs

# TSE's urns sign SHA-512(h), where h is the SHA-512 hash of the file.
ok = ed521rs.verify(public_key, signature, hashlib.sha512(listed_hash).digest())
ed521rs.reason(public_key, signature, message)           # "ok" or a reason code

key = ed521rs.VerifyingKey(public_key)                   # decode once per key
results = key.verify_many(signatures, messages)          # exact, one bool per signature
reasons = key.reason_many(signatures, messages)          # exact, one reason code each
ca = ed521rs.VerifyingKey(ca_key, precompute=True)       # about 2x faster per call, for busy keys

# Pre-filter only: one bool for the whole batch (cofactored, probabilistic).
if not key.verify_batch(signatures, messages):
    reasons = key.reason_many(signatures, messages)
```

- **Same verdicts everywhere.** Every exact entry point (`verify`, `reason`, `verify_many`,
  `reason_many`, `verify_packed`, with or without `precompute`) returns the same verdict for the
  same input.
- **Automatic speedups.** `verify_many` and friends precompute on their own from four signatures
  and share field inversions.
- **Threads and the GIL.**
  - Every call releases the GIL.
  - `threads` (default 1) caps the threads one call may use.
- **Input types.** Arguments accept `bytes`, `bytearray`, `memoryview` or any other buffer.
- **Reason codes.** They are stable strings (`non_canonical_r`, `s_out_of_range`,
  `invalid_signature`, ...), suitable for audit status columns.
- **Audit metadata.** `ed521rs.__version__` and `ed521rs.backend()` (`"avx2"` or `"serial"`)
  identify the build for audit manifests.

[docs/election-audit.md](https://github.com/tacio/ed521rs/blob/main/docs/election-audit.md) has
notes on adopting ed521rs in [election-audit], including a parity gate before switching.

## Rust

```rust
use ed521::{Mode, Signature, VerifyingKey};

let key = VerifyingKey::from_bytes_with_mode(&public_key, Mode::Strict)?;
key.verify(message, &Signature::from_bytes(&signature))?;
```

See the [crate documentation](https://docs.rs/ed521) and its
[README](https://github.com/tacio/ed521rs/blob/main/crates/ed521/README.md).

## Semantics

Verification checks the cofactorless equation `[S]B = R + [k]A` with
`k = SHAKE256("SigEd521" 00 00 || R || A || M, 132) mod L`. Two modes decide which encodings are
accepted; they differ only on inputs an honest signer never produces.

| | `mode="strict"` (default) | `mode="ecpy"` |
|---|---|---|
| matches | RFC 8032 decoding; the pure-Python verifier of [election-audit] | ECPy at commit [`8143d9ac`][ecpy], pinned by TSE's reference verifier |
| y of R and A | below p | any 527-bit value, taken mod p |
| x = 0 with the sign bit | rejected | accepted |
| S | below L | any 528-bit value, taken mod L, except S = 0 mod L |
| small-order A ([4]A = O) | the equation, as for any key | `[S]B = R`, R canonical |

The last two `ecpy` rules reproduce ECPy's arithmetic rather than the equation. ECPy maps
`S = 0 mod L` to its point at infinity, which never equals a curve point. Its ladder uses the
dedicated (non-unified) addition, which collapses `[k]A` to that point whenever A has order 1, 2
or 4. The edge-case vectors pin every rule against both ECPy and the pure-Python reference.

Running both modes and flagging any signature where they differ is a cheap audit check: on real
data they should never differ.

`verify_batch` checks `[4](Σ z_i (R_i + [k_i]A_i − [S_i]B)) = O`, for 128-bit coefficients drawn
from SHAKE256 over all the inputs.
- It is cofactored, so it also accepts signatures off by a point of order 2 or 4. Exact
  verification rejects those, and an honest signer never makes one.
- A batch containing a forgery passes with probability about 2^-127.
- It is a pre-filter, never a verdict.

## Performance

One thread of an Intel i7-9750H (Coffee Lake, AVX2), in µs per signature:

| | Rust | Python |
|---|---:|---:|
| pure-Python reference ([election-audit]) | | 9 818 |
| `verify` | 269 | 314 |
| `verify` with a precomputed key | 136 | 153 |
| urn section (decode the key, then `verify_many` on 12 signatures) | 112 | 123 |
| `verify_many` on 64 signatures, precomputed key, AVX2 | 92 | |
| `verify_batch` on 12 signatures (pre-filter) | 59 | 67 |

[BENCHMARKS.md] has the full tables and the measurements behind each design choice.

## Backends

On CPUs with AVX2 (detected at run time), `verify_many` and its variants run four signatures'
scalar multiplications at once, one in each 64-bit lane.
- Single and batch verification use the portable serial backend everywhere: the vector code
  measured no real gain there.
- Results never depend on the backend.
- `RUSTFLAGS='--cfg ed521_backend="serial"'` forces the serial backend at build time.

## Test vectors and their provenance

The vectors live in [`crates/ed521/tests/vectors/`][vectors], so the published crate carries its
own tests. Each one records where it came from.

- **`tse-2026.json`: 18 real signatures from TSE's 2026 election (round 2, Acre).**
  - Urn signatures on one section's files and on its vote-hash chain.
  - The AC UE2020 and AC UE2022 signatures on urn certificates and on their revocation lists.
  - Each source file is pinned by its official TSE URL and SHA-256.
  - [`scripts/tse_vectors.py`][tse-script] rebuilds the file from TSE's originals:
    - `just tse-fetch` downloads the urn files from TSE's results site. TSE's other servers turn
      away scripts, so it prints the browser links for the format package and the revocation
      lists, then checks their hashes.
    - `just tse-vectors` decodes the sources with TSE's own ASN.1 specifications and requires
      the result to equal the committed file.
- **`ecpy.json`: the two Ed521 vectors published in [ECPy][ecpy].**
  - ECPy is the library TSE's reference verifier uses.
  - One of them pins the key expansion that the test-only signer reproduces.
- **`edge-cases.json`: 34 crafted cases with each mode's verdict, taken from running the
  oracles themselves.**
  - The cases cover non-canonical encodings, S at and above L, and small-order points.
  - The oracles are ECPy at TSE's pinned commit and the pure-Python reference.

`tests/python/reference_ed521.py` is a verbatim, hash-checked copy of
`election_audit/ed521.py` from [election-audit]. The Python suite checks ed521rs against it, and
against ECPy, on random signatures and mutations of them. `just fuzz` runs three cargo-fuzz
targets against an independent big-integer model.

## Development

Development needs [just], [uv] and a Rust toolchain; MSRV checks also need Rust 1.87, and
fuzzing needs nightly.

```sh
just setup      # .venv with maturin, ruff, ty, asn1tools and the ECPy oracle
just check      # format, clippy, Rust tests (both backends, no_std, MSRV), vectors, Python tests
just bench      # criterion; `python scripts/bench.py` times the Python entry points
just fuzz 600   # differential fuzzing, 10 minutes per target
```

Bug reports and feature requests go to the [issue tracker]; report security problems,
including any wrong verdict, privately as described in [SECURITY.md]. [CONTRIBUTING.md]
explains the development setup and what a change needs before it can be merged.

[CHANGELOG.md] lists the changes in each release, and [RELEASING.md] describes how releases are
published.

## License

[MIT][license].

[DOC-ICP-01.01]: https://www.gov.br/iti/pt-br/assuntos/legislacao/documentos-principais/IN2022_22_DOCICP01.01_compilada.pdf
[election-audit]: https://github.com/tacio/election-audit
[ecpy]: https://github.com/cslashm/ECPy/tree/8143d9ac017de0cb7f980bedaf56cefe6b4d9180
[vectors]: https://github.com/tacio/ed521rs/tree/main/crates/ed521/tests/vectors
[tse-script]: https://github.com/tacio/ed521rs/blob/main/scripts/tse_vectors.py
[SECURITY.md]: https://github.com/tacio/ed521rs/blob/main/SECURITY.md
[BENCHMARKS.md]: https://github.com/tacio/ed521rs/blob/main/BENCHMARKS.md
[CHANGELOG.md]: https://github.com/tacio/ed521rs/blob/main/CHANGELOG.md
[CONTRIBUTING.md]: https://github.com/tacio/ed521rs/blob/main/CONTRIBUTING.md
[issue tracker]: https://github.com/tacio/ed521rs/issues
[RELEASING.md]: https://github.com/tacio/ed521rs/blob/main/RELEASING.md
[license]: https://github.com/tacio/ed521rs/blob/main/LICENSE
[just]: https://github.com/casey/just
[uv]: https://docs.astral.sh/uv/

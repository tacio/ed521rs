# Benchmarks

Intel Core i7-9750H (Coffee Lake, AVX2, no AVX-512), Linux 6.8, rustc 1.99.1, Python 3.14.5,
one thread unless stated otherwise. All runs were on an otherwise idle machine (load ≈ 1) on
2026-11-06; numbers taken while other jobs share the cores' hyperthreads swing by up to 2×.

Reproduce with `just bench` (criterion), the same with
`RUSTFLAGS='--cfg ed521_backend="serial"' CARGO_TARGET_DIR=target/serial` for the serial
column, and `python scripts/bench.py --seconds 3` (Python entry points on the real urn
signatures in `crates/ed521/tests/vectors/tse-2026.json`).

## Python, against the pure-Python reference

| | µs per signature | vs reference |
|---|---:|---:|
| [election-audit](https://github.com/tacio/election-audit)'s `ed521.py` verify (reference) | 9 818 | 1× |
| `ed521rs.verify` (decodes the key each call) | 314 | 31× |
| `VerifyingKey(key).verify` | 294 | 33× |
| `VerifyingKey(key, precompute=True).verify` | 153 | 64× |
| urn group: `VerifyingKey(key).verify_many(12 signatures)` | 123 | 80× |
| urn group: `VerifyingKey(key).verify_batch(12)` (pre-filter only) | 67 | 147× |
| `verify_packed(1024)` | 105 | 93× |
| `verify_packed(1024, threads=4)` | 30 | 331× |

Key decoding costs 19 µs; `precompute=True` costs 231 µs, about 1.5 verifications.

For the national pass (about 9M signatures in urn groups) that is about 18 CPU-minutes exact,
against about 25 CPU-hours for the reference.

## Rust (criterion), serial and AVX2 builds

Medians. The AVX2 build uses its lanes only in `verify_many`; everything else runs the serial
code in both builds, so those rows differ only by noise.

| | serial | AVX2 build | |
|---|---:|---:|---:|
| field mul | 50.2 ns | | fiat-crypto p521: 59.2 ns |
| field square | 29.9 ns | | fiat-crypto p521: 38.7 ns |
| field mul, 4 lanes | | 120.7 ns | 30.2 ns per element |
| field square, 4 lanes | | 63.1 ns | 15.8 ns per element |
| field invert | 15.6 µs | | |
| point decompress | 17.1 µs | | |
| SHAKE256 challenge (64-byte message) | 1.03 µs | | |
| decode key | 17.0 µs | | |
| verify | 269 µs | 264 µs | |
| precompute key tables | 191 µs | 190 µs | |
| verify, precomputed key | 136 µs | 138 µs | |
| `verify_many` 64 signatures, per signature | 245 µs | **159 µs** | 1.54× |
| `verify_many` 64, precomputed key, per signature | 122 µs | **92 µs** | 1.33× |
| urn group (decode + precompute + `verify_many` 12), per signature | 141 µs | **112 µs** | 1.26× |
| urn group `verify_batch` 12, per signature | 58.6 µs | 59.1 µs | |
| urn group `verify_batch` 12, precomputed key, per signature | 46.9 µs | 46.7 µs | |

The design targets were met: single verify 269 µs (target ≤ 300) and precomputed verify 136 µs
(target ≤ 160). The batch target was at least 3× over individual verification for a 12-signature
urn group. The batch reaches 4.6× over single verify (269 → 58.6 µs) and 2.4× over the exact
grouped path.

### Split tables

Width choices for the precomputed key (A tables, B tables), `double_base_split`:

| A width / B width | 6 | 7 | 8 |
|---|---:|---:|---:|
| 5 (8 entries, 9 KiB per key) | 122.6 µs | 119.6 µs | **117.0 µs** |
| 6 (16 entries, 18 KiB per key) | 118.0 µs | 115.7 µs | 113.0 µs |

The precomputed key uses A width 5 and B width 8. Width 6 for A is 3% faster but doubles the
key's memory and adds about 30 µs to precomputation, which a 12-signature urn group doesn't win
back.

## The AVX2 gate

The plan kept AVX2 only where it beats serial by at least 1.3×.

1. **Horizontal layout** (one point per vector, X, Y, Z, T in the four lanes; dalek's approach):
   - Point doubling took 289 ns, against 270 ns for a serial projective doubling step, and an
     addition took 456 ns against 610 ns.
   - `double_base` gained only 1.12× (214 vs 240 µs). The lane shuffles, blends and carries cost
     what the 4-way products save, and a = 1 needs five products per addition (one more than a
     vector holds).
   - **Rejected.**
2. **Vertical layout** (lane j belongs to signature j; regular signed-odd digits so that all
   lanes add at the same positions):
   - 1.54× on `verify_many`, 1.33× on `verify_many` with a precomputed key, and 1.26× on a whole
     urn group, which includes the serial key decode and precomputation.
   - **Kept** for `verify_many` and its variants (`reason_many`, `verify_packed`).
3. **Not vectorized:**
   - Single verify (only one scalar multiplication to run).
   - `verify_batch`: it is add-bound. Lanes do each addition about 1.5× faster, but regular
     digits need about 1.5× more additions than wNAF, and four doubling chains cost about 2.5
     serial ones.
   - Both stay serial.

The first 4-way multiply was no faster than serial (210 ns for four), because LLVM kept the
triangular product loops rolled. The kernels are therefore generated unrolled
(`scripts/gen_avx2_kernels.py`), which brought the multiply to 121 ns. It still spills: 54
vectors of inputs against 16 registers.

# Contributing

Thanks for your interest in ed521rs. Bug reports, test vectors and fixes are welcome.

**Security issues** (including any wrong verdict) go through
[private vulnerability reporting](https://github.com/tacio/ed521rs/security/advisories/new), not
public issues; see [SECURITY.md](SECURITY.md).

## Setup

You need a stable Rust toolchain, [uv](https://docs.astral.sh/uv/) and
[just](https://github.com/casey/just).

```sh
just setup      # .venv with maturin, ruff, ty and the ECPy oracle
just hooks      # run `just lint` before every push, as CI does
just check      # everything CI runs: lint, tests, no_std, MSRV, vectors, Python suite
```

Individual recipes (`just --list` shows them all):

| Recipe | What it does |
|---|---|
| `just fmt` / `just lint` | rustfmt, clippy, ruff and the ty type checker |
| `just test` | Rust tests on the default and serial backends, and `no_std` |
| `just py-test` | build the extension into `.venv` and run the Python suite |
| `just vectors` | regenerate tables, AVX2 kernels and edge cases; fail if anything changed |
| `just fuzz 600` | differential fuzzing against the big-integer model (nightly, `cargo-fuzz`) |
| `just bench` | Criterion benchmarks (see [BENCHMARKS.md](BENCHMARKS.md)) |

## Ground rules

- **Verdicts are the contract.** Any change that could alter whether a signature is accepted
  needs a test vector that shows it, and must keep agreement with TSE's reference verifier in
  `Mode::EcpyCompat`.
- **Generated code is generated.** Don't edit the field tables or AVX2 kernels by hand. Change
  `scripts/gen_tables.py` or `scripts/gen_avx2_kernels.py` and regenerate.
- **Python is fully annotated.** ruff requires annotations on every function in `scripts/`
  and `tests/python/`, and ty must pass (`just lint`). The vendored `reference_ed521.py` is
  the one exception: it is a hash-pinned copy and stays verbatim.
- **No new `unsafe`** outside the AVX2 dispatch. Each `unsafe` block carries a `SAFETY` comment.
- **Performance claims come with numbers.** Include before/after `just bench` output for the
  affected benchmarks.
- Record user-visible changes under `[Unreleased]` in [CHANGELOG.md](CHANGELOG.md).

## Pull requests

Keep each PR to one topic, run `just check` before pushing, and describe what changed and why.
Contributions are licensed under the [MIT License](LICENSE).

# Using ed521rs in election-audit

Notes for switching [election-audit]'s Ed521 checks from its pure-Python verifier
(`election_audit/ed521.py`) to ed521rs. That switch is made in election-audit itself; nothing
here changes it.

## Dependency

```toml
[project.optional-dependencies]
verification = [..., "ed521rs>=0.1,<0.2"]
```

The wheels are abi3 for CPython 3.11 and later. To work against an unreleased checkout instead,
point uv at it:

```toml
[tool.uv.sources]
ed521rs = { path = "../ed521rs" }
```

Record `ed521rs.__version__` and `ed521rs.backend()` (`"avx2"` or `"serial"`) in the run
manifest next to the verification mode. Results never depend on the backend.

## Call sites

| Where | Today | With ed521rs |
|---|---|---|
| `integrity_checks.py` (urn files and self-signatures) | `ed521.verify(key, sig, sha512(h))` | `ed521rs.verify(key, sig, sha512(h))`, same argument order |
| `urn_pki.py` (CA signatures on certificates and revocation lists) | `ed521.verify(key, sig, tbs)` | the same, or a module-level `VerifyingKey(ca_key, precompute=True)` per CA |

For a national pass, verify each section with one key object:

```python
key = ed521rs.VerifyingKey(urn_public_key)               # decode once per urn
reasons = key.reason_many(signatures, messages)          # exact: "ok" or a reason code
```

`reason_many` does several things on its own:

- it precomputes key tables once it has four signatures;
- it shares field inversions across signatures;
- it runs four signatures at a time on AVX2;
- it keeps one thread per process (`threads=1` by default).

The reason codes (`non_canonical_r`, `s_out_of_range`, `invalid_signature`, ...) can go straight
into status columns.

## Modes

- `mode="strict"` (the default) gives exactly `election_audit.ed521.verify`'s verdicts.
- `mode="ecpy"` gives the verdicts of TSE's reference verifier (ECPy `8143d9ac`), quirks
  included (README, "Semantics").
- Running both modes and flagging any signature where they differ is a cheap audit check. On
  real data they should never differ.

`verify_batch` is a cofactored, probabilistic pre-filter. Never record its result as a
per-signature verdict.

## Parity gate before switching

1. Keep `election_audit.ed521` as the oracle for one round. On the national sample, run both and
   require identical verdicts. This repository's Python suite already does that on random
   cases, the TSE vectors and the crafted edge cases.
2. Compare the run's status table with the pure-Python run's, row for row.
3. Then drop the pure-Python path from the hot loop, keeping it for the tests.

## Throughput to plan with

These figures come from one thread of an i7-9750H on an idle machine ([BENCHMARKS.md](../BENCHMARKS.md)).

| Workload | ed521rs | pure-Python reference |
|---|---|---|
| Urn section (key + 12 signatures, exact, from Python), per signature | 123 µs on AVX2, about 145 µs on the serial backend | 9.8 ms |
| About 9 million signatures | about 18 CPU-minutes (about 2 per million) | about 25 CPU-hours |

[election-audit]: https://github.com/tacio/election-audit

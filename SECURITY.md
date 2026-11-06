# Security

## Status

**ed521rs has not been independently audited.** It was written for an election audit and is
checked as follows:

- against TSE's own reference verifier (ECPy at the commit TSE pins) and an independent
  pure-Python implementation, on real TSE signatures, published vectors, 34 crafted edge cases
  and thousands of random signatures and mutations;
- by differential fuzzing of decoding, verification and batch verification against a separate
  big-integer model (`fuzz/`);
- by property tests of the field and scalar arithmetic against `num-bigint` and the formally
  verified `fiat-crypto` P-521 field.

None of this replaces a review by someone else. Treat the code accordingly, and keep an
independent check (such as the pure-Python reference) wherever a wrong verdict would matter.

## Scope and threat model

- **Verification only.** Every input (public keys, signatures, messages) is assumed public.
  Verification is variable time by design, so it must not be used where timing would reveal
  something secret.
- **No production signing.** The crate's hidden `__hazmat-sign` feature signs in variable time with an
  unprotected key and exists only to generate test vectors. Never use it with a key that matters.
- **`verify_batch` is a pre-filter.** It is cofactored and probabilistic: a batch containing a
  forgery passes with probability about 2^-127, and it accepts signatures off by a small-order
  point that exact verification rejects. Record per-signature verdicts only from the exact entry
  points.
- **`unsafe` code** is limited to calling the AVX2 functions after run-time CPU detection; each
  call site carries a `SAFETY` comment.

## Reporting a vulnerability

Please report suspected vulnerabilities privately, through GitHub's
[private vulnerability reporting](https://github.com/tacio/ed521rs/security/advisories/new),
rather than in a public issue. A wrong verdict (a valid signature rejected, an invalid one
accepted, or a disagreement with TSE's reference verifier) counts as a vulnerability.

Reports are acknowledged within a week. Fixes are released as soon as they are ready, together
with an advisory that credits the reporter unless they prefer otherwise.

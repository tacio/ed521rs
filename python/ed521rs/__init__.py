"""Fast Ed521 (EdDSA over E-521, ICP-Brasil DOC-ICP-01.01) signature verification.

``verify(public_key, signature, message)`` takes its arguments in the same order as
``election_audit.ed521.verify`` (https://github.com/tacio/election-audit). TSE's urns sign
``SHA-512(h)``, where ``h`` is the SHA-512 hash of a file; pass that double hash as the message.

``mode="strict"`` (the default) applies RFC 8032 decoding rules. ``mode="ecpy"`` also accepts
the non-canonical encodings that ECPy, TSE's reference verifier, accepts (y >= p, x = 0 with the
sign bit set, S >= L) and reproduces its two quirks: it rejects S = 0 mod L, and for a
small-order key it requires R = [S]B with R canonical.

For many signatures under one key, use ``VerifyingKey``. ``precompute=True`` makes each call
about twice as fast, and ``verify_many``, ``reason_many`` and ``verify_packed`` precompute on
their own and share field inversions. Every method returns exactly what ``verify`` would.

``verify_batch`` (and ``VerifyingKey.verify_batch``) is different: one random-linear-combination
check of many signatures, about 2-3 times faster again, returning a single bool. It checks the
cofactored equation and is probabilistic, so it is a pre-filter, never a verdict: on False, find
the bad signatures with ``reason_many``.

This code has not been independently audited; see
https://github.com/tacio/ed521rs/blob/main/SECURITY.md.
"""

from ed521rs._native import (
    PUBLIC_KEY_LENGTH,
    SIGNATURE_LENGTH,
    VerifyingKey,
    __version__,
    backend,
    reason,
    verify,
    verify_batch,
)

__all__ = [
    "PUBLIC_KEY_LENGTH",
    "SIGNATURE_LENGTH",
    "VerifyingKey",
    "__version__",
    "backend",
    "reason",
    "verify",
    "verify_batch",
]

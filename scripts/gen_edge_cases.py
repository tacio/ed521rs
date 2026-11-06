"""Write the crafted edge cases, with each mode's verdict, to crates/ed521/tests/vectors/edge-cases.json.

Expected values come from running the oracles, never from this script's own logic:

- ``strict``: the vendored pure-Python reference (``tests/python/reference_ed521.py``, the same
  rules as election_audit/ed521.py in https://github.com/tacio/election-audit and RFC 8032);
- ``ecpy``: ECPy at TSE's pinned commit, as TSE's verifier calls it (any exception = invalid);
- ``cofactored``: [4][S]B == [4](R + [k]A) under strict decoding (``null`` when strict decoding
  fails), the equation ``verify_batch`` checks.

``reason`` is the ed521rs strict-mode reason code; the script checks it is "ok" exactly when the
reference accepts. Run with the project environment, where ECPy is installed (``oracle`` group):

    .venv/bin/python -I scripts/gen_edge_cases.py [--check]
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "crates/ed521/tests/vectors/edge-cases.json"
ECPY_COMMIT = "8143d9ac017de0cb7f980bedaf56cefe6b4d9180"
sys.path.insert(0, str(ROOT / "tests/python"))

import reference_ed521 as ref  # noqa: E402

P, L, D = ref.P, ref.L, ref.D
IDENTITY = ref._IDENTITY
ORDER_2 = (0, P - 1, 1, 0)  # (0, -1)
ORDER_4 = (1, 0, 1, 0)  # (1, 0), x odd


def ecpy_verify(key, signature, message):
    """ECPy's verdict and the exception it raised, if any."""
    from ecpy.curves import Curve
    from ecpy.eddsa import EDDSA
    from ecpy.keys import ECPublicKey

    curve = Curve.get_curve("Ed521")
    try:
        point = curve.decode_point(key)
        verdict = EDDSA(hashlib.shake_256, hash_len=132).verify(
            message, signature, ECPublicKey(point)
        )
        return bool(verdict), None
    except Exception as error:  # TSE's scripts treat any failure as an invalid signature
        return False, type(error).__name__


def mul(k, point):
    return ref._multiply(k, point)


def add(p, q):
    return ref._add(p, q)


def affine(point):
    inverse = pow(point[2], -1, P)
    return point[0] * inverse % P, point[1] * inverse % P


def raw(y, sign):
    """A 66-byte point encoding with any 527-bit y."""
    assert 0 <= y < 1 << 527
    return (y | sign << 527).to_bytes(66, "little")


def enc(point, extra_p=0, sign=None):
    """Encoding of ``point``, optionally with y + extra_p * p or a forced sign bit."""
    x, y = affine(point)
    return raw(y + extra_p * P, x & 1 if sign is None else sign)


def challenge(r, a, message):
    return ref._h(r + a + message) % L


def scalar_bytes(s):
    return s.to_bytes(66, "little")


def grind(r, a, label, condition):
    """The first message ``label/i`` whose challenge satisfies ``condition``."""
    i = 0
    while True:
        message = f"{label}/{i}".encode()
        k = challenge(r, a, message)
        if condition(k):
            return message, k
        i += 1


def cofactored(key, signature, message):
    a, r = ref.decode(key), ref.decode(signature[:66])
    s = int.from_bytes(signature[66:], "little")
    if a is None or r is None or s >= L:
        return None
    k = challenge(signature[:66], key, message)
    left = mul(4, ref._base_multiply(s))
    right = mul(4, add(r, mul(k, a)))
    return ref._equal(left, right)


def not_on_curve_y():
    y = 2
    while pow((1 - y * y) * pow(1 - D * y * y, -1, P) % P, (P - 1) // 2, P) != P - 1:
        y += 1
    return y


def cases():
    secret = int.from_bytes(hashlib.shake_256(b"ed521rs edge cases").digest(66), "little") % L
    nonce = int.from_bytes(hashlib.shake_256(b"ed521rs edge nonce").digest(66), "little") % L
    a_point, r_point = mul(secret, ref.BASE), mul(nonce, ref.BASE)
    key, r = enc(a_point), enc(r_point)
    max_p = ((1 << 527) - 1 - affine(r_point)[1]) // P  # largest k with y + k p < 2^527

    def signed(r_bytes, key_bytes, message, a=secret, n=nonce):
        s = (n + challenge(r_bytes, key_bytes, message) * a) % L
        return r_bytes + scalar_bytes(s)

    out = []

    def case(id_, key_bytes, signature, message, reason, note):
        out.append((id_, key_bytes, signature, message, reason, note))

    message = b"edge-case baseline"
    good = signed(r, key, message)
    s = int.from_bytes(good[66:], "little")
    case("baseline", key, good, message, "ok", "an honest signature")
    case("s-plus-l", key, r + scalar_bytes(s + L), message, "s_out_of_range", "S + L")
    top = ((1 << 528) - 1 - s) // L
    case(
        "s-plus-max-l",
        key,
        r + scalar_bytes(s + top * L),
        message,
        "s_out_of_range",
        f"S + {top} L, the largest multiple below 2^528",
    )
    case(
        "s-bit-527",
        key,
        r + scalar_bytes(s + (1 << 527)),
        message,
        "s_out_of_range",
        "S + 2^527, a different value mod L",
    )
    case(
        "r-sign-flipped",
        key,
        bytes(good[:65]) + bytes([good[65] ^ 0x80]) + good[66:],
        message,
        "invalid_signature",
        "R with its x sign bit flipped",
    )
    case(
        "r-y-plus-2-521-unsigned",
        key,
        raw(affine(r_point)[1] + (1 << 521), affine(r_point)[0] & 1) + good[66:],
        message,
        "non_canonical_r",
        "bit 521 of R's y set after signing",
    )

    # Non-canonical encodings, signed over the bytes as given (ECPy hashes R and A as received).
    r_plus_p = enc(r_point, 1)
    case(
        "r-y-plus-p",
        key,
        signed(r_plus_p, key, message),
        message,
        "non_canonical_r",
        "R encoded with y + p, signed over those bytes",
    )
    r_plus_max = enc(r_point, max_p)
    case(
        "r-y-plus-max-p",
        key,
        signed(r_plus_max, key, message),
        message,
        "non_canonical_r",
        f"R encoded with y + {max_p} p",
    )
    key_plus_p = enc(a_point, 1)
    case(
        "key-y-plus-p",
        key_plus_p,
        signed(r, key_plus_p, message),
        message,
        "non_canonical_public_key",
        "A encoded with y + p, signed over those bytes",
    )

    # Points with x = 0 encoded with the sign bit set.
    r_id_signed = enc(IDENTITY, sign=1)
    msg = b"edge-case r identity"
    k = challenge(r_id_signed, key, msg)
    case(
        "r-identity-x0-sign",
        key,
        r_id_signed + scalar_bytes(k * secret % L),
        msg,
        "non_canonical_r",
        "R = identity with the sign bit, S = k a",
    )
    r_id = enc(IDENTITY)
    k = challenge(r_id, key, msg)
    case(
        "r-identity",
        key,
        r_id + scalar_bytes(k * secret % L),
        msg,
        "ok",
        "R = identity, S = k a: valid in every mode",
    )
    r_id_plus_p = enc(IDENTITY, 1)
    k = challenge(r_id_plus_p, key, msg)
    case(
        "r-identity-y-plus-p",
        key,
        r_id_plus_p + scalar_bytes(k * secret % L),
        msg,
        "non_canonical_r",
        "R = identity encoded with y = 1 + p, S = k a",
    )

    # Small-order public keys (cofactorless verification accepts them when [k]A vanishes).
    key_2 = enc(ORDER_2)
    msg, _ = grind(r, key_2, "edge-case order-2 even", lambda k: k % 2 == 0)
    case(
        "key-order-2-k-even",
        key_2,
        r + scalar_bytes(nonce),
        msg,
        "ok",
        "A = (0, -1), R = [r]B, S = r, k even: [k]A = O",
    )
    msg, _ = grind(r, key_2, "edge-case order-2 odd", lambda k: k % 2 == 1)
    case(
        "key-order-2-k-odd",
        key_2,
        r + scalar_bytes(nonce),
        msg,
        "invalid_signature",
        "A = (0, -1), k odd: fails cofactorless, passes cofactored",
    )
    key_2_signed = enc(ORDER_2, sign=1)
    msg, _ = grind(r, key_2_signed, "edge-case order-2 sign", lambda k: k % 2 == 0)
    case(
        "key-order-2-x0-sign",
        key_2_signed,
        r + scalar_bytes(nonce),
        msg,
        "non_canonical_public_key",
        "A = (0, -1) with the sign bit, k even",
    )
    msg, _ = grind(r, key_2_signed, "edge-case order-2 sign odd", lambda k: k % 2 == 1)
    case(
        "key-order-2-x0-sign-k-odd",
        key_2_signed,
        r + scalar_bytes(nonce),
        msg,
        "non_canonical_public_key",
        "A = (0, -1) with the sign bit, k odd",
    )
    r_t2 = enc(add(r_point, ORDER_2))
    msg, _ = grind(r_t2, key_2, "edge-case order-2 r torsion", lambda k: k % 2 == 1)
    case(
        "key-order-2-r-torsion-k-odd",
        key_2,
        r_t2 + scalar_bytes(nonce),
        msg,
        "ok",
        "A = (0, -1), R = [r]B + (0, -1), S = r, k odd: R + [k]A = [r]B",
    )
    key_4 = enc(ORDER_4)
    msg, _ = grind(r, key_4, "edge-case order-4 k 1", lambda k: k % 4 == 1)
    case(
        "key-order-4-k-1-mod-4",
        key_4,
        r + scalar_bytes(nonce),
        msg,
        "invalid_signature",
        "A = (1, 0), R = [r]B, S = r, k = 1 mod 4",
    )
    r_t4 = enc(add(r_point, (P - 1, 0, 1, 0)))  # R + (-1, 0), so that R + [k]A = [r]B
    msg, _ = grind(r_t4, key_4, "edge-case order-4 r torsion", lambda k: k % 4 == 1)
    case(
        "key-order-4-r-torsion-k-1-mod-4",
        key_4,
        r_t4 + scalar_bytes(nonce),
        msg,
        "ok",
        "A = (1, 0), R = [r]B - (1, 0), S = r, k = 1 mod 4",
    )
    key_4_p = enc(ORDER_4, 1)  # y = p, which is 0 mod p
    msg, _ = grind(r, key_4_p, "edge-case order-4 y=p", lambda k: k % 4 == 0)
    case(
        "key-order-4-y-equals-p",
        key_4_p,
        r + scalar_bytes(nonce),
        msg,
        "non_canonical_public_key",
        "A = (1, 0) encoded with y = p, k = 0 mod 4",
    )
    key_id = enc(IDENTITY)
    msg = b"edge-case identity key"
    case(
        "key-identity",
        key_id,
        r + scalar_bytes(nonce),
        msg,
        "ok",
        "A = identity: any R = [S]B verifies, for every message",
    )
    case(
        "key-identity-r-y-plus-p",
        key_id,
        r_plus_p + scalar_bytes(nonce),
        msg,
        "non_canonical_r",
        "A = identity and R = [S]B encoded with y + p",
    )
    case(
        "key-identity-x0-sign",
        enc(IDENTITY, sign=1),
        r + scalar_bytes(nonce),
        msg,
        "non_canonical_public_key",
        "A = identity with the sign bit",
    )
    case(
        "key-identity-x0-sign-r-y-plus-p",
        enc(IDENTITY, sign=1),
        r_plus_p + scalar_bytes(nonce),
        msg,
        "non_canonical_public_key",
        "A = identity with the sign bit, R with y + p",
    )
    case(
        "key-identity-y-plus-p",
        enc(IDENTITY, 1),
        r + scalar_bytes(nonce),
        msg,
        "non_canonical_public_key",
        "A = identity encoded with y = 1 + p",
    )

    # S = 0 (mod L).
    msg, _ = grind(r_id, key_id, "edge-case s zero", lambda k: True)
    case("s-zero-identity", key_id, r_id + scalar_bytes(0), msg, "ok", "A = R = identity, S = 0")
    case(
        "s-l-identity",
        key_id,
        r_id + scalar_bytes(L),
        msg,
        "s_out_of_range",
        "A = R = identity, S = L",
    )
    r_2 = enc(ORDER_2)
    msg, _ = grind(r_2, key_2, "edge-case s zero order 2", lambda k: k % 2 == 1)
    case("s-zero-order-2", key_2, r_2 + scalar_bytes(0), msg, "ok", "A = R = (0, -1), k odd, S = 0")

    # Torsion components on an otherwise honest key or R.
    key_t = enc(add(a_point, ORDER_4))
    msg, _ = grind(r, key_t, "edge-case torsion key 0", lambda k: k % 4 == 0)
    case(
        "key-torsion-k-0-mod-4",
        key_t,
        signed(r, key_t, msg),
        msg,
        "ok",
        "A = [a]B + (1, 0), k = 0 mod 4",
    )
    msg, _ = grind(r, key_t, "edge-case torsion key 1", lambda k: k % 4 == 1)
    case(
        "key-torsion-k-1-mod-4",
        key_t,
        signed(r, key_t, msg),
        msg,
        "invalid_signature",
        "A = [a]B + (1, 0), k = 1 mod 4: fails cofactorless, passes cofactored",
    )
    r_t = enc(add(r_point, ORDER_2))
    msg = b"edge-case torsion r"
    case(
        "r-torsion",
        key,
        signed(r_t, key, msg),
        msg,
        "invalid_signature",
        "R = [r]B + (0, -1): fails cofactorless, passes cofactored",
    )

    # Not on the curve.
    bad = raw(not_on_curve_y(), 0)
    case(
        "r-not-on-curve",
        key,
        bad + good[66:],
        message,
        "r_not_on_curve",
        "R's y has no x on the curve",
    )
    case(
        "key-not-on-curve",
        bad,
        good,
        message,
        "public_key_not_on_curve",
        "A's y has no x on the curve",
    )
    return out


def render():
    vectors = []
    for id_, key, signature, message, reason, note in cases():
        strict = ref.verify(key, signature, message)
        assert strict == (reason == "ok"), (id_, strict, reason)
        ecpy, exception = ecpy_verify(key, signature, message)
        record = {
            "id": id_,
            "key": key.hex(),
            "signature": signature.hex(),
            "message": message.hex(),
            "strict": strict,
            "reason": reason,
            "ecpy": ecpy,
            "cofactored": cofactored(key, signature, message),
            "note": note,
        }
        if exception:
            record["ecpy_exception"] = exception
        vectors.append(record)
    document = {
        "description": "Crafted Ed521 edge cases with the verdict of each verification rule",
        "generator": "scripts/gen_edge_cases.py",
        "oracles": {
            "strict": "tests/python/reference_ed521.py (election_audit/ed521.py, https://github.com/tacio/election-audit)",
            "ecpy": f"ECPy {ECPY_COMMIT}",
            "cofactored": "[4][S]B == [4](R + [k]A), computed with the reference's arithmetic",
        },
        "vectors": vectors,
    }
    return json.dumps(document, indent=1) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    text = render()
    if args.check:
        if OUTPUT.read_text() != text:
            sys.exit(f"{OUTPUT} differs from the regenerated edge cases")
        print(f"{OUTPUT.name}: edge cases match")
        return
    OUTPUT.write_text(text)
    print(f"wrote {OUTPUT}")


if __name__ == "__main__":
    main()

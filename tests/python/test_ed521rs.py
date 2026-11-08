"""Tests of the ed521rs extension against the JSON vectors and the pure-Python reference.

Run after building the extension into the environment (``just py-test``):

    python -m unittest discover -s tests/python -v

``ED521RS_PARITY_CASES`` sets the number of random parity cases (default 200; ``just py-parity``
runs 10000). Each case signs with the reference, then checks ed521rs, the reference and, when it
is installed, ECPy agree on the signature and on mutated copies of it.
"""

import hashlib
import importlib.util
import json
import os
import random
import sys
import unittest
from pathlib import Path

import ed521rs

HERE = Path(__file__).resolve().parent
VECTORS = HERE.parent.parent / "crates/ed521/tests/vectors"
sys.path.insert(0, str(HERE))
import reference_ed521 as ref  # noqa: E402

# Verbatim copy of election_audit/ed521.py from https://github.com/tacio/election-audit,
# vendored on 2026-11-06; the test below keeps it unedited.
REFERENCE_SHA256 = "c5c8e63b6bc702c9a94ddf34b8aea29e22b83d550de739744963c4e79e774979"
PARITY_CASES = int(os.environ.get("ED521RS_PARITY_CASES", "200"))
HAVE_ECPY = importlib.util.find_spec("ecpy") is not None

# id, public key, signature, message
Vector = tuple[str, bytes, bytes, bytes]


def load(name: str) -> list[Vector]:
    document = json.loads((VECTORS / name).read_text())
    return [
        (
            v["id"],
            bytes.fromhex(v["key"]),
            bytes.fromhex(v["signature"]),
            bytes.fromhex(v["message"]),
        )
        for v in document["vectors"]
    ]


def ecpy_verify(key: bytes, signature: bytes, message: bytes) -> bool:
    """ECPy's verdict, as TSE's scripts take it (assertion and value errors mean invalid)."""
    from ecpy.curves import Curve
    from ecpy.eddsa import EDDSA
    from ecpy.keys import ECPublicKey

    curve = Curve.get_curve("Ed521")
    try:
        point = curve.decode_point(key)
        return EDDSA(hashlib.shake_256, hash_len=132).verify(message, signature, ECPublicKey(point))
    except Exception:  # TSE's scripts treat any failure as an invalid signature
        return False


class VectorTests(unittest.TestCase):
    def test_reference_copy_is_pinned(self) -> None:
        digest = hashlib.sha256((HERE / "reference_ed521.py").read_bytes()).hexdigest()
        self.assertEqual(digest, REFERENCE_SHA256)

    def test_vectors_verify_in_both_modes(self) -> None:
        vectors = load("tse-2026.json") + load("ecpy.json")
        self.assertEqual(len(vectors), 20)
        for id_, key, signature, message in vectors:
            with self.subTest(id=id_):
                self.assertTrue(ed521rs.verify(key, signature, message))
                self.assertTrue(ed521rs.verify(key, signature, message, mode="ecpy"))
                self.assertEqual(ed521rs.reason(key, signature, message), "ok")
                self.assertTrue(ref.verify(key, signature, message))

    def test_a_changed_file_hash_fails_with_its_reason(self) -> None:
        _, key, signature, message = load("tse-2026.json")[0]
        changed = bytes([message[0] ^ 1]) + message[1:]
        self.assertFalse(ed521rs.verify(key, signature, changed))
        self.assertEqual(ed521rs.reason(key, signature, changed), "invalid_signature")
        too_large = signature[:66] + (int.from_bytes(signature[66:], "little") + ref.L).to_bytes(
            66, "little"
        )
        self.assertEqual(ed521rs.reason(key, too_large, message), "s_out_of_range")
        self.assertFalse(ref.verify(key, too_large, message))
        # TSE's reference (ECPy) does not range-check S.
        self.assertTrue(ed521rs.verify(key, too_large, message, mode="ecpy"))
        self.assertEqual(ed521rs.reason(key, signature[:131], message), "invalid_length")


class EdgeCaseTests(unittest.TestCase):
    """crates/ed521/tests/vectors/edge-cases.json: each mode gives its oracle's verdict."""

    def test_edge_cases(self) -> None:
        document = json.loads((VECTORS / "edge-cases.json").read_text())
        for v in document["vectors"]:
            key, signature, message = (bytes.fromhex(v[f]) for f in ("key", "signature", "message"))
            with self.subTest(id=v["id"]):
                self.assertEqual(ed521rs.reason(key, signature, message), v["reason"])
                self.assertEqual(ed521rs.verify(key, signature, message), v["strict"])
                self.assertEqual(ref.verify(key, signature, message), v["strict"])
                self.assertEqual(ed521rs.verify(key, signature, message, mode="ecpy"), v["ecpy"])
                if HAVE_ECPY:
                    self.assertEqual(ecpy_verify(key, signature, message), v["ecpy"])


class ApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.vectors = [v for v in load("tse-2026.json") if v[0].startswith(("urn", "bu"))]
        self.key = ed521rs.VerifyingKey(self.vectors[0][1])

    def test_key_object(self) -> None:
        key_bytes = self.vectors[0][1]
        self.assertEqual(self.key.to_bytes(), key_bytes)
        self.assertEqual(self.key.mode, "strict")
        self.assertEqual(ed521rs.VerifyingKey(key_bytes, mode="ecpy").mode, "ecpy")
        for _, _, signature, message in self.vectors:
            self.assertTrue(self.key.verify(signature, message))
            self.assertEqual(self.key.reason(signature, message), "ok")
        with self.assertRaisesRegex(ValueError, "invalid_length"):
            ed521rs.VerifyingKey(key_bytes[:65])
        with self.assertRaisesRegex(ValueError, "mode"):
            ed521rs.VerifyingKey(key_bytes, mode="loose")  # ty: ignore[invalid-argument-type]
        non_canonical = b"\xff" * 65 + b"\x01"  # y = p
        with self.assertRaisesRegex(ValueError, "non_canonical_public_key"):
            ed521rs.VerifyingKey(non_canonical)

    def test_precomputed_key(self) -> None:
        key_bytes = self.vectors[0][1]
        for mode in ("strict", "ecpy"):
            precomputed = ed521rs.VerifyingKey(key_bytes, mode=mode, precompute=True)
            self.assertTrue(precomputed.precomputed)
            self.assertFalse(ed521rs.VerifyingKey(key_bytes, mode=mode).precomputed)
            self.assertEqual(precomputed.mode, mode)
            self.assertIn("precompute=True", repr(precomputed))
            for _, _, signature, message in self.vectors:
                self.assertTrue(precomputed.verify(signature, message))
                self.assertFalse(precomputed.verify(signature, message + b"x"))
                self.assertEqual(precomputed.reason(signature[:-1], message), "invalid_length")
        with self.assertRaisesRegex(ValueError, "non_canonical_public_key"):
            ed521rs.VerifyingKey(b"\xff" * 65 + b"\x01", precompute=True)

    def test_reason_many_on_edge_cases(self) -> None:
        """Mixed failures through the batched paths, for both key types and both modes."""
        document = json.loads((VECTORS / "edge-cases.json").read_text())
        key = bytes.fromhex(document["vectors"][0]["key"])
        signatures = [bytes.fromhex(v["signature"]) for v in document["vectors"]] + [b"short"]
        messages = [bytes.fromhex(v["message"]) for v in document["vectors"]] + [b""]
        for mode in ("strict", "ecpy"):
            single = ed521rs.VerifyingKey(key, mode=mode)
            expected = [single.reason(s, m) for s, m in zip(signatures, messages)]
            self.assertIn("invalid_length", expected)
            self.assertGreaterEqual(expected.count("ok"), 3)
            for precompute in (False, True):
                k = ed521rs.VerifyingKey(key, mode=mode, precompute=precompute)
                for threads in (1, 3):
                    with self.subTest(mode=mode, precompute=precompute, threads=threads):
                        got = k.reason_many(signatures, messages, threads=threads)
                        self.assertEqual(got, expected)
                        self.assertEqual(
                            k.verify_many(signatures, messages, threads=threads),
                            [r == "ok" for r in expected],
                        )
                        for n in (1, 2, 3):  # below the automatic precompute threshold
                            self.assertEqual(
                                k.reason_many(signatures[:n], messages[:n]), expected[:n]
                            )

    def test_batch(self) -> None:
        signatures = [v[2] for v in self.vectors]
        messages = [v[3] for v in self.vectors]
        for precompute in (False, True):
            key = ed521rs.VerifyingKey(self.vectors[0][1], precompute=precompute)
            self.assertTrue(key.verify_batch(signatures, messages))
            self.assertTrue(key.verify_batch([], []))
            self.assertFalse(key.verify_batch(signatures, messages[1:] + messages[:1]))
            self.assertFalse(key.verify_batch(signatures[:-1] + [b"short"], messages))
            with self.assertRaises(ValueError):
                key.verify_batch(signatures, messages[:-1])
        everything = load("tse-2026.json") + load("ecpy.json")
        triples = [(k, s, m) for _, k, s, m in everything]
        self.assertTrue(ed521rs.verify_batch(triples))
        self.assertTrue(ed521rs.verify_batch(triples, mode="ecpy"))
        self.assertFalse(ed521rs.verify_batch(triples[:-1] + [(triples[0][0], *triples[-1][1:])]))
        self.assertFalse(ed521rs.verify_batch([(b"\x00" * 65, triples[0][1], triples[0][2])]))

    def test_many_and_packed_agree_with_single_calls(self) -> None:
        signatures = [v[2] for v in self.vectors]
        messages = [v[3] for v in self.vectors]
        signatures[3] = bytes(132)  # one invalid
        expected = [self.key.verify(s, m) for s, m in zip(signatures, messages)]
        self.assertEqual(expected.count(False), 1)
        for threads in (1, 2, 5, 64):
            with self.subTest(threads=threads):
                self.assertEqual(
                    self.key.verify_many(signatures, messages, threads=threads), expected
                )
                packed = self.key.verify_packed(
                    b"".join(signatures), b"".join(messages), 64, threads=threads
                )
                self.assertEqual(packed, expected)
        self.assertEqual(self.key.verify_many([], []), [])
        with self.assertRaises(ValueError):
            self.key.verify_many(signatures, messages[:-1])
        with self.assertRaises(ValueError):
            self.key.verify_packed(b"".join(signatures), b"".join(messages), 63)
        with self.assertRaises(ValueError):
            self.key.verify_many(signatures, messages, threads=0)

    def test_bytes_like_arguments(self) -> None:
        """bytearray and memoryview work wherever bytes do, as with election_audit.ed521."""
        _, key, signature, message = self.vectors[0]
        for convert in (bytearray, memoryview):
            with self.subTest(type=convert.__name__):
                args = (convert(key), convert(signature), convert(message))
                self.assertTrue(ed521rs.verify(*args))
                self.assertEqual(ed521rs.reason(*args), "ok")
                k = ed521rs.VerifyingKey(convert(key))
                self.assertTrue(k.verify(convert(signature), convert(message)))
                self.assertEqual(k.verify_packed(convert(signature), convert(message), 64), [True])
        self.assertTrue(self.key.verify_many([bytearray(signature)], [bytearray(message)])[0])
        with self.assertRaisesRegex(TypeError, "bytes-like"):
            ed521rs.verify(key, "not bytes", message)  # ty: ignore[invalid-argument-type]

    def test_metadata(self) -> None:
        self.assertEqual(ed521rs.backend(), ed521rs.backend())
        self.assertIn(ed521rs.backend(), {"serial", "avx2"})
        self.assertRegex(ed521rs.__version__, r"^\d+\.\d+\.\d+")
        self.assertEqual((ed521rs.PUBLIC_KEY_LENGTH, ed521rs.SIGNATURE_LENGTH), (66, 132))


class ParityTests(unittest.TestCase):
    """Random signatures from the reference signer; ed521rs, the reference and ECPy must agree."""

    def test_random_signatures_and_mutations(self) -> None:
        rng = random.Random(20261106)
        for case in range(PARITY_CASES):
            seed = rng.randbytes(66)
            message = rng.randbytes(rng.choice([0, 1, 64, 200, 569]))
            key = ref.public_key(seed)
            signature = ref.sign(seed, message)
            candidates: list[tuple[bytes, bytes, bool | None]] = [(signature, message, True)]
            mutated = bytearray(signature)
            mutated[rng.randrange(132)] ^= 1 << rng.randrange(8)
            candidates.append((bytes(mutated), message, None))
            if message:
                changed = bytearray(message)
                changed[rng.randrange(len(changed))] ^= 1
                candidates.append((signature, bytes(changed), False))
            for sig, msg, expected in candidates:
                with self.subTest(case=case):
                    ours = ed521rs.verify(key, sig, msg)
                    theirs = ref.verify(key, sig, msg)
                    self.assertEqual(ours, theirs)
                    if expected is not None:
                        self.assertEqual(ours, expected)
                    if HAVE_ECPY:
                        self.assertEqual(
                            ed521rs.verify(key, sig, msg, mode="ecpy"),
                            ecpy_verify(key, sig, msg),
                        )


if __name__ == "__main__":
    unittest.main()

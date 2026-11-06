"""Write crates/ed521/tests/vectors/ecpy.json from the Ed521 test vectors published in ECPy's eddsa.py.

ECPy is the library TSE's reference verifier uses (commit 8143d9ac). Its ``__main__`` block holds
two Ed521 vectors: a key pair with an expected signature of "Message for Ed521 signing", and a
signature over an X.509 TBSCertificate. This script reads that source file as text (it never
imports or runs it), takes the literal constants with ``ast``, and checks both vectors with the
vendored pure-Python reference before writing them:

    python -I scripts/gen_ecpy_vectors.py --ecpy-eddsa path/to/ecpy/eddsa.py [--check]

The signing vector also pins ECPy's key expansion, which differs from a literal reading of
DOC-ICP-01.01: the 66-byte big-endian private value is hashed with SHAKE256 to 132 bytes with no
dom5 prefix, and the low half is clamped with ``a[0] &= 0xFC; a[65] = 0x80``.
"""

import argparse
import ast
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "crates/ed521/tests/vectors/ecpy.json"
ECPY_COMMIT = "8143d9ac017de0cb7f980bedaf56cefe6b4d9180"


def literal(node):
    """Value of int(0x...), 0x..., b'...' or int(...).to_bytes(n, 'big'); None otherwise."""
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "int":
        return literal(node.args[0])
    return None


def ed521_blocks(source):
    """Assignments following each ``Curve.get_curve('Ed521')`` up to the next get_curve."""
    blocks, current = [], None
    for node in ast.walk(ast.parse(source)):
        body = getattr(node, "body", None)
        if not isinstance(body, list):
            continue
        for statement in body:
            if not isinstance(statement, (ast.Assign, ast.Expr)):
                continue  # compound statements are visited through their own bodies
            text = ast.unparse(statement)
            if "get_curve(" in text:
                current = {} if "'Ed521'" in text else None
                if current is not None:
                    blocks.append(current)
                continue
            if current is None or not isinstance(statement, ast.Assign):
                continue
            target = statement.targets[0]
            if isinstance(target, ast.Name):
                value = literal(statement.value)
                if value is not None:
                    current[target.id] = value
                elif "to_bytes" in text and target.id in current:
                    size = statement.value.args[0].value
                    current[target.id] = current[target.id].to_bytes(size, "big")
    return blocks


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--ecpy-eddsa", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    sys.path.insert(0, str(ROOT / "tests/python"))
    import reference_ed521 as ref

    raw = args.ecpy_eddsa.read_bytes()
    blocks = ed521_blocks(raw.decode())
    assert len(blocks) == 2, f"expected 2 Ed521 vectors, found {len(blocks)}"

    def encode(x, y):
        return (y | (x & 1) << 527).to_bytes(66, "little")

    vectors = []
    signing, x509 = blocks
    key = encode(signing["x"], signing["y"])
    signature = signing["expected_sig"]
    message = signing["msg"]
    assert ref.verify(key, signature, message)
    # ECPy key expansion: SHAKE256(d as 66 big-endian bytes, 132), no prefix; clamp the low half.
    digest = hashlib.shake_256(signing["s"].to_bytes(66, "big")).digest(132)
    clamped = bytearray(digest[:66])
    clamped[0] &= 0xFC
    clamped[65] = 0x80
    scalar = int.from_bytes(clamped, "little")
    assert ref.encode(ref._multiply(scalar, ref.BASE)) == key
    nonce = ref._h(digest[66:] + message) % ref.L
    r = ref.encode(ref._multiply(nonce, ref.BASE))
    s = (nonce + ref._h(r + key + message) * scalar) % ref.L
    assert r + s.to_bytes(66, "little") == signature, "ECPy signing convention not reproduced"
    vectors.append(
        {
            "id": "ecpy-sign-message",
            "key": key.hex(),
            "private": signing["s"].to_bytes(66, "big").hex(),
            "signature": signature.hex(),
            "message": message.hex(),
            "valid": True,
            "note": "ECPy key pair; signature reproduced by ECPy's key expansion",
        }
    )
    key = encode(x509["x"], x509["y"])
    assert ref.verify(key, x509["sig"], x509["msg"])
    vectors.append(
        {
            "id": "ecpy-x509-tbs",
            "key": key.hex(),
            "signature": x509["sig"].hex(),
            "message": x509["msg"].hex(),
            "valid": True,
            "note": "ITI root v7 TBSCertificate, verified by ECPy",
        }
    )
    document = {
        "description": "Ed521 vectors published in ECPy's eddsa.py",
        "generator": "scripts/gen_ecpy_vectors.py",
        "sources": {
            f"https://github.com/cslashm/ECPy/blob/{ECPY_COMMIT}/src/ecpy/eddsa.py": (
                hashlib.sha256(raw).hexdigest()
            )
        },
        "vectors": vectors,
    }
    text = json.dumps(document, indent=1) + "\n"
    if args.check:
        if OUTPUT.read_text() != text:
            sys.exit(f"{OUTPUT} differs from the regenerated vectors")
        print(f"{OUTPUT.name}: {len(vectors)} vectors match")
        return
    OUTPUT.write_text(text)
    print(f"wrote {len(vectors)} vectors to {OUTPUT}")


if __name__ == "__main__":
    main()

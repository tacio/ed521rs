"""Python-level timings of ed521rs on real urn signatures (crates/ed521/tests/vectors/tse-2026.json).

    .venv/bin/python scripts/bench.py [--seconds 2] [--no-reference]

Reports microseconds per signature for each entry point, including the pure-Python reference
(tests/python/reference_ed521.py) for scale. The urn workload is one key with about a dozen
signatures, so ``urn group`` decodes a key and verifies its 12 signatures with ``verify_many``.
"""

import argparse
import json
import os
import platform
import sys
import time
from pathlib import Path

import ed521rs

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests/python"))
import reference_ed521 as ref  # noqa: E402


def per_call(function, seconds, items=1):
    """Microseconds per item: the best of three runs of ``seconds / 3`` each."""
    function()
    best = float("inf")
    for _ in range(3):
        count, start = 0, time.perf_counter()
        while (elapsed := time.perf_counter() - start) < seconds / 3:
            function()
            count += 1
        best = min(best, elapsed / count)
    return best * 1e6 / items


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seconds", type=float, default=2.0)
    parser.add_argument("--no-reference", action="store_true")
    args = parser.parse_args(argv)

    document = json.loads((ROOT / "crates/ed521/tests/vectors/tse-2026.json").read_text())
    urn = [v for v in document["vectors"] if v["id"].startswith(("urn", "bu"))]
    key = bytes.fromhex(urn[0]["key"])
    signatures = [bytes.fromhex(v["signature"]) for v in urn]
    messages = [bytes.fromhex(v["message"]) for v in urn]
    assert len(signatures) >= 12 and all(len(m) == 64 for m in messages)
    sig, msg = signatures[0], messages[0]
    plain = ed521rs.VerifyingKey(key)
    precomputed = ed521rs.VerifyingKey(key, precompute=True)
    big = 1024
    packed_sigs = b"".join(signatures[i % len(signatures)] for i in range(big))
    packed_msgs = b"".join(messages[i % len(messages)] for i in range(big))
    group_sigs, group_msgs = signatures[:12], messages[:12]

    rows = []
    if not args.no_reference:
        rows.append(("reference ed521.py verify", per_call(lambda: ref.verify(key, sig, msg), 3)))
    rows += [
        (
            "ed521rs.verify (decodes the key)",
            per_call(lambda: ed521rs.verify(key, sig, msg), args.seconds),
        ),
        ("VerifyingKey(key)", per_call(lambda: ed521rs.VerifyingKey(key), args.seconds)),
        (
            "VerifyingKey(key, precompute=True)",
            per_call(lambda: ed521rs.VerifyingKey(key, precompute=True), args.seconds),
        ),
        ("key.verify", per_call(lambda: plain.verify(sig, msg), args.seconds)),
        ("precomputed key.verify", per_call(lambda: precomputed.verify(sig, msg), args.seconds)),
        (
            "urn group: key + verify_many(12)",
            per_call(
                lambda: ed521rs.VerifyingKey(key).verify_many(group_sigs, group_msgs),
                args.seconds,
                12,
            ),
        ),
        (
            "urn group: key + verify_batch(12)",
            per_call(
                lambda: ed521rs.VerifyingKey(key).verify_batch(group_sigs, group_msgs),
                args.seconds,
                12,
            ),
        ),
        (
            f"verify_packed({big})",
            per_call(lambda: plain.verify_packed(packed_sigs, packed_msgs, 64), args.seconds, big),
        ),
    ]
    threads = min(4, os.cpu_count() or 1)
    rows.append(
        (
            f"verify_packed({big}, threads={threads})",
            per_call(
                lambda: plain.verify_packed(packed_sigs, packed_msgs, 64, threads=threads),
                args.seconds,
                big,
            ),
        )
    )

    machine = platform.processor() or platform.machine()
    print(
        f"ed521rs {ed521rs.__version__} ({ed521rs.backend()}), Python {platform.python_version()}"
    )
    print(f"machine: {machine}, load average: {' '.join(f'{x:.1f}' for x in os.getloadavg())}")
    width = max(len(name) for name, _ in rows)
    reference = rows[0][1] if not args.no_reference else None
    for name, micros in rows:
        speedup = f"  {reference / micros:7.1f}x" if reference else ""
        print(f"{name:<{width}}  {micros:10.1f} us{speedup}")


if __name__ == "__main__":
    main()

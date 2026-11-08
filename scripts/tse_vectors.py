"""Real Ed521 signatures from TSE's 2026 election, from TSE's own publications.

Two steps, both run from the repository root:

    python -I scripts/tse_vectors.py fetch [--browser-downloads ~/Downloads]
    uv run --group tse python -I scripts/tse_vectors.py extract [--check]

``fetch`` gathers every source file into ``tse-sources/`` (ignored by git) and checks each against
the SHA-256 pinned in ``SOURCES``. The urn files are downloaded from TSE's results site, which
also confirms (``"f": "o"`` in the section's auxiliary file) that they are the official
publication. TSE's other servers refuse non-browser clients (HTTP 403), so the format package and
the two revocation lists must be downloaded in a browser from the URLs ``fetch`` prints; it then
picks them up from ``--browser-downloads``.

``extract`` decodes the sources with TSE's own ASN.1 specifications (from the format package) and
writes ``crates/ed521/tests/vectors/tse-2026.json``. Every vector must verify under the vendored
pure-Python reference before it is written. With ``--check`` nothing is written: the output must
equal the committed file.

The vectors are (public key, signature, message) triples exactly as TSE's devices signed them:

- urn hardware signatures (``-vota.vsc``): message = SHA-512(h), h the listed 64-byte SHA-512;
- vote-hash-chain signatures in the BU (``-bu.dat``): message = SHA-512(ultimoHashVotosVotavel);
- the AC UE2020 and AC UE2022 signatures on urn certificates (taken from two other sections'
  ``-vota.vsc``) and on their revocation lists: message = the raw TBSCertificate / TBSCertList.
"""

import argparse
import base64
import hashlib
import io
import json
import re
import sys
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SOURCES_DIR = ROOT / "tse-sources"
OUTPUT = ROOT / "crates/ed521/tests/vectors/tse-2026.json"
USER_AGENT = "ed521rs-tse-vectors (https://github.com/tacio/ed521rs)"

RESULTS = "https://resultados.tse.jus.br/oficial/ele2026/arquivo-urna/3221/dados"
PACKAGE = "formato-arquivos-de-bu-rdv-e-assinatura-digital.zip"

# Round 2 of the 2026 general election (pleito 3221), state of Acre. Section 01015/0002/0088
# supplies the urn signatures; the other two carry one urn certificate from each Ed521 CA.
SECTIONS = {
    "o03221ac0101500020088": ("01015", "0002", "0088"),
    "o03221ac0139200090038": ("01392", "0009", "0038"),
    "o03221ac0139200090168": ("01392", "0009", "0168"),
}

# file name -> (where it comes from, SHA-256). "section" files are fetched; "browser" ones are not.
SOURCES = {
    "o03221ac0101500020088-vota.vsc": (
        "section",
        "f42b7bdcf81ab9adda845fdf9c159ff9ddf044d2ce443974a627599d7ed9c164",
    ),
    "o03221ac0101500020088-bu.dat": (
        "section",
        "e41aaf20c15e3a10d5532ee6afd4418e20b60aad9efc0c7d8617dc58239bf1ce",
    ),
    "o03221ac0139200090038-vota.vsc": (
        "section",
        "34e339c34e5684b8af5c82c6c14fcf049e1f4bb4febbe93265c4a9a6121b4ddb",
    ),
    "o03221ac0139200090168-vota.vsc": (
        "section",
        "829f04334479b20bf96beeb96aca2d929aa008babcf663001a7bb9780b2ce1b3",
    ),
    PACKAGE: (
        "https://www.tse.jus.br/eleicoes/eleicoes-2026-content/arquivos/"
        "formato-arquivos-de-bu-rdv-e-assinatura-digital",
        "b5ac413e81121d53de2bb1657af611f84a45fdc84388e9d9821872994bbfbafd",
    ),
    "acue2020.crl": (
        "http://lcr.acue2020.tse.jus.br/acue2020.crl",
        "dc4c91e7da5fab37ad1c543560ed5ef29c0cccca66dcd12a9fda86690c5a8058",
    ),
    "acue2022.crl": (
        "http://lcr.acue2022.tse.jus.br/acue2022.crl",
        "cc9b2ce0721aa1ee418293525db38fb8120cfb2a83b3a1e469384823130a68d7",
    ),
}

# The CA certificates are embedded in the format package's reference code, as PEM bodies after a
# "# <name>.crt" comment (python/lib/mr_util.py).
CA_SOURCE = "python/lib/mr_util.py"
CA_SHA256 = {
    "acue2020": "77f31bef3d8eb35f0cc969a2b9bba3ff2a498cc339d29a375d3181e0547c0376",
    "acue2022": "6ae65790dae7cc5d97394e461204744c8e2f7a810d0303af828d4d3dbecfa293",
}


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def get(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def section_url(name: str) -> str:
    """The official URL of one section file, from the section's auxiliary file."""
    stem = name.split("-")[0]
    municipality, zone, section = SECTIONS[stem]
    directory = f"{RESULTS}/ac/{municipality}/{zone}/{section}"
    aux = json.loads(get(f"{directory}/p003221-ac-m{municipality}-z{zone}-s{section}-aux.json"))
    if str(aux.get("f", "")).lower() != "o":
        raise SystemExit(f"{directory}: the auxiliary file is not marked official")
    for group in aux["hashes"]:
        if any(entry["nm"] == name for entry in group.get("arq", [])):
            return f"{directory}/{group['hash']}/{name}"
    raise SystemExit(f"{directory}: {name} is not listed")


def source_url(name: str) -> str:
    origin, _ = SOURCES[name]
    return section_url(name) if origin == "section" else origin


def fetch(args: argparse.Namespace) -> None:
    SOURCES_DIR.mkdir(exist_ok=True)
    missing: list[tuple[str, str]] = []
    for name, (origin, digest) in SOURCES.items():
        target = SOURCES_DIR / name
        if target.exists() and sha256(target.read_bytes()) == digest:
            print(f"ok       {name}")
            continue
        if origin == "section":
            raw = get(section_url(name))
        else:
            candidate = args.browser_downloads.expanduser() / name
            if not candidate.exists():
                missing.append((name, origin))
                continue
            raw = candidate.read_bytes()
        if sha256(raw) != digest:
            hint = (
                " TSE reissues each revocation list about every 90 days, and the vectors pin the"
                " issue of 2026-09-27. To move to the new issue, update its digest in SOURCES"
                " and run `extract` without --check."
                if name.endswith(".crl")
                else ""
            )
            raise SystemExit(f"{name}: SHA-256 {sha256(raw)}, expected {digest}.{hint}")
        target.write_bytes(raw)
        print(f"fetched  {name}")
    if missing:
        print(
            "\nTSE refuses these to non-browser clients. Download each in a browser into "
            f"{args.browser_downloads} (or pass --browser-downloads) and run fetch again:"
        )
        for name, url in missing:
            print(f"  {name}\n    {url}")
        sys.exit(1)


# Minimal DER reading: enough to cut certificates and revocation lists into their parts.


def tlv(der: bytes, offset: int) -> tuple[int, int, int]:
    """(tag, content start, end) of the DER element at ``offset``."""
    tag, length = der[offset], der[offset + 1]
    start = offset + 2
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(der[start : start + count], "big")
        start += count
    return tag, start, start + length


def signed_parts(der: bytes) -> tuple[bytes, bytes]:
    """(raw TBS element, signature bytes) of an X.509 certificate or revocation list."""
    _, start, _ = tlv(der, 0)
    _, _, tbs_end = tlv(der, start)
    _, _, algorithm_end = tlv(der, tbs_end)
    tag, bits_start, bits_end = tlv(der, algorithm_end)
    assert tag == 0x03 and der[bits_start] == 0, "signature is not a whole-byte BIT STRING"
    return der[start:tbs_end], der[bits_start + 1 : bits_end]


def subject_key(der: bytes) -> bytes:
    """The 66-byte subject public key of an Ed521 certificate."""
    _, start, _ = tlv(der, 0)
    _, offset, _ = tlv(der, start)  # tbsCertificate contents
    if der[offset] == 0xA0:  # [0] version
        offset = tlv(der, offset)[2]
    for _ in range(5):  # serialNumber, signature, issuer, validity, subject
        offset = tlv(der, offset)[2]
    _, spki_start, _ = tlv(der, offset)
    _, _, algorithm_end = tlv(der, spki_start)
    tag, key_start, key_end = tlv(der, algorithm_end)
    assert tag == 0x03 and key_end - key_start == 67 and der[key_start] == 0, "not an Ed521 key"
    return der[key_start + 1 : key_end]


def pem_certificates(raw: bytes) -> list[bytes]:
    bodies = re.findall(rb"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", raw, re.S)
    return [base64.b64decode(b"".join(body.split())) for body in bodies]


def extract(args: argparse.Namespace) -> None:
    import asn1tools

    sys.path.insert(0, str(ROOT / "tests/python"))
    import reference_ed521 as ref

    def read(name: str) -> bytes:
        raw = (SOURCES_DIR / name).read_bytes()
        if sha256(raw) != SOURCES[name][1]:
            raise SystemExit(f"{name}: run `scripts/tse_vectors.py fetch` first")
        return raw

    package = zipfile.ZipFile(io.BytesIO(read(PACKAGE)))

    def member(path: str) -> str:
        return package.read(path).decode()

    signature_codec = asn1tools.compile_string(member("spec/assinatura.asn1"), codec="der")
    bu_codec = asn1tools.compile_string(member("spec/bu.asn1"), codec="ber")

    vectors: list[dict[str, object]] = []

    def add(id_: str, source: str, key: bytes, signature: bytes, message: bytes, note: str) -> None:
        assert ref.verify(key, signature, message), id_  # the Python reference agrees
        vectors.append(
            {
                "id": id_,
                "source": source,
                "key": key.hex(),
                "signature": signature.hex(),
                "message": message.hex(),
                "valid": True,
                "note": note,
            }
        )

    def urn_certificate(name: str) -> tuple[dict[str, Any], bytes]:
        entity = signature_codec.decode("EntidadeAssinaturaEcourna", read(name))
        hardware = entity["assinaturaHW"]
        kind, pem = hardware["informacaoChave"]
        assert kind == "certificadoDigital", name
        (certificate,) = pem_certificates(pem)
        return hardware, certificate

    # Urn hardware signatures: the self-signature and every listed file.
    section = "o03221ac0101500020088"
    vsc = f"{section}-vota.vsc"
    hardware, certificate = urn_certificate(vsc)
    urn_key = subject_key(certificate)
    auto = hardware["autoAssinado"]["assinatura"]
    add(
        "urn-self",
        vsc,
        urn_key,
        auto["assinatura"],
        hashlib.sha512(auto["hash"]).digest(),
        "hardware self-signature over SHA-512 of the signed-list hash",
    )
    listed = signature_codec.decode("Assinatura", hardware["conteudoAutoAssinado"])
    for entry in listed["arquivosAssinados"]:
        signed = entry["assinatura"]
        add(
            f"urn-file-{entry['nomeArquivo']}",
            vsc,
            urn_key,
            signed["assinatura"],
            hashlib.sha512(signed["hash"]).digest(),
            "hardware signature over SHA-512 of the listed SHA-512 file hash",
        )

    # Vote-hash-chain signatures, one per election in the BU, by the same urn key.
    bu_name = f"{section}-bu.dat"
    envelope = bu_codec.decode("EntidadeEnvelopeGenerico", read(bu_name))
    bu = bu_codec.decode("EntidadeBoletimUrna", envelope["conteudo"])
    for election in bu["resultadosVotacaoPorEleicao"]:
        add(
            f"bu-chain-{election['idEleicao']}",
            bu_name,
            urn_key,
            election["assinaturaUltimoHashVotosVotavel"],
            hashlib.sha512(election["ultimoHashVotosVotavel"]).digest(),
            "BU signature over SHA-512 of ultimoHashVotosVotavel",
        )

    # CA signatures on one urn certificate each and on the CAs' revocation lists.
    ca_pems = dict(re.findall(r'# (\w+)\.crt\s*"""(.*?)"""', member(CA_SOURCE), re.S))
    leaves = {
        "acue2020": "o03221ac0139200090168-vota.vsc",
        "acue2022": "o03221ac0139200090038-vota.vsc",
    }
    for stem, leaf_name in leaves.items():
        ca = base64.b64decode("".join(ca_pems[stem].split()))
        assert sha256(ca) == CA_SHA256[stem], stem
        ca_key = subject_key(ca)
        _, leaf = urn_certificate(leaf_name)
        tbs, signature = signed_parts(leaf)
        add(
            f"ca-{stem}-leaf",
            leaf_name,
            ca_key,
            signature,
            tbs,
            f"{stem} signature over the raw TBSCertificate of the urn certificate in this file "
            f"(CA key from {PACKAGE}, {CA_SOURCE})",
        )
        crl_name = f"{stem}.crl"
        tbs, signature = signed_parts(read(crl_name))
        add(
            f"ca-{stem}-crl",
            crl_name,
            ca_key,
            signature,
            tbs,
            f"{stem} signature over the raw TBSCertList",
        )

    document = {
        "description": "Real Ed521 signatures from TSE's 2026 election (round 2, Acre)",
        "generator": "scripts/tse_vectors.py",
        "sources": {
            name: {"url": source_url(name), "sha256": digest}
            for name, (_, digest) in sorted(SOURCES.items())
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


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    fetch_parser = commands.add_parser("fetch", help="download and check the TSE source files")
    fetch_parser.add_argument("--browser-downloads", type=Path, default=Path("~/Downloads"))
    extract_parser = commands.add_parser("extract", help="write tse-2026.json from the sources")
    extract_parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    {"fetch": fetch, "extract": extract}[args.command](args)


if __name__ == "__main__":
    main()

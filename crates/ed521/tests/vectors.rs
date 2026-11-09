//! The JSON vectors in `tests/vectors/`: real TSE 2026 signatures and ECPy's published ones.

use ed521::{Error, Mode, Signature, VerifyingKey, verify};
use serde_json::Value;

struct Vector {
    id: String,
    key: Vec<u8>,
    signature: Vec<u8>,
    message: Vec<u8>,
    #[cfg_attr(not(feature = "__hazmat-sign"), allow(dead_code))] // read by the signing test
    private: Option<Vec<u8>>,
}

fn load(name: &str) -> Vec<Vector> {
    let path = format!("{}/tests/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    let document: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let hex = |v: &Value| hex::decode(v.as_str().unwrap()).unwrap();
    document["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            assert_eq!(v["valid"], Value::Bool(true));
            Vector {
                id: v["id"].as_str().unwrap().to_owned(),
                key: hex(&v["key"]),
                signature: hex(&v["signature"]),
                message: hex(&v["message"]),
                private: v.get("private").map(hex),
            }
        })
        .collect()
}

fn all() -> Vec<Vector> {
    let mut vectors = load("tse-2026.json");
    vectors.extend(load("ecpy.json"));
    assert_eq!(vectors.len(), 20);
    vectors
}

#[test]
fn every_vector_verifies_in_both_modes() {
    for v in all() {
        for mode in [Mode::Strict, Mode::EcpyCompat] {
            assert_eq!(verify(&v.key, &v.signature, &v.message, mode), Ok(()), "{} {mode:?}", v.id);
        }
    }
}

#[test]
fn single_bit_changes_are_rejected() {
    for v in all().iter().step_by(3) {
        let key = VerifyingKey::from_slice(&v.key, Mode::Strict).unwrap();
        for bit in (0..132 * 8).step_by(37) {
            let mut signature = v.signature.clone();
            signature[bit / 8] ^= 1 << (bit % 8);
            let signature = Signature::from_slice(&signature).unwrap();
            assert!(key.verify(&v.message, &signature).is_err(), "{} signature bit {bit}", v.id);
        }
        let signature = Signature::from_slice(&v.signature).unwrap();
        for bit in (0..v.message.len() * 8).step_by(61) {
            let mut message = v.message.clone();
            message[bit / 8] ^= 1 << (bit % 8);
            assert_eq!(key.verify(&message, &signature), Err(Error::InvalidSignature), "{}", v.id);
        }
        let mut other = v.key.clone();
        other[0] ^= 1;
        if let Ok(other) = VerifyingKey::from_slice(&other, Mode::Strict) {
            assert_eq!(other.verify(&v.message, &signature), Err(Error::InvalidSignature));
        }
    }
}

#[test]
fn urn_signatures_need_the_double_hash() {
    // The urns sign SHA-512(h); verifying h itself must fail.
    let v = &load("tse-2026.json")[0];
    let key = VerifyingKey::from_slice(&v.key, Mode::Strict).unwrap();
    assert!(key.verify(&v.message[..32], &Signature::from_slice(&v.signature).unwrap()).is_err());
}

#[cfg(feature = "__hazmat-sign")]
#[test]
fn ecpy_signing_vector_is_reproduced() {
    let v = load("ecpy.json").into_iter().find(|v| v.private.is_some()).unwrap();
    let signer = ed521::hazmat::SigningKey::from_ecpy_private(
        v.private.as_deref().unwrap().try_into().unwrap(),
    );
    assert_eq!(signer.verifying_key().to_bytes().as_slice(), v.key.as_slice());
    assert_eq!(signer.sign(&v.message).to_bytes().as_slice(), v.signature.as_slice());
}

/// `tests/vectors/edge-cases.json`: each mode must give its oracle's verdict (the pure-Python
/// reference for strict, ECPy for compat), and strict failures must carry the recorded reason.
#[test]
fn edge_cases_match_the_oracles() {
    let path = format!("{}/tests/vectors/edge-cases.json", env!("CARGO_MANIFEST_DIR"));
    let document: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let hex = |v: &Value| hex::decode(v.as_str().unwrap()).unwrap();
    let vectors = document["vectors"].as_array().unwrap();
    assert!(vectors.len() >= 30);
    for v in vectors {
        let id = v["id"].as_str().unwrap();
        let (key, signature, message) = (hex(&v["key"]), hex(&v["signature"]), hex(&v["message"]));
        let strict = verify(&key, &signature, &message, Mode::Strict);
        let reason = match strict {
            Ok(()) => "ok",
            Err(e) => e.code(),
        };
        assert_eq!(reason, v["reason"].as_str().unwrap(), "{id} strict reason");
        assert_eq!(strict.is_ok(), v["strict"].as_bool().unwrap(), "{id} strict");
        let compat = verify(&key, &signature, &message, Mode::EcpyCompat);
        assert_eq!(compat.is_ok(), v["ecpy"].as_bool().unwrap(), "{id} ecpy: {compat:?}");
        for (mode, expected) in [(Mode::Strict, strict), (Mode::EcpyCompat, compat)] {
            if let Ok(decoded) = VerifyingKey::from_slice(&key, mode) {
                let signature = Signature::from_slice(&signature).unwrap();
                assert_eq!(decoded.precompute().verify(&message, &signature), expected, "{id}");
            }
        }
    }
}

#[test]
fn precomputed_keys_agree() {
    for v in all() {
        for mode in [Mode::Strict, Mode::EcpyCompat] {
            let key = VerifyingKey::from_slice(&v.key, mode).unwrap();
            let precomputed = key.precompute();
            let signature = Signature::from_slice(&v.signature).unwrap();
            assert_eq!(precomputed.verify(&v.message, &signature), Ok(()), "{}", v.id);
            let mut bad = v.signature.clone();
            bad[70] ^= 4;
            let bad = Signature::from_slice(&bad).unwrap();
            assert_eq!(precomputed.verify(&v.message, &bad), key.verify(&v.message, &bad));
        }
    }
}

/// `verify_many` (shared inversions) gives the per-signature results of `verify`, on a mix of
/// valid, invalid and malformed signatures, for both key types and chunk boundaries.
#[test]
fn verify_many_matches_verify() {
    let path = format!("{}/tests/vectors/edge-cases.json", env!("CARGO_MANIFEST_DIR"));
    let document: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let hex = |v: &Value| hex::decode(v.as_str().unwrap()).unwrap();
    let base = &document["vectors"].as_array().unwrap()[0];
    let key_bytes = hex(&base["key"]);
    // Every edge case's signature and message against the baseline key, plus mutations.
    let mut messages = Vec::new();
    let mut signatures = Vec::new();
    for v in document["vectors"].as_array().unwrap() {
        let signature = hex(&v["signature"]);
        let message = hex(&v["message"]);
        for flip in [None, Some(3usize), Some(100)] {
            let mut sig = signature.clone();
            if let Some(byte) = flip {
                sig[byte] ^= 1;
            }
            signatures.push(Signature::from_slice(&sig).unwrap());
            messages.push(message.clone());
        }
    }
    let messages: Vec<&[u8]> = messages.iter().map(Vec::as_slice).collect();
    for mode in [Mode::Strict, Mode::EcpyCompat] {
        let key = VerifyingKey::from_slice(&key_bytes, mode).unwrap();
        let expected: Vec<_> =
            messages.iter().zip(&signatures).map(|(m, s)| key.verify(m, s)).collect();
        assert!(expected.iter().filter(|r| r.is_ok()).count() >= 3);
        assert!(expected.contains(&Err(Error::NonCanonicalR)) || mode != Mode::Strict);
        let precomputed = key.precompute();
        for n in [0, 1, 15, 16, 17, messages.len()] {
            let mut results = vec![Ok(()); n];
            key.verify_many(&messages[..n], &signatures[..n], &mut results);
            assert_eq!(results, expected[..n], "{mode:?} n = {n}");
            let mut results = vec![Ok(()); n];
            precomputed.verify_many(&messages[..n], &signatures[..n], &mut results);
            assert_eq!(results, expected[..n], "{mode:?} precomputed n = {n}");
        }
    }
}

#[test]
fn keys_compare_by_encoding_and_mode() {
    use std::collections::HashSet;
    let vectors = all();
    let mut keys = HashSet::new();
    for v in &vectors {
        for mode in [Mode::Strict, Mode::EcpyCompat] {
            let key = VerifyingKey::from_slice(&v.key, mode).unwrap();
            assert_eq!(key, VerifyingKey::from_slice(&v.key, mode).unwrap());
            keys.insert(key);
        }
    }
    let distinct: HashSet<&[u8]> = vectors.iter().map(|v| &v.key[..]).collect();
    assert!(distinct.len() > 1);
    assert_eq!(keys.len(), 2 * distinct.len());
    let key = &vectors[0].key;
    assert_ne!(
        VerifyingKey::from_slice(key, Mode::Strict).unwrap(),
        VerifyingKey::from_slice(key, Mode::EcpyCompat).unwrap()
    );
    // In EcpyCompat, y + p decodes to the same point, but it is a different key: the encoding
    // enters the challenge hash.
    let path = format!("{}/tests/vectors/edge-cases.json", env!("CARGO_MANIFEST_DIR"));
    let document: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let key_of = |id: &str| {
        let v = document["vectors"].as_array().unwrap().iter().find(|v| v["id"] == id).unwrap();
        VerifyingKey::from_slice(
            &hex::decode(v["key"].as_str().unwrap()).unwrap(),
            Mode::EcpyCompat,
        )
        .unwrap()
    };
    assert_ne!(key_of("baseline"), key_of("key-y-plus-p"));
}

#[test]
fn small_order_keys_are_flagged_and_rejected_on_request() {
    let path = format!("{}/tests/vectors/edge-cases.json", env!("CARGO_MANIFEST_DIR"));
    let document: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut small = 0;
    for v in document["vectors"].as_array().unwrap() {
        let id = v["id"].as_str().unwrap();
        let expected = id.starts_with("key-identity")
            || id.starts_with("key-order-")
            || matches!(id, "s-zero-identity" | "s-l-identity" | "s-zero-order-2");
        let key = hex::decode(v["key"].as_str().unwrap()).unwrap();
        for mode in [Mode::Strict, Mode::EcpyCompat] {
            let Ok(key) = VerifyingKey::from_slice(&key, mode) else { continue };
            assert_eq!(key.is_small_order(), expected, "{id}");
            assert_eq!(
                key.reject_small_order().err(),
                expected.then_some(Error::SmallOrderPublicKey),
                "{id}"
            );
            small += usize::from(expected);
        }
    }
    assert!(small > 0);
    for v in all() {
        let key = VerifyingKey::from_slice(&v.key, Mode::Strict).unwrap();
        assert!(!key.is_small_order());
    }
}

//! Random-linear-combination batch verification against exact verification.

use ed521::hazmat::SigningKey;
use ed521::{Error, Mode, Signature, VerifyingKey, verify_batch};
use serde_json::Value;

struct Item {
    key: VerifyingKey,
    message: Vec<u8>,
    signature: Signature,
}

fn items(names: &[&str], mode: Mode) -> Vec<Item> {
    let mut out = Vec::new();
    for name in names {
        let path = format!("{}/tests/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
        let document: Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let hex = |v: &Value| hex::decode(v.as_str().unwrap()).unwrap();
        for v in document["vectors"].as_array().unwrap() {
            out.push(Item {
                key: VerifyingKey::from_slice(&hex(&v["key"]), mode).unwrap(),
                message: hex(&v["message"]),
                signature: Signature::from_slice(&hex(&v["signature"])).unwrap(),
            });
        }
    }
    out
}

fn batch(items: &[Item]) -> Result<(), Error> {
    let refs: Vec<_> = items.iter().map(|i| (&i.key, i.message.as_slice(), &i.signature)).collect();
    verify_batch(&refs)
}

#[test]
fn real_signatures_pass_under_mixed_keys() {
    for mode in [Mode::Strict, Mode::EcpyCompat] {
        let all = items(&["tse-2026.json", "ecpy.json"], mode);
        assert_eq!(all.len(), 20);
        assert_eq!(batch(&all), Ok(()), "{mode:?}");
        assert_eq!(batch(&all[..1]), Ok(()));
        assert_eq!(batch(&[]), Ok(()));
        for i in [0, 7, 19] {
            let mut broken = items(&["tse-2026.json", "ecpy.json"], mode);
            broken[i].message[0] ^= 1;
            assert_eq!(batch(&broken), Err(Error::BatchInvalid), "{mode:?} item {i}");
        }
    }
}

#[test]
fn one_key_batches_plain_and_precomputed() {
    let urn: Vec<_> =
        items(&["tse-2026.json"], Mode::Strict).into_iter().take(14).collect::<Vec<_>>();
    assert!(urn.iter().all(|i| i.key.to_bytes() == urn[0].key.to_bytes()));
    let messages: Vec<&[u8]> = urn.iter().map(|i| i.message.as_slice()).collect();
    let signatures: Vec<Signature> = urn.iter().map(|i| i.signature).collect();
    let key = urn[0].key;
    let precomputed = key.precompute();
    assert_eq!(key.verify_batch(&messages, &signatures), Ok(()));
    assert_eq!(precomputed.verify_batch(&messages, &signatures), Ok(()));
    let mut bad = signatures;
    let mut bytes = bad[5].to_bytes();
    bytes[100] ^= 0x10;
    bad[5] = Signature::from_bytes(&bytes);
    assert_eq!(key.verify_batch(&messages, &bad), Err(Error::BatchInvalid));
    assert_eq!(precomputed.verify_batch(&messages, &bad), Err(Error::BatchInvalid));
}

/// Each edge case joins an honest signature in a strict batch: the batch passes exactly when the
/// case satisfies the cofactored equation, and malformed cases report their decoding error.
#[test]
fn edge_cases_follow_the_cofactored_equation() {
    let path = format!("{}/tests/vectors/edge-cases.json", env!("CARGO_MANIFEST_DIR"));
    let document: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let hex = |v: &Value| hex::decode(v.as_str().unwrap()).unwrap();
    let vectors = document["vectors"].as_array().unwrap();
    let honest = &vectors[0];
    let honest_key = VerifyingKey::from_slice(&hex(&honest["key"]), Mode::Strict).unwrap();
    let honest_signature = Signature::from_slice(&hex(&honest["signature"])).unwrap();
    let honest_message = hex(&honest["message"]);
    let mut divergent = 0;
    for v in vectors {
        let id = v["id"].as_str().unwrap();
        let (key, signature, message) = (hex(&v["key"]), hex(&v["signature"]), hex(&v["message"]));
        let signature = Signature::from_slice(&signature).unwrap();
        let result = match VerifyingKey::from_slice(&key, Mode::Strict) {
            Ok(key) => verify_batch(&[
                (&honest_key, &honest_message, &honest_signature),
                (&key, &message, &signature),
            ]),
            Err(e) => Err(e),
        };
        match v["cofactored"].as_bool() {
            Some(true) => assert_eq!(result, Ok(()), "{id}"),
            Some(false) => assert_eq!(result, Err(Error::BatchInvalid), "{id}"),
            None => assert_eq!(result.unwrap_err().code(), v["reason"].as_str().unwrap(), "{id}"),
        }
        if v["cofactored"] == Value::Bool(true) && v["strict"] == Value::Bool(false) {
            divergent += 1;
        }
    }
    // Torsion cases the batch accepts and exact verification rejects, as documented.
    assert!(divergent >= 3, "{divergent}");
}

#[test]
fn random_batches_catch_any_single_bad_signature() {
    let signers: Vec<_> = (1..=3u8).map(|i| SigningKey::from_ecpy_private(&[i; 66])).collect();
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for n in [1usize, 2, 5, 16, 33] {
        let mut all = Vec::new();
        for i in 0..n {
            let signer = &signers[(next() % 3) as usize];
            let message = format!("message {n} {i}").into_bytes();
            let signature = signer.sign(&message);
            all.push(Item { key: signer.verifying_key(), message, signature });
        }
        assert_eq!(batch(&all), Ok(()), "n = {n}");
        let victim = (next() % n as u64) as usize;
        let mut bytes = all[victim].signature.to_bytes();
        let bit = (next() % (132 * 8)) as usize;
        bytes[bit / 8] ^= 1 << (bit % 8);
        all[victim].signature = Signature::from_bytes(&bytes);
        let exact = all[victim].key.verify(&all[victim].message, &all[victim].signature);
        let result = batch(&all);
        match exact {
            Err(Error::InvalidSignature) => assert_eq!(result, Err(Error::BatchInvalid)),
            Err(e) => assert_eq!(result, Err(e), "n = {n}"),
            Ok(()) => panic!("a flipped bit verified"),
        }
    }
}

//! `verify_batch` against the cofactored equation of the big-integer model, on batches of up to
//! eight crafted signatures under up to three keys.
#![no_main]

use ed521::hazmat::SigningKey;
use ed521::{Error, Mode, Signature, VerifyingKey, verify_batch};
use ed521_fuzz::{cofactored, mutate};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let signers: Vec<_> =
        (0..3u8).map(|i| SigningKey::from_ecpy_private(&[i ^ data[0]; 66])).collect();
    let mut items = Vec::new();
    for (i, chunk) in data[1..].chunks(3).take(8).enumerate() {
        let signer = &signers[usize::from(chunk[0]) % 3];
        let message = vec![i as u8, chunk[0]];
        let mut key = signer.verifying_key().to_bytes();
        let mut signature = signer.sign(&message).to_bytes();
        if chunk.len() == 3 {
            mutate(chunk[1], chunk[2], &mut key, &mut signature);
        }
        items.push((key, signature, message));
    }
    let mut decoded = Vec::new();
    let mut expected = Ok(());
    for (key, signature, message) in &items {
        match (
            VerifyingKey::from_bytes_with_mode(key, Mode::Strict),
            cofactored(key, signature, message),
        ) {
            (Ok(k), Some(valid)) => {
                if !valid && expected.is_ok() {
                    expected = Err(Error::BatchInvalid);
                }
                decoded.push((k, Signature::from_bytes(signature), message.as_slice()));
            }
            _ => return, // malformed: covered by the verify target
        }
    }
    let refs: Vec<_> = decoded.iter().map(|(k, s, m)| (k, *m, s)).collect();
    assert_eq!(verify_batch(&refs), expected);
});

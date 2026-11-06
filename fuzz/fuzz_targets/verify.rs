//! Every exact entry point against the big-integer model, on signatures made by the test signer
//! and then crafted by `mutate`, and on raw fuzz bytes.
#![no_main]

use ed521::hazmat::SigningKey;
use ed521::{Mode, Signature, VerifyingKey, verify};
use ed521_fuzz::{mutate, verify_ecpy, verify_strict};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 70 {
        return;
    }
    let (seed, rest) = data.split_at(66);
    let (ops, message) = rest.split_at(4);
    let signer = SigningKey::from_ecpy_private(seed.try_into().unwrap());
    let mut key = signer.verifying_key().to_bytes();
    let mut signature = signer.sign(message).to_bytes();
    mutate(ops[0], ops[1], &mut key, &mut signature);
    mutate(ops[2], ops[3], &mut key, &mut signature);
    check(&key, &signature, message);
    // Raw bytes as well, when there are enough.
    if message.len() >= 198 {
        check(&message[..66], &message[66..198], &message[198..]);
    }
});

fn check(key: &[u8], signature: &[u8], message: &[u8]) {
    for (mode, expected) in [
        (Mode::Strict, verify_strict(key, signature, message)),
        (Mode::EcpyCompat, verify_ecpy(key, signature, message)),
    ] {
        let result = verify(key, signature, message, mode);
        assert_eq!(result.is_ok(), expected, "{mode:?}: {result:?}");
        let Ok(verifying_key) = VerifyingKey::from_slice(key, mode) else { continue };
        let signature = Signature::from_slice(signature).unwrap();
        assert_eq!(verifying_key.precompute().verify(message, &signature), result);
        // Five copies: one AVX2 lane group plus a serial remainder.
        let messages = [message; 5];
        let signatures = [signature; 5];
        let mut results = [Ok(()); 5];
        verifying_key.verify_many(&messages, &signatures, &mut results);
        assert!(results.iter().all(|r| *r == result), "verify_many {results:?} vs {result:?}");
        verifying_key.precompute().verify_many(&messages, &signatures, &mut results);
        assert!(results.iter().all(|r| *r == result), "precomputed verify_many");
    }
}

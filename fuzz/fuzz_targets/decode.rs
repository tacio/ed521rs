//! Public-key decoding in both modes against the big-integer model, on arbitrary 66 bytes.
#![no_main]

use ed521::{Mode, VerifyingKey};
use ed521_fuzz::decode;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(bytes) = <[u8; 66]>::try_from(data) else { return };
    for (mode, strict) in [(Mode::Strict, true), (Mode::EcpyCompat, false)] {
        let ours = VerifyingKey::from_bytes_with_mode(&bytes, mode);
        assert_eq!(ours.is_ok(), decode(&bytes, strict).is_some(), "{mode:?}");
        if let Ok(key) = ours {
            assert_eq!(key.to_bytes(), bytes);
        }
    }
});

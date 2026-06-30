//! Round-trip tests for the post-quantum HPKE ciphersuites used by the MLS PQ
//! ciphersuites draft (draft-ietf-mls-pq-ciphersuites), implemented in the
//! libcrux provider behind the `draft-ietf-hpke-pq` feature.
//!
//! These exercise seal/open, secret export, and `DeriveKeyPair` for every KEM
//! required by the MLS suites, paired with the SHAKE256 KDF and AES-GCM. They
//! confirm internal consistency (round-trips); byte-exact interop still needs
//! the draft Appendix test vectors.

#![cfg(feature = "draft-ietf-hpke-pq")]

extern crate hpke_rs as hpke;

use hpke::prelude::*;
use hpke_rs_crypto::types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
use hpke_rs_libcrux::HpkeLibcrux;

/// Every (KEM, AEAD) combination the MLS PQ ciphersuites need; all use the
/// SHAKE256 KDF.
const SUITES: &[(KemAlgorithm, AeadAlgorithm)] = &[
    (KemAlgorithm::MlKem512, AeadAlgorithm::Aes128Gcm),
    (KemAlgorithm::MlKem768, AeadAlgorithm::Aes256Gcm),
    (KemAlgorithm::MlKem1024, AeadAlgorithm::Aes256Gcm),
    (KemAlgorithm::XWingDraft06, AeadAlgorithm::Aes128Gcm),
    (KemAlgorithm::XWingDraft06, AeadAlgorithm::Aes256Gcm),
    (KemAlgorithm::MlKem768P256, AeadAlgorithm::Aes128Gcm),
    (KemAlgorithm::MlKem768P256, AeadAlgorithm::Aes256Gcm),
    #[cfg(feature = "libcrux-rustcrypto-p-curves")]
    (KemAlgorithm::MlKem1024P384, AeadAlgorithm::Aes256Gcm),
];

fn hpke(kem: KemAlgorithm, aead: AeadAlgorithm) -> Hpke<HpkeLibcrux> {
    Hpke::<HpkeLibcrux>::new(HpkeMode::Base, kem, KdfAlgorithm::Shake256, aead)
}

#[test]
fn seal_open_round_trip() {
    let info = b"test info";
    let aad = b"test aad";
    let msg = b"post-quantum HPKE round trip";

    for &(kem, aead) in SUITES {
        let mut sender = hpke(kem, aead);
        let kp = sender.generate_key_pair().expect("key gen");
        let pk_r = kp.public_key().clone();

        let (enc, ct) = sender
            .seal(&pk_r, info, aad, msg, None, None, None)
            .unwrap_or_else(|e| panic!("seal failed for {kem:?}/{aead:?}: {e:?}"));

        let receiver = hpke(kem, aead);
        let pt = receiver
            .open(&enc, kp.private_key(), info, aad, &ct, None, None, None)
            .unwrap_or_else(|e| panic!("open failed for {kem:?}/{aead:?}: {e:?}"));

        assert_eq!(pt, msg, "round-trip mismatch for {kem:?}/{aead:?}");
    }
}

#[test]
fn derive_key_pair_is_deterministic_and_usable() {
    let ikm = [42u8; 64];
    let info = b"";
    let aad = b"";
    let msg = b"derived key pair";

    for &(kem, aead) in SUITES {
        let sender = hpke(kem, aead);

        // DeriveKeyPair must be deterministic in the input key material.
        let kp1 = sender.derive_key_pair(&ikm).expect("derive 1");
        let kp2 = sender.derive_key_pair(&ikm).expect("derive 2");
        assert_eq!(
            kp1.public_key().as_slice(),
            kp2.public_key().as_slice(),
            "DeriveKeyPair not deterministic for {kem:?}"
        );

        // ... and the derived key pair must work end-to-end.
        let mut sender = hpke(kem, aead);
        let (enc, ct) = sender
            .seal(kp1.public_key(), info, aad, msg, None, None, None)
            .expect("seal with derived key");
        let receiver = hpke(kem, aead);
        let pt = receiver
            .open(&enc, kp1.private_key(), info, aad, &ct, None, None, None)
            .expect("open with derived key");
        assert_eq!(pt, msg, "derived-key round-trip mismatch for {kem:?}");
    }
}

#[test]
fn export_secret_matches() {
    let info = b"export info";
    let exporter_context = b"context";

    for &(kem, aead) in SUITES {
        let mut sender = hpke(kem, aead);
        let kp = sender.generate_key_pair().expect("key gen");

        let (enc, sender_secret) = sender
            .send_export(
                kp.public_key(),
                info,
                None,
                None,
                None,
                exporter_context,
                32,
            )
            .expect("send_export");

        let receiver = hpke(kem, aead);
        let receiver_secret = receiver
            .receiver_export(
                &enc,
                kp.private_key(),
                info,
                None,
                None,
                None,
                exporter_context,
                32,
            )
            .expect("receiver_export");

        assert_eq!(
            sender_secret, receiver_secret,
            "exporter mismatch for {kem:?}"
        );
    }
}

/// The one-stage (SHAKE) key schedule length-prefixes `psk`/`psk_id`/`info`
/// with a 2-byte prefix, so any of those exceeding `u16::MAX` bytes must be
/// rejected rather than silently truncated.
#[test]
fn over_long_info_is_rejected() {
    let (kem, aead) = (KemAlgorithm::MlKem768, AeadAlgorithm::Aes256Gcm);
    let mut sender = hpke(kem, aead);
    let kp = sender
        .generate_key_pair()
        .expect("key gen failed unexpectedly");

    // One byte past what a 2-byte length prefix can encode.
    let info = vec![0u8; u16::MAX as usize + 1];

    let err = sender
        .seal(kp.public_key(), &info, b"", b"msg", None, None, None)
        .expect_err("over-long info must be rejected");
    assert_eq!(err, HpkeError::InvalidInput);
}

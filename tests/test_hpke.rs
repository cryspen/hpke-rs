#![allow(non_snake_case)]

extern crate hpke_rs as hpke;

use hpke::prelude::*;
use hpke_crypto_trait::types::{AeadType, KdfType, KemType};
use lazy_static::lazy_static;
use rand::{rngs::OsRng, RngCore};
use rust_crypto_provider::HpkeRustCrypto;

lazy_static! {
    static ref TEST_CASES: Vec<(Mode, KemType, KdfType, AeadType)> = {
        let mut tests = Vec::new();
        for mode in 0u8..4 {
            let hpke_mode = Mode::try_from(mode).unwrap();
            for aead_mode in 1u16..4 {
                let aead_mode = AeadType::try_from(aead_mode).unwrap();
                for kdf_mode in 1u16..4 {
                    let kdf_mode = KdfType::try_from(kdf_mode).unwrap();
                    for &kem_mode in &[0x10u16, 0x20] {
                        let kem_mode = KemType::try_from(kem_mode).unwrap();
                        tests.push((hpke_mode, kem_mode, kdf_mode, aead_mode));
                        println!(
                            "generate_test_case!({}, HpkeMode::{:?}, KemType::{:?}, KdfType::{:?}, AeadType::{:?});",
                            Hpke::<HpkeRustCrypto>::new(hpke_mode, kem_mode, kdf_mode, aead_mode),
                            hpke_mode,
                            kem_mode,
                            kdf_mode,
                            aead_mode
                        );
                    }
                }
            }
        }
        tests
    };
}

macro_rules! generate_test_case {
    ($name:ident, $hpke_mode:expr, $kem_mode:expr, $kdf_mode:expr, $aead_mode:expr) => {
        #[test]
        fn $name() {
            let hpke = Hpke::<HpkeRustCrypto>::new($hpke_mode, $kem_mode, $kdf_mode, $aead_mode);
            println!("Self test {}", hpke);

            // Self test seal and open with random keys.
            let (sk_r, pk_r) = hpke.generate_key_pair().unwrap().into_keys();
            let (sk_s, pk_s) = hpke.generate_key_pair().unwrap().into_keys();
            let info = b"HPKE self test info";
            let aad = b"HPKE self test aad";
            let plain_txt = b"HPKE self test plain text";
            let exporter_context = b"HPKE self test exporter context";
            let mut psk = [0u8; 32];
            OsRng.fill_bytes(&mut psk);
            let mut psk_id = [0u8; 32];
            OsRng.fill_bytes(&mut psk_id);
            let (psk, psk_id): (Option<&[u8]>, Option<&[u8]>) = match $hpke_mode {
                Mode::Base | Mode::Auth => (None, None),
                Mode::Psk | Mode::AuthPsk => (Some(&psk), Some(&psk_id)),
            };
            let (sk_s_option, pk_s_option) = match $hpke_mode {
                Mode::Auth | Mode::AuthPsk => (Some(&sk_s), Some(&pk_s)),
                Mode::Psk | Mode::Base => (None, None),
            };
            let (enc, ctxt) = hpke
                .seal(&pk_r, info, aad, plain_txt, psk, psk_id, sk_s_option)
                .unwrap();
            let ptxt = hpke
                .open(&enc, &sk_r, info, aad, &ctxt, psk, psk_id, pk_s_option)
                .unwrap();
            assert_eq!(ptxt, plain_txt);

            // Exporter test
            let (enc, sender_exporter) = hpke
                .send_export(&pk_r, info, psk, psk_id, sk_s_option, exporter_context, 64)
                .unwrap();
            let receiver_exporter = hpke
                .receiver_export(
                    &enc,
                    &sk_r,
                    info,
                    psk,
                    psk_id,
                    pk_s_option,
                    exporter_context,
                    64,
                )
                .unwrap();
            assert_eq!(sender_exporter, receiver_exporter);

            // Self test with context
            let (enc, mut sender_context) = hpke
                .setup_sender(&pk_r, info, psk, psk_id, sk_s_option)
                .unwrap();
            let mut receiver_context = hpke
                .setup_receiver(&enc, &sk_r, info, psk, psk_id, pk_s_option)
                .unwrap();

            for _ in 0..17 {
                let ctxt = sender_context.seal(aad, plain_txt).unwrap();
                let ptxt = receiver_context.open(aad, &ctxt).unwrap();
                assert_eq!(ptxt, plain_txt);
            }

            // Exporter test
            let sender_exporter = sender_context.export(exporter_context, 64);
            let receiver_exporter = receiver_context.export(exporter_context, 64);
            assert_eq!(sender_exporter, receiver_exporter);
        }
    };
}

generate_test_case!(
    base_dhkemp256_hkdfsha256_Aes128Gcm,
    HpkeMode::Base,
    KemType::DhKemP256,
    KdfType::HkdfSha256,
    AeadType::Aes128Gcm
);
generate_test_case!(
    base_dhkem25519_hkdfsha256_Aes128Gcm,
    HpkeMode::Base,
    KemType::DhKem25519,
    KdfType::HkdfSha256,
    AeadType::Aes128Gcm
);
generate_test_case!(
    base_dhkemp256_hkdfsha384_Aes128Gcm,
    HpkeMode::Base,
    KemType::DhKemP256,
    KdfType::HkdfSha384,
    AeadType::Aes128Gcm
);
generate_test_case!(
    base_dhkem25519_hkdfsha384_Aes128Gcm,
    HpkeMode::Base,
    KemType::DhKem25519,
    KdfType::HkdfSha384,
    AeadType::Aes128Gcm
);
generate_test_case!(
    base_dhkemp256_hkdfsha512_Aes128Gcm,
    HpkeMode::Base,
    KemType::DhKemP256,
    KdfType::HkdfSha512,
    AeadType::Aes128Gcm
);
generate_test_case!(
    base_dhkem25519_hkdfsha512_Aes128Gcm,
    HpkeMode::Base,
    KemType::DhKem25519,
    KdfType::HkdfSha512,
    AeadType::Aes128Gcm
);
generate_test_case!(
    base_dhkemp256_hkdfsha256_Aes256Gcm,
    HpkeMode::Base,
    KemType::DhKemP256,
    KdfType::HkdfSha256,
    AeadType::Aes256Gcm
);
generate_test_case!(
    base_dhkem25519_hkdfsha256_Aes256Gcm,
    HpkeMode::Base,
    KemType::DhKem25519,
    KdfType::HkdfSha256,
    AeadType::Aes256Gcm
);
generate_test_case!(
    base_dhkemp256_hkdfsha384_Aes256Gcm,
    HpkeMode::Base,
    KemType::DhKemP256,
    KdfType::HkdfSha384,
    AeadType::Aes256Gcm
);
generate_test_case!(
    base_dhkem25519_hkdfsha384_Aes256Gcm,
    HpkeMode::Base,
    KemType::DhKem25519,
    KdfType::HkdfSha384,
    AeadType::Aes256Gcm
);
generate_test_case!(
    base_dhkemp256_hkdfsha512_Aes256Gcm,
    HpkeMode::Base,
    KemType::DhKemP256,
    KdfType::HkdfSha512,
    AeadType::Aes256Gcm
);
generate_test_case!(
    base_dhkem25519_hkdfsha512_Aes256Gcm,
    HpkeMode::Base,
    KemType::DhKem25519,
    KdfType::HkdfSha512,
    AeadType::Aes256Gcm
);
generate_test_case!(
    base_dhkemp256_hkdfsha256_chacha20poly1305,
    HpkeMode::Base,
    KemType::DhKemP256,
    KdfType::HkdfSha256,
    AeadType::ChaCha20Poly1305
);
generate_test_case!(
    base_dhkem25519_hkdfsha256_chacha20poly1305,
    HpkeMode::Base,
    KemType::DhKem25519,
    KdfType::HkdfSha256,
    AeadType::ChaCha20Poly1305
);
generate_test_case!(
    base_dhkemp256_hkdfsha384_chacha20poly1305,
    HpkeMode::Base,
    KemType::DhKemP256,
    KdfType::HkdfSha384,
    AeadType::ChaCha20Poly1305
);
generate_test_case!(
    base_dhkem25519_hkdfsha384_chacha20poly1305,
    HpkeMode::Base,
    KemType::DhKem25519,
    KdfType::HkdfSha384,
    AeadType::ChaCha20Poly1305
);
generate_test_case!(
    base_dhkemp256_hkdfsha512_chacha20poly1305,
    HpkeMode::Base,
    KemType::DhKemP256,
    KdfType::HkdfSha512,
    AeadType::ChaCha20Poly1305
);
generate_test_case!(
    base_dhkem25519_hkdfsha512_chacha20poly1305,
    HpkeMode::Base,
    KemType::DhKem25519,
    KdfType::HkdfSha512,
    AeadType::ChaCha20Poly1305
);
generate_test_case!(
    psk_dhkemp256_hkdfsha256_Aes128Gcm,
    HpkeMode::Psk,
    KemType::DhKemP256,
    KdfType::HkdfSha256,
    AeadType::Aes128Gcm
);
generate_test_case!(
    psk_dhkem25519_hkdfsha256_Aes128Gcm,
    HpkeMode::Psk,
    KemType::DhKem25519,
    KdfType::HkdfSha256,
    AeadType::Aes128Gcm
);
generate_test_case!(
    psk_dhkemp256_hkdfsha384_Aes128Gcm,
    HpkeMode::Psk,
    KemType::DhKemP256,
    KdfType::HkdfSha384,
    AeadType::Aes128Gcm
);
generate_test_case!(
    psk_dhkem25519_hkdfsha384_Aes128Gcm,
    HpkeMode::Psk,
    KemType::DhKem25519,
    KdfType::HkdfSha384,
    AeadType::Aes128Gcm
);
generate_test_case!(
    psk_dhkemp256_hkdfsha512_Aes128Gcm,
    HpkeMode::Psk,
    KemType::DhKemP256,
    KdfType::HkdfSha512,
    AeadType::Aes128Gcm
);
generate_test_case!(
    psk_dhkem25519_hkdfsha512_Aes128Gcm,
    HpkeMode::Psk,
    KemType::DhKem25519,
    KdfType::HkdfSha512,
    AeadType::Aes128Gcm
);
generate_test_case!(
    psk_dhkemp256_hkdfsha256_Aes256Gcm,
    HpkeMode::Psk,
    KemType::DhKemP256,
    KdfType::HkdfSha256,
    AeadType::Aes256Gcm
);
generate_test_case!(
    psk_dhkem25519_hkdfsha256_Aes256Gcm,
    HpkeMode::Psk,
    KemType::DhKem25519,
    KdfType::HkdfSha256,
    AeadType::Aes256Gcm
);
generate_test_case!(
    psk_dhkemp256_hkdfsha384_Aes256Gcm,
    HpkeMode::Psk,
    KemType::DhKemP256,
    KdfType::HkdfSha384,
    AeadType::Aes256Gcm
);
generate_test_case!(
    psk_dhkem25519_hkdfsha384_Aes256Gcm,
    HpkeMode::Psk,
    KemType::DhKem25519,
    KdfType::HkdfSha384,
    AeadType::Aes256Gcm
);
generate_test_case!(
    psk_dhkemp256_hkdfsha512_Aes256Gcm,
    HpkeMode::Psk,
    KemType::DhKemP256,
    KdfType::HkdfSha512,
    AeadType::Aes256Gcm
);
generate_test_case!(
    psk_dhkem25519_hkdfsha512_Aes256Gcm,
    HpkeMode::Psk,
    KemType::DhKem25519,
    KdfType::HkdfSha512,
    AeadType::Aes256Gcm
);
generate_test_case!(
    psk_dhkemp256_hkdfsha256_chacha20poly1305,
    HpkeMode::Psk,
    KemType::DhKemP256,
    KdfType::HkdfSha256,
    AeadType::ChaCha20Poly1305
);
generate_test_case!(
    psk_dhkem25519_hkdfsha256_chacha20poly1305,
    HpkeMode::Psk,
    KemType::DhKem25519,
    KdfType::HkdfSha256,
    AeadType::ChaCha20Poly1305
);
generate_test_case!(
    psk_dhkemp256_hkdfsha384_chacha20poly1305,
    HpkeMode::Psk,
    KemType::DhKemP256,
    KdfType::HkdfSha384,
    AeadType::ChaCha20Poly1305
);
generate_test_case!(
    psk_dhkem25519_hkdfsha384_chacha20poly1305,
    HpkeMode::Psk,
    KemType::DhKem25519,
    KdfType::HkdfSha384,
    AeadType::ChaCha20Poly1305
);
generate_test_case!(
    psk_dhkemp256_hkdfsha512_chacha20poly1305,
    HpkeMode::Psk,
    KemType::DhKemP256,
    KdfType::HkdfSha512,
    AeadType::ChaCha20Poly1305
);
generate_test_case!(
    psk_dhkem25519_hkdfsha512_chacha20poly1305,
    HpkeMode::Psk,
    KemType::DhKem25519,
    KdfType::HkdfSha512,
    AeadType::ChaCha20Poly1305
);
generate_test_case!(
    auth_dhkemp256_hkdfsha256_Aes128Gcm,
    HpkeMode::Auth,
    KemType::DhKemP256,
    KdfType::HkdfSha256,
    AeadType::Aes128Gcm
);
generate_test_case!(
    auth_dhkem25519_hkdfsha256_Aes128Gcm,
    HpkeMode::Auth,
    KemType::DhKem25519,
    KdfType::HkdfSha256,
    AeadType::Aes128Gcm
);
generate_test_case!(
    auth_dhkemp256_hkdfsha384_Aes128Gcm,
    HpkeMode::Auth,
    KemType::DhKemP256,
    KdfType::HkdfSha384,
    AeadType::Aes128Gcm
);
generate_test_case!(
    auth_dhkem25519_hkdfsha384_Aes128Gcm,
    HpkeMode::Auth,
    KemType::DhKem25519,
    KdfType::HkdfSha384,
    AeadType::Aes128Gcm
);
generate_test_case!(
    auth_dhkemp256_hkdfsha512_Aes128Gcm,
    HpkeMode::Auth,
    KemType::DhKemP256,
    KdfType::HkdfSha512,
    AeadType::Aes128Gcm
);
generate_test_case!(
    auth_dhkem25519_hkdfsha512_Aes128Gcm,
    HpkeMode::Auth,
    KemType::DhKem25519,
    KdfType::HkdfSha512,
    AeadType::Aes128Gcm
);
generate_test_case!(
    auth_dhkemp256_hkdfsha256_Aes256Gcm,
    HpkeMode::Auth,
    KemType::DhKemP256,
    KdfType::HkdfSha256,
    AeadType::Aes256Gcm
);
generate_test_case!(
    auth_dhkem25519_hkdfsha256_Aes256Gcm,
    HpkeMode::Auth,
    KemType::DhKem25519,
    KdfType::HkdfSha256,
    AeadType::Aes256Gcm
);
generate_test_case!(
    auth_dhkemp256_hkdfsha384_Aes256Gcm,
    HpkeMode::Auth,
    KemType::DhKemP256,
    KdfType::HkdfSha384,
    AeadType::Aes256Gcm
);
generate_test_case!(
    auth_dhkem25519_hkdfsha384_Aes256Gcm,
    HpkeMode::Auth,
    KemType::DhKem25519,
    KdfType::HkdfSha384,
    AeadType::Aes256Gcm
);
generate_test_case!(
    auth_dhkemp256_hkdfsha512_Aes256Gcm,
    HpkeMode::Auth,
    KemType::DhKemP256,
    KdfType::HkdfSha512,
    AeadType::Aes256Gcm
);
generate_test_case!(
    auth_dhkem25519_hkdfsha512_Aes256Gcm,
    HpkeMode::Auth,
    KemType::DhKem25519,
    KdfType::HkdfSha512,
    AeadType::Aes256Gcm
);
generate_test_case!(
    auth_dhkemp256_hkdfsha256_chacha20poly1305,
    HpkeMode::Auth,
    KemType::DhKemP256,
    KdfType::HkdfSha256,
    AeadType::ChaCha20Poly1305
);
generate_test_case!(
    auth_dhkem25519_hkdfsha256_chacha20poly1305,
    HpkeMode::Auth,
    KemType::DhKem25519,
    KdfType::HkdfSha256,
    AeadType::ChaCha20Poly1305
);
generate_test_case!(
    auth_dhkemp256_hkdfsha384_chacha20poly1305,
    HpkeMode::Auth,
    KemType::DhKemP256,
    KdfType::HkdfSha384,
    AeadType::ChaCha20Poly1305
);
generate_test_case!(
    auth_dhkem25519_hkdfsha384_chacha20poly1305,
    HpkeMode::Auth,
    KemType::DhKem25519,
    KdfType::HkdfSha384,
    AeadType::ChaCha20Poly1305
);
generate_test_case!(
    auth_dhkemp256_hkdfsha512_chacha20poly1305,
    HpkeMode::Auth,
    KemType::DhKemP256,
    KdfType::HkdfSha512,
    AeadType::ChaCha20Poly1305
);
generate_test_case!(
    auth_dhkem25519_hkdfsha512_chacha20poly1305,
    HpkeMode::Auth,
    KemType::DhKem25519,
    KdfType::HkdfSha512,
    AeadType::ChaCha20Poly1305
);
generate_test_case!(
    authpsk_dhkemp256_hkdfsha256_Aes128Gcm,
    HpkeMode::AuthPsk,
    KemType::DhKemP256,
    KdfType::HkdfSha256,
    AeadType::Aes128Gcm
);
generate_test_case!(
    authpsk_dhkem25519_hkdfsha256_Aes128Gcm,
    HpkeMode::AuthPsk,
    KemType::DhKem25519,
    KdfType::HkdfSha256,
    AeadType::Aes128Gcm
);
generate_test_case!(
    authpsk_dhkemp256_hkdfsha384_Aes128Gcm,
    HpkeMode::AuthPsk,
    KemType::DhKemP256,
    KdfType::HkdfSha384,
    AeadType::Aes128Gcm
);
generate_test_case!(
    authpsk_dhkem25519_hkdfsha384_Aes128Gcm,
    HpkeMode::AuthPsk,
    KemType::DhKem25519,
    KdfType::HkdfSha384,
    AeadType::Aes128Gcm
);
generate_test_case!(
    authpsk_dhkemp256_hkdfsha512_Aes128Gcm,
    HpkeMode::AuthPsk,
    KemType::DhKemP256,
    KdfType::HkdfSha512,
    AeadType::Aes128Gcm
);
generate_test_case!(
    authpsk_dhkem25519_hkdfsha512_Aes128Gcm,
    HpkeMode::AuthPsk,
    KemType::DhKem25519,
    KdfType::HkdfSha512,
    AeadType::Aes128Gcm
);
generate_test_case!(
    authpsk_dhkemp256_hkdfsha256_Aes256Gcm,
    HpkeMode::AuthPsk,
    KemType::DhKemP256,
    KdfType::HkdfSha256,
    AeadType::Aes256Gcm
);
generate_test_case!(
    authpsk_dhkem25519_hkdfsha256_Aes256Gcm,
    HpkeMode::AuthPsk,
    KemType::DhKem25519,
    KdfType::HkdfSha256,
    AeadType::Aes256Gcm
);
generate_test_case!(
    authpsk_dhkemp256_hkdfsha384_Aes256Gcm,
    HpkeMode::AuthPsk,
    KemType::DhKemP256,
    KdfType::HkdfSha384,
    AeadType::Aes256Gcm
);
generate_test_case!(
    authpsk_dhkem25519_hkdfsha384_Aes256Gcm,
    HpkeMode::AuthPsk,
    KemType::DhKem25519,
    KdfType::HkdfSha384,
    AeadType::Aes256Gcm
);
generate_test_case!(
    authpsk_dhkemp256_hkdfsha512_Aes256Gcm,
    HpkeMode::AuthPsk,
    KemType::DhKemP256,
    KdfType::HkdfSha512,
    AeadType::Aes256Gcm
);
generate_test_case!(
    authpsk_dhkem25519_hkdfsha512_Aes256Gcm,
    HpkeMode::AuthPsk,
    KemType::DhKem25519,
    KdfType::HkdfSha512,
    AeadType::Aes256Gcm
);
generate_test_case!(
    authpsk_dhkemp256_hkdfsha256_chacha20poly1305,
    HpkeMode::AuthPsk,
    KemType::DhKemP256,
    KdfType::HkdfSha256,
    AeadType::ChaCha20Poly1305
);
generate_test_case!(
    authpsk_dhkem25519_hkdfsha256_chacha20poly1305,
    HpkeMode::AuthPsk,
    KemType::DhKem25519,
    KdfType::HkdfSha256,
    AeadType::ChaCha20Poly1305
);
generate_test_case!(
    authpsk_dhkemp256_hkdfsha384_chacha20poly1305,
    HpkeMode::AuthPsk,
    KemType::DhKemP256,
    KdfType::HkdfSha384,
    AeadType::ChaCha20Poly1305
);
generate_test_case!(
    authpsk_dhkem25519_hkdfsha384_chacha20poly1305,
    HpkeMode::AuthPsk,
    KemType::DhKem25519,
    KdfType::HkdfSha384,
    AeadType::ChaCha20Poly1305
);
generate_test_case!(
    authpsk_dhkemp256_hkdfsha512_chacha20poly1305,
    HpkeMode::AuthPsk,
    KemType::DhKemP256,
    KdfType::HkdfSha512,
    AeadType::ChaCha20Poly1305
);
generate_test_case!(
    authpsk_dhkem25519_hkdfsha512_chacha20poly1305,
    HpkeMode::AuthPsk,
    KemType::DhKem25519,
    KdfType::HkdfSha512,
    AeadType::ChaCha20Poly1305
);

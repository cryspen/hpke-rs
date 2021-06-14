#[cfg(feature = "openmls-crypto-api")]
mod openmls_crypto_tests {
    use crypto_algorithms::{AeadType, AsymmetricKeyType, KdfType, KemKeyType};
    use evercrypt::{
        openmls_crypto::Evercrypt,
        sqlite_key_store::{KeyStore, Status},
    };
    use hpke_rs::Hpke;
    use openmls_crypto::{
        hpke::{HpkeOpen, HpkeSeal},
        key_generation::GenerateKeys,
    };

    #[test]
    fn key_gen() {
        let ks = KeyStore::default();

        // Generate KEM key pair and use it in HPKE.
        let (pk, sk_id) = Evercrypt::new_key_pair(
            &ks,
            AsymmetricKeyType::KemKey(KemKeyType::X25519),
            Status::Hidden,
            b"hidden x25519 key pair",
        )
        .expect("Error generating x25519 key pair");

        let (ct, enc) = Hpke::hpke_seal_to_pk(
            KdfType::HkdfSha256,
            AeadType::Aes128Gcm,
            &pk,
            b"info string",
            b"test aad",
            b"HPKE test payload",
        )
        .expect("Error sealing to PK");

        let msg = Hpke::hpke_open_with_sk(
            &ks,
            KdfType::HkdfSha256,
            AeadType::Aes128Gcm,
            &sk_id,
            &ct,
            &enc,
            b"info string",
            b"test aad",
        )
        .expect("Error opening HPKE.");
        assert_eq!(msg.as_slice(), b"HPKE test payload");
    }
}

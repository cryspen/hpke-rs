use std::convert::TryInto;

use crypto_algorithms::{AeadType, AsymmetricKeyType, KdfType, KemKeyType};
use openmls_crypto::{hpke::HpkeSeal, keys::PublicKey, secret::Secret};

use crate::{kem, Hpke, Mode as HpkeMode};

fn evercrypt_kem_type(
    key_type: AsymmetricKeyType,
) -> Result<kem::Mode, openmls_crypto::errors::Error> {
    match key_type {
        AsymmetricKeyType::KemKey(KemKeyType::P256) => Ok(kem::Mode::DhKemP256),
        AsymmetricKeyType::KemKey(KemKeyType::P384) => Ok(kem::Mode::DhKemP384),
        AsymmetricKeyType::KemKey(KemKeyType::P521) => Ok(kem::Mode::DhKemP521),
        AsymmetricKeyType::KemKey(KemKeyType::X25519) => Ok(kem::Mode::DhKem25519),
        AsymmetricKeyType::KemKey(KemKeyType::X448) => Ok(kem::Mode::DhKem448),
        _ => {
            return Err(openmls_crypto::errors::Error::UnsupportedAlgorithm(
                format!("{:?}", key_type),
            ))
        }
    }
}

impl HpkeSeal for Hpke {
    type KeyStoreType;
    type KeyStoreIndex;

    fn hpke_seal(
        key_store: &Self::KeyStoreType,
        kdf: KdfType,
        aead: AeadType,
        key_id: &Self::KeyStoreIndex,
        info: &[u8],
        aad: &[u8],
        payload: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), openmls_crypto::errors::Error> {
        let (pk_r, _): (PublicKey, _) = key_store.internal_read(key_id)?;
        Hpke::hpke_seal_to_pk(kdf, aead, &pk_r, info, aad, payload)
    }

    fn hpke_seal_to_pk(
        key_store: &Self::KeyStoreType,
        kdf: KdfType,
        aead: AeadType,
        key: &PublicKey,
        info: &[u8],
        aad: &[u8],
        payload: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), openmls_crypto::errors::Error> {
        let kem = evercrypt_kem_type(key.key_type())?;
        let hpke = Hpke::new(
            HpkeMode::Base,
            (kem as u16).try_into().unwrap(),
            (kdf as u16).try_into().unwrap(),
            (aead as u16).try_into().unwrap(),
        );
        let (kem_output, ciphertext) = hpke
            .seal(&key.as_slice().into(), info, aad, payload, None, None, None)
            .map_err(|e| {
                openmls_crypto::errors::Error::CryptoLibError(format!("HPKE Seal error: {:?}", e))
            })?;
        Ok((ciphertext, kem_output))
    }

    fn hpke_seal_secret(
        key_store: &Self::KeyStoreType,
        kdf: KdfType,
        aead: AeadType,
        key_id: &Self::KeyStoreIndex,
        info: &[u8],
        aad: &[u8],
        secret_id: &Self::KeyStoreIndex,
    ) -> Result<(Vec<u8>, Vec<u8>), openmls_crypto::errors::Error> {
        let (pk_r, _): (PublicKey, _) = key_store.internal_read(key_id)?;
        Self::hpke_seal_secret_to_pk(key_store, kdf, aead, &pk_r, info, aad, secret_id)
    }

    fn hpke_seal_secret_to_pk(
        key_store: &Self::KeyStoreType,
        kdf: KdfType,
        aead: AeadType,
        key: &PublicKey,
        info: &[u8],
        aad: &[u8],
        secret_id: &Self::KeyStoreIndex,
    ) -> Result<(Vec<u8>, Vec<u8>), openmls_crypto::errors::Error> {
        let kem = evercrypt_kem_type(key.key_type())?;
        let (secret, _): (Secret, _) = key_store.internal_read(secret_id)?;
        let hpke = Hpke::new(
            HpkeMode::Base,
            (kem as u16).try_into().unwrap(),
            (kdf as u16).try_into().unwrap(),
            (aead as u16).try_into().unwrap(),
        );
        let (kem_output, ciphertext) = hpke
            .seal(
                &key.as_slice().into(),
                info,
                aad,
                secret.as_slice(),
                None,
                None,
                None,
            )
            .map_err(|e| {
                openmls_crypto::errors::Error::CryptoLibError(format!("HPKE Seal error: {:?}", e))
            })?;
        Ok((ciphertext, kem_output))
    }
}

// impl HpkeOpen for KeyStore {
//     fn hpke_open_with_sk(
//         &self,
//         kdf: HpkeKdfType,
//         aead: AeadType,
//         key_id: &impl KeyStoreId,
//         cipher_text: &[u8],
//         kem_out: &KemOutput,
//         info: &[u8],
//         aad: &[u8],
//     ) -> Result<Plaintext, openmls_crypto::errors::Error> {
//         let (sk_r, _status): (PrivateKey, Status) = self.internal_read(key_id)?;
//         let kem = evercrypt_kem_type(sk_r.key_type())?;
//         let hpke = Hpke::new(
//             hpke::Mode::Base,
//             (kem as u16).try_into().unwrap(),
//             (kdf as u16).try_into().unwrap(),
//             (aead as u16).try_into().unwrap(),
//         );
//         let ptxt = hpke
//             .open(
//                 kem_out.as_slice(),
//                 &sk_r.as_slice().into(),
//                 info,
//                 aad,
//                 cipher_text,
//                 None,
//                 None,
//                 None,
//             )
//             .map_err(|e| Error::CryptoLibError(format!("HPKE Open error: {:?}", e)))?;
//         Ok(Plaintext::new(ptxt))
//     }
// }

// impl HpkeDerive for KeyStore {
//     fn derive_key_pair(
//         &self,
//         kem: HpkeKemType,
//         kdf: HpkeKdfType,
//         aead: AeadType,
//         ikm_id: &impl KeyStoreId,
//         private_key_id: &impl KeyStoreId,
//         label: &[u8],
//     ) -> Result<PublicKey, openmls_crypto::errors::Error> {
//         let (ikm, _status): (Secret, Status) = self.internal_read(ikm_id)?;
//         let hpke = Hpke::new(
//             hpke::Mode::Base,
//             (kem as u16).try_into().unwrap(),
//             (kdf as u16).try_into().unwrap(),
//             (aead as u16).try_into().unwrap(),
//         );
//         let key_pair = hpke
//             .derive_key_pair(ikm.as_slice())
//             .map_err(|e| Error::CryptoLibError(format!("HPKE Derive key pair error: {:?}", e)))?;
//         let (private_key, public_key) = key_pair.into_keys();
//         let key_type = AsymmetricKeyType::try_from(kem)?;
//         let public_key = PublicKey::from(key_type, public_key.as_slice(), label);
//         let private_key = PrivateKey::from(key_type, private_key.as_slice(), label, &public_key);
//         self.store(private_key_id, &private_key)?;
//         Ok(public_key)
//     }
// }

// // Generate KEM key pair and use it in HPKE.
// let (pk, sk_id) = ks
//     .new_key_pair(
//         AsymmetricKeyType::KemKey(KemKeyType::X25519),
//         Status::Hidden,
//         b"hidden x25519 key pair",
//     )
//     .expect("Error generating x25519 key pair");
// let err: Result<PrivateKey> = ks.read(&sk_id);
// assert_eq!(err.err(), Some(Error::ForbiddenExtraction));

// let (ct, enc) = ks
//     .hpke_seal_to_pk(
//         KdfType::HkdfSha256,
//         AeadType::Aes128Gcm,
//         &pk,
//         b"info string",
//         b"test aad",
//         b"HPKE test payload",
//     )
//     .expect("Error sealing to PK");

// let msg = ks
//     .hpke_open_with_sk(
//         KdfType::HkdfSha256,
//         AeadType::Aes128Gcm,
//         &sk_id,
//         &ct,
//         &enc,
//         b"info string",
//         b"test aad",
//     )
//     .expect("Error opening HPKE.");
// assert_eq!(msg.as_slice(), b"HPKE test payload");

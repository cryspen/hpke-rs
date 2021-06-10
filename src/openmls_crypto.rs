//! # OpenMLS Crypto API
//!
//! This module implements the [`openmls_crypto`] API for HPKE.

use std::convert::TryInto;

use crypto_algorithms::{AeadType, AsymmetricKeyType, HashType, KdfType, KemKeyType, KemType};
use evercrypt::{
    openmls_crypto::Evercrypt,
    sqlite_key_store::{KeyStoreTrait, PrivateKey},
};
use openmls_crypto::{
    hash::Hash,
    hpke::{HpkeDerive, HpkeOpen, HpkeSeal},
    keys::PublicKey,
    secret::Secret,
};

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
    type KeyStoreType = evercrypt::sqlite_key_store::KeyStore;
    type KeyStoreIndex = evercrypt::sqlite_key_store::KeyStoreId;

    fn hpke_seal(
        key_store: &Self::KeyStoreType,
        kdf: KdfType,
        aead: AeadType,
        key_id: &Self::KeyStoreIndex,
        info: &[u8],
        aad: &[u8],
        payload: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), openmls_crypto::errors::Error> {
        let (pk_r, _): (PublicKey, _) = key_store.unsafe_read(key_id)?;
        Hpke::hpke_seal_to_pk(kdf, aead, &pk_r, info, aad, payload)
    }

    fn hpke_seal_to_pk(
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
        let (pk_r, _): (PublicKey, _) = key_store.unsafe_read(key_id)?;
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
        let (secret, _): (Secret, _) = key_store.unsafe_read(secret_id)?;
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

impl HpkeOpen for Hpke {
    type KeyStoreType = evercrypt::sqlite_key_store::KeyStore;
    type KeyStoreIndex = evercrypt::sqlite_key_store::KeyStoreId;

    fn hpke_open_with_sk(
        key_store: &Self::KeyStoreType,
        kdf: KdfType,
        aead: AeadType,
        key_id: &Self::KeyStoreIndex,
        cipher_text: &[u8],
        kem_enc: &[u8],
        info: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, openmls_crypto::errors::Error> {
        let (sk_r, _): (PrivateKey, _) = key_store.unsafe_read(key_id)?;
        let kem = evercrypt_kem_type(sk_r.key_type())?;
        let hpke = Hpke::new(
            HpkeMode::Base,
            (kem as u16).try_into().unwrap(),
            (kdf as u16).try_into().unwrap(),
            (aead as u16).try_into().unwrap(),
        );
        let ptxt = hpke
            .open(
                kem_enc,
                &sk_r.as_slice().into(),
                info,
                aad,
                cipher_text,
                None,
                None,
                None,
            )
            .map_err(|e| {
                openmls_crypto::errors::Error::CryptoLibError(format!("HPKE Open error: {:?}", e))
            })?;
        Ok(ptxt)
    }
}

impl HpkeDerive for Hpke {
    type KeyStoreType = evercrypt::sqlite_key_store::KeyStore;
    type KeyStoreIndex = evercrypt::sqlite_key_store::KeyStoreId;

    fn derive_key_pair(
        key_store: &Self::KeyStoreType,
        kem: KemType,
        kdf: KdfType,
        aead: AeadType,
        ikm_id: &Self::KeyStoreIndex,
        label: &[u8],
    ) -> Result<(PublicKey, Self::KeyStoreIndex), openmls_crypto::errors::Error> {
        let (ikm, _): (Secret, _) = key_store.unsafe_read(ikm_id)?;
        let hpke = Hpke::new(
            HpkeMode::Base,
            (kem as u16).try_into().unwrap(),
            (kdf as u16).try_into().unwrap(),
            (aead as u16).try_into().unwrap(),
        );
        let key_pair = hpke.derive_key_pair(ikm.as_slice()).map_err(|e| {
            openmls_crypto::errors::Error::CryptoLibError(format!(
                "HPKE Derive key pair error: {:?}",
                e
            ))
        })?;
        let (private_key, public_key) = key_pair.into_keys();
        let key_type = AsymmetricKeyType::from(kem);
        let public_key = PublicKey::from(key_type, public_key.as_slice(), label);
        let private_key = PrivateKey::from(key_type, private_key.as_slice(), label, &public_key);

        let mut sha256 = Evercrypt::hasher(HashType::Sha2_256)?;
        sha256.update(label)?;
        sha256.update(public_key.as_slice())?;
        let mut private_key_id = [0u8; 32];
        private_key_id.clone_from_slice(&sha256.finish()?);

        key_store.store_with_status(
            &private_key_id,
            &private_key,
            evercrypt::sqlite_key_store::Status::Hidden,
        )?;
        Ok((public_key, private_key_id))
    }
}

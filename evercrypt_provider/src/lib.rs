//! # Evercrypt Provider
//!
//! An implementation of the HPKE crypto trait using evercrypt.

use evercrypt::prelude::*;
use hpke_crypto_trait::{
    error::Error,
    types::{AeadType, KdfType, KemType},
    HpkeCrypto,
};

/// The Evercrypt HPKE Provider
#[derive(Debug)]
pub struct HpkeEvercrypt {}

impl HpkeCrypto for HpkeEvercrypt {
    fn kdf_extract(alg: KdfType, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        match alg {
            KdfType::HkdfSha256 => hkdf_extract(HmacMode::Sha256, salt, ikm),
            KdfType::HkdfSha384 => hkdf_extract(HmacMode::Sha384, salt, ikm),
            KdfType::HkdfSha512 => hkdf_extract(HmacMode::Sha512, salt, ikm),
        }
    }

    fn kdf_expand(
        alg: KdfType,
        prk: &[u8],
        info: &[u8],
        output_size: usize,
    ) -> Result<Vec<u8>, Error> {
        Ok(match alg {
            KdfType::HkdfSha256 => hkdf_expand(HmacMode::Sha256, prk, info, output_size),
            KdfType::HkdfSha384 => hkdf_expand(HmacMode::Sha384, prk, info, output_size),
            KdfType::HkdfSha512 => hkdf_expand(HmacMode::Sha512, prk, info, output_size),
        })
    }

    fn kem_derive(alg: KemType, pk: &[u8], sk: &[u8]) -> Result<Vec<u8>, Error> {
        let evercrypt_mode = kem_key_type_to_mode(alg)?;
        ecdh_derive(evercrypt_mode, pk, sk)
            .map_err(|e| Error::CryptoLibraryError(format!("ECDH derive error: {:?}", e)))
    }

    fn kem_derive_base(alg: KemType, sk: &[u8]) -> Result<Vec<u8>, Error> {
        let evercrypt_mode = kem_key_type_to_mode(alg)?;
        ecdh_derive_base(evercrypt_mode, sk)
            .map_err(|e| Error::CryptoLibraryError(format!("ECDH derive base error: {:?}", e)))
            .map(|p| {
                if evercrypt_mode == EcdhMode::P256 {
                    nist_format_uncompressed(p)
                } else {
                    p
                }
            })
    }

    fn kem_key_gen(alg: KemType) -> Result<Vec<u8>, Error> {
        let evercrypt_mode = kem_key_type_to_mode(alg)?;
        ecdh::key_gen(evercrypt_mode)
            .map_err(|e| Error::CryptoLibraryError(format!("ECDH key gen error: {:?}", e)))
    }

    fn kem_validate_sk(alg: KemType, sk: &[u8]) -> Result<Vec<u8>, Error> {
        match alg {
            KemType::DhKemP256 => p256_validate_sk(&sk)
                .map_err(|e| Error::CryptoLibraryError(format!("ECDH invalid sk error: {:?}", e)))
                .map(|sk| sk.to_vec()),
            _ => Err(Error::UnknownKemAlgorithm),
        }
    }

    fn aead_seal(
        alg: AeadType,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        msg: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mode = aead_type_to_mode(alg)?;
        if nonce.len() != 12 {
            return Err(Error::AeadInvalidNonce);
        }

        let cipher = match Aead::new(mode, key) {
            Ok(c) => c,
            Err(_) => return Err(Error::CryptoLibraryError(format!("Invalid configuration"))),
        };

        cipher
            .encrypt_combined(&msg, &nonce, &aad)
            .map_err(|e| Error::CryptoLibraryError(format!("AEAD encrypt error: {:?}", e)))
    }

    fn aead_open(
        alg: AeadType,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        cipher_txt: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let nonce_length = Self::aead_nonce_length(alg);
        let mode = aead_type_to_mode(alg)?;
        if nonce.len() != nonce_length {
            return Err(Error::AeadInvalidNonce);
        }
        let tag_length = Self::aead_tag_length(alg);
        if cipher_txt.len() <= tag_length {
            return Err(Error::AeadInvalidCiphertext);
        }

        let cipher = match Aead::new(mode, key) {
            Ok(c) => c,
            Err(_) => return Err(Error::CryptoLibraryError(format!("Invalid configuration"))),
        };

        cipher
            .decrypt_combined(&cipher_txt, &nonce, &aad)
            .map_err(|e| Error::CryptoLibraryError(format!("AEAD decryption error: {:?}", e)))
    }
}

/// Prepend 0x04 for uncompressed NIST curve points.
#[inline(always)]
fn nist_format_uncompressed(mut pk: Vec<u8>) -> Vec<u8> {
    let mut tmp = Vec::with_capacity(pk.len() + 1);
    tmp.push(0x04);
    tmp.append(&mut pk);
    tmp
}

#[inline(always)]
fn kem_key_type_to_mode(alg: KemType) -> Result<EcdhMode, Error> {
    match alg {
        KemType::DhKem25519 => Ok(EcdhMode::X25519),
        KemType::DhKemP256 => Ok(EcdhMode::P256),
        _ => Err(Error::UnknownKemAlgorithm),
    }
}

#[inline(always)]
fn aead_type_to_mode(alg: AeadType) -> Result<AeadMode, Error> {
    match alg {
        AeadType::Aes128Gcm => Ok(AeadMode::Aes128Gcm),
        AeadType::Aes256Gcm => Ok(AeadMode::Aes256Gcm),
        AeadType::ChaCha20Poly1305 => Ok(AeadMode::Chacha20Poly1305),
        _ => Err(Error::UnknownKemAlgorithm),
    }
}

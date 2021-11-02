//! # Pure Rust Crypto Provider
//!
//! An implementation of the HPKE crypto trait using pure Rust crypto primitives.

use hpke_crypto_trait::{
    error::Error,
    types::{AeadType, KdfType, KemType},
    HpkeCrypto,
};
use p256::{elliptic_curve::ecdh::diffie_hellman, EncodedPoint, PublicKey, SecretKey};
use rand::rngs::OsRng;
use x25519_dalek_ng::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

mod aead;
mod hkdf;
use crate::aead::*;
use crate::hkdf::*;

/// The Rust Crypto HPKE Provider
#[derive(Debug)]
pub struct HpkeRustCrypto {}

impl HpkeCrypto for HpkeRustCrypto {
    fn kdf_extract(alg: KdfType, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        match alg {
            KdfType::HkdfSha256 => sha256_extract(salt, ikm),
            KdfType::HkdfSha384 => sha384_extract(salt, ikm),
            KdfType::HkdfSha512 => sha512_extract(salt, ikm),
        }
    }

    fn kdf_expand(
        alg: KdfType,
        prk: &[u8],
        info: &[u8],
        output_size: usize,
    ) -> Result<Vec<u8>, Error> {
        match alg {
            KdfType::HkdfSha256 => sha256_expand(prk, info, output_size),
            KdfType::HkdfSha384 => sha384_expand(prk, info, output_size),
            KdfType::HkdfSha512 => sha512_expand(prk, info, output_size),
        }
    }

    fn kem_derive(alg: KemType, pk: &[u8], sk: &[u8]) -> Result<Vec<u8>, Error> {
        match alg {
            KemType::DhKem25519 => {
                if sk.len() != 32 {
                    return Err(Error::KemInvalidSecretKey);
                }
                if pk.len() != 32 {
                    return Err(Error::KemInvalidPublicKey);
                }
                let mut sk_array = [0u8; 32];
                sk_array.clone_from_slice(sk);
                let mut pk_array = [0u8; 32];
                pk_array.clone_from_slice(pk);
                let sk = X25519StaticSecret::from(sk_array);
                Ok(sk
                    .diffie_hellman(&X25519PublicKey::from(pk_array))
                    .as_bytes()
                    .to_vec())
            }
            KemType::DhKemP256 => {
                let sk = SecretKey::from_bytes(sk).map_err(|_| Error::KemInvalidSecretKey)?;
                let pk = PublicKey::from_sec1_bytes(pk).map_err(|_| Error::KemInvalidPublicKey)?;
                Ok(diffie_hellman(sk.to_secret_scalar(), pk.as_affine())
                    .as_bytes()
                    .as_slice()
                    .into())
            }
            _ => Err(Error::UnknownKemAlgorithm),
        }
    }

    fn kem_derive_base(alg: KemType, sk: &[u8]) -> Result<Vec<u8>, Error> {
        match alg {
            KemType::DhKem25519 => {
                if sk.len() != 32 {
                    return Err(Error::KemInvalidSecretKey);
                }
                let mut sk_array = [0u8; 32];
                sk_array.clone_from_slice(sk);
                let sk = X25519StaticSecret::from(sk_array);
                Ok(X25519PublicKey::from(&sk).as_bytes().to_vec())
            }
            KemType::DhKemP256 => {
                let sk = SecretKey::from_bytes(sk).map_err(|_| Error::KemInvalidSecretKey)?;
                Ok(EncodedPoint::encode(
                    PublicKey::from_secret_scalar(&sk.to_secret_scalar()),
                    false,
                )
                .as_bytes()
                .into())
            }
            _ => Err(Error::UnknownKemAlgorithm),
        }
    }

    fn kem_key_gen(alg: KemType) -> Result<Vec<u8>, Error> {
        match alg {
            KemType::DhKem25519 => Ok(X25519StaticSecret::new(&mut OsRng).to_bytes().to_vec()),
            KemType::DhKemP256 => Ok(SecretKey::random(&mut OsRng).to_bytes().as_slice().into()),
            _ => Err(Error::UnknownKemAlgorithm),
        }
    }

    fn kem_validate_sk(alg: KemType, sk: &[u8]) -> Result<Vec<u8>, Error> {
        match alg {
            KemType::DhKemP256 => SecretKey::from_bytes(sk)
                .map_err(|_| Error::KemInvalidSecretKey)
                .map(|_| sk.into()),
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
        match alg {
            AeadType::Aes128Gcm => aes128_seal(key, nonce, aad, msg),
            AeadType::Aes256Gcm => aes256_seal(key, nonce, aad, msg),
            AeadType::ChaCha20Poly1305 => chacha_seal(key, nonce, aad, msg),
            AeadType::HpkeExport => Err(Error::UnknownAeadAlgorithm),
        }
    }

    fn aead_open(
        alg: AeadType,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        msg: &[u8],
    ) -> Result<Vec<u8>, Error> {
        match alg {
            AeadType::Aes128Gcm => aes128_open(alg, key, nonce, aad, msg),
            AeadType::Aes256Gcm => aes256_open(alg, key, nonce, aad, msg),
            AeadType::ChaCha20Poly1305 => chacha_open(alg, key, nonce, aad, msg),
            AeadType::HpkeExport => Err(Error::UnknownAeadAlgorithm),
        }
    }
}

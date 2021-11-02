//! # HPKE Crypto Traits
//!
//! The [`hpke-rs`] can be used with different cryptography backends to perform
//! the actual cryptographic operations.
//! This crate defines traits that have to be passed into HPKE functions that
//! implement the cryptographic primitives needed.

use error::Error;
use types::{AeadType, KemType};

pub mod error;
pub mod types;

pub trait HpkeCrypto: core::fmt::Debug + Send + Sync {
    /// Get the length of the output digest.
    #[inline(always)]
    fn kdf_digest_length(alg: types::KdfType) -> usize {
        match alg {
            types::KdfType::HkdfSha256 => 32,
            types::KdfType::HkdfSha384 => 48,
            types::KdfType::HkdfSha512 => 64,
        }
    }

    /// KDF Extract
    fn kdf_extract(alg: types::KdfType, salt: &[u8], ikm: &[u8]) -> Vec<u8>;

    /// KDF Expand
    fn kdf_expand(
        alg: types::KdfType,
        prk: &[u8],
        info: &[u8],
        output_size: usize,
    ) -> Result<Vec<u8>, Error>;

    /// KEM Derive
    fn kem_derive(alg: KemType, pk: &[u8], sk: &[u8]) -> Result<Vec<u8>, Error>;

    /// KEM Derive with base
    fn kem_derive_base(alg: KemType, sk: &[u8]) -> Result<Vec<u8>, Error>;

    /// KEM Key generation
    fn kem_key_gen(alg: KemType) -> Result<Vec<u8>, Error>;

    /// Validate a secret key for its correctness.
    fn kem_validate_sk(alg: KemType, sk: &[u8]) -> Result<Vec<u8>, Error>;

    /// AEAD encrypt.
    fn aead_seal(
        alg: AeadType,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        msg: &[u8],
    ) -> Result<Vec<u8>, Error>;

    /// AEAD decrypt.
    fn aead_open(
        alg: AeadType,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        msg: &[u8],
    ) -> Result<Vec<u8>, Error>;

    /// Get key length for AEAD.
    ///
    /// Note that this function returns `0` for export only keys of unknown size.
    fn aead_key_length(alg: AeadType) -> usize {
        match alg {
            AeadType::Aes128Gcm => 16,
            AeadType::Aes256Gcm => 32,
            AeadType::ChaCha20Poly1305 => 32,
            AeadType::HpkeExport => 0,
        }
    }

    /// Get key length for AEAD.
    ///
    /// Note that this function returns `0` for export only nonces of unknown size.
    fn aead_nonce_length(alg: AeadType) -> usize {
        match alg {
            AeadType::Aes128Gcm => 12,
            AeadType::Aes256Gcm => 12,
            AeadType::ChaCha20Poly1305 => 12,
            AeadType::HpkeExport => 0,
        }
    }

    /// Get key length for AEAD.
    ///
    /// Note that this function returns `0` for export only tags of unknown size.
    fn aead_tag_length(alg: AeadType) -> usize {
        match alg {
            AeadType::Aes128Gcm => 16,
            AeadType::Aes256Gcm => 16,
            AeadType::ChaCha20Poly1305 => 16,
            AeadType::HpkeExport => 0,
        }
    }
}

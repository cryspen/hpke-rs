//! # HPKE Types
//!
//! Algorithm definitions for the [`HpkeCrypto`] trait.

use serde::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

use crate::error;

// /// KEM key types.
// /// This uses the TLS IANA parameters
// /// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
// #[derive(
//     Debug, PartialEq, Eq, Clone, Copy, TlsSerialize, TlsDeserialize, TlsSize, Serialize, Deserialize,
// )]
// #[repr(u16)]
// pub enum KemKeyType {
//     /// ECDH Curve25519 key
//     X25519 = 29,

//     /// ECDH Curve448 key
//     X448 = 30,

//     /// ECDH NIST P256 key (secp256r1)
//     P256 = 23,

//     /// ECDH NIST P384 key (secp384r1)
//     P384 = 24,

//     /// ECDH NIST P521 key (secp521r1)
//     P521 = 25,
// }

/// KEM Modes
#[derive(PartialEq, Copy, Clone, Debug, Serialize, Deserialize)]
#[repr(u16)]
pub enum KemType {
    /// DH KEM on P256
    DhKemP256 = 0x0010,

    /// DH KEM on P384
    DhKemP384 = 0x0011,

    /// DH KEM on P521
    DhKemP521 = 0x0012,

    /// DH KEM on x25519
    DhKem25519 = 0x0020,

    /// DH KEM on x448
    DhKem448 = 0x0021,
}

impl std::fmt::Display for KemType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::convert::TryFrom<u16> for KemType {
    type Error = error::Error;
    fn try_from(x: u16) -> Result<KemType, Self::Error> {
        match x {
            0x0010 => Ok(KemType::DhKemP256),
            0x0011 => Ok(KemType::DhKemP384),
            0x0012 => Ok(KemType::DhKemP521),
            0x0020 => Ok(KemType::DhKem25519),
            0x0021 => Ok(KemType::DhKem448),
            _ => Err(Self::Error::UnknownKemAlgorithm),
        }
    }
}

impl KemType {
    /// Get the length of the private key for the KEM in bytes.
    pub fn private_key_len(&self) -> usize {
        match self {
            KemType::DhKemP256 => 32,
            KemType::DhKemP384 => 48,
            KemType::DhKemP521 => 66,
            KemType::DhKem25519 => 32,
            KemType::DhKem448 => 56,
        }
    }

    /// Get the length of the shared secret for the KEM in bytes.
    pub fn shared_secret_len(&self) -> usize {
        match self {
            KemType::DhKemP256 => 32,
            KemType::DhKemP384 => 48,
            KemType::DhKemP521 => 64,
            KemType::DhKem25519 => 32,
            KemType::DhKem448 => 64,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize)]
#[repr(u16)]
/// AEAD types
pub enum AeadType {
    /// AES GCM 128
    Aes128Gcm = 0x0001,

    /// AES GCM 256
    Aes256Gcm = 0x0002,

    /// ChaCha20 Poly1305
    ChaCha20Poly1305 = 0x0003,

    /// HPKE Export-only
    HpkeExport = 0xFFFF,
}

impl std::fmt::Display for AeadType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::convert::TryFrom<u16> for AeadType {
    type Error = error::Error;
    fn try_from(x: u16) -> Result<AeadType, Self::Error> {
        match x {
            0x0001 => Ok(AeadType::Aes128Gcm),
            0x0002 => Ok(AeadType::Aes256Gcm),
            0x0003 => Ok(AeadType::ChaCha20Poly1305),
            0xFFFF => Ok(AeadType::HpkeExport),
            _ => Err(Self::Error::UnknownAeadAlgorithm),
        }
    }
}

impl AeadType {
    /// Get the tag size of the [`AeadType`] in bytes.
    ///
    /// Note that the function returns `0` for unknown lengths such as the
    /// [`AeadType::HpkeExport`] type.
    pub const fn tag_length(&self) -> usize {
        match self {
            AeadType::Aes128Gcm => 16,
            AeadType::Aes256Gcm => 16,
            AeadType::ChaCha20Poly1305 => 16,
            AeadType::HpkeExport => 0,
        }
    }

    /// Get the key size of the [`AeadType`] in bytes.
    ///
    /// Note that the function returns `0` for unknown lengths such as the
    /// [`AeadType::HpkeExport`] type.
    pub const fn key_length(&self) -> usize {
        match self {
            AeadType::Aes128Gcm => 16,
            AeadType::Aes256Gcm => 32,
            AeadType::ChaCha20Poly1305 => 32,
            AeadType::HpkeExport => 0,
        }
    }

    /// Get the nonce size of the [`AeadType`] in bytes.
    ///
    /// Note that the function returns `0` for unknown lengths such as the
    /// [`AeadType::HpkeExport`] type.
    ///
    /// Further note that while the AEAD mechanisms generally allow for different
    /// nonce lengths, this HPKE implementation expects the most common nonce size.
    pub const fn nonce_length(&self) -> usize {
        match self {
            AeadType::Aes128Gcm => 12,
            AeadType::Aes256Gcm => 12,
            AeadType::ChaCha20Poly1305 => 12,
            AeadType::HpkeExport => 0,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize)]
#[repr(u16)]
/// KDF types
/// Value are taken from the HPKE RFC (not published yet)
/// TODO: update when HPKE has been published and values have been registered with
///       IANA.
pub enum KdfType {
    /// HKDF SHA 256
    HkdfSha256 = 0x0001,

    /// HKDF SHA 384
    HkdfSha384 = 0x0002,

    /// HKDF SHA 512
    HkdfSha512 = 0x0003,
}

impl std::fmt::Display for KdfType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::convert::TryFrom<u16> for KdfType {
    type Error = error::Error;
    fn try_from(x: u16) -> Result<KdfType, Self::Error> {
        match x {
            0x0001 => Ok(KdfType::HkdfSha256),
            0x0002 => Ok(KdfType::HkdfSha384),
            0x0003 => Ok(KdfType::HkdfSha512),
            _ => Err(Self::Error::UnknownKdfAlgorithm),
        }
    }
}

impl From<KemType> for KdfType {
    fn from(kem: KemType) -> Self {
        match kem {
            KemType::DhKemP256 => KdfType::HkdfSha256,
            KemType::DhKemP384 => KdfType::HkdfSha384,
            KemType::DhKemP521 => KdfType::HkdfSha512,
            KemType::DhKem25519 => KdfType::HkdfSha256,
            KemType::DhKem448 => KdfType::HkdfSha512,
        }
    }
}

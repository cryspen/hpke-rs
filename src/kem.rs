use std::marker::PhantomData;

use hpke_crypto_trait::{
    error::Error,
    types::{KdfType, KemType},
    HpkeCrypto,
};
#[cfg(feature = "serialization")]
pub(crate) use serde::{Deserialize, Serialize};

use crate::dh_kem;
use crate::util;

// /// KEM Modes
// #[derive(PartialEq, Copy, Clone, Debug)]
// #[cfg_attr(feature = "serialization", derive(Serialize, Deserialize))]
// #[repr(u16)]
// pub enum Mode {
//     /// DH KEM on P256
//     DhKemP256 = 0x0010,

//     /// DH KEM on P384
//     DhKemP384 = 0x0011,

//     /// DH KEM on P521
//     DhKemP521 = 0x0012,

//     /// DH KEM on x25519
//     DhKem25519 = 0x0020,

//     /// DH KEM on x448
//     DhKem448 = 0x0021,
// }

// /// KEM key types.
// /// This uses the TLS IANA parameters
// /// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
// #[allow(dead_code)]
// #[cfg_attr(feature = "serialization", derive(Serialize, Deserialize))]
// #[derive(Debug, PartialEq, Eq, Clone, Copy)]
// #[repr(u16)]
// pub(crate) enum KemKeyType {
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

// /// KEM Errors
// #[derive(Debug)]
// pub enum Error {
//     /// The KEM mode is unknown.
//     UnknownMode,

//     /// A cryptographic operation failed.
//     CryptoError,

//     /// Key generation error.
//     KeyGenerationError,

//     /// Invalid secret key.
//     InvalidSecretKey,

//     /// Invalid public key.
//     InvalidPublicKey,
// }

// Map KEM to KDF according to spec.
fn kdf(mode: KemType) -> KdfType {
    match mode {
        KemType::DhKemP256 => KdfType::HkdfSha256,
        KemType::DhKemP384 => KdfType::HkdfSha384,
        KemType::DhKemP521 => KdfType::HkdfSha512,
        KemType::DhKem25519 => KdfType::HkdfSha256,
        KemType::DhKem448 => KdfType::HkdfSha512,
    }
}

pub(crate) type PrivateKey = Vec<u8>;
pub(crate) type PublicKey = Vec<u8>;

// pub(crate) trait KemTrait: std::fmt::Debug + Send + Sync {
//     fn new(kdf_id: KdfType) -> Self
//     where
//         Self: Sized;

//     fn key_gen(&self) -> Result<(Vec<u8>, Vec<u8>), Error>;
//     fn derive_key_pair(
//         &self,
//         suite_id: &[u8],
//         ikm: &[u8],
//     ) -> Result<(PublicKey, PrivateKey), Error>;

//     fn encaps(&self, pk_r: &[u8], suite_id: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error>;
//     fn decaps(&self, enc: &[u8], sk_r: &[u8], suite_id: &[u8]) -> Result<Vec<u8>, Error>;
//     fn auth_encaps(
//         &self,
//         pk_r: &[u8],
//         sk_s: &[u8],
//         suite_id: &[u8],
//     ) -> Result<(Vec<u8>, Vec<u8>), Error>;
//     fn auth_decaps(
//         &self,
//         enc: &[u8],
//         sk_r: &[u8],
//         pk_s: &[u8],
//         suite_id: &[u8],
//     ) -> Result<Vec<u8>, Error>;

//     fn secret_len(&self) -> usize;
//     fn encoded_pk_len(&self) -> usize;

//     #[cfg(feature = "deterministic")]
//     fn set_random(&mut self, r: &[u8]);
// }

// #[derive(Debug)]
// pub struct Kem<Crypto: HpkeCrypto> {
//     mode: Mode,
//     kem: Box<dyn KemTrait>,
//     phantom: PhantomData<Crypto>,
// }

// #[cfg(feature = "serialization")]
// impl<Crypto: HpkeCrypto> Serialize for Kem<Crypto> {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: serde::ser::Serializer,
//     {
//         self.mode.serialize(serializer)
//     }
// }

// #[cfg(feature = "serialization")]
// impl<'de, Crypto: 'static + HpkeCrypto> Deserialize<'de> for Kem<Crypto> {
//     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//     where
//         D: serde::Deserializer<'de>,
//     {
//         let mode = Mode::deserialize(deserializer)?;
//         Ok(Self::new(mode))
//     }
// }

// impl<Crypto: HpkeCrypto> std::fmt::Display for Kem<Crypto> {
//     fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
//         write!(f, "{}", self.mode)
//     }
// }

// fn kem_object<Crypto: 'static + HpkeCrypto>(mode: Mode, kdf_id: KdfType) -> Box<dyn KemTrait> {
//     match mode {
//         Mode::DhKem25519 => Box::new(dh_kem::DhKem::<Crypto>::init(kdf_id, KemKeyType::X25519)),
//         Mode::DhKemP256 => Box::new(dh_kem::DhKem::<Crypto>::init(kdf_id, KemKeyType::P256)),
//         _ => panic!("KEM {:?} is not implemented", mode),
//     }
// }

// impl<Crypto: 'static + HpkeCrypto> Kem<Crypto> {
//     pub(crate) fn new(mode: Mode) -> Self {
//         Self {
//             mode,
//             kem: kem_object::<Crypto>(mode, kdf(mode)),
//             phantom: PhantomData,
//         }
//     }

#[inline(always)]
fn ciphersuite(alg: KemType) -> Vec<u8> {
    util::concat(&[b"KEM", &(alg as u16).to_be_bytes()])
}

pub(crate) fn encaps<Crypto: HpkeCrypto>(
    alg: KemType,
    pk_r: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    match alg {
        KemType::DhKemP256
        | KemType::DhKemP384
        | KemType::DhKemP521
        | KemType::DhKem25519
        | KemType::DhKem448 => dh_kem::encaps::<Crypto>(alg, pk_r, &ciphersuite(alg)),
    }
}
pub(crate) fn decaps<Crypto: HpkeCrypto>(
    alg: KemType,
    enc: &[u8],
    sk_r: &[u8],
) -> Result<Vec<u8>, Error> {
    match alg {
        KemType::DhKemP256
        | KemType::DhKemP384
        | KemType::DhKemP521
        | KemType::DhKem25519
        | KemType::DhKem448 => dh_kem::decaps::<Crypto>(alg, enc, sk_r, &ciphersuite(alg)),
    }
}
pub(crate) fn auth_encaps<Crypto: HpkeCrypto>(
    alg: KemType,
    pk_r: &[u8],
    sk_s: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    match alg {
        KemType::DhKemP256
        | KemType::DhKemP384
        | KemType::DhKemP521
        | KemType::DhKem25519
        | KemType::DhKem448 => dh_kem::auth_encaps::<Crypto>(alg, pk_r, sk_s, &ciphersuite(alg)),
    }
}
pub(crate) fn auth_decaps<Crypto: HpkeCrypto>(
    alg: KemType,
    enc: &[u8],
    sk_r: &[u8],
    pk_s: &[u8],
) -> Result<Vec<u8>, Error> {
    match alg {
        KemType::DhKemP256
        | KemType::DhKemP384
        | KemType::DhKemP521
        | KemType::DhKem25519
        | KemType::DhKem448 => {
            dh_kem::auth_decaps::<Crypto>(alg, enc, sk_r, pk_s, &ciphersuite(alg))
        }
    }
}
pub(crate) fn key_gen<Crypto: HpkeCrypto>(alg: KemType) -> Result<(Vec<u8>, Vec<u8>), Error> {
    match alg {
        KemType::DhKemP256
        | KemType::DhKemP384
        | KemType::DhKemP521
        | KemType::DhKem25519
        | KemType::DhKem448 => dh_kem::key_gen::<Crypto>(alg),
    }
}

/// Derive key pair from the input key material `ikm`.
///
/// Returns (PublicKey, PrivateKey).
pub(crate) fn derive_key_pair<Crypto: HpkeCrypto>(
    alg: KemType,
    ikm: &[u8],
) -> Result<(PublicKey, PrivateKey), Error> {
    dh_kem::derive_key_pair::<Crypto>(alg, &ciphersuite(alg), ikm)
}

// #[cfg(feature = "deterministic")]
// pub(crate) fn set_random(&mut self, r: &[u8]) {
//     self.kem.set_random(r);
// }
// }

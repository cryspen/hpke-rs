use hpke_crypto_trait::{error::Error, types::KemType, HpkeCrypto};

use crate::dh_kem;
use crate::util;

pub(crate) type PrivateKey = Vec<u8>;
pub(crate) type PublicKey = Vec<u8>;

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

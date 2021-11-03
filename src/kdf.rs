use hpke_crypto_trait::{error::Error, types::KdfType, HpkeCrypto};

use crate::util::concat;

const HPKE_VERSION: &[u8] = b"HPKE-v1";

pub(crate) fn labeled_extract<Crypto: HpkeCrypto>(
    alg: KdfType,
    salt: &[u8],
    suite_id: &[u8],
    label: &str,
    ikm: &[u8],
) -> Vec<u8> {
    let labeled_ikm = concat(&[HPKE_VERSION, suite_id, label.as_bytes(), ikm]);
    Crypto::kdf_extract(alg, salt, &labeled_ikm)
}

pub(crate) fn labeled_expand<Crypto: HpkeCrypto>(
    alg: KdfType,
    prk: &[u8],
    suite_id: &[u8],
    label: &'static str,
    info: &[u8],
    len: usize,
) -> Result<Vec<u8>, Error> {
    debug_assert!(len < 256);
    let len_bytes = (len as u16).to_be_bytes();
    let labeled_info = concat(&[&len_bytes, HPKE_VERSION, suite_id, label.as_bytes(), info]);
    Crypto::kdf_expand(alg, prk, &labeled_info, len)
}

#[cfg(test)]
pub(crate) fn extract<Crypto: HpkeCrypto>(alg: KdfType, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    Crypto::kdf_extract(alg, salt, ikm)
}

#[cfg(test)]
pub(crate) fn expand<Crypto: HpkeCrypto>(
    alg: KdfType,
    prk: &[u8],
    info: &[u8],
    output_size: usize,
) -> Vec<u8> {
    match Crypto::kdf_expand(alg, prk, info, output_size) {
        Ok(r) => r,
        Err(_) => Vec::new(),
    }
}

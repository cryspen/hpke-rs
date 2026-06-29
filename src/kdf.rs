use alloc::vec::Vec;

use hpke_rs_crypto::{error::Error, types::KdfAlgorithm, HpkeCrypto};

use crate::util::concat;

const HPKE_VERSION: &[u8] = b"HPKE-v1";

#[inline]
/// requires: x.len() <= u16::MAX.
pub(crate) fn length_prefixed(x: &[u8]) -> Vec<u8> {
    concat(&[&(x.len() as u16).to_be_bytes(), x])
}

#[inline]
/// `LabeledDerive` for single-stage KDFs (draft-ietf-hpke-pq):
/// `Derive(ikm ‖ "HPKE-v1" ‖ suite_id ‖ I2OSP(len(label),2) ‖ label ‖ I2OSP(L,2) ‖ context, L)`.
///
/// `Derive(input, L)` is computed as `Expand(input, "", L)`, which the provider
/// implements as `SHAKE(input, 8*L)` for the single-stage KDFs.
pub(crate) fn labeled_derive<Crypto: HpkeCrypto>(
    alg: KdfAlgorithm,
    suite_id: &[u8],
    ikm: &[u8],
    label: &str,
    context: &[u8],
    len: usize,
) -> Result<Vec<u8>, Error> {
    if len > u16::MAX.into() {
        return Err(Error::HpkeInvalidOutputLength);
    }

    let labeled_ikm = shake256_labeled_ikm(suite_id, label, context, ikm, len);
    Crypto::kdf_expand(alg, &labeled_ikm, &[], len)
}

#[inline]
/// Build the `LabeledDerive` input for the single-stage KDFs:
/// `ikm ‖ "HPKE-v1" ‖ suite_id ‖ I2OSP(len(label),2) ‖ label ‖ I2OSP(L,2) ‖ context`.
///
/// requires: len <= u16::MAX.
pub(crate) fn shake256_labeled_ikm(
    suite_id: &[u8],
    label: &str,
    context: &[u8],
    ikm: &[u8],
    len: usize,
) -> Vec<u8> {
    concat(&[
        ikm,
        HPKE_VERSION,
        suite_id,
        &length_prefixed(label.as_bytes()),
        &(len as u16).to_be_bytes(),
        context,
    ])
}

#[inline]
pub(crate) fn labeled_extract<Crypto: HpkeCrypto>(
    alg: KdfAlgorithm,
    salt: &[u8],
    suite_id: &[u8],
    label: &str,
    ikm: &[u8],
) -> Result<Vec<u8>, Error> {
    let labeled_ikm = concat(&[HPKE_VERSION, suite_id, label.as_bytes(), ikm]);
    Crypto::kdf_extract(alg, salt, &labeled_ikm)
}

#[inline]
pub(crate) fn labeled_expand<Crypto: HpkeCrypto>(
    alg: KdfAlgorithm,
    prk: &[u8],
    suite_id: &[u8],
    label: &'static str,
    info: &[u8],
    len: usize,
) -> Result<Vec<u8>, Error> {
    if len > u16::MAX.into() {
        return Err(Error::HpkeInvalidOutputLength);
    }

    let len_bytes = (len as u16).to_be_bytes();
    let labeled_info = concat(&[&len_bytes, HPKE_VERSION, suite_id, label.as_bytes(), info]);
    Crypto::kdf_expand(alg, prk, &labeled_info, len)
}

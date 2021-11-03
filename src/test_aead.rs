use hpke_crypto_trait::{types::AeadType, HpkeCrypto};
use hpke_rust_crypto::HpkeRustCrypto;

#[test]
fn test_aes_gcm_128_self() {
    let key = [
        0x5b, 0x96, 0x04, 0xfe, 0x14, 0xea, 0xdb, 0xa9, 0x31, 0xb0, 0xcc, 0xf3, 0x48, 0x43, 0xda,
        0xb9,
    ];
    let nonce = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ];
    let aad = [0x03, 0x04, 0x05];
    let msg = b"test message";
    let ctxt = HpkeRustCrypto::aead_seal(AeadType::Aes128Gcm, &key, &nonce, &aad, msg).unwrap();
    let ptxt = HpkeRustCrypto::aead_open(AeadType::Aes128Gcm, &key, &nonce, &aad, &ctxt).unwrap();
    assert_eq!(&ptxt, msg);
}

use evercrypt::prelude::*;
use hpke::prelude::*;
use std::convert::TryFrom;

#[test]
fn test_self() {
    // XXX: Make these individual tests.
    for mode in 0u16..4 {
        let hpke_mode = Mode::try_from(mode).unwrap();
        for aead_mode in 1u16..4 {
            let aead_mode = HpkeAeadMode::try_from(aead_mode).unwrap();
            for kdf_mode in 1u16..4 {
                let kdf_mode = HpkeKdfMode::try_from(kdf_mode).unwrap();
                for &kem_mode in &[0x10u16, 0x20] {
                    let kem_mode = HpkeKemMode::try_from(kem_mode).unwrap();

                    let hpke = Hpke::new(hpke_mode, kem_mode, kdf_mode, aead_mode);

                    println!("Self test {:?}", hpke);

                    // Self test seal and open with random keys.
                    let (sk_r, pk_r) = hpke.generate_key_pair().into_keys();
                    let (sk_s, pk_s) = hpke.generate_key_pair().into_keys();
                    let info = b"HPKE self test info";
                    let aad = b"HPKE self test aad";
                    let plain_txt = b"HPKE self test plain text";
                    let psk = get_random_vec(32);
                    let psk_id = get_random_vec(32);
                    let (psk, psk_id): (Option<&[u8]>, Option<&[u8]>) = match hpke_mode {
                        Mode::Base | Mode::Auth => (None, None),
                        Mode::Psk | Mode::AuthPsk => (Some(&psk), Some(&psk_id)),
                    };
                    let (sk_s_seal, pk_s_open) = match hpke_mode {
                        Mode::Auth | Mode::AuthPsk => (Some(&sk_s), Some(&pk_s)),
                        Mode::Psk | Mode::Base => (None, None),
                    };
                    let (enc, ctxt) = hpke
                        .seal(&pk_r, info, aad, plain_txt, psk, psk_id, sk_s_seal)
                        .unwrap();
                    let ptxt = hpke
                        .open(&enc, &sk_r, info, aad, &ctxt, psk, psk_id, pk_s_open)
                        .unwrap();
                    assert_eq!(ptxt, plain_txt);
                }
            }
        }
    }
}

#![allow(non_snake_case)]

use hpke_rs_tests::{kat_fun, test_funs};

test_funs!(hpke_rs_rust_crypto::HpkeRustCrypto);
kat_fun!(hpke_rs_rust_crypto::HpkeRustCrypto);

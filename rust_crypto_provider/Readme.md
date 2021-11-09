# HPKE Crypto provider using native Rust

This crate provides an implementation of the [HpkeCrypto] trait using native Rust crypto implementations
([hkdf], [sha2], [p256], [p384], [x25519-dalek-ng], [chacha20poly1305], [aes-gcm]).

[hkdf]: https://docs.rs/hkdf/
[sha2]: https://docs.rs/sha2
[p256]: https://docs.rs/p256
[p384]: https://docs.rs/p384
[x25519-dalek-ng]: https://docs.rs/x25519-dalek-ng
[chacha20poly1305]: https://docs.rs/chacha20poly1305
[aes-gcm]: https://docs.rs/aes-gcm
[HpkeCrypto]: https://github.com/franziskuskiefer/hpke-rs/tree/main/traits

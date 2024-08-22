# Tests for Crypto Providers

This crate exposes macros that define crypto provider test functions.

## Usage

```rust
struct MyCryptoProvider;

impl hpke_rs_crypto::CryptoProvider for MyCryptoProvider {
    // ...
}

#[cfg(tests)]
mod tests {
    hpke_rs_tests::test_funs!(MyCryptoProvider);
    hpke_rs_tests::kat_fun!(MyCryptoProvider);
}
```
//! # HPKE Trait Errors
//!
//! Errors thrown by crypto functions implementing the [`HpkeCrypto`] traits.

use std::fmt::Display;

/// Errors thrown by [`HpkeCrypto`] trait implementations.
#[derive(Debug)]
pub enum Error {
    HpkeInvalidOutputLength,
    UnknownKdfAlgorithm,
    KemInvalidSecretKey,
    KemInvalidPublicKey,
    UnknownKemAlgorithm,
    UnknownAeadAlgorithm,
    AeadInvalidNonce,
    AeadOpenError,
    AeadInvalidCiphertext,
    InsufficientRandomness,
    CryptoLibraryError(String),
}

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HPKE Crypto Trait Error: {:?}", self)
    }
}

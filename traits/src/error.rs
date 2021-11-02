//! # HPKE Trait Errors
//! 
//! Errors thrown by crypto functions implementing the [`HpkeCrypto`] traits.

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
    CryptoLibraryError(String),
}

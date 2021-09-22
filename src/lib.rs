//! # Hybrid Public Key Encryption (HPKE).
//! <https://cfrg.github.io/draft-irtf-cfrg-hpke/draft-irtf-cfrg-hpke.html>
//!
//! From the RFC:
//! > This scheme provides a variant of public-key encryption of arbitrary-sized plaintexts for a recipient public key. It also includes three authenticated variants, including one which authenticates possession of a pre-shared key, and two optional ones which authenticate possession of a KEM private key.
//!
//! ## Cryptographic Provider
//! This crate does not implement its own cryptographic primitives.
//! Instead it uses cryptographic libraries or provider that implement the necessary
//! primitives.
//!
//! ## Supported algorithms
//! ### Evercrypt
//! Here we use the [Evercrypt Rust](https://github.com/franziskuskiefer/evercrypt-rust/)
//! bindings for the formally verified cryptography library [Evercrypt](https://github.com/project-everest/hacl-star).
//! * DHKEM(P-256, HKDF-SHA256)
//! * DHKEM(X25519, HKDF-SHA256)
//!
//! ### Rust Crypto
//!
//! ## A note on randomness
//! This crate does not generate its own randomness for key material.
//! Instead it relies on the cryptographic library used to generate random keys.

#![forbid(unsafe_code, unused_must_use, unstable_features)]
#![deny(
    trivial_casts,
    trivial_numeric_casts,
    missing_docs,
    unused_import_braces,
    unused_extern_crates,
    unused_qualifications
)]

#[cfg(feature = "serialization")]
pub(crate) use serde::{Deserialize, Serialize};

pub(crate) mod aead;
mod aead_impl;
mod dh_kem;
mod hkdf;
pub(crate) mod kdf;
pub(crate) mod kem;
pub mod prelude;

mod util;

#[cfg(test)]
mod test_aead;
#[cfg(test)]
mod test_kdf;

#[deprecated(
    since = "0.0.7",
    note = "Please use HpkeError instead. This alias will be removed with the first stable  0.1 release."
)]
#[allow(dead_code)]
#[allow(clippy::upper_case_acronyms)]
type HPKEError = HpkeError;

/// HPKE Error types.
#[derive(Debug, Clone, PartialEq)]
pub enum HpkeError {
    /// Error opening an HPKE ciphertext.
    OpenError,

    /// Invalid configuration or arguments.
    InvalidConfig,

    /// Invalid input.
    InvalidInput,

    /// Unknown HPKE mode.
    UnknownMode,

    /// Inconsistent PSK input.
    InconsistentPsk,

    /// PSK input is required but missing.
    MissingPsk,

    /// PSK input is provided but not needed.
    UnnecessaryPsk,

    /// PSK input is too short (needs to be at least 32 bytes).
    InsecurePsk,

    /// An error in the crypto library occurred.
    CryptoError,

    /// The message limit for this AEAD, key, and nonce.
    MessageLimitReached,
}

#[deprecated(
    since = "0.0.7",
    note = "Please use HpkePublicKey instead. This alias will be removed with the first stable  0.1 release."
)]
#[allow(clippy::upper_case_acronyms)]
#[allow(missing_docs)]
pub type HPKEPublicKey = HpkePublicKey;

/// An HPKE public key is a byte vector.
#[derive(Debug, PartialEq, Clone, Default)]
#[cfg_attr(feature = "serialization", derive(Serialize, Deserialize))]
pub struct HpkePublicKey {
    value: Vec<u8>,
}

#[deprecated(
    since = "0.0.7",
    note = "Please use HpkePrivateKey instead. This alias will be removed with the first stable  0.1 release."
)]
#[allow(clippy::upper_case_acronyms)]
#[allow(missing_docs)]
pub type HPKEPrivateKey = HpkePrivateKey;

/// An HPKE private key is a byte vector.
#[derive(Default)]
#[cfg_attr(feature = "serialization", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "hazmat", derive(Clone))]
pub struct HpkePrivateKey {
    value: Vec<u8>,
}

#[deprecated(
    since = "0.0.7",
    note = "Please use HpkeKeyPair instead. This alias will be removed with the first stable  0.1 release."
)]
#[allow(clippy::upper_case_acronyms)]
#[allow(missing_docs)]
pub type HPKEKeyPair = HpkeKeyPair;

/// An HPKE key pair has an HPKE private and public key.
#[derive(Debug, Default)]
#[cfg_attr(feature = "serialization", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "hazmat", derive(Clone))]
pub struct HpkeKeyPair {
    private_key: HpkePrivateKey,
    public_key: HpkePublicKey,
}

/// HPKE supports four modes.
#[derive(PartialEq, Copy, Clone, Debug)]
#[cfg_attr(feature = "serialization", derive(Serialize, Deserialize))]
#[repr(u8)]
pub enum Mode {
    /// HPKE Base mode.
    Base = 0x00,

    /// HPKE with PSK.
    Psk = 0x01,

    /// Authenticated HPKE.
    Auth = 0x02,

    /// Authenticated HPKE with PSK.
    AuthPsk = 0x03,
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::convert::TryFrom<u8> for Mode {
    type Error = HpkeError;
    fn try_from(x: u8) -> Result<Mode, HpkeError> {
        match x {
            0x00 => Ok(Mode::Base),
            0x01 => Ok(Mode::Psk),
            0x02 => Ok(Mode::Auth),
            0x03 => Ok(Mode::AuthPsk),
            _ => Err(HpkeError::UnknownMode),
        }
    }
}

/// Type alias for encapsulated secrets.
/// A byte vector.
type EncapsulatedSecret = Vec<u8>;

/// Type alias for ciphertexts.
/// A byte vector.
type Ciphertext = Vec<u8>;

/// Type alias for plain text.
/// A byte vector.
type Plaintext = Vec<u8>;

/// The HPKE context.
/// Note that the RFC currently doesn't define this.
/// Also see <https://github.com/cfrg/draft-irtf-cfrg-hpke/issues/161>.
pub struct Context<'a> {
    key: Vec<u8>,
    nonce: Vec<u8>,
    exporter_secret: Vec<u8>,
    sequence_number: u32,
    hpke: &'a Hpke,
}

#[cfg(feature = "hazmat")]
impl<'a> std::fmt::Debug for Context<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Context {{\n  key: {:?}\n  nonce: {:?}\n exporter_secret: {:?}\n seq no: {:?}\n}}",
            self.key, self.nonce, self.exporter_secret, self.sequence_number
        )
    }
}

#[cfg(not(feature = "hazmat"))]
impl<'a> std::fmt::Debug for Context<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Context {{\n  key: {:?}\n  nonce: {:?}\n exporter_secret: {:?}\n seq no: {:?}\n}}",
            &"***", &"***", &"***", &"***"
        )
    }
}

impl<'a> Context<'a> {
    /// 5.2. Encryption and Decryption
    ///
    /// Takes the associated data and the plain text as byte slices and returns
    /// the ciphertext or an error.
    ///
    /// ```text
    /// def Context.Seal(aad, pt):
    ///   ct = Seal(self.key, self.ComputeNonce(self.seq), aad, pt)
    ///   self.IncrementSeq()
    ///   return ct
    /// ```
    pub fn seal(&mut self, aad: &[u8], plain_txt: &[u8]) -> Result<Ciphertext, HpkeError> {
        let ctxt = self
            .hpke
            .aead
            .seal(&self.key, &self.compute_nonce(), aad, plain_txt)?;
        self.increment_seq()?;
        Ok(ctxt)
    }

    /// 5.2. Encryption and Decryption
    ///
    /// Takes the associated data and the ciphertext as byte slices and returns
    /// the plain text or an error.
    ///
    /// ```text
    /// def Context.Open(aad, ct):
    ///   pt = Open(self.key, self.ComputeNonce(self.seq), aad, ct)
    ///   if pt == OpenError:
    ///     raise OpenError
    ///   self.IncrementSeq()
    ///   return pt
    /// ```
    pub fn open(&mut self, aad: &[u8], cipher_txt: &[u8]) -> Result<Plaintext, HpkeError> {
        let ptxt = self
            .hpke
            .aead
            .open(&self.key, &self.compute_nonce(), aad, cipher_txt)?;
        self.increment_seq()?;
        Ok(ptxt)
    }

    /// 5.3. Secret Export
    ///
    /// Takes a serialised exporter context as byte slice and a length for the
    /// output secret and returns an exporter secret as byte vector.
    ///
    /// ```text
    /// def Context.Export(exporter_context, L):
    ///  return LabeledExpand(self.exporter_secret, "sec", exporter_context, L)
    ///```
    pub fn export(&self, exporter_context: &[u8], length: usize) -> Vec<u8> {
        self.hpke.kdf.labeled_expand(
            &self.exporter_secret,
            &self.hpke.ciphersuite(),
            "sec",
            exporter_context,
            length,
        )
    }

    /// def Context<ROLE>.ComputeNonce(seq):
    ///     seq_bytes = I2OSP(seq, Nn)
    ///     return xor(self.base_nonce, seq_bytes)
    fn compute_nonce(&self) -> Vec<u8> {
        let seq = self.sequence_number.to_be_bytes();
        let mut enc_seq = vec![0u8; self.nonce.len() - seq.len()];
        enc_seq.extend_from_slice(&seq);
        util::xor_bytes(&enc_seq, &self.nonce)
    }

    /// def Context<ROLE>.IncrementSeq():
    ///     if self.seq >= (1 << (8*Nn)) - 1:
    ///       raise MessageLimitReached
    ///     self.seq += 1
    fn increment_seq(&mut self) -> Result<(), HpkeError> {
        if self.sequence_number >= self.hpke.aead.message_limit() {
            return Err(HpkeError::MessageLimitReached);
        }
        self.sequence_number += 1;
        Ok(())
    }
}

/// The HPKE configuration struct.
/// This holds the configuration for HPKE but no state.
/// To use HPKE first instantiate the configuration with
/// `let hpke = Hpke::new(mode, kem_mode, kdf_mode, aead_mode)`.
/// Now one can use the `hpke` configuration.
#[derive(Debug)]
#[cfg_attr(feature = "serialization", derive(Serialize, Deserialize))]
pub struct Hpke {
    mode: Mode,
    kem_id: kem::Mode,
    kdf_id: kdf::Mode,
    aead_id: aead::Mode,
    kem: kem::Kem,
    kdf: kdf::Kdf,
    aead: aead::Aead,
    nk: usize,
    nn: usize,
    nh: usize,
}

impl std::fmt::Display for Hpke {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}_{}_{}_{}",
            self.mode.to_string().to_lowercase(),
            self.kem_id.to_string().to_lowercase(),
            self.kdf_id.to_string().to_lowercase(),
            self.aead_id.to_string().to_lowercase()
        )
    }
}

impl Hpke {
    /// Set up the configuration for HPKE.
    pub fn new(mode: Mode, kem_id: kem::Mode, kdf_id: kdf::Mode, aead_id: aead::Mode) -> Self {
        let kem = kem::Kem::new(kem_id);
        let kdf = kdf::Kdf::new(kdf_id);
        let aead = aead::Aead::new(aead_id);
        Self {
            mode,
            kem_id,
            kdf_id,
            aead_id,
            nk: aead.nk(),
            nn: aead.nn(),
            nh: kdf.nh(),
            kem,
            kdf,
            aead,
        }
    }

    /// Set up an HPKE sender.
    ///
    /// For the base and PSK modes this encapsulates the public key `pk_r`
    /// of the receiver.
    /// For the Auth and AuthPSK modes this encapsulates and authenticates
    /// the public key `pk_r` of the receiver with the senders secret key `sk_s`.
    ///
    /// The encapsulated secret is returned together with the context.
    /// If the secret key is missing in an authenticated mode, an error is returned.
    pub fn setup_sender(
        &self,
        pk_r: &HpkePublicKey,
        info: &[u8],
        psk: Option<&[u8]>,
        psk_id: Option<&[u8]>,
        sk_s: Option<&HpkePrivateKey>,
    ) -> Result<(EncapsulatedSecret, Context), HpkeError> {
        let (zz, enc) = match self.mode {
            Mode::Base | Mode::Psk => self.kem.encaps(pk_r.value.as_slice())?,
            Mode::Auth | Mode::AuthPsk => {
                let sk_s = match sk_s {
                    Some(s) => &s.value,
                    None => return Err(HpkeError::InvalidInput),
                };
                self.kem.auth_encaps(pk_r.value.as_slice(), sk_s)?
            }
        };
        Ok((
            enc,
            self.key_schedule(
                &zz,
                info,
                psk.unwrap_or_default(),
                psk_id.unwrap_or_default(),
            )?,
        ))
    }

    /// Set up an HPKE receiver.
    ///
    /// For the base and PSK modes this decapsulates `enc` with the secret key
    /// `sk_r` of the receiver.
    /// For the Auth and AuthPSK modes this decapsulates and authenticates `enc`
    /// with the secret key `sk_r` of the receiver and the senders public key `pk_s`.
    ///
    /// The context based on the decapsulated values and, if present, the PSK is
    /// returned.
    /// If the secret key is missing in an authenticated mode, an error is returned.
    pub fn setup_receiver(
        &self,
        enc: &[u8],
        sk_r: &HpkePrivateKey,
        info: &[u8],
        psk: Option<&[u8]>,
        psk_id: Option<&[u8]>,
        pk_s: Option<&HpkePublicKey>,
    ) -> Result<Context, HpkeError> {
        let zz = match self.mode {
            Mode::Base | Mode::Psk => self.kem.decaps(enc, &sk_r.value)?,
            Mode::Auth | Mode::AuthPsk => {
                let pk_s = match pk_s {
                    Some(s) => s.value.as_slice(),
                    None => return Err(HpkeError::InvalidInput),
                };
                self.kem.auth_decaps(enc, &sk_r.value, pk_s)?
            }
        };
        self.key_schedule(
            &zz,
            info,
            psk.unwrap_or_default(),
            psk_id.unwrap_or_default(),
        )
    }

    /// 6. Single-Shot APIs
    /// 6.1. Encryption and Decryption
    ///
    /// Single shot API to encrypt the bytes in `plain_text` to the public key
    /// `pk_r`.
    ///
    /// Returns the encapsulated secret and the ciphertext, or an error.
    #[allow(clippy::too_many_arguments)]
    pub fn seal(
        &self,
        pk_r: &HpkePublicKey,
        info: &[u8],
        aad: &[u8],
        plain_txt: &[u8],
        psk: Option<&[u8]>,
        psk_id: Option<&[u8]>,
        sk_s: Option<&HpkePrivateKey>,
    ) -> Result<(EncapsulatedSecret, Ciphertext), HpkeError> {
        let (enc, mut context) = self.setup_sender(pk_r, info, psk, psk_id, sk_s)?;
        let ctxt = context.seal(aad, plain_txt)?;
        Ok((enc, ctxt))
    }

    /// 6. Single-Shot APIs
    /// 6.1. Encryption and Decryption
    ///
    /// Single shot API to decrypt the bytes in `ct` with the private key `sk_r`.
    ///
    /// Returns the decrypted plain text, or an error.
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        &self,
        enc: &[u8],
        sk_r: &HpkePrivateKey,
        info: &[u8],
        aad: &[u8],
        ct: &[u8],
        psk: Option<&[u8]>,
        psk_id: Option<&[u8]>,
        pk_s: Option<&HpkePublicKey>,
    ) -> Result<Plaintext, HpkeError> {
        let mut context = self.setup_receiver(enc, sk_r, info, psk, psk_id, pk_s)?;
        context.open(aad, ct)
    }

    /// 6. Single-Shot APIs
    /// 6.2. Secret Export
    ///
    /// Single shot API to derive an exporter secret for receiver with public key
    /// `pk_r`.
    ///
    /// Returns the encapsulated secret and the exporter secret for the given
    /// exporter context and length.
    #[allow(clippy::too_many_arguments)]
    pub fn send_export(
        &self,
        pk_r: &HpkePublicKey,
        info: &[u8],
        psk: Option<&[u8]>,
        psk_id: Option<&[u8]>,
        sk_s: Option<&HpkePrivateKey>,
        exporter_context: &[u8],
        length: usize,
    ) -> Result<(EncapsulatedSecret, Vec<u8>), HpkeError> {
        let (enc, context) = self.setup_sender(pk_r, info, psk, psk_id, sk_s)?;
        Ok((enc, context.export(exporter_context, length)))
    }

    /// 6. Single-Shot APIs
    /// 6.2. Secret Export
    ///
    /// Single shot API to derive an exporter secret for receiver with private key
    /// `sk_r`.
    ///
    /// Returns the exporter secret for the given exporter context and length.
    #[allow(clippy::too_many_arguments)]
    pub fn receiver_export(
        &self,
        enc: &[u8],
        sk_r: &HpkePrivateKey,
        info: &[u8],
        psk: Option<&[u8]>,
        psk_id: Option<&[u8]>,
        pk_s: Option<&HpkePublicKey>,
        exporter_context: &[u8],
        length: usize,
    ) -> Result<Vec<u8>, HpkeError> {
        let context = self.setup_receiver(enc, sk_r, info, psk, psk_id, pk_s)?;
        Ok(context.export(exporter_context, length))
    }

    /// Verify PSKs.
    #[inline(always)]
    fn verify_psk_inputs(&self, psk: &[u8], psk_id: &[u8]) -> Result<(), HpkeError> {
        let got_psk = !psk.is_empty();
        let got_psk_id = !psk_id.is_empty();
        if (got_psk && !got_psk_id) || (!got_psk && got_psk_id) {
            return Err(HpkeError::InconsistentPsk);
        }

        if got_psk && (self.mode == Mode::Base || self.mode == Mode::Auth) {
            return Err(HpkeError::UnnecessaryPsk);
        }
        if !got_psk && (self.mode == Mode::Psk || self.mode == Mode::AuthPsk) {
            return Err(HpkeError::MissingPsk);
        }

        // The PSK MUST have at least 32 bytes of entropy and SHOULD be of length Nh bytes or longer.
        if (self.mode == Mode::Psk || self.mode == Mode::AuthPsk) && psk.len() < 32 {
            return Err(HpkeError::InsecurePsk);
        }

        Ok(())
    }

    #[inline]
    fn ciphersuite(&self) -> Vec<u8> {
        util::concat(&[
            b"HPKE",
            &(self.kem_id as u16).to_be_bytes(),
            &(self.kdf_id as u16).to_be_bytes(),
            &(self.aead_id as u16).to_be_bytes(),
        ])
    }

    #[inline]
    fn key_schedule_context(&self, info: &[u8], psk_id: &[u8], suite_id: &[u8]) -> Vec<u8> {
        let psk_id_hash = self
            .kdf
            .labeled_extract(&[0], suite_id, "psk_id_hash", psk_id);
        let info_hash = self.kdf.labeled_extract(&[0], suite_id, "info_hash", info);
        util::concat(&[&[self.mode as u8], &psk_id_hash, &info_hash])
    }

    /// 5.1. Creating the Encryption Context
    /// Generate the HPKE context from the given input.
    ///
    /// ```text
    /// default_psk = ""
    /// default_psk_id = ""
    ///
    /// def VerifyPSKInputs(mode, psk, psk_id):
    ///   got_psk = (psk != default_psk)
    ///   got_psk_id = (psk_id != default_psk_id)
    ///   if got_psk != got_psk_id:
    ///     raise Exception("Inconsistent PSK inputs")
    ///
    ///   if got_psk and (mode in [mode_base, mode_auth]):
    ///     raise Exception("PSK input provided when not needed")
    ///   if (not got_psk) and (mode in [mode_psk, mode_auth_psk]):
    ///     raise Exception("Missing required PSK input")
    ///
    /// def KeySchedule(mode, shared_secret, info, psk, psk_id):
    ///   VerifyPSKInputs(mode, psk, psk_id)
    ///
    ///   psk_id_hash = LabeledExtract("", "psk_id_hash", psk_id)
    ///   info_hash = LabeledExtract("", "info_hash", info)
    ///   key_schedule_context = concat(mode, psk_id_hash, info_hash)
    ///
    ///   secret = LabeledExtract(shared_secret, "secret", psk)
    ///
    ///   key = LabeledExpand(secret, "key", key_schedule_context, Nk)
    ///   base_nonce = LabeledExpand(secret, "base_nonce", key_schedule_context, Nn)
    ///   exporter_secret = LabeledExpand(secret, "exp", key_schedule_context, Nh)
    ///
    ///   return Context(key, base_nonce, 0, exporter_secret)
    /// ```
    pub fn key_schedule(
        &self,
        shared_secret: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Result<Context, HpkeError> {
        self.verify_psk_inputs(psk, psk_id)?;
        let suite_id = self.ciphersuite();
        let key_schedule_context = self.key_schedule_context(info, psk_id, &suite_id);
        let secret = self
            .kdf
            .labeled_extract(shared_secret, &suite_id, "secret", psk);

        let key =
            self.kdf
                .labeled_expand(&secret, &suite_id, "key", &key_schedule_context, self.nk);
        let base_nonce = self.kdf.labeled_expand(
            &secret,
            &suite_id,
            "base_nonce",
            &key_schedule_context,
            self.nn,
        );
        let exporter_secret =
            self.kdf
                .labeled_expand(&secret, &suite_id, "exp", &key_schedule_context, self.nh);

        Ok(Context {
            key,
            nonce: base_nonce,
            exporter_secret,
            sequence_number: 0,
            hpke: self,
        })
    }

    /// 4. Cryptographic Dependencies
    /// Randomized algorithm to generate a key pair `(skX, pkX)` for the KEM.
    /// This is equivalent to `derive_key_pair(random_vector(sk.len()))`
    ///
    /// Returns an `HpkeKeyPair`.
    pub fn generate_key_pair(&self) -> Result<HpkeKeyPair, HpkeError> {
        let (sk, pk) = self.kem.key_gen()?;
        Ok(HpkeKeyPair::new(sk, pk))
    }

    /// 7.1.2. DeriveKeyPair
    /// Derive a key pair for the used KEM with the given input key material.
    ///
    /// Returns an `HpkeKeyPair` result or an `HpkeError` if key derivation fails.
    pub fn derive_key_pair(&self, ikm: &[u8]) -> Result<HpkeKeyPair, HpkeError> {
        let (pk, sk) = self.kem.derive_key_pair(ikm)?;
        Ok(HpkeKeyPair::new(sk, pk))
    }

    /// Set randomness for testing HPKE (KEM) without randomness.
    #[cfg(feature = "deterministic")]
    pub fn set_kem_random(mut self, r: &[u8]) -> Self {
        self.kem.set_random(r);
        self
    }
}

impl HpkeKeyPair {
    /// Create a new HPKE key pair.
    /// Consumes the private and public key bytes.
    pub fn new(sk: Vec<u8>, pk: Vec<u8>) -> Self {
        Self {
            private_key: HpkePrivateKey::new(sk),
            public_key: HpkePublicKey::new(pk),
        }
    }

    /// Get a reference to the HPKE private key of this key pair.
    pub fn private_key(&self) -> &HpkePrivateKey {
        &self.private_key
    }

    /// Get a reference to the HPKE public key of this key pair.
    pub fn public_key(&self) -> &HpkePublicKey {
        &self.public_key
    }

    /// Split the key pair into the two keys
    pub fn into_keys(self) -> (HpkePrivateKey, HpkePublicKey) {
        (self.private_key, self.public_key)
    }

    /// Build a key pair from two keys
    pub fn from_keys(private_key: HpkePrivateKey, public_key: HpkePublicKey) -> Self {
        Self {
            private_key,
            public_key,
        }
    }
}

impl From<(Vec<u8>, Vec<u8>)> for HpkeKeyPair {
    fn from((sk, pk): (Vec<u8>, Vec<u8>)) -> Self {
        Self::new(sk, pk)
    }
}

impl From<(&[u8], &[u8])> for HpkeKeyPair {
    fn from((sk, pk): (&[u8], &[u8])) -> Self {
        Self::new(sk.to_vec(), pk.to_vec())
    }
}

impl HpkePrivateKey {
    /// Create a new HPKE private key.
    /// Consumes the private key bytes.
    pub fn new(b: Vec<u8>) -> Self {
        Self { value: b }
    }

    /// Get the raw key as byte slice.
    #[cfg(feature = "hazmat")]
    pub fn as_slice(&self) -> &[u8] {
        &self.value
    }
}

impl From<Vec<u8>> for HpkePrivateKey {
    fn from(b: Vec<u8>) -> Self {
        Self::new(b)
    }
}

impl From<&[u8]> for HpkePrivateKey {
    fn from(b: &[u8]) -> Self {
        Self::new(b.to_vec())
    }
}

/// Hopefully constant time comparison of the two values as long as they have the
/// same length.
impl PartialEq for HpkePrivateKey {
    fn eq(&self, other: &Self) -> bool {
        if self.value.len() != other.value.len() {
            return false;
        }

        let mut different_bits = 0u8;
        for (&byte_a, &byte_b) in self.value.iter().zip(other.value.iter()) {
            different_bits |= byte_a ^ byte_b;
        }
        (1u8 & ((different_bits.wrapping_sub(1)).wrapping_shr(8)).wrapping_sub(1)) == 0
    }
}

#[cfg(not(feature = "hazmat"))]
impl std::fmt::Debug for HpkePrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.debug_struct("HpkePrivateKey")
            .field("value", &"***")
            .finish()
    }
}

#[cfg(feature = "hazmat")]
impl std::fmt::Debug for HpkePrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.debug_struct("HpkePrivateKey")
            .field("value", &self.value)
            .finish()
    }
}

impl HpkePublicKey {
    /// Create a new HPKE public key.
    /// Consumes the public key bytes.
    pub fn new(value: Vec<u8>) -> Self {
        Self { value }
    }

    /// Get the raw key as byte slice.
    pub fn as_slice(&self) -> &[u8] {
        self.value.as_slice()
    }
}

impl From<Vec<u8>> for HpkePublicKey {
    fn from(b: Vec<u8>) -> Self {
        Self::new(b)
    }
}

impl From<&[u8]> for HpkePublicKey {
    fn from(b: &[u8]) -> Self {
        Self::new(b.to_vec())
    }
}

#[cfg(feature = "serialization")]
impl tls_codec::Size for HpkePublicKey {
    #[inline(always)]
    fn tls_serialized_len(&self) -> usize {
        tls_codec::TlsByteSliceU16(self.as_slice()).tls_serialized_len()
    }
}

#[cfg(feature = "serialization")]
impl tls_codec::Serialize for HpkePublicKey {
    #[inline(always)]
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        tls_codec::TlsByteSliceU16(self.as_slice()).tls_serialize(writer)
    }
}

#[cfg(feature = "serialization")]
impl tls_codec::Size for &HpkePublicKey {
    #[inline(always)]
    fn tls_serialized_len(&self) -> usize {
        tls_codec::TlsByteSliceU16(self.as_slice()).tls_serialized_len()
    }
}

#[cfg(feature = "serialization")]
impl tls_codec::Serialize for &HpkePublicKey {
    #[inline(always)]
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        tls_codec::TlsByteSliceU16(self.as_slice()).tls_serialize(writer)
    }
}

#[cfg(feature = "serialization")]
impl tls_codec::Deserialize for HpkePublicKey {
    #[inline(always)]
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        Ok(Self {
            value: tls_codec::TlsByteVecU16::tls_deserialize(bytes)?.into(),
        })
    }
}

#[cfg(feature = "serialization")]
impl tls_codec::Deserialize for &HpkePublicKey {
    #[inline(always)]
    fn tls_deserialize<R: std::io::Read>(_: &mut R) -> Result<Self, tls_codec::Error> {
        Err(tls_codec::Error::DecodingError(
            "Error trying to deserialize a reference.".to_string(),
        ))
    }
}

/// Test util module. Should be moved really.
#[cfg(feature = "hpke-test")]
pub mod test_util {
    // TODO: don't build for release
    impl<'a> super::Context<'_> {
        /// Get a reference to the key in the context.
        #[doc(hidden)]
        pub fn key(&self) -> &[u8] {
            &self.key
        }
        /// Get a reference to the nonce in the context.
        #[doc(hidden)]
        pub fn nonce(&self) -> &[u8] {
            &self.nonce
        }
        /// Get a reference to the exporter secret in the context.
        #[doc(hidden)]
        pub fn exporter_secret(&self) -> &[u8] {
            &self.exporter_secret
        }
        /// Get a reference to the sequence number in the context.
        #[doc(hidden)]
        pub fn sequence_number(&self) -> u32 {
            self.sequence_number
        }
    }

    /// Convert `bytes` to a hex string.
    pub fn bytes_to_hex(bytes: &[u8]) -> String {
        let mut hex = String::new();
        for &b in bytes {
            hex += &format!("{:02X}", b);
        }
        hex
    }

    /// Convert a hex string to a byte vector.
    pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
        assert!(hex.len() % 2 == 0);
        let mut bytes = Vec::new();
        for i in 0..(hex.len() / 2) {
            bytes.push(u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap());
        }
        bytes
    }

    /// Convert a hex string to a byte vector.
    /// If the input is `None`, this returns an empty vector.
    pub fn hex_to_bytes_option(hex: Option<String>) -> Vec<u8> {
        match hex {
            Some(s) => hex_to_bytes(&s),
            None => vec![],
        }
    }

    /// Convert a byte slice into byte slice option.
    /// Returns `Nonce` if the byte slice is empty and `Some(v)` otherwise.
    pub fn vec_to_option_slice(v: &[u8]) -> Option<&[u8]> {
        if v.is_empty() {
            None
        } else {
            Some(v)
        }
    }
}

impl From<aead::Error> for HpkeError {
    fn from(e: aead::Error) -> Self {
        match e {
            aead::Error::OpenError => HpkeError::OpenError,
            aead::Error::InvalidNonce | aead::Error::InvalidCiphertext => HpkeError::InvalidInput,
            aead::Error::InvalidConfig => HpkeError::InvalidConfig,
            aead::Error::UnknownMode => HpkeError::UnknownMode,
            aead::Error::CryptoLibError(_) => HpkeError::CryptoError,
        }
    }
}

impl From<kem::Error> for HpkeError {
    fn from(e: kem::Error) -> Self {
        match e {
            kem::Error::UnknownMode => HpkeError::UnknownMode,
            _ => HpkeError::CryptoError,
        }
    }
}

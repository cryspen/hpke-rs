//! Tests for X25519 All-Zero Shared Secret Validation (RFC 9180 Section 7.1.4)
//!
//! RFC 9180 Section 7.1.4 states:
//! > "For X25519 and X448, public keys and Diffie-Hellman outputs MUST be
//! > validated as described in [RFC7748]. In particular, recipients MUST
//! > check whether the Diffie-Hellman shared secret is the all-zero value
//! > and abort if so."
//!
//! These tests verify that low-order points are properly rejected.
//!
//! Run with: cargo test --test x25519_zero_check -- --nocapture

use hpke_rs::{Hpke, HpkePublicKey, Mode};
use hpke_rs::hpke_types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
use hpke_rs_crypto::HpkeCrypto;
use hpke_rs_rust_crypto::HpkeRustCrypto;

const LOW_ORDER_POINTS: [[u8; 32]; 2] = [
    // Point of order 1 (identity/neutral element)
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],

    // Point of order 8
    [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
];

#[test]
fn poc_x25519_accepts_low_order_points() {
    println!("\nX25519 All-Zero Shared Secret\n");

    // Create HPKE instance with X25519
    let mut hpke = Hpke::<HpkeRustCrypto>::new(
        Mode::Base,
        KemAlgorithm::DhKem25519,
        KdfAlgorithm::HkdfSha256,
        AeadAlgorithm::Aes128Gcm,
    );

    let plaintext = b"Nadim's hummus recipe";
    let info = b"I sure hope this HPKE implementation follows the RFC";
    let aad = b"Since how else would cryptography be truly high assurance";

    println!("Testing {} known low-order points...\n", LOW_ORDER_POINTS.len());

    for (i, low_order_point) in LOW_ORDER_POINTS.iter().enumerate() {
        // Use the low-order point as the "recipient's public key"
        let malicious_pk = HpkePublicKey::new(low_order_point.to_vec());

        // Attempt to encrypt to this malicious public key
        let result = hpke.seal(
            &malicious_pk,
            info,
            aad,
            plaintext,
            None,  // no PSK
            None,  // no PSK ID
            None,  // no sender key (Base mode)
        );

        match result {
            Ok((enc, ciphertext)) => {
                println!("Point #{}: Encryption succeeded, in violation of RFC 9180 Section 7.1.4", i);
                println!("  Low-order point: {:02x?}...", &low_order_point[..8]);
                println!("  Encapsulated key (enc): {:02x?}...", &enc[..8]);
                println!("  Ciphertext length: {} bytes", ciphertext.len());
            }
            Err(e) => {
                println!("Point #{}: Safe - Rejected with error: {:?}", i, e);
            }
        }
    }
}

#[test]
fn poc_demonstrate_predictable_key_derivation() {
    println!("\n Demonstrating Predictable Key Derivation\n");

    // The all-zero point (identity element)
    let zero_point = [0u8; 32];
    let malicious_pk = HpkePublicKey::new(zero_point.to_vec());

    let plaintext = b"Nadim's hummus recipe";
    let info = b"I sure hope this HPKE implementation follows the RFC";
    let aad = b"Since how else would cryptography be truly high assurance";

    let mut victim_hpke = Hpke::<HpkeRustCrypto>::new(
        Mode::Base,
        KemAlgorithm::DhKem25519,
        KdfAlgorithm::HkdfSha256,
        AeadAlgorithm::Aes128Gcm,
    );

    let seal_result = victim_hpke.seal(
        &malicious_pk,
        info,
        aad,
        plaintext,
        None,
        None,
        None,
    );

    match seal_result {
        Ok((enc, ciphertext)) => {
            println!("Encapsulated key (enc): {:02x?}", &enc);
            println!("Ciphertext: {:02x?}...\n", &ciphertext[..16]);
        }
        Err(e) => {
            println!("Good news: Encryption was rejected: {:?}", e);
            println!("The implementation properly validates the public key.");
        }
    }
}

/// Test that directly shows DH with low-order point returns all zeros.
/// This uses a known test private key to demonstrate the issue.
#[test]
fn poc_show_all_zero_dh_result() {
    println!("\nDirect DH with Low-Order Point ===\n");


    let test_sk: [u8; 32] = [
        0x99, 0x07, 0xd9, 0x0a, 0x33, 0x48, 0xa5, 0x7f,
        0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
        0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
        0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
    ];

    println!("Using test private key: {:02x?}...", &test_sk[..8]);

    let zero_point = [0u8; 32];

    let dh_result = HpkeRustCrypto::dh(
        KemAlgorithm::DhKem25519,
        &zero_point,
        &test_sk,
    );

    match dh_result {
        Ok(shared_secret) => {
            let is_all_zero = shared_secret.iter().all(|&b: &u8| b == 0);
            println!("DH result: {:02x?}", shared_secret);
            println!("Is all zeros: {}", is_all_zero);
            if is_all_zero {
                println!("RFC 9180 Section 7.1.4 REQUIRES this to be rejected.");
            }
        }
        Err(e) => {
            println!("DH was rejected: {:?}", e);
            println!("This is the correct behavior per RFC 9180.");
        }
    }
}

/// Test verifying that low-order points are rejected for all private keys
#[test]
fn poc_attack_independent_of_sender_key() {
    println!("\n=== Verify Fix: Low-Order Points Rejected for All Keys ===\n");

    let zero_point = [0u8; 32];

    // Multiple different test private keys
    let test_keys: [[u8; 32]; 3] = [
        // Key 1
        [0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
         0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
         0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
         0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a],
        // Key 2 (different)
        [0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
         0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
         0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
         0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb],
        // Key 3 (different)
        [0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d,
         0x3b, 0x16, 0x15, 0x4b, 0x82, 0x46, 0x5e, 0xdd,
         0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc, 0x5a, 0x18,
         0x50, 0x6a, 0x22, 0x44, 0xba, 0x44, 0x9a, 0xc4],
    ];

    for (i, sk) in test_keys.iter().enumerate() {
        let dh_result = HpkeRustCrypto::dh(
            KemAlgorithm::DhKem25519,
            &zero_point,
            sk,
        );

        match dh_result {
            Ok(_) => {
                panic!("DH with zero point should have been rejected for key #{}", i + 1);
            }
            Err(e) => {
                println!("Private key #{}: Correctly rejected with error: {:?}", i + 1, e);
            }
        }
    }

    println!("\nFix verified: All attempts to use low-order points are rejected.");
}

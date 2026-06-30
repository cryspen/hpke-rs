//! Benchmarks for post-quantum HPKE ciphersuites (draft-ietf-hpke-pq).
//!
//! Run with: `cargo bench --bench bench_pq --F draft-ietf-hpke-pq`

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use hpke_rs::{prelude::*, Hpke};
use hpke_rs_crypto::{
    types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm},
    HpkeCrypto,
};
use hpke_rs_libcrux::HpkeLibcrux;
use rand::Rng;

// Constants
const AEAD_IDS: [AeadAlgorithm; 3] = [
    AeadAlgorithm::Aes128Gcm,
    AeadAlgorithm::Aes256Gcm,
    AeadAlgorithm::ChaCha20Poly1305,
];

/// One two-stage (HKDF) and one single-stage (SHAKE) KDF, to cover both
/// key-schedule shapes for the post-quantum suites.
const PQ_KDF_IDS: [KdfAlgorithm; 2] = [KdfAlgorithm::HkdfSha256, KdfAlgorithm::Shake256];

/// Post-quantum KEMs from `draft-ietf-hpke-pq`.
const PQ_KEM_IDS: &[KemAlgorithm] = &[
    KemAlgorithm::MlKem512,
    KemAlgorithm::MlKem768,
    KemAlgorithm::MlKem1024,
    KemAlgorithm::MlKem768P256,
    #[cfg(feature = "libcrux-rustcrypto-p-curves")]
    KemAlgorithm::MlKem1024P384,
    KemAlgorithm::XWingDraft06,
];

const AEAD_PAYLOAD: usize = 128;
const AEAD_AAD: usize = 48;

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    hpke_rs::test_util::hex_to_bytes(hex)
}

fn random_aad() -> Vec<u8> {
    let mut aad = vec![0u8; AEAD_AAD];
    rand::rng().fill_bytes(&mut aad);
    aad
}

fn random_ptxt() -> Vec<u8> {
    let mut ptxt = vec![0u8; AEAD_PAYLOAD];
    rand::rng().fill_bytes(&mut ptxt);
    ptxt
}

fn get_psk_params(mode: Mode) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    if mode == HpkeMode::AuthPsk || mode == HpkeMode::Psk {
        (
            Some(hex_to_bytes(
                "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82",
            )),
            Some(hex_to_bytes("456e6e796e20447572696e206172616e204d6f726961")),
        )
    } else {
        (None, None)
    }
}

fn get_sender_keypair<Crypto: HpkeCrypto + 'static>(
    mode: Mode,
    hpke: &mut Hpke<Crypto>,
) -> (Option<HpkePublicKey>, Option<HpkePrivateKey>) {
    if mode == HpkeMode::AuthPsk || mode == HpkeMode::Auth {
        let kp = hpke.generate_key_pair().unwrap();
        (
            Some(kp.public_key().clone()),
            Some(kp.private_key().clone()),
        )
    } else {
        (None, None)
    }
}

/// Benchmark every HPKE operation for a single post-quantum ciphersuite.
///
/// When `bench_keygen` is set, a `Generate Key Pair` benchmark is added in front
/// of the others. This is used for the post-quantum suites, where key generation
/// is a non-trivial cost worth measuring on its own.
fn bench_suite<Crypto: HpkeCrypto + 'static>(
    c: &mut Criterion,
    hpke_mode: Mode,
    kem_mode: KemAlgorithm,
    kdf_mode: KdfAlgorithm,
    aead_mode: AeadAlgorithm,
    bench_keygen: bool,
) {
    let mut hpke = Hpke::<Crypto>::new(hpke_mode, kem_mode, kdf_mode, aead_mode);
    let label = format!("{} {}", Crypto::name(), hpke);

    let kp_r = hpke.generate_key_pair().unwrap();
    let sk_rm = kp_r.private_key();
    let pk_rm = kp_r.public_key();

    let info = hex_to_bytes("4f6465206f6e2061204772656369616e2055726e");
    let (psk, psk_id) = get_psk_params(hpke_mode);
    let (pk_sm, sk_sm) = get_sender_keypair::<Crypto>(hpke_mode, &mut hpke);

    let mut group = c.benchmark_group(label.to_string());

    // Generate Key Pair (only for PQ KEMs)
    if bench_keygen {
        group.bench_function("Generate Key Pair", |b| {
            b.iter(|| {
                let mut hpke = Hpke::<Crypto>::new(hpke_mode, kem_mode, kdf_mode, aead_mode);
                let _kp = hpke.generate_key_pair().unwrap();
            })
        });
    }

    // Setup Sender
    group.bench_function("Setup Sender", |b| {
        b.iter(|| {
            let mut hpke = Hpke::<Crypto>::new(hpke_mode, kem_mode, kdf_mode, aead_mode);
            hpke.setup_sender(
                pk_rm,
                &info,
                psk.as_ref().map(Vec::as_ref),
                psk_id.as_ref().map(Vec::as_ref),
                sk_sm.as_ref(),
            )
            .unwrap();
        })
    });

    // Setup Receiver - uses iter_batched to generate proper encapsulation
    group.bench_function("Setup Receiver", |b| {
        b.iter_batched(
            || {
                let mut hpke = Hpke::<Crypto>::new(hpke_mode, kem_mode, kdf_mode, aead_mode);
                let (enc, _) = hpke
                    .setup_sender(
                        pk_rm,
                        &info,
                        psk.as_ref().map(Vec::as_ref),
                        psk_id.as_ref().map(Vec::as_ref),
                        sk_sm.as_ref(),
                    )
                    .unwrap();
                enc
            },
            |enc| {
                let hpke = Hpke::<Crypto>::new(hpke_mode, kem_mode, kdf_mode, aead_mode);
                hpke.setup_receiver(
                    &enc,
                    sk_rm,
                    &info,
                    psk.as_ref().map(Vec::as_ref),
                    psk_id.as_ref().map(Vec::as_ref),
                    pk_sm.as_ref(),
                )
                .unwrap();
            },
            BatchSize::SmallInput,
        )
    });

    // Seal
    group.bench_function(format!("Seal {}({})", AEAD_PAYLOAD, AEAD_AAD), |b| {
        b.iter_batched(
            || {
                let mut hpke = Hpke::<Crypto>::new(hpke_mode, kem_mode, kdf_mode, aead_mode);
                let (_enc, context) = hpke
                    .setup_sender(
                        pk_rm,
                        &info,
                        psk.as_ref().map(Vec::as_ref),
                        psk_id.as_ref().map(Vec::as_ref),
                        sk_sm.as_ref(),
                    )
                    .unwrap();
                let aad = random_aad();
                let ptxt = random_ptxt();
                (context, aad, ptxt)
            },
            |(mut context, aad, ptxt)| {
                let _ctxt = context.seal(&aad, &ptxt).unwrap();
            },
            BatchSize::SmallInput,
        )
    });

    // Open
    group.bench_function(format!("Open {}({})", AEAD_PAYLOAD, AEAD_AAD), |b| {
        b.iter_batched(
            || {
                let mut hpke = Hpke::<Crypto>::new(hpke_mode, kem_mode, kdf_mode, aead_mode);
                let (enc, mut sender_context) = hpke
                    .setup_sender(
                        pk_rm,
                        &info,
                        psk.as_ref().map(Vec::as_ref),
                        psk_id.as_ref().map(Vec::as_ref),
                        sk_sm.as_ref(),
                    )
                    .unwrap();
                let aad = random_aad();
                let ptxt = random_ptxt();
                let ctxt = sender_context.seal(&aad, &ptxt).unwrap();

                let context = hpke
                    .setup_receiver(
                        &enc,
                        sk_rm,
                        &info,
                        psk.as_ref().map(Vec::as_ref),
                        psk_id.as_ref().map(Vec::as_ref),
                        pk_sm.as_ref(),
                    )
                    .unwrap();
                (context, aad, ctxt)
            },
            |(mut context, aad, ctxt)| {
                let _ctxt_out = context.open(&aad, &ctxt).unwrap();
            },
            BatchSize::SmallInput,
        )
    });

    // Single-Shot Seal
    group.bench_function(
        format!("Single-Shot Seal {}({})", AEAD_PAYLOAD, AEAD_AAD),
        |b| {
            b.iter_batched(
                || {
                    let hpke = Hpke::<Crypto>::new(hpke_mode, kem_mode, kdf_mode, aead_mode);
                    let aad = random_aad();
                    let ptxt = random_ptxt();
                    (hpke, aad, ptxt)
                },
                |(mut hpke, aad, ptxt)| {
                    let _ctxt = hpke
                        .seal(
                            pk_rm,
                            &info,
                            &aad,
                            &ptxt,
                            psk.as_ref().map(Vec::as_ref),
                            psk_id.as_ref().map(Vec::as_ref),
                            sk_sm.as_ref(),
                        )
                        .unwrap();
                },
                BatchSize::SmallInput,
            )
        },
    );

    // Single-Shot Open
    group.bench_function(
        format!("Single-Shot Open {}({})", AEAD_PAYLOAD, AEAD_AAD),
        |b| {
            b.iter_batched(
                || {
                    let mut hpke = Hpke::<Crypto>::new(hpke_mode, kem_mode, kdf_mode, aead_mode);
                    let (enc, mut sender_context) = hpke
                        .setup_sender(
                            pk_rm,
                            &info,
                            psk.as_ref().map(Vec::as_ref),
                            psk_id.as_ref().map(Vec::as_ref),
                            sk_sm.as_ref(),
                        )
                        .unwrap();
                    let aad = random_aad();
                    let ptxt = random_ptxt();
                    let ctxt = sender_context.seal(&aad, &ptxt).unwrap();

                    (hpke, aad, ctxt, enc)
                },
                |(hpke, aad, ctxt, enc)| {
                    let _ctxt_out = hpke
                        .open(
                            &enc,
                            sk_rm,
                            &info,
                            &aad,
                            &ctxt,
                            psk.as_ref().map(Vec::as_ref),
                            psk_id.as_ref().map(Vec::as_ref),
                            pk_sm.as_ref(),
                        )
                        .unwrap();
                },
                BatchSize::SmallInput,
            )
        },
    );
}

/// Benchmark the post-quantum ciphersuites.
///
/// Restricted to `Base` mode: the PQ KEMs return `UnsupportedKemOperation` for the
/// `Auth`/`AuthPsk` modes, and PSK is out of scope here. Key generation is timed in
/// addition to the usual operations.
fn benchmark_post_quantum<Crypto: HpkeCrypto + 'static>(c: &mut Criterion) {
    for aead_mode in AEAD_IDS {
        if Crypto::supports_aead(aead_mode).is_err() {
            continue;
        }
        for kdf_mode in PQ_KDF_IDS {
            if Crypto::supports_kdf(kdf_mode).is_err() {
                continue;
            }
            for &kem_mode in PQ_KEM_IDS {
                if Crypto::supports_kem(kem_mode).is_err() {
                    continue;
                }
                bench_suite::<Crypto>(c, HpkeMode::Base, kem_mode, kdf_mode, aead_mode, true);
            }
        }
    }
}

fn bench_pq(c: &mut Criterion) {
    benchmark_post_quantum::<HpkeLibcrux>(c);
}

criterion_group!(benches, bench_pq,);
criterion_main!(benches);

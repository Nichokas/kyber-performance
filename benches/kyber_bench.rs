use iai_callgrind::{library_benchmark, library_benchmark_group, main, LibraryBenchmarkConfig};
use oqs::kem;
use sha2::Sha256;
use std::hint::black_box;
use hkdf::Hkdf;

fn kyber_derive_chacha_key(shared_secret: &[u8]) -> [u8; 32] {
    let salt = b"Kyber-ChaCha20Poly1305";
    let info = b"key derivation for Kyber-ChaCha20Poly1305";
    let hk = Hkdf::<Sha256>::new(Some(salt), shared_secret);
    let mut chacha_key = [0u8; 32];
    hk.expand(info, &mut chacha_key).expect("HKDF expansion failed");
    chacha_key
}

// Setup para encapsulación
fn setup_kyber_encapsulate() -> (kem::Kem, kem::PublicKey) {
    let kem = kem::Kem::new(kem::Algorithm::MlKem768).unwrap();
    let (public_key, _) = kem.keypair().unwrap();
    (kem, public_key)
}

// Setup para desencapsulación
fn setup_kyber_decapsulate() -> (kem::Kem, kem::SecretKey, kem::Ciphertext) {
    let kem = kem::Kem::new(kem::Algorithm::MlKem768).unwrap();
    let (public_key, private_key) = kem.keypair().unwrap();
    let (ciphertext, _) = kem.encapsulate(&public_key).unwrap();
    (kem, private_key, ciphertext)
}

#[library_benchmark]
fn bench_kyber_key_generation() {
    let kem = kem::Kem::new(kem::Algorithm::MlKem768).unwrap();
    black_box(kem.keypair().unwrap());
}

#[library_benchmark]
#[bench::encapsulate(setup = setup_kyber_encapsulate)]
fn bench_kyber_encapsulate(input: (kem::Kem, kem::PublicKey)) {
    let (kem, public_key) = input;

    // Solo medimos encapsulación
    let (_, shared_secret) = black_box(kem.encapsulate(&public_key).unwrap());
    black_box(kyber_derive_chacha_key(&shared_secret.into_vec()));
}

#[library_benchmark]
#[bench::decapsulate(setup = setup_kyber_decapsulate)]
fn bench_kyber_decapsulate(input: (kem::Kem, kem::SecretKey, kem::Ciphertext)) {
    let (kem, private_key, ciphertext) = input;

    // Solo medimos desencapsulación
    let shared_secret = black_box(kem.decapsulate(&private_key, &ciphertext).unwrap());
    black_box(kyber_derive_chacha_key(&shared_secret.into_vec()));
}

library_benchmark_group!(
    name = kyber_benchmarks_group;
    benchmarks = bench_kyber_key_generation, bench_kyber_encapsulate, bench_kyber_decapsulate
);

main!(library_benchmark_groups = kyber_benchmarks_group);
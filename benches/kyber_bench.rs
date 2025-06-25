use hkdf::Hkdf;
use iai_callgrind::{black_box, library_benchmark, library_benchmark_group, main};
use kychacha_crypto::{decrypt, encrypt, generate_keypair};
use sha2::Sha256;
use oqs::kem;

fn kyber_derive_chacha_key(shared_secret: &[u8]) -> [u8; 32] {
    let salt = b"Kyber-ChaCha20Poly1305";
    let info = b"key derivation for Kyber-ChaCha20Poly1305";
    let hk = Hkdf::<Sha256>::new(Some(salt), shared_secret);
    let mut chacha_key = [0u8; 32];
    hk.expand(info, &mut chacha_key).expect("HKDF expansion failed");
    chacha_key
}

#[library_benchmark]
fn bench_kyber_key_generation() {
    let kem = kem::Kem::new(kem::Algorithm::MlKem768).unwrap();
    black_box(kem.keypair().unwrap());
}

#[library_benchmark]
fn bench_kyber_encapsulate() {
    let kem = kem::Kem::new(kem::Algorithm::MlKem768).unwrap();
    let (public_key, _) = kem.keypair().unwrap();
    let (_, shared_secret) = kem.encapsulate(&public_key).unwrap();

    // Derivamos la clave simétrica
    black_box(kyber_derive_chacha_key(&shared_secret.into_vec()));
}

#[library_benchmark]
fn bench_kyber_decapsulate() {
    let kem = kem::Kem::new(kem::Algorithm::MlKem768).unwrap();
    let (public_key, private_key) = kem.keypair().unwrap();
    let (ciphertext, _) = kem.encapsulate(&public_key).unwrap();
    let shared_secret = kem.decapsulate(&private_key, &ciphertext).unwrap();

    black_box(kyber_derive_chacha_key(&shared_secret.into_vec()));
}

library_benchmark_group!(
    name = kyber_benchmarks_group;
    benchmarks = bench_kyber_key_generation, bench_kyber_encapsulate, bench_kyber_decapsulate
);

main!(library_benchmark_groups = kyber_benchmarks_group);
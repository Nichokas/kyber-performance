use crypto_testing::ml_kem_derive_chacha_key;
use gungraun::{library_benchmark, library_benchmark_group, main};
use oqs::kem;
use std::hint::black_box;

fn new_kem() -> kem::Kem {
    oqs::init();
    kem::Kem::new(kem::Algorithm::MlKem768).unwrap()
}

fn warm_kem() -> kem::Kem {
    let kem = new_kem();
    kem.keypair().unwrap();
    kem
}

fn setup_kyber_encapsulate() -> (kem::Kem, kem::PublicKey) {
    let kem = new_kem();
    let (public_key, _) = kem.keypair().unwrap();
    (kem, public_key)
}

fn setup_kyber_decapsulate() -> (kem::Kem, kem::SecretKey, kem::Ciphertext) {
    let kem = new_kem();
    let (public_key, private_key) = kem.keypair().unwrap();
    let (ciphertext, _) = kem.encapsulate(&public_key).unwrap();
    (kem, private_key, ciphertext)
}

#[library_benchmark]
#[bench::warm(setup = warm_kem)]
fn bench_kyber_key_generation(kem: kem::Kem) {
    black_box(kem.keypair().unwrap());
}

#[library_benchmark]
#[bench::encapsulate(setup = setup_kyber_encapsulate)]
fn bench_kyber_encapsulate(input: (kem::Kem, kem::PublicKey)) {
    let (kem, public_key) = input;
    let (_, shared_secret) = black_box(kem.encapsulate(&public_key).unwrap());
    black_box(ml_kem_derive_chacha_key(shared_secret.as_ref()));
}

#[library_benchmark]
#[bench::decapsulate(setup = setup_kyber_decapsulate)]
fn bench_kyber_decapsulate(input: (kem::Kem, kem::SecretKey, kem::Ciphertext)) {
    let (kem, private_key, ciphertext) = input;
    let shared_secret = black_box(kem.decapsulate(&private_key, &ciphertext).unwrap());
    black_box(ml_kem_derive_chacha_key(shared_secret.as_ref()));
}

library_benchmark_group!(
    name = kyber_benchmarks_group;
    benchmarks = bench_kyber_key_generation, bench_kyber_encapsulate, bench_kyber_decapsulate
);

main!(library_benchmark_groups = kyber_benchmarks_group);

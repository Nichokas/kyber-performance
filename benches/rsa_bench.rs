use crypto_testing::{rsa_decrypt_key, rsa_derive_chacha_key, rsa_encrypt_key};
use gungraun::{LibraryBenchmarkConfig, library_benchmark, library_benchmark_group, main};
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::Rsa;
use rand::{RngCore, rngs::OsRng};
use std::env;
use std::fs;
use std::hint::black_box;

fn warm_rsa() {
    Rsa::generate(1024).unwrap();
}

fn transport_key() -> PKey<Private> {
    // CI generates the transport fixture outside Valgrind so each sample profiles one prime search.
    match env::var_os("KYBER_BENCH_RSA_KEY") {
        Some(path) => PKey::private_key_from_der(&fs::read(path).unwrap()).unwrap(),
        None => PKey::from_rsa(Rsa::generate(7680).unwrap()).unwrap(),
    }
}

fn setup_rsa_encrypt() -> (PKey<Public>, [u8; 32]) {
    let key = transport_key();
    let public_key = PKey::public_key_from_der(&key.public_key_to_der().unwrap()).unwrap();
    let mut secret = [0; 32];
    OsRng.fill_bytes(&mut secret);
    (public_key, secret)
}

fn setup_rsa_decrypt() -> (PKey<Private>, Vec<u8>) {
    let key = transport_key();
    let mut secret = [0; 32];
    OsRng.fill_bytes(&mut secret);
    let encrypted_key = rsa_encrypt_key(&key, &secret);
    (key, encrypted_key)
}

#[library_benchmark]
#[bench::warm(setup = warm_rsa)]
fn bench_rsa_key_generation(_: ()) {
    black_box(Rsa::generate(7680).unwrap());
}

#[library_benchmark]
#[bench::encrypt(setup = setup_rsa_encrypt)]
fn bench_rsa_key_transport_encrypt(input: (PKey<Public>, [u8; 32])) {
    let (key, secret) = input;
    black_box(rsa_encrypt_key(&key, &secret));
    black_box(rsa_derive_chacha_key(&secret));
}

#[library_benchmark]
#[bench::decrypt(setup = setup_rsa_decrypt)]
fn bench_rsa_key_transport_decrypt(input: (PKey<Private>, Vec<u8>)) {
    let (key, encrypted_key) = input;
    let secret = rsa_decrypt_key(&key, &encrypted_key);
    black_box(rsa_derive_chacha_key(&secret));
}

library_benchmark_group!(
    name = rsa_benchmarks_group;
    config = LibraryBenchmarkConfig::default().pass_through_env("KYBER_BENCH_RSA_KEY");
    benchmarks = bench_rsa_key_generation, bench_rsa_key_transport_encrypt, bench_rsa_key_transport_decrypt
);

main!(library_benchmark_groups = rsa_benchmarks_group);

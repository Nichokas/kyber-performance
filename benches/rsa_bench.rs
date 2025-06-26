use openssl::rsa::{Rsa, Padding};
use openssl::pkey::Private;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use hkdf::Hkdf;
use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use std::hint::black_box;

fn rsa_derive_chacha_key(shared_secret: &[u8]) -> [u8; 32] {
    let salt = b"RSA-ChaCha20Poly1305";
    let info = b"key derivation for RSA-ChaCha20Poly1305";
    let hk = Hkdf::<Sha256>::new(Some(salt), shared_secret);
    let mut chacha_key = [0u8; 32];
    hk.expand(info, &mut chacha_key).expect("HKDF expansion failed");
    chacha_key
}

// Setup para encriptación RSA
fn setup_rsa_encrypt() -> (Rsa<Private>, [u8; 32]) {
    let key = Rsa::generate(7680).unwrap();
    let mut random_key = [0u8; 32];
    OsRng.fill_bytes(&mut random_key);
    (key, random_key)
}

// Setup para desencriptación RSA
fn setup_rsa_decrypt() -> (Rsa<Private>, Vec<u8>) {
    let key = Rsa::generate(7680).unwrap();
    let mut random_key = [0u8; 32];
    OsRng.fill_bytes(&mut random_key);
    let mut encrypt_buf = vec![0; key.size() as usize];
    let encrypted_len = key.public_encrypt(&random_key, &mut encrypt_buf, Padding::PKCS1)
        .expect("Encryption failed");
    encrypt_buf.truncate(encrypted_len);
    (key, encrypt_buf)
}

#[library_benchmark]
fn bench_rsa_key_generation() {
    black_box(Rsa::generate(7680).unwrap());
}

#[library_benchmark]
#[bench::encrypt(setup = setup_rsa_encrypt)]
fn bench_rsa_key_transport_encrypt(input: (Rsa<Private>, [u8; 32])) {
    let (key, random_key) = input;
    let mut encrypt_buf = vec![0; key.size() as usize];

    // Solo medimos la encriptación
    black_box(
        key.public_encrypt(&random_key, &mut encrypt_buf, Padding::PKCS1)
            .expect("Encryption failed")
    );
    black_box(rsa_derive_chacha_key(&random_key));
}

#[library_benchmark]
#[bench::decrypt(setup = setup_rsa_decrypt)]
fn bench_rsa_key_transport_decrypt(input: (Rsa<Private>, Vec<u8>)) {
    let (key, encrypt_buf) = input;
    let mut decrypt_buf = vec![0; key.size() as usize];

    // Solo medimos la desencriptación
    let decrypted_len = black_box(
        key.private_decrypt(&encrypt_buf, &mut decrypt_buf, Padding::PKCS1)
            .expect("Decryption failed")
    );
    black_box(rsa_derive_chacha_key(&decrypt_buf[..decrypted_len]));
}

library_benchmark_group!(
    name = rsa_benchmarks_group;
    benchmarks = bench_rsa_key_generation, bench_rsa_key_transport_encrypt, bench_rsa_key_transport_decrypt
);

main!(library_benchmark_groups = rsa_benchmarks_group);
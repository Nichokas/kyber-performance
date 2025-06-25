use openssl::rsa::{Rsa, Padding};
use chacha20poly1305::{aead::{KeyInit, Aead}, ChaCha20Poly1305, Nonce, Key};
use rand::{Rng, rngs::OsRng};
use sha2::Sha256;
use hkdf::Hkdf;
use iai_callgrind::{black_box, library_benchmark, library_benchmark_group, main};

fn rsa_derive_chacha_key(shared_secret: &[u8]) -> [u8; 32] {
    let salt = b"RSA-ChaCha20Poly1305";
    let info = b"key derivation for RSA-ChaCha20Poly1305";
    let hk = Hkdf::<Sha256>::new(Some(salt), shared_secret);
    let mut chacha_key = [0u8; 32];
    hk.expand(info, &mut chacha_key).expect("HKDF expansion failed");
    chacha_key
}

#[library_benchmark]
fn bench_rsa_key_generation() {
    black_box(Rsa::generate(7680).unwrap());
}

#[library_benchmark]
fn bench_rsa_key_transport_encrypt() {
    let mut random_key = [0u8; 32];
    OsRng.fill(&mut random_key);

    // Derivamos la clave simétrica
    black_box(rsa_derive_chacha_key(&random_key));
}

#[library_benchmark]
fn bench_rsa_key_transport_decrypt() {
    let key = Rsa::generate(7680).unwrap();
    let mut random_key = [0u8; 32];
    OsRng.fill(&mut random_key);
    let mut encrypt_buf = vec![0; key.size() as usize];
    let encrypted_len = key.public_encrypt(&random_key, &mut encrypt_buf, Padding::PKCS1).unwrap();

    let mut decrypt_buf = vec![0; key.size() as usize];
    let decrypted_len = key.private_decrypt(
        &encrypt_buf[..encrypted_len],
        &mut decrypt_buf,
        Padding::PKCS1
    ).unwrap();

    // Derivamos la clave simétrica
    black_box(rsa_derive_chacha_key(&decrypt_buf[..decrypted_len]));
}

library_benchmark_group!(
    name = rsa_benchmarks_group;
    benchmarks = bench_rsa_key_generation, bench_rsa_key_transport_encrypt, bench_rsa_key_transport_decrypt
);

main!(library_benchmark_groups = rsa_benchmarks_group);
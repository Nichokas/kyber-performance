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
fn bench_rsa_key_transport() {
    let keys = Rsa::generate(7680).unwrap();
    let mut random_key = [0u8; 32];
    OsRng.fill(&mut random_key);
    let mut encrypt_buf = vec![0; keys.size() as usize];

    black_box(keys.public_encrypt(
        black_box(&random_key),
        &mut encrypt_buf,
        Padding::PKCS1
    ).unwrap());
}

#[library_benchmark]
fn bench_rsa_key_recovery() {
    let keys = Rsa::generate(7680).unwrap();
    let mut random_key = [0u8; 32];
    OsRng.fill(&mut random_key);

    let mut encrypt_buf = vec![0; keys.size() as usize];
    let encrypted_len = keys.public_encrypt(&random_key, &mut encrypt_buf, Padding::PKCS1).unwrap();
    encrypt_buf.truncate(encrypted_len);

    let mut decrypt_buf = vec![0; keys.size() as usize];

    black_box(keys.private_decrypt(
        black_box(&encrypt_buf),
        &mut decrypt_buf,
        Padding::PKCS1
    ).unwrap());
}

#[library_benchmark]
fn bench_rsa_symmetric_encrypt() {
    let chacha_key = [0u8; 32];
    let message = b"Secret message";
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&chacha_key));

    black_box(cipher.encrypt(black_box(nonce), black_box(message.as_ref())).expect("Encryption failed"));
}

#[library_benchmark]
fn bench_rsa_symmetric_decrypt() {
    let chacha_key = [0u8; 32];
    let message = b"Secret message";
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&chacha_key));

    let ciphertext = cipher.encrypt(nonce, message.as_ref()).unwrap();

    black_box(cipher.decrypt(black_box(nonce), black_box(ciphertext.as_ref())).expect("Decryption failed"));
}

library_benchmark_group!(
    name = rsa_benchmarks_group;
    benchmarks = bench_rsa_key_generation, bench_rsa_key_transport, bench_rsa_key_recovery,
                bench_rsa_symmetric_encrypt, bench_rsa_symmetric_decrypt
);

main!(library_benchmark_groups = rsa_benchmarks_group);
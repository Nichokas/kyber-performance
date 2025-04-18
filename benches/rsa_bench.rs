use criterion::{black_box, criterion_group, criterion_main, Criterion};
use openssl::rsa::{Rsa, Padding};

fn generate_keypair() {
    let _rsa = Rsa::generate(7680).unwrap();
}

fn round_trip(keys: Rsa<openssl::pkey::Private>) {
    let message = b"Secret message";

    let mut encrypt_buf = vec![0; keys.size() as usize];
    let encrypted_len = keys.public_encrypt(message, &mut encrypt_buf, Padding::PKCS1).unwrap();
    encrypt_buf.truncate(encrypted_len);

    let mut decrypt_buf = vec![0; keys.size() as usize];
    let decrypted_len = keys.private_decrypt(&encrypt_buf, &mut decrypt_buf, Padding::PKCS1).unwrap();
    decrypt_buf.truncate(decrypted_len);
}

fn criterion_benchmark(c: &mut Criterion) {

    c.bench_function("Generate RSA keypair", |b| b.iter(generate_keypair));

    let rsa = Rsa::generate(7680).unwrap();
    c.bench_function("RSA Encryption and Decryption", |b| {
        b.iter(|| round_trip(black_box(rsa.clone())))
    });
}

criterion_group! {
    name = rsa;
    config = Criterion::default()
        .sample_size(1000)
        .warm_up_time(std::time::Duration::from_secs(5))
        .measurement_time(std::time::Duration::from_secs(30))
        .confidence_level(0.99)
        .with_plots();
    targets = criterion_benchmark
}
criterion_main!(rsa);

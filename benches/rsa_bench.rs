use criterion::{black_box, criterion_group, criterion_main, Criterion};
use openssl::rsa::{Rsa, Padding};

fn generate_keypair() {
    let rsa = Rsa::generate(7680).unwrap();
}

fn round_trip(keys: Rsa<openssl::pkey::Private>){
    let message = b"Secret message";
    let mut buf = vec![0; keys.size() as usize];
    let _encrypted_len = keys.public_encrypt(message, &mut buf, Padding::PKCS1).unwrap();
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("Generate RSA keypair", |b| b.iter(generate_keypair));

    let rsa = Rsa::generate(7680).unwrap();
    c.bench_function("Kyber Encryption and Decryption (and key exchange)", |b| {
        b.iter(|| round_trip(black_box(rsa.clone())))
    });
}

criterion_group!(rsa, criterion_benchmark);
criterion_main!(rsa);
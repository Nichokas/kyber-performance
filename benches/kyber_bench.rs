use criterion::{black_box, criterion_group, criterion_main, Criterion};
use kychacha_crypto::{decrypt, encrypt, generate_keypair, Keypair};

fn round_trip(server_kp:Keypair){
    let message = b"Secret message";
    let encrypted_data: Vec<u8> = encrypt(&server_kp.public, message).unwrap();
    let decrypted_message = decrypt(&encrypted_data, &server_kp).unwrap();
}

fn criterion_benchmark(c: &mut Criterion) {
    let server_kp = generate_keypair().unwrap();

    c.bench_function("Generate kyber keypair", |b| b.iter(|| generate_keypair()));
    c.bench_function("Encryption and Decryption (and key exchange)", |b| b.iter(|| round_trip(black_box(server_kp))));
}

criterion_group!(kyber, criterion_benchmark);
criterion_main!(kyber);
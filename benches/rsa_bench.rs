use criterion::{black_box, criterion_group, criterion_main, Criterion};
use openssl::rsa::{Rsa, Padding};

fn generate_keypair() {
    let rsa = Rsa::generate(7680).unwrap();
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("Generate RSA keypair", |b| b.iter(generate_keypair));
}

criterion_group!(rsa, criterion_benchmark);
criterion_main!(rsa);
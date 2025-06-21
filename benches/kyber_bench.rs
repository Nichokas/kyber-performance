use iai_callgrind::{black_box, library_benchmark, library_benchmark_group, main};
use kychacha_crypto::{decrypt, encrypt, generate_keypair};

#[library_benchmark]
fn bench_kyber_key_generation() {
    black_box(generate_keypair());
}

#[library_benchmark]
fn bench_kyber_encapsulate() {
    let server_kp = generate_keypair();
    let message = b"Secret message";
    black_box(encrypt(black_box(server_kp.public_key), black_box(message)));
}

#[library_benchmark]
fn bench_kyber_decapsulate() {
    let server_kp = generate_keypair();
    let message = b"Secret message";
    let encrypted_data: Vec<u8> = encrypt(server_kp.public_key, message).unwrap();
    black_box(decrypt(
        black_box(&encrypted_data),
        black_box(&server_kp.private_key),
    ));
}

library_benchmark_group!(
    name = kyber_benchmarks_group;
    benchmarks = bench_kyber_key_generation, bench_kyber_encapsulate, bench_kyber_decapsulate
);

main!(library_benchmark_groups = kyber_benchmarks_group);
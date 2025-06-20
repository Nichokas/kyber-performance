use iai::black_box;
use kychacha_crypto::{decrypt, encrypt, generate_keypair};

/// Mide únicamente la generación del par de claves de Kyber.
fn bench_kyber_key_generation() {
    black_box(generate_keypair());
}

/// Mide la encapsulación: usa una clave pública para generar un secreto compartido y un ciphertext.
fn bench_kyber_encapsulate() {
    let server_kp = generate_keypair();
    let message = b"Secret message";
    // Medimos solo la función `encrypt`
    black_box(encrypt(black_box(server_kp.public_key), black_box(message)));
}

/// Mide la desencapsulación: usa una clave privada para recuperar el secreto compartido.
fn bench_kyber_decapsulate() {
    let server_kp = generate_keypair();
    let message = b"Secret message";
    // Preparamos los datos cifrados fuera de la medición principal
    let encrypted_data: Vec<u8> = encrypt(server_kp.public_key, message).unwrap();
    // Medimos solo la función `decrypt`
    black_box(decrypt(
        black_box(&encrypted_data),
        black_box(&server_kp.private_key),
    ));
}

iai::main!(
    bench_kyber_key_generation,
    bench_kyber_encapsulate,
    bench_kyber_decapsulate,
);

use openssl::rsa::{Rsa, Padding};
use iai::black_box;

/// Mide únicamente la generación del par de claves RSA de 7680 bits.
fn bench_rsa_key_generation() {
    black_box(Rsa::generate(7680).unwrap());
}

/// Mide únicamente la operación de cifrado con la clave pública.
fn bench_rsa_encrypt() {
    let keys = Rsa::generate(7680).unwrap();
    let message = b"Secret message";
    let mut encrypt_buf = vec![0; keys.size() as usize];

    // Medimos solo la función `public_encrypt`
    black_box(keys.public_encrypt(black_box(message), &mut encrypt_buf, Padding::PKCS1).unwrap());
}

/// Mide únicamente la operación de descifrado con la clave privada.
fn bench_rsa_decrypt() {
    let keys = Rsa::generate(7680).unwrap();
    let message = b"Secret message";
    // Preparamos los datos cifrados fuera de la medición principal
    let mut encrypt_buf = vec![0; keys.size() as usize];
    let encrypted_len = keys.public_encrypt(message, &mut encrypt_buf, Padding::PKCS1).unwrap();
    encrypt_buf.truncate(encrypted_len);

    let mut decrypt_buf = vec![0; keys.size() as usize];
    // Medimos solo la función `private_decrypt`
    black_box(keys.private_decrypt(black_box(&encrypt_buf), &mut decrypt_buf, Padding::PKCS1).unwrap());
}

iai::main!(
    bench_rsa_key_generation,
    bench_rsa_encrypt,
    bench_rsa_decrypt,
);
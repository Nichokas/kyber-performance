use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use openssl::derive::Deriver;
use chacha20poly1305::{aead::{KeyInit, Aead}, ChaCha20Poly1305, Nonce, Key};
use rand::{Rng, rngs::OsRng};
use sha2::Sha256;
use hkdf::Hkdf;
use iai::black_box;

// La función auxiliar para derivar la clave simétrica se mantiene igual
fn derive_chacha_key(shared_secret: &[u8]) -> [u8; 32] {
    let salt = b"SECP384R1-ChaCha20Poly1305";
    let info = b"key derivation for ECDH-ChaCha20Poly1305";
    let hk = Hkdf::<Sha256>::new(Some(salt), shared_secret);
    let mut chacha_key = [0u8; 32];
    hk.expand(info, &mut chacha_key).expect("HKDF expansion failed");
    chacha_key
}

/// Mide únicamente la generación del par de claves ECC (SECP384R1).
fn bench_ecc_key_generation() {
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    black_box(EcKey::generate(&group).unwrap());
}

/// Mide la derivación del secreto compartido (el núcleo de ECDH).
fn bench_ecc_shared_secret_derivation() {
    // Preparamos las claves de las dos partes
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let private_key_a = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    let public_key_b = PKey::from_ec_key(EcKey::generate(&group).unwrap().public_key_to_pem().and_then(|pem| EcKey::public_key_from_pem(&pem)).unwrap()).unwrap();

    let mut deriver = Deriver::new(&private_key_a).unwrap();
    deriver.set_peer(&public_key_b).unwrap();

    // Medimos solo la función `derive_to_vec`
    black_box(deriver.derive_to_vec().unwrap());
}

/// Mide el cifrado simétrico con ChaCha20Poly1305, usando una clave previamente derivada.
fn bench_ecc_symmetric_encrypt() {
    let chacha_key = [0u8; 32]; // Usamos una clave dummy, ya que no medimos la derivación aquí
    let message = b"Secret message";
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&chacha_key));

    // Medimos solo la función `encrypt`
    black_box(cipher.encrypt(black_box(nonce), black_box(message.as_ref())).expect("Encryption failed"));
}

/// Mide el descifrado simétrico con ChaCha20Poly1305.
fn bench_ecc_symmetric_decrypt() {
    let chacha_key = [0u8; 32];
    let message = b"Secret message";
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&chacha_key));
    // Preparamos el ciphertext
    let ciphertext = cipher.encrypt(nonce, message.as_ref()).unwrap();

    // Medimos solo la función `decrypt`
    black_box(cipher.decrypt(black_box(nonce), black_box(ciphertext.as_ref())).expect("Decryption failed"));
}

iai::main!(
    bench_ecc_key_generation,
    bench_ecc_shared_secret_derivation,
    bench_ecc_symmetric_encrypt,
    bench_ecc_symmetric_decrypt,
);
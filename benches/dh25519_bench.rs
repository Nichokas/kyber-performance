use criterion::{black_box, criterion_group, criterion_main, Criterion};
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use openssl::derive::Deriver;
use chacha20poly1305::{
    aead::{KeyInit, Aead},
    ChaCha20Poly1305, Nonce, Key,
};
use rand::{Rng, rngs::OsRng};
use sha2::Sha256;
use hkdf::Hkdf;
use bincode::{config, Encode, Decode};

// Serialized encrypted data format
#[derive(Encode, Decode, Debug)]
struct EncryptedMessage {
    #[bincode(with_serde)]
    nonce: Vec<u8>,
    #[bincode(with_serde)]
    ciphertext: Vec<u8>,
}

fn generate_keypair() {
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();

    let key = EcKey::generate(&group).unwrap();
    let _priv_key = PKey::from_ec_key(key.clone()).unwrap();
    let pub_key_point = key.public_key();
    let pub_key = EcKey::from_public_key(&group, pub_key_point).unwrap();
    let _pub_pkey = PKey::from_ec_key(pub_key).unwrap();
}

// Derive ChaCha20Poly1305 key
fn derive_chacha_key(shared_secret: &[u8]) -> [u8; 32] {
    // Derivar clave usando HKDF con SHA-256
    let salt = b"SECP384R1-ChaCha20Poly1305";
    let info = b"key derivation for ECDH-ChaCha20Poly1305";

    let hk = Hkdf::<Sha256>::new(Some(salt), shared_secret);
    let mut chacha_key = [0u8; 32];
    hk.expand(info, &mut chacha_key).expect("HKDF expansion failed");

    chacha_key
}

fn round_trip(private_key: PKey<Private>, public_key: PKey<Public>) {
    let message = b"Secret message";

    let mut deriver = Deriver::new(&private_key).unwrap();
    deriver.set_peer(&public_key).unwrap();
    let shared_secret = deriver.derive_to_vec().unwrap();
    let chacha_key = derive_chacha_key(&shared_secret);

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&chacha_key));
    let ciphertext = cipher.encrypt(nonce, message.as_ref())
        .expect("Encryption failed");

    // Bincode Serialization/Deserialization
    let encrypted_msg = EncryptedMessage {
        nonce: nonce_bytes.to_vec(),
        ciphertext,
    };

    let config = config::standard()
        .with_big_endian()
        .with_variable_int_encoding();

    let serialized = bincode::encode_to_vec(&encrypted_msg, config).unwrap();

    let (deserialized, _) = bincode::decode_from_slice::<EncryptedMessage, _>(&serialized, config).unwrap();

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&chacha_key));
    let _plaintext = cipher.decrypt(
        Nonce::from_slice(&deserialized.nonce),
        deserialized.ciphertext.as_ref()
    ).expect("Decryption failed");
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("Generate SECP384R1 keypair", |b| b.iter(generate_keypair));

    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let key = EcKey::generate(&group).unwrap();
    let priv_key = PKey::from_ec_key(key.clone()).unwrap();
    let pub_key_point = key.public_key();
    let pub_key = EcKey::from_public_key(&group, pub_key_point).unwrap();
    let pub_pkey = PKey::from_ec_key(pub_key).unwrap();
    c.bench_function("SECP384R1 Encryption and Decryption (also key exchange and serializations(bincode)", |b| {
        b.iter(|| round_trip(black_box(priv_key.clone()), black_box(pub_pkey.clone())))
    });
}

criterion_group! {
    name = ecc;
    config = Criterion::default()
        .sample_size(1000)
        .warm_up_time(std::time::Duration::from_secs(5))
        .measurement_time(std::time::Duration::from_secs(30))
        .confidence_level(0.99)
        .with_plots();
    targets = criterion_benchmark
}
criterion_main!(ecc);


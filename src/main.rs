use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit},
};
use crypto_testing::{
    ecies_receiver, ecies_sender, ml_kem_derive_chacha_key, rsa_decrypt_key, rsa_derive_chacha_key,
    rsa_encrypt_key,
};
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use oqs::kem::{Algorithm, Kem};
use rand::{RngCore, rngs::OsRng};

struct EncryptedPayload {
    nonce: Nonce,
    ciphertext: Vec<u8>,
}

impl EncryptedPayload {
    fn encrypt(key: &[u8; 32], message: &[u8]) -> Self {
        let mut nonce = Nonce::default();
        OsRng.fill_bytes(&mut nonce);
        let cipher = ChaCha20Poly1305::new(&Key::from(*key));
        let ciphertext = cipher
            .encrypt(&nonce, message)
            .expect("ChaCha20-Poly1305 encryption failed");
        Self { nonce, ciphertext }
    }

    fn decrypt(&self, key: &[u8; 32]) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new(&Key::from(*key));
        cipher
            .decrypt(&self.nonce, self.ciphertext.as_slice())
            .expect("ChaCha20-Poly1305 decryption failed")
    }
}

struct ECCEncryptedMessage {
    ephemeral_pk: Vec<u8>,
    payload: EncryptedPayload,
}

struct RSAEncryptedMessage {
    encrypted_key: Vec<u8>,
    payload: EncryptedPayload,
}

struct MlKemEncryptedMessage {
    kem_ciphertext: Vec<u8>,
    payload: EncryptedPayload,
}

fn print_overhead(message_size: usize, key_material: &[u8], payload: &EncryptedPayload) {
    let key_bytes = key_material.len();
    let nonce_bytes = payload.nonce.len();
    let tag_bytes = payload.ciphertext.len() - message_size;
    let wire_bytes = key_bytes + nonce_bytes + tag_bytes;
    print!(",{key_bytes},{nonce_bytes},{tag_bytes},{wire_bytes}");
}

fn main() {
    oqs::init();
    let kem = Kem::new(Algorithm::MlKem768).unwrap();
    let (kem_public, kem_private) = kem.keypair().unwrap();

    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let recipient = EcKey::generate(&group).unwrap();
    let ec_public =
        PKey::from_ec_key(EcKey::from_public_key(&group, recipient.public_key()).unwrap()).unwrap();
    let ec_private = PKey::from_ec_key(recipient).unwrap();

    let rsa_private = PKey::from_rsa(Rsa::generate(7680).unwrap()).unwrap();
    let rsa_public = PKey::public_key_from_der(&rsa_private.public_key_to_der().unwrap()).unwrap();

    println!(concat!(
        "message_bytes,",
        "ml_kem_ciphertext_bytes,ml_kem_nonce_bytes,ml_kem_tag_bytes,ml_kem_wire_overhead_bytes,",
        "ecc_ephemeral_key_bytes,ecc_nonce_bytes,ecc_tag_bytes,ecc_wire_overhead_bytes,",
        "rsa_wrapped_key_bytes,rsa_nonce_bytes,rsa_tag_bytes,rsa_wire_overhead_bytes"
    ));

    for size in [0, 16, 64, 256, 1024, 4096] {
        let message = vec![0u8; size];

        let (kem_ciphertext, secret) = kem.encapsulate(&kem_public).unwrap();
        let kem_msg = MlKemEncryptedMessage {
            kem_ciphertext: kem_ciphertext.into_vec(),
            payload: EncryptedPayload::encrypt(
                &ml_kem_derive_chacha_key(secret.as_ref()),
                &message,
            ),
        };
        let received_ciphertext = kem
            .ciphertext_from_bytes(&kem_msg.kem_ciphertext)
            .expect("Invalid ML-KEM ciphertext length");
        let received_secret = kem.decapsulate(&kem_private, received_ciphertext).unwrap();
        assert_eq!(secret.as_ref(), received_secret.as_ref());
        let key = ml_kem_derive_chacha_key(received_secret.as_ref());
        assert_eq!(kem_msg.payload.decrypt(&key), message);

        let (ephemeral_pk, key) = ecies_sender(&group, &ec_public);
        let ec_msg = ECCEncryptedMessage {
            ephemeral_pk,
            payload: EncryptedPayload::encrypt(&key, &message),
        };
        let key = ecies_receiver(&group, &ec_private, &ec_msg.ephemeral_pk);
        assert_eq!(ec_msg.payload.decrypt(&key), message);

        let mut secret = [0; 32];
        OsRng.fill_bytes(&mut secret);
        let rsa_msg = RSAEncryptedMessage {
            encrypted_key: rsa_encrypt_key(&rsa_public, &secret),
            payload: EncryptedPayload::encrypt(&rsa_derive_chacha_key(&secret), &message),
        };
        let received_secret = rsa_decrypt_key(&rsa_private, &rsa_msg.encrypted_key);
        let key = rsa_derive_chacha_key(&received_secret);
        assert_eq!(rsa_msg.payload.decrypt(&key), message);

        print!("{size}");
        print_overhead(size, &kem_msg.kem_ciphertext, &kem_msg.payload);
        print_overhead(size, &ec_msg.ephemeral_pk, &ec_msg.payload);
        print_overhead(size, &rsa_msg.encrypted_key, &rsa_msg.payload);
        println!();
    }
}

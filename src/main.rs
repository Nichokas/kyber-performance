use bincode::{config, Decode, Encode};
use bincode::encode_to_vec;
use kychacha_crypto::{encrypt, generate_keypair};
use chacha20poly1305::{
    aead::{KeyInit, Aead},
    ChaCha20Poly1305, Nonce, Key,
};
use chacha20poly1305::aead::OsRng;
use hkdf::Hkdf;
use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use rand::Rng;
use sha2::Sha256;

#[derive(Encode, Decode, Debug)]
struct ECCEncryptedMessage {
    #[bincode(with_serde)]
    nonce: Vec<u8>,
    #[bincode(with_serde)]
    ciphertext: Vec<u8>,
}

fn ecc_derive_chacha_key(shared_secret: &[u8]) -> [u8; 32] {
    // Derivar clave usando HKDF con SHA-256
    let salt = b"SECP384R1-ChaCha20Poly1305";
    let info = b"key derivation for ECDH-ChaCha20Poly1305";

    let hk = Hkdf::<Sha256>::new(Some(salt), shared_secret);
    let mut chacha_key = [0u8; 32];
    hk.expand(info, &mut chacha_key).expect("HKDF expansion failed");

    chacha_key
}

fn main() {
    let message = b"Secret message";
    println!("message len: {:?}", message.len());


    // kyber (with authentication and nonce)
    {
    let server_kp=generate_keypair().unwrap();
    let encrypted_data: Vec<u8> = encrypt(&server_kp.public, message).unwrap();
    println!("Kyber (with authentication and nonce) len: {:?}", encrypted_data.len());
    }

    // ECC (with nonce)
    {
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let key = EcKey::generate(&group).unwrap();
    let priv_key = PKey::from_ec_key(key.clone()).unwrap();
    let pub_key_point = key.public_key();
    let pub_key = EcKey::from_public_key(&group, pub_key_point).unwrap();
    let pub_pkey = PKey::from_ec_key(pub_key).unwrap();

    let mut deriver = Deriver::new(&priv_key).unwrap();
    deriver.set_peer(&pub_pkey).unwrap();
    let shared_secret = deriver.derive_to_vec().unwrap();
    let chacha_key = ecc_derive_chacha_key(&shared_secret);

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&chacha_key));
    let ciphertext = cipher.encrypt(nonce, message.as_ref())
        .expect("Encryption failed");

    let encrypted_msg = ECCEncryptedMessage {
        nonce: nonce_bytes.to_vec(),
        ciphertext,
    };

    let config = config::standard()
        .with_big_endian()
        .with_variable_int_encoding();

    let serialized = encode_to_vec(&encrypted_msg, config).unwrap();
        println!("ECC (with nonce) len: {:?}", serialized.len());
    }

    // RSA
    {
        let rsa = openssl::rsa::Rsa::generate(7680).unwrap();

        let mut encrypt_buf = vec![0; rsa.size() as usize];
        let encrypted_len = rsa.public_encrypt(message, &mut encrypt_buf, openssl::rsa::Padding::PKCS1).unwrap();
        encrypt_buf.truncate(encrypted_len);

        println!("RSA len: {:?}", encrypt_buf.len());
    }
}
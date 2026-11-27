use hkdf::Hkdf;
use openssl::bn::BigNumContext;
use openssl::derive::Deriver;
use openssl::ec::{EcGroupRef, EcKey, EcPoint, PointConversionForm};
use openssl::md::Md;
use openssl::pkey::{HasPublic, PKey, PKeyRef, Private, Public};
use openssl::pkey_ctx::PkeyCtx;
use openssl::rsa::Padding;
use sha2::Sha256;

fn derive_chacha_key(secret: &[u8], salt: &[u8], info: &[&[u8]]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), secret);
    let mut key = [0; 32];
    hkdf.expand_multi_info(info, &mut key)
        .expect("HKDF expansion failed");
    key
}

pub fn ml_kem_derive_chacha_key(secret: &[u8]) -> [u8; 32] {
    derive_chacha_key(
        secret,
        b"Kyber-ChaCha20Poly1305",
        &[b"key derivation for Kyber-ChaCha20Poly1305"],
    )
}

pub fn rsa_derive_chacha_key(secret: &[u8]) -> [u8; 32] {
    derive_chacha_key(
        secret,
        b"RSA-ChaCha20Poly1305",
        &[b"key derivation for RSA-ChaCha20Poly1305"],
    )
}

fn ecies_derive_chacha_key(
    private_key: &PKeyRef<Private>,
    peer: &PKeyRef<Public>,
    ephemeral_pk: &[u8],
) -> [u8; 32] {
    let mut deriver = Deriver::new(private_key).unwrap();
    deriver.set_peer(peer).unwrap();
    let secret = deriver.derive_to_vec().unwrap();
    derive_chacha_key(
        &secret,
        b"SECP384R1-ChaCha20Poly1305",
        &[b"key derivation for ECDH-ChaCha20Poly1305", ephemeral_pk],
    )
}

pub fn ecies_sender(group: &EcGroupRef, recipient_public: &PKeyRef<Public>) -> (Vec<u8>, [u8; 32]) {
    let ephemeral = EcKey::generate(group).unwrap();
    let mut context = BigNumContext::new().unwrap();
    let ephemeral_pk = ephemeral
        .public_key()
        .to_bytes(group, PointConversionForm::UNCOMPRESSED, &mut context)
        .unwrap();
    let ephemeral_private = PKey::from_ec_key(ephemeral).unwrap();
    let key = ecies_derive_chacha_key(&ephemeral_private, recipient_public, &ephemeral_pk);
    (ephemeral_pk, key)
}

pub fn ecies_receiver(
    group: &EcGroupRef,
    recipient_private: &PKeyRef<Private>,
    ephemeral_pk: &[u8],
) -> [u8; 32] {
    let mut context = BigNumContext::new().unwrap();
    let point = EcPoint::from_bytes(group, ephemeral_pk, &mut context).unwrap();
    let ephemeral_public =
        PKey::from_ec_key(EcKey::from_public_key(group, &point).unwrap()).unwrap();
    ecies_derive_chacha_key(recipient_private, &ephemeral_public, ephemeral_pk)
}

fn configure_oaep<T>(context: &mut PkeyCtx<T>) {
    context.set_rsa_padding(Padding::PKCS1_OAEP).unwrap();
    context.set_rsa_oaep_md(Md::sha256()).unwrap();
    context.set_rsa_mgf1_md(Md::sha256()).unwrap();
}

pub fn rsa_encrypt_key(key: &PKeyRef<impl HasPublic>, secret: &[u8]) -> Vec<u8> {
    let mut context = PkeyCtx::new(key).unwrap();
    context.encrypt_init().unwrap();
    configure_oaep(&mut context);
    let mut encrypted_key = Vec::new();
    context
        .encrypt_to_vec(secret, &mut encrypted_key)
        .expect("RSA-OAEP encryption failed");
    encrypted_key
}

pub fn rsa_decrypt_key(key: &PKeyRef<Private>, encrypted_key: &[u8]) -> Vec<u8> {
    let mut context = PkeyCtx::new(key).unwrap();
    context.decrypt_init().unwrap();
    configure_oaep(&mut context);
    let mut secret = Vec::new();
    context
        .decrypt_to_vec(encrypted_key, &mut secret)
        .expect("RSA-OAEP decryption failed");
    secret
}

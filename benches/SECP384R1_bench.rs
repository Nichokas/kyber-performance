use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use openssl::derive::Deriver;
use chacha20poly1305::{aead::{KeyInit, Aead}, ChaCha20Poly1305, Nonce, Key};
use rand::{Rng, rngs::OsRng};
use sha2::Sha256;
use hkdf::Hkdf;
use iai_callgrind::{black_box, library_benchmark, library_benchmark_group, main};

// La función auxiliar para derivar la clave simétrica se mantiene igual
fn derive_chacha_key(shared_secret: &[u8]) -> [u8; 32] {
    let salt = b"SECP384R1-ChaCha20Poly1305";
    let info = b"key derivation for ECDH-ChaCha20Poly1305";
    let hk = Hkdf::<Sha256>::new(Some(salt), shared_secret);
    let mut chacha_key = [0u8; 32];
    hk.expand(info, &mut chacha_key).expect("HKDF expansion failed");
    chacha_key
}

#[library_benchmark]
fn bench_ecc_key_generation() {
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    black_box(EcKey::generate(&group).unwrap());
}

#[library_benchmark]
fn bench_ecc_shared_secret_derivation() {
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let private_key_a = EcKey::generate(&group).unwrap();
    let public_key_b = EcKey::generate(&group).unwrap();

    let private_pkey = PKey::from_ec_key(private_key_a).unwrap();
    let public_pkey = PKey::from_ec_key(public_key_b).unwrap();

    let mut deriver = Deriver::new(&private_pkey).unwrap();
    deriver.set_peer(&public_pkey).unwrap();
    let shared_secret = deriver.derive_to_vec().unwrap();

    // Incluimos la derivación de la clave simétrica
    black_box(derive_chacha_key(&shared_secret));
}


library_benchmark_group!(
    name = ecc_benchmarks_group;
    benchmarks = bench_ecc_shared_secret_derivation, bench_ecc_key_generation
);

main!(library_benchmark_groups = ecc_benchmarks_group);
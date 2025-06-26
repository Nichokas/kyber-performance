use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use openssl::derive::Deriver;
use sha2::Sha256;
use hkdf::Hkdf;
use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use std::hint::black_box;

fn derive_chacha_key(shared_secret: &[u8]) -> [u8; 32] {
    let salt = b"SECP384R1-ChaCha20Poly1305";
    let info = b"key derivation for ECDH-ChaCha20Poly1305";
    let hk = Hkdf::<Sha256>::new(Some(salt), shared_secret);
    let mut chacha_key = [0u8; 32];
    hk.expand(info, &mut chacha_key).expect("HKDF expansion failed");
    chacha_key
}

// Setup function para generar claves (excluida de la medición)
fn setup_ecc_keys() -> (PKey<Private>, PKey<Public>) {
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();

    // Generar clave privada
    let private_key = EcKey::generate(&group).unwrap();
    let private_pkey = PKey::from_ec_key(private_key).unwrap();

    // Generar clave pública separada
    let public_key = EcKey::generate(&group).unwrap();
    let public_point = public_key.public_key().to_owned(&group).unwrap();
    let public_ec_key = EcKey::from_public_key(&group, &public_point).unwrap();
    let public_pkey = PKey::from_ec_key(public_ec_key).unwrap();

    (private_pkey, public_pkey)
}

#[library_benchmark]
fn bench_ecc_key_generation() {
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    black_box(EcKey::generate(&group).unwrap());
}

#[library_benchmark]
#[bench::with_setup(setup = setup_ecc_keys)]
fn bench_ecc_shared_secret_derivation(keys: (PKey<Private>, PKey<Public>)) {
    let (private_key, public_key) = keys;
    let mut deriver = Deriver::new(&private_key).unwrap();
    deriver.set_peer(&public_key).unwrap();

    // Solo medimos desde aquí
    let shared_secret = black_box(deriver.derive_to_vec().unwrap());
    black_box(derive_chacha_key(&shared_secret));
}

library_benchmark_group!(
    name = ecc_benchmarks_group;
    benchmarks = bench_ecc_key_generation, bench_ecc_shared_secret_derivation
);

main!(library_benchmark_groups = ecc_benchmarks_group);
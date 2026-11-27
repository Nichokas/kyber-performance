use crypto_testing::{ecies_receiver, ecies_sender};
use gungraun::{library_benchmark, library_benchmark_group, main};
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use std::hint::black_box;

fn warm_group() -> EcGroup {
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    EcKey::generate(&group).unwrap();
    group
}

fn setup_sender() -> (EcGroup, PKey<Public>) {
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let recipient = EcKey::generate(&group).unwrap();
    let public = EcKey::from_public_key(&group, recipient.public_key()).unwrap();
    (group, PKey::from_ec_key(public).unwrap())
}

fn setup_receiver() -> (EcGroup, PKey<Private>, Vec<u8>) {
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let recipient = EcKey::generate(&group).unwrap();
    let public = EcKey::from_public_key(&group, recipient.public_key()).unwrap();
    let public = PKey::from_ec_key(public).unwrap();
    let (ephemeral_pk, _) = ecies_sender(&group, &public);
    (group, PKey::from_ec_key(recipient).unwrap(), ephemeral_pk)
}

#[library_benchmark]
#[bench::warm(setup = warm_group)]
fn bench_ecc_key_generation(group: EcGroup) {
    black_box(EcKey::generate(&group).unwrap());
}

#[library_benchmark]
#[bench::sender(setup = setup_sender)]
fn bench_ecies_sender(input: (EcGroup, PKey<Public>)) {
    let (group, recipient_public) = input;
    black_box(ecies_sender(&group, &recipient_public));
}

#[library_benchmark]
#[bench::receiver(setup = setup_receiver)]
fn bench_ecies_receiver(input: (EcGroup, PKey<Private>, Vec<u8>)) {
    let (group, recipient_private, ephemeral_pk) = input;
    black_box(ecies_receiver(&group, &recipient_private, &ephemeral_pk));
}

library_benchmark_group!(
    name = ecc_benchmarks_group;
    benchmarks = bench_ecc_key_generation, bench_ecies_sender, bench_ecies_receiver
);

main!(library_benchmark_groups = ecc_benchmarks_group);

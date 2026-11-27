# Post-Quantum Crypto: A Performance and Overhead Analysis

Code for the [study](https://doi.org/10.48550/arXiv.2508.01694) comparing ML-KEM-768, RSA-7680, and ECIES over secp384r1.

## Run locally

Install Rust, Valgrind, Clang with libclang, CMake, Perl, and a C toolchain.

```bash
cargo install --locked gungraun-runner --version 0.20.0
cargo run --release --locked
cargo bench --locked
```

To time only RSA key generation:

```bash
time cargo bench --locked --bench rsa_bench -- \
  'rsa_bench::rsa_benchmarks_group::bench_rsa_key_generation::warm'
```

## Run in CI

In **Actions**, run **Benchmarks (Blacksmith)** or **Benchmarks (Depot)**. Each workflow runs on x86_64 and AArch64 with 2 vCPU per runner. Download the artifacts for the samples, summary statistics, and `lscpu` output.

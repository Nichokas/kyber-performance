# Post-Quantum Crypto: A Performance and Overhead Analysis
This repository contains the source code for a comparative study on the performance and storage overhead of Kyber, RSA, and ECC cryptographic algorithms.
## Prerequisites
Ensure you have the following software installed:
* Rust: Install from rustup.rs.
* Valgrind: Required for the iai-callgrind benchmarking tool.
* iai-callgrind-runner: Install the crate iai-callgrind-runner for running the benchmarks:
  ```bash
  cargo install iai-callgrind-runner
  ```

## How to Reproduce the Data
> [!WARNING]  
> This command will take a significant amount of time to complete as it runs extensive performance tests. It is expected to take more than two hours.

To measure the computational performance of key generation, encapsulation/encryption, and decapsulation/decryption, run the following command from the project root:
```bash
cargo bench
```
This will execute all benchmark tests located in the benches/ directory for Kyber, RSA, and ECC.

## Storage Overhead
To calculate the storage overhead for encrypted messages of various sizes, run this command:
```bash
cargo run --release
```
This command will display the results on your screen.

## Study DOI
For a detailed analysis of the methodology and results, please refer to the full study.

DOI: https://doi.org/10.48550/arXiv.2508.01694

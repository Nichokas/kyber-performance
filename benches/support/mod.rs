use gungraun::{Callgrind, LibraryBenchmarkConfig};

pub fn callgrind_config() -> LibraryBenchmarkConfig {
    LibraryBenchmarkConfig::default()
        .tool(Callgrind::default().args([
            "--I1=32768,8,64",
            "--D1=32768,8,64",
            "--LL=8388608,16,64",
        ]))
        .pass_through_envs(["OPENSSL_ia32cap", "OPENSSL_armcap"])
        .clone()
}

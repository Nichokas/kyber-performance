use oqs::ffi::common::{OQS_CPU_EXT, OQS_CPU_has_extension};
use std::ffi::{CStr, c_char, c_int};

const OPENSSL_INFO_CPU_SETTINGS: c_int = 1008;

unsafe extern "C" {
    fn OPENSSL_info(kind: c_int) -> *const c_char;
}

#[cfg(target_arch = "x86_64")]
fn print_rust_features() {
    macro_rules! features {
        ($($name:tt),+ $(,)?) => {
            $(println!("rust.{}={}", $name, std::arch::is_x86_feature_detected!($name));)+
        };
    }
    features!(
        "aes",
        "avx",
        "avx2",
        "adx",
        "bmi1",
        "bmi2",
        "popcnt",
        "sha",
        "ssse3",
        "sse4.1",
        "avx512f",
        "avx512ifma",
        "avx512vl",
        "pclmulqdq",
        "rdrand",
        "rdseed",
    );
}

#[cfg(target_arch = "aarch64")]
fn print_rust_features() {
    macro_rules! features {
        ($($name:tt),+ $(,)?) => {
            $(println!("rust.{}={}", $name, std::arch::is_aarch64_feature_detected!($name));)+
        };
    }
    features!("aes", "neon", "pmull", "sha2", "sha3", "sve", "sve2");
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn print_rust_features() {}

fn main() {
    println!("architecture={}", std::env::consts::ARCH);
    print_rust_features();
    println!("openssl.version={}", openssl::version::version());
    openssl::init();
    // SAFETY: OPENSSL_info returns null or a process-lifetime C string.
    let settings = unsafe {
        let ptr = OPENSSL_info(OPENSSL_INFO_CPU_SETTINGS);
        (!ptr.is_null()).then(|| CStr::from_ptr(ptr))
    };
    if let Some(settings) = settings {
        println!("openssl.{}", settings.to_string_lossy());
    }
    for name in ["OPENSSL_ia32cap", "OPENSSL_armcap"] {
        if let Some(value) = std::env::var_os(name) {
            println!("override.{name}={}", value.to_string_lossy());
        }
    }

    oqs::init();
    use OQS_CPU_EXT::*;
    for feature in [
        OQS_CPU_EXT_ADX,
        OQS_CPU_EXT_AES,
        OQS_CPU_EXT_AVX,
        OQS_CPU_EXT_AVX2,
        OQS_CPU_EXT_AVX512,
        OQS_CPU_EXT_BMI1,
        OQS_CPU_EXT_BMI2,
        OQS_CPU_EXT_PCLMULQDQ,
        OQS_CPU_EXT_VPCLMULQDQ,
        OQS_CPU_EXT_POPCNT,
        OQS_CPU_EXT_ARM_AES,
        OQS_CPU_EXT_ARM_NEON,
        OQS_CPU_EXT_ARM_SHA2,
        OQS_CPU_EXT_ARM_SHA3,
    ] {
        // SAFETY: Every feature is a valid liboqs CPU extension.
        let detected = unsafe { OQS_CPU_has_extension(feature) != 0 };
        println!("liboqs.{feature:?}={detected}");
    }
}

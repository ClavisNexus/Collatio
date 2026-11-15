//! Collatio measurement spike (spike/README.md).
//!
//! Only what the spike measures: P-256 ECDSA verification, RSASSA-PKCS1-v1_5
//! verification on crypto-bigint, and the RFC 8785 number form.
//! This is not the verifier. The ABI follows `collatio-abi@1` (ABI.md) so that
//! the hosts written for the spike can be reused.
#![no_std]

extern crate alloc;

mod abi;
mod jcs;
mod ops;
mod rsa;

pub use ops::run;

#[cfg(target_arch = "wasm32")]
#[global_allocator]
static ALLOC: dlmalloc::GlobalDlmalloc = dlmalloc::GlobalDlmalloc;

#[cfg(all(target_arch = "wasm32", not(test)))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}

//! Collatio: the verifier for Clavis receipts, records and ledger evidence.
//!
//! One WebAssembly module (`wasm32v1-none`, no imports) that every party runs to check the same
//! evidence the same way. Hosts call it through `collatio-abi@1` (ABI.md).
#![cfg_attr(target_arch = "wasm32", no_std)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )
)]

extern crate alloc;

pub mod b64;
pub mod challenge;
pub mod commit;
pub mod cose;
pub mod der;
pub mod digest;
pub mod dimension;
pub mod envelope;
pub mod fields;
pub mod jcs;
pub mod json;
pub mod keylog;
pub mod ledger;
pub mod logs;
pub mod reason;
pub mod receipt;
pub mod registry;
pub mod rsa;
pub mod shown;
pub mod text;
pub mod trust;
pub mod tsa;
pub mod tsa_registry;
pub mod webauthn;
pub mod x509;

mod ops;
pub use ops::{MAX_INPUT, run};

#[cfg(target_arch = "wasm32")]
mod abi;

#[cfg(all(target_arch = "wasm32", not(test)))]
#[global_allocator]
static ALLOC: dlmalloc::GlobalDlmalloc = dlmalloc::GlobalDlmalloc;

#[cfg(all(target_arch = "wasm32", not(test)))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}

//! `collatio-abi@1` exports (ABI.md).
//!
//! - `abi_version() -> i32`: the spec says an i32 global, but Rust cannot
//!   export a value global (a `static` exports its address), so the spike
//!   exports a function. Recorded as a finding.
//! - `alloc(len) -> ptr`, `free(ptr, len)`.
//! - `verify(in_ptr, in_len) -> out_ptr`: the answer starts with a 4-byte
//!   little-endian length; the caller returns it with `free(out_ptr, 4 + len)`.

#[cfg(target_arch = "wasm32")]
mod exports {
    use alloc::alloc::{Layout, alloc as raw_alloc, dealloc};
    use alloc::vec::Vec;

    /// Inputs above this are refused before parsing.
    const MAX_INPUT: usize = 4 * 1024 * 1024;

    #[unsafe(no_mangle)]
    pub extern "C" fn abi_version() -> i32 {
        1
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn alloc(len: usize) -> *mut u8 {
        if len == 0 {
            return core::ptr::NonNull::<u8>::dangling().as_ptr();
        }
        match Layout::from_size_align(len, 1) {
            Ok(layout) => unsafe { raw_alloc(layout) },
            Err(_) => core::ptr::null_mut(),
        }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn free(ptr: *mut u8, len: usize) {
        if len == 0 || ptr.is_null() {
            return;
        }
        if let Ok(layout) = Layout::from_size_align(len, 1) {
            unsafe { dealloc(ptr, layout) }
        }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn verify(in_ptr: *const u8, in_len: usize) -> *mut u8 {
        let answer: Vec<u8> = if in_len > MAX_INPUT {
            br#"{"ok":false,"reason":"input_too_large"}"#.to_vec()
        } else {
            let input = unsafe { core::slice::from_raw_parts(in_ptr, in_len) };
            crate::ops::run(input)
        };
        let total = 4 + answer.len();
        let out = alloc(total);
        if out.is_null() {
            core::arch::wasm32::unreachable();
        }
        unsafe {
            core::ptr::copy_nonoverlapping((answer.len() as u32).to_le_bytes().as_ptr(), out, 4);
            core::ptr::copy_nonoverlapping(answer.as_ptr(), out.add(4), answer.len());
        }
        out
    }
}

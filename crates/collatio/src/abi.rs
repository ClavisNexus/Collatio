//! `collatio-abi@1` (ABI.md). Only built for WebAssembly.
//!
//! - `abi_version() -> i32` returns 1.
//! - `alloc(len) -> ptr` and `free(ptr, len)` manage byte buffers in linear memory.
//! - `verify(in_ptr, in_len) -> out_ptr`: the answer starts with its length as 4 little-endian
//!   bytes; the caller returns it with `free(out_ptr, 4 + len)`.

use alloc::alloc::{Layout, alloc as raw_alloc, dealloc};

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
        // SAFETY: the layout has a non-zero size.
        Ok(layout) => unsafe { raw_alloc(layout) },
        Err(_) => core::ptr::null_mut(),
    }
}

/// # Safety
/// `ptr` and `len` come from one earlier `alloc` (or a `verify` answer) and are freed once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn free(ptr: *mut u8, len: usize) {
    if len == 0 || ptr.is_null() {
        return;
    }
    if let Ok(layout) = Layout::from_size_align(len, 1) {
        // SAFETY: guaranteed by the caller.
        unsafe { dealloc(ptr, layout) }
    }
}

/// # Safety
/// `in_ptr` points to `in_len` readable bytes in linear memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn verify(in_ptr: *const u8, in_len: usize) -> *mut u8 {
    let answer = if in_len > crate::ops::MAX_INPUT || in_ptr.is_null() {
        crate::ops::refused(crate::reason::Reason::InputTooLarge)
    } else {
        // SAFETY: guaranteed by the caller.
        let input = unsafe { core::slice::from_raw_parts(in_ptr, in_len) };
        crate::ops::run(input)
    };
    let Ok(len) = u32::try_from(answer.len()) else {
        core::arch::wasm32::unreachable()
    };
    let total = answer.len().saturating_add(4);
    let out = alloc(total);
    if out.is_null() {
        core::arch::wasm32::unreachable()
    }
    // SAFETY: `out` has `total` bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(len.to_le_bytes().as_ptr(), out, 4);
        core::ptr::copy_nonoverlapping(answer.as_ptr(), out.add(4), answer.len());
    }
    out
}

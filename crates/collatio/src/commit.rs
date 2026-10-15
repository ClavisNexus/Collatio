//! Salted commitments, the content of ledger leaves.
//!
//! c = SHA-256("clavis.commit.v1" ‖ salt(32) ‖ UTF-8(JCS(record))), in lowercase hex. Only the
//! holder of the opening (salt and record) can show what a leaf commits to; erasing the opening
//! leaves the leaf bound to nothing.

use alloc::string::String;
use alloc::vec::Vec;
use sha2::{Digest as _, Sha256};

use crate::b64;
use crate::jcs::canonical;
use crate::json::Value;

pub const COMMIT_DOMAIN: &str = "clavis.commit.v1";
pub const SALT_BYTES: usize = 32;

const HEX: &[u8; 16] = b"0123456789abcdef";

pub fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        out.push(char::from(
            HEX.get(usize::from(b >> 4)).copied().unwrap_or(b'0'),
        ));
        out.push(char::from(
            HEX.get(usize::from(b & 0xf)).copied().unwrap_or(b'0'),
        ));
    }
    out
}

/// 64 lowercase hex digits.
pub fn is_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let digit = |b: u8| match b {
        b'0'..=b'9' => Some(b.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(b.wrapping_sub(b'a').wrapping_add(10)),
        _ => None,
    };
    s.as_bytes()
        .chunks(2)
        .map(|pair| match pair {
            [hi, lo] => Some(digit(*hi)?.wrapping_shl(4) | digit(*lo)?),
            _ => None,
        })
        .collect()
}

/// The commitment for an opening, or `None` when the salt is not 32 bytes of Base64URL.
pub fn commitment(salt_b64u: &str, record: &Value) -> Option<String> {
    let salt = b64::decode_len(salt_b64u, SALT_BYTES)?;
    let mut h = Sha256::new();
    h.update(COMMIT_DOMAIN.as_bytes());
    h.update(&salt);
    h.update(canonical(record).as_bytes());
    Some(to_hex(&h.finalize()))
}

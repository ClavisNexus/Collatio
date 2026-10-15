//! Key records: when a passkey's public key was bound to an account and when it was unbound.
//! Their commitments are leaves of the first-party ledger; only holders of the opening can check
//! them.

use crate::b64;
use crate::digest::is_digest;
use crate::json::{Object, Value};

pub const KEY_BOUND_1: &str = "key.bound@1";
pub const KEY_UNBOUND_1: &str = "key.unbound@1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyRecordKind {
    Bound,
    Unbound,
}

/// The ID grammar: 1 to 200 of `A-Z a-z 0-9 . _ ~ : @ + = / -`.
pub fn is_id(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._~:@+=/-".contains(&b))
}

/// Non-empty Base64URL text whose length can be Base64URL. Decoding is checked where the bytes
/// are used.
pub fn is_b64u_text(s: &str) -> bool {
    !s.is_empty()
        && s.len() % 4 != 1
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn safe_non_negative(o: &Object, key: &str) -> bool {
    o.get(key)
        .and_then(Value::as_number)
        .and_then(|n| n.as_safe_integer())
        .is_some_and(|i| i >= 0)
}

/// Checks the shape of a key record and says which kind it is.
pub fn parse_key_record(v: &Value) -> Option<KeyRecordKind> {
    let o = v.as_object()?;
    if !safe_non_negative(o, "at") {
        return None;
    }
    let signer = o.get("signer")?.as_str()?;
    let credential = o.get("credential")?.as_str()?;
    if !is_id(signer, 200) || !is_b64u_text(credential) {
        return None;
    }
    match o.get("type")?.as_str()? {
        KEY_BOUND_1 => {
            if o.len() != 8 {
                return None;
            }
            let public_key = o.get("public_key")?.as_str()?;
            let alg = o.get("alg")?.as_number()?.as_safe_integer()?;
            let rp = o.get("rp")?.as_str()?;
            let by = o.get("by")?.as_str()?;
            let rp_len = crate::text::utf16_len(rp);
            let by_ok = matches!(by, "registration" | "recovery" | "genesis") || is_digest(by);
            (is_b64u_text(public_key)
                && (alg == -7 || alg == -8)
                && rp_len > 0
                && rp_len <= 253
                && by_ok)
                .then_some(KeyRecordKind::Bound)
        }
        KEY_UNBOUND_1 => {
            if o.len() != 5 {
                return None;
            }
            let reason = o.get("reason")?.as_str()?;
            matches!(reason, "revoked" | "replaced" | "recovery" | "erased")
                .then_some(KeyRecordKind::Unbound)
        }
        _ => None,
    }
}

/// The opening `{ salt, record }` of a `key.bound@1` leaf: exactly two members, a 32-byte salt and
/// a bound record.
pub fn parse_key_opening(v: &Value) -> Option<(&str, &Value)> {
    let o = v.as_object()?;
    if o.len() != 2 {
        return None;
    }
    let salt = o.get("salt")?.as_str()?;
    let record = o.get("record")?;
    (salt.len() == 43
        && b64::decode_len(salt, 32).is_some()
        && parse_key_record(record) == Some(KeyRecordKind::Bound))
    .then_some((salt, record))
}

//! The WebAuthn challenge for an envelope (signing-layers §5): SHA-256 of the UTF-8 of the
//! method name, a 0x00 byte, and the UTF-8 of the envelope's canonical form. The method name
//! separates methods, so the same envelope gives a different challenge under another method.

use alloc::string::String;
use alloc::vec::Vec;

use crate::b64;
use crate::digest::sha256;
use crate::jcs::canonical;
use crate::json::Value;

/// The challenge bytes, or `None` when the envelope has no string `suite`.
pub fn envelope_challenge_bytes(envelope: &Value) -> Option<[u8; 32]> {
    let suite = envelope.get("suite")?.as_str()?;
    let canon = canonical(envelope);
    let mut input = Vec::with_capacity(suite.len().saturating_add(canon.len()).saturating_add(1));
    input.extend_from_slice(suite.as_bytes());
    input.push(0);
    input.extend_from_slice(canon.as_bytes());
    Some(sha256(&input))
}

/// The challenge as Base64URL, as the authenticator returns it in `clientDataJSON`.
pub fn envelope_challenge(envelope: &Value) -> Option<String> {
    envelope_challenge_bytes(envelope).map(|c| b64::encode(&c))
}

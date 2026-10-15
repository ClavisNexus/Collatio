//! `verify(op, input)` for the spike. Input and answer are UTF-8 JSON.
//!
//! - `p256`: `{key:{x,y}, msg, sig, format:"der"|"raw"}` (base64url). SHA-256 over `msg`.
//! - `rsa`: `{n, e, msg, sig, hash:"sha256"|"sha384"|"sha512"}` (base64url).
//! - `ed25519`: `{key, msg, sig}` (base64url). `verify_strict` (signed notes use Ed25519).
//! - `x509`, `cbor` (feature `probe`): parse only, to see that the crates build for the target.
//! - `jcs_numbers`: `{bits:["<16 hex digits>", ...]}` → `{ok, out:[string|null]}`.
//! - `repeat`: `{times, call:{op,input}}` runs one call many times (CPU measurement).
//! - `trap`: traps on purpose (recovery measurement).

use alloc::string::String;
use alloc::vec::Vec;
use base64ct::{Base64UrlUnpadded, Encoding};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
struct Call {
    op: String,
    #[serde(default)]
    input: Value,
}

fn fail(reason: &str) -> Value {
    json!({ "ok": false, "reason": reason })
}

fn b64(v: &Value, field: &str) -> Result<Vec<u8>, Value> {
    let s = v.get(field).and_then(Value::as_str).ok_or_else(|| fail("bad_input"))?;
    Base64UrlUnpadded::decode_vec(s).map_err(|_| fail("bad_base64"))
}

fn p256(input: &Value) -> Result<Value, Value> {
    use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
    let key = input.get("key").ok_or_else(|| fail("bad_input"))?;
    let x = b64(key, "x")?;
    let y = b64(key, "y")?;
    if x.len() != 32 || y.len() != 32 {
        return Err(fail("bad_key"));
    }
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    let vk = VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| fail("bad_key"))?;
    let msg = b64(input, "msg")?;
    let sig = b64(input, "sig")?;
    let sig = match input.get("format").and_then(Value::as_str).unwrap_or("der") {
        "der" => Signature::from_der(&sig),
        "raw" => Signature::from_slice(&sig),
        _ => return Err(fail("bad_input")),
    }
    .map_err(|_| fail("bad_signature_encoding"))?;
    vk.verify(&msg, &sig).map_err(|_| fail("signature"))?;
    Ok(json!({ "ok": true }))
}

fn rsa(input: &Value) -> Result<Value, Value> {
    let hash = match input.get("hash").and_then(Value::as_str).unwrap_or("sha256") {
        "sha256" => crate::rsa::Hash::Sha256,
        "sha384" => crate::rsa::Hash::Sha384,
        "sha512" => crate::rsa::Hash::Sha512,
        _ => return Err(fail("bad_input")),
    };
    let n = b64(input, "n")?;
    let e = b64(input, "e")?;
    let msg = b64(input, "msg")?;
    let sig = b64(input, "sig")?;
    match crate::rsa::verify(&n, &e, &msg, &sig, hash) {
        Ok(()) => Ok(json!({ "ok": true })),
        Err(crate::rsa::RsaError::Key) => Err(fail("bad_key")),
        Err(crate::rsa::RsaError::Length) => Err(fail("signature_length")),
        Err(crate::rsa::RsaError::Mismatch) => Err(fail("signature")),
    }
}

fn ed25519(input: &Value) -> Result<Value, Value> {
    use ed25519_dalek::{Signature, VerifyingKey};
    let key: [u8; 32] = b64(input, "key")?.try_into().map_err(|_| fail("bad_key"))?;
    let vk = VerifyingKey::from_bytes(&key).map_err(|_| fail("bad_key"))?;
    let sig = Signature::from_slice(&b64(input, "sig")?).map_err(|_| fail("bad_signature_encoding"))?;
    vk.verify_strict(&b64(input, "msg")?, &sig).map_err(|_| fail("signature"))?;
    Ok(json!({ "ok": true }))
}

#[cfg(feature = "probe")]
fn x509(input: &Value) -> Result<Value, Value> {
    use x509_cert::der::Decode;
    let der = b64(input, "der")?;
    let cert = x509_cert::Certificate::from_der(&der).map_err(|_| fail("bad_certificate"))?;
    let spki = cert.tbs_certificate().subject_public_key_info();
    Ok(json!({ "ok": true, "spki_bits": spki.subject_public_key.raw_bytes().len() * 8 }))
}

#[cfg(feature = "probe")]
fn cbor(input: &Value) -> Result<Value, Value> {
    let bytes = b64(input, "bytes")?;
    let mut d = minicbor::Decoder::new(&bytes);
    let mut items = 0u64;
    while d.position() < bytes.len() {
        d.skip().map_err(|_| fail("bad_cbor"))?;
        items += 1;
    }
    Ok(json!({ "ok": true, "items": items }))
}

fn jcs_numbers(input: &Value) -> Result<Value, Value> {
    let bits = input.get("bits").and_then(Value::as_array).ok_or_else(|| fail("bad_input"))?;
    let mut out = Vec::with_capacity(bits.len());
    for b in bits {
        let s = b.as_str().ok_or_else(|| fail("bad_input"))?;
        let raw = u64::from_str_radix(s, 16).map_err(|_| fail("bad_input"))?;
        out.push(match crate::jcs::number(f64::from_bits(raw)) {
            Some(s) => Value::String(s),
            None => Value::Null,
        });
    }
    Ok(json!({ "ok": true, "out": out }))
}

fn repeat(input: &Value) -> Result<Value, Value> {
    let times = input.get("times").and_then(Value::as_u64).ok_or_else(|| fail("bad_input"))?;
    let call: Call =
        serde_json::from_value(input.get("call").cloned().ok_or_else(|| fail("bad_input"))?)
            .map_err(|_| fail("bad_input"))?;
    if call.op == "repeat" || times > 10_000 {
        return Err(fail("bad_input"));
    }
    let mut passed = 0u64;
    for _ in 0..times {
        if dispatch(&call.op, &call.input).is_ok() {
            passed += 1;
        }
    }
    Ok(json!({ "ok": true, "times": times, "passed": passed }))
}

fn dispatch(op: &str, input: &Value) -> Result<Value, Value> {
    match op {
        "p256" => p256(input),
        "rsa" => rsa(input),
        "ed25519" => ed25519(input),
        #[cfg(feature = "probe")]
        "x509" => x509(input),
        #[cfg(feature = "probe")]
        "cbor" => cbor(input),
        "jcs_numbers" => jcs_numbers(input),
        "repeat" => repeat(input),
        #[cfg(target_arch = "wasm32")]
        "trap" => core::arch::wasm32::unreachable(),
        _ => Err(fail("unknown_op")),
    }
}

/// Runs one call and returns the answer as UTF-8 JSON bytes.
pub fn run(input: &[u8]) -> Vec<u8> {
    let answer = match serde_json::from_slice::<Call>(input) {
        Ok(call) => match dispatch(&call.op, &call.input) {
            Ok(v) | Err(v) => v,
        },
        Err(_) => fail("bad_json"),
    };
    serde_json::to_vec(&answer).unwrap_or_else(|_| br#"{"ok":false,"reason":"internal"}"#.to_vec())
}

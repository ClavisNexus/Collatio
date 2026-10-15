//! `verify(op, input)`: reads the outer input, dispatches on `op`, writes the answer.
//!
//! The outer input is a JSON object `{ "op": "<name>", … }` built by the host. Evidence, trust
//! documents and registries travel inside it as JSON strings and are read again, strictly, by the
//! operation that needs them. The answer is `{"ok":true,…}` or `{"ok":false,"reason":"…"}` in
//! canonical form.

use alloc::string::String;
use alloc::vec::Vec;

use crate::jcs::canonical;
use crate::json::{self, Object, Value};
use crate::reason::Reason;

/// Inputs above this size are refused before reading (ABI.md).
pub const MAX_INPUT: usize = 4 * 1024 * 1024;

/// Runs one call and returns the answer as UTF-8 JSON.
pub fn run(input: &[u8]) -> Vec<u8> {
    let answer = match call(input) {
        Ok(fields) => answer_ok(fields),
        Err(reason) => answer_refused(reason),
    };
    canonical(&Value::Object(answer)).into_bytes()
}

/// The answer that refuses with `reason` (used by the WebAssembly exports).
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
pub fn refused(reason: Reason) -> Vec<u8> {
    canonical(&Value::Object(answer_refused(reason))).into_bytes()
}

fn call(input: &[u8]) -> Result<Object, Reason> {
    if input.len() > MAX_INPUT {
        return Err(Reason::InputTooLarge);
    }
    let outer = json::parse(input).map_err(|_| Reason::InputMalformed)?;
    let op = outer
        .get("op")
        .and_then(Value::as_str)
        .ok_or(Reason::InputMalformed)?;
    dispatch(op, &outer)
}

fn dispatch(op: &str, _outer: &Value) -> Result<Object, Reason> {
    // The operations of genesis.md §18.3 are added here as their layers land.
    let _ = op;
    Err(Reason::UnknownOp)
}

fn answer_ok(fields: Object) -> Object {
    let mut out = Object::default();
    out.insert(String::from("ok"), Value::Bool(true));
    for (k, v) in fields.iter() {
        out.insert(String::from(k), v.clone());
    }
    out
}

fn answer_refused(reason: Reason) -> Object {
    let mut out = Object::default();
    out.insert(String::from("ok"), Value::Bool(false));
    out.insert(String::from("reason"), Value::from(reason.as_str()));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(input: &[u8]) -> String {
        String::from_utf8(run(input)).unwrap()
    }

    #[test]
    fn outer_input() {
        assert_eq!(
            answer(br#"{"op":"nope"}"#),
            r#"{"ok":false,"reason":"unknown_op"}"#
        );
        assert_eq!(answer(b"[]"), r#"{"ok":false,"reason":"input_malformed"}"#);
        assert_eq!(
            answer(br#"{"op":1}"#),
            r#"{"ok":false,"reason":"input_malformed"}"#
        );
        assert_eq!(
            answer(br#"{"op":"a","op":"b"}"#),
            r#"{"ok":false,"reason":"input_malformed"}"#
        );
        let big = vec![b' '; MAX_INPUT + 1];
        assert_eq!(answer(&big), r#"{"ok":false,"reason":"input_too_large"}"#);
    }
}

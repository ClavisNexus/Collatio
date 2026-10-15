//! RFC 8785 (JSON Canonicalization Scheme).
//!
//! - Object members are ordered by their keys as UTF-16 code units, which is not the order of
//!   UTF-8 bytes for characters above U+FFFF.
//! - Numbers use the ECMAScript `Number.prototype.toString` form; −0 is written `0`.
//! - Strings use the ECMAScript `JSON.stringify` form: `"` and `\` escaped, the C0 controls as
//!   `\b \t \n \f \r` or `\u00xx` (lowercase hex), everything else as is.
//!
//! The reader has already refused lone surrogates and non-finite numbers, so every [`Value`] can
//! be written.

use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;

use crate::json::{Number, Value};

/// The canonical form of a value.
pub fn canonical(value: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, value);
    out
}

fn write_value(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => write_number(out, n),
        Value::String(s) => write_string(out, s),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, item);
            }
            out.push(']');
        }
        Value::Object(object) => {
            let mut members: Vec<(&str, &Value)> = object.iter().collect();
            members.sort_by(|a, b| utf16_cmp(a.0, b.0));
            out.push('{');
            for (i, (key, item)) in members.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(out, key);
                out.push(':');
                write_value(out, item);
            }
            out.push('}');
        }
    }
}

/// Orders strings by UTF-16 code units, as ECMAScript's default sort does.
pub fn utf16_cmp(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// Writes a double in the ECMAScript form. The value is finite (the reader refuses the rest).
pub fn write_f64(out: &mut String, value: f64) {
    if value == 0.0 {
        out.push('0');
        return;
    }
    let mut buffer = ryu_js::Buffer::new();
    out.push_str(buffer.format_finite(value));
}

fn write_number(out: &mut String, n: &Number) {
    write_f64(out, n.as_f64());
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                let code = c as usize;
                out.push_str("\\u00");
                out.push(char::from(HEX.get(code >> 4).copied().unwrap_or(b'0')));
                out.push(char::from(HEX.get(code & 0xf).copied().unwrap_or(b'0')));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::parse;

    fn canon(s: &str) -> String {
        canonical(&parse(s.as_bytes()).unwrap())
    }

    #[test]
    fn rfc8785_examples() {
        // RFC 8785 §3.2.2 and §3.2.3.
        assert_eq!(
            canon(
                r#"{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"string":"\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/","literals":[null,true,false]}"#
            ),
            r#"{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}"#
        );
        assert_eq!(
            canon(
                "{\"\\u20ac\":\"Euro Sign\",\"\\r\":\"Carriage Return\",\"\\ufb33\":\"Hebrew Letter Dalet With Dagesh\",\"1\":\"One\",\"\\ud83d\\ude00\":\"Emoji: Grinning Face\",\"\\u0080\":\"Control\",\"\\u00f6\":\"Latin Small Letter O With Diaeresis\"}"
            ),
            "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u{80}\":\"Control\",\"\u{f6}\":\"Latin Small Letter O With Diaeresis\",\"\u{20ac}\":\"Euro Sign\",\"\u{1f600}\":\"Emoji: Grinning Face\",\"\u{fb33}\":\"Hebrew Letter Dalet With Dagesh\"}"
        );
    }

    #[test]
    fn numbers_and_strings_follow_ecmascript() {
        assert_eq!(
            canon("[-0,0.0,1e21,1e-7,123456789012345680000,5e-324]"),
            "[0,0,1e+21,1e-7,123456789012345680000,5e-324]"
        );
        assert_eq!(
            canon("\"\\u2028\\u007f\\u0000\""),
            "\"\u{2028}\u{7f}\\u0000\""
        );
    }
}

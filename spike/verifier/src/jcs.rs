//! RFC 8785 §3.2.2.3 number serialization: the ECMAScript Number::toString form.
//! `ryu-js` produces it; NaN and infinities are not JSON and are refused.

use alloc::string::String;

pub fn number(value: f64) -> Option<String> {
    if !value.is_finite() {
        return None;
    }
    if value == 0.0 {
        // -0 serializes as "0" in ECMAScript.
        return Some(String::from("0"));
    }
    let mut buf = ryu_js::Buffer::new();
    Some(String::from(buf.format_finite(value)))
}

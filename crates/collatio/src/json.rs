//! The strict JSON reader.
//!
//! Every document Collatio reads goes through this reader, never through a lenient one:
//!
//! - the input is UTF-8 and one JSON value (RFC 8259), with only space, tab, LF and CR around it;
//! - an object never repeats a key (a lenient reader keeps the last one, so two readers of the
//!   same bytes could see different values);
//! - a `\u` escape never leaves a lone surrogate;
//! - a number is kept as written and as the IEEE 754 double ECMAScript would read; a number that
//!   reads as infinity is refused;
//! - nesting is at most [`MAX_DEPTH`] deep.
//!
//! Objects keep their members in input order. Whether a field may hold a number with a fraction
//! is decided by the rules for that field, not here (see [`Number::as_safe_integer`]).

use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

/// Deepest nesting of arrays and objects the reader accepts.
pub const MAX_DEPTH: usize = 64;

/// Largest integer every reader (including IEEE 754 doubles) represents exactly: 2^53 − 1.
pub const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(Number),
    String(String),
    Array(Vec<Value>),
    Object(Object),
}

/// An object with unique keys, in input order.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Object(Vec<(String, Value)>);

#[derive(Clone, Debug, PartialEq)]
pub struct Number {
    raw: Box<str>,
    value: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JsonError {
    /// The input is not UTF-8.
    Utf8,
    /// The input is not one JSON value.
    Syntax,
    /// An object repeats a key.
    DuplicateKey,
    /// A `\u` escape leaves a lone surrogate.
    LoneSurrogate,
    /// A number reads as infinity.
    NonFinite,
    /// Arrays and objects nest deeper than [`MAX_DEPTH`].
    TooDeep,
}

impl Number {
    /// The number as written in the input.
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// The number as an IEEE 754 double, as `JSON.parse` would read it.
    pub fn as_f64(&self) -> f64 {
        self.value
    }

    /// The number when it is written as an integer (no fraction, no exponent) within ±(2^53 − 1).
    pub fn as_safe_integer(&self) -> Option<i64> {
        let digits = self.raw.strip_prefix('-').unwrap_or(&self.raw);
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        if digits.len() > 1 && digits.starts_with('0') {
            return None;
        }
        let magnitude: i64 = digits.parse().ok()?;
        if magnitude > MAX_SAFE_INTEGER {
            return None;
        }
        if self.raw.starts_with('-') {
            magnitude.checked_neg()
        } else {
            Some(magnitude)
        }
    }

    pub(crate) fn from_parts(raw: &str, value: f64) -> Number {
        Number {
            raw: raw.into(),
            value,
        }
    }
}

impl Object {
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v))
    }

    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(|(k, _)| k.as_str())
    }

    /// Adds a member. Returns false (and changes nothing) when the key is already present.
    pub fn insert(&mut self, key: String, value: Value) -> bool {
        if self.0.iter().any(|(k, _)| *k == key) {
            return false;
        }
        self.0.push((key, value));
        true
    }

    /// The members without the one named `key`.
    pub fn without(&self, key: &str) -> Object {
        Object(self.0.iter().filter(|(k, _)| k != key).cloned().collect())
    }
}

impl Value {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&Object> {
        match self {
            Value::Object(o) => Some(o),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_number(&self) -> Option<&Number> {
        match self {
            Value::Number(n) => Some(n),
            _ => None,
        }
    }

    /// The value of member `key` when this is an object.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_object().and_then(|o| o.get(key))
    }
}

/// Reads one JSON value from UTF-8 bytes.
pub fn parse(input: &[u8]) -> Result<Value, JsonError> {
    let text = core::str::from_utf8(input).map_err(|_| JsonError::Utf8)?;
    let mut reader = Reader {
        text,
        bytes: text.as_bytes(),
        pos: 0,
    };
    reader.skip_ws();
    let value = reader.value(0)?;
    reader.skip_ws();
    if reader.pos != reader.bytes.len() {
        return Err(JsonError::Syntax);
    }
    Ok(value)
}

struct Reader<'a> {
    text: &'a str,
    bytes: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos = self.pos.saturating_add(1);
        Some(b)
    }

    fn expect(&mut self, b: u8) -> Result<(), JsonError> {
        if self.bump() == Some(b) {
            Ok(())
        } else {
            Err(JsonError::Syntax)
        }
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos = self.pos.saturating_add(1);
        }
    }

    fn literal(&mut self, word: &[u8], value: Value) -> Result<Value, JsonError> {
        let end = self.pos.checked_add(word.len()).ok_or(JsonError::Syntax)?;
        if self.bytes.get(self.pos..end) == Some(word) {
            self.pos = end;
            Ok(value)
        } else {
            Err(JsonError::Syntax)
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, JsonError> {
        match self.peek() {
            Some(b'n') => self.literal(b"null", Value::Null),
            Some(b't') => self.literal(b"true", Value::Bool(true)),
            Some(b'f') => self.literal(b"false", Value::Bool(false)),
            Some(b'"') => Ok(Value::String(self.string()?)),
            Some(b'[') => self.array(depth),
            Some(b'{') => self.object(depth),
            Some(b'-' | b'0'..=b'9') => Ok(Value::Number(self.number()?)),
            _ => Err(JsonError::Syntax),
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, JsonError> {
        let depth = depth.checked_add(1).ok_or(JsonError::TooDeep)?;
        if depth > MAX_DEPTH {
            return Err(JsonError::TooDeep);
        }
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos = self.pos.saturating_add(1);
            return Ok(Value::Array(items));
        }
        loop {
            self.skip_ws();
            items.push(self.value(depth)?);
            self.skip_ws();
            match self.bump() {
                Some(b',') => continue,
                Some(b']') => return Ok(Value::Array(items)),
                _ => return Err(JsonError::Syntax),
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, JsonError> {
        let depth = depth.checked_add(1).ok_or(JsonError::TooDeep)?;
        if depth > MAX_DEPTH {
            return Err(JsonError::TooDeep);
        }
        self.expect(b'{')?;
        let mut object = Object::default();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos = self.pos.saturating_add(1);
            return Ok(Value::Object(object));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(JsonError::Syntax);
            }
            let key = self.string()?;
            self.skip_ws();
            self.expect(b':')?;
            self.skip_ws();
            let value = self.value(depth)?;
            if !object.insert(key, value) {
                return Err(JsonError::DuplicateKey);
            }
            self.skip_ws();
            match self.bump() {
                Some(b',') => continue,
                Some(b'}') => return Ok(Value::Object(object)),
                _ => return Err(JsonError::Syntax),
            }
        }
    }

    fn hex4(&mut self) -> Result<u16, JsonError> {
        let mut v: u16 = 0;
        for _ in 0..4 {
            let d = match self.bump() {
                Some(c @ b'0'..=b'9') => c.wrapping_sub(b'0'),
                Some(c @ b'a'..=b'f') => c.wrapping_sub(b'a').wrapping_add(10),
                Some(c @ b'A'..=b'F') => c.wrapping_sub(b'A').wrapping_add(10),
                _ => return Err(JsonError::Syntax),
            };
            v = v.wrapping_shl(4) | u16::from(d);
        }
        Ok(v)
    }

    fn string(&mut self) -> Result<String, JsonError> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let start = self.pos;
            // Copy the run of plain characters at once (the input is valid UTF-8).
            while let Some(b) = self.peek() {
                if b == b'"' || b == b'\\' || b < 0x20 {
                    break;
                }
                self.pos = self.pos.saturating_add(1);
            }
            if let Some(run) = self.text.get(start..self.pos) {
                out.push_str(run);
            } else {
                return Err(JsonError::Syntax);
            }
            match self.bump() {
                Some(b'"') => return Ok(out),
                Some(b'\\') => {}
                _ => return Err(JsonError::Syntax),
            }
            match self.bump() {
                Some(b'"') => out.push('"'),
                Some(b'\\') => out.push('\\'),
                Some(b'/') => out.push('/'),
                Some(b'b') => out.push('\u{8}'),
                Some(b'f') => out.push('\u{c}'),
                Some(b'n') => out.push('\n'),
                Some(b'r') => out.push('\r'),
                Some(b't') => out.push('\t'),
                Some(b'u') => {
                    let first = self.hex4()?;
                    let c = match first {
                        0xd800..=0xdbff => {
                            if self.bump() != Some(b'\\') || self.bump() != Some(b'u') {
                                return Err(JsonError::LoneSurrogate);
                            }
                            let second = self.hex4()?;
                            if !(0xdc00..=0xdfff).contains(&second) {
                                return Err(JsonError::LoneSurrogate);
                            }
                            let high = u32::from(first).wrapping_sub(0xd800);
                            let low = u32::from(second).wrapping_sub(0xdc00);
                            char::from_u32(
                                0x10000_u32
                                    .wrapping_add(high.wrapping_shl(10))
                                    .wrapping_add(low),
                            )
                        }
                        0xdc00..=0xdfff => return Err(JsonError::LoneSurrogate),
                        _ => char::from_u32(u32::from(first)),
                    };
                    out.push(c.ok_or(JsonError::Syntax)?);
                }
                _ => return Err(JsonError::Syntax),
            }
        }
    }

    fn digits(&mut self) -> usize {
        let start = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos = self.pos.saturating_add(1);
        }
        self.pos.saturating_sub(start)
    }

    fn number(&mut self) -> Result<Number, JsonError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos = self.pos.saturating_add(1);
        }
        match self.peek() {
            Some(b'0') => self.pos = self.pos.saturating_add(1),
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return Err(JsonError::Syntax),
        }
        if self.peek() == Some(b'.') {
            self.pos = self.pos.saturating_add(1);
            if self.digits() == 0 {
                return Err(JsonError::Syntax);
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos = self.pos.saturating_add(1);
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos = self.pos.saturating_add(1);
            }
            if self.digits() == 0 {
                return Err(JsonError::Syntax);
            }
        }
        let raw = self.text.get(start..self.pos).ok_or(JsonError::Syntax)?;
        // Rust's float parsing is correctly rounded, like ECMAScript's.
        let value: f64 = raw.parse().map_err(|_| JsonError::Syntax)?;
        if !value.is_finite() {
            return Err(JsonError::NonFinite);
        }
        Ok(Number::from_parts(raw, value))
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Value {
        Value::String(s.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(s: &str) -> JsonError {
        match parse(s.as_bytes()) {
            Err(e) => e,
            Ok(v) => panic!("accepted {s:?} as {v:?}"),
        }
    }

    #[test]
    fn reads_values() {
        let v = parse(br#" {"a":[1,-0,2.5e3,"x\u00e9\ud83d\ude00"],"b":{"c":null,"d":true}} "#)
            .unwrap();
        let a = v.get("a").unwrap().as_array().unwrap();
        assert_eq!(a[3].as_str(), Some("x\u{e9}\u{1f600}"));
        assert_eq!(a[2].as_number().unwrap().as_f64(), 2500.0);
        assert_eq!(v.get("b").unwrap().get("d"), Some(&Value::Bool(true)));
    }

    #[test]
    fn refuses_what_a_lenient_reader_would_take() {
        assert_eq!(err(r#"{"a":1,"a":2}"#), JsonError::DuplicateKey);
        assert_eq!(err(r#"{"a":1,"a":2}"#), JsonError::DuplicateKey);
        assert_eq!(err(r#""\ud800""#), JsonError::LoneSurrogate);
        assert_eq!(err(r#""\udc00\ud800""#), JsonError::LoneSurrogate);
        assert_eq!(err(r#""\ud800x""#), JsonError::LoneSurrogate);
        assert_eq!(err("1e400"), JsonError::NonFinite);
        assert_eq!(err("\u{feff}{}"), JsonError::Syntax);
        assert_eq!(err("[1,]"), JsonError::Syntax);
        assert_eq!(err("01"), JsonError::Syntax);
        assert_eq!(err("+1"), JsonError::Syntax);
        assert_eq!(err("1."), JsonError::Syntax);
        assert_eq!(err(".5"), JsonError::Syntax);
        assert_eq!(err("\"a\u{1}\""), JsonError::Syntax);
        assert_eq!(err("{} {}"), JsonError::Syntax);
        assert_eq!(err("NaN"), JsonError::Syntax);
        assert_eq!(err("\u{a0}1"), JsonError::Syntax);
        assert_eq!(parse(&[0x22, 0xff, 0x22]), Err(JsonError::Utf8));
    }

    #[test]
    fn limits_depth() {
        let ok = "[".repeat(MAX_DEPTH) + &"]".repeat(MAX_DEPTH);
        assert!(parse(ok.as_bytes()).is_ok());
        let deep = "[".repeat(MAX_DEPTH + 1) + &"]".repeat(MAX_DEPTH + 1);
        assert_eq!(err(&deep), JsonError::TooDeep);
    }

    #[test]
    fn safe_integers() {
        let n = |s: &str| {
            parse(s.as_bytes())
                .unwrap()
                .as_number()
                .unwrap()
                .as_safe_integer()
        };
        assert_eq!(n("0"), Some(0));
        assert_eq!(n("-0"), Some(0));
        assert_eq!(n("9007199254740991"), Some(MAX_SAFE_INTEGER));
        assert_eq!(n("-9007199254740991"), Some(-MAX_SAFE_INTEGER));
        assert_eq!(n("9007199254740992"), None);
        assert_eq!(n("1.0"), None);
        assert_eq!(n("1e2"), None);
    }
}

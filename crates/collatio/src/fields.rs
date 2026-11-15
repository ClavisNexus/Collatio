//! Field kinds: the strings a `registry@1` document uses to say what a statement field holds
//! (`id`, `text(200)`, `nullable(digest)`, …). The strings are knowledge carried by the registry;
//! how each is read is a rule of this module, so a new kind is a new verifier release.
//!
//! The kinds are those of the pre-genesis registry, read the same way, plus `org`. Base64URL
//! values of a fixed length (`bytes32`) are canonical here, which the pre-genesis reader did not
//! check.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use crate::b64;
use crate::digest::is_digest;
use crate::jcs::utf16_cmp;
use crate::json::Value;
use crate::keylog::{is_b64u_text, is_id};
use crate::text::{has_no_ascii_upper, has_no_whitespace, is_trimmed_text, utf16_len};

const MAX_KIND_LEN: usize = 512;
const MAX_DEPTH: usize = 4;
const MAX_TEXT: usize = 100_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    Id,
    Uuid,
    App,
    Subject,
    Credential,
    Digest,
    Bytes32,
    Hex64,
    Domain,
    Email,
    /// `<cell>.<UUID>` (FORMATS.md §2).
    Org,
    Text(usize),
    Int(i64, i64),
    OneOf(Vec<String>),
    SortedSet(Box<Kind>, usize),
    Nullable(Box<Kind>),
}

/// Reads a kind string. `None` when it is unknown or malformed.
pub fn parse_kind(s: &str) -> Option<Kind> {
    if s.is_empty() || s.len() > MAX_KIND_LEN || !s.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return None;
    }
    build(s, 0)
}

fn build(s: &str, depth: usize) -> Option<Kind> {
    if depth > MAX_DEPTH {
        return None;
    }
    let scalar = match s {
        "id" => Some(Kind::Id),
        "uuid" => Some(Kind::Uuid),
        "app" => Some(Kind::App),
        "subject" => Some(Kind::Subject),
        "credential" => Some(Kind::Credential),
        "digest" => Some(Kind::Digest),
        "bytes32" => Some(Kind::Bytes32),
        "hex64" => Some(Kind::Hex64),
        "domain" => Some(Kind::Domain),
        "email" => Some(Kind::Email),
        "org" => Some(Kind::Org),
        _ => None,
    };
    if scalar.is_some() {
        return scalar;
    }
    let open = s.find('(')?;
    let name = s.get(..open)?;
    let inner = s.get(open.checked_add(1)?..)?.strip_suffix(')')?;
    if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphabetic()) {
        return None;
    }
    let args = split_top(inner)?;
    match (name, args.as_slice()) {
        ("text", [max]) => {
            let max = usize::try_from(int_arg(max, false)?).ok()?;
            (1..=MAX_TEXT).contains(&max).then_some(Kind::Text(max))
        }
        ("int", [min, max]) => {
            let (min, max) = (int_arg(min, true)?, int_arg(max, true)?);
            (min <= max).then_some(Kind::Int(min, max))
        }
        ("oneOf", [values]) => {
            let values: Vec<String> = values.split('|').map(String::from).collect();
            let ok = values.iter().enumerate().all(|(i, v)| {
                is_one_of_value(v) && !values.get(..i).is_some_and(|before| before.contains(v))
            });
            ok.then_some(Kind::OneOf(values))
        }
        ("sortedSet", [item, max]) => {
            let item = build(item, depth.checked_add(1)?)?;
            let max = usize::try_from(int_arg(max, false)?).ok()?;
            (max >= 1).then(|| Kind::SortedSet(Box::new(item), max))
        }
        ("nullable", [inner]) => Some(Kind::Nullable(Box::new(build(
            inner,
            depth.checked_add(1)?,
        )?))),
        _ => None,
    }
}

/// Splits at commas outside parentheses; `None` when the parentheses do not balance.
fn split_top(s: &str) -> Option<Vec<&str>> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;
    for (i, b) in s.bytes().enumerate() {
        match b {
            b'(' => depth = depth.checked_add(1)?,
            b')' => depth = depth.checked_sub(1)?,
            b',' if depth == 0 => {
                out.push(s.get(start..i)?);
                start = i.checked_add(1)?;
            }
            _ => {}
        }
    }
    if depth != 0 {
        return None;
    }
    out.push(s.get(start..)?);
    Some(out)
}

/// `0|[1-9][0-9]{0,15}`, with a leading `-` when signed, within ±(2^53 − 1).
fn int_arg(s: &str, signed: bool) -> Option<i64> {
    let digits = if signed {
        s.strip_prefix('-').unwrap_or(s)
    } else {
        s
    };
    if digits.is_empty()
        || digits.len() > 16
        || !digits.bytes().all(|b| b.is_ascii_digit())
        || (digits.len() > 1 && digits.starts_with('0'))
    {
        return None;
    }
    let n: i64 = digits.parse().ok()?;
    if n > crate::json::MAX_SAFE_INTEGER {
        return None;
    }
    if s.starts_with('-') {
        n.checked_neg()
    } else {
        Some(n)
    }
}

fn is_one_of_value(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 64
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-')
}

fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn is_uuid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    matches!(parts.as_slice(), [a, b, c, d, e]
        if is_hex(a, 8) && is_hex(b, 4) && is_hex(c, 4) && is_hex(d, 4) && is_hex(e, 12))
}

/// A cell ID: `[a-z]{2}[1-9][0-9]{0,2}` (FORMATS.md §2).
pub fn is_cell(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 3
        && b.len() <= 5
        && b.get(..2)
            .is_some_and(|p| p.iter().all(u8::is_ascii_lowercase))
        && b.get(2).is_some_and(|&c| (b'1'..=b'9').contains(&c))
        && b.get(3..).is_some_and(|r| r.iter().all(u8::is_ascii_digit))
}

/// An Org ID: `<cell>.<UUID>`.
pub fn is_org(s: &str) -> bool {
    s.split_once('.')
        .is_some_and(|(cell, id)| is_cell(cell) && is_uuid(id))
}

/// An App ID: a lowercase UUID or a slug.
pub fn is_app(s: &str) -> bool {
    is_uuid(s) || is_app_slug(s)
}

fn is_app_slug(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 127
        && b.first()
            .is_some_and(|&c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && b.iter().all(|&c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'.' || c == b'_' || c == b'-'
        })
}

fn is_label(s: &str) -> bool {
    let b = s.as_bytes();
    let alnum = |c: &u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    !b.is_empty()
        && b.len() <= 63
        && b.first().is_some_and(alnum)
        && b.last().is_some_and(alnum)
        && b.iter().all(|c| alnum(c) || *c == b'-')
}

/// A lowercase domain name with at least two labels.
pub fn is_domain(s: &str) -> bool {
    !s.is_empty() && s.len() <= 253 && s.split('.').count() >= 2 && s.split('.').all(is_label)
}

/// A lowercase host: one or more labels (the envelope's `rp`).
pub fn is_host(s: &str) -> bool {
    !s.is_empty() && s.len() <= 253 && s.split('.').all(is_label)
}

fn is_email(s: &str) -> bool {
    utf16_len(s) <= 254
        && has_no_ascii_upper(s)
        && has_no_whitespace(s)
        && s.split_once('@')
            .is_some_and(|(a, b)| !a.is_empty() && !b.is_empty() && !b.contains('@'))
}

impl Kind {
    /// Whether `v` is a value of this kind.
    pub fn check(&self, v: &Value) -> bool {
        match self {
            Kind::Nullable(inner) => matches!(v, Value::Null) || inner.check(v),
            Kind::Int(min, max) => v
                .as_number()
                .and_then(|n| n.as_safe_integer())
                .is_some_and(|n| *min <= n && n <= *max),
            Kind::SortedSet(item, max) => v.as_array().is_some_and(|items| {
                items.len() <= *max
                    && items.iter().all(|x| x.as_str().is_some() && item.check(x))
                    && items.windows(2).all(|w| match w {
                        [a, b] => a
                            .as_str()
                            .zip(b.as_str())
                            .is_some_and(|(a, b)| utf16_cmp(a, b) == core::cmp::Ordering::Less),
                        _ => false,
                    })
            }),
            _ => v.as_str().is_some_and(|s| self.check_str(s)),
        }
    }

    fn check_str(&self, s: &str) -> bool {
        match self {
            Kind::Id | Kind::Subject => is_id(s, 200),
            Kind::Uuid => is_uuid(s),
            Kind::App => is_app(s),
            Kind::Credential => s.len() <= 1366 && is_b64u_text(s),
            Kind::Digest => is_digest(s),
            Kind::Bytes32 => s.len() == 43 && b64::decode_len(s, 32).is_some(),
            Kind::Hex64 => is_hex(s, 64),
            Kind::Domain => is_domain(s),
            Kind::Email => is_email(s),
            Kind::Org => is_org(s),
            Kind::Text(max) => is_trimmed_text(s, *max),
            Kind::OneOf(values) => values.iter().any(|v| v == s),
            Kind::Int(..) | Kind::SortedSet(..) | Kind::Nullable(..) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(json: &str) -> Value {
        crate::json::parse(json.as_bytes()).unwrap()
    }

    #[test]
    fn kinds() {
        for ok in [
            "id",
            "org",
            "text(200)",
            "int(0,100000000000)",
            "int(-5,5)",
            "oneOf(member|admin)",
            "sortedSet(oneOf(EEA|GB),4)",
            "nullable(digest)",
            "nullable(nullable(nullable(nullable(id))))",
        ] {
            assert!(parse_kind(ok).is_some(), "{ok}");
        }
        for bad in [
            "",
            "ID",
            "text(0)",
            "text(100001)",
            "text(01)",
            "text( 5)",
            "int(5,1)",
            "int(1)",
            "oneOf(a|a)",
            "oneOf()",
            "oneOf(a,b)",
            "sortedSet(id,0)",
            "nullable(nullable(nullable(nullable(nullable(id)))))",
            "nullable(id",
            "constructor",
            "line(5)",
        ] {
            assert!(parse_kind(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn values() {
        let k = |s: &str| parse_kind(s).unwrap();
        assert!(k("org").check(&v(r#""eu1.0b5c0e2e-9d39-4c1f-9b1b-2b0f7e7c1a10""#)));
        assert!(!k("org").check(&v(r#""eu01.0b5c0e2e-9d39-4c1f-9b1b-2b0f7e7c1a10""#)));
        assert!(!k("org").check(&v(r#""0b5c0e2e-9d39-4c1f-9b1b-2b0f7e7c1a10""#)));
        assert!(k("int(0,10)").check(&v("10")));
        assert!(!k("int(0,10)").check(&v("10.0")));
        assert!(!k("int(0,10)").check(&v("11")));
        assert!(k("nullable(digest)").check(&v("null")));
        assert!(k("sortedSet(oneOf(EEA|GB),4)").check(&v(r#"["EEA","GB"]"#)));
        assert!(!k("sortedSet(oneOf(EEA|GB),4)").check(&v(r#"["GB","EEA"]"#)));
        assert!(k("email").check(&v(r#""a@b.example""#)));
        assert!(!k("email").check(&v(r#""A@b.example""#)));
        assert!(!k("email").check(&v(r#""a@b@c""#)));
        assert!(k("domain").check(&v(r#""clavis.nexus""#)));
        assert!(!k("domain").check(&v(r#""localhost""#)));
        assert!(k("bytes32").check(&v(r#""AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA""#)));
        assert!(!k("bytes32").check(&v(r#""AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB""#)));
    }
}

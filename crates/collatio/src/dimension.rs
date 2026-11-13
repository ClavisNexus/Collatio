//! `dimension@1`: what a dimension accepts and how its receipts are made (FORMATS.md §3). The
//! definition travels inside every receipt and is named by digest from the envelope.

use alloc::string::String;
use alloc::vec::Vec;

use crate::digest::{is_digest, is_type_id};
use crate::jcs::utf16_cmp;
use crate::json::{Object, Value};

pub const DIMENSION_1: &str = "dimension@1";
const MAX_SET: usize = 512;

const KEYS: [&str; 14] = [
    "type",
    "name",
    "statements",
    "suites",
    "verifier",
    "registry",
    "signer",
    "sessions",
    "rp",
    "freshness",
    "single_use",
    "ext",
    "receipts",
    "key_log",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signer {
    Account,
    Pairwise,
}

impl Signer {
    pub fn as_str(self) -> &'static str {
        match self {
            Signer::Account => "account",
            Signer::Pairwise => "pairwise",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Dimension {
    pub name: String,
    pub statements: Vec<String>,
    pub suites: Vec<String>,
    pub verifier: String,
    pub registry: String,
    pub signer: Signer,
    pub ext_required: Vec<String>,
    pub ext_allowed: Vec<String>,
    pub holder_receipts: bool,
    pub app_receipts: bool,
}

/// A non-empty (when asked) set: strictly increasing by UTF-16 code units, every item checked.
pub fn sorted_set(v: &Value, non_empty: bool, check: impl Fn(&str) -> bool) -> Option<Vec<String>> {
    let items = v.as_array()?;
    if (non_empty && items.is_empty()) || items.len() > MAX_SET {
        return None;
    }
    let mut out: Vec<String> = Vec::with_capacity(items.len());
    for item in items {
        let s = item.as_str()?;
        if !check(s) {
            return None;
        }
        if let Some(last) = out.last()
            && utf16_cmp(last, s) != core::cmp::Ordering::Less
        {
            return None;
        }
        out.push(String::from(s));
    }
    Some(out)
}

fn is_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && b.first().is_some_and(u8::is_ascii_lowercase)
        && b.iter()
            .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
}

fn has_exactly(o: &Object, keys: &[&str]) -> bool {
    o.len() == keys.len() && keys.iter().all(|k| o.get(k).is_some())
}

pub fn parse_dimension(v: &Value) -> Option<Dimension> {
    let o = v.as_object()?;
    if !has_exactly(o, &KEYS) || o.get("type")?.as_str()? != DIMENSION_1 {
        return None;
    }
    let name = o.get("name")?.as_str()?;
    let statements = sorted_set(o.get("statements")?, true, is_type_id)?;
    let suites = sorted_set(o.get("suites")?, true, is_type_id)?;
    let verifier = o.get("verifier")?.as_str()?;
    let registry = o.get("registry")?.as_str()?;
    let signer = match o.get("signer")?.as_str()? {
        "account" => Signer::Account,
        "pairwise" => Signer::Pairwise,
        _ => return None,
    };
    sorted_set(o.get("sessions")?, true, |s| s == "app" || s == "portal")?;
    if o.get("rp")?.as_str()? != "platform" {
        return None;
    }
    match o.get("freshness")? {
        Value::Null => {}
        f => {
            if f.as_number()?.as_safe_integer()? <= 0 {
                return None;
            }
        }
    }
    o.get("single_use")?.as_bool()?;
    o.get("key_log")?.as_bool()?;
    let ext = o.get("ext")?.as_object()?;
    if !has_exactly(ext, &["required", "allowed"]) {
        return None;
    }
    let ext_required = sorted_set(ext.get("required")?, false, is_type_id)?;
    let ext_allowed = sorted_set(ext.get("allowed")?, false, is_type_id)?;
    if !ext_required.iter().all(|r| ext_allowed.contains(r)) {
        return None;
    }
    let receipts = sorted_set(o.get("receipts")?, true, |s| s == "app" || s == "holder")?;
    (is_name(name) && is_digest(verifier) && is_digest(registry)).then(|| Dimension {
        name: String::from(name),
        statements,
        suites,
        verifier: String::from(verifier),
        registry: String::from(registry),
        signer,
        ext_required,
        ext_allowed,
        holder_receipts: receipts.iter().any(|r| r == "holder"),
        app_receipts: receipts.iter().any(|r| r == "app"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const D: &str = "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn doc(patch: &str) -> Value {
        let base = alloc::format!(
            r#"{{"type":"dimension@1","name":"app_sign","statements":["app.sign@1"],"suites":["webauthn@1"],"verifier":"{D}","registry":"{D}","signer":"pairwise","sessions":["app"],"rp":"platform","freshness":300,"single_use":true,"ext":{{"required":["shown@1"],"allowed":["shown@1"]}},"receipts":["app","holder"],"key_log":true{patch}}}"#
        );
        crate::json::parse(base.as_bytes()).unwrap()
    }

    #[test]
    fn reads() {
        let d = parse_dimension(&doc("")).unwrap();
        assert_eq!(d.signer, Signer::Pairwise);
        assert!(d.holder_receipts && d.app_receipts);
        assert!(parse_dimension(&doc(r#","x":1"#)).is_none());
    }

    #[test]
    fn refuses() {
        let good = crate::jcs::canonical(&doc(""));
        for (from, to) in [
            (r#""freshness":300"#, r#""freshness":0"#),
            (r#""freshness":300"#, r#""freshness":1.5"#),
            (
                r#""receipts":["app","holder"]"#,
                r#""receipts":["holder","app"]"#,
            ),
            (r#""receipts":["app","holder"]"#, r#""receipts":[]"#),
            (r#""sessions":["app"]"#, r#""sessions":["apps"]"#),
            (r#""required":["shown@1"]"#, r#""required":["other@1"]"#),
            (r#""rp":"platform""#, r#""rp":"clavis.nexus""#),
            (r#""name":"app_sign""#, r#""name":"App""#),
            (r#""signer":"pairwise""#, r#""signer":"org""#),
        ] {
            assert!(good.contains(from), "{from}");
            let bad = good.replace(from, to);
            let v = crate::json::parse(bad.as_bytes()).unwrap();
            assert!(parse_dimension(&v).is_none(), "{to}");
        }
    }
}

//! The envelope: who signed, when, for which writer (`aud`), and what (FORMATS.md §1). The
//! WebAuthn challenge is its hash (challenge.rs). Known extensions are checked whether or not they
//! are critical; an unknown one is ignored unless `crit` names it, which the receipt check refuses.

use alloc::string::String;
use alloc::vec::Vec;

use crate::b64;
use crate::digest::{is_digest, is_type_id};
use crate::fields::is_host;
use crate::json::{Object, Value};
use crate::keylog::is_id;
use crate::registry::is_aud;
use crate::shown::{SHOWN_1, is_shown_v1};

const CORE: [&str; 10] = [
    "suite",
    "dimension",
    "aud",
    "statement",
    "signer",
    "rp",
    "iat",
    "nonce",
    "ext",
    "crit",
];

#[derive(Clone, Debug)]
pub struct Envelope<'a> {
    pub value: &'a Value,
    pub suite: &'a str,
    pub dimension: &'a str,
    pub aud: &'a str,
    pub statement: &'a str,
    pub signer: &'a str,
    pub rp: &'a str,
    pub iat: i64,
    pub ext: Option<&'a Object>,
    pub crit: Vec<String>,
}

/// The extensions this module knows, with their checks.
pub fn is_known_extension(name: &str) -> bool {
    name == SHOWN_1
}

fn check_extension(name: &str, v: &Value) -> bool {
    match name {
        SHOWN_1 => is_shown_v1(v),
        _ => true,
    }
}

pub fn parse_envelope(v: &Value) -> Option<Envelope<'_>> {
    let o = v.as_object()?;
    if o.keys().any(|k| !CORE.contains(&k)) {
        return None;
    }
    let s = |key: &str| o.get(key).and_then(Value::as_str);
    let (suite, dimension, aud) = (s("suite")?, s("dimension")?, s("aud")?);
    let (statement, signer, rp, nonce) = (s("statement")?, s("signer")?, s("rp")?, s("nonce")?);
    let iat = o.get("iat")?.as_number()?.as_safe_integer()?;
    if !is_type_id(suite)
        || !is_digest(dimension)
        || !is_digest(statement)
        || !is_aud(aud)
        || !is_id(signer, 200)
        || !is_host(rp)
        || iat < 0
        || nonce.len() != 43
        || b64::decode_len(nonce, 32).is_none()
    {
        return None;
    }
    let ext = match o.get("ext") {
        None => None,
        Some(e) => {
            let e = e.as_object()?;
            if e.is_empty()
                || e.iter()
                    .any(|(n, v)| !is_type_id(n) || !check_extension(n, v))
            {
                return None;
            }
            Some(e)
        }
    };
    let crit = match o.get("crit") {
        None => Vec::new(),
        Some(c) => {
            let ext = ext?;
            let names = crate::dimension::sorted_set(c, true, is_type_id)?;
            if !names.iter().all(|n| ext.get(n).is_some()) {
                return None;
            }
            names
        }
    };
    Some(Envelope {
        value: v,
        suite,
        dimension,
        aud,
        statement,
        signer,
        rp,
        iat,
        ext,
        crit,
    })
}

impl Envelope<'_> {
    pub fn has_extension(&self, name: &str) -> bool {
        self.ext.is_some_and(|e| e.get(name).is_some())
    }

    pub fn extension_names(&self) -> impl Iterator<Item = &str> {
        self.ext.into_iter().flat_map(|e| e.keys())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const D: &str = "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const N: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn env(extra: &str) -> Value {
        let s = alloc::format!(
            r#"{{"suite":"webauthn@1","dimension":"{D}","aud":"request:eu1.abc","statement":"{D}","signer":"p_1","rp":"clavis.nexus","iat":1791747761,"nonce":"{N}"{extra}}}"#
        );
        crate::json::parse(s.as_bytes()).unwrap()
    }

    #[test]
    fn reads() {
        let v = env("");
        let e = parse_envelope(&v).unwrap();
        assert_eq!(e.aud, "request:eu1.abc");
        let v = env(r#","ext":{"shown@1":{"app":"A","host":"a.example"}},"crit":["shown@1"]"#);
        let e = parse_envelope(&v).unwrap();
        assert_eq!(e.crit, ["shown@1"]);
        let v = env(r#","ext":{"other@1":[1,2]}"#);
        assert!(parse_envelope(&v).is_some());
    }

    #[test]
    fn refuses() {
        for extra in [
            r#","x":1"#,
            r#","ext":{}"#,
            r#","crit":["shown@1"]"#,
            r#","ext":{"shown@1":{"app":"A","host":"A.example"}}"#,
            r#","ext":{"other@1":1},"crit":["shown@1"]"#,
            r#","ext":{"a@1":1,"b@1":1},"crit":["b@1","a@1"]"#,
        ] {
            assert!(parse_envelope(&env(extra)).is_none(), "{extra}");
        }
        let s = crate::jcs::canonical(&env(""));
        for (from, to) in [
            (r#""aud":"request:eu1.abc""#, r#""aud":"app""#),
            (r#""iat":1791747761"#, r#""iat":-1"#),
            (r#""iat":1791747761"#, r#""iat":1.5"#),
            (r#""rp":"clavis.nexus""#, r#""rp":"Clavis.nexus""#),
            (
                r#""nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA""#,
                r#""nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB""#,
            ),
        ] {
            assert!(s.contains(from), "{from}");
            let v = crate::json::parse(s.replace(from, to).as_bytes()).unwrap();
            assert!(parse_envelope(&v).is_none(), "{to}");
        }
    }
}

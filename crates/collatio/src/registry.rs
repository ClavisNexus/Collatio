//! `registry@1`: the statement types a dimension accepts, their fields and their `aud` template.
//! The document lives outside the module and is named by digest from the dimension definition
//! (FORMATS.md §2); this module holds only the rules for reading it.

use alloc::string::String;
use alloc::vec::Vec;

use crate::digest::is_type_id;
use crate::fields::{Kind, parse_kind};
use crate::json::Value;

pub const REGISTRY_1: &str = "registry@1";

/// The longest `aud` (a 253-character domain after `domain:`).
pub const MAX_AUD: usize = 260;
const MAX_WRITER: usize = 32;

#[derive(Clone, Debug)]
pub struct Field {
    pub name: String,
    pub kind: Kind,
    pub optional: bool,
}

#[derive(Clone, Debug)]
pub struct Rule {
    pub aud: String,
    pub fields: Vec<Field>,
}

#[derive(Clone, Debug)]
pub struct Registry {
    rules: Vec<(String, Rule)>,
}

fn is_field_name(s: &str) -> bool {
    let b = s.as_bytes();
    b.first().is_some_and(u8::is_ascii_lowercase)
        && b.iter()
            .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
}

/// The writer part of an `aud`: `[a-z][a-z0-9_]{0,31}`.
fn is_writer(s: &str) -> bool {
    s.len() <= MAX_WRITER && is_field_name(s)
}

/// `<writer>:<id>` where the whole value has the ID characters and is at most 260 long.
pub fn is_aud(s: &str) -> bool {
    s.len() <= MAX_AUD
        && s.split_once(':')
            .is_some_and(|(writer, rest)| is_writer(writer) && !rest.is_empty())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._~:@+=/-".contains(&b))
}

/// The pieces of an `aud` template: literal text and `<name>` placeholders.
enum Piece<'a> {
    Text(&'a str),
    Field(&'a str),
}

fn template_pieces(t: &str) -> Option<Vec<Piece<'_>>> {
    let mut out = Vec::new();
    let mut rest = t;
    while !rest.is_empty() {
        if let Some(after) = rest.strip_prefix('<') {
            let end = after.find('>')?;
            let name = after.get(..end)?;
            if !is_field_name(name) {
                return None;
            }
            out.push(Piece::Field(name));
            rest = after.get(end.checked_add(1)?..)?;
        } else {
            let end = rest.find('<').unwrap_or(rest.len());
            let text = rest.get(..end)?;
            if !text
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b":._-".contains(&b))
            {
                return None;
            }
            out.push(Piece::Text(text));
            rest = rest.get(end..)?;
        }
    }
    Some(out)
}

fn compile_rule(v: &Value) -> Option<Rule> {
    let o = v.as_object()?;
    if o.len() != 2 {
        return None;
    }
    let aud = o.get("aud")?.as_str()?;
    let mut fields = Vec::new();
    for (name, raw) in o.get("fields")?.as_object()?.iter() {
        if !is_field_name(name) || name == "type" || name == "signer" {
            return None;
        }
        let raw = raw.as_str()?;
        let (kind, optional) = match raw.strip_suffix('?') {
            Some(k) => (k, true),
            None => (raw, false),
        };
        fields.push(Field {
            name: String::from(name),
            kind: parse_kind(kind)?,
            optional,
        });
    }
    // The template starts with a literal writer and `:`, and every placeholder names the signer
    // or a required field.
    let pieces = template_pieces(aud)?;
    let Some(Piece::Text(head)) = pieces.first() else {
        return None;
    };
    let (writer, _) = head.split_once(':')?;
    if !is_writer(writer) {
        return None;
    }
    for p in &pieces {
        if let Piece::Field(name) = p
            && *name != "signer"
            && !fields.iter().any(|f| f.name == *name && !f.optional)
        {
            return None;
        }
    }
    Some(Rule {
        aud: String::from(aud),
        fields,
    })
}

/// Reads a `registry@1` document. Any rule that does not read makes the whole document unusable.
pub fn parse_registry(v: &Value) -> Option<Registry> {
    let o = v.as_object()?;
    if o.len() != 2 || o.get("type")?.as_str()? != REGISTRY_1 {
        return None;
    }
    let statements = o.get("statements")?.as_object()?;
    if statements.is_empty() {
        return None;
    }
    let mut rules = Vec::with_capacity(statements.len());
    for (ty, rule) in statements.iter() {
        if !is_type_id(ty) {
            return None;
        }
        rules.push((String::from(ty), compile_rule(rule)?));
    }
    Some(Registry { rules })
}

impl Registry {
    pub fn rule(&self, ty: &str) -> Option<&Rule> {
        self.rules.iter().find(|(t, _)| t == ty).map(|(_, r)| r)
    }

    /// Checks a statement: its type is in the registry, it has exactly the fields of the rule
    /// (optional ones may be left out), and every field has its kind. Returns the rule.
    pub fn statement<'a>(&self, v: &'a Value) -> Option<(&'a str, &Rule)> {
        let o = v.as_object()?;
        let ty = o.get("type")?.as_str()?;
        let rule = self.rule(ty)?;
        if o.keys()
            .any(|k| k != "type" && !rule.fields.iter().any(|f| f.name == k))
        {
            return None;
        }
        for f in &rule.fields {
            match o.get(&f.name) {
                None if f.optional => {}
                None => return None,
                Some(value) if !f.kind.check(value) => return None,
                Some(_) => {}
            }
        }
        Some((ty, rule))
    }
}

impl Rule {
    /// The `aud` the template gives for a statement and the envelope's signer.
    pub fn aud(&self, statement: &Value, signer: &str) -> Option<String> {
        let mut out = String::new();
        for p in template_pieces(&self.aud)? {
            match p {
                Piece::Text(t) => out.push_str(t),
                Piece::Field("signer") => out.push_str(signer),
                Piece::Field(name) => out.push_str(statement.get(name)?.as_str()?),
            }
        }
        is_aud(&out).then_some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(json: &str) -> Value {
        crate::json::parse(json.as_bytes()).unwrap()
    }

    const DOC: &str = r#"{"type":"registry@1","statements":{
        "app.sign@1":{"aud":"request:<request>","fields":{"request":"id","app":"app","digest":"bytes32"}},
        "profile.patch@1":{"aud":"account:<signer>","fields":{"display_name":"text(200)"}},
        "org.seat.revoke@1":{"aud":"org:<org>","fields":{"org":"org","seat":"id","note":"text(10)?"}}}}"#;

    #[test]
    fn reads_and_checks() {
        let r = parse_registry(&v(DOC)).unwrap();
        let st = v(r#"{"type":"profile.patch@1","display_name":"Hamachi"}"#);
        let (ty, rule) = r.statement(&st).unwrap();
        assert_eq!(ty, "profile.patch@1");
        assert_eq!(
            rule.aud(&st, "eu1.Q2xh").as_deref(),
            Some("account:eu1.Q2xh")
        );
        let st = v(
            r#"{"type":"org.seat.revoke@1","org":"eu1.0b5c0e2e-9d39-4c1f-9b1b-2b0f7e7c1a10","seat":"s1"}"#,
        );
        let (_, rule) = r.statement(&st).unwrap();
        assert_eq!(
            rule.aud(&st, "x").as_deref(),
            Some("org:eu1.0b5c0e2e-9d39-4c1f-9b1b-2b0f7e7c1a10")
        );
        assert!(
            r.statement(&v(r#"{"type":"profile.patch@1","display_name":" x"}"#))
                .is_none()
        );
        assert!(
            r.statement(&v(
                r#"{"type":"profile.patch@1","display_name":"x","extra":1}"#
            ))
            .is_none()
        );
        assert!(r.statement(&v(r#"{"type":"nope@1"}"#)).is_none());
    }

    #[test]
    fn refuses_bad_documents() {
        for bad in [
            r#"{"type":"registry@1","statements":{}}"#,
            r#"{"type":"registry@2","statements":{"a@1":{"aud":"account:<signer>","fields":{}}}}"#,
            r#"{"type":"registry@1","statements":{"a@1":{"aud":"account:<signer>","fields":{"x":"line(5)"}}}}"#,
            r#"{"type":"registry@1","statements":{"a@1":{"aud":"account:<x>","fields":{"x":"id?"}}}}"#,
            r#"{"type":"registry@1","statements":{"a@1":{"aud":"account:<y>","fields":{"x":"id"}}}}"#,
            r#"{"type":"registry@1","statements":{"a@1":{"aud":"<x>","fields":{"x":"id"}}}}"#,
            r#"{"type":"registry@1","statements":{"a@1":{"aud":"Account:<x>","fields":{"x":"id"}}}}"#,
            r#"{"type":"registry@1","statements":{"a@1":{"aud":"account:<signer>","fields":{"signer":"id"}}}}"#,
            r#"{"type":"registry@1","statements":{"a@1":{"aud":"account:<signer>","fields":{"type":"id"}}}}"#,
            r#"{"type":"registry@1","statements":{"A@1":{"aud":"account:<signer>","fields":{}}}}"#,
            r#"{"type":"registry@1","statements":{"a@1":{"aud":"account:<signer>","fields":{},"x":1}}}"#,
        ] {
            assert!(parse_registry(&v(bad)).is_none(), "{bad}");
        }
    }

    #[test]
    fn auds() {
        assert!(is_aud("account:eu1.Q2xh_-"));
        assert!(is_aud("domain:a.example"));
        assert!(!is_aud("account:"));
        assert!(!is_aud("account"));
        assert!(!is_aud("Account:x"));
        assert!(!is_aud("account:a b"));
        let long = alloc::format!("domain:{}", "a".repeat(253));
        assert!(is_aud(&long));
        assert!(!is_aud(&alloc::format!("{long}a")));
    }
}

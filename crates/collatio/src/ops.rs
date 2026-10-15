//! `verify(op, input)`: reads the outer input, dispatches on `op`, writes the answer.
//!
//! The outer input is a JSON object `{ "op": "<name>", … }` built by the host. Evidence, trust
//! documents and registries travel inside it as JSON strings and are read again, strictly, by the
//! operation that needs them. The answer is `{"ok":true,…}` or `{"ok":false,"reason":"…"}` in
//! canonical form.

use alloc::string::String;
use alloc::vec::Vec;

use crate::bundle::verify_bundle;
use crate::chain::verify_chain;
use crate::digest::digest_of;
use crate::envelope::parse_envelope;
use crate::jcs::canonical;
use crate::json::{self, Number, Object, Value};
use crate::ledger::merkle::{verify_consistency, verify_inclusion};
use crate::logs::{Body, verify_log_note};
use crate::mandate::{GrantContext, parse_terms, read_grant, verify_close, verify_use};
use crate::reason::Reason;
use crate::receipt::{Expect, Kind, RECEIPT_1, RECEIPT_APP_1, verify_receipt};
use crate::trust::{PublicKey, document, read_trust};
use crate::webauthn::{WebauthnOk, verify_webauthn1};

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

fn dispatch(op: &str, outer: &Value) -> Result<Object, Reason> {
    match op {
        "trust" => op_trust(outer),
        "proof" => op_proof(outer),
        "receipt" => op_receipt(outer, Kind::Holder),
        "app_receipt" => op_receipt(outer, Kind::App),
        "ledger_note" => op_ledger_note(outer),
        "inclusion" => op_inclusion(outer),
        "consistency" => op_consistency(outer),
        "mandate_history" => op_mandate_history(outer),
        "chain" => op_chain(outer),
        "bundle" => op_bundle(outer),
        _ => Err(Reason::UnknownOp),
    }
}

fn obj(members: Vec<(&str, Value)>) -> Object {
    let mut o = Object::default();
    for (k, v) in members {
        o.insert(String::from(k), v);
    }
    o
}

fn int(n: i64) -> Value {
    let raw = alloc::format!("{n}");
    #[allow(clippy::cast_precision_loss)]
    let f = n as f64;
    Value::Number(Number::from_parts(&raw, f))
}

fn uint(n: u64) -> Value {
    int(i64::try_from(n).unwrap_or(i64::MAX))
}

fn strings(items: &[String]) -> Value {
    Value::Array(items.iter().map(|s| Value::from(s.as_str())).collect())
}

fn safe_uint(outer: &Value, key: &str) -> Result<u64, Reason> {
    outer
        .get(key)
        .and_then(Value::as_number)
        .and_then(Number::as_safe_integer)
        .and_then(|n| u64::try_from(n).ok())
        .ok_or(Reason::InputMalformed)
}

fn hash32(v: Option<&Value>) -> Result<[u8; 32], Reason> {
    use base64ct::{Base64, Encoding};
    let s = v.and_then(Value::as_str).ok_or(Reason::InputMalformed)?;
    Base64::decode_vec(s)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        .ok_or(Reason::InputMalformed)
}

fn hash_list(v: Option<&Value>) -> Result<Vec<[u8; 32]>, Reason> {
    let list = v.and_then(Value::as_array).ok_or(Reason::InputMalformed)?;
    if list.len() > 64 {
        return Err(Reason::InputMalformed);
    }
    list.iter().map(|h| hash32(Some(h))).collect()
}

fn std_b64(bytes: &[u8]) -> Value {
    use base64ct::{Base64, Encoding};
    Value::from(Base64::encode_string(bytes).as_str())
}

fn op_trust(outer: &Value) -> Result<Object, Reason> {
    let t = read_trust(outer.get("trust"))?;
    let keys = t
        .keys
        .iter()
        .map(|k| {
            let alg = match k.key {
                PublicKey::Es256(_) => "ES256",
                PublicKey::Ed25519(_) => "EdDSA",
            };
            Value::Object(obj(alloc::vec![
                ("kid", Value::from(k.kid.as_str())),
                ("slot", Value::from(k.slot.as_str())),
                ("alg", Value::from(alg)),
            ]))
        })
        .collect();
    let logs = t
        .catalog
        .logs
        .iter()
        .map(|(id, kid)| {
            Value::Object(obj(alloc::vec![
                ("id", Value::from(id.as_str())),
                ("kid", Value::from(kid.as_str())),
            ]))
        })
        .collect();
    let catalog = |k: &str| t.catalog.value.get(k).cloned().unwrap_or(Value::Null);
    Ok(obj(alloc::vec![
        ("instance", Value::from(t.nomination.instance_id.as_str())),
        ("sealer", Value::from(t.nomination.sealer_kid.as_str())),
        ("issued_at", int(t.catalog.issued_at)),
        ("keys", Value::Array(keys)),
        ("logs", Value::Array(logs)),
        ("verifiers", catalog("verifiers")),
        ("revoked", catalog("revoked")),
        ("registries", strings(&t.catalog.registries)),
        ("dimensions", strings(&t.catalog.dimensions)),
    ]))
}

fn proof_fields(ok: &WebauthnOk) -> Vec<(&'static str, Value)> {
    alloc::vec![
        ("origin", Value::from(ok.origin.as_str())),
        ("counter", int(i64::from(ok.counter))),
        ("alg", int(ok.alg)),
        ("backup_eligible", Value::Bool(ok.backup_eligible)),
        ("backed_up", Value::Bool(ok.backed_up)),
    ]
}

fn op_proof(outer: &Value) -> Result<Object, Reason> {
    let envelope = document(outer.get("envelope"))?;
    let proof = document(outer.get("proof"))?;
    let key = document(outer.get("key"))?;
    parse_envelope(&envelope).ok_or(Reason::EnvelopeShape)?;
    let ok = verify_webauthn1(&envelope, &proof, &key).map_err(Reason::from)?;
    Ok(obj(proof_fields(&ok)))
}

fn op_receipt(outer: &Value, kind: Kind) -> Result<Object, Reason> {
    let trust = read_trust(outer.get("trust"))?;
    let evidence = document(outer.get("evidence"))?;
    let holder_proof = match (kind, outer.get("holder_proof")) {
        (Kind::App, Some(p)) => Some(document(Some(p))?),
        (_, None) => None,
        (Kind::Holder, Some(_)) => return Err(Reason::InputMalformed),
    };
    let expect = match outer.get("expect") {
        None => Expect::default(),
        Some(e) => {
            let e = e.as_object().ok_or(Reason::InputMalformed)?;
            let member = |k: &str| match e.get(k) {
                None => Ok(None),
                Some(v) => v.as_str().map(Some).ok_or(Reason::InputMalformed),
            };
            if e.keys()
                .any(|k| !matches!(k, "statement" | "aud" | "signer"))
            {
                return Err(Reason::InputMalformed);
            }
            Expect {
                statement: member("statement")?,
                aud: member("aud")?,
                signer: member("signer")?,
            }
        }
    };
    let v = verify_receipt(&trust, &evidence, kind, holder_proof.as_ref(), &expect)?;
    let accepted = v
        .accepted
        .iter()
        .map(|(kid, at)| {
            Value::Object(obj(alloc::vec![
                ("kid", Value::from(kid.as_str())),
                ("at", int(*at)),
            ]))
        })
        .collect();
    let key_record = match &v.key_record {
        None => Value::Null,
        Some(r) => Value::Object(obj(alloc::vec![
            ("log", Value::from(r.place.log.as_str())),
            ("index", uint(r.place.index)),
            ("at", int(r.at)),
        ])),
    };
    let mut fields = alloc::vec![
        (
            "type",
            Value::from(match kind {
                Kind::Holder => RECEIPT_1,
                Kind::App => RECEIPT_APP_1,
            })
        ),
        ("statement", v.statement.clone()),
        ("envelope", v.envelope.clone()),
        (
            "dimension",
            Value::Object(obj(alloc::vec![
                ("digest", Value::from(v.dimension_digest.as_str())),
                ("name", Value::from(v.dimension.name.as_str())),
                ("verifier", Value::from(v.dimension.verifier.as_str())),
                ("registry", Value::from(v.dimension.registry.as_str())),
                ("signer", Value::from(v.dimension.signer.as_str())),
            ])),
        ),
        ("accepted", Value::Array(accepted)),
        (
            "anchor",
            Value::Object(obj(alloc::vec![
                ("log", Value::from(v.anchor.log.as_str())),
                ("index", uint(v.anchor.index)),
            ])),
        ),
    ];
    if kind == Kind::Holder {
        fields.push(("key_record", key_record));
    }
    if let Some(p) = &v.proof {
        fields.extend(proof_fields(p));
    }
    Ok(obj(fields))
}

fn op_ledger_note(outer: &Value) -> Result<Object, Reason> {
    let trust = read_trust(outer.get("trust"))?;
    let note = outer
        .get("note")
        .and_then(Value::as_str)
        .ok_or(Reason::InputMalformed)?;
    let v = verify_log_note(&trust, note)?;
    let body = match &v.body {
        Body::Receipt(r) => obj(alloc::vec![
            ("kind", Value::from("receipt")),
            ("origin", Value::from(r.origin.as_str())),
            ("index", uint(r.index)),
            ("leaf_hash", std_b64(&r.leaf_hash)),
        ]),
        Body::Checkpoint(c) => obj(alloc::vec![
            ("kind", Value::from("checkpoint")),
            ("origin", Value::from(c.origin.as_str())),
            ("size", uint(c.size)),
            ("root", std_b64(&c.root)),
            ("time", uint(c.time)),
        ]),
    };
    Ok(obj(alloc::vec![
        ("log", Value::from(v.log.as_str())),
        ("kid", Value::from(v.kid.as_str())),
        ("body", Value::Object(body)),
    ]))
}

fn op_inclusion(outer: &Value) -> Result<Object, Reason> {
    let (index, size) = (safe_uint(outer, "index")?, safe_uint(outer, "size")?);
    let leaf = hash32(outer.get("leaf_hash"))?;
    let root = hash32(outer.get("root"))?;
    let proof = hash_list(outer.get("proof"))?;
    if !verify_inclusion(index, size, &leaf, &proof, &root) {
        return Err(Reason::InclusionProof);
    }
    Ok(Object::default())
}

fn strings_of(v: Option<&Value>) -> Result<Vec<Value>, Reason> {
    v.and_then(Value::as_array)
        .ok_or(Reason::InputMalformed)?
        .iter()
        .map(|s| document(Some(s)))
        .collect()
}

fn op_mandate_history(outer: &Value) -> Result<Object, Reason> {
    let trust = read_trust(outer.get("trust"))?;
    let grant_doc = document(outer.get("grant"))?;
    let kind = match grant_doc.get("type").and_then(Value::as_str) {
        Some(RECEIPT_1) => Kind::Holder,
        Some(RECEIPT_APP_1) => Kind::App,
        _ => return Err(Reason::ReceiptType),
    };
    let receipt = verify_receipt(&trust, &grant_doc, kind, None, &Expect::default())?;
    let grant = read_grant(&receipt.statement).ok_or(Reason::MandateGrant)?;
    let terms_doc = document(outer.get("terms"))?;
    let terms = parse_terms(&terms_doc).ok_or(Reason::MandateTermsShape)?;
    if digest_of(&terms_doc) != grant.terms {
        return Err(Reason::MandateTermsDigest);
    }
    let digest = digest_of(&receipt.envelope);
    let iat = receipt
        .envelope
        .get("iat")
        .and_then(Value::as_number)
        .and_then(Number::as_safe_integer)
        .ok_or(Reason::EnvelopeShape)?;
    let g = GrantContext {
        grant: &grant,
        terms: &terms,
        digest: &digest,
        iat,
    };
    let mut uses = Vec::new();
    for doc in strings_of(outer.get("uses"))? {
        let u = verify_use(&trust, &g, &doc, uses.last())?;
        uses.push(u);
    }
    let close = match outer.get("close") {
        None | Some(Value::Null) => Value::Null,
        Some(c) => {
            let c = verify_close(&trust, &g, &document(Some(c))?, uses.last())?;
            if usize::try_from(c.uses).ok() != Some(uses.len()) {
                return Err(Reason::MandateCloseUses);
            }
            Value::Object(obj(alloc::vec![
                ("reason", Value::from(c.reason.as_str())),
                ("at", int(c.at)),
                ("uses", int(c.uses)),
            ]))
        }
    };
    let totals = |t: &crate::mandate::Totals| {
        let mut f = alloc::vec![("uses", int(t.uses))];
        if let Some(a) = t.amount {
            f.push(("amount", int(a)));
        }
        Value::Object(obj(f))
    };
    let uses = uses
        .iter()
        .map(|u| {
            Value::Object(obj(alloc::vec![
                ("seq", int(u.seq)),
                ("operation", Value::from(u.request.operation.as_str())),
                ("at", int(u.at)),
                ("totals", totals(&u.totals)),
            ]))
        })
        .collect();
    let on_behalf = match &grant.on_behalf {
        None => Value::Null,
        Some((org, domain)) => Value::Object(obj(alloc::vec![
            ("org", Value::from(org.as_str())),
            ("domain", Value::from(domain.as_str())),
        ])),
    };
    Ok(obj(alloc::vec![
        (
            "grant",
            Value::Object(obj(alloc::vec![
                ("type", Value::from(grant.kind)),
                ("mandate", Value::from(grant.mandate.as_str())),
                ("app", Value::from(grant.app.as_str())),
                ("request", Value::from(grant.request.as_str())),
                ("on_behalf", on_behalf),
            ])),
        ),
        ("terms", terms.value.clone()),
        ("uses", Value::Array(uses)),
        ("close", close),
    ]))
}

fn op_chain(outer: &Value) -> Result<Object, Reason> {
    let trust = read_trust(outer.get("trust"))?;
    let events = strings_of(outer.get("events"))?;
    let from = match outer.get("from") {
        None | Some(Value::Null) => None,
        Some(f) => Some(f.as_str().ok_or(Reason::InputMalformed)?),
    };
    let mut contents = Vec::new();
    if let Some(list) = outer.get("contents") {
        for c in list.as_array().ok_or(Reason::InputMalformed)? {
            let seq = c
                .get("seq")
                .and_then(Value::as_number)
                .and_then(Number::as_safe_integer)
                .ok_or(Reason::InputMalformed)?;
            contents.push((seq, document(c.get("content"))?));
        }
    }
    let snapshot = match outer.get("snapshot") {
        None | Some(Value::Null) => None,
        Some(s) => Some(document(Some(s))?),
    };
    let ok = verify_chain(&trust, &events, from, &contents, snapshot.as_ref())?;
    let opened = ok
        .opened
        .iter()
        .map(|o| {
            Value::Object(obj(alloc::vec![
                ("seq", int(o.seq)),
                ("change", Value::from(o.change.as_str())),
                ("at", int(o.at)),
            ]))
        })
        .collect();
    Ok(obj(alloc::vec![
        ("actor", Value::from(ok.actor.as_str())),
        ("first", int(ok.first)),
        ("last", int(ok.last)),
        ("head", Value::from(ok.head.as_str())),
        ("opened", Value::Array(opened)),
        ("snapshot", ok.snapshot.map_or(Value::Null, int)),
    ]))
}

fn op_bundle(outer: &Value) -> Result<Object, Reason> {
    let trust = read_trust(outer.get("trust"))?;
    let ok = verify_bundle(&trust, &document(outer.get("evidence"))?)?;
    let anchor = match &ok.anchor {
        None => Value::Null,
        Some(a) => Value::Object(obj(alloc::vec![
            ("anchored_by", uint(a.anchored_by)),
            ("tsa", uint(u64::try_from(a.tsa).unwrap_or(u64::MAX))),
        ])),
    };
    Ok(obj(alloc::vec![
        ("log", Value::from(ok.log.as_str())),
        ("index", uint(ok.index)),
        ("committed_by", uint(ok.committed_by)),
        ("opening", Value::Bool(ok.opening)),
        ("anchor", anchor),
    ]))
}

fn op_consistency(outer: &Value) -> Result<Object, Reason> {
    let (first, second) = (safe_uint(outer, "first")?, safe_uint(outer, "second")?);
    let first_root = hash32(outer.get("first_root"))?;
    let second_root = hash32(outer.get("second_root"))?;
    let proof = hash_list(outer.get("proof"))?;
    if !verify_consistency(first, second, &first_root, &second_root, &proof) {
        return Err(Reason::ConsistencyProof);
    }
    Ok(Object::default())
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

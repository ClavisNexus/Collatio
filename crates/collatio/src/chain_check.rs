//! `key.chain@1` and the `chain_check` operation (FORMATS.md §4.5).
//!
//! Entity and handle events are `ledger.bundle@1` strings, checked with [`verify_bundle`].
//! A `map.proof@1` is checked by verifying its `heads` bundle. That bundle's inclusion proof
//! is the Merkle inclusion this crate already implements. The map path is not folded, and no
//! other hash is defined.

use alloc::string::String;
use alloc::vec::Vec;

use crate::bundle::verify_bundle;
use crate::digest::{digest_of, is_digest};
use crate::json::{self, Number, Object, Value};
use crate::reason::Reason;
use crate::trust::Trust;

const KEY_CHAIN_1: &str = "key.chain@1";
const MAP_PROOF_1: &str = "map.proof@1";
const MAP_ROOT_1: &str = "map.root@1";
const KEY_SET_1: &str = "key.set@1";

/// The chain a caller asked to be checked. `handle` and `event` are absent when null.
pub struct ChainExpect<'a> {
    pub entity: &'a str,
    pub handle: Option<&'a str>,
    pub event: Option<&'a str>,
}

/// Pieces of a `key.chain@1` or of a `chain_check` input, after the caller's shape check.
pub struct ChainParts<'a> {
    pub entity_events: &'a [Value],
    pub head: &'a Value,
    pub handle_events: Option<&'a [Value]>,
    pub keys: Option<&'a Value>,
}

/// One event the chain contains, named by `expect.event`.
pub struct FoundEvent {
    pub seq: i64,
    pub log: String,
    pub index: u64,
    pub key: String,
}

/// One key record the keys proof contains.
pub struct FoundKey {
    pub key: String,
    pub by: String,
    pub method: Option<String>,
    pub rp: Option<String>,
    pub use_for: String,
    pub bound_at: i64,
    pub unbound_at: Option<i64>,
    pub reason: Option<String>,
}

/// What the reader established.
pub struct ChainOk {
    pub handle: Option<String>,
    pub last_seq: Option<i64>,
    pub event: Option<FoundEvent>,
    pub keys: Vec<FoundKey>,
    pub covers: i64,
    pub as_of: i64,
}

struct Opened {
    seq: i64,
    log: String,
    index: u64,
    digest: String,
    signing_key: String,
    handle: Option<String>,
    key_id: Option<String>,
    method: Option<String>,
    rp: Option<String>,
}

struct Proof {
    as_of: i64,
    covers: Option<i64>,
    value: Option<Value>,
}

struct RawKey {
    key: String,
    by: String,
    use_for: String,
    bound_at: i64,
    unbound_at: Option<i64>,
    reason: Option<String>,
}

fn nonneg(o: &Object, key: &str, fail: Reason) -> Result<i64, Reason> {
    let n = o
        .get(key)
        .and_then(Value::as_number)
        .and_then(Number::as_safe_integer)
        .ok_or(fail)?;
    if n < 0 {
        return Err(fail);
    }
    Ok(n)
}

fn opt_text(o: &Object, key: &str, fail: Reason) -> Result<Option<String>, Reason> {
    match o.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => {
            let text = v.as_str().ok_or(fail)?;
            if text.is_empty() {
                return Err(fail);
            }
            Ok(Some(String::from(text)))
        }
    }
}

fn as_document(v: &Value, fail: Reason) -> Result<Value, Reason> {
    match v {
        Value::Object(_) => Ok(v.clone()),
        Value::String(text) => json::parse(text.as_bytes()).map_err(|_| fail),
        _ => Err(fail),
    }
}

fn signing_key(record: &Object, fail: Reason) -> Result<String, Reason> {
    let sigs = record.get("sigs").and_then(Value::as_array).ok_or(fail)?;
    let mut first = None;
    let mut event = None;
    for sig in sigs {
        let o = sig.as_object().ok_or(fail)?;
        let key = o
            .get("key")
            .and_then(Value::as_str)
            .filter(|k| is_digest(k))
            .ok_or(fail)?;
        if first.is_none() {
            first = Some(key);
        }
        if o.get("role").and_then(Value::as_str) == Some("event") {
            event = Some(key);
        }
    }
    event.or(first).map(String::from).ok_or(fail)
}

fn key_digest(record: &Object, fail: Reason) -> Result<Option<String>, Reason> {
    match record.get("key") {
        None | Some(Value::Null) | Some(Value::Object(_)) => Ok(None),
        Some(v) => {
            let text = v.as_str().ok_or(fail)?;
            if !is_digest(text) {
                return Err(fail);
            }
            Ok(Some(String::from(text)))
        }
    }
}

fn names_entity(record: &Object, digest: &str, entity: &str, fail: Reason) -> Result<(), Reason> {
    match record.get("entity") {
        None => {
            if digest == entity {
                Ok(())
            } else {
                Err(fail)
            }
        }
        Some(v) => {
            let text = v.as_str().ok_or(fail)?;
            if text == entity { Ok(()) } else { Err(fail) }
        }
    }
}

fn open_bundle(
    trust: &Trust,
    item: &Value,
    entity: &str,
    require_handle: bool,
    fail: Reason,
) -> Result<Opened, Reason> {
    let text = item.as_str().ok_or(fail)?;
    let bundle = json::parse(text.as_bytes()).map_err(|_| fail)?;
    let verified = verify_bundle(trust, &bundle).map_err(|_| fail)?;
    if !verified.opening {
        return Err(fail);
    }
    let record = bundle
        .get("opening")
        .and_then(|opening| opening.get("record"))
        .and_then(Value::as_object)
        .ok_or(fail)?;
    let seq = nonneg(record, "seq", fail)?;
    if seq < 1 {
        return Err(fail);
    }
    let bare = Value::Object(record.without("sigs").without("approve"));
    let digest = digest_of(&bare);
    names_entity(record, &digest, entity, fail)?;
    let handle = opt_text(record, "handle", fail)?;
    if require_handle && handle.is_none() {
        return Err(fail);
    }
    Ok(Opened {
        seq,
        log: verified.log,
        index: verified.index,
        digest,
        signing_key: signing_key(record, fail)?,
        handle,
        key_id: key_digest(record, fail)?,
        method: opt_text(record, "method", fail)?,
        rp: opt_text(record, "rp", fail)?,
    })
}

fn read_events(
    trust: &Trust,
    items: &[Value],
    entity: &str,
    require_handle: bool,
    fail: Reason,
) -> Result<Vec<Opened>, Reason> {
    if items.is_empty() {
        return Err(fail);
    }
    let mut out = Vec::new();
    for item in items {
        out.push(open_bundle(trust, item, entity, require_handle, fail)?);
    }
    Ok(out)
}

fn proof_root(root: &Object, fail: Reason) -> Result<(i64, Option<i64>), Reason> {
    if root.get("type").and_then(Value::as_str) != Some(MAP_ROOT_1) {
        return Err(fail);
    }
    let as_of = nonneg(root, "as_of", fail)?;
    let covers = match root.get("covers") {
        None => None,
        Some(_) => Some(nonneg(root, "covers", fail)?),
    };
    Ok((as_of, covers))
}

fn read_proof(trust: &Trust, v: &Value, fail: Reason) -> Result<Proof, Reason> {
    let doc = as_document(v, fail)?;
    let o = doc.as_object().ok_or(fail)?;
    if o.get("type").and_then(Value::as_str) != Some(MAP_PROOF_1) {
        return Err(fail);
    }
    let at = o.get("at").and_then(Value::as_object).ok_or(fail)?;
    let heads = as_document(at.get("heads").ok_or(fail)?, fail)?;
    verify_bundle(trust, &heads).map_err(|_| fail)?;
    let root = at.get("root").and_then(Value::as_object).ok_or(fail)?;
    let (as_of, covers) = proof_root(root, fail)?;
    let value = match at.get("value") {
        None | Some(Value::Null) => None,
        Some(value) => Some(value.clone()),
    };
    Ok(Proof {
        as_of,
        covers,
        value,
    })
}

fn nullable_text(o: &Object, key: &str, fail: Reason) -> Result<Option<String>, Reason> {
    match o.get(key) {
        Some(Value::Null) => Ok(None),
        Some(v) => Ok(Some(String::from(v.as_str().ok_or(fail)?))),
        None => Err(fail),
    }
}

fn one_key(item: &Value, fail: Reason) -> Result<RawKey, Reason> {
    let o = item.as_object().ok_or(fail)?;
    let key = o.get("key").and_then(Value::as_str).ok_or(fail)?;
    if !is_digest(key) {
        return Err(fail);
    }
    let by = o.get("by").and_then(Value::as_str).ok_or(fail)?;
    let use_for = o.get("use").and_then(Value::as_str).ok_or(fail)?;
    if by.is_empty() || use_for.is_empty() {
        return Err(fail);
    }
    let unbound_at = match o.get("unbound_at").ok_or(fail)? {
        Value::Null => None,
        other => {
            let n = other
                .as_number()
                .and_then(Number::as_safe_integer)
                .ok_or(fail)?;
            if n < 0 {
                return Err(fail);
            }
            Some(n)
        }
    };
    Ok(RawKey {
        key: String::from(key),
        by: String::from(by),
        use_for: String::from(use_for),
        bound_at: nonneg(o, "bound_at", fail)?,
        unbound_at,
        reason: nullable_text(o, "reason", fail)?,
    })
}

fn read_key_records(value: Option<&Value>, fail: Reason) -> Result<Vec<RawKey>, Reason> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let o = value.as_object().ok_or(fail)?;
    if o.get("type").and_then(Value::as_str) != Some(KEY_SET_1) {
        return Err(fail);
    }
    let list = o.get("keys").and_then(Value::as_array).ok_or(fail)?;
    let mut out = Vec::new();
    for item in list {
        out.push(one_key(item, fail)?);
    }
    Ok(out)
}

fn same_handle(events: &[Opened], expect: Option<&str>, fail: Reason) -> Result<String, Reason> {
    let handle = events
        .first()
        .and_then(|event| event.handle.clone())
        .ok_or(fail)?;
    if events
        .iter()
        .any(|event| event.handle.as_deref() != Some(handle.as_str()))
    {
        return Err(fail);
    }
    if expect.is_some_and(|wanted| wanted != handle) {
        return Err(fail);
    }
    Ok(handle)
}

/// Reads the bundles and the head proof. `entity_events` and `head` fail as `entity_chain`.
/// `handle_events` and `keys`, when present, fail as `key_chain`.
pub fn read_chain(
    trust: &Trust,
    parts: ChainParts<'_>,
    expect: ChainExpect<'_>,
) -> Result<ChainOk, Reason> {
    let entity_events = read_events(
        trust,
        parts.entity_events,
        expect.entity,
        false,
        Reason::EntityChain,
    )?;
    let head = read_proof(trust, parts.head, Reason::EntityChain)?;
    let covers = head.covers.ok_or(Reason::EntityChain)?;
    let handle_events = match parts.handle_events {
        None => None,
        Some(items) => Some(read_events(
            trust,
            items,
            expect.entity,
            true,
            Reason::KeyChain,
        )?),
    };
    let keys_proof = match parts.keys {
        None => None,
        Some(proof) => Some(read_proof(trust, proof, Reason::KeyChain)?),
    };
    let raw_keys = match &keys_proof {
        None => Vec::new(),
        Some(proof) => read_key_records(proof.value.as_ref(), Reason::KeyChain)?,
    };
    let as_of = match &keys_proof {
        Some(proof) => proof.as_of,
        None => head.as_of,
    };
    let (handle, last_seq) = match &handle_events {
        None => {
            if expect.handle.is_some() {
                return Err(Reason::KeyChain);
            }
            (None, None)
        }
        Some(events) => {
            let handle = same_handle(events, expect.handle, Reason::KeyChain)?;
            let last_seq = events
                .last()
                .map(|event| event.seq)
                .ok_or(Reason::KeyChain)?;
            (Some(handle), Some(last_seq))
        }
    };
    let keys = raw_keys
        .into_iter()
        .map(|raw| {
            let (method, rp) = match &handle_events {
                None => (None, None),
                Some(events) => events
                    .iter()
                    .find(|event| event.key_id.as_deref() == Some(raw.key.as_str()))
                    .map(|event| (event.method.clone(), event.rp.clone()))
                    .unwrap_or((None, None)),
            };
            FoundKey {
                key: raw.key,
                by: raw.by,
                method,
                rp,
                use_for: raw.use_for,
                bound_at: raw.bound_at,
                unbound_at: raw.unbound_at,
                reason: raw.reason,
            }
        })
        .collect();
    let event = match expect.event {
        None => None,
        Some(wanted) => {
            let found = entity_events
                .iter()
                .find(|event| event.digest == wanted)
                .or_else(|| {
                    handle_events
                        .as_ref()
                        .and_then(|events| events.iter().find(|event| event.digest == wanted))
                })
                .ok_or(Reason::ChainEvent)?;
            Some(FoundEvent {
                seq: found.seq,
                log: found.log.clone(),
                index: found.index,
                key: found.signing_key.clone(),
            })
        }
    };
    Ok(ChainOk {
        handle,
        last_seq,
        event,
        keys,
        covers,
        as_of,
    })
}

/// Whether `v` is one `key.chain@1` object with the members §4.5 allows.
/// A failure here is the disclosure's shape, before the bundles are read.
pub fn disclosure_parts(v: &Value) -> Result<ChainParts<'_>, Reason> {
    let list = v.as_array().ok_or(Reason::DisclosureShape)?;
    if list.len() != 1 {
        return Err(Reason::DisclosureShape);
    }
    let o = list
        .first()
        .and_then(Value::as_object)
        .ok_or(Reason::DisclosureShape)?;
    if o.get("type").and_then(Value::as_str) != Some(KEY_CHAIN_1) {
        return Err(Reason::DisclosureShape);
    }
    let allowed = [
        "type",
        "entity_events",
        "head",
        "handle_events",
        "keys",
        "closure",
        "cosign",
    ];
    if o.keys().any(|key| !allowed.contains(&key)) {
        return Err(Reason::DisclosureShape);
    }
    let entity_events = o
        .get("entity_events")
        .and_then(Value::as_array)
        .ok_or(Reason::DisclosureShape)?;
    let head = o.get("head").ok_or(Reason::DisclosureShape)?;
    if !matches!(head, Value::String(_) | Value::Object(_)) {
        return Err(Reason::DisclosureShape);
    }
    let handle_events = match o.get("handle_events") {
        None | Some(Value::Null) => None,
        Some(value) => Some(value.as_array().ok_or(Reason::DisclosureShape)?),
    };
    let keys = match o.get("keys") {
        None | Some(Value::Null) => None,
        Some(value @ (Value::String(_) | Value::Object(_))) => Some(value),
        Some(_) => return Err(Reason::DisclosureShape),
    };
    match o.get("closure") {
        None | Some(Value::Null) | Some(Value::Object(_)) => {}
        Some(_) => return Err(Reason::DisclosureShape),
    }
    match o.get("cosign") {
        None | Some(Value::Null) | Some(Value::Object(_)) => {}
        Some(_) => return Err(Reason::DisclosureShape),
    }
    Ok(ChainParts {
        entity_events,
        head,
        handle_events,
        keys,
    })
}

#[cfg(test)]
pub(crate) mod fixture {
    use super::*;
    use crate::b64;
    use crate::commit::commitment;
    use crate::jcs::canonical;
    use crate::json::parse;
    use crate::ledger::leaf::Leaf;
    use crate::ledger::note::key_hash;
    use base64ct::{Base64, Encoding};

    const LOG: &str = "first-party.0";
    const ORIGIN: &str = "clavis.nexus/ledger/first-party.0";

    fn num(n: i64) -> Value {
        parse(n.to_string().as_bytes()).unwrap()
    }

    fn obj(pairs: Vec<(&str, Value)>) -> Value {
        let mut out = Object::default();
        for (key, value) in pairs {
            assert!(out.insert(key.to_string(), value));
        }
        Value::Object(out)
    }

    fn sign_note(secret: &[u8; 32], body: &str) -> String {
        use ed25519_dalek::Signer;
        let key = ed25519_dalek::SigningKey::from_bytes(secret);
        let public = key.verifying_key().to_bytes();
        let mut raw = Vec::with_capacity(68);
        raw.extend_from_slice(&key_hash("ledger", &public));
        raw.extend_from_slice(&key.sign(body.as_bytes()).to_bytes());
        format!("{body}\n\u{2014} ledger {}\n", Base64::encode_string(&raw))
    }

    pub struct EventLeaf {
        pub text: String,
        pub digest: String,
    }

    /// A size-1 bundle whose opening is an entity event for `entity`.
    pub fn event_bundle(ledger: &[u8; 32], entity: &str, seq: i64, signing_key: &str) -> EventLeaf {
        let record = obj(vec![
            ("type", Value::from("entity.event@1")),
            ("entity", Value::from(entity)),
            ("seq", num(seq)),
            (
                "sigs",
                Value::Array(vec![obj(vec![
                    ("role", Value::from("event")),
                    ("key", Value::from(signing_key)),
                ])]),
            ),
        ]);
        let bare = record
            .as_object()
            .unwrap()
            .without("sigs")
            .without("approve");
        let digest = digest_of(&Value::Object(bare));
        let salt = b64::encode(&[3u8; 32]);
        let c = commitment(&salt, &record).unwrap();
        let leaf = Leaf { c, slot: None };
        let hash = leaf.hash();
        let hash_b64 = Base64::encode_string(&hash);
        let receipt = sign_note(
            ledger,
            &format!("clavis.ledger.receipt/v1\n{ORIGIN}\n0\n{hash_b64}\n"),
        );
        let checkpoint = sign_note(
            ledger,
            &format!("{ORIGIN}\n1\n{hash_b64}\ntime 1700000000\n"),
        );
        let bundle = obj(vec![
            ("type", Value::from("ledger.bundle@1")),
            ("log", Value::from(LOG)),
            ("leaf", leaf.to_value()),
            ("index", num(0)),
            ("receipt", Value::from(receipt.as_str())),
            ("checkpoint", Value::from(checkpoint.as_str())),
            ("inclusion", Value::Array(vec![])),
            (
                "opening",
                obj(vec![
                    ("salt", Value::from(salt.as_str())),
                    ("record", record),
                ]),
            ),
        ]);
        EventLeaf {
            text: canonical(&bundle),
            digest,
        }
    }

    pub fn map_proof(heads: &str, as_of: i64, covers: Option<i64>, value: Option<Value>) -> Value {
        let mut root_pairs = vec![("type", Value::from(MAP_ROOT_1)), ("as_of", num(as_of))];
        if let Some(covers) = covers {
            root_pairs.push(("covers", num(covers)));
        }
        let mut at_pairs = vec![("heads", Value::from(heads)), ("root", obj(root_pairs))];
        if let Some(value) = value {
            at_pairs.push(("value", value));
        }
        obj(vec![
            ("type", Value::from(MAP_PROOF_1)),
            ("at", obj(at_pairs)),
        ])
    }

    pub fn key_value(key: &str, bound_at: i64) -> Value {
        obj(vec![
            ("type", Value::from(KEY_SET_1)),
            (
                "keys",
                Value::Array(vec![obj(vec![
                    ("key", Value::from(key)),
                    ("by", Value::from("registration")),
                    ("use", Value::from("sign")),
                    ("bound_at", num(bound_at)),
                    ("unbound_at", Value::Null),
                    ("reason", Value::Null),
                ])]),
            ),
        ])
    }

    /// A disclosure whose bundles and head proof verify under `ledger`.
    pub fn disclosure(ledger: &[u8; 32], entity: &str) -> Value {
        let event = event_bundle(
            ledger,
            entity,
            1,
            "sha256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o",
        );
        obj(vec![
            ("type", Value::from(KEY_CHAIN_1)),
            (
                "entity_events",
                Value::Array(vec![Value::from(event.text.as_str())]),
            ),
            ("head", map_proof(&event.text, 1, Some(1), None)),
        ])
    }

    pub fn broken_inclusion(bundle: &str) -> String {
        let value = parse(bundle.as_bytes()).unwrap();
        let mut next = value.as_object().unwrap().without("inclusion");
        let bad = Base64::encode_string(&[0x11u8; 32]);
        assert!(next.insert(
            "inclusion".into(),
            Value::Array(vec![Value::from(bad.as_str())])
        ));
        canonical(&Value::Object(next))
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::{broken_inclusion, event_bundle, key_value, map_proof};
    use crate::jcs::canonical;
    use crate::json::{Object, Value, parse};
    use crate::reason::Reason;

    const ENTITY: &str = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    const SIGNING: &str = "sha256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o";
    const KEY: &str = "sha256:kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk";
    const MISSING: &str = "sha256:mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm";
    const SEQ: i64 = 4;
    const COVERS: i64 = 813;
    const AS_OF: i64 = 1_700_000_001_000;
    const BOUND_AT: i64 = 1_700_000_000_000;

    fn secret(last: u8) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[31] = last;
        out
    }

    fn obj(pairs: Vec<(&str, Value)>) -> Value {
        let mut out = Object::default();
        for (key, value) in pairs {
            assert!(out.insert(key.to_string(), value));
        }
        Value::Object(out)
    }

    struct Ready {
        trust: Value,
        bundle: String,
        broken: String,
        head: Value,
        keys: String,
        digest: String,
    }

    fn ready() -> Ready {
        let ledger = [9u8; 32];
        let event = event_bundle(&ledger, ENTITY, SEQ, SIGNING);
        let head = map_proof(&event.text, 5, Some(COVERS), None);
        let keys = canonical(&map_proof(
            &event.text,
            AS_OF,
            None,
            Some(key_value(KEY, BOUND_AT)),
        ));
        let broken = broken_inclusion(&event.text);
        Ready {
            trust: crate::receipt2_tests::trust_value(secret(2), secret(3), &ledger),
            bundle: event.text,
            broken,
            head,
            keys,
            digest: event.digest,
        }
    }

    fn run(ready: &Ready, bundle: &str, event: Option<&str>) -> Value {
        let event = match event {
            None => Value::Null,
            Some(event) => Value::from(event),
        };
        let input = obj(vec![
            ("op", Value::from("chain_check")),
            ("trust", ready.trust.clone()),
            (
                "chain",
                obj(vec![
                    ("entity_events", Value::Array(vec![Value::from(bundle)])),
                    ("head", ready.head.clone()),
                    ("handle_events", Value::Null),
                    ("keys", Value::from(ready.keys.as_str())),
                ]),
            ),
            (
                "expect",
                obj(vec![
                    ("entity", Value::from(ENTITY)),
                    ("handle", Value::Null),
                    ("event", event),
                ]),
            ),
        ]);
        parse(crate::run(canonical(&input).as_bytes()).as_slice()).unwrap()
    }

    fn integer(v: Option<&Value>) -> Option<i64> {
        v.and_then(Value::as_number)
            .and_then(crate::json::Number::as_safe_integer)
    }

    #[test]
    fn chain_check_verifies() {
        let ready = ready();
        let answer = run(&ready, &ready.bundle, Some(&ready.digest));
        assert_eq!(answer.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(answer.get("handle"), Some(&Value::Null));
        assert_eq!(answer.get("last_seq"), Some(&Value::Null));
        assert_eq!(integer(answer.get("covers")), Some(COVERS));
        assert_eq!(integer(answer.get("as_of")), Some(AS_OF));
        let event = answer.get("event").and_then(Value::as_object).unwrap();
        assert_eq!(integer(event.get("seq")), Some(SEQ));
        assert_eq!(
            event.get("log").and_then(Value::as_str),
            Some("first-party.0")
        );
        assert_eq!(integer(event.get("index")), Some(0));
        assert_eq!(event.get("key").and_then(Value::as_str), Some(SIGNING));
        let keys = answer.get("keys").and_then(Value::as_array).unwrap();
        assert_eq!(keys.len(), 1);
        let key = keys.first().and_then(Value::as_object).unwrap();
        assert_eq!(key.get("key").and_then(Value::as_str), Some(KEY));
        assert_eq!(key.get("by").and_then(Value::as_str), Some("registration"));
        assert_eq!(key.get("method"), Some(&Value::Null));
        assert_eq!(key.get("rp"), Some(&Value::Null));
        assert_eq!(key.get("use").and_then(Value::as_str), Some("sign"));
        assert_eq!(integer(key.get("bound_at")), Some(BOUND_AT));
        assert_eq!(key.get("unbound_at"), Some(&Value::Null));
        assert_eq!(key.get("reason"), Some(&Value::Null));

        let unnamed = run(&ready, &ready.bundle, None);
        assert_eq!(unnamed.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(unnamed.get("event"), Some(&Value::Null));
    }

    #[test]
    fn chain_check_broken_bundle() {
        let ready = ready();
        let answer = run(&ready, &ready.broken, Some(&ready.digest));
        assert_eq!(answer.get("ok").and_then(Value::as_bool), Some(false));
        assert_eq!(
            answer.get("reason").and_then(Value::as_str),
            Some(Reason::EntityChain.as_str())
        );
    }

    #[test]
    fn chain_check_missing_event() {
        let ready = ready();
        let answer = run(&ready, &ready.bundle, Some(MISSING));
        assert_eq!(answer.get("ok").and_then(Value::as_bool), Some(false));
        assert_eq!(
            answer.get("reason").and_then(Value::as_str),
            Some(Reason::ChainEvent.as_str())
        );
    }
}

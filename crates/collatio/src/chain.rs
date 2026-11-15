//! Event chains (FORMATS.md §8): skeletons that link and commit, contents
//! that open the commitments, and snapshots of the state, all signed by a `state-attest` key.

use alloc::string::String;
use alloc::vec::Vec;

use sha2::{Digest as _, Sha256};

use crate::b64;
use crate::commit::{COMMIT_DOMAIN, to_hex};
use crate::digest::{DIGEST_PREFIX, digest_of, is_digest, is_type_id};
use crate::fields::{is_cell, is_uuid};
use crate::jcs::canonical;
use crate::json::{Number, Object, Value};
use crate::reason::Reason;
use crate::trust::{PublicKey, Trust};

pub const EVENT_1: &str = "event@1";
pub const EVENT_CONTENT_1: &str = "event.content@1";
pub const STATE_SNAPSHOT_1: &str = "state.snapshot@1";
pub const STATE_HEAD_1: &str = "state.head@1";
pub const EVENT_DOMAIN: &str = "clavis.event.v1";
pub const SLOT_STATE_ATTEST: &str = "state-attest";

const MAX_LEAVES: usize = 16;

fn has_exactly(o: &Object, keys: &[&str]) -> bool {
    o.len() == keys.len() && keys.iter().all(|k| o.get(k).is_some())
}

fn str_of<'a>(o: &'a Object, k: &str) -> Option<&'a str> {
    o.get(k)?.as_str()
}

fn uint(o: &Object, k: &str) -> Option<i64> {
    o.get(k)?
        .as_number()
        .and_then(Number::as_safe_integer)
        .filter(|n| *n >= 0)
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// An account ID (`<cell>.<32 bytes Base64URL>`) or an Org ID (`<cell>.<UUID>`).
pub fn is_actor(s: &str) -> bool {
    s.split_once('.').is_some_and(|(cell, id)| {
        is_cell(cell) && (is_uuid(id) || (id.len() == 43 && b64::decode_len(id, 32).is_some()))
    })
}

/// Checks `attest` (Ed25519 by a `state-attest` key over the document without `attest`).
fn attest_ok(trust: &Trust, o: &Object) -> bool {
    let Some(a) = o.get("attest").and_then(Value::as_object) else {
        return false;
    };
    let (Some(kid), Some(sig)) = (str_of(a, "kid"), str_of(a, "sig")) else {
        return false;
    };
    if !has_exactly(a, &["kid", "alg", "sig"]) || str_of(a, "alg") != Some("EdDSA") {
        return false;
    }
    let Some(PublicKey::Ed25519(x)) = trust.key(kid, SLOT_STATE_ATTEST) else {
        return false;
    };
    let (Some(raw), Ok(vk)) = (
        b64::decode_len(sig, 64),
        ed25519_dalek::VerifyingKey::from_bytes(x),
    ) else {
        return false;
    };
    let Ok(sig) = ed25519_dalek::Signature::from_slice(&raw) else {
        return false;
    };
    let signed = canonical(&Value::Object(o.without("attest")));
    vk.verify_strict(signed.as_bytes(), &sig).is_ok()
}

#[derive(Clone, Debug)]
pub struct Skeleton {
    pub actor: String,
    pub seq: i64,
    pub prev: Option<String>,
    pub commit: String,
    pub envelope: Option<String>,
    pub leaves: Vec<String>,
    /// `digestOf(skeleton without attest)`.
    pub digest: String,
}

pub fn parse_skeleton(v: &Value) -> Option<Skeleton> {
    let o = v.as_object()?;
    let keys = [
        "type", "actor", "seq", "prev", "commit", "envelope", "leaves", "attest",
    ];
    if !has_exactly(o, &keys) || str_of(o, "type")? != EVENT_1 {
        return None;
    }
    let actor = str_of(o, "actor").filter(|a| is_actor(a))?;
    let seq = uint(o, "seq").filter(|s| *s >= 1)?;
    let nullable_digest = |k: &str| -> Option<Option<String>> {
        match o.get(k)? {
            Value::Null => Some(None),
            d => Some(Some(String::from(d.as_str().filter(|d| is_digest(d))?))),
        }
    };
    let prev = nullable_digest("prev")?;
    let envelope = nullable_digest("envelope")?;
    if (seq == 1) != prev.is_none() {
        return None;
    }
    let commit = str_of(o, "commit").filter(|c| is_digest(c))?;
    let list = o.get("leaves")?.as_array()?;
    if list.len() > MAX_LEAVES {
        return None;
    }
    let mut leaves: Vec<String> = Vec::with_capacity(list.len());
    for l in list {
        let c = l.as_str().filter(|c| is_hex64(c))?;
        if leaves.iter().any(|x| x == c) {
            return None;
        }
        leaves.push(String::from(c));
    }
    Some(Skeleton {
        actor: String::from(actor),
        seq,
        prev,
        commit: String::from(commit),
        envelope,
        leaves,
        digest: digest_of(&Value::Object(o.without("attest"))),
    })
}

/// Opens a content `{ salt, change, at, payload, receipt }`: its commitment, change and time.
pub fn open_content(v: &Value) -> Option<(String, String, i64)> {
    let o = v.as_object()?;
    if !has_exactly(o, &["salt", "change", "at", "payload", "receipt"]) {
        return None;
    }
    let salt = str_of(o, "salt").filter(|s| s.len() == 43)?;
    let salt = b64::decode_len(salt, 32)?;
    let change = str_of(o, "change").filter(|c| is_type_id(c))?;
    let at = uint(o, "at")?;
    o.get("payload")?.as_object()?;
    match o.get("receipt")? {
        Value::Null | Value::String(_) => {}
        _ => return None,
    }
    let mut committed = o.without("salt");
    committed.insert(String::from("type"), Value::from(EVENT_CONTENT_1));
    let mut h = Sha256::new();
    h.update(EVENT_DOMAIN.as_bytes());
    h.update(&salt);
    h.update(canonical(&Value::Object(committed)).as_bytes());
    let mut commit = String::from(DIGEST_PREFIX);
    commit.push_str(&b64::encode(&h.finalize()));
    Some((commit, String::from(change), at))
}

/// The leaf `c` of a chain head: hex(SHA-256(`clavis.commit.v1` ‖ salt ‖ JCS({ type, seq, head }))).
pub fn head_commitment(salt_b64u: &str, seq: i64, head: &str) -> Option<String> {
    let salt = b64::decode_len(salt_b64u, 32)?;
    let raw = alloc::format!("{seq}");
    #[allow(clippy::cast_precision_loss)]
    let n = Value::Number(Number::from_parts(&raw, seq as f64));
    let mut o = Object::default();
    o.insert(String::from("type"), Value::from(STATE_HEAD_1));
    o.insert(String::from("seq"), n);
    o.insert(String::from("head"), Value::from(head));
    let mut h = Sha256::new();
    h.update(COMMIT_DOMAIN.as_bytes());
    h.update(&salt);
    h.update(canonical(&Value::Object(o)).as_bytes());
    Some(to_hex(&h.finalize()))
}

#[derive(Clone, Debug)]
pub struct Opened {
    pub seq: i64,
    pub change: String,
    pub at: i64,
}

#[derive(Clone, Debug)]
pub struct ChainOk {
    pub actor: String,
    pub first: i64,
    pub last: i64,
    pub head: String,
    pub opened: Vec<Opened>,
    pub snapshot: Option<i64>,
}

/// Checks consecutive skeletons, the contents given and a snapshot.
pub fn verify_chain(
    trust: &Trust,
    events: &[Value],
    from: Option<&str>,
    contents: &[(i64, Value)],
    snapshot: Option<&Value>,
) -> Result<ChainOk, Reason> {
    let mut skeletons: Vec<Skeleton> = Vec::with_capacity(events.len());
    for v in events {
        let s = parse_skeleton(v).ok_or(Reason::ChainShape)?;
        let o = v.as_object().ok_or(Reason::ChainShape)?;
        if !attest_ok(trust, o) {
            return Err(Reason::ChainAttest);
        }
        let linked = match skeletons.last() {
            None => s.prev.as_deref() == from,
            Some(p) => {
                if p.actor != s.actor {
                    return Err(Reason::ChainActor);
                }
                p.seq.checked_add(1) == Some(s.seq) && s.prev.as_deref() == Some(p.digest.as_str())
            }
        };
        if !linked {
            return Err(Reason::ChainLink);
        }
        skeletons.push(s);
    }
    let (Some(first), Some(last)) = (skeletons.first(), skeletons.last()) else {
        return Err(Reason::InputMalformed);
    };
    let at_seq = |seq: i64| skeletons.iter().find(|s| s.seq == seq);
    let mut opened = Vec::with_capacity(contents.len());
    for (seq, content) in contents {
        let skeleton = at_seq(*seq).ok_or(Reason::ChainContentSeq)?;
        let (commit, change, at) = open_content(content).ok_or(Reason::ChainContentShape)?;
        if commit != skeleton.commit {
            return Err(Reason::ChainContentCommit);
        }
        opened.push(Opened {
            seq: *seq,
            change,
            at,
        });
    }
    let snapshot = match snapshot {
        None => None,
        Some(v) => {
            let o = v.as_object().ok_or(Reason::ChainSnapshotShape)?;
            let keys = ["type", "actor", "seq", "head", "state", "attest"];
            let (Some(seq), Some(head)) = (uint(o, "seq"), str_of(o, "head")) else {
                return Err(Reason::ChainSnapshotShape);
            };
            if !has_exactly(o, &keys)
                || str_of(o, "type") != Some(STATE_SNAPSHOT_1)
                || str_of(o, "actor") != Some(first.actor.as_str())
                || o.get("state").and_then(Value::as_object).is_none()
            {
                return Err(Reason::ChainSnapshotShape);
            }
            if at_seq(seq).is_none_or(|s| s.digest != head) {
                return Err(Reason::ChainSnapshotHead);
            }
            if !attest_ok(trust, o) {
                return Err(Reason::ChainAttest);
            }
            Some(seq)
        }
    };
    Ok(ChainOk {
        actor: first.actor.clone(),
        first: first.seq,
        last: last.seq,
        head: last.digest.clone(),
        opened,
        snapshot,
    })
}

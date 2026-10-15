//! The ledger evidence bundle `ledger.bundle@1` (FORMATS.md §9): a leaf, its receipt, the
//! checkpoint that includes it, optionally the opening, and optionally the anchor with TSA tokens.

use alloc::string::String;
use alloc::vec::Vec;

use base64ct::{Base64, Encoding};

use crate::commit::{commitment, to_hex};
use crate::digest::sha256;
use crate::fields::is_org;
use crate::json::{Number, Object, Value};
use crate::ledger::leaf::{Leaf, parse_leaf};
use crate::ledger::merkle::{Hash, verify_inclusion};
use crate::logs::{Body, verify_log_note_with_body};
use crate::reason::Reason;
use crate::trust::{Trust, first_party_shard};
use crate::tsa::{TsaTrust, verify_time_stamp_token};
use crate::tsa_registry::REGISTRY;

pub const LEDGER_BUNDLE_1: &str = "ledger.bundle@1";
const MAX_PROOF: usize = 64;
const MAX_TSA: usize = 8;

fn has_members(o: &Object, required: &[&str], optional: &[&str]) -> bool {
    required.iter().all(|k| o.get(k).is_some())
        && o.keys()
            .all(|k| required.contains(&k) || optional.contains(&k))
}

fn index_of(o: &Object) -> Option<u64> {
    o.get("index")?
        .as_number()
        .and_then(Number::as_safe_integer)
        .and_then(|n| u64::try_from(n).ok())
}

fn proof(v: Option<&Value>) -> Option<Vec<Hash>> {
    let list = v?.as_array()?;
    if list.len() > MAX_PROOF {
        return None;
    }
    list.iter()
        .map(|h| {
            Base64::decode_vec(h.as_str()?)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        })
        .collect()
}

/// `<host>/ledger/<log>` → the host.
fn host_of<'a>(origin: &'a str, log: &str) -> Option<&'a str> {
    origin.strip_suffix(log)?.strip_suffix("/ledger/")
}

#[derive(Clone, Debug)]
pub struct Anchored {
    pub anchored_by: u64,
    pub tsa: usize,
}

#[derive(Clone, Debug)]
pub struct BundleOk {
    pub log: String,
    pub index: u64,
    pub committed_by: u64,
    pub opening: bool,
    pub anchor: Option<Anchored>,
}

fn tsa_count(tokens: &[Value], message: &[u8]) -> Option<usize> {
    let roots: Vec<Vec<Vec<u8>>> = REGISTRY
        .iter()
        .map(|e| {
            e.roots
                .iter()
                .filter_map(|r| Base64::decode_vec(r).ok())
                .collect()
        })
        .collect();
    let root_refs: Vec<Vec<&[u8]>> = roots
        .iter()
        .map(|rs| rs.iter().map(Vec::as_slice).collect())
        .collect();
    let trust: Vec<TsaTrust<'_>> = REGISTRY
        .iter()
        .zip(root_refs.iter())
        .map(|(e, rs)| TsaTrust {
            id: e.id,
            policies: e.policies,
            roots: rs.as_slice(),
        })
        .collect();
    let mut good = 0usize;
    for t in tokens {
        let o = t.as_object()?;
        if !has_members(o, &["response"], &["url"])
            || o.get("url").is_some_and(|u| u.as_str().is_none())
        {
            return None;
        }
        let der = Base64::decode_vec(o.get("response")?.as_str()?).ok()?;
        if verify_time_stamp_token(&der, message, None, &trust).is_ok() {
            good = good.saturating_add(1);
        }
    }
    Some(good)
}

pub fn verify_bundle(trust: &Trust, v: &Value) -> Result<BundleOk, Reason> {
    let shape = Reason::BundleShape;
    let o = v.as_object().ok_or(shape)?;
    let required = [
        "type",
        "log",
        "leaf",
        "index",
        "receipt",
        "checkpoint",
        "inclusion",
    ];
    if !has_members(o, &required, &["opening", "anchor"])
        || o.get("type").and_then(Value::as_str) != Some(LEDGER_BUNDLE_1)
    {
        return Err(shape);
    }
    let log = o.get("log").and_then(Value::as_str).ok_or(shape)?;
    if first_party_shard(log).is_none() && !is_org(log) {
        return Err(Reason::BundleLog);
    }
    let leaf: Leaf = parse_leaf(o.get("leaf").ok_or(shape)?).ok_or(shape)?;
    let index = index_of(o).ok_or(shape)?;
    let path = proof(o.get("inclusion")).ok_or(shape)?;
    let note = |k: &str| o.get(k).and_then(Value::as_str).ok_or(shape);

    let (receipt, _) = verify_log_note_with_body(trust, note("receipt")?)?;
    let Body::Receipt(r) = receipt.body else {
        return Err(shape);
    };
    let (checkpoint, cp_body) = verify_log_note_with_body(trust, note("checkpoint")?)?;
    let Body::Checkpoint(cp) = checkpoint.body else {
        return Err(shape);
    };
    if receipt.log != log || checkpoint.log != log || r.origin != cp.origin {
        return Err(Reason::BundleLog);
    }
    if r.index != index || r.leaf_hash != leaf.hash() {
        return Err(Reason::BundleReceipt);
    }
    if !verify_inclusion(index, cp.size, &leaf.hash(), &path, &cp.root) {
        return Err(Reason::BundleInclusion);
    }

    let opening = match o.get("opening") {
        None => false,
        Some(op) => {
            let op = op.as_object().ok_or(shape)?;
            let (Some(salt), Some(record)) =
                (op.get("salt").and_then(Value::as_str), op.get("record"))
            else {
                return Err(shape);
            };
            if !has_members(op, &["salt", "record"], &[])
                || commitment(salt, record).as_deref() != Some(leaf.c.as_str())
            {
                return Err(Reason::BundleOpening);
            }
            true
        }
    };

    let anchor = match o.get("anchor") {
        None => None,
        Some(a) => {
            let a = a.as_object().ok_or(shape)?;
            if !has_members(a, &["index", "checkpoint", "inclusion", "tsa"], &[]) {
                return Err(shape);
            }
            let a_index = index_of(a).ok_or(shape)?;
            let a_path = proof(a.get("inclusion")).ok_or(shape)?;
            let tokens = a
                .get("tsa")
                .and_then(Value::as_array)
                .filter(|t| t.len() <= MAX_TSA)
                .ok_or(shape)?;
            let a_note = a.get("checkpoint").and_then(Value::as_str).ok_or(shape)?;
            let (anchor_cp, a_body) = verify_log_note_with_body(trust, a_note)?;
            let Body::Checkpoint(acp) = anchor_cp.body else {
                return Err(shape);
            };
            if anchor_cp.log != "anchor"
                || host_of(&acp.origin, "anchor") != host_of(&cp.origin, log)
            {
                return Err(Reason::BundleAnchor);
            }
            let anchor_leaf = Leaf {
                c: to_hex(&sha256(cp_body.as_bytes())),
                slot: None,
            };
            if !verify_inclusion(a_index, acp.size, &anchor_leaf.hash(), &a_path, &acp.root) {
                return Err(Reason::BundleAnchor);
            }
            let tsa = tsa_count(tokens, a_body.as_bytes()).ok_or(shape)?;
            Some(Anchored {
                anchored_by: acp.time,
                tsa,
            })
        }
    };
    Ok(BundleOk {
        log: String::from(log),
        index,
        committed_by: cp.time,
        opening,
        anchor,
    })
}

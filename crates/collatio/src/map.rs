//! Verifiable maps (FORMATS.md §10).
//!
//! A map is a prefix tree over 256-bit keys. A subtree without keys is empty, a subtree with one
//! key is that key's leaf (at any depth), and a subtree with two or more is a node split on the
//! next bit. The keys alone decide the shape, so a root binds one answer per key. A Clavis writer
//! keeps one map, commits each of its roots (`map.root@1`) to its organisation's log through a
//! `map.heads@1` leaf, and answers a question with a path from such a root.

use alloc::string::String;
use alloc::vec::Vec;

use base64ct::{Base64, Encoding};
use sha2::{Digest as _, Sha256};

use crate::bundle::verify_bundle;
use crate::commit::is_hex64;
use crate::digest::{digest_of, is_digest};
use crate::fields::{is_app, is_org};
use crate::jcs::canonical;
use crate::json::{Number, Object, Value};
use crate::keylog::is_id;
use crate::reason::Reason;
use crate::trust::{Trust, document};

pub const MAP_PATH_1: &str = "map.path@1";
pub const MAP_ROOT_1: &str = "map.root@1";
pub const MAP_HEADS_1: &str = "map.heads@1";
pub const MAP_PROOF_1: &str = "map.proof@1";
pub const MAP_LEAF_1: &str = "map.leaf@1";
pub const AGREEMENT_SERIES_1: &str = "agreement.series@1";
pub const AGREEMENT_REFUSALS_1: &str = "agreement.refusals@1";

const KEY_SERIES: &str = "agreement.series.key@1";
const KEY_REFUSALS: &str = "agreement.refusals.key@1";

/// Keys have 256 bits, so no path is longer.
pub const MAX_DEPTH: usize = 256;
/// The most roots one `map.heads@1` leaf lists.
const MAX_HEADS_ROOTS: usize = 1000;
/// The most children `map_combine` folds at once.
const MAX_CHILDREN: usize = 256;
/// An organisation's agreement writers (`agreements/0` to `agreements/15`). A person's decisions
/// stay in one writer.
const AGREEMENT_SHARDS: u32 = 16;
/// A consent thread stays at least this long after they close before retention may
/// remove them. The readings rely on it.
pub const RETENTION_FLOOR_MS: i64 = 730 * 86_400_000;

pub type Hash = [u8; 32];

fn sha(parts: &[&[u8]]) -> Hash {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// E = SHA-256("clavis.map.empty.v1")
pub fn empty() -> Hash {
    sha(&[b"clavis.map.empty.v1"])
}

/// vh = SHA-256("clavis.map.value.v1" ‖ 0x00 ‖ JCS(value))
pub fn value_hash(value: &Value) -> Hash {
    sha(&[b"clavis.map.value.v1", &[0], canonical(value).as_bytes()])
}

/// SHA-256("clavis.map.leaf.v1" ‖ 0x00 ‖ key ‖ vh)
pub fn leaf_hash(key: &Hash, vh: &Hash) -> Hash {
    sha(&[b"clavis.map.leaf.v1", &[0], key, vh])
}

/// SHA-256("clavis.map.node.v1" ‖ 0x00 ‖ left ‖ right)
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    sha(&[b"clavis.map.node.v1", &[0], left, right])
}

/// key = SHA-256("clavis.map.key.v1" ‖ 0x00 ‖ JCS(id))
pub fn key_of(id: &Value) -> Hash {
    sha(&[b"clavis.map.key.v1", &[0], canonical(id).as_bytes()])
}

/// Bit `i` of a key, reading from the most significant bit of the first byte.
fn bit(key: &Hash, i: usize) -> bool {
    let Some(byte) = i.checked_shr(3).and_then(|j| key.get(j)) else {
        return false;
    };
    let shift = u32::try_from(i & 7).unwrap_or(0);
    0x80u8.checked_shr(shift).is_some_and(|m| byte & m != 0)
}

/// The organisation writer that holds a person's agreement decisions.
pub fn agreement_shard(subject: &str) -> u32 {
    let d = sha(&[b"clavis.lex.org.v1\0", subject.as_bytes()]);
    let head: [u8; 4] = d
        .get(..4)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .unwrap_or([0; 4]);
    u32::from_be_bytes(head) % AGREEMENT_SHARDS
}

fn has_members(o: &Object, required: &[&str], optional: &[&str]) -> bool {
    required.iter().all(|k| o.get(k).is_some())
        && o.keys()
            .all(|k| required.contains(&k) || optional.contains(&k))
}

fn text<'a>(o: &'a Object, k: &str) -> Option<&'a str> {
    o.get(k).and_then(Value::as_str)
}

fn safe(v: Option<&Value>) -> Option<i64> {
    v?.as_number().and_then(Number::as_safe_integer)
}

/// A safe integer at least `min`.
fn at_least(v: Option<&Value>, min: i64) -> Option<i64> {
    safe(v).filter(|n| *n >= min)
}

fn hash_b64(v: Option<&Value>) -> Option<Hash> {
    Base64::decode_vec(v?.as_str()?)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
}

pub fn b64(hash: &Hash) -> String {
    Base64::encode_string(hash)
}

fn nullable_digest(v: Option<&Value>) -> Option<Option<String>> {
    match v? {
        Value::Null => Some(None),
        Value::String(s) if is_digest(s) => Some(Some(s.clone())),
        _ => None,
    }
}

// ---------------------------------------------------------------- keys

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdKind {
    Series,
    Refusals,
}

/// A key's source (`id`), the log it belongs to, the map that holds it and the key itself.
#[derive(Clone, Debug)]
pub struct MapId {
    pub kind: IdKind,
    pub doc: Value,
    pub log: String,
    pub map: String,
    pub key: Hash,
}

pub fn parse_id(v: &Value) -> Option<MapId> {
    let o = v.as_object()?;
    let (kind, log, map) = match text(o, "type")? {
        t @ (KEY_SERIES | KEY_REFUSALS) => {
            if !has_members(o, &["type", "org", "subject", "app", "situation"], &[]) {
                return None;
            }
            let org = text(o, "org").filter(|s| is_org(s))?;
            let subject = text(o, "subject").filter(|s| is_id(s, 200))?;
            text(o, "app").filter(|s| is_app(s))?;
            text(o, "situation").filter(|s| is_id(s, 64))?;
            let kind = if t == KEY_SERIES {
                IdKind::Series
            } else {
                IdKind::Refusals
            };
            (
                kind,
                org,
                alloc::format!("agreements/{}", agreement_shard(subject)),
            )
        }
        _ => return None,
    };
    Some(MapId {
        kind,
        doc: v.clone(),
        log: String::from(log),
        map,
        key: key_of(v),
    })
}

fn is_map_name(s: &str) -> bool {
    s == "mandate"
        || s == "slots"
        || s.strip_prefix("agreements/").is_some_and(|n| {
            !n.is_empty()
                && n.len() <= 2
                && n.bytes().all(|b| b.is_ascii_digit())
                && !(n.len() == 2 && n.starts_with('0'))
                && n.parse::<u32>().is_ok_and(|v| v < AGREEMENT_SHARDS)
        })
}

// ---------------------------------------------------------------- paths

#[derive(Clone, Debug)]
pub enum End {
    Empty,
    Leaf { key: Hash, vh: Hash },
}

#[derive(Clone, Debug)]
pub struct Path {
    /// From the root's children down to the level above the end.
    pub siblings: Vec<Hash>,
    pub end: End,
}

pub fn parse_path(v: &Value) -> Option<Path> {
    let o = v.as_object()?;
    if !has_members(o, &["type", "siblings", "end"], &[]) || text(o, "type")? != MAP_PATH_1 {
        return None;
    }
    let list = o.get("siblings")?.as_array()?;
    if list.len() > MAX_DEPTH {
        return None;
    }
    let siblings = list
        .iter()
        .map(|s| hash_b64(Some(s)))
        .collect::<Option<Vec<_>>>()?;
    let e = o.get("end")?.as_object()?;
    let end = match text(e, "kind")? {
        "empty" if has_members(e, &["kind"], &[]) => End::Empty,
        "leaf" if has_members(e, &["kind", "key", "value"], &[]) => End::Leaf {
            key: hash_b64(e.get("key"))?,
            vh: hash_b64(e.get("value"))?,
        },
        _ => return None,
    };
    Some(Path { siblings, end })
}

/// What a path says about a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Found {
    Present(Hash),
    Absent,
}

/// The root a path folds to for `key`, and what it says about the key. `None` when the path cannot
/// belong to the key (its end is another key's leaf off the key's prefix).
pub fn fold(key: &Hash, path: &Path) -> Option<(Hash, Found)> {
    let depth = path.siblings.len();
    let (mut acc, found) = match &path.end {
        End::Empty => (empty(), Found::Absent),
        End::Leaf { key: other, vh } => {
            if other == key {
                (leaf_hash(other, vh), Found::Present(*vh))
            } else if (0..depth).all(|i| bit(other, i) == bit(key, i)) {
                (leaf_hash(other, vh), Found::Absent)
            } else {
                return None;
            }
        }
    };
    for (i, sibling) in path.siblings.iter().enumerate().rev() {
        acc = if bit(key, i) {
            node_hash(sibling, &acc)
        } else {
            node_hash(&acc, sibling)
        };
    }
    Some((acc, found))
}

// ---------------------------------------------------------------- subtrees

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubKind {
    Empty,
    Leaf,
    Node,
}

impl SubKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SubKind::Empty => "empty",
            SubKind::Leaf => "leaf",
            SubKind::Node => "node",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sub {
    pub kind: SubKind,
    pub hash: Hash,
    pub count: u64,
}

fn empty_sub() -> Sub {
    Sub {
        kind: SubKind::Empty,
        hash: empty(),
        count: 0,
    }
}

/// The canonical parent of two sibling subtrees: one key collapses upward, two or more make a node.
pub fn combine2(left: &Sub, right: &Sub) -> Sub {
    match (left.kind, right.kind) {
        (SubKind::Empty, SubKind::Empty) => empty_sub(),
        (SubKind::Empty, SubKind::Leaf) => *right,
        (SubKind::Leaf, SubKind::Empty) => *left,
        _ => Sub {
            kind: SubKind::Node,
            hash: node_hash(&left.hash, &right.hash),
            count: left.count.saturating_add(right.count),
        },
    }
}

/// The canonical subtree of `leaves` (keys strictly increasing, all sharing the first `depth` bits).
pub fn build(leaves: &[(Hash, Hash)], depth: usize) -> Sub {
    match leaves {
        [] => empty_sub(),
        [(key, vh)] => Sub {
            kind: SubKind::Leaf,
            hash: leaf_hash(key, vh),
            count: 1,
        },
        _ if depth >= MAX_DEPTH => empty_sub(),
        _ => {
            let split = leaves.partition_point(|(k, _)| !bit(k, depth));
            let (left, right) = leaves.split_at(split);
            let next = depth.saturating_add(1);
            combine2(&build(left, next), &build(right, next))
        }
    }
}

/// `{ kind, hash, count }`, as `map_subtree` and `map_combine` answer them.
pub fn parse_sub(v: &Value) -> Option<Sub> {
    let o = v.as_object()?;
    if !has_members(o, &["kind", "hash", "count"], &[]) {
        return None;
    }
    let count = u64::try_from(at_least(o.get("count"), 0)?).ok()?;
    let hash = hash_b64(o.get("hash"))?;
    let kind = match (text(o, "kind")?, count) {
        ("empty", 0) if hash == empty() => SubKind::Empty,
        ("leaf", 1) => SubKind::Leaf,
        ("node", n) if n >= 2 => SubKind::Node,
        _ => return None,
    };
    Some(Sub { kind, hash, count })
}

/// Folds 2, 4, … or 256 sibling subtrees, in key order, into their common parent.
pub fn combine(children: &[Value]) -> Result<Sub, Reason> {
    let bad = Reason::MapChildren;
    if children.len() < 2 || children.len() > MAX_CHILDREN || !children.len().is_power_of_two() {
        return Err(bad);
    }
    let mut level: Vec<Sub> = children
        .iter()
        .map(|c| parse_sub(c).ok_or(bad))
        .collect::<Result<_, _>>()?;
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| match pair {
                [a, b] => Ok(combine2(a, b)),
                _ => Err(bad),
            })
            .collect::<Result<_, _>>()?;
    }
    level.first().copied().ok_or(bad)
}

/// A prefix written as `0` and `1` characters.
fn parse_prefix(s: &str) -> Option<Vec<bool>> {
    if s.len() > MAX_DEPTH {
        return None;
    }
    s.bytes()
        .map(|b| match b {
            b'0' => Some(false),
            b'1' => Some(true),
            _ => None,
        })
        .collect()
}

/// One verified `map.leaf@1`: the key's source, its value and the index contents.
#[derive(Clone, Debug)]
pub struct LeafDoc {
    pub id: Value,
    pub value: Value,
    pub index: Option<Value>,
    pub key: Hash,
    pub vh: Hash,
}

pub struct SubtreeOk {
    pub sub: Sub,
    pub owner: Option<(String, String)>,
    pub leaves: Vec<LeafDoc>,
}

fn parse_leaf_doc(v: &Value) -> Result<(MapId, LeafDoc), Reason> {
    let o = v.as_object().ok_or(Reason::MapLeaves)?;
    if !has_members(o, &["type", "id", "value"], &["index"]) || text(o, "type") != Some(MAP_LEAF_1)
    {
        return Err(Reason::MapLeaves);
    }
    let id = parse_id(o.get("id").ok_or(Reason::MapLeaves)?).ok_or(Reason::MapId)?;
    let value = o.get("value").ok_or(Reason::MapLeaves)?;
    check_value(&id, value)?;
    let index = o.get("index");
    check_index(&id, value, index)?;
    let vh = value_hash(value);
    Ok((
        id.clone(),
        LeafDoc {
            id: id.doc.clone(),
            value: value.clone(),
            index: index.cloned(),
            key: id.key,
            vh,
        },
    ))
}

/// The entries of an agreement value with an index digest must each have the index contents in the
/// leaf, and nothing else may be there. Other values carry no index.
fn check_index(id: &MapId, value: &Value, index: Option<&Value>) -> Result<(), Reason> {
    let bad = Reason::MapLeaves;
    let entries = agreement_entries(id.kind, value);
    let with_index: Vec<(&str, &str)> = entries
        .iter()
        .filter_map(|e| Some((text(e, "decision")?, text(e, "index")?)))
        .collect();
    match index {
        None if with_index.is_empty() => Ok(()),
        None => Err(bad),
        Some(v) => {
            let o = v.as_object().ok_or(bad)?;
            if o.len() != with_index.len() {
                return Err(bad);
            }
            for (decision, digest) in with_index {
                let contents = o
                    .get(decision)
                    .filter(|c| c.as_object().is_some())
                    .ok_or(bad)?;
                if digest_of(contents) != digest {
                    return Err(bad);
                }
            }
            Ok(())
        }
    }
}

fn agreement_entries(kind: IdKind, value: &Value) -> Vec<&Object> {
    match kind {
        IdKind::Series => value
            .get("threads")
            .and_then(Value::as_array)
            .unwrap_or(&[])
            .iter()
            .filter_map(|t| t.get("decisions").and_then(Value::as_array))
            .flatten()
            .filter_map(Value::as_object)
            .collect(),
        IdKind::Refusals => value
            .get("decisions")
            .and_then(Value::as_array)
            .unwrap_or(&[])
            .iter()
            .filter_map(Value::as_object)
            .collect(),
    }
}

/// Verifies one prefix's leaves and builds its canonical subtree (`map_subtree`).
pub fn verify_subtree(prefix: &str, leaves: &[Value]) -> Result<SubtreeOk, Reason> {
    let bits = parse_prefix(prefix).ok_or(Reason::InputMalformed)?;
    let mut docs: Vec<LeafDoc> = Vec::with_capacity(leaves.len());
    let mut owner: Option<(String, String)> = None;
    for raw in leaves {
        let (id, doc) = parse_leaf_doc(&document(Some(raw))?)?;
        if bits.iter().enumerate().any(|(i, b)| bit(&doc.key, i) != *b) {
            return Err(Reason::MapLeaves);
        }
        match &owner {
            None => owner = Some((id.log, id.map)),
            Some((log, map)) if *log == id.log && *map == id.map => {}
            Some(_) => return Err(Reason::MapLeaves),
        }
        if docs.last().is_some_and(|last| last.key >= doc.key) {
            return Err(Reason::MapLeaves);
        }
        docs.push(doc);
    }
    let pairs: Vec<(Hash, Hash)> = docs.iter().map(|d| (d.key, d.vh)).collect();
    Ok(SubtreeOk {
        sub: build(&pairs, bits.len()),
        owner,
        leaves: docs,
    })
}

// ---------------------------------------------------------------- values

/// Times in values are Unix milliseconds.
fn time(v: Option<&Value>) -> Option<i64> {
    at_least(v, 0)
}

#[derive(Clone, Debug)]
pub struct Entry {
    pub decision: String,
    pub action: String,
    pub effective_at: i64,
    pub raw: Object,
}

fn parse_entry(v: &Value, actions: &[&str]) -> Option<Entry> {
    let o = v.as_object()?;
    let members = [
        "decision",
        "action",
        "outcome",
        "decided_at",
        "effective_at",
        "leaf",
        "c",
        "index",
        "index_v",
    ];
    if !has_members(o, &members, &[]) {
        return None;
    }
    let decision = text(o, "decision").filter(|s| is_id(s, 200))?;
    let action = text(o, "action").filter(|s| actions.contains(s))?;
    text(o, "outcome").filter(|s| is_id(s, 64))?;
    time(o.get("decided_at"))?;
    let effective_at = time(o.get("effective_at"))?;
    match o.get("leaf")? {
        Value::Null => {}
        v => {
            at_least(Some(v), 0)?;
        }
    }
    match o.get("c")? {
        Value::Null => {}
        Value::String(s) if is_hex64(s) => {}
        _ => return None,
    }
    let index = nullable_digest(o.get("index"))?;
    let index_v = match o.get("index_v")? {
        Value::Null => None,
        v => Some(at_least(Some(v), 1)?),
    };
    if index.is_some() != index_v.is_some() {
        return None;
    }
    Some(Entry {
        decision: String::from(decision),
        action: String::from(action),
        effective_at,
        raw: o.clone(),
    })
}

/// Entries in order of `effective_at`, strictly (the writer's clock never repeats).
fn parse_entries(v: Option<&Value>, actions: &[&str]) -> Option<Vec<Entry>> {
    let list = v?.as_array()?;
    let entries = list
        .iter()
        .map(|e| parse_entry(e, actions))
        .collect::<Option<Vec<_>>>()?;
    let ordered = entries
        .windows(2)
        .all(|w| matches!(w, [a, b] if a.effective_at < b.effective_at));
    ordered.then_some(entries)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Closed {
    Decision { at: i64, decision: String },
    Account { at: i64 },
}

impl Closed {
    fn at(&self) -> i64 {
        match self {
            Closed::Decision { at, .. } | Closed::Account { at } => *at,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Thread {
    pub thread: String,
    pub opened_at: i64,
    pub closed: Option<Closed>,
    pub decisions: Vec<Entry>,
}

#[derive(Clone, Debug)]
pub struct Series {
    pub threads: Vec<Thread>,
    pub dropped: i64,
}

fn same_identity(o: &Object, id: &MapId) -> bool {
    ["org", "subject", "app", "situation"]
        .iter()
        .all(|k| o.get(k).is_some() && o.get(k) == id.doc.get(k))
}

fn parse_closed(v: &Value) -> Option<Option<Closed>> {
    match v {
        Value::Null => Some(None),
        Value::Object(o) => {
            let at = time(o.get("at"))?;
            match text(o, "by")? {
                "decision" if has_members(o, &["at", "by", "decision"], &[]) => {
                    let decision = text(o, "decision").filter(|s| is_id(s, 200))?;
                    Some(Some(Closed::Decision {
                        at,
                        decision: String::from(decision),
                    }))
                }
                "account" if has_members(o, &["at", "by"], &[]) => {
                    Some(Some(Closed::Account { at }))
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn parse_thread(v: &Value) -> Option<Thread> {
    let o = v.as_object()?;
    if !has_members(o, &["thread", "opened_at", "closed", "decisions"], &[]) {
        return None;
    }
    let thread = text(o, "thread").filter(|s| is_id(s, 200))?;
    let opened_at = time(o.get("opened_at"))?;
    let closed = parse_closed(o.get("closed")?)?;
    let decisions = parse_entries(o.get("decisions"), &["grant", "withdraw"])?;
    let first = decisions.first()?;
    if first.effective_at != opened_at || first.action != "grant" {
        return None;
    }
    // Only the decision that closes a thread withdraws, and it is the last one.
    let withdrawals = decisions.iter().filter(|e| e.action == "withdraw").count();
    match &closed {
        None if withdrawals == 0 => {}
        Some(Closed::Account { at })
            if withdrawals == 0 && *at > decisions.last()?.effective_at => {}
        Some(Closed::Decision { at, decision }) => {
            let last = decisions.last()?;
            if withdrawals != 1
                || last.action != "withdraw"
                || last.decision != *decision
                || last.effective_at != *at
            {
                return None;
            }
        }
        _ => return None,
    }
    Some(Thread {
        thread: String::from(thread),
        opened_at,
        closed,
        decisions,
    })
}

pub fn parse_series(v: &Value, id: &MapId) -> Option<Series> {
    let o = v.as_object()?;
    let members = [
        "type",
        "org",
        "subject",
        "app",
        "situation",
        "threads",
        "dropped",
    ];
    if !has_members(o, &members, &[])
        || text(o, "type")? != AGREEMENT_SERIES_1
        || !same_identity(o, id)
    {
        return None;
    }
    let threads = o
        .get("threads")?
        .as_array()?
        .iter()
        .map(parse_thread)
        .collect::<Option<Vec<_>>>()?;
    // In order, without overlap: every thread but the last is closed before the next opens.
    let ordered = threads.windows(2).all(|w| match w {
        [a, b] => a.closed.as_ref().is_some_and(|c| c.at() < b.opened_at),
        _ => false,
    });
    let dropped = at_least(o.get("dropped"), 0)?;
    (ordered && (!threads.is_empty() || dropped > 0)).then_some(Series { threads, dropped })
}

pub struct Refusals {
    pub decisions: Vec<Entry>,
    pub dropped: i64,
}

pub fn parse_refusals(v: &Value, id: &MapId) -> Option<Refusals> {
    let o = v.as_object()?;
    let members = [
        "type",
        "org",
        "subject",
        "app",
        "situation",
        "decisions",
        "dropped",
    ];
    if !has_members(o, &members, &[])
        || text(o, "type")? != AGREEMENT_REFUSALS_1
        || !same_identity(o, id)
    {
        return None;
    }
    let decisions = parse_entries(o.get("decisions"), &["deny", "abort", "withdraw"])?;
    let dropped = at_least(o.get("dropped"), 0)?;
    (!decisions.is_empty() || dropped > 0).then_some(Refusals { decisions, dropped })
}

fn check_value(id: &MapId, value: &Value) -> Result<(), Reason> {
    let ok = match id.kind {
        IdKind::Series => parse_series(value, id).is_some(),
        IdKind::Refusals => parse_refusals(value, id).is_some(),
    };
    if ok {
        Ok(())
    } else {
        Err(Reason::MapValueShape)
    }
}

// ---------------------------------------------------------------- roots and heads

#[derive(Clone, Debug)]
pub struct Root {
    pub doc: Value,
    pub digest: String,
    pub map: String,
    pub seq: i64,
    pub prev: Option<String>,
    pub root: Hash,
    pub as_of: i64,
    pub erased_total: i64,
    pub swept_total: i64,
    pub restored: Option<i64>,
}

pub fn parse_root(v: &Value) -> Option<Root> {
    let o = v.as_object()?;
    let required = [
        "type",
        "map",
        "seq",
        "prev",
        "root",
        "as_of",
        "erased_total",
        "swept_total",
    ];
    if !has_members(o, &required, &["restored"]) || text(o, "type")? != MAP_ROOT_1 {
        return None;
    }
    let map = text(o, "map").filter(|s| s.starts_with("agreements/") && is_map_name(s))?;
    let seq = at_least(o.get("seq"), 1)?;
    let prev = nullable_digest(o.get("prev"))?;
    // Only the first root has no previous root.
    if prev.is_none() != (seq == 1) {
        return None;
    }
    let restored = match o.get("restored") {
        None => None,
        Some(v) => Some(at_least(Some(v), 1).filter(|r| *r < seq)?),
    };
    Some(Root {
        doc: v.clone(),
        digest: digest_of(v),
        map: String::from(map),
        seq,
        prev,
        root: hash_b64(o.get("root"))?,
        as_of: time(o.get("as_of"))?,
        erased_total: at_least(o.get("erased_total"), 0)?,
        swept_total: at_least(o.get("swept_total"), 0)?,
        restored,
    })
}

#[derive(Clone, Debug)]
pub struct HeadsEntry {
    pub map: String,
    pub seq: i64,
    pub digest: String,
}

#[derive(Clone, Debug)]
pub struct Heads {
    pub log: String,
    pub seq: i64,
    pub roots: Vec<HeadsEntry>,
}

pub fn parse_heads(v: &Value) -> Option<Heads> {
    let o = v.as_object()?;
    if !has_members(o, &["type", "log", "seq", "prev", "roots"], &[])
        || text(o, "type")? != MAP_HEADS_1
    {
        return None;
    }
    let log = text(o, "log").filter(|s| is_org(s))?;
    let seq = at_least(o.get("seq"), 1)?;
    let prev = nullable_digest(o.get("prev"))?;
    if prev.is_none() != (seq == 1) {
        return None;
    }
    let list = o.get("roots")?.as_array()?;
    if list.is_empty() || list.len() > MAX_HEADS_ROOTS {
        return None;
    }
    let roots = list
        .iter()
        .map(|r| {
            let r = r.as_object()?;
            if !has_members(r, &["map", "seq", "digest"], &[]) {
                return None;
            }
            Some(HeadsEntry {
                map: String::from(text(r, "map").filter(|s| is_map_name(s))?),
                seq: at_least(r.get("seq"), 1)?,
                digest: String::from(text(r, "digest").filter(|s| is_digest(s))?),
            })
        })
        .collect::<Option<Vec<_>>>()?;
    // In (map, seq) order, each map's roots consecutive.
    let ordered = roots.windows(2).all(|w| match w {
        [a, b] => a.map < b.map || (a.map == b.map && b.seq == a.seq.saturating_add(1)),
        _ => false,
    });
    ordered.then(|| Heads {
        log: String::from(log),
        seq,
        roots,
    })
}

// ---------------------------------------------------------------- proofs

/// One root of a proof, verified: the heads leaf is in the organisation's log and lists the root.
#[derive(Clone, Debug)]
pub struct Side {
    /// The organisation's log.
    pub log: String,
    pub root: Root,
    pub committed_by: u64,
    pub anchored_by: Option<u64>,
    pub found: Option<(Found, Option<Value>)>,
}

/// The `heads` and `root` of a side: the bundle with its opening, a heads record of the bundle's
/// log that lists the root under its map and `seq`, and the root dated no later than the
/// checkpoint allows. With `id`, the log and the map must also be the key's.
fn verify_listed(trust: &Trust, o: &Object, id: Option<&MapId>) -> Result<Side, Reason> {
    let bundle = document(o.get("heads"))?;
    let ok = verify_bundle(trust, &bundle)?;
    let record = bundle
        .get("opening")
        .and_then(|op| op.get("record"))
        .ok_or(Reason::MapHeads)?;
    let heads = parse_heads(record).ok_or(Reason::MapHeads)?;
    if heads.log != ok.log || id.is_some_and(|id| heads.log != id.log) {
        return Err(Reason::MapHeads);
    }
    let root = parse_root(o.get("root").ok_or(Reason::MapShape)?).ok_or(Reason::MapRoot)?;
    if id.is_some_and(|id| root.map != id.map) {
        return Err(Reason::MapId);
    }
    let listed = heads
        .roots
        .iter()
        .any(|e| e.map == root.map && e.seq == root.seq && e.digest == root.digest);
    if !listed {
        return Err(Reason::MapRootNotInHeads);
    }
    let bound = i64::try_from(ok.committed_by)
        .ok()
        .and_then(|t| t.checked_add(1))
        .and_then(|t| t.checked_mul(1000))
        .ok_or(Reason::MapTime)?;
    if root.as_of > bound {
        return Err(Reason::MapTime);
    }
    Ok(Side {
        log: heads.log,
        root,
        committed_by: ok.committed_by,
        anchored_by: ok.anchor.map(|a| a.anchored_by),
        found: None,
    })
}

fn verify_side(trust: &Trust, v: &Value, id: &MapId, with_path: bool) -> Result<Side, Reason> {
    let shape = Reason::MapShape;
    let o = v.as_object().ok_or(shape)?;
    let members: &[&str] = if with_path {
        &["heads", "root", "path", "value"]
    } else {
        &["heads", "root"]
    };
    if !has_members(o, members, &[]) {
        return Err(shape);
    }
    let mut side = verify_listed(trust, o, Some(id))?;
    if with_path {
        let path = parse_path(o.get("path").ok_or(shape)?).ok_or(shape)?;
        let (folded, found) = fold(&id.key, &path).ok_or(Reason::MapPath)?;
        if folded != side.root.root {
            return Err(Reason::MapPath);
        }
        let value = o.get("value").ok_or(shape)?;
        side.found = match (found, value) {
            (Found::Present(vh), v) if !matches!(v, Value::Null) => {
                if value_hash(v) != vh {
                    return Err(Reason::MapValue);
                }
                check_value(id, v)?;
                Some((found, Some(v.clone())))
            }
            (Found::Absent, Value::Null) => Some((found, None)),
            _ => return Err(Reason::MapValue),
        };
    }
    Ok(side)
}

/// Checks a root and the heads leaf that lists it (`{ heads, root }`) against the whole map,
/// folded from its leaves by `map_subtree` and `map_combine` (`map_root`). The root record holds no
/// count, so the count answered is the subtree's, as the host passed it.
pub fn verify_root(trust: &Trust, v: &Value, whole: &Sub) -> Result<Side, Reason> {
    let shape = Reason::MapShape;
    let o = v.as_object().ok_or(shape)?;
    if !has_members(o, &["heads", "root"], &[]) {
        return Err(shape);
    }
    let side = verify_listed(trust, o, None)?;
    if whole.hash != side.root.root {
        return Err(Reason::MapFold);
    }
    Ok(side)
}

/// What a proof says about one key at time T.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Open,
    Closed,
    None,
    NotOpen,
    Dropped,
    NoneOrRemoved,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Open => "open",
            State::Closed => "closed",
            State::None => "none",
            State::NotOpen => "not_open",
            State::Dropped => "dropped",
            State::NoneOrRemoved => "none_or_removed",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Reading {
    pub state: State,
    /// For an open series: the thread and the decision in force at T.
    pub thread: Option<String>,
    pub decision: Option<String>,
}

pub struct ProofOk {
    pub id: MapId,
    pub at: Side,
    pub before: Option<Side>,
    /// Keys removed after `before` (by an erasure instruction, by retention).
    pub removed_since: Option<(i64, i64)>,
    pub reading: Option<Reading>,
}

fn reading_of(state: State) -> Reading {
    Reading {
        state,
        thread: None,
        decision: None,
    }
}

/// The reading for a key without a value at the proof's root.
fn absent_reading(at: &Side, removed: Option<(i64, i64)>, t: i64) -> Reading {
    let floor_passed = t
        .checked_add(RETENTION_FLOOR_MS)
        .is_none_or(|limit| at.root.as_of >= limit);
    let state = match removed {
        None => State::NoneOrRemoved,
        Some((erased, _)) if erased > 0 => State::NoneOrRemoved,
        Some((_, 0)) => State::None,
        Some(_) if !floor_passed => State::NotOpen,
        Some(_) => State::NoneOrRemoved,
    };
    reading_of(state)
}

fn series_reading(series: &Series, at: &Side, t: i64) -> Reading {
    for th in &series.threads {
        let open_at_t = th.opened_at <= t && th.closed.as_ref().is_none_or(|c| c.at() > t);
        if open_at_t {
            let decision = th
                .decisions
                .iter()
                .rev()
                .find(|e| e.effective_at <= t)
                .map(|e| e.decision.clone());
            return Reading {
                state: State::Open,
                thread: Some(th.thread.clone()),
                decision,
            };
        }
    }
    if series.threads.iter().any(|th| th.opened_at <= t) {
        return reading_of(State::Closed);
    }
    if series.dropped == 0 {
        return reading_of(State::None);
    }
    // The dropped threads are older than the remaining ones and closed at least the floor before
    // they went; when the root is within the floor after T, they closed before T.
    let within_floor = t
        .checked_add(RETENTION_FLOOR_MS)
        .is_some_and(|limit| at.root.as_of < limit);
    reading_of(if within_floor {
        State::Closed
    } else {
        State::Dropped
    })
}

/// Verifies a `map.proof@1` (`map_proof`). `t` is the time asked about, if any.
pub fn verify_proof(trust: &Trust, v: &Value, t: Option<i64>) -> Result<ProofOk, Reason> {
    let shape = Reason::MapShape;
    let o = v.as_object().ok_or(shape)?;
    if !has_members(o, &["type", "id", "at"], &["before"]) || text(o, "type") != Some(MAP_PROOF_1) {
        return Err(shape);
    }
    let id = parse_id(o.get("id").ok_or(shape)?).ok_or(Reason::MapId)?;
    let at = verify_side(trust, o.get("at").ok_or(shape)?, &id, true)?;
    if t.is_some_and(|t| t < 0 || t >= at.root.as_of) {
        return Err(Reason::MapTime);
    }
    let before = match o.get("before") {
        None => None,
        Some(b) => {
            let t = t.ok_or(Reason::MapTime)?;
            let side = verify_side(trust, b, &id, false)?;
            if side.root.seq >= at.root.seq || side.root.as_of > t {
                return Err(Reason::MapTime);
            }
            Some(side)
        }
    };
    let removed_since = match &before {
        None => None,
        Some(b) => Some((
            at.root
                .erased_total
                .checked_sub(b.root.erased_total)
                .filter(|n| *n >= 0)
                .ok_or(Reason::MapRoot)?,
            at.root
                .swept_total
                .checked_sub(b.root.swept_total)
                .filter(|n| *n >= 0)
                .ok_or(Reason::MapRoot)?,
        )),
    };
    let value = at.found.as_ref().and_then(|(_, v)| v.as_ref());
    let reading = match (t, id.kind, value) {
        (Some(t), IdKind::Series, Some(v)) => {
            let series = parse_series(v, &id).ok_or(Reason::MapValueShape)?;
            Some(series_reading(&series, &at, t))
        }
        (Some(t), IdKind::Series, None) => Some(absent_reading(&at, removed_since, t)),
        _ => None,
    };
    Ok(ProofOk {
        id,
        at,
        before,
        removed_since,
        reading,
    })
}

// ---------------------------------------------------------------- conflicts

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rule {
    C1,
    C2,
    C3,
    C4,
    C5,
}

impl Rule {
    pub fn as_str(self) -> &'static str {
        match self {
            Rule::C1 => "c1",
            Rule::C2 => "c2",
            Rule::C3 => "c3",
            Rule::C4 => "c4",
            Rule::C5 => "c5",
        }
    }
}

pub struct ConflictOk {
    pub rule: Option<Rule>,
    pub restored: bool,
}

fn proof_side(trust: &Trust, v: &Value) -> Result<(MapId, Side), Reason> {
    let shape = Reason::MapShape;
    let o = v.as_object().ok_or(shape)?;
    if !has_members(o, &["type", "id", "at"], &["before"]) || text(o, "type") != Some(MAP_PROOF_1) {
        return Err(shape);
    }
    let id = parse_id(o.get("id").ok_or(shape)?).ok_or(Reason::MapId)?;
    let side = verify_side(trust, o.get("at").ok_or(shape)?, &id, true)?;
    Ok((id, side))
}

fn value_of(side: &Side) -> Option<&Value> {
    side.found.as_ref().and_then(|(_, v)| v.as_ref())
}

/// Whether a change of one entry between two values is one the writer may make: `leaf`, `c` and
/// `index` may go from null to a value once, and `index` may change when `index_v` rises.
fn entry_change_allowed(a: &Object, b: &Object) -> bool {
    let fixed = [
        "decision",
        "action",
        "outcome",
        "decided_at",
        "effective_at",
    ];
    if fixed.iter().any(|k| a.get(k) != b.get(k)) {
        return false;
    }
    let null_to_value = |k: &str| a.get(k) == b.get(k) || matches!(a.get(k), Some(Value::Null));
    if !null_to_value("leaf") || !null_to_value("c") {
        return false;
    }
    let va = safe(a.get("index_v"));
    let vb = safe(b.get("index_v"));
    match (va, vb) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(x), Some(y)) if y > x => true,
        (Some(x), Some(y)) => x == y && a.get("index") == b.get("index"),
    }
}

/// C3, C4 and C5 for the entries of one agreement key.
fn entries_rule(a: &[Entry], b: &[Entry], a_as_of: i64, b_dropped_more: bool) -> Option<Rule> {
    for e in b {
        if e.effective_at < a_as_of && !a.iter().any(|x| x.decision == e.decision) {
            return Some(Rule::C3);
        }
    }
    for x in a {
        match b.iter().find(|e| e.decision == x.decision) {
            Some(e) if !entry_change_allowed(&x.raw, &e.raw) => return Some(Rule::C4),
            Some(_) => {}
            None if !b_dropped_more => return Some(Rule::C5),
            None => {}
        }
    }
    None
}

fn series_rule(a: Option<&Series>, b: Option<&Series>, sa: &Side, sb: &Side) -> Option<Rule> {
    let a_as_of = sa.root.as_of;
    let b_entries: Vec<Entry> = b
        .map(|s| s.threads.iter().flat_map(|t| t.decisions.clone()).collect())
        .unwrap_or_default();
    let Some(a) = a else {
        return entries_rule(&[], &b_entries, a_as_of, false);
    };
    let Some(b) = b else {
        return absent_after_rule(
            a.threads.iter().map(|t| t.closed.as_ref().map(Closed::at)),
            sa,
            sb,
        );
    };
    let a_entries: Vec<Entry> = a.threads.iter().flat_map(|t| t.decisions.clone()).collect();
    if let Some(rule) = entries_rule(&a_entries, &b_entries, a_as_of, b.dropped > a.dropped) {
        return Some(rule);
    }
    for ta in &a.threads {
        match b.threads.iter().find(|tb| tb.thread == ta.thread) {
            Some(tb) => {
                let reopened = ta.closed.is_some() && tb.closed != ta.closed;
                if tb.opened_at != ta.opened_at || reopened {
                    return Some(Rule::C4);
                }
            }
            None => {
                // Only retention drops a thread from a key that stays, and not within the floor.
                let swept_ok = b.dropped > a.dropped
                    && ta
                        .closed
                        .as_ref()
                        .and_then(|c| c.at().checked_add(RETENTION_FLOOR_MS))
                        .is_some_and(|limit| limit <= sb.root.as_of);
                if !swept_ok {
                    return Some(Rule::C5);
                }
            }
        }
    }
    None
}

/// C5 for a key that the later root no longer holds. `closes` gives, per thread,
/// when it closed (None while open).
fn absent_after_rule(
    closes: impl Iterator<Item = Option<i64>>,
    sa: &Side,
    sb: &Side,
) -> Option<Rule> {
    let erased = sb.root.erased_total.saturating_sub(sa.root.erased_total);
    let swept = sb.root.swept_total.saturating_sub(sa.root.swept_total);
    if erased > 0 {
        return None;
    }
    if swept == 0 {
        return Some(Rule::C5);
    }
    let sweepable = |c: Option<i64>| {
        c.and_then(|at| at.checked_add(RETENTION_FLOOR_MS))
            .is_some_and(|limit| limit <= sb.root.as_of)
    };
    let mut closes = closes;
    if closes.any(|c| !sweepable(c)) {
        return Some(Rule::C5);
    }
    None
}

fn refusals_rule(a: Option<&Refusals>, b: Option<&Refusals>, sa: &Side, sb: &Side) -> Option<Rule> {
    match (a, b) {
        (None, None) => None,
        (None, Some(b)) => entries_rule(&[], &b.decisions, sa.root.as_of, false),
        (Some(_), None) => {
            let erased = sb.root.erased_total.saturating_sub(sa.root.erased_total);
            let swept = sb.root.swept_total.saturating_sub(sa.root.swept_total);
            (erased == 0 && swept == 0).then_some(Rule::C5)
        }
        (Some(a), Some(b)) => entries_rule(
            &a.decisions,
            &b.decisions,
            sa.root.as_of,
            b.dropped > a.dropped,
        ),
    }
}

/// Checks two proofs of one map against each other (`map_conflict`). `between` holds sides of the
/// roots in between, read only for `restored`.
pub fn verify_conflict(
    trust: &Trust,
    first: &Value,
    second: &Value,
    between: &[Value],
) -> Result<ConflictOk, Reason> {
    let (ida, a) = proof_side(trust, first)?;
    let (idb, b) = proof_side(trust, second)?;
    if ida.log != idb.log || ida.map != idb.map {
        return Err(Reason::MapScope);
    }
    let (ida, sa, idb, sb) = if a.root.seq <= b.root.seq {
        (ida, a, idb, b)
    } else {
        (idb, b, ida, a)
    };
    let mut restored = sb.root.restored.is_some();
    for raw in between {
        let side = verify_side(trust, &document(Some(raw))?, &ida, false)?;
        if side.root.seq <= sa.root.seq || side.root.seq >= sb.root.seq {
            return Err(Reason::MapScope);
        }
        restored = restored || side.root.restored.is_some();
    }
    let rule = if sa.root.seq == sb.root.seq {
        (sa.root.digest != sb.root.digest).then_some(Rule::C1)
    } else if (sb.root.seq == sa.root.seq.saturating_add(1)
        && sb.root.prev.as_deref() != Some(sa.root.digest.as_str()))
        || sb.root.as_of <= sa.root.as_of
    {
        Some(Rule::C2)
    } else if ida.key != idb.key {
        None
    } else {
        let (va, vb) = (value_of(&sa), value_of(&sb));
        match ida.kind {
            IdKind::Series => {
                let a = va.and_then(|v| parse_series(v, &ida));
                let b = vb.and_then(|v| parse_series(v, &ida));
                series_rule(a.as_ref(), b.as_ref(), &sa, &sb)
            }
            IdKind::Refusals => {
                let a = va.and_then(|v| parse_refusals(v, &ida));
                let b = vb.and_then(|v| parse_refusals(v, &ida));
                refusals_rule(a.as_ref(), b.as_ref(), &sa, &sb)
            }
        }
    };
    Ok(ConflictOk { rule, restored })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(byte0: u8) -> Hash {
        let mut h = [0u8; 32];
        h[0] = byte0;
        h
    }

    #[test]
    fn shapes_follow_the_keys() {
        let vh = [7u8; 32];
        assert_eq!(build(&[], 0).hash, empty());
        let one = build(&[(k(0x80), vh)], 0);
        assert_eq!(one.kind, SubKind::Leaf);
        assert_eq!(one.hash, leaf_hash(&k(0x80), &vh));
        // 0x00 and 0x40 share the first bit, so the root is a node with an empty right child.
        let two = build(&[(k(0x00), vh), (k(0x40), vh)], 0);
        let inner = node_hash(&leaf_hash(&k(0x00), &vh), &leaf_hash(&k(0x40), &vh));
        assert_eq!(two.hash, node_hash(&inner, &empty()));
    }

    #[test]
    fn paths_fold_to_the_root() {
        let vh = [7u8; 32];
        let leaves = [(k(0x00), vh), (k(0x40), vh), (k(0x80), vh)];
        let root = build(&leaves, 0).hash;
        // 0x40: depth 2, siblings: the right subtree of the root, then the leaf of 0x00.
        let path = Path {
            siblings: alloc::vec![leaf_hash(&k(0x80), &vh), leaf_hash(&k(0x00), &vh)],
            end: End::Leaf { key: k(0x40), vh },
        };
        assert_eq!(fold(&k(0x40), &path), Some((root, Found::Present(vh))));
        // 0xc0 is absent: its path ends at 0x80's leaf, which shares the first bit.
        let absent = Path {
            siblings: alloc::vec![build(&leaves[..2], 1).hash],
            end: End::Leaf { key: k(0x80), vh },
        };
        assert_eq!(fold(&k(0xc0), &absent), Some((root, Found::Absent)));
        // A leaf off the asked key's prefix is not a path for it.
        assert_eq!(fold(&k(0x40), &absent), None);
    }

    /// `{ kind, hash, count }` as the operations answer it.
    fn sub_value(kind: &str, hash: &Hash, count: u64) -> Value {
        let mut o = Object::default();
        o.insert("kind".into(), Value::from(kind));
        o.insert("hash".into(), Value::from(b64(hash).as_str()));
        o.insert(
            "count".into(),
            Value::Number(Number::from_parts(&alloc::format!("{count}"), count as f64)),
        );
        Value::Object(o)
    }

    #[test]
    fn combining_matches_building() {
        let vh = [9u8; 32];
        let leaves = [(k(0x00), vh), (k(0x10), vh), (k(0x90), vh)];
        let whole = build(&leaves, 0);
        let parts: Vec<Value> = [build(&leaves[..2], 1), build(&leaves[2..], 1)]
            .iter()
            .map(|s| sub_value(s.kind.as_str(), &s.hash, s.count))
            .collect();
        assert_eq!(combine(&parts).unwrap(), whole);
    }

    #[test]
    fn a_whole_map_is_read_as_one_subtree() {
        let vh = [3u8; 32];
        let whole = build(&[(k(0x00), vh), (k(0x80), vh)], 0);
        assert_eq!(parse_sub(&sub_value("node", &whole.hash, 2)), Some(whole));
        assert_eq!(
            parse_sub(&sub_value("empty", &empty(), 0)),
            Some(empty_sub())
        );
        // An empty map has one hash, a map of one key is its leaf, and a node holds two or more.
        assert_eq!(parse_sub(&sub_value("empty", &whole.hash, 0)), None);
        assert_eq!(parse_sub(&sub_value("leaf", &whole.hash, 2)), None);
        assert_eq!(parse_sub(&sub_value("node", &whole.hash, 1)), None);
    }

    #[test]
    fn writers_match_clavis() {
        // The writer numbers Clavis assigns.
        assert_eq!(agreement_shard("subject-1"), 2);
        assert_eq!(agreement_shard("p_user-42"), 14);
    }
}

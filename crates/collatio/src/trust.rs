//! The trust chain (FORMATS.md §5): the Master public key the caller pins → the sealer the Master
//! nominated → the aggregated JWKS and the catalog, both signed by that sealer. Nothing else is
//! trusted: a key is used only after this chain has checked it.

use alloc::string::String;
use alloc::vec::Vec;

use crate::b64;
use crate::digest::is_digest;
use crate::jcs::canonical;
use crate::json::{self, Number, Object, Value};
use crate::keylog::is_id;
use crate::reason::Reason;
use crate::text::is_trimmed_text;

pub const NOMINATE_PURPOSE: &str = "platform.sealer.nominate";
pub const JWKS_CHILD_PURPOSE: &str = "signed-jwks-child";
pub const CATALOG_1: &str = "catalog@1";

pub const SLOT_SIGN_RECEIPT: &str = "sign-receipt";
pub const SLOT_LEDGER_LOG: &str = "ledger-log";

const MAX_KEYS: usize = 256;
const MAX_LIST: usize = 4096;

/// A P-256 public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct P256 {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

impl P256 {
    /// Checks an ES256 signature given as raw r‖s in Base64URL.
    pub fn verify(&self, msg: &[u8], sig_b64u: &str) -> bool {
        use p256::ecdsa::signature::Verifier;
        use p256::ecdsa::{Signature, VerifyingKey};
        let Some(raw) = b64::decode_len(sig_b64u, 64) else {
            return false;
        };
        let mut sec1 = Vec::with_capacity(65);
        sec1.push(0x04);
        sec1.extend_from_slice(&self.x);
        sec1.extend_from_slice(&self.y);
        let (Ok(vk), Ok(sig)) = (
            VerifyingKey::from_sec1_bytes(&sec1),
            Signature::from_slice(&raw),
        ) else {
            return false;
        };
        vk.verify(msg, &sig).is_ok()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicKey {
    Es256(P256),
    Ed25519([u8; 32]),
}

#[derive(Clone, Debug)]
pub struct Key {
    pub kid: String,
    pub slot: String,
    pub key: PublicKey,
}

#[derive(Clone, Debug)]
pub struct Nomination {
    pub instance_id: String,
    pub sealer_kid: String,
    pub sealer: P256,
    pub iat: i64,
}

#[derive(Clone, Debug)]
pub struct Catalog {
    pub value: Value,
    pub issued_at: i64,
    pub registries: Vec<String>,
    pub dimensions: Vec<String>,
    /// `(log ID, kid)`; a log has more than one kid while its key rotates.
    pub logs: Vec<(String, String)>,
}

#[derive(Clone, Debug)]
pub struct Trust {
    pub ns: String,
    pub nomination: Nomination,
    pub keys: Vec<Key>,
    pub catalog: Catalog,
    /// The registry documents the caller passed, as JSON strings, read when a dimension names one.
    pub registries: Vec<String>,
}

fn b64_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 43 {
        return None;
    }
    b64::decode_len(s, 32)?.as_slice().try_into().ok()
}

fn p256_point(x: &str, y: &str) -> Option<P256> {
    let key = P256 {
        x: b64_32(x)?,
        y: b64_32(y)?,
    };
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&key.x);
    sec1.extend_from_slice(&key.y);
    p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).ok()?;
    Some(key)
}

fn has_exactly(o: &Object, keys: &[&str]) -> bool {
    o.len() == keys.len() && keys.iter().all(|k| o.get(k).is_some())
}

fn str_of<'a>(o: &'a Object, key: &str) -> Option<&'a str> {
    o.get(key)?.as_str()
}

/// The Master public key the caller pins: an EC P-256 JWK without a private part. Members other
/// than `kty`, `crv`, `x`, `y` are not read, except that `alg`, when present, must be ES256.
pub fn parse_master(v: &Value) -> Option<P256> {
    let o = v.as_object()?;
    if str_of(o, "kty")? != "EC" || str_of(o, "crv")? != "P-256" || o.get("d").is_some() {
        return None;
    }
    if o.get("alg").is_some_and(|a| a.as_str() != Some("ES256")) {
        return None;
    }
    p256_point(str_of(o, "x")?, str_of(o, "y")?)
}

/// A Master-signed sealer nomination (`platform.sealer.nominate`).
pub fn verify_nomination(v: &Value, master: &P256) -> Option<Nomination> {
    let o = v.as_object()?;
    if !has_exactly(o, &["payload", "signature"]) {
        return None;
    }
    let payload = o.get("payload")?;
    let p = payload.as_object()?;
    let keys = [
        "v",
        "purpose",
        "instance_id",
        "sealer_kid",
        "sealer_public_jwk",
        "iat",
    ];
    if !has_exactly(p, &keys)
        || p.get("v")?.as_number()?.as_safe_integer()? != 1
        || str_of(p, "purpose")? != NOMINATE_PURPOSE
    {
        return None;
    }
    let instance_id = str_of(p, "instance_id")?;
    let sealer_kid = str_of(p, "sealer_kid")?;
    let iat = p.get("iat")?.as_number()?.as_safe_integer()?;
    let jwk = p.get("sealer_public_jwk")?.as_object()?;
    if !has_exactly(jwk, &["kty", "crv", "x", "y", "kid", "alg"])
        || str_of(jwk, "kty")? != "EC"
        || str_of(jwk, "crv")? != "P-256"
        || str_of(jwk, "alg")? != "ES256"
        || str_of(jwk, "kid")? != sealer_kid
        || !is_id(instance_id, 200)
        || !is_id(sealer_kid, 200)
        || iat < 0
    {
        return None;
    }
    let sealer = p256_point(str_of(jwk, "x")?, str_of(jwk, "y")?)?;
    let signature = str_of(o, "signature")?;
    master
        .verify(canonical(payload).as_bytes(), signature)
        .then(|| Nomination {
            instance_id: String::from(instance_id),
            sealer_kid: String::from(sealer_kid),
            sealer,
            iat,
        })
}

fn is_ns(s: &str) -> bool {
    let b = s.as_bytes();
    (2..=32).contains(&b.len())
        && b.first().is_some_and(u8::is_ascii_lowercase)
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

fn is_slot(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && b.first().is_some_and(u8::is_ascii_lowercase)
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

fn int_value(n: i64) -> Value {
    let raw = alloc::format!("{n}");
    #[allow(clippy::cast_precision_loss)]
    let f = n as f64;
    Value::Number(Number::from_parts(&raw, f))
}

/// The payload the sealer signs for one JWKS key.
fn child_payload(ns: &str, slot: &str, jwk: &Object) -> Value {
    let mut public = Object::default();
    for k in ["kty", "crv", "x"] {
        public.insert(String::from(k), jwk.get(k).cloned().unwrap_or(Value::Null));
    }
    public.insert(
        String::from("y"),
        jwk.get("y").cloned().unwrap_or(Value::Null),
    );
    for k in ["kid", "alg"] {
        public.insert(String::from(k), jwk.get(k).cloned().unwrap_or(Value::Null));
    }
    let mut p = Object::default();
    p.insert(String::from("version"), int_value(1));
    p.insert(String::from("purpose"), Value::from(JWKS_CHILD_PURPOSE));
    p.insert(String::from("protocol_ns"), Value::from(ns));
    p.insert(String::from("slot"), Value::from(slot));
    p.insert(String::from("public_jwk"), Value::Object(public));
    Value::Object(p)
}

/// The aggregated JWKS: every key carries `${ns}-slot` and the sealer's signature over it.
pub fn verify_jwks(v: &Value, master: &P256) -> Result<(String, Nomination, Vec<Key>), Reason> {
    let o = v.as_object().ok_or(Reason::TrustJwks)?;
    let nomination = verify_nomination(o.get("sealer").ok_or(Reason::TrustJwks)?, master)
        .ok_or(Reason::TrustNomination)?;
    let list = o
        .get("keys")
        .and_then(Value::as_array)
        .filter(|l| !l.is_empty() && l.len() <= MAX_KEYS)
        .ok_or(Reason::TrustJwks)?;
    let ns = list
        .first()
        .and_then(Value::as_object)
        .and_then(|k| k.keys().find_map(|n| n.strip_suffix("-sealer-signature")))
        .filter(|ns| is_ns(ns))
        .map(String::from)
        .ok_or(Reason::TrustJwks)?;
    let slot_field = alloc::format!("{ns}-slot");
    let sig_field = alloc::format!("{ns}-sealer-signature");
    let mut keys: Vec<Key> = Vec::with_capacity(list.len());
    for item in list {
        let k = item.as_object().ok_or(Reason::TrustJwks)?;
        let s = |key: &str| str_of(k, key).ok_or(Reason::TrustJwks);
        let (kty, crv, x, kid, alg) = (s("kty")?, s("crv")?, s("x")?, s("kid")?, s("alg")?);
        let (slot, sig) = (s(&slot_field)?, s(&sig_field)?);
        let key = match (kty, crv, alg) {
            ("EC", "P-256", "ES256")
                if has_exactly(
                    k,
                    &[
                        "kty",
                        "crv",
                        "x",
                        "y",
                        "kid",
                        "alg",
                        &slot_field,
                        &sig_field,
                    ],
                ) =>
            {
                PublicKey::Es256(p256_point(x, s("y")?).ok_or(Reason::TrustJwks)?)
            }
            ("OKP", "Ed25519", "EdDSA")
                if has_exactly(
                    k,
                    &["kty", "crv", "x", "kid", "alg", &slot_field, &sig_field],
                ) =>
            {
                let raw = b64_32(x).ok_or(Reason::TrustJwks)?;
                ed25519_dalek::VerifyingKey::from_bytes(&raw).map_err(|_| Reason::TrustJwks)?;
                PublicKey::Ed25519(raw)
            }
            _ => return Err(Reason::TrustJwks),
        };
        if !is_id(kid, 200) || !is_slot(slot) || keys.iter().any(|e| e.kid == kid) {
            return Err(Reason::TrustJwks);
        }
        let payload = canonical(&child_payload(&ns, slot, k));
        if !nomination.sealer.verify(payload.as_bytes(), sig) {
            return Err(Reason::TrustJwksSignature);
        }
        keys.push(Key {
            kid: String::from(kid),
            slot: String::from(slot),
            key,
        });
    }
    Ok((ns, nomination, keys))
}

fn digest_list(v: &Value) -> Option<Vec<String>> {
    let items = v.as_array()?;
    if items.len() > MAX_LIST {
        return None;
    }
    let mut out: Vec<String> = Vec::with_capacity(items.len());
    for item in items {
        let d = item.as_str()?;
        if !is_digest(d) || out.iter().any(|e| e == d) {
            return None;
        }
        out.push(String::from(d));
    }
    Some(out)
}

/// `first-party.<n>` (a first-party shard) or `anchor`.
pub fn is_log_id(s: &str) -> bool {
    s == "anchor" || first_party_shard(s).is_some()
}

pub fn first_party_shard(s: &str) -> Option<u64> {
    let n = s.strip_prefix("first-party.")?;
    if n.is_empty() || n.len() > 6 || !n.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if n.len() > 1 && n.starts_with('0') {
        return None;
    }
    n.parse().ok()
}

fn is_lower_hex(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_source(v: &Value) -> bool {
    let Some(o) = v.as_object() else {
        return false;
    };
    let (Some(repo), Some(tag), Some(commit)) =
        (str_of(o, "repo"), str_of(o, "tag"), str_of(o, "commit"))
    else {
        return false;
    };
    let printable = |s: &str, max: usize| {
        !s.is_empty() && s.len() <= max && s.bytes().all(|b| (0x21..=0x7e).contains(&b))
    };
    has_exactly(o, &["repo", "tag", "commit"])
        && repo.starts_with("https://")
        && printable(repo, 200)
        && printable(tag, 128)
        && (commit.len() == 40 || commit.len() == 64)
        && is_lower_hex(commit)
}

/// `catalog@1`, signed by the nominated sealer.
pub fn verify_catalog(v: &Value, master: &P256) -> Result<Catalog, Reason> {
    let bad = Reason::TrustCatalog;
    let o = v.as_object().ok_or(bad)?;
    let keys = [
        "type",
        "issued_at",
        "sealer",
        "verifiers",
        "revoked",
        "registries",
        "dimensions",
        "logs",
        "signature",
    ];
    if !has_exactly(o, &keys) || str_of(o, "type") != Some(CATALOG_1) {
        return Err(bad);
    }
    let nomination =
        verify_nomination(o.get("sealer").ok_or(bad)?, master).ok_or(Reason::TrustNomination)?;
    let issued_at = o
        .get("issued_at")
        .and_then(Value::as_number)
        .and_then(Number::as_safe_integer)
        .filter(|t| *t >= 0)
        .ok_or(bad)?;

    let verifiers = o.get("verifiers").and_then(Value::as_array).ok_or(bad)?;
    let mut digests: Vec<&str> = Vec::with_capacity(verifiers.len());
    for item in verifiers {
        let e = item.as_object().ok_or(bad)?;
        let d = str_of(e, "digest").ok_or(bad)?;
        if !has_exactly(e, &["digest", "source"])
            || !is_digest(d)
            || digests.contains(&d)
            || !e.get("source").is_some_and(is_source)
        {
            return Err(bad);
        }
        digests.push(d);
    }
    if digests.is_empty() || digests.len() > MAX_LIST {
        return Err(bad);
    }
    let revoked = o.get("revoked").and_then(Value::as_array).ok_or(bad)?;
    let mut seen: Vec<&str> = Vec::new();
    for item in revoked {
        let e = item.as_object().ok_or(bad)?;
        let (Some(verifier), Some(reason), Some(successor)) = (
            str_of(e, "verifier"),
            str_of(e, "reason"),
            str_of(e, "successor"),
        ) else {
            return Err(bad);
        };
        if !has_exactly(e, &["verifier", "reason", "successor"])
            || !digests.contains(&verifier)
            || !digests.contains(&successor)
            || verifier == successor
            || seen.contains(&verifier)
            || !is_trimmed_text(reason, 500)
        {
            return Err(bad);
        }
        seen.push(verifier);
    }
    let registries = digest_list(o.get("registries").ok_or(bad)?).ok_or(bad)?;
    let dimensions = digest_list(o.get("dimensions").ok_or(bad)?).ok_or(bad)?;
    let mut logs: Vec<(String, String)> = Vec::new();
    for item in o.get("logs").and_then(Value::as_array).ok_or(bad)? {
        let e = item.as_object().ok_or(bad)?;
        let (Some(id), Some(kid)) = (str_of(e, "id"), str_of(e, "kid")) else {
            return Err(bad);
        };
        if !has_exactly(e, &["id", "kid"])
            || !is_log_id(id)
            || !is_id(kid, 200)
            || logs.iter().any(|(i, k)| i == id && k == kid)
            || logs.len() >= MAX_LIST
        {
            return Err(bad);
        }
        logs.push((String::from(id), String::from(kid)));
    }

    let sig = o.get("signature").and_then(Value::as_object).ok_or(bad)?;
    if !has_exactly(sig, &["kid", "alg", "sig"])
        || str_of(sig, "alg") != Some("ES256")
        || str_of(sig, "kid") != Some(nomination.sealer_kid.as_str())
    {
        return Err(bad);
    }
    let signed = canonical(&Value::Object(o.without("signature")));
    if !nomination
        .sealer
        .verify(signed.as_bytes(), str_of(sig, "sig").ok_or(bad)?)
    {
        return Err(Reason::TrustCatalogSignature);
    }
    Ok(Catalog {
        value: v.clone(),
        issued_at,
        registries,
        dimensions,
        logs,
    })
}

/// Reads a JSON document the caller passed as a string, strictly.
pub fn document(v: Option<&Value>) -> Result<Value, Reason> {
    let text = v.and_then(Value::as_str).ok_or(Reason::InputMalformed)?;
    json::parse(text.as_bytes()).map_err(Reason::from)
}

/// The outer `trust` member: `{ master, jwks, catalog, registries? }`.
pub fn read_trust(v: Option<&Value>) -> Result<Trust, Reason> {
    let o = v.and_then(Value::as_object).ok_or(Reason::InputMalformed)?;
    let master =
        parse_master(o.get("master").ok_or(Reason::InputMalformed)?).ok_or(Reason::TrustMaster)?;
    let (ns, nomination, keys) = verify_jwks(&document(o.get("jwks"))?, &master)?;
    let catalog = verify_catalog(&document(o.get("catalog"))?, &master)?;
    let registries = match o.get("registries") {
        None => Vec::new(),
        Some(r) => r
            .as_array()
            .ok_or(Reason::InputMalformed)?
            .iter()
            .map(|x| x.as_str().map(String::from).ok_or(Reason::InputMalformed))
            .collect::<Result<_, _>>()?,
    };
    Ok(Trust {
        ns,
        nomination,
        keys,
        catalog,
        registries,
    })
}

impl Trust {
    /// The key with `kid` in `slot`.
    pub fn key(&self, kid: &str, slot: &str) -> Option<&PublicKey> {
        self.keys
            .iter()
            .find(|k| k.kid == kid && k.slot == slot)
            .map(|k| &k.key)
    }

    /// The Ed25519 keys that may sign a log's notes, with their kids: the ones the catalog lists
    /// for a first-party shard or `anchor`, and any `ledger-log` key for an Org's log, which the
    /// catalog does not list.
    pub fn log_keys<'a>(&'a self, log: &'a str) -> Vec<(&'a str, &'a [u8; 32])> {
        let ledger_key = |kid: &'a str| match self.key(kid, SLOT_LEDGER_LOG) {
            Some(PublicKey::Ed25519(x)) => Some((kid, x)),
            _ => None,
        };
        if crate::fields::is_org(log) {
            return self
                .keys
                .iter()
                .filter_map(|k| ledger_key(k.kid.as_str()))
                .collect();
        }
        self.catalog
            .logs
            .iter()
            .filter(|(id, _)| id == log)
            .filter_map(|(_, kid)| ledger_key(kid.as_str()))
            .collect()
    }

    /// The registry document whose digest is `digest`, read strictly.
    pub fn registry(&self, digest: &str) -> Result<Value, Reason> {
        for text in &self.registries {
            let v = json::parse(text.as_bytes()).map_err(|_| Reason::RegistryShape)?;
            if crate::digest::digest_of(&v) == digest {
                return Ok(v);
            }
        }
        Err(Reason::RegistryMissing)
    }
}

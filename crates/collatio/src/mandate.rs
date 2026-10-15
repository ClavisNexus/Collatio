//! Delegation records (FORMATS.md §7): the scope (`mandate.terms@1`), each use
//! (`mandate.use@1` with the app's request and JWT), and the close (`mandate.close@1`), checked
//! against the grant receipt. The scope check and the totals are the pre-genesis rules.

use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;

use crate::b64;
use crate::commit::to_hex;
use crate::digest::{digest_of, is_digest, sha256};
use crate::fields::{is_app, is_domain, is_org, is_uuid};
use crate::jcs::{canonical, utf16_cmp};
use crate::json::{self, Number, Object, Value};
use crate::reason::Reason;
use crate::text::is_line;
use crate::trust::{P256, PublicKey, Trust};

pub const MANDATE_TERMS_1: &str = "mandate.terms@1";
pub const MANDATE_USE_REQUEST_1: &str = "mandate.use_request@1";
pub const MANDATE_USE_1: &str = "mandate.use@1";
pub const MANDATE_CLOSE_1: &str = "mandate.close@1";
pub const MANDATE_GRANT_1: &str = "mandate.grant@1";
pub const MANDATE_GRANT_ON_BEHALF_1: &str = "mandate.grant.on_behalf@1";
pub const SLOT_MANDATE_ATTEST: &str = "mandate-attest";

const OPERATIONS_MAX: usize = 16;
const TARGETS_MAX: usize = 32;
const USES_MAX: i64 = 1000;
const LABEL_MAX: usize = 80;
const AMOUNT_MAX: i64 = 1_000_000_000_000_000;
const TIME_MAX: i64 = 100_000_000_000;
const JWT_SKEW: i64 = 30;
const JWT_AUD: &str = "clavis-ledger";

const CLOSE_REASONS: [&str; 6] = [
    "account_closed",
    "exhausted",
    "expired",
    "revoked_by_app",
    "revoked_by_holder",
    "signer_designation_ended",
];

fn has_exactly(o: &Object, required: &[&str], optional: &[&str]) -> bool {
    required.iter().all(|k| o.get(k).is_some())
        && o.keys()
            .all(|k| required.contains(&k) || optional.contains(&k))
}

fn int(v: Option<&Value>, min: i64, max: i64) -> Option<i64> {
    v?.as_number()
        .and_then(Number::as_safe_integer)
        .filter(|n| (min..=max).contains(n))
}

fn str_of<'a>(o: &'a Object, k: &str) -> Option<&'a str> {
    o.get(k)?.as_str()
}

/// A name shown to the holder: one line of at most 80, without direction marks or bidi controls.
pub fn is_label(s: &str) -> bool {
    is_line(s, LABEL_MAX)
        && !s.chars().any(|c| {
            matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
}

fn is_operation_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 128
        && b.first().is_some_and(u8::is_ascii_alphanumeric)
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || b"._:-".contains(c))
}

fn is_printable(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

fn is_target_id(s: &str) -> bool {
    is_printable(s, 256)
}

fn is_agent_id(s: &str) -> bool {
    is_printable(s, 512)
}

#[derive(Clone, Debug)]
pub struct Amount {
    pub total: i64,
    pub per_use: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct Terms {
    pub value: Value,
    pub operations: Vec<String>,
    pub uses: i64,
    pub not_after: i64,
    pub amount: Option<Amount>,
    pub targets: Option<Vec<String>>,
    pub agent: Option<String>,
}

/// `[{ <key>, label }]`: non-empty, at most `max`, strictly increasing by `key`.
fn labelled(
    v: Option<&Value>,
    key: &str,
    check: fn(&str) -> bool,
    max: usize,
) -> Option<Vec<String>> {
    let items = v?.as_array()?;
    if items.is_empty() || items.len() > max {
        return None;
    }
    let mut out: Vec<String> = Vec::with_capacity(items.len());
    for item in items {
        let o = item.as_object()?;
        let id = str_of(o, key)?;
        if !has_exactly(o, &[key, "label"], &[]) || !check(id) || !is_label(str_of(o, "label")?) {
            return None;
        }
        if out
            .last()
            .is_some_and(|last| utf16_cmp(last, id) != Ordering::Less)
        {
            return None;
        }
        out.push(String::from(id));
    }
    Some(out)
}

pub fn parse_terms(v: &Value) -> Option<Terms> {
    let o = v.as_object()?;
    if str_of(o, "type")? != MANDATE_TERMS_1
        || !has_exactly(
            o,
            &["type", "operations", "uses", "not_after"],
            &["amount", "targets", "agent"],
        )
    {
        return None;
    }
    let operations = labelled(
        o.get("operations"),
        "name",
        is_operation_name,
        OPERATIONS_MAX,
    )?;
    let uses = int(o.get("uses"), 1, USES_MAX)?;
    let not_after = int(o.get("not_after"), 0, TIME_MAX)?;
    let amount = match o.get("amount") {
        None => None,
        Some(a) => {
            let a = a.as_object()?;
            let currency = str_of(a, "currency")?;
            if !has_exactly(a, &["currency", "total"], &["per_use"])
                || currency.len() != 3
                || !currency.bytes().all(|b| b.is_ascii_uppercase())
            {
                return None;
            }
            let total = int(a.get("total"), 1, AMOUNT_MAX)?;
            let per_use = match a.get("per_use") {
                None => None,
                Some(p) => Some(int(Some(p), 1, total)?),
            };
            Some(Amount { total, per_use })
        }
    };
    let targets = match o.get("targets") {
        None => None,
        Some(t) => Some(labelled(Some(t), "id", is_target_id, TARGETS_MAX)?),
    };
    let agent = match o.get("agent") {
        None => None,
        Some(a) => {
            let a = a.as_object()?;
            let id = str_of(a, "id")?;
            if !has_exactly(a, &["id", "label"], &[])
                || !is_agent_id(id)
                || !is_label(str_of(a, "label")?)
            {
                return None;
            }
            Some(String::from(id))
        }
    };
    Some(Terms {
        value: v.clone(),
        operations,
        uses,
        not_after,
        amount,
        targets,
        agent,
    })
}

#[derive(Clone, Debug)]
pub struct UseRequest {
    pub value: Value,
    pub mandate: String,
    pub operation: String,
    pub target: Option<String>,
    pub amount: Option<i64>,
    pub agent: Option<String>,
}

pub fn parse_use_request(v: &Value) -> Option<UseRequest> {
    let o = v.as_object()?;
    if str_of(o, "type")? != MANDATE_USE_REQUEST_1
        || !has_exactly(
            o,
            &["type", "mandate", "use", "operation", "call"],
            &["target", "amount", "agent"],
        )
    {
        return None;
    }
    let mandate = str_of(o, "mandate")?;
    let operation = str_of(o, "operation")?;
    if !is_uuid(mandate)
        || !is_uuid(str_of(o, "use")?)
        || !is_operation_name(operation)
        || !is_digest(str_of(o, "call")?)
    {
        return None;
    }
    let target = match o.get("target") {
        None => None,
        Some(t) => Some(String::from(t.as_str().filter(|t| is_target_id(t))?)),
    };
    let amount = match o.get("amount") {
        None => None,
        Some(a) => Some(int(Some(a), 1, AMOUNT_MAX)?),
    };
    let agent = match o.get("agent") {
        None => None,
        Some(a) => Some(String::from(a.as_str().filter(|a| is_agent_id(a))?)),
    };
    Some(UseRequest {
        value: v.clone(),
        mandate: String::from(mandate),
        operation: String::from(operation),
        target,
        amount,
        agent,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Totals {
    pub uses: i64,
    pub amount: Option<i64>,
}

#[derive(Clone, Debug)]
pub enum AppKey {
    Ed25519([u8; 32]),
    Es256(P256),
}

#[derive(Clone, Debug)]
pub struct Use {
    pub value: Value,
    pub grant: String,
    pub seq: i64,
    pub prev: Option<String>,
    pub request: UseRequest,
    pub jwt: String,
    pub key: AppKey,
    pub totals: Totals,
    pub at: i64,
}

fn b64_32(s: &str) -> Option<[u8; 32]> {
    (s.len() == 43)
        .then(|| b64::decode_len(s, 32))??
        .as_slice()
        .try_into()
        .ok()
}

fn parse_app_key(v: &Value) -> Option<AppKey> {
    let o = v.as_object()?;
    match (str_of(o, "kty")?, str_of(o, "crv")?) {
        ("OKP", "Ed25519") if has_exactly(o, &["kty", "crv", "x"], &[]) => {
            Some(AppKey::Ed25519(b64_32(str_of(o, "x")?)?))
        }
        ("EC", "P-256") if has_exactly(o, &["kty", "crv", "x", "y"], &[]) => {
            Some(AppKey::Es256(P256 {
                x: b64_32(str_of(o, "x")?)?,
                y: b64_32(str_of(o, "y")?)?,
            }))
        }
        _ => None,
    }
}

fn parse_totals(v: &Value) -> Option<Totals> {
    let o = v.as_object()?;
    if !has_exactly(o, &["uses"], &["amount"]) {
        return None;
    }
    Some(Totals {
        uses: int(o.get("uses"), 1, USES_MAX)?,
        amount: match o.get("amount") {
            None => None,
            Some(a) => Some(int(Some(a), 1, AMOUNT_MAX)?),
        },
    })
}

/// `sigs`: 1–4 of `{ kid, alg, sig }`.
fn sigs_shape(v: Option<&Value>) -> bool {
    let Some(list) = v.and_then(Value::as_array) else {
        return false;
    };
    !list.is_empty()
        && list.len() <= 4
        && list.iter().all(|s| {
            s.as_object().is_some_and(|o| {
                let (kid, alg, sig) = (str_of(o, "kid"), str_of(o, "alg"), str_of(o, "sig"));
                has_exactly(o, &["kid", "alg", "sig"], &[])
                    && kid.is_some_and(|k| !k.is_empty() && k.len() <= 128)
                    && alg.is_some_and(|a| !a.is_empty() && a.len() <= 32)
                    && sig.is_some_and(crate::keylog::is_b64u_text)
            })
        })
}

fn is_jwt(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    s.len() <= 4096
        && parts.len() == 3
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

pub fn parse_use(v: &Value) -> Option<Use> {
    let o = v.as_object()?;
    let keys = [
        "type", "grant", "seq", "prev", "request", "app", "totals", "at", "sigs",
    ];
    if str_of(o, "type")? != MANDATE_USE_1 || !has_exactly(o, &keys, &[]) {
        return None;
    }
    let grant = str_of(o, "grant").filter(|g| is_digest(g))?;
    let seq = int(o.get("seq"), 1, USES_MAX)?;
    let prev = match o.get("prev")? {
        Value::Null => None,
        p => Some(String::from(p.as_str().filter(|p| is_digest(p))?)),
    };
    if (seq == 1) != prev.is_none() {
        return None;
    }
    let request = parse_use_request(o.get("request")?)?;
    let app = o.get("app")?.as_object()?;
    let jwt = str_of(app, "jwt").filter(|j| is_jwt(j))?;
    if !has_exactly(app, &["jwt", "key"], &[]) {
        return None;
    }
    let key = parse_app_key(app.get("key")?)?;
    let totals = parse_totals(o.get("totals")?)?;
    if totals.uses != seq || totals.amount.is_none() != request.amount.is_none() {
        return None;
    }
    let at = int(o.get("at"), 0, TIME_MAX)?;
    if !sigs_shape(o.get("sigs")) {
        return None;
    }
    Some(Use {
        value: v.clone(),
        grant: String::from(grant),
        seq,
        prev,
        request,
        jwt: String::from(jwt),
        key,
        totals,
        at,
    })
}

#[derive(Clone, Debug)]
pub struct Close {
    pub value: Value,
    pub grant: String,
    pub mandate: String,
    pub reason: String,
    pub uses: i64,
    pub last: Option<String>,
    pub at: i64,
}

pub fn parse_close(v: &Value) -> Option<Close> {
    let o = v.as_object()?;
    let keys = [
        "type", "grant", "mandate", "reason", "uses", "last", "at", "sigs",
    ];
    if str_of(o, "type")? != MANDATE_CLOSE_1 || !has_exactly(o, &keys, &[]) {
        return None;
    }
    let grant = str_of(o, "grant").filter(|g| is_digest(g))?;
    let mandate = str_of(o, "mandate").filter(|m| is_uuid(m))?;
    let reason = str_of(o, "reason").filter(|r| CLOSE_REASONS.contains(r))?;
    let uses = int(o.get("uses"), 0, USES_MAX)?;
    let last = match o.get("last")? {
        Value::Null => None,
        l => Some(String::from(l.as_str().filter(|l| is_digest(l))?)),
    };
    if (uses == 0) != last.is_none() || !sigs_shape(o.get("sigs")) {
        return None;
    }
    Some(Close {
        value: v.clone(),
        grant: String::from(grant),
        mandate: String::from(mandate),
        reason: String::from(reason),
        uses,
        last,
        at: int(o.get("at"), 0, TIME_MAX)?,
    })
}

/// The first rule a use breaks, in the pre-genesis order, or the totals after it.
pub fn check_use(
    terms: &Terms,
    before: &Totals,
    request: &UseRequest,
    at: i64,
) -> Result<Totals, &'static str> {
    let mut found: Vec<&'static str> = Vec::new();
    if at > terms.not_after {
        found.push("expired");
    }
    if !terms.operations.contains(&request.operation) {
        found.push("operation");
    }
    if let Some(targets) = &terms.targets
        && !request.target.as_ref().is_some_and(|t| targets.contains(t))
    {
        found.push("target");
    }
    let spent = before.amount.unwrap_or(0);
    match (&terms.amount, request.amount) {
        (Some(_), None) => found.push("amount_missing"),
        (Some(a), Some(n)) => {
            if a.per_use.is_some_and(|p| n > p) {
                found.push("amount_per_use");
            }
            if spent.checked_add(n).is_none_or(|t| t > a.total) {
                found.push("amount_total");
            }
        }
        (None, Some(_)) => found.push("amount_not_allowed"),
        (None, None) => {}
    }
    if before.uses.checked_add(1).is_none_or(|u| u > terms.uses) {
        found.push("uses");
    }
    if let Some(agent) = &terms.agent
        && request.agent.as_ref() != Some(agent)
    {
        found.push("agent");
    }
    if let Some(first) = found.first() {
        return Err(first);
    }
    Ok(Totals {
        uses: before.uses.saturating_add(1),
        amount: match (&terms.amount, request.amount) {
            (Some(_), Some(n)) => Some(spent.saturating_add(n)),
            _ => None,
        },
    })
}

/// Whether the uses or the amount are used up after these totals.
pub fn exhausted(terms: &Terms, totals: &Totals) -> bool {
    totals.uses >= terms.uses
        || terms
            .amount
            .as_ref()
            .is_some_and(|a| totals.amount.unwrap_or(0) >= a.total)
}

/// A record's digest: `digestOf(record without sigs)`.
pub fn record_digest(v: &Value) -> String {
    match v.as_object() {
        Some(o) => digest_of(&Value::Object(o.without("sigs"))),
        None => digest_of(v),
    }
}

/// At least one ES256 signature in `sigs` verifies with a `mandate-attest` key.
pub fn verify_sigs(trust: &Trust, v: &Value) -> bool {
    let Some(o) = v.as_object() else {
        return false;
    };
    let input = canonical(&Value::Object(o.without("sigs")));
    o.get("sigs").and_then(Value::as_array).is_some_and(|sigs| {
        sigs.iter().any(|s| {
            let (Some(kid), Some(alg), Some(sig)) = (
                s.get("kid").and_then(Value::as_str),
                s.get("alg").and_then(Value::as_str),
                s.get("sig").and_then(Value::as_str),
            ) else {
                return false;
            };
            alg == "ES256"
                && matches!(trust.key(kid, SLOT_MANDATE_ATTEST), Some(PublicKey::Es256(k)) if k.verify(input.as_bytes(), sig))
        })
    })
}

fn jwt_part(segment: &str) -> Option<Object> {
    let bytes = b64::decode(segment)?;
    match json::parse(&bytes).ok()? {
        Value::Object(o) => Some(o),
        _ => None,
    }
}

/// The app's JWT on a use request (FORMATS.md §7).
pub fn verify_app_jwt(
    jwt: &str,
    key: &AppKey,
    app: &str,
    request: &UseRequest,
    at: i64,
) -> Result<(), Reason> {
    let parts: Vec<&str> = jwt.split('.').collect();
    let [h, p, s] = parts.as_slice() else {
        return Err(Reason::MandateAppJwtShape);
    };
    let (Some(header), Some(payload), Some(sig)) = (jwt_part(h), jwt_part(p), b64::decode(s))
    else {
        return Err(Reason::MandateAppJwtShape);
    };
    let mut signed = String::with_capacity(h.len().saturating_add(p.len()).saturating_add(1));
    signed.push_str(h);
    signed.push('.');
    signed.push_str(p);
    let verified = match (str_of(&header, "alg"), key) {
        (Some("EdDSA"), AppKey::Ed25519(x)) => {
            let (Ok(vk), Ok(sig)) = (
                ed25519_dalek::VerifyingKey::from_bytes(x),
                ed25519_dalek::Signature::from_slice(&sig),
            ) else {
                return Err(Reason::MandateAppJwtSignature);
            };
            vk.verify_strict(signed.as_bytes(), &sig).is_ok()
        }
        (Some("ES256"), AppKey::Es256(k)) => sig.len() == 64 && k.verify(signed.as_bytes(), s),
        _ => return Err(Reason::MandateAppJwtAlg),
    };
    if !verified {
        return Err(Reason::MandateAppJwtSignature);
    }
    let iss = alloc::format!("app:{app}");
    if !is_app(app)
        || str_of(&payload, "iss") != Some(iss.as_str())
        || str_of(&payload, "app_id") != Some(app)
    {
        return Err(Reason::MandateAppJwtApp);
    }
    if str_of(&payload, "aud") != Some(JWT_AUD) {
        return Err(Reason::MandateAppJwtAud);
    }
    let body = to_hex(&sha256(canonical(&request.value).as_bytes()));
    if str_of(&payload, "body_sha256") != Some(body.as_str()) {
        return Err(Reason::MandateAppJwtBody);
    }
    let time = |k: &str| {
        payload
            .get(k)
            .and_then(Value::as_number)
            .and_then(Number::as_safe_integer)
    };
    let (Some(iat), Some(exp)) = (time("iat"), time("exp")) else {
        return Err(Reason::MandateAppJwtTime);
    };
    if iat > at.saturating_add(JWT_SKEW) || exp < at.saturating_sub(JWT_SKEW) {
        return Err(Reason::MandateAppJwtTime);
    }
    Ok(())
}

/// What a grant statement says about the mandate it opens.
#[derive(Clone, Debug)]
pub struct Grant {
    pub kind: &'static str,
    pub request: String,
    pub app: String,
    pub mandate: String,
    pub terms: String,
    pub on_behalf: Option<(String, String)>,
}

/// Reads a grant statement by its type's rule.
pub fn read_grant(statement: &Value) -> Option<Grant> {
    let o = statement.as_object()?;
    let kind = match str_of(o, "type")? {
        MANDATE_GRANT_1 => MANDATE_GRANT_1,
        MANDATE_GRANT_ON_BEHALF_1 => MANDATE_GRANT_ON_BEHALF_1,
        _ => return None,
    };
    let (request, app, mandate, terms) = (
        str_of(o, "request")?,
        str_of(o, "app")?,
        str_of(o, "mandate")?,
        str_of(o, "terms")?,
    );
    if !is_app(app) || !is_uuid(mandate) || !is_digest(terms) {
        return None;
    }
    let on_behalf = if kind == MANDATE_GRANT_ON_BEHALF_1 {
        let (org, domain) = (str_of(o, "org")?, str_of(o, "domain")?);
        if !is_org(org) || !is_domain(domain) {
            return None;
        }
        Some((String::from(org), String::from(domain)))
    } else {
        None
    };
    Some(Grant {
        kind,
        request: String::from(request),
        app: String::from(app),
        mandate: String::from(mandate),
        terms: String::from(terms),
        on_behalf,
    })
}

/// The grant receipt's parts the records are checked against.
pub struct GrantContext<'a> {
    pub grant: &'a Grant,
    pub terms: &'a Terms,
    /// `digestOf(grant envelope)`, which every record names.
    pub digest: &'a str,
    pub iat: i64,
}

/// A use, after the one before it (`prev` is None for the first).
pub fn verify_use(
    trust: &Trust,
    g: &GrantContext<'_>,
    v: &Value,
    prev: Option<&Use>,
) -> Result<Use, Reason> {
    let u = parse_use(v).ok_or(Reason::MandateUseShape)?;
    if u.grant != g.digest {
        return Err(Reason::MandateGrantDigest);
    }
    if u.request.mandate != g.grant.mandate {
        return Err(Reason::MandateMismatch);
    }
    if !verify_sigs(trust, v) {
        return Err(Reason::MandateAttestSignature);
    }
    verify_app_jwt(&u.jwt, &u.key, &g.grant.app, &u.request, u.at)?;
    if u.at < g.iat {
        return Err(Reason::MandateBeforeGrant);
    }
    let in_place = match prev {
        None => u.seq == 1,
        Some(p) => {
            p.grant == u.grant
                && p.seq.checked_add(1) == Some(u.seq)
                && u.prev.as_deref() == Some(record_digest(&p.value).as_str())
                && p.at <= u.at
        }
    };
    if !in_place {
        return Err(Reason::MandateUseChain);
    }
    let before = Totals {
        uses: u.seq.saturating_sub(1),
        amount: match u.totals.amount {
            None => None,
            Some(t) => Some(t.saturating_sub(u.request.amount.unwrap_or(0))),
        },
    };
    // The first use starts from nothing; later ones start from the totals of the use before.
    // (The pre-genesis check let a first use carry an amount spent before it.)
    let started = match prev {
        None => before.amount.is_none_or(|a| a == 0),
        Some(p) => p.totals == before,
    };
    if !started
        || before.amount.is_some_and(|a| a < 0)
        || g.terms.amount.is_none() != u.totals.amount.is_none()
    {
        return Err(Reason::MandateTotals);
    }
    let totals =
        check_use(g.terms, &before, &u.request, u.at).map_err(|_| Reason::MandateOutside)?;
    if totals != u.totals {
        return Err(Reason::MandateTotals);
    }
    Ok(u)
}

/// The close, after the last use (None when there was none).
pub fn verify_close(
    trust: &Trust,
    g: &GrantContext<'_>,
    v: &Value,
    last: Option<&Use>,
) -> Result<Close, Reason> {
    let c = parse_close(v).ok_or(Reason::MandateCloseShape)?;
    if c.reason == "signer_designation_ended" && g.grant.on_behalf.is_none() {
        return Err(Reason::MandateCloseReason);
    }
    if c.grant != g.digest {
        return Err(Reason::MandateGrantDigest);
    }
    if c.mandate != g.grant.mandate {
        return Err(Reason::MandateMismatch);
    }
    if !verify_sigs(trust, v) {
        return Err(Reason::MandateAttestSignature);
    }
    if c.uses > g.terms.uses {
        return Err(Reason::MandateCloseUses);
    }
    if c.at < g.iat {
        return Err(Reason::MandateBeforeGrant);
    }
    if c.reason == "expired" && c.at != g.terms.not_after {
        return Err(Reason::MandateCloseExpired);
    }
    match last {
        Some(l) => {
            if l.grant != c.grant
                || l.seq != c.uses
                || c.last.as_deref() != Some(record_digest(&l.value).as_str())
            {
                return Err(Reason::MandateCloseLast);
            }
            if c.reason == "exhausted" && !exhausted(g.terms, &l.totals) {
                return Err(Reason::MandateCloseExhausted);
            }
        }
        None => {
            if c.uses != 0 {
                return Err(Reason::MandateCloseUses);
            }
            if c.reason == "exhausted" {
                return Err(Reason::MandateCloseExhausted);
            }
        }
    }
    Ok(c)
}

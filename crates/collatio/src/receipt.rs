//! Receipts (FORMATS.md §4, genesis.md §5.3–§5.4): the core fixed by the signer's proof, the
//! attestations that vouch for it (`accepted@1`, `ledger.receipt@1`), and the disclosures that
//! open ledger leaves (`key.opening@1`). An attestation or disclosure of an unknown type is passed
//! over unread; a known one that fails refuses the receipt.

use alloc::string::String;
use alloc::vec::Vec;

use crate::commit::{commitment, to_hex};
use crate::digest::{digest_of, is_digest, is_type_id, sha256};
use crate::dimension::{Dimension, Signer, parse_dimension};
use crate::envelope::{Envelope, is_known_extension, parse_envelope};
use crate::jcs::canonical;
use crate::json::{Number, Object, Value};
use crate::keylog::parse_key_opening;
use crate::ledger::leaf::Leaf;
use crate::logs::{Body, verify_log_note};
use crate::reason::Reason;
use crate::registry::parse_registry;
use crate::trust::{PublicKey, SLOT_SIGN_RECEIPT, Trust, first_party_shard};
use crate::webauthn::{WEBAUTHN_1, WebauthnOk, verify_webauthn1};

pub const RECEIPT_1: &str = "receipt@1";
pub const RECEIPT_APP_1: &str = "receipt.app@1";
pub const ACCEPTED_1: &str = "accepted@1";
pub const LEDGER_RECEIPT_1: &str = "ledger.receipt@1";
pub const KEY_OPENING_1: &str = "key.opening@1";
pub const RECEIPT_ANCHOR_1: &str = "receipt.anchor@1";

const MAX_ITEMS: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Holder,
    App,
}

/// What the caller expects the receipt to be for. Each member that is present must match.
#[derive(Clone, Debug, Default)]
pub struct Expect<'a> {
    pub statement: Option<&'a str>,
    pub aud: Option<&'a str>,
    pub signer: Option<&'a str>,
}

#[derive(Clone, Debug)]
pub struct LedgerPlace {
    pub log: String,
    pub index: u64,
}

#[derive(Clone, Debug)]
pub struct KeyRecord {
    pub place: LedgerPlace,
    pub at: i64,
}

#[derive(Clone, Debug)]
pub struct Verified {
    pub kind: Kind,
    pub statement: Value,
    pub envelope: Value,
    pub dimension_digest: String,
    pub dimension: Dimension,
    pub proof: Option<WebauthnOk>,
    pub accepted: Vec<(String, i64)>,
    pub anchor: LedgerPlace,
    pub key_record: Option<KeyRecord>,
}

fn has_exactly(o: &Object, keys: &[&str]) -> bool {
    o.len() == keys.len() && keys.iter().all(|k| o.get(k).is_some())
}

fn items(v: Option<&Value>, reason: Reason) -> Result<Vec<(&str, &Object)>, Reason> {
    let list = v.and_then(Value::as_array).ok_or(reason)?;
    if list.is_empty() || list.len() > MAX_ITEMS {
        return Err(reason);
    }
    list.iter()
        .map(|item| {
            let o = item.as_object().ok_or(reason)?;
            let ty = o
                .get("type")
                .and_then(Value::as_str)
                .filter(|t| is_type_id(t))
                .ok_or(reason)?;
            Ok((ty, o))
        })
        .collect()
}

/// The leaf `c` of the receipt anchor: hex(SHA-256(UTF-8(JCS({ type, envelope, proof })))).
pub fn anchor_commitment(envelope: &Value, proof_digest: &str) -> String {
    let mut o = Object::default();
    o.insert(String::from("type"), Value::from(RECEIPT_ANCHOR_1));
    o.insert(
        String::from("envelope"),
        Value::from(digest_of(envelope).as_str()),
    );
    o.insert(String::from("proof"), Value::from(proof_digest));
    to_hex(&sha256(canonical(&Value::Object(o)).as_bytes()))
}

/// Statement, envelope and dimension agree with each other, the registry and the catalog.
fn check_core(
    trust: &Trust,
    statement: &Value,
    env: &Envelope<'_>,
    dimension: &Value,
) -> Result<Dimension, Reason> {
    let dim = parse_dimension(dimension).ok_or(Reason::DimensionShape)?;
    let dim_digest = digest_of(dimension);
    if dim_digest != env.dimension {
        return Err(Reason::DimensionDigest);
    }
    if !trust.catalog.dimensions.contains(&dim_digest) {
        return Err(Reason::DimensionNotInCatalog);
    }
    if !trust.catalog.registries.contains(&dim.registry) {
        return Err(Reason::RegistryNotInCatalog);
    }
    let registry = parse_registry(&trust.registry(&dim.registry)?).ok_or(Reason::RegistryShape)?;
    let (ty, rule) = registry
        .statement(statement)
        .ok_or(Reason::StatementShape)?;
    if digest_of(statement) != env.statement {
        return Err(Reason::StatementDigest);
    }
    if !dim.statements.iter().any(|s| s == ty) {
        return Err(Reason::StatementNotInDimension);
    }
    if !dim.suites.iter().any(|s| s == env.suite) {
        return Err(Reason::SuiteNotInDimension);
    }
    if env.suite != WEBAUTHN_1 {
        return Err(Reason::SuiteUnknown);
    }
    if rule.aud(statement, env.signer).as_deref() != Some(env.aud) {
        return Err(Reason::Aud);
    }
    if !dim.ext_required.iter().all(|r| env.has_extension(r)) {
        return Err(Reason::ExtensionRequired);
    }
    if !env
        .extension_names()
        .all(|n| dim.ext_allowed.iter().any(|a| a == n))
    {
        return Err(Reason::ExtensionNotAllowed);
    }
    if !env.crit.iter().all(|c| is_known_extension(c)) {
        return Err(Reason::ExtensionUnknown);
    }
    Ok(dim)
}

fn check_expect(statement: &Value, env: &Envelope<'_>, expect: &Expect<'_>) -> Result<(), Reason> {
    let ty = statement.get("type").and_then(Value::as_str);
    if expect.statement.is_some_and(|e| ty != Some(e)) {
        return Err(Reason::ExpectStatement);
    }
    if expect.aud.is_some_and(|e| e != env.aud) {
        return Err(Reason::ExpectAud);
    }
    if expect.signer.is_some_and(|e| e != env.signer) {
        return Err(Reason::ExpectSigner);
    }
    Ok(())
}

struct Opening {
    leaf: [u8; 32],
    at: i64,
    place: Option<LedgerPlace>,
}

/// A `key.opening@1` disclosure: the record binds the receipt's key, for the envelope's rp and,
/// in `account` dimensions, its signer.
fn check_opening(
    o: &Object,
    key: &Value,
    env: &Envelope<'_>,
    dim: &Dimension,
) -> Result<Opening, Reason> {
    if !has_exactly(o, &["type", "salt", "record"]) {
        return Err(Reason::KeyOpeningShape);
    }
    let mut opening = Object::default();
    for k in ["salt", "record"] {
        opening.insert(String::from(k), o.get(k).cloned().unwrap_or(Value::Null));
    }
    let opening = Value::Object(opening);
    let (salt, record) = parse_key_opening(&opening).ok_or(Reason::KeyOpeningShape)?;
    let same = |k: &str| record.get(k).is_some() && record.get(k) == key.get(k);
    let binds = same("credential")
        && same("public_key")
        && record
            .get("alg")
            .and_then(Value::as_number)
            .and_then(Number::as_safe_integer)
            == key
                .get("alg")
                .and_then(Value::as_number)
                .and_then(Number::as_safe_integer)
        && record.get("rp").and_then(Value::as_str) == Some(env.rp)
        && (dim.signer == Signer::Pairwise
            || record.get("signer").and_then(Value::as_str) == Some(env.signer));
    if !binds {
        return Err(Reason::KeyOpeningBinding);
    }
    let c = commitment(salt, record).ok_or(Reason::KeyOpeningShape)?;
    let at = record
        .get("at")
        .and_then(Value::as_number)
        .and_then(Number::as_safe_integer)
        .ok_or(Reason::KeyOpeningShape)?;
    Ok(Opening {
        leaf: Leaf { c, slot: None }.hash(),
        at,
        place: None,
    })
}

fn check_accepted(
    trust: &Trust,
    o: &Object,
    subject: &str,
) -> Result<Option<(String, i64)>, Reason> {
    if !has_exactly(o, &["type", "subject", "at", "kid", "alg", "sig"]) {
        return Err(Reason::AcceptedShape);
    }
    let s = |k: &str| {
        o.get(k)
            .and_then(Value::as_str)
            .ok_or(Reason::AcceptedShape)
    };
    let (att_subject, kid, alg, sig) = (s("subject")?, s("kid")?, s("alg")?, s("sig")?);
    let at = o
        .get("at")
        .and_then(Value::as_number)
        .and_then(Number::as_safe_integer)
        .filter(|t| *t >= 0)
        .ok_or(Reason::AcceptedShape)?;
    if !is_digest(att_subject) {
        return Err(Reason::AcceptedShape);
    }
    if alg != "ES256" {
        // Another algorithm (a post-quantum signature added beside this one) is not read.
        return Ok(None);
    }
    if att_subject != subject {
        return Err(Reason::AcceptedSubject);
    }
    let Some(PublicKey::Es256(key)) = trust.key(kid, SLOT_SIGN_RECEIPT) else {
        return Err(Reason::AcceptedKey);
    };
    let signed = canonical(&Value::Object(o.without("sig")));
    if !key.verify(signed.as_bytes(), sig) {
        return Err(Reason::AcceptedSignature);
    }
    Ok(Some((String::from(kid), at)))
}

/// Checks a receipt of `kind`. `holder_proof`, for an app receipt, is the holder's proof the
/// caller kept; its digest must be the receipt's `proof`.
pub fn verify_receipt(
    trust: &Trust,
    evidence: &Value,
    kind: Kind,
    holder_proof: Option<&Value>,
    expect: &Expect<'_>,
) -> Result<Verified, Reason> {
    let o = evidence.as_object().ok_or(Reason::ReceiptShape)?;
    let ty = o.get("type").and_then(Value::as_str);
    let want = match kind {
        Kind::Holder => RECEIPT_1,
        Kind::App => RECEIPT_APP_1,
    };
    if ty != Some(want) {
        return Err(Reason::ReceiptType);
    }
    let (base, may_disclose): (&[&str], bool) = match kind {
        Kind::Holder => (
            &[
                "type",
                "statement",
                "envelope",
                "proof",
                "key",
                "dimension",
                "attestations",
            ],
            true,
        ),
        Kind::App => (
            &[
                "type",
                "statement",
                "envelope",
                "proof",
                "dimension",
                "attestations",
            ],
            false,
        ),
    };
    let disclosing = may_disclose && o.get("disclosures").is_some();
    if !base.iter().all(|k| o.get(k).is_some())
        || o.len() != base.len().saturating_add(usize::from(disclosing))
    {
        return Err(Reason::ReceiptShape);
    }
    let field = |k: &str| o.get(k).ok_or(Reason::ReceiptShape);
    let (statement, envelope, dimension) =
        (field("statement")?, field("envelope")?, field("dimension")?);
    let env = parse_envelope(envelope).ok_or(Reason::EnvelopeShape)?;
    let dim = check_core(trust, statement, &env, dimension)?;
    let allowed = match kind {
        Kind::Holder => dim.holder_receipts,
        Kind::App => dim.app_receipts,
    };
    if !allowed {
        return Err(Reason::ReceiptKind);
    }
    check_expect(statement, &env, expect)?;

    let (proof, proof_digest) = match kind {
        Kind::Holder => {
            let ok =
                verify_webauthn1(envelope, field("proof")?, field("key")?).map_err(Reason::from)?;
            (Some(ok), digest_of(field("proof")?))
        }
        Kind::App => {
            let d = field("proof")?
                .as_str()
                .filter(|d| is_digest(d))
                .ok_or(Reason::ReceiptShape)?;
            if holder_proof.is_some_and(|p| digest_of(p) != d) {
                return Err(Reason::HolderProof);
            }
            (None, String::from(d))
        }
    };

    let mut core = o.without("attestations");
    core = core.without("disclosures");
    let subject = digest_of(&Value::Object(core));
    let anchor_leaf = Leaf {
        c: anchor_commitment(envelope, &proof_digest),
        slot: None,
    }
    .hash();

    let mut openings: Vec<Opening> = Vec::new();
    if let Some(list) = o.get("disclosures") {
        for (ty, d) in items(Some(list), Reason::DisclosureShape)? {
            if ty == KEY_OPENING_1 {
                // One key, so at most one opening of its record.
                if !openings.is_empty() {
                    return Err(Reason::KeyOpeningShape);
                }
                openings.push(check_opening(d, field("key")?, &env, &dim)?);
            }
        }
    }

    let mut accepted = Vec::new();
    let mut anchor = None;
    for (ty, a) in items(o.get("attestations"), Reason::AttestationShape)? {
        match ty {
            ACCEPTED_1 => {
                if let Some(ok) = check_accepted(trust, a, &subject)? {
                    accepted.push(ok);
                }
            }
            LEDGER_RECEIPT_1 => {
                if !has_exactly(a, &["type", "note"]) {
                    return Err(Reason::LedgerReceiptShape);
                }
                let note = a
                    .get("note")
                    .and_then(Value::as_str)
                    .ok_or(Reason::LedgerReceiptShape)?;
                let verified = verify_log_note(trust, note)?;
                let Body::Receipt(r) = verified.body else {
                    return Err(Reason::LedgerReceiptShape);
                };
                if first_party_shard(&verified.log).is_none() {
                    return Err(Reason::LedgerReceiptLog);
                }
                let place = LedgerPlace {
                    log: verified.log,
                    index: r.index,
                };
                if r.leaf_hash == anchor_leaf {
                    anchor = Some(place);
                } else if let Some(op) = openings.iter_mut().find(|op| op.leaf == r.leaf_hash) {
                    op.place = Some(place);
                } else {
                    return Err(Reason::LedgerReceiptLeaf);
                }
            }
            _ => {}
        }
    }
    if accepted.is_empty() {
        return Err(Reason::AcceptedMissing);
    }
    let anchor = anchor.ok_or(Reason::AnchorMissing)?;
    let key_record = match openings.pop() {
        None => None,
        Some(op) => Some(KeyRecord {
            place: op.place.ok_or(Reason::KeyOpeningUnanchored)?,
            at: op.at,
        }),
    };
    Ok(Verified {
        kind,
        statement: statement.clone(),
        envelope: envelope.clone(),
        dimension_digest: String::from(env.dimension),
        dimension: dim,
        proof,
        accepted,
        anchor,
        key_record,
    })
}

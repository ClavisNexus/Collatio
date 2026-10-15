//! Signed notes from the ledger, checked against the trust chain: the origin names a log, and a
//! key that may sign it signed the note. A first-party shard or `anchor` uses the kids the
//! catalog lists for it; an Org's log, which the catalog does not list, any `ledger-log` key.

use alloc::string::String;

use crate::fields::{is_host, is_org};
use crate::ledger::note::{
    Checkpoint, RECEIPT_HEADER, Receipt, note_body, parse_checkpoint_body, parse_receipt_body,
    signer_names, verify_note,
};
use crate::reason::Reason;
use crate::trust::{Trust, is_log_id};

/// The longest note read (as the pre-genesis binding's receipt).
pub const MAX_NOTE: usize = 4096;

#[derive(Clone, Debug)]
pub enum Body {
    Checkpoint(Checkpoint),
    Receipt(Receipt),
}

#[derive(Clone, Debug)]
pub struct VerifiedNote {
    pub log: String,
    pub kid: String,
    pub body: Body,
}

/// `<host>/ledger/<log ID>` → the log ID: a first-party shard, `anchor`, or an Org ID.
pub fn origin_log(origin: &str) -> Option<&str> {
    let (host, log) = origin.rsplit_once("/ledger/")?;
    (is_host(host) && (is_log_id(log) || is_org(log))).then_some(log)
}

pub fn verify_log_note(trust: &Trust, note: &str) -> Result<VerifiedNote, Reason> {
    verify_log_note_with_body(trust, note).map(|(v, _)| v)
}

/// As [`verify_log_note`], with the signed body (signatures cover it, so anchors hash it).
pub fn verify_log_note_with_body<'a>(
    trust: &Trust,
    note: &'a str,
) -> Result<(VerifiedNote, &'a str), Reason> {
    if note.len() > MAX_NOTE {
        return Err(Reason::LedgerNoteShape);
    }
    let unverified = note_body(note).ok_or(Reason::LedgerNoteShape)?;
    let origin = match unverified.strip_prefix(RECEIPT_HEADER) {
        Some(rest) => rest.strip_prefix('\n').and_then(|r| r.split('\n').next()),
        None => unverified.split('\n').next(),
    }
    .ok_or(Reason::LedgerNoteShape)?;
    let log = origin_log(origin).ok_or(Reason::LedgerNoteLog)?;
    let names = signer_names(note);
    let (kid, key) = trust
        .log_keys(log)
        .into_iter()
        .find(|(kid, _)| names.contains(kid))
        .ok_or(Reason::LedgerNoteSigner)?;
    let signed = verify_note(note, kid, key).map_err(|_| Reason::LedgerNoteSignature)?;
    let body = if signed.starts_with(RECEIPT_HEADER) {
        Body::Receipt(parse_receipt_body(signed).ok_or(Reason::LedgerNoteShape)?)
    } else {
        Body::Checkpoint(parse_checkpoint_body(signed).ok_or(Reason::LedgerNoteShape)?)
    };
    Ok((
        VerifiedNote {
            log: String::from(log),
            kid: String::from(kid),
            body,
        },
        signed,
    ))
}

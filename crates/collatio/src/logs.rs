//! Signed notes from the ledger, checked against the trust chain: the origin names a log the
//! catalog lists, and one of that log's keys in the JWKS (`ledger-log`) signed the note.

use alloc::string::String;

use crate::fields::is_host;
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

/// `<host>/ledger/<log ID>` → the log ID.
pub fn origin_log(origin: &str) -> Option<&str> {
    let (host, log) = origin.rsplit_once("/ledger/")?;
    (is_host(host) && is_log_id(log)).then_some(log)
}

pub fn verify_log_note(trust: &Trust, note: &str) -> Result<VerifiedNote, Reason> {
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
        .find(|(kid, _)| names.contains(kid))
        .ok_or(Reason::LedgerNoteSigner)?;
    let body = verify_note(note, kid, key).map_err(|_| Reason::LedgerNoteSignature)?;
    let body = if body.starts_with(RECEIPT_HEADER) {
        Body::Receipt(parse_receipt_body(body).ok_or(Reason::LedgerNoteShape)?)
    } else {
        Body::Checkpoint(parse_checkpoint_body(body).ok_or(Reason::LedgerNoteShape)?)
    };
    Ok(VerifiedNote {
        log: String::from(log),
        kid: String::from(kid),
        body,
    })
}

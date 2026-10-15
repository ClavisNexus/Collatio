//! C2SP signed notes (Ed25519), and the two bodies the ledger signs: checkpoints and receipts.
//!
//! note = body + "\n" + one or more lines "— <name> <base64(keyhash(4) ‖ signature(64))>\n"
//! keyhash = SHA-256(name ‖ "\n" ‖ 0x01 ‖ public key)[..4]. The name is the kid of the ledger key.

use alloc::string::String;
use alloc::vec::Vec;
use base64ct::{Base64, Encoding};
use sha2::{Digest as _, Sha256};

use super::parse_safe_decimal;

const SIGNATURE_PREFIX: &str = "\u{2014} ";
const ED25519_ALG_BYTE: u8 = 0x01;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoteError {
    Malformed,
    PublicKeyInvalid,
    SignatureLineMalformed,
    SignatureEncoding,
    SignatureInvalid,
    SignerNotFound,
}

impl NoteError {
    pub fn as_str(self) -> &'static str {
        match self {
            NoteError::Malformed => "note_malformed",
            NoteError::PublicKeyInvalid => "note_public_key_invalid",
            NoteError::SignatureLineMalformed => "note_signature_line_malformed",
            NoteError::SignatureEncoding => "note_signature_encoding",
            NoteError::SignatureInvalid => "note_signature_invalid",
            NoteError::SignerNotFound => "note_signer_not_found",
        }
    }
}

pub fn key_hash(name: &str, public_key: &[u8; 32]) -> [u8; 4] {
    let mut h = Sha256::new();
    h.update(name.as_bytes());
    h.update(b"\n");
    h.update([ED25519_ALG_BYTE]);
    h.update(public_key);
    let d = h.finalize();
    let mut out = [0u8; 4];
    for (o, b) in out.iter_mut().zip(d.iter()) {
        *o = *b;
    }
    out
}

/// The body (up to and including the newline before the signature block), or `None`.
pub fn note_body(note: &str) -> Option<&str> {
    let sep = note.rfind("\n\n")?;
    note.get(..sep.checked_add(1)?)
}

/// The names on the signature lines, in order.
pub fn signer_names(note: &str) -> Vec<&str> {
    let Some(sep) = note.rfind("\n\n") else {
        return Vec::new();
    };
    let block = note.get(sep.saturating_add(2)..).unwrap_or("");
    block
        .split('\n')
        .filter_map(|line| line.strip_prefix(SIGNATURE_PREFIX))
        .filter_map(|rest| rest.rfind(' ').and_then(|sp| rest.get(..sp)))
        .collect()
}

/// Checks the note's signature by `name` with `public_key`; returns the body.
pub fn verify_note<'a>(
    note: &'a str,
    name: &str,
    public_key: &[u8; 32],
) -> Result<&'a str, NoteError> {
    let sep = note.rfind("\n\n").ok_or(NoteError::Malformed)?;
    let body = note
        .get(..sep.saturating_add(1))
        .ok_or(NoteError::Malformed)?;
    let block = note
        .get(sep.saturating_add(2)..)
        .ok_or(NoteError::Malformed)?;
    let lines = block.strip_suffix('\n').ok_or(NoteError::Malformed)?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(public_key)
        .map_err(|_| NoteError::PublicKeyInvalid)?;
    let want = key_hash(name, public_key);
    for line in lines.split('\n') {
        let rest = line
            .strip_prefix(SIGNATURE_PREFIX)
            .ok_or(NoteError::SignatureLineMalformed)?;
        let sp = rest.rfind(' ').ok_or(NoteError::SignatureLineMalformed)?;
        let (line_name, encoded) = (
            rest.get(..sp).unwrap_or(""),
            rest.get(sp.saturating_add(1)..).unwrap_or(""),
        );
        if line_name != name {
            continue;
        }
        let raw = Base64::decode_vec(encoded).map_err(|_| NoteError::SignatureEncoding)?;
        let (Some(hash), Some(sig)) = (raw.get(..4), raw.get(4..)) else {
            continue;
        };
        if raw.len() != 68 || hash != want {
            continue;
        }
        let sig =
            ed25519_dalek::Signature::from_slice(sig).map_err(|_| NoteError::SignatureInvalid)?;
        return key
            .verify_strict(body.as_bytes(), &sig)
            .map(|()| body)
            .map_err(|_| NoteError::SignatureInvalid);
    }
    Err(NoteError::SignerNotFound)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub origin: String,
    pub size: u64,
    pub root: [u8; 32],
    /// Unix seconds. In the ledger only checkpoints carry time.
    pub time: u64,
}

fn root32(b64: &str) -> Option<[u8; 32]> {
    Base64::decode_vec(b64).ok()?.as_slice().try_into().ok()
}

/// `<origin>\n<size>\n<base64 root>\ntime <unix seconds>\n`
pub fn parse_checkpoint_body(body: &str) -> Option<Checkpoint> {
    let lines: Vec<&str> = body.split('\n').collect();
    let [origin, size, root, time, ""] = lines.as_slice() else {
        return None;
    };
    if origin.is_empty() {
        return None;
    }
    Some(Checkpoint {
        origin: String::from(*origin),
        size: parse_safe_decimal(size)?,
        root: root32(root)?,
        time: parse_safe_decimal(time.strip_prefix("time ")?)?,
    })
}

pub const RECEIPT_HEADER: &str = "clavis.ledger.receipt/v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub origin: String,
    pub index: u64,
    pub leaf_hash: [u8; 32],
}

/// `clavis.ledger.receipt/v1\n<origin>\n<index>\n<base64 leaf hash>\n`
pub fn parse_receipt_body(body: &str) -> Option<Receipt> {
    let lines: Vec<&str> = body.split('\n').collect();
    let [RECEIPT_HEADER, origin, index, leaf, ""] = lines.as_slice() else {
        return None;
    };
    if origin.is_empty() {
        return None;
    }
    Some(Receipt {
        origin: String::from(*origin),
        index: parse_safe_decimal(index)?,
        leaf_hash: root32(leaf)?,
    })
}

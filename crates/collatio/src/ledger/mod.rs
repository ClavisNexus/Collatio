//! The ledger: signed notes (checkpoints and receipts), leaves and Merkle proofs.

pub mod leaf;
pub mod merkle;
pub mod note;

/// A decimal written without leading zeros, at most 2^53 − 1 (what every reader holds exactly).
pub(crate) fn parse_safe_decimal(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0'))
    {
        return None;
    }
    let n: u64 = s.parse().ok()?;
    (n <= crate::json::MAX_SAFE_INTEGER.unsigned_abs()).then_some(n)
}

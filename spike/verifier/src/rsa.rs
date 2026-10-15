//! RSASSA-PKCS1-v1_5 verification (RFC 8017 §8.2.2) on crypto-bigint.
//!
//! Public-key operation only, so variable time is fine. The `rsa` crate is not
//! used (RUSTSEC-2023-0071, genesis.md §18.8).

use alloc::vec::Vec;
use crypto_bigint::modular::{BoxedMontyForm, BoxedMontyParams};
use crypto_bigint::{BoxedUint, Odd};
use sha2::Digest;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hash {
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    /// DER of DigestInfo up to (but not including) the digest bytes (RFC 8017 §9.2 note 1).
    fn prefix(self) -> &'static [u8] {
        match self {
            Hash::Sha256 => &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20,
            ],
            Hash::Sha384 => &[
                0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x02, 0x05, 0x00, 0x04, 0x30,
            ],
            Hash::Sha512 => &[
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x03, 0x05, 0x00, 0x04, 0x40,
            ],
        }
    }

    fn digest(self, msg: &[u8]) -> Vec<u8> {
        match self {
            Hash::Sha256 => sha2::Sha256::digest(msg).to_vec(),
            Hash::Sha384 => sha2::Sha384::digest(msg).to_vec(),
            Hash::Sha512 => sha2::Sha512::digest(msg).to_vec(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum RsaError {
    /// Modulus or exponent outside the accepted range.
    Key,
    /// Signature length differs from the modulus length, or s >= n.
    Length,
    /// Encoded message does not match.
    Mismatch,
}

/// Accepted modulus sizes. TSA and CA keys in use are 2048–4096 bits.
const MIN_BITS: usize = 2048;
const MAX_BITS: usize = 4096;

fn trim(bytes: &[u8]) -> &[u8] {
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[first..]
}

pub fn verify(n: &[u8], e: &[u8], msg: &[u8], sig: &[u8], hash: Hash) -> Result<(), RsaError> {
    let n = trim(n);
    let e = trim(e);
    let k = n.len();
    let n_bits = k * 8 - n.first().map_or(8, |b| b.leading_zeros() as usize);
    if !(MIN_BITS..=MAX_BITS).contains(&n_bits) {
        return Err(RsaError::Key);
    }
    // e: odd, 3 <= e < 2^32 (keeps pow_bounded_exp cheap; real keys use 65537).
    if e.is_empty() || e.len() > 4 || e[e.len() - 1] & 1 == 0 || (e.len() == 1 && e[0] < 3) {
        return Err(RsaError::Key);
    }
    if sig.len() != k {
        return Err(RsaError::Length);
    }

    let precision = (k * 8) as u32;
    let modulus = BoxedUint::from_be_slice(n, precision).map_err(|_| RsaError::Key)?;
    let modulus: Odd<BoxedUint> = Option::from(Odd::new(modulus)).ok_or(RsaError::Key)?;
    let s = BoxedUint::from_be_slice(sig, precision).map_err(|_| RsaError::Length)?;
    if &s >= modulus.as_ref() {
        return Err(RsaError::Length);
    }
    let exponent = BoxedUint::from_be_slice(e, 32).map_err(|_| RsaError::Key)?;

    let params = BoxedMontyParams::new_vartime(modulus);
    let m = BoxedMontyForm::new(s, &params)
        .pow_bounded_exp(&exponent, 32)
        .retrieve();
    let em_full = m.to_be_bytes();
    // The precision is limb-aligned, so the encoding may be longer than k; m < n, so the extra
    // leading bytes are zero.
    let em = &em_full[em_full.len() - k..];
    if em_full[..em_full.len() - k].iter().any(|&b| b != 0) {
        return Err(RsaError::Mismatch);
    }

    let prefix = hash.prefix();
    let digest = hash.digest(msg);
    let t_len = prefix.len() + digest.len();
    if k < t_len + 11 {
        return Err(RsaError::Key);
    }
    let ps_len = k - t_len - 3;
    let mut expected = Vec::with_capacity(k);
    expected.push(0x00);
    expected.push(0x01);
    expected.resize(2 + ps_len, 0xff);
    expected.push(0x00);
    expected.extend_from_slice(prefix);
    expected.extend_from_slice(&digest);
    if em == expected.as_slice() {
        Ok(())
    } else {
        Err(RsaError::Mismatch)
    }
}

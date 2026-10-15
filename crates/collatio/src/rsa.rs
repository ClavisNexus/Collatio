//! RSASSA-PKCS1-v1_5 verification (RFC 8017 §8.2.2) on crypto-bigint.
//!
//! Only what TSA tokens need: moduli of 2048–4096 bits, public exponent 65537, SHA-256/384/512.
//! The expected encoding `00 01 FF…FF 00 ‖ DigestInfo ‖ hash` is built and compared whole, so no
//! lenient parsing of the decoded block can be abused. This is a public-key operation, so it does
//! not need to be constant time. The `rsa` crate is not used (RUSTSEC-2023-0071).

use alloc::vec::Vec;
use crypto_bigint::modular::{BoxedMontyForm, BoxedMontyParams};
use crypto_bigint::{BoxedUint, Odd};
use sha2::Digest as _;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hash {
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    /// DigestInfo DER before the digest bytes (RFC 8017 §9.2, note 1).
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

    pub fn digest(self, msg: &[u8]) -> Vec<u8> {
        match self {
            Hash::Sha256 => sha2::Sha256::digest(msg).to_vec(),
            Hash::Sha384 => sha2::Sha384::digest(msg).to_vec(),
            Hash::Sha512 => sha2::Sha512::digest(msg).to_vec(),
        }
    }

    /// The hash an OID names (`id-sha256` etc.).
    pub fn from_oid(oid: &str) -> Option<Hash> {
        match oid {
            "2.16.840.1.101.3.4.2.1" => Some(Hash::Sha256),
            "2.16.840.1.101.3.4.2.2" => Some(Hash::Sha384),
            "2.16.840.1.101.3.4.2.3" => Some(Hash::Sha512),
            _ => None,
        }
    }
}

pub struct PublicKey<'a> {
    /// Modulus, big-endian, without leading zeros.
    pub n: &'a [u8],
    pub e: &'a [u8],
}

const MIN_BITS: usize = 2048;
const MAX_BITS: usize = 4096;

/// Checks a signature over the digest of `msg`.
pub fn verify(key: &PublicKey<'_>, msg: &[u8], sig: &[u8], hash: Hash) -> bool {
    verify_digest(key, &hash.digest(msg), sig, hash)
}

/// Checks a signature over an already computed digest.
pub fn verify_digest(key: &PublicKey<'_>, digest: &[u8], sig: &[u8], hash: Hash) -> bool {
    let n = crate::der::unsigned(key.n);
    let e = crate::der::unsigned(key.e);
    if e != [0x01, 0x00, 0x01] {
        return false;
    }
    let k = n.len();
    let n_bits = k
        .saturating_mul(8)
        .saturating_sub(n.first().map_or(8, |b| b.leading_zeros() as usize));
    if !(MIN_BITS..=MAX_BITS).contains(&n_bits) || sig.len() != k {
        return false;
    }
    let Ok(precision) = u32::try_from(k.saturating_mul(8)) else {
        return false;
    };
    let Ok(modulus) = BoxedUint::from_be_slice(n, precision) else {
        return false;
    };
    let Some(modulus) = Option::<Odd<BoxedUint>>::from(Odd::new(modulus)) else {
        return false;
    };
    let Ok(s) = BoxedUint::from_be_slice(sig, precision) else {
        return false;
    };
    if s >= *modulus.as_ref() {
        return false;
    }
    let Ok(exponent) = BoxedUint::from_be_slice(e, 32) else {
        return false;
    };
    let params = BoxedMontyParams::new_vartime(modulus);
    let m = BoxedMontyForm::new(s, &params)
        .pow_bounded_exp(&exponent, 17)
        .retrieve();
    let em_full = m.to_be_bytes();
    let Some(split) = em_full.len().checked_sub(k) else {
        return false;
    };
    let (Some(extra), Some(em)) = (em_full.get(..split), em_full.get(split..)) else {
        return false;
    };
    if extra.iter().any(|&b| b != 0) {
        return false;
    }
    let prefix = hash.prefix();
    let t_len = prefix.len().saturating_add(digest.len());
    let Some(ps_len) = k.checked_sub(t_len.saturating_add(3)) else {
        return false;
    };
    if ps_len < 8 {
        return false;
    }
    let mut expected = Vec::with_capacity(k);
    expected.extend_from_slice(&[0x00, 0x01]);
    expected.resize(ps_len.saturating_add(2), 0xff);
    expected.push(0x00);
    expected.extend_from_slice(prefix);
    expected.extend_from_slice(digest);
    em == expected.as_slice()
}

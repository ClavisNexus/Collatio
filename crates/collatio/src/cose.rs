//! COSE public keys (WebAuthn `credentialPublicKey`) and the signatures they check.
//!
//! Only ES256 (EC2 P-256, alg −7) and EdDSA (OKP Ed25519, alg −8) are accepted. The CBOR reader
//! takes what a COSE key needs and nothing more: definite lengths up to 32 bits, integers, byte
//! and text strings, arrays, maps with integer or text keys and no repeated key, `false`, `true`,
//! `null`, depth at most 8, and no trailing bytes.

use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, Debug, PartialEq)]
enum Cbor {
    Int(i64),
    Bytes(Vec<u8>),
    Text(String),
    Bool(bool),
    Null,
    Array(Vec<Cbor>),
    Map(Vec<(Key, Cbor)>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Key {
    Int(i64),
    Text(String),
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn byte(&mut self) -> Option<u8> {
        let b = *self.bytes.get(self.pos)?;
        self.pos = self.pos.checked_add(1)?;
        Some(b)
    }

    fn take(&mut self, n: usize) -> Option<&[u8]> {
        let end = self.pos.checked_add(n)?;
        let out = self.bytes.get(self.pos..end)?;
        self.pos = end;
        Some(out)
    }

    fn arg(&mut self, info: u8) -> Option<u64> {
        match info {
            0..=23 => Some(u64::from(info)),
            24 => self.byte().map(u64::from),
            25 => {
                let b = self.take(2)?;
                Some(u64::from(u16::from_be_bytes([*b.first()?, *b.get(1)?])))
            }
            26 => {
                let b = self.take(4)?;
                Some(u64::from(u32::from_be_bytes([
                    *b.first()?,
                    *b.get(1)?,
                    *b.get(2)?,
                    *b.get(3)?,
                ])))
            }
            _ => None,
        }
    }

    fn len(&mut self, info: u8) -> Option<usize> {
        usize::try_from(self.arg(info)?).ok()
    }

    fn value(&mut self, depth: u8) -> Option<Cbor> {
        if depth > 8 {
            return None;
        }
        let head = self.byte()?;
        let major = head >> 5;
        let info = head & 0x1f;
        match major {
            0 => Some(Cbor::Int(i64::try_from(self.arg(info)?).ok()?)),
            1 => {
                let n = i64::try_from(self.arg(info)?).ok()?;
                Some(Cbor::Int((-1_i64).checked_sub(n)?))
            }
            2 => {
                let n = self.len(info)?;
                Some(Cbor::Bytes(self.take(n)?.to_vec()))
            }
            3 => {
                let n = self.len(info)?;
                let text = core::str::from_utf8(self.take(n)?).ok()?;
                Some(Cbor::Text(String::from(text)))
            }
            4 => {
                let n = self.len(info)?;
                let mut items = Vec::new();
                for _ in 0..n {
                    items.push(self.value(depth.checked_add(1)?)?);
                }
                Some(Cbor::Array(items))
            }
            5 => {
                let n = self.len(info)?;
                let mut entries: Vec<(Key, Cbor)> = Vec::new();
                for _ in 0..n {
                    let key = match self.value(depth.checked_add(1)?)? {
                        Cbor::Int(i) => Key::Int(i),
                        Cbor::Text(t) => Key::Text(t),
                        _ => return None,
                    };
                    if entries.iter().any(|(k, _)| *k == key) {
                        return None;
                    }
                    let value = self.value(depth.checked_add(1)?)?;
                    entries.push((key, value));
                }
                Some(Cbor::Map(entries))
            }
            7 => match info {
                20 => Some(Cbor::Bool(false)),
                21 => Some(Cbor::Bool(true)),
                22 => Some(Cbor::Null),
                _ => None,
            },
            _ => None,
        }
    }
}

fn decode(bytes: &[u8]) -> Option<Cbor> {
    let mut r = Reader { bytes, pos: 0 };
    let v = r.value(0)?;
    if r.pos != bytes.len() {
        return None;
    }
    Some(v)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoseKey {
    Es256 { x: [u8; 32], y: [u8; 32] },
    EdDsa { x: [u8; 32] },
}

impl CoseKey {
    /// The COSE algorithm number.
    pub fn alg(&self) -> i64 {
        match self {
            CoseKey::Es256 { .. } => -7,
            CoseKey::EdDsa { .. } => -8,
        }
    }
}

fn bytes32(v: Option<&Cbor>) -> Option<[u8; 32]> {
    match v {
        Some(Cbor::Bytes(b)) => b.as_slice().try_into().ok(),
        _ => None,
    }
}

/// Reads a COSE key. Members other than kty (1), alg (3), crv (−1), x (−2) and y (−3) are ignored.
pub fn parse_cose_key(bytes: &[u8]) -> Option<CoseKey> {
    let Cbor::Map(entries) = decode(bytes)? else {
        return None;
    };
    let get = |k: i64| {
        entries
            .iter()
            .find(|(key, _)| *key == Key::Int(k))
            .map(|(_, v)| v)
    };
    let int = |k: i64| match get(k) {
        Some(Cbor::Int(i)) => Some(*i),
        _ => None,
    };
    match (int(1), int(3), int(-1)) {
        (Some(2), Some(-7), Some(1)) => Some(CoseKey::Es256 {
            x: bytes32(get(-2))?,
            y: bytes32(get(-3))?,
        }),
        (Some(1), Some(-8), Some(6)) => Some(CoseKey::EdDsa {
            x: bytes32(get(-2))?,
        }),
        _ => None,
    }
}

/// ES256 DER signature → r‖s. The integers are read as unsigned and their leading zeros dropped
/// (authenticators are not always minimal); each must fit in 32 bytes.
pub fn der_to_raw_ecdsa(der: &[u8]) -> Option<[u8; 64]> {
    let mut r = Reader { bytes: der, pos: 0 };
    if r.byte()? != 0x30 {
        return None;
    }
    let len = r.byte()?;
    if len & 0x80 != 0 || usize::from(len) != der.len().checked_sub(2)? {
        return None;
    }
    let mut out = [0u8; 64];
    for half in 0..2usize {
        if r.byte()? != 0x02 {
            return None;
        }
        let n = usize::from(r.byte()?);
        if n == 0 || n > 33 {
            return None;
        }
        let int = r.take(n)?;
        let first = int
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(int.len().saturating_sub(1));
        let int = int.get(first..)?;
        if int.len() > 32 {
            return None;
        }
        let start = half
            .checked_mul(32)?
            .checked_add(32usize.checked_sub(int.len())?)?;
        let end = half.checked_mul(32)?.checked_add(32)?;
        out.get_mut(start..end)?.copy_from_slice(int);
    }
    if r.pos != der.len() {
        return None;
    }
    Some(out)
}

/// Checks `signature` over `data` with the key. A malformed key or signature is a failed check.
pub fn verify_signature(key: &CoseKey, signature: &[u8], data: &[u8]) -> bool {
    match key {
        CoseKey::Es256 { x, y } => {
            use p256::ecdsa::signature::Verifier;
            use p256::ecdsa::{Signature, VerifyingKey};
            let Some(raw) = der_to_raw_ecdsa(signature) else {
                return false;
            };
            let mut sec1 = Vec::with_capacity(65);
            sec1.push(0x04);
            sec1.extend_from_slice(x);
            sec1.extend_from_slice(y);
            let (Ok(vk), Ok(sig)) = (
                VerifyingKey::from_sec1_bytes(&sec1),
                Signature::from_slice(&raw),
            ) else {
                return false;
            };
            vk.verify(data, &sig).is_ok()
        }
        CoseKey::EdDsa { x } => {
            use ed25519_dalek::{Signature, VerifyingKey};
            let (Ok(vk), Ok(sig)) = (
                VerifyingKey::from_bytes(x),
                Signature::from_slice(signature),
            ) else {
                return false;
            };
            vk.verify_strict(data, &sig).is_ok()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cbor_limits() {
        assert_eq!(decode(&[0x01]), Some(Cbor::Int(1)));
        assert_eq!(decode(&[0x20]), Some(Cbor::Int(-1)));
        assert_eq!(decode(&[0x01, 0x00]), None); // trailing byte
        assert_eq!(decode(&[0xa2, 0x01, 0x01, 0x01, 0x02]), None); // repeated key
        assert_eq!(decode(&[0x1b, 0, 0, 0, 0, 0, 0, 0, 1]), None); // 64-bit argument
        assert_eq!(decode(&[0x5f]), None); // indefinite length
        assert_eq!(decode(&[0xc0, 0x01]), None); // tag
        assert_eq!(decode(&[0xf9, 0x3c, 0x00]), None); // float
    }

    #[test]
    fn der() {
        // Non-minimal leading zeros are tolerated; long-form length is not.
        let mut der = vec![0x30, 0x46, 0x02, 0x21, 0x00];
        der.extend([1u8; 32]);
        der.extend([0x02, 0x21, 0x00]);
        der.extend([2u8; 32]);
        let raw = der_to_raw_ecdsa(&der).unwrap();
        assert_eq!(&raw[..32], &[1u8; 32]);
        assert_eq!(&raw[32..], &[2u8; 32]);
        der[1] = 0x81;
        assert_eq!(der_to_raw_ecdsa(&der), None);
    }
}

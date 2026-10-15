//! X.509 certificates, read as far as TSA chains need: the signed part, the signature, names,
//! validity, the RSA public key and the extensions.

use alloc::vec::Vec;

use crate::der::{
    self, BIT_STRING, BOOLEAN, INTEGER, OCTET_STRING, OID, Reader, SEQUENCE, Tlv, context,
};
use crate::rsa::{self, Hash, PublicKey};

pub const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
pub const SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";
pub const SHA384_WITH_RSA: &str = "1.2.840.113549.1.1.12";
pub const SHA512_WITH_RSA: &str = "1.2.840.113549.1.1.13";

pub const EXT_SUBJECT_KEY_IDENTIFIER: &str = "2.5.29.14";
pub const EXT_KEY_USAGE: &str = "2.5.29.15";
pub const EXT_SUBJECT_ALT_NAME: &str = "2.5.29.17";
pub const EXT_BASIC_CONSTRAINTS: &str = "2.5.29.19";
pub const EXT_EXT_KEY_USAGE: &str = "2.5.29.37";

#[derive(Clone, Debug)]
pub struct Extension<'a> {
    pub oid: alloc::string::String,
    pub critical: bool,
    /// The content of extnValue.
    pub value: &'a [u8],
}

#[derive(Clone, Debug)]
pub struct Certificate<'a> {
    pub raw: &'a [u8],
    pub tbs: &'a [u8],
    pub signature_algorithm: alloc::string::String,
    pub signature: &'a [u8],
    pub serial: &'a [u8],
    /// DER of the issuer Name.
    pub issuer: &'a [u8],
    /// DER of the subject Name.
    pub subject: &'a [u8],
    pub not_before: i64,
    pub not_after: i64,
    pub key_algorithm: alloc::string::String,
    /// The subjectPublicKey bits (for RSA, the DER of RSAPublicKey).
    pub key: &'a [u8],
    pub extensions: Vec<Extension<'a>>,
}

/// AlgorithmIdentifier → its OID; parameters are not read.
pub fn algorithm(r: &mut Reader<'_>) -> Option<alloc::string::String> {
    let mut alg = r.nested(SEQUENCE)?;
    der::oid_string(alg.expect(OID)?.value)
}

/// The content of a BIT STRING with no unused bits.
pub fn bit_string_bytes<'a>(t: &Tlv<'a>) -> Option<&'a [u8]> {
    if t.tag != BIT_STRING {
        return None;
    }
    let (&unused, rest) = t.value.split_first()?;
    (unused == 0).then_some(rest)
}

/// A Name: SEQUENCE OF non-empty SET OF SEQUENCE { OID, value }. Kept as raw bytes, but the
/// structure is checked so a malformed name is not carried along unread.
fn is_name(t: &Tlv<'_>) -> bool {
    if t.tag != SEQUENCE {
        return false;
    }
    let mut rdns = Reader::new(t.value);
    while !rdns.is_empty() {
        let Some(mut set) = rdns.nested(der::SET) else {
            return false;
        };
        if set.is_empty() {
            return false;
        }
        while !set.is_empty() {
            let Some(mut atv) = set.nested(SEQUENCE) else {
                return false;
            };
            let oid_ok = atv
                .expect(OID)
                .and_then(|o| der::oid_string(o.value))
                .is_some();
            if !oid_ok || atv.any().is_none() || !atv.is_empty() {
                return false;
            }
        }
    }
    true
}

pub fn parse(raw: &[u8]) -> Option<Certificate<'_>> {
    let cert = der::single(raw)?;
    if cert.tag != SEQUENCE {
        return None;
    }
    let mut c = Reader::new(cert.value);
    let tbs = c.expect(SEQUENCE)?;
    let signature_algorithm = algorithm(&mut c)?;
    let signature = bit_string_bytes(&c.expect(BIT_STRING)?)?;
    if !c.is_empty() {
        return None;
    }

    let mut t = Reader::new(tbs.value);
    if t.peek_tag() == Some(context(0)) {
        t.any()?; // version
    }
    let serial = t.expect(INTEGER)?.value;
    let _inner_algorithm = algorithm(&mut t)?;
    let issuer = t.expect(SEQUENCE).filter(is_name)?.raw;
    let mut validity = t.nested(SEQUENCE)?;
    let not_before = der::time(&validity.any()?)?;
    let not_after = der::time(&validity.any()?)?;
    let subject = t.expect(SEQUENCE).filter(is_name)?.raw;
    let mut spki = t.nested(SEQUENCE)?;
    let key_algorithm = algorithm(&mut spki)?;
    let key = bit_string_bytes(&spki.expect(BIT_STRING)?)?;
    let mut extensions = Vec::new();
    while !t.is_empty() {
        let field = t.any()?;
        if field.tag != context(3) {
            continue; // issuerUniqueID / subjectUniqueID
        }
        let mut list = Reader::new(field.value).nested(SEQUENCE)?;
        while !list.is_empty() {
            let mut ext = list.nested(SEQUENCE)?;
            let oid = der::oid_string(ext.expect(OID)?.value)?;
            let critical = match ext.optional(BOOLEAN) {
                Some(b) => b.value.first().copied().unwrap_or(0) != 0,
                None => false,
            };
            let value = ext.expect(OCTET_STRING)?.value;
            extensions.push(Extension {
                oid,
                critical,
                value,
            });
        }
    }
    Some(Certificate {
        raw,
        tbs: tbs.raw,
        signature_algorithm,
        signature,
        serial,
        issuer,
        subject,
        not_before,
        not_after,
        key_algorithm,
        key,
        extensions,
    })
}

impl<'a> Certificate<'a> {
    pub fn extension(&self, oid: &str) -> Option<&Extension<'a>> {
        self.extensions.iter().find(|e| e.oid == oid)
    }

    /// The RSA public key, when the key is RSA.
    pub fn rsa_key(&self) -> Option<PublicKey<'a>> {
        if self.key_algorithm != RSA_ENCRYPTION {
            return None;
        }
        let mut r = der::single(self.key)
            .filter(|t| t.tag == SEQUENCE)
            .map(|t| Reader::new(t.value))?;
        let n = r.expect(INTEGER)?.value;
        let e = r.expect(INTEGER)?.value;
        r.is_empty().then_some(PublicKey { n, e })
    }

    /// Whether `issuer`'s key verifies this certificate's signature.
    pub fn signed_by(&self, issuer: &Certificate<'_>) -> bool {
        let hash = match self.signature_algorithm.as_str() {
            SHA256_WITH_RSA => Hash::Sha256,
            SHA384_WITH_RSA => Hash::Sha384,
            SHA512_WITH_RSA => Hash::Sha512,
            _ => return false,
        };
        issuer
            .rsa_key()
            .is_some_and(|key| rsa::verify(&key, self.tbs, self.signature, hash))
    }

    /// basicConstraints cA = TRUE.
    pub fn is_ca(&self) -> bool {
        let Some(ext) = self.extension(EXT_BASIC_CONSTRAINTS) else {
            return false;
        };
        let Some(mut r) = der::single(ext.value)
            .filter(|t| t.tag == SEQUENCE)
            .map(|t| Reader::new(t.value))
        else {
            return false;
        };
        r.optional(BOOLEAN)
            .is_some_and(|b| b.value.first().copied().unwrap_or(0) != 0)
    }

    /// keyUsage bits (the BIT STRING content after the unused-bits byte), when present.
    pub fn key_usage(&self) -> Option<&'a [u8]> {
        let ext = self.extension(EXT_KEY_USAGE)?;
        let t = der::single(ext.value)?;
        if t.tag != BIT_STRING {
            return None;
        }
        t.value.get(1..)
    }

    pub fn valid_at(&self, t: i64) -> bool {
        self.not_before <= t && t <= self.not_after
    }
}

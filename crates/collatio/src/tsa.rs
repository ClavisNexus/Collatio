//! RFC 3161 time-stamp tokens.
//!
//! A token counts only when all of these hold:
//! - the CMS signature verifies and the signer's chain reaches a root in the trust registry,
//!   with every certificate valid at genTime (revocation is not checked);
//! - the signer certificate is for time stamping only (critical EKU with only id-kp-timeStamping;
//!   key usage, when present, digitalSignature and/or nonRepudiation only);
//! - a signingCertificate / signingCertificateV2 attribute points at the signer certificate;
//! - TSTInfo's policy is one the registry accepts, its imprint is the SHA-256 of the message, and
//!   its nonce is the requested one when a nonce is expected.
//!
//! The order of checks and the reason names follow the TypeScript implementation this replaces.

use alloc::string::String;
use alloc::vec::Vec;
use sha2::Digest as _;

use crate::der::{
    self, BOOLEAN, GENERALIZED_TIME, INTEGER, OCTET_STRING, OID, Reader, SEQUENCE, SET, Tlv,
    context,
};
use crate::rsa::{self, Hash};
use crate::x509::{self, Certificate};

const SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
const TST_INFO: &str = "1.2.840.113549.1.9.16.1.4";
const SHA256: &str = "2.16.840.1.101.3.4.2.1";
const KP_TIME_STAMPING: &str = "1.3.6.1.5.5.7.3.8";
const AA_SIGNING_CERTIFICATE: &str = "1.2.840.113549.1.9.16.2.12";
const AA_SIGNING_CERTIFICATE_V2: &str = "1.2.840.113549.1.9.16.2.47";
const AA_CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
const AA_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";

/// A trusted TSA: the policies it signs under and its self-signed roots (DER).
pub struct TsaTrust<'a> {
    pub id: &'a str,
    pub policies: &'a [&'a str],
    pub roots: &'a [&'a [u8]],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TsaReject {
    /// Not a TimeStampResp, not granted, or no token.
    RespInvalid,
    /// The CMS structure, the number of signers, or finding the signer certificate.
    CmsInvalid,
    TstInvalid,
    ImprintMismatch,
    NonceMismatch,
    SignerNotTimestamping,
    SigningCertificateMismatch,
    NameMismatch,
    PolicyMismatch,
    /// The signature does not verify or the chain does not reach a registry root.
    ChainUntrusted,
}

impl TsaReject {
    pub fn as_str(self) -> &'static str {
        match self {
            TsaReject::RespInvalid => "tsa_resp_invalid",
            TsaReject::CmsInvalid => "tsa_cms_invalid",
            TsaReject::TstInvalid => "tsa_tst_invalid",
            TsaReject::ImprintMismatch => "tsa_imprint_mismatch",
            TsaReject::NonceMismatch => "tsa_nonce_mismatch",
            TsaReject::SignerNotTimestamping => "tsa_signer_not_timestamping",
            TsaReject::SigningCertificateMismatch => "tsa_signing_certificate_mismatch",
            TsaReject::NameMismatch => "tsa_name_mismatch",
            TsaReject::PolicyMismatch => "tsa_policy_mismatch",
            TsaReject::ChainUntrusted => "tsa_chain_untrusted",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TsaOk {
    /// The registry entry that the chain reached.
    pub tsa: String,
    pub policy: String,
    /// genTime, Unix seconds.
    pub gen_time: i64,
}

struct TstInfo<'a> {
    policy: String,
    imprint_algorithm: String,
    imprint: &'a [u8],
    gen_time: i64,
    nonce: Option<&'a [u8]>,
    /// The GeneralName inside `tsa [0] EXPLICIT`.
    tsa: Option<Tlv<'a>>,
}

struct SignerInfo<'a> {
    sid: Tlv<'a>,
    digest_algorithm: String,
    signed_attrs: Option<Tlv<'a>>,
    signature_algorithm: String,
    signature: &'a [u8],
}

struct SignedData<'a> {
    content_type: String,
    content: Vec<u8>,
    certificates: Vec<Certificate<'a>>,
    signers: Vec<SignerInfo<'a>>,
}

fn token_of(der_bytes: &[u8]) -> Option<Tlv<'_>> {
    let outer = der::single(der_bytes)?;
    if outer.tag != SEQUENCE {
        return None;
    }
    let mut r = Reader::new(outer.value);
    let mut status = r.nested(SEQUENCE)?;
    let code = der::small_int(&status.expect(INTEGER)?)?;
    if code != 0 && code != 1 {
        return None;
    }
    r.expect(SEQUENCE)
}

fn signed_data<'a>(token: &Tlv<'a>) -> Option<SignedData<'a>> {
    let mut ci = Reader::new(token.value);
    if der::oid_string(ci.expect(OID)?.value)? != SIGNED_DATA {
        return None;
    }
    let mut sd = Reader::new(ci.expect(context(0))?.value).nested(SEQUENCE)?;
    sd.expect(INTEGER)?;
    sd.expect(SET)?;
    let mut encap = sd.nested(SEQUENCE)?;
    let content_type = der::oid_string(encap.expect(OID)?.value)?;
    let content = match encap.optional(context(0)) {
        Some(explicit) => der::octets(&der::single(explicit.value)?)?,
        None => Vec::new(),
    };
    let mut certificates = Vec::new();
    if let Some(set) = sd.optional(context(0)) {
        let mut r = Reader::new(set.value);
        while !r.is_empty() {
            let t = r.expect(SEQUENCE)?;
            certificates.push(x509::parse(t.raw)?);
        }
    }
    sd.optional(context(1));
    let mut infos = sd.nested(SET)?;
    let mut signers = Vec::new();
    while !infos.is_empty() {
        let mut si = infos.nested(SEQUENCE)?;
        si.expect(INTEGER)?;
        let sid = si.any()?;
        let digest_algorithm = x509::algorithm(&mut si)?;
        let signed_attrs = si.optional(context(0));
        let signature_algorithm = x509::algorithm(&mut si)?;
        let signature = si.expect(OCTET_STRING)?.value;
        signers.push(SignerInfo {
            sid,
            digest_algorithm,
            signed_attrs,
            signature_algorithm,
            signature,
        });
    }
    Some(SignedData {
        content_type,
        content,
        certificates,
        signers,
    })
}

fn tst_info(content: &[u8]) -> Option<TstInfo<'_>> {
    let t = der::single(content)?;
    if t.tag != SEQUENCE {
        return None;
    }
    let mut r = Reader::new(t.value);
    r.expect(INTEGER)?;
    let policy = der::oid_string(r.expect(OID)?.value)?;
    let mut imprint = r.nested(SEQUENCE)?;
    let imprint_algorithm = x509::algorithm(&mut imprint)?;
    let imprint = imprint.expect(OCTET_STRING)?.value;
    r.expect(INTEGER)?;
    let gen_time = der::time(&r.expect(GENERALIZED_TIME)?)?;
    r.optional(SEQUENCE); // accuracy
    r.optional(BOOLEAN); // ordering
    let nonce = r.optional(INTEGER).map(|n| n.value);
    let tsa = match r.optional(context(0)) {
        Some(explicit) => Some(der::single(explicit.value)?),
        None => None,
    };
    Some(TstInfo {
        policy,
        imprint_algorithm,
        imprint,
        gen_time,
        nonce,
        tsa,
    })
}

fn signer_certificate<'c, 'a>(
    certs: &'c [Certificate<'a>],
    sid: &Tlv<'_>,
) -> Option<&'c Certificate<'a>> {
    if sid.tag == SEQUENCE {
        let mut r = Reader::new(sid.value);
        let issuer = r.expect(SEQUENCE)?.raw;
        let serial = der::unsigned(r.expect(INTEGER)?.value);
        return certs
            .iter()
            .find(|c| c.issuer == issuer && der::unsigned(c.serial) == serial);
    }
    if sid.tag == der::context_primitive(0) {
        return certs.iter().find(|c| {
            c.extension(x509::EXT_SUBJECT_KEY_IDENTIFIER)
                .and_then(|e| der::single(e.value))
                .is_some_and(|t| t.tag == OCTET_STRING && t.value == sid.value)
        });
    }
    None
}

fn is_time_stamping(cert: &Certificate<'_>) -> bool {
    let Some(eku) = cert.extension(x509::EXT_EXT_KEY_USAGE) else {
        return false;
    };
    if !eku.critical {
        return false;
    }
    let Some(mut purposes) = der::single(eku.value)
        .filter(|t| t.tag == SEQUENCE)
        .map(|t| Reader::new(t.value))
    else {
        return false;
    };
    let mut count = 0usize;
    while !purposes.is_empty() {
        match purposes.expect(OID).and_then(|o| der::oid_string(o.value)) {
            Some(p) if p == KP_TIME_STAMPING => count = count.saturating_add(1),
            _ => return false,
        }
    }
    if count == 0 {
        return false;
    }
    if cert.extension(x509::EXT_KEY_USAGE).is_some() {
        let Some(bits) = cert.key_usage() else {
            return false;
        };
        let first = bits.first().copied().unwrap_or(0);
        if first & 0xc0 == 0 || first & 0x3f != 0 || bits.iter().skip(1).any(|&b| b != 0) {
            return false;
        }
    }
    true
}

/// Attributes of `signedAttrs` as (type, first value).
fn attributes<'a>(signed_attrs: &Tlv<'a>) -> Option<Vec<(String, Tlv<'a>)>> {
    let mut r = Reader::new(signed_attrs.value);
    let mut out = Vec::new();
    while !r.is_empty() {
        let mut attr = r.nested(SEQUENCE)?;
        let kind = der::oid_string(attr.expect(OID)?.value)?;
        let first = attr.nested(SET)?.any()?;
        out.push((kind, first));
    }
    Some(out)
}

fn signing_certificate_matches(signer: &SignerInfo<'_>, cert: &Certificate<'_>) -> bool {
    let Some(attrs) = signer.signed_attrs.as_ref().and_then(attributes) else {
        return false;
    };
    let mut seen = false;
    for (kind, value) in &attrs {
        let v2 = kind == AA_SIGNING_CERTIFICATE_V2;
        if !v2 && kind != AA_SIGNING_CERTIFICATE {
            continue;
        }
        let first = (|| {
            if value.tag != SEQUENCE {
                return None;
            }
            let mut certs = Reader::new(value.value).nested(SEQUENCE)?;
            let mut id = certs.nested(SEQUENCE)?;
            let algorithm = if id.peek_tag() == Some(SEQUENCE) {
                Some(x509::algorithm(&mut id)?)
            } else {
                None
            };
            let hash = id.expect(OCTET_STRING)?.value;
            Some((algorithm, hash))
        })();
        let Some((algorithm, hash)) = first else {
            return false;
        };
        let got = if v2 {
            match Hash::from_oid(algorithm.as_deref().unwrap_or(SHA256)) {
                Some(h) => h.digest(cert.raw),
                None => return false,
            }
        } else {
            sha1::Sha1::digest(cert.raw).to_vec()
        };
        if got != hash {
            return false;
        }
        seen = true;
    }
    seen
}

fn tsa_name_matches(name: &Tlv<'_>, cert: &Certificate<'_>) -> bool {
    if name.tag == context(4) {
        return name.value == cert.subject;
    }
    let Some(san) = cert.extension(x509::EXT_SUBJECT_ALT_NAME) else {
        return false;
    };
    let Some(mut names) = der::single(san.value)
        .filter(|t| t.tag == SEQUENCE)
        .map(|t| Reader::new(t.value))
    else {
        return false;
    };
    while let Some(n) = names.any() {
        if n.raw == name.raw {
            return true;
        }
    }
    false
}

fn hash_for_signature(signer: &SignerInfo<'_>) -> Option<Hash> {
    match signer.signature_algorithm.as_str() {
        x509::RSA_ENCRYPTION => Hash::from_oid(&signer.digest_algorithm),
        x509::SHA256_WITH_RSA => Some(Hash::Sha256),
        x509::SHA384_WITH_RSA => Some(Hash::Sha384),
        x509::SHA512_WITH_RSA => Some(Hash::Sha512),
        _ => None,
    }
}

/// The CMS signature over the signed attributes (or over the content when there are none).
fn signature_verifies(
    sd: &SignedData<'_>,
    signer: &SignerInfo<'_>,
    cert: &Certificate<'_>,
) -> bool {
    let (Some(hash), Some(digest_hash), Some(key)) = (
        hash_for_signature(signer),
        Hash::from_oid(&signer.digest_algorithm),
        cert.rsa_key(),
    ) else {
        return false;
    };
    let Some(attrs_tlv) = &signer.signed_attrs else {
        return rsa::verify(&key, &sd.content, signer.signature, hash);
    };
    let Some(attrs) = attributes(attrs_tlv) else {
        return false;
    };
    let content_digest = digest_hash.digest(&sd.content);
    let digest_ok = attrs.iter().any(|(k, v)| {
        k == AA_MESSAGE_DIGEST && v.tag == OCTET_STRING && v.value == content_digest.as_slice()
    });
    let type_ok = attrs
        .iter()
        .filter(|(k, _)| k == AA_CONTENT_TYPE)
        .all(|(_, v)| {
            v.tag == OID && der::oid_string(v.value).is_some_and(|o| o == sd.content_type)
        });
    if !digest_ok || !type_ok {
        return false;
    }
    let mut set = attrs_tlv.raw.to_vec();
    let Some(first) = set.first_mut() else {
        return false;
    };
    *first = SET;
    rsa::verify(&key, &set, signer.signature, hash)
}

fn can_sign_certificates(cert: &Certificate<'_>) -> bool {
    cert.is_ca()
        && cert
            .key_usage()
            .is_none_or(|bits| bits.first().is_some_and(|b| b & 0x04 != 0))
}

/// Builds a path from `leaf` to one of `roots` through `pool`, every certificate valid at `at`.
fn chain_reaches(
    leaf: &Certificate<'_>,
    pool: &[Certificate<'_>],
    roots: &[Certificate<'_>],
    at: i64,
) -> bool {
    let mut current = leaf;
    let mut used: Vec<usize> = Vec::new();
    for _ in 0..8 {
        if !current.valid_at(at) {
            return false;
        }
        if let Some(root) = roots
            .iter()
            .find(|r| r.subject == current.issuer && current.signed_by(r))
        {
            return root.valid_at(at) && can_sign_certificates(root);
        }
        let next = pool.iter().enumerate().find(|(i, c)| {
            !used.contains(i)
                && c.subject == current.issuer
                && c.raw != current.raw
                && can_sign_certificates(c)
                && current.signed_by(c)
        });
        let Some((i, c)) = next else {
            return false;
        };
        used.push(i);
        current = c;
    }
    false
}

/// Checks a granted TimeStampResp for `message`. `nonce` is the requested nonce, when the caller
/// made the request; `trust` is the registry.
pub fn verify_time_stamp_token(
    der_bytes: &[u8],
    message: &[u8],
    nonce: Option<&[u8]>,
    trust: &[TsaTrust<'_>],
) -> Result<TsaOk, TsaReject> {
    let token = token_of(der_bytes).ok_or(TsaReject::RespInvalid)?;
    let sd = signed_data(&token).ok_or(TsaReject::CmsInvalid)?;
    if sd.content_type != TST_INFO || sd.signers.len() != 1 {
        return Err(TsaReject::CmsInvalid);
    }
    let tst = tst_info(&sd.content).ok_or(TsaReject::TstInvalid)?;

    if tst.imprint_algorithm != SHA256 || tst.imprint != sha2::Sha256::digest(message).as_slice() {
        return Err(TsaReject::ImprintMismatch);
    }
    if let Some(want) = nonce {
        let got = tst.nonce.ok_or(TsaReject::NonceMismatch)?;
        if der::unsigned(got) != der::unsigned(want) {
            return Err(TsaReject::NonceMismatch);
        }
    }

    let signer = sd.signers.first().ok_or(TsaReject::CmsInvalid)?;
    let cert = signer_certificate(&sd.certificates, &signer.sid).ok_or(TsaReject::CmsInvalid)?;
    if !is_time_stamping(cert) {
        return Err(TsaReject::SignerNotTimestamping);
    }
    if !signing_certificate_matches(signer, cert) {
        return Err(TsaReject::SigningCertificateMismatch);
    }
    if let Some(name) = &tst.tsa
        && !tsa_name_matches(name, cert)
    {
        return Err(TsaReject::NameMismatch);
    }

    let candidates: Vec<&TsaTrust<'_>> = trust
        .iter()
        .filter(|t| t.policies.contains(&tst.policy.as_str()))
        .collect();
    if candidates.is_empty() {
        return Err(if trust.is_empty() {
            TsaReject::ChainUntrusted
        } else {
            TsaReject::PolicyMismatch
        });
    }
    if !signature_verifies(&sd, signer, cert) {
        return Err(TsaReject::ChainUntrusted);
    }
    for candidate in candidates {
        let roots: Vec<Certificate<'_>> = candidate
            .roots
            .iter()
            .filter_map(|r| x509::parse(r))
            .collect();
        if chain_reaches(cert, &sd.certificates, &roots, tst.gen_time) {
            return Ok(TsaOk {
                tsa: String::from(candidate.id),
                policy: tst.policy,
                gen_time: tst.gen_time,
            });
        }
    }
    Err(TsaReject::ChainUntrusted)
}

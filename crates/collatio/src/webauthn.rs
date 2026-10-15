//! The method `webauthn@1` (signing-layers §6).
//!
//! The challenge is the envelope challenge ([`crate::challenge`]). The proof is
//! `{ credential, authenticator_data, client_data_json, signature }` and the key is
//! `{ credential, public_key, alg }` (a COSE public key in Base64URL; alg −7 ES256 or −8 EdDSA).
//! The checks and their order follow the TypeScript implementation they replace, so the same
//! failure gives the same reason.
//!
//! Collatio is stricter in three places, none of which a browser produces: Base64URL with
//! non-zero trailing bits, `clientDataJSON` that repeats a key or starts with a byte order mark,
//! and `alg` written as a non-integer (`-7.0`).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::b64;
use crate::challenge::envelope_challenge;
use crate::cose::{parse_cose_key, verify_signature};
use crate::digest::sha256;
use crate::json::{self, Value};

pub const WEBAUTHN_1: &str = "webauthn@1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WebauthnError {
    /// The proof or the key does not have its shape.
    Shape,
    /// The proof and the key name different credentials.
    Credential,
    /// The envelope's method is not `webauthn@1`.
    Suite,
    /// A Base64URL member does not decode.
    Encoding,
    /// `clientDataJSON` is not a JSON object.
    ClientData,
    ClientDataType,
    Challenge,
    CrossOrigin,
    /// The origin is not https on the rp or a subdomain of it.
    Origin,
    AuthenticatorData,
    /// The rpIdHash is not the SHA-256 of the rp.
    Rp,
    UserPresence,
    UserVerification,
    PublicKey,
    Signature,
    /// The COSE key's algorithm differs from the key's `alg`.
    KeyAlg,
}

impl WebauthnError {
    pub fn as_str(self) -> &'static str {
        match self {
            WebauthnError::Shape => "shape",
            WebauthnError::Credential => "credential",
            WebauthnError::Suite => "suite",
            WebauthnError::Encoding => "encoding",
            WebauthnError::ClientData => "client_data",
            WebauthnError::ClientDataType => "client_data_type",
            WebauthnError::Challenge => "challenge",
            WebauthnError::CrossOrigin => "cross_origin",
            WebauthnError::Origin => "origin",
            WebauthnError::AuthenticatorData => "authenticator_data",
            WebauthnError::Rp => "rp",
            WebauthnError::UserPresence => "user_presence",
            WebauthnError::UserVerification => "user_verification",
            WebauthnError::PublicKey => "public_key",
            WebauthnError::Signature => "signature",
            WebauthnError::KeyAlg => "key_alg",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebauthnOk {
    pub origin: String,
    pub counter: u32,
    pub alg: i64,
    pub backup_eligible: bool,
    pub backed_up: bool,
}

const UP: u8 = 0x01;
const UV: u8 = 0x04;
const BE: u8 = 0x08;
const BS: u8 = 0x10;

/// Non-empty, Base64URL characters only, and a length that can be Base64URL.
fn is_b64u_text(v: &str) -> bool {
    !v.is_empty()
        && v.len() % 4 != 1
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn b64u_member<'a>(o: &'a json::Object, key: &str, max: usize) -> Option<&'a str> {
    let s = o.get(key)?.as_str()?;
    (is_b64u_text(s) && s.len() <= max).then_some(s)
}

struct Proof<'a> {
    credential: &'a str,
    authenticator_data: &'a str,
    client_data_json: &'a str,
    signature: &'a str,
}

struct Key<'a> {
    credential: &'a str,
    public_key: &'a str,
    alg: i64,
}

fn parse_proof(v: &Value) -> Option<Proof<'_>> {
    let o = v.as_object()?;
    if o.len() != 4 {
        return None;
    }
    Some(Proof {
        credential: b64u_member(o, "credential", 16384)?,
        authenticator_data: b64u_member(o, "authenticator_data", 16384)?,
        client_data_json: b64u_member(o, "client_data_json", 16384)?,
        signature: b64u_member(o, "signature", 16384)?,
    })
}

fn parse_key(v: &Value) -> Option<Key<'_>> {
    let o = v.as_object()?;
    if o.len() != 3 {
        return None;
    }
    let alg = o.get("alg")?.as_number()?.as_safe_integer()?;
    if alg != -7 && alg != -8 {
        return None;
    }
    Some(Key {
        credential: b64u_member(o, "credential", 1366)?,
        public_key: b64u_member(o, "public_key", 2048)?,
        alg,
    })
}

/// https, and the host is the rp or below it (the WebAuthn rpId rule). The origin must already be
/// in serialized form: lowercase, no default port, no path, no user info.
pub fn origin_belongs_to_rp(origin: &str, rp: &str) -> bool {
    let Some(rest) = origin.strip_prefix("https://") else {
        return false;
    };
    let (host, port) = match rest.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (rest, None),
    };
    if let Some(p) = port {
        let canonical =
            !p.is_empty() && !p.starts_with('0') && p.bytes().all(|b| b.is_ascii_digit());
        match p.parse::<u32>() {
            Ok(n) if canonical && (1..=65535).contains(&n) && n != 443 => {}
            _ => return false,
        }
    }
    let host_ok = !host.is_empty()
        && host.split('.').all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        });
    host_ok && !rp.is_empty() && (host == rp || host.ends_with(&format!(".{rp}")))
}

/// Checks the proof over the envelope with the key (genesis.md §5.4 step 3).
pub fn verify_webauthn1(
    envelope: &Value,
    proof: &Value,
    key: &Value,
) -> Result<WebauthnOk, WebauthnError> {
    let (Some(proof), Some(key)) = (parse_proof(proof), parse_key(key)) else {
        return Err(WebauthnError::Shape);
    };
    if proof.credential != key.credential {
        return Err(WebauthnError::Credential);
    }
    if envelope.get("suite").and_then(Value::as_str) != Some(WEBAUTHN_1) {
        return Err(WebauthnError::Suite);
    }
    let challenge = envelope_challenge(envelope).ok_or(WebauthnError::Suite)?;
    let rp = envelope.get("rp").and_then(Value::as_str).unwrap_or("");

    let (Some(auth_data), Some(client_data_bytes), Some(signature), Some(public_key)) = (
        b64::decode(proof.authenticator_data),
        b64::decode(proof.client_data_json),
        b64::decode(proof.signature),
        b64::decode(key.public_key),
    ) else {
        return Err(WebauthnError::Encoding);
    };

    let client_data = json::parse(&client_data_bytes).map_err(|_| WebauthnError::ClientData)?;
    if client_data.as_object().is_none() {
        return Err(WebauthnError::ClientData);
    }
    if client_data.get("type").and_then(Value::as_str) != Some("webauthn.get") {
        return Err(WebauthnError::ClientDataType);
    }
    if client_data.get("challenge").and_then(Value::as_str) != Some(challenge.as_str()) {
        return Err(WebauthnError::Challenge);
    }
    if client_data.get("crossOrigin") == Some(&Value::Bool(true)) {
        return Err(WebauthnError::CrossOrigin);
    }
    let origin = client_data
        .get("origin")
        .and_then(Value::as_str)
        .ok_or(WebauthnError::Origin)?;
    if !origin_belongs_to_rp(origin, rp) {
        return Err(WebauthnError::Origin);
    }

    let (Some(rp_id_hash), Some(&flags), Some(counter)) = (
        auth_data.get(..32),
        auth_data.get(32),
        auth_data.get(33..37),
    ) else {
        return Err(WebauthnError::AuthenticatorData);
    };
    if rp_id_hash != sha256(rp.as_bytes()) {
        return Err(WebauthnError::Rp);
    }
    if flags & UP == 0 {
        return Err(WebauthnError::UserPresence);
    }
    if flags & UV == 0 {
        return Err(WebauthnError::UserVerification);
    }
    let counter = u32::from_be_bytes(
        counter
            .try_into()
            .map_err(|_| WebauthnError::AuthenticatorData)?,
    );

    let cose = parse_cose_key(&public_key).ok_or(WebauthnError::PublicKey)?;
    let mut signed = Vec::with_capacity(auth_data.len().saturating_add(32));
    signed.extend_from_slice(&auth_data);
    signed.extend_from_slice(&sha256(&client_data_bytes));
    if !verify_signature(&cose, &signature, &signed) {
        return Err(WebauthnError::Signature);
    }
    if cose.alg() != key.alg {
        return Err(WebauthnError::KeyAlg);
    }
    Ok(WebauthnOk {
        origin: String::from(origin),
        counter,
        alg: cose.alg(),
        backup_eligible: flags & BE != 0,
        backed_up: flags & BS != 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins() {
        let rp = "clavis.nexus";
        for ok in [
            "https://clavis.nexus",
            "https://id.clavis.nexus",
            "https://a_b.clavis.nexus",
            "https://id.clavis.nexus:8443",
        ] {
            assert!(origin_belongs_to_rp(ok, rp), "{ok}");
        }
        for bad in [
            "http://id.clavis.nexus",
            "https://evilclavis.nexus",
            "https://id.clavis.nexus/",
            "https://ID.clavis.nexus",
            "https://id.clavis.nexus:443",
            "https://id.clavis.nexus:0443",
            "https://id.clavis.nexus.",
            "https://user@id.clavis.nexus",
            "https://id.clavis.nexus:",
            "https://%41.clavis.nexus",
            "https://clavis.nexus.evil",
        ] {
            assert!(!origin_belongs_to_rp(bad, rp), "{bad}");
        }
        assert!(!origin_belongs_to_rp("https://x", ""));
    }

    #[test]
    fn strict_client_data() {
        // A browser never repeats a key; the strict reader refuses it.
        let cd = br#"{"type":"webauthn.get","type":"webauthn.get"}"#;
        assert!(json::parse(cd).is_err());
    }
}

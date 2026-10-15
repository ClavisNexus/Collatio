//! Digests and type IDs.
//!
//! A digest is `sha256:` followed by the Base64URL of a SHA-256 (43 characters). The digest of a
//! value is the digest of the UTF-8 of its canonical form (RFC 8785).

use alloc::string::String;
use sha2::{Digest as _, Sha256};

use crate::b64;
use crate::jcs::canonical;
use crate::json::Value;

pub const DIGEST_PREFIX: &str = "sha256:";

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub fn digest_of_bytes(bytes: &[u8]) -> String {
    let mut out = String::from(DIGEST_PREFIX);
    out.push_str(&b64::encode(&sha256(bytes)));
    out
}

/// `sha256:` + b64u(SHA-256(UTF-8(JCS(value))))
pub fn digest_of(value: &Value) -> String {
    digest_of_bytes(canonical(value).as_bytes())
}

/// Whether `text` has the form of a digest.
pub fn is_digest(text: &str) -> bool {
    match text.strip_prefix(DIGEST_PREFIX) {
        Some(rest) => rest.len() == 43 && b64::decode_len(rest, 32).is_some(),
        None => false,
    }
}

/// Whether `text` is a type ID: `<name>@<version>`. The name is dot-separated parts of lowercase
/// letters, digits and `_`, each starting with a letter; the version is 1 or more without leading
/// zeros; at most 128 characters.
pub fn is_type_id(text: &str) -> bool {
    if text.is_empty() || text.len() > 128 {
        return false;
    }
    let Some((name, version)) = text.split_once('@') else {
        return false;
    };
    let version_ok = !version.is_empty()
        && version.bytes().all(|b| b.is_ascii_digit())
        && !version.starts_with('0');
    let name_ok = !name.is_empty()
        && name.split('.').all(|part| {
            let mut bytes = part.bytes();
            matches!(bytes.next(), Some(b'a'..=b'z'))
                && bytes.all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_'))
        });
    version_ok && name_ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::parse;

    #[test]
    fn digests() {
        // SHA-256 of "{}".
        assert_eq!(
            digest_of(&parse(b" { } ").unwrap()),
            "sha256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o"
        );
        assert!(is_digest(
            "sha256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o"
        ));
        assert!(!is_digest(
            "sha256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4p"
        ));
        assert!(!is_digest(
            "sha384:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o"
        ));
    }

    #[test]
    fn type_ids() {
        for ok in ["receipt@1", "mandate.use_request@1", "a.b2@10"] {
            assert!(is_type_id(ok), "{ok}");
        }
        for bad in [
            "receipt",
            "receipt@0",
            "receipt@01",
            "Receipt@1",
            "a..b@1",
            "1a@1",
            "a.@1",
            "a@1@2",
            "a-b@1",
        ] {
            assert!(!is_type_id(bad), "{bad}");
        }
    }
}

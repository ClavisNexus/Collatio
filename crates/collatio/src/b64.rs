//! Base64URL without padding (RFC 4648 §5).
//!
//! Decoding is strict: no padding, no other alphabet, and the unused bits of the last character
//! are zero. A text therefore names exactly one byte string.

use alloc::string::String;
use alloc::vec::Vec;
use base64ct::{Base64UrlUnpadded, Encoding};

pub fn encode(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

pub fn decode(text: &str) -> Option<Vec<u8>> {
    Base64UrlUnpadded::decode_vec(text).ok()
}

/// Decodes and requires exactly `len` bytes.
pub fn decode_len(text: &str, len: usize) -> Option<Vec<u8>> {
    decode(text).filter(|b| b.len() == len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict() {
        assert_eq!(decode("AQID"), Some(vec![1, 2, 3]));
        assert_eq!(decode(""), Some(vec![]));
        assert_eq!(encode(&[0xfb, 0xff]), "-_8");
        assert_eq!(decode("-_8"), Some(vec![0xfb, 0xff]));
        // Padding, the standard alphabet, a dangling character and non-zero trailing bits.
        assert_eq!(decode("AQ=="), None);
        assert_eq!(decode("+/8"), None);
        assert_eq!(decode("AQIDB"), None);
        assert_eq!(decode("AR"), None);
        assert_eq!(decode_len("AQID", 2), None);
    }
}

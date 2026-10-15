//! The fixed list of reasons an answer gives when it refuses (ABI.md §Reasons).
//!
//! Hosts map a reason to their own errors, so a reason is never renamed or reused for another
//! meaning; new reasons are only added.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// The input is larger than the ABI allows.
    InputTooLarge,
    /// The input is not a JSON object with a string `op`.
    InputMalformed,
    /// No operation by that name.
    UnknownOp,
    /// A document is not UTF-8 or not one JSON value.
    JsonSyntax,
    /// A document repeats a key in an object.
    JsonDuplicateKey,
    /// A document has a `\u` escape that leaves a lone surrogate.
    JsonLoneSurrogate,
    /// A document has a number that reads as infinity.
    JsonNonFinite,
    /// A document nests deeper than the reader allows.
    JsonTooDeep,
}

impl Reason {
    pub const ALL: &'static [Reason] = &[
        Reason::InputTooLarge,
        Reason::InputMalformed,
        Reason::UnknownOp,
        Reason::JsonSyntax,
        Reason::JsonDuplicateKey,
        Reason::JsonLoneSurrogate,
        Reason::JsonNonFinite,
        Reason::JsonTooDeep,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Reason::InputTooLarge => "input_too_large",
            Reason::InputMalformed => "input_malformed",
            Reason::UnknownOp => "unknown_op",
            Reason::JsonSyntax => "json_syntax",
            Reason::JsonDuplicateKey => "json_duplicate_key",
            Reason::JsonLoneSurrogate => "json_lone_surrogate",
            Reason::JsonNonFinite => "json_non_finite",
            Reason::JsonTooDeep => "json_too_deep",
        }
    }
}

impl From<crate::json::JsonError> for Reason {
    fn from(e: crate::json::JsonError) -> Reason {
        use crate::json::JsonError;
        match e {
            JsonError::Utf8 | JsonError::Syntax => Reason::JsonSyntax,
            JsonError::DuplicateKey => Reason::JsonDuplicateKey,
            JsonError::LoneSurrogate => Reason::JsonLoneSurrogate,
            JsonError::NonFinite => Reason::JsonNonFinite,
            JsonError::TooDeep => Reason::JsonTooDeep,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_unique_snake_case() {
        let mut seen = std::collections::BTreeSet::new();
        for r in Reason::ALL {
            let s = r.as_str();
            assert!(
                s.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "{s}"
            );
            assert!(seen.insert(s), "{s} twice");
        }
    }
}

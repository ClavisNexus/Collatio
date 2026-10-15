//! The fixed list of reasons an answer gives when it refuses (ABI.md §Reasons).
//!
//! Hosts map a reason to their own errors, so a reason is never renamed or reused for another
//! meaning; new reasons are only added. ABI.md lists the same names in the same order, which a
//! test checks.

macro_rules! reasons {
    ($($variant:ident => $name:literal,)*) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Reason {
            $($variant,)*
        }

        impl Reason {
            pub const ALL: &'static [Reason] = &[$(Reason::$variant,)*];

            pub fn as_str(self) -> &'static str {
                match self {
                    $(Reason::$variant => $name,)*
                }
            }
        }
    };
}

reasons! {
    InputTooLarge => "input_too_large",
    InputMalformed => "input_malformed",
    UnknownOp => "unknown_op",
    JsonSyntax => "json_syntax",
    JsonDuplicateKey => "json_duplicate_key",
    JsonLoneSurrogate => "json_lone_surrogate",
    JsonNonFinite => "json_non_finite",
    JsonTooDeep => "json_too_deep",
    TrustMaster => "trust_master",
    TrustNomination => "trust_nomination",
    TrustJwks => "trust_jwks",
    TrustJwksSignature => "trust_jwks_signature",
    TrustCatalog => "trust_catalog",
    TrustCatalogSignature => "trust_catalog_signature",
    RegistryMissing => "registry_missing",
    RegistryShape => "registry_shape",
    RegistryNotInCatalog => "registry_not_in_catalog",
    ReceiptType => "receipt_type",
    ReceiptShape => "receipt_shape",
    EnvelopeShape => "envelope_shape",
    DimensionShape => "dimension_shape",
    DimensionDigest => "dimension_digest",
    DimensionNotInCatalog => "dimension_not_in_catalog",
    StatementShape => "statement_shape",
    StatementDigest => "statement_digest",
    StatementNotInDimension => "statement_not_in_dimension",
    SuiteNotInDimension => "suite_not_in_dimension",
    SuiteUnknown => "suite_unknown",
    Aud => "aud",
    ExtensionRequired => "extension_required",
    ExtensionNotAllowed => "extension_not_allowed",
    ExtensionUnknown => "extension_unknown",
    ReceiptKind => "receipt_kind",
    ExpectStatement => "expect_statement",
    ExpectAud => "expect_aud",
    ExpectSigner => "expect_signer",
    HolderProof => "holder_proof",
    ProofShape => "proof_shape",
    ProofCredential => "proof_credential",
    ProofSuite => "proof_suite",
    ProofEncoding => "proof_encoding",
    ProofClientData => "proof_client_data",
    ProofClientDataType => "proof_client_data_type",
    ProofChallenge => "proof_challenge",
    ProofCrossOrigin => "proof_cross_origin",
    ProofOrigin => "proof_origin",
    ProofAuthenticatorData => "proof_authenticator_data",
    ProofRp => "proof_rp",
    ProofUserPresence => "proof_user_presence",
    ProofUserVerification => "proof_user_verification",
    ProofPublicKey => "proof_public_key",
    ProofSignature => "proof_signature",
    ProofKeyAlg => "proof_key_alg",
    AttestationShape => "attestation_shape",
    AcceptedShape => "accepted_shape",
    AcceptedSubject => "accepted_subject",
    AcceptedKey => "accepted_key",
    AcceptedSignature => "accepted_signature",
    AcceptedMissing => "accepted_missing",
    LedgerReceiptShape => "ledger_receipt_shape",
    LedgerReceiptLog => "ledger_receipt_log",
    LedgerReceiptLeaf => "ledger_receipt_leaf",
    AnchorMissing => "anchor_missing",
    DisclosureShape => "disclosure_shape",
    KeyOpeningShape => "key_opening_shape",
    KeyOpeningBinding => "key_opening_binding",
    KeyOpeningUnanchored => "key_opening_unanchored",
    LedgerNoteShape => "ledger_note_shape",
    LedgerNoteLog => "ledger_note_log",
    LedgerNoteSigner => "ledger_note_signer",
    LedgerNoteSignature => "ledger_note_signature",
    InclusionProof => "inclusion_proof",
    ConsistencyProof => "consistency_proof",
    MandateGrant => "mandate_grant",
    MandateTermsShape => "mandate_terms_shape",
    MandateTermsDigest => "mandate_terms_digest",
    MandateUseShape => "mandate_use_shape",
    MandateGrantDigest => "mandate_grant_digest",
    MandateMismatch => "mandate_mismatch",
    MandateAttestSignature => "mandate_attest_signature",
    MandateAppJwtShape => "mandate_app_jwt_shape",
    MandateAppJwtAlg => "mandate_app_jwt_alg",
    MandateAppJwtSignature => "mandate_app_jwt_signature",
    MandateAppJwtApp => "mandate_app_jwt_app",
    MandateAppJwtAud => "mandate_app_jwt_aud",
    MandateAppJwtBody => "mandate_app_jwt_body",
    MandateAppJwtTime => "mandate_app_jwt_time",
    MandateBeforeGrant => "mandate_before_grant",
    MandateTotals => "mandate_totals",
    MandateOutside => "mandate_outside",
    MandateUseChain => "mandate_use_chain",
    MandateCloseShape => "mandate_close_shape",
    MandateCloseReason => "mandate_close_reason",
    MandateCloseUses => "mandate_close_uses",
    MandateCloseExpired => "mandate_close_expired",
    MandateCloseLast => "mandate_close_last",
    MandateCloseExhausted => "mandate_close_exhausted",
    ChainShape => "chain_shape",
    ChainAttest => "chain_attest",
    ChainActor => "chain_actor",
    ChainLink => "chain_link",
    ChainContentSeq => "chain_content_seq",
    ChainContentShape => "chain_content_shape",
    ChainContentCommit => "chain_content_commit",
    ChainSnapshotShape => "chain_snapshot_shape",
    ChainSnapshotHead => "chain_snapshot_head",
    BundleShape => "bundle_shape",
    BundleLog => "bundle_log",
    BundleReceipt => "bundle_receipt",
    BundleInclusion => "bundle_inclusion",
    BundleOpening => "bundle_opening",
    BundleAnchor => "bundle_anchor",
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

impl From<crate::webauthn::WebauthnError> for Reason {
    fn from(e: crate::webauthn::WebauthnError) -> Reason {
        use crate::webauthn::WebauthnError as W;
        match e {
            W::Shape => Reason::ProofShape,
            W::Credential => Reason::ProofCredential,
            W::Suite => Reason::ProofSuite,
            W::Encoding => Reason::ProofEncoding,
            W::ClientData => Reason::ProofClientData,
            W::ClientDataType => Reason::ProofClientDataType,
            W::Challenge => Reason::ProofChallenge,
            W::CrossOrigin => Reason::ProofCrossOrigin,
            W::Origin => Reason::ProofOrigin,
            W::AuthenticatorData => Reason::ProofAuthenticatorData,
            W::Rp => Reason::ProofRp,
            W::UserPresence => Reason::ProofUserPresence,
            W::UserVerification => Reason::ProofUserVerification,
            W::PublicKey => Reason::ProofPublicKey,
            W::Signature => Reason::ProofSignature,
            W::KeyAlg => Reason::ProofKeyAlg,
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

    #[test]
    fn abi_lists_the_same_reasons_in_order() {
        let abi = include_str!("../../../ABI.md");
        let section = abi.split("## Reasons").nth(1).unwrap();
        let listed: Vec<&str> = section
            .lines()
            .filter_map(|l| l.strip_prefix("| `"))
            .filter_map(|l| l.split('`').next())
            .collect();
        let ours: Vec<&str> = Reason::ALL.iter().map(|r| r.as_str()).collect();
        assert_eq!(listed, ours);
    }
}

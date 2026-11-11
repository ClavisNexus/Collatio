//! One valid `receipt@2` and the failures FORMATS.md §4.4 names.

use crate::b64;
use crate::digest::{digest_of, is_digest, sha256};
use crate::jcs::canonical;
use crate::json::{Object, Value, parse};
use crate::ledger::leaf::Leaf;
use crate::ledger::note::key_hash;
use crate::reason::Reason;
use crate::receipt::{Expect, Kind, RECEIPT_2, anchor_commitment, verify_receipt};
use crate::trust::read_trust;
use base64ct::Encoding;

#[derive(Clone, Copy)]
enum Fault {
    None,
    Type,
    Proof,
    Subject,
    Leaf,
    Disclosure,
}

fn scalar(last: u8) -> [u8; 32] {
    let mut secret = [0u8; 32];
    secret[31] = last;
    secret
}

fn number(raw: &str) -> Value {
    parse(raw.as_bytes()).unwrap()
}

fn obj(pairs: Vec<(&str, Value)>) -> Value {
    let mut out = Object::default();
    for (key, value) in pairs {
        assert!(out.insert(key.to_string(), value));
    }
    Value::Object(out)
}

fn p256(secret: [u8; 32]) -> p256::ecdsa::SigningKey {
    p256::ecdsa::SigningKey::from_slice(&secret).unwrap()
}

fn xy(secret: [u8; 32]) -> ([u8; 32], [u8; 32]) {
    let point = p256(secret).verifying_key().to_sec1_point(false);
    let x: [u8; 32] = point.x().unwrap().as_slice().try_into().unwrap();
    let y: [u8; 32] = point.y().unwrap().as_slice().try_into().unwrap();
    (x, y)
}

fn sign_b64(secret: [u8; 32], message: &[u8]) -> String {
    use p256::ecdsa::signature::Signer;
    let signature: p256::ecdsa::Signature = p256(secret).sign(message);
    b64::encode(signature.to_bytes().as_ref())
}

fn sign_raw(secret: [u8; 32], message: &[u8]) -> [u8; 64] {
    use p256::ecdsa::signature::Signer;
    let signature: p256::ecdsa::Signature = p256(secret).sign(message);
    let bytes = signature.to_bytes();
    bytes.as_slice().try_into().unwrap()
}

fn ec_jwk(secret: [u8; 32], kid: &str) -> Value {
    let (x, y) = xy(secret);
    obj(vec![
        ("kty", Value::from("EC")),
        ("crv", Value::from("P-256")),
        ("x", Value::from(b64::encode(&x).as_str())),
        ("y", Value::from(b64::encode(&y).as_str())),
        ("kid", Value::from(kid)),
        ("alg", Value::from("ES256")),
    ])
}

fn child_payload(slot: &str, jwk: &Value) -> Value {
    let jwk = jwk.as_object().unwrap();
    let mut public = Object::default();
    for key in ["kty", "crv", "x", "y", "kid", "alg"] {
        assert!(public.insert(
            key.to_string(),
            jwk.get(key).cloned().unwrap_or(Value::Null)
        ));
    }
    obj(vec![
        ("version", number("1")),
        ("purpose", Value::from("signed-jwks-child")),
        ("protocol_ns", Value::from("clavis")),
        ("slot", Value::from(slot)),
        ("public_jwk", Value::Object(public)),
    ])
}

fn with_slot(public: &Value, slot: &str, signature: &str) -> Value {
    let mut key = public.as_object().unwrap().clone();
    assert!(key.insert("clavis-slot".into(), Value::from(slot)));
    assert!(key.insert("clavis-sealer-signature".into(), Value::from(signature)));
    Value::Object(key)
}

fn cose_es256(secret: [u8; 32]) -> Vec<u8> {
    let (x, y) = xy(secret);
    let mut out = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
    out.extend_from_slice(&x);
    out.extend_from_slice(&[0x22, 0x58, 0x20]);
    out.extend_from_slice(&y);
    out
}

fn receipt_note(secret: &[u8; 32], index: u64, leaf: &[u8; 32]) -> String {
    use ed25519_dalek::Signer;
    let key = ed25519_dalek::SigningKey::from_bytes(secret);
    let leaf_b64 = base64ct::Base64::encode_string(leaf);
    let body = format!(
        "clavis.ledger.receipt/v1\nclavis.nexus/ledger/first-party.0\n{index}\n{leaf_b64}\n"
    );
    let public = key.verifying_key().to_bytes();
    let mut raw = Vec::with_capacity(68);
    raw.extend_from_slice(&key_hash("ledger", &public));
    raw.extend_from_slice(&key.sign(body.as_bytes()).to_bytes());
    format!(
        "{body}\n\u{2014} ledger {}\n",
        base64ct::Base64::encode_string(&raw)
    )
}

pub(crate) fn trust_value(sealer: [u8; 32], receipt_key: [u8; 32], ledger: &[u8; 32]) -> Value {
    let sealer_jwk = ec_jwk(sealer, "sealer");
    let payload = obj(vec![
        ("v", number("1")),
        ("purpose", Value::from("platform.sealer.nominate")),
        ("instance_id", Value::from("clavis.nexus")),
        ("sealer_kid", Value::from("sealer")),
        ("sealer_public_jwk", sealer_jwk),
        ("iat", number("1")),
    ]);
    let nomination = obj(vec![
        ("payload", payload.clone()),
        (
            "signature",
            Value::from(sign_b64(scalar(1), canonical(&payload).as_bytes()).as_str()),
        ),
    ]);
    let receipt_public = ec_jwk(receipt_key, "sign-receipt");
    let receipt_payload = child_payload("sign-receipt", &receipt_public);
    let receipt_jwk = with_slot(
        &receipt_public,
        "sign-receipt",
        &sign_b64(sealer, canonical(&receipt_payload).as_bytes()),
    );
    let ledger_public = {
        let public = ed25519_dalek::SigningKey::from_bytes(ledger)
            .verifying_key()
            .to_bytes();
        obj(vec![
            ("kty", Value::from("OKP")),
            ("crv", Value::from("Ed25519")),
            ("x", Value::from(b64::encode(&public).as_str())),
            ("kid", Value::from("ledger")),
            ("alg", Value::from("EdDSA")),
        ])
    };
    let ledger_payload = child_payload("ledger-log", &ledger_public);
    let ledger_jwk = with_slot(
        &ledger_public,
        "ledger-log",
        &sign_b64(sealer, canonical(&ledger_payload).as_bytes()),
    );
    let jwks = obj(vec![
        ("keys", Value::Array(vec![receipt_jwk, ledger_jwk])),
        ("sealer", nomination.clone()),
    ]);
    let digest = "sha256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o";
    let mut catalog = Object::default();
    for (key, value) in [
        ("type", Value::from("catalog@1")),
        ("issued_at", number("1")),
        ("sealer", nomination),
        (
            "verifiers",
            Value::Array(vec![obj(vec![
                ("digest", Value::from(digest)),
                (
                    "source",
                    obj(vec![
                        (
                            "repo",
                            Value::from("https://github.com/clavisnexus/collatio"),
                        ),
                        ("tag", Value::from("v1")),
                        (
                            "commit",
                            Value::from("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                        ),
                    ]),
                ),
            ])]),
        ),
        ("revoked", Value::Array(vec![])),
        ("registries", Value::Array(vec![])),
        ("dimensions", Value::Array(vec![])),
        (
            "logs",
            Value::Array(vec![obj(vec![
                ("id", Value::from("first-party.0")),
                ("kid", Value::from("ledger")),
            ])]),
        ),
    ] {
        assert!(catalog.insert(key.to_string(), value));
    }
    let signature = sign_b64(
        sealer,
        canonical(&Value::Object(catalog.clone())).as_bytes(),
    );
    assert!(catalog.insert(
        "signature".into(),
        obj(vec![
            ("kid", Value::from("sealer")),
            ("alg", Value::from("ES256")),
            ("sig", Value::from(signature.as_str())),
        ])
    ));
    let (x, y) = xy(scalar(1));
    obj(vec![
        (
            "master",
            obj(vec![
                ("kty", Value::from("EC")),
                ("crv", Value::from("P-256")),
                ("x", Value::from(b64::encode(&x).as_str())),
                ("y", Value::from(b64::encode(&y).as_str())),
                ("alg", Value::from("ES256")),
            ]),
        ),
        ("jwks", Value::from(canonical(&jwks).as_str())),
        (
            "catalog",
            Value::from(canonical(&Value::Object(catalog)).as_str()),
        ),
    ])
}

fn sample(fault: Fault) -> (Value, Value) {
    const PASSKEY: u8 = 4;
    const RECEIPT_KEY: u8 = 3;
    const SEALER: u8 = 2;
    let ledger = [9u8; 32];
    let digest = "sha256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o";
    let statement = obj(vec![
        ("type", Value::from("profile.patch@1")),
        ("display_name", Value::from("ada")),
    ]);
    let dimension = obj(vec![
        ("type", Value::from("dimension@2")),
        ("name", Value::from("profile")),
        ("verifier", Value::from(digest)),
        ("registry", Value::from(digest)),
        (
            "statements",
            obj(vec![("profile.patch@1", obj(vec![("floor", number("1"))]))]),
        ),
    ]);
    let envelope = obj(vec![
        ("statement", Value::from(digest_of(&statement).as_str())),
        ("entity", Value::from(digest)),
        ("signer", Value::from("ada")),
        ("rp", Value::from("clavis.nexus")),
        ("aud", Value::from("entity:ada")),
        ("suite", Value::from("webauthn.relayed@1")),
        ("dimension", Value::from(digest_of(&dimension).as_str())),
        ("iat", number("1700000000")),
    ]);
    let client = br#"{"type":"webauthn.get"}"#;
    let mut auth = [0u8; 37];
    auth[32] = 0x05;
    let mut message = Vec::from(auth);
    message.extend_from_slice(&sha256(client));
    let cose = cose_es256(scalar(PASSKEY));
    let mut signature = sign_raw(scalar(PASSKEY), &message);
    assert!(crate::cose::parse_cose_key(&cose).is_some());
    if !matches!(fault, Fault::Proof) {
        assert!(crate::cose::verify_carried_signature(
            &crate::cose::parse_cose_key(&cose).unwrap(),
            &signature,
            &message
        ));
    } else {
        signature = [0u8; 64];
    }
    let proof = obj(vec![
        (
            "authenticator_data",
            Value::from(b64::encode(&auth).as_str()),
        ),
        (
            "client_data_json",
            Value::from(b64::encode(client).as_str()),
        ),
        ("signature", Value::from(b64::encode(&signature).as_str())),
    ]);
    let key = obj(vec![("cose", Value::from(b64::encode(&cose).as_str()))]);
    let core = obj(vec![
        ("type", Value::from("receipt@2")),
        ("statement", statement.clone()),
        ("envelope", envelope.clone()),
        ("proof", proof.clone()),
        ("key", key.clone()),
        ("dimension", dimension.clone()),
    ]);
    let subject = digest_of(&core);
    let other = format!("sha256:{}", "a".repeat(43));
    assert!(is_digest(&other));
    let shown = if matches!(fault, Fault::Subject) {
        other.as_str()
    } else {
        subject.as_str()
    };
    let unsigned = obj(vec![
        ("type", Value::from("accepted@1")),
        ("subject", Value::from(subject.as_str())),
        ("at", number("1700000000")),
        ("kid", Value::from("sign-receipt")),
        ("alg", Value::from("ES256")),
    ]);
    let accepted = obj(vec![
        ("type", Value::from("accepted@1")),
        ("subject", Value::from(shown)),
        ("at", number("1700000000")),
        ("kid", Value::from("sign-receipt")),
        ("alg", Value::from("ES256")),
        (
            "sig",
            Value::from(sign_b64(scalar(RECEIPT_KEY), canonical(&unsigned).as_bytes()).as_str()),
        ),
    ]);
    let leaf = Leaf {
        c: anchor_commitment(&envelope, &digest_of(&proof)),
        slot: None,
    }
    .hash();
    let leaf = if matches!(fault, Fault::Leaf) {
        [0x11u8; 32]
    } else {
        leaf
    };
    let note = receipt_note(&ledger, 7, &leaf);
    let evidence = obj(vec![
        (
            "type",
            Value::from(if matches!(fault, Fault::Type) {
                "receipt@3"
            } else {
                "receipt@2"
            }),
        ),
        ("statement", statement),
        ("envelope", envelope),
        ("proof", proof),
        ("key", key),
        ("dimension", dimension),
        (
            "attestations",
            Value::Array(vec![
                accepted,
                obj(vec![
                    ("type", Value::from("ledger.receipt@1")),
                    ("note", Value::from(note.as_str())),
                ]),
                obj(vec![
                    ("type", Value::from("rp.claim@1")),
                    ("body", number("1")),
                ]),
            ]),
        ),
        (
            "disclosures",
            Value::Array(vec![if matches!(fault, Fault::Disclosure) {
                obj(vec![("type", Value::from("key.chain@1"))])
            } else {
                crate::chain_check::fixture::disclosure(&ledger, digest)
            }]),
        ),
    ]);
    (
        trust_value(scalar(SEALER), scalar(RECEIPT_KEY), &ledger),
        evidence,
    )
}

fn refuse(fault: Fault) -> Reason {
    let (trust_v, evidence) = sample(fault);
    let trust = read_trust(Some(&trust_v)).unwrap_or_else(|e| panic!("{}", e.as_str()));
    verify_receipt(&trust, &evidence, Kind::Holder, None, &Expect::default()).unwrap_err()
}

#[test]
fn receipt2_ok() {
    let (trust_v, evidence) = sample(Fault::None);
    let trust = read_trust(Some(&trust_v)).unwrap_or_else(|e| panic!("{}", e.as_str()));
    let verified = verify_receipt(&trust, &evidence, Kind::Holder, None, &Expect::default())
        .unwrap_or_else(|e| panic!("{}", e.as_str()));
    assert_eq!(verified.kind, Kind::Holder);
    assert!(verified.proof.is_none());
    assert!(verified.key_record.is_none());
    assert!(verified.dimension.signer.is_none());
    assert_eq!(verified.dimension.name, "profile");
    assert_eq!(verified.anchor.log, "first-party.0");
    assert_eq!(verified.anchor.index, 7);
    assert_eq!(
        verified.statement.get("type").and_then(Value::as_str),
        Some("profile.patch@1")
    );
    assert_eq!(
        verified.accepted.first().map(|(kid, _)| kid.as_str()),
        Some("sign-receipt")
    );

    let mut outer = Object::default();
    assert!(outer.insert("op".into(), Value::from("receipt")));
    assert!(outer.insert("trust".into(), trust_v));
    assert!(outer.insert(
        "evidence".into(),
        Value::from(canonical(&evidence).as_str())
    ));
    let answer = parse(&crate::run(canonical(&Value::Object(outer)).as_bytes())).unwrap();
    assert_eq!(answer.get("ok").and_then(Value::as_bool), Some(true));
    assert_eq!(answer.get("type").and_then(Value::as_str), Some(RECEIPT_2));
    assert!(
        answer
            .get("dimension")
            .and_then(Value::as_object)
            .unwrap()
            .get("signer")
            .is_none()
    );
    assert_eq!(answer.get("key_record"), Some(&Value::Null));
    assert!(answer.get("origin").is_none());
}

#[test]
fn receipt2_wrong_type() {
    assert_eq!(refuse(Fault::Type), Reason::ReceiptType);
}

#[test]
fn receipt2_bad_proof() {
    assert_eq!(refuse(Fault::Proof), Reason::ProofSignature);
}

#[test]
fn receipt2_bad_accepted_subject() {
    assert_eq!(refuse(Fault::Subject), Reason::AcceptedSubject);
}

#[test]
fn receipt2_bad_anchor_leaf() {
    assert_eq!(refuse(Fault::Leaf), Reason::LedgerReceiptLeaf);
}

#[test]
fn receipt2_type_only_disclosure() {
    assert_eq!(refuse(Fault::Disclosure), Reason::DisclosureShape);
}

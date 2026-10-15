//! Differential check against the TypeScript evidence code before genesis (evidence-pregenesis,
//! genesis.md §18.6): the same noisy texts must give the same canonical bytes, digests and
//! challenges. The vectors are written by the Clavis Nexus repository
//! (`packages/shared/scripts/collatio-vectors.mts`).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use collatio::challenge::envelope_challenge;
use collatio::digest::digest_of;
use collatio::jcs::canonical;
use collatio::json::{Value, parse};

fn load() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/pregenesis/jcs-1.json"
    );
    parse(&std::fs::read(path).expect("vectors")).expect("vector file reads")
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap()
}

#[test]
fn canonical_and_digest_match_pregenesis() {
    let file = load();
    let cases = file.get("cases").and_then(Value::as_array).unwrap();
    assert!(cases.len() >= 3000);
    for (i, case) in cases.iter().enumerate() {
        let value = parse(s(case, "text").as_bytes()).unwrap_or_else(|e| panic!("case {i}: {e:?}"));
        assert_eq!(canonical(&value), s(case, "canonical"), "case {i}");
        assert_eq!(digest_of(&value), s(case, "digest"), "case {i}");
    }
}

#[test]
fn challenges_match_pregenesis() {
    let file = load();
    let cases = file.get("challenges").and_then(Value::as_array).unwrap();
    assert!(cases.len() >= 500);
    for (i, case) in cases.iter().enumerate() {
        let value = parse(s(case, "text").as_bytes()).unwrap();
        assert_eq!(
            envelope_challenge(&value).as_deref(),
            Some(s(case, "challenge")),
            "challenge {i}"
        );
    }
}

#[test]
fn webauthn1_matches_pregenesis() {
    use collatio::webauthn::verify_webauthn1;
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/pregenesis/webauthn-1.json"
    );
    let file = parse(&std::fs::read(path).expect("vectors")).expect("vector file reads");
    let cases = file.get("cases").and_then(Value::as_array).unwrap();
    assert!(cases.len() >= 900);
    let mut accepted = 0;
    for (i, case) in cases.iter().enumerate() {
        let expect = case.get("expect").unwrap();
        let got = verify_webauthn1(
            case.get("envelope").unwrap(),
            case.get("proof").unwrap(),
            case.get("key").unwrap(),
        );
        match (expect.get("ok"), got) {
            (Some(Value::Bool(true)), Ok(ok)) => {
                accepted += 1;
                assert_eq!(ok.origin, s(expect, "origin"), "case {i}");
                let counter = expect
                    .get("counter")
                    .and_then(Value::as_number)
                    .and_then(|n| n.as_safe_integer());
                assert_eq!(Some(i64::from(ok.counter)), counter, "case {i}");
            }
            (Some(Value::Bool(false)), Err(e)) => {
                assert_eq!(e.as_str(), s(expect, "reason"), "case {i}")
            }
            (_, got) => panic!("case {i}: expected {expect:?}, got {got:?}"),
        }
    }
    assert!(accepted >= 200);
}

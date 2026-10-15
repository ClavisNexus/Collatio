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

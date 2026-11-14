//! Differential check against the Clavis TypeScript evidence code before genesis: the same noisy
//! texts must give the same canonical bytes, digests and challenges. The vectors in
//! `vectors/pregenesis` hold that code's answers.
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
    load_file("jcs-1.json")
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

fn load_file(name: &str) -> Value {
    let path = format!(
        "{}/../../vectors/pregenesis/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    parse(&std::fs::read(path).expect("vectors")).expect("vector file reads")
}

fn arr<'a>(v: &'a Value, k: &str) -> &'a [Value] {
    v.get(k).and_then(Value::as_array).unwrap()
}

fn b(v: &Value, k: &str) -> bool {
    v.get(k).and_then(Value::as_bool).unwrap()
}

fn u(v: &Value, k: &str) -> u64 {
    let n = v
        .get(k)
        .and_then(Value::as_number)
        .and_then(|n| n.as_safe_integer())
        .unwrap();
    u64::try_from(n).unwrap()
}

fn h32(s: &str) -> [u8; 32] {
    collatio::commit::from_hex(s).unwrap().try_into().unwrap()
}

#[test]
fn records_match_pregenesis() {
    use collatio::commit::commitment;
    use collatio::keylog::{KeyRecordKind, parse_key_record};
    use collatio::shown::is_shown_v1;
    use collatio::text::{has_no_ascii_upper, is_line, is_trimmed_text};
    let file = load_file("records-1.json");
    for (i, t) in arr(&file, "texts").iter().enumerate() {
        let txt = s(t, "s");
        assert_eq!(
            is_trimmed_text(txt, 8),
            b(t, "trimmed_8"),
            "text {i} {txt:?}"
        );
        assert_eq!(is_line(txt, 8), b(t, "line_8"), "text {i} {txt:?}");
        assert_eq!(is_line(txt, 80), b(t, "line_80"), "text {i} {txt:?}");
        assert_eq!(has_no_ascii_upper(txt), b(t, "no_upper"), "text {i}");
    }
    for (i, c) in arr(&file, "shown").iter().enumerate() {
        assert_eq!(
            is_shown_v1(c.get("value").unwrap()),
            b(c, "ok"),
            "shown {i}"
        );
    }
    for (i, c) in arr(&file, "key_records").iter().enumerate() {
        let want = c.get("kind").and_then(Value::as_str);
        let got = parse_key_record(c.get("record").unwrap()).map(|k| match k {
            KeyRecordKind::Bound => "bound",
            KeyRecordKind::Unbound => "unbound",
        });
        assert_eq!(got, want, "key record {i}");
    }
    for (i, c) in arr(&file, "commitments").iter().enumerate() {
        assert_eq!(
            commitment(s(c, "salt"), c.get("record").unwrap()).as_deref(),
            Some(s(c, "c")),
            "commitment {i}"
        );
    }
}

#[test]
fn ledger_matches_pregenesis() {
    use collatio::ledger::leaf::parse_leaf;
    use collatio::ledger::merkle::{verify_consistency, verify_inclusion};
    use collatio::ledger::note::{parse_checkpoint_body, parse_receipt_body, verify_note};
    let file = load_file("ledger-1.json");
    let mut accepted = 0;
    for (i, c) in arr(&file, "notes").iter().enumerate() {
        let key: [u8; 32] = collatio::b64::decode(s(c, "public_key"))
            .unwrap()
            .try_into()
            .unwrap();
        let expect = c.get("expect").unwrap();
        match (
            b(expect, "ok"),
            verify_note(s(c, "note"), s(c, "name"), &key),
        ) {
            (true, Ok(body)) => {
                accepted += 1;
                assert_eq!(body, s(expect, "body"), "note {i}");
            }
            (false, Err(e)) => assert_eq!(e.as_str(), s(expect, "error"), "note {i}"),
            (_, got) => panic!("note {i}: expected {expect:?}, got {got:?}"),
        }
    }
    assert!(accepted >= 100);
    let b64 = |x: &[u8]| base64::encode(x);
    for (i, c) in arr(&file, "bodies").iter().enumerate() {
        let body = s(c, "body");
        let expect = c.get("expect").unwrap();
        if s(c, "kind") == "checkpoint" {
            let got = parse_checkpoint_body(body);
            match (expect, got) {
                (Value::Null, None) => {}
                (e, Some(cp)) if *e != Value::Null => {
                    assert_eq!(cp.origin, s(e, "origin"), "body {i}");
                    assert_eq!(cp.size, u(e, "size"), "body {i}");
                    assert_eq!(cp.time, u(e, "time"), "body {i}");
                    assert_eq!(b64(&cp.root), s(e, "root"), "body {i}");
                }
                (e, got) => panic!("body {i}: expected {e:?}, got {got:?}"),
            }
        } else {
            let got = parse_receipt_body(body);
            match (expect, got) {
                (Value::Null, None) => {}
                (e, Some(rc)) if *e != Value::Null => {
                    assert_eq!(rc.origin, s(e, "origin"), "body {i}");
                    assert_eq!(rc.index, u(e, "index"), "body {i}");
                    assert_eq!(b64(&rc.leaf_hash), s(e, "leaf_hash"), "body {i}");
                }
                (e, got) => panic!("body {i}: expected {e:?}, got {got:?}"),
            }
        }
    }
    for (i, c) in arr(&file, "leaves").iter().enumerate() {
        let got = parse_leaf(c.get("leaf").unwrap()).map(|l| collatio::commit::to_hex(&l.hash()));
        assert_eq!(
            got.as_deref(),
            c.get("hash").and_then(Value::as_str),
            "leaf {i}"
        );
    }
    for (i, c) in arr(&file, "merkle").iter().enumerate() {
        let proof: Vec<[u8; 32]> = arr(c, "proof")
            .iter()
            .map(|p| h32(p.as_str().unwrap()))
            .collect();
        let got = if s(c, "kind") == "inclusion" {
            verify_inclusion(
                u(c, "index"),
                u(c, "size"),
                &h32(s(c, "leaf")),
                &proof,
                &h32(s(c, "root")),
            )
        } else {
            verify_consistency(
                u(c, "first"),
                u(c, "second"),
                &h32(s(c, "first_root")),
                &h32(s(c, "second_root")),
                &proof,
            )
        };
        assert_eq!(got, b(c, "expect"), "merkle {i}");
    }
}

mod base64 {
    use base64ct::{Base64, Encoding};
    pub fn encode(x: &[u8]) -> String {
        Base64::encode_string(x)
    }
}

/// Whether a kind string uses the kind `org`, which only Collatio knows.
fn uses_org(kind: &str) -> bool {
    kind.split(['(', ')', ',']).any(|part| part == "org")
}

/// Where Collatio is stricter on purpose: integers written with a fraction or an exponent, and
/// Base64URL of a fixed length whose unused bits are not zero.
fn stricter_on_purpose(kind: &str, value: &str) -> bool {
    let number_spelling = value.contains(['.', 'e', 'E']) && !value.starts_with(['"', '[', '{']);
    let non_canonical = kind.contains("bytes32") && value.len() == 45 && !value.ends_with("A\"");
    (kind.contains("int(") && number_spelling) || non_canonical
}

#[test]
fn field_kinds_match_pregenesis() {
    use collatio::fields::parse_kind;
    let file = load_file("fields-1.json");
    let kinds = file.get("kinds").and_then(Value::as_array).unwrap();
    assert!(kinds.len() >= 1000);
    for case in kinds {
        let kind = s(case, "kind");
        let ts = case.get("ok").and_then(Value::as_bool).unwrap();
        let ours = parse_kind(kind).is_some();
        assert!(
            ours == ts || (ours && uses_org(kind)),
            "kind {kind:?}: {ours}, pre-genesis {ts}"
        );
    }
    let values = file.get("values").and_then(Value::as_array).unwrap();
    assert!(values.len() >= 1000);
    let mut stricter = 0;
    for case in values {
        let (kind, text) = (s(case, "kind"), s(case, "value"));
        let ts = case.get("ok").and_then(Value::as_bool).unwrap();
        let value = parse(text.as_bytes()).unwrap();
        let ours = parse_kind(kind).unwrap().check(&value);
        if ours != ts {
            assert!(
                ts && !ours && stricter_on_purpose(kind, text),
                "kind {kind:?} value {text}: {ours}, pre-genesis {ts}"
            );
            stricter += 1;
        }
    }
    assert!(stricter <= 20, "{stricter} stricter answers");
}

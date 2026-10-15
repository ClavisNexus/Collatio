//! Calls through `run` with the answers FORMATS.md requires. The genesis vectors are written by an
//! independent implementation of the issuing side (`tools/genesis-vectors.mjs`); the Merkle cases
//! reuse the pre-genesis ledger vectors through the `inclusion` and `consistency` operations.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use base64ct::{Base64, Encoding};
use collatio::jcs::canonical;
use collatio::json::{Object, Value, parse};
use collatio::run;

fn load(name: &str) -> Value {
    let path = format!("{}/../../vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    parse(&std::fs::read(&path).expect("vectors")).expect("vector file reads")
}

fn answer(input: &Value) -> Value {
    parse(&run(canonical(input).as_bytes())).expect("answer reads")
}

#[test]
fn genesis_ops() {
    let file = load("genesis/ops-1.json");
    let cases = file.get("cases").and_then(Value::as_array).unwrap();
    assert!(cases.len() >= 60);
    let mut failures = Vec::new();
    for case in cases {
        let name = case.get("name").and_then(Value::as_str).unwrap();
        let want = case.get("answer").and_then(Value::as_object).unwrap();
        let got = answer(case.get("input").unwrap());
        // Every member the vector states must be in the answer, the same.
        for (k, v) in want.iter() {
            let ours = got.get(k).map(canonical);
            if ours.as_deref() != Some(canonical(v).as_str()) {
                failures.push(format!(
                    "{name}: {k} = {} (want {})",
                    ours.unwrap_or_else(|| "missing".into()),
                    canonical(v)
                ));
                break;
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

fn hex_to_b64(h: &str) -> Value {
    let bytes: Vec<u8> = (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
        .collect();
    Value::from(Base64::encode_string(&bytes).as_str())
}

#[test]
fn merkle_ops_match_pregenesis() {
    let file = load("pregenesis/ledger-1.json");
    let cases = file.get("merkle").and_then(Value::as_array).unwrap();
    for (i, case) in cases.iter().enumerate() {
        let c = case.as_object().unwrap();
        let mut input = Object::default();
        let kind = c.get("kind").and_then(Value::as_str).unwrap();
        input.insert("op".into(), Value::from(kind));
        for (k, v) in c.iter() {
            match k {
                "kind" | "expect" => {}
                "leaf" => {
                    input.insert("leaf_hash".into(), hex_to_b64(v.as_str().unwrap()));
                }
                "root" | "first_root" | "second_root" => {
                    input.insert(k.into(), hex_to_b64(v.as_str().unwrap()));
                }
                "proof" => {
                    let list = v.as_array().unwrap();
                    input.insert(
                        k.into(),
                        Value::Array(
                            list.iter()
                                .map(|h| hex_to_b64(h.as_str().unwrap()))
                                .collect(),
                        ),
                    );
                }
                _ => {
                    input.insert(k.into(), v.clone());
                }
            }
        }
        let got = answer(&Value::Object(input));
        let expect = c.get("expect").and_then(Value::as_bool).unwrap();
        let ok = got.get("ok").and_then(Value::as_bool).unwrap();
        if ok != expect {
            // An oversized proof is refused as malformed input rather than checked.
            let reason = got.get("reason").and_then(Value::as_str).unwrap_or("");
            panic!("case {i} ({kind}): ok = {ok}, want {expect} ({reason})");
        }
    }
}

//! TSA tokens against the TypeScript verifier before genesis (vectors/pregenesis/tsa-1.json).
//! Exact cases must give the same reason; flipped tokens must give the same verdict.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use base64ct::{Base64, Encoding};
use collatio::json::{Value, parse};
use collatio::tsa::{TsaTrust, verify_time_stamp_token};
use collatio::tsa_registry::REGISTRY;

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap()
}

#[test]
fn tsa_matches_pregenesis() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/pregenesis/tsa-1.json"
    );
    let file = parse(&std::fs::read(path).unwrap()).unwrap();
    let roots: Vec<Vec<Vec<u8>>> = REGISTRY
        .iter()
        .map(|e| {
            e.roots
                .iter()
                .map(|r| Base64::decode_vec(r).unwrap())
                .collect()
        })
        .collect();
    let root_refs: Vec<Vec<&[u8]>> = roots
        .iter()
        .map(|rs| rs.iter().map(Vec::as_slice).collect())
        .collect();
    let entry = |i: usize, roots_of: usize| TsaTrust {
        id: REGISTRY[i].id,
        policies: REGISTRY[i].policies,
        roots: &root_refs[roots_of],
    };
    let n = REGISTRY.len();
    let variant = |name: &str| -> Vec<TsaTrust<'_>> {
        match name {
            "registry" => (0..n).map(|i| entry(i, i)).collect(),
            "empty" => vec![],
            "sectigo_only" => (0..n)
                .filter(|&i| REGISTRY[i].id == "sectigo-qualified")
                .map(|i| entry(i, i))
                .collect(),
            "digicert_only" => (0..n)
                .filter(|&i| REGISTRY[i].id == "digicert")
                .map(|i| entry(i, i))
                .collect(),
            "roots_swapped" => (0..n).map(|i| entry(i, (i + 1) % n)).collect(),
            other => panic!("unknown trust variant {other}"),
        }
    };
    let mut problems = Vec::new();
    let mut stricter: Vec<String> = Vec::new();
    let cases = file.get("cases").and_then(Value::as_array).unwrap();
    for c in cases {
        let der = Base64::decode_vec(s(c, "response")).unwrap();
        let nonce = c
            .get("nonce")
            .and_then(Value::as_str)
            .map(|h| collatio::commit::from_hex(h).unwrap());
        let trust = variant(s(c, "trust"));
        let got =
            verify_time_stamp_token(&der, s(c, "message").as_bytes(), nonce.as_deref(), &trust);
        let expect = c.get("expect").unwrap();
        let want_ok = expect.get("ok").and_then(Value::as_bool).unwrap();
        let exact = c.get("exact").and_then(Value::as_bool).unwrap();
        let name = s(c, "name");
        match (&got, want_ok) {
            (Ok(ok), true) => {
                let gen_time = expect
                    .get("genTime")
                    .and_then(Value::as_number)
                    .and_then(|n| n.as_safe_integer())
                    .unwrap();
                if ok.tsa != s(expect, "tsa")
                    || ok.gen_time != gen_time
                    || ok.policy != s(expect, "policy")
                {
                    problems.push(format!("{name}: ok but {ok:?} vs {expect:?}"));
                }
            }
            (Err(e), false) => {
                if exact && e.as_str() != s(expect, "reason") {
                    problems.push(format!(
                        "{name}: reason {} vs {}",
                        e.as_str(),
                        s(expect, "reason")
                    ));
                }
            }
            // On a corrupted token Collatio may refuse what the TypeScript let through (it reads
            // every element strictly, including ones nothing signs); it must never accept what the
            // TypeScript refused.
            (Err(_), true) if !exact => stricter.push(name.to_string()),
            (got, _) => problems.push(format!(
                "{name}: verdict {got:?} vs {}",
                if want_ok {
                    "ok".into()
                } else {
                    s(expect, "reason").to_string()
                }
            )),
        }
    }
    assert!(
        problems.is_empty(),
        "{} problems:\n{}",
        problems.len(),
        problems.join("\n")
    );
    // A handful of flips land in headers and unsigned certificates; more would mean a reader that
    // refuses real tokens.
    assert!(
        stricter.len() <= 12,
        "stricter on {} flipped tokens: {stricter:?}",
        stricter.len()
    );
    eprintln!(
        "stricter than the TypeScript on {} flipped tokens: {stricter:?}",
        stricter.len()
    );
}

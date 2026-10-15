//! RSASSA-PKCS1-v1_5 verification against Project Wycheproof (spike/vectors/wycheproof, pinned).
//! Valid signatures must verify and invalid ones must not; "acceptable" cases may go either way.
//! 8192-bit keys and public exponents other than 65537 are outside the accepted range and must be
//! refused.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use collatio::commit::from_hex;
use collatio::json::{Value, parse};
use collatio::rsa::{Hash, PublicKey, verify};

#[test]
fn wycheproof_pkcs1_v15() {
    let dir = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../spike/vectors/wycheproof"
    );
    let mut checked = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        if !name.starts_with("rsa_signature_") {
            continue;
        }
        let file = parse(&std::fs::read(&path).unwrap()).unwrap();
        for group in file.get("testGroups").and_then(Value::as_array).unwrap() {
            let hash = match group.get("sha").and_then(Value::as_str).unwrap() {
                "SHA-256" => Hash::Sha256,
                "SHA-384" => Hash::Sha384,
                "SHA-512" => Hash::Sha512,
                other => panic!("{other}"),
            };
            let key = group.get("publicKey").unwrap();
            let n = from_hex(key.get("modulus").and_then(Value::as_str).unwrap()).unwrap();
            let e = from_hex(key.get("publicExponent").and_then(Value::as_str).unwrap()).unwrap();
            let pk = PublicKey { n: &n, e: &e };
            let outside = name.contains("8192") || e != [0x01, 0x00, 0x01];
            for t in group.get("tests").and_then(Value::as_array).unwrap() {
                let msg = from_hex(t.get("msg").and_then(Value::as_str).unwrap()).unwrap();
                let sig = from_hex(t.get("sig").and_then(Value::as_str).unwrap()).unwrap();
                let got = verify(&pk, &msg, &sig, hash);
                let id = t.get("tcId").and_then(Value::as_number).unwrap().as_f64();
                match t.get("result").and_then(Value::as_str).unwrap() {
                    _ if outside => {
                        assert!(!got, "{name} {id}: key outside the accepted range accepted")
                    }
                    "valid" => assert!(got, "{name} {id}: valid refused"),
                    "invalid" => assert!(!got, "{name} {id}: invalid accepted"),
                    _ => {}
                }
                checked += 1;
            }
        }
    }
    assert!(checked > 2500, "{checked}");
}

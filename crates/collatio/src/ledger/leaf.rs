//! Ledger leaves: `{ v: 1, c, slot? }`. No time, subject, kind or app identifier.
//! leaf hash = SHA-256(0x00 ‖ JCS(leaf)).

use alloc::string::String;

use super::merkle::{Hash, leaf_hash};
use crate::commit::is_hex64;
use crate::jcs::canonical;
use crate::json::{Number, Object, Value};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Leaf {
    /// The commitment, 64 lowercase hex digits.
    pub c: String,
    /// A unique slot, 64 lowercase hex digits, when the leaf claims one.
    pub slot: Option<String>,
}

pub fn parse_leaf(v: &Value) -> Option<Leaf> {
    let o = v.as_object()?;
    if o.keys().any(|k| k != "v" && k != "c" && k != "slot") {
        return None;
    }
    if o.get("v")?.as_number()?.as_safe_integer()? != 1 {
        return None;
    }
    let c = o.get("c")?.as_str()?;
    if !is_hex64(c) {
        return None;
    }
    let slot = match o.get("slot") {
        None => None,
        Some(s) => {
            let s = s.as_str()?;
            if !is_hex64(s) {
                return None;
            }
            Some(String::from(s))
        }
    };
    Some(Leaf {
        c: String::from(c),
        slot,
    })
}

impl Leaf {
    pub fn to_value(&self) -> Value {
        let mut o = Object::default();
        o.insert(
            String::from("v"),
            Value::Number(Number::from_parts("1", 1.0)),
        );
        o.insert(String::from("c"), Value::from(self.c.as_str()));
        if let Some(slot) = &self.slot {
            o.insert(String::from("slot"), Value::from(slot.as_str()));
        }
        Value::Object(o)
    }

    pub fn hash(&self) -> Hash {
        leaf_hash(canonical(&self.to_value()).as_bytes())
    }
}

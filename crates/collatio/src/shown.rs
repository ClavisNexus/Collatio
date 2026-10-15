//! The envelope extension `shown@1`: the line Connect showed right before the signature (who and
//! what). Only the normalized form passes; normalizing is the issuer's job.

use crate::json::Value;
use crate::text::{has_no_ascii_upper, is_line};

pub const SHOWN_1: &str = "shown@1";
pub const SHOWN_APP_MAX: usize = 80;
pub const SHOWN_HOST_MAX: usize = 253;
pub const SHOWN_ACTION_MAX: usize = 500;

/// `{ app, host, action? }`: the product name (or the host), the confirmed app host in lowercase,
/// and the operation the app named, when it named one.
pub fn is_shown_v1(v: &Value) -> bool {
    let Some(o) = v.as_object() else {
        return false;
    };
    if o.keys().any(|k| k != "app" && k != "host" && k != "action") {
        return false;
    }
    let line = |key: &str, max: usize| {
        o.get(key)
            .and_then(Value::as_str)
            .is_some_and(|s| is_line(s, max))
    };
    if !line("app", SHOWN_APP_MAX) {
        return false;
    }
    if !(line("host", SHOWN_HOST_MAX)
        && o.get("host")
            .and_then(Value::as_str)
            .is_some_and(has_no_ascii_upper))
    {
        return false;
    }
    if o.get("action").is_some() && !line("action", SHOWN_ACTION_MAX) {
        return false;
    }
    true
}

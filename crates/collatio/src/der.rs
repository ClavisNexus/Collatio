//! A small DER reader for the structures the verifier reads (certificates, CMS, TSTInfo).
//!
//! Lengths are definite and at most 4 bytes; tags are one byte (no high-tag-number form). The
//! reader keeps the raw bytes of every element, because signatures cover encodings, not values.
//! The only BER it accepts is a constructed OCTET STRING, through [`octets`].

use alloc::vec::Vec;

pub const SEQUENCE: u8 = 0x30;
pub const SET: u8 = 0x31;
pub const INTEGER: u8 = 0x02;
pub const BIT_STRING: u8 = 0x03;
pub const OCTET_STRING: u8 = 0x04;
pub const NULL: u8 = 0x05;
pub const OID: u8 = 0x06;
pub const BOOLEAN: u8 = 0x01;
pub const UTC_TIME: u8 = 0x17;
pub const GENERALIZED_TIME: u8 = 0x18;
pub const CONSTRUCTED_OCTET_STRING: u8 = 0x24;

/// Context-specific tag number `n`, constructed.
pub const fn context(n: u8) -> u8 {
    0xa0 | n
}

/// Context-specific tag number `n`, primitive.
pub const fn context_primitive(n: u8) -> u8 {
    0x80 | n
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tlv<'a> {
    pub tag: u8,
    /// The whole element: tag, length and value.
    pub raw: &'a [u8],
    pub value: &'a [u8],
}

/// Reads elements one after another from a byte string.
#[derive(Clone, Debug)]
pub struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Reader<'a> {
        Reader { bytes, pos: 0 }
    }

    pub fn is_empty(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    pub fn peek_tag(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    /// The next element, whatever its tag.
    pub fn any(&mut self) -> Option<Tlv<'a>> {
        let start = self.pos;
        let tag = *self.bytes.get(start)?;
        if tag & 0x1f == 0x1f {
            return None;
        }
        let first = *self.bytes.get(start.checked_add(1)?)?;
        let mut p = start.checked_add(2)?;
        let len = if first & 0x80 == 0 {
            usize::from(first)
        } else {
            let n = usize::from(first & 0x7f);
            if n == 0 || n > 4 {
                return None;
            }
            let mut len = 0usize;
            for _ in 0..n {
                len = len
                    .checked_mul(256)?
                    .checked_add(usize::from(*self.bytes.get(p)?))?;
                p = p.checked_add(1)?;
            }
            len
        };
        let end = p.checked_add(len)?;
        let value = self.bytes.get(p..end)?;
        let raw = self.bytes.get(start..end)?;
        self.pos = end;
        Some(Tlv { tag, raw, value })
    }

    /// The next element, which must have `tag`.
    pub fn expect(&mut self, tag: u8) -> Option<Tlv<'a>> {
        if self.peek_tag()? != tag {
            return None;
        }
        self.any()
    }

    /// The next element when it has `tag`; otherwise nothing is read.
    pub fn optional(&mut self, tag: u8) -> Option<Tlv<'a>> {
        if self.peek_tag() == Some(tag) {
            self.any()
        } else {
            None
        }
    }

    /// Reader over the value of the next element with `tag`.
    pub fn nested(&mut self, tag: u8) -> Option<Reader<'a>> {
        self.expect(tag).map(|t| Reader::new(t.value))
    }
}

/// Reads exactly one element covering all of `bytes`.
pub fn single(bytes: &[u8]) -> Option<Tlv<'_>> {
    let mut r = Reader::new(bytes);
    let t = r.any()?;
    r.is_empty().then_some(t)
}

/// The content of an OCTET STRING element, primitive or constructed (BER chunks concatenated).
pub fn octets(t: &Tlv<'_>) -> Option<Vec<u8>> {
    match t.tag {
        OCTET_STRING => Some(t.value.to_vec()),
        CONSTRUCTED_OCTET_STRING => {
            let mut out = Vec::new();
            let mut r = Reader::new(t.value);
            while !r.is_empty() {
                let chunk = r.any()?;
                out.extend_from_slice(&octets(&chunk)?);
            }
            Some(out)
        }
        _ => None,
    }
}

/// An INTEGER's value without leading zero bytes (at least one byte).
pub fn unsigned(value: &[u8]) -> &[u8] {
    let first = value
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(value.len().saturating_sub(1));
    value.get(first..).unwrap_or(value)
}

/// A small non-negative INTEGER.
pub fn small_int(t: &Tlv<'_>) -> Option<u64> {
    if t.tag != INTEGER || t.value.is_empty() || t.value.len() > 8 || t.value.first()? & 0x80 != 0 {
        return None;
    }
    Some(
        t.value
            .iter()
            .fold(0u64, |acc, &b| acc.wrapping_shl(8) | u64::from(b)),
    )
}

/// The dotted form of an OID's content bytes.
pub fn oid_string(value: &[u8]) -> Option<alloc::string::String> {
    use core::fmt::Write;
    let mut out = alloc::string::String::new();
    let mut acc: u64 = 0;
    let mut first = true;
    if value.is_empty() || value.last()? & 0x80 != 0 {
        return None;
    }
    for &b in value {
        if acc == 0 && b == 0x80 {
            return None; // non-minimal
        }
        acc = acc.checked_mul(128)?.checked_add(u64::from(b & 0x7f))?;
        if b & 0x80 == 0 {
            if first {
                let (a, rest) = match acc {
                    0..=39 => (0, acc),
                    40..=79 => (1, acc.wrapping_sub(40)),
                    _ => (2, acc.wrapping_sub(80)),
                };
                write!(out, "{a}.{rest}").ok()?;
                first = false;
            } else {
                write!(out, ".{acc}").ok()?;
            }
            acc = 0;
        }
    }
    Some(out)
}

/// Unix seconds from UTCTime (`YYMMDDHHMMSSZ`, 1950–2049) or GeneralizedTime
/// (`YYYYMMDDHHMMSS[.fraction]Z`; the fraction is dropped).
pub fn time(t: &Tlv<'_>) -> Option<i64> {
    let s = core::str::from_utf8(t.value).ok()?;
    let s = s.strip_suffix('Z')?;
    let (year, rest) = match t.tag {
        UTC_TIME => {
            if s.len() != 12 {
                return None;
            }
            let yy: i64 = digits(s.get(0..2)?)?;
            (
                if yy < 50 {
                    yy.checked_add(2000)?
                } else {
                    yy.checked_add(1900)?
                },
                s.get(2..)?,
            )
        }
        GENERALIZED_TIME => {
            let main = s.split_once('.').map_or(s, |(m, frac)| {
                if frac.is_empty() || !frac.bytes().all(|b| b.is_ascii_digit()) {
                    ""
                } else {
                    m
                }
            });
            if main.len() != 14 {
                return None;
            }
            (digits(main.get(0..4)?)?, main.get(4..)?)
        }
        _ => return None,
    };
    let month: i64 = digits(rest.get(0..2)?)?;
    let day: i64 = digits(rest.get(2..4)?)?;
    let hour: i64 = digits(rest.get(4..6)?)?;
    let minute: i64 = digits(rest.get(6..8)?)?;
    let second: i64 = digits(rest.get(8..10)?)?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let days = days_from_civil(year, month, day)?;
    days.checked_mul(86_400)?
        .checked_add(hour.checked_mul(3600)?)?
        .checked_add(minute.checked_mul(60)?)?
        .checked_add(second)
}

fn digits(s: &str) -> Option<i64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// Days since 1970-01-01 (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> Option<i64> {
    let y = if m <= 2 { y.checked_sub(1)? } else { y };
    let era = y.div_euclid(400);
    let yoe = y.checked_sub(era.checked_mul(400)?)?;
    let mp = if m > 2 {
        m.checked_sub(3)?
    } else {
        m.checked_add(9)?
    };
    let doy = (153_i64.checked_mul(mp)?.checked_add(2)?)
        .checked_div(5)?
        .checked_add(d)?
        .checked_sub(1)?;
    let doe = yoe
        .checked_mul(365)?
        .checked_add(yoe / 4)?
        .checked_sub(yoe / 100)?
        .checked_add(doy)?;
    era.checked_mul(146_097)?
        .checked_add(doe)?
        .checked_sub(719_468)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times() {
        let t = |tag: u8, s: &str| {
            time(&Tlv {
                tag,
                raw: &[],
                value: s.as_bytes(),
            })
        };
        assert_eq!(t(UTC_TIME, "700101000000Z"), Some(0));
        assert_eq!(t(GENERALIZED_TIME, "20261011193547Z"), Some(1_791_747_347));
        assert_eq!(
            t(GENERALIZED_TIME, "20261011193547.123Z"),
            Some(1_791_747_347)
        );
        assert_eq!(t(UTC_TIME, "490101000000Z"), Some(2_493_072_000));
        assert_eq!(t(GENERALIZED_TIME, "20261311193547Z"), None);
    }

    #[test]
    fn oids() {
        assert_eq!(
            oid_string(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]).as_deref(),
            Some("1.2.840.113549.1.1.11")
        );
        assert_eq!(
            oid_string(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]).as_deref(),
            Some("2.16.840.1.101.3.4.2.1")
        );
    }
}

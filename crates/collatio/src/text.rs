//! Character rules for text fields. They do not depend on a Unicode version: no normalization,
//! no `\s`, no case mapping. Whitespace is the ECMAScript WhiteSpace and LineTerminator set
//! (Unicode 15) written out by code point. Normalization is the issuer's job; the verifier only
//! checks the resulting form.

/// U+0009–U+000D, U+0020, U+00A0, U+1680, U+2000–U+200A, U+2028, U+2029, U+202F, U+205F,
/// U+3000, U+FEFF.
pub fn is_whitespace(c: char) -> bool {
    matches!(
        c,
        '\u{9}'..='\u{d}'
            | ' '
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
            | '\u{feff}'
    )
}

/// C0, DEL and C1.
pub fn is_control(c: char) -> bool {
    matches!(c, '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}')
}

/// Length in UTF-16 code units, as ECMAScript counts it.
pub fn utf16_len(s: &str) -> usize {
    s.chars().map(char::len_utf16).sum()
}

/// 1..=max UTF-16 code units, no control characters, no whitespace at either end.
pub fn is_trimmed_text(s: &str, max: usize) -> bool {
    let len = utf16_len(s);
    len > 0
        && len <= max
        && !s.chars().any(is_control)
        && !s.chars().next().is_some_and(is_whitespace)
        && !s.chars().next_back().is_some_and(is_whitespace)
}

/// A line people read: trimmed text whose only whitespace is U+0020, never two in a row.
pub fn is_line(s: &str, max: usize) -> bool {
    is_trimmed_text(s, max) && !s.chars().any(|c| c != ' ' && is_whitespace(c)) && !s.contains("  ")
}

pub fn has_no_ascii_upper(s: &str) -> bool {
    !s.bytes().any(|b| b.is_ascii_uppercase())
}

/// Contains neither whitespace nor control characters.
pub fn has_no_whitespace(s: &str) -> bool {
    !s.chars().any(|c| is_whitespace(c) || is_control(c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines() {
        assert!(is_line("Shop", 80));
        assert!(!is_line(" Shop", 80));
        assert!(!is_line("Sh  op", 80));
        assert!(!is_line("Sh\u{a0}op", 80));
        assert!(!is_line("Sh\u{85}op", 80));
        assert!(is_trimmed_text("Sh\u{a0}op", 80));
        assert!(!is_trimmed_text("", 80));
        assert!(is_line("\u{1f600}", 2));
        assert!(!is_line("\u{1f600}", 1));
    }
}

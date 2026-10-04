//! Tokenizer for display filters.

use crate::error::{FilterError, Span};

/// Longest accepted filter, in bytes.
pub const MAX_FILTER_BYTES: usize = 1024;
/// Most tokens in one filter.
pub const MAX_TOKENS: usize = 256;
/// Longest string literal, in characters.
pub const MAX_STRING_CHARS: usize = 255;

#[derive(Debug, Clone, PartialEq)]
pub enum TokenKind {
    /// A field name or keyword such as `ip.src`, `tcp`, `and`, `contains`.
    Word(String),
    /// An unquoted value: a number, IP address, CIDR block or bare word
    /// value. Kept as text; its type is checked against the field.
    Literal(String),
    /// A double-quoted string with `\"` and `\\` escapes.
    Str(String),
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
    Not,
    LParen,
    RParen,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Token {
    pub kind: TokenKind,
    pub span: Span,
}

fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':' | '/')
}

/// Splits `input` into tokens. Rejects over-long input, non-ASCII outside
/// strings, unterminated strings and unknown characters, reporting the byte
/// offset of the problem.
pub fn tokenize(input: &str) -> Result<Vec<Token>, FilterError> {
    if input.len() > MAX_FILTER_BYTES {
        return Err(FilterError::TooLong {
            max: MAX_FILTER_BYTES,
        });
    }
    let chars: Vec<(usize, char)> = input.char_indices().collect();
    let mut tokens = Vec::new();
    let mut i = 0;
    while let Some(&(start, c)) = chars.get(i) {
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if tokens.len() == MAX_TOKENS {
            return Err(FilterError::TooComplex {
                reason: "too many tokens",
                span: Span::char_at(start, c),
            });
        }
        let two: String = chars.iter().skip(i).take(2).map(|&(_, c)| c).collect();
        let (kind, consumed) = match (c, two.as_str()) {
            (_, "==") => (TokenKind::Eq, 2),
            (_, "!=") => (TokenKind::Ne, 2),
            (_, "<=") => (TokenKind::Le, 2),
            (_, ">=") => (TokenKind::Ge, 2),
            (_, "&&") => (TokenKind::And, 2),
            (_, "||") => (TokenKind::Or, 2),
            ('<', _) => (TokenKind::Lt, 1),
            ('>', _) => (TokenKind::Gt, 1),
            ('!', _) => (TokenKind::Not, 1),
            ('(', _) => (TokenKind::LParen, 1),
            (')', _) => (TokenKind::RParen, 1),
            ('"', _) => {
                let (text, consumed) = read_string(&chars, i)?;
                (TokenKind::Str(text), consumed)
            }
            (c, _) if is_word_char(c) => {
                let word: String = chars
                    .iter()
                    .skip(i)
                    .map(|&(_, c)| c)
                    .take_while(|&c| is_word_char(c))
                    .collect();
                let consumed = word.chars().count();
                if consumed > MAX_STRING_CHARS {
                    return Err(FilterError::TooComplex {
                        reason: "value is longer than 255 characters",
                        span: Span::at(start),
                    });
                }
                let lower = word.to_ascii_lowercase();
                let kind = match lower.as_str() {
                    "and" => TokenKind::And,
                    "or" => TokenKind::Or,
                    "not" => TokenKind::Not,
                    "eq" => TokenKind::Eq,
                    "ne" => TokenKind::Ne,
                    "lt" => TokenKind::Lt,
                    "le" => TokenKind::Le,
                    "gt" => TokenKind::Gt,
                    "ge" => TokenKind::Ge,
                    _ if word.starts_with(|c: char| c.is_ascii_alphabetic())
                        && word
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_') =>
                    {
                        TokenKind::Word(lower)
                    }
                    _ => TokenKind::Literal(word),
                };
                (kind, consumed)
            }
            (c, _) => {
                return Err(FilterError::UnexpectedCharacter {
                    character: if c.is_ascii_graphic() { c } else { '?' },
                    span: Span::char_at(start, c),
                });
            }
        };
        let end = chars.get(i + consumed).map_or(input.len(), |&(pos, _)| pos);
        tokens.push(Token {
            kind,
            span: Span { start, end },
        });
        i += consumed;
    }
    Ok(tokens)
}

/// Reads a string literal starting at the opening quote `chars[i]`. Returns
/// the unescaped text and the number of characters consumed.
fn read_string(chars: &[(usize, char)], i: usize) -> Result<(String, usize), FilterError> {
    let start = chars.get(i).map_or(0, |&(p, _)| p);
    let mut text = String::new();
    let mut j = i + 1;
    loop {
        let Some(&(_, c)) = chars.get(j) else {
            return Err(FilterError::UnterminatedString {
                span: Span::at(start),
            });
        };
        match c {
            '"' => return Ok((text, j - i + 1)),
            '\\' => {
                let escaped = chars.get(j + 1).map(|&(_, c)| c);
                match escaped {
                    Some(e @ ('"' | '\\')) => text.push(e),
                    _ => {
                        return Err(FilterError::InvalidEscape {
                            span: Span::at(chars.get(j).map_or(start, |&(p, _)| p)),
                        });
                    }
                }
                j += 2;
            }
            c if c.is_control() => {
                return Err(FilterError::UnexpectedCharacter {
                    character: '?',
                    span: Span::char_at(chars.get(j).map_or(start, |&(p, _)| p), c),
                });
            }
            c => {
                text.push(c);
                j += 1;
            }
        }
        if text.chars().count() > MAX_STRING_CHARS {
            return Err(FilterError::TooComplex {
                reason: "string literal is longer than 255 characters",
                span: Span::at(start),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(input: &str) -> Vec<TokenKind> {
        tokenize(input)
            .unwrap()
            .into_iter()
            .map(|t| t.kind)
            .collect()
    }

    #[test]
    fn tokenizes_comparisons_and_logic() {
        assert_eq!(
            kinds(
                "ip.src == 192.0.2.0/24 && !(tcp.port >= 1024) or dns.qry.name contains \"ex\\\"a\""
            ),
            vec![
                TokenKind::Word("ip.src".into()),
                TokenKind::Eq,
                TokenKind::Literal("192.0.2.0/24".into()),
                TokenKind::And,
                TokenKind::Not,
                TokenKind::LParen,
                TokenKind::Word("tcp.port".into()),
                TokenKind::Ge,
                TokenKind::Literal("1024".into()),
                TokenKind::RParen,
                TokenKind::Or,
                TokenKind::Word("dns.qry.name".into()),
                TokenKind::Word("contains".into()),
                TokenKind::Str("ex\"a".into()),
            ]
        );
    }

    #[test]
    fn keywords_are_case_insensitive() {
        assert_eq!(
            kinds("TCP AND Udp"),
            vec![
                TokenKind::Word("tcp".into()),
                TokenKind::And,
                TokenKind::Word("udp".into()),
            ]
        );
        assert_eq!(
            kinds("2001:db8::1"),
            vec![TokenKind::Literal("2001:db8::1".into())]
        );
    }

    #[test]
    fn errors_report_positions() {
        assert_eq!(
            tokenize("ip.src == 'x'").unwrap_err(),
            FilterError::UnexpectedCharacter {
                character: '\'',
                span: Span::at(10)
            }
        );
        assert_eq!(
            tokenize("http.host == \"abc").unwrap_err(),
            FilterError::UnterminatedString { span: Span::at(13) }
        );
        assert_eq!(
            tokenize("x == \"a\\nb\"").unwrap_err(),
            FilterError::InvalidEscape { span: Span::at(7) }
        );
        assert!(matches!(
            tokenize("x;DROP TABLE"),
            Err(FilterError::UnexpectedCharacter { character: ';', .. })
        ));
    }

    #[test]
    fn limits_are_enforced() {
        assert!(matches!(
            tokenize(&"a ".repeat(600)),
            Err(FilterError::TooLong { .. })
        ));
        assert!(matches!(
            tokenize(&"a ".repeat(300)),
            Err(FilterError::TooComplex { .. })
        ));
        let long = format!("\"{}\"", "x".repeat(300));
        assert!(matches!(
            tokenize(&long),
            Err(FilterError::TooComplex { .. })
        ));
    }
}

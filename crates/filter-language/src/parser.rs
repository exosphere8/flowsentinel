//! Recursive-descent parser producing an untyped AST.
//!
//! Grammar (lowest precedence first):
//!
//! ```text
//! expr       = or
//! or         = and { ("or" | "||") and }
//! and        = unary { ("and" | "&&") unary }
//! unary      = ("not" | "!") unary | primary
//! primary    = "(" expr ")" | field [ operator value ]
//! operator   = "==" | "!=" | "<" | "<=" | ">" | ">=" | "contains"
//!              (or the word forms eq ne lt le gt ge)
//! value      = number | ip | cidr | word | "string"
//! ```
//!
//! A bare field (no operator) tests presence, for example `dns` or
//! `tcp.flags.syn`.

use crate::error::{FilterError, Span};
use crate::lexer::{Token, TokenKind, tokenize};

/// Deepest allowed nesting of parentheses and `not`.
pub const MAX_DEPTH: usize = 16;
/// Most comparisons and presence tests in one filter.
pub const MAX_CLAUSES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Contains,
}

impl Op {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Eq => "==",
            Self::Ne => "!=",
            Self::Lt => "<",
            Self::Le => "<=",
            Self::Gt => ">",
            Self::Ge => ">=",
            Self::Contains => "contains",
        }
    }
}

/// A literal as written; typed later against the field.
#[derive(Debug, Clone, PartialEq)]
pub enum RawValue {
    /// Unquoted text (number, address, CIDR or bare word).
    Bare(String),
    /// Quoted string.
    Quoted(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    And(Vec<Expr>),
    Or(Vec<Expr>),
    Not(Box<Expr>),
    /// `field` alone.
    Present {
        field: String,
        span: Span,
    },
    Compare {
        field: String,
        field_span: Span,
        op: Op,
        op_span: Span,
        value: RawValue,
        value_span: Span,
    },
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    depth: usize,
    clauses: usize,
    end: usize,
}

/// Parses `input` into an AST, enforcing size, depth and clause limits.
pub fn parse(input: &str) -> Result<Expr, FilterError> {
    let tokens = tokenize(input)?;
    if tokens.is_empty() {
        return Err(FilterError::Empty);
    }
    let mut parser = Parser {
        tokens,
        pos: 0,
        depth: 0,
        clauses: 0,
        end: input.len(),
    };
    let expr = parser.or()?;
    if let Some(token) = parser.peek() {
        return Err(FilterError::Syntax {
            expected: "`and`, `or` or the end of the filter",
            span: token.span,
        });
    }
    Ok(expr)
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.pos).cloned();
        if token.is_some() {
            self.pos += 1;
        }
        token
    }

    fn here(&self) -> Span {
        self.peek().map_or(Span::empty(self.end), |t| t.span)
    }

    fn or(&mut self) -> Result<Expr, FilterError> {
        let mut items = vec![self.and()?];
        while matches!(self.peek().map(|t| &t.kind), Some(TokenKind::Or)) {
            self.pos += 1;
            items.push(self.and()?);
        }
        Ok(match items.len() {
            1 => items.pop().unwrap_or(Expr::Or(Vec::new())),
            _ => Expr::Or(items),
        })
    }

    fn and(&mut self) -> Result<Expr, FilterError> {
        let mut items = vec![self.unary()?];
        while matches!(self.peek().map(|t| &t.kind), Some(TokenKind::And)) {
            self.pos += 1;
            items.push(self.unary()?);
        }
        Ok(match items.len() {
            1 => items.pop().unwrap_or(Expr::And(Vec::new())),
            _ => Expr::And(items),
        })
    }

    fn enter(&mut self) -> Result<(), FilterError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(FilterError::TooComplex {
                reason: "nesting is deeper than 16 levels",
                span: self.here(),
            });
        }
        Ok(())
    }

    fn unary(&mut self) -> Result<Expr, FilterError> {
        if matches!(self.peek().map(|t| &t.kind), Some(TokenKind::Not)) {
            self.pos += 1;
            self.enter()?;
            let inner = self.unary()?;
            self.depth -= 1;
            return Ok(Expr::Not(Box::new(inner)));
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<Expr, FilterError> {
        let span = self.here();
        match self.next().map(|t| t.kind) {
            Some(TokenKind::LParen) => {
                self.enter()?;
                let inner = self.or()?;
                self.depth -= 1;
                match self.next() {
                    Some(Token {
                        kind: TokenKind::RParen,
                        ..
                    }) => Ok(inner),
                    other => Err(FilterError::Syntax {
                        expected: "`)`",
                        span: other.map_or(Span::empty(self.end), |t| t.span),
                    }),
                }
            }
            Some(TokenKind::Word(field)) => {
                self.clauses += 1;
                if self.clauses > MAX_CLAUSES {
                    return Err(FilterError::TooComplex {
                        reason: "more than 64 comparisons",
                        span,
                    });
                }
                let op_span = self.here();
                let op = match self.peek().map(|t| &t.kind) {
                    Some(TokenKind::Eq) => Op::Eq,
                    Some(TokenKind::Ne) => Op::Ne,
                    Some(TokenKind::Lt) => Op::Lt,
                    Some(TokenKind::Le) => Op::Le,
                    Some(TokenKind::Gt) => Op::Gt,
                    Some(TokenKind::Ge) => Op::Ge,
                    Some(TokenKind::Word(w)) if w == "contains" => Op::Contains,
                    _ => return Ok(Expr::Present { field, span }),
                };
                self.pos += 1;
                let value_span = self.here();
                let value = match self.next().map(|t| t.kind) {
                    Some(TokenKind::Literal(text) | TokenKind::Word(text)) => RawValue::Bare(text),
                    Some(TokenKind::Str(text)) => RawValue::Quoted(text),
                    _ => {
                        return Err(FilterError::Syntax {
                            expected: "a value",
                            span: value_span,
                        });
                    }
                };
                Ok(Expr::Compare {
                    field,
                    field_span: span,
                    op,
                    op_span,
                    value,
                    value_span,
                })
            }
            _ => Err(FilterError::Syntax {
                expected: "a field name, `not` or `(`",
                span,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precedence_is_not_then_and_then_or() {
        let expr = parse("a or b and not c").unwrap();
        let Expr::Or(items) = expr else {
            panic!("{expr:?}")
        };
        assert!(matches!(&items[0], Expr::Present { field, .. } if field == "a"));
        let Expr::And(inner) = &items[1] else {
            panic!()
        };
        assert!(matches!(&inner[1], Expr::Not(_)));
    }

    #[test]
    fn parentheses_group() {
        let expr = parse("(a || b) && c").unwrap();
        let Expr::And(items) = expr else { panic!() };
        assert!(matches!(items[0], Expr::Or(_)));
    }

    #[test]
    fn comparisons_carry_spans() {
        let Expr::Compare {
            field,
            op,
            value,
            value_span,
            ..
        } = parse("tcp.port >= 1024").unwrap()
        else {
            panic!()
        };
        assert_eq!((field.as_str(), op), ("tcp.port", Op::Ge));
        assert_eq!(value, RawValue::Bare("1024".into()));
        assert_eq!(value_span, Span { start: 12, end: 16 });
    }

    #[test]
    fn syntax_errors_point_at_the_problem() {
        let cases = [
            ("", FilterError::Empty),
            (
                "a ==",
                FilterError::Syntax {
                    expected: "a value",
                    span: Span::empty(4),
                },
            ),
            (
                "(a",
                FilterError::Syntax {
                    expected: "`)`",
                    span: Span::empty(2),
                },
            ),
            (
                "a b",
                FilterError::Syntax {
                    expected: "`and`, `or` or the end of the filter",
                    span: Span { start: 2, end: 3 },
                },
            ),
            (
                "== 1",
                FilterError::Syntax {
                    expected: "a field name, `not` or `(`",
                    span: Span { start: 0, end: 2 },
                },
            ),
            (
                "a and",
                FilterError::Syntax {
                    expected: "a field name, `not` or `(`",
                    span: Span::empty(5),
                },
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(parse(input).unwrap_err(), expected, "{input:?}");
        }
    }

    #[test]
    fn depth_and_clause_limits() {
        let deep = format!("{}a{}", "(".repeat(17), ")".repeat(17));
        assert!(matches!(parse(&deep), Err(FilterError::TooComplex { .. })));
        let ok = format!("{}a{}", "(".repeat(16), ")".repeat(16));
        assert!(parse(&ok).is_ok());
        let nots = format!("{}a", "not ".repeat(17));
        assert!(matches!(parse(&nots), Err(FilterError::TooComplex { .. })));
        let many = vec!["a"; 65].join(" or ");
        assert!(matches!(parse(&many), Err(FilterError::TooComplex { .. })));
    }
}

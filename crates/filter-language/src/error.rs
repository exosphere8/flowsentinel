//! Filter errors with byte positions.

use serde::Serialize;

/// Byte range `[start, end)` in the filter text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    /// A one-byte span at `offset` (an ASCII character).
    pub fn at(offset: usize) -> Self {
        Self {
            start: offset,
            end: offset.saturating_add(1),
        }
    }

    /// The span of character `c` at `offset`.
    pub fn char_at(offset: usize, c: char) -> Self {
        Self {
            start: offset,
            end: offset.saturating_add(c.len_utf8()),
        }
    }

    /// An empty span at `offset`, for example the end of the input.
    pub fn empty(offset: usize) -> Self {
        Self {
            start: offset,
            end: offset,
        }
    }
}

/// Why a filter was rejected. Messages quote only short, sanitized parts of
/// the filter (field names), never arbitrary input.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum FilterError {
    #[error("filter is empty")]
    Empty,
    #[error("filter is longer than {max} bytes")]
    TooLong { max: usize },
    #[error("filter is too complex: {reason}")]
    TooComplex { reason: &'static str, span: Span },
    #[error("unexpected character '{character}' at position {}", span.start)]
    UnexpectedCharacter { character: char, span: Span },
    #[error("unterminated string starting at position {}", span.start)]
    UnterminatedString { span: Span },
    #[error("invalid escape at position {}; only \\\" and \\\\ are allowed", span.start)]
    InvalidEscape { span: Span },
    #[error("expected {expected} at position {}", span.start)]
    Syntax { expected: &'static str, span: Span },
    #[error("unknown field `{field}` at position {}", span.start)]
    UnknownField { field: String, span: Span },
    #[error("operator `{operator}` cannot be used with field `{field}` (type {field_type}) at position {}", span.start)]
    InvalidOperator {
        operator: &'static str,
        field: String,
        field_type: &'static str,
        span: Span,
    },
    #[error("invalid value for `{field}` (expected {expected}) at position {}", span.start)]
    InvalidValue {
        field: String,
        expected: &'static str,
        span: Span,
    },
}

impl FilterError {
    /// Stable machine-readable code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Empty => "empty_filter",
            Self::TooLong { .. } => "filter_too_long",
            Self::TooComplex { .. } => "filter_too_complex",
            Self::UnexpectedCharacter { .. } => "unexpected_character",
            Self::UnterminatedString { .. } => "unterminated_string",
            Self::InvalidEscape { .. } => "invalid_escape",
            Self::Syntax { .. } => "syntax_error",
            Self::UnknownField { .. } => "unknown_field",
            Self::InvalidOperator { .. } => "invalid_operator",
            Self::InvalidValue { .. } => "invalid_value",
        }
    }

    /// Where in the filter the problem is, if it has a position.
    pub fn span(&self) -> Option<Span> {
        match self {
            Self::Empty | Self::TooLong { .. } => None,
            Self::TooComplex { span, .. }
            | Self::UnexpectedCharacter { span, .. }
            | Self::UnterminatedString { span }
            | Self::InvalidEscape { span }
            | Self::Syntax { span, .. }
            | Self::UnknownField { span, .. }
            | Self::InvalidOperator { span, .. }
            | Self::InvalidValue { span, .. } => Some(*span),
        }
    }
}

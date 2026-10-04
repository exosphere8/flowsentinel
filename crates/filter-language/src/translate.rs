//! Type checking and translation to parameterized SQL.

use std::fmt::Write as _;
use std::net::IpAddr;

use crate::error::{FilterError, Span};
use crate::fields::{Column, Field, FieldType, Target, lookup};
use crate::parser::{Expr, Op, RawValue};

/// A value bound as a query parameter.
#[derive(Debug, Clone, PartialEq)]
pub enum Param {
    Text(String),
    Int(i64),
    Float(f64),
}

/// A piece of a translated condition: fixed SQL text or a parameter.
#[derive(Debug, Clone, PartialEq)]
pub enum Piece {
    Sql(&'static str),
    Param(Param),
}

/// A validated filter: SQL pieces to append to a `WHERE` clause, and a
/// normalized rendering of the filter for display.
#[derive(Debug, Clone, PartialEq)]
pub struct CompiledFilter {
    pub target: Target,
    pub pieces: Vec<Piece>,
    pub normalized: String,
}

impl CompiledFilter {
    /// Number of bound parameters.
    pub fn param_count(&self) -> usize {
        self.pieces
            .iter()
            .filter(|p| matches!(p, Piece::Param(_)))
            .count()
    }
}

/// Parses, validates and translates `input` for `target`.
pub fn compile(input: &str, target: Target) -> Result<CompiledFilter, FilterError> {
    let expr = crate::parser::parse(input)?;
    let mut out = Translator {
        target,
        pieces: Vec::new(),
        normalized: String::new(),
    };
    out.expr(&expr, Parent::Top)?;
    Ok(CompiledFilter {
        target,
        pieces: out.pieces,
        normalized: out.normalized,
    })
}

/// Where an expression sits, which decides whether its normalized form
/// needs parentheses.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Parent {
    Top,
    And,
    Or,
    Not,
}

struct Translator {
    target: Target,
    pieces: Vec<Piece>,
    normalized: String,
}

/// A typed comparison value.
#[derive(Clone)]
enum Value {
    Ip { text: String },
    Int(i64),
    Float(f64),
    Text(String),
    Bool(bool),
}

fn field_for(target: Target, name: &str, span: Span) -> Result<&'static Field, FilterError> {
    lookup(target, name).ok_or_else(|| FilterError::UnknownField {
        field: name.chars().take(64).collect(),
        span,
    })
}

fn raw_text(value: &RawValue) -> &str {
    match value {
        RawValue::Bare(text) | RawValue::Quoted(text) => text,
    }
}

/// Parses `a.b.c.d`, an IPv6 address, or either with `/prefix`. Returns the
/// canonical `address/prefix` text Postgres accepts as `inet`.
fn parse_ip(text: &str) -> Option<String> {
    let (address, prefix) = match text.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (text, None),
    };
    let ip: IpAddr = address.parse().ok()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix {
        None => max,
        Some(p) if !p.is_empty() && p.len() <= 3 && p.bytes().all(|b| b.is_ascii_digit()) => {
            p.parse::<u8>().ok().filter(|&p| p <= max)?
        }
        Some(_) => return None,
    };
    Some(format!("{ip}/{prefix}"))
}

fn typed_value(field: &Field, value: &RawValue, span: Span) -> Result<Value, FilterError> {
    let invalid = || FilterError::InvalidValue {
        field: field.name.to_owned(),
        expected: field.field_type.name(),
        span,
    };
    let text = raw_text(value);
    match field.field_type {
        FieldType::Ip => parse_ip(text)
            .map(|text| Value::Ip { text })
            .ok_or_else(invalid),
        FieldType::UInt { max } => {
            let parsed =
                (!text.is_empty() && text.len() <= 20 && text.bytes().all(|b| b.is_ascii_digit()))
                    .then(|| text.parse::<u64>().ok())
                    .flatten()
                    .filter(|&v| v <= max)
                    .and_then(|v| i64::try_from(v).ok());
            parsed.map(Value::Int).ok_or_else(invalid)
        }
        FieldType::Float => {
            let valid = !text.is_empty()
                && text.len() <= 32
                && text.bytes().all(|b| b.is_ascii_digit() || b == b'.')
                && text.bytes().filter(|&b| b == b'.').count() <= 1;
            valid
                .then(|| text.parse::<f64>().ok())
                .flatten()
                .filter(|v| v.is_finite())
                .map(Value::Float)
                .ok_or_else(invalid)
        }
        FieldType::Text => Ok(Value::Text(text.to_owned())),
        FieldType::Enum(allowed) => {
            let lower = text.to_ascii_lowercase();
            allowed
                .iter()
                .find(|a| **a == lower)
                .map(|a| Value::Text((*a).to_owned()))
                .ok_or_else(invalid)
        }
        FieldType::Bool => match text.to_ascii_lowercase().as_str() {
            "true" | "1" => Ok(Value::Bool(true)),
            "false" | "0" => Ok(Value::Bool(false)),
            _ => Err(invalid()),
        },
    }
}

/// The operators a field type accepts, as written in filters. Boolean
/// fields can also be used bare (`tcp.flags.syn`).
pub fn operators(field_type: FieldType) -> &'static [&'static str] {
    match field_type {
        FieldType::UInt { .. } | FieldType::Float => &["==", "!=", "<", "<=", ">", ">="],
        FieldType::Text => &["==", "!=", "contains"],
        FieldType::Ip | FieldType::Enum(_) | FieldType::Bool => &["==", "!="],
    }
}

fn operator_allowed(field_type: FieldType, op: Op) -> bool {
    match field_type {
        FieldType::UInt { .. } | FieldType::Float => op != Op::Contains,
        FieldType::Text => matches!(op, Op::Eq | Op::Ne | Op::Contains),
        FieldType::Ip | FieldType::Enum(_) | FieldType::Bool => matches!(op, Op::Eq | Op::Ne),
    }
}

impl Translator {
    fn sql(&mut self, text: &'static str) {
        self.pieces.push(Piece::Sql(text));
    }

    fn param(&mut self, param: Param) {
        self.pieces.push(Piece::Param(param));
    }

    fn expr(&mut self, expr: &Expr, parent: Parent) -> Result<(), FilterError> {
        match expr {
            Expr::And(items) | Expr::Or(items) => {
                let and = matches!(expr, Expr::And(_));
                let (sql_sep, text_sep, this) = if and {
                    (" AND ", " and ", Parent::And)
                } else {
                    (" OR ", " or ", Parent::Or)
                };
                // The parser builds a nested group only from parentheses the
                // user wrote, except an `and` group inside `or`, which
                // precedence implies. Printing exactly those keeps the
                // normalized form's tree, and its nesting depth, the same.
                let parens = parent != Parent::Top && !(and && parent == Parent::Or);
                self.sql("(");
                if parens {
                    self.normalized.push('(');
                }
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        self.sql(sql_sep);
                        self.normalized.push_str(text_sep);
                    }
                    self.expr(item, this)?;
                }
                self.sql(")");
                if parens {
                    self.normalized.push(')');
                }
            }
            Expr::Not(inner) => {
                self.sql("(NOT ");
                self.normalized.push_str("not ");
                self.expr(inner, Parent::Not)?;
                self.sql(")");
            }
            Expr::Present { field, span } => {
                let field = field_for(self.target, field, *span)?;
                let Column::Predicate(predicate) = field.column else {
                    return Err(FilterError::Syntax {
                        expected: "an operator after a non-boolean field",
                        span: *span,
                    });
                };
                self.sql("COALESCE((");
                self.sql(predicate);
                self.sql("), false)");
                self.normalized.push_str(field.name);
            }
            Expr::Compare {
                field,
                field_span,
                op,
                op_span,
                value,
                value_span,
            } => self.compare(field, *field_span, *op, *op_span, value, *value_span)?,
        }
        Ok(())
    }

    fn compare(
        &mut self,
        name: &str,
        field_span: Span,
        op: Op,
        op_span: Span,
        raw: &RawValue,
        value_span: Span,
    ) -> Result<(), FilterError> {
        let field = field_for(self.target, name, field_span)?;
        if !operator_allowed(field.field_type, op) {
            return Err(FilterError::InvalidOperator {
                operator: op.as_str(),
                field: field.name.to_owned(),
                field_type: field.field_type.name(),
                span: op_span,
            });
        }
        let value = typed_value(field, raw, value_span)?;
        let _ = write!(self.normalized, "{} {} ", field.name, op.as_str());
        match &value {
            Value::Text(text) | Value::Ip { text } => {
                let _ = write!(
                    self.normalized,
                    "\"{}\"",
                    text.replace('\\', "\\\\").replace('"', "\\\"")
                );
            }
            Value::Int(v) => {
                let _ = write!(self.normalized, "{v}");
            }
            Value::Float(_) => {
                // The text as written: it was validated as digits and at most
                // one dot, and reformatting could make it longer.
                self.normalized.push_str(raw_text(raw));
            }
            Value::Bool(v) => {
                let _ = write!(self.normalized, "{v}");
            }
        }

        // Every comparison is wrapped in COALESCE(..., false) so a missing
        // value (NULL) never makes `not` match unexpectedly.
        self.sql("COALESCE((");
        if let Some(guard) = field.guard {
            self.sql(guard);
            self.sql(" AND ");
        }
        let negate = op == Op::Ne;
        if negate {
            self.sql("NOT ");
        }
        match (field.column, value) {
            (Column::Predicate(predicate), Value::Bool(expected)) => {
                if !expected {
                    self.sql("NOT ");
                }
                self.sql("(");
                self.sql(predicate);
                self.sql(")");
            }
            (Column::One(column), value) => self.leaf(column, op, value),
            (Column::Either(a, b), value) => {
                let second = match &value {
                    Value::Ip { text } => Value::Ip { text: text.clone() },
                    Value::Int(v) => Value::Int(*v),
                    Value::Float(v) => Value::Float(*v),
                    Value::Text(t) => Value::Text(t.clone()),
                    Value::Bool(v) => Value::Bool(*v),
                };
                self.sql("(");
                self.leaf(a, op, value);
                self.sql(" OR ");
                self.leaf(b, op, second);
                self.sql(")");
            }
            (Column::Predicate(_), _) => {
                return Err(FilterError::InvalidValue {
                    field: field.name.to_owned(),
                    expected: "true or false",
                    span: value_span,
                });
            }
        }
        self.sql("), false)");
        Ok(())
    }

    /// One column compared with one value. For `!=` the caller has already
    /// emitted `NOT`, so this emits the equality form.
    fn leaf(&mut self, column: &'static str, op: Op, value: Value) {
        match value {
            Value::Ip { text } => {
                // `<<=` is "is contained in or equals" for inet values.
                self.sql("(");
                self.sql(column);
                self.sql(" <<= ");
                self.param(Param::Text(text));
                self.sql("::inet)");
            }
            Value::Text(text) => {
                if op == Op::Contains {
                    // strpos avoids LIKE wildcards in user input.
                    self.sql("(strpos(lower(");
                    self.sql(column);
                    self.sql("), lower(");
                    self.param(Param::Text(text));
                    self.sql(")) > 0)");
                } else {
                    self.sql("(lower(");
                    self.sql(column);
                    self.sql(") = lower(");
                    self.param(Param::Text(text));
                    self.sql("))");
                }
            }
            Value::Int(v) => self.numeric(column, op, Param::Int(v)),
            Value::Float(v) => self.numeric(column, op, Param::Float(v)),
            Value::Bool(_) => self.sql("false"),
        }
    }

    fn numeric(&mut self, column: &'static str, op: Op, param: Param) {
        let operator = match op {
            Op::Eq | Op::Ne => " = ",
            Op::Lt => " < ",
            Op::Le => " <= ",
            Op::Gt => " > ",
            Op::Ge => " >= ",
            Op::Contains => " = ",
        };
        self.sql("(");
        self.sql(column);
        self.sql(operator);
        self.param(param);
        self.sql(")");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Renders pieces with `$n` placeholders, as Postgres would see them.
    fn render(filter: &CompiledFilter) -> (String, Vec<Param>) {
        let mut sql = String::new();
        let mut params = Vec::new();
        for piece in &filter.pieces {
            match piece {
                Piece::Sql(text) => sql.push_str(text),
                Piece::Param(param) => {
                    params.push(param.clone());
                    let _ = write!(sql, "${}", params.len());
                }
            }
        }
        (sql, params)
    }

    fn packets(input: &str) -> (String, Vec<Param>) {
        render(&compile(input, Target::Packets).unwrap())
    }

    #[test]
    fn translates_comparisons_with_bound_values() {
        let (sql, params) = packets("ip.src == 192.0.2.0/24");
        assert_eq!(sql, "COALESCE(((src_ip <<= $1::inet)), false)");
        assert_eq!(params, [Param::Text("192.0.2.0/24".into())]);

        let (sql, params) = packets("tcp.port == 443");
        assert_eq!(
            sql,
            "COALESCE(('tcp' = ANY(protocols) AND ((src_port = $1) OR (dst_port = $2))), false)"
        );
        assert_eq!(params, [Param::Int(443), Param::Int(443)]);

        let (sql, _) = packets("frame.len >= 1000 and not arp");
        assert_eq!(
            sql,
            "(COALESCE(((original_length >= $1)), false) AND (NOT COALESCE(('arp' = ANY(protocols)), false)))"
        );

        let (sql, params) = packets("http.host contains \"Example\"");
        assert_eq!(
            sql,
            "COALESCE(((strpos(lower(http_host), lower($1)) > 0)), false)"
        );
        assert_eq!(params, [Param::Text("Example".into())]);
    }

    #[test]
    fn not_equal_on_two_columns_means_neither() {
        let (sql, _) = packets("ip.addr != 2001:db8::1");
        assert_eq!(
            sql,
            "COALESCE((NOT ((src_ip <<= $1::inet) OR (dst_ip <<= $2::inet))), false)"
        );
    }

    #[test]
    fn booleans_and_enums() {
        let (sql, _) = packets("tcp.flags.syn == false");
        assert_eq!(sql, "COALESCE((NOT ((tcp_flags & 2) <> 0)), false)");
        let (sql, params) = packets("decode.status == MALFORMED");
        assert_eq!(sql, "COALESCE(((lower(decode_status) = lower($1))), false)");
        assert_eq!(params, [Param::Text("malformed".into())]);
    }

    #[test]
    fn flow_fields() {
        let (sql, params) = render(&compile("flow.bytes > 1000000 && tls", Target::Flows).unwrap());
        assert_eq!(
            sql,
            "(COALESCE(((bytes_total > $1)), false) AND COALESCE(('tls' = ANY(application_protocols)), false))"
        );
        assert_eq!(params, [Param::Int(1_000_000)]);
        assert!(compile("frame.len > 1", Target::Flows).is_err());
        assert!(compile("flow.bytes > 1", Target::Packets).is_err());
    }

    #[test]
    fn type_errors_are_reported_with_positions() {
        let err = compile("tcp.port == http", Target::Packets).unwrap_err();
        assert_eq!(err.code(), "invalid_value");
        assert_eq!(err.span(), Some(Span { start: 12, end: 16 }));

        let err = compile("ip.src > 192.0.2.1", Target::Packets).unwrap_err();
        assert_eq!(err.code(), "invalid_operator");
        assert_eq!(err.span(), Some(Span { start: 7, end: 8 }));

        let err = compile("tcp.port == 70000", Target::Packets).unwrap_err();
        assert_eq!(err.code(), "invalid_value");

        let err = compile("ip.src == 192.0.2.1/33", Target::Packets).unwrap_err();
        assert_eq!(err.code(), "invalid_value");

        let err = compile("nosuch.field == 1", Target::Packets).unwrap_err();
        assert_eq!(err.code(), "unknown_field");
        assert_eq!(err.span(), Some(Span { start: 0, end: 12 }));

        let err = compile("tcp.port", Target::Packets).unwrap_err();
        assert_eq!(err.code(), "syntax_error");
    }

    #[test]
    fn injection_attempts_never_reach_sql_text() {
        let attempts = [
            "http.host == \"x' OR '1'='1\"",
            "http.host == \"); DROP TABLE packets; --\"",
            "dns.qry.name contains \"%' OR 1=1 --\"",
            "tls.sni == \"\\\"; DELETE FROM flows\"",
        ];
        for input in attempts {
            let filter = compile(input, Target::Packets).unwrap();
            let (sql, params) = render(&filter);
            assert!(
                !sql.contains("DROP") && !sql.contains("DELETE") && !sql.contains("'1'"),
                "{input}: {sql}"
            );
            assert_eq!(params.len(), 1, "{input}");
        }
        // Unquoted attempts do not even tokenize or parse.
        for input in [
            "http.host == x;DROP",
            "ip.src == 1 OR 1=1",
            "frame.len == 1--",
        ] {
            assert!(compile(input, Target::Packets).is_err(), "{input}");
        }
    }

    #[test]
    fn normalized_form_round_trips() {
        let filter = compile(
            "ip.addr==192.0.2.1 && (tcp || udp) and !dns",
            Target::Packets,
        )
        .unwrap();
        assert_eq!(
            filter.normalized,
            "ip.addr == \"192.0.2.1/32\" and (tcp or udp) and not dns"
        );
        let again = compile(&filter.normalized, Target::Packets).unwrap();
        assert_eq!(again.normalized, filter.normalized);
        assert_eq!(again.pieces, filter.pieces);
    }

    /// Normalizing must not add nesting, lengthen numbers or quote values
    /// past the limits, so the normalized form is accepted again.
    #[test]
    fn normalized_form_stays_within_the_limits() {
        let deep = format!("{}udp{}", "(udp or tcp and ".repeat(15), ")".repeat(15));
        let long_float = format!("flow.duration > {}", "9".repeat(32));
        let cases = [
            (deep.as_str(), Target::Packets),
            (long_float.as_str(), Target::Flows),
            (
                "tcp and (udp or arp) or not (dns and tls) or ((icmp))",
                Target::Packets,
            ),
            ("(tcp and udp) and arp", Target::Packets),
            ("not not (tcp or udp)", Target::Packets),
            ("tcp or udp and arp", Target::Packets),
            (
                "flow.duration >= 0.000000000000000000000000000001",
                Target::Flows,
            ),
        ];
        for (input, target) in cases {
            let filter = compile(input, target).unwrap_or_else(|e| panic!("{input}: {e}"));
            let again = compile(&filter.normalized, target)
                .unwrap_or_else(|e| panic!("{input} -> {}: {e}", filter.normalized));
            assert_eq!(again.pieces, filter.pieces, "{input}");
            assert_eq!(again.normalized, filter.normalized, "{input}");
        }
        let filter = compile(&long_float, Target::Flows).unwrap();
        assert_eq!(filter.normalized, long_float);
    }

    #[test]
    fn bare_values_have_the_string_limit() {
        let bare = format!("http.host == {}", "a".repeat(256));
        assert!(matches!(
            compile(&bare, Target::Packets),
            Err(FilterError::TooComplex { .. })
        ));
        let ok = format!("http.host == {}", "a".repeat(255));
        assert!(compile(&ok, Target::Packets).is_ok());
    }

    #[test]
    fn error_spans_cover_whole_characters() {
        let err = compile("tcp and \u{e9}", Target::Packets).unwrap_err();
        assert_eq!(err.span(), Some(Span { start: 8, end: 10 }));
        let err = compile("tcp and", Target::Packets).unwrap_err();
        assert_eq!(err.span(), Some(Span { start: 7, end: 7 }));
    }

    #[test]
    fn flow_port_fields_need_a_port_protocol() {
        let filter = compile("port == 0", Target::Flows).unwrap();
        let sql: String = filter
            .pieces
            .iter()
            .filter_map(|p| match p {
                Piece::Sql(s) => Some(*s),
                Piece::Param(_) => None,
            })
            .collect();
        assert!(sql.contains("protocol IN (6, 17)"), "{sql}");
    }
}

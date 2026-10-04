//! Property tests: arbitrary input never panics, errors point inside the
//! input, and every accepted filter binds its values as parameters.

use filter_language::{
    FLOW_FIELDS, FieldType, FilterError, MAX_FILTER_BYTES, PACKET_FIELDS, Piece, Target, compile,
};
use proptest::prelude::*;

/// A value of the right shape for `field_type`.
fn value_for(field_type: FieldType, seed: u32) -> String {
    match field_type {
        FieldType::Ip => format!("192.0.2.{}/{}", seed % 256, 16 + seed % 17),
        FieldType::UInt { max } => (u64::from(seed) % max.max(1)).to_string(),
        // Up to 32 characters of digits with one dot, the longest accepted.
        FieldType::Float => match seed % 3 {
            0 => format!("{}.5", seed % 1000),
            1 => "9".repeat(1 + seed as usize % 32),
            _ => format!("0.{}", "0".repeat(seed as usize % 30)) + "1",
        },
        // Quoted, or bare up to the 255-character limit.
        FieldType::Text if seed % 4 == 0 => "h".repeat(1 + seed as usize % 255),
        FieldType::Text => format!("\"host{seed}.example\""),
        FieldType::Enum(values) => values[seed as usize % values.len()].to_owned(),
        FieldType::Bool => if seed % 2 == 0 { "true" } else { "false" }.to_owned(),
    }
}

fn clause(target: Target, index: usize, seed: u32) -> String {
    let fields = match target {
        Target::Packets => PACKET_FIELDS,
        Target::Flows => FLOW_FIELDS,
    };
    let field = &fields[index % fields.len()];
    let op = match field.field_type {
        FieldType::Text => ["==", "!=", "contains"][seed as usize % 3],
        FieldType::UInt { .. } | FieldType::Float => {
            ["==", "!=", "<", "<=", ">", ">="][seed as usize % 6]
        }
        _ => ["==", "!="][seed as usize % 2],
    };
    if field.field_type == FieldType::Bool && seed % 3 == 0 {
        return field.name.to_owned();
    }
    format!(
        "{} {} {}",
        field.name,
        op,
        value_for(field.field_type, seed)
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    #[test]
    fn arbitrary_text_never_panics(input in ".{0,300}") {
        for target in [Target::Packets, Target::Flows] {
            match compile(&input, target) {
                Ok(filter) => prop_assert!(!filter.pieces.is_empty()),
                Err(err) => {
                    if let Some(span) = err.span() {
                        // Spans are whole characters inside (or at the end of) the input.
                        prop_assert!(
                            span.start <= span.end && input.get(span.start..span.end).is_some(),
                            "{err:?} for {input:?}"
                        );
                    }
                    prop_assert!(!err.to_string().is_empty());
                }
            }
        }
    }

    #[test]
    fn filter_like_text_never_panics(input in "[a-z.()!=<>&| \"0-9/:]{0,120}") {
        let _ = compile(&input, Target::Packets);
        let _ = compile(&input, Target::Flows);
    }

    #[test]
    fn generated_filters_compile_and_round_trip(
        clauses in proptest::collection::vec((0usize..64, any::<u32>(), any::<bool>(), any::<bool>()), 1..8),
        flows in any::<bool>(),
    ) {
        let target = if flows { Target::Flows } else { Target::Packets };
        let mut text = String::new();
        for (i, (index, seed, or, not)) in clauses.iter().enumerate() {
            if i > 0 {
                text.push_str(if *or { " or " } else { " and " });
            }
            if *not {
                text.push_str("not ");
            }
            text.push('(');
            text.push_str(&clause(target, *index, *seed));
            text.push(')');
        }
        let filter = compile(&text, target).map_err(|e| TestCaseError::fail(format!("{text}: {e}")))?;
        let params = filter.pieces.iter().filter(|p| matches!(p, Piece::Param(_))).count();
        prop_assert_eq!(params, filter.param_count());
        let again = compile(&filter.normalized, target)
            .map_err(|e| TestCaseError::fail(format!("{}: {e}", filter.normalized)))?;
        prop_assert_eq!(again.pieces, filter.pieces);
        prop_assert_eq!(again.normalized, filter.normalized);
    }

    /// Random expression trees: nesting, negation and both operators. The
    /// normalized form reparses to the same SQL whenever it fits the length
    /// limit (normalization adds spaces and quotes, never nesting).
    #[test]
    fn nested_filters_round_trip(tree in expr_tree(), flows in any::<bool>()) {
        let target = if flows { Target::Flows } else { Target::Packets };
        let text = render(&tree, target);
        let Ok(filter) = compile(&text, target) else {
            return Ok(());
        };
        match compile(&filter.normalized, target) {
            Ok(again) => {
                prop_assert_eq!(&again.pieces, &filter.pieces);
                prop_assert_eq!(&again.normalized, &filter.normalized);
            }
            Err(FilterError::TooLong { .. }) => {
                prop_assert!(filter.normalized.len() > MAX_FILTER_BYTES);
            }
            Err(err) => {
                return Err(TestCaseError::fail(format!("{text} -> {}: {err}", filter.normalized)));
            }
        }
    }

    /// User text only ever appears inside parameters. (Control characters
    /// are rejected by the lexer, so they are left out here.)
    #[test]
    fn quoted_text_is_always_a_parameter(text in "[^\"\\\\\\p{Cc}]{0,100}") {
        let input = format!("http.host == \"{text}\"");
        let filter = compile(&input, Target::Packets).unwrap();
        let sql: String = filter.pieces.iter().filter_map(|p| match p {
            Piece::Sql(s) => Some(*s),
            Piece::Param(_) => None,
        }).collect();
        prop_assert_eq!(sql, "COALESCE(((lower(http_host) = lower(::text))), false)".replace("::text", ""));
    }
}

#[derive(Debug, Clone)]
enum Tree {
    Clause(usize, u32),
    Not(Box<Tree>),
    And(Vec<Tree>),
    Or(Vec<Tree>),
    Group(Box<Tree>),
}

fn expr_tree() -> impl Strategy<Value = Tree> {
    let leaf = (0usize..64, any::<u32>()).prop_map(|(i, s)| Tree::Clause(i, s));
    leaf.prop_recursive(6, 40, 4, |inner| {
        prop_oneof![
            inner.clone().prop_map(|t| Tree::Not(Box::new(t))),
            inner.clone().prop_map(|t| Tree::Group(Box::new(t))),
            proptest::collection::vec(inner.clone(), 2..4).prop_map(Tree::And),
            proptest::collection::vec(inner, 2..4).prop_map(Tree::Or),
        ]
    })
}

fn render(tree: &Tree, target: Target) -> String {
    match tree {
        Tree::Clause(index, seed) => clause(target, *index, *seed),
        Tree::Not(inner) => format!("not ({})", render(inner, target)),
        Tree::Group(inner) => format!("({})", render(inner, target)),
        Tree::And(items) => items
            .iter()
            .map(|t| render(t, target))
            .collect::<Vec<_>>()
            .join(" and "),
        Tree::Or(items) => items
            .iter()
            .map(|t| render(t, target))
            .collect::<Vec<_>>()
            .join(" || "),
    }
}

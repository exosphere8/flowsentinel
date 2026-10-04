//! A small, safe display-filter language for packets and flows.
//!
//! ```text
//! ip.addr == 192.0.2.0/24 and tcp.port == 443
//! dns.qry.name contains "example" or tls.sni == "www.example.com"
//! not arp and frame.len > 1000
//! flow.bytes >= 1000000 && flow.duration > 60
//! ```
//!
//! Filters are tokenized with byte positions, parsed with depth and size
//! limits, type-checked against a fixed field catalog per target, and
//! translated into SQL pieces in which all user values are bound
//! parameters. The crate has no database dependency; the storage layer turns
//! the pieces into a parameterized query.

mod error;
mod fields;
mod lexer;
mod parser;
mod translate;

pub use error::{FilterError, Span};
pub use fields::{Column, FLOW_FIELDS, Field, FieldType, PACKET_FIELDS, Target, fields, lookup};
pub use lexer::{MAX_FILTER_BYTES, MAX_STRING_CHARS, MAX_TOKENS};
pub use parser::{MAX_CLAUSES, MAX_DEPTH};
pub use translate::{CompiledFilter, Param, Piece, compile, operators};

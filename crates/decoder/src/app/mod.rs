//! Application-layer metadata: DNS, DHCP, HTTP/1.x and visible TLS
//! handshake fields.
//!
//! Recognition is conservative. A parser accepts a payload only when its
//! structure is valid; well-known ports merely decide which parsers are
//! tried for UDP and for DNS over TCP. TLS and HTTP are recognized by
//! structure on any TCP port. Anything else stays unknown: no application
//! layer is added.
//!
//! Each TCP segment is examined on its own (there is no stream reassembly),
//! so a message is recognized only when it starts at the beginning of a
//! segment. Parsers see at most [`MAX_APPLICATION_BYTES`] of payload.

pub mod dhcp;
pub mod dns;
pub mod http;
mod text;
pub mod tls;

use serde::Serialize;

use crate::bytes::u16_at;
use crate::context::Context;
use crate::model::{DecodeStatus, DecodeWarningCode, Layer, Protocol};

/// Most payload bytes examined per packet by application parsers.
pub const MAX_APPLICATION_BYTES: usize = 8192;

/// UDP ports on which DNS is tried: DNS, mDNS, LLMNR.
const DNS_PORTS: [u16; 3] = [53, 5353, 5355];
/// TCP ports on which DNS (with its length prefix) is tried.
const DNS_TCP_PORTS: [u16; 1] = [53];
const DHCP_PORTS: [u16; 2] = [67, 68];
const DNS_HEADER_LEN: usize = 12;
/// BOOTP fixed fields plus the magic cookie.
const DHCP_HEADER_LEN: usize = 240;

/// Transport that carried an application message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AppTransport {
    Udp,
    Tcp,
}

/// A problem found after a message was recognized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Issue {
    pub code: DecodeWarningCode,
    pub detail: &'static str,
}

pub(crate) type Issues = Vec<Issue>;

impl Issue {
    /// The bytes ran out before the message ended. Classified later as
    /// capture truncation, an inspection limit or segment continuation.
    pub(crate) fn ran_out(detail: &'static str) -> Self {
        Self {
            code: DecodeWarningCode::IncompleteApplicationData,
            detail,
        }
    }

    pub(crate) fn malformed(detail: &'static str) -> Self {
        Self {
            code: DecodeWarningCode::MalformedApplicationData,
            detail,
        }
    }

    pub(crate) fn limit(detail: &'static str) -> Self {
        Self {
            code: DecodeWarningCode::ApplicationLimitReached,
            detail,
        }
    }

    pub(crate) fn redacted(detail: &'static str) -> Self {
        Self {
            code: DecodeWarningCode::SensitiveDataRedacted,
            detail,
        }
    }
}

/// The transport payload of one packet, as seen by application parsers.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Payload<'a> {
    pub transport: AppTransport,
    pub source_port: u16,
    pub destination_port: u16,
    /// Captured payload bytes (possibly fewer than declared).
    pub bytes: &'a [u8],
    /// Payload length declared by the transport/IP headers.
    pub declared_length: usize,
}

/// Tries the application parsers that apply to `payload` and records the
/// result. Unknown payloads add nothing.
pub(crate) fn decode(ctx: &mut Context, payload: Payload<'_>) {
    if payload.bytes.is_empty() {
        return;
    }
    let window = payload
        .bytes
        .get(..MAX_APPLICATION_BYTES)
        .unwrap_or(payload.bytes);
    let cut = Cut {
        transport: payload.transport,
        capture_cut: payload.bytes.len() < payload.declared_length,
        at_limit: window.len() < payload.bytes.len(),
    };
    let ports = [payload.source_port, payload.destination_port];
    let hinted = |list: &[u16]| ports.iter().any(|p| list.contains(p));

    match payload.transport {
        AppTransport::Udp => {
            let mut tried = None;
            if hinted(&DNS_PORTS) {
                // A datagram is one whole message unless the capture or the
                // inspection limit cut it.
                let short = cut.capture_cut || cut.at_limit;
                let completeness = dns::Completeness {
                    incomplete: short,
                    tolerate_short_questions: short,
                };
                if let Some((dns, issues)) = dns::parse(window, AppTransport::Udp, completeness) {
                    return record(ctx, Layer::Dns(Box::new(dns)), Protocol::Dns, issues, cut);
                }
                tried = Some((Protocol::Dns, DNS_HEADER_LEN));
            }
            if hinted(&DHCP_PORTS) {
                if let Some((dhcp, issues)) = dhcp::parse(window) {
                    return record(
                        ctx,
                        Layer::Dhcp(Box::new(dhcp)),
                        Protocol::Dhcp,
                        issues,
                        cut,
                    );
                }
                tried = Some((Protocol::Dhcp, DHCP_HEADER_LEN));
            }
            if let Some((protocol, header_len)) = tried {
                if cut.capture_cut && window.len() < header_len {
                    // Too little was captured to judge.
                    ctx.truncated(
                        protocol,
                        "the snapshot length cut the message before its header ended",
                    );
                } else {
                    ctx.warn(
                        DecodeWarningCode::UnrecognizedApplicationData,
                        Some(protocol),
                        "payload on a well-known port is not a valid message of that protocol",
                    );
                }
            }
        }
        AppTransport::Tcp => {
            if hinted(&DNS_TCP_PORTS) {
                // DNS over TCP: a 2-byte length prefix, then the message.
                // Later segments of a long message are not recognized.
                if let Some(length) = u16_at(window, 0).map(usize::from).filter(|&l| l >= 12) {
                    let end = (2 + length).min(window.len());
                    let message = window.get(2..end).unwrap_or(&[]);
                    let ran_out = end < 2 + length;
                    let completeness = dns::Completeness {
                        // The message continues beyond these bytes (snapshot
                        // cut, inspection limit or a later segment).
                        incomplete: ran_out,
                        // Only a snapshot-length cut may excuse a broken
                        // question section; a segment boundary does not.
                        tolerate_short_questions: ran_out && cut.capture_cut,
                    };
                    if let Some((dns, issues)) =
                        dns::parse(message, AppTransport::Tcp, completeness)
                    {
                        let cut = Cut {
                            capture_cut: cut.capture_cut && ran_out,
                            ..cut
                        };
                        return record(ctx, Layer::Dns(Box::new(dns)), Protocol::Dns, issues, cut);
                    }
                }
            }
            if let Some((tls, issues)) = tls::parse(window) {
                record(ctx, Layer::Tls(Box::new(tls)), Protocol::Tls, issues, cut);
            } else if let Some((http, issues)) = http::parse(window) {
                record(
                    ctx,
                    Layer::Http(Box::new(http)),
                    Protocol::Http,
                    issues,
                    cut,
                );
            }
        }
    }
}

/// Why a parser may have run out of bytes.
#[derive(Debug, Clone, Copy)]
struct Cut {
    transport: AppTransport,
    /// The capture's snapshot length cut the payload short.
    capture_cut: bool,
    /// The payload exceeded [`MAX_APPLICATION_BYTES`].
    at_limit: bool,
}

fn record(ctx: &mut Context, layer: Layer, protocol: Protocol, issues: Issues, cut: Cut) {
    ctx.push(layer);
    for issue in issues {
        match issue.code {
            DecodeWarningCode::IncompleteApplicationData if cut.capture_cut => ctx.stop(
                DecodeStatus::Truncated,
                DecodeWarningCode::TruncatedHeader,
                Some(protocol),
                issue.detail,
            ),
            DecodeWarningCode::IncompleteApplicationData if cut.at_limit => ctx.warn(
                DecodeWarningCode::ApplicationLimitReached,
                Some(protocol),
                "application message is longer than the 8192-byte inspection limit",
            ),
            // A UDP datagram is a whole message: if its bytes run out early,
            // the message itself is malformed.
            DecodeWarningCode::IncompleteApplicationData if cut.transport == AppTransport::Udp => {
                ctx.stop(
                    DecodeStatus::Malformed,
                    DecodeWarningCode::MalformedApplicationData,
                    Some(protocol),
                    issue.detail,
                );
            }
            DecodeWarningCode::MalformedApplicationData => {
                ctx.stop(
                    DecodeStatus::Malformed,
                    issue.code,
                    Some(protocol),
                    issue.detail,
                );
            }
            code => ctx.warn(code, Some(protocol), issue.detail),
        }
    }
}

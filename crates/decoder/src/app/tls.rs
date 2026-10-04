//! Visible TLS handshake metadata from ClientHello and ServerHello messages.
//!
//! Nothing is decrypted. Only fields sent in the clear in the first
//! handshake record are read: versions, server name (SNI), ALPN protocols,
//! cipher-suite IDs, supported versions and groups, and extension types.
//! Random values, session IDs, key shares, pre-shared-key identities,
//! tickets and certificates are skipped without being copied.

use serde::Serialize;

use super::{Issue, Issues, text};
use crate::bytes::{slice, u8_at, u16_at};

/// Cipher suites recorded per ClientHello.
pub const MAX_CIPHER_SUITES: usize = 128;
/// Extensions recorded per hello.
pub const MAX_EXTENSIONS: usize = 64;
/// ALPN protocol names recorded.
pub const MAX_ALPN: usize = 16;
/// Supported versions / groups recorded.
pub const MAX_LIST_ITEMS: usize = 64;
const MAX_ALPN_CHARS: usize = 32;
const MAX_RECORD_LEN: usize = 16_384 + 2_048;
const HANDSHAKE: u8 = 22;
const CLIENT_HELLO: u8 = 1;
const SERVER_HELLO: u8 = 2;

/// Fixed label carried in every TLS result.
pub const VISIBILITY: &str = "visible handshake metadata only; nothing is decrypted";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TlsExtension {
    pub extension_type: u16,
    pub name: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TlsHandshake {
    /// Always [`VISIBILITY`].
    pub visibility: &'static str,
    pub record_version: u16,
    pub record_version_name: Option<&'static str>,
    pub handshake_type: u8,
    /// `client_hello` or `server_hello`.
    pub handshake_type_name: &'static str,
    /// The hello's legacy version field.
    pub hello_version: u16,
    pub hello_version_name: Option<&'static str>,
    /// Server Name Indication host name (ClientHello).
    pub server_name: Option<String>,
    pub alpn: Vec<String>,
    /// Offered cipher suites (ClientHello, first 128) or the selected one
    /// (ServerHello).
    pub cipher_suites: Vec<u16>,
    pub cipher_suite_count: u16,
    /// supported_versions: offered (ClientHello) or selected (ServerHello).
    pub supported_versions: Vec<u16>,
    pub supported_groups: Vec<u16>,
    pub extensions: Vec<TlsExtension>,
    /// For a ServerHello, the negotiated version: the supported_versions
    /// selection if present, otherwise the legacy version.
    pub negotiated_version: Option<u16>,
    pub negotiated_version_name: Option<&'static str>,
    /// The whole hello was inside the captured segment.
    pub complete: bool,
}

/// Recognizes a TLS handshake record carrying a ClientHello or ServerHello.
pub(crate) fn parse(payload: &[u8]) -> Option<(TlsHandshake, Issues)> {
    let (content_type, record_version, record_len) = (
        u8_at(payload, 0)?,
        u16_at(payload, 1)?,
        usize::from(u16_at(payload, 3)?),
    );
    if content_type != HANDSHAKE
        || !(0x0300..=0x0304).contains(&record_version)
        || record_len == 0
        || record_len > MAX_RECORD_LEN
    {
        return None;
    }
    // Only this record's bytes belong to the hello. A hello longer than the
    // record continues in the next record, whose header must not be read as
    // hello data.
    let record_end = 5usize.saturating_add(record_len);
    let record = payload.get(5..record_end.min(payload.len())).unwrap_or(&[]);
    let handshake_type = u8_at(record, 0)?;
    let handshake_type_name = match handshake_type {
        CLIENT_HELLO => "client_hello",
        SERVER_HELLO => "server_hello",
        _ => return None,
    };
    let body_len = usize::from(u8_at(record, 1)?) << 16
        | usize::from(u8_at(record, 2)?) << 8
        | usize::from(u8_at(record, 3)?);
    let hello_version = u16_at(record, 4)?;
    if !(0x0300..=0x0304).contains(&hello_version) || body_len < 38 {
        return None;
    }

    let mut tls = TlsHandshake {
        visibility: VISIBILITY,
        record_version,
        record_version_name: version_name(record_version),
        handshake_type,
        handshake_type_name,
        hello_version,
        hello_version_name: version_name(hello_version),
        server_name: None,
        alpn: Vec::new(),
        cipher_suites: Vec::new(),
        cipher_suite_count: 0,
        supported_versions: Vec::new(),
        supported_groups: Vec::new(),
        extensions: Vec::new(),
        negotiated_version: None,
        negotiated_version_name: None,
        complete: false,
    };
    let mut issues = Issues::default();
    let body = record
        .get(4..4usize.saturating_add(body_len).min(record.len()))
        .unwrap_or(&[]);
    // When the whole hello is visible, running out of fields means it is
    // malformed; otherwise the rest is in a later record or segment.
    let whole = body.len() == body_len;
    let short = |mut issues: Issues| {
        issues.push(if whole {
            Issue::malformed("TLS hello fields extend past its declared length")
        } else {
            Issue::ran_out("TLS hello continues beyond the visible bytes")
        });
        issues
    };
    let is_client = handshake_type == CLIENT_HELLO;

    // version(2) random(32), then session id.
    let mut pos: usize = 34;
    let Some(session_len) = u8_at(body, pos) else {
        return Some((tls, short(issues)));
    };
    if session_len > 32 {
        return None;
    }
    pos += 1 + usize::from(session_len);

    if is_client {
        let Some(suites_len) = u16_at(body, pos).map(usize::from) else {
            return Some((tls, short(issues)));
        };
        if suites_len < 2 || suites_len % 2 != 0 {
            return None;
        }
        let Some(suites) = slice(body, pos + 2, suites_len) else {
            return Some((tls, short(issues)));
        };
        tls.cipher_suite_count = u16::try_from(suites_len / 2).unwrap_or(u16::MAX);
        tls.cipher_suites = u16_list(suites, MAX_CIPHER_SUITES);
        if suites_len / 2 > MAX_CIPHER_SUITES {
            issues.push(Issue::limit("more TLS cipher suites than are recorded"));
        }
        pos += 2 + suites_len;
        let Some(compression_len) = u8_at(body, pos) else {
            return Some((tls, short(issues)));
        };
        pos += 1 + usize::from(compression_len);
    } else {
        let Some(suite) = u16_at(body, pos) else {
            return Some((tls, short(issues)));
        };
        tls.cipher_suites = vec![suite];
        tls.cipher_suite_count = 1;
        pos += 3; // cipher suite + compression method
    }

    if pos > body_len {
        issues.push(Issue::malformed(
            "TLS hello fields extend past its declared length",
        ));
        return Some((tls, issues));
    }
    if pos > body.len() {
        return Some((tls, short(issues)));
    }
    // Extensions are optional; their absence ends the hello.
    if pos == body_len {
        tls.complete = whole;
        finish(&mut tls);
        return Some((tls, issues));
    }
    let Some(ext_total) = u16_at(body, pos).map(usize::from) else {
        return Some((tls, short(issues)));
    };
    pos += 2;
    let ext_end = pos + ext_total;
    if ext_end != body_len {
        issues.push(Issue::malformed(
            "TLS extension block length does not match the hello length",
        ));
        return Some((tls, issues));
    }
    while pos < ext_end {
        let (Some(ext_type), Some(ext_len)) = (u16_at(body, pos), u16_at(body, pos + 2)) else {
            return Some((tls, short(issues)));
        };
        let ext_len = usize::from(ext_len);
        if pos + 4 + ext_len > ext_end {
            issues.push(Issue::malformed(
                "TLS extension extends past the extension block",
            ));
            return Some((tls, issues));
        }
        if tls.extensions.len() == MAX_EXTENSIONS {
            issues.push(Issue::limit("more TLS extensions than are recorded"));
            break;
        }
        tls.extensions.push(TlsExtension {
            extension_type: ext_type,
            name: extension_name(ext_type),
        });
        let Some(data) = slice(body, pos + 4, ext_len) else {
            return Some((tls, short(issues)));
        };
        match read_extension(&mut tls, ext_type, data, is_client) {
            ExtensionRead::Ok => {}
            ExtensionRead::Truncated => {
                issues.push(Issue::limit(
                    "a TLS extension lists more values than are recorded",
                ));
            }
            ExtensionRead::Malformed => {
                issues.push(Issue::malformed("TLS extension contents are malformed"));
            }
        }
        pos += 4 + ext_len;
    }
    tls.complete = whole && pos >= ext_end;
    finish(&mut tls);
    Some((tls, issues))
}

fn finish(tls: &mut TlsHandshake) {
    if tls.handshake_type == SERVER_HELLO {
        let version = tls
            .supported_versions
            .first()
            .copied()
            .unwrap_or(tls.hello_version);
        tls.negotiated_version = Some(version);
        tls.negotiated_version_name = version_name(version);
    }
}

enum ExtensionRead {
    Ok,
    /// Valid, but more values than the recording limit.
    Truncated,
    Malformed,
}

impl From<bool> for ExtensionRead {
    fn from(valid: bool) -> Self {
        if valid { Self::Ok } else { Self::Malformed }
    }
}

/// Reads the extensions whose contents are exposed.
fn read_extension(
    tls: &mut TlsHandshake,
    ext_type: u16,
    data: &[u8],
    is_client: bool,
) -> ExtensionRead {
    let valid = match ext_type {
        // server_name: list_len(2) { name_type(1) len(2) name }
        0 if is_client => {
            let Some(list_len) = u16_at(data, 0).map(usize::from) else {
                return ExtensionRead::Malformed;
            };
            let Some(list) = slice(data, 2, list_len) else {
                return ExtensionRead::Malformed;
            };
            let mut pos = 0;
            while let (Some(kind), Some(len)) = (u8_at(list, pos), u16_at(list, pos + 1)) {
                let Some(name) = slice(list, pos + 3, usize::from(len)) else {
                    return ExtensionRead::Malformed;
                };
                if kind == 0 && tls.server_name.is_none() {
                    match text::hostname(name) {
                        Some(host) => tls.server_name = Some(host),
                        None => return ExtensionRead::Malformed,
                    }
                }
                pos += 3 + usize::from(len);
            }
            pos == list.len()
        }
        0 => true, // a ServerHello's server_name extension is empty
        // ALPN: list_len(2) { len(1) name }
        16 => {
            let Some(list_len) = u16_at(data, 0).map(usize::from) else {
                return ExtensionRead::Malformed;
            };
            let Some(list) = slice(data, 2, list_len) else {
                return ExtensionRead::Malformed;
            };
            let mut pos = 0;
            let mut dropped = false;
            while let Some(len) = u8_at(list, pos) {
                let Some(name) = slice(list, pos + 1, usize::from(len)) else {
                    return ExtensionRead::Malformed;
                };
                if len == 0 {
                    return ExtensionRead::Malformed;
                }
                // GREASE values (RFC 8701) and other non-printable names are
                // skipped, not shown.
                if name.iter().all(u8::is_ascii_graphic) {
                    if tls.alpn.len() < MAX_ALPN {
                        tls.alpn.push(text::printable(name, MAX_ALPN_CHARS).0);
                    } else {
                        dropped = true;
                    }
                }
                pos += 1 + usize::from(len);
            }
            if dropped {
                return ExtensionRead::Truncated;
            }
            true
        }
        // supported_versions: client len(1) list; server selected(2)
        43 if is_client => match u8_at(data, 0).and_then(|len| slice(data, 1, usize::from(len))) {
            Some(list) if list.len() % 2 == 0 => {
                tls.supported_versions = u16_list(list, MAX_LIST_ITEMS);
                if list.len() / 2 > MAX_LIST_ITEMS {
                    return ExtensionRead::Truncated;
                }
                true
            }
            _ => false,
        },
        43 => match (data.len(), u16_at(data, 0)) {
            (2, Some(version)) => {
                tls.supported_versions = vec![version];
                true
            }
            _ => false,
        },
        // supported_groups: len(2) list
        10 => match u16_at(data, 0).and_then(|len| slice(data, 2, usize::from(len))) {
            Some(list) if list.len() % 2 == 0 => {
                tls.supported_groups = u16_list(list, MAX_LIST_ITEMS);
                if list.len() / 2 > MAX_LIST_ITEMS {
                    return ExtensionRead::Truncated;
                }
                true
            }
            _ => false,
        },
        // Everything else (key_share, pre_shared_key, session_ticket, ...)
        // is recorded by type only.
        _ => true,
    };
    ExtensionRead::from(valid)
}

fn u16_list(bytes: &[u8], max: usize) -> Vec<u16> {
    bytes
        .chunks_exact(2)
        .take(max)
        .filter_map(|pair| u16_at(pair, 0))
        .collect()
}

/// Name of a TLS protocol version.
pub fn version_name(version: u16) -> Option<&'static str> {
    Some(match version {
        0x0300 => "SSL 3.0",
        0x0301 => "TLS 1.0",
        0x0302 => "TLS 1.1",
        0x0303 => "TLS 1.2",
        0x0304 => "TLS 1.3",
        v if is_grease(v) => "GREASE",
        _ => return None,
    })
}

/// GREASE values (RFC 8701): 0x0A0A, 0x1A1A, ... 0xFAFA.
pub fn is_grease(value: u16) -> bool {
    let [hi, lo] = value.to_be_bytes();
    hi == lo && hi & 0x0F == 0x0A
}

/// Name of a TLS extension type.
pub fn extension_name(ext_type: u16) -> Option<&'static str> {
    Some(match ext_type {
        0 => "server_name",
        1 => "max_fragment_length",
        5 => "status_request",
        10 => "supported_groups",
        11 => "ec_point_formats",
        13 => "signature_algorithms",
        14 => "use_srtp",
        15 => "heartbeat",
        16 => "application_layer_protocol_negotiation",
        18 => "signed_certificate_timestamp",
        21 => "padding",
        22 => "encrypt_then_mac",
        23 => "extended_master_secret",
        27 => "compress_certificate",
        28 => "record_size_limit",
        35 => "session_ticket",
        41 => "pre_shared_key",
        42 => "early_data",
        43 => "supported_versions",
        44 => "cookie",
        45 => "psk_key_exchange_modes",
        47 => "certificate_authorities",
        49 => "post_handshake_auth",
        50 => "signature_algorithms_cert",
        51 => "key_share",
        57 => "quic_transport_parameters",
        17_513 => "application_settings",
        65_037 => "encrypted_client_hello",
        65_281 => "renegotiation_info",
        v if is_grease(v) => "GREASE",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::DecodeWarningCode;

    fn ext(ext_type: u16, data: &[u8]) -> Vec<u8> {
        let mut out = ext_type.to_be_bytes().to_vec();
        out.extend((data.len() as u16).to_be_bytes());
        out.extend(data);
        out
    }

    fn record(handshake_type: u8, body: &[u8]) -> Vec<u8> {
        let mut hs = vec![handshake_type];
        hs.extend(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend(body);
        let mut out = vec![22, 3, 1];
        out.extend((hs.len() as u16).to_be_bytes());
        out.extend(hs);
        out
    }

    fn client_hello(extensions: &[u8]) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend([0xAB; 32]); // random: must never be exposed
        body.push(0); // no session id
        body.extend([0, 4, 0x13, 0x01, 0xC0, 0x2F]);
        body.extend([1, 0]);
        body.extend((extensions.len() as u16).to_be_bytes());
        body.extend(extensions);
        record(1, &body)
    }

    fn sni(name: &[u8]) -> Vec<u8> {
        let mut entry = vec![0];
        entry.extend((name.len() as u16).to_be_bytes());
        entry.extend(name);
        let mut data = (entry.len() as u16).to_be_bytes().to_vec();
        data.extend(entry);
        ext(0, &data)
    }

    #[test]
    fn client_hello_fields() {
        let mut exts = sni(b"WWW.Example.COM");
        exts.extend(ext(16, &[0, 3, 2, b'h', b'2']));
        exts.extend(ext(43, &[4, 0x03, 0x04, 0x03, 0x03]));
        exts.extend(ext(10, &[0, 2, 0x00, 0x1D]));
        exts.extend(ext(51, &[0xEE; 40])); // key_share: recorded by type only
        let (tls, issues) = parse(&client_hello(&exts)).unwrap();
        assert!(issues.is_empty(), "{issues:?}");
        assert!(tls.complete);
        assert_eq!(tls.visibility, VISIBILITY);
        assert_eq!(tls.server_name.as_deref(), Some("www.example.com"));
        assert_eq!(tls.alpn, ["h2"]);
        assert_eq!(tls.supported_versions, [0x0304, 0x0303]);
        assert_eq!(tls.supported_groups, [0x001D]);
        assert_eq!(tls.cipher_suites, [0x1301, 0xC02F]);
        assert_eq!(tls.cipher_suite_count, 2);
        let types: Vec<u16> = tls.extensions.iter().map(|e| e.extension_type).collect();
        assert_eq!(types, [0, 16, 43, 10, 51]);
        assert_eq!(tls.negotiated_version, None);
        let json = serde_json::to_string(&tls).unwrap();
        assert!(!json.contains("random"));
        assert!(!json.to_ascii_lowercase().contains("abab"));
    }

    #[test]
    fn server_hello_negotiated_version() {
        let mut body = vec![3, 3];
        body.extend([0; 32]);
        body.push(0);
        body.extend([0x13, 0x01, 0]);
        let exts = ext(43, &[0x03, 0x04]);
        body.extend((exts.len() as u16).to_be_bytes());
        body.extend(exts);
        let (tls, _) = parse(&record(2, &body)).unwrap();
        assert_eq!(tls.handshake_type_name, "server_hello");
        assert_eq!(tls.cipher_suites, [0x1301]);
        assert_eq!(tls.negotiated_version, Some(0x0304));
        assert_eq!(tls.negotiated_version_name, Some("TLS 1.3"));
        assert!(tls.complete);
    }

    #[test]
    fn hellos_split_across_segments_are_partial() {
        let hello = client_hello(&sni(b"a.example"));
        let (tls, issues) = parse(&hello[..60]).unwrap();
        assert!(!tls.complete);
        assert_eq!(issues[0].code, DecodeWarningCode::IncompleteApplicationData);
    }

    #[test]
    fn non_hello_records_are_not_recognized() {
        // Application data, alert, and a Certificate handshake message.
        assert!(parse(&[23, 3, 3, 0, 5, 1, 2, 3, 4, 5]).is_none());
        assert!(parse(&[21, 3, 3, 0, 2, 2, 40]).is_none());
        assert!(parse(&record(11, &[0; 40])).is_none());
        // Bad record version.
        let mut hello = client_hello(&[]);
        hello[1] = 9;
        assert!(parse(&hello).is_none());
    }

    #[test]
    fn invalid_extension_contents_are_malformed() {
        let (tls, issues) = parse(&client_hello(&sni(b"bad host!"))).unwrap();
        assert_eq!(tls.server_name, None);
        assert_eq!(issues[0].code, DecodeWarningCode::MalformedApplicationData);
        // Extension block longer than the hello.
        let mut hello = client_hello(&sni(b"a.example"));
        let len_pos = 9 + 2 + 32 + 1 + 2 + 4 + 2;
        hello[len_pos..len_pos + 2].copy_from_slice(&500u16.to_be_bytes());
        let (_, issues) = parse(&hello).unwrap();
        assert_eq!(issues[0].code, DecodeWarningCode::MalformedApplicationData);
    }

    #[test]
    fn extension_count_is_capped() {
        let mut exts = Vec::new();
        for i in 0..(MAX_EXTENSIONS as u16 + 10) {
            exts.extend(ext(1000 + i, &[]));
        }
        let (tls, issues) = parse(&client_hello(&exts)).unwrap();
        assert_eq!(tls.extensions.len(), MAX_EXTENSIONS);
        assert_eq!(issues[0].code, DecodeWarningCode::ApplicationLimitReached);
    }

    #[test]
    fn grease_values_are_named() {
        assert!(is_grease(0x0A0A) && is_grease(0xFAFA));
        assert!(!is_grease(0x0A0B) && !is_grease(0x1301));
        assert_eq!(extension_name(0x3A3A), Some("GREASE"));
        assert_eq!(version_name(0x0304), Some("TLS 1.3"));
    }
}

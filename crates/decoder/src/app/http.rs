//! HTTP/1.x request and response metadata.
//!
//! Recognition requires a valid request line (known method, target, version)
//! or status line at the start of a TCP segment. Only a fixed set of fields
//! is extracted. Bodies, query strings, credentials in URLs, cookies,
//! authorization headers and other credential-bearing headers are never
//! exposed; their presence is reported as a redaction.

use serde::Serialize;

use super::{Issue, Issues, text};

/// Header lines examined per message.
pub const MAX_HEADERS: usize = 64;
/// Longest request, status or header line examined, in bytes.
pub const MAX_LINE_BYTES: usize = 2048;
/// Longest path shown, in characters.
pub const MAX_PATH_CHARS: usize = 256;
/// Longest reason phrase shown, in characters.
pub const MAX_REASON_CHARS: usize = 64;
const MAX_CONTENT_TYPE_CHARS: usize = 100;

const METHODS: [&str; 9] = [
    "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH",
];

/// Header names whose values are never exposed.
const SENSITIVE_HEADERS: [&str; 10] = [
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "x-access-token",
    "x-csrf-token",
    "x-xsrf-token",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpKind {
    Request,
    Response,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HttpMessage {
    pub kind: HttpKind,
    /// `HTTP/1.0` or `HTTP/1.1`.
    pub version: &'static str,
    pub method: Option<&'static str>,
    /// Request path without query string or fragment; printable ASCII,
    /// at most 256 characters.
    pub path: Option<String>,
    pub path_truncated: bool,
    /// A query string or `;` path parameters were present and removed.
    pub query_redacted: bool,
    /// Path segments replaced with `{redacted}` because they look like
    /// tokens (see the documentation for the rule).
    pub path_segments_redacted: u8,
    /// Credentials (`user:password@`) in an absolute URL were removed.
    pub userinfo_redacted: bool,
    /// Host header (or URL authority), validated hostname with optional port.
    pub host: Option<String>,
    pub status_code: Option<u16>,
    pub reason: Option<String>,
    pub content_length: Option<u64>,
    /// Media type only (`type/subtype`), lowercased; parameters dropped.
    pub content_type: Option<String>,
    /// `Connection` header tokens, lowercased (for example `keep-alive`).
    pub connection: Option<String>,
    pub chunked: bool,
    /// Names of credential-bearing headers that were present; values are
    /// never read.
    pub redacted_headers: Vec<&'static str>,
    pub header_count: u16,
    /// How header parsing ended.
    pub header_block: HeaderBlock,
    /// The request target was not shown: it was not an origin-form path or
    /// an `http(s)://host[:port]` URL (other schemes, scheme-relative or
    /// ambiguous targets may embed credentials).
    pub target_withheld: bool,
}

/// How parsing of the header block ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HeaderBlock {
    /// The blank line ending the headers was seen.
    Complete,
    /// The headers continue beyond this packet.
    Incomplete,
    /// Parsing stopped at a limit or a malformed line.
    Stopped,
}

pub(crate) fn parse(payload: &[u8]) -> Option<(HttpMessage, Issues)> {
    let mut lines = Lines {
        data: payload,
        pos: 0,
    };
    let first = lines.next_line()?.ok()?;
    let mut message = parse_start_line(first)?;
    let mut issues = Issues::default();
    if message.query_redacted {
        issues.push(Issue::redacted(
            "HTTP query string removed from the request path",
        ));
    }
    if message.userinfo_redacted {
        issues.push(Issue::redacted(
            "credentials removed from an absolute request URL",
        ));
    }
    if message.path_segments_redacted > 0 {
        issues.push(Issue::redacted(
            "token-like HTTP path segments replaced with {redacted}",
        ));
    }
    if message.target_withheld {
        issues.push(Issue::redacted(
            "HTTP request target withheld: not an origin-form path or a plain http(s) URL",
        ));
    }

    loop {
        let line = match lines.next_line() {
            None => {
                issues.push(Issue::ran_out(
                    "HTTP header block continues beyond this packet",
                ));
                break;
            }
            Some(Err(LineTooLong)) => {
                message.header_block = HeaderBlock::Stopped;
                issues.push(Issue::limit(
                    "HTTP header line longer than the inspection limit",
                ));
                break;
            }
            Some(Ok(line)) => line,
        };
        if line.is_empty() {
            message.header_block = HeaderBlock::Complete;
            break;
        }
        if usize::from(message.header_count) == MAX_HEADERS {
            message.header_block = HeaderBlock::Stopped;
            issues.push(Issue::limit("more HTTP header lines than are examined"));
            break;
        }
        message.header_count += 1;
        let Some((name, value)) = split_header(line) else {
            message.header_block = HeaderBlock::Stopped;
            issues.push(Issue::malformed("HTTP header line is not `name: value`"));
            break;
        };
        apply_header(&mut message, &mut issues, &name, value);
    }
    if !message.redacted_headers.is_empty() {
        issues.push(Issue::redacted(
            "HTTP credential or cookie headers present; values not read",
        ));
    }
    Some((message, issues))
}

fn parse_start_line(line: &[u8]) -> Option<HttpMessage> {
    let mut parts = line.split(|&b| b == b' ');
    let (a, b) = (parts.next()?, parts.next()?);
    let rest: Vec<&[u8]> = parts.collect();
    let mut message = HttpMessage {
        kind: HttpKind::Request,
        version: "HTTP/1.1",
        method: None,
        path: None,
        path_truncated: false,
        query_redacted: false,
        path_segments_redacted: 0,
        userinfo_redacted: false,
        host: None,
        status_code: None,
        reason: None,
        content_length: None,
        content_type: None,
        connection: None,
        chunked: false,
        redacted_headers: Vec::new(),
        header_count: 0,
        header_block: HeaderBlock::Incomplete,
        target_withheld: false,
    };

    if let Some(version) = version(a) {
        // Status line: HTTP/1.x SP 3DIGIT SP reason
        if b.len() != 3 || !b.iter().all(u8::is_ascii_digit) {
            return None;
        }
        let code = std::str::from_utf8(b).ok()?.parse::<u16>().ok()?;
        if !(100..=599).contains(&code) {
            return None;
        }
        message.kind = HttpKind::Response;
        message.version = version;
        message.status_code = Some(code);
        let reason = rest.join(&b' ');
        message.reason = Some(text::printable(&reason, MAX_REASON_CHARS).0);
        return Some(message);
    }

    // Request line: METHOD SP target SP HTTP/1.x
    let method = METHODS.iter().copied().find(|m| m.as_bytes() == a)?;
    let [version_bytes] = rest.as_slice() else {
        return None;
    };
    message.version = version(version_bytes)?;
    message.method = Some(method);
    if b.is_empty() || !b.iter().all(|c| c.is_ascii_graphic()) {
        return None;
    }
    apply_target(&mut message, method, b);
    Some(message)
}

fn version(bytes: &[u8]) -> Option<&'static str> {
    match bytes {
        b"HTTP/1.1" => Some("HTTP/1.1"),
        b"HTTP/1.0" => Some("HTTP/1.0"),
        _ => None,
    }
}

fn apply_target(message: &mut HttpMessage, method: &str, target: &[u8]) {
    if method == "CONNECT" {
        // authority-form: host:port
        message.host = host_value(target);
        message.target_withheld = message.host.is_none();
        return;
    }
    if target == b"*" {
        message.path = Some("*".to_owned());
        return;
    }
    let path = if target.starts_with(b"/") && !target.starts_with(b"//") {
        // origin-form
        target
    } else if let Some(rest) = strip_prefix_ignore_case(target, b"http://")
        .or_else(|| strip_prefix_ignore_case(target, b"https://"))
    {
        // absolute-form: the authority runs to the first '/'.
        let auth_end = rest.iter().position(|&c| c == b'/').unwrap_or(rest.len());
        let authority = rest.get(..auth_end).unwrap_or(&[]);
        let host_part = match authority.iter().rposition(|&c| c == b'@') {
            Some(at) => {
                message.userinfo_redacted = true;
                authority.get(at + 1..).unwrap_or(&[])
            }
            None => authority,
        };
        // Anything other than a clean host[:port] (for example '?' or '#'
        // before the first '/') makes the target ambiguous: withhold it.
        let Some(host) = host_value(host_part)
            .filter(|_| !authority.contains(&b'?') && !authority.contains(&b'#'))
        else {
            message.target_withheld = true;
            return;
        };
        message.host = Some(host);
        match rest.get(auth_end..) {
            Some(tail) if !tail.is_empty() => tail,
            _ => b"/",
        }
    } else {
        // Other schemes, scheme-relative and malformed targets are never shown.
        message.target_withheld = true;
        return;
    };
    let end = path
        .iter()
        .position(|&c| matches!(c, b'?' | b'#' | b';'))
        .unwrap_or(path.len());
    if path.get(end).is_some_and(|&c| c == b'?' || c == b';') {
        message.query_redacted = true;
    }
    // The whole target is bounded by the request-line limit. Mask before
    // shortening, so a secret that straddles the cut is not partly shown.
    let (whole, _) = text::printable(path.get(..end).unwrap_or(&[]), MAX_LINE_BYTES);
    let (masked, count) = mask_sensitive_segments(&whole);
    message.path_truncated = masked.len() > MAX_PATH_CHARS;
    message.path = Some(masked.chars().take(MAX_PATH_CHARS).collect());
    message.path_segments_redacted = count;
}

/// Replaces path segments that may carry secrets with `{redacted}`:
///
/// - segments of 32 or more characters, or of 16 or more that mix letters
///   and digits (password-reset tokens, session IDs, API keys);
/// - segments containing `@` or `%40` (credentials or e-mail addresses);
/// - everything after an embedded URL scheme such as `/fetch/http://...`,
///   whose authority may hold credentials.
///
/// This is a heuristic: shorter or purely alphabetic secrets are not caught.
fn mask_sensitive_segments(path: &str) -> (String, u8) {
    let mut count: u8 = 0;
    let segments: Vec<&str> = path.split('/').collect();
    let mut kept: Vec<&str> = Vec::with_capacity(segments.len());
    for (index, segment) in segments.iter().copied().enumerate() {
        let embedded_url = is_scheme(segment)
            && segments.get(index + 1) == Some(&"")
            && index + 2 < segments.len();
        if embedded_url {
            count = count.saturating_add(1);
            kept.push("{redacted}");
            break;
        }
        let len = segment.chars().count();
        let mixed = segment.chars().any(|c| c.is_ascii_digit())
            && segment.chars().any(|c| c.is_ascii_alphabetic());
        let address = segment.contains('@') || segment.to_ascii_lowercase().contains("%40");
        if len >= 32 || (len >= 16 && mixed) || address {
            count = count.saturating_add(1);
            kept.push("{redacted}");
        } else {
            kept.push(segment);
        }
    }
    (kept.join("/"), count)
}

/// `scheme:` as in RFC 3986: a letter, then letters, digits, `+`, `-` or `.`.
fn is_scheme(segment: &str) -> bool {
    let Some(name) = segment.strip_suffix(':') else {
        return false;
    };
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

fn strip_prefix_ignore_case<'a>(data: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    let head = data.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| data.get(prefix.len()..).unwrap_or(&[]))
}

/// `host[:port]` or `[ipv6][:port]`: a hostname of letters, digits, `-`,
/// `_` and `.` (or a bracketed IPv6 literal of hex digits, `:` and `.`),
/// optionally followed by `:` and 1-5 digits. Lowercased.
fn host_value(bytes: &[u8]) -> Option<String> {
    let port = if bytes.first() == Some(&b'[') {
        let close = bytes.iter().position(|&b| b == b']')?;
        let inside = bytes.get(1..close)?;
        // Must be a real IPv6 address, which also bounds its length.
        std::str::from_utf8(inside)
            .ok()?
            .parse::<std::net::Ipv6Addr>()
            .ok()?;
        bytes.get(close + 1..)?
    } else {
        let colon = bytes.iter().position(|&b| b == b':').unwrap_or(bytes.len());
        if !text::is_hostname(bytes.get(..colon)?) {
            return None;
        }
        bytes.get(colon..)?
    };
    if let Some(digits) = port.strip_prefix(b":") {
        if digits.is_empty() || digits.len() > 5 || !digits.iter().all(u8::is_ascii_digit) {
            return None;
        }
    } else if !port.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(bytes).to_ascii_lowercase())
}

fn split_header(line: &[u8]) -> Option<(String, &[u8])> {
    let colon = line.iter().position(|&b| b == b':')?;
    let (name, value) = (line.get(..colon)?, line.get(colon + 1..)?);
    let token = |b: &u8| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(b);
    if name.is_empty() || !name.iter().all(token) {
        return None;
    }
    Some((
        String::from_utf8_lossy(name).to_ascii_lowercase(),
        value.trim_ascii(),
    ))
}

fn apply_header(message: &mut HttpMessage, issues: &mut Issues, name: &str, value: &[u8]) {
    if let Some(&sensitive) = SENSITIVE_HEADERS.iter().find(|s| **s == name) {
        if !message.redacted_headers.contains(&sensitive) {
            message.redacted_headers.push(sensitive);
        }
        return;
    }
    match name {
        "host" => message.host = host_value(value),
        "content-length" => {
            let parsed = std::str::from_utf8(value)
                .ok()
                .filter(|v| !v.is_empty() && v.len() <= 19 && v.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|v| v.parse::<u64>().ok());
            match (parsed, message.content_length) {
                (Some(new), Some(old)) if new != old => {
                    issues.push(Issue::malformed("conflicting HTTP Content-Length headers"));
                }
                (Some(new), _) => message.content_length = Some(new),
                (None, _) => issues.push(Issue::malformed("invalid HTTP Content-Length value")),
            }
        }
        "content-type" => {
            let media = value
                .split(|&b| b == b';')
                .next()
                .unwrap_or(&[])
                .trim_ascii();
            let valid = media.iter().filter(|&&b| b == b'/').count() == 1
                && media
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || b"!#$&-^_.+/".contains(b));
            if valid {
                message.content_type = Some(
                    text::printable(media, MAX_CONTENT_TYPE_CHARS)
                        .0
                        .to_ascii_lowercase(),
                );
            }
        }
        "connection" => {
            let tokens: Vec<String> = value
                .split(|&b| b == b',')
                .map(|t| String::from_utf8_lossy(t.trim_ascii()).to_ascii_lowercase())
                .filter(|t| matches!(t.as_str(), "keep-alive" | "close" | "upgrade"))
                .collect();
            if !tokens.is_empty() {
                message.connection = Some(tokens.join(","));
            }
        }
        "transfer-encoding" => {
            message.chunked = value
                .split(|&b| b == b',')
                .any(|t| t.trim_ascii().eq_ignore_ascii_case(b"chunked"));
        }
        _ => {}
    }
}

struct LineTooLong;

/// Splits CRLF- (or bare LF-) terminated lines without allocating.
struct Lines<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Lines<'a> {
    /// Next complete line without its terminator. `None` when no complete
    /// line remains; `Err` when a line exceeds [`MAX_LINE_BYTES`].
    fn next_line(&mut self) -> Option<Result<&'a [u8], LineTooLong>> {
        let rest = self.data.get(self.pos..)?;
        let window = rest.get(..MAX_LINE_BYTES + 2).unwrap_or(rest);
        let Some(lf) = window.iter().position(|&b| b == b'\n') else {
            return (window.len() > MAX_LINE_BYTES).then_some(Err(LineTooLong));
        };
        self.pos += lf + 1;
        let line = rest.get(..lf)?;
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        Some(Ok(line))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::DecodeWarningCode;

    fn codes(issues: &Issues) -> Vec<DecodeWarningCode> {
        issues.iter().map(|i| i.code).collect()
    }

    #[test]
    fn parses_a_request_and_redacts_secrets() {
        let req = b"GET /search?q=secret&token=abc HTTP/1.1\r\nHost: WWW.Example.COM\r\nAuthorization: Bearer abc\r\nCookie: s=1\r\nConnection: keep-alive\r\n\r\nBODY";
        let (m, issues) = parse(req).unwrap();
        assert_eq!(m.kind, HttpKind::Request);
        assert_eq!(m.method, Some("GET"));
        assert_eq!(m.path.as_deref(), Some("/search"));
        assert!(m.query_redacted);
        assert_eq!(m.host.as_deref(), Some("www.example.com"));
        assert_eq!(m.redacted_headers, ["authorization", "cookie"]);
        assert_eq!(m.connection.as_deref(), Some("keep-alive"));
        assert_eq!(m.header_block, HeaderBlock::Complete);
        assert_eq!(m.header_count, 4);
        assert_eq!(
            codes(&issues),
            [
                DecodeWarningCode::SensitiveDataRedacted,
                DecodeWarningCode::SensitiveDataRedacted
            ]
        );
        let json = serde_json::to_string(&m).unwrap();
        assert!(!json.contains("secret") && !json.contains("abc") && !json.contains("BODY"));
    }

    #[test]
    fn parses_a_response() {
        let resp = b"HTTP/1.0 404 Not Found\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 12\r\nSet-Cookie: a=b\r\n\r\n";
        let (m, _) = parse(resp).unwrap();
        assert_eq!(m.kind, HttpKind::Response);
        assert_eq!(m.version, "HTTP/1.0");
        assert_eq!(m.status_code, Some(404));
        assert_eq!(m.reason.as_deref(), Some("Not Found"));
        assert_eq!(m.content_type.as_deref(), Some("text/html"));
        assert_eq!(m.content_length, Some(12));
        assert_eq!(m.redacted_headers, ["set-cookie"]);
    }

    #[test]
    fn absolute_urls_lose_credentials() {
        let req = b"GET http://user:pw@proxy.example:8080/a/b?x=1 HTTP/1.1\r\n\r\n";
        let (m, _) = parse(req).unwrap();
        assert_eq!(m.host.as_deref(), Some("proxy.example:8080"));
        assert_eq!(m.path.as_deref(), Some("/a/b"));
        assert!(m.query_redacted);
        assert!(m.userinfo_redacted);
        assert!(!serde_json::to_string(&m).unwrap().contains("pw"));
    }

    #[test]
    fn embedded_urls_and_addresses_in_paths_are_masked() {
        let path = |target: &str| {
            let req = format!("GET {target} HTTP/1.1\r\n\r\n");
            let (m, _) = parse(req.as_bytes()).unwrap();
            (m.path.unwrap(), m.path_segments_redacted)
        };
        assert_eq!(
            path("/fetch/http://admin:secretpw@db.internal/"),
            ("/fetch/{redacted}".to_owned(), 1)
        );
        assert_eq!(
            path("/proxy/HTTPS://admin:secret/pw@db/x"),
            ("/proxy/{redacted}".to_owned(), 1)
        );
        assert_eq!(
            path("/users/someone@example.org/inbox"),
            ("/users/{redacted}/inbox".to_owned(), 1)
        );
        assert_eq!(path("/u/a%40b/x"), ("/u/{redacted}/x".to_owned(), 1));
        // A colon alone is not a scheme.
        assert_eq!(
            path("/wiki/Special:Search"),
            ("/wiki/Special:Search".to_owned(), 0)
        );
        assert_eq!(path("/a/http:/b"), ("/a/http:/b".to_owned(), 0));
    }

    #[test]
    fn tokens_straddling_the_length_limit_are_masked_whole() {
        let prefix = "/seg".repeat(62); // 248 characters
        let token = "Ab3dE6gH9jK2mN5pQ8rS1tV4wX7zA0cE3fG6"; // 36 characters
        let req = format!("GET {prefix}/{token}/end HTTP/1.1\r\n\r\n");
        let (m, _) = parse(req.as_bytes()).unwrap();
        let shown = m.path.unwrap();
        assert!(m.path_truncated);
        assert_eq!(shown.len(), MAX_PATH_CHARS);
        assert!(!shown.contains("Ab3d"), "{shown}");
        assert!(shown.ends_with("/{redact"), "{shown}");
        assert_eq!(m.path_segments_redacted, 1);
    }

    #[test]
    fn rejects_non_http() {
        for data in [
            &b"FLOWSENTINEL GET / HTTP/1.1\r\n"[..],
            b"GET / HTTP/2.0\r\n",
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
            b"GET  HTTP/1.1\r\n",
            b"HTTP/1.1 99 Too Low\r\n",
            b"HTTP/1.1 2000 OK\r\n",
            b"\x16\x03\x01\x00\x05",
            b"GET / HTTP/1.1", // no line terminator in this segment
        ] {
            assert!(parse(data).is_none(), "{:?}", String::from_utf8_lossy(data));
        }
    }

    #[test]
    fn limits_are_enforced() {
        let mut req = b"GET / HTTP/1.1\r\n".to_vec();
        for i in 0..(MAX_HEADERS + 5) {
            req.extend(format!("X-H{i}: v\r\n").as_bytes());
        }
        let (m, issues) = parse(&req).unwrap();
        assert_eq!(usize::from(m.header_count), MAX_HEADERS);
        assert_eq!(codes(&issues), [DecodeWarningCode::ApplicationLimitReached]);

        let mut req = b"GET / HTTP/1.1\r\nX-Long: ".to_vec();
        req.extend(vec![b'a'; MAX_LINE_BYTES + 10]);
        req.extend(b"\r\n\r\n");
        let (_, issues) = parse(&req).unwrap();
        assert_eq!(codes(&issues), [DecodeWarningCode::ApplicationLimitReached]);

        let long_path = format!("GET {} HTTP/1.1\r\n\r\n", "/abc".repeat(100));
        let (m, _) = parse(long_path.as_bytes()).unwrap();
        assert!(m.path_truncated);
        assert_eq!(m.path.unwrap().len(), MAX_PATH_CHARS);
    }

    #[test]
    fn invalid_header_values_are_ignored_or_flagged() {
        let req = b"POST /x HTTP/1.1\r\nContent-Length: 12abc\r\nHost: bad host\r\nContent-Type: <script>\r\n\r\n";
        let (m, issues) = parse(req).unwrap();
        assert_eq!(m.content_length, None);
        assert_eq!(m.host, None);
        assert_eq!(m.content_type, None);
        assert_eq!(
            codes(&issues),
            [DecodeWarningCode::MalformedApplicationData]
        );
    }

    #[test]
    fn partial_header_blocks_are_reported() {
        let (m, _) = parse(b"GET / HTTP/1.1\r\nHost: a.example\r\nAccept: */").unwrap();
        assert_eq!(m.header_block, HeaderBlock::Incomplete);
        assert_eq!(m.host.as_deref(), Some("a.example"));
    }
}

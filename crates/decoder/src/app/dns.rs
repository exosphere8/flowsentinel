//! DNS message metadata (RFC 1035) over UDP or TCP.
//!
//! Recognition requires a structurally valid header and question section.
//! Names are decoded with compression-pointer loop protection: every pointer
//! must target an offset strictly lower than any offset already visited, and
//! at most [`MAX_POINTER_JUMPS`] pointers are followed per name.

use std::net::{Ipv4Addr, Ipv6Addr};

use serde::Serialize;

use super::{AppTransport, Issue, Issues};
use crate::bytes::{array, slice, u8_at, u16_at, u32_at};

/// Most questions a message may declare and still be recognized as DNS.
pub const MAX_QUESTIONS: usize = 16;
/// Questions kept per message.
pub const MAX_KEPT_QUESTIONS: usize = 4;
/// Answer records summarized per message.
pub const MAX_ANSWERS: usize = 32;
/// Longest name kept, in output characters; longer names are shortened and
/// end in `...`.
pub const MAX_NAME_CHARS: usize = 255;
/// Output characters (names and answer data) kept per message. Escaping can
/// make text up to four times longer than the wire bytes, so this bounds the
/// memory one message can take.
pub const MAX_MESSAGE_TEXT_CHARS: usize = 2048;
/// Compression pointers followed per name.
pub const MAX_POINTER_JUMPS: usize = 16;
/// Longest name in wire octets (RFC 1035).
const MAX_NAME_OCTETS: usize = 255;
const HEADER_LEN: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DnsQuestion {
    pub name: String,
    pub record_type: u16,
    pub type_name: Option<&'static str>,
    pub class: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DnsAnswer {
    pub name: String,
    pub record_type: u16,
    pub type_name: Option<&'static str>,
    pub class: u16,
    pub ttl: u32,
    /// Safe summary of the record data: an address for A/AAAA, a name for
    /// CNAME/NS/PTR, `preference exchange` for MX, `priority weight port
    /// target` for SRV. `None` for other types, whose data is not shown.
    pub data: Option<String>,
    pub data_length: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DnsMessage {
    pub transport: AppTransport,
    pub transaction_id: u16,
    pub is_response: bool,
    pub opcode: u8,
    pub opcode_name: Option<&'static str>,
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub response_code: u8,
    pub response_code_name: Option<&'static str>,
    pub question_count: u16,
    pub answer_count: u16,
    pub authority_count: u16,
    pub additional_count: u16,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsAnswer>,
}

/// Why a name or record could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fail {
    /// The available bytes ended before the encoding did.
    Short,
    /// The encoding is invalid: bad label type, pointer loop or overlong name.
    Bad,
}

/// What the caller knows about how much of the message is present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Completeness {
    /// The bytes end before the message does (snapshot length, TCP
    /// segmentation or the application byte limit), so running out of data
    /// in the answer section is not malformation.
    pub incomplete: bool,
    /// The snapshot length cut the message, so even the question section may
    /// be cut short and the message still be recognized.
    pub tolerate_short_questions: bool,
}

/// Parses `message` (the DNS message without any TCP length prefix).
pub(crate) fn parse(
    message: &[u8],
    transport: AppTransport,
    completeness: Completeness,
) -> Option<(DnsMessage, Issues)> {
    let (Some(id), Some(flags), Some(qd), Some(an), Some(ns), Some(ar)) = (
        u16_at(message, 0),
        u16_at(message, 2),
        u16_at(message, 4),
        u16_at(message, 6),
        u16_at(message, 8),
        u16_at(message, 10),
    ) else {
        return None;
    };
    let is_response = flags & 0x8000 != 0;
    let opcode = u8::try_from((flags >> 11) & 0x0F).unwrap_or(u8::MAX);
    let opcode_name = opcode_name(opcode);
    // Structural plausibility: known opcode, zero Z bit, sane question count.
    if opcode_name.is_none()
        || flags & 0x0040 != 0
        || usize::from(qd) > MAX_QUESTIONS
        || (qd == 0 && !is_response)
    {
        return None;
    }

    let mut issues = Issues::default();
    let mut offset = HEADER_LEN;
    let mut questions = Vec::new();
    let mut budget = MAX_MESSAGE_TEXT_CHARS;
    for _ in 0..qd {
        let keep = questions.len() < MAX_KEPT_QUESTIONS;
        // Questions beyond those kept are only walked, not decoded.
        let parsed = if keep {
            read_name(message, offset).map(|(name, end)| (Some(name), end))
        } else {
            skip_name(message, offset).map(|end| (None, end))
        }
        .and_then(
            |(name, end)| match (u16_at(message, end), u16_at(message, end + 2)) {
                (Some(record_type), Some(class)) => Ok((name, record_type, class, end + 4)),
                _ => Err(Fail::Short),
            },
        );
        let (name, record_type, class, end) = match parsed {
            Ok(parsed) => parsed,
            Err(Fail::Short) if completeness.tolerate_short_questions => {
                issues.push(Issue::ran_out(
                    "DNS message ends inside the question section",
                ));
                break;
            }
            Err(_) => return None,
        };
        offset = end;
        if let Some(name) = name {
            budget = budget.saturating_sub(name.len());
            questions.push(DnsQuestion {
                name,
                record_type,
                type_name: type_name(record_type),
                class: class & 0x7FFF,
            });
        }
    }
    if usize::from(qd) > MAX_KEPT_QUESTIONS {
        issues.push(Issue::limit("more DNS questions than are kept"));
    }

    let mut answers = Vec::new();
    if issues.is_empty() {
        for index in 0..an {
            if usize::from(index) == MAX_ANSWERS {
                issues.push(Issue::limit("more DNS answers than are summarized"));
                break;
            }
            match read_record(message, offset) {
                Ok((answer, end)) => {
                    let cost = answer.name.len() + answer.data.as_ref().map_or(0, String::len);
                    if cost > budget {
                        issues.push(Issue::limit("DNS names exceed the per-message text limit"));
                        break;
                    }
                    budget -= cost;
                    answers.push(answer);
                    offset = end;
                }
                Err(Fail::Short) if completeness.incomplete => {
                    issues.push(Issue::ran_out("DNS message ends inside the answer section"));
                    break;
                }
                Err(Fail::Short) => {
                    issues.push(Issue::malformed(
                        "DNS message declares more answer data than it contains",
                    ));
                    break;
                }
                Err(Fail::Bad) => {
                    issues.push(Issue::malformed("DNS answer record is malformed"));
                    break;
                }
            }
        }
    }

    let dns = DnsMessage {
        transport,
        transaction_id: id,
        is_response,
        opcode,
        opcode_name,
        authoritative: flags & 0x0400 != 0,
        truncated: flags & 0x0200 != 0,
        recursion_desired: flags & 0x0100 != 0,
        recursion_available: flags & 0x0080 != 0,
        response_code: u8::try_from(flags & 0x000F).unwrap_or(0),
        response_code_name: rcode_name(u8::try_from(flags & 0x000F).unwrap_or(0)),
        question_count: qd,
        answer_count: an,
        authority_count: ns,
        additional_count: ar,
        questions,
        answers,
    };
    Some((dns, issues))
}

fn read_record(message: &[u8], offset: usize) -> Result<(DnsAnswer, usize), Fail> {
    let (name, end) = read_name(message, offset)?;
    let (Some(record_type), Some(class), Some(ttl), Some(data_length)) = (
        u16_at(message, end),
        u16_at(message, end + 2),
        u32_at(message, end + 4),
        u16_at(message, end + 8),
    ) else {
        return Err(Fail::Short);
    };
    let data_start = end + 10;
    let rdata = slice(message, data_start, usize::from(data_length)).ok_or(Fail::Short)?;
    let data = summarize(message, record_type, rdata, data_start);
    let answer = DnsAnswer {
        name,
        record_type,
        type_name: type_name(record_type),
        class: class & 0x7FFF,
        ttl,
        data,
        data_length,
    };
    Ok((answer, data_start + usize::from(data_length)))
}

fn summarize(
    message: &[u8],
    record_type: u16,
    rdata: &[u8],
    rdata_offset: usize,
) -> Option<String> {
    let name_at = |offset: usize| {
        read_name(message, offset).ok().and_then(|(name, end)| {
            // The name must lie within the record data.
            (end <= rdata_offset + rdata.len()).then_some(name)
        })
    };
    match record_type {
        1 if rdata.len() == 4 => array::<4>(rdata, 0).map(|a| Ipv4Addr::from(a).to_string()),
        28 if rdata.len() == 16 => array::<16>(rdata, 0).map(|a| Ipv6Addr::from(a).to_string()),
        2 | 5 | 12 => name_at(rdata_offset),
        15 => {
            let preference = u16_at(rdata, 0)?;
            Some(format!("{preference} {}", name_at(rdata_offset + 2)?))
        }
        33 => {
            let (priority, weight, port) =
                (u16_at(rdata, 0)?, u16_at(rdata, 2)?, u16_at(rdata, 4)?);
            Some(format!(
                "{priority} {weight} {port} {}",
                name_at(rdata_offset + 6)?
            ))
        }
        _ => None,
    }
}

/// Reads a possibly compressed name starting at `start`. Returns the
/// presentation-format name, shortened to [`MAX_NAME_CHARS`] (ending in
/// `...`), and the offset just after the name's encoding at `start` (after
/// the first pointer, if any).
///
/// The whole encoding is validated, but text is only built up to the
/// character limit, so the work per name is bounded however the labels are
/// encoded.
pub(crate) fn read_name(message: &[u8], start: usize) -> Result<(String, usize), Fail> {
    let mut pos = start;
    // Lowest offset visited so far; pointers must jump strictly below it.
    let mut floor = start;
    let mut jumps = 0;
    let mut end = None;
    let mut octets = 0;
    let mut name = String::new();
    let mut shortened = false;
    loop {
        let len = u8_at(message, pos).ok_or(Fail::Short)?;
        match len & 0xC0 {
            0x00 if len == 0 => {
                octets += 1;
                if octets > MAX_NAME_OCTETS {
                    return Err(Fail::Bad);
                }
                let end = end.unwrap_or(pos + 1);
                if name.is_empty() {
                    name.push('.');
                }
                return Ok((name, end));
            }
            0x00 => {
                let label = slice(message, pos + 1, usize::from(len)).ok_or(Fail::Short)?;
                octets += usize::from(len) + 1;
                if octets > MAX_NAME_OCTETS {
                    return Err(Fail::Bad);
                }
                if !shortened {
                    if !name.is_empty() {
                        name.push('.');
                    }
                    push_label(&mut name, label);
                    if name.len() > MAX_NAME_CHARS {
                        // Names are ASCII (non-printable bytes are escaped),
                        // so any byte index is a character boundary.
                        name.truncate(MAX_NAME_CHARS - 3);
                        name.push_str("...");
                        shortened = true;
                    }
                }
                pos += usize::from(len) + 1;
            }
            0xC0 => {
                let target = usize::from(u16_at(message, pos).ok_or(Fail::Short)? & 0x3FFF);
                if target >= floor || jumps == MAX_POINTER_JUMPS {
                    return Err(Fail::Bad);
                }
                end.get_or_insert(pos + 2);
                jumps += 1;
                floor = target;
                pos = target;
            }
            // 0x40 and 0x80 are obsolete/extended label types.
            _ => return Err(Fail::Bad),
        }
    }
}

/// Walks over a name without decoding it and returns the offset just after
/// its encoding at `start`. A compression pointer ends the walk; it must
/// point backwards but is not followed.
fn skip_name(message: &[u8], start: usize) -> Result<usize, Fail> {
    let mut pos = start;
    let mut octets = 0;
    loop {
        let len = u8_at(message, pos).ok_or(Fail::Short)?;
        match len & 0xC0 {
            0x00 if len == 0 => return Ok(pos + 1),
            0x00 => {
                octets += usize::from(len) + 1;
                if octets >= MAX_NAME_OCTETS {
                    return Err(Fail::Bad);
                }
                slice(message, pos + 1, usize::from(len)).ok_or(Fail::Short)?;
                pos += usize::from(len) + 1;
            }
            0xC0 => {
                let target = usize::from(u16_at(message, pos).ok_or(Fail::Short)? & 0x3FFF);
                return if target < start {
                    Ok(pos + 2)
                } else {
                    Err(Fail::Bad)
                };
            }
            _ => return Err(Fail::Bad),
        }
    }
}

/// Appends a label in DNS presentation format: printable characters as is,
/// `.` and `\` escaped, everything else as `\DDD`.
fn push_label(out: &mut String, label: &[u8]) {
    for &b in label {
        match b {
            b'.' | b'\\' => {
                out.push('\\');
                out.push(char::from(b));
            }
            0x21..=0x7E => out.push(char::from(b)),
            _ => {
                out.push('\\');
                out.push(char::from(b'0' + b / 100));
                out.push(char::from(b'0' + b / 10 % 10));
                out.push(char::from(b'0' + b % 10));
            }
        }
    }
}

fn opcode_name(opcode: u8) -> Option<&'static str> {
    Some(match opcode {
        0 => "QUERY",
        1 => "IQUERY",
        2 => "STATUS",
        4 => "NOTIFY",
        5 => "UPDATE",
        _ => return None,
    })
}

fn rcode_name(rcode: u8) -> Option<&'static str> {
    Some(match rcode {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        6 => "YXDOMAIN",
        7 => "YXRRSET",
        8 => "NXRRSET",
        9 => "NOTAUTH",
        10 => "NOTZONE",
        _ => return None,
    })
}

/// Name of a DNS record type.
pub fn type_name(record_type: u16) -> Option<&'static str> {
    Some(match record_type {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        13 => "HINFO",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        35 => "NAPTR",
        41 => "OPT",
        43 => "DS",
        46 => "RRSIG",
        47 => "NSEC",
        48 => "DNSKEY",
        50 => "NSEC3",
        64 => "SVCB",
        65 => "HTTPS",
        99 => "SPF",
        251 => "IXFR",
        252 => "AXFR",
        255 => "ANY",
        257 => "CAA",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMPLETE: Completeness = Completeness {
        incomplete: false,
        tolerate_short_questions: false,
    };

    fn header(id: u16, flags: u16, qd: u16, an: u16) -> Vec<u8> {
        let mut out = Vec::new();
        for v in [id, flags, qd, an, 0, 0] {
            out.extend(v.to_be_bytes());
        }
        out
    }

    fn name(labels: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for l in labels {
            out.push(l.len() as u8);
            out.extend(l.as_bytes());
        }
        out.push(0);
        out
    }

    #[test]
    fn reads_plain_and_compressed_names() {
        let mut msg = header(1, 0, 1, 0);
        msg.extend(name(&["www", "example", "com"]));
        let (n, end) = read_name(&msg, 12).unwrap();
        assert_eq!((n.as_str(), end), ("www.example.com", 12 + 17));

        // "mail" + pointer to "example.com" at offset 16.
        let start = msg.len();
        msg.extend([4, b'm', b'a', b'i', b'l', 0xC0, 16]);
        let (n, end) = read_name(&msg, start).unwrap();
        assert_eq!((n.as_str(), end), ("mail.example.com", start + 7));
    }

    #[test]
    fn root_name_is_a_dot() {
        assert_eq!(read_name(&[0], 0), Ok((".".to_owned(), 1)));
    }

    #[test]
    fn pointer_loops_are_rejected() {
        // Self-pointer.
        let mut msg = header(1, 0, 1, 0);
        msg.extend([0xC0, 12]);
        assert_eq!(read_name(&msg, 12).ok(), None);
        // Forward pointer.
        let mut msg = header(1, 0, 1, 0);
        msg.extend([0xC0, 14, 0]);
        assert_eq!(read_name(&msg, 12).ok(), None);
        // Two-step loop: label at 12 then pointer back to 12.
        let mut msg = header(1, 0, 1, 0);
        msg.extend([1, b'a', 0xC0, 12]);
        assert_eq!(read_name(&msg, 12).ok(), None);
        // Mutual pointers.
        let mut msg = header(1, 0, 1, 0);
        msg.extend([0xC0, 14, 0xC0, 12]);
        assert_eq!(read_name(&msg, 14).ok(), None);
    }

    #[test]
    fn long_pointer_chains_are_capped() {
        // Offset 0 holds the root label; pointer k at offset 2k jumps to 2(k-1).
        let mut msg = vec![0u8, 0];
        for k in 1..=40u16 {
            msg.extend((0xC000 | (2 * (k - 1))).to_be_bytes());
        }
        // 16 jumps are allowed, 17 are not.
        assert_eq!(read_name(&msg, 32).map(|(n, _)| n), Ok(".".to_owned()));
        assert_eq!(read_name(&msg, 34).ok(), None);
        assert_eq!(read_name(&msg, 80).ok(), None);
    }

    #[test]
    fn overlong_names_are_rejected() {
        let mut msg = Vec::new();
        for _ in 0..5 {
            msg.push(63);
            msg.extend([b'a'; 63]);
        }
        msg.push(0);
        assert_eq!(read_name(&msg, 0).ok(), None);
    }

    #[test]
    fn unusual_bytes_are_escaped() {
        let msg = [3, b'a', b'.', 0x07, 0];
        assert_eq!(read_name(&msg, 0).unwrap().0, "a\\.\\007");
    }

    #[test]
    fn rejects_non_dns_headers() {
        // Unknown opcode 3.
        let mut msg = header(1, 3 << 11, 1, 0);
        msg.extend(name(&["a"]));
        msg.extend([0, 1, 0, 1]);
        assert!(parse(&msg, AppTransport::Udp, COMPLETE).is_none());
        // Query without questions.
        assert!(parse(&header(1, 0, 0, 0), AppTransport::Udp, COMPLETE).is_none());
        // Too short.
        assert!(parse(&[0; 11], AppTransport::Udp, COMPLETE).is_none());
    }

    #[test]
    fn names_are_shortened_while_reading() {
        // 255 octets of non-printable bytes: 3 labels of 63 and one of 61.
        let mut msg = Vec::new();
        for len in [63u8, 63, 63, 61] {
            msg.push(len);
            msg.extend(std::iter::repeat_n(0xFF, usize::from(len)));
        }
        msg.push(0);
        let (name, end) = read_name(&msg, 0).unwrap();
        assert_eq!(end, 255);
        assert_eq!(name.len(), MAX_NAME_CHARS);
        assert!(name.starts_with("\\255\\255"));
        assert!(name.ends_with("..."));
    }

    #[test]
    fn failures_separate_missing_bytes_from_bad_encodings() {
        assert_eq!(read_name(&[3, b'a', b'b'], 0), Err(Fail::Short));
        assert_eq!(read_name(&[0x40, 0], 0), Err(Fail::Bad));
        assert_eq!(skip_name(&[3, b'a', b'b'], 0), Err(Fail::Short));
        assert_eq!(skip_name(&[0, 1, b'a', 0xC0, 0], 1), Ok(5));
        assert_eq!(skip_name(&[0xC0, 0], 0), Err(Fail::Bad));
    }

    #[test]
    fn answers_cut_short_are_incomplete_only_when_the_message_is() {
        let mut msg = header(1, 0x8180, 1, 1);
        msg.extend(name(&["a", "example"]));
        msg.extend([0, 16, 0, 1]);
        msg.extend([0xC0, 12, 0, 16, 0, 1, 0, 0, 0, 60, 0, 200]);
        msg.extend([7; 20]);
        let incomplete = Completeness {
            incomplete: true,
            tolerate_short_questions: false,
        };
        let (_, issues) = parse(&msg, AppTransport::Tcp, incomplete).unwrap();
        assert_eq!(
            issues.first().map(|i| i.code),
            Some(crate::DecodeWarningCode::IncompleteApplicationData)
        );
        let (_, issues) = parse(&msg, AppTransport::Udp, COMPLETE).unwrap();
        assert_eq!(
            issues.first().map(|i| i.code),
            Some(crate::DecodeWarningCode::MalformedApplicationData)
        );
    }
}

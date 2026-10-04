//! Application-layer recognition rules, exercised through `decode_packet`.

mod common;

use common::*;
use decoder::{
    DecodeStatus, DecodeWarningCode, DecodedPacket, LINKTYPE_ETHERNET, Layer, Protocol, TcpFlags,
    decode_packet,
};
use proptest::prelude::*;

fn udp_packet(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    ethernet(0x0800, &ipv4(&Ipv4::default(), &udp(sport, dport, payload)))
}

fn tcp_packet(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let opts = Ipv4 {
        protocol: 6,
        ..Ipv4::default()
    };
    ethernet(
        0x0800,
        &ipv4(
            &opts,
            &tcp(sport, dport, TcpFlags::PSH | TcpFlags::ACK, &[], payload),
        ),
    )
}

fn decode(frame: &[u8]) -> DecodedPacket {
    decode_packet(LINKTYPE_ETHERNET, frame, frame.len() as u32)
}

fn codes(packet: &DecodedPacket) -> Vec<DecodeWarningCode> {
    packet.warnings.iter().map(|w| w.code).collect()
}

fn dns_query(id: u16, name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for v in [id, 0x0100, 1, 0, 0, 0] {
        out.extend(v.to_be_bytes());
    }
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend(label.as_bytes());
    }
    out.extend([0, 0, 1, 0, 1]);
    out
}

#[test]
fn dns_over_udp_and_tcp() {
    let packet = decode(&udp_packet(40000, 53, &dns_query(7, "www.example.com")));
    assert_eq!(packet.status, DecodeStatus::Complete);
    let Some(Layer::Dns(dns)) = packet.layers.last() else {
        panic!("{packet:?}")
    };
    assert_eq!(dns.transaction_id, 7);
    assert_eq!(dns.questions[0].name, "www.example.com");
    assert_eq!(packet.info(), "query 0x0007 A www.example.com");

    let query = dns_query(8, "a.example");
    let mut framed = (query.len() as u16).to_be_bytes().to_vec();
    framed.extend(&query);
    let packet = decode(&tcp_packet(40000, 53, &framed));
    let Some(Layer::Dns(dns)) = packet.layers.last() else {
        panic!("{packet:?}")
    };
    assert_eq!(dns.transaction_id, 8);
    assert_eq!(
        serde_json::to_value(dns.as_ref()).unwrap()["transport"],
        "tcp"
    );
}

#[test]
fn ports_are_hints_not_proof() {
    // Not DNS on a DNS port: unknown, with a warning.
    let packet = decode(&udp_packet(40000, 53, MARKER));
    assert_eq!(packet.top_protocol(), Some(Protocol::Udp));
    assert_eq!(
        codes(&packet),
        [DecodeWarningCode::UnrecognizedApplicationData]
    );

    // A valid DNS message on an unrelated UDP port is not guessed at.
    let packet = decode(&udp_packet(40000, 9999, &dns_query(1, "a.example")));
    assert_eq!(packet.top_protocol(), Some(Protocol::Udp));
    assert!(packet.warnings.is_empty());

    // HTTP on a non-standard port is recognized by structure.
    let packet = decode(&tcp_packet(
        40000,
        8081,
        b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n",
    ));
    assert_eq!(packet.top_protocol(), Some(Protocol::Http));

    // Non-HTTP on port 80 stays unknown, silently (it may be a continuation).
    let packet = decode(&tcp_packet(40000, 80, MARKER));
    assert_eq!(packet.top_protocol(), Some(Protocol::Tcp));
    assert!(packet.warnings.is_empty());
}

#[test]
fn fragments_are_not_examined() {
    let opts = Ipv4 {
        flags_fragment: 0x2000,
        ..Ipv4::default()
    };
    let frame = ethernet(
        0x0800,
        &ipv4(&opts, &udp(40000, 53, &dns_query(1, "a.example"))),
    );
    let packet = decode(&frame);
    assert_eq!(packet.top_protocol(), Some(Protocol::Udp));
}

#[test]
fn snapped_application_data_is_truncated() {
    let mut response = Vec::new();
    for v in [9u16, 0x8180, 1, 1, 0, 0] {
        response.extend(v.to_be_bytes());
    }
    response.extend([1, b'a', 0, 0, 1, 0, 1]);
    response.extend([0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1]);
    let frame = udp_packet(53, 40000, &response);
    let full = decode(&frame);
    assert_eq!(full.status, DecodeStatus::Complete);
    let cut = decode_packet(
        LINKTYPE_ETHERNET,
        &frame[..frame.len() - 6],
        frame.len() as u32,
    );
    assert_eq!(cut.status, DecodeStatus::Truncated);
    assert_eq!(cut.top_protocol(), Some(Protocol::Dns));
}

#[test]
fn segment_continuations_are_incomplete_not_truncated() {
    // A ClientHello whose record continues in the next segment: version,
    // random, empty session id and the start of the cipher-suite list.
    let mut payload = vec![22u8, 3, 1, 1, 0, 1, 0, 0, 252, 3, 3];
    payload.extend([0u8; 32]);
    payload.extend([0, 0, 2]);
    let packet = decode(&tcp_packet(40000, 443, &payload));
    assert_eq!(packet.status, DecodeStatus::Complete);
    assert_eq!(packet.top_protocol(), Some(Protocol::Tls));
    assert_eq!(
        codes(&packet),
        [DecodeWarningCode::IncompleteApplicationData]
    );
}

#[test]
fn inspection_is_capped_at_the_application_limit() {
    let mut request = b"GET / HTTP/1.1\r\n".to_vec();
    while request.len() < decoder::app::MAX_APPLICATION_BYTES + 100 {
        request.extend(b"X-Filler: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n");
    }
    let packet = decode(&tcp_packet(40000, 80, &request));
    let Some(Layer::Http(http)) = packet.layers.last() else {
        panic!()
    };
    assert_eq!(http.header_block, decoder::app::http::HeaderBlock::Stopped);
    assert!(usize::from(http.header_count) <= decoder::app::http::MAX_HEADERS);
}

#[test]
fn secrets_never_reach_any_output() {
    let secret = "FLOWSENTINEL-SECRET";
    let request = format!(
        "GET http://u:{secret}@a.example/p?token={secret} HTTP/1.1\r\nAuthorization: Basic {secret}\r\nCookie: {secret}\r\nX-Api-Key: {secret}\r\n\r\n{secret}"
    );
    let response =
        format!("HTTP/1.1 302 Found\r\nSet-Cookie: s={secret}\r\nLocation: /?{secret}\r\n\r\n");
    for frame in [
        tcp_packet(40000, 80, request.as_bytes()),
        tcp_packet(80, 40000, response.as_bytes()),
    ] {
        let packet = decode(&frame);
        assert_eq!(packet.top_protocol(), Some(Protocol::Http));
        let json = serde_json::to_string(&packet).unwrap();
        let text = format!(
            "{}{}",
            packet.info(),
            packet
                .layers
                .iter()
                .map(Layer::describe)
                .collect::<String>()
        );
        assert!(!json.contains(secret), "{json}");
        assert!(!text.contains(secret), "{text}");
        assert!(
            packet
                .warnings
                .iter()
                .any(|w| w.code == DecodeWarningCode::SensitiveDataRedacted)
        );
    }
}

#[test]
fn json_layers_are_tagged() {
    let packet = decode(&udp_packet(40000, 53, &dns_query(7, "www.example.com")));
    let json = serde_json::to_value(&packet).unwrap();
    assert_eq!(json["layers"][3]["layer"], "dns");
    assert_eq!(json["layers"][3]["questions"][0]["type_name"], "A");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    /// Arbitrary payloads on every application port never panic, and any
    /// recognized layer serializes.
    #[test]
    fn arbitrary_application_payloads_never_panic(
        port in prop_oneof![Just(53u16), Just(5353), Just(67), Just(68), Just(80), Just(443), any::<u16>()],
        tcp_transport in any::<bool>(),
        payload in proptest::collection::vec(any::<u8>(), 0..2048),
    ) {
        let frame = if tcp_transport { tcp_packet(40000, port, &payload) } else { udp_packet(40000, port, &payload) };
        let packet = decode(&frame);
        prop_assert!(serde_json::to_string(&packet).is_ok());
        let _ = packet.info();
        for layer in &packet.layers {
            let _ = layer.describe();
        }
    }

    /// Payloads that start like a valid message but continue randomly.
    #[test]
    fn structured_prefixes_never_panic(
        prefix in prop_oneof![
            Just(b"GET / HTTP/1.1\r\n".to_vec()),
            Just(b"HTTP/1.1 200 OK\r\n".to_vec()),
            Just(vec![22u8, 3, 1, 0x02, 0x00, 1, 0, 1, 0xFC, 3, 3]),
            Just(vec![0x12u8, 0x34, 0x81, 0x80, 0, 1, 0, 8, 0, 0, 0, 0]),
        ],
        tail in proptest::collection::vec(any::<u8>(), 0..1024),
    ) {
        let mut payload = prefix.clone();
        payload.extend(tail);
        let port = if prefix[0] == 0x12 { 53 } else { 443 };
        let packet = decode(&udp_packet(40000, port, &payload));
        prop_assert!(serde_json::to_string(&packet).is_ok());
        let packet = decode(&tcp_packet(40000, port, &payload));
        prop_assert!(serde_json::to_string(&packet).is_ok());
    }
}

/// A request target that must never appear in output.
const TARGET_SECRET: &str = "Zq9SecretMarker";

#[test]
fn unusual_request_targets_never_leak_credentials() {
    let s = TARGET_SECRET;
    let targets = [
        format!("ftp://user:{s}@files.example/x"),
        format!("ws://u:{s}@h.example/"),
        format!("//user:{s}@host.example/p"),
        format!("http:///u:{s}@h.example"),
        format!("https:/u:{s}@h.example"),
        format!("http://admin:{s}?x@host.example/"),
        format!("http://admin:{s}#x@host.example/"),
        format!("http://u:p/{s}@h.example/"),
        format!("http://user:{s}@host.example/path"),
        format!("/p;jsessionid={s}"),
        format!("/p?token={s}"),
        format!("/reset/{s}0123456789abc"),
        format!("HTTP://{s}:{s}@a.example/"),
    ];
    for target in targets {
        let request = format!("GET {target} HTTP/1.1\r\nHost: a.example\r\n\r\n");
        let packet = decode(&tcp_packet(40000, 80, request.as_bytes()));
        assert_eq!(packet.top_protocol(), Some(Protocol::Http), "{target}");
        let json = serde_json::to_string(&packet).unwrap().to_ascii_lowercase();
        let text = format!(
            "{}{}",
            packet.info(),
            packet
                .layers
                .iter()
                .map(Layer::describe)
                .collect::<String>()
        )
        .to_ascii_lowercase();
        let needle = s.to_ascii_lowercase();
        assert!(!json.contains(&needle), "{target}: {json}");
        assert!(!text.contains(&needle), "{target}: {text}");
        assert!(
            packet
                .warnings
                .iter()
                .any(|w| w.code == DecodeWarningCode::SensitiveDataRedacted),
            "{target}"
        );
    }
}

#[test]
fn host_values_must_be_host_and_port() {
    for (host, expected) in [
        ("a.example", Some("a.example")),
        ("A.Example:8080", Some("a.example:8080")),
        ("[2001:db8::1]:443", Some("[2001:db8::1]:443")),
        ("user:pass", None),
        ("a.example:99999x", None),
        ("a.example:", None),
        ("bad host", None),
        ("a@b.example", None),
    ] {
        let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");
        let packet = decode(&tcp_packet(40000, 80, request.as_bytes()));
        let Some(Layer::Http(http)) = packet.layers.last() else {
            panic!()
        };
        assert_eq!(http.host.as_deref(), expected, "{host}");
    }
}

fn tls_ext(ext_type: u16, data: &[u8]) -> Vec<u8> {
    let mut out = ext_type.to_be_bytes().to_vec();
    out.extend((data.len() as u16).to_be_bytes());
    out.extend(data);
    out
}

fn sni_ext(name: &[u8]) -> Vec<u8> {
    let mut entry = vec![0];
    entry.extend((name.len() as u16).to_be_bytes());
    entry.extend(name);
    let mut data = (entry.len() as u16).to_be_bytes().to_vec();
    data.extend(entry);
    tls_ext(0, &data)
}

/// A ClientHello handshake message (without record header).
fn hello_message(extensions: &[u8]) -> Vec<u8> {
    let mut body = vec![3, 3];
    body.extend([0u8; 32]);
    body.push(0);
    body.extend([0, 2, 0x13, 0x01, 1, 0]);
    body.extend((extensions.len() as u16).to_be_bytes());
    body.extend(extensions);
    let mut msg = vec![1];
    msg.extend(&(body.len() as u32).to_be_bytes()[1..]);
    msg.extend(body);
    msg
}

fn record(fragment: &[u8]) -> Vec<u8> {
    let mut out = vec![22, 3, 1];
    out.extend((fragment.len() as u16).to_be_bytes());
    out.extend(fragment);
    out
}

#[test]
fn tls_hellos_split_across_records_are_not_misread() {
    // The hello is split over two records in one segment. Reading straight
    // through would treat the second record's header as hello bytes and
    // could show an SNI the real hello does not contain.
    let hello = hello_message(&sni_ext(b"real.example"));
    let (first, second) = hello.split_at(50);
    let mut payload = record(first);
    payload.extend(record(second));
    let packet = decode(&tcp_packet(40000, 443, &payload));
    let Some(Layer::Tls(tls)) = packet.layers.last() else {
        panic!("{packet:?}")
    };
    assert!(!tls.complete);
    assert_eq!(tls.server_name, None);
    assert!(
        packet
            .warnings
            .iter()
            .any(|w| w.code == DecodeWarningCode::IncompleteApplicationData)
    );

    // The same hello in one record is read fully.
    let packet = decode(&tcp_packet(40000, 443, &record(&hello)));
    let Some(Layer::Tls(tls)) = packet.layers.last() else {
        panic!()
    };
    assert!(tls.complete);
    assert_eq!(tls.server_name.as_deref(), Some("real.example"));
}

#[test]
fn complete_but_inconsistent_tls_hellos_are_malformed() {
    let mut hello = hello_message(&sni_ext(b"a.example"));
    hello.extend([0, 0]); // trailing bytes after the extensions...
    let body_len = (hello.len() - 4) as u32;
    hello[1..4].copy_from_slice(&body_len.to_be_bytes()[1..]); // ...inside the declared length
    let packet = decode(&tcp_packet(40000, 443, &record(&hello)));
    assert_eq!(packet.status, DecodeStatus::Malformed);
}

#[test]
fn alpn_grease_is_skipped_and_long_lists_are_limited() {
    let mut list = vec![2, 0x0A, 0x0A, 2, b'h', b'2'];
    for _ in 0..20 {
        list.extend([3, b'a', b'b', b'c']);
    }
    let mut data = (list.len() as u16).to_be_bytes().to_vec();
    data.extend(list);
    let packet = decode(&tcp_packet(
        40000,
        443,
        &record(&hello_message(&tls_ext(16, &data))),
    ));
    let Some(Layer::Tls(tls)) = packet.layers.last() else {
        panic!()
    };
    assert_eq!(tls.alpn.first().map(String::as_str), Some("h2"));
    assert_eq!(tls.alpn.len(), decoder::app::tls::MAX_ALPN);
    assert_ne!(packet.status, DecodeStatus::Malformed);
    assert!(codes(&packet).contains(&DecodeWarningCode::ApplicationLimitReached));
}

#[test]
fn dns_text_is_bounded_per_message() {
    // 16 questions and 32 CNAME answers all pointing at a 255-octet name of
    // 0xFF bytes, each of which escapes to four characters.
    let mut msg = Vec::new();
    for v in [1u16, 0x8180, 16, 32, 0, 0] {
        msg.extend(v.to_be_bytes());
    }
    let long_name_at = msg.len() as u16;
    // Three 63-byte labels and one 61-byte label: exactly 255 wire octets.
    for len in [63u8, 63, 63, 61] {
        msg.push(len);
        msg.extend(std::iter::repeat_n(0xFF, usize::from(len)));
    }
    msg.push(0);
    msg.extend([0, 1, 0, 1]);
    for _ in 1..16 {
        msg.extend((0xC000 | long_name_at).to_be_bytes());
        msg.extend([0, 1, 0, 1]);
    }
    for _ in 0..32 {
        msg.extend((0xC000 | long_name_at).to_be_bytes());
        msg.extend([0, 5, 0, 1, 0, 0, 0, 60, 0, 2]);
        msg.extend((0xC000 | long_name_at).to_be_bytes());
    }
    let packet = decode(&udp_packet(53, 40000, &msg));
    let Some(Layer::Dns(dns)) = packet.layers.last() else {
        panic!("{packet:?}")
    };
    assert!(dns.questions.len() <= decoder::app::dns::MAX_KEPT_QUESTIONS);
    assert!(
        dns.questions
            .iter()
            .all(|q| q.name.len() <= decoder::app::dns::MAX_NAME_CHARS)
    );
    let size = serde_json::to_string(&packet).unwrap().len();
    assert!(
        size < 8 * 1024,
        "decoded DNS message serialized to {size} bytes"
    );
    assert!(codes(&packet).contains(&DecodeWarningCode::ApplicationLimitReached));
}

#[test]
fn tcp_dns_ports_fall_back_to_http_and_tls() {
    let packet = decode(&tcp_packet(
        53,
        40000,
        b"GET /x HTTP/1.1\r\nHost: a.example\r\n\r\n",
    ));
    assert_eq!(packet.top_protocol(), Some(Protocol::Http));
    // mDNS port over TCP is not DNS.
    let mut framed = (dns_query(1, "a.example").len() as u16)
        .to_be_bytes()
        .to_vec();
    framed.extend(dns_query(1, "a.example"));
    let packet = decode(&tcp_packet(40000, 5353, &framed));
    assert_eq!(packet.top_protocol(), Some(Protocol::Tcp));
}

#[test]
fn tcp_dns_split_across_segments_is_incomplete() {
    // A TXT response declared as 1300 bytes, of which the first segment
    // carries 400: the boundary falls inside the answer data.
    let mut msg = Vec::new();
    for v in [9u16, 0x8180, 1, 1, 0, 0] {
        msg.extend(v.to_be_bytes());
    }
    msg.extend([1, b'a', 7]);
    msg.extend(b"example");
    msg.extend([0, 0, 16, 0, 1]);
    msg.extend([0xC0, 12, 0, 16, 0, 1, 0, 0, 0, 60]);
    let rdata_len = 1300 - msg.len() - 2;
    msg.extend((rdata_len as u16).to_be_bytes());
    msg.extend(std::iter::repeat_n(b'x', rdata_len));
    assert_eq!(msg.len(), 1300);
    let mut segment = (msg.len() as u16).to_be_bytes().to_vec();
    segment.extend(&msg[..398]);
    let packet = decode(&tcp_packet(53, 40000, &segment));
    assert_eq!(packet.status, DecodeStatus::Complete, "{packet:?}");
    assert_eq!(packet.top_protocol(), Some(Protocol::Dns));
    assert_eq!(
        codes(&packet),
        [DecodeWarningCode::IncompleteApplicationData]
    );

    // The same message, complete in one segment, has no warnings, and a
    // complete message whose counts overrun it is malformed.
    let mut whole = (msg.len() as u16).to_be_bytes().to_vec();
    whole.extend(&msg);
    let packet = decode(&tcp_packet(53, 40000, &whole));
    assert_eq!(codes(&packet), []);
    let mut lying = msg.clone();
    lying[7] = 2; // two answers declared, one present
    let mut framed = (lying.len() as u16).to_be_bytes().to_vec();
    framed.extend(&lying);
    let packet = decode(&tcp_packet(53, 40000, &framed));
    assert_eq!(packet.status, DecodeStatus::Malformed);
}

#[test]
fn udp_messages_that_end_early_are_malformed() {
    let mut response = Vec::new();
    for v in [1u16, 0x8180, 1, 3, 0, 0] {
        response.extend(v.to_be_bytes());
    }
    response.extend([1, b'a', 0, 0, 1, 0, 1]); // question, then no answers at all
    let packet = decode(&udp_packet(53, 40000, &response));
    assert_eq!(packet.status, DecodeStatus::Malformed);
    assert_eq!(
        codes(&packet),
        [DecodeWarningCode::MalformedApplicationData]
    );
}

#[test]
fn snapped_application_headers_are_truncated_not_unrecognized() {
    let mut dhcp = vec![1u8, 1, 6, 0];
    dhcp.extend([0u8; 300]);
    let frame = udp_packet(68, 67, &dhcp);
    let packet = decode_packet(
        LINKTYPE_ETHERNET,
        &frame[..14 + 20 + 8 + 100],
        frame.len() as u32,
    );
    assert_eq!(packet.status, DecodeStatus::Truncated);
    assert!(!codes(&packet).contains(&DecodeWarningCode::UnrecognizedApplicationData));
}

fn assert_no_control_characters(value: &serde_json::Value) {
    match value {
        serde_json::Value::String(s) => {
            assert!(
                !s.chars().any(char::is_control),
                "control character in {s:?}"
            );
        }
        serde_json::Value::Array(items) => items.iter().for_each(assert_no_control_characters),
        serde_json::Value::Object(map) => map.values().for_each(assert_no_control_characters),
        _ => {}
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    /// No decoded string can carry control characters (terminal escapes,
    /// newlines) into output, whatever the payload.
    #[test]
    fn decoded_text_has_no_control_characters(
        port in prop_oneof![Just(53u16), Just(67), Just(80), Just(443)],
        tcp_transport in any::<bool>(),
        prefix in prop_oneof![
            Just(b"GET /".to_vec()),
            Just(b"HTTP/1.1 200 ".to_vec()),
            Just(vec![22u8, 3, 1, 0x01, 0x00, 1, 0, 0, 0xFC, 3, 3]),
            Just(vec![0x12u8, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]),
            Just(Vec::new()),
        ],
        tail in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let mut payload = prefix;
        payload.extend(tail);
        let frame = if tcp_transport { tcp_packet(40000, port, &payload) } else { udp_packet(40000, port, &payload) };
        let packet = decode(&frame);
        assert_no_control_characters(&serde_json::to_value(&packet).unwrap());
        prop_assert!(!packet.info().chars().any(char::is_control));
        for layer in &packet.layers {
            prop_assert!(!layer.describe().chars().any(char::is_control));
        }
    }

    /// DHCP behind a valid fixed header and magic cookie, with random
    /// options, so the option walker is actually exercised.
    #[test]
    fn dhcp_option_walker_never_panics(options in proptest::collection::vec(any::<u8>(), 0..600)) {
        let mut dhcp = vec![2u8, 1, 6, 0];
        dhcp.extend([0u8; 232]);
        dhcp.extend([0x63, 0x82, 0x53, 0x63]);
        dhcp.extend(options);
        let packet = decode(&udp_packet(67, 68, &dhcp));
        prop_assert!(matches!(packet.layers.last(), Some(Layer::Dhcp(_))));
        prop_assert!(serde_json::to_string(&packet).is_ok());
    }

    /// DNS over TCP with a correct length prefix and random message body.
    #[test]
    fn tcp_dns_never_panics(body in proptest::collection::vec(any::<u8>(), 0..512), snap in any::<bool>()) {
        let mut message = vec![0x12u8, 0x34, 0x01, 0x00, 0, 1, 0, 1, 0, 0, 0, 0];
        message.extend(body);
        let mut framed = (message.len() as u16).to_be_bytes().to_vec();
        framed.extend(message);
        let frame = tcp_packet(40000, 53, &framed);
        let captured = if snap { frame.len() * 2 / 3 } else { frame.len() };
        let packet = decode_packet(LINKTYPE_ETHERNET, &frame[..captured], frame.len() as u32);
        prop_assert!(serde_json::to_string(&packet).is_ok());
    }
}

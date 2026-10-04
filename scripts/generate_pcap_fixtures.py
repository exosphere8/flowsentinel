#!/usr/bin/env python3
"""Generate the synthetic PCAP fixtures under fixtures/pcap/.

Every file is built byte by byte from constants in this script, so the output
is fully deterministic: running the script twice produces identical bytes, and
CI regenerates the fixtures and fails if they differ from the committed copies.

Safety rules for everything generated here:

* Addresses come from documentation ranges only: IPv4 192.0.2.0/24 and
  198.51.100.0/24 (RFC 5737) and locally administered MACs 02:00:00:00:00:xx.
* Packet payloads contain only PAYLOAD_MARKER. Tests assert that this marker
  never appears in any FlowSentinel output, which proves payload bytes are not
  echoed back to the user.
* No real traffic, credentials or personal data.

Usage: python3 scripts/generate_pcap_fixtures.py
Requires only the Python 3 standard library.
"""

from __future__ import annotations

import struct
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "pcap"

# 2026-01-01T00:00:00Z. Fixed so timestamps in test expectations never drift.
BASE_TIME = 1767225600

PAYLOAD_MARKER = b"FLOWSENTINEL-SYNTHETIC-PAYLOAD-MARKER"

MAGIC_USEC = 0xA1B2C3D4
MAGIC_NSEC = 0xA1B23C4D
MAGIC_MODIFIED = 0xA1B2CD34
LINKTYPE_ETHERNET = 1
DEFAULT_SNAPLEN = 65535

MAC_A = bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
MAC_B = bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x02])
IP_A = bytes([192, 0, 2, 10])
IP_B = bytes([198, 51, 100, 20])


def ipv4_checksum(header: bytes) -> int:
    total = 0
    for i in range(0, len(header), 2):
        total += (header[i] << 8) | header[i + 1]
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def udp_frame(seq: int, payload: bytes = PAYLOAD_MARKER) -> bytes:
    """Ethernet II / IPv4 / UDP frame from 192.0.2.10:40000+seq to 198.51.100.20:9."""
    udp_len = 8 + len(payload)
    udp = struct.pack("!HHHH", 40000 + seq, 9, udp_len, 0) + payload
    total_len = 20 + udp_len
    ip_wo_csum = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, total_len, seq & 0xFFFF, 0x4000, 64, 17, 0, IP_A, IP_B
    )
    ip = ip_wo_csum[:10] + struct.pack("!H", ipv4_checksum(ip_wo_csum)) + ip_wo_csum[12:]
    return MAC_B + MAC_A + struct.pack("!H", 0x0800) + ip + udp


# --- Protocol builders for the decoder fixtures (Milestone 2) --------------

IP6_A = bytes.fromhex("20010db8000000000000000000000a00")  # 2001:db8::a00
IP6_B = bytes.fromhex("20010db8000000000000000000001400")  # 2001:db8::1400
GATEWAY = bytes([192, 0, 2, 1])
BROADCAST = b"\xff" * 6


def eth(ethertype: int, payload: bytes, src: bytes = MAC_A, dst: bytes = MAC_B) -> bytes:
    return dst + src + struct.pack("!H", ethertype) + payload


def vlan_eth(tags: list[tuple[int, int]], ethertype: int, payload: bytes) -> bytes:
    out = MAC_B + MAC_A
    for tpid, tci in tags:
        out += struct.pack("!HH", tpid, tci)
    return out + struct.pack("!H", ethertype) + payload


def ipv4(
    proto: int,
    payload: bytes,
    ident: int = 1,
    flags_frag: int = 0x4000,
    ttl: int = 64,
    src: bytes = IP_A,
    dst: bytes = IP_B,
    version_ihl: int = 0x45,
    total_len: int | None = None,
) -> bytes:
    header_len = (version_ihl & 0x0F) * 4
    total = header_len + len(payload) if total_len is None else total_len
    hdr = struct.pack(
        "!BBHHHBBH4s4s", version_ihl, 0, total, ident, flags_frag, ttl, proto, 0, src, dst
    )
    hdr += b"\x00" * max(0, header_len - 20)
    hdr = hdr[:10] + struct.pack("!H", ipv4_checksum(hdr)) + hdr[12:]
    return hdr + payload


def ipv6(next_header: int, payload: bytes, src: bytes = IP6_A, dst: bytes = IP6_B) -> bytes:
    word0 = (6 << 28) | 0x12345
    return struct.pack("!IHBB", word0, len(payload), next_header, 64) + src + dst + payload


def udp(sport: int, dport: int, payload: bytes = PAYLOAD_MARKER, length: int | None = None) -> bytes:
    udp_len = 8 + len(payload) if length is None else length
    return struct.pack("!HHHH", sport, dport, udp_len, 0) + payload


TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK = 0x01, 0x02, 0x04, 0x08, 0x10


def tcp(
    sport: int,
    dport: int,
    flags: int,
    seq: int,
    ack: int = 0,
    payload: bytes = b"",
    options: bytes = b"",
    data_offset: int | None = None,
) -> bytes:
    offset = (20 + len(options)) // 4 if data_offset is None else data_offset
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, offset << 4, flags, 64240, 0, 0)
    return hdr + options + payload


def icmp(icmp_type: int, ident: int, seq: int, payload: bytes = PAYLOAD_MARKER) -> bytes:
    return struct.pack("!BBHHH", icmp_type, 0, 0, ident, seq) + payload


def arp(op: int, sender_ip: bytes, target_ip: bytes) -> bytes:
    target_mac = b"\x00" * 6 if op == 1 else MAC_B
    return struct.pack("!HHBBH", 1, 0x0800, 6, 4, op) + MAC_A + sender_ip + target_mac + target_ip


def ext_header(next_header: int, units: int = 0) -> bytes:
    return bytes([next_header, units]) + b"\x00" * ((units + 1) * 8 - 2)


def frag_header(next_header: int, offset: int, more: bool, ident: int) -> bytes:
    return struct.pack("!BBHI", next_header, 0, (offset // 8) << 3 | int(more), ident)


def capture_of(frames: list[bytes], linktype: int = LINKTYPE_ETHERNET, snaplen: int = DEFAULT_SNAPLEN,
               cut: dict[int, int] | None = None) -> bytes:
    """Capture with one frame every 10 ms. `cut` maps a frame index to a
    captured length, simulating a short snapshot length for that frame."""
    out = global_header("<", snaplen=snaplen, linktype=linktype)
    for i, frame in enumerate(frames):
        captured = frame[: cut[i]] if cut and i in cut else frame
        out += record("<", BASE_TIME + i // 100, (i % 100) * 10_000, captured, orig_len=len(frame))
    return out


def decode_fixtures() -> dict[str, bytes]:
    mss = bytes([2, 4, 0x05, 0xB4, 1, 1, 4, 2])  # MSS 1460, NOP, NOP, SACK permitted
    ipv4_frames = [
        eth(0x0806, arp(1, IP_A, GATEWAY), dst=BROADCAST),
        eth(0x0806, arp(2, GATEWAY, IP_A), src=MAC_B, dst=MAC_A),
        eth(0x0800, ipv4(17, udp(40000, 9))),
        eth(0x0800, ipv4(6, tcp(40001, 9, TCP_SYN, 1000, options=mss))),
        eth(0x0800, ipv4(6, tcp(9, 40001, TCP_SYN | TCP_ACK, 5000, 1001, options=mss), src=IP_B, dst=IP_A), src=MAC_B, dst=MAC_A),
        eth(0x0800, ipv4(6, tcp(40001, 9, TCP_ACK, 1001, 5001))),
        eth(0x0800, ipv4(6, tcp(40001, 9, TCP_PSH | TCP_ACK, 1001, 5001, PAYLOAD_MARKER))),
        eth(0x0800, ipv4(6, tcp(40001, 9, TCP_FIN | TCP_ACK, 1038, 5001))),
        eth(0x0800, ipv4(1, icmp(8, 0x0101, 1))),
        eth(0x0800, ipv4(1, icmp(0, 0x0101, 1), src=IP_B, dst=IP_A), src=MAC_B, dst=MAC_A),
        vlan_eth([(0x8100, 0x200A)], 0x0800, ipv4(17, udp(40002, 9))),
        vlan_eth([(0x88A8, 100), (0x8100, 10)], 0x0800, ipv4(17, udp(40003, 9))),
        # One UDP datagram split into two IPv4 fragments.
        eth(0x0800, ipv4(17, udp(40004, 9, b"\x00" * 16, length=8 + 40), ident=77, flags_frag=0x2000)),
        eth(0x0800, ipv4(17, PAYLOAD_MARKER[:24], ident=77, flags_frag=3)),
    ]
    ipv6_frames = [
        eth(0x86DD, ipv6(17, udp(40000, 9))),
        eth(0x86DD, ipv6(6, tcp(40001, 9, TCP_SYN, 1000, options=mss))),
        eth(0x86DD, ipv6(58, icmp(128, 0x0202, 1))),
        eth(0x86DD, ipv6(58, icmp(135, 0, 0, b"\x00" * 16))),
        eth(0x86DD, ipv6(0, ext_header(60) + ext_header(17, 1) + udp(40005, 9))),
        eth(0x86DD, ipv6(44, frag_header(17, 0, True, 0xABCD) + udp(40006, 9, b"\x00" * 16, length=8 + 64))),
        eth(0x86DD, ipv6(44, frag_header(17, 24, False, 0xABCD) + PAYLOAD_MARKER)),
        eth(0x86DD, ipv6(50, b"\x00" * 8 + PAYLOAD_MARKER)),
        eth(0x86DD, ipv6(59, b"")),
    ]
    unsupported_frames = [
        eth(0x88CC, b"\x02\x07\x04" + MAC_A + b"\x00" * 20),  # LLDP
        eth(len(PAYLOAD_MARKER) + 3, b"\xaa\xaa\x03" + PAYLOAD_MARKER),  # 802.3 + LLC
        eth(0x0800, ipv4(47, b"\x00\x00\x08\x00" + PAYLOAD_MARKER)),  # GRE
        vlan_eth([(0x88A8, 1), (0x8100, 2), (0x8100, 3)], 0x0800, ipv4(17, udp(40000, 9))),
        eth(0x0800, ipv4(17, udp(40000, 9))),
    ]
    tcp_frame = eth(0x0800, ipv4(6, tcp(40001, 9, TCP_ACK, 1, 1, PAYLOAD_MARKER)))
    malformed_frames = [
        eth(0x0800, ipv4(17, udp(40000, 9)))[:10],  # 0: truncated Ethernet
        eth(0x0800, ipv4(17, udp(40000, 9), version_ihl=0x55)),  # 1: IPv4 version 5
        eth(0x0800, ipv4(17, udp(40000, 9), version_ihl=0x44)),  # 2: IHL 4
        eth(0x0800, ipv4(17, udp(40000, 9), total_len=12)),  # 3: total length < header
        eth(0x0800, ipv4(6, tcp(40001, 9, TCP_ACK, 1, data_offset=4))),  # 4: TCP data offset 4
        eth(0x0800, ipv4(17, udp(40000, 9, length=4))),  # 5: UDP length < 8
        eth(0x0800, ipv4(17, udp(40000, 9, length=600))),  # 6: UDP length > IP payload
        tcp_frame,  # 7: cut inside the TCP header (see `cut`)
        eth(0x86DD, ipv6(17, udp(40000, 9)))[:14] + b"\x45" + eth(0x86DD, ipv6(17, udp(40000, 9)))[15:],  # 8: IPv6 version 4
        eth(0x86DD, ipv6(60, bytes([17, 6]) + b"\x00" * 6)),  # 9: ext header longer than payload length
        eth(0x86DD, ipv6(60, ext_header(17, 1) + udp(40000, 9))),  # 10: cut inside the ext header
        eth(0x0800, ipv4(17, udp(40000, 9), total_len=1500)),  # 11: total length beyond the frame
        eth(0x0800, ipv4(17, udp(40000, 9))),  # 12: valid packet after the damage
    ]
    raw_frames = [ipv4(17, udp(40000, 9)), ipv4(1, icmp(8, 1, 1))]
    return {
        "decode-ipv4.pcap": capture_of(ipv4_frames),
        "decode-ipv6.pcap": capture_of(ipv6_frames),
        "decode-unsupported.pcap": capture_of(unsupported_frames),
        "decode-malformed.pcap": capture_of(malformed_frames, cut={7: 14 + 20 + 12, 10: 14 + 40 + 10}),
        "decode-raw-linktype.pcap": capture_of(raw_frames, linktype=101),
    }


# --- Application-protocol builders (Milestone 3) ---------------------------
#
# Every credential-like value below contains SECRET_MARKER. Tests assert that
# no FlowSentinel output ever contains it, which proves redaction works.

SECRET_MARKER = b"FLOWSENTINEL-SECRET"
DNS_SERVER = bytes([192, 0, 2, 53])
WEB_SERVER = bytes([198, 51, 100, 80])


def dns_name(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def dns_header(ident: int, flags: int, qd: int, an: int, ns: int = 0, ar: int = 0) -> bytes:
    return struct.pack("!HHHHHH", ident, flags, qd, an, ns, ar)


def dns_question(name: str, qtype: int, qclass: int = 1) -> bytes:
    return dns_name(name) + struct.pack("!HH", qtype, qclass)


def dns_rr(name: bytes, rtype: int, ttl: int, rdata: bytes, rclass: int = 1) -> bytes:
    return name + struct.pack("!HHIH", rtype, rclass, ttl, len(rdata)) + rdata


def udp_ip(src: bytes, dst: bytes, sport: int, dport: int, payload: bytes, ident: int = 1) -> bytes:
    return eth(0x0800, ipv4(17, udp(sport, dport, payload), ident=ident, src=src, dst=dst))


def tcp_ip(src: bytes, dst: bytes, sport: int, dport: int, payload: bytes, seq: int = 1) -> bytes:
    return eth(0x0800, ipv4(6, tcp(sport, dport, TCP_PSH | TCP_ACK, seq, 1, payload), src=src, dst=dst))


def dns_frames() -> list[bytes]:
    q = dns_header(0x1A2B, 0x0100, 1, 0) + dns_question("www.example.com", 1)
    # Response: CNAME www.example.com -> web.example.com, A web.example.com.
    # Names are compressed: 0xC00C points to the question name at offset 12.
    cname_target = b"\x03web" + b"\xc0\x10"  # "web" + pointer to "example.com"
    resp = (
        dns_header(0x1A2B, 0x8180, 1, 2)
        + dns_question("www.example.com", 1)
        + dns_rr(b"\xc0\x0c", 5, 300, cname_target)
        + dns_rr(b"\xc0\x2d", 1, 60, WEB_SERVER)
    )
    aaaa_q = dns_header(0x0002, 0x0100, 1, 0) + dns_question("www.example.com", 28)
    aaaa_r = (
        dns_header(0x0002, 0x8180, 1, 1)
        + dns_question("www.example.com", 28)
        + dns_rr(b"\xc0\x0c", 28, 60, bytes.fromhex("20010db8000000000000000000000080"))
    )
    nx = dns_header(0x0003, 0x8183, 1, 0) + dns_question("missing.example", 1)
    mx = (
        dns_header(0x0004, 0x8180, 1, 1)
        + dns_question("example.com", 15)
        + dns_rr(b"\xc0\x0c", 15, 3600, struct.pack("!H", 10) + b"\x04mail\xc0\x0c")
    )
    txt = (
        dns_header(0x0005, 0x8180, 1, 1)
        + dns_question("example.com", 16)
        + dns_rr(b"\xc0\x0c", 16, 60, bytes([len(SECRET_MARKER) + 4]) + SECRET_MARKER + b"-TXT")
    )
    mdns = dns_header(0, 0x8400, 0, 1) + dns_rr(
        dns_name("printer.local"), 1, 120, bytes([192, 0, 2, 77]), rclass=0x8001
    )
    # Answer name is a compression loop: pointer to itself.
    loop_answer = dns_header(0x0006, 0x8180, 1, 1) + dns_question("loop.example", 1)
    loop_answer += b"\xc0" + bytes([len(loop_answer)]) + struct.pack("!HHIH", 1, 1, 60, 4) + bytes(4)
    tcp_query = dns_header(0x0007, 0x0100, 1, 0) + dns_question("www.example.com", 1)
    return [
        udp_ip(IP_A, DNS_SERVER, 53000, 53, q),
        udp_ip(DNS_SERVER, IP_A, 53, 53000, resp),
        udp_ip(IP_A, DNS_SERVER, 53001, 53, aaaa_q),
        udp_ip(DNS_SERVER, IP_A, 53, 53001, aaaa_r),
        udp_ip(DNS_SERVER, IP_A, 53, 53002, nx),
        udp_ip(DNS_SERVER, IP_A, 53, 53003, mx),
        udp_ip(DNS_SERVER, IP_A, 53, 53004, txt),
        eth(0x0800, ipv4(17, udp(5353, 5353, mdns), src=bytes([192, 0, 2, 77]), dst=bytes([224, 0, 0, 251]))),
        udp_ip(DNS_SERVER, IP_A, 53, 53005, loop_answer),
        tcp_ip(IP_A, DNS_SERVER, 53006, 53, struct.pack("!H", len(tcp_query)) + tcp_query),
        udp_ip(IP_A, DNS_SERVER, 53007, 53, PAYLOAD_MARKER),  # not DNS
        udp_ip(DNS_SERVER, IP_A, 53, 53000, resp),  # cut by the snapshot length below
    ]


def dhcp_message(op: int, msg_type: int, xid: int, yiaddr: bytes, options: bytes,
                 ciaddr: bytes = bytes(4), broadcast: bool = True) -> bytes:
    fixed = struct.pack("!BBBBIHH", op, 1, 6, 0, xid, 0, 0x8000 if broadcast else 0)
    siaddr = GATEWAY if op == 2 else bytes(4)  # only server replies name a server
    fixed += ciaddr + yiaddr + siaddr + bytes(4)
    fixed += MAC_A + bytes(10) + bytes(64) + bytes(128)
    return fixed + struct.pack("!I", 0x63825363) + bytes([53, 1, msg_type]) + options + b"\xff"


def dhcp_frames() -> list[bytes]:
    zero, bcast = bytes(4), b"\xff" * 4
    client_id = bytes([61, 7, 1]) + MAC_A
    params = bytes([55, 4, 1, 3, 6, 15])
    hostname = bytes([12, 11]) + b"lab-host-01"
    discover = dhcp_message(1, 1, 0x3903F326, zero, client_id + params + hostname)
    offer = dhcp_message(2, 2, 0x3903F326, IP_A,
                         bytes([54, 4]) + GATEWAY + bytes([51, 4]) + struct.pack("!I", 86400))
    request = dhcp_message(1, 3, 0x3903F326, zero,
                           bytes([50, 4]) + IP_A + bytes([54, 4]) + GATEWAY + hostname)
    ack = dhcp_message(2, 5, 0x3903F326, IP_A,
                       bytes([54, 4]) + GATEWAY + bytes([51, 4]) + struct.pack("!I", 86400))
    return [
        eth(0x0800, ipv4(17, udp(68, 67, discover), src=zero, dst=bcast), dst=BROADCAST),
        eth(0x0800, ipv4(17, udp(67, 68, offer), src=GATEWAY, dst=IP_A), src=MAC_B, dst=MAC_A),
        eth(0x0800, ipv4(17, udp(68, 67, request), src=zero, dst=bcast), dst=BROADCAST),
        eth(0x0800, ipv4(17, udp(67, 68, ack), src=GATEWAY, dst=IP_A), src=MAC_B, dst=MAC_A),
        eth(0x0800, ipv4(17, udp(68, 67, PAYLOAD_MARKER), src=zero, dst=bcast)),  # not DHCP
    ]


def http_frames() -> list[bytes]:
    request = (
        b"GET /index.html?session=" + SECRET_MARKER + b"-QUERY HTTP/1.1\r\n"
        b"Host: www.example.com\r\n"
        b"User-Agent: flowsentinel-fixture\r\n"
        b"Authorization: Bearer " + SECRET_MARKER + b"-TOKEN\r\n"
        b"Cookie: id=" + SECRET_MARKER + b"-COOKIE\r\n"
        b"Accept: */*\r\n\r\n"
    )
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n"
        b"Content-Length: " + str(len(PAYLOAD_MARKER)).encode() + b"\r\n"
        b"Set-Cookie: sid=" + SECRET_MARKER + b"-SETCOOKIE\r\n"
        b"Connection: keep-alive\r\n\r\n" + PAYLOAD_MARKER
    )
    body = b"user=alice&password=" + SECRET_MARKER + b"-PASSWORD"
    post = (
        b"POST http://admin:" + SECRET_MARKER + b"-USERINFO@www.example.com/login HTTP/1.0\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    )
    alt_port = b"HEAD /status HTTP/1.1\r\nHost: www.example.com:8080\r\n\r\n"
    embedded = (
        b"GET /fetch/http://admin:" + SECRET_MARKER + b"-EMBEDDED@db.example/x HTTP/1.1\r\n"
        b"Host: www.example.com\r\n\r\n"
    )
    return [
        tcp_ip(IP_A, WEB_SERVER, 40100, 80, request),
        tcp_ip(WEB_SERVER, IP_A, 80, 40100, response),
        tcp_ip(IP_A, WEB_SERVER, 40101, 80, post),
        tcp_ip(IP_A, WEB_SERVER, 40102, 8080, alt_port),
        tcp_ip(IP_A, WEB_SERVER, 40103, 80, PAYLOAD_MARKER),  # not HTTP
        tcp_ip(IP_A, WEB_SERVER, 40104, 80, embedded),  # URL with credentials inside the path
    ]


def tls_extension(ext_type: int, data: bytes) -> bytes:
    return struct.pack("!HH", ext_type, len(data)) + data


def tls_record(handshake_type: int, body: bytes, record_version: int = 0x0301) -> bytes:
    handshake = bytes([handshake_type]) + len(body).to_bytes(3, "big") + body
    return struct.pack("!BHH", 22, record_version, len(handshake)) + handshake


def client_hello(server_name: bytes) -> bytes:
    random = SECRET_MARKER + b"-TLS-RANDOM!!"  # exactly 32 bytes
    session = SECRET_MARKER + b"-SESSION-ID!!"  # exactly 32 bytes
    assert len(random) == 32 and len(session) == 32
    suites = [0x1A1A, 0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F]
    sni = struct.pack("!BH", 0, len(server_name)) + server_name
    alpn_list = b"\x02h2\x08http/1.1"
    extensions = b"".join([
        tls_extension(0x0A0A, b""),  # GREASE
        tls_extension(0, struct.pack("!H", len(sni)) + sni),
        tls_extension(16, struct.pack("!H", len(alpn_list)) + alpn_list),
        tls_extension(43, bytes([6]) + struct.pack("!HHH", 0x2A2A, 0x0304, 0x0303)),
        tls_extension(10, struct.pack("!HHH", 4, 0x001D, 0x0017)),
        tls_extension(51, struct.pack("!HHH", 38, 0x001D, 32) + SECRET_MARKER + b"-KEYSHARE-BYTE"),
        tls_extension(13, struct.pack("!HHH", 4, 0x0403, 0x0804)),
    ])
    body = struct.pack("!H", 0x0303) + random + bytes([32]) + session
    body += struct.pack("!H", 2 * len(suites)) + b"".join(struct.pack("!H", s) for s in suites)
    body += b"\x01\x00" + struct.pack("!H", len(extensions)) + extensions
    return tls_record(1, body)


def server_hello() -> bytes:
    random = SECRET_MARKER + b"-SRV-RANDOM!!!"[:13]
    random = (random + b"!" * 32)[:32]
    extensions = tls_extension(43, struct.pack("!H", 0x0304)) + tls_extension(
        51, struct.pack("!HH", 0x001D, 32) + bytes(32)
    )
    body = struct.pack("!H", 0x0303) + random + bytes([0]) + struct.pack("!HB", 0x1301, 0)
    body += struct.pack("!H", len(extensions)) + extensions
    return tls_record(2, body, record_version=0x0303)


def tls_frames() -> list[bytes]:
    certificate = tls_record(11, b"\x00\x00\x10" + SECRET_MARKER[:16], record_version=0x0303)
    app_data = struct.pack("!BHH", 23, 0x0303, len(PAYLOAD_MARKER)) + PAYLOAD_MARKER
    return [
        tcp_ip(IP_A, WEB_SERVER, 40200, 443, client_hello(b"www.example.com")),
        tcp_ip(WEB_SERVER, IP_A, 443, 40200, server_hello()),
        tcp_ip(WEB_SERVER, IP_A, 443, 40200, certificate),  # not a hello: unknown
        tcp_ip(IP_A, WEB_SERVER, 40200, 443, app_data),  # encrypted data: unknown
        tcp_ip(IP_A, WEB_SERVER, 40201, 8443, client_hello(b"api.example.org")),
    ]


def application_fixtures() -> dict[str, bytes]:
    dns = dns_frames()
    return {
        "app-dns.pcap": capture_of(dns, cut={len(dns) - 1: 14 + 20 + 8 + 40}),
        "app-dhcp.pcap": capture_of(dhcp_frames()),
        "app-http.pcap": capture_of(http_frames()),
        "app-tls.pcap": capture_of(tls_frames()),
    }


def global_header(
    endian: str,
    magic: int = MAGIC_USEC,
    major: int = 2,
    minor: int = 4,
    thiszone: int = 0,
    snaplen: int = DEFAULT_SNAPLEN,
    linktype: int = LINKTYPE_ETHERNET,
) -> bytes:
    return struct.pack(endian + "IHHiIII", magic, major, minor, thiszone, 0, snaplen, linktype)


def record(
    endian: str,
    ts_sec: int,
    ts_frac: int,
    data: bytes,
    incl_len: int | None = None,
    orig_len: int | None = None,
) -> bytes:
    incl = len(data) if incl_len is None else incl_len
    orig = len(data) if orig_len is None else orig_len
    return struct.pack(endian + "IIII", ts_sec, ts_frac, incl, orig) + data


def simple_capture(endian: str, magic: int, count: int, frac_step: int) -> bytes:
    out = global_header(endian, magic=magic)
    for i in range(count):
        out += record(endian, BASE_TIME + i // 4, (i % 4) * frac_step, udp_frame(i))
    return out


def pcapng_minimal() -> bytes:
    """Section Header Block plus an Ethernet Interface Description Block."""
    shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    shb_len = 12 + len(shb_body)
    shb = struct.pack("<II", 0x0A0D0D0A, shb_len) + shb_body + struct.pack("<I", shb_len)
    idb_body = struct.pack("<HHI", LINKTYPE_ETHERNET, 0, DEFAULT_SNAPLEN)
    idb_len = 12 + len(idb_body)
    idb = struct.pack("<II", 0x00000001, idb_len) + idb_body + struct.pack("<I", idb_len)
    return shb + idb


def fixtures() -> dict[str, bytes]:
    le, be = "<", ">"
    files: dict[str, bytes] = {}

    # Valid captures in every supported magic/byte-order combination.
    files["le-usec.pcap"] = simple_capture(le, MAGIC_USEC, 3, 250_000)
    files["be-usec.pcap"] = simple_capture(be, MAGIC_USEC, 3, 250_000)
    files["le-nsec.pcap"] = simple_capture(le, MAGIC_NSEC, 3, 250_000_000)
    files["be-nsec.pcap"] = simple_capture(be, MAGIC_NSEC, 3, 250_000_000)
    files["UPPERCASE-EXTENSION.PCAP"] = simple_capture(le, MAGIC_USEC, 1, 0)
    files["header-only.pcap"] = global_header(le)
    files["many-packets.pcap"] = simple_capture(le, MAGIC_USEC, 25, 250_000)

    # Valid container with record-level oddities that produce warnings.
    warn = global_header(le, snaplen=64)
    frame = udp_frame(0)  # 79 bytes, larger than the 64-byte snaplen
    warn += record(le, BASE_TIME + 10, 0, frame)  # captured > snaplen
    warn += record(le, BASE_TIME + 5, 0, frame[:60], orig_len=60)  # out of order
    warn += record(le, BASE_TIME + 11, 0, frame[:60], orig_len=40)  # captured > original
    warn += record(le, BASE_TIME + 12, 1_000_000, frame[:60])  # bad usec fraction
    warn += record(le, BASE_TIME + 13, 0, frame, orig_len=100)  # captured > snaplen again
    files["record-warnings.pcap"] = warn

    # Container-level failures.
    files["truncated-global-header.pcap"] = global_header(le)[:12]
    files["invalid-magic.pcap"] = b"NOTA" + global_header(le)[4:]
    files["pcapng-content.pcap"] = pcapng_minimal()
    files["modified-pcap.pcap"] = global_header(le, magic=MAGIC_MODIFIED)
    files["bad-version.pcap"] = global_header(le, major=3, minor=0)
    files["bad-version-minor.pcap"] = global_header(le, minor=5)

    # Historical versions: before 2.3 the two length fields were swapped on disk.
    frame = udp_frame(0)
    files["v2-2-swapped-lengths.pcap"] = global_header(le, minor=2) + record(
        le, BASE_TIME, 0, frame[:64], incl_len=len(frame), orig_len=64
    )
    files["zero-snaplen.pcap"] = global_header(le, snaplen=0)
    files["reserved-linktype-bits.pcap"] = global_header(le, linktype=0x00010001)
    files["minimal.pcapng"] = pcapng_minimal()

    # Record-level failures.
    good = record(le, BASE_TIME, 0, udp_frame(0))
    files["truncated-record-header.pcap"] = global_header(le) + good + good[:7]
    files["truncated-record-data.pcap"] = (
        global_header(le) + good + record(le, BASE_TIME + 1, 0, udp_frame(1)[:10], incl_len=79)
    )
    files["huge-captured-length.pcap"] = (
        global_header(le) + good + struct.pack("<IIII", BASE_TIME + 1, 0, 0xFFFFFFF0, 0xFFFFFFF0)
    )
    files.update(decode_fixtures())
    files.update(application_fixtures())
    return files


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    generated = fixtures()
    # Remove fixtures the script no longer produces, so CI notices stale files.
    for stale in sorted(OUT_DIR.iterdir()):
        if stale.is_file() and stale.name not in generated:
            stale.unlink()
            print(f"removed stale fixtures/pcap/{stale.name}")
    for name, data in sorted(generated.items()):
        (OUT_DIR / name).write_bytes(data)
        print(f"wrote fixtures/pcap/{name} ({len(data)} bytes)")


if __name__ == "__main__":
    main()

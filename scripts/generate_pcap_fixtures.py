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

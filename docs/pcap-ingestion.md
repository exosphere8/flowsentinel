# Offline PCAP ingestion

`flowsentinel inspect` reads an offline capture file and reports **container metadata only**: the
PCAP global header and the header of each packet record. It does not decode Ethernet, IP or any
higher protocol, and it never prints, stores or logs packet contents.

> Inspect only captures you own or are explicitly authorized to analyze.

## Usage

```bash
flowsentinel inspect --pcap <PATH> [--max-file-size-mb <MB>] [--max-packets <COUNT>]
                     [--max-duration-seconds <SECONDS>] [--json]
```

| Flag | Default | Allowed | Effect |
| --- | --- | --- | --- |
| `--pcap <PATH>` | required | | Classic libpcap file to inspect |
| `--max-file-size-mb` | 512 | 1–65536 | Files larger than this are rejected before parsing |
| `--max-packets` | 100000 | 1–1000000 | Stop after this many records; result is marked partial |
| `--max-duration-seconds` | 60 | 1–3600 | Stop after this much processing time; result is marked partial |
| `--json` | off | | Print one JSON object on stdout instead of tables |

Values outside the allowed ranges are usage errors (exit code 2).

### Example

```text
$ flowsentinel inspect --pcap fixtures/pcap/le-usec.pcap
Capture summary
  File               le-usec.pcap (309 bytes)
  Format             pcap 2.4, little-endian, microsecond timestamps
  Snapshot length    65535 bytes
  Link type          1 (ETHERNET)
  Packets processed  3
  Captured bytes     237 (original 237)
  Earliest packet    2026-01-01T00:00:00.000000Z
  Latest packet      2026-01-01T00:00:00.500000Z
  Completion         complete
  Limits             512 MiB, 100000 packets, 60 s

Warnings
  none

Packets
        #  Timestamp (UTC)                 Captured  Original
        1  2026-01-01T00:00:00.000000Z           79        79
        2  2026-01-01T00:00:00.250000Z           79        79
        3  2026-01-01T00:00:00.500000Z           79        79
```

## Supported input

- **Classic libpcap files only**, with the `.pcap` extension (any letter case).
- Magic numbers `0xA1B2C3D4` (microsecond timestamps) and `0xA1B23C4D` (nanosecond timestamps),
  in either byte order.
- Format versions 2.0 to 2.4. As in libpcap, files older than 2.3 store the captured and original
  lengths swapped, and 2.3 files are swapped when the captured length exceeds the original
  length. Both are corrected and produce an `unusual_version_minor` warning. Versions above 2.4
  are rejected.
- Any link-layer type. The type is reported by number and, when recognized, by its `LINKTYPE_*`
  name. Packets are not decoded in this milestone, so the link type does not change processing.

Not supported:

- **pcapng** (`.pcapng` files, or pcapng content inside a `.pcap` file). Convert with
  `editcap -F pcap in.pcapng out.pcap`.
- The "modified" libpcap format (magic `0xA1B2CD34`).
- Compressed captures.

## Validation order

Each check runs before the work it protects:

1. The path exists. A path whose parent is a file, such as `trace.pcap/x.pcap`, also counts as
   missing.
2. It is a regular file. Directories are rejected on every platform. On Unix, devices, sockets and
   FIFOs are rejected too. The file is opened non-blocking and re-checked through the open
   handle, so a path swapped for a FIFO after validation cannot hang the read. On Windows the
   standard library cannot tell named pipes apart from files, so inspect only ordinary files there.
3. The extension is `.pcap`, case-insensitive. `.pcapng` gets a dedicated error.
4. The file size is within `--max-file-size-mb`. The size is checked again on the opened handle.
   Exactly that many bytes are read, so a file that grows during the read cannot push past the
   validated size. If the size changed by the end, a `file_size_changed` warning is added.
5. The global header: magic number, length, version, snapshot length and reserved link-type bits.
6. Each record header, before its packet data is touched.

## Output

### JSON

`--json` prints exactly one JSON object followed by a newline:

```json
{
  "summary": {
    "file_name": "le-usec.pcap",
    "file_size_bytes": 309,
    "format": "pcap",
    "header": {
      "version": { "major": 2, "minor": 4 },
      "endianness": "little",
      "timestamp_resolution": "microsecond",
      "timezone_offset_seconds": 0,
      "snap_length": 65535,
      "link_type": 1,
      "link_type_name": "ETHERNET",
      "fcs_length_bytes": null
    },
    "packets_processed": 3,
    "captured_bytes_total": 237,
    "original_bytes_total": 237,
    "earliest_timestamp": { "unix_seconds": 1767225600, "nanos": 0, "rfc3339": "2026-01-01T00:00:00.000000Z" },
    "latest_timestamp": { "unix_seconds": 1767225600, "nanos": 500000000, "rfc3339": "2026-01-01T00:00:00.500000Z" },
    "limits": { "max_file_size_bytes": 536870912, "max_packets": 100000, "max_duration_seconds": 60 }
  },
  "packets": [
    {
      "index": 1,
      "file_offset": 24,
      "timestamp": { "unix_seconds": 1767225600, "nanos": 0, "rfc3339": "2026-01-01T00:00:00.000000Z" },
      "captured_length": 79,
      "original_length": 79
    }
  ],
  "completion_state": "complete",
  "warnings": []
}
```

(The output is compact on one line; it is formatted here for reading.)

| Field | Meaning |
| --- | --- |
| `summary.file_name` | Final path component only. Control characters and Unicode bidirectional overrides are replaced with `?`; names over 128 characters are shortened. |
| `packets[].index` | 1-based record number, matching Wireshark frame numbers |
| `packets[].file_offset` | Byte offset of the record header in the file |
| `packets[].timestamp` | `null` if the record's fraction is out of range (see warnings) |
| `completion_state` | `complete`, `packet_limit_reached` or `time_limit_reached` |

Timestamps are printed as written in the file, with 6 or 9 fractional digits to match the file's
resolution. `earliest_timestamp` and `latest_timestamp` are the minimum and maximum, not the first
and last records, so out-of-order files are summarized correctly.

### Errors

Without `--json`, errors are printed to stderr as `error: <message>`. With `--json`, input,
format and I/O errors are printed to stdout as one object:

```json
{"error":{"code":"invalid_magic","category":"malformed","message":"not a classic PCAP file: ..."}}
```

Command-line usage errors (exit code 2), such as `--max-packets 0`, are detected before any
processing. They are always printed as plain text on stderr, even with `--json`, and stdout stays
empty.

## Completion states

Reaching a packet or time limit is **not an error**. Inspection stops, everything read so far is
reported, the exit code is 0, and `completion_state` says why it stopped. The reader looks ahead
without consuming input, so a file with exactly `--max-packets` records is reported as `complete`.

## Warnings

Warnings describe oddities that do not stop processing. Each kind is reported once, with a count
and the first packet it affected, so a hostile file cannot inflate the output.

| Code | Trigger |
| --- | --- |
| `unusual_version_minor` | The minor version is below 4; record lengths were read in that version's historical order |
| `nonzero_timezone_offset` | The header's time zone field is not 0. Timestamps are shown unadjusted. |
| `captured_length_exceeds_snap_length` | A record holds more bytes than the declared snapshot length |
| `captured_length_exceeds_original_length` | A record holds more bytes than were on the wire |
| `timestamp_fraction_out_of_range` | A fraction is ≥ 1,000,000 µs or ≥ 1,000,000,000 ns. That record's timestamp is `null`. |
| `timestamp_out_of_order` | A record is earlier than the one before it |
| `file_size_changed` | The file changed size during the read. Only the bytes present at validation were read. |

## Errors and exit codes

| Exit | Category | Codes |
| --- | --- | --- |
| 0 | | Success, including partial results at a limit |
| 2 | usage | Invalid or missing command-line arguments |
| 3 | `input` | `missing_path`, `not_a_file`, `unsupported_extension`, `pcapng_not_supported`, `file_too_large`, `unsupported_format` |
| 4 | `malformed` | `truncated_global_header`, `invalid_magic`, `corrupt_global_header`, `invalid_version`, `invalid_snap_length`, `truncated_record_header`, `truncated_record_data`, `unsafe_captured_length` |
| 5 | `io` | `io_error` (including failure to write output) |

| Code | Meaning |
| --- | --- |
| `unsupported_format` | The content is recognizably pcapng or modified pcap, even though the extension is `.pcap` |
| `corrupt_global_header` | Reserved bits (mask `0x03FF0000`) of the link-type field are set |
| `invalid_version` | The version is not between 2.0 and 2.4 |
| `invalid_snap_length` | The snapshot length is 0 |
| `truncated_record_header` | Between 1 and 15 bytes follow the last complete record |
| `truncated_record_data` | A record declares more bytes than remain in the file |
| `unsafe_captured_length` | A record declares more than libpcap's maximum for the link type: 262,144 bytes for most types; 1 MiB for USBPcap, 8 MiB for EBHSCR and 128 MiB for D-Bus |

A truncated or corrupt record is a hard error. Its message gives the packet index and byte offset
so you can locate the damage, for example to cut the file at the last good record. Errors never
include bytes from the file.

## Safety properties

- **Streaming.** The file is read through a 64 KiB buffer. Packet data passes through that
  buffer and is discarded; it is never retained or returned. Memory use is independent of file
  size. The only growing structure is the packet table, at 40 bytes per record, bounded by
  `--max-packets`. Library callers get the same bounds: `CaptureLimits` values outside the
  documented ranges are clamped, and the effective values are reported in `summary.limits`.
- **No untrusted allocation.** No buffer is sized from a value in the file. A record that declares
  more than its link type's maximum (262,144 bytes for most types) stops the read before
  anything is skipped or allocated.
- **Checked arithmetic.** Offsets and totals use saturating arithmetic; every header field is read
  through bounds-checked slices.
- **Deterministic limits.** The time limit reads an injectable `Clock`, which tests replace with a
  scripted one.
- **Metadata only.** Public models (`CaptureReport`, `PacketRecordMetadata`) have no field that
  could hold packet bytes. Integration tests embed a marker string in every fixture payload and
  assert that it never appears in any output.

## Library use

The `capture` crate can be used directly:

```rust
use std::path::Path;
use capture::{CaptureLimits, inspect_file};

let report = inspect_file(Path::new("trace.pcap"), &CaptureLimits::default())?;
for packet in &report.packets {
    println!("{} {}", packet.index, packet.captured_length);
}
```

For streaming use without retaining records, use `capture::PcapReader` over any `BufRead`.

## Fixtures

All test captures are synthetic and generated by
[`scripts/generate_pcap_fixtures.py`](../scripts/generate_pcap_fixtures.py), which needs only the
Python 3 standard library:

```bash
python3 scripts/generate_pcap_fixtures.py
```

CI regenerates the fixtures and fails if they differ from the committed files. See
[`fixtures/README.md`](../fixtures/README.md) for the list.

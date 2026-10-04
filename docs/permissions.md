# Permissions

FlowSentinel needs no special privileges for anything except
[live capture](live-capture.md). Never run the whole server as root or Administrator. Give the
one capability capture needs to the server binary only, and only on machines where you are
authorized to capture.

## What needs which permission

| Feature | Needs |
| --- | --- |
| `flowsentinel inspect`, `flows`, `detect` (the CLI) | Read access to the capture file |
| The API server and dashboard | Its listen port (use one above 1023), its database, read-write access to its upload directory |
| Live capture | Additionally, permission to open a packet capture on the chosen interface (below) |

When the server lacks the capture permission, starting a capture fails with
`503 capture_permission_denied`, and the message points here. Nothing else changes. The server
does not try to gain privileges.

## Linux

Capturing needs the `CAP_NET_RAW` capability. Grant it to the server binary:

```bash
sudo setcap cap_net_raw=eip /usr/local/bin/flowsentinel-api
getcap /usr/local/bin/flowsentinel-api      # /usr/local/bin/flowsentinel-api cap_net_raw=eip
```

- Then run the server as an ordinary, dedicated user. The capability applies only to that binary,
  so it is lost when the binary is replaced. Run `setcap` again after each upgrade.
- We tested this: a non-root user running a binary with `cap_net_raw` only captured loopback
  traffic with promiscuous mode off, and the same binary without it was refused with
  `capture_permission_denied`. CI repeats this test as an unprivileged user.
- Promiscuous mode was not part of that test. If enabling it fails with a permission error on
  your system, `CAP_NET_ADMIN` may also be needed (`setcap cap_net_raw,cap_net_admin=eip ...`).
  Grant it only if you need promiscuous mode.
- Do not use `sudo` or `setuid` to start the server, and do not run it as root.

With systemd, prefer giving the capability to the service rather than the file, and keep the rest
locked down:

```ini
[Service]
User=flowsentinel
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
NoNewPrivileges=yes
```

## Docker

The Compose `app` service drops all capabilities and cannot capture. To capture from a container:

- **Add only `NET_RAW`** to the service (`cap_add: [NET_RAW]`). Keep `cap_drop: [ALL]` and
  `no-new-privileges`.
- **Choose the network the container sees.**
  - On its default network, the container sees only its own interface, which carries only its own
    traffic.
  - Capturing the host's interfaces needs `network_mode: host`. That also removes the
    container's network isolation, and the server then listens directly on the host. Weigh that
    before using it, and keep `FLOWSENTINEL_API_ADDR` on loopback or behind HTTPS.
- **Enable live capture** with `FLOWSENTINEL_LIVE_CAPTURE=true`, and list the allowed interfaces
  in `FLOWSENTINEL_LIVE_INTERFACES`.
- **The capability must reach the process.** The image runs as UID 10001, and capabilities added
  with `cap_add` reach a non-root process only as ambient capabilities. If capture is still
  refused, grant the capability to the binary in a derived image instead:
  `RUN setcap cap_net_raw=eip /usr/local/bin/flowsentinel-api`, with `libcap2-bin` installed.
  Keep `cap_add: [NET_RAW]`, because a file capability cannot exceed the container's bounding set.

The image and Compose file in this repository do none of this by default.

## macOS

libpcap opens `/dev/bpf*` devices, which only root can read by default. Wireshark's ChmodBPF
package, or an equivalent launch daemon, gives a group (for example `access_bpf`) read access.

- Add the server's user to that group instead of running the server as root.
- macOS loopback (`lo0`) does not use Ethernet framing. Packets captured there are stored with the
  status `unsupported`; see [live-capture.md](live-capture.md#limits-of-this-design).

## Windows

Install [Npcap](https://npcap.com/).

- To build with live capture, the linker also needs the Npcap SDK's `wpcap.lib` and
  `Packet.lib`. Set `LIB` to the SDK's `Lib\x64` folder, then
  `cargo build --release -p api-server --features live-capture`.
- If Npcap was installed with "Restrict Npcap driver's access to Administrators only", capture
  needs an elevated process. Reinstall without that option rather than running the server as
  Administrator.
- Builds without the feature work everywhere and answer `501 live_capture_unavailable`.

## Least privilege beyond capture

- Live capture is off unless `FLOWSENTINEL_LIVE_CAPTURE=true`, admin-only, and confirmed by the
  admin for each capture.
- `FLOWSENTINEL_LIVE_INTERFACES` limits which interfaces can be used, for example to a dedicated
  monitoring port.
- The capture file is written to the upload directory with owner-only permissions on Unix, and
  deleted after import. Give that directory to the server's user only.
- The database user needs no superuser rights: the server only reads and writes its own tables
  and runs its migrations.

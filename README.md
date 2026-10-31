# Syncbox

Syncbox is a Rust command-line application for synchronizing multiple independent shared directories over a peer-to-peer Iroh network.

## Features

- One global Iroh device identity per installation.
- Independent `share_id` and `share_secret` for every shared directory.
- Binary, versioned `syncbox1:` ShareTickets with strict validation and checksums.
- Persistent application state in the operating system data directory, never in the shared directory.
- Runtime status with heartbeat, lock, PID, and stale-process detection.
- Local changes trigger a scan via filesystem notifications; a full scan still runs every 60 seconds
  to catch missed events. If watching fails, Syncbox falls back to scanning every 5 seconds.
- Unfiltered QUIC candidates through Iroh N0 discovery, with port mapping, automatic direct-path
  selection, and N0 relay fallback. Connections are reused across synchronization rounds and shares;
  each stream authenticates its share independently. Iroh prefers direct paths over relay paths and
  selects by biased RTT, not measured file-transfer throughput. The outgoing pool holds at most
  32 peers and evicts only unused connections; active streams retain connection leases.
- Shares run independent outbound synchronization loops, with at most four share cycles active at
  once. A slow share does not delay the next scan or retry cycle of others with available capacity.
- Independent peer retry backoff with jitter and rotating candidate selection. Connection attempts
  have a 20-second deadline and authentication a 10-second deadline. Blocked network reads and writes
  time out after 60 seconds without progress, rather than imposing a fixed total transfer duration.
  Incoming connections without active streams are released after 90 seconds of application inactivity.
  Busy receivers queue streams for up to 5 seconds instead of immediately resetting them.
- Local mDNS discovery is enabled by default for finding known peers without external DNS or a relay.
  It advertises the device Endpoint ID and IP addresses, not share credentials or file information.
  Set `SYNCBOX_DISABLE_MDNS=1` to disable it for both `run` and `join`; any value, including an empty
  value, disables it. If mDNS cannot start, synchronization continues with the other discovery services.
- Local address changes and relay reconnections wake peer retries, coalesced to at most once every
  5 seconds without discarding usable connections. Debug logs include connection reuse, selected
  IPv4/IPv6/relay path snapshots, setup time, and RTT.
- On Unix, POSIX permission bits for regular files and subdirectories are synchronized. Ownership,
  ACLs, extended attributes, and the selected shared-root directory's own mode remain local.
- Symbolic links are synchronized as links on Unix and never followed while scanning. Following
  Syncthing's cross-platform policy, Windows does not create or publish symbolic links: remote links
  are retained as unsupported state, reported by `syncbox status`, and do not block unrelated files.

## Upgrades

Protocol version 6 peers do not communicate with earlier protocol versions. Version 6 sends
file chunks as bounded binary frames instead of base64 JSON. Version 5 introduced compact
manifest digests before full manifest exchange. Upgrade every peer in a share as one maintenance operation: stop the services,
install the same version everywhere, then start them again.

## Quick start

Register a directory on the first device:

```text
syncbox init /path/to/shared-directory
```

Give the printed ShareTicket to another trusted device and join it there:

```text
syncbox join 'syncbox1:...' /path/to/shared-directory
syncbox run
```

On the owner device, keep synchronization running with:

```text
syncbox run
```

Useful commands:

```text
syncbox id
syncbox status
syncbox status --json
syncbox scan SHARE_ID
syncbox ticket SHARE_ID
syncbox remove SHARE_ID
```

`syncbox ticket` reprints an existing share credential. A ShareTicket is a bearer credential: anyone who obtains the complete ticket can join that share. Do not put tickets in logs or public issue reports.

`syncbox remove` unregisters the share only on the current device and leaves its local directory and files unchanged. Stop any running Syncbox service first. Removing a share does not revoke existing ShareTickets or affect other devices, and the share can be joined again later with a valid ticket.

## State layout

Syncbox stores state under `/var/lib/syncbox` on Unix and `%LOCALAPPDATA%\syncbox` on Windows, unless `SYNCBOX_DATA_DIR` specifies an absolute path. The global device identity is stored at `identity/device.key`. Share-specific records are stored below `shares/<share_id>/`, and locks are stored below `locks/`. Syncbox does not create `.syncbox` or other state files inside synchronized directories.

## Service installation

Example service templates are included in:

- `packaging/systemd/syncbox.service`
- `packaging/openwrt/syncbox.init`

Set `SYNCBOX_DATA_DIR` to an explicit service-owned data directory when installing a system service.

## Build

Native Linux amd64 build:

```text
cargo build --release
```

Cross builds used for the release:

```text
CROSS_CONTAINER_ENGINE=podman cross build --release --target aarch64-unknown-linux-musl
CROSS_CONTAINER_ENGINE=podman cross build --release --target x86_64-pc-windows-gnu
```

## Current transfer limits

The current protocol streams file contents in binary chunks of up to 1 MiB, each prefixed by a
16-byte big-endian header: file index (u32, in the agreed transfer list), offset (u64), and payload
length (u32). Receivers validate the header before allocating payload storage and verify each
completed file against its SHA-256, including resumed files. There are no per-file or per-exchange
byte limits. Each exchange handles up to 256 files, with additional files left pending, and JSON
control frames are capped at 96 MiB.

## License

Licensed under either of:

- Apache License, Version 2.0
- MIT License

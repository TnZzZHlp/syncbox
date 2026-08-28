# Syncbox

Syncbox is a Rust command-line application for synchronizing multiple independent shared directories over a peer-to-peer Iroh network.

## Features

- One global Iroh device identity per installation.
- Independent `share_id` and `share_secret` for every shared directory.
- Binary, versioned `syncbox1:` ShareTickets with strict validation and checksums.
- Persistent application state in the operating system data directory, never in the shared directory.
- Runtime status with heartbeat, lock, PID, and stale-process detection.
- Direct or relayed QUIC transport through Iroh.
- On Unix, POSIX permission bits for regular files and subdirectories are synchronized. Ownership,
  ACLs, extended attributes, and the selected shared-root directory's own mode remain local.

## Upgrades

Protocol version 5 peers do not communicate with version 4 peers. Version 5 compares compact
manifest digests before sending full manifests; version 4 removed a duplicate manifest from
transfer requests. Upgrade every peer in a share as one maintenance operation: stop the services,
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
```

`syncbox ticket` reprints an existing share credential. A ShareTicket is a bearer credential: anyone who obtains the complete ticket can join that share. Do not put tickets in logs or public issue reports.

## State layout

Syncbox stores state under the platform application-data directory. The global device identity is stored at `identity/device.key`. Share-specific records are stored below `shares/<share_id>/`, and locks are stored below `locks/`. Syncbox does not create `.syncbox` or other state files inside synchronized directories.

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

The current protocol transfers up to 16 MiB per file, 64 MiB per exchange, and 256 files per exchange. Larger files remain pending rather than being falsely reported as synchronized.

## License

Licensed under either of:

- Apache License, Version 2.0
- MIT License

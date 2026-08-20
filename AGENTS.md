# Syncbox

## Overview

Syncbox is a Rust 2024 command-line application for synchronizing multiple independent shared directories between trusted peers over an Iroh QUIC network. It uses one global device identity and keeps share state outside synchronized directories.

## Repository layout

- `src/main.rs`: Clap CLI entry point and command dispatch.
- `src/app.rs`: application workflows for init, join, run, scan, status, and tickets.
- `src/network.rs`: Iroh transport, peer authentication, synchronization, and chunk transfers.
- `src/manifest.rs`: directory scanning, hashes, metadata, versions, and merge logic.
- `src/storage.rs`: platform data paths, locks, validation, and atomic persistent-state writes.
- `src/identity.rs`, `src/ticket.rs`, `src/types.rs`: device identity, ShareTickets, and shared data types.
- `tests/cli.rs`: CLI integration tests; service templates are under `packaging/`.

## Development commands

Run from the repository root:

```text
cargo build --release
cargo test --all-targets
cargo fmt --all -- --check
cargo lint
```

The repository documents release cross-builds with `cross` and Podman in `README.md`; native development uses Cargo.

## Conventions

- Keep orchestration in `App`, CLI formatting and dispatch in `main.rs`, and protocol/file-transfer behavior in `network.rs`.
- Use `cargo fmt`; add focused module unit tests for library behavior and CLI integration tests in `tests/cli.rs` for command behavior. Existing tests use `tempfile` and `assert_cmd`.
- Before marking any Rust task complete, run `cargo lint` and require zero errors and warnings.
- Route durable state through `DataPaths`. Preserve its validation, atomic replacement, locking, and platform permission behavior rather than writing state directly.
- Preserve strict validation for manifests, paths, serialized state, peer messages, and ShareTickets; do not bypass safe path handling or symlink checks.

## Constraints and pitfalls

- `SYNCBOX_DATA_DIR`, when set, must be an absolute path. Shared directories must not overlap the Syncbox data root or another registered share, and Syncbox must not create state inside a shared directory.
- ShareTickets contain bearer credentials. Never put complete tickets, device keys, or share secrets in logs, diagnostics, issue reports, or untrusted channels.
- Wire-protocol changes require all peers in a share to be upgraded together. Keep the implementation's protocol/version constants and `README.md` compatibility notes synchronized.
- On Unix, persistent state is intended to remain private (`700` directories and `600` files). Do not weaken this when changing storage or service configuration.
- The documented sync behavior preserves Unix permission bits for regular files and subdirectories but does not synchronize ownership, ACLs, extended attributes, or the shared root directory's own mode.

# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
cargo build              # Build the library
cargo test               # Run all tests
cargo test <test_name>   # Run a specific test
cargo test --lib         # Run library tests only
cargo clippy             # Run linter
cargo fmt                # Format code
```

## Architecture

rbit is a BitTorrent library implementing BEP (BitTorrent Enhancement Proposals) specifications. It's structured as a Rust library with no binary targets.

### Module Overview

- **bencode** - BEP-3 encoder/decoder for BitTorrent's data serialization format. Uses `Value` enum (Integer, Bytes, List, Dict with BTreeMap).

- **metainfo** - Torrent file parsing, magnet links (BEP-9), and v2 torrent support (BEP-52). `InfoHash` enum handles both v1 (20-byte SHA1) and v2 (32-byte SHA256) hashes.

- **peer** - Peer wire protocol implementation:
  - `PeerConnection` manages TCP connections with handshake, message send/receive
  - `ChokingState` tracks 4-way choke/interest state
  - Supports Fast Extension (BEP-6) and Extension Protocol (BEP-10)
  - Messages are framed with 4-byte length prefix

- **tracker** - HTTP (BEP-3) and UDP (BEP-15) tracker clients with compact peer format (BEP-23)

- **dht** - Kademlia-based DHT (BEP-5):
  - `DhtServer` handles UDP socket, query/response routing, token management
  - `RoutingTable` with k-buckets for node storage
  - `NodeId` is 160-bit identifier with XOR distance metric

- **pex** - Peer Exchange (BEP-11) for sharing peer lists between connected peers

- **lsd** - Local Service Discovery (BEP-14) via UDP multicast on port 6771

- **storage** - Disk I/O with piece/block mapping across files:
  - `TorrentStorage` handles per-torrent file operations with file handle caching
  - `DiskManager` coordinates multiple torrents with semaphore-limited concurrent I/O
  - Validates file paths against directory traversal attacks

- **cache** - Memory caching layer:
  - `PieceCache` / `BlockCache` for downloaded data
  - `BufferPool` for buffer reuse
  - `MemoryBudget` with permit system for memory limits

### Key Patterns

- Async throughout using tokio runtime
- `parking_lot` for sync primitives, `dashmap` for concurrent maps
- `thiserror` for error types in each module
- `tracing` for logging
- `bytes::Bytes` for zero-copy byte handling

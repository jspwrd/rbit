# Implementation Plan: BEP-42, BEP-19, BEP-55

This document outlines the implementation plan for three BitTorrent Enhancement Proposals.

---

## BEP-42: DHT Security Extension

### Overview
BEP-42 prevents Sybil attacks on the DHT by restricting node ID selection based on external IP address. This prevents adversaries from positioning multiple nodes near a target info-hash to intercept traffic.

### Implementation Tasks

#### 1. Add CRC32C Dependency
- Add `crc32c` crate to `Cargo.toml` (hardware-accelerated via SSE 4.2)

#### 2. Create Node ID Generation Module (`src/dht/node_id_security.rs`)

Core functions needed:
- `generate_secure_node_id(ip: IpAddr) -> NodeId`
- `validate_node_id(node_id: &NodeId, ip: IpAddr) -> bool`
- `is_local_network(ip: IpAddr) -> bool`

**IPv4 Formula:**
- Mask IP with `0x030f3fff`, OR with `r << 29` (r is random 0-7)
- Compute CRC32C of masked value as big-endian bytes
- First 21 bits of node_id must match hash, last byte must equal r

**IPv6 Formula:**
- Mask high 64 bits with `0x0103070f1f3f7fff`, OR with `r << 61`
- Same constraints apply

**Local Network Exemptions:**
- `10.0.0.0/8`
- `172.16.0.0/12`
- `192.168.0.0/16`
- `169.254.0.0/16`
- `127.0.0.0/8`
- IPv6 link-local and private ranges

#### 3. Modify DHT Message Handling (`src/dht/message.rs`)

- Add `ip` field to DHT responses (compact binary: IP + 2-byte port)
- Parse incoming `ip` field for external IP discovery

#### 4. Update DhtServer (`src/dht/server.rs`)

- Add `external_ip: RwLock<Option<IpAddr>>` field
- Add `external_ip_votes: RwLock<HashMap<IpAddr, u32>>` for voting
- Modify `bind()` to accept optional external IP or discover it
- Add method `update_external_ip()` that:
  - Collects votes from incoming responses
  - Triggers node ID regeneration when consensus reached
- Add `enforcement_mode: bool` configuration

#### 5. Modify Node Validation in Routing Table (`src/dht/routing.rs`)

- Add validation check in `should_add_node()`
- If enforcement enabled and not local network, validate node ID against IP
- Reject nodes that fail validation

#### 6. Modify get_peers Response Handling

- Non-compliant nodes should not receive valid tokens
- Non-compliant nodes excluded from lookup termination

#### 7. Add Constants (`src/constants.rs`)

- `BEP42_IPV4_MASK: u32 = 0x030f3fff`
- `BEP42_IPV6_MASK: u64 = 0x0103070f1f3f7fff`
- `BEP42_REQUIRED_VOTES: u32 = 3`

#### 8. Unit Tests

- Test node ID generation for various IPs
- Test node ID validation (valid and invalid cases)
- Test local network detection
- Test IP voting mechanism
- Test enforcement mode behavior

---

## BEP-19: WebSeed - HTTP/FTP Seeding

### Overview
BEP-19 allows BitTorrent clients to use HTTP/FTP servers as additional sources for downloading torrent data, enabling hybrid P2P + web downloads.

### Implementation Tasks

#### 1. Parse `url-list` in Metainfo (`src/metainfo/torrent.rs`)

- Add `url_list: Vec<String>` field to `Metainfo`
- Parse from bencode: handle both single URL (Bytes) and list of URLs (List)

#### 2. Create WebSeed Module (`src/webseed.rs` or `src/webseed/mod.rs`)

Create `WebSeedClient` struct with:
- HTTP client instance
- Base URLs list
- Blacklisted URLs set

Methods:
- `new(urls: Vec<String>) -> Self`
- `download_piece(piece_index, ...) -> Result<Bytes, WebSeedError>`
- `blacklist_url(url: &str)`
- `construct_url(base: &str, info: &Info, file_index: usize) -> String`

#### 3. URL Construction Logic

**Single-file torrent:**
- If base URL ends with `/`, append torrent name
- Otherwise use base URL as-is

**Multi-file torrent:**
- Append `{name}/{path/to/file}` to base URL

#### 4. HTTP Range Request Support

- Use `Range: bytes=start-end` header for partial downloads
- Handle `206 Partial Content` response
- Handle `200 OK` for servers that don't support ranges

#### 5. Piece Selection Strategy Modification

BEP-19 modifies "rarest first" to create gaps for HTTP connections:
- Create `GapAwarePieceSelector` struct
- Formula: `X = sqrt(peers) - 1`
- Select pieces that are "pretty rare with biggest gap"
- Priority logic based on rarity threshold and gap distance

#### 6. Gap-Filling Algorithm for HTTP

- When file > 50% complete, randomly use gap-filling selection
- Find piece with smallest gap to completed section

#### 7. Error Handling and Blacklisting

Define `WebSeedError` enum:
- `HttpError` - HTTP status error
- `ConnectionFailed` - Network error
- `HashMismatch` - Failed piece verification (triggers blacklist)
- `TemporarilyBusy` - Server busy, don't blacklist

#### 8. Add Constants

- `WEBSEED_CONNECT_TIMEOUT: Duration` (30 seconds)
- `WEBSEED_READ_TIMEOUT: Duration` (60 seconds)
- `WEBSEED_MAX_RETRIES: u32` (3)
- `WEBSEED_GAP_FILL_THRESHOLD: f64` (0.5)

#### 9. Integration Points

- Extend `MagnetLink` to expose existing `web_seeds` field (already parsed)
- Add `WebSeedClient` to download orchestration layer
- Coordinate between peer downloads and HTTP downloads

#### 10. Unit Tests

- Test URL construction (single-file, multi-file, trailing slash)
- Test range request handling
- Test blacklisting on hash failure
- Test gap-aware piece selection

---

## BEP-55: Holepunch Extension

### Overview
BEP-55 enables NAT traversal by allowing peers to coordinate connection attempts through a relay peer, enabling direct uTP connections between peers behind firewalls.

### Implementation Tasks

#### 1. Define Holepunch Message Types (`src/peer/holepunch.rs`)

Define enums:
- `HolepunchMessageType`: Rendezvous (0x00), Connect (0x01), Error (0x02)
- `HolepunchAddrType`: IPv4 (0x00), IPv6 (0x01)
- `HolepunchError`: NoSuchPeer (0x01), NotConnected (0x02), NoSupport (0x03), NoSelf (0x04)

Define `HolepunchMessage` struct:
- `msg_type`: Message type
- `addr_type`: Address type
- `addr`: IP address
- `port`: Port number
- `err_code`: Error code (0 for non-error)

#### 2. Binary Encoding/Decoding

Implement `encode()` and `decode()` for `HolepunchMessage`:
- 1 byte msg_type
- 1 byte addr_type
- 4 or 16 bytes address (big-endian)
- 2 bytes port (big-endian)
- 4 bytes err_code (big-endian)

#### 3. Register Extension in Handshake (`src/peer/extension.rs`)

- Add `ut_holepunch` to extension handshake map
- Assign extension ID

#### 4. Handle Holepunch Messages in PeerConnection

Add `handle_holepunch()` method that routes to:
- `handle_rendezvous()` for relay requests
- `handle_connect()` for connection initiation
- `handle_holepunch_error()` for error responses

#### 5. Implement Relay Logic

When acting as relay peer on rendezvous:
- Check if target is self (return NoSelf error)
- Look up target peer connection (return NotConnected if not found)
- Check if target supports holepunch (return NoSupport if not)
- Send Connect message to both initiator and target with each other's addresses

#### 6. Implement uTP Connection Initiation

When receiving Connect message:
- Check if already connected (silently ignore if so)
- Initiate uTP connection to target address
- Both peers do this simultaneously for NAT hole-punching

#### 7. Add uTP Support (if not present)

BEP-55 requires uTP (BEP-29) for the actual holepunch connections. Check if uTP is implemented; if not, this becomes a dependency.

Looking at `BEP.txt`, BEP-29 is listed, so uTP may need to be implemented first or concurrently.

#### 8. PeerManager Integration

Extend PeerManager with:
- `holepunch_pending` map to track pending holepunches
- `supports_holepunch()` method
- `request_holepunch()` method

#### 9. Add Constants

- `HOLEPUNCH_TIMEOUT: Duration` (30 seconds)
- `HOLEPUNCH_RETRY_DELAY: Duration` (5 seconds)

#### 10. Unit Tests

- Test message encoding/decoding
- Test rendezvous handling (success and error cases)
- Test connect message handling
- Test error code generation

---

## Implementation Order

### Recommended Sequence

1. **BEP-42 (DHT Security)** - Independent, hardens existing DHT
2. **BEP-19 (WebSeed)** - Independent, adds download source
3. **BEP-55 (Holepunch)** - May depend on uTP (BEP-29)

### Dependencies

- BEP-42: No dependencies (uses existing DHT)
- BEP-19: Requires HTTP client (reqwest)
- BEP-55: Requires BEP-10 (Extension Protocol) - already exists; Requires BEP-29 (uTP) - check status

---

## New Files to Create

| File | Purpose |
|------|---------|
| `src/dht/node_id_security.rs` | BEP-42 node ID generation/validation |
| `src/webseed.rs` or `src/webseed/mod.rs` | BEP-19 HTTP/FTP seeding |
| `src/peer/holepunch.rs` | BEP-55 holepunch messages |

## Files to Modify

| File | Changes |
|------|---------|
| `Cargo.toml` | Add `crc32c`, possibly `reqwest` |
| `src/dht/mod.rs` | Export new module |
| `src/dht/server.rs` | External IP tracking, enforcement |
| `src/dht/message.rs` | Add `ip` field to responses |
| `src/dht/routing.rs` | Node validation |
| `src/metainfo/torrent.rs` | Parse `url-list` |
| `src/peer/mod.rs` | Export holepunch module |
| `src/peer/extension.rs` | Register `ut_holepunch` |
| `src/peer/connection.rs` | Handle holepunch messages |
| `src/constants.rs` | Add new constants |
| `src/lib.rs` | Export webseed module |

---

## Testing Strategy

### Unit Tests
- Each BEP gets dedicated test module
- Test edge cases (local networks, malformed messages)
- Test encoding/decoding round-trips

### Integration Tests
- BEP-42: Test with mock DHT network
- BEP-19: Test with local HTTP server
- BEP-55: Test relay scenario between three peers

### Compatibility Tests
- Test against known-good implementations
- Verify interoperability with popular clients

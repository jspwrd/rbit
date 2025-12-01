//! rbit - A BitTorrent library
//!
//! This library provides a complete implementation of the BitTorrent protocol
//! following BEP (BitTorrent Enhancement Proposals) specifications.
//!
//! # Modules
//!
//! - [`bencode`] - BEP-3 Bencode encoding/decoding
//! - [`metainfo`] - BEP-3/9/52 Torrent metainfo, magnet links, v2 torrents
//! - [`peer`] - BEP-3/6/10 Peer wire protocol, fast extension, extension protocol
//! - [`tracker`] - BEP-3/15/23 HTTP and UDP tracker protocols
//! - [`dht`] - BEP-5 Distributed Hash Table
//! - [`pex`] - BEP-11 Peer Exchange
//! - [`lsd`] - BEP-14 Local Service Discovery
//! - [`storage`] - Disk I/O and file management
//! - [`cache`] - Memory caching for pieces and blocks

pub mod bencode;
pub mod cache;
pub mod dht;
pub mod lsd;
pub mod metainfo;
pub mod peer;
pub mod pex;
pub mod storage;
pub mod tracker;

pub use bencode::{decode, encode, BencodeError, Value};
pub use cache::{BlockCache, BufferPool, MemoryBudget, PieceCache};
pub use dht::{DhtError, DhtMessage, DhtServer, Node, NodeId, RoutingTable};
pub use lsd::{LsdAnnounce, LsdError, LsdService};
pub use metainfo::{File, Info, InfoHash, MagnetLink, Metainfo, MetainfoError};
pub use peer::{
    Bitfield, Block, BlockRequest, ChokingAlgorithm, ExtensionHandshake, Handshake, Message,
    PeerConnection, PeerError, PeerId, PeerState,
};
pub use pex::{PexFlags, PexMessage, PexPeer};
pub use storage::{AllocationMode, DiskManager, FileEntry, PieceInfo, StorageError, TorrentStorage};
pub use tracker::{
    AnnounceResponse, CompactPeer, HttpTracker, ScrapeResponse, TrackerError, TrackerEvent,
    UdpTracker,
};

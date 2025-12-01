//! Torrent metainfo handling (BEP-3, BEP-9, BEP-52)
//!
//! This module handles torrent file parsing, magnet links, and info hashes
//! for both v1 and v2 torrents.

mod error;
mod info_hash;
mod magnet;
mod merkle;
mod torrent;

pub use error::MetainfoError;
pub use info_hash::InfoHash;
pub use magnet::MagnetLink;
pub use merkle::MerkleTree;
pub use torrent::{File, Info, Metainfo};

#[cfg(test)]
mod tests;

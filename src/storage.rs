//! Disk storage and I/O management
//!
//! This module handles reading and writing torrent data to disk,
//! piece verification, and file allocation.

mod error;
mod file;
mod manager;

pub use error::StorageError;
pub use file::{AllocationMode, FileEntry, PieceInfo};
pub use manager::{DiskManager, TorrentStorage};

#[cfg(test)]
mod tests;

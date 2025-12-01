//! Peer wire protocol (BEP-3, BEP-6, BEP-10)
//!
//! This module implements the BitTorrent peer wire protocol including
//! the base protocol, fast extension, and extension protocol.

mod bitfield;
mod choking;
mod connection;
mod error;
mod extension;
mod fast;
mod message;
mod peer_id;
mod piece;
mod transport;

pub use bitfield::Bitfield;
pub use choking::{ChokingAlgorithm, ChokingState, PeerStats};
pub use connection::{PeerConnection, PeerState};
pub use error::PeerError;
pub use extension::{ExtensionHandshake, ExtensionMessage};
pub use fast::FastExtension;
pub use message::{Handshake, Message, MessageId};
pub use peer_id::PeerId;
pub use piece::{Block, BlockRequest};
pub use transport::PeerTransport;

#[cfg(test)]
mod tests;

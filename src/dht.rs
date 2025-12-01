//! Distributed Hash Table (BEP-5)
//!
//! This module implements the Kademlia-based DHT used by BitTorrent
//! for trackerless peer discovery.

mod error;
mod message;
mod node;
mod routing;
mod server;

pub use error::DhtError;
pub use message::{DhtMessage, DhtQuery, DhtResponse, TransactionId};
pub use node::{Node, NodeId};
pub use routing::RoutingTable;
pub use server::DhtServer;

#[cfg(test)]
mod tests;

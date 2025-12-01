//! Tracker protocols ([BEP-3], [BEP-15], [BEP-23]).
//!
//! Trackers are servers that help peers find each other. This module implements
//! both HTTP and UDP tracker protocols.
//!
//! # Overview
//!
//! When downloading a torrent, clients "announce" to trackers to:
//! 1. Register themselves in the swarm
//! 2. Get a list of other peers to connect to
//! 3. Report download/upload statistics
//!
//! # HTTP Trackers
//!
//! HTTP trackers use simple GET requests with query parameters. The response
//! is a bencoded dictionary containing peer information.
//!
//! ```no_run
//! use rbit::tracker::{HttpTracker, TrackerEvent};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let tracker = HttpTracker::new("http://tracker.example.com/announce")?;
//!
//! let response = tracker.announce(
//!     &[0u8; 20],           // info_hash
//!     &[0u8; 20],           // peer_id
//!     6881,                 // port
//!     0,                    // uploaded
//!     0,                    // downloaded
//!     1000000,              // left (bytes remaining)
//!     TrackerEvent::Started,
//! ).await?;
//!
//! println!("Interval: {} seconds", response.interval);
//! println!("Seeders: {:?}", response.complete);
//! println!("Leechers: {:?}", response.incomplete);
//!
//! for peer in response.peers {
//!     println!("Peer: {}", peer);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # UDP Trackers
//!
//! UDP trackers ([BEP-15]) are more efficient than HTTP, using a connection-based
//! protocol with binary messages.
//!
//! ```no_run
//! use rbit::tracker::{UdpTracker, TrackerEvent};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut tracker = UdpTracker::connect("udp://tracker.example.com:6969").await?;
//!
//! let response = tracker.announce(
//!     &[0u8; 20],           // info_hash
//!     &[0u8; 20],           // peer_id
//!     0,                    // downloaded
//!     1000000,              // left
//!     0,                    // uploaded
//!     TrackerEvent::Started,
//!     6881,                 // port
//! ).await?;
//!
//! for peer in response.peers {
//!     println!("Peer: {}", peer);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Tracker Events
//!
//! Clients send different events during the torrent lifecycle:
//!
//! - **Started** - First announce when beginning the download
//! - **Completed** - Sent when download finishes (becomes a seeder)
//! - **Stopped** - Sent when removing the torrent
//! - **None** - Regular periodic announcement
//!
//! # Compact Peer Format
//!
//! [BEP-23] defines a compact format for peer lists that's more efficient than
//! the dictionary format. IPv4 peers are 6 bytes (4 IP + 2 port), IPv6 peers
//! are 18 bytes (16 IP + 2 port).
//!
//! [BEP-3]: http://bittorrent.org/beps/bep_0003.html
//! [BEP-15]: http://bittorrent.org/beps/bep_0015.html
//! [BEP-23]: http://bittorrent.org/beps/bep_0023.html

mod error;
mod http;
mod response;
mod udp;

pub use error::TrackerError;
pub use http::HttpTracker;
pub use response::{AnnounceResponse, CompactPeer, ScrapeResponse, TrackerEvent};
pub use udp::UdpTracker;

#[cfg(test)]
mod tests;

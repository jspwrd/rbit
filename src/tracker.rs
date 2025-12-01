//! Tracker protocol (BEP-3, BEP-15, BEP-23)
//!
//! This module implements HTTP and UDP tracker protocols for peer discovery.

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

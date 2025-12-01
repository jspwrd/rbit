//! Bencode encoding and decoding (BEP-3)
//!
//! Bencode is the encoding used by BitTorrent for storing and transmitting
//! loosely structured data.

mod decode;
mod encode;
mod error;
mod value;

pub use decode::decode;
pub use encode::encode;
pub use error::BencodeError;
pub use value::Value;

#[cfg(test)]
mod tests;

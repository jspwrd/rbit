use thiserror::Error;

#[derive(Debug, Error)]
pub enum PeerError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid handshake")]
    InvalidHandshake,

    #[error("info hash mismatch")]
    InfoHashMismatch,

    #[error("invalid message: {0}")]
    InvalidMessage(String),

    #[error("invalid message id: {0}")]
    InvalidMessageId(u8),

    #[error("connection closed")]
    ConnectionClosed,

    #[error("timeout")]
    Timeout,

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("extension error: {0}")]
    Extension(String),

    #[error("bencode error: {0}")]
    Bencode(#[from] crate::bencode::BencodeError),
}

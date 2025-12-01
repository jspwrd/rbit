use crate::bencode::BencodeError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MetainfoError {
    #[error("bencode error: {0}")]
    Bencode(#[from] BencodeError),

    #[error("missing field: {0}")]
    MissingField(&'static str),

    #[error("invalid field: {0}")]
    InvalidField(&'static str),

    #[error("invalid info hash length")]
    InvalidInfoHashLength,

    #[error("invalid magnet link: {0}")]
    InvalidMagnetLink(String),

    #[error("unsupported torrent version")]
    UnsupportedVersion,

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

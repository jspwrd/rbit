use thiserror::Error;

#[derive(Debug, Error)]
pub enum BencodeError {
    #[error("unexpected end of input")]
    UnexpectedEof,

    #[error("invalid integer: {0}")]
    InvalidInteger(String),

    #[error("invalid string length")]
    InvalidStringLength,

    #[error("unexpected character: {0}")]
    UnexpectedChar(char),

    #[error("trailing data after value")]
    TrailingData,

    #[error("nesting too deep")]
    NestingTooDeep,

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

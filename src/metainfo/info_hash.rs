use super::error::MetainfoError;
use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum InfoHash {
    V1([u8; 20]),
    V2([u8; 32]),
}

impl InfoHash {
    pub fn from_v1_bytes(bytes: &[u8]) -> Result<Self, MetainfoError> {
        if bytes.len() != 20 {
            return Err(MetainfoError::InvalidInfoHashLength);
        }
        let mut arr = [0u8; 20];
        arr.copy_from_slice(bytes);
        Ok(InfoHash::V1(arr))
    }

    pub fn from_v2_bytes(bytes: &[u8]) -> Result<Self, MetainfoError> {
        if bytes.len() != 32 {
            return Err(MetainfoError::InvalidInfoHashLength);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(InfoHash::V2(arr))
    }

    pub fn from_hex(s: &str) -> Result<Self, MetainfoError> {
        let bytes = hex_decode(s).ok_or(MetainfoError::InvalidInfoHashLength)?;
        match bytes.len() {
            20 => Self::from_v1_bytes(&bytes),
            32 => Self::from_v2_bytes(&bytes),
            _ => Err(MetainfoError::InvalidInfoHashLength),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            InfoHash::V1(arr) => arr,
            InfoHash::V2(arr) => arr,
        }
    }

    pub fn is_v1(&self) -> bool {
        matches!(self, InfoHash::V1(_))
    }

    pub fn is_v2(&self) -> bool {
        matches!(self, InfoHash::V2(_))
    }

    pub fn to_hex(&self) -> String {
        hex_encode(self.as_bytes())
    }
}

impl fmt::Debug for InfoHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "InfoHash({})", self.to_hex())
    }
}

impl fmt::Display for InfoHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
        s
    })
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

use rand::Rng as _;
use std::fmt;

const PEER_ID_PREFIX: &[u8] = b"-RB0001-";

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerId(pub [u8; 20]);

impl PeerId {
    pub fn generate() -> Self {
        let mut id = [0u8; 20];
        id[..8].copy_from_slice(PEER_ID_PREFIX);
        rand::rng().fill(&mut id[8..]);
        Self(id)
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 20 {
            return None;
        }
        let mut id = [0u8; 20];
        id.copy_from_slice(bytes);
        Some(Self(id))
    }

    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    pub fn client_id(&self) -> Option<&str> {
        if self.0[0] == b'-' && self.0[7] == b'-' {
            std::str::from_utf8(&self.0[1..7]).ok()
        } else {
            None
        }
    }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(client) = self.client_id() {
            write!(f, "PeerId({})", client)
        } else {
            write!(f, "PeerId({:02x?})", &self.0[..8])
        }
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            if byte.is_ascii_alphanumeric() || *byte == b'-' {
                write!(f, "{}", *byte as char)?;
            } else {
                write!(f, "%{:02x}", byte)?;
            }
        }
        Ok(())
    }
}

use super::error::MetainfoError;
use std::fmt;

/// A BitTorrent info hash identifying a torrent.
///
/// The info hash is a cryptographic hash of the torrent's `info` dictionary,
/// used to uniquely identify a torrent across the BitTorrent network.
///
/// # Versions
///
/// - **V1**: 20-byte SHA1 hash (original BitTorrent, [BEP-3])
/// - **V2**: 32-byte SHA256 hash (BitTorrent v2, [BEP-52])
///
/// # Examples
///
/// ```
/// use rbit::metainfo::InfoHash;
///
/// // Parse from a hex string (automatically detects version)
/// let v1_hash = InfoHash::from_hex("c12fe1c06bba254a9dc9f519b335aa7c1367a88a").unwrap();
/// assert!(v1_hash.is_v1());
/// assert_eq!(v1_hash.as_bytes().len(), 20);
///
/// // Create from raw bytes
/// let bytes = [0u8; 20];
/// let hash = InfoHash::from_v1_bytes(&bytes).unwrap();
///
/// // Display as hex
/// println!("{}", hash);  // prints 40-character hex string
/// ```
///
/// [BEP-3]: http://bittorrent.org/beps/bep_0003.html
/// [BEP-52]: http://bittorrent.org/beps/bep_0052.html
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum InfoHash {
    /// BitTorrent v1 info hash (20-byte SHA1).
    V1([u8; 20]),
    /// BitTorrent v2 info hash (32-byte SHA256).
    V2([u8; 32]),
}

impl InfoHash {
    /// Creates a v1 info hash from a 20-byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`MetainfoError::InvalidInfoHashLength`] if the slice is not exactly 20 bytes.
    pub fn from_v1_bytes(bytes: &[u8]) -> Result<Self, MetainfoError> {
        if bytes.len() != 20 {
            return Err(MetainfoError::InvalidInfoHashLength);
        }
        let mut arr = [0u8; 20];
        arr.copy_from_slice(bytes);
        Ok(InfoHash::V1(arr))
    }

    /// Creates a v2 info hash from a 32-byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`MetainfoError::InvalidInfoHashLength`] if the slice is not exactly 32 bytes.
    pub fn from_v2_bytes(bytes: &[u8]) -> Result<Self, MetainfoError> {
        if bytes.len() != 32 {
            return Err(MetainfoError::InvalidInfoHashLength);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(InfoHash::V2(arr))
    }

    /// Parses an info hash from a hexadecimal string.
    ///
    /// The version is determined by the string length:
    /// - 40 characters → v1 (20 bytes)
    /// - 64 characters → v2 (32 bytes)
    ///
    /// # Errors
    ///
    /// Returns [`MetainfoError::InvalidInfoHashLength`] if the string length
    /// is invalid or contains non-hex characters.
    ///
    /// # Examples
    ///
    /// ```
    /// use rbit::metainfo::InfoHash;
    ///
    /// let hash = InfoHash::from_hex("c12fe1c06bba254a9dc9f519b335aa7c1367a88a").unwrap();
    /// assert!(hash.is_v1());
    /// ```
    pub fn from_hex(s: &str) -> Result<Self, MetainfoError> {
        let bytes = hex_decode(s).ok_or(MetainfoError::InvalidInfoHashLength)?;
        match bytes.len() {
            20 => Self::from_v1_bytes(&bytes),
            32 => Self::from_v2_bytes(&bytes),
            _ => Err(MetainfoError::InvalidInfoHashLength),
        }
    }

    /// Returns the raw bytes of the info hash.
    ///
    /// Returns 20 bytes for v1 or 32 bytes for v2.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            InfoHash::V1(arr) => arr,
            InfoHash::V2(arr) => arr,
        }
    }

    /// Returns `true` if this is a v1 (SHA1) info hash.
    pub fn is_v1(&self) -> bool {
        matches!(self, InfoHash::V1(_))
    }

    /// Returns `true` if this is a v2 (SHA256) info hash.
    pub fn is_v2(&self) -> bool {
        matches!(self, InfoHash::V2(_))
    }

    /// Converts the info hash to a lowercase hexadecimal string.
    ///
    /// # Examples
    ///
    /// ```
    /// use rbit::metainfo::InfoHash;
    ///
    /// let hash = InfoHash::from_v1_bytes(&[0xab; 20]).unwrap();
    /// assert_eq!(hash.to_hex(), "abababababababababababababababababababab");
    /// ```
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

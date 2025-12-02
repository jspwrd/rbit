use super::error::MetainfoError;
use super::info_hash::{InfoHash, InfoHashV1, InfoHashV2};
use crate::bencode::{decode, encode, Value};
use bytes::Bytes;
use sha1::{Digest, Sha1};
use sha2::Sha256;
use std::path::PathBuf;

/// The version of a torrent file.
///
/// BitTorrent has evolved through multiple versions:
/// - **V1**: Original BitTorrent protocol (BEP-3)
/// - **V2**: BitTorrent v2 with improved piece hashing (BEP-52)
/// - **Hybrid**: Supports both v1 and v2 clients (BEP-47)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TorrentVersion {
    /// BitTorrent v1 (BEP-3) - SHA1 piece hashes.
    V1,
    /// BitTorrent v2 (BEP-52) - SHA256 piece hashes with merkle trees.
    V2,
    /// Hybrid torrent (BEP-47) - Compatible with both v1 and v2 clients.
    Hybrid,
}

impl TorrentVersion {
    /// Returns true if this version supports v1 clients.
    pub fn supports_v1(&self) -> bool {
        matches!(self, TorrentVersion::V1 | TorrentVersion::Hybrid)
    }

    /// Returns true if this version supports v2 clients.
    pub fn supports_v2(&self) -> bool {
        matches!(self, TorrentVersion::V2 | TorrentVersion::Hybrid)
    }
}

/// A parsed torrent file.
///
/// Contains all metadata from a `.torrent` file, including file information,
/// piece hashes, and tracker URLs.
///
/// # Examples
///
/// ```no_run
/// use rbit::metainfo::Metainfo;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let data = std::fs::read("example.torrent")?;
/// let metainfo = Metainfo::from_bytes(&data)?;
///
/// println!("Torrent: {}", metainfo.info.name);
/// println!("Size: {} bytes", metainfo.info.total_length);
/// println!("Info hash: {}", metainfo.info_hash);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct Metainfo {
    /// The info dictionary containing file and piece information.
    pub info: Info,
    /// The unique identifier for this torrent (hash of the info dictionary).
    pub info_hash: InfoHash,
    /// Primary tracker URL.
    pub announce: Option<String>,
    /// Multi-tier tracker list ([BEP-12](http://bittorrent.org/beps/bep_0012.html)).
    pub announce_list: Vec<Vec<String>>,
    /// Unix timestamp when the torrent was created.
    pub creation_date: Option<i64>,
    /// Optional comment about the torrent.
    pub comment: Option<String>,
    /// Name/version of the program that created the torrent.
    pub created_by: Option<String>,
    /// The torrent version (V1, V2, or Hybrid).
    pub version: TorrentVersion,
    raw_info: Bytes,
}

/// The info dictionary from a torrent file.
///
/// Contains the core metadata that identifies the torrent content.
/// The SHA1 hash of this dictionary (in bencode format) is the info hash.
#[derive(Debug, Clone)]
pub struct Info {
    /// Suggested name for the file or directory.
    pub name: String,
    /// Number of bytes per piece.
    pub piece_length: u64,
    /// SHA1 hash of each piece (20 bytes each).
    pub pieces: Vec<[u8; 20]>,
    /// List of files in the torrent.
    pub files: Vec<File>,
    /// Total size of all files combined.
    pub total_length: u64,
    /// If true, clients should only use trackers in the metainfo (no DHT/PEX).
    pub private: bool,
}

/// A file within a torrent.
///
/// For single-file torrents, there is one file with the torrent name.
/// For multi-file torrents, paths are relative to the torrent's root directory.
#[derive(Debug, Clone)]
pub struct File {
    /// Path to the file (relative to torrent root).
    pub path: PathBuf,
    /// Size of the file in bytes.
    pub length: u64,
    /// Byte offset within the torrent's piece data.
    pub offset: u64,
}

impl Metainfo {
    /// Parses a torrent file from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The data is not valid bencode
    /// - Required fields are missing (info, name, pieces, etc.)
    /// - The pieces field length is not a multiple of 20
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rbit::metainfo::Metainfo;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let data = std::fs::read("example.torrent")?;
    /// let metainfo = Metainfo::from_bytes(&data)?;
    /// println!("Name: {}", metainfo.info.name);
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_bytes(data: &[u8]) -> Result<Self, MetainfoError> {
        let value = decode(data)?;
        let dict = value.as_dict().ok_or(MetainfoError::InvalidField("root"))?;

        let info_value = dict
            .get(b"info".as_slice())
            .ok_or(MetainfoError::MissingField("info"))?;

        let info_dict = info_value
            .as_dict()
            .ok_or(MetainfoError::InvalidField("info"))?;

        let raw_info = Bytes::from(encode(info_value)?);

        // Detect version based on presence of v1/v2 specific fields
        let has_pieces = info_dict.get(b"pieces".as_slice()).is_some();
        let has_file_tree = info_dict.get(b"file tree".as_slice()).is_some();
        let meta_version = info_dict
            .get(b"meta version".as_slice())
            .and_then(|v| v.as_integer());

        let version = match (has_pieces, has_file_tree, meta_version) {
            (true, true, _) => TorrentVersion::Hybrid,
            (false, true, Some(2)) => TorrentVersion::V2,
            (true, false, _) => TorrentVersion::V1,
            _ => TorrentVersion::V1, // Default to V1 for backwards compatibility
        };

        let info_hash = match version {
            TorrentVersion::V1 => compute_info_hash(&raw_info),
            TorrentVersion::V2 => compute_v2_info_hash(&raw_info),
            TorrentVersion::Hybrid => {
                let v1 = InfoHashV1::from_info_bytes(&raw_info);
                let v2 = InfoHashV2::from_info_bytes(&raw_info);
                InfoHash::hybrid(v1, v2)
            }
        };

        let info = parse_info(info_value)?;

        let announce = dict
            .get(b"announce".as_slice())
            .and_then(|v| v.as_str())
            .map(String::from);

        let announce_list = dict
            .get(b"announce-list".as_slice())
            .and_then(|v| v.as_list())
            .map(|list| {
                list.iter()
                    .filter_map(|tier| {
                        tier.as_list().map(|urls| {
                            urls.iter()
                                .filter_map(|u| u.as_str().map(String::from))
                                .collect()
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        let creation_date = dict
            .get(b"creation date".as_slice())
            .and_then(|v| v.as_integer());

        let comment = dict
            .get(b"comment".as_slice())
            .and_then(|v| v.as_str())
            .map(String::from);

        let created_by = dict
            .get(b"created by".as_slice())
            .and_then(|v| v.as_str())
            .map(String::from);

        Ok(Self {
            info,
            info_hash,
            announce,
            announce_list,
            creation_date,
            comment,
            created_by,
            version,
            raw_info,
        })
    }

    /// Returns the raw bencoded info dictionary.
    ///
    /// This is useful for computing the info hash or for extension protocols
    /// that need to share the raw info dictionary.
    pub fn raw_info(&self) -> &Bytes {
        &self.raw_info
    }

    /// Returns all tracker URLs from both `announce` and `announce-list`.
    ///
    /// The primary tracker (from `announce`) comes first, followed by
    /// trackers from `announce-list`. Duplicates are removed.
    pub fn trackers(&self) -> Vec<String> {
        let mut trackers = Vec::new();

        if let Some(ref announce) = self.announce {
            trackers.push(announce.clone());
        }

        for tier in &self.announce_list {
            for tracker in tier {
                if !trackers.contains(tracker) {
                    trackers.push(tracker.clone());
                }
            }
        }

        trackers
    }

    /// Returns `true` if this is a BitTorrent v2 torrent.
    pub fn is_v2(&self) -> bool {
        matches!(self.version, TorrentVersion::V2)
    }

    /// Returns `true` if this is a hybrid torrent (BEP-47).
    pub fn is_hybrid(&self) -> bool {
        matches!(self.version, TorrentVersion::Hybrid)
    }
}

fn parse_info(value: &Value) -> Result<Info, MetainfoError> {
    let dict = value.as_dict().ok_or(MetainfoError::InvalidField("info"))?;

    let name = dict
        .get(b"name".as_slice())
        .and_then(|v| v.as_str())
        .ok_or(MetainfoError::MissingField("name"))?
        .to_string();

    let piece_length = dict
        .get(b"piece length".as_slice())
        .and_then(|v| v.as_integer())
        .ok_or(MetainfoError::MissingField("piece length"))? as u64;

    let pieces_bytes = dict
        .get(b"pieces".as_slice())
        .and_then(|v| v.as_bytes())
        .ok_or(MetainfoError::MissingField("pieces"))?;

    if pieces_bytes.len() % 20 != 0 {
        return Err(MetainfoError::InvalidField("pieces"));
    }

    let pieces: Vec<[u8; 20]> = pieces_bytes
        .chunks_exact(20)
        .map(|chunk| {
            let mut arr = [0u8; 20];
            arr.copy_from_slice(chunk);
            arr
        })
        .collect();

    let private = dict
        .get(b"private".as_slice())
        .and_then(|v| v.as_integer())
        .map(|v| v == 1)
        .unwrap_or(false);

    let (files, total_length) = if let Some(length) =
        dict.get(b"length".as_slice()).and_then(|v| v.as_integer())
    {
        let length = length as u64;
        let file = File {
            path: PathBuf::from(&name),
            length,
            offset: 0,
        };
        (vec![file], length)
    } else if let Some(files_list) = dict.get(b"files".as_slice()).and_then(|v| v.as_list()) {
        let mut files = Vec::new();
        let mut offset = 0u64;

        for file_value in files_list {
            let file_dict = file_value
                .as_dict()
                .ok_or(MetainfoError::InvalidField("files"))?;

            let length = file_dict
                .get(b"length".as_slice())
                .and_then(|v| v.as_integer())
                .ok_or(MetainfoError::MissingField("file length"))? as u64;

            let path_list = file_dict
                .get(b"path".as_slice())
                .and_then(|v| v.as_list())
                .ok_or(MetainfoError::MissingField("file path"))?;

            let path: PathBuf = std::iter::once(name.clone())
                .chain(
                    path_list
                        .iter()
                        .filter_map(|p| p.as_str().map(String::from)),
                )
                .collect();

            files.push(File {
                path,
                length,
                offset,
            });

            offset += length;
        }

        let total = offset;
        (files, total)
    } else {
        return Err(MetainfoError::MissingField("length or files"));
    };

    Ok(Info {
        name,
        piece_length,
        pieces,
        files,
        total_length,
        private,
    })
}

fn compute_info_hash(raw_info: &[u8]) -> InfoHash {
    let mut hasher = Sha1::new();
    hasher.update(raw_info);
    let hash: [u8; 20] = hasher.finalize().into();
    InfoHash::V1(hash)
}

fn compute_v2_info_hash(raw_info: &[u8]) -> InfoHash {
    let mut hasher = Sha256::new();
    hasher.update(raw_info);
    let hash: [u8; 32] = hasher.finalize().into();
    InfoHash::V2(hash)
}

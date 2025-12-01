use super::error::MetainfoError;
use super::info_hash::InfoHash;
use crate::bencode::{decode, encode, Value};
use bytes::Bytes;
use sha1::{Digest, Sha1};
use sha2::Sha256;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Metainfo {
    pub info: Info,
    pub info_hash: InfoHash,
    pub announce: Option<String>,
    pub announce_list: Vec<Vec<String>>,
    pub creation_date: Option<i64>,
    pub comment: Option<String>,
    pub created_by: Option<String>,
    raw_info: Bytes,
}

#[derive(Debug, Clone)]
pub struct Info {
    pub name: String,
    pub piece_length: u64,
    pub pieces: Vec<[u8; 20]>,
    pub files: Vec<File>,
    pub total_length: u64,
    pub private: bool,
}

#[derive(Debug, Clone)]
pub struct File {
    pub path: PathBuf,
    pub length: u64,
    pub offset: u64,
}

impl Metainfo {
    pub fn from_bytes(data: &[u8]) -> Result<Self, MetainfoError> {
        let value = decode(data)?;
        let dict = value
            .as_dict()
            .ok_or(MetainfoError::InvalidField("root"))?;

        let info_value = dict
            .get(b"info".as_slice())
            .ok_or(MetainfoError::MissingField("info"))?;

        let raw_info = Bytes::from(encode(info_value)?);
        let info_hash = compute_info_hash(&raw_info);

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
            raw_info,
        })
    }

    pub fn raw_info(&self) -> &Bytes {
        &self.raw_info
    }

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

    pub fn is_v2(&self) -> bool {
        self.info_hash.is_v2()
    }
}

fn parse_info(value: &Value) -> Result<Info, MetainfoError> {
    let dict = value
        .as_dict()
        .ok_or(MetainfoError::InvalidField("info"))?;

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

    let (files, total_length) = if let Some(length) = dict
        .get(b"length".as_slice())
        .and_then(|v| v.as_integer())
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

pub fn compute_v2_info_hash(raw_info: &[u8]) -> InfoHash {
    let mut hasher = Sha256::new();
    hasher.update(raw_info);
    let hash: [u8; 32] = hasher.finalize().into();
    InfoHash::V2(hash)
}

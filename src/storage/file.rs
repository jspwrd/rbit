use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AllocationMode {
    #[default]
    Sparse,
    Full,
}

#[derive(Debug, Clone)]
pub struct FileEntry {
    pub path: PathBuf,
    pub length: u64,
    pub offset: u64,
    /// The merkle root hash for this file (v2 torrents only).
    pub pieces_root: Option<[u8; 32]>,
    /// Whether this is a padding file (v2/hybrid torrents).
    pub is_padding: bool,
}

#[derive(Debug, Clone)]
pub struct PieceInfo {
    pub index: u32,
    pub hash: Vec<u8>,
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug)]
pub struct PieceFileSpan {
    pub file_index: usize,
    pub file_offset: u64,
    pub length: u64,
}

impl FileEntry {
    /// Creates a new file entry (v1 style, no merkle root).
    pub fn new(path: PathBuf, length: u64, offset: u64) -> Self {
        Self {
            path,
            length,
            offset,
            pieces_root: None,
            is_padding: false,
        }
    }

    /// Creates a new v2 file entry with merkle root.
    pub fn new_v2(
        path: PathBuf,
        length: u64,
        offset: u64,
        pieces_root: Option<[u8; 32]>,
        is_padding: bool,
    ) -> Self {
        Self {
            path,
            length,
            offset,
            pieces_root,
            is_padding,
        }
    }

    pub fn byte_range(&self) -> std::ops::Range<u64> {
        self.offset..self.offset + self.length
    }

    pub fn contains_offset(&self, offset: u64) -> bool {
        offset >= self.offset && offset < self.offset + self.length
    }
}

impl PieceInfo {
    pub fn v1(index: u32, hash: [u8; 20], offset: u64, length: u64) -> Self {
        Self {
            index,
            hash: hash.to_vec(),
            offset,
            length,
        }
    }

    pub fn v2(index: u32, hash: [u8; 32], offset: u64, length: u64) -> Self {
        Self {
            index,
            hash: hash.to_vec(),
            offset,
            length,
        }
    }

    pub fn byte_range(&self) -> std::ops::Range<u64> {
        self.offset..self.offset + self.length
    }

    /// Returns the hash as a 20-byte array (v1).
    pub fn hash_v1(&self) -> Option<[u8; 20]> {
        if self.hash.len() == 20 {
            let mut arr = [0u8; 20];
            arr.copy_from_slice(&self.hash);
            Some(arr)
        } else {
            None
        }
    }

    /// Returns the hash as a 32-byte array (v2).
    pub fn hash_v2(&self) -> Option<[u8; 32]> {
        if self.hash.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&self.hash);
            Some(arr)
        } else {
            None
        }
    }

    /// Returns true if this is a v2 piece (32-byte hash).
    pub fn is_v2(&self) -> bool {
        self.hash.len() == 32
    }
}

/// Mapping of v2 pieces to files.
///
/// In v2 torrents, each file has its own piece numbering starting from 0.
/// This struct helps map between global piece indices and file-local indices.
#[derive(Debug, Clone)]
pub struct V2PieceMap {
    /// For each file: (file_index, first_global_piece_index, piece_count)
    file_piece_ranges: Vec<(usize, u32, u32)>,
    /// Total number of pieces across all files
    total_pieces: u32,
    /// Piece length in bytes
    piece_length: u64,
}

impl V2PieceMap {
    /// Creates a new v2 piece map from file entries.
    pub fn new(files: &[FileEntry], piece_length: u64) -> Self {
        let mut file_piece_ranges = Vec::new();
        let mut global_piece_index = 0u32;

        for (file_idx, file) in files.iter().enumerate() {
            // Skip padding files - they don't have pieces
            if file.is_padding || file.length == 0 {
                continue;
            }

            let piece_count = file.length.div_ceil(piece_length) as u32;
            file_piece_ranges.push((file_idx, global_piece_index, piece_count));
            global_piece_index += piece_count;
        }

        Self {
            file_piece_ranges,
            total_pieces: global_piece_index,
            piece_length,
        }
    }

    /// Returns the total number of pieces.
    pub fn total_pieces(&self) -> u32 {
        self.total_pieces
    }

    /// Maps a global piece index to (file_index, file_local_piece_index).
    pub fn global_to_file(&self, global_index: u32) -> Option<(usize, u32)> {
        for &(file_idx, first_global, piece_count) in &self.file_piece_ranges {
            if global_index >= first_global && global_index < first_global + piece_count {
                return Some((file_idx, global_index - first_global));
            }
        }
        None
    }

    /// Maps a file index and file-local piece index to a global piece index.
    pub fn file_to_global(&self, file_index: usize, local_index: u32) -> Option<u32> {
        for &(file_idx, first_global, piece_count) in &self.file_piece_ranges {
            if file_idx == file_index && local_index < piece_count {
                return Some(first_global + local_index);
            }
        }
        None
    }

    /// Returns the piece length.
    pub fn piece_length(&self) -> u64 {
        self.piece_length
    }

    /// Returns the file index and piece count for each file with pieces.
    pub fn file_ranges(&self) -> &[(usize, u32, u32)] {
        &self.file_piece_ranges
    }
}

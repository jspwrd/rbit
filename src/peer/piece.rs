use bytes::Bytes;

#[allow(dead_code)]
pub const BLOCK_SIZE: u32 = 16384;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BlockRequest {
    pub piece: u32,
    pub offset: u32,
    pub length: u32,
}

impl BlockRequest {
    pub fn new(piece: u32, offset: u32, length: u32) -> Self {
        Self {
            piece,
            offset,
            length,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Block {
    pub piece: u32,
    pub offset: u32,
    pub data: Bytes,
}

impl Block {
    pub fn new(piece: u32, offset: u32, data: Bytes) -> Self {
        Self {
            piece,
            offset,
            data,
        }
    }

    pub fn request(&self) -> BlockRequest {
        BlockRequest {
            piece: self.piece,
            offset: self.offset,
            length: self.data.len() as u32,
        }
    }
}

#[allow(dead_code)]
pub fn compute_block_count(piece_length: u64, block_size: u32) -> u32 {
    piece_length.div_ceil(block_size as u64) as u32
}

#[allow(dead_code)]
pub fn compute_block_length(piece_length: u64, block_index: u32, block_size: u32) -> u32 {
    let offset = block_index as u64 * block_size as u64;
    let remaining = piece_length.saturating_sub(offset);
    remaining.min(block_size as u64) as u32
}

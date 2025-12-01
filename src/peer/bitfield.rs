use bytes::Bytes;

#[derive(Debug, Clone)]
pub struct Bitfield {
    bits: Vec<u8>,
    num_pieces: usize,
}

impl Bitfield {
    pub fn new(num_pieces: usize) -> Self {
        let num_bytes = (num_pieces + 7) / 8;
        Self {
            bits: vec![0; num_bytes],
            num_pieces,
        }
    }

    pub fn from_bytes(bytes: Bytes, num_pieces: usize) -> Self {
        let mut bits = bytes.to_vec();
        let expected_bytes = (num_pieces + 7) / 8;

        if bits.len() < expected_bytes {
            bits.resize(expected_bytes, 0);
        }

        Self { bits, num_pieces }
    }

    pub fn has(&self, index: usize) -> bool {
        if index >= self.num_pieces {
            return false;
        }
        let byte_index = index / 8;
        let bit_index = 7 - (index % 8);
        (self.bits[byte_index] & (1 << bit_index)) != 0
    }

    pub fn set(&mut self, index: usize) {
        if index >= self.num_pieces {
            return;
        }
        let byte_index = index / 8;
        let bit_index = 7 - (index % 8);
        self.bits[byte_index] |= 1 << bit_index;
    }

    pub fn clear(&mut self, index: usize) {
        if index >= self.num_pieces {
            return;
        }
        let byte_index = index / 8;
        let bit_index = 7 - (index % 8);
        self.bits[byte_index] &= !(1 << bit_index);
    }

    pub fn count_ones(&self) -> usize {
        let mut count = 0;
        for i in 0..self.num_pieces {
            if self.has(i) {
                count += 1;
            }
        }
        count
    }

    pub fn is_complete(&self) -> bool {
        self.count_ones() == self.num_pieces
    }

    pub fn is_empty(&self) -> bool {
        self.count_ones() == 0
    }

    pub fn num_pieces(&self) -> usize {
        self.num_pieces
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bits
    }

    pub fn to_bytes(&self) -> Bytes {
        Bytes::copy_from_slice(&self.bits)
    }

    pub fn missing_pieces(&self) -> Vec<usize> {
        (0..self.num_pieces).filter(|&i| !self.has(i)).collect()
    }

    pub fn available_pieces(&self) -> Vec<usize> {
        (0..self.num_pieces).filter(|&i| self.has(i)).collect()
    }
}

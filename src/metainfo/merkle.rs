use sha2::{Digest, Sha256};

pub struct MerkleTree {
    leaves: Vec<[u8; 32]>,
    nodes: Vec<[u8; 32]>,
}

impl MerkleTree {
    pub fn new() -> Self {
        Self {
            leaves: Vec::new(),
            nodes: Vec::new(),
        }
    }

    pub fn from_piece_hashes(hashes: Vec<[u8; 32]>) -> Self {
        let mut tree = Self {
            leaves: hashes,
            nodes: Vec::new(),
        };
        tree.build();
        tree
    }

    pub fn add_leaf(&mut self, hash: [u8; 32]) {
        self.leaves.push(hash);
    }

    pub fn build(&mut self) {
        if self.leaves.is_empty() {
            return;
        }

        let leaf_count = self.leaves.len().next_power_of_two();
        let mut level: Vec<[u8; 32]> = self.leaves.clone();

        while level.len() < leaf_count {
            level.push([0u8; 32]);
        }

        self.nodes.clear();
        self.nodes.extend_from_slice(&level);

        while level.len() > 1 {
            let mut next_level = Vec::with_capacity(level.len() / 2);

            for chunk in level.chunks(2) {
                let hash = hash_pair(&chunk[0], &chunk[1]);
                next_level.push(hash);
            }

            self.nodes.extend_from_slice(&next_level);
            level = next_level;
        }
    }

    pub fn root(&self) -> Option<[u8; 32]> {
        self.nodes.last().copied()
    }

    pub fn proof(&self, leaf_index: usize) -> Option<Vec<[u8; 32]>> {
        if leaf_index >= self.leaves.len() {
            return None;
        }

        let leaf_count = self.leaves.len().next_power_of_two();
        let mut proof = Vec::new();
        let mut index = leaf_index;
        let mut level_start = 0;
        let mut level_size = leaf_count;

        while level_size > 1 {
            let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };

            if level_start + sibling_index < self.nodes.len() {
                proof.push(self.nodes[level_start + sibling_index]);
            }

            level_start += level_size;
            level_size /= 2;
            index /= 2;
        }

        Some(proof)
    }

    pub fn verify(root: &[u8; 32], leaf: &[u8; 32], index: usize, proof: &[[u8; 32]]) -> bool {
        let mut hash = *leaf;
        let mut idx = index;

        for sibling in proof {
            hash = if idx % 2 == 0 {
                hash_pair(&hash, sibling)
            } else {
                hash_pair(sibling, &hash)
            };
            idx /= 2;
        }

        &hash == root
    }

    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }
}

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

#[allow(dead_code)]
pub fn hash_block(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

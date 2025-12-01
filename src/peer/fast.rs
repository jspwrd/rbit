use sha1::{Digest, Sha1};
use std::net::IpAddr;

const ALLOWED_FAST_SET_SIZE: usize = 10;

pub struct FastExtension {
    allowed_fast_set: Vec<u32>,
}

impl FastExtension {
    pub fn new() -> Self {
        Self {
            allowed_fast_set: Vec::new(),
        }
    }

    pub fn compute_allowed_fast_set(
        &mut self,
        info_hash: &[u8; 20],
        peer_ip: IpAddr,
        num_pieces: u32,
    ) {
        self.allowed_fast_set.clear();

        let ip_bytes = match peer_ip {
            IpAddr::V4(ip) => {
                let octets = ip.octets();
                [octets[0], octets[1], octets[2], 0]
            }
            IpAddr::V6(ip) => {
                let octets = ip.octets();
                [octets[0], octets[1], octets[2], octets[3]]
            }
        };

        let mut x = Vec::with_capacity(24);
        x.extend_from_slice(&ip_bytes);
        x.extend_from_slice(info_hash);

        while self.allowed_fast_set.len() < ALLOWED_FAST_SET_SIZE {
            let mut hasher = Sha1::new();
            hasher.update(&x);
            let hash = hasher.finalize();

            for chunk in hash.chunks(4) {
                if self.allowed_fast_set.len() >= ALLOWED_FAST_SET_SIZE {
                    break;
                }

                let index = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])
                    % num_pieces;

                if !self.allowed_fast_set.contains(&index) {
                    self.allowed_fast_set.push(index);
                }
            }

            x = hash.to_vec();
        }
    }

    pub fn allowed_fast_set(&self) -> &[u32] {
        &self.allowed_fast_set
    }

    pub fn is_allowed_fast(&self, piece: u32) -> bool {
        self.allowed_fast_set.contains(&piece)
    }
}

impl Default for FastExtension {
    fn default() -> Self {
        Self::new()
    }
}

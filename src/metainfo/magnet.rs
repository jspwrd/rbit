use super::error::MetainfoError;
use super::info_hash::InfoHash;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct MagnetLink {
    pub info_hash: InfoHash,
    pub display_name: Option<String>,
    pub trackers: Vec<String>,
    pub web_seeds: Vec<String>,
    pub peer_addresses: Vec<String>,
}

impl MagnetLink {
    pub fn parse(uri: &str) -> Result<Self, MetainfoError> {
        if !uri.starts_with("magnet:?") {
            return Err(MetainfoError::InvalidMagnetLink(
                "missing magnet:? prefix".into(),
            ));
        }

        let query = &uri[8..];
        let params = parse_query_string(query);

        let xt = params
            .get("xt")
            .and_then(|v| v.first())
            .ok_or_else(|| MetainfoError::InvalidMagnetLink("missing xt parameter".into()))?;

        let info_hash = if let Some(hash) = xt.strip_prefix("urn:btih:") {
            if hash.len() == 40 {
                InfoHash::from_hex(hash)?
            } else if hash.len() == 32 {
                let decoded = base32_decode(hash)
                    .ok_or_else(|| MetainfoError::InvalidMagnetLink("invalid base32".into()))?;
                InfoHash::from_v1_bytes(&decoded)?
            } else {
                return Err(MetainfoError::InvalidMagnetLink(
                    "invalid info hash length".into(),
                ));
            }
        } else if let Some(hash) = xt.strip_prefix("urn:btmh:1220") {
            InfoHash::from_hex(hash)?
        } else {
            return Err(MetainfoError::InvalidMagnetLink(
                "unsupported xt format".into(),
            ));
        };

        let display_name = params
            .get("dn")
            .and_then(|v| v.first())
            .map(|s| url_decode(s));

        let trackers = params
            .get("tr")
            .map(|v| v.iter().map(|s| url_decode(s)).collect())
            .unwrap_or_default();

        let web_seeds = params
            .get("ws")
            .map(|v| v.iter().map(|s| url_decode(s)).collect())
            .unwrap_or_default();

        let peer_addresses = params
            .get("x.pe")
            .map(|v| v.iter().map(|s| url_decode(s)).collect())
            .unwrap_or_default();

        Ok(Self {
            info_hash,
            display_name,
            trackers,
            web_seeds,
            peer_addresses,
        })
    }

    pub fn to_uri(&self) -> String {
        let mut uri = String::from("magnet:?");

        let hash_str = match &self.info_hash {
            InfoHash::V1(_) => format!("urn:btih:{}", self.info_hash.to_hex()),
            InfoHash::V2(_) => format!("urn:btmh:1220{}", self.info_hash.to_hex()),
        };
        uri.push_str(&format!("xt={}", hash_str));

        if let Some(ref name) = self.display_name {
            uri.push_str(&format!("&dn={}", url_encode(name)));
        }

        for tracker in &self.trackers {
            uri.push_str(&format!("&tr={}", url_encode(tracker)));
        }

        for ws in &self.web_seeds {
            uri.push_str(&format!("&ws={}", url_encode(ws)));
        }

        uri
    }
}

fn parse_query_string(query: &str) -> HashMap<String, Vec<String>> {
    let mut params: HashMap<String, Vec<String>> = HashMap::new();

    for part in query.split('&') {
        if let Some((key, value)) = part.split_once('=') {
            params
                .entry(key.to_string())
                .or_default()
                .push(value.to_string());
        }
    }

    params
}

fn url_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte as char);
                    continue;
                }
            }
            result.push('%');
            result.push_str(&hex);
        } else if c == '+' {
            result.push(' ');
        } else {
            result.push(c);
        }
    }

    result
}

fn url_encode(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 3);

    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            _ => {
                result.push_str(&format!("%{:02X}", byte));
            }
        }
    }

    result
}

fn base32_decode(input: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    let input = input.to_uppercase();
    let input = input.trim_end_matches('=');

    let mut output = Vec::with_capacity(input.len() * 5 / 8);
    let mut buffer: u64 = 0;
    let mut bits_in_buffer = 0;

    for c in input.chars() {
        let value = ALPHABET.iter().position(|&x| x == c as u8)? as u64;
        buffer = (buffer << 5) | value;
        bits_in_buffer += 5;

        if bits_in_buffer >= 8 {
            bits_in_buffer -= 8;
            output.push((buffer >> bits_in_buffer) as u8);
            buffer &= (1 << bits_in_buffer) - 1;
        }
    }

    Some(output)
}

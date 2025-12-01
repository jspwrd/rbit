use super::error::TrackerError;
use super::response::{parse_compact_peers, parse_compact_peers6, AnnounceResponse, TrackerEvent};
use crate::bencode::decode;
use reqwest::Client;
use std::time::Duration;

const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

pub struct HttpTracker {
    client: Client,
    url: String,
}

impl HttpTracker {
    pub fn new(url: &str) -> Result<Self, TrackerError> {
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(TrackerError::InvalidUrl(url.to_string()));
        }

        let client = Client::builder()
            .timeout(HTTP_TIMEOUT)
            .build()
            .map_err(TrackerError::Http)?;

        Ok(Self {
            client,
            url: url.to_string(),
        })
    }

    pub async fn announce(
        &self,
        info_hash: &[u8; 20],
        peer_id: &[u8; 20],
        port: u16,
        uploaded: u64,
        downloaded: u64,
        left: u64,
        event: TrackerEvent,
    ) -> Result<AnnounceResponse, TrackerError> {
        let mut url = format!(
            "{}?info_hash={}&peer_id={}&port={}&uploaded={}&downloaded={}&left={}&compact=1",
            self.url,
            url_encode(info_hash),
            url_encode(peer_id),
            port,
            uploaded,
            downloaded,
            left
        );

        let event_str = event.as_str();
        if !event_str.is_empty() {
            url.push_str(&format!("&event={}", event_str));
        }

        let response = self.client.get(&url).send().await?;
        let bytes = response.bytes().await?;

        let value = decode(&bytes)?;
        let dict = value
            .as_dict()
            .ok_or_else(|| TrackerError::InvalidResponse("expected dict".into()))?;

        if let Some(failure) = dict.get(b"failure reason".as_slice()).and_then(|v| v.as_str()) {
            return Err(TrackerError::TrackerError(failure.to_string()));
        }

        let interval = dict
            .get(b"interval".as_slice())
            .and_then(|v| v.as_integer())
            .ok_or_else(|| TrackerError::InvalidResponse("missing interval".into()))?
            as u32;

        let mut response = AnnounceResponse::new(interval);

        response.min_interval = dict
            .get(b"min interval".as_slice())
            .and_then(|v| v.as_integer())
            .map(|v| v as u32);

        response.complete = dict
            .get(b"complete".as_slice())
            .and_then(|v| v.as_integer())
            .map(|v| v as u32);

        response.incomplete = dict
            .get(b"incomplete".as_slice())
            .and_then(|v| v.as_integer())
            .map(|v| v as u32);

        response.warning_message = dict
            .get(b"warning message".as_slice())
            .and_then(|v| v.as_str())
            .map(String::from);

        response.tracker_id = dict
            .get(b"tracker id".as_slice())
            .and_then(|v| v.as_str())
            .map(String::from);

        if let Some(peers) = dict.get(b"peers".as_slice()) {
            if let Some(bytes) = peers.as_bytes() {
                response.peers = parse_compact_peers(bytes);
            } else if let Some(list) = peers.as_list() {
                for peer in list {
                    if let Some(dict) = peer.as_dict() {
                        let ip = dict
                            .get(b"ip".as_slice())
                            .and_then(|v| v.as_str())
                            .and_then(|s| s.parse().ok());
                        let port = dict
                            .get(b"port".as_slice())
                            .and_then(|v| v.as_integer())
                            .map(|p| p as u16);

                        if let (Some(ip), Some(port)) = (ip, port) {
                            response.peers.push(std::net::SocketAddr::new(ip, port));
                        }
                    }
                }
            }
        }

        if let Some(peers6) = dict.get(b"peers6".as_slice()).and_then(|v| v.as_bytes()) {
            response.peers6 = parse_compact_peers6(peers6);
        }

        Ok(response)
    }

    pub fn url(&self) -> &str {
        &self.url
    }
}

fn url_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| {
            if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b'~' {
                format!("{}", b as char)
            } else {
                format!("%{:02X}", b)
            }
        })
        .collect()
}

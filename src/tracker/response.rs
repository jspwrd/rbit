use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackerEvent {
    None,
    Started,
    Stopped,
    Completed,
}

impl TrackerEvent {
    pub fn as_str(&self) -> &'static str {
        match self {
            TrackerEvent::None => "",
            TrackerEvent::Started => "started",
            TrackerEvent::Stopped => "stopped",
            TrackerEvent::Completed => "completed",
        }
    }

    pub fn as_udp_id(&self) -> u32 {
        match self {
            TrackerEvent::None => 0,
            TrackerEvent::Completed => 1,
            TrackerEvent::Started => 2,
            TrackerEvent::Stopped => 3,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AnnounceResponse {
    pub interval: u32,
    pub min_interval: Option<u32>,
    pub complete: Option<u32>,
    pub incomplete: Option<u32>,
    pub peers: Vec<SocketAddr>,
    pub peers6: Vec<SocketAddr>,
    pub warning_message: Option<String>,
    pub tracker_id: Option<String>,
}

impl AnnounceResponse {
    pub fn new(interval: u32) -> Self {
        Self {
            interval,
            min_interval: None,
            complete: None,
            incomplete: None,
            peers: Vec::new(),
            peers6: Vec::new(),
            warning_message: None,
            tracker_id: None,
        }
    }

    pub fn all_peers(&self) -> impl Iterator<Item = &SocketAddr> {
        self.peers.iter().chain(self.peers6.iter())
    }
}

#[derive(Debug, Clone)]
pub struct ScrapeResponse {
    pub files: Vec<ScrapeFile>,
}

#[derive(Debug, Clone)]
pub struct ScrapeFile {
    pub info_hash: [u8; 20],
    pub complete: u32,
    pub incomplete: u32,
    pub downloaded: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct CompactPeer {
    pub ip: IpAddr,
    pub port: u16,
}

impl CompactPeer {
    pub fn from_v4_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 6 {
            return None;
        }
        let ip = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
        let port = u16::from_be_bytes([bytes[4], bytes[5]]);
        Some(Self {
            ip: IpAddr::V4(ip),
            port,
        })
    }

    pub fn from_v6_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 18 {
            return None;
        }
        let mut ip_bytes = [0u8; 16];
        ip_bytes.copy_from_slice(&bytes[..16]);
        let ip = Ipv6Addr::from(ip_bytes);
        let port = u16::from_be_bytes([bytes[16], bytes[17]]);
        Some(Self {
            ip: IpAddr::V6(ip),
            port,
        })
    }

    pub fn to_socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.ip, self.port)
    }
}

pub fn parse_compact_peers(data: &[u8]) -> Vec<SocketAddr> {
    data.chunks_exact(6)
        .filter_map(CompactPeer::from_v4_bytes)
        .map(|p| p.to_socket_addr())
        .collect()
}

pub fn parse_compact_peers6(data: &[u8]) -> Vec<SocketAddr> {
    data.chunks_exact(18)
        .filter_map(CompactPeer::from_v6_bytes)
        .map(|p| p.to_socket_addr())
        .collect()
}

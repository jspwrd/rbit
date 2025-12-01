use super::bitfield::Bitfield;
use super::choking::ChokingState;
use super::error::PeerError;
use super::extension::ExtensionHandshake;
use super::message::{Handshake, Message};
use super::peer_id::PeerId;
use super::transport::PeerTransport;
use std::net::SocketAddr;
use std::time::Instant;
use tokio::net::TcpStream;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    Connecting,
    Handshaking,
    Connected,
    Disconnected,
}

pub struct PeerConnection {
    pub addr: SocketAddr,
    pub peer_id: Option<PeerId>,
    pub state: PeerState,
    pub choking: ChokingState,
    pub bitfield: Option<Bitfield>,
    pub extension_handshake: Option<ExtensionHandshake>,
    pub supports_fast: bool,
    pub supports_extension: bool,
    pub connected_at: Instant,
    pub last_message_at: Instant,
    pub bytes_downloaded: u64,
    pub bytes_uploaded: u64,
    transport: Option<PeerTransport>,
}

impl PeerConnection {
    pub async fn connect(
        addr: SocketAddr,
        info_hash: [u8; 20],
        our_peer_id: [u8; 20],
    ) -> Result<Self, PeerError> {
        let stream = TcpStream::connect(addr).await?;
        let mut transport = PeerTransport::new(stream);

        let handshake = Handshake::new(info_hash, our_peer_id);
        transport.send_handshake(&handshake).await?;

        let their_handshake = transport.receive_handshake().await?;

        if their_handshake.info_hash != info_hash {
            return Err(PeerError::InfoHashMismatch);
        }

        let now = Instant::now();
        Ok(Self {
            addr,
            peer_id: PeerId::from_bytes(&their_handshake.peer_id),
            state: PeerState::Connected,
            choking: ChokingState::default(),
            bitfield: None,
            extension_handshake: None,
            supports_fast: their_handshake.supports_fast_extension(),
            supports_extension: their_handshake.supports_extension_protocol(),
            connected_at: now,
            last_message_at: now,
            bytes_downloaded: 0,
            bytes_uploaded: 0,
            transport: Some(transport),
        })
    }

    pub async fn accept(
        stream: TcpStream,
        info_hash: [u8; 20],
        our_peer_id: [u8; 20],
    ) -> Result<Self, PeerError> {
        let addr = stream.peer_addr()?;
        let mut transport = PeerTransport::new(stream);

        let their_handshake = transport.receive_handshake().await?;

        if their_handshake.info_hash != info_hash {
            return Err(PeerError::InfoHashMismatch);
        }

        let handshake = Handshake::new(info_hash, our_peer_id);
        transport.send_handshake(&handshake).await?;

        let now = Instant::now();
        Ok(Self {
            addr,
            peer_id: PeerId::from_bytes(&their_handshake.peer_id),
            state: PeerState::Connected,
            choking: ChokingState::default(),
            bitfield: None,
            extension_handshake: None,
            supports_fast: their_handshake.supports_fast_extension(),
            supports_extension: their_handshake.supports_extension_protocol(),
            connected_at: now,
            last_message_at: now,
            bytes_downloaded: 0,
            bytes_uploaded: 0,
            transport: Some(transport),
        })
    }

    pub async fn send(&mut self, message: Message) -> Result<(), PeerError> {
        if let Some(ref mut transport) = self.transport {
            transport.send_message(&message).await?;

            if let Message::Piece { ref data, .. } = message {
                self.bytes_uploaded += data.len() as u64;
            }

            Ok(())
        } else {
            Err(PeerError::ConnectionClosed)
        }
    }

    pub async fn receive(&mut self) -> Result<Message, PeerError> {
        if let Some(ref mut transport) = self.transport {
            let message = transport.receive_message().await?;
            self.last_message_at = Instant::now();

            match &message {
                Message::Choke => self.choking.peer_choking = true,
                Message::Unchoke => self.choking.peer_choking = false,
                Message::Interested => self.choking.peer_interested = true,
                Message::NotInterested => self.choking.peer_interested = false,
                Message::Piece { data, .. } => {
                    self.bytes_downloaded += data.len() as u64;
                }
                _ => {}
            }

            Ok(message)
        } else {
            Err(PeerError::ConnectionClosed)
        }
    }

    pub fn disconnect(&mut self) {
        self.transport = None;
        self.state = PeerState::Disconnected;
    }

    pub fn is_connected(&self) -> bool {
        self.state == PeerState::Connected && self.transport.is_some()
    }

    pub fn can_request(&self) -> bool {
        self.is_connected() && !self.choking.peer_choking && self.choking.am_interested
    }

    pub fn set_interested(&mut self, interested: bool) {
        self.choking.am_interested = interested;
    }

    pub fn set_choking(&mut self, choking: bool) {
        self.choking.am_choking = choking;
    }
}

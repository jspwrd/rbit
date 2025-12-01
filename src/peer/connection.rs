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

/// The connection state of a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    /// TCP connection in progress.
    Connecting,
    /// Connected, performing BitTorrent handshake.
    Handshaking,
    /// Fully connected and ready for data exchange.
    Connected,
    /// Connection has been closed.
    Disconnected,
}

/// A connection to a BitTorrent peer.
///
/// Manages the TCP connection and protocol state for communicating with a
/// single peer, including handshake, message exchange, and choking state.
///
/// # Examples
///
/// ```no_run
/// use rbit::peer::{PeerConnection, PeerId, Message};
/// use std::net::SocketAddr;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let addr: SocketAddr = "192.168.1.100:6881".parse()?;
/// let info_hash = [0u8; 20];
/// let peer_id = PeerId::generate();
///
/// let mut conn = PeerConnection::connect(addr, info_hash, *peer_id.as_bytes()).await?;
///
/// // Express interest and wait for unchoke
/// conn.send(Message::Interested).await?;
/// # Ok(())
/// # }
/// ```
pub struct PeerConnection {
    /// The peer's socket address.
    pub addr: SocketAddr,
    /// The peer's ID (if received in handshake).
    pub peer_id: Option<PeerId>,
    /// Current connection state.
    pub state: PeerState,
    /// Choking state for this connection.
    pub choking: ChokingState,
    /// The peer's bitfield (pieces they have).
    pub bitfield: Option<Bitfield>,
    /// Extension handshake data (if BEP-10 is supported).
    pub extension_handshake: Option<ExtensionHandshake>,
    /// Whether the peer supports the Fast Extension (BEP-6).
    pub supports_fast: bool,
    /// Whether the peer supports the Extension Protocol (BEP-10).
    pub supports_extension: bool,
    /// When the connection was established.
    pub connected_at: Instant,
    /// When the last message was received.
    pub last_message_at: Instant,
    /// Total bytes downloaded from this peer.
    pub bytes_downloaded: u64,
    /// Total bytes uploaded to this peer.
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

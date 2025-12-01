use super::error::PeerError;
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// The BitTorrent protocol identifier.
pub const PROTOCOL: &[u8] = b"BitTorrent protocol";
/// Length of the handshake message in bytes.
pub const HANDSHAKE_LEN: usize = 68;

/// Message type identifiers in the peer wire protocol.
///
/// Each message (except KeepAlive) has a one-byte ID following the length prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageId {
    /// Stop sending data to the peer.
    Choke = 0,
    /// Ready to send data to the peer.
    Unchoke = 1,
    /// Want data from the peer.
    Interested = 2,
    /// Don't want data from the peer.
    NotInterested = 3,
    /// Announce a newly-acquired piece.
    Have = 4,
    /// Announce all available pieces.
    Bitfield = 5,
    /// Request a data block.
    Request = 6,
    /// Send piece data.
    Piece = 7,
    /// Cancel a pending request.
    Cancel = 8,
    /// DHT port announcement.
    Port = 9,
    // Fast extension (BEP-6)
    /// Suggest a piece to download.
    Suggest = 13,
    /// Peer has all pieces (seeder).
    HaveAll = 14,
    /// Peer has no pieces.
    HaveNone = 15,
    /// Reject a block request.
    Reject = 16,
    /// Allow downloading while choked.
    AllowedFast = 17,
    // Extension protocol (BEP-10)
    /// Extension protocol message.
    Extended = 20,
}

impl TryFrom<u8> for MessageId {
    type Error = PeerError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(MessageId::Choke),
            1 => Ok(MessageId::Unchoke),
            2 => Ok(MessageId::Interested),
            3 => Ok(MessageId::NotInterested),
            4 => Ok(MessageId::Have),
            5 => Ok(MessageId::Bitfield),
            6 => Ok(MessageId::Request),
            7 => Ok(MessageId::Piece),
            8 => Ok(MessageId::Cancel),
            9 => Ok(MessageId::Port),
            13 => Ok(MessageId::Suggest),
            14 => Ok(MessageId::HaveAll),
            15 => Ok(MessageId::HaveNone),
            16 => Ok(MessageId::Reject),
            17 => Ok(MessageId::AllowedFast),
            20 => Ok(MessageId::Extended),
            _ => Err(PeerError::InvalidMessageId(value)),
        }
    }
}

/// The BitTorrent handshake message.
///
/// The handshake is the first message exchanged between peers and includes:
/// - Protocol identifier ("BitTorrent protocol")
/// - Reserved bytes (8 bytes, used for capability flags)
/// - Info hash (20 bytes, identifies the torrent)
/// - Peer ID (20 bytes, identifies the client)
///
/// # Reserved Bytes
///
/// Bits in the reserved bytes indicate protocol extensions:
/// - Byte 5, bit 4: Extension protocol ([BEP-10])
/// - Byte 7, bit 0: DHT ([BEP-5])
/// - Byte 7, bit 2: Fast extension ([BEP-6])
///
/// [BEP-5]: http://bittorrent.org/beps/bep_0005.html
/// [BEP-6]: http://bittorrent.org/beps/bep_0006.html
/// [BEP-10]: http://bittorrent.org/beps/bep_0010.html
#[derive(Debug, Clone)]
pub struct Handshake {
    /// The torrent's info hash.
    pub info_hash: [u8; 20],
    /// The sender's peer ID.
    pub peer_id: [u8; 20],
    /// Reserved bytes for protocol extensions.
    pub reserved: [u8; 8],
}

impl Handshake {
    /// Creates a new handshake with extension protocol and fast extension enabled.
    pub fn new(info_hash: [u8; 20], peer_id: [u8; 20]) -> Self {
        let mut reserved = [0u8; 8];
        reserved[5] |= 0x10; // Extension protocol (BEP-10)
        reserved[7] |= 0x04; // Fast extension (BEP-6)
        Self {
            info_hash,
            peer_id,
            reserved,
        }
    }

    /// Returns `true` if the peer supports the extension protocol ([BEP-10]).
    pub fn supports_extension_protocol(&self) -> bool {
        (self.reserved[5] & 0x10) != 0
    }

    /// Returns `true` if the peer supports the fast extension ([BEP-6]).
    pub fn supports_fast_extension(&self) -> bool {
        (self.reserved[7] & 0x04) != 0
    }

    /// Returns `true` if the peer supports DHT ([BEP-5]).
    pub fn supports_dht(&self) -> bool {
        (self.reserved[7] & 0x01) != 0
    }

    /// Encodes the handshake to bytes for transmission.
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(HANDSHAKE_LEN);
        buf.put_u8(19);
        buf.put_slice(PROTOCOL);
        buf.put_slice(&self.reserved);
        buf.put_slice(&self.info_hash);
        buf.put_slice(&self.peer_id);
        buf.freeze()
    }

    pub fn decode(data: &[u8]) -> Result<Self, PeerError> {
        if data.len() < HANDSHAKE_LEN {
            return Err(PeerError::InvalidHandshake);
        }

        if data[0] != 19 || &data[1..20] != PROTOCOL {
            return Err(PeerError::InvalidHandshake);
        }

        let mut reserved = [0u8; 8];
        reserved.copy_from_slice(&data[20..28]);

        let mut info_hash = [0u8; 20];
        info_hash.copy_from_slice(&data[28..48]);

        let mut peer_id = [0u8; 20];
        peer_id.copy_from_slice(&data[48..68]);

        Ok(Self {
            info_hash,
            peer_id,
            reserved,
        })
    }
}

/// A peer wire protocol message.
///
/// Messages are length-prefixed: a 4-byte big-endian length followed by
/// a 1-byte message ID (except KeepAlive which has length 0) and payload.
///
/// # Examples
///
/// ```
/// use rbit::peer::Message;
///
/// // Create a request for piece 0, offset 0, 16KB
/// let request = Message::Request {
///     index: 0,
///     begin: 0,
///     length: 16384,
/// };
///
/// // Encode to bytes
/// let bytes = request.encode();
/// assert_eq!(bytes.len(), 17); // 4-byte length + 1-byte ID + 12-byte payload
/// ```
#[derive(Debug, Clone)]
pub enum Message {
    /// Empty message to keep the connection alive.
    KeepAlive,
    /// We are choking the peer (not sending data).
    Choke,
    /// We are unchoking the peer (ready to send data).
    Unchoke,
    /// We are interested in the peer's data.
    Interested,
    /// We are not interested in the peer's data.
    NotInterested,
    /// Announce that we have a piece.
    Have { piece: u32 },
    /// Bitfield of all pieces we have.
    Bitfield(Bytes),
    /// Request a block of data.
    Request { index: u32, begin: u32, length: u32 },
    /// Send piece data.
    Piece { index: u32, begin: u32, data: Bytes },
    /// Cancel a pending request.
    Cancel { index: u32, begin: u32, length: u32 },
    /// DHT port announcement.
    Port(u16),
    // Fast extension
    /// Suggest a piece to download (fast extension).
    Suggest { piece: u32 },
    /// Peer has all pieces (fast extension, seeder shortcut).
    HaveAll,
    /// Peer has no pieces (fast extension).
    HaveNone,
    /// Reject a block request (fast extension).
    Reject { index: u32, begin: u32, length: u32 },
    /// Allow downloading this piece while choked (fast extension).
    AllowedFast { piece: u32 },
    // Extension protocol
    /// Extension protocol message ([BEP-10]).
    Extended { id: u8, payload: Bytes },
}

impl Message {
    /// Encodes the message to bytes for transmission.
    ///
    /// The output includes the 4-byte length prefix.
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();

        match self {
            Message::KeepAlive => {
                buf.put_u32(0);
            }
            Message::Choke => {
                buf.put_u32(1);
                buf.put_u8(MessageId::Choke as u8);
            }
            Message::Unchoke => {
                buf.put_u32(1);
                buf.put_u8(MessageId::Unchoke as u8);
            }
            Message::Interested => {
                buf.put_u32(1);
                buf.put_u8(MessageId::Interested as u8);
            }
            Message::NotInterested => {
                buf.put_u32(1);
                buf.put_u8(MessageId::NotInterested as u8);
            }
            Message::Have { piece } => {
                buf.put_u32(5);
                buf.put_u8(MessageId::Have as u8);
                buf.put_u32(*piece);
            }
            Message::Bitfield(bits) => {
                buf.put_u32(1 + bits.len() as u32);
                buf.put_u8(MessageId::Bitfield as u8);
                buf.put_slice(bits);
            }
            Message::Request {
                index,
                begin,
                length,
            } => {
                buf.put_u32(13);
                buf.put_u8(MessageId::Request as u8);
                buf.put_u32(*index);
                buf.put_u32(*begin);
                buf.put_u32(*length);
            }
            Message::Piece { index, begin, data } => {
                buf.put_u32(9 + data.len() as u32);
                buf.put_u8(MessageId::Piece as u8);
                buf.put_u32(*index);
                buf.put_u32(*begin);
                buf.put_slice(data);
            }
            Message::Cancel {
                index,
                begin,
                length,
            } => {
                buf.put_u32(13);
                buf.put_u8(MessageId::Cancel as u8);
                buf.put_u32(*index);
                buf.put_u32(*begin);
                buf.put_u32(*length);
            }
            Message::Port(port) => {
                buf.put_u32(3);
                buf.put_u8(MessageId::Port as u8);
                buf.put_u16(*port);
            }
            Message::Suggest { piece } => {
                buf.put_u32(5);
                buf.put_u8(MessageId::Suggest as u8);
                buf.put_u32(*piece);
            }
            Message::HaveAll => {
                buf.put_u32(1);
                buf.put_u8(MessageId::HaveAll as u8);
            }
            Message::HaveNone => {
                buf.put_u32(1);
                buf.put_u8(MessageId::HaveNone as u8);
            }
            Message::Reject {
                index,
                begin,
                length,
            } => {
                buf.put_u32(13);
                buf.put_u8(MessageId::Reject as u8);
                buf.put_u32(*index);
                buf.put_u32(*begin);
                buf.put_u32(*length);
            }
            Message::AllowedFast { piece } => {
                buf.put_u32(5);
                buf.put_u8(MessageId::AllowedFast as u8);
                buf.put_u32(*piece);
            }
            Message::Extended { id, payload } => {
                buf.put_u32(2 + payload.len() as u32);
                buf.put_u8(MessageId::Extended as u8);
                buf.put_u8(*id);
                buf.put_slice(payload);
            }
        }

        buf.freeze()
    }

    pub fn decode(mut data: Bytes) -> Result<Self, PeerError> {
        if data.len() < 4 {
            return Err(PeerError::InvalidMessage("too short".into()));
        }

        let length = data.get_u32() as usize;

        if length == 0 {
            return Ok(Message::KeepAlive);
        }

        if data.remaining() < length {
            return Err(PeerError::InvalidMessage("incomplete message".into()));
        }

        let id = MessageId::try_from(data.get_u8())?;

        match id {
            MessageId::Choke => Ok(Message::Choke),
            MessageId::Unchoke => Ok(Message::Unchoke),
            MessageId::Interested => Ok(Message::Interested),
            MessageId::NotInterested => Ok(Message::NotInterested),
            MessageId::Have => {
                if data.remaining() < 4 {
                    return Err(PeerError::InvalidMessage("have too short".into()));
                }
                Ok(Message::Have {
                    piece: data.get_u32(),
                })
            }
            MessageId::Bitfield => Ok(Message::Bitfield(data.copy_to_bytes(length - 1))),
            MessageId::Request => {
                if data.remaining() < 12 {
                    return Err(PeerError::InvalidMessage("request too short".into()));
                }
                Ok(Message::Request {
                    index: data.get_u32(),
                    begin: data.get_u32(),
                    length: data.get_u32(),
                })
            }
            MessageId::Piece => {
                if data.remaining() < 8 {
                    return Err(PeerError::InvalidMessage("piece too short".into()));
                }
                let index = data.get_u32();
                let begin = data.get_u32();
                let block_data = data.copy_to_bytes(length - 9);
                Ok(Message::Piece {
                    index,
                    begin,
                    data: block_data,
                })
            }
            MessageId::Cancel => {
                if data.remaining() < 12 {
                    return Err(PeerError::InvalidMessage("cancel too short".into()));
                }
                Ok(Message::Cancel {
                    index: data.get_u32(),
                    begin: data.get_u32(),
                    length: data.get_u32(),
                })
            }
            MessageId::Port => {
                if data.remaining() < 2 {
                    return Err(PeerError::InvalidMessage("port too short".into()));
                }
                Ok(Message::Port(data.get_u16()))
            }
            MessageId::Suggest => {
                if data.remaining() < 4 {
                    return Err(PeerError::InvalidMessage("suggest too short".into()));
                }
                Ok(Message::Suggest {
                    piece: data.get_u32(),
                })
            }
            MessageId::HaveAll => Ok(Message::HaveAll),
            MessageId::HaveNone => Ok(Message::HaveNone),
            MessageId::Reject => {
                if data.remaining() < 12 {
                    return Err(PeerError::InvalidMessage("reject too short".into()));
                }
                Ok(Message::Reject {
                    index: data.get_u32(),
                    begin: data.get_u32(),
                    length: data.get_u32(),
                })
            }
            MessageId::AllowedFast => {
                if data.remaining() < 4 {
                    return Err(PeerError::InvalidMessage("allowed fast too short".into()));
                }
                Ok(Message::AllowedFast {
                    piece: data.get_u32(),
                })
            }
            MessageId::Extended => {
                if data.remaining() < 1 {
                    return Err(PeerError::InvalidMessage("extended too short".into()));
                }
                let ext_id = data.get_u8();
                let payload = data.copy_to_bytes(length - 2);
                Ok(Message::Extended {
                    id: ext_id,
                    payload,
                })
            }
        }
    }
}

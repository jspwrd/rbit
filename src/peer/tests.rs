use super::*;
use bytes::Bytes;

#[test]
fn test_peer_id_generate() {
    let id1 = PeerId::generate();
    let id2 = PeerId::generate();
    assert_ne!(id1.0, id2.0);
    assert!(id1.client_id().is_some());
}

#[test]
fn test_bitfield() {
    let mut bf = Bitfield::new(100);
    assert!(!bf.has(0));

    bf.set(0);
    assert!(bf.has(0));

    bf.set(99);
    assert!(bf.has(99));

    bf.clear(0);
    assert!(!bf.has(0));

    assert_eq!(bf.count_ones(), 1);
}

#[test]
fn test_bitfield_from_bytes() {
    let bytes = Bytes::from_static(&[0x80, 0x00]);
    let bf = Bitfield::from_bytes(bytes, 16);

    assert!(bf.has(0));
    assert!(!bf.has(1));
}

#[test]
fn test_handshake_encode_decode() {
    let info_hash = [1u8; 20];
    let peer_id = [2u8; 20];

    let handshake = Handshake::new(info_hash, peer_id);
    let encoded = handshake.encode();

    let decoded = Handshake::decode(&encoded).unwrap();
    assert_eq!(decoded.info_hash, info_hash);
    assert_eq!(decoded.peer_id, peer_id);
    assert!(decoded.supports_extension_protocol());
    assert!(decoded.supports_fast_extension());
}

#[test]
fn test_message_encode_decode() {
    let messages = vec![
        Message::KeepAlive,
        Message::Choke,
        Message::Unchoke,
        Message::Interested,
        Message::NotInterested,
        Message::Have { piece: 42 },
        Message::Request {
            index: 1,
            begin: 0,
            length: 16384,
        },
        Message::Cancel {
            index: 1,
            begin: 0,
            length: 16384,
        },
        Message::Port(6881),
        Message::HaveAll,
        Message::HaveNone,
    ];

    for msg in messages {
        let encoded = msg.encode();
        let decoded = Message::decode(encoded).unwrap();

        match (&msg, &decoded) {
            (Message::KeepAlive, Message::KeepAlive) => {}
            (Message::Choke, Message::Choke) => {}
            (Message::Unchoke, Message::Unchoke) => {}
            (Message::Interested, Message::Interested) => {}
            (Message::NotInterested, Message::NotInterested) => {}
            (Message::Have { piece: p1 }, Message::Have { piece: p2 }) => {
                assert_eq!(p1, p2);
            }
            (
                Message::Request {
                    index: i1,
                    begin: b1,
                    length: l1,
                },
                Message::Request {
                    index: i2,
                    begin: b2,
                    length: l2,
                },
            ) => {
                assert_eq!((i1, b1, l1), (i2, b2, l2));
            }
            (
                Message::Cancel {
                    index: i1,
                    begin: b1,
                    length: l1,
                },
                Message::Cancel {
                    index: i2,
                    begin: b2,
                    length: l2,
                },
            ) => {
                assert_eq!((i1, b1, l1), (i2, b2, l2));
            }
            (Message::Port(p1), Message::Port(p2)) => {
                assert_eq!(p1, p2);
            }
            (Message::HaveAll, Message::HaveAll) => {}
            (Message::HaveNone, Message::HaveNone) => {}
            _ => panic!("message mismatch"),
        }
    }
}

#[test]
fn test_piece_message() {
    let data = Bytes::from_static(b"hello world");
    let msg = Message::Piece {
        index: 0,
        begin: 0,
        data: data.clone(),
    };

    let encoded = msg.encode();
    let decoded = Message::decode(encoded).unwrap();

    if let Message::Piece {
        index,
        begin,
        data: decoded_data,
    } = decoded
    {
        assert_eq!(index, 0);
        assert_eq!(begin, 0);
        assert_eq!(decoded_data, data);
    } else {
        panic!("expected piece message");
    }
}

#[test]
fn test_extension_handshake() {
    let mut hs = ExtensionHandshake::new();
    hs.extensions.insert("ut_pex".to_string(), 1);
    hs.extensions.insert("ut_metadata".to_string(), 2);
    hs.client = Some("rbit/0.1".to_string());

    let encoded = hs.encode().unwrap();
    let decoded = ExtensionHandshake::decode(&encoded).unwrap();

    assert_eq!(decoded.get_extension_id("ut_pex"), Some(1));
    assert_eq!(decoded.get_extension_id("ut_metadata"), Some(2));
    assert_eq!(decoded.client, Some("rbit/0.1".to_string()));
}

#[test]
fn test_block_request() {
    let req = BlockRequest::new(0, 0, 16384);
    assert_eq!(req.piece_index, 0);
    assert_eq!(req.offset, 0);
    assert_eq!(req.length, 16384);
}

#[test]
fn test_choking_state_default() {
    let state = ChokingState::default();
    assert!(state.am_choking);
    assert!(!state.am_interested);
    assert!(state.peer_choking);
    assert!(!state.peer_interested);
}

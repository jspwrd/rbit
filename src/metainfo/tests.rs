use super::*;

#[test]
fn test_info_hash_from_hex() {
    let hex = "0123456789abcdef0123456789abcdef01234567";
    let hash = InfoHash::from_hex(hex).unwrap();
    assert!(hash.is_v1());
    assert_eq!(hash.to_hex(), hex);
}

#[test]
fn test_info_hash_v2() {
    let hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let hash = InfoHash::from_hex(hex).unwrap();
    assert!(hash.is_v2());
    assert_eq!(hash.to_hex(), hex);
}

#[test]
fn test_magnet_link_parse() {
    let uri = "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=test&tr=http://tracker.example.com/announce";
    let magnet = MagnetLink::parse(uri).unwrap();

    assert!(magnet.info_hash.is_v1());
    assert_eq!(magnet.display_name, Some("test".to_string()));
    assert_eq!(magnet.trackers.len(), 1);
}

#[test]
fn test_magnet_link_roundtrip() {
    let original = "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=test";
    let magnet = MagnetLink::parse(original).unwrap();
    let uri = magnet.to_uri();

    assert!(uri.contains("xt=urn:btih:0123456789abcdef0123456789abcdef01234567"));
    assert!(uri.contains("dn=test"));
}

#[test]
fn test_merkle_tree() {
    let hashes: Vec<[u8; 32]> = (0..4)
        .map(|i| {
            let mut h = [0u8; 32];
            h[0] = i;
            h
        })
        .collect();

    let tree = MerkleTree::from_piece_hashes(hashes.clone());
    assert!(tree.root().is_some());

    let proof = tree.proof(0).unwrap();
    let root = tree.root().unwrap();
    assert!(MerkleTree::verify(&root, &hashes[0], 0, &proof));
}

#[test]
fn test_merkle_tree_single_leaf() {
    let hash = [42u8; 32];
    let tree = MerkleTree::from_piece_hashes(vec![hash]);

    assert!(tree.root().is_some());
    assert_eq!(tree.leaf_count(), 1);
}

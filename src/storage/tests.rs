use super::*;
use std::path::PathBuf;
use tempfile::TempDir;

fn create_test_storage(temp: &TempDir, piece_length: u64, file_size: u64) -> TorrentStorage {
    let base_path = temp.path().to_path_buf();
    let piece_count = file_size.div_ceil(piece_length) as usize;

    let files = vec![FileEntry::new(PathBuf::from("test.dat"), file_size, 0)];

    let pieces: Vec<PieceInfo> = (0..piece_count)
        .map(|i| {
            let offset = i as u64 * piece_length;
            let length = if i == piece_count - 1 {
                let rem = file_size % piece_length;
                if rem == 0 {
                    piece_length
                } else {
                    rem
                }
            } else {
                piece_length
            };
            PieceInfo::v1(i as u32, [0u8; 20], offset, length)
        })
        .collect();

    TorrentStorage::new(base_path, files, pieces, file_size, false).expect("test storage creation")
}

#[tokio::test]
async fn test_preallocate() {
    let temp = TempDir::new().unwrap();
    let storage = create_test_storage(&temp, 16384, 65536);

    storage.preallocate().await.unwrap();

    let path = temp.path().join("test.dat");
    let metadata = tokio::fs::metadata(&path).await.unwrap();
    assert_eq!(metadata.len(), 65536);
}

#[tokio::test]
async fn test_write_and_read_piece() {
    let temp = TempDir::new().unwrap();
    let storage = create_test_storage(&temp, 16384, 32768);

    storage.preallocate().await.unwrap();

    let data: Vec<u8> = (0..16384).map(|i| (i % 256) as u8).collect();
    storage.write_piece(0, &data).await.unwrap();

    let read_data = storage.read_piece(0).await.unwrap();
    assert_eq!(read_data.as_ref(), data.as_slice());
}

#[tokio::test]
async fn test_write_and_read_block() {
    let temp = TempDir::new().unwrap();
    let storage = create_test_storage(&temp, 32768, 65536);

    storage.preallocate().await.unwrap();

    let block_data: Vec<u8> = (0..16384).map(|i| (i % 256) as u8).collect();

    storage.write_block(0, 0, &block_data).await.unwrap();
    storage.write_block(0, 16384, &block_data).await.unwrap();

    let read_block = storage.read_block(0, 0, 16384).await.unwrap();
    assert_eq!(read_block.as_ref(), block_data.as_slice());

    let read_block2 = storage.read_block(0, 16384, 16384).await.unwrap();
    assert_eq!(read_block2.as_ref(), block_data.as_slice());
}

#[tokio::test]
async fn test_multifile_storage() {
    let temp = TempDir::new().unwrap();
    let base_path = temp.path().to_path_buf();

    let files = vec![
        FileEntry::new(PathBuf::from("file1.dat"), 10000, 0),
        FileEntry::new(PathBuf::from("file2.dat"), 10000, 10000),
    ];

    let pieces = vec![
        PieceInfo::v1(0, [0u8; 20], 0, 16384),
        PieceInfo::v1(1, [0u8; 20], 16384, 3616),
    ];

    let storage =
        TorrentStorage::new(base_path, files, pieces, 20000, false).expect("test storage creation");
    storage.preallocate().await.unwrap();

    let data: Vec<u8> = (0..16384).map(|i| (i % 256) as u8).collect();
    storage.write_piece(0, &data).await.unwrap();

    let read_data = storage.read_piece(0).await.unwrap();
    assert_eq!(read_data.as_ref(), data.as_slice());
}

#[tokio::test]
async fn test_disk_manager() {
    let temp = TempDir::new().unwrap();
    let storage = create_test_storage(&temp, 16384, 32768);
    storage.preallocate().await.unwrap();

    let manager = DiskManager::new();
    manager.register("test_hash".to_string(), storage);

    let data: Vec<u8> = (0..16384).map(|i| (i % 256) as u8).collect();
    manager.write_piece("test_hash", 0, &data).await.unwrap();

    let read_data = manager.read_piece("test_hash", 0).await.unwrap();
    assert_eq!(read_data.as_ref(), data.as_slice());

    manager.unregister("test_hash");
    assert!(manager.read_piece("test_hash", 0).await.is_err());
}

#[tokio::test]
async fn test_invalid_piece_index() {
    let temp = TempDir::new().unwrap();
    let storage = create_test_storage(&temp, 16384, 32768);
    storage.preallocate().await.unwrap();

    let result = storage.read_piece(999).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_invalid_block_offset() {
    let temp = TempDir::new().unwrap();
    let storage = create_test_storage(&temp, 16384, 32768);
    storage.preallocate().await.unwrap();

    let result = storage.read_block(0, 20000, 1000).await;
    assert!(result.is_err());
}

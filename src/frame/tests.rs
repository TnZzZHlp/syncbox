use super::*;

#[tokio::test]
async fn json_frames_preserve_boundaries_while_growing() {
    let value = "x".repeat(200_000);
    let (mut send, mut recv) = tokio::io::duplex(4096);
    let sending = async {
        write_json(&mut send, &value, 256 * 1024).await.unwrap();
        write_json(&mut send, &"next", 256 * 1024).await.unwrap();
    };
    let receiving = async {
        let first: String = read_json(&mut recv, 256 * 1024).await.unwrap();
        let second: String = read_json(&mut recv, 256 * 1024).await.unwrap();
        assert_eq!(first, value);
        assert_eq!(second, "next");
    };
    tokio::join!(sending, receiving);
}

#[tokio::test]
async fn truncated_large_frames_do_not_preallocate_the_announced_size() {
    let length = 96_u32 * 1024 * 1024;
    let header = length.to_be_bytes();
    let mut bytes = Vec::new();
    assert!(
        read_frame(&mut header.as_slice(), length as usize, &mut bytes)
            .await
            .is_err()
    );
    assert!(bytes.capacity() <= INITIAL_READ_BYTES);
}

#[tokio::test]
async fn frame_size_limits_apply_to_both_directions() {
    let mut output = Vec::new();
    assert!(write_json(&mut output, &"123456", 7).await.is_err());
    assert_eq!(output, [] as [u8; 0]);
    let header = 8_u32.to_be_bytes();
    let mut bytes = Vec::new();
    assert!(
        read_frame(&mut header.as_slice(), 7, &mut bytes)
            .await
            .is_err()
    );
    assert_eq!(bytes.capacity(), 0);
}

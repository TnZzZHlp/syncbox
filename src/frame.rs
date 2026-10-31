use anyhow::{Context, Result, bail};
use serde::{Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const INITIAL_READ_BYTES: usize = 64 * 1024;

pub async fn write_json<W: AsyncWrite + Unpin, T: Serialize + Sync>(
    writer: &mut W,
    value: &T,
    limit: usize,
) -> Result<()> {
    let payload = serde_json::to_vec(value).context("unable to serialize sync protocol message")?;
    if payload.len() > limit {
        bail!("sync protocol message exceeds its maximum size");
    }
    let length = u32::try_from(payload.len()).context("sync protocol message is too large")?;
    writer
        .write_all(&length.to_be_bytes())
        .await
        .context("unable to write sync protocol frame length")?;
    writer
        .write_all(&payload)
        .await
        .context("unable to write sync protocol frame")?;
    Ok(())
}

pub async fn read_json<R: AsyncRead + Unpin, T: DeserializeOwned>(
    reader: &mut R,
    limit: usize,
) -> Result<T> {
    let mut bytes = Vec::new();
    read_frame(reader, limit, &mut bytes).await?;
    serde_json::from_slice(&bytes).context("unable to parse sync protocol frame")
}

async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    limit: usize,
    bytes: &mut Vec<u8>,
) -> Result<()> {
    let mut header = [0_u8; 4];
    reader
        .read_exact(&mut header)
        .await
        .context("unable to read sync protocol frame length")?;
    let length = usize::try_from(u32::from_be_bytes(header))
        .context("sync protocol frame length overflow")?;
    if length > limit {
        bail!("sync protocol frame exceeds its maximum size");
    }
    bytes.clear();
    while bytes.len() < length {
        if bytes.len() == bytes.capacity() {
            let capacity = bytes
                .capacity()
                .saturating_mul(2)
                .max(INITIAL_READ_BYTES)
                .min(length);
            bytes
                .try_reserve_exact(capacity - bytes.len())
                .context("unable to allocate sync protocol frame")?;
        }
        let start = bytes.len();
        bytes.resize(bytes.capacity().min(length), 0);
        reader
            .read_exact(&mut bytes[start..])
            .await
            .context("unable to read sync protocol frame")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
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
}

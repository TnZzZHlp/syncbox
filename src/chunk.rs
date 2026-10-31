use anyhow::{Context, Result, bail};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_CHUNK_BYTES: usize = 1024 * 1024;

pub async fn write_chunk<W: AsyncWrite + Unpin>(
    writer: &mut W,
    file_index: u32,
    offset: u64,
    data: &[u8],
) -> Result<()> {
    if data.is_empty() || data.len() > MAX_CHUNK_BYTES {
        bail!("chunk frame has an invalid payload length");
    }
    let length = u32::try_from(data.len()).context("chunk payload length overflow")?;
    let mut header = [0_u8; 16];
    header[..4].copy_from_slice(&file_index.to_be_bytes());
    header[4..12].copy_from_slice(&offset.to_be_bytes());
    header[12..].copy_from_slice(&length.to_be_bytes());
    writer
        .write_all(&header)
        .await
        .context("unable to write chunk header")?;
    writer
        .write_all(data)
        .await
        .context("unable to write chunk payload")?;
    Ok(())
}

pub async fn read_chunk<R: AsyncRead + Unpin>(
    reader: &mut R,
    file_index: u32,
    offset: u64,
    remaining: u64,
    buffer: &mut Vec<u8>,
) -> Result<usize> {
    let mut header = [0_u8; 16];
    reader
        .read_exact(&mut header)
        .await
        .context("unable to read chunk header")?;
    if header[..4] != file_index.to_be_bytes() || header[4..12] != offset.to_be_bytes() {
        bail!("chunk frame does not match the requested transfer");
    }
    let length = u32::from_be_bytes(header[12..].try_into()?);
    if length == 0 || u64::from(length) > remaining || u64::from(length) > MAX_CHUNK_BYTES as u64 {
        bail!("chunk frame has an invalid payload length");
    }
    let length = usize::try_from(length).context("chunk payload length overflow")?;
    if buffer.len() < length {
        buffer.resize(length, 0);
    }
    reader
        .read_exact(&mut buffer[..length])
        .await
        .context("unable to read chunk payload")?;
    Ok(length)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn binary_chunks_preserve_resumed_offsets_and_file_order() {
        let payload = vec![0xa5; MAX_CHUNK_BYTES];
        let (mut sender, mut receiver) = tokio::io::duplex(4096);
        let send = async {
            write_chunk(&mut sender, 0, 73, &payload).await.unwrap();
            write_chunk(&mut sender, 1, 0, b"next").await.unwrap();
        };
        let receive = async {
            let mut buffer = Vec::new();
            let count = read_chunk(&mut receiver, 0, 73, MAX_CHUNK_BYTES as u64, &mut buffer)
                .await
                .unwrap();
            assert_eq!(&buffer[..count], payload.as_slice());
            let count = read_chunk(&mut receiver, 1, 0, 4, &mut buffer)
                .await
                .unwrap();
            assert_eq!(&buffer[..count], b"next");
        };
        tokio::join!(send, receive);
    }

    #[tokio::test]
    async fn invalid_chunk_headers_are_rejected_before_allocation() {
        for (index, offset, length, remaining) in [
            (1_u32, 0_u64, 1_u32, 1_u64),
            (0, 1, 1, 1),
            (0, 0, 0, 1),
            (0, 0, u32::MAX, u64::MAX),
            (0, 0, 2, 1),
        ] {
            let mut header = Vec::new();
            header.extend_from_slice(&index.to_be_bytes());
            header.extend_from_slice(&offset.to_be_bytes());
            header.extend_from_slice(&length.to_be_bytes());
            let mut buffer = Vec::new();
            assert!(
                read_chunk(&mut header.as_slice(), 0, 0, remaining, &mut buffer)
                    .await
                    .is_err()
            );
            assert_eq!(buffer.capacity(), 0);
        }
    }

    #[tokio::test]
    async fn truncated_chunk_payloads_are_rejected() {
        let mut bytes = Vec::new();
        write_chunk(&mut bytes, 0, 0, b"payload").await.unwrap();
        bytes.pop();
        assert!(
            read_chunk(&mut bytes.as_slice(), 0, 0, 7, &mut Vec::new())
                .await
                .is_err()
        );
    }
}

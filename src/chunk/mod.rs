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
mod tests;

use anyhow::{Context, Result, anyhow, bail};
use hmac::{Hmac, KeyInit as _, Mac as _};
use iroh::EndpointId;
use sha2::Sha256;
use subtle::ConstantTimeEq as _;

use crate::types::{PROTOCOL_VERSION, ShareConfig, ShareId};

use tokio::io::AsyncReadExt as _;

use super::io::RecvStream;

pub const AUTH_MAGIC: [u8; 4] = *b"SBXA";
pub const CLIENT_HELLO_LENGTH: usize = 4 + 2 + 32 + 32 + 32 + 32;
pub const SERVER_HELLO_LENGTH: usize = 4 + 2 + 32 + 32 + 32 + 32 + 32;
pub type HmacSha256 = Hmac<Sha256>;

pub fn make_client_hello(
    config: &ShareConfig,
    client: &EndpointId,
    server: &EndpointId,
    nonce: [u8; 32],
) -> [u8; CLIENT_HELLO_LENGTH] {
    let mut output = [0_u8; CLIENT_HELLO_LENGTH];
    let mut cursor = 0_usize;
    put(&mut output, &mut cursor, &AUTH_MAGIC);
    put(&mut output, &mut cursor, &PROTOCOL_VERSION.to_be_bytes());
    put(&mut output, &mut cursor, config.share_id.as_bytes());
    put(&mut output, &mut cursor, client.as_bytes());
    put(&mut output, &mut cursor, &nonce);
    let proof = client_proof(config, client, server, nonce);
    put(&mut output, &mut cursor, &proof);
    output
}

pub fn make_server_hello(
    config: &ShareConfig,
    client: &EndpointId,
    server: &EndpointId,
    client_nonce: [u8; 32],
    server_nonce: [u8; 32],
) -> [u8; SERVER_HELLO_LENGTH] {
    let mut output = [0_u8; SERVER_HELLO_LENGTH];
    let mut cursor = 0_usize;
    put(&mut output, &mut cursor, &AUTH_MAGIC);
    put(&mut output, &mut cursor, &PROTOCOL_VERSION.to_be_bytes());
    put(&mut output, &mut cursor, config.share_id.as_bytes());
    put(&mut output, &mut cursor, server.as_bytes());
    put(&mut output, &mut cursor, &client_nonce);
    put(&mut output, &mut cursor, &server_nonce);
    let proof = server_proof(config, client, server, client_nonce, server_nonce);
    put(&mut output, &mut cursor, &proof);
    output
}

pub struct ClientHello {
    pub(crate) share_id: ShareId,
    client_id: EndpointId,
    pub(crate) nonce: [u8; 32],
    proof: [u8; 32],
}

pub struct ServerHello {
    share_id: ShareId,
    server_id: EndpointId,
    client_nonce: [u8; 32],
    server_nonce: [u8; 32],
    proof: [u8; 32],
}

pub async fn read_client_hello(recv: &mut RecvStream) -> Result<ClientHello> {
    let mut bytes = [0_u8; CLIENT_HELLO_LENGTH];
    recv.read_exact(&mut bytes)
        .await
        .context("unable to read sync authentication")?;
    let mut cursor = 0_usize;
    if take::<4>(&bytes, &mut cursor)? != AUTH_MAGIC {
        bail!("invalid sync authentication magic");
    }
    if u16::from_be_bytes(take(&bytes, &mut cursor)?) != PROTOCOL_VERSION {
        bail!("unsupported sync protocol version");
    }
    let share_id = ShareId(take(&bytes, &mut cursor)?);
    let client_bytes: [u8; 32] = take(&bytes, &mut cursor)?;
    let client_id = EndpointId::from_bytes(&client_bytes)
        .map_err(|_| anyhow!("invalid sync client endpoint ID"))?;
    let nonce = take(&bytes, &mut cursor)?;
    let proof = take(&bytes, &mut cursor)?;
    Ok(ClientHello {
        share_id,
        client_id,
        nonce,
        proof,
    })
}

pub async fn read_server_hello(recv: &mut RecvStream) -> Result<ServerHello> {
    let mut bytes = [0_u8; SERVER_HELLO_LENGTH];
    recv.read_exact(&mut bytes)
        .await
        .context("unable to read sync authentication")?;
    let mut cursor = 0_usize;
    if take::<4>(&bytes, &mut cursor)? != AUTH_MAGIC {
        bail!("invalid sync authentication magic");
    }
    if u16::from_be_bytes(take(&bytes, &mut cursor)?) != PROTOCOL_VERSION {
        bail!("unsupported sync protocol version");
    }
    let share_id = ShareId(take(&bytes, &mut cursor)?);
    let server_bytes: [u8; 32] = take(&bytes, &mut cursor)?;
    let server_id = EndpointId::from_bytes(&server_bytes)
        .map_err(|_| anyhow!("invalid sync server endpoint ID"))?;
    let client_nonce = take(&bytes, &mut cursor)?;
    let server_nonce = take(&bytes, &mut cursor)?;
    let proof = take(&bytes, &mut cursor)?;
    Ok(ServerHello {
        share_id,
        server_id,
        client_nonce,
        server_nonce,
        proof,
    })
}

pub fn validate_client_hello(
    hello: &ClientHello,
    config: &ShareConfig,
    transport_client: &EndpointId,
    server: &EndpointId,
) -> Result<()> {
    if hello.share_id != config.share_id || hello.client_id != *transport_client {
        bail!("sync client authentication is not bound to its transport identity");
    }
    let expected = client_proof(config, &hello.client_id, server, hello.nonce);
    if expected.ct_eq(&hello.proof).unwrap_u8() != 1 {
        bail!("sync client authentication failed");
    }
    Ok(())
}

pub fn validate_server_hello(
    hello: &ServerHello,
    config: &ShareConfig,
    client: &EndpointId,
    transport_server: &EndpointId,
    expected_client_nonce: [u8; 32],
) -> Result<()> {
    if hello.share_id != config.share_id
        || hello.server_id != *transport_server
        || hello.client_nonce != expected_client_nonce
    {
        bail!("sync server authentication is not bound to its transport identity");
    }
    let expected = server_proof(
        config,
        client,
        &hello.server_id,
        hello.client_nonce,
        hello.server_nonce,
    );
    if expected.ct_eq(&hello.proof).unwrap_u8() != 1 {
        bail!("sync server authentication failed");
    }
    Ok(())
}

pub fn client_proof(
    config: &ShareConfig,
    client: &EndpointId,
    server: &EndpointId,
    nonce: [u8; 32],
) -> [u8; 32] {
    proof(config, b"client", client, server, &[nonce.as_slice()])
}

pub fn server_proof(
    config: &ShareConfig,
    client: &EndpointId,
    server: &EndpointId,
    client_nonce: [u8; 32],
    server_nonce: [u8; 32],
) -> [u8; 32] {
    proof(
        config,
        b"server",
        client,
        server,
        &[client_nonce.as_slice(), server_nonce.as_slice()],
    )
}

pub fn proof(
    config: &ShareConfig,
    role: &[u8],
    client: &EndpointId,
    server: &EndpointId,
    nonces: &[&[u8]],
) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(config.share_secret.as_bytes())
        .expect("HMAC accepts a fixed-size key");
    mac.update(b"syncbox/auth/v1");
    mac.update(role);
    mac.update(config.share_id.as_bytes());
    mac.update(client.as_bytes());
    mac.update(server.as_bytes());
    for nonce in nonces {
        mac.update(nonce);
    }
    let bytes = mac.finalize().into_bytes();
    let mut output = [0_u8; 32];
    output.copy_from_slice(&bytes);
    output
}

pub fn put<const N: usize>(target: &mut [u8], cursor: &mut usize, value: &[u8; N]) {
    target[*cursor..*cursor + N].copy_from_slice(value);
    *cursor += N;
}

pub fn take<const N: usize>(source: &[u8], cursor: &mut usize) -> Result<[u8; N]> {
    let end = cursor
        .checked_add(N)
        .ok_or_else(|| anyhow!("sync authentication length overflow"))?;
    let bytes = source
        .get(*cursor..end)
        .ok_or_else(|| anyhow!("sync authentication is truncated"))?;
    *cursor = end;
    bytes
        .try_into()
        .map_err(|_| anyhow!("sync authentication has an invalid length"))
}

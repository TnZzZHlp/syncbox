use std::fmt;

use anyhow::{Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use iroh::EndpointId;
use subtle::ConstantTimeEq as _;

use crate::types::{PROTOCOL_VERSION, ShareId, ShareSecret};

pub const TICKET_PREFIX: &str = "syncbox1:";
const TICKET_MAGIC: [u8; 4] = *b"SBTK";
const CHECKSUM_LENGTH: usize = 16;
pub const MAX_INITIAL_PEERS: usize = 64;
pub const MAX_TICKET_TEXT_LENGTH: usize = 4096;
const TICKET_CHECKSUM_DOMAIN: &[u8] = b"syncbox-ticket-v1";

#[derive(Clone)]
pub struct ShareTicket {
    pub protocol_version: u16,
    pub share_id: ShareId,
    pub share_secret: ShareSecret,
    pub initial_peers: Vec<EndpointId>,
}

impl ShareTicket {
    pub fn new(
        share_id: ShareId,
        share_secret: ShareSecret,
        mut initial_peers: Vec<EndpointId>,
    ) -> Result<Self> {
        initial_peers.sort_by_key(std::string::ToString::to_string);
        let ticket = Self {
            protocol_version: PROTOCOL_VERSION,
            share_id,
            share_secret,
            initial_peers,
        };
        ticket.validate()?;
        Ok(ticket)
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            bail!(
                "unsupported ShareTicket protocol version {}",
                self.protocol_version
            );
        }
        if self.initial_peers.len() > MAX_INITIAL_PEERS {
            bail!("ShareTicket contains too many initial peers");
        }
        let mut previous: Option<String> = None;
        for endpoint_id in &self.initial_peers {
            let value = endpoint_id.to_string();
            if previous.as_ref().is_some_and(|previous| previous >= &value) {
                bail!("ShareTicket initial peers must be unique and sorted");
            }
            previous = Some(value);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<String> {
        self.validate()?;
        let peer_count: u16 = self
            .initial_peers
            .len()
            .try_into()
            .map_err(|_| anyhow!("ShareTicket contains too many initial peers"))?;
        let capacity = 4 + 2 + 2 + 32 + 32 + usize::from(peer_count) * 32 + CHECKSUM_LENGTH;
        let mut bytes = Vec::with_capacity(capacity);
        bytes.extend_from_slice(&TICKET_MAGIC);
        bytes.extend_from_slice(&self.protocol_version.to_be_bytes());
        bytes.extend_from_slice(&peer_count.to_be_bytes());
        bytes.extend_from_slice(self.share_id.as_bytes());
        bytes.extend_from_slice(self.share_secret.as_bytes());
        for endpoint_id in &self.initial_peers {
            bytes.extend_from_slice(endpoint_id.as_bytes());
        }
        let checksum = ticket_checksum(&bytes);
        bytes.extend_from_slice(&checksum);
        let encoded = URL_SAFE_NO_PAD.encode(bytes);
        let value = format!("{TICKET_PREFIX}{encoded}");
        if value.len() > MAX_TICKET_TEXT_LENGTH {
            bail!("ShareTicket exceeds the maximum supported length");
        }
        Ok(value)
    }

    pub fn parse(value: &str) -> Result<Self> {
        if value.len() > MAX_TICKET_TEXT_LENGTH {
            bail!("ShareTicket exceeds the maximum supported length");
        }
        let encoded = value
            .strip_prefix(TICKET_PREFIX)
            .ok_or_else(|| anyhow!("ShareTicket must start with {TICKET_PREFIX}"))?;
        if encoded.is_empty()
            || encoded
                .bytes()
                .any(|byte| !(byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'))
        {
            bail!("ShareTicket is not canonical base64url data");
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| anyhow!("ShareTicket is not valid base64url data"))?;
        if URL_SAFE_NO_PAD.encode(&bytes) != encoded {
            bail!("ShareTicket must use canonical unpadded base64url encoding");
        }
        let minimum_length = 4 + 2 + 2 + 32 + 32 + CHECKSUM_LENGTH;
        if bytes.len() < minimum_length {
            bail!("ShareTicket is truncated");
        }
        let content_length = bytes.len() - CHECKSUM_LENGTH;
        let expected_checksum = ticket_checksum(&bytes[..content_length]);
        if expected_checksum
            .ct_eq(&bytes[content_length..])
            .unwrap_u8()
            != 1
        {
            bail!("ShareTicket checksum does not match");
        }

        let mut cursor = 0_usize;
        let magic: [u8; 4] = take(&bytes[..content_length], &mut cursor)?;
        if magic != TICKET_MAGIC {
            bail!("ShareTicket has an unknown format");
        }
        let protocol_version = u16::from_be_bytes(take(&bytes[..content_length], &mut cursor)?);
        if protocol_version != PROTOCOL_VERSION {
            bail!("unsupported ShareTicket protocol version {protocol_version}");
        }
        let peer_count = usize::from(u16::from_be_bytes(take(
            &bytes[..content_length],
            &mut cursor,
        )?));
        if peer_count > MAX_INITIAL_PEERS {
            bail!("ShareTicket contains too many initial peers");
        }
        let expected_content_length = 4 + 2 + 2 + 32 + 32 + peer_count * 32;
        if content_length != expected_content_length {
            bail!("ShareTicket has an invalid length or unsupported trailing fields");
        }
        let share_id = ShareId(take(&bytes[..content_length], &mut cursor)?);
        let share_secret = ShareSecret::from_bytes(take(&bytes[..content_length], &mut cursor)?);
        let mut initial_peers = Vec::with_capacity(peer_count);
        for _ in 0..peer_count {
            let bytes: [u8; 32] = take(&bytes[..content_length], &mut cursor)?;
            let endpoint_id = EndpointId::from_bytes(&bytes)
                .map_err(|_| anyhow!("ShareTicket contains an invalid initial endpoint ID"))?;
            initial_peers.push(endpoint_id);
        }
        if cursor != content_length {
            bail!("ShareTicket has unsupported trailing fields");
        }
        let ticket = Self {
            protocol_version,
            share_id,
            share_secret,
            initial_peers,
        };
        ticket.validate()?;
        Ok(ticket)
    }
}

impl fmt::Debug for ShareTicket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShareTicket")
            .field("protocol_version", &self.protocol_version)
            .field("share_id", &self.share_id)
            .field("share_secret", &"REDACTED")
            .field("initial_peers", &self.initial_peers.len())
            .finish()
    }
}

fn take<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Result<[u8; N]> {
    let end = cursor
        .checked_add(N)
        .ok_or_else(|| anyhow!("ShareTicket length overflow"))?;
    let part = bytes
        .get(*cursor..end)
        .ok_or_else(|| anyhow!("ShareTicket is truncated"))?;
    *cursor = end;
    part.try_into()
        .map_err(|_| anyhow!("ShareTicket has an invalid field length"))
}

fn ticket_checksum(bytes: &[u8]) -> [u8; CHECKSUM_LENGTH] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(TICKET_CHECKSUM_DOMAIN);
    hasher.update(bytes);
    let mut checksum = [0_u8; CHECKSUM_LENGTH];
    checksum.copy_from_slice(&hasher.finalize().as_bytes()[..CHECKSUM_LENGTH]);
    checksum
}

#[cfg(test)]
mod tests {
    use iroh::SecretKey;

    use super::*;

    #[test]
    fn ticket_round_trip_is_canonical_and_deterministic() {
        let peer = SecretKey::from_bytes(&[7; 32]).public();
        let ticket = ShareTicket::new(
            ShareId([3; 32]),
            ShareSecret::from_bytes([4; 32]),
            vec![peer],
        )
        .unwrap();
        let encoded = ticket.encode().unwrap();
        assert!(encoded.starts_with(TICKET_PREFIX));
        let parsed = ShareTicket::parse(&encoded).unwrap();
        assert_eq!(parsed.share_id, ticket.share_id);
        assert_eq!(parsed.share_secret, ticket.share_secret);
        assert_eq!(parsed.initial_peers[0], peer);
        assert_eq!(parsed.encode().unwrap(), encoded);
    }

    #[test]
    fn ticket_rejects_padding_and_checksum_tampering() {
        let peer = SecretKey::from_bytes(&[8; 32]).public();
        let ticket = ShareTicket::new(
            ShareId([5; 32]),
            ShareSecret::from_bytes([6; 32]),
            vec![peer],
        )
        .unwrap()
        .encode()
        .unwrap();
        assert!(ShareTicket::parse(&(ticket.clone() + "=")).is_err());
        let mut altered = ticket.into_bytes();
        let last = altered.len() - 1;
        altered[last] = if altered[last] == b'A' { b'B' } else { b'A' };
        assert!(ShareTicket::parse(std::str::from_utf8(&altered).unwrap()).is_err());
    }

    #[test]
    fn ticket_canonicalizes_initial_peer_order() {
        let first = SecretKey::from_bytes(&[10; 32]).public();
        let second = SecretKey::from_bytes(&[11; 32]).public();
        let left = ShareTicket::new(
            ShareId([12; 32]),
            ShareSecret::from_bytes([13; 32]),
            vec![first, second],
        )
        .unwrap()
        .encode()
        .unwrap();
        let right = ShareTicket::new(
            ShareId([12; 32]),
            ShareSecret::from_bytes([13; 32]),
            vec![second, first],
        )
        .unwrap()
        .encode()
        .unwrap();
        assert_eq!(left, right);
    }
}

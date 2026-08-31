//! Secret handling primitives.
//!
//! Bearer/session/confirmation values are stored as one-way SHA-256 digests.
//! Google refresh tokens are recoverable credentials and therefore use a
//! versioned XChaCha20-Poly1305 envelope with explicit associated data.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fmt};
use subtle::ConstantTimeEq;

pub const ENVELOPE_PREFIX: &str = "am1";

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("invalid token digest")]
    InvalidDigest,
    #[error("invalid keyring: {0}")]
    InvalidKeyring(String),
    #[error("keyring has no active key")]
    NoActiveKey,
    #[error("encryption key version {0} is unavailable")]
    UnknownKeyVersion(u32),
    #[error("invalid encrypted envelope")]
    InvalidEnvelope,
    #[error("encrypted token authentication failed")]
    AuthenticationFailed,
}

#[derive(Clone)]
pub struct Keyring {
    keys: BTreeMap<u32, [u8; 32]>,
    active: u32,
}

impl fmt::Debug for Keyring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keyring")
            .field("versions", &self.keys.keys().collect::<Vec<_>>())
            .field("active", &self.active)
            .finish()
    }
}

impl Keyring {
    pub fn new(active: u32, keys: BTreeMap<u32, [u8; 32]>) -> Result<Self, CryptoError> {
        if active == 0 || !keys.contains_key(&active) || keys.is_empty() {
            return Err(CryptoError::NoActiveKey);
        }
        Ok(Self { keys, active })
    }

    /// Parse `active=2;v1=<base64>;v2=<base64>` (commas/newlines also work).
    /// Keys may be URL-safe base64 without padding, standard base64, or hex.
    pub fn parse(value: &str) -> Result<Self, CryptoError> {
        let mut keys = BTreeMap::new();
        let mut active = None;
        for item in value.split([';', ',', '\n']) {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }
            let (name, encoded) = item.split_once(['=', ':']).ok_or_else(|| {
                CryptoError::InvalidKeyring(format!("entry {item:?} is not version=value"))
            })?;
            let name = name.trim().trim_start_matches('v');
            if name.eq_ignore_ascii_case("active") {
                active = Some(
                    encoded
                        .trim()
                        .trim_start_matches('v')
                        .parse::<u32>()
                        .map_err(|_| {
                            CryptoError::InvalidKeyring(
                                "active version is not an integer".to_owned(),
                            )
                        })?,
                );
                continue;
            }
            let version = name
                .parse::<u32>()
                .map_err(|_| CryptoError::InvalidKeyring(format!("invalid version {name:?}")))?;
            if version == 0 {
                return Err(CryptoError::InvalidKeyring(
                    "version must be positive".to_owned(),
                ));
            }
            let bytes = decode_key(encoded.trim()).ok_or_else(|| {
                CryptoError::InvalidKeyring(format!("key v{version} is not 32 bytes"))
            })?;
            keys.insert(version, bytes);
        }
        let active = active
            .or_else(|| keys.keys().next_back().copied())
            .ok_or(CryptoError::NoActiveKey)?;
        Self::new(active, keys)
    }

    pub fn active_version(&self) -> u32 {
        self.active
    }

    pub fn versions(&self) -> impl Iterator<Item = u32> + '_ {
        self.keys.keys().copied()
    }

    fn key(&self, version: u32) -> Result<&[u8; 32], CryptoError> {
        self.keys
            .get(&version)
            .ok_or(CryptoError::UnknownKeyVersion(version))
    }
}

fn decode_key(value: &str) -> Option<[u8; 32]> {
    let bytes = if value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()) {
        hex::decode(value).ok()?
    } else {
        URL_SAFE_NO_PAD
            .decode(value)
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(value))
            .or_else(|_| hex::decode(value))
            .ok()?
    };
    bytes.try_into().ok()
}

/// Return a stable, printable digest. The input is never retained by this API.
pub fn hash_token(token: impl AsRef<[u8]>) -> String {
    hex::encode(Sha256::digest(token.as_ref()))
}

pub fn verify_token(
    token: impl AsRef<[u8]>,
    expected_hex_digest: &str,
) -> Result<bool, CryptoError> {
    let expected = hex::decode(expected_hex_digest).map_err(|_| CryptoError::InvalidDigest)?;
    if expected.len() != 32 {
        return Err(CryptoError::InvalidDigest);
    }
    Ok(Sha256::digest(token.as_ref())
        .as_slice()
        .ct_eq(expected.as_slice())
        .into())
}

pub fn aad_for_refresh_token(user_id: &str, connection_id: &str) -> String {
    format!(
        "agentmail:refresh-token:user:{user_id}:connection:{connection_id}:credential:google-refresh-token"
    )
}

pub fn encrypt_token(
    token: impl AsRef<[u8]>,
    aad: impl AsRef<[u8]>,
    keyring: &Keyring,
) -> Result<String, CryptoError> {
    let version = keyring.active_version();
    let cipher = XChaCha20Poly1305::new_from_slice(keyring.key(version)?)
        .map_err(|_| CryptoError::UnknownKeyVersion(version))?;
    let nonce_bytes: [u8; 24] = rand::random();
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: token.as_ref(),
                aad: aad.as_ref(),
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    Ok(format!(
        "{ENVELOPE_PREFIX}.{version}.{}.{}",
        URL_SAFE_NO_PAD.encode(nonce_bytes),
        URL_SAFE_NO_PAD.encode(ciphertext)
    ))
}

pub fn decrypt_token(
    envelope: &str,
    aad: impl AsRef<[u8]>,
    keyring: &Keyring,
) -> Result<Vec<u8>, CryptoError> {
    let mut parts = envelope.split('.');
    if parts.next() != Some(ENVELOPE_PREFIX) {
        return Err(CryptoError::InvalidEnvelope);
    }
    let version = parts
        .next()
        .and_then(|v| v.parse::<u32>().ok())
        .ok_or(CryptoError::InvalidEnvelope)?;
    let nonce_bytes = parts
        .next()
        .and_then(|v| URL_SAFE_NO_PAD.decode(v).ok())
        .ok_or(CryptoError::InvalidEnvelope)?;
    let ciphertext = parts
        .next()
        .and_then(|v| URL_SAFE_NO_PAD.decode(v).ok())
        .ok_or(CryptoError::InvalidEnvelope)?;
    if parts.next().is_some() || nonce_bytes.len() != 24 {
        return Err(CryptoError::InvalidEnvelope);
    }
    let cipher = XChaCha20Poly1305::new_from_slice(keyring.key(version)?)
        .map_err(|_| CryptoError::UnknownKeyVersion(version))?;
    cipher
        .decrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload {
                msg: &ciphertext,
                aad: aad.as_ref(),
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)
}

pub fn encrypt_refresh_token(
    token: impl AsRef<[u8]>,
    user_id: &str,
    connection_id: &str,
    keyring: &Keyring,
) -> Result<String, CryptoError> {
    encrypt_token(
        token,
        aad_for_refresh_token(user_id, connection_id),
        keyring,
    )
}

pub fn decrypt_refresh_token(
    envelope: &str,
    user_id: &str,
    connection_id: &str,
    keyring: &Keyring,
) -> Result<Vec<u8>, CryptoError> {
    decrypt_token(
        envelope,
        aad_for_refresh_token(user_id, connection_id),
        keyring,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ring() -> Keyring {
        Keyring::parse("v1=0707070707070707070707070707070707070707070707070707070707070707;v2=0808080808080808080808080808080808080808080808080808080808080808;active=v2").unwrap()
    }

    #[test]
    fn hashes_verify_without_plaintext_storage() {
        let digest = hash_token("secret");
        assert!(verify_token("secret", &digest).unwrap());
        assert!(!verify_token("other", &digest).unwrap());
        assert!(verify_token("secret", "00").is_err());
    }

    #[test]
    fn envelope_round_trips_and_aad_binds_context() {
        let keyring = ring();
        let envelope =
            encrypt_refresh_token("refresh-value", "user-1", "conn-1", &keyring).unwrap();
        assert!(envelope.starts_with("am1.2."));
        assert_eq!(
            decrypt_refresh_token(&envelope, "user-1", "conn-1", &keyring).unwrap(),
            b"refresh-value"
        );
        assert!(decrypt_refresh_token(&envelope, "user-2", "conn-1", &keyring).is_err());
        assert!(
            decrypt_refresh_token(
                &envelope,
                "user-1",
                "conn-1",
                &Keyring::parse(
                    "v1=0707070707070707070707070707070707070707070707070707070707070707;active=v1"
                )
                .unwrap()
            )
            .is_err()
        );
    }
}

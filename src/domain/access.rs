//! Bearer Access Key value objects and grant policy.

use crate::domain::identity::{ConnectionId, UserId};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fmt};
use subtle::ConstantTimeEq;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AccessKeyId(Uuid);
impl AccessKeyId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
    pub const fn from_uuid(v: Uuid) -> Self {
        Self(v)
    }
    pub const fn into_uuid(self) -> Uuid {
        self.0
    }
}
impl Default for AccessKeyId {
    fn default() -> Self {
        Self::new()
    }
}
impl fmt::Display for AccessKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeyPublicId(Uuid);
impl KeyPublicId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
    pub(crate) const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }
}
impl Default for KeyPublicId {
    fn default() -> Self {
        Self::new()
    }
}
impl fmt::Display for KeyPublicId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessKeyStatus {
    #[default]
    Active,
    Revoked,
}
impl AccessKeyStatus {
    pub const fn accepts_requests(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GrantSet(BTreeSet<ConnectionId>);
impl GrantSet {
    pub fn new(connections: impl IntoIterator<Item = ConnectionId>) -> Self {
        Self(connections.into_iter().collect())
    }
    pub fn empty() -> Self {
        Self(BTreeSet::new())
    }
    pub fn contains(&self, connection: ConnectionId) -> bool {
        self.0.contains(&connection)
    }
    pub fn grant(&mut self, connection: ConnectionId) -> bool {
        self.0.insert(connection)
    }
    pub fn revoke(&mut self, connection: ConnectionId) -> bool {
        self.0.remove(&connection)
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn iter(&self) -> impl Iterator<Item = &ConnectionId> {
        self.0.iter()
    }
}
impl Default for GrantSet {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct AccessKey {
    pub id: AccessKeyId,
    pub owner_id: UserId,
    pub name: String,
    pub public_id: KeyPublicId,
    /// Argon2id PHC string; it is never included in API or debug output.
    #[serde(skip_serializing)]
    secret_hash: String,
    pub generation: u64,
    pub status: AccessKeyStatus,
    pub grants: GrantSet,
}

impl fmt::Debug for AccessKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccessKey")
            .field("id", &self.id)
            .field("owner_id", &self.owner_id)
            .field("name", &self.name)
            .field("public_id", &self.public_id)
            .field("generation", &self.generation)
            .field("status", &self.status)
            .field("grants", &self.grants)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewAccessKey {
    pub key: AccessKey,
    pub credential: String,
}

pub(crate) struct PersistedAccessKey {
    pub id: AccessKeyId,
    pub owner_id: UserId,
    pub name: String,
    pub public_id: KeyPublicId,
    pub secret_hash: String,
    pub generation: u64,
    pub status: AccessKeyStatus,
    pub grants: GrantSet,
}

impl AccessKey {
    /// Rebuild a key loaded from durable storage for domain transitions.
    pub(crate) fn from_persisted(value: PersistedAccessKey) -> Self {
        Self {
            id: value.id,
            owner_id: value.owner_id,
            name: value.name,
            public_id: value.public_id,
            secret_hash: value.secret_hash,
            generation: value.generation,
            status: value.status,
            grants: value.grants,
        }
    }

    pub(crate) fn secret_hash(&self) -> &str {
        &self.secret_hash
    }

    pub fn generate(
        owner_id: UserId,
        name: impl Into<String>,
        connections: impl IntoIterator<Item = ConnectionId>,
    ) -> Result<NewAccessKey, AccessError> {
        let name = name.into();
        validate_name(&name)?;
        let public_id = KeyPublicId::new();
        let secret = random_secret();
        let credential = format!("amk_{public_id}.{secret}");
        let key = Self {
            id: AccessKeyId::new(),
            owner_id,
            name,
            public_id,
            secret_hash: hash_secret(&secret)?,
            generation: 1,
            status: AccessKeyStatus::Active,
            grants: GrantSet::new(connections),
        };
        Ok(NewAccessKey { key, credential })
    }

    pub fn verify_credential(&self, credential: &str) -> Result<bool, AccessError> {
        let parsed = parse_credential(credential)?;
        if parsed.public_id != self.public_id || !self.status.accepts_requests() {
            return Ok(false);
        }
        verify_secret(&parsed.secret, &self.secret_hash)
    }
    pub fn allows(&self, connection: ConnectionId) -> bool {
        self.status.accepts_requests() && self.grants.contains(connection)
    }
    pub fn grant(&mut self, connection: ConnectionId) -> bool {
        self.grants.grant(connection)
    }
    pub fn revoke_grant(&mut self, connection: ConnectionId) -> bool {
        self.grants.revoke(connection)
    }
    pub fn revoke(&mut self) -> bool {
        if self.status.accepts_requests() {
            self.status = AccessKeyStatus::Revoked;
            self.generation = self.generation.saturating_add(1);
            true
        } else {
            false
        }
    }
    pub fn rotate(&mut self) -> Result<String, AccessError> {
        if !self.status.accepts_requests() {
            return Err(AccessError::Revoked);
        }
        let secret = random_secret();
        self.secret_hash = hash_secret(&secret)?;
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(AccessError::GenerationOverflow)?;
        Ok(format!("amk_{}.{secret}", self.public_id))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedCredential {
    pub public_id: KeyPublicId,
    pub secret: String,
}

pub fn parse_credential(value: &str) -> Result<ParsedCredential, AccessError> {
    let Some(value) = value.strip_prefix("amk_") else {
        return Err(AccessError::InvalidFormat);
    };
    let (id, secret) = value.split_once('.').ok_or(AccessError::InvalidFormat)?;
    if id.is_empty() || secret.is_empty() || secret.contains('.') {
        return Err(AccessError::InvalidFormat);
    }
    let public_id = Uuid::parse_str(id)
        .map(KeyPublicId)
        .map_err(|_| AccessError::InvalidFormat)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(secret)
        .map_err(|_| AccessError::InvalidSecret)?;
    if bytes.len() != 32 {
        return Err(AccessError::InvalidSecret);
    }
    Ok(ParsedCredential {
        public_id,
        secret: secret.to_owned(),
    })
}

pub fn hash_secret(secret: &str) -> Result<String, AccessError> {
    let mut salt_bytes = [0_u8; 16];
    rand::rng().fill_bytes(&mut salt_bytes);
    let salt = SaltString::encode_b64(&salt_bytes).map_err(|_| AccessError::HashFailed)?;
    Argon2::default()
        .hash_password(secret.as_bytes(), &salt)
        .map(|v| v.to_string())
        .map_err(|_| AccessError::HashFailed)
}
pub fn verify_secret(secret: &str, hash: &str) -> Result<bool, AccessError> {
    let parsed = PasswordHash::new(hash).map_err(|_| AccessError::InvalidHash)?;
    // Argon2's verifier uses a constant-time tag comparison. Keep the final
    // boolean comparison constant-time too, making the contract explicit.
    let valid = Argon2::default()
        .verify_password(secret.as_bytes(), &parsed)
        .is_ok();
    Ok(bool::from((valid as u8).ct_eq(&1)))
}
pub fn random_secret() -> String {
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn validate_name(name: &str) -> Result<(), AccessError> {
    if name.trim().is_empty() || name.len() > 120 || name.chars().any(|c| c.is_control()) {
        Err(AccessError::InvalidName)
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessError {
    InvalidFormat,
    InvalidSecret,
    InvalidHash,
    InvalidName,
    HashFailed,
    Revoked,
    GenerationOverflow,
}
impl fmt::Display for AccessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidFormat => "invalid access key format",
            Self::InvalidSecret => "invalid access key secret",
            Self::InvalidHash => "invalid stored secret hash",
            Self::InvalidName => "invalid access key name",
            Self::HashFailed => "could not hash access key secret",
            Self::Revoked => "access key is revoked",
            Self::GenerationOverflow => "access key generation overflow",
        })
    }
}
impl std::error::Error for AccessError {}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn format_hash_and_rotation() {
        let owner = UserId::new();
        let c = ConnectionId::new();
        let mut created = AccessKey::generate(owner, "test", [c]).unwrap();
        assert!(created.key.verify_credential(&created.credential).unwrap());
        assert!(created.credential.starts_with("amk_"));
        let old = created.credential;
        let new = created.key.rotate().unwrap();
        assert!(!created.key.verify_credential(&old).unwrap());
        assert!(created.key.verify_credential(&new).unwrap());
    }
    #[test]
    fn grant_is_required_even_for_single_connection() {
        let mut created = AccessKey::generate(UserId::new(), "test", []).unwrap();
        let c = ConnectionId::new();
        assert!(!created.key.allows(c));
        assert!(created.key.grant(c));
        assert!(created.key.allows(c));
        assert!(created.key.revoke_grant(c));
        assert!(!created.key.allows(c));
    }
    #[test]
    fn malformed_credentials_are_rejected() {
        assert!(parse_credential("Bearer nope").is_err());
        assert!(parse_credential("amk_00000000-0000-0000-0000-000000000000.AQ").is_err());
    }

    #[test]
    fn secret_hash_is_not_serialized_or_debugged() {
        let created = AccessKey::generate(UserId::new(), "test", []).unwrap();
        let json = serde_json::to_string(&created.key).unwrap();
        assert!(!json.contains("secret_hash"));
        assert!(!format!("{:?}", created.key).contains("secret_hash"));
    }
}

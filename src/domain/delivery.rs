//! Managed draft versions and the two-phase send confirmation state machine.

use crate::domain::{access::AccessKeyId, identity::ConnectionId};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use subtle::ConstantTimeEq;
use uuid::Uuid;

macro_rules! uuid_id {
    ($name:ident) => {
        #[derive(
            Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(Uuid);
        impl $name {
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }
            pub const fn from_uuid(v: Uuid) -> Self {
                Self(v)
            }
        }
        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }
    };
}
uuid_id!(DraftId);
uuid_id!(ConfirmationId);

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DraftVersion(String);
impl DraftVersion {
    pub fn from_content(content: impl AsRef<[u8]>) -> Self {
        Self(blake3::hash(content.as_ref()).to_hex().to_string())
    }
    pub fn new(value: impl Into<String>) -> Result<Self, DeliveryError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b'-' || b == b'_')
        {
            Err(DeliveryError::InvalidVersion)
        } else {
            Ok(Self(value))
        }
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl fmt::Display for DraftVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedDraftState {
    #[default]
    Active,
    Sending,
    Sent,
    Deleted,
    SendStateUnknown,
}
impl ManagedDraftState {
    pub const fn writable(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ManagedDraft {
    pub id: DraftId,
    pub connection_id: ConnectionId,
    pub gmail_draft_id: String,
    pub message_id: String,
    pub version: DraftVersion,
    pub state: ManagedDraftState,
}
impl ManagedDraft {
    pub fn new(
        connection_id: ConnectionId,
        gmail_draft_id: impl Into<String>,
        message_id: impl Into<String>,
        content: impl AsRef<[u8]>,
    ) -> Result<Self, DeliveryError> {
        let gmail_draft_id = gmail_draft_id.into();
        let message_id = message_id.into();
        if gmail_draft_id.trim().is_empty() || message_id.trim().is_empty() {
            return Err(DeliveryError::MissingDraftIdentity);
        }
        Ok(Self {
            id: DraftId::new(),
            connection_id,
            gmail_draft_id,
            message_id,
            version: DraftVersion::from_content(content),
            state: ManagedDraftState::Active,
        })
    }
    pub fn update(
        &mut self,
        expected: &DraftVersion,
        content: impl AsRef<[u8]>,
    ) -> Result<DraftVersion, DeliveryError> {
        self.check_expected(expected)?;
        if !self.state.writable() {
            return Err(DeliveryError::InvalidState);
        }
        self.version = DraftVersion::from_content(content);
        Ok(self.version.clone())
    }
    pub fn delete(&mut self, expected: &DraftVersion) -> Result<(), DeliveryError> {
        self.check_expected(expected)?;
        if !self.state.writable() {
            return Err(DeliveryError::InvalidState);
        }
        self.state = ManagedDraftState::Deleted;
        Ok(())
    }
    pub fn mark_sending(&mut self, expected: &DraftVersion) -> Result<(), DeliveryError> {
        self.check_expected(expected)?;
        if !self.state.writable() {
            return Err(DeliveryError::InvalidState);
        }
        self.state = ManagedDraftState::Sending;
        Ok(())
    }
    pub fn mark_sent(&mut self) -> Result<(), DeliveryError> {
        if self.state != ManagedDraftState::Sending {
            return Err(DeliveryError::InvalidState);
        }
        self.state = ManagedDraftState::Sent;
        Ok(())
    }
    pub fn mark_send_unknown(&mut self) -> Result<(), DeliveryError> {
        if self.state != ManagedDraftState::Sending {
            return Err(DeliveryError::InvalidState);
        }
        self.state = ManagedDraftState::SendStateUnknown;
        Ok(())
    }

    pub fn mark_send_failed(&mut self) -> Result<(), DeliveryError> {
        if self.state != ManagedDraftState::Sending {
            return Err(DeliveryError::InvalidState);
        }
        self.state = ManagedDraftState::Active;
        Ok(())
    }
    fn check_expected(&self, expected: &DraftVersion) -> Result<(), DeliveryError> {
        if &self.version == expected {
            Ok(())
        } else {
            Err(DeliveryError::DraftChanged)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SendPreview {
    pub connection_id: ConnectionId,
    pub draft_id: DraftId,
    pub version: DraftVersion,
    pub from: Option<String>,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub subject: String,
    pub body_summary: String,
    pub attachment_names: Vec<String>,
    pub safety_notice: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedSend {
    pub confirmation_id: ConfirmationId,
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub preview: SendPreview,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SendOutcome {
    Sent { gmail_message_id: String },
    StateUnknown,
    Failed { code: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SendConfirmation {
    pub id: ConfirmationId,
    pub token_hash: [u8; 32],
    pub key_id: AccessKeyId,
    pub key_generation: u64,
    pub connection_id: ConnectionId,
    pub draft_id: DraftId,
    pub draft_version: DraftVersion,
    pub expires_at: DateTime<Utc>,
    pub invalidated: bool,
    pub outcome: Option<SendOutcome>,
}

impl SendConfirmation {
    /// SHA-256 digest for durable lookup; plaintext confirmation tokens are never persisted.
    pub fn token_digest_hex(token: &str) -> String {
        token_hash_hex(hash_token(token))
    }

    pub fn token_hash_hex(&self) -> String {
        token_hash_hex(self.token_hash)
    }

    pub fn matches_token_digest_hex(&self, digest: &str) -> bool {
        decode_token_hash_hex(digest)
            .is_ok_and(|candidate| bool::from(self.token_hash.ct_eq(&candidate)))
    }
    pub fn prepare(
        key_id: AccessKeyId,
        key_generation: u64,
        draft: &ManagedDraft,
        preview: SendPreview,
        now: DateTime<Utc>,
    ) -> Result<(Self, PreparedSend), DeliveryError> {
        if draft.state != ManagedDraftState::Active
            || preview.connection_id != draft.connection_id
            || preview.draft_id != draft.id
            || preview.version != draft.version
        {
            return Err(DeliveryError::InvalidState);
        }
        let token = random_token();
        let confirmation = Self {
            id: ConfirmationId::new(),
            token_hash: hash_token(&token),
            key_id,
            key_generation,
            connection_id: draft.connection_id,
            draft_id: draft.id,
            draft_version: draft.version.clone(),
            expires_at: now + Duration::minutes(5),
            invalidated: false,
            outcome: None,
        };
        let prepared = PreparedSend {
            confirmation_id: confirmation.id,
            token,
            expires_at: confirmation.expires_at,
            preview,
        };
        Ok((confirmation, prepared))
    }
    /// Atomically claim an active draft and let the transport adapter perform the send.
    ///
    /// The adapter is the only source of `SendOutcome`; callers cannot provide a
    /// fabricated result. Replays return the cached first result without sending.
    pub fn claim(
        &mut self,
        token: &str,
        key_id: AccessKeyId,
        generation: u64,
        draft: &mut ManagedDraft,
        now: DateTime<Utc>,
    ) -> Result<Option<ConsumeResult>, DeliveryError> {
        if !bool::from(hash_token(token).ct_eq(&self.token_hash)) {
            return Err(DeliveryError::InvalidToken);
        }
        if key_id != self.key_id
            || generation != self.key_generation
            || draft.id != self.draft_id
            || draft.connection_id != self.connection_id
            || draft.version != self.draft_version
        {
            return Err(DeliveryError::ConfirmationMismatch);
        }
        if let Some(first) = &self.outcome {
            return Ok(Some(ConsumeResult {
                outcome: first.clone(),
                replayed: true,
            }));
        }
        if self.invalidated || now >= self.expires_at {
            return Err(DeliveryError::ConfirmationExpired);
        }
        if draft.state != ManagedDraftState::Active {
            return Err(DeliveryError::InvalidState);
        }
        draft.mark_sending(&self.draft_version)?;
        Ok(None)
    }

    pub fn complete(
        &mut self,
        draft: &mut ManagedDraft,
        outcome: SendOutcome,
    ) -> Result<ConsumeResult, DeliveryError> {
        if let Some(first) = &self.outcome {
            return Ok(ConsumeResult {
                outcome: first.clone(),
                replayed: true,
            });
        }
        if draft.id != self.draft_id
            || draft.connection_id != self.connection_id
            || draft.state != ManagedDraftState::Sending
        {
            return Err(DeliveryError::InvalidState);
        }
        match &outcome {
            SendOutcome::Sent { .. } => draft.mark_sent()?,
            SendOutcome::StateUnknown => draft.mark_send_unknown()?,
            SendOutcome::Failed { .. } => draft.mark_send_failed()?,
        }
        self.outcome = Some(outcome.clone());
        Ok(ConsumeResult {
            outcome,
            replayed: false,
        })
    }

    /// Atomically claims an active draft and obtains the result from the adapter callback.
    /// Replays return the cached first result without invoking the callback.
    pub fn consume<F>(
        &mut self,
        token: &str,
        key_id: AccessKeyId,
        generation: u64,
        draft: &mut ManagedDraft,
        now: DateTime<Utc>,
        send: F,
    ) -> Result<ConsumeResult, DeliveryError>
    where
        F: FnOnce(&ManagedDraft) -> SendOutcome,
    {
        if let Some(replayed) = self.claim(token, key_id, generation, draft, now)? {
            return Ok(replayed);
        }
        let outcome = send(draft);
        self.complete(draft, outcome)
    }
    pub fn invalidate(&mut self) {
        self.invalidated = true;
    }
    pub fn invalidate_if_generation_changed(&mut self, generation: u64) {
        if generation != self.key_generation {
            self.invalidate();
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumeResult {
    pub outcome: SendOutcome,
    pub replayed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IdempotencyRecord {
    pub caller: String,
    pub operation: String,
    /// SHA-256 of the untrusted Idempotency-Key header; raw key is never stored.
    pub idempotency_key_hash: [u8; 32],
    pub request_hash: [u8; 32],
    pub result: Option<SendOutcome>,
}
impl IdempotencyRecord {
    pub fn new(
        caller: impl Into<String>,
        operation: impl Into<String>,
        idempotency_key: impl AsRef<[u8]>,
        request: impl AsRef<[u8]>,
    ) -> Self {
        Self {
            caller: caller.into(),
            operation: operation.into(),
            idempotency_key_hash: hash_token_bytes(idempotency_key.as_ref()),
            request_hash: hash_token_bytes(request.as_ref()),
            result: None,
        }
    }
    /// Errors when the same key is reused with a different payload.
    pub fn validate(
        &self,
        caller: &str,
        operation: &str,
        idempotency_key: impl AsRef<[u8]>,
        request: impl AsRef<[u8]>,
    ) -> Result<bool, DeliveryError> {
        if self.caller != caller || self.operation != operation {
            return Ok(false);
        }
        if !bool::from(
            self.idempotency_key_hash
                .ct_eq(&hash_token_bytes(idempotency_key.as_ref())),
        ) {
            return Ok(false);
        }
        if !bool::from(self.request_hash.ct_eq(&hash_token_bytes(request.as_ref()))) {
            return Err(DeliveryError::IdempotencyKeyConflict);
        }
        Ok(true)
    }
    pub fn matches(
        &self,
        caller: &str,
        operation: &str,
        idempotency_key: impl AsRef<[u8]>,
        request: impl AsRef<[u8]>,
    ) -> bool {
        self.validate(caller, operation, idempotency_key, request)
            .unwrap_or(false)
    }
    pub fn complete(&mut self, result: SendOutcome) {
        self.result = Some(result);
    }
}

fn random_token() -> String {
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
fn hash_token(value: &str) -> [u8; 32] {
    hash_token_bytes(value.as_bytes())
}
fn hash_token_bytes(value: &[u8]) -> [u8; 32] {
    let mut out = [0_u8; 32];
    out.copy_from_slice(&Sha256::digest(value));
    out
}

fn token_hash_hex(hash: [u8; 32]) -> String {
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn decode_token_hash_hex(value: &str) -> Result<[u8; 32], ()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(());
    }
    let mut hash = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        hash[index] = std::str::from_utf8(pair)
            .ok()
            .and_then(|pair| u8::from_str_radix(pair, 16).ok())
            .ok_or(())?;
    }
    Ok(hash)
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryError {
    MissingDraftIdentity,
    InvalidVersion,
    DraftChanged,
    InvalidState,
    InvalidToken,
    ConfirmationExpired,
    ConfirmationMismatch,
    IdempotencyKeyConflict,
}
impl fmt::Display for DeliveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MissingDraftIdentity => "draft identity is missing",
            Self::InvalidVersion => "invalid draft version",
            Self::DraftChanged => "draft changed",
            Self::InvalidState => "invalid draft state",
            Self::InvalidToken => "invalid confirmation token",
            Self::ConfirmationExpired => "confirmation expired or invalidated",
            Self::ConfirmationMismatch => "confirmation does not match request",
            Self::IdempotencyKeyConflict => "idempotency key was reused with a different request",
        })
    }
}
impl std::error::Error for DeliveryError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn preview(draft: &ManagedDraft) -> SendPreview {
        SendPreview {
            connection_id: draft.connection_id,
            draft_id: draft.id,
            version: draft.version.clone(),
            from: None,
            to: vec!["a@example.com".into()],
            cc: vec![],
            bcc: vec![],
            subject: "s".into(),
            body_summary: "b".into(),
            attachment_names: vec![],
            safety_notice: "untrusted".into(),
        }
    }

    #[test]
    fn optimistic_version_conflict_is_enforced() {
        let c = ConnectionId::new();
        let mut d = ManagedDraft::new(c, "gd", "<a@agentmail>", "hello").unwrap();
        let old = d.version.clone();
        d.update(&old, "changed").unwrap();
        assert_eq!(d.update(&old, "again"), Err(DeliveryError::DraftChanged));
    }

    #[test]
    fn confirmation_claims_active_draft_and_replays_result() {
        let c = ConnectionId::new();
        let mut d = ManagedDraft::new(c, "gd", "<a@agentmail>", "hello").unwrap();
        let (mut conf, prepared) =
            SendConfirmation::prepare(AccessKeyId::new(), 1, &d, preview(&d), Utc::now()).unwrap();
        let key = conf.key_id;
        let first = conf
            .consume(&prepared.token, key, 1, &mut d, Utc::now(), |_| {
                SendOutcome::Sent {
                    gmail_message_id: "m".into(),
                }
            })
            .unwrap();
        assert!(!first.replayed);
        assert_eq!(d.state, ManagedDraftState::Sent);
        let second = conf
            .consume(&prepared.token, key, 1, &mut d, Utc::now(), |_| {
                panic!("replay must not send")
            })
            .unwrap();
        assert!(second.replayed);
        assert_eq!(first.outcome, second.outcome);
    }

    #[test]
    fn confirmation_rejects_deleted_draft_before_adapter() {
        let c = ConnectionId::new();
        let mut d = ManagedDraft::new(c, "gd", "<a@agentmail>", "hello").unwrap();
        let (mut conf, prepared) =
            SendConfirmation::prepare(AccessKeyId::new(), 1, &d, preview(&d), Utc::now()).unwrap();
        d.delete(&d.version.clone()).unwrap();
        assert_eq!(
            conf.consume(
                &prepared.token,
                conf.key_id,
                1,
                &mut d,
                Utc::now(),
                |_| panic!("must not send")
            ),
            Err(DeliveryError::InvalidState)
        );
    }

    #[test]
    fn rotation_invalidates_confirmation() {
        let c = ConnectionId::new();
        let mut d = ManagedDraft::new(c, "gd", "<a@agentmail>", "hello").unwrap();
        let (mut conf, prepared) =
            SendConfirmation::prepare(AccessKeyId::new(), 1, &d, preview(&d), Utc::now()).unwrap();
        conf.invalidate_if_generation_changed(2);
        assert_eq!(
            conf.consume(&prepared.token, conf.key_id, 1, &mut d, Utc::now(), |_| {
                SendOutcome::StateUnknown
            }),
            Err(DeliveryError::ConfirmationExpired)
        );
    }

    #[test]
    fn confirmation_token_digest_is_hex_and_constant_time_verifiable() {
        let draft = ManagedDraft::new(ConnectionId::new(), "gd", "<a@agentmail>", "hello").unwrap();
        let (confirmation, prepared) =
            SendConfirmation::prepare(AccessKeyId::new(), 1, &draft, preview(&draft), Utc::now())
                .unwrap();
        let digest = SendConfirmation::token_digest_hex(&prepared.token);
        assert_eq!(digest.len(), 64);
        assert!(confirmation.matches_token_digest_hex(&digest));
        assert!(!confirmation.matches_token_digest_hex(&"0".repeat(64)));
        assert!(!confirmation.matches_token_digest_hex("not-a-digest"));
    }
    #[test]
    fn idempotency_key_reuse_with_different_payload_is_conflict() {
        let record = IdempotencyRecord::new("caller", "create", "key", "body");
        assert!(record.validate("caller", "create", "key", "body").unwrap());
        assert_eq!(
            record.validate("caller", "create", "key", "other"),
            Err(DeliveryError::IdempotencyKeyConflict)
        );
        assert!(!record.matches("caller", "create", "different", "body"));
    }
}

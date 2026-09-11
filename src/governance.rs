//! Rate-limit and metadata-only audit primitives.

use crate::domain::{
    access::AccessKeyId,
    identity::{ConnectionId, UserId},
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitKind {
    ApiPerMinute,
    PreparePerHour,
    SendPerHour,
    SendPerDay,
}

impl LimitKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ApiPerMinute => "api_per_minute",
            Self::PreparePerHour => "prepare_per_hour",
            Self::SendPerHour => "send_per_hour",
            Self::SendPerDay => "send_per_day",
        }
    }

    pub const fn limit(self) -> u32 {
        match self {
            Self::ApiPerMinute => 120,
            Self::PreparePerHour => 30,
            Self::SendPerHour => 10,
            Self::SendPerDay => 50,
        }
    }

    pub const fn window_seconds(self) -> i64 {
        match self {
            Self::ApiPerMinute => 60,
            Self::PreparePerHour | Self::SendPerHour => 3_600,
            Self::SendPerDay => 86_400,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuditContext {
    pub user_id: Option<UserId>,
    pub access_key_id: Option<AccessKeyId>,
    pub connection_id: Option<ConnectionId>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RateBucket {
    pub bucket_key: String,
    pub kind: LimitKind,
    pub window_started_at: DateTime<Utc>,
    pub request_count: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("rate limit exceeded; retry after {retry_after_seconds} seconds")]
pub struct RateLimitExceeded {
    pub retry_after_seconds: u64,
}

impl RateBucket {
    pub fn new(bucket_key: impl Into<String>, kind: LimitKind, now: DateTime<Utc>) -> Self {
        Self {
            bucket_key: bucket_key.into(),
            kind,
            window_started_at: aligned_window(kind, now),
            request_count: 0,
        }
    }

    pub fn charge(&mut self, now: DateTime<Utc>) -> Result<ChargeReceipt, RateLimitExceeded> {
        let start = aligned_window(self.kind, now);
        if start != self.window_started_at {
            self.window_started_at = start;
            self.request_count = 0;
        }
        if self.request_count >= self.kind.limit() {
            let reset = self.window_started_at + Duration::seconds(self.kind.window_seconds());
            let seconds = (reset - now).num_seconds().max(1) as u64;
            return Err(RateLimitExceeded {
                retry_after_seconds: seconds,
            });
        }
        self.request_count += 1;
        Ok(ChargeReceipt {
            bucket_key: self.bucket_key.clone(),
            kind: self.kind,
            window_started_at: self.window_started_at,
            nonce: Uuid::now_v7(),
            consumed: false,
        })
    }

    /// Refund exactly the charge represented by `receipt`. A receipt is bound
    /// to this bucket, its limit kind, and its fixed window; it is consumed on
    /// success so replaying it cannot mint capacity.
    pub fn refund(&mut self, receipt: &mut ChargeReceipt, now: DateTime<Utc>) -> bool {
        if receipt.consumed
            || receipt.bucket_key != self.bucket_key
            || receipt.kind != self.kind
            || receipt.window_started_at != self.window_started_at
            || aligned_window(self.kind, now) != receipt.window_started_at
            || self.request_count == 0
        {
            return false;
        }
        receipt.consumed = true;
        self.request_count -= 1;
        true
    }
}

/// A non-forgeable-in-practice reservation receipt for one rate-limit charge.
/// It deliberately is not `Clone` or deserializable: callers must retain and
/// consume the original in-memory receipt returned by `charge`.
#[derive(Debug, Eq, PartialEq)]
pub struct ChargeReceipt {
    bucket_key: String,
    kind: LimitKind,
    window_started_at: DateTime<Utc>,
    nonce: Uuid,
    consumed: bool,
}

impl ChargeReceipt {
    pub fn id(&self) -> Uuid {
        self.nonce
    }
}

fn aligned_window(kind: LimitKind, now: DateTime<Utc>) -> DateTime<Utc> {
    let seconds = kind.window_seconds();
    let aligned = now.timestamp().div_euclid(seconds) * seconds;
    DateTime::from_timestamp(aligned, 0).expect("aligned timestamp is representable")
}

#[derive(Clone, Debug)]
pub struct ReadConcurrency {
    permits: Arc<Semaphore>,
}

impl Default for ReadConcurrency {
    fn default() -> Self {
        Self {
            permits: Arc::new(Semaphore::new(4)),
        }
    }
}

impl ReadConcurrency {
    pub async fn acquire(&self) -> Result<OwnedSemaphorePermit, tokio::sync::AcquireError> {
        self.permits.clone().acquire_owned().await
    }

    pub fn available(&self) -> usize {
        self.permits.available_permits()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AuditOperation {
    #[serde(rename = "auth.login")]
    AuthLogin,
    #[serde(rename = "auth.gmail")]
    AuthGmail,
    #[serde(rename = "messages.search")]
    MessagesSearch,
    #[serde(rename = "messages.get")]
    MessagesGet,
    #[serde(rename = "threads.get")]
    ThreadsGet,
    #[serde(rename = "attachments.get")]
    AttachmentsGet,
    #[serde(rename = "drafts.list")]
    DraftsList,
    #[serde(rename = "drafts.get")]
    DraftsGet,
    #[serde(rename = "draft.prepare")]
    DraftPrepare,
    #[serde(rename = "draft.send")]
    DraftSend,
    #[serde(rename = "connection.create")]
    ConnectionCreate,
    #[serde(rename = "connection.revoke")]
    ConnectionRevoke,
    #[serde(rename = "access_key.create")]
    AccessKeyCreate,
    #[serde(rename = "access_key.rotate")]
    AccessKeyRotate,
    #[serde(rename = "access_key.revoke")]
    AccessKeyRevoke,
    #[serde(rename = "invitation.create")]
    InvitationCreate,
    #[serde(rename = "invitation.accept")]
    InvitationAccept,
    #[serde(rename = "health")]
    Health,
}

impl AuditOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthLogin => "auth.login",
            Self::AuthGmail => "auth.gmail",
            Self::MessagesSearch => "messages.search",
            Self::MessagesGet => "messages.get",
            Self::ThreadsGet => "threads.get",
            Self::AttachmentsGet => "attachments.get",
            Self::DraftsList => "drafts.list",
            Self::DraftsGet => "drafts.get",
            Self::DraftPrepare => "draft.prepare",
            Self::DraftSend => "draft.send",
            Self::ConnectionCreate => "connection.create",
            Self::ConnectionRevoke => "connection.revoke",
            Self::AccessKeyCreate => "access_key.create",
            Self::AccessKeyRotate => "access_key.rotate",
            Self::AccessKeyRevoke => "access_key.revoke",
            Self::InvitationCreate => "invitation.create",
            Self::InvitationAccept => "invitation.accept",
            Self::Health => "health",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AuditResult {
    #[serde(rename = "ok")]
    Ok,
    #[serde(rename = "error")]
    Error,
    #[serde(rename = "conflict")]
    Conflict,
    #[serde(rename = "unauthorized")]
    Unauthorized,
    #[serde(rename = "forbidden")]
    Forbidden,
    #[serde(rename = "not_found")]
    NotFound,
    #[serde(rename = "rate_limited")]
    RateLimited,
    #[serde(rename = "unavailable")]
    Unavailable,
}

impl AuditResult {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Error => "error",
            Self::Conflict => "conflict",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::RateLimited => "rate_limited",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct RequestId(String);

#[derive(Debug, Clone, Eq, PartialEq, thiserror::Error)]
#[error("invalid audit metadata value")]
pub struct AuditMetadataError;

impl RequestId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for RequestId {
    type Error = AuditMetadataError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
        {
            return Err(AuditMetadataError);
        }
        Ok(Self(value))
    }
}

impl TryFrom<&str> for RequestId {
    type Error = AuditMetadataError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::try_from(value.to_owned())
    }
}

impl Serialize for RequestId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RequestId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::try_from(String::deserialize(deserializer).map_err(serde::de::Error::custom)?)
            .map_err(serde::de::Error::custom)
    }
}

impl TryFrom<String> for AuditOperation {
    type Error = AuditMetadataError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl TryFrom<&str> for AuditOperation {
    type Error = AuditMetadataError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "auth.login" => Ok(Self::AuthLogin),
            "auth.gmail" => Ok(Self::AuthGmail),
            "messages.search" => Ok(Self::MessagesSearch),
            "messages.get" => Ok(Self::MessagesGet),
            "threads.get" => Ok(Self::ThreadsGet),
            "attachments.get" => Ok(Self::AttachmentsGet),
            "drafts.list" => Ok(Self::DraftsList),
            "drafts.get" => Ok(Self::DraftsGet),
            "draft.prepare" => Ok(Self::DraftPrepare),
            "draft.send" => Ok(Self::DraftSend),
            "connection.create" => Ok(Self::ConnectionCreate),
            "connection.revoke" => Ok(Self::ConnectionRevoke),
            "access_key.create" => Ok(Self::AccessKeyCreate),
            "access_key.rotate" => Ok(Self::AccessKeyRotate),
            "access_key.revoke" => Ok(Self::AccessKeyRevoke),
            "invitation.create" => Ok(Self::InvitationCreate),
            "invitation.accept" => Ok(Self::InvitationAccept),
            "health" => Ok(Self::Health),
            _ => Err(AuditMetadataError),
        }
    }
}

impl TryFrom<String> for AuditResult {
    type Error = AuditMetadataError;

    fn try_from(value: String) -> Result<Self, AuditMetadataError> {
        Self::try_from(value.as_str())
    }
}

impl TryFrom<&str> for AuditResult {
    type Error = AuditMetadataError;

    fn try_from(value: &str) -> Result<Self, AuditMetadataError> {
        match value {
            "ok" => Ok(Self::Ok),
            "error" => Ok(Self::Error),
            "conflict" => Ok(Self::Conflict),
            "unauthorized" => Ok(Self::Unauthorized),
            "forbidden" => Ok(Self::Forbidden),
            "not_found" => Ok(Self::NotFound),
            "rate_limited" => Ok(Self::RateLimited),
            "unavailable" => Ok(Self::Unavailable),
            _ => Err(AuditMetadataError),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: Uuid,
    pub user_id: Option<UserId>,
    pub access_key_id: Option<AccessKeyId>,
    pub connection_id: Option<ConnectionId>,
    pub operation: AuditOperation,
    pub result_category: AuditResult,
    pub latency_ms: u64,
    pub request_id: RequestId,
    pub created_at: DateTime<Utc>,
}

impl AuditEvent {
    pub fn metadata(
        context: AuditContext,
        operation: AuditOperation,
        result_category: AuditResult,
        latency_ms: u64,
        request_id: RequestId,
        created_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id: Uuid::now_v7(),
            user_id: context.user_id,
            access_key_id: context.access_key_id,
            connection_id: context.connection_id,
            operation,
            result_category,
            latency_ms,
            request_id,
            created_at,
        }
    }
}

pub fn audit_cleanup_cutoff(now: DateTime<Utc>, retention_days: u32) -> DateTime<Utc> {
    now - Duration::days(i64::from(retention_days))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_window_returns_retry_and_resets() {
        let now = DateTime::parse_from_rfc3339("2026-08-31T12:00:00Z")
            .unwrap()
            .to_utc();
        let mut bucket = RateBucket::new("key", LimitKind::SendPerHour, now);
        for _ in 0..10 {
            bucket.charge(now).unwrap();
        }
        assert_eq!(bucket.charge(now).unwrap_err().retry_after_seconds, 3_600);
        bucket.charge(now + Duration::hours(1)).unwrap();
        assert_eq!(bucket.request_count, 1);
    }

    #[test]
    fn unknown_send_can_be_refunded_once() {
        let now = Utc::now();
        let mut bucket = RateBucket::new("connection", LimitKind::SendPerDay, now);
        let mut receipt = bucket.charge(now).unwrap();
        assert!(bucket.refund(&mut receipt, now));
        assert!(!bucket.refund(&mut receipt, now));
    }

    #[test]
    fn receipt_cannot_refund_another_bucket_or_window() {
        let now = Utc::now();
        let mut source = RateBucket::new("source", LimitKind::SendPerDay, now);
        let mut receipt = source.charge(now).unwrap();
        let mut other = RateBucket::new("other", LimitKind::SendPerDay, now);
        other.charge(now).unwrap();
        assert!(!other.refund(&mut receipt, now));
        assert_eq!(other.request_count, 1);
        assert!(source.refund(&mut receipt, now));
        assert!(!source.refund(&mut receipt, now));
        let mut later = source.charge(now).unwrap();
        assert!(!source.refund(&mut later, now + Duration::days(1)));
    }

    #[test]
    fn audit_shape_has_no_mail_content_fields() {
        let event = AuditEvent::metadata(
            AuditContext::default(),
            AuditOperation::MessagesSearch,
            AuditResult::Ok,
            4,
            RequestId::try_from("req").unwrap(),
            Utc::now(),
        );
        let value = serde_json::to_value(event).unwrap();
        for forbidden in [
            "query",
            "email",
            "subject",
            "body",
            "snippet",
            "attachment",
            "token",
        ] {
            assert!(value.get(forbidden).is_none());
        }
    }

    #[test]
    fn audit_metadata_rejects_unbounded_values() {
        assert!(AuditOperation::try_from("messages.search\nsecret").is_err());
        assert!(AuditResult::try_from("ok\nsecret").is_err());
        assert!(RequestId::try_from("request\nsecret").is_err());
        assert!(RequestId::try_from("x".repeat(129)).is_err());
    }
}

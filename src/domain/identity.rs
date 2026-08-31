//! Identity and instance-level policy types.
//!
//! These types deliberately contain no persistence or HTTP concerns.  The
//! database layer can use them as the vocabulary for users, connections and
//! the monotonic Personal Use counter.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fmt};
use uuid::Uuid;

pub const GMAIL_READONLY_SCOPE: &str = "gmail.readonly";
pub const GMAIL_COMPOSE_SCOPE: &str = "gmail.compose";
const GMAIL_READONLY_URL: &str = "https://www.googleapis.com/auth/gmail.readonly";
const GMAIL_COMPOSE_URL: &str = "https://www.googleapis.com/auth/gmail.compose";

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
            pub const fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }
            pub const fn into_uuid(self) -> Uuid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
        impl From<Uuid> for $name {
            fn from(value: Uuid) -> Self {
                Self(value)
            }
        }
        impl From<$name> for Uuid {
            fn from(value: $name) -> Self {
                value.0
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }
    };
}

uuid_id!(UserId);
uuid_id!(ConnectionId);
uuid_id!(InvitationId);
uuid_id!(SessionId);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserRole {
    Owner,
    #[default]
    Member,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserStatus {
    #[default]
    Active,
    Revoking,
}

impl UserStatus {
    pub const fn accepts_requests(self) -> bool {
        matches!(self, Self::Active)
    }
    pub fn begin_revoke(&mut self) -> bool {
        if self.accepts_requests() {
            *self = Self::Revoking;
            true
        } else {
            false
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionStatus {
    #[default]
    Active,
    ReauthRequired,
    Revoking,
}

impl ConnectionStatus {
    pub const fn accepts_requests(self) -> bool {
        matches!(self, Self::Active)
    }
    pub fn begin_revoke(&mut self) -> bool {
        if self.accepts_requests() {
            *self = Self::Revoking;
            true
        } else {
            false
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct User {
    pub id: UserId,
    pub google_sub: String,
    pub email: String,
    pub role: UserRole,
    pub status: UserStatus,
    pub last_activity_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl User {
    pub fn new(
        google_sub: impl Into<String>,
        email: impl AsRef<str>,
        role: UserRole,
        now: DateTime<Utc>,
    ) -> Result<Self, IdentityError> {
        let google_sub = google_sub.into();
        if google_sub.trim().is_empty() {
            return Err(IdentityError::EmptyGoogleSubject);
        }
        Ok(Self {
            id: UserId::new(),
            google_sub,
            email: normalize_email(email.as_ref())?,
            role,
            status: UserStatus::Active,
            last_activity_at: None,
            created_at: now,
            updated_at: now,
        })
    }

    pub fn touch(&mut self, now: DateTime<Utc>) {
        self.last_activity_at = Some(now);
        self.updated_at = now;
    }
    pub fn begin_revoke(&mut self, now: DateTime<Utc>) -> bool {
        let changed = self.status.begin_revoke();
        if changed {
            self.updated_at = now;
        }
        changed
    }
    pub const fn can_manage_owner_ui(&self) -> bool {
        matches!(self.role, UserRole::Owner) && self.status.accepts_requests()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GmailConnection {
    pub id: ConnectionId,
    pub owner_id: UserId,
    pub google_sub: String,
    pub email: String,
    pub status: ConnectionStatus,
    pub granted_scopes: Vec<String>,
    pub last_used_at: Option<DateTime<Utc>>,
}

impl GmailConnection {
    pub fn new(
        owner_id: UserId,
        google_sub: impl Into<String>,
        email: impl AsRef<str>,
        scopes: Vec<String>,
    ) -> Result<Self, IdentityError> {
        let google_sub = google_sub.into();
        if google_sub.trim().is_empty() {
            return Err(IdentityError::EmptyGoogleSubject);
        }
        if !has_required_gmail_scopes(&scopes) {
            return Err(IdentityError::MissingRequiredGmailScopes);
        }
        Ok(Self {
            id: ConnectionId::new(),
            owner_id,
            google_sub,
            email: normalize_email(email.as_ref())?,
            status: ConnectionStatus::Active,
            granted_scopes: scopes,
            last_used_at: None,
        })
    }
    pub fn touch(&mut self, now: DateTime<Utc>) {
        self.last_used_at = Some(now);
    }
}

fn has_required_gmail_scopes(scopes: &[String]) -> bool {
    [GMAIL_READONLY_SCOPE, GMAIL_COMPOSE_SCOPE]
        .iter()
        .all(|required| {
            scopes.iter().any(|scope| {
                scope == *required
                    || (*required == GMAIL_READONLY_SCOPE && scope == GMAIL_READONLY_URL)
                    || (*required == GMAIL_COMPOSE_SCOPE && scope == GMAIL_COMPOSE_URL)
            })
        })
}

pub fn normalize_email(value: &str) -> Result<String, IdentityError> {
    let value = value.trim().to_ascii_lowercase();
    if value.is_empty()
        || value.len() > 320
        || value.contains(char::is_whitespace)
        || value.contains(['\r', '\n'])
    {
        return Err(IdentityError::InvalidEmail);
    }
    let Some((local, domain)) = value.rsplit_once('@') else {
        return Err(IdentityError::InvalidEmail);
    };
    if local.is_empty()
        || domain.is_empty()
        || domain.starts_with('.')
        || domain.ends_with('.')
        || !domain.contains('.')
    {
        return Err(IdentityError::InvalidEmail);
    }
    Ok(value)
}

/// Monotonic accounting required by Google's Personal Use OAuth exemption.
/// `authorized_subjects` is intentionally retained when users/connections are
/// deleted, so reauthorization and rotation cannot consume another slot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PersonalUseCounter {
    pub current_members: u32,
    pub historical_authorizations: u32,
    pub limit: u32,
    authorized_subjects: BTreeSet<String>,
}

impl PersonalUseCounter {
    pub const DEFAULT_LIMIT: u32 = 90;
    pub const HARD_LIMIT: u32 = 99;
    pub fn new(limit: u32) -> Result<Self, IdentityError> {
        if limit == 0 || limit > Self::HARD_LIMIT {
            return Err(IdentityError::InvalidPersonalUseLimit);
        }
        Ok(Self {
            current_members: 0,
            historical_authorizations: 0,
            limit,
            authorized_subjects: BTreeSet::new(),
        })
    }
    pub fn remaining(&self) -> u32 {
        self.limit.saturating_sub(self.historical_authorizations)
    }
    pub fn can_authorize(&self, google_sub: &str) -> bool {
        self.authorized_subjects.contains(google_sub) || self.historical_authorizations < self.limit
    }
    /// Returns true only when this is the first authorization for the subject.
    pub fn record_first_authorization(
        &mut self,
        google_sub: impl Into<String>,
    ) -> Result<bool, IdentityError> {
        let subject = google_sub.into();
        if subject.trim().is_empty() {
            return Err(IdentityError::EmptyGoogleSubject);
        }
        if !self.authorized_subjects.insert(subject.clone()) {
            return Ok(false);
        }
        if self.historical_authorizations >= self.limit {
            // Keep the set unchanged only for a rejected new subject.
            self.authorized_subjects.remove(&subject);
            return Err(IdentityError::PersonalUseLimitReached);
        }
        self.historical_authorizations += 1;
        Ok(true)
    }
    pub fn member_added(&mut self) -> Result<(), IdentityError> {
        if self.current_members >= self.limit {
            Err(IdentityError::PersonalUseLimitReached)
        } else {
            self.current_members += 1;
            Ok(())
        }
    }
    pub fn member_removed(&mut self) {
        self.current_members = self.current_members.saturating_sub(1);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityError {
    EmptyGoogleSubject,
    MissingRequiredGmailScopes,
    InvalidEmail,
    InvalidPersonalUseLimit,
    PersonalUseLimitReached,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::EmptyGoogleSubject => "google subject is empty",
            Self::MissingRequiredGmailScopes => "required Gmail scopes are missing",
            Self::InvalidEmail => "invalid email address",
            Self::InvalidPersonalUseLimit => "personal use limit must be between 1 and 99",
            Self::PersonalUseLimitReached => "personal use authorization limit reached",
        })
    }
}
impl std::error::Error for IdentityError {}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn email_is_normalized_and_rejected_when_unsafe() {
        assert_eq!(
            normalize_email(" User@Example.COM ").unwrap(),
            "user@example.com"
        );
        assert!(normalize_email("a\nb@example.com").is_err());
    }
    #[test]
    fn counter_is_monotonic_and_reauth_is_free() {
        let mut c = PersonalUseCounter::new(1).unwrap();
        assert!(c.record_first_authorization("sub").unwrap());
        assert!(!c.record_first_authorization("sub").unwrap());
        assert_eq!(c.remaining(), 0);
        assert!(c.record_first_authorization("other").is_err());
    }
    #[test]
    fn revoking_user_cannot_accept_requests() {
        let now = Utc::now();
        let mut u = User::new("sub", "a@example.com", UserRole::Member, now).unwrap();
        assert!(u.begin_revoke(now));
        assert!(!u.status.accepts_requests());
        assert!(!u.begin_revoke(now));
    }

    #[test]
    fn connection_requires_both_gmail_scopes() {
        let owner = UserId::new();
        assert_eq!(
            GmailConnection::new(
                owner,
                "sub",
                "a@example.com",
                vec![GMAIL_READONLY_SCOPE.into()]
            ),
            Err(IdentityError::MissingRequiredGmailScopes)
        );
        assert!(
            GmailConnection::new(
                owner,
                "sub",
                "a@example.com",
                vec![GMAIL_READONLY_SCOPE.into(), GMAIL_COMPOSE_SCOPE.into()]
            )
            .is_ok()
        );
    }
}

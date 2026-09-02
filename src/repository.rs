//! SQLite repository for durable AgentMail metadata.
use crate::{
    crypto::{ENVELOPE_PREFIX, hash_token},
    database::Database,
    domain::{
        access::{
            AccessError, AccessKey, AccessKeyId, AccessKeyStatus, GrantSet, NewAccessKey,
            hash_secret, parse_credential, verify_secret,
        },
        delivery::{
            ConfirmationId, DraftId, DraftVersion, ManagedDraft, ManagedDraftState,
            SendConfirmation, SendOutcome,
        },
        identity::{
            ConnectionId, ConnectionStatus, GmailConnection, SessionId, User, UserId, UserRole,
            UserStatus, normalize_email,
        },
    },
    governance::AuditEvent,
    oauth::{OAuthFlowKind, OAuthTransactionRecord, validate_granted_gmail_scopes},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, SecondsFormat, Utc};
use sqlx::{Row, SqlitePool};
use std::{fmt, num::TryFromIntError};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum RepositoryError {
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    #[error(transparent)]
    Access(#[from] AccessError),
    #[error("stored record is malformed: {0}")]
    Corrupt(&'static str),
    #[error("stored record has an invalid value: {0}")]
    InvalidValue(String),
    #[error("optimistic concurrency conflict")]
    Conflict,
    #[error("personal-use authorization limit reached")]
    PersonalUseLimitReached,
    #[error("integer value is out of range")]
    IntegerRange(#[from] TryFromIntError),
}

/// An encrypted PKCE verifier envelope. The plaintext verifier is never
/// accepted by the repository and is never exposed by this type's Debug
/// implementation.
#[derive(Clone, Eq, PartialEq)]
pub struct EncryptedPkceVerifier(String);

impl EncryptedPkceVerifier {
    pub fn from_envelope(envelope: impl Into<String>) -> Result<Self, RepositoryError> {
        let envelope = envelope.into();
        let mut parts = envelope.split('.');
        let valid = parts.next() == Some(ENVELOPE_PREFIX)
            && parts
                .next()
                .and_then(|value| value.parse::<u32>().ok())
                .is_some_and(|version| version > 0)
            && parts
                .next()
                .and_then(|value| URL_SAFE_NO_PAD.decode(value).ok())
                .is_some_and(|value| value.len() == 24)
            && parts
                .next()
                .and_then(|value| URL_SAFE_NO_PAD.decode(value).ok())
                .is_some_and(|value| !value.is_empty())
            && parts.next().is_none();
        if !valid {
            return Err(RepositoryError::InvalidValue(
                "PKCE verifier must be an AgentMail encrypted envelope".to_owned(),
            ));
        }
        Ok(Self(envelope))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for EncryptedPkceVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EncryptedPkceVerifier([REDACTED])")
    }
}

/// One-time material returned by a successful durable OAuth callback claim.
/// State is intentionally absent: callers receive only the nonce hash and
/// encrypted verifier needed to complete the exchange.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OAuthTransactionClaim {
    pub id: Uuid,
    pub flow: OAuthFlowKind,
    pub nonce_hash: String,
    pub pkce_verifier: EncryptedPkceVerifier,
    pub initiated_by: Option<UserId>,
    pub target_connection: Option<ConnectionId>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Durable browser session metadata. Both bearer values are already one-way
/// digests; plaintext session/CSRF values never cross this boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebSession {
    pub id: SessionId,
    pub user_id: UserId,
    pub token_hash: String,
    pub csrf_token_hash: String,
    pub idle_expires_at: DateTime<Utc>,
    pub absolute_expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
}

/// Input for a new browser session. Token fields must contain SHA-256
/// digests, never the plaintext values sent to a browser.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewWebSession {
    pub id: SessionId,
    pub user_id: UserId,
    pub token_hash: String,
    pub csrf_token_hash: String,
    pub idle_expires_at: DateTime<Utc>,
    pub absolute_expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// Atomic Owner bootstrap/login input. Session credentials are already
/// digests; plaintext values never cross the repository boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewOwnerSession {
    pub expected_owner_email: String,
    pub google_sub: String,
    pub verified_email: String,
    pub session_id: SessionId,
    pub token_hash: String,
    pub csrf_token_hash: String,
    pub idle_expires_at: DateTime<Utc>,
    pub absolute_expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// Durable invitation metadata. The token field is always a SHA-256 digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Invitation {
    pub id: crate::domain::identity::InvitationId,
    pub target_email: String,
    pub token_hash: String,
    pub invited_by: UserId,
    pub expires_at: DateTime<Utc>,
    pub accepted_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Hash-only input for creating an invitation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewInvitation {
    pub id: crate::domain::identity::InvitationId,
    pub target_email: String,
    pub token_hash: String,
    pub invited_by: UserId,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredSendConfirmation {
    pub confirmation: SendConfirmation,
    pub consumed_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DurableSendClaim {
    Claimed {
        confirmation: SendConfirmation,
        draft: ManagedDraft,
    },
    Replayed {
        confirmation: SendConfirmation,
        outcome: SendOutcome,
    },
    InProgress {
        confirmation: SendConfirmation,
    },
}
pub struct EncryptedRefreshToken(String);

impl EncryptedRefreshToken {
    pub fn from_envelope(envelope: impl Into<String>) -> Result<Self, RepositoryError> {
        let envelope = envelope.into();
        if !envelope.starts_with("am1.") || envelope.split('.').count() != 4 {
            return Err(RepositoryError::InvalidValue(
                "refresh token must be an AgentMail encrypted envelope".to_owned(),
            ));
        }
        Ok(Self(envelope))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for EncryptedRefreshToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EncryptedRefreshToken([REDACTED])")
    }
}
#[derive(Clone, Debug)]
pub struct Repository {
    pool: SqlitePool,
}
impl Repository {
    pub fn new(database: &Database) -> Self {
        Self {
            pool: database.pool().clone(),
        }
    }
    pub fn from_pool(pool: SqlitePool) -> Self {
        Self { pool }
    }
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
    /// Persist a newly-created OAuth transaction. Only an encrypted PKCE
    /// envelope may cross this boundary; state and nonce are already hashes
    /// in the OAuth record.
    pub async fn insert_oauth_transaction(
        &self,
        id: Uuid,
        record: &OAuthTransactionRecord,
        pkce_verifier: &EncryptedPkceVerifier,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "INSERT INTO oauth_transactions (id,flow_type,state_hash,pkce_verifier,nonce_hash,initiated_by,target_connection_id,expires_at,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
        )
        .bind(id.to_string())
        .bind(oauth_flow(record.flow))
        .bind(&record.state_hash)
        .bind(pkce_verifier.as_str())
        .bind(&record.nonce_hash)
        .bind(record.initiated_by.as_deref())
        .bind(record.target_connection.as_deref())
        .bind(encode_time(record.expires_at))
        .bind(encode_time(record.created_at))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Atomically claim an OAuth callback. SQLite's UPDATE ... RETURNING
    /// ensures that concurrent callbacks can expose the nonce/verifier to
    /// only the transaction that changed consumed_at.
    pub async fn claim_oauth_transaction(
        &self,
        id: Uuid,
        presented_state: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<OAuthTransactionClaim>, RepositoryError> {
        let state_hash = hash_token(presented_state);
        let row = sqlx::query(
            "UPDATE oauth_transactions SET consumed_at=? WHERE id=? AND consumed_at IS NULL AND expires_at > ? AND state_hash=? RETURNING id,flow_type,nonce_hash,pkce_verifier,initiated_by,target_connection_id,created_at,expires_at",
        )
        .bind(encode_time(now))
        .bind(id.to_string())
        .bind(encode_time(now))
        .bind(state_hash)
        .fetch_optional(&self.pool)
        .await?;
        row.map(oauth_claim_from_row).transpose()
    }

    /// Atomically claim a callback only when its persisted flow matches the route.
    pub async fn claim_oauth_transaction_for_flow(
        &self,
        id: Uuid,
        presented_state: &str,
        flow: OAuthFlowKind,
        now: DateTime<Utc>,
    ) -> Result<Option<OAuthTransactionClaim>, RepositoryError> {
        let state_hash = hash_token(presented_state);
        let row = sqlx::query(
            "UPDATE oauth_transactions SET consumed_at=? WHERE id=? AND flow_type=? AND consumed_at IS NULL AND expires_at > ? AND state_hash=? RETURNING id,flow_type,nonce_hash,pkce_verifier,initiated_by,target_connection_id,created_at,expires_at",
        )
        .bind(encode_time(now))
        .bind(id.to_string())
        .bind(oauth_flow(flow))
        .bind(encode_time(now))
        .bind(state_hash)
        .fetch_optional(&self.pool)
        .await?;
        row.map(oauth_claim_from_row).transpose()
    }

    /// Naming alias for callers that use callback terminology.
    pub async fn claim_oauth_callback(
        &self,
        id: Uuid,
        presented_state: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<OAuthTransactionClaim>, RepositoryError> {
        self.claim_oauth_transaction(id, presented_state, now).await
    }

    pub async fn insert_user(&self, user: &User) -> Result<(), RepositoryError> {
        sqlx::query("INSERT INTO users (id,google_sub,login_email,role,status,last_activity_at,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)")
            .bind(user.id.to_string()).bind(&user.google_sub).bind(&user.email).bind(user_role(user.role)).bind(user_status(user.status))
            .bind(user.last_activity_at.map(encode_time)).bind(encode_time(user.created_at)).bind(encode_time(user.updated_at)).execute(&self.pool).await?;
        Ok(())
    }
    pub async fn get_user(&self, id: UserId) -> Result<Option<User>, RepositoryError> {
        let row = sqlx::query("SELECT id,google_sub,login_email,role,status,last_activity_at,created_at,updated_at FROM users WHERE id=?").bind(id.to_string()).fetch_optional(&self.pool).await?;
        row.map(user_from_row).transpose()
    }
    pub async fn find_user_by_google_sub(
        &self,
        sub: &str,
    ) -> Result<Option<User>, RepositoryError> {
        let row = sqlx::query("SELECT id,google_sub,login_email,role,status,last_activity_at,created_at,updated_at FROM users WHERE google_sub=?").bind(sub).fetch_optional(&self.pool).await?;
        row.map(user_from_row).transpose()
    }
    pub async fn find_user_by_email(&self, email: &str) -> Result<Option<User>, RepositoryError> {
        let email = normalize_email(email)
            .map_err(|_| RepositoryError::InvalidValue("invalid email".to_owned()))?;
        let row = sqlx::query("SELECT id,google_sub,login_email,role,status,last_activity_at,created_at,updated_at FROM users WHERE login_email=?")
            .bind(email)
            .fetch_optional(&self.pool)
            .await?;
        row.map(user_from_row).transpose()
    }

    pub async fn create_invitation(
        &self,
        invitation: &NewInvitation,
    ) -> Result<Invitation, RepositoryError> {
        let target_email = normalize_email(&invitation.target_email)
            .map_err(|_| RepositoryError::InvalidValue("invalid invitation email".to_owned()))?;
        validate_token_hash(&invitation.token_hash, "invitation token hash")?;
        if invitation.expires_at <= invitation.created_at {
            return Err(RepositoryError::InvalidValue(
                "invitation expiry must be in the future".to_owned(),
            ));
        }
        let result = sqlx::query("INSERT INTO invitations (id,target_email,token_hash,invited_by,expires_at,created_at) SELECT ?,?,?,?,?,? WHERE EXISTS (SELECT 1 FROM users WHERE id=? AND role='owner' AND status='active')")
            .bind(invitation.id.to_string())
            .bind(&target_email)
            .bind(&invitation.token_hash)
            .bind(invitation.invited_by.to_string())
            .bind(encode_time(invitation.expires_at))
            .bind(encode_time(invitation.created_at))
            .bind(invitation.invited_by.to_string())
            .execute(&self.pool)
            .await?;
        if result.rows_affected() != 1 {
            return Err(RepositoryError::InvalidValue(
                "owner is not active".to_owned(),
            ));
        }
        Ok(Invitation {
            id: invitation.id,
            target_email,
            token_hash: invitation.token_hash.clone(),
            invited_by: invitation.invited_by,
            expires_at: invitation.expires_at,
            accepted_at: None,
            created_at: invitation.created_at,
        })
    }

    pub async fn list_invitations(
        &self,
        owner_id: UserId,
    ) -> Result<Vec<Invitation>, RepositoryError> {
        let owner: Option<String> = sqlx::query_scalar(
            "SELECT id FROM users WHERE id=? AND role='owner' AND status='active'",
        )
        .bind(owner_id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        if owner.is_none() {
            return Err(RepositoryError::InvalidValue(
                "owner is not active".to_owned(),
            ));
        }
        let rows = sqlx::query(
            "SELECT id,target_email,token_hash,invited_by,expires_at,accepted_at,created_at FROM invitations WHERE invited_by=? ORDER BY created_at DESC,id",
        )
        .bind(owner_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(invitation_from_row).collect()
    }

    /// Atomically consume an invitation and create its Member. UPDATE
    /// RETURNING makes concurrent claims have at most one winner.
    pub async fn claim_invitation(
        &self,
        token_hash: &str,
        verified_email: &str,
        google_sub: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<(Invitation, User)>, RepositoryError> {
        validate_token_hash(token_hash, "invitation token hash")?;
        let verified_email = normalize_email(verified_email)
            .map_err(|_| RepositoryError::InvalidValue("invalid verified email".to_owned()))?;
        if google_sub.trim().is_empty() {
            return Err(RepositoryError::InvalidValue(
                "google subject is empty".to_owned(),
            ));
        }
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query("UPDATE invitations SET accepted_at=? WHERE token_hash=? AND target_email=? AND accepted_at IS NULL AND expires_at > ? AND EXISTS (SELECT 1 FROM users WHERE users.id=invitations.invited_by AND users.role='owner' AND users.status='active') RETURNING id,target_email,token_hash,invited_by,expires_at,accepted_at,created_at")
            .bind(encode_time(now))
            .bind(token_hash)
            .bind(&verified_email)
            .bind(encode_time(now))
            .fetch_optional(&mut *tx)
            .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let invitation = invitation_from_row(row)?;
        let user = User::new(google_sub, &verified_email, UserRole::Member, now)
            .map_err(|_| RepositoryError::InvalidValue("invalid member identity".to_owned()))?;
        sqlx::query("INSERT INTO users (id,google_sub,login_email,role,status,last_activity_at,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)")
            .bind(user.id.to_string())
            .bind(&user.google_sub)
            .bind(&user.email)
            .bind(user_role(user.role))
            .bind(user_status(user.status))
            .bind(user.last_activity_at.map(encode_time))
            .bind(encode_time(user.created_at))
            .bind(encode_time(user.updated_at))
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(Some((invitation, user)))
    }

    /// Revoke an unaccepted invitation. Deletion is the schema's revocation
    /// representation because invitations have no separate revoked_at field.
    pub async fn revoke_invitation(
        &self,
        owner_id: UserId,
        invitation_id: crate::domain::identity::InvitationId,
    ) -> Result<bool, RepositoryError> {
        let owner: Option<String> = sqlx::query_scalar(
            "SELECT id FROM users WHERE id=? AND role='owner' AND status='active'",
        )
        .bind(owner_id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        if owner.is_none() {
            return Err(RepositoryError::InvalidValue(
                "owner is not active".to_owned(),
            ));
        }
        let result = sqlx::query(
            "DELETE FROM invitations WHERE id=? AND invited_by=? AND accepted_at IS NULL",
        )
        .bind(invitation_id.to_string())
        .bind(owner_id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Atomically create the sole initial Owner. The conditional INSERT is a
    /// single SQLite write, so concurrent bootstrap attempts have one winner.
    pub async fn bootstrap_owner(
        &self,
        expected_owner_email: &str,
        google_sub: &str,
        verified_email: &str,
        now: DateTime<Utc>,
    ) -> Result<User, RepositoryError> {
        let expected_owner_email = normalize_email(expected_owner_email)
            .map_err(|_| RepositoryError::InvalidValue("invalid owner email".to_owned()))?;
        let verified_email = normalize_email(verified_email)
            .map_err(|_| RepositoryError::InvalidValue("invalid verified email".to_owned()))?;
        if expected_owner_email != verified_email {
            return Err(RepositoryError::InvalidValue(
                "owner email mismatch".to_owned(),
            ));
        }
        if google_sub.trim().is_empty() {
            return Err(RepositoryError::InvalidValue(
                "google subject is empty".to_owned(),
            ));
        }

        let mut user = User::new(google_sub, &verified_email, UserRole::Owner, now)
            .map_err(|_| RepositoryError::InvalidValue("invalid owner identity".to_owned()))?;
        user.touch(now);
        let result = sqlx::query(
            "INSERT INTO users (id,google_sub,login_email,role,status,last_activity_at,created_at,updated_at) SELECT ?,?,?,?,?,?,?,? WHERE NOT EXISTS (SELECT 1 FROM users WHERE role='owner')",
        )
        .bind(user.id.to_string())
        .bind(&user.google_sub)
        .bind(&user.email)
        .bind(user_role(user.role))
        .bind(user_status(user.status))
        .bind(user.last_activity_at.map(encode_time))
        .bind(encode_time(user.created_at))
        .bind(encode_time(user.updated_at))
        .execute(&self.pool)
        .await?;
        if result.rows_affected() != 1 {
            return Err(RepositoryError::Conflict);
        }
        Ok(user)
    }

    /// Atomically bootstrap or re-authenticate the sole Owner and create a
    /// session. Any session insert failure rolls back a newly inserted user.
    pub async fn bootstrap_owner_with_session(
        &self,
        request: &NewOwnerSession,
    ) -> Result<(User, WebSession), RepositoryError> {
        let expected_owner_email = normalize_email(&request.expected_owner_email)
            .map_err(|_| RepositoryError::InvalidValue("invalid owner email".to_owned()))?;
        let verified_email = normalize_email(&request.verified_email)
            .map_err(|_| RepositoryError::InvalidValue("invalid verified email".to_owned()))?;
        if expected_owner_email != verified_email {
            return Err(RepositoryError::InvalidValue(
                "owner email mismatch".to_owned(),
            ));
        }
        if request.google_sub.trim().is_empty() {
            return Err(RepositoryError::InvalidValue(
                "google subject is empty".to_owned(),
            ));
        }
        validate_token_hash(&request.token_hash, "session token hash")?;
        validate_token_hash(&request.csrf_token_hash, "CSRF token hash")?;
        if request.idle_expires_at <= request.created_at
            || request.absolute_expires_at <= request.created_at
        {
            return Err(RepositoryError::InvalidValue(
                "session expiry must be in the future".to_owned(),
            ));
        }

        let mut candidate = User::new(
            &request.google_sub,
            &verified_email,
            UserRole::Owner,
            request.created_at,
        )
        .map_err(|_| RepositoryError::InvalidValue("invalid owner identity".to_owned()))?;
        candidate.touch(request.created_at);
        let mut tx = self.pool.begin().await?;

        let inserted = sqlx::query(
            "INSERT INTO users (id,google_sub,login_email,role,status,last_activity_at,created_at,updated_at) SELECT ?,?,?,?,?,?,?,? WHERE NOT EXISTS (SELECT 1 FROM users WHERE role='owner')",
        )
        .bind(candidate.id.to_string())
        .bind(&candidate.google_sub)
        .bind(&candidate.email)
        .bind(user_role(candidate.role))
        .bind(user_status(candidate.status))
        .bind(candidate.last_activity_at.map(encode_time))
        .bind(encode_time(candidate.created_at))
        .bind(encode_time(candidate.updated_at))
        .execute(&mut *tx)
        .await?
        .rows_affected()
            == 1;

        let user = if inserted {
            candidate
        } else {
            let row = sqlx::query(
                "SELECT id,google_sub,login_email,role,status,last_activity_at,created_at,updated_at FROM users WHERE role='owner' LIMIT 1",
            )
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(RepositoryError::Conflict)?;
            let owner = user_from_row(row)?;
            if owner.google_sub != request.google_sub
                || owner.email != verified_email
                || owner.role != UserRole::Owner
                || owner.status != UserStatus::Active
            {
                return Err(RepositoryError::InvalidValue(
                    "owner identity mismatch".to_owned(),
                ));
            }
            owner
        };

        let id = request.session_id.to_string();
        sqlx::query("INSERT INTO web_sessions (id,token_hash,user_id,csrf_token_hash,idle_expires_at,absolute_expires_at,created_at,last_seen_at) VALUES (?,?,?,?,?,?,?,?)")
            .bind(&id)
            .bind(&request.token_hash)
            .bind(user.id.to_string())
            .bind(&request.csrf_token_hash)
            .bind(encode_time(request.idle_expires_at))
            .bind(encode_time(request.absolute_expires_at))
            .bind(encode_time(request.created_at))
            .bind(encode_time(request.created_at))
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        let user_id = user.id;
        Ok((
            user,
            WebSession {
                id: request.session_id,
                user_id,
                token_hash: request.token_hash.clone(),
                csrf_token_hash: request.csrf_token_hash.clone(),
                idle_expires_at: request.idle_expires_at,
                absolute_expires_at: request.absolute_expires_at,
                created_at: request.created_at,
                last_seen_at: request.created_at,
            },
        ))
    }

    pub async fn insert_web_session(
        &self,
        session: &NewWebSession,
    ) -> Result<WebSession, RepositoryError> {
        validate_token_hash(&session.token_hash, "session token hash")?;
        validate_token_hash(&session.csrf_token_hash, "CSRF token hash")?;
        if session.idle_expires_at <= session.created_at
            || session.absolute_expires_at <= session.created_at
        {
            return Err(RepositoryError::InvalidValue(
                "session expiry must be in the future".to_owned(),
            ));
        }
        sqlx::query("INSERT INTO web_sessions (id,token_hash,user_id,csrf_token_hash,idle_expires_at,absolute_expires_at,created_at,last_seen_at) VALUES (?,?,?,?,?,?,?,?)")
            .bind(session.id.to_string())
            .bind(&session.token_hash)
            .bind(session.user_id.to_string())
            .bind(&session.csrf_token_hash)
            .bind(encode_time(session.idle_expires_at))
            .bind(encode_time(session.absolute_expires_at))
            .bind(encode_time(session.created_at))
            .bind(encode_time(session.created_at))
            .execute(&self.pool)
            .await?;
        Ok(WebSession {
            id: session.id,
            user_id: session.user_id,
            token_hash: session.token_hash.clone(),
            csrf_token_hash: session.csrf_token_hash.clone(),
            idle_expires_at: session.idle_expires_at,
            absolute_expires_at: session.absolute_expires_at,
            created_at: session.created_at,
            last_seen_at: session.created_at,
        })
    }

    pub async fn lookup_web_session(
        &self,
        token_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<WebSession>, RepositoryError> {
        validate_token_hash(token_hash, "session token hash")?;
        let row = sqlx::query("SELECT s.id,s.token_hash,s.user_id,s.csrf_token_hash,s.idle_expires_at,s.absolute_expires_at,s.created_at,s.last_seen_at FROM web_sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.idle_expires_at > ? AND s.absolute_expires_at > ? AND u.status='active'")
            .bind(token_hash)
            .bind(encode_time(now))
            .bind(encode_time(now))
            .fetch_optional(&self.pool)
            .await?;
        row.map(web_session_from_row).transpose()
    }

    /// Refresh idle expiry while leaving the absolute expiry unchanged.
    pub async fn touch_web_session(
        &self,
        token_hash: &str,
        now: DateTime<Utc>,
        idle_expires_at: DateTime<Utc>,
    ) -> Result<bool, RepositoryError> {
        validate_token_hash(token_hash, "session token hash")?;
        if idle_expires_at <= now {
            return Err(RepositoryError::InvalidValue(
                "session expiry must be in the future".to_owned(),
            ));
        }
        let now = encode_time(now);
        let requested_idle = encode_time(idle_expires_at);
        let result = sqlx::query("UPDATE web_sessions SET idle_expires_at = CASE WHEN ? < absolute_expires_at THEN ? ELSE absolute_expires_at END, last_seen_at=? WHERE token_hash=? AND idle_expires_at > ? AND absolute_expires_at > ? AND EXISTS (SELECT 1 FROM users WHERE users.id=web_sessions.user_id AND users.status='active')")
            .bind(&requested_idle)
            .bind(&requested_idle)
            .bind(&now)
            .bind(token_hash)
            .bind(&now)
            .bind(&now)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn delete_web_session(&self, token_hash: &str) -> Result<bool, RepositoryError> {
        validate_token_hash(token_hash, "session token hash")?;
        let result = sqlx::query("DELETE FROM web_sessions WHERE token_hash=?")
            .bind(token_hash)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn update_user(&self, user: &User) -> Result<bool, RepositoryError> {
        let result = sqlx::query("UPDATE users SET google_sub=?,login_email=?,role=?,status=?,last_activity_at=?,updated_at=? WHERE id=?").bind(&user.google_sub).bind(&user.email).bind(user_role(user.role)).bind(user_status(user.status)).bind(user.last_activity_at.map(encode_time)).bind(encode_time(user.updated_at)).bind(user.id.to_string()).execute(&self.pool).await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn insert_connection(
        &self,
        c: &GmailConnection,
        envelope: Option<&EncryptedRefreshToken>,
    ) -> Result<(), RepositoryError> {
        let now = encode_time(Utc::now());
        let result = sqlx::query("INSERT INTO gmail_connections (id,owner_id,google_sub,primary_email,status,granted_scopes,refresh_token_envelope,last_used_at,created_at,updated_at) SELECT ?,?,?,?,?,?,?,?,?,? WHERE EXISTS (SELECT 1 FROM users WHERE id=? AND status='active')")
            .bind(c.id.to_string())
            .bind(c.owner_id.to_string())
            .bind(&c.google_sub)
            .bind(&c.email)
            .bind(connection_status(c.status))
            .bind(scopes_json(&c.granted_scopes)?)
            .bind(envelope.map(EncryptedRefreshToken::as_str))
            .bind(c.last_used_at.map(encode_time))
            .bind(&now)
            .bind(now.clone())
            .bind(c.owner_id.to_string())
            .execute(&self.pool)
            .await?;
        if result.rows_affected() != 1 {
            return Err(RepositoryError::InvalidValue(
                "connection owner is not active".to_owned(),
            ));
        }
        Ok(())
    }
    pub async fn get_connection(
        &self,
        id: ConnectionId,
    ) -> Result<Option<GmailConnection>, RepositoryError> {
        let row=sqlx::query("SELECT id,owner_id,google_sub,primary_email,status,granted_scopes,last_used_at FROM gmail_connections WHERE id=?").bind(id.to_string()).fetch_optional(&self.pool).await?;
        row.map(connection_from_row).transpose()
    }
    pub async fn list_active_connections_for_user(
        &self,
        user_id: UserId,
    ) -> Result<Vec<GmailConnection>, RepositoryError> {
        let rows = sqlx::query(
            "SELECT id,owner_id,google_sub,primary_email,status,granted_scopes,last_used_at FROM gmail_connections WHERE owner_id=? AND status='active' ORDER BY primary_email,id",
        )
        .bind(user_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(connection_from_row).collect()
    }
    pub async fn list_active_connections_for_access_key(
        &self,
        key_id: AccessKeyId,
        owner_id: UserId,
    ) -> Result<Vec<GmailConnection>, RepositoryError> {
        let rows = sqlx::query(
            "SELECT c.id,c.owner_id,c.google_sub,c.primary_email,c.status,c.granted_scopes,c.last_used_at FROM gmail_connections c JOIN access_key_grants g ON g.connection_id=c.id JOIN access_keys k ON k.id=g.access_key_id WHERE c.owner_id=? AND c.status='active' AND k.id=? AND k.owner_id=? AND k.status='active' ORDER BY c.primary_email,c.id",
        )
        .bind(owner_id.to_string())
        .bind(key_id.to_string())
        .bind(owner_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(connection_from_row).collect()
    }
    pub async fn find_connection_by_google_sub(
        &self,
        sub: &str,
    ) -> Result<Option<GmailConnection>, RepositoryError> {
        let row=sqlx::query("SELECT id,owner_id,google_sub,primary_email,status,granted_scopes,last_used_at FROM gmail_connections WHERE google_sub=?").bind(sub).fetch_optional(&self.pool).await?;
        row.map(connection_from_row).transpose()
    }
    pub async fn update_connection(&self, c: &GmailConnection) -> Result<bool, RepositoryError> {
        let result=sqlx::query("UPDATE gmail_connections SET primary_email=?,status=?,granted_scopes=?,last_used_at=?,updated_at=? WHERE id=?").bind(&c.email).bind(connection_status(c.status)).bind(scopes_json(&c.granted_scopes)?).bind(c.last_used_at.map(encode_time)).bind(encode_time(Utc::now())).bind(c.id.to_string()).execute(&self.pool).await?;
        Ok(result.rows_affected() == 1)
    }
    pub async fn update_refresh_token_envelope(
        &self,
        id: ConnectionId,
        envelope: Option<&EncryptedRefreshToken>,
    ) -> Result<bool, RepositoryError> {
        let result = sqlx::query(
            "UPDATE gmail_connections SET refresh_token_envelope=?,updated_at=? WHERE id=?",
        )
        .bind(envelope.map(EncryptedRefreshToken::as_str))
        .bind(encode_time(Utc::now()))
        .bind(id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Replace a target connection only when owner and previous Google subject
    /// still match. The conditional update prevents a concurrent reauth race.
    pub async fn reauthorize_connection(
        &self,
        id: ConnectionId,
        owner_id: UserId,
        expected_google_sub: &str,
        email: &str,
        scopes: &[String],
        envelope: &EncryptedRefreshToken,
    ) -> Result<bool, RepositoryError> {
        if expected_google_sub.trim().is_empty() {
            return Err(RepositoryError::InvalidValue(
                "google subject must not be empty".to_owned(),
            ));
        }
        let email = normalize_email(email)
            .map_err(|_| RepositoryError::InvalidValue("invalid email".to_owned()))?;
        let scopes = validate_granted_gmail_scopes(scopes.iter()).map_err(|_| {
            RepositoryError::InvalidValue("required Gmail scopes are missing".to_owned())
        })?;
        let mut tx = self.pool.begin().await?;
        let result = sqlx::query(
            "UPDATE gmail_connections SET primary_email=?,status='active',granted_scopes=?,refresh_token_envelope=?,updated_at=? WHERE id=? AND owner_id=? AND google_sub=? AND status <> 'revoking' AND EXISTS (SELECT 1 FROM users WHERE users.id=gmail_connections.owner_id AND users.status='active')",
        )
        .bind(email)
        .bind(scopes_json(&scopes)?)
        .bind(envelope.as_str())
        .bind(encode_time(Utc::now()))
        .bind(id.to_string())
        .bind(owner_id.to_string())
        .bind(expected_google_sub)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn insert_access_key(
        &self,
        created: &NewAccessKey,
    ) -> Result<StoredAccessKey, RepositoryError> {
        let parsed = parse_credential(&created.credential)?;
        if !created.key.verify_credential(&created.credential)? {
            return Err(RepositoryError::InvalidValue(
                "credential does not match key".into(),
            ));
        }
        let key = StoredAccessKey {
            id: created.key.id,
            owner_id: created.key.owner_id,
            name: created.key.name.clone(),
            public_prefix: parsed.public_id.to_string(),
            secret_hash: hash_secret(&parsed.secret)?,
            generation: created.key.generation,
            status: created.key.status,
            grants: created.key.grants.clone(),
            last_used_at: None,
        };
        self.insert_access_key_record(&key).await?;
        Ok(key)
    }
    pub async fn insert_access_key_with_credential(
        &self,
        key: &AccessKey,
        credential: &str,
    ) -> Result<StoredAccessKey, RepositoryError> {
        let parsed = parse_credential(credential)?;
        if parsed.public_id.to_string() != key.public_id.to_string()
            || !key.verify_credential(credential)?
        {
            return Err(RepositoryError::InvalidValue(
                "credential does not match key".into(),
            ));
        }
        let stored = StoredAccessKey {
            id: key.id,
            owner_id: key.owner_id,
            name: key.name.clone(),
            public_prefix: parsed.public_id.to_string(),
            secret_hash: hash_secret(&parsed.secret)?,
            generation: key.generation,
            status: key.status,
            grants: key.grants.clone(),
            last_used_at: None,
        };
        self.insert_access_key_record(&stored).await?;
        Ok(stored)
    }
    async fn insert_access_key_record(&self, k: &StoredAccessKey) -> Result<(), RepositoryError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("INSERT INTO access_keys (id,owner_id,name,public_prefix,secret_hash,generation,status,last_used_at,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)").bind(k.id.to_string()).bind(k.owner_id.to_string()).bind(&k.name).bind(&k.public_prefix).bind(&k.secret_hash).bind(i64::try_from(k.generation)?).bind(key_status(k.status)).bind(k.last_used_at.map(encode_time)).bind(encode_time(Utc::now())).bind(encode_time(Utc::now())).execute(&mut *tx).await?;
        for c in k.grants.iter() {
            sqlx::query("INSERT INTO access_key_grants (access_key_id,connection_id,created_at) VALUES (?,?,?)").bind(k.id.to_string()).bind(c.to_string()).bind(encode_time(Utc::now())).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(())
    }
    pub async fn find_access_key_by_public_prefix(
        &self,
        prefix: &str,
    ) -> Result<Option<StoredAccessKey>, RepositoryError> {
        let row=sqlx::query("SELECT id,owner_id,name,public_prefix,secret_hash,generation,status,last_used_at FROM access_keys WHERE public_prefix=?").bind(prefix).fetch_optional(&self.pool).await?;
        let Some(row) = row else { return Ok(None) };
        self.access_key_from_row(row).await.map(Some)
    }
    pub async fn authenticate_access_key(
        &self,
        credential: &str,
    ) -> Result<Option<StoredAccessKey>, RepositoryError> {
        let parsed = parse_credential(credential)?;
        let Some(mut k) = self
            .find_access_key_by_public_prefix(&parsed.public_id.to_string())
            .await?
        else {
            return Ok(None);
        };
        if !k.verify_credential(credential)? {
            return Ok(None);
        };
        let now = Utc::now();
        sqlx::query("UPDATE access_keys SET last_used_at=?,updated_at=? WHERE id=?")
            .bind(encode_time(now))
            .bind(encode_time(now))
            .bind(k.id.to_string())
            .execute(&self.pool)
            .await?;
        k.last_used_at = Some(now);
        Ok(Some(k))
    }
    pub async fn set_access_key_grant(
        &self,
        key: AccessKeyId,
        connection: ConnectionId,
        granted: bool,
    ) -> Result<(), RepositoryError> {
        let valid: i64 = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM access_keys k JOIN users u ON u.id=k.owner_id JOIN gmail_connections c ON c.owner_id=u.id WHERE k.id=? AND c.id=? AND k.owner_id=c.owner_id AND k.status='active' AND u.status='active' AND c.status='active')",
        )
        .bind(key.to_string())
        .bind(connection.to_string())
        .fetch_one(&self.pool)
        .await?;
        if valid == 0 {
            return Err(RepositoryError::InvalidValue(
                "active key, user, and same-owner connection are required".into(),
            ));
        }
        if granted {
            sqlx::query("INSERT OR IGNORE INTO access_key_grants (access_key_id,connection_id,created_at) VALUES (?,?,?)").bind(key.to_string()).bind(connection.to_string()).bind(encode_time(Utc::now())).execute(&self.pool).await?;
        } else {
            sqlx::query("DELETE FROM access_key_grants WHERE access_key_id=? AND connection_id=?")
                .bind(key.to_string())
                .bind(connection.to_string())
                .execute(&self.pool)
                .await?;
        }
        Ok(())
    }
    pub async fn access_key_allows(
        &self,
        key: AccessKeyId,
        connection: ConnectionId,
    ) -> Result<bool, RepositoryError> {
        let v:i64=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM access_keys k JOIN users u ON u.id=k.owner_id JOIN access_key_grants g ON g.access_key_id=k.id JOIN gmail_connections c ON c.id=g.connection_id WHERE k.id=? AND g.connection_id=? AND k.owner_id=c.owner_id AND k.owner_id=u.id AND k.status='active' AND u.status='active' AND c.status='active')").bind(key.to_string()).bind(connection.to_string()).fetch_one(&self.pool).await?;
        Ok(v != 0)
    }

    pub async fn insert_draft(&self, d: &ManagedDraft) -> Result<(), RepositoryError> {
        let now = encode_time(Utc::now());
        sqlx::query("INSERT INTO managed_drafts (id,connection_id,gmail_draft_id,stable_message_id,current_version,status,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)").bind(d.id.to_string()).bind(d.connection_id.to_string()).bind(&d.gmail_draft_id).bind(&d.message_id).bind(d.version.as_str()).bind(draft_status(d.state)).bind(&now).bind(now.clone()).execute(&self.pool).await?;
        Ok(())
    }
    pub async fn get_draft(&self, id: DraftId) -> Result<Option<ManagedDraft>, RepositoryError> {
        let row=sqlx::query("SELECT id,connection_id,gmail_draft_id,stable_message_id,current_version,status FROM managed_drafts WHERE id=?").bind(id.to_string()).fetch_optional(&self.pool).await?;
        row.map(draft_from_row).transpose()
    }
    pub async fn find_draft_by_gmail_id(
        &self,
        c: ConnectionId,
        gmail_id: &str,
    ) -> Result<Option<ManagedDraft>, RepositoryError> {
        let row=sqlx::query("SELECT id,connection_id,gmail_draft_id,stable_message_id,current_version,status FROM managed_drafts WHERE connection_id=? AND gmail_draft_id=?").bind(c.to_string()).bind(gmail_id).fetch_optional(&self.pool).await?;
        row.map(draft_from_row).transpose()
    }
    pub async fn update_draft_if_version(
        &self,
        d: &ManagedDraft,
        expected: &DraftVersion,
    ) -> Result<bool, RepositoryError> {
        let r=sqlx::query("UPDATE managed_drafts SET current_version=?,status=?,updated_at=? WHERE id=? AND current_version=? AND connection_id=?").bind(d.version.as_str()).bind(draft_status(d.state)).bind(encode_time(Utc::now())).bind(d.id.to_string()).bind(expected.as_str()).bind(d.connection_id.to_string()).execute(&self.pool).await?;
        Ok(r.rows_affected() == 1)
    }
    pub async fn update_draft(
        &self,
        d: &ManagedDraft,
        expected: &DraftVersion,
    ) -> Result<(), RepositoryError> {
        if self.update_draft_if_version(d, expected).await? {
            Ok(())
        } else {
            Err(RepositoryError::Conflict)
        }
    }

    pub async fn insert_send_confirmation(
        &self,
        confirmation: &SendConfirmation,
        now: DateTime<Utc>,
    ) -> Result<(), RepositoryError> {
        if confirmation.invalidated || confirmation.outcome.is_some() {
            return Err(RepositoryError::InvalidValue(
                "new send confirmation state".to_owned(),
            ));
        }
        let token_hash = confirmation.token_hash_hex();
        validate_token_hash(&token_hash, "send confirmation token hash")?;
        sqlx::query("INSERT INTO send_confirmations (id,token_hash,access_key_id,key_generation,connection_id,draft_id,draft_version,expires_at,consumed_at,result_json,created_at) VALUES (?,?,?,?,?,?,?,?,NULL,NULL,?)")
            .bind(confirmation.id.to_string())
            .bind(token_hash)
            .bind(confirmation.key_id.to_string())
            .bind(i64::try_from(confirmation.key_generation)?)
            .bind(confirmation.connection_id.to_string())
            .bind(confirmation.draft_id.to_string())
            .bind(confirmation.draft_version.as_str())
            .bind(encode_time(confirmation.expires_at))
            .bind(encode_time(now))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn lookup_send_confirmation(
        &self,
        token_hash: &str,
    ) -> Result<Option<StoredSendConfirmation>, RepositoryError> {
        validate_token_hash(token_hash, "send confirmation token hash")?;
        let row = sqlx::query("SELECT id,token_hash,access_key_id,key_generation,connection_id,draft_id,draft_version,expires_at,consumed_at,result_json FROM send_confirmations WHERE token_hash=?")
            .bind(token_hash)
            .fetch_optional(&self.pool)
            .await?;
        row.map(send_confirmation_from_row).transpose()
    }

    pub async fn claim_send_confirmation(
        &self,
        token_hash: &str,
        key_id: AccessKeyId,
        generation: u64,
        draft: &ManagedDraft,
        now: DateTime<Utc>,
    ) -> Result<Option<DurableSendClaim>, RepositoryError> {
        validate_token_hash(token_hash, "send confirmation token hash")?;
        let mut transaction = self.pool.begin().await?;
        let row = sqlx::query("SELECT id,token_hash,access_key_id,key_generation,connection_id,draft_id,draft_version,expires_at,consumed_at,result_json FROM send_confirmations WHERE token_hash=?")
            .bind(token_hash)
            .fetch_optional(&mut *transaction)
            .await?;
        let Some(stored) = row.map(send_confirmation_from_row).transpose()? else {
            return Ok(None);
        };
        let confirmation = stored.confirmation;
        if confirmation.key_id != key_id
            || confirmation.key_generation != generation
            || confirmation.connection_id != draft.connection_id
            || confirmation.draft_id != draft.id
            || confirmation.draft_version != draft.version
        {
            return Ok(None);
        }
        if let Some(outcome) = confirmation.outcome.clone() {
            transaction.commit().await?;
            return Ok(Some(DurableSendClaim::Replayed {
                confirmation,
                outcome,
            }));
        }
        if stored.consumed_at.is_some() {
            transaction.commit().await?;
            return Ok(Some(DurableSendClaim::InProgress { confirmation }));
        }
        if confirmation.expires_at <= now || draft.state != ManagedDraftState::Active {
            return Ok(None);
        }
        let mut sending = draft.clone();
        sending
            .mark_sending(&confirmation.draft_version)
            .map_err(|_| RepositoryError::Conflict)?;
        let claimed = sqlx::query("UPDATE send_confirmations SET consumed_at=? WHERE id=? AND token_hash=? AND consumed_at IS NULL AND result_json IS NULL AND expires_at > ?")
            .bind(encode_time(now))
            .bind(confirmation.id.to_string())
            .bind(token_hash)
            .bind(encode_time(now))
            .execute(&mut *transaction)
            .await?;
        if claimed.rows_affected() != 1 {
            return Err(RepositoryError::Conflict);
        }
        let updated = sqlx::query("UPDATE managed_drafts SET status='sending',updated_at=? WHERE id=? AND connection_id=? AND current_version=? AND status='active'")
            .bind(encode_time(now))
            .bind(sending.id.to_string())
            .bind(sending.connection_id.to_string())
            .bind(sending.version.as_str())
            .execute(&mut *transaction)
            .await?;
        if updated.rows_affected() != 1 {
            return Err(RepositoryError::Conflict);
        }
        transaction.commit().await?;
        Ok(Some(DurableSendClaim::Claimed {
            confirmation,
            draft: sending,
        }))
    }

    pub async fn complete_send_confirmation(
        &self,
        confirmation: &SendConfirmation,
        draft: &ManagedDraft,
        now: DateTime<Utc>,
    ) -> Result<(), RepositoryError> {
        let Some(outcome) = confirmation.outcome.as_ref() else {
            return Err(RepositoryError::InvalidValue(
                "send confirmation outcome".to_owned(),
            ));
        };
        if draft.id != confirmation.draft_id
            || draft.connection_id != confirmation.connection_id
            || draft.version != confirmation.draft_version
            || !matches!(
                draft.state,
                ManagedDraftState::Active
                    | ManagedDraftState::Sent
                    | ManagedDraftState::SendStateUnknown
            )
        {
            return Err(RepositoryError::InvalidValue(
                "send confirmation completion state".to_owned(),
            ));
        }
        let result_json =
            serde_json::to_string(outcome).map_err(|_| RepositoryError::Corrupt("send outcome"))?;
        let mut transaction = self.pool.begin().await?;
        let completed = sqlx::query("UPDATE send_confirmations SET result_json=? WHERE id=? AND consumed_at IS NOT NULL AND result_json IS NULL")
            .bind(result_json)
            .bind(confirmation.id.to_string())
            .execute(&mut *transaction)
            .await?;
        if completed.rows_affected() != 1 {
            return Err(RepositoryError::Conflict);
        }
        let updated = sqlx::query("UPDATE managed_drafts SET status=?,updated_at=? WHERE id=? AND connection_id=? AND current_version=? AND status='sending'")
            .bind(draft_status(draft.state))
            .bind(encode_time(now))
            .bind(draft.id.to_string())
            .bind(draft.connection_id.to_string())
            .bind(draft.version.as_str())
            .execute(&mut *transaction)
            .await?;
        if updated.rows_affected() != 1 {
            return Err(RepositoryError::Conflict);
        }
        transaction.commit().await?;
        Ok(())
    }
    pub async fn record_audit_event(&self, e: &AuditEvent) -> Result<(), RepositoryError> {
        sqlx::query("INSERT INTO audit_events (id,user_id,access_key_id,connection_id,operation,result_category,latency_ms,request_id,created_at) VALUES (?,?,?,?,?,?,?,?,?)").bind(e.id.to_string()).bind(e.user_id.map(|v|v.to_string())).bind(e.access_key_id.map(|v|v.to_string())).bind(e.connection_id.map(|v|v.to_string())).bind(e.operation.as_str()).bind(e.result_category.as_str()).bind(i64::try_from(e.latency_ms)?).bind(e.request_id.as_str()).bind(encode_time(e.created_at)).execute(&self.pool).await?;
        Ok(())
    }
    pub async fn record_first_authorized_subject(
        &self,
        sub: &str,
        now: DateTime<Utc>,
        limit: u32,
    ) -> Result<FirstAuthorization, RepositoryError> {
        if sub.trim().is_empty() {
            return Err(RepositoryError::InvalidValue("empty Google subject".into()));
        }
        let mut tx = self.pool.begin().await?;
        let current:i64=sqlx::query_scalar("SELECT counter_value FROM instance_counters WHERE counter_name='historical_gmail_authorizations'").fetch_one(&mut *tx).await?;
        let inserted=sqlx::query("INSERT OR IGNORE INTO authorized_gmail_subjects (google_sub,first_authorized_at) VALUES (?,?)").bind(sub).bind(encode_time(now)).execute(&mut *tx).await?.rows_affected()==1;
        if !inserted {
            tx.commit().await?;
            return Ok(FirstAuthorization {
                first: false,
                historical_authorizations: u32::try_from(current)?,
            });
        }
        if current < 0 || current >= i64::from(limit) {
            return Err(RepositoryError::PersonalUseLimitReached);
        }
        let changed=sqlx::query("UPDATE instance_counters SET counter_value=counter_value+1,updated_at=? WHERE counter_name='historical_gmail_authorizations' AND counter_value=?").bind(encode_time(now)).bind(current).execute(&mut *tx).await?;
        if changed.rows_affected() != 1 {
            return Err(RepositoryError::Conflict);
        }
        tx.commit().await?;
        Ok(FirstAuthorization {
            first: true,
            historical_authorizations: u32::try_from(current + 1)?,
        })
    }
    async fn access_key_from_row(
        &self,
        row: sqlx::sqlite::SqliteRow,
    ) -> Result<StoredAccessKey, RepositoryError> {
        let id = parse_uuid(row.try_get::<String, _>("id")?)?;
        let owner = parse_uuid(row.try_get::<String, _>("owner_id")?)?;
        let rows=sqlx::query("SELECT connection_id FROM access_key_grants WHERE access_key_id=? ORDER BY connection_id").bind(id.to_string()).fetch_all(&self.pool).await?;
        let grants = rows
            .into_iter()
            .map(|r| {
                parse_uuid(r.try_get::<String, _>("connection_id")?).map(ConnectionId::from_uuid)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(StoredAccessKey {
            id: AccessKeyId::from_uuid(id),
            owner_id: UserId::from_uuid(owner),
            name: row.try_get("name")?,
            public_prefix: row.try_get("public_prefix")?,
            secret_hash: row.try_get("secret_hash")?,
            generation: u64::try_from(row.try_get::<i64, _>("generation")?)?,
            status: parse_key_status(row.try_get("status")?)?,
            grants: GrantSet::new(grants),
            last_used_at: parse_opt_time(row.try_get("last_used_at")?)?,
        })
    }
}

pub struct StoredAccessKey {
    pub id: AccessKeyId,
    pub owner_id: UserId,
    pub name: String,
    pub public_prefix: String,
    secret_hash: String,
    pub generation: u64,
    pub status: AccessKeyStatus,
    pub grants: GrantSet,
    pub last_used_at: Option<DateTime<Utc>>,
}
impl fmt::Debug for StoredAccessKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredAccessKey")
            .field("id", &self.id)
            .field("owner_id", &self.owner_id)
            .field("name", &self.name)
            .field("public_prefix", &self.public_prefix)
            .field("generation", &self.generation)
            .field("status", &self.status)
            .field("grants", &self.grants)
            .finish()
    }
}
impl StoredAccessKey {
    pub fn verify_credential(&self, credential: &str) -> Result<bool, RepositoryError> {
        let p = parse_credential(credential)?;
        if p.public_id.to_string() != self.public_prefix || !self.status.accepts_requests() {
            return Ok(false);
        }
        Ok(verify_secret(&p.secret, &self.secret_hash)?)
    }
    pub fn allows(&self, c: ConnectionId) -> bool {
        self.status.accepts_requests() && self.grants.contains(c)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FirstAuthorization {
    pub first: bool,
    pub historical_authorizations: u32,
}

#[async_trait::async_trait]
impl crate::gmail_credentials::GmailCredentialStore for Repository {
    async fn load(
        &self,
        owner_id: UserId,
        connection_id: ConnectionId,
    ) -> Result<
        Option<crate::gmail_credentials::StoredGmailCredential>,
        crate::gmail_credentials::CredentialError,
    > {
        let row = sqlx::query("SELECT c.id,c.owner_id,c.google_sub,c.primary_email,c.status,c.granted_scopes,c.refresh_token_envelope,c.last_used_at FROM gmail_connections c JOIN users u ON u.id=c.owner_id WHERE c.id=? AND c.owner_id=? AND u.status='active'")
            .bind(connection_id.to_string())
            .bind(owner_id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| crate::gmail_credentials::CredentialError::StoreUnavailable)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let envelope = row
            .try_get::<Option<String>, _>("refresh_token_envelope")
            .map_err(|_| crate::gmail_credentials::CredentialError::StoreUnavailable)?
            .map(EncryptedRefreshToken::from_envelope)
            .transpose()
            .map_err(|_| crate::gmail_credentials::CredentialError::InvalidCredential)?
            .map(|value| value.as_str().to_owned());
        let connection = connection_from_row(row)
            .map_err(|_| crate::gmail_credentials::CredentialError::InvalidCredential)?;
        Ok(Some(crate::gmail_credentials::StoredGmailCredential::new(
            connection, envelope,
        )))
    }

    async fn mark_reauth_required(
        &self,
        connection_id: ConnectionId,
    ) -> Result<(), crate::gmail_credentials::CredentialError> {
        let result = sqlx::query("UPDATE gmail_connections SET status='reauth_required',updated_at=? WHERE id=? AND status='active' AND EXISTS (SELECT 1 FROM users WHERE users.id=gmail_connections.owner_id AND users.status='active')")
            .bind(encode_time(Utc::now()))
            .bind(connection_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|_| crate::gmail_credentials::CredentialError::StoreUnavailable)?;
        if result.rows_affected() != 1 {
            return Err(crate::gmail_credentials::CredentialError::AccessDenied);
        }
        Ok(())
    }

    async fn persist_refresh_token(
        &self,
        owner_id: UserId,
        connection_id: ConnectionId,
        envelope: String,
    ) -> Result<(), crate::gmail_credentials::CredentialError> {
        let envelope = EncryptedRefreshToken::from_envelope(envelope)
            .map_err(|_| crate::gmail_credentials::CredentialError::InvalidCredential)?;
        let result = sqlx::query("UPDATE gmail_connections SET refresh_token_envelope=?,updated_at=? WHERE id=? AND owner_id=? AND status='active' AND EXISTS (SELECT 1 FROM users WHERE users.id=gmail_connections.owner_id AND users.status='active')")
            .bind(envelope.as_str())
            .bind(encode_time(Utc::now()))
            .bind(connection_id.to_string())
            .bind(owner_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|_| crate::gmail_credentials::CredentialError::StoreUnavailable)?;
        if result.rows_affected() != 1 {
            return Err(crate::gmail_credentials::CredentialError::AccessDenied);
        }
        Ok(())
    }
}
fn oauth_flow(v: OAuthFlowKind) -> &'static str {
    match v {
        OAuthFlowKind::Login => "login",
        OAuthFlowKind::Gmail => "gmail",
    }
}
fn parse_oauth_flow(v: String) -> Result<OAuthFlowKind, RepositoryError> {
    match v.as_str() {
        "login" => Ok(OAuthFlowKind::Login),
        "gmail" => Ok(OAuthFlowKind::Gmail),
        _ => Err(RepositoryError::InvalidValue(v)),
    }
}
fn parse_optional_id<T>(
    value: Option<String>,
    constructor: fn(Uuid) -> T,
) -> Result<Option<T>, RepositoryError> {
    value
        .map(|value| parse_uuid(value).map(constructor))
        .transpose()
}
fn oauth_claim_from_row(
    r: sqlx::sqlite::SqliteRow,
) -> Result<OAuthTransactionClaim, RepositoryError> {
    let id = parse_uuid(r.try_get("id")?)?;
    let envelope = EncryptedPkceVerifier::from_envelope(r.try_get::<String, _>("pkce_verifier")?)?;
    Ok(OAuthTransactionClaim {
        id,
        flow: parse_oauth_flow(r.try_get("flow_type")?)?,
        nonce_hash: r.try_get("nonce_hash")?,
        pkce_verifier: envelope,
        initiated_by: parse_optional_id(r.try_get("initiated_by")?, UserId::from_uuid)?,
        target_connection: parse_optional_id(
            r.try_get("target_connection_id")?,
            ConnectionId::from_uuid,
        )?,
        created_at: parse_time(r.try_get("created_at")?)?,
        expires_at: parse_time(r.try_get("expires_at")?)?,
    })
}
fn user_role(v: UserRole) -> &'static str {
    match v {
        UserRole::Owner => "owner",
        UserRole::Member => "member",
    }
}
fn parse_user_role(v: String) -> Result<UserRole, RepositoryError> {
    match v.as_str() {
        "owner" => Ok(UserRole::Owner),
        "member" => Ok(UserRole::Member),
        _ => Err(RepositoryError::InvalidValue(v)),
    }
}
fn user_status(v: UserStatus) -> &'static str {
    match v {
        UserStatus::Active => "active",
        UserStatus::Revoking => "revoking",
    }
}
fn parse_user_status(v: String) -> Result<UserStatus, RepositoryError> {
    match v.as_str() {
        "active" => Ok(UserStatus::Active),
        "revoking" => Ok(UserStatus::Revoking),
        _ => Err(RepositoryError::InvalidValue(v)),
    }
}
fn connection_status(v: ConnectionStatus) -> &'static str {
    match v {
        ConnectionStatus::Active => "active",
        ConnectionStatus::ReauthRequired => "reauth_required",
        ConnectionStatus::Revoking => "revoking",
    }
}
fn parse_connection_status(v: String) -> Result<ConnectionStatus, RepositoryError> {
    match v.as_str() {
        "active" => Ok(ConnectionStatus::Active),
        "reauth_required" => Ok(ConnectionStatus::ReauthRequired),
        "revoking" => Ok(ConnectionStatus::Revoking),
        _ => Err(RepositoryError::InvalidValue(v)),
    }
}
fn key_status(v: AccessKeyStatus) -> &'static str {
    match v {
        AccessKeyStatus::Active => "active",
        AccessKeyStatus::Revoked => "revoked",
    }
}
fn parse_key_status(v: String) -> Result<AccessKeyStatus, RepositoryError> {
    match v.as_str() {
        "active" => Ok(AccessKeyStatus::Active),
        "revoked" => Ok(AccessKeyStatus::Revoked),
        _ => Err(RepositoryError::InvalidValue(v)),
    }
}
fn draft_status(v: ManagedDraftState) -> &'static str {
    match v {
        ManagedDraftState::Active => "active",
        ManagedDraftState::Sending => "sending",
        ManagedDraftState::Sent => "sent",
        ManagedDraftState::Deleted => "deleted",
        ManagedDraftState::SendStateUnknown => "send_state_unknown",
    }
}
fn parse_draft_status(v: String) -> Result<ManagedDraftState, RepositoryError> {
    match v.as_str() {
        "active" => Ok(ManagedDraftState::Active),
        "sending" => Ok(ManagedDraftState::Sending),
        "sent" => Ok(ManagedDraftState::Sent),
        "deleted" => Ok(ManagedDraftState::Deleted),
        "send_state_unknown" => Ok(ManagedDraftState::SendStateUnknown),
        _ => Err(RepositoryError::InvalidValue(v)),
    }
}
fn encode_time(v: DateTime<Utc>) -> String {
    v.to_rfc3339_opts(SecondsFormat::Nanos, true)
}
fn parse_time(v: String) -> Result<DateTime<Utc>, RepositoryError> {
    DateTime::parse_from_rfc3339(&v)
        .map(|x| x.with_timezone(&Utc))
        .map_err(|_| RepositoryError::InvalidValue("invalid timestamp".into()))
}
fn parse_opt_time(v: Option<String>) -> Result<Option<DateTime<Utc>>, RepositoryError> {
    v.map(parse_time).transpose()
}
fn parse_uuid(v: String) -> Result<Uuid, RepositoryError> {
    Uuid::parse_str(&v).map_err(|_| RepositoryError::InvalidValue("invalid UUID".into()))
}
fn validate_token_hash(value: &str, field: &'static str) -> Result<(), RepositoryError> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(RepositoryError::InvalidValue(field.to_owned()));
    }
    Ok(())
}
fn scopes_json(v: &[String]) -> Result<String, RepositoryError> {
    serde_json::to_string(v).map_err(|_| RepositoryError::Corrupt("scopes"))
}
fn scopes_from_json(v: String) -> Result<Vec<String>, RepositoryError> {
    serde_json::from_str(&v).map_err(|_| RepositoryError::Corrupt("scopes"))
}
fn user_from_row(r: sqlx::sqlite::SqliteRow) -> Result<User, RepositoryError> {
    Ok(User {
        id: UserId::from_uuid(parse_uuid(r.try_get("id")?)?),
        google_sub: r.try_get("google_sub")?,
        email: r.try_get("login_email")?,
        role: parse_user_role(r.try_get("role")?)?,
        status: parse_user_status(r.try_get("status")?)?,
        last_activity_at: parse_opt_time(r.try_get("last_activity_at")?)?,
        created_at: parse_time(r.try_get("created_at")?)?,
        updated_at: parse_time(r.try_get("updated_at")?)?,
    })
}
fn web_session_from_row(r: sqlx::sqlite::SqliteRow) -> Result<WebSession, RepositoryError> {
    Ok(WebSession {
        id: SessionId::from_uuid(parse_uuid(r.try_get("id")?)?),
        token_hash: r.try_get("token_hash")?,
        user_id: UserId::from_uuid(parse_uuid(r.try_get("user_id")?)?),
        csrf_token_hash: r.try_get("csrf_token_hash")?,
        idle_expires_at: parse_time(r.try_get("idle_expires_at")?)?,
        absolute_expires_at: parse_time(r.try_get("absolute_expires_at")?)?,
        created_at: parse_time(r.try_get("created_at")?)?,
        last_seen_at: parse_time(r.try_get("last_seen_at")?)?,
    })
}

fn invitation_from_row(r: sqlx::sqlite::SqliteRow) -> Result<Invitation, RepositoryError> {
    Ok(Invitation {
        id: crate::domain::identity::InvitationId::from_uuid(parse_uuid(r.try_get("id")?)?),
        target_email: r.try_get("target_email")?,
        token_hash: r.try_get("token_hash")?,
        invited_by: UserId::from_uuid(parse_uuid(r.try_get("invited_by")?)?),
        expires_at: parse_time(r.try_get("expires_at")?)?,
        accepted_at: parse_opt_time(r.try_get("accepted_at")?)?,
        created_at: parse_time(r.try_get("created_at")?)?,
    })
}
fn connection_from_row(r: sqlx::sqlite::SqliteRow) -> Result<GmailConnection, RepositoryError> {
    let id = ConnectionId::from_uuid(parse_uuid(r.try_get("id")?)?);
    let owner = UserId::from_uuid(parse_uuid(r.try_get("owner_id")?)?);
    let scopes = scopes_from_json(r.try_get("granted_scopes")?)?;
    let mut c = GmailConnection::new(
        owner,
        r.try_get::<String, _>("google_sub")?,
        r.try_get::<String, _>("primary_email")?,
        scopes,
    )
    .map_err(|_| RepositoryError::Corrupt("gmail connection"))?;
    c.id = id;
    c.status = parse_connection_status(r.try_get("status")?)?;
    c.last_used_at = parse_opt_time(r.try_get("last_used_at")?)?;
    Ok(c)
}
fn draft_from_row(r: sqlx::sqlite::SqliteRow) -> Result<ManagedDraft, RepositoryError> {
    Ok(ManagedDraft {
        id: DraftId::from_uuid(parse_uuid(r.try_get("id")?)?),
        connection_id: ConnectionId::from_uuid(parse_uuid(r.try_get("connection_id")?)?),
        gmail_draft_id: r.try_get("gmail_draft_id")?,
        message_id: r.try_get("stable_message_id")?,
        version: DraftVersion::new(r.try_get::<String, _>("current_version")?)
            .map_err(|_| RepositoryError::Corrupt("draft version"))?,
        state: parse_draft_status(r.try_get("status")?)?,
    })
}

fn decode_token_hash(value: String) -> Result<[u8; 32], RepositoryError> {
    validate_token_hash(&value, "send confirmation token hash")?;
    let mut hash = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        hash[index] = std::str::from_utf8(pair)
            .ok()
            .and_then(|pair| u8::from_str_radix(pair, 16).ok())
            .ok_or(RepositoryError::Corrupt("send confirmation token hash"))?;
    }
    Ok(hash)
}
fn send_confirmation_from_row(
    row: sqlx::sqlite::SqliteRow,
) -> Result<StoredSendConfirmation, RepositoryError> {
    let result_json: Option<String> = row.try_get("result_json")?;
    let outcome = result_json
        .map(|value| {
            serde_json::from_str(&value).map_err(|_| RepositoryError::Corrupt("send outcome"))
        })
        .transpose()?;
    let key_generation: i64 = row.try_get("key_generation")?;
    Ok(StoredSendConfirmation {
        confirmation: SendConfirmation {
            id: ConfirmationId::from_uuid(parse_uuid(row.try_get("id")?)?),
            token_hash: decode_token_hash(row.try_get("token_hash")?)?,
            key_id: AccessKeyId::from_uuid(parse_uuid(row.try_get("access_key_id")?)?),
            key_generation: u64::try_from(key_generation)
                .map_err(|_| RepositoryError::Corrupt("send confirmation generation"))?,
            connection_id: ConnectionId::from_uuid(parse_uuid(row.try_get("connection_id")?)?),
            draft_id: DraftId::from_uuid(parse_uuid(row.try_get("draft_id")?)?),
            draft_version: DraftVersion::new(row.try_get::<String, _>("draft_version")?)
                .map_err(|_| RepositoryError::Corrupt("send confirmation version"))?,
            expires_at: parse_time(row.try_get("expires_at")?)?,
            invalidated: false,
            outcome,
        },
        consumed_at: parse_opt_time(row.try_get("consumed_at")?)?,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Keyring;
    use crate::domain::identity::{GMAIL_COMPOSE_SCOPE, GMAIL_READONLY_SCOPE};
    use crate::oauth::LoginFlow;
    use chrono::Duration;
    use std::collections::BTreeMap;
    use tempfile::tempdir;

    async fn repository() -> Repository {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        db.migrate().await.unwrap();
        Repository::new(&db)
    }

    fn test_keyring() -> Keyring {
        Keyring::new(1, BTreeMap::from([(1, [7; 32])])).unwrap()
    }

    async fn insert_oauth(
        repository: &Repository,
        ttl: Duration,
    ) -> (Uuid, LoginFlow, DateTime<Utc>) {
        let now = Utc::now();
        let flow = LoginFlow::with_ttl(
            &url::Url::parse("https://agentmail.example").unwrap(),
            "client",
            now,
            ttl,
        )
        .unwrap();
        let id = Uuid::now_v7();
        let envelope = flow
            .transaction()
            .encrypted_pkce_verifier(&id.to_string(), &test_keyring())
            .unwrap();
        let envelope = EncryptedPkceVerifier::from_envelope(envelope).unwrap();
        repository
            .insert_oauth_transaction(id, &flow.transaction().persistence(), &envelope)
            .await
            .unwrap();
        (id, flow, now)
    }
    fn owner() -> User {
        User::new(
            "owner-sub",
            "Owner@Example.com",
            UserRole::Owner,
            Utc::now(),
        )
        .unwrap()
    }

    async fn connection(repository: &Repository, user: &User) -> GmailConnection {
        let connection = GmailConnection::new(
            user.id,
            "gmail-sub",
            "Mail@Example.com",
            vec![GMAIL_READONLY_SCOPE.into(), GMAIL_COMPOSE_SCOPE.into()],
        )
        .unwrap();
        repository
            .insert_connection(&connection, None)
            .await
            .unwrap();
        connection
    }

    #[test]
    fn refresh_token_storage_requires_an_encrypted_envelope() {
        assert!(EncryptedRefreshToken::from_envelope("plain-refresh-token").is_err());
        let encrypted = EncryptedRefreshToken::from_envelope("am1.1.nonce.ciphertext").unwrap();
        assert!(!format!("{encrypted:?}").contains("ciphertext"));
    }
    #[tokio::test]
    async fn users_and_connections_round_trip() {
        let repository = repository().await;
        let user = owner();
        repository.insert_user(&user).await.unwrap();
        let _connection = connection(&repository, &user).await;
        assert_eq!(
            repository
                .find_connection_by_google_sub("gmail-sub")
                .await
                .unwrap()
                .unwrap()
                .email,
            "mail@example.com"
        );
    }

    #[tokio::test]
    async fn owner_bootstrap_requires_matching_verified_email_and_is_unique() {
        let repository = repository().await;
        let now = Utc::now();
        let mismatch = repository
            .bootstrap_owner("owner@example.com", "owner-sub", "other@example.com", now)
            .await;
        assert!(
            matches!(mismatch, Err(RepositoryError::InvalidValue(message)) if message == "owner email mismatch")
        );
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(repository.pool())
            .await
            .unwrap();
        assert_eq!(count, 0);

        let created = repository
            .bootstrap_owner("Owner@Example.com", "owner-sub", "OWNER@example.com", now)
            .await
            .unwrap();
        assert_eq!(created.role, UserRole::Owner);
        assert_eq!(created.email, "owner@example.com");
        assert!(created.last_activity_at.is_some());
        assert_eq!(
            repository
                .find_user_by_email(" OWNER@EXAMPLE.COM ")
                .await
                .unwrap()
                .unwrap()
                .id,
            created.id
        );
        assert_eq!(
            repository
                .find_user_by_google_sub("owner-sub")
                .await
                .unwrap()
                .unwrap()
                .id,
            created.id
        );
        assert!(matches!(
            repository
                .bootstrap_owner("owner@example.com", "other-sub", "owner@example.com", now)
                .await,
            Err(RepositoryError::Conflict)
        ));
    }

    #[tokio::test]
    async fn owner_bootstrap_has_one_concurrent_winner() {
        let dir = tempdir().unwrap();
        let database = Database::connect(format!(
            "sqlite://{}",
            dir.path().join("bootstrap.db").display()
        ))
        .await
        .unwrap();
        database.migrate().await.unwrap();
        let repository = Repository::new(&database);
        let now = Utc::now();
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let repository = repository.clone();
            tasks.push(tokio::spawn(async move {
                repository
                    .bootstrap_owner("owner@example.com", "owner-sub", "owner@example.com", now)
                    .await
            }));
        }
        let mut winners = 0;
        for task in tasks {
            if task.await.unwrap().is_ok() {
                winners += 1;
            }
        }
        assert_eq!(winners, 1);
        let owners: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE role='owner'")
            .fetch_one(repository.pool())
            .await
            .unwrap();
        assert_eq!(owners, 1);
    }

    #[tokio::test]
    async fn owner_and_first_session_are_atomic_and_returning_login_is_allowed() {
        let repository = repository().await;
        let now = Utc::now();
        let member = User::new("member-sub", "member@example.com", UserRole::Member, now).unwrap();
        repository.insert_user(&member).await.unwrap();
        let duplicate_session_id = SessionId::new();
        repository
            .insert_web_session(&NewWebSession {
                id: duplicate_session_id,
                user_id: member.id,
                token_hash: hash_token("existing-session"),
                csrf_token_hash: hash_token("existing-csrf"),
                idle_expires_at: now + Duration::minutes(10),
                absolute_expires_at: now + Duration::hours(1),
                created_at: now,
            })
            .await
            .unwrap();

        let failed = repository
            .bootstrap_owner_with_session(&NewOwnerSession {
                expected_owner_email: "owner@example.com".to_owned(),
                google_sub: "owner-sub".to_owned(),
                verified_email: "owner@example.com".to_owned(),
                session_id: duplicate_session_id,
                token_hash: hash_token("failed-session"),
                csrf_token_hash: hash_token("failed-csrf"),
                idle_expires_at: now + Duration::minutes(10),
                absolute_expires_at: now + Duration::hours(1),
                created_at: now,
            })
            .await;
        assert!(failed.is_err());
        let owner_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE role='owner'")
            .fetch_one(repository.pool())
            .await
            .unwrap();
        assert_eq!(owner_count, 0);

        let first = repository
            .bootstrap_owner_with_session(&NewOwnerSession {
                expected_owner_email: "owner@example.com".to_owned(),
                google_sub: "owner-sub".to_owned(),
                verified_email: "owner@example.com".to_owned(),
                session_id: SessionId::new(),
                token_hash: hash_token("owner-session-one"),
                csrf_token_hash: hash_token("owner-csrf-one"),
                idle_expires_at: now + Duration::minutes(10),
                absolute_expires_at: now + Duration::hours(1),
                created_at: now,
            })
            .await
            .unwrap();
        let returning = repository
            .bootstrap_owner_with_session(&NewOwnerSession {
                expected_owner_email: "owner@example.com".to_owned(),
                google_sub: "owner-sub".to_owned(),
                verified_email: "OWNER@example.com".to_owned(),
                session_id: SessionId::new(),
                token_hash: hash_token("owner-session-two"),
                csrf_token_hash: hash_token("owner-csrf-two"),
                idle_expires_at: now + Duration::minutes(10),
                absolute_expires_at: now + Duration::hours(1),
                created_at: now,
            })
            .await
            .unwrap();
        assert_eq!(first.0.id, returning.0.id);
        let owner_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE role='owner'")
            .fetch_one(repository.pool())
            .await
            .unwrap();
        assert_eq!(owner_count, 1);
    }
    #[tokio::test]
    async fn web_sessions_are_hash_only_expire_and_follow_user_status() {
        let repository = repository().await;
        let now = Utc::now();
        let user = repository
            .bootstrap_owner("owner@example.com", "owner-sub", "owner@example.com", now)
            .await
            .unwrap();
        let plaintext = "session-secret";
        let csrf_plaintext = "csrf-secret";
        let token_hash = hash_token(plaintext);
        let csrf_token_hash = hash_token(csrf_plaintext);
        assert!(
            repository
                .insert_web_session(&NewWebSession {
                    id: SessionId::new(),
                    user_id: user.id,
                    token_hash: plaintext.to_owned(),
                    csrf_token_hash: csrf_token_hash.clone(),
                    idle_expires_at: now + Duration::minutes(10),
                    absolute_expires_at: now + Duration::hours(1),
                    created_at: now,
                })
                .await
                .is_err()
        );
        let session = NewWebSession {
            id: SessionId::new(),
            user_id: user.id,
            token_hash: token_hash.clone(),
            csrf_token_hash: csrf_token_hash.clone(),
            idle_expires_at: now + Duration::minutes(10),
            absolute_expires_at: now + Duration::hours(1),
            created_at: now,
        };
        repository.insert_web_session(&session).await.unwrap();
        let stored_token: String = sqlx::query_scalar("SELECT token_hash FROM web_sessions")
            .fetch_one(repository.pool())
            .await
            .unwrap();
        let stored_csrf: String = sqlx::query_scalar("SELECT csrf_token_hash FROM web_sessions")
            .fetch_one(repository.pool())
            .await
            .unwrap();
        assert_eq!(stored_token, token_hash);
        assert_eq!(stored_csrf, csrf_token_hash);
        assert!(!stored_token.contains(plaintext));
        assert!(!stored_csrf.contains(csrf_plaintext));
        assert!(repository.lookup_web_session(plaintext, now).await.is_err());

        let active = repository
            .lookup_web_session(&token_hash, now + Duration::minutes(1))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(active.user_id, user.id);
        assert!(
            repository
                .touch_web_session(
                    &token_hash,
                    now + Duration::minutes(1),
                    now + Duration::hours(2)
                )
                .await
                .unwrap()
        );
        let touched = repository
            .lookup_web_session(&token_hash, now + Duration::minutes(2))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(touched.idle_expires_at, touched.absolute_expires_at);
        assert_eq!(touched.absolute_expires_at, now + Duration::hours(1));

        let idle_hash = hash_token("idle-session");
        repository
            .insert_web_session(&NewWebSession {
                id: SessionId::new(),
                user_id: user.id,
                token_hash: idle_hash.clone(),
                csrf_token_hash: hash_token("idle-csrf"),
                idle_expires_at: now + Duration::minutes(1),
                absolute_expires_at: now + Duration::hours(1),
                created_at: now,
            })
            .await
            .unwrap();
        assert!(
            repository
                .lookup_web_session(&idle_hash, now + Duration::minutes(2))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            !repository
                .touch_web_session(
                    &idle_hash,
                    now + Duration::minutes(2),
                    now + Duration::hours(1)
                )
                .await
                .unwrap()
        );

        let absolute_hash = hash_token("absolute-session");
        repository
            .insert_web_session(&NewWebSession {
                id: SessionId::new(),
                user_id: user.id,
                token_hash: absolute_hash.clone(),
                csrf_token_hash: hash_token("absolute-csrf"),
                idle_expires_at: now + Duration::hours(1),
                absolute_expires_at: now + Duration::minutes(2),
                created_at: now,
            })
            .await
            .unwrap();
        assert!(
            repository
                .lookup_web_session(&absolute_hash, now + Duration::minutes(3))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            !repository
                .touch_web_session(
                    &absolute_hash,
                    now + Duration::minutes(3),
                    now + Duration::hours(1)
                )
                .await
                .unwrap()
        );

        let mut revoked = user.clone();
        assert!(revoked.begin_revoke(now + Duration::minutes(4)));
        repository.update_user(&revoked).await.unwrap();
        assert!(
            repository
                .lookup_web_session(&token_hash, now + Duration::minutes(4))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            !repository
                .touch_web_session(
                    &token_hash,
                    now + Duration::minutes(4),
                    now + Duration::hours(1)
                )
                .await
                .unwrap()
        );
        assert!(repository.delete_web_session(&token_hash).await.unwrap());
        assert!(!repository.delete_web_session(&token_hash).await.unwrap());
    }

    #[tokio::test]
    async fn access_auth_grants_and_secret_redaction() {
        let repository = repository().await;
        let user = owner();
        repository.insert_user(&user).await.unwrap();
        let connection = connection(&repository, &user).await;
        let created = AccessKey::generate(user.id, "test-key", [connection.id]).unwrap();
        let credential = created.credential.clone();
        let stored = repository.insert_access_key(&created).await.unwrap();
        assert!(
            repository
                .authenticate_access_key(&credential)
                .await
                .unwrap()
                .unwrap()
                .verify_credential(&credential)
                .unwrap()
        );
        assert!(stored.allows(connection.id));
        repository
            .set_access_key_grant(stored.id, connection.id, false)
            .await
            .unwrap();
        assert!(
            !repository
                .access_key_allows(stored.id, connection.id)
                .await
                .unwrap()
        );
        let hash: String = sqlx::query_scalar("SELECT secret_hash FROM access_keys")
            .fetch_one(repository.pool())
            .await
            .unwrap();
        assert!(!hash.contains(&credential));
        assert!(!format!("{stored:?}").contains("secret_hash"));
    }

    #[tokio::test]
    async fn access_grants_cannot_cross_user_boundaries() {
        let repository = repository().await;
        let first = owner();
        let second = User::new(
            "member-sub",
            "member@example.com",
            UserRole::Member,
            Utc::now(),
        )
        .unwrap();
        repository.insert_user(&first).await.unwrap();
        repository.insert_user(&second).await.unwrap();
        let foreign_connection = connection(&repository, &second).await;
        let key = AccessKey::generate(first.id, "first-key", []).unwrap();
        let stored = repository.insert_access_key(&key).await.unwrap();

        assert!(matches!(
            repository
                .set_access_key_grant(stored.id, foreign_connection.id, true)
                .await,
            Err(RepositoryError::InvalidValue(_))
        ));
        assert!(
            !repository
                .access_key_allows(stored.id, foreign_connection.id)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn drafts_use_version_conflict_and_ledger_is_monotonic() {
        let repository = repository().await;
        let user = owner();
        repository.insert_user(&user).await.unwrap();
        let connection = connection(&repository, &user).await;
        let draft = ManagedDraft::new(connection.id, "gmail-draft", "<stable@example.com>", "body")
            .unwrap();
        let expected = draft.version.clone();
        repository.insert_draft(&draft).await.unwrap();
        let mut changed = draft.clone();
        changed.update(&expected, "new body").unwrap();
        assert!(
            repository
                .update_draft_if_version(&changed, &expected)
                .await
                .unwrap()
        );
        assert!(
            !repository
                .update_draft_if_version(&draft, &expected)
                .await
                .unwrap()
        );
        let now = Utc::now();
        assert_eq!(
            repository
                .record_first_authorized_subject("subject-1", now, 1)
                .await
                .unwrap(),
            FirstAuthorization {
                first: true,
                historical_authorizations: 1
            }
        );
        assert_eq!(
            repository
                .record_first_authorized_subject("subject-1", now, 1)
                .await
                .unwrap(),
            FirstAuthorization {
                first: false,
                historical_authorizations: 1
            }
        );
        assert!(matches!(
            repository
                .record_first_authorized_subject("subject-2", now, 1)
                .await,
            Err(RepositoryError::PersonalUseLimitReached)
        ));
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM authorized_gmail_subjects")
            .fetch_one(repository.pool())
            .await
            .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn oauth_claim_is_state_bound_and_single_use() {
        let repository = repository().await;
        let (id, flow, now) = insert_oauth(&repository, Duration::minutes(10)).await;
        assert!(
            repository
                .claim_oauth_transaction(id, "wrong-state", now)
                .await
                .unwrap()
                .is_none()
        );
        let claim = repository
            .claim_oauth_transaction(id, flow.state(), now)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(claim.id, id);
        assert_eq!(claim.flow, OAuthFlowKind::Login);
        assert_eq!(claim.nonce_hash, flow.transaction().nonce_hash());
        assert!(claim.pkce_verifier.as_str().starts_with("am1."));
        assert!(format!("{claim:?}").contains("REDACTED"));
        assert!(
            repository
                .claim_oauth_transaction(id, flow.state(), now)
                .await
                .unwrap()
                .is_none()
        );
        let consumed: Option<String> =
            sqlx::query_scalar("SELECT consumed_at FROM oauth_transactions WHERE id=?")
                .bind(id.to_string())
                .fetch_one(repository.pool())
                .await
                .unwrap();
        assert!(consumed.is_some());
    }

    #[tokio::test]
    async fn oauth_claim_rejects_expired_transaction() {
        let repository = repository().await;
        let (id, flow, now) = insert_oauth(&repository, Duration::seconds(1)).await;
        assert!(
            repository
                .claim_oauth_transaction(id, flow.state(), now + Duration::seconds(1))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn oauth_claim_has_one_winner_under_concurrency() {
        let dir = tempdir().unwrap();
        let database = Database::connect(format!(
            "sqlite://{}",
            dir.path().join("oauth.db").display()
        ))
        .await
        .unwrap();
        database.migrate().await.unwrap();
        let repository = Repository::new(&database);
        let (id, flow, now) = insert_oauth(&repository, Duration::minutes(10)).await;
        let state = flow.state().to_owned();
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let repository = repository.clone();
            let state = state.clone();
            tasks.push(tokio::spawn(async move {
                repository.claim_oauth_transaction(id, &state, now).await
            }));
        }
        let mut winners = 0;
        for task in tasks {
            if task.await.unwrap().unwrap().is_some() {
                winners += 1;
            }
        }
        assert_eq!(winners, 1);
    }

    #[tokio::test]
    async fn flow_scoped_claim_rejects_wrong_flow_without_consuming() {
        let repository = repository().await;
        let (id, flow, now) = insert_oauth(&repository, Duration::minutes(10)).await;

        assert!(
            repository
                .claim_oauth_transaction_for_flow(id, flow.state(), OAuthFlowKind::Gmail, now)
                .await
                .unwrap()
                .is_none()
        );
        let claim = repository
            .claim_oauth_transaction_for_flow(id, flow.state(), OAuthFlowKind::Login, now)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(claim.flow, OAuthFlowKind::Login);
    }

    #[tokio::test]
    async fn reauthorize_preserves_id_and_updates_identity_material() {
        let repository = repository().await;
        let user = owner();
        repository.insert_user(&user).await.unwrap();
        let connection = connection(&repository, &user).await;
        let scopes = vec![
            GMAIL_READONLY_SCOPE.to_owned(),
            GMAIL_COMPOSE_SCOPE.to_owned(),
        ];
        let envelope = EncryptedRefreshToken::from_envelope("am1.1.rotated.ciphertext").unwrap();

        assert!(
            repository
                .reauthorize_connection(
                    connection.id,
                    user.id,
                    "gmail-sub",
                    "Updated@Example.com",
                    &scopes,
                    &envelope,
                )
                .await
                .unwrap()
        );
        let updated = repository
            .get_connection(connection.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated.id, connection.id);
        assert_eq!(updated.owner_id, user.id);
        assert_eq!(updated.google_sub, "gmail-sub");
        assert_eq!(updated.email, "updated@example.com");
        assert_eq!(
            updated.granted_scopes,
            vec![
                crate::oauth::GMAIL_READONLY_SCOPE.to_owned(),
                crate::oauth::GMAIL_COMPOSE_SCOPE.to_owned(),
            ]
        );
        assert_eq!(updated.status, ConnectionStatus::Active);
        let stored_envelope: String =
            sqlx::query_scalar("SELECT refresh_token_envelope FROM gmail_connections WHERE id=?")
                .bind(connection.id.to_string())
                .fetch_one(repository.pool())
                .await
                .unwrap();
        assert_eq!(stored_envelope, envelope.as_str());
    }

    #[tokio::test]
    async fn reauthorize_rejects_wrong_owner_subject_revoking_and_inactive_owner() {
        let repository = repository().await;
        let now = Utc::now();
        let user = owner();
        let other = User::new("other-sub", "other@example.com", UserRole::Member, now).unwrap();
        repository.insert_user(&user).await.unwrap();
        repository.insert_user(&other).await.unwrap();
        let connection = connection(&repository, &user).await;
        let scopes = vec![
            GMAIL_READONLY_SCOPE.to_owned(),
            GMAIL_COMPOSE_SCOPE.to_owned(),
        ];
        let envelope = EncryptedRefreshToken::from_envelope("am1.1.nonce.cipher").unwrap();

        assert!(
            !repository
                .reauthorize_connection(
                    connection.id,
                    other.id,
                    "gmail-sub",
                    "mail@example.com",
                    &scopes,
                    &envelope,
                )
                .await
                .unwrap()
        );
        assert!(
            !repository
                .reauthorize_connection(
                    connection.id,
                    user.id,
                    "wrong-sub",
                    "mail@example.com",
                    &scopes,
                    &envelope,
                )
                .await
                .unwrap()
        );

        let mut revoking = connection.clone();
        revoking.status = ConnectionStatus::Revoking;
        assert!(repository.update_connection(&revoking).await.unwrap());
        assert!(
            !repository
                .reauthorize_connection(
                    connection.id,
                    user.id,
                    "gmail-sub",
                    "mail@example.com",
                    &scopes,
                    &envelope,
                )
                .await
                .unwrap()
        );

        let second = GmailConnection::new(
            user.id,
            "gmail-sub-2",
            "second@example.com",
            vec![GMAIL_READONLY_SCOPE.into(), GMAIL_COMPOSE_SCOPE.into()],
        )
        .unwrap();
        repository.insert_connection(&second, None).await.unwrap();
        let mut inactive = user.clone();
        assert!(inactive.begin_revoke(now + Duration::seconds(1)));
        repository.update_user(&inactive).await.unwrap();
        assert!(
            !repository
                .reauthorize_connection(
                    second.id,
                    user.id,
                    "gmail-sub-2",
                    "second@example.com",
                    &scopes,
                    &envelope,
                )
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn durable_send_confirmation_claims_completes_and_replays_without_plaintext() {
        let repository = repository().await;
        let user = owner();
        repository.insert_user(&user).await.unwrap();
        let connection = connection(&repository, &user).await;
        let created = AccessKey::generate(user.id, "send-key", [connection.id]).unwrap();
        let stored_key = repository.insert_access_key(&created).await.unwrap();
        let draft =
            ManagedDraft::new(connection.id, "gmail-draft", "<stable@agentmail>", "body").unwrap();
        repository.insert_draft(&draft).await.unwrap();
        let preview = crate::domain::delivery::SendPreview {
            connection_id: connection.id,
            draft_id: draft.id,
            version: draft.version.clone(),
            from: None,
            to: vec![],
            cc: vec![],
            bcc: vec![],
            subject: String::new(),
            body_summary: String::new(),
            attachment_names: vec![],
            safety_notice: String::new(),
        };
        let now = Utc::now();
        let (confirmation, prepared) =
            SendConfirmation::prepare(stored_key.id, stored_key.generation, &draft, preview, now)
                .unwrap();
        let digest = SendConfirmation::token_digest_hex(&prepared.token);
        repository
            .insert_send_confirmation(&confirmation, now)
            .await
            .unwrap();
        let stored_hash: String = sqlx::query_scalar("SELECT token_hash FROM send_confirmations")
            .fetch_one(repository.pool())
            .await
            .unwrap();
        assert_eq!(stored_hash, digest);
        assert!(!stored_hash.contains(&prepared.token));

        let (mut claimed_confirmation, mut sending) = match repository
            .claim_send_confirmation(&digest, stored_key.id, stored_key.generation, &draft, now)
            .await
            .unwrap()
            .unwrap()
        {
            DurableSendClaim::Claimed {
                confirmation,
                draft,
            } => (confirmation, draft),
            other => panic!("unexpected claim: {other:?}"),
        };
        assert_eq!(sending.state, ManagedDraftState::Sending);
        assert!(matches!(
            repository
                .claim_send_confirmation(
                    &digest,
                    stored_key.id,
                    stored_key.generation,
                    &sending,
                    now
                )
                .await
                .unwrap(),
            Some(DurableSendClaim::InProgress { .. })
        ));
        let outcome = SendOutcome::Sent {
            gmail_message_id: "sent-message".into(),
        };
        claimed_confirmation
            .complete(&mut sending, outcome.clone())
            .unwrap();
        repository
            .complete_send_confirmation(&claimed_confirmation, &sending, now)
            .await
            .unwrap();
        assert!(matches!(
            repository
                .claim_send_confirmation(&digest, stored_key.id, stored_key.generation, &sending, now)
                .await
                .unwrap(),
            Some(DurableSendClaim::Replayed { outcome: replayed, .. }) if replayed == outcome
        ));
    }
    #[tokio::test]
    async fn audit_stores_metadata_only() {
        let repository = repository().await;
        let event = AuditEvent::metadata(
            crate::governance::AuditContext::default(),
            crate::governance::AuditOperation::DraftPrepare,
            crate::governance::AuditResult::Ok,
            3,
            crate::governance::RequestId::try_from("request-1").unwrap(),
            Utc::now(),
        );
        repository.record_audit_event(&event).await.unwrap();
        let operation: String = sqlx::query_scalar("SELECT operation FROM audit_events")
            .fetch_one(repository.pool())
            .await
            .unwrap();
        assert_eq!(operation, "draft.prepare");
    }
}

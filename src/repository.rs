//! SQLite repository for durable AgentMail metadata.
use crate::{
    crypto::{ENVELOPE_PREFIX, hash_token},
    database::Database,
    domain::{
        access::{
            AccessError, AccessKey, AccessKeyId, AccessKeyStatus, GrantSet, NewAccessKey,
            hash_secret, parse_credential, verify_secret,
        },
        delivery::{DraftId, DraftVersion, ManagedDraft, ManagedDraftState},
        identity::{
            ConnectionId, ConnectionStatus, GmailConnection, User, UserId, UserRole, UserStatus,
        },
    },
    governance::AuditEvent,
    oauth::{OAuthFlowKind, OAuthTransactionRecord},
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
        sqlx::query("INSERT INTO gmail_connections (id,owner_id,google_sub,primary_email,status,granted_scopes,refresh_token_envelope,last_used_at,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)").bind(c.id.to_string()).bind(c.owner_id.to_string()).bind(&c.google_sub).bind(&c.email).bind(connection_status(c.status)).bind(scopes_json(&c.granted_scopes)?).bind(envelope.map(EncryptedRefreshToken::as_str)).bind(c.last_used_at.map(encode_time)).bind(&now).bind(now.clone()).execute(&self.pool).await?;
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

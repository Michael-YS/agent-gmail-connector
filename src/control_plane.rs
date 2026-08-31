//! Application service for the browser control plane.
//!
//! HTTP handlers should pass only validated OIDC identities and token hashes
//! into this module.  Raw ID tokens and plaintext session values never enter
//! the repository.

use crate::{
    crypto::{hash_token, verify_token},
    domain::identity::{User, normalize_email},
    oauth::ValidatedOidcIdentity,
    repository::{NewOwnerSession, Repository, RepositoryError, WebSession},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use std::fmt;

const DEFAULT_SESSION_IDLE_TTL: Duration = Duration::hours(8);
const DEFAULT_SESSION_ABSOLUTE_TTL: Duration = Duration::days(30);

#[derive(Debug, thiserror::Error)]
pub enum ControlPlaneError {
    #[error("invalid expected owner email")]
    InvalidOwnerEmail,
    #[error("invalid session lifetime")]
    InvalidSessionLifetime,
    #[error("session is not authenticated")]
    Unauthenticated,
    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

/// Attributes the HTTP layer should use when emitting the session cookie.
/// This service deliberately does not construct or send HTTP responses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionCookiePolicy {
    pub name: &'static str,
    pub http_only: bool,
    pub secure: bool,
    pub same_site_lax: bool,
    pub path: &'static str,
}

impl Default for SessionCookiePolicy {
    fn default() -> Self {
        Self {
            name: "__Host-agentmail_session",
            http_only: true,
            secure: true,
            same_site_lax: true,
            path: "/",
        }
    }
}

/// The plaintext values are returned by owner bootstrap only so the HTTP
/// layer can put them in a cookie/form response.  They are not persisted.
#[derive(Clone, Eq, PartialEq)]
pub struct SessionCredentials {
    pub user: User,
    pub session: WebSession,
    pub session_token: String,
    pub csrf_token: String,
    pub cookie: SessionCookiePolicy,
}

impl fmt::Debug for SessionCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionCredentials")
            .field("user", &self.user)
            .field("session", &self.session)
            .field("session_token", &"[REDACTED]")
            .field("csrf_token", &"[REDACTED]")
            .field("cookie", &self.cookie)
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct ControlPlaneService {
    repository: Repository,
    expected_owner_email: String,
    session_idle_ttl: Duration,
    session_absolute_ttl: Duration,
}

impl ControlPlaneService {
    pub fn new(
        repository: Repository,
        expected_owner_email: &str,
    ) -> Result<Self, ControlPlaneError> {
        Self::with_ttls(
            repository,
            expected_owner_email,
            DEFAULT_SESSION_IDLE_TTL,
            DEFAULT_SESSION_ABSOLUTE_TTL,
        )
    }

    pub fn with_ttls(
        repository: Repository,
        expected_owner_email: &str,
        session_idle_ttl: Duration,
        session_absolute_ttl: Duration,
    ) -> Result<Self, ControlPlaneError> {
        let expected_owner_email = normalize_email(expected_owner_email)
            .map_err(|_| ControlPlaneError::InvalidOwnerEmail)?;
        if session_idle_ttl <= Duration::zero() || session_absolute_ttl <= Duration::zero() {
            return Err(ControlPlaneError::InvalidSessionLifetime);
        }
        Ok(Self {
            repository,
            expected_owner_email,
            session_idle_ttl,
            session_absolute_ttl,
        })
    }

    /// Bootstrap the sole Owner from an already validated Google identity and
    /// create a browser session. Raw OIDC tokens are intentionally not accepted.
    pub async fn bootstrap_owner_session(
        &self,
        identity: &ValidatedOidcIdentity,
        now: DateTime<Utc>,
    ) -> Result<SessionCredentials, ControlPlaneError> {
        let session_token = random_secret();
        let csrf_token = random_secret();
        let (user, session) = self
            .repository
            .bootstrap_owner_with_session(&NewOwnerSession {
                expected_owner_email: self.expected_owner_email.clone(),
                google_sub: identity.subject.clone(),
                verified_email: identity.email.clone(),
                session_id: crate::domain::identity::SessionId::new(),
                token_hash: hash_token(&session_token),
                csrf_token_hash: hash_token(&csrf_token),
                idle_expires_at: now + self.session_idle_ttl,
                absolute_expires_at: now + self.session_absolute_ttl,
                created_at: now,
            })
            .await?;
        Ok(SessionCredentials {
            user,
            session,
            session_token,
            csrf_token,
            cookie: SessionCookiePolicy::default(),
        })
    }

    /// Authenticate using the presented session token's hash, then refresh
    /// only idle expiry. The caller must hash the cookie value first.
    pub async fn authenticate_session(
        &self,
        presented_token_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<WebSession, ControlPlaneError> {
        if self
            .repository
            .lookup_web_session(presented_token_hash, now)
            .await?
            .is_none()
        {
            return Err(ControlPlaneError::Unauthenticated);
        }
        if !self
            .repository
            .touch_web_session(presented_token_hash, now, now + self.session_idle_ttl)
            .await?
        {
            return Err(ControlPlaneError::Unauthenticated);
        }
        self.repository
            .lookup_web_session(presented_token_hash, now)
            .await?
            .ok_or(ControlPlaneError::Unauthenticated)
    }

    /// Verify a submitted CSRF plaintext against the stored digest.
    pub fn verify_csrf(&self, csrf_token_hash: &str, presented_token: &str) -> bool {
        verify_token(presented_token, csrf_token_hash).unwrap_or(false)
    }

    pub async fn logout(&self, presented_token_hash: &str) -> Result<bool, ControlPlaneError> {
        Ok(self
            .repository
            .delete_web_session(presented_token_hash)
            .await?)
    }
}

fn random_secret() -> String {
    URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{database::Database, domain::identity::UserStatus};
    use tempfile::tempdir;

    async fn service() -> (ControlPlaneService, Repository) {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        db.migrate().await.unwrap();
        let repository = Repository::new(&db);
        let service = ControlPlaneService::with_ttls(
            repository.clone(),
            "Owner@Example.com",
            Duration::minutes(10),
            Duration::hours(1),
        )
        .unwrap();
        (service, repository)
    }

    fn identity(email: &str) -> ValidatedOidcIdentity {
        ValidatedOidcIdentity {
            subject: "owner-sub".to_owned(),
            email: email.to_owned(),
        }
    }

    #[tokio::test]
    async fn bootstrap_returns_plaintext_once_and_repository_keeps_hashes() {
        let (service, repository) = service().await;
        let now = Utc::now();
        let credentials = service
            .bootstrap_owner_session(&identity("OWNER@example.com"), now)
            .await
            .unwrap();
        assert_eq!(credentials.user.email, "owner@example.com");
        assert!(credentials.cookie.http_only);
        assert!(credentials.cookie.secure);
        assert!(credentials.cookie.same_site_lax);
        assert_eq!(credentials.cookie.path, "/");
        assert!(!format!("{credentials:?}").contains(&credentials.session_token));
        let stored: (String, String) =
            sqlx::query_as("SELECT token_hash,csrf_token_hash FROM web_sessions")
                .fetch_one(repository.pool())
                .await
                .unwrap();
        assert_eq!(stored.0, hash_token(&credentials.session_token));
        assert_eq!(stored.1, hash_token(&credentials.csrf_token));
        assert!(service.verify_csrf(&stored.1, &credentials.csrf_token));
        assert!(!service.verify_csrf(&stored.1, "wrong"));
        let token_hash = hash_token(&credentials.session_token);
        assert!(
            service
                .authenticate_session(&token_hash, now + Duration::minutes(1))
                .await
                .is_ok()
        );
        assert!(service.logout(&token_hash).await.unwrap());
        assert!(
            service
                .authenticate_session(&token_hash, now + Duration::minutes(1))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn bootstrap_rejects_email_mismatch_without_writing() {
        let (service, repository) = service().await;
        let result = service
            .bootstrap_owner_session(&identity("other@example.com"), Utc::now())
            .await;
        assert!(matches!(
            result,
            Err(ControlPlaneError::Repository(RepositoryError::InvalidValue(message)))
                if message == "owner email mismatch"
        ));
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(repository.pool())
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn authenticate_rejects_idle_absolute_expiry_and_revoking_user() {
        let (service, repository) = service().await;
        let now = Utc::now();
        let credentials = service
            .bootstrap_owner_session(&identity("owner@example.com"), now)
            .await
            .unwrap();
        let token_hash = hash_token(&credentials.session_token);
        assert!(
            service
                .authenticate_session(&token_hash, now + Duration::minutes(11))
                .await
                .is_err()
        );

        let absolute_hash = hash_token("absolute-session");
        repository
            .insert_web_session(&NewWebSession {
                id: crate::domain::identity::SessionId::new(),
                user_id: credentials.user.id,
                token_hash: absolute_hash.clone(),
                csrf_token_hash: hash_token("absolute-csrf"),
                idle_expires_at: now + Duration::hours(1),
                absolute_expires_at: now + Duration::minutes(1),
                created_at: now,
            })
            .await
            .unwrap();
        assert!(
            service
                .authenticate_session(&absolute_hash, now + Duration::minutes(2))
                .await
                .is_err()
        );

        let returning_credentials = service
            .bootstrap_owner_session(&identity("owner@example.com"), now)
            .await
            .unwrap();
        assert_eq!(returning_credentials.user.id, credentials.user.id);

        let user = repository
            .find_user_by_google_sub("owner-sub")
            .await
            .unwrap()
            .unwrap();
        let mut revoked = user.clone();
        assert!(revoked.begin_revoke(now + Duration::minutes(12)));
        repository.update_user(&revoked).await.unwrap();
        assert!(matches!(revoked.status, UserStatus::Revoking));
        assert!(
            service
                .authenticate_session(&token_hash, now + Duration::minutes(12))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn absolute_expiry_is_not_extended_by_idle_touch() {
        let (service, _) = service().await;
        let now = Utc::now();
        let credentials = service
            .bootstrap_owner_session(&identity("owner@example.com"), now)
            .await
            .unwrap();
        let token_hash = hash_token(&credentials.session_token);
        let touched = service
            .authenticate_session(&token_hash, now + Duration::minutes(5))
            .await
            .unwrap();
        assert_eq!(touched.absolute_expires_at, now + Duration::hours(1));
        assert!(touched.idle_expires_at <= touched.absolute_expires_at);
    }

    #[tokio::test]
    async fn service_can_be_constructed_with_file_repository() {
        let dir = tempdir().unwrap();
        let db = Database::connect(format!(
            "sqlite://{}",
            dir.path().join("control-plane.db").display()
        ))
        .await
        .unwrap();
        db.migrate().await.unwrap();
        assert!(ControlPlaneService::new(Repository::new(&db), "owner@example.com").is_ok());
    }
}

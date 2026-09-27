//! Application service for the browser control plane.
//!
//! HTTP handlers should pass only validated OIDC identities and token hashes
//! into this module.  Raw ID tokens and plaintext session values never enter
//! the repository.

use crate::{
    crypto::{hash_token, verify_token},
    domain::identity::{User, normalize_email},
    oauth::ValidatedOidcIdentity,
    repository::{
        NewExistingUserSession, NewInvitationMemberSession, NewOwnerSession, NewSessionCredentials,
        Repository, RepositoryError, WebSession,
    },
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
    #[error("Google identity has no AgentMail account")]
    IdentityNotAllowed,
    #[error("invitation is invalid, expired, already accepted, or email does not match")]
    InvitationNotClaimable,
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

    /// Log in an existing active Owner or Member when both OIDC identity
    /// values match. Only when no such user exists may the first Owner be
    /// bootstrapped by the established owner-email rule.
    pub async fn login_session(
        &self,
        identity: &ValidatedOidcIdentity,
        now: DateTime<Utc>,
    ) -> Result<SessionCredentials, ControlPlaneError> {
        let (session_token, csrf_token, session) = self.new_session_credentials(now);
        if let Some((user, stored_session)) = self
            .repository
            .login_existing_user_with_session(&NewExistingUserSession {
                verified_email: identity.email.clone(),
                google_sub: identity.subject.clone(),
                session,
            })
            .await?
        {
            return Ok(self.session_credentials(user, stored_session, session_token, csrf_token));
        }
        // A normal login cannot enroll an arbitrary Google identity. Only the
        // configured initial Owner may bootstrap; all others need an invitation.
        let verified_email =
            normalize_email(&identity.email).map_err(|_| ControlPlaneError::IdentityNotAllowed)?;
        if verified_email != self.expected_owner_email
            || self
                .repository
                .find_user_by_email(&verified_email)
                .await?
                .is_some()
        {
            return Err(ControlPlaneError::IdentityNotAllowed);
        }
        self.bootstrap_owner_session(identity, now).await
    }

    /// Atomically consume a hash-bound invitation, create its Member, and
    /// create the browser session after the OIDC identity has been verified.
    pub async fn accept_invitation_session(
        &self,
        invitation_token_hash: &str,
        identity: &ValidatedOidcIdentity,
        now: DateTime<Utc>,
    ) -> Result<SessionCredentials, ControlPlaneError> {
        let (session_token, csrf_token, session) = self.new_session_credentials(now);
        let Some((_invitation, user, stored_session)) = self
            .repository
            .claim_invitation_with_session(
                &NewInvitationMemberSession {
                    invitation_token_hash: invitation_token_hash.to_owned(),
                    verified_email: identity.email.clone(),
                    google_sub: identity.subject.clone(),
                    session,
                },
                now,
            )
            .await?
        else {
            return Err(ControlPlaneError::InvitationNotClaimable);
        };
        Ok(self.session_credentials(user, stored_session, session_token, csrf_token))
    }

    fn new_session_credentials(
        &self,
        now: DateTime<Utc>,
    ) -> (String, String, NewSessionCredentials) {
        let session_token = random_secret();
        let csrf_token = random_secret();
        let session = NewSessionCredentials {
            id: crate::domain::identity::SessionId::new(),
            token_hash: hash_token(&session_token),
            csrf_token_hash: hash_token(&csrf_token),
            idle_expires_at: now + self.session_idle_ttl,
            absolute_expires_at: now + self.session_absolute_ttl,
            created_at: now,
        };
        (session_token, csrf_token, session)
    }

    fn session_credentials(
        &self,
        user: User,
        session: WebSession,
        session_token: String,
        csrf_token: String,
    ) -> SessionCredentials {
        SessionCredentials {
            user,
            session,
            session_token,
            csrf_token,
            cookie: SessionCookiePolicy::default(),
        }
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
    use crate::{
        database::Database,
        domain::identity::{InvitationId, User, UserRole, UserStatus},
        repository::{NewInvitation, NewWebSession},
    };
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
    async fn normal_login_rejects_uninvited_and_different_subject_without_new_sessions() {
        let (service, repository) = service().await;
        let now = Utc::now();
        let outsider = ValidatedOidcIdentity {
            subject: "outsider-sub".to_owned(),
            email: "outsider@example.com".to_owned(),
        };
        assert!(matches!(
            service.login_session(&outsider, now).await,
            Err(ControlPlaneError::IdentityNotAllowed)
        ));
        let owner = service
            .bootstrap_owner_session(&identity("owner@example.com"), now)
            .await
            .unwrap();
        let impostor = ValidatedOidcIdentity {
            subject: "different-sub".to_owned(),
            email: owner.user.email.clone(),
        };
        assert!(matches!(
            service.login_session(&impostor, now).await,
            Err(ControlPlaneError::IdentityNotAllowed)
        ));
        let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(repository.pool())
            .await
            .unwrap();
        let sessions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM web_sessions")
            .fetch_one(repository.pool())
            .await
            .unwrap();
        assert_eq!((users, sessions), (1, 1));
    }

    #[tokio::test]
    async fn existing_member_login_and_invitation_accept_create_secure_sessions() {
        let (service, repository) = service().await;
        let now = Utc::now();
        let member = User::new("member-sub", "member@example.com", UserRole::Member, now).unwrap();
        repository.insert_user(&member).await.unwrap();
        let member_identity = ValidatedOidcIdentity {
            subject: "member-sub".to_owned(),
            email: " MEMBER@EXAMPLE.COM ".to_owned(),
        };
        let logged_in = service.login_session(&member_identity, now).await.unwrap();
        assert_eq!(logged_in.user.id, member.id);
        assert_eq!(logged_in.user.role, UserRole::Member);
        assert!(
            service
                .authenticate_session(&hash_token(&logged_in.session_token), now)
                .await
                .is_ok()
        );
        let wrong_email = ValidatedOidcIdentity {
            email: "other@example.com".to_owned(),
            ..member_identity.clone()
        };
        assert!(service.login_session(&wrong_email, now).await.is_err());

        let owner = User::new("owner-sub", "owner@example.com", UserRole::Owner, now).unwrap();
        repository.insert_user(&owner).await.unwrap();
        let invitation_token = "test-invitation-token";
        repository
            .create_invitation(&NewInvitation {
                id: InvitationId::new(),
                target_email: "invitee@example.com".to_owned(),
                token_hash: hash_token(invitation_token),
                invited_by: owner.id,
                expires_at: now + Duration::hours(1),
                created_at: now,
            })
            .await
            .unwrap();
        let invitee = ValidatedOidcIdentity {
            subject: "invitee-sub".to_owned(),
            email: "INVITEE@example.com".to_owned(),
        };
        let accepted = service
            .accept_invitation_session(&hash_token(invitation_token), &invitee, now)
            .await
            .unwrap();
        assert_eq!(accepted.user.role, UserRole::Member);
        assert!(
            service
                .authenticate_session(&hash_token(&accepted.session_token), now)
                .await
                .is_ok()
        );
        assert!(matches!(
            service
                .accept_invitation_session(&hash_token(invitation_token), &invitee, now)
                .await,
            Err(ControlPlaneError::InvitationNotClaimable)
        ));
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

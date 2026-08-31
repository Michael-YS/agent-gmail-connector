//! Owner-managed, one-time invitations for Member access.

use crate::{
    crypto::hash_token,
    domain::identity::{InvitationId, User, UserId},
    repository::{Invitation, NewInvitation, Repository, RepositoryError},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use std::fmt;

const DEFAULT_INVITATION_TTL: Duration = Duration::days(7);

#[derive(Debug, thiserror::Error)]
pub enum InviteError {
    #[error("invalid invitation lifetime")]
    InvalidLifetime,
    #[error("invitation is invalid, expired, already accepted, or email does not match")]
    NotClaimable,
    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

/// A plaintext invitation token. It is generated and exposed only by the
/// application service; repository methods accept only its digest.
#[derive(Clone, Eq, PartialEq)]
pub struct InvitationToken(String);

impl InvitationToken {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for InvitationToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InvitationToken([REDACTED])")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuedInvitation {
    pub invitation: Invitation,
    pub token: InvitationToken,
}

#[derive(Clone, Debug)]
pub struct InviteService {
    repository: Repository,
    invitation_ttl: Duration,
}

impl InviteService {
    pub fn new(repository: Repository) -> Self {
        Self {
            repository,
            invitation_ttl: DEFAULT_INVITATION_TTL,
        }
    }

    pub fn with_ttl(repository: Repository, invitation_ttl: Duration) -> Result<Self, InviteError> {
        if invitation_ttl <= Duration::zero() {
            return Err(InviteError::InvalidLifetime);
        }
        Ok(Self {
            repository,
            invitation_ttl,
        })
    }

    pub async fn issue(
        &self,
        owner: &User,
        target_email: &str,
        now: DateTime<Utc>,
    ) -> Result<IssuedInvitation, InviteError> {
        let token = InvitationToken(random_token());
        let invitation = self
            .repository
            .create_invitation(&NewInvitation {
                id: InvitationId::new(),
                target_email: target_email.to_owned(),
                token_hash: hash_token(token.as_str()),
                invited_by: owner.id,
                expires_at: now + self.invitation_ttl,
                created_at: now,
            })
            .await?;
        Ok(IssuedInvitation { invitation, token })
    }

    pub async fn list(&self, owner_id: UserId) -> Result<Vec<Invitation>, InviteError> {
        Ok(self.repository.list_invitations(owner_id).await?)
    }

    pub async fn accept(
        &self,
        token: &InvitationToken,
        verified_email: &str,
        google_sub: &str,
        now: DateTime<Utc>,
    ) -> Result<(Invitation, User), InviteError> {
        self.repository
            .claim_invitation(&hash_token(token.as_str()), verified_email, google_sub, now)
            .await?
            .ok_or(InviteError::NotClaimable)
    }

    /// Delete an unaccepted invitation as its revoke representation. Call
    /// [`Self::issue`] again to regenerate; revoked history is not retained
    /// because the current schema has no `revoked_at` column.
    pub async fn revoke(
        &self,
        owner_id: UserId,
        invitation_id: InvitationId,
    ) -> Result<bool, InviteError> {
        Ok(self
            .repository
            .revoke_invitation(owner_id, invitation_id)
            .await?)
    }
}

fn random_token() -> String {
    URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{database::Database, domain::identity::UserRole};
    use std::sync::Arc;

    async fn service() -> (InviteService, Repository, User, DateTime<Utc>) {
        let database = Database::connect("sqlite::memory:").await.unwrap();
        database.migrate().await.unwrap();
        let repository = Repository::new(&database);
        let now = Utc::now();
        let owner = User::new("owner-sub", "OWNER@example.com", UserRole::Owner, now).unwrap();
        repository.insert_user(&owner).await.unwrap();
        (
            InviteService::with_ttl(repository.clone(), Duration::days(7)).unwrap(),
            repository,
            owner,
            now,
        )
    }

    #[tokio::test]
    async fn issue_accept_is_hash_only_and_one_time() {
        let (service, repository, owner, now) = service().await;
        let issued = service
            .issue(&owner, "Member@Example.com", now)
            .await
            .unwrap();
        assert_eq!(issued.invitation.target_email, "member@example.com");
        assert!(!format!("{issued:?}").contains(issued.token.as_str()));
        let stored: String = sqlx::query_scalar("SELECT token_hash FROM invitations")
            .fetch_one(repository.pool())
            .await
            .unwrap();
        assert_eq!(stored, hash_token(issued.token.as_str()));
        assert!(!stored.contains(issued.token.as_str()));

        let (invitation, member) = service
            .accept(&issued.token, " MEMBER@example.com ", "member-sub", now)
            .await
            .unwrap();
        assert!(invitation.accepted_at.is_some());
        assert_eq!(member.email, "member@example.com");
        assert_eq!(member.role, UserRole::Member);
        assert!(matches!(
            service
                .accept(&issued.token, "member@example.com", "member-sub-2", now)
                .await,
            Err(InviteError::NotClaimable)
        ));
    }

    #[tokio::test]
    async fn wrong_email_expiry_and_revocation_do_not_consume() {
        let (service, repository, owner, now) = service().await;
        let issued = service
            .issue(&owner, "member@example.com", now)
            .await
            .unwrap();
        assert!(matches!(
            service
                .accept(&issued.token, "other@example.com", "member-sub", now)
                .await,
            Err(InviteError::NotClaimable)
        ));

        let short = InviteService::with_ttl(repository.clone(), Duration::seconds(1)).unwrap();
        let expired = short
            .issue(&owner, "expired@example.com", now)
            .await
            .unwrap();
        assert!(matches!(
            short
                .accept(
                    &expired.token,
                    "expired@example.com",
                    "expired-sub",
                    now + Duration::seconds(2),
                )
                .await,
            Err(InviteError::NotClaimable)
        ));
        let accepted_at: Option<String> =
            sqlx::query_scalar("SELECT accepted_at FROM invitations WHERE id=?")
                .bind(expired.invitation.id.to_string())
                .fetch_one(repository.pool())
                .await
                .unwrap();
        assert!(accepted_at.is_none());

        assert!(
            service
                .revoke(owner.id, issued.invitation.id)
                .await
                .unwrap()
        );
        assert!(matches!(
            service
                .accept(&issued.token, "member@example.com", "member-sub", now)
                .await,
            Err(InviteError::NotClaimable)
        ));

        let mut revoked = owner.clone();
        assert!(revoked.begin_revoke(now));
        repository.update_user(&revoked).await.unwrap();
        assert!(matches!(
            service.issue(&owner, "new@example.com", now).await,
            Err(InviteError::Repository(RepositoryError::InvalidValue(message)))
                if message == "owner is not active"
        ));
    }

    #[tokio::test]
    async fn member_insert_failure_rolls_back_invitation_claim() {
        let (service, repository, owner, now) = service().await;
        let issued = service
            .issue(&owner, "member@example.com", now)
            .await
            .unwrap();
        let existing = User::new(
            "already-used-sub",
            "existing@example.com",
            UserRole::Member,
            now,
        )
        .unwrap();
        repository.insert_user(&existing).await.unwrap();

        assert!(matches!(
            service
                .accept(&issued.token, "member@example.com", "already-used-sub", now,)
                .await,
            Err(InviteError::Repository(RepositoryError::Sqlx(_)))
        ));
        let accepted_at: Option<String> =
            sqlx::query_scalar("SELECT accepted_at FROM invitations WHERE id=?")
                .bind(issued.invitation.id.to_string())
                .fetch_one(repository.pool())
                .await
                .unwrap();
        assert!(accepted_at.is_none());
    }

    #[tokio::test]
    async fn concurrent_claim_has_one_winner() {
        let (service, _repository, owner, now) = service().await;
        let issued = service
            .issue(&owner, "member@example.com", now)
            .await
            .unwrap();
        let service = Arc::new(service);
        let mut tasks = Vec::new();
        for index in 0..8 {
            let service = Arc::clone(&service);
            let token = issued.token.clone();
            tasks.push(tokio::spawn(async move {
                service
                    .accept(
                        &token,
                        "member@example.com",
                        &format!("member-sub-{index}"),
                        now,
                    )
                    .await
                    .is_ok()
            }));
        }
        let mut winners = 0;
        for task in tasks {
            if task.await.unwrap() {
                winners += 1;
            }
        }
        assert_eq!(winners, 1);
    }
}

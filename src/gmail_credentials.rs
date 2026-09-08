//! Short-lived Gmail access-token provider.
//!
//! The repository-facing trait is intentionally small: the current repository
//! does not yet expose the encrypted refresh-token column, so its adapter can
//! be added without making this module handle SQL or plaintext persistence.
//! Refresh tokens are decrypted only for one refresh call and are never cached.

use crate::{
    crypto::{Keyring, decrypt_refresh_token, encrypt_refresh_token},
    domain::identity::{ConnectionId, ConnectionStatus, GmailConnection, UserId},
    google_token::{GoogleTokenClient, GoogleTokenError, TokenSet},
};
use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use std::{
    collections::HashMap,
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::sync::Mutex;

/// Refresh-token material returned by a trusted repository adapter.
///
/// The envelope is deliberately a string rather than `EncryptedRefreshToken`:
/// that repository type currently hides its accessor.  The production adapter
/// should validate it with `EncryptedRefreshToken::from_envelope` before
/// constructing this value and must never put plaintext here.
pub struct StoredGmailCredential {
    connection: GmailConnection,
    refresh_token_envelope: Option<String>,
}

impl StoredGmailCredential {
    pub(crate) fn new(connection: GmailConnection, refresh_token_envelope: Option<String>) -> Self {
        Self {
            connection,
            refresh_token_envelope,
        }
    }
}

impl fmt::Debug for StoredGmailCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredGmailCredential")
            .field("connection", &self.connection)
            .field(
                "refresh_token_envelope",
                &self.refresh_token_envelope.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// Minimal persistence boundary needed by the provider.
#[async_trait]
pub trait GmailCredentialStore: Send + Sync {
    async fn load(
        &self,
        owner_id: UserId,
        connection_id: ConnectionId,
    ) -> Result<Option<StoredGmailCredential>, CredentialError>;

    /// Atomically transition an active connection to `reauth_required`.
    async fn mark_reauth_required(
        &self,
        connection_id: ConnectionId,
    ) -> Result<(), CredentialError>;

    /// Persist a newly returned refresh token, if Google rotates one.
    async fn persist_refresh_token(
        &self,
        owner_id: UserId,
        connection_id: ConnectionId,
        envelope: String,
    ) -> Result<(), CredentialError>;
}

/// Token endpoint boundary.  The production implementation is
/// `GoogleTokenClient`; tests can use a deterministic fake without credentials
/// or network access.
#[async_trait]
pub trait GmailTokenRefresher: Send + Sync {
    async fn refresh(&self, refresh_token: &SecretString) -> Result<TokenSet, GoogleTokenError>;
}

#[async_trait]
impl GmailTokenRefresher for GoogleTokenClient {
    async fn refresh(&self, refresh_token: &SecretString) -> Result<TokenSet, GoogleTokenError> {
        GoogleTokenClient::refresh(self, refresh_token).await
    }
}

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum CredentialError {
    #[error("connection is not accessible")]
    AccessDenied,
    #[error("Gmail authorization must be renewed")]
    ReauthRequired,
    #[error("stored Gmail credential is invalid")]
    InvalidCredential,
    #[error("credential store is unavailable")]
    StoreUnavailable,
    #[error("Gmail token endpoint is rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("Gmail token endpoint is unavailable")]
    Upstream,
    #[error("Gmail token endpoint timed out")]
    Timeout,
    #[error("Gmail token response is invalid")]
    InvalidResponse,
}

const REFRESH_SAFETY_WINDOW: Duration = Duration::from_secs(60);

struct CachedAccessToken {
    token: SecretString,
    expires_at: Instant,
}

struct ConnectionCache {
    // Held only around a single connection's refresh, never around unrelated
    // connections.  This is the single-flight gate.
    refresh_gate: Mutex<()>,
    cached: Mutex<Option<CachedAccessToken>>,
}

impl ConnectionCache {
    fn new() -> Self {
        Self {
            refresh_gate: Mutex::new(()),
            cached: Mutex::new(None),
        }
    }
}

/// Decrypts and refreshes one connection's credential, caching only the
/// short-lived access token in memory.
pub struct GmailCredentialProvider<S, T> {
    store: Arc<S>,
    refresher: Arc<T>,
    keyring: Arc<Keyring>,
    entries: Mutex<HashMap<ConnectionId, Arc<ConnectionCache>>>,
}

impl<S, T> fmt::Debug for GmailCredentialProvider<S, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GmailCredentialProvider")
            .field("store", &"[REDACTED]")
            .field("refresher", &"[REDACTED]")
            .field("keyring", &"[REDACTED]")
            .finish()
    }
}

impl<S, T> GmailCredentialProvider<S, T>
where
    S: GmailCredentialStore + 'static,
    T: GmailTokenRefresher + 'static,
{
    pub fn new(store: Arc<S>, refresher: Arc<T>, keyring: Keyring) -> Self {
        Self {
            store,
            refresher,
            keyring: Arc::new(keyring),
            entries: Mutex::new(HashMap::new()),
        }
    }

    async fn entry(&self, connection_id: ConnectionId) -> Arc<ConnectionCache> {
        let mut entries = self.entries.lock().await;
        entries
            .entry(connection_id)
            .or_insert_with(|| Arc::new(ConnectionCache::new()))
            .clone()
    }

    /// Return a usable access token for an explicitly owned connection.
    /// Concurrent callers for the same connection share one refresh request.
    pub async fn access_token(
        &self,
        owner_id: UserId,
        connection_id: ConnectionId,
    ) -> Result<SecretString, CredentialError> {
        let record = self
            .store
            .load(owner_id, connection_id)
            .await?
            .ok_or(CredentialError::AccessDenied)?;
        validate_active_record(&record, owner_id, connection_id)?;

        let entry = self.entry(connection_id).await;
        let _gate = entry.refresh_gate.lock().await;
        // Re-read authorization state even on a cache hit so revocation,
        // ownership changes, and reauthorization take effect immediately.
        let record = self
            .store
            .load(owner_id, connection_id)
            .await?
            .ok_or(CredentialError::AccessDenied)?;
        validate_active_record(&record, owner_id, connection_id)?;
        if let Some(token) = self.cached_token(&entry).await {
            return Ok(token);
        }
        let envelope = match record.refresh_token_envelope {
            Some(value) if !value.is_empty() => value,
            _ => return self.reauth(connection_id).await,
        };
        let refresh_bytes = decrypt_refresh_token(
            &envelope,
            &owner_id.to_string(),
            &connection_id.to_string(),
            &self.keyring,
        )
        .map_err(|_| CredentialError::InvalidCredential)?;
        let refresh_value =
            String::from_utf8(refresh_bytes).map_err(|_| CredentialError::InvalidCredential)?;
        if refresh_value.is_empty() {
            return Err(CredentialError::InvalidCredential);
        }
        let refresh_token = SecretString::from(refresh_value);
        let tokens = match self.refresher.refresh(&refresh_token).await {
            Ok(tokens) => tokens,
            Err(GoogleTokenError::InvalidGrant) => return self.reauth(connection_id).await,
            Err(GoogleTokenError::RateLimited {
                retry_after_seconds,
            }) => {
                return Err(CredentialError::RateLimited {
                    retry_after_seconds,
                });
            }
            Err(GoogleTokenError::Timeout) => return Err(CredentialError::Timeout),
            Err(GoogleTokenError::Upstream) => return Err(CredentialError::Upstream),
            Err(GoogleTokenError::InvalidResponse) => return Err(CredentialError::InvalidResponse),
            Err(_) => return Err(CredentialError::InvalidResponse),
        };

        let current = self
            .store
            .load(owner_id, connection_id)
            .await?
            .ok_or(CredentialError::AccessDenied)?;
        validate_active_record(&current, owner_id, connection_id)?;

        if let Some(rotated) = &tokens.refresh_token {
            let rotated_envelope = encrypt_refresh_token(
                rotated.expose_secret(),
                &owner_id.to_string(),
                &connection_id.to_string(),
                &self.keyring,
            )
            .map_err(|_| CredentialError::InvalidCredential)?;
            self.store
                .persist_refresh_token(owner_id, connection_id, rotated_envelope)
                .await?;
        }

        let access_token = tokens.access_token;
        let expires_at = Instant::now()
            .checked_add(Duration::from_secs(tokens.expires_in))
            .ok_or(CredentialError::InvalidResponse)?;
        *entry.cached.lock().await = Some(CachedAccessToken {
            token: access_token.clone(),
            expires_at,
        });
        Ok(access_token)
    }

    async fn cached_token(&self, entry: &ConnectionCache) -> Option<SecretString> {
        let cached = entry.cached.lock().await;
        let valid_until = Instant::now() + REFRESH_SAFETY_WINDOW;
        cached
            .as_ref()
            .filter(|value| value.expires_at > valid_until)
            .map(|value| value.token.clone())
    }

    async fn reauth(&self, connection_id: ConnectionId) -> Result<SecretString, CredentialError> {
        *self.entry(connection_id).await.cached.lock().await = None;
        self.store.mark_reauth_required(connection_id).await?;
        Err(CredentialError::ReauthRequired)
    }

    /// Clear a token after the Gmail API rejects it.  The adapter should then
    /// call `mark_reauth_required` through its store if the rejection is 401.
    pub async fn invalidate(&self, connection_id: ConnectionId) {
        if let Some(entry) = self.entries.lock().await.get(&connection_id).cloned() {
            let _gate = entry.refresh_gate.lock().await;
            *entry.cached.lock().await = None;
        }
    }
}

fn validate_active_record(
    record: &StoredGmailCredential,
    owner_id: UserId,
    connection_id: ConnectionId,
) -> Result<(), CredentialError> {
    if record.connection.id != connection_id || record.connection.owner_id != owner_id {
        return Err(CredentialError::AccessDenied);
    }
    match record.connection.status {
        ConnectionStatus::Active => Ok(()),
        ConnectionStatus::ReauthRequired => Err(CredentialError::ReauthRequired),
        ConnectionStatus::Revoking => Err(CredentialError::AccessDenied),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::encrypt_refresh_token;
    use std::{
        collections::BTreeMap,
        sync::atomic::{AtomicUsize, Ordering},
    };
    use tokio::time::sleep;

    #[derive(Clone)]
    struct FakeStore {
        record: Arc<Mutex<Option<StoredGmailCredential>>>,
        marked: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl GmailCredentialStore for FakeStore {
        async fn load(
            &self,
            _owner_id: UserId,
            _connection_id: ConnectionId,
        ) -> Result<Option<StoredGmailCredential>, CredentialError> {
            Ok(self
                .record
                .lock()
                .await
                .as_ref()
                .map(|record| StoredGmailCredential {
                    connection: record.connection.clone(),
                    refresh_token_envelope: record.refresh_token_envelope.clone(),
                }))
        }
        async fn mark_reauth_required(
            &self,
            _connection_id: ConnectionId,
        ) -> Result<(), CredentialError> {
            self.marked.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        async fn persist_refresh_token(
            &self,
            _owner_id: UserId,
            _connection_id: ConnectionId,
            envelope: String,
        ) -> Result<(), CredentialError> {
            self.record
                .lock()
                .await
                .as_mut()
                .unwrap()
                .refresh_token_envelope = Some(envelope);
            Ok(())
        }
    }

    struct FakeRefresher {
        calls: AtomicUsize,
        result: Mutex<Result<TokenSet, GoogleTokenError>>,
    }

    #[async_trait]
    impl GmailTokenRefresher for FakeRefresher {
        async fn refresh(&self, token: &SecretString) -> Result<TokenSet, GoogleTokenError> {
            assert_eq!(token.expose_secret(), "refresh-secret");
            self.calls.fetch_add(1, Ordering::SeqCst);
            sleep(Duration::from_millis(20)).await;
            self.result.lock().await.clone()
        }
    }

    fn setup(
        result: Result<TokenSet, GoogleTokenError>,
    ) -> (
        GmailCredentialProvider<FakeStore, FakeRefresher>,
        UserId,
        ConnectionId,
        Arc<FakeStore>,
        Arc<FakeRefresher>,
    ) {
        let owner = UserId::new();
        let connection = GmailConnection::new(
            owner,
            "google-sub",
            "gmail@example.com",
            vec!["gmail.readonly".into(), "gmail.compose".into()],
        )
        .unwrap();
        let connection_id = connection.id;
        let keyring = Keyring::new(1, BTreeMap::from([(1, [7; 32])])).unwrap();
        let envelope = encrypt_refresh_token(
            "refresh-secret",
            &owner.to_string(),
            &connection_id.to_string(),
            &keyring,
        )
        .unwrap();
        let store = Arc::new(FakeStore {
            record: Arc::new(Mutex::new(Some(StoredGmailCredential {
                connection,
                refresh_token_envelope: Some(envelope),
            }))),
            marked: Arc::new(AtomicUsize::new(0)),
        });
        let refresher = Arc::new(FakeRefresher {
            calls: AtomicUsize::new(0),
            result: Mutex::new(result),
        });
        let provider = GmailCredentialProvider::new(store.clone(), refresher.clone(), keyring);
        (provider, owner, connection_id, store, refresher)
    }

    fn token_set() -> TokenSet {
        TokenSet {
            access_token: SecretString::from("access-secret"),
            expires_in: 3600,
            refresh_token: None,
            id_token: None,
            scope: vec!["gmail.readonly".into()],
        }
    }

    #[tokio::test]
    async fn decrypts_refresh_and_caches_single_flight() {
        let (provider, owner, connection, _store, refresher) = setup(Ok(token_set()));
        let first = provider.access_token(owner, connection);
        let second = provider.access_token(owner, connection);
        let (first, second) = tokio::join!(first, second);
        assert_eq!(first.unwrap().expose_secret(), "access-secret");
        assert_eq!(second.unwrap().expose_secret(), "access-secret");
        assert_eq!(refresher.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn invalid_grant_marks_connection_for_reauth_without_secret_in_error() {
        let (provider, owner, connection, store, _refresher) =
            setup(Err(GoogleTokenError::InvalidGrant));
        assert!(matches!(
            provider.access_token(owner, connection).await,
            Err(CredentialError::ReauthRequired)
        ));
        assert_eq!(store.marked.load(Ordering::SeqCst), 1);
        assert!(!format!("{:?}", CredentialError::ReauthRequired).contains("refresh-secret"));
    }

    #[tokio::test]
    async fn cached_token_does_not_bypass_revocation_state() {
        let (provider, owner, connection, store, refresher) = setup(Ok(token_set()));
        provider.access_token(owner, connection).await.unwrap();
        store
            .record
            .lock()
            .await
            .as_mut()
            .unwrap()
            .connection
            .status = ConnectionStatus::Revoking;

        assert!(matches!(
            provider.access_token(owner, connection).await,
            Err(CredentialError::AccessDenied)
        ));
        assert_eq!(refresher.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn revocation_during_refresh_does_not_return_or_cache_access_token() {
        let (provider, owner, connection, store, refresher) = setup(Ok(token_set()));
        let pending = provider.access_token(owner, connection);
        let revoke = async {
            while refresher.calls.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
            store
                .record
                .lock()
                .await
                .as_mut()
                .unwrap()
                .connection
                .status = ConnectionStatus::Revoking;
        };
        let (result, ()) = tokio::join!(pending, revoke);
        assert!(matches!(result, Err(CredentialError::AccessDenied)));
        assert!(
            provider
                .entry(connection)
                .await
                .cached
                .lock()
                .await
                .is_none()
        );
        assert_eq!(refresher.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn wrong_owner_and_inactive_connection_are_rejected() {
        let (provider, owner, connection, store, _refresher) = setup(Ok(token_set()));
        assert!(matches!(
            provider.access_token(UserId::new(), connection).await,
            Err(CredentialError::AccessDenied)
        ));
        assert!(provider.entries.lock().await.is_empty());
        store
            .record
            .lock()
            .await
            .as_mut()
            .unwrap()
            .connection
            .status = ConnectionStatus::ReauthRequired;
        assert!(matches!(
            provider.access_token(owner, connection).await,
            Err(CredentialError::ReauthRequired)
        ));
    }

    #[tokio::test]
    async fn absurd_access_token_ttl_is_rejected_without_panic() {
        let (provider, owner, connection, _store, _refresher) = setup(Ok(TokenSet {
            expires_in: u64::MAX,
            ..token_set()
        }));
        assert!(matches!(
            provider.access_token(owner, connection).await,
            Err(CredentialError::InvalidResponse)
        ));
    }
}

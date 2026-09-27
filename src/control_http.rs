//! Axum control-plane HTTP seam.
//!
//! This module is deliberately independent from the application's main router:
//! the main binary supplies the verified OIDC adapter and token exchanger,
//! then nests [`router`] under its public router. Request `Host` and forwarded
//! headers are never used to construct OAuth URLs.

use async_trait::async_trait;
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, Request, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::json;
use std::{fmt, sync::Arc};
use uuid::Uuid;

use crate::{
    config::AppConfig,
    control_plane::{ControlPlaneError, ControlPlaneService, SessionCookiePolicy},
    crypto::{CryptoError, decrypt_refresh_token, encrypt_refresh_token, hash_token, verify_token},
    domain::{
        access::{AccessKey, AccessKeyId},
        identity::{
            ConnectionId, ConnectionStatus, GmailConnection, InvitationId, User, UserId, UserRole,
        },
    },
    google_oidc::{GoogleJwksVerifier, GoogleOidcError},
    google_token::{GoogleTokenClient, GoogleTokenError, TokenSet},
    governance::{AuditContext, AuditEvent, AuditOperation, AuditResult, RequestId},
    invitations::InviteService,
    oauth::{
        GMAIL_CALLBACK_PATH, GOOGLE_ISSUER, GmailFlow, LOGIN_CALLBACK_PATH, LoginFlow, OAuthError,
        OAuthFlowKind, OidcClaims, ValidatedOidcIdentity, validate_granted_gmail_scopes,
        validate_oidc_claims,
    },
    repository::{
        EncryptedRefreshToken, Repository, RepositoryError, StoredAccessKey, UserRevocation,
    },
};

const LOGIN_TRANSACTION_COOKIE: &str = "__Host-agentmail_login_tx";
const GMAIL_TRANSACTION_COOKIE: &str = "__Host-agentmail_gmail_tx";
const OAUTH_TRANSACTION_MAX_AGE: i64 = 600;
const MAX_OAUTH_QUERY_VALUE_BYTES: usize = 4096;

#[derive(Debug, thiserror::Error)]
pub enum ControlHttpError {
    #[error("invalid OAuth request")]
    InvalidRequest,
    #[error("invalid OAuth transaction cookie")]
    InvalidTransactionCookie,
    #[error("OIDC verification failed")]
    OidcVerification,
    #[error("OIDC token response did not contain an ID token")]
    MissingIdToken,
    #[error("OIDC nonce does not match the OAuth transaction")]
    NonceMismatch,
    #[error(transparent)]
    OAuth(#[from] OAuthError),
    #[error(transparent)]
    GoogleToken(#[from] GoogleTokenError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Repository(#[from] RepositoryError),
    #[error(transparent)]
    ControlPlane(#[from] ControlPlaneError),
}

/// Small dependency-injection seam around the concrete Google token client.
/// Tests can return a deterministic [`TokenSet`] without making network calls.
#[async_trait]
pub trait OAuthCodeExchanger: Send + Sync + 'static {
    async fn exchange_code(
        &self,
        code: &str,
        code_verifier: &SecretString,
    ) -> Result<TokenSet, GoogleTokenError>;

    async fn revoke(&self, _token: &SecretString) -> Result<(), GoogleTokenError> {
        Err(GoogleTokenError::Upstream)
    }
}

/// Async verifier boundary so the callback can refresh JWKS on an unknown key.
#[async_trait]
pub trait OidcTokenVerifier: Send + Sync + 'static {
    async fn verify_with_refresh(&self, id_token: &str) -> Result<OidcClaims, GoogleOidcError>;
}

#[async_trait]
impl OidcTokenVerifier for GoogleJwksVerifier {
    async fn verify_with_refresh(&self, id_token: &str) -> Result<OidcClaims, GoogleOidcError> {
        GoogleJwksVerifier::verify_with_refresh(self, id_token).await
    }
}

#[async_trait]
impl OAuthCodeExchanger for GoogleTokenClient {
    async fn exchange_code(
        &self,
        code: &str,
        code_verifier: &SecretString,
    ) -> Result<TokenSet, GoogleTokenError> {
        GoogleTokenClient::exchange_code(self, code, code_verifier).await
    }

    async fn revoke(&self, token: &SecretString) -> Result<(), GoogleTokenError> {
        GoogleTokenClient::revoke(self, token).await
    }
}

pub struct ControlHttpState<V, E>
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    pub config: AppConfig,
    pub repository: Repository,
    pub control_plane: ControlPlaneService,
    pub oidc_verifier: Arc<V>,
    pub login_token_exchanger: Arc<E>,
    pub gmail_token_exchanger: Arc<E>,
}

impl<V, E> Clone for ControlHttpState<V, E>
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            repository: self.repository.clone(),
            control_plane: self.control_plane.clone(),
            oidc_verifier: Arc::clone(&self.oidc_verifier),
            login_token_exchanger: Arc::clone(&self.login_token_exchanger),
            gmail_token_exchanger: Arc::clone(&self.gmail_token_exchanger),
        }
    }
}

impl<V, E> fmt::Debug for ControlHttpState<V, E>
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ControlHttpState")
            .field("config", &self.config)
            .field("repository", &self.repository)
            .field("control_plane", &self.control_plane)
            .field("oidc_verifier", &"[adapter]")
            .field("login_token_exchanger", &"[adapter]")
            .field("gmail_token_exchanger", &"[adapter]")
            .finish()
    }
}

impl<V, E> ControlHttpState<V, E>
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    pub fn new(
        config: AppConfig,
        repository: Repository,
        oidc_verifier: V,
        login_token_exchanger: E,
        gmail_token_exchanger: E,
    ) -> Result<Self, ControlHttpError> {
        let control_plane = ControlPlaneService::new(repository.clone(), &config.owner_email)?;
        Ok(Self {
            config,
            repository,
            control_plane,
            oidc_verifier: Arc::new(oidc_verifier),
            login_token_exchanger: Arc::new(login_token_exchanger),
            gmail_token_exchanger: Arc::new(gmail_token_exchanger),
        })
    }
}

#[derive(Clone, Debug)]
pub struct SessionContext {
    pub user_id: UserId,
    pub token_hash: String,
    pub csrf_token_hash: String,
}

#[derive(Debug, Deserialize)]
pub struct OAuthCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct GmailStartQuery {
    pub connection_id: Option<Uuid>,
}

/// Routes to nest into the main application router.
pub fn router<V, E>(state: ControlHttpState<V, E>) -> Router
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    Router::new()
        .route("/auth/google/login", get(login_start::<V, E>))
        .route(
            "/auth/invitations/accept",
            post(invitation_accept_start::<V, E>),
        )
        .route(LOGIN_CALLBACK_PATH, get(login_callback::<V, E>))
        .route(GMAIL_CALLBACK_PATH, get(gmail_callback::<V, E>))
        .route("/auth/google/gmail", post(gmail_start::<V, E>))
        .route("/auth/logout", post(logout::<V, E>))
        .route(
            "/control/api/account/delete",
            post(delete_own_account::<V, E>),
        )
        .route(
            "/control/api/members/{user_id}/revoke",
            post(revoke_member::<V, E>),
        )
        .route(
            "/control/api/connections/{connection_id}/revoke",
            post(revoke_connection::<V, E>),
        )
        .route(
            "/control/api/connections/{connection_id}/reauthorize",
            post(reauthorize_connection::<V, E>),
        )
        .route(
            "/control/api/invitations",
            get(list_invitations::<V, E>).post(create_invitation::<V, E>),
        )
        .route(
            "/control/api/invitations/{invitation_id}/revoke",
            post(revoke_invitation::<V, E>),
        )
        .route(
            "/control/api/invitations/{invitation_id}/regenerate",
            post(regenerate_invitation::<V, E>),
        )
        .route(
            "/control/api/access-keys",
            get(list_access_keys::<V, E>).post(create_access_key::<V, E>),
        )
        .route(
            "/control/api/access-keys/{key_id}/rotate",
            post(rotate_access_key::<V, E>),
        )
        .route(
            "/control/api/access-keys/{key_id}/revoke",
            post(revoke_access_key::<V, E>),
        )
        .route(
            "/control/api/access-keys/{key_id}/connections/{connection_id}",
            axum::routing::put(grant_access_key::<V, E>).delete(remove_access_key_grant::<V, E>),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            control_audit_middleware::<V, E>,
        ))
        .with_state(state)
}

/// Records the outcome of control-plane mutations and OAuth transitions without
/// inspecting request bodies, query strings, response bodies, or credentials.
/// A best-effort session lookup supplies an actor ID when the request already
/// has one; failed authentication and login callbacks intentionally remain
/// actorless.
pub(crate) async fn control_audit_middleware<V, E>(
    State(state): State<ControlHttpState<V, E>>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let operation = control_audit_operation(request.method(), request.uri().path());
    let context = if operation.is_some() {
        control_audit_context(&state, request.headers()).await
    } else {
        AuditContext::default()
    };
    let started = std::time::Instant::now();
    let response = next.run(request).await;
    if let Some(operation) = operation {
        let event = AuditEvent::metadata(
            context,
            operation,
            control_audit_result(response.status()),
            u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            RequestId::try_from(Uuid::now_v7().to_string()).expect("UUID is a valid request id"),
            Utc::now(),
        );
        if let Err(error) = state.repository.record_audit_event(&event).await {
            tracing::warn!(error = %error, operation = operation.as_str(), "control audit write failed");
        }
    }
    response
}

fn control_audit_operation(method: &axum::http::Method, path: &str) -> Option<AuditOperation> {
    use axum::http::Method;

    match (method, path) {
        (&Method::GET, "/auth/google/login") => Some(AuditOperation::AuthLogin),
        (&Method::POST, "/auth/invitations/accept") => Some(AuditOperation::InvitationAccept),
        (&Method::GET, LOGIN_CALLBACK_PATH) => Some(AuditOperation::AuthLogin),
        (&Method::GET, GMAIL_CALLBACK_PATH) | (&Method::POST, "/auth/google/gmail") => {
            Some(AuditOperation::AuthGmail)
        }
        (&Method::POST, "/auth/logout") => Some(AuditOperation::AuthLogout),
        (&Method::POST, "/control/api/account/delete") => Some(AuditOperation::AccountRevoke),
        (&Method::POST, "/control/account/delete") => Some(AuditOperation::AccountRevoke),
        (&Method::POST, "/control/api/invitations") => Some(AuditOperation::InvitationCreate),
        (&Method::POST, "/control/invitations") => Some(AuditOperation::InvitationCreate),
        (&Method::POST, path)
            if path.starts_with("/control/api/invitations/") && path.ends_with("/revoke") =>
        {
            Some(AuditOperation::InvitationRevoke)
        }
        (&Method::POST, path)
            if path.starts_with("/control/invitations/") && path.ends_with("/revoke") =>
        {
            Some(AuditOperation::InvitationRevoke)
        }
        (&Method::POST, path)
            if path.starts_with("/control/api/invitations/") && path.ends_with("/regenerate") =>
        {
            Some(AuditOperation::InvitationRegenerate)
        }
        (&Method::POST, path)
            if path.starts_with("/control/invitations/") && path.ends_with("/regenerate") =>
        {
            Some(AuditOperation::InvitationRegenerate)
        }
        (&Method::POST, "/control/api/access-keys") => Some(AuditOperation::AccessKeyCreate),
        (&Method::POST, "/control/account/access-keys") => Some(AuditOperation::AccessKeyCreate),
        (&Method::POST, path)
            if path.starts_with("/control/api/access-keys/") && path.ends_with("/rotate") =>
        {
            Some(AuditOperation::AccessKeyRotate)
        }
        (&Method::POST, path)
            if path.starts_with("/control/account/access-keys/") && path.ends_with("/rotate") =>
        {
            Some(AuditOperation::AccessKeyRotate)
        }
        (&Method::POST, path)
            if path.starts_with("/control/api/access-keys/") && path.ends_with("/revoke") =>
        {
            Some(AuditOperation::AccessKeyRevoke)
        }
        (&Method::POST, path)
            if path.starts_with("/control/account/access-keys/") && path.ends_with("/revoke") =>
        {
            Some(AuditOperation::AccessKeyRevoke)
        }
        (&Method::PUT, path) | (&Method::DELETE, path)
            if path.starts_with("/control/api/access-keys/") && path.contains("/connections/") =>
        {
            Some(AuditOperation::AccessKeyGrant)
        }
        (&Method::POST, path)
            if path.starts_with("/control/account/access-keys/") && path.ends_with("/grants") =>
        {
            Some(AuditOperation::AccessKeyGrant)
        }
        (&Method::POST, path)
            if path.starts_with("/control/api/connections/") && path.ends_with("/revoke") =>
        {
            Some(AuditOperation::ConnectionRevoke)
        }
        (&Method::POST, path)
            if path.starts_with("/control/api/connections/") && path.ends_with("/reauthorize") =>
        {
            Some(AuditOperation::ConnectionReauthorize)
        }
        (&Method::POST, "/control/account/connections/new") => Some(AuditOperation::AuthGmail),
        (&Method::POST, path)
            if path.starts_with("/control/account/connections/")
                && path.ends_with("/reauthorize") =>
        {
            Some(AuditOperation::AuthGmail)
        }
        (&Method::POST, path)
            if path.starts_with("/control/account/connections/") && path.ends_with("/revoke") =>
        {
            Some(AuditOperation::ConnectionRevoke)
        }
        (&Method::POST, path)
            if path.starts_with("/control/api/members/") && path.ends_with("/revoke") =>
        {
            Some(AuditOperation::AccountRevoke)
        }
        (&Method::POST, path)
            if path.starts_with("/control/members/") && path.ends_with("/revoke") =>
        {
            Some(AuditOperation::AccountRevoke)
        }
        _ => None,
    }
}

async fn control_audit_context<V, E>(
    state: &ControlHttpState<V, E>,
    headers: &HeaderMap,
) -> AuditContext
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let Some(token_hash) = session_token_hash(headers).ok() else {
        return AuditContext::default();
    };
    match state
        .control_plane
        .authenticate_session(&token_hash, Utc::now())
        .await
    {
        Ok(session) => AuditContext {
            user_id: Some(session.user_id),
            access_key_id: None,
            connection_id: None,
        },
        Err(_) => AuditContext::default(),
    }
}

fn control_audit_result(status: StatusCode) -> AuditResult {
    match status {
        StatusCode::UNAUTHORIZED => AuditResult::Unauthorized,
        StatusCode::FORBIDDEN => AuditResult::Forbidden,
        StatusCode::NOT_FOUND => AuditResult::NotFound,
        StatusCode::CONFLICT => AuditResult::Conflict,
        StatusCode::TOO_MANY_REQUESTS => AuditResult::RateLimited,
        StatusCode::SERVICE_UNAVAILABLE | StatusCode::GATEWAY_TIMEOUT => AuditResult::Unavailable,
        status if status.is_success() || status.is_redirection() => AuditResult::Ok,
        _ => AuditResult::Error,
    }
}

#[derive(Debug, Deserialize)]
struct InvitationAcceptRequest {
    token: String,
}

#[derive(Debug, Deserialize)]
struct CreateInvitationRequest {
    target_email: String,
}

#[derive(Debug, Deserialize)]
struct CreateAccessKeyRequest {
    name: String,
    #[serde(default)]
    connection_ids: Vec<Uuid>,
}

async fn list_invitations<V, E>(
    State(state): State<ControlHttpState<V, E>>,
    headers: HeaderMap,
) -> Response
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let owner = match require_owner_session(&state, &headers, false).await {
        Ok(owner) => owner,
        Err(response) => return response,
    };
    match state.repository.list_invitations(owner.user_id).await {
        Ok(invitations) => (
            StatusCode::OK,
            Json(json!({
                "invitations": invitations.iter().map(invitation_view).collect::<Vec<_>>()
            })),
        )
            .into_response(),
        Err(error) => error_response(error.into()),
    }
}

async fn create_invitation<V, E>(
    State(state): State<ControlHttpState<V, E>>,
    headers: HeaderMap,
    Json(request): Json<CreateInvitationRequest>,
) -> Response
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let owner = match require_owner_session(&state, &headers, true).await {
        Ok(owner) => owner,
        Err(response) => return response,
    };
    let owner = match active_owner(&state, owner.user_id).await {
        Ok(owner) => owner,
        Err(response) => return response,
    };
    let issued = match InviteService::new(state.repository.clone())
        .issue(&owner, &request.target_email, Utc::now())
        .await
    {
        Ok(issued) => issued,
        Err(crate::invitations::InviteError::InvalidLifetime)
        | Err(crate::invitations::InviteError::Repository(RepositoryError::InvalidValue(_))) => {
            return control_api_error(StatusCode::BAD_REQUEST, "invalid_request");
        }
        Err(crate::invitations::InviteError::Repository(error)) => {
            return error_response(error.into());
        }
        Err(crate::invitations::InviteError::NotClaimable) => {
            return control_api_error(StatusCode::CONFLICT, "invalid_state");
        }
    };
    invitation_issued_response(&issued)
}

async fn revoke_invitation<V, E>(
    State(state): State<ControlHttpState<V, E>>,
    Path(invitation_id): Path<Uuid>,
    headers: HeaderMap,
) -> Response
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let owner = match require_owner_session(&state, &headers, true).await {
        Ok(owner) => owner,
        Err(response) => return response,
    };
    match state
        .repository
        .revoke_invitation(owner.user_id, InvitationId::from_uuid(invitation_id))
        .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => control_api_error(StatusCode::NOT_FOUND, "not_found"),
        Err(error) => error_response(error.into()),
    }
}

async fn regenerate_invitation<V, E>(
    State(state): State<ControlHttpState<V, E>>,
    Path(invitation_id): Path<Uuid>,
    headers: HeaderMap,
) -> Response
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let owner = match require_owner_session(&state, &headers, true).await {
        Ok(owner) => owner,
        Err(response) => return response,
    };
    let owner_user = match active_owner(&state, owner.user_id).await {
        Ok(owner) => owner,
        Err(response) => return response,
    };
    let invitation_id = InvitationId::from_uuid(invitation_id);
    let existing = match state.repository.list_invitations(owner.user_id).await {
        Ok(invitations) => invitations
            .into_iter()
            .find(|invitation| invitation.id == invitation_id && invitation.accepted_at.is_none()),
        Err(error) => return error_response(error.into()),
    };
    let Some(existing) = existing else {
        return control_api_error(StatusCode::NOT_FOUND, "not_found");
    };
    // Revocation precedes issuance: an issuance failure can leave no usable
    // invitation, but never leaves both the old and replacement tokens valid.
    match state
        .repository
        .revoke_invitation(owner.user_id, invitation_id)
        .await
    {
        Ok(true) => {}
        Ok(false) => return control_api_error(StatusCode::NOT_FOUND, "not_found"),
        Err(error) => return error_response(error.into()),
    }
    let issued = match InviteService::new(state.repository.clone())
        .issue(&owner_user, &existing.target_email, Utc::now())
        .await
    {
        Ok(issued) => issued,
        Err(crate::invitations::InviteError::InvalidLifetime)
        | Err(crate::invitations::InviteError::Repository(RepositoryError::InvalidValue(_))) => {
            return control_api_error(StatusCode::BAD_REQUEST, "invalid_request");
        }
        Err(crate::invitations::InviteError::Repository(error)) => {
            return error_response(error.into());
        }
        Err(crate::invitations::InviteError::NotClaimable) => {
            return control_api_error(StatusCode::CONFLICT, "invalid_state");
        }
    };
    invitation_issued_response(&issued)
}

async fn active_owner<V, E>(
    state: &ControlHttpState<V, E>,
    user_id: UserId,
) -> Result<User, Response>
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let user = state
        .repository
        .get_user(user_id)
        .await
        .map_err(|error| error_response(error.into()))?
        .ok_or_else(|| control_api_error(StatusCode::FORBIDDEN, "forbidden"))?;
    if !user.can_manage_owner_ui() {
        return Err(control_api_error(StatusCode::FORBIDDEN, "forbidden"));
    }
    Ok(user)
}

async fn list_access_keys<V, E>(
    State(state): State<ControlHttpState<V, E>>,
    headers: HeaderMap,
) -> Response
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let principal = match require_authenticated_session(&state, &headers, false).await {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    match state.repository.list_access_keys(principal.user_id).await {
        Ok(keys) => (
            StatusCode::OK,
            Json(json!({
                "access_keys": keys.iter().map(access_key_view).collect::<Vec<_>>()
            })),
        )
            .into_response(),
        Err(error) => error_response(error.into()),
    }
}

async fn create_access_key<V, E>(
    State(state): State<ControlHttpState<V, E>>,
    headers: HeaderMap,
    Json(request): Json<CreateAccessKeyRequest>,
) -> Response
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let principal = match require_authenticated_session(&state, &headers, true).await {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let connections = request
        .connection_ids
        .into_iter()
        .map(ConnectionId::from_uuid)
        .collect::<Vec<_>>();
    let created = match AccessKey::generate(principal.user_id, request.name, connections) {
        Ok(created) => created,
        Err(_) => return control_api_error(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    let stored = match state.repository.insert_access_key(&created).await {
        Ok(stored) => stored,
        Err(RepositoryError::InvalidValue(_)) => {
            return control_api_error(StatusCode::BAD_REQUEST, "invalid_request");
        }
        Err(error) => return error_response(error.into()),
    };
    credential_response(&stored, created.credential)
}

async fn rotate_access_key<V, E>(
    State(state): State<ControlHttpState<V, E>>,
    Path(key_id): Path<Uuid>,
    headers: HeaderMap,
) -> Response
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let principal = match require_authenticated_session(&state, &headers, true).await {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let key_id = AccessKeyId::from_uuid(key_id);
    match state
        .repository
        .rotate_access_key(principal.user_id, key_id)
        .await
    {
        Ok(Some(rotated)) => credential_response(&rotated.key, rotated.credential),
        Ok(None) => control_api_error(StatusCode::NOT_FOUND, "not_found"),
        Err(RepositoryError::Conflict) => control_api_error(StatusCode::CONFLICT, "invalid_state"),
        Err(error) => error_response(error.into()),
    }
}

async fn revoke_access_key<V, E>(
    State(state): State<ControlHttpState<V, E>>,
    Path(key_id): Path<Uuid>,
    headers: HeaderMap,
) -> Response
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let principal = match require_authenticated_session(&state, &headers, true).await {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let key_id = AccessKeyId::from_uuid(key_id);
    let existing = match state
        .repository
        .get_access_key(principal.user_id, key_id)
        .await
    {
        Ok(Some(key)) => key,
        Ok(None) => return control_api_error(StatusCode::NOT_FOUND, "not_found"),
        Err(error) => return error_response(error.into()),
    };
    if existing.status.accepts_requests()
        && let Err(error) = state
            .repository
            .revoke_access_key(principal.user_id, key_id)
            .await
    {
        return error_response(error.into());
    }
    match state
        .repository
        .get_access_key(principal.user_id, key_id)
        .await
    {
        Ok(Some(stored)) => (
            StatusCode::OK,
            Json(json!({"access_key": access_key_view(&stored)})),
        )
            .into_response(),
        Ok(None) => control_api_error(StatusCode::NOT_FOUND, "not_found"),
        Err(error) => error_response(error.into()),
    }
}

async fn grant_access_key<V, E>(
    State(state): State<ControlHttpState<V, E>>,
    Path((key_id, connection_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Response
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    mutate_access_key_grant(&state, &headers, key_id, connection_id, true).await
}

async fn remove_access_key_grant<V, E>(
    State(state): State<ControlHttpState<V, E>>,
    Path((key_id, connection_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Response
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    mutate_access_key_grant(&state, &headers, key_id, connection_id, false).await
}

async fn mutate_access_key_grant<V, E>(
    state: &ControlHttpState<V, E>,
    headers: &HeaderMap,
    key_id: Uuid,
    connection_id: Uuid,
    granted: bool,
) -> Response
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let principal = match require_authenticated_session(state, headers, true).await {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let key_id = AccessKeyId::from_uuid(key_id);
    match state
        .repository
        .get_access_key(principal.user_id, key_id)
        .await
    {
        Ok(Some(key)) if key.status.accepts_requests() => {}
        Ok(Some(_)) => return control_api_error(StatusCode::CONFLICT, "invalid_state"),
        Ok(None) => return control_api_error(StatusCode::NOT_FOUND, "not_found"),
        Err(error) => return error_response(error.into()),
    }
    match state
        .repository
        .set_access_key_grant(key_id, ConnectionId::from_uuid(connection_id), granted)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(RepositoryError::InvalidValue(_)) => {
            control_api_error(StatusCode::BAD_REQUEST, "invalid_connection")
        }
        Err(error) => error_response(error.into()),
    }
}

async fn require_owner_session<V, E>(
    state: &ControlHttpState<V, E>,
    headers: &HeaderMap,
    require_csrf: bool,
) -> Result<SessionContext, Response>
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let token_hash = session_token_hash(headers).map_err(error_response)?;
    let session = state
        .control_plane
        .authenticate_session(&token_hash, Utc::now())
        .await
        .map_err(|error| error_response(error.into()))?;
    let user = state
        .repository
        .get_user(session.user_id)
        .await
        .map_err(|error| error_response(error.into()))?
        .ok_or_else(|| control_api_error(StatusCode::FORBIDDEN, "forbidden"))?;
    if user.role != UserRole::Owner {
        return Err(control_api_error(StatusCode::FORBIDDEN, "forbidden"));
    }
    if require_csrf {
        let presented = headers
            .get("x-csrf-token")
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| control_api_error(StatusCode::BAD_REQUEST, "invalid_csrf"))?;
        if !state
            .control_plane
            .verify_csrf(&session.csrf_token_hash, presented)
        {
            return Err(control_api_error(StatusCode::BAD_REQUEST, "invalid_csrf"));
        }
    }
    Ok(SessionContext {
        user_id: session.user_id,
        token_hash,
        csrf_token_hash: session.csrf_token_hash,
    })
}

fn invitation_view(invitation: &crate::repository::Invitation) -> serde_json::Value {
    json!({
        "id": invitation.id,
        "target_email": invitation.target_email,
        "expires_at": invitation.expires_at,
        "accepted_at": invitation.accepted_at,
        "created_at": invitation.created_at,
    })
}

fn invitation_issued_response(issued: &crate::invitations::IssuedInvitation) -> Response {
    let mut response = (
        StatusCode::OK,
        Json(json!({
            "invitation": invitation_view(&issued.invitation),
            "token": issued.token.as_str(),
            "accept_path": "/auth/invitations/accept",
            "credential_visible_once": true,
        })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn access_key_view(key: &StoredAccessKey) -> serde_json::Value {
    json!({
        "id": key.id,
        "name": key.name,
        "public_prefix": key.public_prefix,
        "generation": key.generation,
        "status": key.status,
        "connection_ids": key.grants.iter().copied().collect::<Vec<_>>(),
        "last_used_at": key.last_used_at,
    })
}

fn credential_response(key: &StoredAccessKey, credential: String) -> Response {
    let mut response = (
        StatusCode::OK,
        Json(json!({
            "access_key": access_key_view(key),
            "credential": credential,
            "credential_visible_once": true,
        })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn control_api_error(status: StatusCode, code: &'static str) -> Response {
    (status, Json(json!({"error": code}))).into_response()
}

async fn invitation_accept_start<V, E>(
    State(state): State<ControlHttpState<V, E>>,
    Json(request): Json<InvitationAcceptRequest>,
) -> Response
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let valid_token = URL_SAFE_NO_PAD
        .decode(request.token.as_bytes())
        .is_ok_and(|token| token.len() == 32);
    if !valid_token {
        return control_api_error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let now = Utc::now();
    let flow = match LoginFlow::with_invitation_token_hash(
        &state.config.public_base_url,
        state.config.google_login_client_id.clone(),
        hash_token(&request.token),
        now,
        Duration::minutes(10),
    ) {
        Ok(flow) => flow,
        Err(error) => return error_response(error.into()),
    };
    let mut response = begin_login_response(&state, flow, Uuid::now_v7())
        .await
        .unwrap_or_else(error_response);
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

pub async fn login_start<V, E>(State(state): State<ControlHttpState<V, E>>) -> Response
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let now = Utc::now();
    let flow = match LoginFlow::new(
        &state.config.public_base_url,
        state.config.google_login_client_id.clone(),
        now,
    ) {
        Ok(flow) => flow,
        Err(error) => return error_response(error.into()),
    };
    begin_login_response(&state, flow, Uuid::now_v7())
        .await
        .unwrap_or_else(error_response)
}

async fn begin_login_response<V, E>(
    state: &ControlHttpState<V, E>,
    flow: LoginFlow,
    transaction_id: Uuid,
) -> Result<Response, ControlHttpError>
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let envelope = flow.transaction().encrypted_pkce_verifier(
        &transaction_id.to_string(),
        &state.config.encryption_keyring,
    )?;
    persist_oauth_transaction(&state.repository, transaction_id, &flow, envelope).await?;
    Ok(redirect_with_cookie(
        flow.authorize_url().as_str(),
        oauth_transaction_cookie(LOGIN_TRANSACTION_COOKIE, transaction_id),
    ))
}

async fn begin_gmail_response<V, E>(
    state: &ControlHttpState<V, E>,
    flow: GmailFlow,
    transaction_id: Uuid,
) -> Result<Response, ControlHttpError>
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let envelope = flow.transaction().encrypted_pkce_verifier(
        &transaction_id.to_string(),
        &state.config.encryption_keyring,
    )?;
    persist_oauth_transaction(&state.repository, transaction_id, &flow, envelope).await?;
    Ok(redirect_with_cookie(
        flow.authorize_url().as_str(),
        oauth_transaction_cookie(GMAIL_TRANSACTION_COOKIE, transaction_id),
    ))
}

async fn persist_oauth_transaction<F>(
    repository: &Repository,
    transaction_id: Uuid,
    flow: &F,
    envelope: String,
) -> Result<(), ControlHttpError>
where
    F: OAuthFlowPersistence,
{
    let envelope = crate::repository::EncryptedPkceVerifier::from_envelope(envelope)?;
    repository
        .insert_oauth_transaction(transaction_id, &flow.persistence(), &envelope)
        .await?;
    Ok(())
}

trait OAuthFlowPersistence {
    fn persistence(&self) -> crate::oauth::OAuthTransactionRecord;
}
impl OAuthFlowPersistence for LoginFlow {
    fn persistence(&self) -> crate::oauth::OAuthTransactionRecord {
        self.transaction().persistence()
    }
}
impl OAuthFlowPersistence for GmailFlow {
    fn persistence(&self) -> crate::oauth::OAuthTransactionRecord {
        self.transaction().persistence()
    }
}

pub async fn login_callback<V, E>(
    State(state): State<ControlHttpState<V, E>>,
    Query(query): Query<OAuthCallbackQuery>,
    headers: HeaderMap,
) -> Response
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    oauth_callback(
        state,
        query,
        headers,
        OAuthFlowKind::Login,
        LOGIN_TRANSACTION_COOKIE,
    )
    .await
}

/// Cut local access before contacting Google, then discard the local credential
/// even when Google cannot confirm revocation. The spawned operation survives
/// an HTTP client disconnect; process crashes leave a retryable revoking row.
async fn revoke_connection<V, E>(
    State(state): State<ControlHttpState<V, E>>,
    Path(connection_id): Path<Uuid>,
    headers: HeaderMap,
) -> Response
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let token_hash = match session_token_hash(&headers) {
        Ok(hash) => hash,
        Err(error) => return error_response(error),
    };
    let session = match state
        .control_plane
        .authenticate_session(&token_hash, Utc::now())
        .await
    {
        Ok(session) => session,
        Err(error) => return error_response(error.into()),
    };
    let csrf = headers
        .get("x-csrf-token")
        .and_then(|value| value.to_str().ok());
    if !csrf.is_some_and(|csrf| {
        state
            .control_plane
            .verify_csrf(&session.csrf_token_hash, csrf)
    }) {
        return error_response(ControlHttpError::InvalidRequest);
    }
    let connection_id = ConnectionId::from_uuid(connection_id);
    let operation = tokio::spawn(async move {
        revoke_connection_account(&state, session.user_id, connection_id).await
    });
    match operation.await {
        Ok(Ok(Some(remote_status))) => (
            [(header::CACHE_CONTROL, "no-store")],
            Json(json!({
                "connection_id": connection_id.to_string(),
                "local_revoked": true,
                "remote_revocation": remote_status,
            })),
        )
            .into_response(),
        Ok(Ok(None)) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error":"connection_not_found"})),
        )
            .into_response(),
        Ok(Err(error)) => error_response(error.into()),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error":"service_unavailable"})),
        )
            .into_response(),
    }
}

/// Start a Gmail reauthorization flow for an existing managed connection.
/// Missing and foreign connections both return 404 so the endpoint cannot be
/// used to enumerate other users' connections.
async fn reauthorize_connection<V, E>(
    State(state): State<ControlHttpState<V, E>>,
    Path(connection_id): Path<Uuid>,
    headers: HeaderMap,
) -> Response
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let token_hash = match session_token_hash(&headers) {
        Ok(hash) => hash,
        Err(error) => return error_response(error),
    };
    let session = match state
        .control_plane
        .authenticate_session(&token_hash, Utc::now())
        .await
    {
        Ok(session) => session,
        Err(error) => return error_response(error.into()),
    };
    let csrf = headers
        .get("x-csrf-token")
        .and_then(|value| value.to_str().ok());
    if !csrf.is_some_and(|csrf| {
        state
            .control_plane
            .verify_csrf(&session.csrf_token_hash, csrf)
    }) {
        return error_response(ControlHttpError::InvalidRequest);
    }
    let connection_id = ConnectionId::from_uuid(connection_id);
    let connection = match state.repository.get_connection(connection_id).await {
        Ok(Some(connection)) if connection.owner_id == session.user_id => connection,
        Ok(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error":"connection_not_found"})),
            )
                .into_response();
        }
        Err(error) => return error_response(error.into()),
    };
    if connection.status == ConnectionStatus::Revoking {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error":"connection_revoking"})),
        )
            .into_response();
    }
    let flow = match GmailFlow::with_context(
        &state.config.public_base_url,
        state.config.google_gmail_client_id.clone(),
        Some(session.user_id.to_string()),
        Some(connection_id.to_string()),
        Utc::now(),
        Duration::minutes(10),
    ) {
        Ok(flow) => flow,
        Err(error) => return error_response(error.into()),
    };
    let transaction_id = Uuid::now_v7();
    let envelope = match flow.transaction().encrypted_pkce_verifier(
        &transaction_id.to_string(),
        &state.config.encryption_keyring,
    ) {
        Ok(envelope) => envelope,
        Err(error) => return error_response(error.into()),
    };
    if let Err(error) =
        persist_oauth_transaction(&state.repository, transaction_id, &flow, envelope).await
    {
        return error_response(error);
    }
    let authorize_url = flow.authorize_url().as_str().to_owned();
    let mut response = (
        StatusCode::OK,
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({
            "connection_id": connection_id.to_string(),
            "authorize_url": authorize_url,
        })),
    )
        .into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&oauth_transaction_cookie(
            GMAIL_TRANSACTION_COOKIE,
            transaction_id,
        ))
        .expect("cookie value"),
    );
    response
}

pub(crate) async fn revoke_connection_account<V, E>(
    state: &ControlHttpState<V, E>,
    owner_id: UserId,
    connection_id: ConnectionId,
) -> Result<Option<&'static str>, RepositoryError>
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    revoke_connection_account_with_mode(state, owner_id, connection_id, true).await
}

async fn revoke_connection_account_with_mode<V, E>(
    state: &ControlHttpState<V, E>,
    owner_id: UserId,
    connection_id: ConnectionId,
    claim_active: bool,
) -> Result<Option<&'static str>, RepositoryError>
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let revocation = if claim_active {
        state
            .repository
            .claim_connection_revoke(owner_id, connection_id)
            .await?
    } else {
        state
            .repository
            .begin_connection_revoke(owner_id, connection_id)
            .await?
    };
    let Some(revocation) = revocation else {
        return Ok(None);
    };
    let remote_status = match revocation.refresh_token_envelope {
        None => "not_available",
        Some(envelope) => match decrypt_refresh_token(
            envelope.as_str(),
            &owner_id.to_string(),
            &connection_id.to_string(),
            &state.config.encryption_keyring,
        )
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        {
            Some(token) => {
                revoke_google_with_retry(
                    state.gmail_token_exchanger.as_ref(),
                    &SecretString::from(token),
                )
                .await
            }
            None => "credential_unavailable",
        },
    };
    state
        .repository
        .finish_connection_revoke(owner_id, connection_id)
        .await?;
    Ok(Some(remote_status))
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct UserRevocationResult {
    connections: usize,
    remote_revoked: usize,
    remote_unconfirmed: usize,
    credential_unavailable: usize,
}

async fn delete_own_account<V, E>(
    State(state): State<ControlHttpState<V, E>>,
    headers: HeaderMap,
) -> Response
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let session = match require_authenticated_session(&state, &headers, true).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let state_for_task = state.clone();
    let operation = tokio::spawn(async move {
        revoke_member_account(&state_for_task, session.user_id, session.user_id).await
    });
    match operation.await {
        Ok(Ok(Some(result))) => {
            let mut response = user_revocation_response(session.user_id, result);
            append_clear_auth_cookies(&mut response);
            response
        }
        Ok(Ok(None)) => control_api_error(StatusCode::FORBIDDEN, "owner_cannot_be_deleted"),
        Ok(Err(error)) => error_response(error.into()),
        Err(_) => control_api_error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    }
}

async fn revoke_member<V, E>(
    State(state): State<ControlHttpState<V, E>>,
    Path(user_id): Path<Uuid>,
    headers: HeaderMap,
) -> Response
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let owner = match require_owner_session(&state, &headers, true).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let user_id = UserId::from_uuid(user_id);
    let state_for_task = state.clone();
    let operation = tokio::spawn(async move {
        revoke_member_account(&state_for_task, owner.user_id, user_id).await
    });
    match operation.await {
        Ok(Ok(Some(result))) => user_revocation_response(user_id, result),
        Ok(Ok(None)) => control_api_error(StatusCode::NOT_FOUND, "member_not_found"),
        Ok(Err(error)) => error_response(error.into()),
        Err(_) => control_api_error(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable"),
    }
}

pub(crate) async fn revoke_member_account<V, E>(
    state: &ControlHttpState<V, E>,
    actor_id: UserId,
    user_id: UserId,
) -> Result<Option<UserRevocationResult>, RepositoryError>
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let Some(revocation) = state
        .repository
        .begin_user_revoke(actor_id, user_id)
        .await?
    else {
        return Ok(None);
    };
    revoke_user_credentials(state, revocation).await.map(Some)
}

async fn require_authenticated_session<V, E>(
    state: &ControlHttpState<V, E>,
    headers: &HeaderMap,
    require_csrf: bool,
) -> Result<SessionContext, Response>
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let token_hash = session_token_hash(headers).map_err(error_response)?;
    let session = state
        .control_plane
        .authenticate_session(&token_hash, Utc::now())
        .await
        .map_err(|error| error_response(error.into()))?;
    if require_csrf {
        let presented = headers
            .get("x-csrf-token")
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| control_api_error(StatusCode::BAD_REQUEST, "invalid_csrf"))?;
        if !state
            .control_plane
            .verify_csrf(&session.csrf_token_hash, presented)
        {
            return Err(control_api_error(StatusCode::BAD_REQUEST, "invalid_csrf"));
        }
    }
    Ok(SessionContext {
        user_id: session.user_id,
        token_hash,
        csrf_token_hash: session.csrf_token_hash,
    })
}

async fn revoke_user_credentials<V, E>(
    state: &ControlHttpState<V, E>,
    revocation: UserRevocation,
) -> Result<UserRevocationResult, RepositoryError>
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let mut result = UserRevocationResult {
        connections: revocation.connections.len(),
        ..UserRevocationResult::default()
    };
    for connection in revocation.connections {
        let Some(envelope) = connection.refresh_token_envelope else {
            result.credential_unavailable += 1;
            continue;
        };
        let token = decrypt_refresh_token(
            envelope.as_str(),
            &revocation.user_id.to_string(),
            &connection.connection_id.to_string(),
            &state.config.encryption_keyring,
        )
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .map(SecretString::from);
        let Some(token) = token else {
            result.credential_unavailable += 1;
            continue;
        };
        match revoke_google_with_retry(state.gmail_token_exchanger.as_ref(), &token).await {
            "revoked" => result.remote_revoked += 1,
            _ => result.remote_unconfirmed += 1,
        }
    }
    state
        .repository
        .finish_user_revoke(revocation.user_id)
        .await?;
    Ok(result)
}

/// Complete Member and standalone Connection revocations left by an
/// interrupted process before the server begins accepting requests.
pub async fn recover_pending_revocations<V, E>(
    state: &ControlHttpState<V, E>,
) -> Result<usize, RepositoryError>
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let users = state.repository.list_revoking_members().await?;
    let mut completed = 0;
    for user_id in users {
        if let Some(revocation) = state.repository.resume_user_revoke(user_id).await? {
            revoke_user_credentials(state, revocation).await?;
            completed += 1;
        }
    }
    for (owner_id, connection_id) in state.repository.list_revoking_connections().await? {
        if revoke_connection_account_with_mode(state, owner_id, connection_id, false)
            .await?
            .is_some()
        {
            completed += 1;
        }
    }
    Ok(completed)
}

fn user_revocation_response(user_id: UserId, result: UserRevocationResult) -> Response {
    (
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({
            "user_id": user_id.to_string(),
            "local_revoked": true,
            "connections": result.connections,
            "remote_revoked": result.remote_revoked,
            "remote_unconfirmed": result.remote_unconfirmed,
            "credential_unavailable": result.credential_unavailable,
        })),
    )
        .into_response()
}

fn append_clear_auth_cookies(response: &mut Response) {
    let policy = SessionCookiePolicy::default();
    for value in [
        format!(
            "{}=; HttpOnly; Secure; SameSite=Lax; Path={}; Max-Age=0",
            policy.name, policy.path
        ),
        crate::control_ui::csrf_cookie_clear(),
    ] {
        response.headers_mut().append(
            header::SET_COOKIE,
            HeaderValue::from_str(&value).expect("fixed cookie attributes are valid"),
        );
    }
}

async fn revoke_google_with_retry<E: OAuthCodeExchanger>(
    exchanger: &E,
    token: &SecretString,
) -> &'static str {
    for attempt in 0..3 {
        let result =
            tokio::time::timeout(std::time::Duration::from_secs(3), exchanger.revoke(token))
                .await
                .unwrap_or(Err(GoogleTokenError::Timeout));
        match result {
            Ok(()) => return "revoked",
            Err(GoogleTokenError::RateLimited {
                retry_after_seconds,
            }) if attempt < 2 => {
                let seconds = retry_after_seconds.unwrap_or(1);
                if seconds > 1 {
                    return "unconfirmed";
                }
                tokio::time::sleep(std::time::Duration::from_secs(seconds)).await;
            }
            Err(GoogleTokenError::Upstream | GoogleTokenError::Timeout) if attempt < 2 => {
                tokio::time::sleep(std::time::Duration::from_millis(100 * (attempt + 1))).await;
            }
            Err(_) => return "unconfirmed",
        }
    }
    "unconfirmed"
}

pub async fn gmail_start<V, E>(
    State(state): State<ControlHttpState<V, E>>,
    Query(query): Query<GmailStartQuery>,
    headers: HeaderMap,
) -> Response
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let token_hash = match session_token_hash(&headers) {
        Ok(hash) => hash,
        Err(error) => return error_response(error),
    };
    let session = match state
        .control_plane
        .authenticate_session(&token_hash, Utc::now())
        .await
    {
        Ok(session) => session,
        Err(error) => return error_response(error.into()),
    };
    let Some(csrf) = headers
        .get("x-csrf-token")
        .and_then(|value| value.to_str().ok())
    else {
        return error_response(ControlHttpError::InvalidRequest);
    };
    if !state
        .control_plane
        .verify_csrf(&session.csrf_token_hash, csrf)
    {
        return error_response(ControlHttpError::InvalidRequest);
    }
    if let Some(connection_id) = query.connection_id {
        let connection = match state
            .repository
            .get_connection(ConnectionId::from_uuid(connection_id))
            .await
        {
            Ok(Some(connection)) => connection,
            Ok(None) => return error_response(ControlHttpError::InvalidRequest),
            Err(error) => return error_response(error.into()),
        };
        if connection.owner_id != session.user_id {
            return error_response(ControlHttpError::InvalidRequest);
        }
    }
    let now = Utc::now();
    let flow = match GmailFlow::with_context(
        &state.config.public_base_url,
        state.config.google_gmail_client_id.clone(),
        Some(session.user_id.to_string()),
        query.connection_id.map(|id| id.to_string()),
        now,
        Duration::minutes(10),
    ) {
        Ok(flow) => flow,
        Err(error) => return error_response(error.into()),
    };
    begin_gmail_response(&state, flow, Uuid::now_v7())
        .await
        .unwrap_or_else(error_response)
}

pub async fn gmail_callback<V, E>(
    State(state): State<ControlHttpState<V, E>>,
    Query(query): Query<OAuthCallbackQuery>,
    headers: HeaderMap,
) -> Response
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    oauth_callback(
        state,
        query,
        headers,
        OAuthFlowKind::Gmail,
        GMAIL_TRANSACTION_COOKIE,
    )
    .await
}

async fn oauth_callback<V, E>(
    state: ControlHttpState<V, E>,
    query: OAuthCallbackQuery,
    headers: HeaderMap,
    expected_flow: OAuthFlowKind,
    transaction_cookie: &str,
) -> Response
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let mut response =
        oauth_callback_inner(state, query, headers, expected_flow, transaction_cookie).await;
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&clear_cookie(transaction_cookie)).expect("cookie value"),
    );
    response
}
async fn oauth_callback_inner<V, E>(
    state: ControlHttpState<V, E>,
    query: OAuthCallbackQuery,
    headers: HeaderMap,
    expected_flow: OAuthFlowKind,
    transaction_cookie: &str,
) -> Response
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    if query
        .error
        .as_ref()
        .is_some_and(|value| value.len() > MAX_OAUTH_QUERY_VALUE_BYTES)
    {
        return error_response(ControlHttpError::InvalidRequest);
    }
    if query.error.is_some() {
        return error_response(ControlHttpError::InvalidRequest);
    }
    let Some(code) = query.code.filter(|value| !value.trim().is_empty()) else {
        return error_response(ControlHttpError::InvalidRequest);
    };
    if code.len() > MAX_OAUTH_QUERY_VALUE_BYTES {
        return error_response(ControlHttpError::InvalidRequest);
    }
    let Some(state_value) = query.state.filter(|value| !value.trim().is_empty()) else {
        return error_response(ControlHttpError::InvalidRequest);
    };
    if state_value.len() > MAX_OAUTH_QUERY_VALUE_BYTES {
        return error_response(ControlHttpError::InvalidRequest);
    }
    let transaction_id = match transaction_cookie_value(&headers, transaction_cookie) {
        Ok(id) => id,
        Err(error) => return error_response(error),
    };
    let claim = match state
        .repository
        .claim_oauth_transaction_for_flow(transaction_id, &state_value, expected_flow, Utc::now())
        .await
    {
        Ok(Some(claim)) if claim.flow == expected_flow => claim,
        Ok(_) => return error_response(ControlHttpError::InvalidRequest),
        Err(error) => return error_response(error.into()),
    };
    let verifier = match crate::oauth::decrypt_pkce_verifier(
        claim.pkce_verifier.as_str(),
        &transaction_id.to_string(),
        &state.config.encryption_keyring,
    ) {
        Ok(verifier) => verifier,
        Err(error) => return error_response(error.into()),
    };
    let token_exchanger = match expected_flow {
        OAuthFlowKind::Login => &state.login_token_exchanger,
        OAuthFlowKind::Gmail => &state.gmail_token_exchanger,
    };
    let token_set = match token_exchanger.exchange_code(&code, &verifier).await {
        Ok(tokens) => tokens,
        Err(error) => {
            tracing::warn!(flow = ?expected_flow, error = ?error, "OAuth token exchange failed");
            return error_response(error.into());
        }
    };
    let Some(id_token) = token_set.id_token.as_ref() else {
        return error_response(ControlHttpError::MissingIdToken);
    };
    let claims = match state
        .oidc_verifier
        .verify_with_refresh(id_token.expose_secret())
        .await
    {
        Ok(claims) => claims,
        Err(error) => {
            tracing::warn!(flow = ?expected_flow, error = ?error, "OIDC token verification failed");
            return error_response(ControlHttpError::OidcVerification);
        }
    };
    let identity = match validate_verified_claims(
        &claims,
        &claim.nonce_hash,
        expected_client_id(&state, expected_flow),
        Utc::now(),
    ) {
        Ok(identity) => identity,
        Err(error) => {
            tracing::warn!(flow = ?expected_flow, error = ?error, "OIDC claims validation failed");
            return error_response(error);
        }
    };
    let response = match expected_flow {
        OAuthFlowKind::Login => finish_login(&state, identity, claim, Utc::now()).await,
        OAuthFlowKind::Gmail => finish_gmail(&state, identity, token_set, claim).await,
    };
    match response {
        Ok((mut response, session_cookie)) => {
            if let Some(cookie) = session_cookie {
                response.headers_mut().append(
                    header::SET_COOKIE,
                    HeaderValue::from_str(&cookie).expect("cookie value"),
                );
            }
            response
        }
        Err(error) => {
            tracing::warn!(
                flow = ?expected_flow,
                error_category = control_http_error_category(&error),
                "OAuth flow completion failed"
            );
            error_response(error)
        }
    }
}

fn control_http_error_category(error: &ControlHttpError) -> &'static str {
    match error {
        ControlHttpError::InvalidRequest => "invalid_request",
        ControlHttpError::InvalidTransactionCookie => "invalid_transaction_cookie",
        ControlHttpError::OidcVerification => "oidc_verification",
        ControlHttpError::MissingIdToken => "missing_id_token",
        ControlHttpError::NonceMismatch => "nonce_mismatch",
        ControlHttpError::OAuth(_) => "oauth",
        ControlHttpError::GoogleToken(_) => "google_token",
        ControlHttpError::Crypto(_) => "crypto",
        ControlHttpError::Repository(_) => "repository",
        ControlHttpError::ControlPlane(_) => "control_plane",
    }
}

fn expected_client_id<V, E>(state: &ControlHttpState<V, E>, flow: OAuthFlowKind) -> &str
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    match flow {
        OAuthFlowKind::Login => &state.config.google_login_client_id,
        OAuthFlowKind::Gmail => &state.config.google_gmail_client_id,
    }
}

fn validate_verified_claims(
    claims: &OidcClaims,
    nonce_hash: &str,
    expected_audience: &str,
    now: DateTime<Utc>,
) -> Result<ValidatedOidcIdentity, ControlHttpError> {
    // The plaintext nonce is intentionally not persisted. The semantic
    // validator still checks issuer/audience/expiry/email; this extra digest
    // check binds the returned ID token to the consumed transaction.
    let identity =
        validate_oidc_claims(claims, &claims.nonce, expected_audience, GOOGLE_ISSUER, now)?;
    if !verify_token(&claims.nonce, nonce_hash).unwrap_or(false) {
        return Err(ControlHttpError::NonceMismatch);
    }
    Ok(identity)
}

async fn finish_login<V, E>(
    state: &ControlHttpState<V, E>,
    identity: ValidatedOidcIdentity,
    claim: crate::repository::OAuthTransactionClaim,
    now: DateTime<Utc>,
) -> Result<(Response, Option<String>), ControlHttpError>
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let credentials = if let Some(invitation_token_hash) = claim.invitation_token_hash {
        state
            .control_plane
            .accept_invitation_session(&invitation_token_hash, &identity, now)
            .await?
    } else {
        state.control_plane.login_session(&identity, now).await?
    };
    let location = match credentials.user.role {
        UserRole::Owner => "/control",
        UserRole::Member => "/control/account",
    };
    let mut response = Redirect::to(location).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&crate::control_ui::csrf_cookie_value(
            &credentials.csrf_token,
        ))
        .expect("csrf cookie header"),
    );
    Ok((
        response,
        Some(session_cookie(
            &credentials.cookie,
            &credentials.session_token,
        )),
    ))
}

async fn finish_gmail<V, E>(
    state: &ControlHttpState<V, E>,
    identity: ValidatedOidcIdentity,
    token_set: TokenSet,
    claim: crate::repository::OAuthTransactionClaim,
) -> Result<(Response, Option<String>), ControlHttpError>
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let user_id = claim.initiated_by.ok_or(ControlHttpError::InvalidRequest)?;
    let scopes = validate_granted_gmail_scopes(token_set.scope.iter())?;
    let refresh_token = token_set
        .refresh_token
        .as_ref()
        .ok_or(ControlHttpError::InvalidRequest)?;

    let _connection = if let Some(connection_id) = claim.target_connection {
        let existing = state
            .repository
            .get_connection(connection_id)
            .await?
            .ok_or(ControlHttpError::InvalidRequest)?;
        if existing.owner_id != user_id
            || existing.google_sub != identity.subject
            || existing.status == ConnectionStatus::Revoking
        {
            return Err(ControlHttpError::InvalidRequest);
        }
        let envelope = encrypt_refresh_token(
            refresh_token.expose_secret(),
            &user_id.to_string(),
            &connection_id.to_string(),
            &state.config.encryption_keyring,
        )?;
        let envelope = EncryptedRefreshToken::from_envelope(envelope)?;
        if !state
            .repository
            .reauthorize_connection(
                connection_id,
                user_id,
                &identity.subject,
                &identity.email,
                &scopes,
                &envelope,
            )
            .await?
        {
            return Err(ControlHttpError::InvalidRequest);
        }
        let mut updated = existing;
        updated.email = identity.email;
        updated.granted_scopes = scopes;
        updated.status = ConnectionStatus::Active;
        updated
    } else {
        state
            .repository
            .record_first_authorized_subject(
                &identity.subject,
                Utc::now(),
                u32::from(state.config.personal_use_user_limit),
            )
            .await?;
        let connection = GmailConnection::new(user_id, identity.subject, identity.email, scopes)
            .map_err(|_| ControlHttpError::InvalidRequest)?;
        let envelope = encrypt_refresh_token(
            refresh_token.expose_secret(),
            &user_id.to_string(),
            &connection.id.to_string(),
            &state.config.encryption_keyring,
        )?;
        let envelope = EncryptedRefreshToken::from_envelope(envelope)?;
        state
            .repository
            .insert_connection(&connection, Some(&envelope))
            .await?;
        connection
    };

    let mut response = Redirect::to("/control/account").into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok((response, None))
}
pub async fn logout<V, E>(
    State(state): State<ControlHttpState<V, E>>,
    headers: HeaderMap,
) -> Response
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let token_hash = match session_token_hash(&headers) {
        Ok(hash) => hash,
        Err(error) => return error_response(error),
    };
    let session = match state
        .control_plane
        .authenticate_session(&token_hash, Utc::now())
        .await
    {
        Ok(session) => session,
        Err(error) => return error_response(error.into()),
    };
    let Some(csrf) = headers.get("x-csrf-token").and_then(|v| v.to_str().ok()) else {
        return error_response(ControlHttpError::InvalidRequest);
    };
    if !state
        .control_plane
        .verify_csrf(&session.csrf_token_hash, csrf)
    {
        return error_response(ControlHttpError::InvalidRequest);
    }
    match state.control_plane.logout(&token_hash).await {
        Ok(_) => {
            let mut response = StatusCode::NO_CONTENT.into_response();
            response.headers_mut().append(
                header::SET_COOKIE,
                HeaderValue::from_str(&clear_cookie(SessionCookiePolicy::default().name))
                    .expect("cookie value"),
            );
            response
        }
        Err(error) => error_response(error.into()),
    }
}

/// Middleware for protected subroutes. It stores only the session hash and
/// metadata in request extensions; handlers never receive the cookie plaintext.
pub async fn session_middleware<V, E>(
    state: ControlHttpState<V, E>,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Response
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let token_hash = match session_token_hash(request.headers()) {
        Ok(hash) => hash,
        Err(error) => return error_response(error),
    };
    let session = match state
        .control_plane
        .authenticate_session(&token_hash, Utc::now())
        .await
    {
        Ok(session) => session,
        Err(error) => return error_response(error.into()),
    };
    request.extensions_mut().insert(SessionContext {
        user_id: session.user_id,
        token_hash,
        csrf_token_hash: session.csrf_token_hash,
    });
    next.run(request).await
}

fn session_token_hash(headers: &HeaderMap) -> Result<String, ControlHttpError> {
    let token = cookie_value(headers, SessionCookiePolicy::default().name)
        .ok_or(ControlHttpError::InvalidTransactionCookie)?;
    if token.trim().is_empty() {
        return Err(ControlHttpError::InvalidTransactionCookie);
    }
    Ok(hash_token(token))
}

fn transaction_cookie_value(headers: &HeaderMap, name: &str) -> Result<Uuid, ControlHttpError> {
    let value = cookie_value(headers, name).ok_or(ControlHttpError::InvalidTransactionCookie)?;
    Uuid::parse_str(value).map_err(|_| ControlHttpError::InvalidTransactionCookie)
}

pub(crate) fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .find_map(|(key, value)| (key == name).then_some(value))
}

fn oauth_transaction_cookie(name: &str, id: Uuid) -> String {
    format!(
        "{name}={id}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={OAUTH_TRANSACTION_MAX_AGE}"
    )
}

fn session_cookie(policy: &SessionCookiePolicy, token: &str) -> String {
    let mut value = format!("{}={}", policy.name, token);
    if policy.http_only {
        value.push_str("; HttpOnly");
    }
    if policy.secure {
        value.push_str("; Secure");
    }
    if policy.same_site_lax {
        value.push_str("; SameSite=Lax");
    }
    value.push_str("; Path=");
    value.push_str(policy.path);
    value
}

fn clear_cookie(name: &str) -> String {
    format!("{name}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0")
}

fn redirect_with_cookie(location: &str, cookie: String) -> Response {
    let mut response = Redirect::temporary(location).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).expect("cookie value"),
    );
    response
}

fn error_response(error: ControlHttpError) -> Response {
    let (status, code) = match error {
        ControlHttpError::ControlPlane(ControlPlaneError::Unauthenticated)
        | ControlHttpError::InvalidTransactionCookie => {
            (StatusCode::UNAUTHORIZED, "authentication_failed")
        }
        ControlHttpError::Repository(_)
        | ControlHttpError::ControlPlane(ControlPlaneError::Repository(_)) => {
            (StatusCode::SERVICE_UNAVAILABLE, "service_unavailable")
        }
        ControlHttpError::OAuth(_)
        | ControlHttpError::GoogleToken(_)
        | ControlHttpError::Crypto(_)
        | ControlHttpError::ControlPlane(_)
        | ControlHttpError::InvalidRequest
        | ControlHttpError::OidcVerification
        | ControlHttpError::MissingIdToken
        | ControlHttpError::NonceMismatch => (StatusCode::BAD_REQUEST, "authentication_failed"),
    };
    (status, Json(json!({"error":code}))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        database::Database,
        domain::{
            access::AccessKey,
            identity::{
                GMAIL_COMPOSE_SCOPE, GMAIL_READONLY_SCOPE, SessionId, User, UserRole, UserStatus,
            },
        },
        repository::NewWebSession,
    };
    use axum::{body::Body, http::Method};

    use serde_json::Value;
    use std::collections::BTreeMap;
    use tower::ServiceExt;

    #[derive(Clone)]
    struct UnusedVerifier;

    #[async_trait::async_trait]
    impl OidcTokenVerifier for UnusedVerifier {
        async fn verify_with_refresh(
            &self,
            _id_token: &str,
        ) -> Result<OidcClaims, GoogleOidcError> {
            panic!("OIDC verification is not used by access-key route tests")
        }
    }

    #[derive(Clone)]
    struct UnusedExchanger;

    #[derive(Clone)]
    struct CallbackVerifier(OidcClaims);

    #[async_trait::async_trait]
    impl OidcTokenVerifier for CallbackVerifier {
        async fn verify_with_refresh(&self, _: &str) -> Result<OidcClaims, GoogleOidcError> {
            Ok(self.0.clone())
        }
    }

    #[derive(Clone)]
    struct CallbackExchanger(TokenSet);

    #[async_trait::async_trait]
    impl OAuthCodeExchanger for CallbackExchanger {
        async fn exchange_code(
            &self,
            _: &str,
            _: &SecretString,
        ) -> Result<TokenSet, GoogleTokenError> {
            Ok(self.0.clone())
        }
    }

    #[tokio::test]
    async fn gmail_callback_accepts_owner_identity_with_google_scope_urls() {
        let database = Database::connect("sqlite::memory:").await.unwrap();
        database.migrate().await.unwrap();
        let repository = Repository::new(&database);
        let now = Utc::now();
        let config = test_config();
        let owner = User::new("owner-sub", "owner@example.com", UserRole::Owner, now).unwrap();
        repository.insert_user(&owner).await.unwrap();
        let flow = GmailFlow::with_context(
            &config.public_base_url,
            config.google_gmail_client_id.clone(),
            Some(owner.id.to_string()),
            None,
            now,
            Duration::minutes(10),
        )
        .unwrap();
        let exchanger = CallbackExchanger(TokenSet {
            access_token: "test-access".into(),
            expires_in: 3600,
            refresh_token: Some("test-refresh".into()),
            id_token: Some("test-id-token".into()),
            scope: [
                "openid",
                "https://www.googleapis.com/auth/userinfo.email",
                "https://www.googleapis.com/auth/userinfo.profile",
                crate::oauth::GMAIL_READONLY_SCOPE,
                crate::oauth::GMAIL_COMPOSE_SCOPE,
            ]
            .map(str::to_owned)
            .to_vec(),
        });
        let state = ControlHttpState::new(
            config,
            repository.clone(),
            CallbackVerifier(OidcClaims {
                issuer: GOOGLE_ISSUER.to_owned(),
                audience: vec!["gmail-client-id".to_owned()],
                azp: None,
                subject: owner.google_sub.clone(),
                email: owner.email.clone(),
                email_verified: true,
                expires_at: (now + Duration::hours(1)).timestamp(),
                nonce: flow.nonce().to_owned(),
            }),
            exchanger.clone(),
            exchanger,
        )
        .unwrap();
        let transaction_id = Uuid::now_v7();
        begin_gmail_response(&state, flow.clone(), transaction_id)
            .await
            .unwrap();
        let app = router(state);
        let request = || {
            axum::http::Request::builder()
                .uri(format!(
                    "{GMAIL_CALLBACK_PATH}?code=test-code&state={}",
                    flow.state()
                ))
                .header(
                    header::COOKIE,
                    format!("{GMAIL_TRANSACTION_COOKIE}={transaction_id}"),
                )
                .body(Body::empty())
                .unwrap()
        };
        let response = app.clone().oneshot(request()).await.unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers()[header::LOCATION], "/control/account");
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let connections = repository
            .list_connections_for_user(owner.id)
            .await
            .unwrap();
        assert_eq!(connections.len(), 1);
        assert_eq!(connections[0].google_sub, owner.google_sub);
        assert_eq!(connections[0].email, owner.email);
        assert_eq!(connections[0].granted_scopes, crate::oauth::GMAIL_SCOPES);
        let replay = app.oneshot(request()).await.unwrap();
        assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            repository
                .list_connections_for_user(owner.id)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[async_trait::async_trait]
    impl OAuthCodeExchanger for UnusedExchanger {
        async fn exchange_code(
            &self,
            _code: &str,
            _code_verifier: &SecretString,
        ) -> Result<TokenSet, GoogleTokenError> {
            panic!("OAuth exchange is not used by access-key route tests")
        }
    }

    fn test_config() -> AppConfig {
        let key = URL_SAFE_NO_PAD.encode([11_u8; 32]);
        AppConfig::from_map(BTreeMap::from([
            ("APP_ENV".to_owned(), "production".to_owned()),
            (
                "PUBLIC_BASE_URL".to_owned(),
                "https://agentmail.example".to_owned(),
            ),
            ("OWNER_EMAIL".to_owned(), "owner@example.com".to_owned()),
            (
                "GOOGLE_LOGIN_CLIENT_ID".to_owned(),
                "login-client-id".to_owned(),
            ),
            (
                "GOOGLE_GMAIL_CLIENT_ID".to_owned(),
                "gmail-client-id".to_owned(),
            ),
            ("LOGIN_CLIENT_SECRET".to_owned(), "l".repeat(32)),
            ("GMAIL_CLIENT_SECRET".to_owned(), "g".repeat(32)),
            ("SESSION_SECRET".to_owned(), "s".repeat(32)),
            ("CSRF_SECRET".to_owned(), "c".repeat(32)),
            (
                "CREDENTIAL_ENCRYPTION_KEYRING".to_owned(),
                format!("v1={key}"),
            ),
        ]))
        .unwrap()
    }

    #[derive(Clone)]
    struct RevokeExchanger {
        repository: Repository,
        connection_id: ConnectionId,
        calls: Arc<std::sync::atomic::AtomicUsize>,
        failure: bool,
    }

    struct RejectedRevoke {
        error: GoogleTokenError,
        calls: std::sync::atomic::AtomicUsize,
    }

    /// A deterministic remote-revoke stand-in. It pauses after the local
    /// barrier commits so authorization reads can be stressed before cleanup.
    #[derive(Clone)]
    struct BlockingRevokeExchanger {
        repository: Repository,
        user_id: Option<UserId>,
        connection_ids: Vec<ConnectionId>,
        calls: Arc<std::sync::atomic::AtomicUsize>,
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    }

    #[async_trait]
    impl OAuthCodeExchanger for RejectedRevoke {
        async fn exchange_code(
            &self,
            _: &str,
            _: &SecretString,
        ) -> Result<TokenSet, GoogleTokenError> {
            unreachable!()
        }
        async fn revoke(&self, _: &SecretString) -> Result<(), GoogleTokenError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(self.error.clone())
        }
    }

    #[tokio::test]
    async fn connection_revoke_does_not_retry_permanent_errors_or_exceed_retry_after_budget() {
        for error in [
            GoogleTokenError::InvalidGrant,
            GoogleTokenError::InvalidResponse,
            GoogleTokenError::RateLimited {
                retry_after_seconds: Some(3600),
            },
        ] {
            let exchanger = RejectedRevoke {
                error,
                calls: std::sync::atomic::AtomicUsize::new(0),
            };
            assert_eq!(
                revoke_google_with_retry(&exchanger, &SecretString::from("synthetic-refresh"))
                    .await,
                "unconfirmed"
            );
            assert_eq!(exchanger.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        }
    }

    #[async_trait]
    impl OAuthCodeExchanger for RevokeExchanger {
        async fn exchange_code(
            &self,
            _: &str,
            _: &SecretString,
        ) -> Result<TokenSet, GoogleTokenError> {
            unreachable!()
        }

        async fn revoke(&self, _: &SecretString) -> Result<(), GoogleTokenError> {
            assert_eq!(
                self.repository
                    .get_connection(self.connection_id)
                    .await
                    .unwrap()
                    .unwrap()
                    .status,
                ConnectionStatus::Revoking
            );
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.failure {
                Err(GoogleTokenError::Upstream)
            } else {
                Ok(())
            }
        }
    }

    #[async_trait]
    impl OAuthCodeExchanger for BlockingRevokeExchanger {
        async fn exchange_code(
            &self,
            _: &str,
            _: &SecretString,
        ) -> Result<TokenSet, GoogleTokenError> {
            unreachable!()
        }

        async fn revoke(&self, _: &SecretString) -> Result<(), GoogleTokenError> {
            if let Some(user_id) = self.user_id {
                assert_eq!(
                    self.repository
                        .get_user(user_id)
                        .await
                        .unwrap()
                        .unwrap()
                        .status,
                    UserStatus::Revoking,
                    "the account must be locally revoked before a remote call"
                );
            }
            for connection_id in &self.connection_ids {
                assert_eq!(
                    self.repository
                        .get_connection(*connection_id)
                        .await
                        .unwrap()
                        .unwrap()
                        .status,
                    ConnectionStatus::Revoking,
                    "every affected connection must be locally revoked before a remote call"
                );
            }
            if self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                self.entered.notify_one();
                self.release.notified().await;
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn concurrent_connection_revoke_pressure_denies_local_access_before_remote_cleanup() {
        let (_, repository, user, connection, _, _) = key_fixture(UserRole::Member).await;
        let created = AccessKey::generate(user.id, "pressure-key", [connection.id]).unwrap();
        let credential = created.credential.clone();
        let key = repository.insert_access_key(&created).await.unwrap();
        let config = test_config();
        let envelope = EncryptedRefreshToken::from_envelope(
            encrypt_refresh_token(
                b"connection-pressure-refresh",
                &user.id.to_string(),
                &connection.id.to_string(),
                &config.encryption_keyring,
            )
            .unwrap(),
        )
        .unwrap();
        repository
            .update_refresh_token_envelope(connection.id, Some(&envelope))
            .await
            .unwrap();
        let exchanger = BlockingRevokeExchanger {
            repository: repository.clone(),
            user_id: None,
            connection_ids: vec![connection.id],
            calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            entered: Arc::new(tokio::sync::Notify::new()),
            release: Arc::new(tokio::sync::Notify::new()),
        };
        let state = ControlHttpState::new(
            config,
            repository.clone(),
            UnusedVerifier,
            exchanger.clone(),
            exchanger.clone(),
        )
        .unwrap();

        let entered = exchanger.entered.notified();
        let state_for_revoke = state.clone();
        let first = tokio::spawn(async move {
            revoke_connection_account(&state_for_revoke, user.id, connection.id).await
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), entered)
            .await
            .expect("remote revoke should be reached");

        let state_for_second_revoke = state.clone();
        let second = tokio::spawn(async move {
            revoke_connection_account(&state_for_second_revoke, user.id, connection.id).await
        });

        // The in-memory fixture deliberately uses one SQLite connection; keep
        // the pressure queue bounded so the test exercises overlap without
        // turning pool contention into a 30-second acquire timeout.
        let mut pressure = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let repository = repository.clone();
            let credential = credential.clone();
            pressure.spawn(async move {
                let key = repository
                    .authenticate_access_key(&credential)
                    .await
                    .unwrap()
                    .unwrap();
                assert!(!key.allows(connection.id));
                assert!(
                    repository
                        .list_active_connections_for_access_key(key.id, user.id)
                        .await
                        .unwrap()
                        .is_empty()
                );
            });
        }
        exchanger.release.notify_one();
        while let Some(result) = pressure.join_next().await {
            result.unwrap();
        }
        assert_eq!(first.await.unwrap().unwrap(), Some("revoked"));
        assert_eq!(second.await.unwrap().unwrap(), None);
        assert_eq!(exchanger.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(
            repository
                .get_connection(connection.id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            repository
                .list_active_connections_for_access_key(key.id, user.id)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn concurrent_account_revoke_pressure_invalidates_every_local_record_before_remote_cleanup()
     {
        let (_, repository, member, connection, session, _) = key_fixture(UserRole::Member).await;
        let owner = User::new(
            "pressure-owner",
            "pressure-owner@example.com",
            UserRole::Owner,
            Utc::now(),
        )
        .unwrap();
        repository.insert_user(&owner).await.unwrap();
        let second_connection = GmailConnection::new(
            member.id,
            "pressure-second-gmail",
            "second-pressure@example.com",
            vec![GMAIL_READONLY_SCOPE.into(), GMAIL_COMPOSE_SCOPE.into()],
        )
        .unwrap();
        repository
            .insert_connection(&second_connection, None)
            .await
            .unwrap();
        let created = AccessKey::generate(
            member.id,
            "account-pressure-key",
            [connection.id, second_connection.id],
        )
        .unwrap();
        let credential = created.credential.clone();
        let key = repository.insert_access_key(&created).await.unwrap();
        let config = test_config();
        for connection_id in [connection.id, second_connection.id] {
            let envelope = EncryptedRefreshToken::from_envelope(
                encrypt_refresh_token(
                    b"account-pressure-refresh",
                    &member.id.to_string(),
                    &connection_id.to_string(),
                    &config.encryption_keyring,
                )
                .unwrap(),
            )
            .unwrap();
            repository
                .update_refresh_token_envelope(connection_id, Some(&envelope))
                .await
                .unwrap();
        }
        let exchanger = BlockingRevokeExchanger {
            repository: repository.clone(),
            user_id: Some(member.id),
            connection_ids: vec![connection.id, second_connection.id],
            calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            entered: Arc::new(tokio::sync::Notify::new()),
            release: Arc::new(tokio::sync::Notify::new()),
        };
        let state = ControlHttpState::new(
            config,
            repository.clone(),
            UnusedVerifier,
            exchanger.clone(),
            exchanger.clone(),
        )
        .unwrap();

        let entered = exchanger.entered.notified();
        let state_for_revoke = state.clone();
        let first = tokio::spawn(async move {
            revoke_member_account(&state_for_revoke, owner.id, member.id).await
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), entered)
            .await
            .expect("remote revoke should be reached");

        let state_for_second_revoke = state.clone();
        let second = tokio::spawn(async move {
            revoke_member_account(&state_for_second_revoke, owner.id, member.id).await
        });

        // The in-memory fixture deliberately uses one SQLite connection; keep
        // the pressure queue bounded so the test exercises overlap without
        // turning pool contention into a 30-second acquire timeout.
        let mut pressure = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let repository = repository.clone();
            let credential = credential.clone();
            let session = session.clone();
            pressure.spawn(async move {
                assert!(
                    repository
                        .authenticate_access_key(&credential)
                        .await
                        .unwrap()
                        .is_none()
                );
                assert!(
                    repository
                        .lookup_web_session(&hash_token(&session), Utc::now())
                        .await
                        .unwrap()
                        .is_none()
                );
                assert!(
                    repository
                        .list_active_connections_for_access_key(key.id, member.id)
                        .await
                        .unwrap()
                        .is_empty()
                );
            });
        }
        exchanger.release.notify_one();
        while let Some(result) = pressure.join_next().await {
            result.unwrap();
        }
        let result = first.await.unwrap().unwrap().unwrap();
        assert_eq!(second.await.unwrap().unwrap(), None);
        assert_eq!(result.connections, 2);
        assert_eq!(result.remote_revoked, 2);
        assert_eq!(exchanger.calls.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert!(repository.get_user(member.id).await.unwrap().is_none());
        assert!(
            repository
                .get_connection(connection.id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            repository
                .get_connection(second_connection.id)
                .await
                .unwrap()
                .is_none()
        );
        for table in [
            "web_sessions",
            "access_keys",
            "access_key_grants",
            "send_confirmations",
            "oauth_transactions",
        ] {
            let remaining: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
                .fetch_one(repository.pool())
                .await
                .unwrap();
            assert_eq!(remaining, 0, "{table} must not retain account-scoped state");
        }
    }

    #[tokio::test]
    async fn connection_revoke_authentication_csrf_and_ownership_are_required() {
        let (app, repository, _, connection, session, csrf) = key_fixture(UserRole::Member).await;
        let uri = format!("/control/api/connections/{}/revoke", connection.id);
        for (session, csrf, expected) in [
            (None, Some(csrf.as_str()), StatusCode::UNAUTHORIZED),
            (Some(session.as_str()), None, StatusCode::BAD_REQUEST),
            (
                Some(session.as_str()),
                Some("wrong"),
                StatusCode::BAD_REQUEST,
            ),
        ] {
            assert_eq!(
                control_json(&app, Method::POST, uri.clone(), session, csrf, json!({}))
                    .await
                    .0,
                expected
            );
        }
        let foreign = User::new(
            "foreign",
            "foreign@example.com",
            UserRole::Member,
            Utc::now(),
        )
        .unwrap();
        repository.insert_user(&foreign).await.unwrap();
        let foreign_connection = GmailConnection::new(
            foreign.id,
            "foreign-gmail",
            "foreign@example.com",
            vec![GMAIL_READONLY_SCOPE.into(), GMAIL_COMPOSE_SCOPE.into()],
        )
        .unwrap();
        repository
            .insert_connection(&foreign_connection, None)
            .await
            .unwrap();
        assert_eq!(
            control_json(
                &app,
                Method::POST,
                format!("/control/api/connections/{}/revoke", foreign_connection.id),
                Some(&session),
                Some(&csrf),
                json!({})
            )
            .await
            .0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            repository
                .get_connection(connection.id)
                .await
                .unwrap()
                .unwrap()
                .status,
            ConnectionStatus::Active
        );
        assert!(
            repository
                .get_connection(foreign_connection.id)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn connection_reauthorize_authentication_csrf_and_ownership_are_required() {
        let (app, repository, _user, connection, session, csrf) =
            key_fixture(UserRole::Member).await;
        let uri = format!("/control/api/connections/{}/reauthorize", connection.id);
        for (session, csrf, expected) in [
            (None, Some(csrf.as_str()), StatusCode::UNAUTHORIZED),
            (Some(session.as_str()), None, StatusCode::BAD_REQUEST),
            (
                Some(session.as_str()),
                Some("wrong"),
                StatusCode::BAD_REQUEST,
            ),
        ] {
            assert_eq!(
                control_json(&app, Method::POST, uri.clone(), session, csrf, json!({}))
                    .await
                    .0,
                expected
            );
        }
        let foreign = User::new(
            "foreign",
            "foreign@example.com",
            UserRole::Member,
            Utc::now(),
        )
        .unwrap();
        repository.insert_user(&foreign).await.unwrap();
        let foreign_connection = GmailConnection::new(
            foreign.id,
            "foreign-gmail",
            "foreign@example.com",
            vec![GMAIL_READONLY_SCOPE.into(), GMAIL_COMPOSE_SCOPE.into()],
        )
        .unwrap();
        repository
            .insert_connection(&foreign_connection, None)
            .await
            .unwrap();
        let (status, _, body) = control_json(
            &app,
            Method::POST,
            format!(
                "/control/api/connections/{}/reauthorize",
                foreign_connection.id
            ),
            Some(&session),
            Some(&csrf),
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], "connection_not_found");
        let (status, _, body) = control_json(
            &app,
            Method::POST,
            format!("/control/api/connections/{}/reauthorize", Uuid::now_v7()),
            Some(&session),
            Some(&csrf),
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], "connection_not_found");
        assert_eq!(
            repository
                .get_connection(connection.id)
                .await
                .unwrap()
                .unwrap()
                .status,
            ConnectionStatus::Active
        );
        assert!(
            repository
                .get_connection(foreign_connection.id)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn connection_reauthorize_starts_gmail_flow_with_transaction_cookie() {
        let (app, repository, _user, connection, session, csrf) =
            key_fixture(UserRole::Member).await;
        let (status, headers, body) = control_json(
            &app,
            Method::POST,
            format!("/control/api/connections/{}/reauthorize", connection.id),
            Some(&session),
            Some(&csrf),
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
        assert_eq!(body["connection_id"], connection.id.to_string());
        let authorize_url = body["authorize_url"].as_str().unwrap();
        assert!(authorize_url.starts_with("https://accounts.google.com/"));
        assert!(authorize_url.contains("response_type=code"));
        let cookies = headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .collect::<Vec<_>>();
        assert!(
            cookies
                .iter()
                .any(|value| value.starts_with("__Host-agentmail_gmail_tx=")),
            "the Gmail transaction cookie must be set for the callback"
        );
        let stored: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM oauth_transactions")
            .fetch_one(repository.pool())
            .await
            .unwrap();
        assert_eq!(stored, 1);
        // An active connection stays untouched by starting reauthorization.
        assert_eq!(
            repository
                .get_connection(connection.id)
                .await
                .unwrap()
                .unwrap()
                .status,
            ConnectionStatus::Active
        );
    }

    #[tokio::test]
    async fn connection_reauthorize_rejects_revoking_connection() {
        let (app, repository, user, connection, session, csrf) =
            key_fixture(UserRole::Member).await;
        // Leave the connection in the revoking state without finishing the
        // revoke so the endpoint must refuse a new reauthorization flow.
        repository
            .begin_connection_revoke(user.id, connection.id)
            .await
            .unwrap()
            .expect("active connection must be claimable for revocation");
        assert_eq!(
            repository
                .get_connection(connection.id)
                .await
                .unwrap()
                .unwrap()
                .status,
            ConnectionStatus::Revoking
        );
        let (status, _, body) = control_json(
            &app,
            Method::POST,
            format!("/control/api/connections/{}/reauthorize", connection.id),
            Some(&session),
            Some(&csrf),
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["error"], "connection_revoking");
    }

    #[tokio::test]
    async fn connection_revoke_cuts_access_before_google_and_cleans_up_on_failure() {
        for failure in [false, true] {
            let (_, repository, user, connection, session, csrf) =
                key_fixture(UserRole::Member).await;
            let config = test_config();
            let envelope = EncryptedRefreshToken::from_envelope(
                encrypt_refresh_token(
                    b"synthetic-refresh",
                    &user.id.to_string(),
                    &connection.id.to_string(),
                    &config.encryption_keyring,
                )
                .unwrap(),
            )
            .unwrap();
            repository
                .update_refresh_token_envelope(connection.id, Some(&envelope))
                .await
                .unwrap();
            let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let exchanger = RevokeExchanger {
                repository: repository.clone(),
                connection_id: connection.id,
                calls: calls.clone(),
                failure,
            };
            let app = router(
                ControlHttpState::new(
                    config,
                    repository.clone(),
                    UnusedVerifier,
                    exchanger.clone(),
                    exchanger,
                )
                .unwrap(),
            );
            let (status, _, body) = control_json(
                &app,
                Method::POST,
                format!("/control/api/connections/{}/revoke", connection.id),
                Some(&session),
                Some(&csrf),
                json!({}),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body["local_revoked"], true);
            assert_eq!(
                body["remote_revocation"],
                if failure { "unconfirmed" } else { "revoked" }
            );
            assert_eq!(
                calls.load(std::sync::atomic::Ordering::SeqCst),
                if failure { 3 } else { 1 }
            );
            assert!(
                repository
                    .get_connection(connection.id)
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(!body.to_string().contains("synthetic-refresh"));
        }
    }

    #[tokio::test]
    async fn connection_revoke_deletes_local_connection_without_usable_credential() {
        for corrupt in [false, true] {
            let (app, repository, _, connection, session, csrf) =
                key_fixture(UserRole::Member).await;
            if corrupt {
                let envelope =
                    EncryptedRefreshToken::from_envelope("am1.999.invalid.invalid").unwrap();
                repository
                    .update_refresh_token_envelope(connection.id, Some(&envelope))
                    .await
                    .unwrap();
            }
            let (status, _, body) = control_json(
                &app,
                Method::POST,
                format!("/control/api/connections/{}/revoke", connection.id),
                Some(&session),
                Some(&csrf),
                json!({}),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(
                body["remote_revocation"],
                if corrupt {
                    "credential_unavailable"
                } else {
                    "not_available"
                }
            );
            assert!(
                repository
                    .get_connection(connection.id)
                    .await
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[tokio::test]
    async fn member_self_delete_clears_cookies_and_owner_cannot_self_delete() {
        for role in [UserRole::Member, UserRole::Owner] {
            let (app, repository, user, _connection, session, csrf) = key_fixture(role).await;
            let (status, headers, body) = control_json(
                &app,
                Method::POST,
                "/control/api/account/delete".to_owned(),
                Some(&session),
                Some(&csrf),
                json!({}),
            )
            .await;
            if role == UserRole::Member {
                assert_eq!(status, StatusCode::OK);
                assert_eq!(body["local_revoked"], true);
                assert!(repository.get_user(user.id).await.unwrap().is_none());
                let cookies = headers
                    .get_all(header::SET_COOKIE)
                    .iter()
                    .filter_map(|value| value.to_str().ok())
                    .collect::<Vec<_>>();
                assert!(
                    cookies
                        .iter()
                        .any(|value| value.starts_with("__Host-agentmail_session=;"))
                );
                assert!(
                    cookies
                        .iter()
                        .any(|value| value.starts_with("__Host-agentmail_csrf=;"))
                );
            } else {
                assert_eq!(status, StatusCode::FORBIDDEN);
                assert_eq!(body["error"], "owner_cannot_be_deleted");
                assert!(repository.get_user(user.id).await.unwrap().is_some());
            }
        }
    }

    #[tokio::test]
    async fn owner_may_revoke_member_but_member_cannot_revoke_another_member() {
        let (app, repository, owner, _connection, owner_session, owner_csrf) =
            key_fixture(UserRole::Owner).await;
        let member = User::new(
            "member-to-revoke",
            "member-to-revoke@example.com",
            UserRole::Member,
            Utc::now(),
        )
        .unwrap();
        repository.insert_user(&member).await.unwrap();
        let member_session = "member-revoke-session";
        let member_csrf = "member-revoke-csrf";
        let now = Utc::now();
        repository
            .insert_web_session(&NewWebSession {
                id: SessionId::new(),
                user_id: member.id,
                token_hash: hash_token(member_session),
                csrf_token_hash: hash_token(member_csrf),
                idle_expires_at: now + Duration::hours(1),
                absolute_expires_at: now + Duration::hours(1),
                created_at: now,
            })
            .await
            .unwrap();
        let target = User::new(
            "second-member",
            "second-member@example.com",
            UserRole::Member,
            Utc::now(),
        )
        .unwrap();
        repository.insert_user(&target).await.unwrap();
        let target_path = format!("/control/api/members/{}/revoke", target.id);
        assert_eq!(
            control_json(
                &app,
                Method::POST,
                target_path.clone(),
                Some(member_session),
                Some(member_csrf),
                json!({}),
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
        assert!(repository.get_user(target.id).await.unwrap().is_some());
        let (status, _, body) = control_json(
            &app,
            Method::POST,
            target_path,
            Some(&owner_session),
            Some(&owner_csrf),
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["local_revoked"], true);
        assert!(repository.get_user(target.id).await.unwrap().is_none());
        assert!(repository.get_user(owner.id).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn startup_recovery_finishes_interrupted_member_revocation() {
        let database = Database::connect("sqlite::memory:").await.unwrap();
        database.migrate().await.unwrap();
        let repository = Repository::new(&database);
        let member = User::new(
            "interrupted-member",
            "interrupted@example.com",
            UserRole::Member,
            Utc::now(),
        )
        .unwrap();
        repository.insert_user(&member).await.unwrap();
        let connection = GmailConnection::new(
            member.id,
            "interrupted-gmail",
            "interrupted.mail@example.com",
            vec![GMAIL_READONLY_SCOPE.into(), GMAIL_COMPOSE_SCOPE.into()],
        )
        .unwrap();
        repository
            .insert_connection(&connection, None)
            .await
            .unwrap();
        repository
            .begin_user_revoke(member.id, member.id)
            .await
            .unwrap()
            .unwrap();
        assert!(repository.get_user(member.id).await.unwrap().is_some());

        let state = ControlHttpState::new(
            test_config(),
            repository.clone(),
            UnusedVerifier,
            UnusedExchanger,
            UnusedExchanger,
        )
        .unwrap();
        assert_eq!(recover_pending_revocations(&state).await.unwrap(), 1);
        assert!(repository.get_user(member.id).await.unwrap().is_none());
        let owner = User::new(
            "recovery-owner",
            "owner@example.com",
            UserRole::Owner,
            Utc::now(),
        )
        .unwrap();
        repository.insert_user(&owner).await.unwrap();
        let owner_connection = GmailConnection::new(
            owner.id,
            "owner-recovery-gmail",
            "owner@example.com",
            vec![GMAIL_READONLY_SCOPE.into(), GMAIL_COMPOSE_SCOPE.into()],
        )
        .unwrap();
        repository
            .insert_connection(&owner_connection, None)
            .await
            .unwrap();
        repository
            .begin_connection_revoke(owner.id, owner_connection.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(recover_pending_revocations(&state).await.unwrap(), 1);
        assert!(
            repository
                .get_connection(owner_connection.id)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(recover_pending_revocations(&state).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn json_and_html_control_routers_merge_without_route_conflicts() {
        let database = Database::connect("sqlite::memory:").await.unwrap();
        database.migrate().await.unwrap();
        let state = ControlHttpState::new(
            test_config(),
            Repository::new(&database),
            UnusedVerifier,
            UnusedExchanger,
            UnusedExchanger,
        )
        .unwrap();
        let _combined = router(state.clone()).merge(crate::control_ui::router(state));
    }

    async fn key_fixture(
        role: UserRole,
    ) -> (Router, Repository, User, GmailConnection, String, String) {
        let database = Database::connect("sqlite::memory:").await.unwrap();
        database.migrate().await.unwrap();
        let repository = Repository::new(&database);
        let user = User::new("test-sub", "owner@example.com", role, Utc::now()).unwrap();
        repository.insert_user(&user).await.unwrap();
        let connection = GmailConnection::new(
            user.id,
            "gmail-sub",
            "owner@example.com",
            vec![GMAIL_READONLY_SCOPE.into(), GMAIL_COMPOSE_SCOPE.into()],
        )
        .unwrap();
        repository
            .insert_connection(&connection, None)
            .await
            .unwrap();
        let session_token = "control-test-session".to_owned();
        let csrf_token = "control-test-csrf".to_owned();
        let now = Utc::now();
        repository
            .insert_web_session(&NewWebSession {
                id: SessionId::new(),
                user_id: user.id,
                token_hash: hash_token(&session_token),
                csrf_token_hash: hash_token(&csrf_token),
                idle_expires_at: now + Duration::hours(1),
                absolute_expires_at: now + Duration::hours(1),
                created_at: now,
            })
            .await
            .unwrap();
        let state = ControlHttpState::new(
            test_config(),
            repository.clone(),
            UnusedVerifier,
            UnusedExchanger,
            UnusedExchanger,
        )
        .unwrap();
        (
            router(state),
            repository,
            user,
            connection,
            session_token,
            csrf_token,
        )
    }

    async fn control_json(
        app: &Router,
        method: Method,
        uri: String,
        session_token: Option<&str>,
        csrf_token: Option<&str>,
        body: Value,
    ) -> (StatusCode, HeaderMap, Value) {
        let mut request = Request::builder().method(method).uri(uri);
        if let Some(session_token) = session_token {
            request = request.header(
                header::COOKIE,
                format!("__Host-agentmail_session={session_token}"),
            );
        }
        if let Some(csrf_token) = csrf_token {
            request = request.header("x-csrf-token", csrf_token);
        }
        let response = app
            .clone()
            .oneshot(
                request
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        (status, headers, body)
    }

    #[test]
    fn host_headers_cannot_change_fixed_callback_url() {
        let base = url::Url::parse("https://agentmail.example").unwrap();
        let mut callback = base.clone();
        callback.set_path(LOGIN_CALLBACK_PATH);
        assert_eq!(
            callback.as_str(),
            "https://agentmail.example/auth/google/callback"
        );
        let mut forged = base;
        forged.set_host(Some("attacker.example")).unwrap();
        assert_ne!(forged.host_str(), callback.host_str());
        assert_eq!(callback.path(), LOGIN_CALLBACK_PATH);
        assert_eq!(GMAIL_CALLBACK_PATH, "/connections/google/callback");
    }

    #[test]
    fn session_cookie_uses_fixed_security_policy() {
        let cookie = session_cookie(&SessionCookiePolicy::default(), "session-token");
        assert_eq!(
            cookie,
            "__Host-agentmail_session=session-token; HttpOnly; Secure; SameSite=Lax; Path=/"
        );
    }

    #[test]
    fn malformed_or_missing_cookie_is_rejected() {
        let mut headers = HeaderMap::new();
        assert!(transaction_cookie_value(&headers, LOGIN_TRANSACTION_COOKIE).is_err());
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("agentmail_login_tx=nope"),
        );
        assert!(transaction_cookie_value(&headers, LOGIN_TRANSACTION_COOKIE).is_err());
    }

    #[tokio::test]
    async fn access_key_list_requires_owner_session_and_redacts_credentials() {
        let (app, repository, user, connection, session, _csrf) =
            key_fixture(UserRole::Owner).await;
        let created = AccessKey::generate(user.id, "listed", [connection.id]).unwrap();
        let credential = created.credential.clone();
        repository.insert_access_key(&created).await.unwrap();

        let (status, _, _) = control_json(
            &app,
            Method::GET,
            "/control/api/access-keys".to_owned(),
            None,
            None,
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let (status, _, listed) = control_json(
            &app,
            Method::GET,
            "/control/api/access-keys".to_owned(),
            Some(&session),
            None,
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(listed["access_keys"].as_array().unwrap().len(), 1);
        let rendered = listed.to_string();
        assert!(!rendered.contains(&credential));
        assert!(!rendered.contains("secret_hash"));
        assert!(
            repository
                .authenticate_access_key(&credential)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn access_key_routes_enforce_csrf_rotation_revocation_and_grants() {
        let (app, repository, _user, connection, session, csrf) =
            key_fixture(UserRole::Owner).await;
        let create_body = json!({"name":"managed","connection_ids":[]});
        let (status, _, _) = control_json(
            &app,
            Method::POST,
            "/control/api/access-keys".to_owned(),
            Some(&session),
            None,
            create_body.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _, _) = control_json(
            &app,
            Method::POST,
            "/control/api/access-keys".to_owned(),
            Some(&session),
            Some("wrong-csrf"),
            create_body.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let (status, headers, created) = control_json(
            &app,
            Method::POST,
            "/control/api/access-keys".to_owned(),
            Some(&session),
            Some(&csrf),
            create_body,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
        assert_eq!(created["credential_visible_once"], true);
        let key_id = created["access_key"]["id"].as_str().unwrap().to_owned();
        let credential = created["credential"].as_str().unwrap().to_owned();
        let stored_hash: String =
            sqlx::query_scalar("SELECT secret_hash FROM access_keys WHERE id=?")
                .bind(&key_id)
                .fetch_one(repository.pool())
                .await
                .unwrap();
        assert!(!stored_hash.contains(&credential));
        assert!(
            repository
                .authenticate_access_key(&credential)
                .await
                .unwrap()
                .is_some()
        );

        let grant_path = format!(
            "/control/api/access-keys/{key_id}/connections/{}",
            connection.id
        );
        let (status, _, _) = control_json(
            &app,
            Method::PUT,
            grant_path.clone(),
            Some(&session),
            Some(&csrf),
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let parsed_key = AccessKeyId::from_uuid(Uuid::parse_str(&key_id).unwrap());
        assert!(
            repository
                .access_key_allows(parsed_key, connection.id)
                .await
                .unwrap()
        );
        let (status, _, _) = control_json(
            &app,
            Method::DELETE,
            grant_path,
            Some(&session),
            Some(&csrf),
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(
            !repository
                .access_key_allows(parsed_key, connection.id)
                .await
                .unwrap()
        );

        let foreign = User::new(
            "member-sub",
            "member@example.com",
            UserRole::Member,
            Utc::now(),
        )
        .unwrap();
        repository.insert_user(&foreign).await.unwrap();
        let foreign_connection = GmailConnection::new(
            foreign.id,
            "foreign-gmail-sub",
            "member@example.com",
            vec![GMAIL_READONLY_SCOPE.into(), GMAIL_COMPOSE_SCOPE.into()],
        )
        .unwrap();
        repository
            .insert_connection(&foreign_connection, None)
            .await
            .unwrap();
        let foreign_key =
            AccessKey::generate(foreign.id, "foreign", [foreign_connection.id]).unwrap();
        let foreign_key = repository.insert_access_key(&foreign_key).await.unwrap();
        let foreign_grant_path = format!(
            "/control/api/access-keys/{key_id}/connections/{}",
            foreign_connection.id
        );
        let (status, _, _) = control_json(
            &app,
            Method::PUT,
            foreign_grant_path,
            Some(&session),
            Some(&csrf),
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _, _) = control_json(
            &app,
            Method::POST,
            format!("/control/api/access-keys/{}/rotate", foreign_key.id),
            Some(&session),
            Some(&csrf),
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, headers, rotated) = control_json(
            &app,
            Method::POST,
            format!("/control/api/access-keys/{key_id}/rotate"),
            Some(&session),
            Some(&csrf),
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
        let rotated_credential = rotated["credential"].as_str().unwrap();
        assert_ne!(rotated_credential, credential);
        assert!(
            repository
                .authenticate_access_key(&credential)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            repository
                .authenticate_access_key(rotated_credential)
                .await
                .unwrap()
                .is_some()
        );

        let (status, _, _) = control_json(
            &app,
            Method::POST,
            format!("/control/api/access-keys/{key_id}/revoke"),
            Some(&session),
            Some(&csrf),
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            repository
                .authenticate_access_key(rotated_credential)
                .await
                .unwrap()
                .is_none()
        );
        let (status, _, listed) = control_json(
            &app,
            Method::GET,
            "/control/api/access-keys".to_owned(),
            Some(&session),
            None,
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(!listed.to_string().contains(rotated_credential));
    }

    #[tokio::test]
    async fn control_mutations_audit_only_actor_outcome_and_request_metadata() {
        let (app, repository, user, _connection, session, csrf) =
            key_fixture(UserRole::Owner).await;
        let private_name = "must-not-enter-audit";
        let (status, _, created) = control_json(
            &app,
            Method::POST,
            "/control/api/access-keys".to_owned(),
            Some(&session),
            Some(&csrf),
            json!({"name": private_name, "connection_ids": []}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let credential = created["credential"].as_str().unwrap();

        let operation: String = sqlx::query_scalar(
            "SELECT operation FROM audit_events ORDER BY created_at DESC LIMIT 1",
        )
        .fetch_one(repository.pool())
        .await
        .unwrap();
        let result: String = sqlx::query_scalar(
            "SELECT result_category FROM audit_events ORDER BY created_at DESC LIMIT 1",
        )
        .fetch_one(repository.pool())
        .await
        .unwrap();
        let actor: String =
            sqlx::query_scalar("SELECT user_id FROM audit_events ORDER BY created_at DESC LIMIT 1")
                .fetch_one(repository.pool())
                .await
                .unwrap();
        let serialized: String = sqlx::query_scalar(
            "SELECT operation || ':' || result_category || ':' || request_id FROM audit_events ORDER BY created_at DESC LIMIT 1",
        )
        .fetch_one(repository.pool())
        .await
        .unwrap();
        assert_eq!(operation, "access_key.create");
        assert_eq!(result, "ok");
        assert_eq!(actor, user.id.to_string());
        assert!(!serialized.contains(private_name));
        assert!(!serialized.contains(credential));
    }

    #[test]
    fn control_audit_route_mapping_covers_mutations_and_oauth_callbacks() {
        assert_eq!(
            control_audit_operation(&Method::GET, LOGIN_CALLBACK_PATH),
            Some(AuditOperation::AuthLogin)
        );
        assert_eq!(
            control_audit_operation(&Method::GET, GMAIL_CALLBACK_PATH),
            Some(AuditOperation::AuthGmail)
        );
        assert_eq!(
            control_audit_operation(&Method::DELETE, "/control/api/access-keys/a/connections/b"),
            Some(AuditOperation::AccessKeyGrant)
        );
        assert_eq!(
            control_audit_operation(&Method::POST, "/control/api/members/a/revoke"),
            Some(AuditOperation::AccountRevoke)
        );
        assert_eq!(
            control_audit_operation(&Method::POST, "/control/api/connections/a/reauthorize"),
            Some(AuditOperation::ConnectionReauthorize)
        );
        assert_eq!(
            control_audit_operation(&Method::POST, "/control/api/connections/a/revoke"),
            Some(AuditOperation::ConnectionRevoke)
        );
        assert_eq!(
            control_audit_operation(&Method::GET, "/control/api/access-keys"),
            None
        );
    }

    #[tokio::test]
    async fn members_manage_own_access_keys_but_not_invitations() {
        let (app, repository, member, connection, session, csrf) =
            key_fixture(UserRole::Member).await;
        let (status, _, listed) = control_json(
            &app,
            Method::GET,
            "/control/api/access-keys".to_owned(),
            Some(&session),
            None,
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(listed["access_keys"], json!([]));
        let (status, headers, created) = control_json(
            &app,
            Method::POST,
            "/control/api/access-keys".to_owned(),
            Some(&session),
            Some(&csrf),
            json!({"name":"member-key","connection_ids":[connection.id]}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
        assert!(
            created["credential"]
                .as_str()
                .is_some_and(|value| value.starts_with("amk_"))
        );
        assert_eq!(
            repository.list_access_keys(member.id).await.unwrap().len(),
            1
        );
        let (status, _, _) = control_json(
            &app,
            Method::GET,
            "/control/api/invitations".to_owned(),
            Some(&session),
            None,
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn invitation_routes_enforce_owner_csrf_redaction_and_regeneration() {
        let (app, repository, _owner, _connection, session, csrf) =
            key_fixture(UserRole::Owner).await;
        let create = json!({"target_email":"member@example.com"});
        let (status, _, _) = control_json(
            &app,
            Method::POST,
            "/control/api/invitations".to_owned(),
            Some(&session),
            None,
            create.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, headers, created) = control_json(
            &app,
            Method::POST,
            "/control/api/invitations".to_owned(),
            Some(&session),
            Some(&csrf),
            create,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
        let token = created["token"].as_str().unwrap().to_owned();
        let invitation_id = created["invitation"]["id"].as_str().unwrap().to_owned();
        assert_eq!(created["credential_visible_once"], true);
        let token_hash: String = sqlx::query_scalar("SELECT token_hash FROM invitations")
            .fetch_one(repository.pool())
            .await
            .unwrap();
        assert_eq!(token_hash, hash_token(&token));
        assert!(!created.to_string().contains(&token_hash));

        let (status, _, listed) = control_json(
            &app,
            Method::GET,
            "/control/api/invitations".to_owned(),
            Some(&session),
            None,
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(!listed.to_string().contains(&token));
        assert!(!listed.to_string().contains(&token_hash));

        let (status, _, _) = control_json(
            &app,
            Method::POST,
            format!("/control/api/invitations/{invitation_id}/regenerate"),
            Some(&session),
            None,
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, headers, regenerated) = control_json(
            &app,
            Method::POST,
            format!("/control/api/invitations/{invitation_id}/regenerate"),
            Some(&session),
            Some(&csrf),
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
        assert_ne!(regenerated["token"].as_str().unwrap(), token);
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM invitations")
            .fetch_one(repository.pool())
            .await
            .unwrap();
        assert_eq!(count, 1);

        let (member_app, _, _, _, member_session, member_csrf) =
            key_fixture(UserRole::Member).await;
        let (status, _, _) = control_json(
            &member_app,
            Method::GET,
            "/control/api/invitations".to_owned(),
            Some(&member_session),
            None,
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _, _) = control_json(
            &member_app,
            Method::POST,
            "/control/api/invitations".to_owned(),
            Some(&member_session),
            Some(&member_csrf),
            json!({"target_email":"x@example.com"}),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn invitation_accept_start_binds_hash_and_never_leaks_token() {
        let (app, repository, _owner, _connection, _session, _csrf) =
            key_fixture(UserRole::Owner).await;
        let token = URL_SAFE_NO_PAD.encode([9_u8; 32]);
        let (status, headers, body) = control_json(
            &app,
            Method::POST,
            "/auth/invitations/accept".to_owned(),
            None,
            None,
            json!({"token": token}),
        )
        .await;
        assert_eq!(status, StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
        assert!(!headers[header::LOCATION].to_str().unwrap().contains(&token));
        assert!(
            !headers[header::SET_COOKIE]
                .to_str()
                .unwrap()
                .contains(&token)
        );
        assert!(body.is_null());
        let stored_hash: String =
            sqlx::query_scalar("SELECT invitation_token_hash FROM oauth_transactions")
                .fetch_one(repository.pool())
                .await
                .unwrap();
        assert_eq!(stored_hash, hash_token(&token));
        let (status, _, _) = control_json(
            &app,
            Method::POST,
            "/auth/invitations/accept".to_owned(),
            None,
            None,
            json!({"token":"not-a-token"}),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    fn login_claim(
        invitation_token_hash: Option<String>,
    ) -> crate::repository::OAuthTransactionClaim {
        crate::repository::OAuthTransactionClaim {
            id: Uuid::now_v7(),
            flow: OAuthFlowKind::Login,
            nonce_hash: hash_token("nonce"),
            pkce_verifier: crate::repository::EncryptedPkceVerifier::from_envelope(format!(
                "am1.1.{}.{}",
                URL_SAFE_NO_PAD.encode([0_u8; 24]),
                URL_SAFE_NO_PAD.encode([1_u8; 1]),
            ))
            .unwrap(),
            initiated_by: None,
            target_connection: None,
            invitation_token_hash,
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(10),
        }
    }

    #[tokio::test]
    async fn login_finish_redirects_by_role_and_invitation_replay_cannot_create_session() {
        let database = Database::connect("sqlite::memory:").await.unwrap();
        database.migrate().await.unwrap();
        let repository = Repository::new(&database);
        let now = Utc::now();
        let owner = User::new("owner-sub", "owner@example.com", UserRole::Owner, now).unwrap();
        let member = User::new("member-sub", "member@example.com", UserRole::Member, now).unwrap();
        repository.insert_user(&owner).await.unwrap();
        repository.insert_user(&member).await.unwrap();
        let state = ControlHttpState::new(
            test_config(),
            repository.clone(),
            UnusedVerifier,
            UnusedExchanger,
            UnusedExchanger,
        )
        .unwrap();
        let (response, cookie) = finish_login(
            &state,
            ValidatedOidcIdentity {
                subject: member.google_sub.clone(),
                email: "MEMBER@example.com".to_owned(),
            },
            login_claim(None),
            now,
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers()[header::LOCATION], "/control/account");
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert!(
            response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .filter_map(|value| value.to_str().ok())
                .any(|value| value.starts_with("__Host-agentmail_csrf="))
        );
        assert!(cookie.unwrap().contains("__Host-agentmail_session="));
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(body.is_empty());

        let (owner_response, owner_cookie) = finish_login(
            &state,
            ValidatedOidcIdentity {
                subject: owner.google_sub.clone(),
                email: owner.email.clone(),
            },
            login_claim(None),
            now,
        )
        .await
        .unwrap();
        assert_eq!(owner_response.status(), StatusCode::SEE_OTHER);
        assert_eq!(owner_response.headers()[header::LOCATION], "/control");
        assert!(owner_cookie.unwrap().contains("__Host-agentmail_session="));

        let invitation_token = "callback-invitation-token";
        repository
            .create_invitation(&crate::repository::NewInvitation {
                id: crate::domain::identity::InvitationId::new(),
                target_email: "invitee@example.com".to_owned(),
                token_hash: hash_token(invitation_token),
                invited_by: owner.id,
                expires_at: now + Duration::hours(1),
                created_at: now,
            })
            .await
            .unwrap();
        let invite_identity = ValidatedOidcIdentity {
            subject: "invitee-sub".to_owned(),
            email: "invitee@example.com".to_owned(),
        };
        finish_login(
            &state,
            invite_identity.clone(),
            login_claim(Some(hash_token(invitation_token))),
            now,
        )
        .await
        .unwrap();
        assert!(matches!(
            finish_login(
                &state,
                invite_identity,
                login_claim(Some(hash_token(invitation_token))),
                now,
            )
            .await,
            Err(ControlHttpError::ControlPlane(
                ControlPlaneError::InvitationNotClaimable
            ))
        ));
        let members: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE role='member'")
            .fetch_one(repository.pool())
            .await
            .unwrap();
        let sessions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM web_sessions")
            .fetch_one(repository.pool())
            .await
            .unwrap();
        assert_eq!((members, sessions), (2, 3));
    }

    #[tokio::test]
    async fn state_replay_is_rejected_by_repository_claim() {
        let database = Database::connect("sqlite::memory:").await.unwrap();
        database.migrate().await.unwrap();
        let repository = Repository::new(&database);
        let now = Utc::now();
        let flow = LoginFlow::new(
            &url::Url::parse("https://agentmail.example").unwrap(),
            "login-client",
            now,
        )
        .unwrap();
        let id = Uuid::now_v7();
        let envelope = flow
            .transaction()
            .encrypted_pkce_verifier(
                &id.to_string(),
                &crate::crypto::Keyring::parse(&format!(
                    "v1={}",
                    URL_SAFE_NO_PAD.encode([3_u8; 32])
                ))
                .unwrap(),
            )
            .unwrap();
        let envelope = crate::repository::EncryptedPkceVerifier::from_envelope(envelope).unwrap();
        repository
            .insert_oauth_transaction(id, &flow.transaction().persistence(), &envelope)
            .await
            .unwrap();
        assert!(
            repository
                .claim_oauth_transaction(id, flow.state(), now)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            repository
                .claim_oauth_transaction(id, flow.state(), now)
                .await
                .unwrap()
                .is_none()
        );
    }
}

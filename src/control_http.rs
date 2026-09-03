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
    middleware::Next,
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
    crypto::{CryptoError, encrypt_refresh_token, hash_token, verify_token},
    domain::{
        access::{AccessKey, AccessKeyId},
        identity::{
            ConnectionId, ConnectionStatus, GmailConnection, InvitationId, User, UserId, UserRole,
        },
    },
    google_oidc::{GoogleJwksVerifier, GoogleOidcError},
    google_token::{GoogleTokenClient, GoogleTokenError, TokenSet},
    invitations::InviteService,
    oauth::{
        GMAIL_CALLBACK_PATH, GOOGLE_ISSUER, GmailFlow, LOGIN_CALLBACK_PATH, LoginFlow, OAuthError,
        OAuthFlowKind, OidcClaims, ValidatedOidcIdentity, validate_granted_gmail_scopes,
        validate_oidc_claims,
    },
    repository::{EncryptedRefreshToken, Repository, RepositoryError, StoredAccessKey},
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
            "/control/invitations",
            get(list_invitations::<V, E>).post(create_invitation::<V, E>),
        )
        .route(
            "/control/invitations/{invitation_id}/revoke",
            post(revoke_invitation::<V, E>),
        )
        .route(
            "/control/invitations/{invitation_id}/regenerate",
            post(regenerate_invitation::<V, E>),
        )
        .route(
            "/control/access-keys",
            get(list_access_keys::<V, E>).post(create_access_key::<V, E>),
        )
        .route(
            "/control/access-keys/{key_id}/rotate",
            post(rotate_access_key::<V, E>),
        )
        .route(
            "/control/access-keys/{key_id}/revoke",
            post(revoke_access_key::<V, E>),
        )
        .route(
            "/control/access-keys/{key_id}/connections/{connection_id}",
            axum::routing::put(grant_access_key::<V, E>).delete(remove_access_key_grant::<V, E>),
        )
        .with_state(state)
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
    let owner = match require_owner_session(&state, &headers, false).await {
        Ok(owner) => owner,
        Err(response) => return response,
    };
    match state.repository.list_access_keys(owner.user_id).await {
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
    let owner = match require_owner_session(&state, &headers, true).await {
        Ok(owner) => owner,
        Err(response) => return response,
    };
    let connections = request
        .connection_ids
        .into_iter()
        .map(ConnectionId::from_uuid)
        .collect::<Vec<_>>();
    let created = match AccessKey::generate(owner.user_id, request.name, connections) {
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
    let owner = match require_owner_session(&state, &headers, true).await {
        Ok(owner) => owner,
        Err(response) => return response,
    };
    let key_id = AccessKeyId::from_uuid(key_id);
    match state
        .repository
        .rotate_access_key(owner.user_id, key_id)
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
    let owner = match require_owner_session(&state, &headers, true).await {
        Ok(owner) => owner,
        Err(response) => return response,
    };
    let key_id = AccessKeyId::from_uuid(key_id);
    let existing = match state.repository.get_access_key(owner.user_id, key_id).await {
        Ok(Some(key)) => key,
        Ok(None) => return control_api_error(StatusCode::NOT_FOUND, "not_found"),
        Err(error) => return error_response(error.into()),
    };
    if existing.status.accepts_requests()
        && let Err(error) = state
            .repository
            .revoke_access_key(owner.user_id, key_id)
            .await
    {
        return error_response(error.into());
    }
    match state.repository.get_access_key(owner.user_id, key_id).await {
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
    let owner = match require_owner_session(state, headers, true).await {
        Ok(owner) => owner,
        Err(response) => return response,
    };
    let key_id = AccessKeyId::from_uuid(key_id);
    match state.repository.get_access_key(owner.user_id, key_id).await {
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
        Err(error) => return error_response(error.into()),
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
        Err(_) => return error_response(ControlHttpError::OidcVerification),
    };
    let identity = match validate_verified_claims(
        &claims,
        &claim.nonce_hash,
        expected_client_id(&state, expected_flow),
        Utc::now(),
    ) {
        Ok(identity) => identity,
        Err(error) => return error_response(error),
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
        Err(error) => error_response(error),
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
    let mut response = (
        StatusCode::OK,
        Json(json!({
            "user_id": credentials.user.id,
            "email": credentials.user.email,
            "role": credentials.user.role,
            "csrf_token": credentials.csrf_token,
        })),
    )
        .into_response();
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

    let connection = if let Some(connection_id) = claim.target_connection {
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

    Ok((
        (
            StatusCode::OK,
            Json(json!({
                "connection_id": connection.id,
                "email": connection.email,
            })),
        )
            .into_response(),
        None,
    ))
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
            identity::{GMAIL_COMPOSE_SCOPE, GMAIL_READONLY_SCOPE, SessionId, User, UserRole},
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
            "/control/access-keys".to_owned(),
            None,
            None,
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let (status, _, listed) = control_json(
            &app,
            Method::GET,
            "/control/access-keys".to_owned(),
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
            "/control/access-keys".to_owned(),
            Some(&session),
            None,
            create_body.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _, _) = control_json(
            &app,
            Method::POST,
            "/control/access-keys".to_owned(),
            Some(&session),
            Some("wrong-csrf"),
            create_body.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let (status, headers, created) = control_json(
            &app,
            Method::POST,
            "/control/access-keys".to_owned(),
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
            "/control/access-keys/{key_id}/connections/{}",
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
            "/control/access-keys/{key_id}/connections/{}",
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
            format!("/control/access-keys/{}/rotate", foreign_key.id),
            Some(&session),
            Some(&csrf),
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, headers, rotated) = control_json(
            &app,
            Method::POST,
            format!("/control/access-keys/{key_id}/rotate"),
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
            format!("/control/access-keys/{key_id}/revoke"),
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
            "/control/access-keys".to_owned(),
            Some(&session),
            None,
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(!listed.to_string().contains(rotated_credential));
    }

    #[tokio::test]
    async fn access_key_routes_reject_member_session() {
        let (app, _, _, _, session, csrf) = key_fixture(UserRole::Member).await;
        let (status, _, _) = control_json(
            &app,
            Method::GET,
            "/control/access-keys".to_owned(),
            Some(&session),
            None,
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _, _) = control_json(
            &app,
            Method::POST,
            "/control/access-keys".to_owned(),
            Some(&session),
            Some(&csrf),
            json!({"name":"member-key"}),
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
            "/control/invitations".to_owned(),
            Some(&session),
            None,
            create.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, headers, created) = control_json(
            &app,
            Method::POST,
            "/control/invitations".to_owned(),
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
            "/control/invitations".to_owned(),
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
            format!("/control/invitations/{invitation_id}/regenerate"),
            Some(&session),
            None,
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, headers, regenerated) = control_json(
            &app,
            Method::POST,
            format!("/control/invitations/{invitation_id}/regenerate"),
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
            "/control/invitations".to_owned(),
            Some(&member_session),
            None,
            Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _, _) = control_json(
            &member_app,
            Method::POST,
            "/control/invitations".to_owned(),
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
    async fn login_finish_sets_member_cookie_and_invitation_replay_cannot_create_session() {
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
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert!(cookie.unwrap().contains("__Host-agentmail_session="));
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap()["role"],
            "member"
        );

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
        assert_eq!((members, sessions), (2, 2));
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

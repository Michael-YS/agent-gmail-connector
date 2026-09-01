//! Axum control-plane HTTP seam.
//!
//! This module is deliberately independent from the application's main router:
//! the main binary supplies the verified OIDC adapter and token exchanger,
//! then nests [`router`] under its public router. Request `Host` and forwarded
//! headers are never used to construct OAuth URLs.

use async_trait::async_trait;
use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, Request, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
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
    domain::identity::{ConnectionId, ConnectionStatus, GmailConnection, UserId},
    google_oidc::{GoogleJwksVerifier, GoogleOidcError},
    google_token::{GoogleTokenClient, GoogleTokenError, TokenSet},
    oauth::{
        GMAIL_CALLBACK_PATH, GOOGLE_ISSUER, GmailFlow, LOGIN_CALLBACK_PATH, LoginFlow, OAuthError,
        OAuthFlowKind, OidcClaims, ValidatedOidcIdentity, validate_granted_gmail_scopes,
        validate_oidc_claims,
    },
    repository::{EncryptedRefreshToken, Repository, RepositoryError},
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
        .route(LOGIN_CALLBACK_PATH, get(login_callback::<V, E>))
        .route(GMAIL_CALLBACK_PATH, get(gmail_callback::<V, E>))
        .route("/auth/google/gmail", post(gmail_start::<V, E>))
        .route("/auth/logout", post(logout::<V, E>))
        .with_state(state)
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
        OAuthFlowKind::Login => finish_login(&state, identity, Utc::now()).await,
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
    now: DateTime<Utc>,
) -> Result<(Response, Option<String>), ControlHttpError>
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let credentials = state
        .control_plane
        .bootstrap_owner_session(&identity, now)
        .await?;
    let mut response = (
        StatusCode::OK,
        Json(json!({
            "user_id": credentials.user.id,
            "email": credentials.user.email,
            "role": "owner",
            "csrf_token": credentials.csrf_token,
        })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
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

fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
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
    let status = match error {
        ControlHttpError::ControlPlane(ControlPlaneError::Unauthenticated)
        | ControlHttpError::InvalidTransactionCookie => StatusCode::UNAUTHORIZED,
        ControlHttpError::OAuth(_)
        | ControlHttpError::GoogleToken(_)
        | ControlHttpError::Crypto(_)
        | ControlHttpError::Repository(_)
        | ControlHttpError::ControlPlane(_)
        | ControlHttpError::InvalidRequest
        | ControlHttpError::OidcVerification
        | ControlHttpError::MissingIdToken
        | ControlHttpError::NonceMismatch => StatusCode::BAD_REQUEST,
    };
    (status, Json(json!({"error":"authentication failed"}))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::Database;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

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

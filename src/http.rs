//! HTTP transport and command entrypoints.
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, Request, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::Utc;
use clap::Subcommand;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Weak},
    time::Instant,
};
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

use crate::{
    adapter::{AdapterError, FakeGmailAdapter, GmailAdapter, MailDraft},
    config::AppConfig,
    control_http::ControlHttpState,
    database::{Database, DatabaseError},
    domain::{
        access::{AccessKey, KeyPublicId, parse_credential},
        delivery::{DraftVersion, ManagedDraft, SendConfirmation, SendOutcome, SendPreview},
        identity::{ConnectionId, GmailConnection, User, UserId, UserRole},
        mailbox::{EmailAddress, Recipients, sanitize_filename},
    },
    gmail_credentials::GmailCredentialProvider,
    google_gmail::GoogleGmailClient,
    google_oidc::GoogleJwksVerifier,
    google_token::GoogleTokenClient,
    governance::{
        AuditContext, AuditEvent, AuditOperation, AuditResult, ChargeReceipt, LimitKind,
        RateBucket, RateLimitExceeded, RequestId,
    },
    live_gmail_adapter::LiveGmailAdapter,
    mailbox_service::{MailboxReadError, MailboxReadService, MessageSearchResult},
    mime::{ReplyHeaders, ReplyKind, reply_recipients},
    repository::{DurableRateCharge, DurableSendClaim, RateChargeError, Repository},
};

#[derive(Debug, Clone, Subcommand)]
pub enum Command {
    Serve,
    Migrate {
        #[command(subcommand)]
        command: Option<MigrateCommand>,
    },
    Database {
        #[command(subcommand)]
        command: DatabaseCommand,
    },
}
#[derive(Debug, Clone, Subcommand)]
pub enum MigrateCommand {
    Status,
}
#[derive(Debug, Clone, Subcommand)]
pub enum DatabaseCommand {
    Backup { target: PathBuf },
}

#[derive(Clone)]
pub struct AppState {
    pub database: Option<Database>,
    pub repository: Option<Repository>,
    pub adapter: Arc<dyn GmailAdapter>,
    pub mailbox_service: MailboxReadService,
    pub users: Arc<RwLock<HashMap<UserId, User>>>,
    pub connections: Arc<RwLock<HashMap<ConnectionId, GmailConnection>>>,
    pub keys: Arc<RwLock<HashMap<KeyPublicId, AccessKey>>>,
    pub drafts: Arc<RwLock<HashMap<crate::domain::delivery::DraftId, ManagedDraft>>>,
    pub draft_locks: Arc<RwLock<HashMap<crate::domain::delivery::DraftId, Weak<Mutex<()>>>>>,
    pub confirmations:
        Arc<RwLock<HashMap<crate::domain::delivery::ConfirmationId, SendConfirmation>>>,
    pub pending_tokens: Arc<RwLock<HashMap<String, crate::domain::delivery::ConfirmationId>>>,
    pub rate_buckets: Arc<Mutex<HashMap<String, RateBucket>>>,
}
impl AppState {
    pub fn new(database: Option<Database>, adapter: Arc<dyn GmailAdapter>) -> Self {
        let repository = database.as_ref().map(Repository::new);
        let mailbox_service = MailboxReadService::new(adapter.clone());
        Self {
            database,
            repository,
            adapter,
            mailbox_service,
            users: Arc::new(RwLock::new(HashMap::new())),
            connections: Arc::new(RwLock::new(HashMap::new())),
            keys: Arc::new(RwLock::new(HashMap::new())),
            drafts: Arc::new(RwLock::new(HashMap::new())),
            draft_locks: Arc::new(RwLock::new(HashMap::new())),
            confirmations: Arc::new(RwLock::new(HashMap::new())),
            pending_tokens: Arc::new(RwLock::new(HashMap::new())),
            rate_buckets: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    pub fn empty() -> Self {
        Self::new(None, Arc::new(FakeGmailAdapter::new()))
    }
    pub fn test_fixture() -> (Self, String, ConnectionId) {
        let (state, credential, connection, _) = Self::test_fixture_with_adapter();
        (state, credential, connection)
    }
    fn test_fixture_with_adapter() -> (Self, String, ConnectionId, Arc<FakeGmailAdapter>) {
        let user = User::new("test-sub", "test@example.com", UserRole::Owner, Utc::now())
            .expect("fixture");
        let uid = user.id;
        let conn = GmailConnection::new(
            uid,
            "gmail-sub",
            "gmail@example.com",
            vec![
                crate::domain::identity::GMAIL_READONLY_SCOPE.into(),
                crate::domain::identity::GMAIL_COMPOSE_SCOPE.into(),
            ],
        )
        .expect("fixture");
        let cid = conn.id;
        let created = AccessKey::generate(uid, "test-key", [cid]).expect("fixture");
        let credential = created.credential.clone();
        let adapter = Arc::new(FakeGmailAdapter::new());
        let state = Self {
            database: None,
            repository: None,
            adapter: adapter.clone(),
            mailbox_service: MailboxReadService::new(adapter.clone()),
            users: Arc::new(RwLock::new(HashMap::from([(uid, user)]))),
            connections: Arc::new(RwLock::new(HashMap::from([(cid, conn)]))),
            keys: Arc::new(RwLock::new(HashMap::from([(
                created.key.public_id,
                created.key,
            )]))),
            drafts: Arc::new(RwLock::new(HashMap::new())),
            draft_locks: Arc::new(RwLock::new(HashMap::new())),
            confirmations: Arc::new(RwLock::new(HashMap::new())),
            pending_tokens: Arc::new(RwLock::new(HashMap::new())),
            rate_buckets: Arc::new(Mutex::new(HashMap::new())),
        };
        (state, credential, cid, adapter)
    }
}
#[derive(Clone, Copy)]
struct AuthContext {
    key: AccessKeyId,
    user: UserId,
    generation: u64,
}

#[derive(Debug)]
enum RateReservation {
    Persistent(Vec<DurableRateCharge>),
    Memory(Vec<(String, ChargeReceipt)>),
}
use crate::domain::access::AccessKeyId;

fn request_id(headers: &HeaderMap) -> String {
    headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unavailable")
        .to_owned()
}
fn error_response(
    status: StatusCode,
    code: &'static str,
    message: &'static str,
    headers: &HeaderMap,
) -> Response {
    let mut response = (status, Json(json!({"error":{"code":code,"message":message,"request_id":request_id(headers),"retryable": status == StatusCode::TOO_MANY_REQUESTS || status == StatusCode::SERVICE_UNAVAILABLE}}))).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

fn rate_limit_response(error: RateLimitExceeded, headers: &HeaderMap) -> Response {
    let mut response = (
        StatusCode::TOO_MANY_REQUESTS,
        Json(json!({"error":{
            "code":"rate_limited",
            "message":"rate limit exceeded",
            "request_id":request_id(headers),
            "retryable":true,
            "retry_after_seconds":error.retry_after_seconds
        }})),
    )
        .into_response();
    response.headers_mut().insert(
        header::RETRY_AFTER,
        HeaderValue::from_str(&error.retry_after_seconds.to_string())
            .expect("retry seconds are a valid header"),
    );
    response
}

async fn reserve_limits(
    state: &AppState,
    headers: &HeaderMap,
    limits: &[(String, LimitKind)],
    now: chrono::DateTime<Utc>,
) -> Result<RateReservation, Response> {
    if let Some(repository) = &state.repository {
        return match repository.charge_rate_limits(limits, now).await {
            Ok(charges) => Ok(RateReservation::Persistent(charges)),
            Err(RateChargeError::Exceeded(error)) => Err(rate_limit_response(error, headers)),
            Err(RateChargeError::Repository(_)) => Err(error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "service_unavailable",
                "service temporarily unavailable",
                headers,
            )),
        };
    }
    let mut buckets = state.rate_buckets.lock().await;
    let mut charges: Vec<(String, ChargeReceipt)> = Vec::with_capacity(limits.len());
    for (subject, kind) in limits {
        let bucket_key = format!("{}:{subject}", kind.as_str());
        let bucket = buckets
            .entry(bucket_key.clone())
            .or_insert_with(|| RateBucket::new(&bucket_key, *kind, now));
        match bucket.charge(now) {
            Ok(receipt) => charges.push((bucket_key, receipt)),
            Err(error) => {
                for (key, mut receipt) in charges {
                    if let Some(bucket) = buckets.get_mut(&key) {
                        bucket.refund(&mut receipt, now);
                    }
                }
                return Err(rate_limit_response(error, headers));
            }
        }
    }
    Ok(RateReservation::Memory(charges))
}

async fn refund_limits(
    state: &AppState,
    headers: &HeaderMap,
    reservation: RateReservation,
    now: chrono::DateTime<Utc>,
) -> Result<(), Response> {
    match reservation {
        RateReservation::Persistent(charges) => state
            .repository
            .as_ref()
            .expect("persistent rate reservation requires repository")
            .refund_rate_limits(charges, now)
            .await
            .map(|_| ())
            .map_err(|_| {
                error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "service_unavailable",
                    "service temporarily unavailable",
                    headers,
                )
            }),
        RateReservation::Memory(charges) => {
            let mut buckets = state.rate_buckets.lock().await;
            for (key, mut receipt) in charges {
                if let Some(bucket) = buckets.get_mut(&key) {
                    bucket.refund(&mut receipt, now);
                }
            }
            Ok(())
        }
    }
}

fn audit_result(status: StatusCode) -> AuditResult {
    match status {
        StatusCode::UNAUTHORIZED => AuditResult::Unauthorized,
        StatusCode::FORBIDDEN => AuditResult::Forbidden,
        StatusCode::NOT_FOUND => AuditResult::NotFound,
        StatusCode::CONFLICT => AuditResult::Conflict,
        StatusCode::TOO_MANY_REQUESTS => AuditResult::RateLimited,
        StatusCode::SERVICE_UNAVAILABLE | StatusCode::GATEWAY_TIMEOUT => AuditResult::Unavailable,
        status if status.is_success() => AuditResult::Ok,
        _ => AuditResult::Error,
    }
}

async fn audit_response(
    state: &AppState,
    headers: &HeaderMap,
    context: AuthContext,
    connection_id: Option<ConnectionId>,
    operation: AuditOperation,
    started: Instant,
    response: Response,
) -> Response {
    if let Some(repository) = &state.repository {
        let request_id = RequestId::try_from(request_id(headers))
            .unwrap_or_else(|_| RequestId::try_from("unavailable").expect("fixed request id"));
        let event = AuditEvent::metadata(
            AuditContext {
                user_id: Some(context.user),
                access_key_id: Some(context.key),
                connection_id,
            },
            operation,
            audit_result(response.status()),
            u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            request_id,
            Utc::now(),
        );
        if let Err(error) = repository.record_audit_event(&event).await {
            tracing::warn!(error = %error, operation = operation.as_str(), "audit write failed");
        }
    }
    response
}

async fn auth(
    headers: &HeaderMap,
    query: Option<&str>,
    state: &AppState,
) -> Result<AuthContext, Response> {
    if query.is_some_and(|q| {
        q.split('&').any(|p| {
            matches!(
                p.split('=').next().unwrap_or(""),
                "token" | "access_token" | "api_key" | "authorization"
            )
        })
    }) {
        return Err(error_response(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "authentication required",
            headers,
        ));
    }
    let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    else {
        return Err(error_response(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "authentication required",
            headers,
        ));
    };
    let Some(credential) = value.strip_prefix("Bearer ") else {
        return Err(error_response(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "authentication required",
            headers,
        ));
    };
    let parsed = parse_credential(credential).map_err(|_| {
        error_response(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "authentication required",
            headers,
        )
    })?;
    if let Some(repository) = &state.repository {
        let key = repository
            .authenticate_access_key(credential)
            .await
            .map_err(|_| {
                error_response(
                    StatusCode::UNAUTHORIZED,
                    "unauthorized",
                    "authentication required",
                    headers,
                )
            })?
            .ok_or_else(|| {
                error_response(
                    StatusCode::UNAUTHORIZED,
                    "unauthorized",
                    "authentication required",
                    headers,
                )
            })?;
        let context = AuthContext {
            key: key.id,
            user: key.owner_id,
            generation: key.generation,
        };
        reserve_limits(
            state,
            headers,
            &[(context.key.to_string(), LimitKind::ApiPerMinute)],
            Utc::now(),
        )
        .await?;
        return Ok(context);
    }
    let keys = state.keys.read().await;
    let key = keys.get(&parsed.public_id).ok_or_else(|| {
        error_response(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "authentication required",
            headers,
        )
    })?;
    let valid = key.verify_credential(credential).map_err(|_| {
        error_response(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "authentication required",
            headers,
        )
    })?;
    if !valid {
        return Err(error_response(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "authentication required",
            headers,
        ));
    }
    let context = AuthContext {
        key: key.id,
        user: key.owner_id,
        generation: key.generation,
    };
    drop(keys);
    reserve_limits(
        state,
        headers,
        &[(context.key.to_string(), LimitKind::ApiPerMinute)],
        Utc::now(),
    )
    .await?;
    Ok(context)
}
async fn authorize(
    headers: &HeaderMap,
    query: Option<&str>,
    state: &AppState,
    connection: ConnectionId,
) -> Result<AuthContext, Response> {
    let ctx = auth(headers, query, state).await?;
    authorize_context(headers, state, connection, ctx).await
}

async fn authorize_context(
    headers: &HeaderMap,
    state: &AppState,
    connection: ConnectionId,
    ctx: AuthContext,
) -> Result<AuthContext, Response> {
    if let Some(repository) = &state.repository {
        let user = repository.get_user(ctx.user).await.map_err(|_| {
            error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "service_unavailable",
                "service temporarily unavailable",
                headers,
            )
        })?;
        if !user.is_some_and(|u| u.status.accepts_requests()) {
            return Err(error_response(
                StatusCode::FORBIDDEN,
                "forbidden",
                "access denied",
                headers,
            ));
        }
        let connection_record = repository.get_connection(connection).await.map_err(|_| {
            error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "service_unavailable",
                "service temporarily unavailable",
                headers,
            )
        })?;
        let Some(connection_record) = connection_record else {
            return Err(error_response(
                StatusCode::FORBIDDEN,
                "forbidden",
                "access denied",
                headers,
            ));
        };
        if connection_record.owner_id != ctx.user
            || !connection_record.status.accepts_requests()
            || !repository
                .access_key_allows(ctx.key, connection)
                .await
                .map_err(|_| {
                    error_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "service_unavailable",
                        "service temporarily unavailable",
                        headers,
                    )
                })?
        {
            return Err(error_response(
                StatusCode::FORBIDDEN,
                "forbidden",
                "access denied",
                headers,
            ));
        }
        return Ok(ctx);
    }
    let users = state.users.read().await;
    if !users
        .get(&ctx.user)
        .is_some_and(|u| u.status.accepts_requests())
    {
        return Err(error_response(
            StatusCode::FORBIDDEN,
            "forbidden",
            "access denied",
            headers,
        ));
    }
    let conns = state.connections.read().await;
    let conn = conns.get(&connection).ok_or_else(|| {
        error_response(StatusCode::FORBIDDEN, "forbidden", "access denied", headers)
    })?;
    if conn.owner_id != ctx.user || !conn.status.accepts_requests() {
        return Err(error_response(
            StatusCode::FORBIDDEN,
            "forbidden",
            "access denied",
            headers,
        ));
    }
    drop(conns);
    let keys = state.keys.read().await;
    if !keys
        .get(&key_public_for(ctx.key, &keys))
        .is_some_and(|k| k.allows(connection))
    {
        // AccessKeyId is intentionally opaque; find it by stable internal id.
        if !keys
            .values()
            .any(|k| k.id == ctx.key && k.allows(connection))
        {
            return Err(error_response(
                StatusCode::FORBIDDEN,
                "forbidden",
                "access denied",
                headers,
            ));
        }
    }
    Ok(ctx)
}
fn key_public_for(id: AccessKeyId, keys: &HashMap<KeyPublicId, AccessKey>) -> KeyPublicId {
    keys.values()
        .find(|k| k.id == id)
        .map(|k| k.public_id)
        .unwrap_or_else(KeyPublicId::new)
}

#[derive(Deserialize, Default)]
struct ListQuery {
    q: Option<String>,
    page_size: Option<usize>,
    cursor: Option<String>,
}
#[derive(Deserialize, Default)]
struct MessageReadQuery {
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    chunk_bytes: Option<usize>,
}

fn wants_html(query: &MessageReadQuery) -> Result<bool, &'static str> {
    match query.format.as_deref().unwrap_or("text") {
        "text" => Ok(false),
        "html" => Ok(true),
        _ => Err("format must be text or html"),
    }
}
#[derive(Serialize)]
struct ConnectionView {
    connection_id: ConnectionId,
    email: String,
    status: String,
    granted_scopes: Vec<String>,
}
fn view_connection(c: &GmailConnection) -> ConnectionView {
    ConnectionView {
        connection_id: c.id,
        email: c.email.clone(),
        status: format!("{:?}", c.status).to_ascii_lowercase(),
        granted_scopes: c.granted_scopes.clone(),
    }
}

async fn list_connections(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: axum::http::Uri,
) -> Response {
    let ctx = match auth(&headers, uri.query(), &state).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Some(repository) = &state.repository {
        let user = match repository.get_user(ctx.user).await {
            Ok(Some(user)) if user.status.accepts_requests() => user,
            Ok(_) => {
                return error_response(
                    StatusCode::FORBIDDEN,
                    "forbidden",
                    "access denied",
                    &headers,
                );
            }
            Err(_) => {
                return error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "service_unavailable",
                    "service temporarily unavailable",
                    &headers,
                );
            }
        };
        let connections = match repository
            .list_active_connections_for_access_key(ctx.key, user.id)
            .await
        {
            Ok(connections) => connections,
            Err(_) => {
                return error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "service_unavailable",
                    "service temporarily unavailable",
                    &headers,
                );
            }
        };
        return ok_json(
            json!({"connections":connections.iter().map(view_connection).collect::<Vec<_>>() }),
            &headers,
        );
    }
    let keys = state.keys.read().await;
    let allowed: Vec<_> = keys
        .values()
        .find(|k| k.id == ctx.key)
        .map(|k| k.grants.iter().copied().collect())
        .unwrap_or_default();
    let conns = state.connections.read().await;
    let result: Vec<_> = allowed
        .iter()
        .filter_map(|id| conns.get(id))
        .filter(|c| c.owner_id == ctx.user && c.status.accepts_requests())
        .map(view_connection)
        .collect();
    ok_json(json!({"connections":result}), &headers)
}
async fn list_messages(
    Path(cid): Path<Uuid>,
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Query(q): Query<ListQuery>,
) -> Response {
    let started = Instant::now();
    let cid = ConnectionId::from_uuid(cid);
    let context = match authorize(&headers, uri.query(), &state, cid).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let response = match state
        .mailbox_service
        .search(cid, q.q.as_deref(), q.page_size, q.cursor.as_deref())
        .await
    {
        Ok(MessageSearchResult {
            messages,
            next_cursor,
        }) => ok_json(
            json!({
                "connection_id": cid,
                "messages": messages,
                "next_cursor": next_cursor
            }),
            &headers,
        ),
        Err(MailboxReadError::Adapter(error)) => adapter_response(error, &headers),
        Err(MailboxReadError::InvalidCursor) => error_response(
            StatusCode::BAD_REQUEST,
            "invalid_cursor",
            "cursor is invalid",
            &headers,
        ),
    };
    audit_response(
        &state,
        &headers,
        context,
        Some(cid),
        AuditOperation::MessagesSearch,
        started,
        response,
    )
    .await
}
async fn get_message(
    Path((cid, mid)): Path<(Uuid, String)>,
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Query(query): Query<MessageReadQuery>,
) -> Response {
    let cid = ConnectionId::from_uuid(cid);
    if authorize(&headers, uri.query(), &state, cid).await.is_err() {
        return error_response(
            StatusCode::FORBIDDEN,
            "forbidden",
            "access denied",
            &headers,
        );
    }
    let html = match wants_html(&query) {
        Ok(value) => value,
        Err(message) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                message,
                &headers,
            );
        }
    };
    match state
        .mailbox_service
        .get_message(cid, &mid, html, query.cursor.as_deref(), query.chunk_bytes)
        .await
    {
        Ok(m) => ok_json(
            json!({"connection_id":cid,"message":m,"untrusted_email_content":true}),
            &headers,
        ),
        Err(MailboxReadError::Adapter(error)) => adapter_response(error, &headers),
        Err(MailboxReadError::InvalidCursor) => error_response(
            StatusCode::BAD_REQUEST,
            "invalid_cursor",
            "cursor is invalid",
            &headers,
        ),
    }
}
async fn list_drafts(
    Path(cid): Path<Uuid>,
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: axum::http::Uri,
) -> Response {
    let cid = ConnectionId::from_uuid(cid);
    if authorize(&headers, uri.query(), &state, cid).await.is_err() {
        return error_response(
            StatusCode::FORBIDDEN,
            "forbidden",
            "access denied",
            &headers,
        );
    }
    match state.adapter.list_drafts(cid).await {
        Ok(v) => {
            let mut views = Vec::with_capacity(v.len());
            for draft in v {
                let managed = managed_draft_for_gmail(&state, cid, &draft.id).await;
                views.push(json!({
                    "draft": draft,
                    "managed_by_agentmail": managed.is_some(),
                    "version": managed.map(|managed| managed.version),
                }));
            }
            ok_json(json!({"connection_id":cid,"drafts":views}), &headers)
        }
        Err(e) => adapter_response(e, &headers),
    }
}
async fn get_draft(
    Path((cid, did)): Path<(Uuid, String)>,
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: axum::http::Uri,
) -> Response {
    let cid = ConnectionId::from_uuid(cid);
    if authorize(&headers, uri.query(), &state, cid).await.is_err() {
        return error_response(
            StatusCode::FORBIDDEN,
            "forbidden",
            "access denied",
            &headers,
        );
    }
    match state.adapter.get_draft(cid, &did).await {
        Ok(v) => {
            let managed = managed_draft_for_gmail(&state, cid, &v.id).await;
            ok_json(
                json!({
                    "connection_id":cid,
                    "draft":v,
                    "managed_by_agentmail":managed.is_some(),
                    "version":managed.map(|managed| managed.version),
                }),
                &headers,
            )
        }
        Err(e) => adapter_response(e, &headers),
    }
}
#[derive(Deserialize, Default)]
struct DraftRequest {
    #[serde(default)]
    kind: DraftKind,
    #[serde(default)]
    source_message_id: Option<String>,
    #[serde(default)]
    subject: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    to: Vec<String>,
    #[serde(default)]
    cc: Vec<String>,
    #[serde(default)]
    bcc: Vec<String>,
    #[serde(default)]
    thread_id: Option<String>,
    #[serde(default)]
    expected_version: Option<String>,
    #[serde(default = "default_include_attachments")]
    include_attachments: bool,
}
fn default_include_attachments() -> bool {
    true
}
#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DraftKind {
    #[default]
    New,
    Reply,
    ReplyAll,
    Forward,
}
#[derive(Deserialize, Default)]
struct ExpectedVersionQuery {
    expected_version: Option<String>,
}
fn parse_recipients(r: &DraftRequest) -> Result<Recipients, &'static str> {
    let parse = |v: &Vec<String>| {
        v.iter()
            .map(EmailAddress::new)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "invalid recipient")
    };
    Recipients::new(parse(&r.to)?, parse(&r.cc)?, parse(&r.bcc)?).map_err(|_| "invalid recipients")
}
async fn connection_primary_address(
    state: &AppState,
    connection: ConnectionId,
) -> Result<EmailAddress, AdapterError> {
    if let Some(value) = state.connections.read().await.get(&connection) {
        return EmailAddress::new(&value.email).map_err(|_| AdapterError::Unavailable);
    }
    let repository = state.repository.as_ref().ok_or(AdapterError::NotFound)?;
    let record = repository
        .get_connection(connection)
        .await
        .map_err(|_| AdapterError::Unavailable)?
        .ok_or(AdapterError::NotFound)?;
    EmailAddress::new(record.email).map_err(|_| AdapterError::Unavailable)
}

fn reply_headers_for(message: &crate::adapter::MailMessage) -> Result<ReplyHeaders, AdapterError> {
    let value = |name: &str| {
        message
            .headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case(name))
            .map(|header| header.value.as_str())
    };
    let parent = value("message-id").ok_or(AdapterError::InvalidInput)?;
    let references = value("references")
        .into_iter()
        .flat_map(|value| value.split_ascii_whitespace())
        .map(str::to_owned)
        .chain(
            value("in-reply-to")
                .into_iter()
                .flat_map(|value| value.split_ascii_whitespace())
                .map(str::to_owned),
        )
        .collect();
    ReplyHeaders::new(parent, references).map_err(|_| AdapterError::InvalidInput)
}

fn reply_subject(subject: &str) -> String {
    if subject.trim_start().to_ascii_lowercase().starts_with("re:") {
        subject.to_owned()
    } else {
        format!("Re: {subject}")
    }
}

fn forward_subject(subject: &str) -> String {
    if subject
        .trim_start()
        .to_ascii_lowercase()
        .starts_with("fwd:")
    {
        subject.to_owned()
    } else {
        format!("Fwd: {subject}")
    }
}
fn draft_fingerprint_content(draft: &MailDraft) -> Vec<u8> {
    // This is deliberately a canonical structured representation instead of
    // display text. Every send-relevant field must invalidate a confirmation.
    serde_json::to_vec(&json!({
        "stable_message_id": draft.stable_message_id,
        "thread_id": draft.thread_id,
        "subject": draft.subject,
        "body": draft.body,
        "to": draft.to,
        "cc": draft.cc,
        "bcc": draft.bcc,
        "attachments": draft.attachments,
    }))
    .expect("draft fingerprint JSON serializes")
}

async fn refresh_managed_draft(
    state: &AppState,
    managed: &mut ManagedDraft,
    headers: &HeaderMap,
) -> Result<MailDraft, Box<Response>> {
    let remote = state
        .adapter
        .get_draft(managed.connection_id, &managed.gmail_draft_id)
        .await
        .map_err(|error| Box::new(adapter_response(error, headers)))?;
    if remote.stable_message_id != managed.message_id {
        return Err(Box::new(error_response(
            StatusCode::CONFLICT,
            "draft_changed",
            "draft no longer has its managed identity",
            headers,
        )));
    }
    let refreshed = DraftVersion::from_content(draft_fingerprint_content(&remote));
    if refreshed != managed.version {
        let previous = managed.version.clone();
        managed.version = refreshed;
        if let Some(repository) = &state.repository
            && repository.update_draft(managed, &previous).await.is_err()
        {
            return Err(Box::new(error_response(
                StatusCode::CONFLICT,
                "draft_changed",
                "request conflicts with current state",
                headers,
            )));
        }
        state
            .drafts
            .write()
            .await
            .insert(managed.id, managed.clone());
    }
    Ok(remote)
}
async fn hydrate_draft(
    state: &AppState,
    id: crate::domain::delivery::DraftId,
    headers: &HeaderMap,
) -> Result<(), Box<Response>> {
    if state.drafts.read().await.contains_key(&id) {
        return Ok(());
    }
    let Some(repository) = &state.repository else {
        return Err(Box::new(error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "resource not found",
            headers,
        )));
    };
    let draft = repository.get_draft(id).await.map_err(|_| {
        Box::new(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "service_unavailable",
            "service temporarily unavailable",
            headers,
        ))
    })?;
    let Some(draft) = draft else {
        return Err(Box::new(error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "resource not found",
            headers,
        )));
    };
    state.drafts.write().await.entry(id).or_insert(draft);
    Ok(())
}
async fn draft_lock(state: &AppState, id: crate::domain::delivery::DraftId) -> Arc<Mutex<()>> {
    let mut locks = state.draft_locks.write().await;
    locks.retain(|_, lock| lock.strong_count() > 0);
    if let Some(lock) = locks.get(&id).and_then(Weak::upgrade) {
        return lock;
    }
    let lock = Arc::new(Mutex::new(()));
    locks.insert(id, Arc::downgrade(&lock));
    lock
}

fn draft_for_connection(
    draft: &ManagedDraft,
    connection: ConnectionId,
    headers: &HeaderMap,
) -> Result<(), Box<Response>> {
    if draft.connection_id == connection {
        Ok(())
    } else {
        Err(Box::new(error_response(
            StatusCode::FORBIDDEN,
            "forbidden",
            "access denied",
            headers,
        )))
    }
}
async fn managed_draft_for_gmail(
    state: &AppState,
    connection: ConnectionId,
    gmail_draft_id: &str,
) -> Option<ManagedDraft> {
    if let Some(draft) = state
        .drafts
        .read()
        .await
        .values()
        .find(|draft| draft.connection_id == connection && draft.gmail_draft_id == gmail_draft_id)
        .cloned()
    {
        return Some(draft);
    }
    state
        .repository
        .as_ref()?
        .find_draft_by_gmail_id(connection, gmail_draft_id)
        .await
        .ok()
        .flatten()
}
async fn create_draft(
    Path(cid): Path<Uuid>,
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Json(req): Json<DraftRequest>,
) -> Response {
    let cid = ConnectionId::from_uuid(cid);
    if authorize(&headers, uri.query(), &state, cid).await.is_err() {
        return error_response(
            StatusCode::FORBIDDEN,
            "forbidden",
            "access denied",
            &headers,
        );
    }
    let stable_message_id = format!("<{}@agentmail.invalid>", Uuid::now_v7());
    let mut draft = MailDraft {
        id: Uuid::now_v7().to_string(),
        stable_message_id,
        thread_id: req.thread_id.clone(),
        subject: req.subject.clone(),
        body: req.body.clone(),
        to: vec![],
        cc: vec![],
        bcc: vec![],
        attachments: vec![],
        html_body: None,
        reply_headers: None,
        attachment_data: vec![],
    };
    match req.kind {
        DraftKind::New => match parse_recipients(&req) {
            Ok(recipients) => {
                draft.to = recipients.to;
                draft.cc = recipients.cc;
                draft.bcc = recipients.bcc;
            }
            Err(message) => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    message,
                    &headers,
                );
            }
        },
        DraftKind::Reply | DraftKind::ReplyAll | DraftKind::Forward => {
            let Some(source_id) = req.source_message_id.as_deref() else {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "source_message_id is required",
                    &headers,
                );
            };
            let source = match state.adapter.get_message(cid, source_id).await {
                Ok(message) => message,
                Err(error) => return adapter_response(error, &headers),
            };
            let primary = match connection_primary_address(&state, cid).await {
                Ok(address) => address,
                Err(error) => return adapter_response(error, &headers),
            };
            match req.kind {
                DraftKind::Reply | DraftKind::ReplyAll => {
                    let Some(from) = source.metadata.from.as_ref() else {
                        return error_response(
                            StatusCode::BAD_REQUEST,
                            "invalid_request",
                            "source has no reply address",
                            &headers,
                        );
                    };
                    let kind = if matches!(req.kind, DraftKind::ReplyAll) {
                        ReplyKind::ReplyAll
                    } else {
                        ReplyKind::Reply
                    };
                    let recipients = match reply_recipients(
                        kind,
                        &primary,
                        from,
                        &source.metadata.to,
                        &source.metadata.cc,
                    ) {
                        Ok(recipients) => recipients,
                        Err(_) => {
                            return error_response(
                                StatusCode::BAD_REQUEST,
                                "invalid_request",
                                "source has no reply recipients",
                                &headers,
                            );
                        }
                    };
                    draft.thread_id = source.metadata.thread_id.clone();
                    draft.subject = reply_subject(&source.metadata.subject);
                    draft.to = recipients.to;
                    draft.cc = recipients.cc;
                    draft.bcc = recipients.bcc;
                    draft.reply_headers = match reply_headers_for(&source) {
                        Ok(headers) => Some(headers),
                        Err(error) => return adapter_response(error, &headers),
                    };
                }
                DraftKind::Forward => {
                    let recipients = match parse_recipients(&req) {
                        Ok(recipients) => recipients,
                        Err(message) => {
                            return error_response(
                                StatusCode::BAD_REQUEST,
                                "invalid_request",
                                message,
                                &headers,
                            );
                        }
                    };
                    draft.subject = forward_subject(&source.metadata.subject);
                    draft.to = recipients.to;
                    draft.cc = recipients.cc;
                    draft.bcc = recipients.bcc;
                    let source_from = source
                        .metadata
                        .from
                        .as_ref()
                        .map(ToString::to_string)
                        .unwrap_or_default();
                    draft.body = format!(
                        "{}\n\n---------- Forwarded message ----------\nFrom: {source_from}\nSubject: {}\n\n{}",
                        req.body, source.metadata.subject, source.body
                    );
                    if req.include_attachments {
                        for attachment in &source.metadata.attachments {
                            let data = match state
                                .adapter
                                .get_attachment(cid, source_id, &attachment.id)
                                .await
                            {
                                Ok(data) => data,
                                Err(error) => return adapter_response(error, &headers),
                            };
                            draft.attachments.push(data.info.clone());
                            draft.attachment_data.push(data);
                        }
                    }
                }
                DraftKind::New => unreachable!(),
            }
        }
    };
    match state.adapter.create_draft(cid, draft).await {
        Ok(v) => {
            let managed = match ManagedDraft::new(
                cid,
                v.id.clone(),
                v.stable_message_id.clone(),
                draft_fingerprint_content(&v),
            ) {
                Ok(draft) => draft,
                Err(_) => {
                    let _ = state.adapter.delete_draft(cid, &v.id).await;
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        "invalid draft",
                        &headers,
                    );
                }
            };
            if let Some(repository) = &state.repository
                && repository.insert_draft(&managed).await.is_err()
            {
                let _ = state.adapter.delete_draft(cid, &v.id).await;
                return error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "service_unavailable",
                    "service temporarily unavailable",
                    &headers,
                );
            }
            state
                .drafts
                .write()
                .await
                .insert(managed.id, managed.clone());
            ok_json(
                json!({"connection_id":cid,"managed_draft":managed,"draft":v}),
                &headers,
            )
        }
        Err(e) => adapter_response(e, &headers),
    }
}
async fn update_draft(
    Path((cid, did)): Path<(Uuid, String)>,
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Json(req): Json<DraftRequest>,
) -> Response {
    let cid = ConnectionId::from_uuid(cid);
    if authorize(&headers, uri.query(), &state, cid).await.is_err() {
        return error_response(
            StatusCode::FORBIDDEN,
            "forbidden",
            "access denied",
            &headers,
        );
    }
    let Some(id) = Uuid::parse_str(&did)
        .ok()
        .map(crate::domain::delivery::DraftId::from_uuid)
    else {
        return error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "resource not found",
            &headers,
        );
    };
    if let Err(response) = hydrate_draft(&state, id, &headers).await {
        return *response;
    }
    let lock = draft_lock(&state, id).await;
    let _guard = lock.lock().await;
    let mut current = match state.drafts.read().await.get(&id).cloned() {
        Some(draft) => draft,
        None => {
            return error_response(
                StatusCode::NOT_FOUND,
                "not_found",
                "resource not found",
                &headers,
            );
        }
    };
    if let Err(response) = draft_for_connection(&current, cid, &headers) {
        return *response;
    }
    if let Err(response) = refresh_managed_draft(&state, &mut current, &headers).await {
        return *response;
    }
    let Some(expected_version) = req.expected_version.as_deref() else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "expected_version is required",
            &headers,
        );
    };
    let expected = match DraftVersion::new(expected_version) {
        Ok(version) => version,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "invalid expected_version",
                &headers,
            );
        }
    };
    let recipients = match parse_recipients(&req) {
        Ok(recipients) => recipients,
        Err(message) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                message,
                &headers,
            );
        }
    };
    let candidate = MailDraft {
        id: current.gmail_draft_id.clone(),
        stable_message_id: current.message_id.clone(),
        thread_id: req.thread_id.clone(),
        subject: req.subject.clone(),
        body: req.body.clone(),
        to: recipients.to.clone(),
        cc: recipients.cc.clone(),
        bcc: recipients.bcc.clone(),
        attachments: vec![],
        html_body: None,
        reply_headers: None,
        attachment_data: vec![],
    };
    let content = draft_fingerprint_content(&candidate);
    let mut changed = current.clone();
    if changed.update(&expected, content).is_err() {
        return error_response(
            StatusCode::CONFLICT,
            "draft_changed",
            "request conflicts with current state",
            &headers,
        );
    }
    let draft = candidate;
    let updated = match state.adapter.update_draft(cid, draft).await {
        Ok(updated) => updated,
        Err(error) => return adapter_response(error, &headers),
    };
    if let Some(repository) = &state.repository
        && repository.update_draft(&changed, &expected).await.is_err()
    {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "service_unavailable",
            "service temporarily unavailable",
            &headers,
        );
    }
    state.drafts.write().await.insert(id, changed.clone());
    ok_json(
        json!({"connection_id":cid,"managed_draft":changed,"draft":updated}),
        &headers,
    )
}
async fn delete_draft(
    Path((cid, did)): Path<(Uuid, String)>,
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Query(query): Query<ExpectedVersionQuery>,
) -> Response {
    let cid = ConnectionId::from_uuid(cid);
    if authorize(&headers, uri.query(), &state, cid).await.is_err() {
        return error_response(
            StatusCode::FORBIDDEN,
            "forbidden",
            "access denied",
            &headers,
        );
    }
    let Some(id) = Uuid::parse_str(&did)
        .ok()
        .map(crate::domain::delivery::DraftId::from_uuid)
    else {
        return error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "resource not found",
            &headers,
        );
    };
    if let Err(response) = hydrate_draft(&state, id, &headers).await {
        return *response;
    }
    let lock = draft_lock(&state, id).await;
    let _guard = lock.lock().await;
    let mut current = match state.drafts.read().await.get(&id).cloned() {
        Some(draft) => draft,
        None => {
            return error_response(
                StatusCode::NOT_FOUND,
                "not_found",
                "resource not found",
                &headers,
            );
        }
    };
    if let Err(response) = draft_for_connection(&current, cid, &headers) {
        return *response;
    }
    if let Err(response) = refresh_managed_draft(&state, &mut current, &headers).await {
        return *response;
    }
    let Some(expected_version) = query.expected_version.as_deref() else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "expected_version is required",
            &headers,
        );
    };
    let expected = match DraftVersion::new(expected_version) {
        Ok(version) => version,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "invalid expected_version",
                &headers,
            );
        }
    };
    let mut deleted = current.clone();
    if deleted.delete(&expected).is_err() {
        return error_response(
            StatusCode::CONFLICT,
            "draft_changed",
            "request conflicts with current state",
            &headers,
        );
    }
    if let Some(repository) = &state.repository
        && repository.update_draft(&deleted, &expected).await.is_err()
    {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "service_unavailable",
            "service temporarily unavailable",
            &headers,
        );
    }
    state.drafts.write().await.insert(id, deleted);
    match state
        .adapter
        .delete_draft(cid, &current.gmail_draft_id)
        .await
    {
        Ok(()) | Err(AdapterError::NotFound) => {
            ok_json(json!({"connection_id":cid,"deleted":true}), &headers)
        }
        Err(AdapterError::Timeout) => adapter_response(AdapterError::Timeout, &headers),
        Err(error) => {
            if let Some(repository) = &state.repository
                && repository.update_draft(&current, &expected).await.is_err()
            {
                return error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "service_unavailable",
                    "service temporarily unavailable",
                    &headers,
                );
            }
            state.drafts.write().await.insert(id, current);
            adapter_response(error, &headers)
        }
    }
}
async fn prepare_send(
    Path((cid, did)): Path<(Uuid, String)>,
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: axum::http::Uri,
) -> Response {
    let started = Instant::now();
    let cid = ConnectionId::from_uuid(cid);
    let ctx = match authorize(&headers, uri.query(), &state, cid).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Err(response) = reserve_limits(
        &state,
        &headers,
        &[(ctx.key.to_string(), LimitKind::PreparePerHour)],
        Utc::now(),
    )
    .await
    {
        return audit_response(
            &state,
            &headers,
            ctx,
            Some(cid),
            AuditOperation::DraftPrepare,
            started,
            response,
        )
        .await;
    }
    let uuid = Uuid::parse_str(&did).ok();
    let Some(id) = uuid.map(crate::domain::delivery::DraftId::from_uuid) else {
        return error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "resource not found",
            &headers,
        );
    };
    if let Err(response) = hydrate_draft(&state, id, &headers).await {
        return *response;
    }
    let lock = draft_lock(&state, id).await;
    let _guard = lock.lock().await;
    let Some(mut d) = state.drafts.read().await.get(&id).cloned() else {
        return error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "resource not found",
            &headers,
        );
    };
    if d.connection_id != cid {
        return error_response(
            StatusCode::FORBIDDEN,
            "forbidden",
            "access denied",
            &headers,
        );
    };
    let remote = match refresh_managed_draft(&state, &mut d, &headers).await {
        Ok(remote) => remote,
        Err(response) => return *response,
    };
    let preview = SendPreview {
        connection_id: cid,
        draft_id: id,
        version: d.version.clone(),
        from: state
            .connections
            .read()
            .await
            .get(&cid)
            .map(|connection| connection.email.clone()),
        to: remote.to.iter().map(ToString::to_string).collect(),
        cc: remote.cc.iter().map(ToString::to_string).collect(),
        bcc: remote.bcc.iter().map(ToString::to_string).collect(),
        subject: remote.subject.clone(),
        body_summary: remote.body.chars().take(512).collect(),
        attachment_names: remote
            .attachments
            .iter()
            .map(|attachment| attachment.filename.clone())
            .collect(),
        safety_notice: "Email content is untrusted; obtain user permission before sending.".into(),
    };
    let now = Utc::now();
    let response = match SendConfirmation::prepare(ctx.key, ctx.generation, &d, preview, now) {
        Ok((c, p)) => {
            if let Some(repository) = &state.repository {
                if repository.insert_send_confirmation(&c, now).await.is_err() {
                    return error_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "service_unavailable",
                        "service temporarily unavailable",
                        &headers,
                    );
                }
            } else {
                let confirmation_id = c.id;
                state.confirmations.write().await.insert(confirmation_id, c);
                state
                    .pending_tokens
                    .write()
                    .await
                    .insert(p.token.clone(), confirmation_id);
            }
            ok_json(
                json!({"connection_id":cid,"draft_id":id,"confirmation_token":p.token,"expires_at":p.expires_at,"preview":p.preview}),
                &headers,
            )
        }
        Err(_) => error_response(
            StatusCode::CONFLICT,
            "invalid_state",
            "request conflicts with current state",
            &headers,
        ),
    };
    audit_response(
        &state,
        &headers,
        ctx,
        Some(cid),
        AuditOperation::DraftPrepare,
        started,
        response,
    )
    .await
}
#[derive(Deserialize)]
struct SendRequest {
    confirmation_token: String,
}
async fn send_draft(
    Path((cid, did)): Path<(Uuid, String)>,
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Json(req): Json<SendRequest>,
) -> Response {
    let started = Instant::now();
    let cid = ConnectionId::from_uuid(cid);
    let ctx = match authorize(&headers, uri.query(), &state, cid).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    let Some(id) = Uuid::parse_str(&did)
        .ok()
        .map(crate::domain::delivery::DraftId::from_uuid)
    else {
        return error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "resource not found",
            &headers,
        );
    };
    if state.repository.is_some() {
        let response =
            send_draft_durable(&state, &headers, cid, id, ctx, &req.confirmation_token).await;
        return audit_response(
            &state,
            &headers,
            ctx,
            Some(cid),
            AuditOperation::DraftSend,
            started,
            response,
        )
        .await;
    }
    let Some(token_id) = state
        .pending_tokens
        .read()
        .await
        .get(&req.confirmation_token)
        .copied()
    else {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "invalid_confirmation",
            "invalid confirmation token",
            &headers,
        );
    };
    if let Err(response) = hydrate_draft(&state, id, &headers).await {
        return *response;
    }
    let lock = draft_lock(&state, id).await;
    let _guard = lock.lock().await;
    let mut draft = match state.drafts.read().await.get(&id).cloned() {
        Some(draft) => draft,
        None => {
            return error_response(
                StatusCode::NOT_FOUND,
                "not_found",
                "resource not found",
                &headers,
            );
        }
    };
    if let Err(response) = draft_for_connection(&draft, cid, &headers) {
        return *response;
    }
    if let Err(response) = refresh_managed_draft(&state, &mut draft, &headers).await {
        return *response;
    }
    let now = Utc::now();
    let mut rate_reservation = match reserve_limits(
        &state,
        &headers,
        &[
            (cid.to_string(), LimitKind::SendPerHour),
            (cid.to_string(), LimitKind::SendPerDay),
        ],
        now,
    )
    .await
    {
        Ok(reservation) => Some(reservation),
        Err(response) => return response,
    };
    let mut confirmation = match state.confirmations.read().await.get(&token_id).cloned() {
        Some(confirmation) => confirmation,
        None => {
            if let Err(response) = refund_limits(
                &state,
                &headers,
                rate_reservation.take().expect("reservation exists"),
                now,
            )
            .await
            {
                return response;
            }
            return error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_confirmation",
                "invalid confirmation token",
                &headers,
            );
        }
    };
    match confirmation.claim(
        &req.confirmation_token,
        ctx.key,
        ctx.generation,
        &mut draft,
        now,
    ) {
        Ok(Some(replayed)) => {
            if let Err(response) = refund_limits(
                &state,
                &headers,
                rate_reservation.take().expect("reservation exists"),
                now,
            )
            .await
            {
                return response;
            }
            if let Some(repository) = &state.repository
                && repository
                    .update_draft(&draft, &draft.version)
                    .await
                    .is_err()
            {
                return error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "service_unavailable",
                    "service temporarily unavailable",
                    &headers,
                );
            }
            return ok_json(
                json!({"connection_id":cid,"draft_id":id,"outcome":replayed.outcome,"replayed":true}),
                &headers,
            );
        }
        Ok(None) => {}
        Err(_) => {
            if let Err(response) = refund_limits(
                &state,
                &headers,
                rate_reservation.take().expect("reservation exists"),
                now,
            )
            .await
            {
                return response;
            }
            return error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_confirmation",
                "invalid confirmation token",
                &headers,
            );
        }
    }
    let claimed_version = draft.version.clone();
    if let Some(repository) = &state.repository
        && repository
            .update_draft(&draft, &claimed_version)
            .await
            .is_err()
    {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "service_unavailable",
            "service temporarily unavailable",
            &headers,
        );
    }
    state.drafts.write().await.insert(id, draft.clone());
    state
        .confirmations
        .write()
        .await
        .insert(token_id, confirmation.clone());

    let outcome = match state.adapter.send_draft(cid, &draft.gmail_draft_id).await {
        Ok(message_id) => SendOutcome::Sent {
            gmail_message_id: message_id,
        },
        Err(AdapterError::Timeout) => SendOutcome::StateUnknown,
        Err(AdapterError::NotFound) => SendOutcome::Failed {
            code: "upstream_not_found".to_owned(),
        },
        Err(AdapterError::InvalidInput) => SendOutcome::Failed {
            code: "invalid_draft".to_owned(),
        },
        Err(AdapterError::RateLimited { .. }) => SendOutcome::Failed {
            code: "upstream_rate_limited".to_owned(),
        },
        Err(AdapterError::Unavailable) => SendOutcome::Failed {
            code: "upstream_unavailable".to_owned(),
        },
    };
    if matches!(&outcome, SendOutcome::Failed { .. })
        && let Err(response) = refund_limits(
            &state,
            &headers,
            rate_reservation
                .take()
                .expect("claimed send keeps reservation"),
            now,
        )
        .await
    {
        return response;
    }
    let result = match confirmation.complete(&mut draft, outcome) {
        Ok(result) => result,
        Err(_) => {
            return error_response(
                StatusCode::CONFLICT,
                "send_state_conflict",
                "request conflicts with current state",
                &headers,
            );
        }
    };
    state.drafts.write().await.insert(id, draft.clone());
    state
        .confirmations
        .write()
        .await
        .insert(token_id, confirmation);
    if let Some(repository) = &state.repository
        && repository
            .update_draft(&draft, &claimed_version)
            .await
            .is_err()
    {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "service_unavailable",
            "service temporarily unavailable",
            &headers,
        );
    }
    let response = ok_json(
        json!({"connection_id":cid,"draft_id":id,"outcome":result.outcome,"replayed":result.replayed}),
        &headers,
    );
    audit_response(
        &state,
        &headers,
        ctx,
        Some(cid),
        AuditOperation::DraftSend,
        started,
        response,
    )
    .await
}

async fn send_draft_durable(
    state: &AppState,
    headers: &HeaderMap,
    connection_id: ConnectionId,
    draft_id: crate::domain::delivery::DraftId,
    auth: AuthContext,
    token: &str,
) -> Response {
    let repository = state.repository.as_ref().expect("durable send repository");
    if let Err(response) = hydrate_draft(state, draft_id, headers).await {
        return *response;
    }
    let lock = draft_lock(state, draft_id).await;
    let _guard = lock.lock().await;
    let mut draft = match state.drafts.read().await.get(&draft_id).cloned() {
        Some(draft) => draft,
        None => {
            return error_response(
                StatusCode::NOT_FOUND,
                "not_found",
                "resource not found",
                headers,
            );
        }
    };
    if let Err(response) = draft_for_connection(&draft, connection_id, headers) {
        return *response;
    }
    if let Err(response) = refresh_managed_draft(state, &mut draft, headers).await {
        return *response;
    }
    let now = Utc::now();
    let mut rate_reservation = match reserve_limits(
        state,
        headers,
        &[
            (connection_id.to_string(), LimitKind::SendPerHour),
            (connection_id.to_string(), LimitKind::SendPerDay),
        ],
        now,
    )
    .await
    {
        Ok(reservation) => Some(reservation),
        Err(response) => return response,
    };
    let digest = SendConfirmation::token_digest_hex(token);
    let claim = match repository
        .claim_send_confirmation(&digest, auth.key, auth.generation, &draft, now)
        .await
    {
        Ok(Some(claim)) => claim,
        Ok(None) => {
            if let Err(response) = refund_limits(
                state,
                headers,
                rate_reservation.take().expect("reservation exists"),
                now,
            )
            .await
            {
                return response;
            }
            return error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_confirmation",
                "invalid confirmation token",
                headers,
            );
        }
        Err(_) => {
            if let Err(response) = refund_limits(
                state,
                headers,
                rate_reservation.take().expect("reservation exists"),
                now,
            )
            .await
            {
                return response;
            }
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "service_unavailable",
                "service temporarily unavailable",
                headers,
            );
        }
    };
    let (mut confirmation, mut draft, outcome) = match claim {
        DurableSendClaim::Replayed { outcome, .. } => {
            if let Err(response) = refund_limits(
                state,
                headers,
                rate_reservation.take().expect("reservation exists"),
                now,
            )
            .await
            {
                return response;
            }
            return ok_json(
                json!({"connection_id":connection_id,"draft_id":draft_id,"outcome":outcome,"replayed":true}),
                headers,
            );
        }
        DurableSendClaim::Claimed {
            confirmation,
            draft,
        } => {
            state.drafts.write().await.insert(draft_id, draft.clone());
            let outcome = match state
                .adapter
                .send_draft(connection_id, &draft.gmail_draft_id)
                .await
            {
                Ok(message_id) => SendOutcome::Sent {
                    gmail_message_id: message_id,
                },
                Err(
                    AdapterError::Timeout
                    | AdapterError::Unavailable
                    | AdapterError::RateLimited { .. },
                ) => reconcile_sent_outcome(state, connection_id, &draft.message_id).await,
                Err(error) => failed_send_outcome(error),
            };
            (confirmation, draft, outcome)
        }
        DurableSendClaim::InProgress { confirmation } => {
            if let Err(response) = refund_limits(
                state,
                headers,
                rate_reservation.take().expect("reservation exists"),
                now,
            )
            .await
            {
                return response;
            }
            let outcome = reconcile_sent_outcome(state, connection_id, &draft.message_id).await;
            (confirmation, draft, outcome)
        }
    };
    if matches!(&outcome, SendOutcome::Failed { .. })
        && let Err(response) = refund_limits(
            state,
            headers,
            rate_reservation
                .take()
                .expect("claimed send keeps reservation"),
            now,
        )
        .await
    {
        return response;
    }
    let result = match confirmation.complete(&mut draft, outcome) {
        Ok(result) => result,
        Err(_) => {
            return error_response(
                StatusCode::CONFLICT,
                "send_state_conflict",
                "request conflicts with current state",
                headers,
            );
        }
    };
    if repository
        .complete_send_confirmation(&confirmation, &draft, Utc::now())
        .await
        .is_err()
    {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "service_unavailable",
            "service temporarily unavailable",
            headers,
        );
    }
    state.drafts.write().await.insert(draft_id, draft);
    ok_json(
        json!({"connection_id":connection_id,"draft_id":draft_id,"outcome":result.outcome,"replayed":false}),
        headers,
    )
}

async fn reconcile_sent_outcome(
    state: &AppState,
    connection_id: ConnectionId,
    stable_message_id: &str,
) -> SendOutcome {
    match state
        .adapter
        .find_sent_message(connection_id, stable_message_id)
        .await
    {
        Ok(Some(message_id)) => SendOutcome::Sent {
            gmail_message_id: message_id,
        },
        Ok(None) | Err(_) => SendOutcome::StateUnknown,
    }
}

fn failed_send_outcome(error: AdapterError) -> SendOutcome {
    SendOutcome::Failed {
        code: match error {
            AdapterError::NotFound => "upstream_not_found",
            AdapterError::InvalidInput => "invalid_draft",
            AdapterError::RateLimited { .. }
            | AdapterError::Unavailable
            | AdapterError::Timeout => "send_state_unknown",
        }
        .to_owned(),
    }
}
fn ok_json(value: Value, headers: &HeaderMap) -> Response {
    let mut response = (StatusCode::OK, Json(value)).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    if let Ok(value) = HeaderValue::from_str(&request_id(headers)) {
        response.headers_mut().insert("x-request-id", value);
    }
    response
}
fn adapter_response(e: AdapterError, h: &HeaderMap) -> Response {
    match e {
        AdapterError::InvalidInput => error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "draft content is invalid",
            h,
        ),
        AdapterError::NotFound => {
            error_response(StatusCode::NOT_FOUND, "not_found", "resource not found", h)
        }
        AdapterError::RateLimited { .. } => error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "rate limit exceeded",
            h,
        ),
        _ => error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "upstream_unavailable",
            "upstream service is temporarily unavailable",
            h,
        ),
    }
}

async fn live(headers: HeaderMap) -> Response {
    ok_json(json!({"status":"ok"}), &headers)
}
async fn ready(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(db) = state.database else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "not_ready",
            "service is not ready",
            &headers,
        );
    };
    match db.ensure_current().await {
        Ok(s) => ok_json(
            json!({"status":"ready","schema":{"current_version":s.current_version,"latest_version":s.latest_version}}),
            &headers,
        ),
        Err(DatabaseError::PendingMigrations { .. }) => error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "pending_migrations",
            "database migrations are pending",
            &headers,
        ),
        Err(_) => error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "not_ready",
            "service is not ready",
            &headers,
        ),
    }
}
async fn landing() -> impl IntoResponse {
    (StatusCode::OK, "AgentMail")
}
async fn privacy() -> impl IntoResponse {
    (StatusCode::OK, "Privacy policy")
}
async fn terms() -> impl IntoResponse {
    (StatusCode::OK, "Terms of service")
}
async fn deletion() -> impl IntoResponse {
    (StatusCode::OK, "Data deletion")
}
async fn api() -> impl IntoResponse {
    Json(
        json!({"name":"agentmail","version":env!("CARGO_PKG_VERSION"),"openapi":"/api/openapi.json"}),
    )
}
async fn openapi() -> impl IntoResponse {
    Json(json!({
        "openapi": "3.1.0",
        "info": {
            "title": "AgentMail API",
            "version": env!("CARGO_PKG_VERSION")
        },
        "paths": {
            "/api/v1/connections/{connection_id}/messages": {
                "get": {
                    "operationId": "searchMessages",
                    "security": [{"bearerAuth": []}],
                    "parameters": [
                        {
                            "name": "connection_id",
                            "in": "path",
                            "required": true,
                            "schema": {"type": "string", "format": "uuid"}
                        },
                        {
                            "name": "q",
                            "in": "query",
                            "required": false,
                            "description": "Gmail search query; never logged or audited",
                            "schema": {"type": "string"}
                        },
                        {
                            "name": "page_size",
                            "in": "query",
                            "required": false,
                            "schema": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20}
                        },
                        {
                            "name": "cursor",
                            "in": "query",
                            "required": false,
                            "schema": {"type": "string"}
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Safe message metadata only",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/MessageSearchResult"}}}
                        },
                        "400": {"description": "Invalid request or unsupported cursor", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ErrorResponse"}}}},
                        "401": {"description": "Missing or invalid Bearer Access Key", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ErrorResponse"}}}},
                        "403": {"description": "Connection is not granted to this key", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ErrorResponse"}}}},
                        "429": {"description": "Rate limited", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ErrorResponse"}}}},
                        "503": {"description": "Upstream unavailable", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ErrorResponse"}}}}
                    }
                }
            }
        },
        "components": {
            "securitySchemes": {
                "bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "AgentMail Access Key"}
            },
            "schemas": {
                "MessageSearchResult": {
                    "type": "object",
                    "required": ["connection_id", "messages", "next_cursor"],
                    "properties": {
                        "connection_id": {"type": "string", "format": "uuid"},
                        "messages": {"type": "array", "items": {"$ref": "#/components/schemas/MessageMetadata"}},
                        "next_cursor": {"type": ["string", "null"]}
                    }
                },
                "MessageMetadata": {
                    "type": "object",
                    "required": ["id", "to", "cc", "subject", "snippet", "attachments"],
                    "properties": {
                        "id": {"type": "string"},
                        "thread_id": {"type": ["string", "null"]},
                        "sent_at": {"type": ["string", "null"]},
                        "from": {"type": ["string", "null"]},
                        "to": {"type": "array", "items": {"type": "string"}},
                        "cc": {"type": "array", "items": {"type": "string"}},
                        "subject": {"type": "string"},
                        "snippet": {"type": "string"},
                        "attachments": {"type": "array", "items": {"type": "object"}}
                    }
                },
                "ErrorResponse": {
                    "type": "object",
                    "required": ["error"],
                    "properties": {
                        "error": {
                            "type": "object",
                            "required": ["code", "message", "request_id", "retryable"],
                            "properties": {
                                "code": {"type": "string"},
                                "message": {"type": "string"},
                                "request_id": {"type": "string"},
                                "retryable": {"type": "boolean"},
                                "retry_after_seconds": {"type": ["integer", "null"]}
                            }
                        }
                    }
                }
            }
        },
        "x-agentmail-mcp": "The current /mcp endpoint exposes a minimal JSON-RPC compatibility surface, not full Streamable HTTP."
    }))
}
async fn get_thread(
    Path((cid, _tid)): Path<(Uuid, String)>,
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Query(query): Query<MessageReadQuery>,
) -> Response {
    let cid = ConnectionId::from_uuid(cid);
    if authorize(&headers, uri.query(), &state, cid).await.is_err() {
        return error_response(
            StatusCode::FORBIDDEN,
            "forbidden",
            "access denied",
            &headers,
        );
    }
    let html = match wants_html(&query) {
        Ok(value) => value,
        Err(message) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                message,
                &headers,
            );
        }
    };
    match state
        .mailbox_service
        .get_thread(cid, &_tid, html, query.chunk_bytes)
        .await
    {
        Ok(messages) => ok_json(
            json!({"connection_id":cid,"thread_id":_tid,"messages":messages,"untrusted_email_content":true}),
            &headers,
        ),
        Err(MailboxReadError::Adapter(error)) => adapter_response(error, &headers),
        Err(MailboxReadError::InvalidCursor) => unreachable!("thread read has no cursor"),
    }
}
async fn get_attachment(
    Path((cid, mid, aid)): Path<(Uuid, String, String)>,
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: axum::http::Uri,
) -> Response {
    let cid = ConnectionId::from_uuid(cid);
    if authorize(&headers, uri.query(), &state, cid).await.is_err() {
        return error_response(
            StatusCode::FORBIDDEN,
            "forbidden",
            "access denied",
            &headers,
        );
    }
    match state.mailbox_service.get_attachment(cid, &mid, &aid).await {
        Ok(attachment) => {
            let filename = sanitize_filename(&attachment.info.filename)
                .chars()
                .map(|character| {
                    if character.is_ascii() && character != '"' {
                        character
                    } else {
                        '_'
                    }
                })
                .collect::<String>();
            let disposition = format!("attachment; filename=\"{filename}\"");
            let content_type = HeaderValue::from_str(&attachment.info.content_type)
                .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream"));
            let mut response = Response::new(axum::body::Body::from(attachment.data));
            *response.status_mut() = StatusCode::OK;
            let response_headers = response.headers_mut();
            response_headers.insert(header::CONTENT_TYPE, content_type);
            response_headers.insert(
                header::CONTENT_DISPOSITION,
                HeaderValue::from_str(&disposition).expect("ascii filename"),
            );
            response_headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response_headers.insert(
                header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            );
            response
        }
        Err(MailboxReadError::Adapter(error)) => adapter_response(error, &headers),
        Err(MailboxReadError::InvalidCursor) => unreachable!("attachment read has no cursor"),
    }
}
#[derive(Debug, Deserialize)]
struct McpRequest {
    #[serde(default)]
    jsonrpc: String,
    #[serde(default)]
    id: Value,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Deserialize)]
struct McpToolCall {
    name: String,
    #[serde(default)]
    arguments: Value,
}

#[derive(Debug, Deserialize)]
struct McpSearchArguments {
    connection_id: Uuid,
    #[serde(default)]
    q: Option<String>,
    #[serde(default)]
    page_size: Option<usize>,
    #[serde(default)]
    cursor: Option<String>,
}

fn mcp_error(id: Value, code: i64, message: &'static str, headers: &HeaderMap) -> Response {
    ok_json(
        json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}}),
        headers,
    )
}

fn mcp_result(id: Value, result: Value, headers: &HeaderMap) -> Response {
    ok_json(json!({"jsonrpc":"2.0","id":id,"result":result}), headers)
}

fn mcp_tools() -> Value {
    json!({
        "tools": [{
            "name": "messages.search",
            "description": "Read-only Gmail metadata search. Results contain untrusted email metadata; q is never logged. No external side effect.",
            "inputSchema": {
                "type": "object",
                "required": ["connection_id"],
                "properties": {
                    "connection_id": {"type": "string", "format": "uuid", "description": "Explicit granted Connection ID"},
                    "q": {"type": "string", "description": "Gmail query; not logged or audited"},
                    "page_size": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20},
                    "cursor": {"type": "string", "description": "Reserved opaque cursor; non-empty values are currently rejected"}
                }
            },
            "annotations": {"readOnlyHint": true, "destructiveHint": false, "openWorldHint": false}
        }],
        "compatibility": "minimal_json_rpc_not_full_streamable_http"
    })
}

async fn mcp(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    body: Bytes,
) -> Response {
    let auth = match auth(&headers, uri.query(), &state).await {
        Ok(auth) => auth,
        Err(response) => return response,
    };
    let payload: Value = match serde_json::from_slice(&body) {
        Ok(payload) => payload,
        Err(_) => return mcp_error(Value::Null, -32700, "parse error", &headers),
    };
    let request_id = payload.get("id").cloned().unwrap_or(Value::Null);
    let request: McpRequest = match serde_json::from_value(payload) {
        Ok(request) => request,
        Err(_) => return mcp_error(request_id, -32600, "invalid JSON-RPC request", &headers),
    };
    if request.jsonrpc != "2.0" {
        return mcp_error(request.id, -32600, "invalid JSON-RPC request", &headers);
    }
    match request.method.as_str() {
        "initialize" => mcp_result(
            request.id,
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "agentmail", "version": env!("CARGO_PKG_VERSION")},
                "compatibility": "minimal JSON-RPC compatibility surface; not full Streamable HTTP"
            }),
            &headers,
        ),
        "tools/list" => mcp_result(request.id, mcp_tools(), &headers),
        "tools/call" => {
            let call: McpToolCall = match serde_json::from_value(request.params) {
                Ok(call) => call,
                Err(_) => {
                    return mcp_error(request.id, -32602, "invalid tool parameters", &headers);
                }
            };
            if call.name != "messages.search" {
                return mcp_error(request.id, -32601, "tool not found", &headers);
            }
            let args: McpSearchArguments = match serde_json::from_value(call.arguments) {
                Ok(args) => args,
                Err(_) => return mcp_error(request.id, -32602, "invalid tool arguments", &headers),
            };
            let cid = ConnectionId::from_uuid(args.connection_id);
            if let Err(response) = authorize_context(&headers, &state, cid, auth).await {
                return response;
            }
            let started = Instant::now();
            let response = match state
                .mailbox_service
                .search(
                    cid,
                    args.q.as_deref(),
                    args.page_size,
                    args.cursor.as_deref(),
                )
                .await
            {
                Ok(result) => {
                    let payload = json!({"connection_id":cid,"messages":result.messages,"next_cursor":result.next_cursor});
                    let text = serde_json::to_string(&payload).expect("JSON value serializes");
                    mcp_result(
                        request.id,
                        json!({"content":[{"type":"text","text":text}],"structuredContent":payload}),
                        &headers,
                    )
                }
                Err(MailboxReadError::InvalidCursor) => mcp_error(
                    request.id,
                    -32602,
                    "non-empty cursor pagination is not supported yet",
                    &headers,
                ),
                Err(MailboxReadError::Adapter(AdapterError::RateLimited { .. })) => {
                    mcp_error(request.id, -32029, "upstream rate limit exceeded", &headers)
                }
                Err(MailboxReadError::Adapter(AdapterError::NotFound)) => {
                    mcp_error(request.id, -32004, "resource not found", &headers)
                }
                Err(MailboxReadError::Adapter(AdapterError::InvalidInput)) => {
                    mcp_error(request.id, -32602, "invalid upstream request", &headers)
                }
                Err(MailboxReadError::Adapter(
                    AdapterError::Unavailable | AdapterError::Timeout,
                )) => mcp_error(request.id, -32003, "upstream service unavailable", &headers),
            };
            audit_response(
                &state,
                &headers,
                auth,
                Some(cid),
                AuditOperation::MessagesSearch,
                started,
                response,
            )
            .await
        }
        _ => mcp_error(request.id, -32601, "method not found", &headers),
    }
}
async fn request_context(mut req: Request<axum::body::Body>, next: Next) -> Response {
    let id = Uuid::now_v7().to_string();
    req.headers_mut()
        .insert("x-request-id", HeaderValue::from_str(&id).expect("uuid"));
    let mut response = next.run(req).await;
    for (name, value) in [
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::REFERRER_POLICY, "no-referrer"),
        (header::CACHE_CONTROL, "no-store"),
    ] {
        response
            .headers_mut()
            .insert(name, HeaderValue::from_static(value));
    }
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        ),
    );
    response.headers_mut().insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    response
        .headers_mut()
        .insert("x-request-id", HeaderValue::from_str(&id).expect("uuid"));
    response
}
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(landing))
        .route("/privacy", get(privacy))
        .route("/terms", get(terms))
        .route("/data-deletion", get(deletion))
        .route("/api", get(api))
        .route("/api/openapi.json", get(openapi))
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .route("/mcp", post(mcp))
        .route("/api/v1/connections", get(list_connections))
        .route(
            "/api/v1/connections/{connection_id}/messages",
            get(list_messages),
        )
        .route(
            "/api/v1/connections/{connection_id}/messages/{message_id}",
            get(get_message),
        )
        .route(
            "/api/v1/connections/{connection_id}/threads/{thread_id}",
            get(get_thread),
        )
        .route(
            "/api/v1/connections/{connection_id}/messages/{message_id}/attachments/{attachment_id}",
            get(get_attachment),
        )
        .route(
            "/api/v1/connections/{connection_id}/drafts",
            get(list_drafts).post(create_draft),
        )
        .route(
            "/api/v1/connections/{connection_id}/drafts/{draft_id}",
            get(get_draft).patch(update_draft).delete(delete_draft),
        )
        .route(
            "/api/v1/connections/{connection_id}/drafts/{draft_id}/prepare-send",
            post(prepare_send),
        )
        .route(
            "/api/v1/connections/{connection_id}/drafts/{draft_id}/send",
            post(send_draft),
        )
        .with_state(state)
        .layer(middleware::from_fn(request_context))
}
pub fn build_router(state: AppState) -> Router {
    router(state)
}

pub async fn run(command: Command) -> anyhow::Result<()> {
    let config = AppConfig::from_env()?;
    match command {
        Command::Migrate {
            command: Some(MigrateCommand::Status),
        } => {
            let db = Database::connect(config.database_url).await?;
            let status = db.migration_status().await?;
            println!(
                "{}",
                serde_json::json!({"current_version": status.current_version, "latest_version": status.latest_version, "pending": status.pending})
            );
            Ok(())
        }
        Command::Migrate { command: None } => {
            let db = Database::connect(config.database_url).await?;
            db.migrate().await?;
            println!("migrations applied");
            Ok(())
        }
        Command::Database {
            command: DatabaseCommand::Backup { target },
        } => {
            let db = Database::connect(config.database_url).await?;
            println!("{}", db.backup(target).await?.display());
            Ok(())
        }
        Command::Serve => {
            let db = Database::connect(config.database_url.clone()).await?;
            db.ensure_current().await?;
            let repository = Repository::new(&db);
            repository
                .cleanup_metadata(Utc::now(), config.audit_retention_days)
                .await?;
            let cleanup_repository = repository.clone();
            let audit_retention_days = config.audit_retention_days;
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(3_600));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                interval.tick().await;
                loop {
                    interval.tick().await;
                    if let Err(error) = cleanup_repository
                        .cleanup_metadata(Utc::now(), audit_retention_days)
                        .await
                    {
                        tracing::warn!(error = %error, "metadata cleanup failed");
                    }
                }
            });
            let oidc_verifier = GoogleJwksVerifier::new()?;
            let login_token_client = GoogleTokenClient::new(
                config.google_login_client_id.clone(),
                config.google_login_client_secret.clone(),
                config.google_login_callback_url(),
            )?;
            let gmail_token_client = GoogleTokenClient::new(
                config.google_gmail_client_id.clone(),
                config.google_gmail_client_secret.clone(),
                config.google_gmail_callback_url(),
            )?;
            let credentials = Arc::new(GmailCredentialProvider::new(
                Arc::new(repository.clone()),
                Arc::new(gmail_token_client.clone()),
                config.encryption_keyring.clone(),
            ));
            let live_adapter = Arc::new(LiveGmailAdapter::new(
                repository.clone(),
                credentials,
                GoogleGmailClient::new()?,
            ));
            let control_state = ControlHttpState::new(
                config.clone(),
                repository,
                oidc_verifier,
                login_token_client,
                gmail_token_client,
            )?;
            crate::control_http::recover_pending_revocations(&control_state).await?;
            let state = AppState::new(Some(db), live_adapter);
            let control_router = crate::control_http::router(control_state.clone())
                .layer(middleware::from_fn(request_context));
            let control_ui_router = crate::control_ui::router(control_state)
                .layer(middleware::from_fn(request_context));
            let app = router(state).merge(control_router).merge(control_ui_router);
            let host = std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".into());
            let port = std::env::var("PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(18080);
            let addr: SocketAddr = format!("{host}:{port}").parse()?;
            let listener = tokio::net::TcpListener::bind(addr).await?;
            axum::serve(listener, app).await?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::identity::{GMAIL_COMPOSE_SCOPE, GMAIL_READONLY_SCOPE};
    use crate::repository::Repository;
    use axum::body::Body;
    use http::{Method, Request};
    use sqlx::Row;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt;

    #[derive(Default)]
    struct TimeoutThenReconcileAdapter {
        inner: FakeGmailAdapter,
        send_calls: AtomicUsize,
        reconcile_calls: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl GmailAdapter for TimeoutThenReconcileAdapter {
        async fn list_messages(
            &self,
            connection: ConnectionId,
            query: Option<&str>,
            page_size: usize,
            cursor: Option<&str>,
        ) -> Result<crate::adapter::MailMessagePage, AdapterError> {
            self.inner
                .list_messages(connection, query, page_size, cursor)
                .await
        }
        async fn get_message(
            &self,
            connection: ConnectionId,
            message_id: &str,
        ) -> Result<crate::adapter::MailMessage, AdapterError> {
            self.inner.get_message(connection, message_id).await
        }
        async fn get_thread(
            &self,
            connection: ConnectionId,
            thread_id: &str,
        ) -> Result<Vec<crate::adapter::MailMessage>, AdapterError> {
            self.inner.get_thread(connection, thread_id).await
        }
        async fn get_attachment(
            &self,
            connection: ConnectionId,
            message_id: &str,
            attachment_id: &str,
        ) -> Result<crate::adapter::MailAttachment, AdapterError> {
            self.inner
                .get_attachment(connection, message_id, attachment_id)
                .await
        }
        async fn list_drafts(
            &self,
            connection: ConnectionId,
        ) -> Result<Vec<MailDraft>, AdapterError> {
            self.inner.list_drafts(connection).await
        }
        async fn get_draft(
            &self,
            connection: ConnectionId,
            draft_id: &str,
        ) -> Result<MailDraft, AdapterError> {
            self.inner.get_draft(connection, draft_id).await
        }
        async fn create_draft(
            &self,
            connection: ConnectionId,
            draft: MailDraft,
        ) -> Result<MailDraft, AdapterError> {
            self.inner.create_draft(connection, draft).await
        }
        async fn update_draft(
            &self,
            connection: ConnectionId,
            draft: MailDraft,
        ) -> Result<MailDraft, AdapterError> {
            self.inner.update_draft(connection, draft).await
        }
        async fn delete_draft(
            &self,
            connection: ConnectionId,
            draft_id: &str,
        ) -> Result<(), AdapterError> {
            self.inner.delete_draft(connection, draft_id).await
        }
        async fn send_draft(
            &self,
            _connection: ConnectionId,
            _draft_id: &str,
        ) -> Result<String, AdapterError> {
            self.send_calls.fetch_add(1, Ordering::SeqCst);
            Err(AdapterError::Timeout)
        }
        async fn find_sent_message(
            &self,
            _connection: ConnectionId,
            _stable_message_id: &str,
        ) -> Result<Option<String>, AdapterError> {
            self.reconcile_calls.fetch_add(1, Ordering::SeqCst);
            Ok(Some("reconciled-message".into()))
        }
    }

    async fn json_request(
        app: &Router,
        method: Method,
        uri: String,
        credential: &str,
        body: Value,
    ) -> (StatusCode, Value) {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("authorization", format!("Bearer {credential}"))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json = serde_json::from_slice(&bytes).unwrap_or_else(|error| {
            panic!(
                "response status {status}, JSON error {error}, body {}",
                String::from_utf8_lossy(&bytes)
            )
        });
        (status, json)
    }

    async fn persisted_state() -> (AppState, String, ConnectionId, ConnectionId) {
        let database = Database::connect("sqlite::memory:").await.unwrap();
        database.migrate().await.unwrap();
        let repository = Repository::new(&database);
        let user = User::new(
            "http-owner",
            "owner@example.com",
            UserRole::Owner,
            Utc::now(),
        )
        .unwrap();
        repository.insert_user(&user).await.unwrap();
        let scopes = vec![GMAIL_READONLY_SCOPE.into(), GMAIL_COMPOSE_SCOPE.into()];
        let first =
            GmailConnection::new(user.id, "http-gmail-1", "first@example.com", scopes.clone())
                .unwrap();
        let second =
            GmailConnection::new(user.id, "http-gmail-2", "second@example.com", scopes).unwrap();
        repository.insert_connection(&first, None).await.unwrap();
        repository.insert_connection(&second, None).await.unwrap();
        let created = AccessKey::generate(user.id, "http-key", [first.id]).unwrap();
        let credential = created.credential.clone();
        repository.insert_access_key(&created).await.unwrap();
        // Construct a fresh state: authentication must not depend on its in-memory maps.
        let state = AppState::new(Some(database), Arc::new(FakeGmailAdapter::new()));
        (state, credential, first.id, second.id)
    }

    #[tokio::test]
    async fn persisted_access_key_authenticates_in_fresh_state_and_lists_grants() {
        let (state, credential, first, second) = persisted_state().await;
        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri("/api/v1/connections")
                    .header("authorization", format!("Bearer {credential}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        let connections = value["connections"].as_array().unwrap();
        assert_eq!(connections.len(), 1);
        assert_eq!(connections[0]["connection_id"], json!(first));
        assert_ne!(connections[0]["connection_id"], json!(second));
    }

    #[tokio::test]
    async fn reply_all_creates_managed_threaded_draft() {
        let (state, credential, connection, adapter) = AppState::test_fixture_with_adapter();
        adapter
            .insert_message(
                connection,
                crate::adapter::MailMessage {
                    metadata: crate::domain::mailbox::MessageMetadata {
                        id: "source-1".into(),
                        thread_id: Some("thread-1".into()),
                        sent_at: None,
                        from: Some(EmailAddress::new("sender@example.com").unwrap()),
                        to: vec![EmailAddress::new("gmail@example.com").unwrap()],
                        cc: vec![EmailAddress::new("copy@example.com").unwrap()],
                        subject: "Topic".into(),
                        snippet: "snippet".into(),
                        attachments: vec![],
                    },
                    body: "original".into(),
                    body_is_html: false,
                    html_body: None,
                    headers: vec![crate::adapter::MailHeader {
                        name: "Message-ID".into(),
                        value: "<parent@example.com>".into(),
                    }],
                },
            )
            .await;
        let (status, response) = json_request(
            &router(state),
            Method::POST,
            format!("/api/v1/connections/{connection}/drafts"),
            &credential,
            json!({"kind":"reply_all","source_message_id":"source-1","body":"answer"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(response["draft"]["thread_id"], "thread-1");
        assert_eq!(response["draft"]["subject"], "Re: Topic");
        assert_eq!(response["draft"]["to"], json!(["sender@example.com"]));
        assert_eq!(response["draft"]["cc"], json!(["copy@example.com"]));
        assert_eq!(response["managed_draft"]["state"], "active");
    }

    #[tokio::test]
    async fn persisted_access_key_cannot_access_ungranted_connection() {
        let (state, credential, _, second) = persisted_state().await;
        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/connections/{second}/messages"))
                    .header("authorization", format!("Bearer {credential}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn durable_confirmation_survives_restart_and_replays_first_result() {
        let (state, credential, connection, _) = persisted_state().await;
        let app = router(state.clone());
        let (status, created) = json_request(
            &app,
            Method::POST,
            format!("/api/v1/connections/{connection}/drafts"),
            &credential,
            json!({"subject":"durable","body":"body","to":["to@example.com"]}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let draft_id = created["managed_draft"]["id"].as_str().unwrap();
        let (status, prepared) = json_request(
            &app,
            Method::POST,
            format!("/api/v1/connections/{connection}/drafts/{draft_id}/prepare-send"),
            &credential,
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let token = prepared["confirmation_token"].as_str().unwrap();

        let restarted = AppState::new(state.database.clone(), state.adapter.clone());
        let restarted_app = router(restarted);
        let request = json!({"confirmation_token":token});
        let (status, first) = json_request(
            &restarted_app,
            Method::POST,
            format!("/api/v1/connections/{connection}/drafts/{draft_id}/send"),
            &credential,
            request.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(first["replayed"], false);
        let (status, replay) = json_request(
            &restarted_app,
            Method::POST,
            format!("/api/v1/connections/{connection}/drafts/{draft_id}/send"),
            &credential,
            request,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(replay["replayed"], true);
        assert_eq!(replay["outcome"], first["outcome"]);
    }

    #[tokio::test]
    async fn restart_after_claim_reconciles_without_resending() {
        let (state, credential, connection, _) = persisted_state().await;
        let app = router(state.clone());
        let (_, created) = json_request(
            &app,
            Method::POST,
            format!("/api/v1/connections/{connection}/drafts"),
            &credential,
            json!({"subject":"crash","body":"body","to":["to@example.com"]}),
        )
        .await;
        let draft_id_text = created["managed_draft"]["id"].as_str().unwrap();
        let draft_id =
            crate::domain::delivery::DraftId::from_uuid(Uuid::parse_str(draft_id_text).unwrap());
        let (_, prepared) = json_request(
            &app,
            Method::POST,
            format!("/api/v1/connections/{connection}/drafts/{draft_id}/prepare-send"),
            &credential,
            json!({}),
        )
        .await;
        let token = prepared["confirmation_token"].as_str().unwrap();
        let repository = state.repository.as_ref().unwrap();
        let key = repository
            .authenticate_access_key(&credential)
            .await
            .unwrap()
            .unwrap();
        let draft = repository.get_draft(draft_id).await.unwrap().unwrap();
        let digest = SendConfirmation::token_digest_hex(token);
        assert!(matches!(
            repository
                .claim_send_confirmation(&digest, key.id, key.generation, &draft, Utc::now())
                .await
                .unwrap(),
            Some(DurableSendClaim::Claimed { .. })
        ));

        let adapter = Arc::new(TimeoutThenReconcileAdapter::default());
        adapter
            .inner
            .insert_draft(
                connection,
                serde_json::from_value(created["draft"].clone()).unwrap(),
            )
            .await;
        let restarted = AppState::new(state.database.clone(), adapter.clone());
        let (status, result) = json_request(
            &router(restarted),
            Method::POST,
            format!("/api/v1/connections/{connection}/drafts/{draft_id}/send"),
            &credential,
            json!({"confirmation_token":token}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            result["outcome"],
            json!({"Sent":{"gmail_message_id":"reconciled-message"}})
        );
        assert_eq!(result["replayed"], false);
        assert_eq!(adapter.send_calls.load(Ordering::SeqCst), 0);
        assert_eq!(adapter.reconcile_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn timeout_reconciles_once_and_replay_never_sends_again() {
        let (state, credential, connection, _) = persisted_state().await;
        let app = router(state.clone());
        let (_, created) = json_request(
            &app,
            Method::POST,
            format!("/api/v1/connections/{connection}/drafts"),
            &credential,
            json!({"subject":"timeout","body":"body","to":["to@example.com"]}),
        )
        .await;
        let draft_id = created["managed_draft"]["id"].as_str().unwrap();
        let (_, prepared) = json_request(
            &app,
            Method::POST,
            format!("/api/v1/connections/{connection}/drafts/{draft_id}/prepare-send"),
            &credential,
            json!({}),
        )
        .await;
        let token = prepared["confirmation_token"].as_str().unwrap();
        let adapter = Arc::new(TimeoutThenReconcileAdapter::default());
        adapter
            .inner
            .insert_draft(
                connection,
                serde_json::from_value(created["draft"].clone()).unwrap(),
            )
            .await;
        let restarted = AppState::new(state.database.clone(), adapter.clone());
        let restarted_app = router(restarted);
        let request = json!({"confirmation_token":token});
        let (status, first) = json_request(
            &restarted_app,
            Method::POST,
            format!("/api/v1/connections/{connection}/drafts/{draft_id}/send"),
            &credential,
            request.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            first["outcome"],
            json!({"Sent":{"gmail_message_id":"reconciled-message"}})
        );
        assert_eq!(adapter.send_calls.load(Ordering::SeqCst), 1);
        assert_eq!(adapter.reconcile_calls.load(Ordering::SeqCst), 1);

        let (_, replay) = json_request(
            &restarted_app,
            Method::POST,
            format!("/api/v1/connections/{connection}/drafts/{draft_id}/send"),
            &credential,
            request,
        )
        .await;
        assert_eq!(replay["replayed"], true);
        assert_eq!(adapter.send_calls.load(Ordering::SeqCst), 1);
        assert_eq!(adapter.reconcile_calls.load(Ordering::SeqCst), 1);
        let repository = state.repository.as_ref().unwrap();
        let counts: Vec<i64> = sqlx::query_scalar(
            "SELECT request_count FROM rate_limit_buckets WHERE bucket_key IN (?,?) ORDER BY bucket_key",
        )
        .bind(format!("send_per_day:{connection}"))
        .bind(format!("send_per_hour:{connection}"))
        .fetch_all(repository.pool())
        .await
        .unwrap();
        assert_eq!(counts, vec![1, 1], "replay must not consume send quota");
        let send_audits: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_events WHERE operation='draft.send' AND result_category='ok'",
        )
        .fetch_one(repository.pool())
        .await
        .unwrap();
        assert_eq!(send_audits, 2, "initial send and replay are both audited");
    }

    #[tokio::test]
    async fn api_rate_limit_returns_retry_seconds_and_header() {
        let (state, credential, _) = AppState::test_fixture();
        let key_id = state.keys.read().await.values().next().unwrap().id;
        let now = Utc::now();
        let bucket_key = format!("api_per_minute:{key_id}");
        let mut bucket = RateBucket::new(&bucket_key, LimitKind::ApiPerMinute, now);
        bucket.request_count = LimitKind::ApiPerMinute.limit() - 1;
        state.rate_buckets.lock().await.insert(bucket_key, bucket);
        let app = router(state);
        let allowed = app
            .clone()
            .oneshot(
                Request::get("/api/v1/connections")
                    .header("authorization", format!("Bearer {credential}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(allowed.status(), StatusCode::OK);
        let response = app
            .oneshot(
                Request::get("/api/v1/connections")
                    .header("authorization", format!("Bearer {credential}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(response.headers().contains_key(header::RETRY_AFTER));
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error"]["code"], "rate_limited");
        assert!(body["error"]["retry_after_seconds"].as_u64().unwrap() >= 1);
    }

    #[tokio::test]
    async fn mcp_request_charges_api_limit_once() {
        let (state, credential, _) = AppState::test_fixture();
        let app = router(state.clone());
        let response = app
            .oneshot(
                Request::post("/mcp")
                    .header("authorization", format!("Bearer {credential}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let buckets = state.rate_buckets.lock().await;
        assert_eq!(buckets.len(), 1);
        assert_eq!(buckets.values().next().unwrap().request_count, 1);
    }

    #[tokio::test]
    async fn prepare_limit_is_enforced_before_confirmation_creation() {
        let (state, credential, connection) = AppState::test_fixture();
        let key_id = state.keys.read().await.values().next().unwrap().id;
        let app = router(state.clone());
        let (status, created) = json_request(
            &app,
            Method::POST,
            format!("/api/v1/connections/{connection}/drafts"),
            &credential,
            json!({"subject":"limited","body":"body","to":["to@example.com"]}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let draft_id = created["managed_draft"]["id"].as_str().unwrap();
        let now = Utc::now();
        let bucket_key = format!("prepare_per_hour:{key_id}");
        let mut bucket = RateBucket::new(&bucket_key, LimitKind::PreparePerHour, now);
        bucket.request_count = LimitKind::PreparePerHour.limit();
        state.rate_buckets.lock().await.insert(bucket_key, bucket);
        let (status, body) = json_request(
            &app,
            Method::POST,
            format!("/api/v1/connections/{connection}/drafts/{draft_id}/prepare-send"),
            &credential,
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body["error"]["code"], "rate_limited");
        assert!(state.confirmations.read().await.is_empty());
    }

    #[tokio::test]
    async fn send_limit_does_not_consume_confirmation() {
        let (state, credential, connection) = AppState::test_fixture();
        let app = router(state.clone());
        let (_, created) = json_request(
            &app,
            Method::POST,
            format!("/api/v1/connections/{connection}/drafts"),
            &credential,
            json!({"subject":"limited","body":"body","to":["to@example.com"]}),
        )
        .await;
        let draft_id = created["managed_draft"]["id"].as_str().unwrap();
        let (_, prepared) = json_request(
            &app,
            Method::POST,
            format!("/api/v1/connections/{connection}/drafts/{draft_id}/prepare-send"),
            &credential,
            json!({}),
        )
        .await;
        let token = prepared["confirmation_token"].as_str().unwrap();
        let now = Utc::now();
        let bucket_key = format!("send_per_hour:{connection}");
        let mut bucket = RateBucket::new(&bucket_key, LimitKind::SendPerHour, now);
        bucket.request_count = LimitKind::SendPerHour.limit();
        state
            .rate_buckets
            .lock()
            .await
            .insert(bucket_key.clone(), bucket);
        let request = json!({"confirmation_token":token});
        let (limited, body) = json_request(
            &app,
            Method::POST,
            format!("/api/v1/connections/{connection}/drafts/{draft_id}/send"),
            &credential,
            request.clone(),
        )
        .await;
        assert_eq!(limited, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body["error"]["code"], "rate_limited");
        state.rate_buckets.lock().await.remove(&bucket_key);
        let (sent, body) = json_request(
            &app,
            Method::POST,
            format!("/api/v1/connections/{connection}/drafts/{draft_id}/send"),
            &credential,
            request,
        )
        .await;
        assert_eq!(sent, StatusCode::OK);
        assert_eq!(body["replayed"], false);
    }

    #[tokio::test]
    async fn rest_search_records_metadata_only_audit() {
        let (state, credential, connection, _) = persisted_state().await;
        let repository = state.repository.clone().unwrap();
        let (status, _) = json_request(
            &router(state),
            Method::GET,
            format!("/api/v1/connections/{connection}/messages?q=secret-query"),
            &credential,
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let row = sqlx::query(
            "SELECT user_id,access_key_id,connection_id,operation,result_category,request_id FROM audit_events",
        )
        .fetch_one(repository.pool())
        .await
        .unwrap();
        assert_eq!(row.get::<String, _>("operation"), "messages.search");
        assert_eq!(row.get::<String, _>("result_category"), "ok");
        assert_eq!(
            row.get::<String, _>("connection_id"),
            connection.to_string()
        );
        assert_ne!(row.get::<String, _>("request_id"), "secret-query");
    }
}

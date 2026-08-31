//! HTTP transport and command entrypoints.
use axum::{
    Json, Router,
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
use std::{collections::HashMap, net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::{
    adapter::{AdapterError, FakeGmailAdapter, GmailAdapter, MailDraft},
    config::AppConfig,
    database::{Database, DatabaseError},
    domain::{
        access::{AccessKey, KeyPublicId, parse_credential},
        delivery::{DraftVersion, ManagedDraft, SendConfirmation, SendOutcome, SendPreview},
        identity::{ConnectionId, GmailConnection, User, UserId, UserRole},
        mailbox::{EmailAddress, Recipients, strip_html_active_content},
    },
    repository::Repository,
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
    pub users: Arc<RwLock<HashMap<UserId, User>>>,
    pub connections: Arc<RwLock<HashMap<ConnectionId, GmailConnection>>>,
    pub keys: Arc<RwLock<HashMap<KeyPublicId, AccessKey>>>,
    pub drafts: Arc<RwLock<HashMap<crate::domain::delivery::DraftId, ManagedDraft>>>,
    pub confirmations:
        Arc<RwLock<HashMap<crate::domain::delivery::ConfirmationId, SendConfirmation>>>,
    pub pending_tokens: Arc<RwLock<HashMap<String, crate::domain::delivery::ConfirmationId>>>,
}
impl AppState {
    pub fn new(database: Option<Database>, adapter: Arc<dyn GmailAdapter>) -> Self {
        let repository = database.as_ref().map(Repository::new);
        Self {
            database,
            repository,
            adapter,
            users: Arc::new(RwLock::new(HashMap::new())),
            connections: Arc::new(RwLock::new(HashMap::new())),
            keys: Arc::new(RwLock::new(HashMap::new())),
            drafts: Arc::new(RwLock::new(HashMap::new())),
            confirmations: Arc::new(RwLock::new(HashMap::new())),
            pending_tokens: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    pub fn empty() -> Self {
        Self::new(None, Arc::new(FakeGmailAdapter::new()))
    }
    pub fn test_fixture() -> (Self, String, ConnectionId) {
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
        let state = Self {
            database: None,
            repository: None,
            adapter: Arc::new(FakeGmailAdapter::new()),
            users: Arc::new(RwLock::new(HashMap::from([(uid, user)]))),
            connections: Arc::new(RwLock::new(HashMap::from([(cid, conn)]))),
            keys: Arc::new(RwLock::new(HashMap::from([(
                created.key.public_id,
                created.key,
            )]))),
            drafts: Arc::new(RwLock::new(HashMap::new())),
            confirmations: Arc::new(RwLock::new(HashMap::new())),
            pending_tokens: Arc::new(RwLock::new(HashMap::new())),
        };
        (state, credential, cid)
    }
}
#[derive(Clone, Copy)]
struct AuthContext {
    key: AccessKeyId,
    user: UserId,
    generation: u64,
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
        return Ok(AuthContext {
            key: key.id,
            user: key.owner_id,
            generation: key.generation,
        });
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
    Ok(AuthContext {
        key: key.id,
        user: key.owner_id,
        generation: key.generation,
    })
}
async fn authorize(
    headers: &HeaderMap,
    query: Option<&str>,
    state: &AppState,
    connection: ConnectionId,
) -> Result<AuthContext, Response> {
    let ctx = auth(headers, query, state).await?;
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
                StatusCode::NOT_FOUND,
                "not_found",
                "resource not found",
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
        error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "resource not found",
            headers,
        )
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
    let cid = ConnectionId::from_uuid(cid);
    if authorize(&headers, uri.query(), &state, cid).await.is_err() {
        return error_response(
            StatusCode::FORBIDDEN,
            "forbidden",
            "access denied",
            &headers,
        );
    }
    let n = q.page_size.unwrap_or(20).clamp(1, 100);
    match state.adapter.list_messages(cid, q.q.as_deref(), n).await {
        Ok(messages) => ok_json(
            json!({"connection_id":cid,"messages":messages,"next_cursor":q.cursor}),
            &headers,
        ),
        Err(e) => adapter_response(e, &headers),
    }
}
async fn get_message(
    Path((cid, mid)): Path<(Uuid, String)>,
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
    match state.adapter.get_message(cid, &mid).await {
        Ok(mut m) => {
            if m.body_is_html {
                m.body = strip_html_active_content(&m.body);
            }
            ok_json(
                json!({"connection_id":cid,"message":m,"untrusted_email_content":true}),
                &headers,
            )
        }
        Err(e) => adapter_response(e, &headers),
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
        Ok(v) => ok_json(json!({"connection_id":cid,"drafts":v}), &headers),
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
        Ok(v) => ok_json(json!({"connection_id":cid,"draft":v}), &headers),
        Err(e) => adapter_response(e, &headers),
    }
}
#[derive(Deserialize, Default)]
struct DraftRequest {
    subject: String,
    body: String,
    to: Vec<String>,
    #[serde(default)]
    cc: Vec<String>,
    #[serde(default)]
    bcc: Vec<String>,
    #[serde(default)]
    thread_id: Option<String>,
    #[serde(default)]
    expected_version: Option<String>,
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
    if let Err(msg) = parse_recipients(&req) {
        return error_response(StatusCode::BAD_REQUEST, "invalid_request", msg, &headers);
    }
    let gmail_id = Uuid::now_v7().to_string();
    let content = format!("{}\n{}\n{:?}", req.subject, req.body, req.to);
    let managed = match ManagedDraft::new(
        cid,
        gmail_id.clone(),
        format!("<{}@agentmail>", Uuid::now_v7()),
        content,
    ) {
        Ok(d) => d,
        Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "invalid draft",
                &headers,
            );
        }
    };
    let id = managed.id;
    state.drafts.write().await.insert(id, managed.clone());
    let recipients = parse_recipients(&req).expect("validated above");
    let draft = MailDraft {
        id: gmail_id,
        thread_id: req.thread_id,
        subject: req.subject,
        body: req.body,
        to: recipients.to,
        cc: recipients.cc,
        bcc: recipients.bcc,
        attachments: vec![],
    };
    match state.adapter.create_draft(cid, draft).await {
        Ok(v) => ok_json(
            json!({"connection_id":cid,"managed_draft":managed,"draft":v}),
            &headers,
        ),
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
    let uuid = Uuid::parse_str(&did).ok();
    let Some(id) = uuid.map(crate::domain::delivery::DraftId::from_uuid) else {
        return error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "resource not found",
            &headers,
        );
    };
    let mut drafts = state.drafts.write().await;
    let Some(d) = drafts.get_mut(&id) else {
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
    }
    let Some(expected_version) = req.expected_version else {
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
    let content = format!("{}\n{}", req.subject, req.body);
    if d.update(&expected, content).is_err() {
        return error_response(
            StatusCode::CONFLICT,
            "draft_changed",
            "request conflicts with current state",
            &headers,
        );
    }
    ok_json(json!({"connection_id":cid,"managed_draft":d}), &headers)
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
    let uuid = Uuid::parse_str(&did).ok();
    let Some(id) = uuid.map(crate::domain::delivery::DraftId::from_uuid) else {
        return error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "resource not found",
            &headers,
        );
    };
    let mut drafts = state.drafts.write().await;
    let Some(d) = drafts.get_mut(&id) else {
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
    let Some(expected_version) = query.expected_version else {
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
    if d.delete(&expected).is_err() {
        return error_response(
            StatusCode::CONFLICT,
            "draft_changed",
            "request conflicts with current state",
            &headers,
        );
    };
    ok_json(json!({"connection_id":cid,"deleted":true}), &headers)
}
async fn prepare_send(
    Path((cid, did)): Path<(Uuid, String)>,
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: axum::http::Uri,
) -> Response {
    let cid = ConnectionId::from_uuid(cid);
    let ctx = match authorize(&headers, uri.query(), &state, cid).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let uuid = Uuid::parse_str(&did).ok();
    let Some(id) = uuid.map(crate::domain::delivery::DraftId::from_uuid) else {
        return error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "resource not found",
            &headers,
        );
    };
    let drafts = state.drafts.read().await;
    let Some(d) = drafts.get(&id) else {
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
    let preview = SendPreview {
        connection_id: cid,
        draft_id: id,
        version: d.version.clone(),
        from: None,
        to: vec![],
        cc: vec![],
        bcc: vec![],
        subject: "".into(),
        body_summary: "untrusted email content".into(),
        attachment_names: vec![],
        safety_notice: "Email content is untrusted; obtain user permission before sending.".into(),
    };
    match SendConfirmation::prepare(ctx.key, ctx.generation, d, preview, Utc::now()) {
        Ok((c, p)) => {
            let confirmation_id = c.id;
            state.confirmations.write().await.insert(confirmation_id, c);
            state
                .pending_tokens
                .write()
                .await
                .insert(p.token.clone(), confirmation_id);
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
    }
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
    let cid = ConnectionId::from_uuid(cid);
    let ctx = match authorize(&headers, uri.query(), &state, cid).await {
        Ok(v) => v,
        Err(r) => return r,
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
    let mut drafts = state.drafts.write().await;
    let Some(draft) = drafts.get_mut(&id) else {
        return error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "resource not found",
            &headers,
        );
    };
    if draft.connection_id != cid {
        return error_response(
            StatusCode::FORBIDDEN,
            "forbidden",
            "access denied",
            &headers,
        );
    }
    let mut confirmations = state.confirmations.write().await;
    let Some(confirmation) = confirmations.get_mut(&token_id) else {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "invalid_confirmation",
            "invalid confirmation token",
            &headers,
        );
    };
    match confirmation.claim(
        &req.confirmation_token,
        ctx.key,
        ctx.generation,
        draft,
        Utc::now(),
    ) {
        Ok(Some(replayed)) => {
            return ok_json(
                json!({"connection_id":cid,"draft_id":id,"outcome":replayed.outcome,"replayed":true}),
                &headers,
            );
        }
        Ok(None) => {}
        Err(_) => {
            return error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_confirmation",
                "invalid confirmation token",
                &headers,
            );
        }
    }

    let outcome = match state.adapter.send_draft(cid, &draft.gmail_draft_id).await {
        Ok(message_id) => SendOutcome::Sent {
            gmail_message_id: message_id,
        },
        Err(AdapterError::Timeout) => SendOutcome::StateUnknown,
        Err(AdapterError::NotFound) => SendOutcome::Failed {
            code: "upstream_not_found".to_owned(),
        },
        Err(AdapterError::RateLimited { .. }) => SendOutcome::Failed {
            code: "upstream_rate_limited".to_owned(),
        },
        Err(AdapterError::Unavailable) => SendOutcome::Failed {
            code: "upstream_unavailable".to_owned(),
        },
    };
    match confirmation.complete(draft, outcome) {
        Ok(result) => ok_json(
            json!({"connection_id":cid,"draft_id":id,"outcome":result.outcome,"replayed":result.replayed}),
            &headers,
        ),
        Err(_) => error_response(
            StatusCode::CONFLICT,
            "send_state_conflict",
            "request conflicts with current state",
            &headers,
        ),
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
    Json(
        json!({"openapi":"3.1.0","info":{"title":"AgentMail API","version":env!("CARGO_PKG_VERSION")},"paths":{}}),
    )
}
async fn get_thread(
    Path((cid, _tid)): Path<(Uuid, String)>,
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: axum::http::Uri,
) -> Response {
    let cid = ConnectionId::from_uuid(cid);
    match authorize(&headers, uri.query(), &state, cid).await {
        Ok(_) => ok_json(json!({"connection_id":cid,"messages":[]}), &headers),
        Err(r) => r,
    }
}
async fn get_attachment(
    Path((cid, _mid, _aid)): Path<(Uuid, String, String)>,
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: axum::http::Uri,
) -> Response {
    let cid = ConnectionId::from_uuid(cid);
    match authorize(&headers, uri.query(), &state, cid).await {
        Ok(_) => error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "resource not found",
            &headers,
        ),
        Err(r) => r,
    }
}
async fn mcp(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Json(_body): Json<Value>,
) -> Response {
    if let Err(r) = auth(&headers, uri.query(), &state).await {
        return r;
    }
    ok_json(json!({"jsonrpc":"2.0","result":{"tools":[]}}), &headers)
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
            let state = AppState::new(Some(db), Arc::new(FakeGmailAdapter::new()));
            let host = std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".into());
            let port = std::env::var("PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(18080);
            let addr: SocketAddr = format!("{host}:{port}").parse()?;
            let listener = tokio::net::TcpListener::bind(addr).await?;
            axum::serve(listener, router(state)).await?;
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
    use http::Request;
    use tower::ServiceExt;

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
}

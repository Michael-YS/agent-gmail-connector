//! Owner and Member control-plane HTML pages.
//!
//! These handlers complement the JSON control-plane API in [`crate::control_http`].
//! They share the same session model and CSRF token, and enforce each route's role, but
//! additionally:
//!
//! - render Askama templates with strict CSP and no external assets,
//! - read the CSRF plaintext from a dedicated `__Host-agentmail_csrf` cookie,
//! - redirect browser users to `/auth/google/login` on session failure instead
//!   of returning JSON error bodies.
//!
//! Account pages show the signed-in user's address and explicitly requested
//! one-time credentials. Other tokens, subjects, message bodies, attachment data,
//! and mailbox query strings are never rendered. Templates rely on Askama's default
//! HTML escaping for every user-controlled field.
#![allow(dead_code, clippy::result_large_err)]

use askama::Template;
use axum::{
    Router,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware,
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    control_http::{
        ControlHttpState, GmailStartQuery, OAuthCodeExchanger, OidcTokenVerifier, SessionContext,
        cookie_value, gmail_start, revoke_connection_account, revoke_member_account,
    },
    control_plane::SessionCookiePolicy,
    domain::access::{AccessKey, AccessKeyId},
    domain::identity::{ConnectionStatus, InvitationId, User, UserRole, UserStatus},
    invitations::{InviteError, InviteService},
    repository::RepositoryError,
};

pub const CSRF_COOKIE: &str = "__Host-agentmail_csrf";
const CSRF_COOKIE_MAX_AGE: i64 = 60 * 60 * 24;
const FLASH_COOKIE: &str = "__Host-agentmail_flash";
const FLASH_COOKIE_MAX_AGE: i64 = 60;
const MAX_FORM_BYTES: usize = 4 * 1024;
const MAX_TARGET_EMAIL_BYTES: usize = 254;

#[derive(Template)]
#[template(path = "owner/dashboard.html")]
struct OwnerDashboardTemplate<'a> {
    show_dashboard: bool,
    show_invitations: bool,
    show_members: bool,
    show_capacity: bool,
    session_email_is_some: bool,
    session_email: &'a str,
    csrf: &'a str,
    current_member_count: u32,
    historical_authorization_count: u32,
    remaining_capacity: u32,
    configured_limit: u32,
    flash_is_some: bool,
    flash_token_is_some: bool,
    flash_css_class: &'a str,
    flash_label: &'a str,
    flash_token: &'a str,
    flash_message: &'a str,
}

#[derive(Template)]
#[template(path = "owner/invitations.html")]
struct InvitationsTemplate<'a> {
    show_dashboard: bool,
    show_invitations: bool,
    show_members: bool,
    show_capacity: bool,
    session_email_is_some: bool,
    session_email: &'a str,
    csrf: &'a str,
    invitations: Vec<InvitationRow>,
    invitations_empty: bool,
    preset_email: &'a str,
    flash_is_some: bool,
    flash_token_is_some: bool,
    flash_css_class: &'a str,
    flash_label: &'a str,
    flash_token: &'a str,
    flash_message: &'a str,
}

struct InvitationRow {
    id: Uuid,
    target_email: String,
    expires_at: String,
    has_accepted_at: bool,
    accepted_at_display: String,
    status_label: String,
    is_pending: bool,
}

#[derive(Template)]
#[template(path = "owner/members.html")]
struct MembersTemplate<'a> {
    show_dashboard: bool,
    show_invitations: bool,
    show_members: bool,
    show_capacity: bool,
    session_email_is_some: bool,
    session_email: &'a str,
    csrf: &'a str,
    members: Vec<MemberRow>,
    members_empty: bool,
    flash_is_some: bool,
    flash_token_is_some: bool,
    flash_css_class: &'a str,
    flash_label: &'a str,
    flash_token: &'a str,
    flash_message: &'a str,
}

struct MemberRow {
    id: Uuid,
    email: String,
    status: String,
    connection_count: u32,
    access_key_count: u32,
    last_activity: String,
    is_revoking: bool,
    can_revoke: bool,
}

#[derive(Template)]
#[template(path = "owner/capacity.html")]
struct CapacityTemplate<'a> {
    show_dashboard: bool,
    show_invitations: bool,
    show_members: bool,
    show_capacity: bool,
    session_email_is_some: bool,
    session_email: &'a str,
    csrf: &'a str,
    current_member_count: u32,
    historical_authorization_count: u32,
    remaining_capacity: u32,
    configured_limit: u32,
    flash_is_some: bool,
    flash_token_is_some: bool,
    flash_css_class: &'a str,
    flash_label: &'a str,
    flash_token: &'a str,
    flash_message: &'a str,
}

#[derive(Template)]
#[template(path = "member/account.html")]
struct AccountTemplate<'a> {
    show_dashboard: bool,
    show_invitations: bool,
    show_members: bool,
    show_capacity: bool,
    session_email_is_some: bool,
    session_email: &'a str,
    csrf: &'a str,
    connections: Vec<AccountConnectionRow>,
    connections_empty: bool,
    active_connections: Vec<AccountConnectionChoice>,
    access_keys: Vec<AccountKeyRow>,
    access_keys_empty: bool,
    may_delete_account: bool,
    flash_is_some: bool,
    flash_token_is_some: bool,
    flash_css_class: &'a str,
    flash_label: &'a str,
    flash_token: &'a str,
    flash_message: &'a str,
}

struct AccountConnectionRow {
    id: Uuid,
    email: String,
    status: String,
    scopes: String,
    last_used: String,
    can_revoke: bool,
    can_reauthorize: bool,
}

#[derive(Clone)]
struct AccountConnectionChoice {
    id: Uuid,
    email: String,
    checked: bool,
}

struct AccountKeyRow {
    id: Uuid,
    name: String,
    public_prefix: String,
    status: String,
    last_used: String,
    active: bool,
    connections: Vec<AccountConnectionChoice>,
}

#[derive(Debug, Deserialize)]
struct CreateInvitationForm {
    target_email: String,
    _csrf: String,
}

#[derive(Debug, Deserialize, Default)]
struct CsrfOnlyForm {
    _csrf: String,
}

#[derive(Debug, Deserialize)]
struct CreateAccessKeyForm {
    name: String,
    #[serde(default)]
    connection_ids: Vec<Uuid>,
    _csrf: String,
}

#[derive(Debug, Deserialize)]
struct ReplaceAccessKeyGrantsForm {
    #[serde(default)]
    connection_ids: Vec<Uuid>,
    _csrf: String,
}

pub fn router<V, E>(state: ControlHttpState<V, E>) -> Router
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    Router::new()
        .route("/control", get(dashboard::<V, E>))
        .route(
            "/control/invitations",
            get(invitations_page::<V, E>).post(create_invitation::<V, E>),
        )
        .route(
            "/control/invitations/{id}/revoke",
            post(revoke_invitation::<V, E>),
        )
        .route(
            "/control/invitations/{id}/regenerate",
            post(regenerate_invitation::<V, E>),
        )
        .route("/control/members", get(members_page::<V, E>))
        .route("/control/members/{id}/revoke", post(revoke_member::<V, E>))
        .route("/control/capacity", get(capacity_page::<V, E>))
        .route("/control/account", get(account_page::<V, E>))
        .route("/control/account/delete", post(delete_own_account::<V, E>))
        .route(
            "/control/account/connections/{id}/revoke",
            post(revoke_own_connection::<V, E>),
        )
        .route(
            "/control/account/connections/new",
            post(start_gmail_connection::<V, E>),
        )
        .route(
            "/control/account/connections/{id}/reauthorize",
            post(reauthorize_gmail_connection::<V, E>),
        )
        .route(
            "/control/account/access-keys",
            post(create_own_access_key::<V, E>),
        )
        .route(
            "/control/account/access-keys/{id}/rotate",
            post(rotate_own_access_key::<V, E>),
        )
        .route(
            "/control/account/access-keys/{id}/revoke",
            post(revoke_own_access_key::<V, E>),
        )
        .route(
            "/control/account/access-keys/{id}/grants",
            post(replace_own_access_key_grants::<V, E>),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            crate::control_http::control_audit_middleware::<V, E>,
        ))
        .with_state(state)
}

struct FlashParts {
    css_class: &'static str,
    label: &'static str,
    token: Option<String>,
    message: Option<&'static str>,
}

struct FlashView {
    is_some: bool,
    token_is_some: bool,
    css_class: &'static str,
    label: &'static str,
    token: String,
    message: &'static str,
}

fn flash_view(flash: Option<FlashParts>) -> FlashView {
    let Some(flash) = flash else {
        return FlashView {
            is_some: false,
            token_is_some: false,
            css_class: "",
            label: "",
            token: String::new(),
            message: "",
        };
    };
    FlashView {
        is_some: true,
        token_is_some: flash.token.is_some(),
        css_class: flash.css_class,
        label: flash.label,
        token: flash.token.unwrap_or_default(),
        message: flash.message.unwrap_or_default(),
    }
}

async fn dashboard<V, E>(
    State(state): State<ControlHttpState<V, E>>,
    headers: HeaderMap,
) -> Response
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let (user, _session) = match load_owner_session(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let csrf = match csrf_cookie(&headers) {
        Ok(token) => token,
        Err(response) => return response,
    };
    let summary = match state
        .repository
        .personal_use_summary(state.config.personal_use_user_limit)
        .await
    {
        Ok(summary) => summary,
        Err(error) => return server_error(error),
    };
    let flash = match take_flash(&headers) {
        Ok(flash) => flash_view(flash),
        Err(response) => return response,
    };
    let mut response = render(OwnerDashboardTemplate {
        show_dashboard: true,
        show_invitations: true,
        show_members: true,
        show_capacity: true,
        session_email_is_some: true,
        session_email: &user.email,
        csrf: &csrf,
        current_member_count: summary.current_member_count,
        historical_authorization_count: summary.historical_authorization_count,
        remaining_capacity: summary.remaining_capacity,
        configured_limit: u32::from(state.config.personal_use_user_limit),
        flash_is_some: flash.is_some,
        flash_token_is_some: flash.token_is_some,
        flash_css_class: flash.css_class,
        flash_label: flash.label,
        flash_token: &flash.token,
        flash_message: flash.message,
    });
    append_clear_flash_cookie(&mut response);
    response
}

async fn invitations_page<V, E>(
    State(state): State<ControlHttpState<V, E>>,
    headers: HeaderMap,
) -> Response
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let (user, session) = match load_owner_session(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let csrf = match csrf_cookie(&headers) {
        Ok(token) => token,
        Err(response) => return response,
    };
    let invitations = match state.repository.list_invitations(session.user_id).await {
        Ok(list) => list,
        Err(error) => return server_error(error),
    };
    let now = Utc::now();
    let rows: Vec<InvitationRow> = invitations
        .into_iter()
        .map(|invitation| {
            let accepted_at = invitation.accepted_at;
            InvitationRow {
                id: invitation.id.into_uuid(),
                target_email: invitation.target_email,
                expires_at: format_rfc3339(invitation.expires_at),
                has_accepted_at: accepted_at.is_some(),
                accepted_at_display: accepted_at.map(format_rfc3339).unwrap_or_default(),
                status_label: invitation_status_label(accepted_at, invitation.expires_at, now),
                is_pending: accepted_at.is_none() && invitation.expires_at > now,
            }
        })
        .collect();
    let invitations_empty = rows.is_empty();
    let flash = match take_flash(&headers) {
        Ok(flash) => flash_view(flash),
        Err(response) => return response,
    };
    let mut response = render(InvitationsTemplate {
        show_dashboard: true,
        show_invitations: true,
        show_members: true,
        show_capacity: true,
        session_email_is_some: true,
        session_email: &user.email,
        csrf: &csrf,
        invitations_empty,
        invitations: rows,
        preset_email: "",
        flash_is_some: flash.is_some,
        flash_token_is_some: flash.token_is_some,
        flash_css_class: flash.css_class,
        flash_label: flash.label,
        flash_token: &flash.token,
        flash_message: flash.message,
    });
    append_clear_flash_cookie(&mut response);
    response
}

async fn create_invitation<V, E>(
    State(state): State<ControlHttpState<V, E>>,
    headers: HeaderMap,
    body: String,
) -> Response
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let (_user, _session) = match load_owner_session(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if body.len() > MAX_FORM_BYTES {
        return redirect_flash("/control/invitations", ("invalid_request", None));
    }
    let form: CreateInvitationForm = match serde_urlencoded::from_str(&body) {
        Ok(form) => form,
        Err(_) => return redirect_flash("/control/invitations", ("invalid_request", None)),
    };
    if let Err(response) = require_csrf(&state, &_session, &form._csrf) {
        return response;
    }
    let target_email = form.target_email.trim().to_owned();
    if target_email.is_empty() || target_email.len() > MAX_TARGET_EMAIL_BYTES {
        return redirect_flash("/control/invitations", ("invalid_request", None));
    }
    let owner = match state.repository.get_user(_session.user_id).await {
        Ok(Some(user)) => user,
        _ => return redirect_to_login(),
    };
    let issued = match InviteService::new(state.repository.clone())
        .issue(&owner, &target_email, Utc::now())
        .await
    {
        Ok(issued) => issued,
        Err(InviteError::InvalidLifetime)
        | Err(InviteError::Repository(RepositoryError::InvalidValue(_))) => {
            return redirect_flash("/control/invitations", ("invalid_request", None));
        }
        Err(InviteError::NotClaimable) => {
            return redirect_flash("/control/invitations", ("invalid_state", None));
        }
        Err(InviteError::Repository(error)) => return server_error(error),
    };
    let token = issued.token.as_str().to_owned();
    redirect_flash("/control/invitations", ("created", Some(token)))
}

async fn revoke_invitation<V, E>(
    State(state): State<ControlHttpState<V, E>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    body: String,
) -> Response
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let (_user, _session) = match load_owner_session(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if body.len() > MAX_FORM_BYTES {
        return redirect_flash("/control/invitations", ("invalid_request", None));
    }
    let form: CsrfOnlyForm = match serde_urlencoded::from_str(&body) {
        Ok(form) => form,
        Err(_) => return redirect_flash("/control/invitations", ("invalid_request", None)),
    };
    if let Err(response) = require_csrf(&state, &_session, &form._csrf) {
        return response;
    }
    let result = state
        .repository
        .revoke_invitation(_session.user_id, InvitationId::from_uuid(id))
        .await;
    match result {
        Ok(true) => redirect_flash("/control/invitations", ("revoked", None)),
        Ok(false) => redirect_flash("/control/invitations", ("not_found", None)),
        Err(error) => server_error(error),
    }
}

async fn regenerate_invitation<V, E>(
    State(state): State<ControlHttpState<V, E>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    body: String,
) -> Response
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let (owner, _session) = match load_owner_session(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if body.len() > MAX_FORM_BYTES {
        return redirect_flash("/control/invitations", ("invalid_request", None));
    }
    let form: CsrfOnlyForm = match serde_urlencoded::from_str(&body) {
        Ok(form) => form,
        Err(_) => return redirect_flash("/control/invitations", ("invalid_request", None)),
    };
    if let Err(response) = require_csrf(&state, &_session, &form._csrf) {
        return response;
    }
    let invitation_id = InvitationId::from_uuid(id);
    let existing = match state.repository.list_invitations(_session.user_id).await {
        Ok(list) => list
            .into_iter()
            .find(|invitation| invitation.id == invitation_id && invitation.accepted_at.is_none()),
        Err(error) => return server_error(error),
    };
    let Some(existing) = existing else {
        return redirect_flash("/control/invitations", ("not_found", None));
    };
    match state
        .repository
        .revoke_invitation(_session.user_id, invitation_id)
        .await
    {
        Ok(true) => {}
        Ok(false) => return redirect_flash("/control/invitations", ("not_found", None)),
        Err(error) => return server_error(error),
    }
    let issued = match InviteService::new(state.repository.clone())
        .issue(&owner, &existing.target_email, Utc::now())
        .await
    {
        Ok(issued) => issued,
        Err(InviteError::InvalidLifetime)
        | Err(InviteError::Repository(RepositoryError::InvalidValue(_))) => {
            return redirect_flash("/control/invitations", ("invalid_request", None));
        }
        Err(InviteError::NotClaimable) => {
            return redirect_flash("/control/invitations", ("invalid_state", None));
        }
        Err(InviteError::Repository(error)) => return server_error(error),
    };
    let token = issued.token.as_str().to_owned();
    redirect_flash("/control/invitations", ("regenerated", Some(token)))
}

async fn members_page<V, E>(
    State(state): State<ControlHttpState<V, E>>,
    headers: HeaderMap,
) -> Response
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let (user, _session) = match load_owner_session(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let csrf = match csrf_cookie(&headers) {
        Ok(token) => token,
        Err(response) => return response,
    };
    let members = match state.repository.list_member_summaries().await {
        Ok(list) => list,
        Err(error) => return server_error(error),
    };
    let rows: Vec<MemberRow> = members
        .into_iter()
        .map(|member| MemberRow {
            id: member.id.into_uuid(),
            email: member.email,
            status: user_status_label(&member.status).to_owned(),
            connection_count: member.connection_count,
            access_key_count: member.access_key_count,
            last_activity: member
                .last_activity_at
                .map(format_rfc3339)
                .unwrap_or_else(|| "—".to_owned()),
            is_revoking: matches!(member.status, UserStatus::Revoking),
            can_revoke: matches!(member.status, UserStatus::Active),
        })
        .collect();
    let members_empty = rows.is_empty();
    let flash = match take_flash(&headers) {
        Ok(flash) => flash_view(flash),
        Err(response) => return response,
    };
    let mut response = render(MembersTemplate {
        show_dashboard: true,
        show_invitations: true,
        show_members: true,
        show_capacity: true,
        session_email_is_some: true,
        session_email: &user.email,
        csrf: &csrf,
        members_empty,
        members: rows,
        flash_is_some: flash.is_some,
        flash_token_is_some: flash.token_is_some,
        flash_css_class: flash.css_class,
        flash_label: flash.label,
        flash_token: &flash.token,
        flash_message: flash.message,
    });
    append_clear_flash_cookie(&mut response);
    response
}

async fn revoke_member<V, E>(
    State(state): State<ControlHttpState<V, E>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    body: String,
) -> Response
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let (_owner, session) = match load_owner_session(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if body.len() > MAX_FORM_BYTES {
        return redirect_flash("/control/members", ("invalid_request", None));
    }
    let form: CsrfOnlyForm = match serde_urlencoded::from_str(&body) {
        Ok(form) => form,
        Err(_) => return redirect_flash("/control/members", ("invalid_request", None)),
    };
    if let Err(response) = require_csrf(&state, &session, &form._csrf) {
        return response;
    }
    let state_for_task = state.clone();
    let target = crate::domain::identity::UserId::from_uuid(id);
    let operation = tokio::spawn(async move {
        revoke_member_account(&state_for_task, session.user_id, target).await
    });
    match operation.await {
        Ok(Ok(Some(_))) => redirect_flash("/control/members", ("member_revoked", None)),
        Ok(Ok(None)) => redirect_flash("/control/members", ("not_found", None)),
        Ok(Err(error)) => server_error(error),
        Err(_) => server_error(RepositoryError::Conflict),
    }
}

async fn capacity_page<V, E>(
    State(state): State<ControlHttpState<V, E>>,
    headers: HeaderMap,
) -> Response
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let (user, _session) = match load_owner_session(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let csrf = match csrf_cookie(&headers) {
        Ok(token) => token,
        Err(response) => return response,
    };
    let summary = match state
        .repository
        .personal_use_summary(state.config.personal_use_user_limit)
        .await
    {
        Ok(summary) => summary,
        Err(error) => return server_error(error),
    };
    let flash = match take_flash(&headers) {
        Ok(flash) => flash_view(flash),
        Err(response) => return response,
    };
    let mut response = render(CapacityTemplate {
        show_dashboard: true,
        show_invitations: true,
        show_members: true,
        show_capacity: true,
        session_email_is_some: true,
        session_email: &user.email,
        csrf: &csrf,
        current_member_count: summary.current_member_count,
        historical_authorization_count: summary.historical_authorization_count,
        remaining_capacity: summary.remaining_capacity,
        configured_limit: u32::from(state.config.personal_use_user_limit),
        flash_is_some: flash.is_some,
        flash_token_is_some: flash.token_is_some,
        flash_css_class: flash.css_class,
        flash_label: flash.label,
        flash_token: &flash.token,
        flash_message: flash.message,
    });
    append_clear_flash_cookie(&mut response);
    response
}

async fn account_page<V, E>(
    State(state): State<ControlHttpState<V, E>>,
    headers: HeaderMap,
) -> Response
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let (user, _session) = match load_session(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let csrf = match csrf_cookie(&headers) {
        Ok(token) => token,
        Err(response) => return response,
    };
    let raw_connections = match state.repository.list_connections_for_user(user.id).await {
        Ok(connections) => connections,
        Err(error) => return server_error(error),
    };
    let connections = raw_connections
        .iter()
        .map(|connection| AccountConnectionRow {
            id: connection.id.into_uuid(),
            email: connection.email.clone(),
            status: connection_status_label(connection.status).to_owned(),
            scopes: connection.granted_scopes.join(", "),
            last_used: connection
                .last_used_at
                .map(format_rfc3339)
                .unwrap_or_else(|| "—".to_owned()),
            can_revoke: !matches!(connection.status, ConnectionStatus::Revoking),
            can_reauthorize: matches!(connection.status, ConnectionStatus::ReauthRequired),
        })
        .collect::<Vec<_>>();
    let connections_empty = connections.is_empty();
    let active_connections = raw_connections
        .iter()
        .filter(|connection| connection.status == ConnectionStatus::Active)
        .map(|connection| AccountConnectionChoice {
            id: connection.id.into_uuid(),
            email: connection.email.clone(),
            checked: false,
        })
        .collect::<Vec<_>>();
    let access_keys = match state.repository.list_access_keys(user.id).await {
        Ok(keys) => keys
            .into_iter()
            .map(|key| AccountKeyRow {
                id: key.id.into_uuid(),
                name: key.name,
                public_prefix: key.public_prefix,
                status: if key.status.accepts_requests() {
                    "Active".to_owned()
                } else {
                    "Revoked".to_owned()
                },
                last_used: key
                    .last_used_at
                    .map(format_rfc3339)
                    .unwrap_or_else(|| "—".to_owned()),
                active: key.status.accepts_requests(),
                connections: active_connections
                    .iter()
                    .map(|connection| AccountConnectionChoice {
                        id: connection.id,
                        email: connection.email.clone(),
                        checked: key.grants.contains(
                            crate::domain::identity::ConnectionId::from_uuid(connection.id),
                        ),
                    })
                    .collect(),
            })
            .collect::<Vec<_>>(),
        Err(error) => return server_error(error),
    };
    let access_keys_empty = access_keys.is_empty();
    let flash = match take_flash(&headers) {
        Ok(flash) => flash_view(flash),
        Err(response) => return response,
    };
    let is_owner = user.role == UserRole::Owner;
    let mut response = render(AccountTemplate {
        show_dashboard: is_owner,
        show_invitations: is_owner,
        show_members: is_owner,
        show_capacity: is_owner,
        session_email_is_some: true,
        session_email: &user.email,
        csrf: &csrf,
        connections_empty,
        connections,
        active_connections,
        access_keys_empty,
        access_keys,
        may_delete_account: !is_owner,
        flash_is_some: flash.is_some,
        flash_token_is_some: flash.token_is_some,
        flash_css_class: flash.css_class,
        flash_label: flash.label,
        flash_token: &flash.token,
        flash_message: flash.message,
    });
    append_clear_flash_cookie(&mut response);
    response
}

async fn revoke_own_connection<V, E>(
    State(state): State<ControlHttpState<V, E>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    body: String,
) -> Response
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let (_user, session) = match load_session(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let form = match csrf_form(&body) {
        Ok(form) => form,
        Err(()) => return redirect_flash("/control/account", ("invalid_request", None)),
    };
    if let Err(response) = require_csrf(&state, &session, &form._csrf) {
        return response;
    }
    let state_for_task = state.clone();
    let connection_id = crate::domain::identity::ConnectionId::from_uuid(id);
    let operation = tokio::spawn(async move {
        revoke_connection_account(&state_for_task, session.user_id, connection_id).await
    });
    match operation.await {
        Ok(Ok(Some(_))) => redirect_flash("/control/account", ("connection_revoked", None)),
        Ok(Ok(None)) => redirect_flash("/control/account", ("not_found", None)),
        Ok(Err(error)) => server_error(error),
        Err(_) => server_error(RepositoryError::Conflict),
    }
}

async fn start_gmail_connection<V, E>(
    State(state): State<ControlHttpState<V, E>>,
    headers: HeaderMap,
    body: String,
) -> Response
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    gmail_form_start(state, headers, body, None).await
}

async fn reauthorize_gmail_connection<V, E>(
    State(state): State<ControlHttpState<V, E>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    body: String,
) -> Response
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    gmail_form_start(state, headers, body, Some(id)).await
}

async fn gmail_form_start<V, E>(
    state: ControlHttpState<V, E>,
    mut headers: HeaderMap,
    body: String,
    connection_id: Option<Uuid>,
) -> Response
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let form = match csrf_form(&body) {
        Ok(form) => form,
        Err(()) => return redirect_flash("/control/account", ("invalid_request", None)),
    };
    let csrf = match HeaderValue::from_str(&form._csrf) {
        Ok(value) => value,
        Err(_) => return redirect_flash("/control/account", ("invalid_request", None)),
    };
    headers.insert("x-csrf-token", csrf);
    gmail_start(
        State(state),
        Query(GmailStartQuery { connection_id }),
        headers,
    )
    .await
}

async fn create_own_access_key<V, E>(
    State(state): State<ControlHttpState<V, E>>,
    headers: HeaderMap,
    body: String,
) -> Response
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let (_user, session) = match load_session(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if body.len() > MAX_FORM_BYTES {
        return redirect_flash("/control/account", ("invalid_request", None));
    }
    let form = match parse_create_access_key_form(&body) {
        Ok(form) => form,
        Err(_) => return redirect_flash("/control/account", ("invalid_request", None)),
    };
    if let Err(response) = require_csrf(&state, &session, &form._csrf) {
        return response;
    }
    let connections = form
        .connection_ids
        .into_iter()
        .map(crate::domain::identity::ConnectionId::from_uuid)
        .collect::<Vec<_>>();
    let generated = match AccessKey::generate(session.user_id, form.name, connections) {
        Ok(generated) => generated,
        Err(_) => return redirect_flash("/control/account", ("invalid_request", None)),
    };
    let credential = generated.credential.clone();
    match state.repository.insert_access_key(&generated).await {
        Ok(_) => redirect_flash("/control/account", ("key_created", Some(credential))),
        Err(RepositoryError::InvalidValue(_)) => {
            redirect_flash("/control/account", ("invalid_request", None))
        }
        Err(error) => server_error(error),
    }
}

async fn rotate_own_access_key<V, E>(
    State(state): State<ControlHttpState<V, E>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    body: String,
) -> Response
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let (_user, session) = match load_session(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let form = match csrf_form(&body) {
        Ok(form) => form,
        Err(()) => return redirect_flash("/control/account", ("invalid_request", None)),
    };
    if let Err(response) = require_csrf(&state, &session, &form._csrf) {
        return response;
    }
    match state
        .repository
        .rotate_access_key(session.user_id, AccessKeyId::from_uuid(id))
        .await
    {
        Ok(Some(rotated)) => redirect_flash(
            "/control/account",
            ("key_rotated", Some(rotated.credential)),
        ),
        Ok(None) => redirect_flash("/control/account", ("not_found", None)),
        Err(RepositoryError::Conflict) => {
            redirect_flash("/control/account", ("invalid_state", None))
        }
        Err(error) => server_error(error),
    }
}

async fn revoke_own_access_key<V, E>(
    State(state): State<ControlHttpState<V, E>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    body: String,
) -> Response
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let (_user, session) = match load_session(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let form = match csrf_form(&body) {
        Ok(form) => form,
        Err(()) => return redirect_flash("/control/account", ("invalid_request", None)),
    };
    if let Err(response) = require_csrf(&state, &session, &form._csrf) {
        return response;
    }
    let key_id = AccessKeyId::from_uuid(id);
    match state
        .repository
        .get_access_key(session.user_id, key_id)
        .await
    {
        Ok(Some(key)) if key.status.accepts_requests() => {
            match state
                .repository
                .revoke_access_key(session.user_id, key_id)
                .await
            {
                Ok(true) => redirect_flash("/control/account", ("key_revoked", None)),
                Ok(false) => redirect_flash("/control/account", ("not_found", None)),
                Err(error) => server_error(error),
            }
        }
        Ok(Some(_)) => redirect_flash("/control/account", ("key_revoked", None)),
        Ok(None) => redirect_flash("/control/account", ("not_found", None)),
        Err(error) => server_error(error),
    }
}

async fn replace_own_access_key_grants<V, E>(
    State(state): State<ControlHttpState<V, E>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    body: String,
) -> Response
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let (_user, session) = match load_session(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if body.len() > MAX_FORM_BYTES {
        return redirect_flash("/control/account", ("invalid_request", None));
    }
    let form = match parse_replace_access_key_grants_form(&body) {
        Ok(form) => form,
        Err(_) => return redirect_flash("/control/account", ("invalid_request", None)),
    };
    if let Err(response) = require_csrf(&state, &session, &form._csrf) {
        return response;
    }
    let connections = form
        .connection_ids
        .into_iter()
        .map(crate::domain::identity::ConnectionId::from_uuid)
        .collect::<Vec<_>>();
    match state
        .repository
        .replace_access_key_grants(session.user_id, AccessKeyId::from_uuid(id), &connections)
        .await
    {
        Ok(true) => redirect_flash("/control/account", ("grants_updated", None)),
        Ok(false) => redirect_flash("/control/account", ("not_found", None)),
        Err(RepositoryError::InvalidValue(_)) => {
            redirect_flash("/control/account", ("invalid_request", None))
        }
        Err(error) => server_error(error),
    }
}

async fn delete_own_account<V, E>(
    State(state): State<ControlHttpState<V, E>>,
    headers: HeaderMap,
    body: String,
) -> Response
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let (user, session) = match load_session(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if user.role == UserRole::Owner {
        return redirect_flash("/control/account", ("owner_delete_forbidden", None));
    }
    let form = match csrf_form(&body) {
        Ok(form) => form,
        Err(()) => return redirect_flash("/control/account", ("invalid_request", None)),
    };
    if let Err(response) = require_csrf(&state, &session, &form._csrf) {
        return response;
    }
    let state_for_task = state.clone();
    let operation = tokio::spawn(async move {
        revoke_member_account(&state_for_task, session.user_id, session.user_id).await
    });
    match operation.await {
        Ok(Ok(Some(_))) => {
            let mut response = Redirect::to("/").into_response();
            clear_auth_cookies(&mut response);
            response
        }
        Ok(Ok(None)) => redirect_flash("/control/account", ("owner_delete_forbidden", None)),
        Ok(Err(error)) => server_error(error),
        Err(_) => server_error(RepositoryError::Conflict),
    }
}

fn csrf_form(body: &str) -> Result<CsrfOnlyForm, ()> {
    if body.len() > MAX_FORM_BYTES {
        return Err(());
    }
    serde_urlencoded::from_str(body).map_err(|_| ())
}

fn parse_create_access_key_form(body: &str) -> Result<CreateAccessKeyForm, ()> {
    if body.len() > MAX_FORM_BYTES {
        return Err(());
    }
    let mut name = None;
    let mut csrf = None;
    let mut connection_ids = Vec::new();
    for (key, value) in url::form_urlencoded::parse(body.as_bytes()) {
        match key.as_ref() {
            "name" if name.is_none() => name = Some(value.into_owned()),
            "_csrf" if csrf.is_none() => csrf = Some(value.into_owned()),
            "connection_ids" => connection_ids.push(value.parse::<Uuid>().map_err(|_| ())?),
            _ => return Err(()),
        }
    }
    Ok(CreateAccessKeyForm {
        name: name.ok_or(())?,
        connection_ids,
        _csrf: csrf.ok_or(())?,
    })
}

fn parse_replace_access_key_grants_form(body: &str) -> Result<ReplaceAccessKeyGrantsForm, ()> {
    if body.len() > MAX_FORM_BYTES {
        return Err(());
    }
    let mut csrf = None;
    let mut connection_ids = Vec::new();
    for (key, value) in url::form_urlencoded::parse(body.as_bytes()) {
        match key.as_ref() {
            "_csrf" if csrf.is_none() => csrf = Some(value.into_owned()),
            "connection_ids" => connection_ids.push(value.parse::<Uuid>().map_err(|_| ())?),
            _ => return Err(()),
        }
    }
    Ok(ReplaceAccessKeyGrantsForm {
        connection_ids,
        _csrf: csrf.ok_or(())?,
    })
}

async fn load_session<V, E>(
    state: &ControlHttpState<V, E>,
    headers: &HeaderMap,
) -> Result<(User, SessionContext), Response>
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let token_hash = session_token_hash_from_headers(headers).map_err(|_| redirect_to_login())?;
    let session = state
        .control_plane
        .authenticate_session(&token_hash, Utc::now())
        .await
        .map_err(|_| redirect_to_login())?;
    let user = state
        .repository
        .get_user(session.user_id)
        .await
        .map_err(server_error)?
        .filter(|user| user.status.accepts_requests())
        .ok_or_else(redirect_to_login)?;
    Ok((
        user,
        SessionContext {
            user_id: session.user_id,
            token_hash,
            csrf_token_hash: session.csrf_token_hash,
        },
    ))
}

fn clear_auth_cookies(response: &mut Response) {
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&clear_session_cookie()).expect("fixed cookie attributes"),
    );
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&csrf_cookie_clear()).expect("fixed cookie attributes"),
    );
}

async fn load_owner_session<V, E>(
    state: &ControlHttpState<V, E>,
    headers: &HeaderMap,
) -> Result<(User, SessionContext), Response>
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    let token_hash = match session_token_hash_from_headers(headers) {
        Ok(hash) => hash,
        Err(_) => return Err(redirect_to_login()),
    };
    let session = state
        .control_plane
        .authenticate_session(&token_hash, Utc::now())
        .await
        .map_err(|_| redirect_to_login())?;
    let user = state
        .repository
        .get_user(session.user_id)
        .await
        .map_err(server_error)?
        .ok_or_else(redirect_to_login)?;
    if user.role != UserRole::Owner || !user.status.accepts_requests() {
        return Err(redirect_to_login());
    }
    Ok((
        user,
        SessionContext {
            user_id: session.user_id,
            token_hash,
            csrf_token_hash: session.csrf_token_hash,
        },
    ))
}

fn session_token_hash_from_headers(headers: &HeaderMap) -> Result<String, ()> {
    let policy = SessionCookiePolicy::default();
    let token = cookie_value(headers, policy.name).ok_or(())?;
    if token.trim().is_empty() {
        return Err(());
    }
    Ok(crate::crypto::hash_token(token))
}

fn require_csrf<V, E>(
    state: &ControlHttpState<V, E>,
    session: &SessionContext,
    presented: &str,
) -> Result<(), Response>
where
    V: OidcTokenVerifier,
    E: OAuthCodeExchanger,
{
    if presented.is_empty() || presented.len() > 128 {
        return Err(redirect_flash(
            "/control/invitations",
            ("invalid_csrf", None),
        ));
    }
    if !state
        .control_plane
        .verify_csrf(&session.csrf_token_hash, presented)
    {
        return Err(redirect_flash(
            "/control/invitations",
            ("invalid_csrf", None),
        ));
    }
    Ok(())
}

fn csrf_cookie(headers: &HeaderMap) -> Result<String, Response> {
    cookie_value(headers, CSRF_COOKIE)
        .filter(|token| !token.is_empty() && token.len() <= 128)
        .map(|token| token.to_owned())
        .ok_or_else(redirect_to_login)
}

fn take_flash(headers: &HeaderMap) -> Result<Option<FlashParts>, Response> {
    let Some(raw) = cookie_value(headers, FLASH_COOKIE) else {
        return Ok(None);
    };
    if raw.len() > 1024 {
        return Err(ui_error_response(StatusCode::BAD_REQUEST, "invalid_flash"));
    }
    let (kind, token) = match raw.split_once('|') {
        Some((kind, token)) => (kind, Some(token.to_owned())),
        None => (raw, None),
    };
    build_flash(kind.to_string(), token)
}

fn build_flash(kind: String, token: Option<String>) -> Result<Option<FlashParts>, Response> {
    let token = token.filter(|value| !value.is_empty() && value.len() <= 256);
    match kind.as_str() {
        "created" => Ok(Some(FlashParts {
            css_class: "",
            label: "Created",
            token,
            message: None,
        })),
        "regenerated" => Ok(Some(FlashParts {
            css_class: "warn",
            label: "Regenerated",
            token,
            message: None,
        })),
        "key_created" => Ok(Some(FlashParts {
            css_class: "",
            label: "Created",
            token,
            message: None,
        })),
        "key_rotated" => Ok(Some(FlashParts {
            css_class: "warn",
            label: "Rotated",
            token,
            message: None,
        })),
        "revoked" => Ok(Some(FlashParts {
            css_class: "",
            label: "Revoked",
            token: None,
            message: Some("Invitation revoked."),
        })),
        "member_revoked" => Ok(Some(FlashParts {
            css_class: "",
            label: "Revoked",
            token: None,
            message: Some("Member account revoked and local data removed."),
        })),
        "connection_revoked" => Ok(Some(FlashParts {
            css_class: "",
            label: "Revoked",
            token: None,
            message: Some("Gmail connection revoked and local credentials removed."),
        })),
        "key_revoked" => Ok(Some(FlashParts {
            css_class: "",
            label: "Revoked",
            token: None,
            message: Some("Access Key revoked."),
        })),
        "grants_updated" => Ok(Some(FlashParts {
            css_class: "",
            label: "Updated",
            token: None,
            message: Some("Access Key connection grants updated."),
        })),
        "owner_delete_forbidden" => Ok(Some(FlashParts {
            css_class: "warn",
            label: "Unavailable",
            token: None,
            message: Some("The Owner account cannot be deleted in the control plane."),
        })),
        "not_found" => Ok(Some(FlashParts {
            css_class: "warn",
            label: "Not found",
            token: None,
            message: Some("Invitation not found or already finalized."),
        })),
        "invalid_request" => Ok(Some(FlashParts {
            css_class: "warn",
            label: "Invalid request",
            token: None,
            message: Some("The submitted form was invalid."),
        })),
        "invalid_state" => Ok(Some(FlashParts {
            css_class: "warn",
            label: "Cannot change",
            token: None,
            message: Some("Invitation is no longer in a claimable state."),
        })),
        "invalid_csrf" => Ok(Some(FlashParts {
            css_class: "warn",
            label: "Expired session",
            token: None,
            message: Some("Please reload the page and try again."),
        })),
        _ => Err(ui_error_response(StatusCode::BAD_REQUEST, "invalid_flash")),
    }
}

fn render<T: Template>(template: T) -> Response {
    match template.render() {
        Ok(body) => (
            StatusCode::OK,
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            )],
            body,
        )
            .into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("template render failed: {error}"),
        )
            .into_response(),
    }
}

fn redirect_flash(location: &str, flash: (&str, Option<String>)) -> Response {
    let mut response = Redirect::to(location).into_response();
    let (kind, token) = flash;
    response
        .headers_mut()
        .append(header::SET_COOKIE, flash_cookie(kind, token.as_deref()));
    response
}

fn flash_cookie(kind: &str, token: Option<&str>) -> HeaderValue {
    let value = match token {
        Some(token) => format!("{kind}|{token}"),
        None => kind.to_owned(),
    };
    HeaderValue::from_str(&format!(
        "{FLASH_COOKIE}={value}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={FLASH_COOKIE_MAX_AGE}"
    ))
    .expect("flash cookie header")
}

fn append_clear_flash_cookie(response: &mut Response) {
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&clear_flash_cookie()).expect("flash clear header"),
    );
}

fn clear_flash_cookie() -> String {
    format!("{FLASH_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0")
}

fn redirect_to_login() -> Response {
    let mut response = Redirect::to("/auth/google/login").into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&clear_session_cookie()).expect("cookie value"),
    );
    response
}

fn clear_session_cookie() -> String {
    let policy = SessionCookiePolicy::default();
    format!(
        "{}=; HttpOnly; Secure; SameSite=Lax; Path={}; Max-Age=0",
        policy.name, policy.path
    )
}

fn ui_error_response(status: StatusCode, code: &'static str) -> Response {
    (status, code).into_response()
}

fn server_error(_error: RepositoryError) -> Response {
    ui_error_response(StatusCode::SERVICE_UNAVAILABLE, "service_unavailable")
}

fn format_rfc3339(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn invitation_status_label(
    accepted_at: Option<DateTime<Utc>>,
    expires_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> String {
    if accepted_at.is_some() {
        "Accepted".to_owned()
    } else if expires_at <= now {
        "Expired".to_owned()
    } else {
        "Pending".to_owned()
    }
}

fn user_status_label(status: &UserStatus) -> &'static str {
    match status {
        UserStatus::Active => "Active",
        UserStatus::Revoking => "Revoking",
    }
}

fn connection_status_label(status: ConnectionStatus) -> &'static str {
    match status {
        ConnectionStatus::Active => "Active",
        ConnectionStatus::ReauthRequired => "Reauthorization required",
        ConnectionStatus::Revoking => "Revoking",
    }
}

pub fn csrf_cookie_value(token: &str) -> String {
    format!(
        "{CSRF_COOKIE}={token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={CSRF_COOKIE_MAX_AGE}"
    )
}

pub fn csrf_cookie_clear() -> String {
    format!("{CSRF_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::AppConfig,
        control_http::{OAuthCodeExchanger, OidcTokenVerifier},
        database::Database,
        domain::identity::{
            GMAIL_COMPOSE_SCOPE, GMAIL_READONLY_SCOPE, GmailConnection, SessionId, User, UserRole,
        },
        google_oidc::GoogleOidcError,
        google_token::{GoogleTokenError, TokenSet},
        oauth::OidcClaims,
        repository::{NewWebSession, Repository},
    };
    use async_trait::async_trait;
    use axum::{
        Router,
        body::Body,
        http::{HeaderMap, Method, Request, StatusCode, header},
    };
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use chrono::{Duration, Utc};
    use secrecy::SecretString;
    use std::collections::BTreeMap;
    use tower::ServiceExt;

    fn test_config() -> AppConfig {
        let key = URL_SAFE_NO_PAD.encode([13_u8; 32]);
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
    struct UnusedVerifier;

    #[async_trait]
    impl OidcTokenVerifier for UnusedVerifier {
        async fn verify_with_refresh(
            &self,
            _id_token: &str,
        ) -> Result<OidcClaims, GoogleOidcError> {
            panic!("OIDC verification must not run on UI route tests")
        }
    }

    #[derive(Clone)]
    struct UnusedExchanger;

    #[async_trait]
    impl OAuthCodeExchanger for UnusedExchanger {
        async fn exchange_code(
            &self,
            _code: &str,
            _code_verifier: &SecretString,
        ) -> Result<TokenSet, GoogleTokenError> {
            panic!("OAuth exchange must not run on UI route tests")
        }
    }

    async fn owner_fixture(role: UserRole) -> (Router, Repository, User, String, String) {
        let database = Database::connect("sqlite::memory:").await.unwrap();
        database.migrate().await.unwrap();
        let repository = Repository::new(&database);
        let email = match role {
            UserRole::Owner => "owner@example.com",
            UserRole::Member => "member@example.com",
        };
        let user = User::new("test-sub", email, role, Utc::now()).unwrap();
        repository.insert_user(&user).await.unwrap();
        let connection = GmailConnection::new(
            user.id,
            "gmail-sub",
            email,
            vec![GMAIL_READONLY_SCOPE.into(), GMAIL_COMPOSE_SCOPE.into()],
        )
        .unwrap();
        repository
            .insert_connection(&connection, None)
            .await
            .unwrap();
        let session_token = "ui-test-session".to_owned();
        let csrf_token = "ui-test-csrf".to_owned();
        let now = Utc::now();
        repository
            .insert_web_session(&NewWebSession {
                id: SessionId::new(),
                user_id: user.id,
                token_hash: crate::crypto::hash_token(&session_token),
                csrf_token_hash: crate::crypto::hash_token(&csrf_token),
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
        (router(state), repository, user, session_token, csrf_token)
    }

    fn owner_cookies(session_token: &str, csrf_token: &str) -> String {
        format!("__Host-agentmail_session={session_token}; {CSRF_COOKIE}={csrf_token}")
    }

    async fn get_page(
        app: &Router,
        path: &str,
        session: Option<&str>,
        csrf: Option<&str>,
    ) -> (StatusCode, HeaderMap, String) {
        let mut builder = Request::builder().method(Method::GET).uri(path);
        if let (Some(session), Some(csrf)) = (session, csrf) {
            builder = builder.header(header::COOKIE, owner_cookies(session, csrf));
        }
        let response = app
            .clone()
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&bytes).into_owned();
        (status, headers, body)
    }

    async fn post_form(
        app: &Router,
        path: &str,
        session: &str,
        csrf: &str,
        body: &str,
    ) -> (StatusCode, HeaderMap, String) {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(path)
                    .header(header::COOKIE, owner_cookies(session, csrf))
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(body.to_owned()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&bytes).into_owned();
        (status, headers, body)
    }

    fn flash_from_headers(headers: &HeaderMap) -> Option<String> {
        headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find_map(|raw| {
                let cookie = raw.split(';').next()?;
                let (name, value) = cookie.split_once('=')?;
                if name == FLASH_COOKIE && !value.is_empty() {
                    Some(value.to_owned())
                } else {
                    None
                }
            })
    }

    #[tokio::test]
    async fn dashboard_renders_owner_and_never_leaks_secrets() {
        let (app, _repo, _user, session, csrf) = owner_fixture(UserRole::Owner).await;
        let (status, headers, body) = get_page(&app, "/control", Some(&session), Some(&csrf)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or(""),
            "text/html; charset=utf-8"
        );
        assert!(body.contains("Owner dashboard"));
        assert!(body.contains("Personal Use capacity"));
        assert!(body.contains("Active members"));
        assert!(
            body.contains(
                "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'"
            )
        );
        assert!(body.contains("<style>"));
        assert!(!body.contains("<script"));
        assert!(!body.contains("secret_hash"));
        assert!(!body.contains("__Host-agentmail_csrf"));
        assert!(!body.contains(&csrf));
    }

    #[tokio::test]
    async fn dashboard_redirects_unauthenticated_user_to_login() {
        let (app, _repo, _user, _session, _csrf) = owner_fixture(UserRole::Owner).await;
        let (status, headers, _) = get_page(&app, "/control", None, None).await;
        assert!(status == StatusCode::SEE_OTHER || status == StatusCode::TEMPORARY_REDIRECT);
        let location = headers
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(location, "/auth/google/login");
    }

    #[tokio::test]
    async fn dashboard_rejects_member_role() {
        let (app, _repo, _user, session, csrf) = owner_fixture(UserRole::Member).await;
        let (status, headers, _) = get_page(&app, "/control", Some(&session), Some(&csrf)).await;
        assert!(status == StatusCode::SEE_OTHER || status == StatusCode::TEMPORARY_REDIRECT);
        let location = headers
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(location, "/auth/google/login");
    }

    #[tokio::test]
    async fn member_account_page_lists_own_connection_and_supports_revoke() {
        let (app, repo, member, session, csrf) = owner_fixture(UserRole::Member).await;
        let connection = repo
            .list_connections_for_user(member.id)
            .await
            .unwrap()
            .pop()
            .unwrap();
        let (status, _, body) =
            get_page(&app, "/control/account", Some(&session), Some(&csrf)).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("member@example.com"));
        assert!(body.contains("Delete my AgentMail account"));
        assert!(body.contains("Connect Gmail"));
        assert!(body.contains(&format!(
            "/control/account/connections/{}/revoke",
            connection.id
        )));
        let (start_status, start_headers, _) = post_form(
            &app,
            "/control/account/connections/new",
            &session,
            &csrf,
            "_csrf=ui-test-csrf",
        )
        .await;
        assert!(
            start_status == StatusCode::SEE_OTHER || start_status == StatusCode::TEMPORARY_REDIRECT
        );
        assert!(
            start_headers
                .get(header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.starts_with("https://accounts.google.com/"))
        );
        let (status, headers, _) = post_form(
            &app,
            &format!("/control/account/connections/{}/revoke", connection.id),
            &session,
            &csrf,
            "_csrf=ui-test-csrf",
        )
        .await;
        assert!(status == StatusCode::SEE_OTHER || status == StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            headers
                .get(header::LOCATION)
                .and_then(|value| value.to_str().ok()),
            Some("/control/account")
        );
        assert!(repo.get_connection(connection.id).await.unwrap().is_none());
        assert!(repo.get_user(member.id).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn member_self_delete_form_clears_auth_cookies() {
        let (app, repo, member, session, csrf) = owner_fixture(UserRole::Member).await;
        let (status, headers, _) = post_form(
            &app,
            "/control/account/delete",
            &session,
            &csrf,
            "_csrf=ui-test-csrf",
        )
        .await;
        assert!(status == StatusCode::SEE_OTHER || status == StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            headers
                .get(header::LOCATION)
                .and_then(|value| value.to_str().ok()),
            Some("/")
        );
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
        assert!(repo.get_user(member.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn member_manages_access_key_and_plaintext_is_flash_only() {
        let (app, repo, member, session, csrf) = owner_fixture(UserRole::Member).await;
        let connection = repo
            .list_connections_for_user(member.id)
            .await
            .unwrap()
            .pop()
            .unwrap();
        let (status, headers, _) = post_form(
            &app,
            "/control/account/access-keys",
            &session,
            &csrf,
            &format!(
                "name=member-key&connection_ids={}&_csrf=ui-test-csrf",
                connection.id
            ),
        )
        .await;
        assert!(status == StatusCode::SEE_OTHER || status == StatusCode::TEMPORARY_REDIRECT);
        let flash = flash_from_headers(&headers).unwrap();
        let credential = flash
            .strip_prefix("key_created|")
            .expect("one-time credential flash");
        assert!(credential.starts_with("amk_"));
        let key = repo
            .list_access_keys(member.id)
            .await
            .unwrap()
            .pop()
            .unwrap();
        assert!(key.grants.contains(connection.id));
        assert!(
            repo.authenticate_access_key(credential)
                .await
                .unwrap()
                .is_some()
        );
        let (_, _, body) = get_page(&app, "/control/account", Some(&session), Some(&csrf)).await;
        assert!(!body.contains(credential));
        assert!(body.contains(&key.public_prefix));

        let (_, rotate_headers, _) = post_form(
            &app,
            &format!("/control/account/access-keys/{}/rotate", key.id),
            &session,
            &csrf,
            "_csrf=ui-test-csrf",
        )
        .await;
        let rotated = flash_from_headers(&rotate_headers)
            .unwrap()
            .strip_prefix("key_rotated|")
            .unwrap()
            .to_owned();
        assert!(
            repo.authenticate_access_key(credential)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            repo.authenticate_access_key(&rotated)
                .await
                .unwrap()
                .is_some()
        );

        post_form(
            &app,
            &format!("/control/account/access-keys/{}/grants", key.id),
            &session,
            &csrf,
            "_csrf=ui-test-csrf",
        )
        .await;
        assert!(
            repo.get_access_key(member.id, key.id)
                .await
                .unwrap()
                .unwrap()
                .grants
                .is_empty()
        );
        post_form(
            &app,
            &format!("/control/account/access-keys/{}/revoke", key.id),
            &session,
            &csrf,
            "_csrf=ui-test-csrf",
        )
        .await;
        assert!(
            repo.authenticate_access_key(&rotated)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn members_page_lists_summaries_without_rediscovering_secrets() {
        let (app, repo, _owner, session, csrf) = owner_fixture(UserRole::Owner).await;
        let member = User::new(
            "member-sub",
            "alice@example.com",
            UserRole::Member,
            Utc::now(),
        )
        .unwrap();
        repo.insert_user(&member).await.unwrap();
        let (status, _, body) =
            get_page(&app, "/control/members", Some(&session), Some(&csrf)).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("alice@example.com"));
        assert!(body.contains("Active"));
        assert!(body.contains("Connections"));
        assert!(body.contains("Access keys"));
        assert!(body.contains(&format!("/control/members/{}/revoke", member.id)));
        assert!(body.contains("Revoke account"));
        assert!(!body.contains("secret_hash"));
        assert!(!body.contains("__Host-agentmail_csrf"));
    }

    #[tokio::test]
    async fn owner_member_revoke_form_requires_csrf_and_removes_member() {
        let (app, repo, _owner, session, csrf) = owner_fixture(UserRole::Owner).await;
        let member = User::new(
            "member-revoke-ui",
            "revoke-ui@example.com",
            UserRole::Member,
            Utc::now(),
        )
        .unwrap();
        repo.insert_user(&member).await.unwrap();
        let path = format!("/control/members/{}/revoke", member.id);
        let (_, bad_headers, _) =
            post_form(&app, &path, &session, &csrf, "_csrf=wrong-token").await;
        assert!(
            flash_from_headers(&bad_headers)
                .unwrap_or_default()
                .contains("invalid_csrf")
        );
        assert!(repo.get_user(member.id).await.unwrap().is_some());

        let (status, headers, _) =
            post_form(&app, &path, &session, &csrf, "_csrf=ui-test-csrf").await;
        assert!(status == StatusCode::SEE_OTHER || status == StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            headers
                .get(header::LOCATION)
                .and_then(|value| value.to_str().ok()),
            Some("/control/members")
        );
        assert!(
            flash_from_headers(&headers)
                .unwrap_or_default()
                .contains("member_revoked")
        );
        assert!(repo.get_user(member.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn capacity_page_renders_quota_and_console_caveat() {
        let (app, _repo, _user, session, csrf) = owner_fixture(UserRole::Owner).await;
        let (status, _, body) =
            get_page(&app, "/control/capacity", Some(&session), Some(&csrf)).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("Personal Use capacity"));
        assert!(body.contains("Google Cloud Console remains the source of truth"));
        assert!(!body.contains("__Host-agentmail_csrf"));
    }

    #[tokio::test]
    async fn invitations_create_shows_token_once_and_clears_flash() {
        let (app, repo, _owner, session, csrf) = owner_fixture(UserRole::Owner).await;
        let (status, headers, _) = post_form(
            &app,
            "/control/invitations",
            &session,
            &csrf,
            "target_email=alice@example.com&_csrf=ui-test-csrf",
        )
        .await;
        assert!(status == StatusCode::SEE_OTHER || status == StatusCode::TEMPORARY_REDIRECT);
        let location = headers
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(location, "/control/invitations");
        let flash = flash_from_headers(&headers).expect("flash cookie set");
        let (kind, token) = flash.split_once('|').expect("kind|token");
        assert_eq!(kind, "created");
        assert!(!token.is_empty());
        assert_eq!(token.len(), 43);
        assert_ne!(
            token,
            crate::crypto::hash_token(token).as_str(),
            "token plaintext must not equal its digest"
        );
        let list = repo.list_invitations(_owner.id).await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].token_hash, crate::crypto::hash_token(token));

        let (_status, headers, body) =
            get_page(&app, "/control/invitations", Some(&session), Some(&csrf)).await;
        assert!(body.contains("alice@example.com"));
        let cleared = headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .any(|raw| raw.starts_with(&format!("{FLASH_COOKIE}=")) && raw.contains("Max-Age=0"));
        assert!(cleared, "flash cookie must be cleared on GET");
    }

    #[tokio::test]
    async fn invitations_create_rejects_bad_csrf() {
        let (app, _repo, _owner, session, _csrf) = owner_fixture(UserRole::Owner).await;
        let (status, headers, _) = post_form(
            &app,
            "/control/invitations",
            &session,
            &session,
            "target_email=alice@example.com&_csrf=wrong-token",
        )
        .await;
        assert!(status == StatusCode::SEE_OTHER || status == StatusCode::TEMPORARY_REDIRECT);
        let flash = flash_from_headers(&headers).unwrap_or_default();
        assert!(flash.contains("invalid_csrf"));
    }

    #[tokio::test]
    async fn invitations_revoke_returns_flash_and_removes_record() {
        let (app, repo, owner, session, csrf) = owner_fixture(UserRole::Owner).await;
        let service = crate::invitations::InviteService::new(repo.clone());
        let issued = service
            .issue(&owner, "alice@example.com", Utc::now())
            .await
            .unwrap();
        let path = format!(
            "/control/invitations/{}/revoke",
            issued.invitation.id.into_uuid()
        );
        let body = format!("_csrf={}", csrf);
        let (status, headers, _) = post_form(&app, &path, &session, &csrf, &body).await;
        assert!(status == StatusCode::SEE_OTHER || status == StatusCode::TEMPORARY_REDIRECT);
        let flash = flash_from_headers(&headers).unwrap_or_default();
        assert!(flash.contains("revoked"));
        let list = repo.list_invitations(owner.id).await.unwrap();
        assert!(list.is_empty(), "revoke deletes the invitation row");
    }

    #[tokio::test]
    async fn invitations_regenerate_replaces_token() {
        let (app, repo, owner, session, csrf) = owner_fixture(UserRole::Owner).await;
        let service = crate::invitations::InviteService::new(repo.clone());
        let first = service
            .issue(&owner, "alice@example.com", Utc::now())
            .await
            .unwrap();
        let path = format!(
            "/control/invitations/{}/regenerate",
            first.invitation.id.into_uuid()
        );
        let body = format!("_csrf={}", csrf);
        let (status, headers, _) = post_form(&app, &path, &session, &csrf, &body).await;
        assert!(status == StatusCode::SEE_OTHER || status == StatusCode::TEMPORARY_REDIRECT);
        let flash = flash_from_headers(&headers).unwrap_or_default();
        let (kind, token) = flash.split_once('|').expect("kind|token");
        assert_eq!(kind, "regenerated");
        assert_ne!(token, first.token.as_str());
        assert_eq!(
            repo.list_invitations(owner.id)
                .await
                .unwrap()
                .into_iter()
                .filter(|inv| inv.token_hash == crate::crypto::hash_token(token))
                .count(),
            1
        );
        assert_eq!(
            repo.list_invitations(owner.id)
                .await
                .unwrap()
                .into_iter()
                .filter(|inv| inv.token_hash == crate::crypto::hash_token(first.token.as_str()))
                .count(),
            0
        );
    }
}

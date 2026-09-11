//! Narrow Gmail REST client for mailbox reads and managed-draft writes.
//!
//! This client intentionally accepts an access token per call and never owns
//! or persists a refresh token.  It returns only a small, safe DTO instead of
//! exposing Gmail's discovery surface or accepting arbitrary request paths.

use crate::domain::mailbox::{MAX_HTTP_ATTACHMENT_BYTES, strip_html_active_content};
use base64::Engine as _;
use reqwest::{Client, StatusCode, Url};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::{fmt, time::Duration};

pub const GMAIL_API_BASE: &str = "https://gmail.googleapis.com/gmail/v1/";
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
pub const MAX_JSON_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_ATTACHMENT_JSON_BYTES: usize = MAX_HTTP_ATTACHMENT_BYTES.div_ceil(3) * 4 + 4096;

#[derive(Debug, thiserror::Error, Clone, Eq, PartialEq)]
pub enum GoogleGmailError {
    #[error("access token is empty")]
    EmptyAccessToken,
    #[error("message id is invalid")]
    InvalidMessageId,
    #[error("draft id is invalid")]
    InvalidDraftId,
    #[error("thread id is invalid")]
    InvalidThreadId,
    #[error("attachment id is invalid")]
    InvalidAttachmentId,
    #[error("page size must be between 1 and 500")]
    InvalidPageSize,
    #[error("Gmail authorization must be renewed")]
    ReauthRequired,
    #[error("Gmail resource was not found")]
    NotFound,
    #[error("Gmail API rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("Gmail API is unavailable")]
    Upstream,
    #[error("Gmail API request timed out")]
    Timeout,
    #[error("Gmail API returned an invalid response")]
    InvalidResponse,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageList {
    pub messages: Vec<MessageListItem>,
    pub next_page_token: Option<String>,
    pub result_size_estimate: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageListItem {
    pub id: String,
    pub thread_id: Option<String>,
}

/// Safe minimum subset of a Gmail message.  Body data is present only for a
/// `full` request and is decoded from Gmail's base64url representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GmailMessage {
    pub id: String,
    pub thread_id: Option<String>,
    pub label_ids: Vec<String>,
    pub snippet: Option<String>,
    pub internal_date: Option<String>,
    pub headers: Vec<MessageHeader>,
    pub body: Option<String>,
    pub body_is_html: bool,
    pub html_body: Option<String>,
    pub attachments: Vec<GmailAttachment>,
    pub untrusted_email_content: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GmailThread {
    pub id: String,
    pub messages: Vec<GmailMessage>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DraftList {
    pub drafts: Vec<GmailDraft>,
    pub next_page_token: Option<String>,
    pub result_size_estimate: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GmailDraftDetail {
    pub id: String,
    pub message: GmailMessage,
}

#[derive(Clone, Eq, PartialEq)]
pub struct GmailAttachment {
    pub attachment_id: Option<String>,
    pub part_id: Option<String>,
    pub filename: String,
    pub mime_type: String,
    pub size: u64,
    pub inline: bool,
    pub content_id: Option<String>,
    /// Embedded MIME part data; absent when Gmail requires attachments.get.
    pub data: Option<Vec<u8>>,
}

impl fmt::Debug for GmailAttachment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GmailAttachment")
            .field("size", &self.size)
            .field("content", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GmailAttachmentData {
    pub size: u64,
    pub data: Vec<u8>,
}

impl fmt::Debug for GmailAttachmentData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GmailAttachmentData")
            .field("size", &self.size)
            .field("data", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageHeader {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GmailDraft {
    pub id: String,
    pub message_id: String,
    pub thread_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GmailSendResult {
    pub message_id: String,
    pub thread_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageFormat {
    Metadata,
    Full,
}

impl MessageFormat {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Metadata => "metadata",
            Self::Full => "full",
        }
    }
}

#[derive(Clone)]
pub struct GoogleGmailClient {
    http: Client,
    base_url: Url,
}

impl fmt::Debug for GoogleGmailClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GoogleGmailClient")
            .field("base_url", &self.base_url)
            .field("authorization", &"[REDACTED per-call]")
            .finish()
    }
}

impl GoogleGmailClient {
    /// Construct a client bound to Gmail's HTTPS API base.
    pub fn new() -> Result<Self, GoogleGmailError> {
        let base_url = Url::parse(GMAIL_API_BASE).expect("constant Gmail API URL");
        let http = Client::builder()
            .timeout(DEFAULT_REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("default reqwest client must build");
        Self::with_base(http, base_url)
    }

    /// Test-only constructor bound to a local fake Gmail API endpoint.
    #[cfg(test)]
    pub(crate) fn for_tests(base_url: Url) -> Result<Self, GoogleGmailError> {
        let http = Client::builder()
            .timeout(DEFAULT_REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("test reqwest client must build");
        Self::with_base(http, base_url)
    }

    fn with_base(http: Client, base_url: Url) -> Result<Self, GoogleGmailError> {
        let path_ok = base_url.path() == "/gmail/v1/";
        let production = base_url.scheme() == "https"
            && base_url.host_str() == Some("gmail.googleapis.com")
            && path_ok;
        let test_local = cfg!(test)
            && base_url.scheme() == "http"
            && matches!(
                base_url.host_str(),
                Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
            )
            && path_ok;
        if !production && !test_local {
            return Err(GoogleGmailError::InvalidResponse);
        }
        if base_url.username() != ""
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
        {
            return Err(GoogleGmailError::InvalidResponse);
        }
        Ok(Self { http, base_url })
    }

    pub async fn list_messages(
        &self,
        access_token: &SecretString,
        query: Option<&str>,
        max_results: Option<u32>,
        page_token: Option<&str>,
    ) -> Result<MessageList, GoogleGmailError> {
        if access_token.expose_secret().is_empty() {
            return Err(GoogleGmailError::EmptyAccessToken);
        }
        if max_results.is_some_and(|value| !(1..=500).contains(&value)) {
            return Err(GoogleGmailError::InvalidPageSize);
        }
        let url = self
            .base_url
            .join("users/me/messages")
            .map_err(|_| GoogleGmailError::InvalidResponse)?;
        let mut request = self.authorized(self.http.get(url), access_token)?;
        let mut params: Vec<(String, String)> = Vec::new();
        if let Some(value) = query {
            params.push(("q".to_owned(), value.to_owned()));
        }
        if let Some(value) = max_results {
            params.push(("maxResults".to_owned(), value.to_string()));
        }
        if let Some(value) = page_token {
            params.push(("pageToken".to_owned(), value.to_owned()));
        }
        if !params.is_empty() {
            request = request.query(&params);
        }
        let raw: RawMessageList = self.send(request).await?;
        Ok(MessageList {
            messages: raw
                .messages
                .unwrap_or_default()
                .into_iter()
                .map(|item| MessageListItem {
                    id: item.id,
                    thread_id: item.thread_id,
                })
                .collect(),
            next_page_token: raw.next_page_token,
            result_size_estimate: raw.result_size_estimate,
        })
    }

    pub async fn get_message(
        &self,
        access_token: &SecretString,
        message_id: &str,
        format: MessageFormat,
    ) -> Result<GmailMessage, GoogleGmailError> {
        if access_token.expose_secret().is_empty() {
            return Err(GoogleGmailError::EmptyAccessToken);
        }
        if message_id.is_empty()
            || !message_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(GoogleGmailError::InvalidMessageId);
        }
        let url = self
            .base_url
            .join(&format!("users/me/messages/{message_id}"))
            .map_err(|_| GoogleGmailError::InvalidResponse)?;
        let request = self
            .authorized(self.http.get(url), access_token)?
            .query(&[("format", format.as_str())]);
        let raw: RawMessage = self.send(request).await?;
        raw.try_into()
    }

    pub async fn get_thread(
        &self,
        access_token: &SecretString,
        thread_id: &str,
        format: MessageFormat,
    ) -> Result<GmailThread, GoogleGmailError> {
        validate_access_token(access_token)?;
        validate_resource_id(thread_id, GoogleGmailError::InvalidThreadId)?;
        let url = self
            .base_url
            .join(&format!("users/me/threads/{thread_id}"))
            .map_err(|_| GoogleGmailError::InvalidResponse)?;
        let request = self
            .authorized(self.http.get(url), access_token)?
            .query(&[("format", format.as_str())]);
        let raw: RawThread = self.send(request).await?;
        validate_resource_id(&raw.id, GoogleGmailError::InvalidResponse)?;
        Ok(GmailThread {
            id: raw.id,
            messages: raw
                .messages
                .unwrap_or_default()
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?,
        })
    }

    pub async fn list_drafts(
        &self,
        access_token: &SecretString,
        query: Option<&str>,
        max_results: Option<u32>,
        page_token: Option<&str>,
    ) -> Result<DraftList, GoogleGmailError> {
        validate_access_token(access_token)?;
        if max_results.is_some_and(|value| !(1..=500).contains(&value)) {
            return Err(GoogleGmailError::InvalidPageSize);
        }
        let url = self
            .base_url
            .join("users/me/drafts")
            .map_err(|_| GoogleGmailError::InvalidResponse)?;
        let mut params = Vec::new();
        if let Some(value) = query {
            params.push(("q", value.to_owned()));
        }
        if let Some(value) = max_results {
            params.push(("maxResults", value.to_string()));
        }
        if let Some(value) = page_token {
            params.push(("pageToken", value.to_owned()));
        }
        let request = self
            .authorized(self.http.get(url), access_token)?
            .query(&params);
        let raw: RawDraftList = self.send(request).await?;
        Ok(DraftList {
            drafts: raw
                .drafts
                .unwrap_or_default()
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?,
            next_page_token: raw.next_page_token,
            result_size_estimate: raw.result_size_estimate,
        })
    }

    pub async fn get_draft(
        &self,
        access_token: &SecretString,
        draft_id: &str,
    ) -> Result<GmailDraftDetail, GoogleGmailError> {
        validate_access_token(access_token)?;
        validate_resource_id(draft_id, GoogleGmailError::InvalidDraftId)?;
        let url = self
            .base_url
            .join(&format!("users/me/drafts/{draft_id}"))
            .map_err(|_| GoogleGmailError::InvalidResponse)?;
        let request = self
            .authorized(self.http.get(url), access_token)?
            .query(&[("format", "full")]);
        let raw: RawDraftDetail = self.send(request).await?;
        validate_resource_id(&raw.id, GoogleGmailError::InvalidResponse)?;
        Ok(GmailDraftDetail {
            id: raw.id,
            message: raw.message.try_into()?,
        })
    }

    pub async fn get_attachment(
        &self,
        access_token: &SecretString,
        message_id: &str,
        attachment_id: &str,
    ) -> Result<GmailAttachmentData, GoogleGmailError> {
        validate_access_token(access_token)?;
        validate_resource_id(message_id, GoogleGmailError::InvalidMessageId)?;
        validate_resource_id(attachment_id, GoogleGmailError::InvalidAttachmentId)?;
        let url = self
            .base_url
            .join(&format!(
                "users/me/messages/{message_id}/attachments/{attachment_id}"
            ))
            .map_err(|_| GoogleGmailError::InvalidResponse)?;
        let request = self.authorized(self.http.get(url), access_token)?;
        let raw: RawBody = self
            .send_bounded(request, MAX_ATTACHMENT_JSON_BYTES)
            .await?;
        let size = raw.size.ok_or(GoogleGmailError::InvalidResponse)?;
        if size > MAX_HTTP_ATTACHMENT_BYTES as u64 {
            return Err(GoogleGmailError::InvalidResponse);
        }
        let data = decode_body_data(
            raw.data
                .as_deref()
                .ok_or(GoogleGmailError::InvalidResponse)?,
        )?;
        if data.len() as u64 != size || data.len() > MAX_HTTP_ATTACHMENT_BYTES {
            return Err(GoogleGmailError::InvalidResponse);
        }
        Ok(GmailAttachmentData { size, data })
    }

    pub async fn create_draft(
        &self,
        access_token: &SecretString,
        raw_mime: &[u8],
        thread_id: Option<&str>,
    ) -> Result<GmailDraft, GoogleGmailError> {
        validate_access_token(access_token)?;
        if let Some(thread_id) = thread_id {
            validate_resource_id(thread_id, GoogleGmailError::InvalidMessageId)?;
        }
        let url = self
            .base_url
            .join("users/me/drafts")
            .map_err(|_| GoogleGmailError::InvalidResponse)?;
        let payload = DraftWriteRequest {
            message: RawWriteMessage {
                raw: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw_mime),
                thread_id,
            },
        };
        let request = self
            .authorized(self.http.post(url), access_token)?
            .json(&payload);
        self.send::<RawDraft>(request).await?.try_into()
    }

    pub async fn update_draft(
        &self,
        access_token: &SecretString,
        draft_id: &str,
        raw_mime: &[u8],
        thread_id: Option<&str>,
    ) -> Result<GmailDraft, GoogleGmailError> {
        validate_access_token(access_token)?;
        validate_resource_id(draft_id, GoogleGmailError::InvalidDraftId)?;
        if let Some(thread_id) = thread_id {
            validate_resource_id(thread_id, GoogleGmailError::InvalidMessageId)?;
        }
        let url = self
            .base_url
            .join(&format!("users/me/drafts/{draft_id}"))
            .map_err(|_| GoogleGmailError::InvalidResponse)?;
        let payload = DraftWriteRequest {
            message: RawWriteMessage {
                raw: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw_mime),
                thread_id,
            },
        };
        let request = self
            .authorized(self.http.put(url), access_token)?
            .json(&payload);
        self.send::<RawDraft>(request).await?.try_into()
    }

    pub async fn delete_draft(
        &self,
        access_token: &SecretString,
        draft_id: &str,
    ) -> Result<(), GoogleGmailError> {
        validate_access_token(access_token)?;
        validate_resource_id(draft_id, GoogleGmailError::InvalidDraftId)?;
        let url = self
            .base_url
            .join(&format!("users/me/drafts/{draft_id}"))
            .map_err(|_| GoogleGmailError::InvalidResponse)?;
        let request = self.authorized(self.http.delete(url), access_token)?;
        self.send_empty(request).await
    }

    pub async fn send_draft(
        &self,
        access_token: &SecretString,
        draft_id: &str,
    ) -> Result<GmailSendResult, GoogleGmailError> {
        validate_access_token(access_token)?;
        validate_resource_id(draft_id, GoogleGmailError::InvalidDraftId)?;
        let url = self
            .base_url
            .join("users/me/drafts/send")
            .map_err(|_| GoogleGmailError::InvalidResponse)?;
        let request = self
            .authorized(self.http.post(url), access_token)?
            .json(&DraftSendRequest { id: draft_id });
        let raw: RawSentMessage = self.send(request).await?;
        if raw.id.is_empty() {
            return Err(GoogleGmailError::InvalidResponse);
        }
        Ok(GmailSendResult {
            message_id: raw.id,
            thread_id: raw.thread_id,
        })
    }

    fn authorized(
        &self,
        request: reqwest::RequestBuilder,
        access_token: &SecretString,
    ) -> Result<reqwest::RequestBuilder, GoogleGmailError> {
        let value = format!("Bearer {}", access_token.expose_secret());
        Ok(request.header(reqwest::header::AUTHORIZATION, value))
    }

    async fn send<T: for<'de> Deserialize<'de>>(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<T, GoogleGmailError> {
        self.send_bounded(request, MAX_JSON_RESPONSE_BYTES).await
    }

    async fn send_bounded<T: for<'de> Deserialize<'de>>(
        &self,
        request: reqwest::RequestBuilder,
        max_bytes: usize,
    ) -> Result<T, GoogleGmailError> {
        let mut response = request.send().await.map_err(classify_transport_error)?;
        ensure_success(&response)?;
        if response
            .content_length()
            .is_some_and(|length| length > max_bytes as u64)
        {
            return Err(GoogleGmailError::InvalidResponse);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(classify_transport_error)? {
            if body.len().saturating_add(chunk.len()) > max_bytes {
                return Err(GoogleGmailError::InvalidResponse);
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).map_err(|_| GoogleGmailError::InvalidResponse)
    }

    async fn send_empty(&self, request: reqwest::RequestBuilder) -> Result<(), GoogleGmailError> {
        let response = request.send().await.map_err(classify_transport_error)?;
        ensure_success(&response)
    }
}

fn ensure_success(response: &reqwest::Response) -> Result<(), GoogleGmailError> {
    let status = response.status();
    if status == StatusCode::UNAUTHORIZED {
        return Err(GoogleGmailError::ReauthRequired);
    }
    if status == StatusCode::NOT_FOUND {
        return Err(GoogleGmailError::NotFound);
    }
    if status == StatusCode::TOO_MANY_REQUESTS {
        let retry_after_seconds = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<u64>().ok());
        return Err(GoogleGmailError::RateLimited {
            retry_after_seconds,
        });
    }
    if status.is_server_error() {
        return Err(GoogleGmailError::Upstream);
    }
    if !status.is_success() {
        return Err(GoogleGmailError::Upstream);
    }
    Ok(())
}

fn validate_access_token(access_token: &SecretString) -> Result<(), GoogleGmailError> {
    if access_token.expose_secret().is_empty() {
        Err(GoogleGmailError::EmptyAccessToken)
    } else {
        Ok(())
    }
}

fn validate_resource_id(value: &str, error: GoogleGmailError) -> Result<(), GoogleGmailError> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        Err(error)
    } else {
        Ok(())
    }
}

#[derive(Debug, Serialize)]
struct DraftWriteRequest<'a> {
    message: RawWriteMessage<'a>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RawWriteMessage<'a> {
    raw: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    thread_id: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct DraftSendRequest<'a> {
    id: &'a str,
}

#[derive(Debug, Deserialize)]
struct RawDraft {
    id: String,
    message: Option<RawDraftMessage>,
}

#[derive(Debug, Deserialize)]
struct RawDraftMessage {
    id: String,
    #[serde(rename = "threadId")]
    thread_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawDraftList {
    drafts: Option<Vec<RawDraft>>,
    next_page_token: Option<String>,
    result_size_estimate: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct RawDraftDetail {
    id: String,
    message: RawMessage,
}

#[derive(Debug, Deserialize)]
struct RawThread {
    id: String,
    messages: Option<Vec<RawMessage>>,
}

impl TryFrom<RawDraft> for GmailDraft {
    type Error = GoogleGmailError;

    fn try_from(raw: RawDraft) -> Result<Self, Self::Error> {
        let message = raw.message.ok_or(GoogleGmailError::InvalidResponse)?;
        if raw.id.is_empty() || message.id.is_empty() {
            return Err(GoogleGmailError::InvalidResponse);
        }
        Ok(Self {
            id: raw.id,
            message_id: message.id,
            thread_id: message.thread_id,
        })
    }
}

#[derive(Debug, Deserialize)]
struct RawSentMessage {
    id: String,
    #[serde(rename = "threadId")]
    thread_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawMessageList {
    messages: Option<Vec<RawMessageListItem>>,
    next_page_token: Option<String>,
    result_size_estimate: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct RawMessageListItem {
    id: String,
    #[serde(rename = "threadId")]
    thread_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawMessage {
    id: String,
    #[serde(rename = "threadId")]
    thread_id: Option<String>,
    #[serde(rename = "labelIds")]
    label_ids: Option<Vec<String>>,
    snippet: Option<String>,
    #[serde(rename = "internalDate")]
    internal_date: Option<String>,
    payload: Option<RawPayload>,
}

#[derive(Debug, Default, Deserialize)]
struct RawPayload {
    #[serde(rename = "partId")]
    part_id: Option<String>,
    filename: Option<String>,
    #[serde(rename = "mimeType")]
    mime_type: Option<String>,
    headers: Option<Vec<RawHeader>>,
    body: Option<RawBody>,
    parts: Option<Vec<RawPayload>>,
}

#[derive(Debug, Deserialize)]
struct RawHeader {
    name: String,
    value: String,
}

#[derive(Debug, Default, Deserialize)]
struct RawBody {
    data: Option<String>,
    size: Option<u64>,
    #[serde(rename = "attachmentId")]
    attachment_id: Option<String>,
}

impl TryFrom<RawMessage> for GmailMessage {
    type Error = GoogleGmailError;

    fn try_from(raw: RawMessage) -> Result<Self, Self::Error> {
        validate_resource_id(&raw.id, GoogleGmailError::InvalidResponse)?;
        let payload = raw
            .payload
            .map(flatten_payload)
            .transpose()?
            .unwrap_or_default();
        let body_is_html = payload.plain.is_none() && payload.html.is_some();
        let body = payload.plain.or_else(|| payload.html.clone());
        Ok(Self {
            id: raw.id,
            thread_id: raw.thread_id,
            label_ids: raw.label_ids.unwrap_or_default(),
            snippet: raw.snippet,
            internal_date: raw.internal_date,
            headers: payload.headers,
            body,
            body_is_html,
            html_body: payload.html,
            attachments: payload.attachments,
            untrusted_email_content: true,
        })
    }
}

#[derive(Default)]
struct ParsedPayload {
    headers: Vec<MessageHeader>,
    plain: Option<String>,
    html: Option<String>,
    attachments: Vec<GmailAttachment>,
}

fn flatten_payload(mut payload: RawPayload) -> Result<ParsedPayload, GoogleGmailError> {
    let mut parsed = ParsedPayload {
        headers: payload
            .headers
            .as_ref()
            .into_iter()
            .flatten()
            .map(|header| MessageHeader {
                name: header.name.clone(),
                value: header.value.clone(),
            })
            .collect(),
        ..Default::default()
    };
    collect_parts(&mut payload, &mut parsed)?;
    Ok(parsed)
}

fn collect_parts(
    payload: &mut RawPayload,
    parsed: &mut ParsedPayload,
) -> Result<(), GoogleGmailError> {
    let header = |name: &str| {
        payload
            .headers
            .as_ref()
            .into_iter()
            .flatten()
            .find(|header| header.name.eq_ignore_ascii_case(name))
            .map(|header| header.value.clone())
    };
    let disposition = header("Content-Disposition").unwrap_or_default();
    let disposition = disposition.split(';').next().unwrap_or_default().trim();
    let content_id = header("Content-ID")
        .map(|value| {
            value
                .trim()
                .trim_start_matches('<')
                .trim_end_matches('>')
                .to_owned()
        })
        .filter(|value| !value.is_empty());
    let mime_type = payload
        .mime_type
        .as_deref()
        .unwrap_or("application/octet-stream");
    let text_plain = mime_type.eq_ignore_ascii_case("text/plain");
    let text_html = mime_type.eq_ignore_ascii_case("text/html");
    let filename = payload.filename.take().unwrap_or_default();
    let body = payload.body.take().unwrap_or_default();
    let attachment = !filename.is_empty()
        || disposition.eq_ignore_ascii_case("attachment")
        || body.attachment_id.is_some()
        || content_id.is_some()
        || (!text_plain
            && !text_html
            && !mime_type.starts_with("multipart/")
            && body.data.is_some());
    if attachment {
        if let Some(id) = &body.attachment_id {
            validate_resource_id(id, GoogleGmailError::InvalidResponse)?;
        }
        let data = body.data.as_deref().map(decode_body_data).transpose()?;
        if body
            .size
            .is_some_and(|size| size > MAX_HTTP_ATTACHMENT_BYTES as u64)
            || data
                .as_ref()
                .is_some_and(|data| data.len() > MAX_HTTP_ATTACHMENT_BYTES)
        {
            return Err(GoogleGmailError::InvalidResponse);
        }
        if let (Some(size), Some(data)) = (body.size, &data)
            && size != data.len() as u64
        {
            return Err(GoogleGmailError::InvalidResponse);
        }
        parsed.attachments.push(GmailAttachment {
            attachment_id: body.attachment_id,
            part_id: payload.part_id.take(),
            filename,
            mime_type: mime_type.to_owned(),
            size: body
                .size
                .unwrap_or_else(|| data.as_ref().map_or(0, |data| data.len() as u64)),
            inline: disposition.eq_ignore_ascii_case("inline") || content_id.is_some(),
            content_id,
            data,
        });
        // Do not promote a nested attached message's contents into this message.
        return Ok(());
    }
    if (text_plain || text_html)
        && let Some(data) = body.data
    {
        let text = String::from_utf8(decode_body_data(&data)?)
            .map_err(|_| GoogleGmailError::InvalidResponse)?;
        if text_plain && parsed.plain.is_none() {
            parsed.plain = Some(text);
        } else if text_html && parsed.html.is_none() {
            parsed.html = Some(strip_html_active_content(&text));
        }
    }
    for part in payload.parts.as_mut().into_iter().flatten() {
        collect_parts(part, parsed)?;
    }
    Ok(())
}

fn decode_body_data(data: &str) -> Result<Vec<u8>, GoogleGmailError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(data)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(data))
        .map_err(|_| GoogleGmailError::InvalidResponse)
}

fn classify_transport_error(error: reqwest::Error) -> GoogleGmailError {
    if error.is_timeout() {
        GoogleGmailError::Timeout
    } else {
        GoogleGmailError::Upstream
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{net::TcpListener, time::sleep};

    async fn fake_server(
        status: u16,
        retry_after: Option<&str>,
        body: &str,
        expected_query: &[(&str, &str)],
        expected_token: &str,
        delay: Option<Duration>,
    ) -> (Url, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = Url::parse(&format!(
            "http://{}/gmail/v1/",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        let response = format!(
            "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{}Connection: close\r\n\r\n{body}",
            body.len(),
            retry_after.map_or(String::new(), |value| format!("Retry-After: {value}\r\n")),
        );
        let expected_query: Vec<(String, String)> = expected_query
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect();
        let expected_token = expected_token.to_owned();
        let handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let stream = stream;
            let mut request = Vec::new();
            loop {
                stream.readable().await.unwrap();
                let mut chunk = [0_u8; 4096];
                match stream.try_read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        request.extend_from_slice(&chunk[..n]);
                        if request.windows(4).any(|window| window == b"\r\n\r\n") {
                            break;
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(_) => break,
                }
            }
            let request_text = String::from_utf8_lossy(&request);
            let request_line = request_text.lines().next().unwrap_or_default();
            let target = request_line.split_whitespace().nth(1).unwrap_or_default();
            let target_url = Url::parse(&format!("http://localhost{target}")).unwrap();
            for (name, value) in expected_query {
                assert_eq!(
                    target_url
                        .query_pairs()
                        .find(|(key, _)| key == &name)
                        .map(|(_, v)| v.into_owned()),
                    Some(value)
                );
            }
            assert!(request_text.lines().any(|line| {
                line.to_ascii_lowercase()
                    .starts_with("authorization: bearer ")
                    && line.ends_with(&expected_token)
            }));
            if let Some(delay) = delay {
                sleep(delay).await;
            }
            let mut written = 0;
            while written < response.len() {
                stream.writable().await.unwrap();
                match stream.try_write(&response.as_bytes()[written..]) {
                    Ok(n) => written += n,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(_) => break,
                }
            }
        });
        (endpoint, handle)
    }

    async fn write_server(
        expected_method: &str,
        expected_path: &str,
        expected_body_fragment: &str,
        status: u16,
        body: &str,
    ) -> (Url, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = Url::parse(&format!(
            "http://{}/gmail/v1/",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        let expected_method = expected_method.to_owned();
        let expected_path = expected_path.to_owned();
        let expected_body_fragment = expected_body_fragment.to_owned();
        let body = body.to_owned();
        let handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut expected_length = None;
            loop {
                stream.readable().await.unwrap();
                let mut chunk = [0_u8; 4096];
                match stream.try_read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => request.extend_from_slice(&chunk[..n]),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(error) => panic!("request read failed: {error}"),
                }
                if let Some(header_end) =
                    request.windows(4).position(|window| window == b"\r\n\r\n")
                {
                    let header_text = String::from_utf8_lossy(&request[..header_end]);
                    let content_length = header_text
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length: ")
                                .map(str::to_owned)
                        })
                        .and_then(|value| value.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    expected_length = Some(header_end + 4 + content_length);
                }
                if expected_length.is_some_and(|length| request.len() >= length) {
                    break;
                }
            }
            let request_text = String::from_utf8_lossy(&request);
            let first_line = request_text.lines().next().unwrap_or_default();
            assert_eq!(
                first_line,
                format!("{expected_method} {expected_path} HTTP/1.1")
            );
            assert!(
                request_text
                    .to_ascii_lowercase()
                    .contains("authorization: bearer access-token")
            );
            assert!(request_text.contains(&expected_body_fragment));
            let response = format!(
                "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let mut written = 0;
            while written < response.len() {
                stream.writable().await.unwrap();
                match stream.try_write(&response.as_bytes()[written..]) {
                    Ok(n) => written += n,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(error) => panic!("response write failed: {error}"),
                }
            }
        });
        (endpoint, handle)
    }

    fn client(endpoint: Url) -> GoogleGmailClient {
        GoogleGmailClient::with_base(
            Client::builder()
                .timeout(Duration::from_millis(40))
                .build()
                .unwrap(),
            endpoint,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn list_and_get_encode_requests_and_return_safe_dto() {
        let token = SecretString::from("access-token");
        let (endpoint, list_server) = fake_server(
            200,
            None,
            r#"{"messages":[{"id":"m1","threadId":"t1"}],"nextPageToken":"next","resultSizeEstimate":1}"#,
            &[
                ("q", "from:a@example.com subject:hello world"),
                ("maxResults", "20"),
                ("pageToken", "page + token"),
            ],
            "access-token",
            None,
        )
        .await;
        let result = client(endpoint)
            .list_messages(
                &token,
                Some("from:a@example.com subject:hello world"),
                Some(20),
                Some("page + token"),
            )
            .await
            .unwrap();
        assert_eq!(result.messages[0].id, "m1");
        assert_eq!(result.next_page_token.as_deref(), Some("next"));
        list_server.await.unwrap();

        let body = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("hello");
        let (endpoint, get_server) = fake_server(
            200,
            None,
            &format!(r#"{{"id":"m1","threadId":"t1","labelIds":["INBOX"],"snippet":"hi","internalDate":"1","payload":{{"mimeType":"text/plain","headers":[{{"name":"Subject","value":"Hi"}}],"body":{{"data":"{body}"}}}}}}"#),
            &[("format", "full")],
            "access-token",
            None,
        )
        .await;
        let message = client(endpoint)
            .get_message(&token, "m1", MessageFormat::Full)
            .await
            .unwrap();
        assert_eq!(message.body.as_deref(), Some("hello"));
        assert_eq!(message.headers[0].name, "Subject");
        get_server.await.unwrap();
    }

    #[tokio::test]
    async fn draft_writes_use_narrow_endpoints_and_base64url_raw() {
        let token = SecretString::from("access-token");
        let (endpoint, server) = write_server(
            "POST",
            "/gmail/v1/users/me/drafts",
            r#""raw":"aGVsbG8","threadId":"thread_1""#,
            200,
            r#"{"id":"draft_1","message":{"id":"message_1","threadId":"thread_1"}}"#,
        )
        .await;
        let draft = client(endpoint)
            .create_draft(&token, b"hello", Some("thread_1"))
            .await
            .unwrap();
        assert_eq!(draft.id, "draft_1");
        assert_eq!(draft.message_id, "message_1");
        server.await.unwrap();

        let (endpoint, server) = write_server(
            "PUT",
            "/gmail/v1/users/me/drafts/draft_1",
            r#""raw":"dXBkYXRlZA""#,
            200,
            r#"{"id":"draft_1","message":{"id":"message_2"}}"#,
        )
        .await;
        let updated = client(endpoint)
            .update_draft(&token, "draft_1", b"updated", None)
            .await
            .unwrap();
        assert_eq!(updated.message_id, "message_2");
        server.await.unwrap();

        let (endpoint, server) = write_server(
            "POST",
            "/gmail/v1/users/me/drafts/send",
            r#""id":"draft_1""#,
            200,
            r#"{"id":"sent_1","threadId":"thread_1"}"#,
        )
        .await;
        let sent = client(endpoint)
            .send_draft(&token, "draft_1")
            .await
            .unwrap();
        assert_eq!(sent.message_id, "sent_1");
        server.await.unwrap();

        let (endpoint, server) =
            write_server("DELETE", "/gmail/v1/users/me/drafts/draft_1", "", 204, "").await;
        client(endpoint)
            .delete_draft(&token, "draft_1")
            .await
            .unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn draft_ids_and_thread_ids_are_validated_before_transport() {
        let client = GoogleGmailClient::new().unwrap();
        let token = SecretString::from("access-token");
        assert_eq!(
            client.delete_draft(&token, "../draft").await.unwrap_err(),
            GoogleGmailError::InvalidDraftId
        );
        assert_eq!(
            client
                .create_draft(&token, b"x", Some("bad/thread"))
                .await
                .unwrap_err(),
            GoogleGmailError::InvalidMessageId
        );
    }

    #[test]
    fn plain_text_is_preferred_and_html_is_sanitized() {
        let encoded = |value: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value);
        let raw: RawMessage = serde_json::from_value(serde_json::json!({
            "id": "m1", "payload": { "mimeType": "multipart/mixed",
            "headers": [{"name":"Subject", "value":"top"}],
            "parts": [
                {"mimeType":"text/plain", "filename":"note.txt", "partId":"0",
                 "body":{"attachmentId":"a1", "size":4}},
                {"mimeType":"multipart/alternative", "parts":[
                    {"mimeType":"text/html", "body":{"data":encoded("<script>x</script><p>html</p>")}},
                    {"mimeType":"text/plain", "headers":[{"name":"Subject","value":"nested"}],
                     "body":{"data":encoded("plain")}}
                ]},
                {"mimeType":"image/png", "filename":"picture.png", "partId":"2",
                 "headers":[{"name":"Content-Disposition","value":"inline; filename=picture.png"},
                            {"name":"Content-ID","value":"<picture>"}],
                 "body":{"attachmentId":"a2", "size":10}},
                {"mimeType":"text/plain", "headers":[{"name":"Content-Disposition","value":"attachment"}],
                 "body":{"data":encoded("attachment"),"size":10}}
            ]}
        })).unwrap();
        let message = GmailMessage::try_from(raw).unwrap();
        assert_eq!(message.body.as_deref(), Some("plain"));
        assert!(!message.body_is_html);
        assert_eq!(message.html_body.as_deref(), Some("<p>html</p>"));
        assert_eq!(message.headers.len(), 1);
        assert_eq!(message.headers[0].value, "top");
        assert_eq!(message.attachments.len(), 3);
        assert_eq!(message.attachments[0].attachment_id.as_deref(), Some("a1"));
        assert_eq!(message.attachments[0].part_id.as_deref(), Some("0"));
        assert_eq!(
            message.attachments[1].content_id.as_deref(),
            Some("picture")
        );
        assert!(message.attachments[1].inline);
        assert_eq!(
            message.attachments[2].data.as_deref(),
            Some(b"attachment".as_slice())
        );

        let raw: RawMessage = serde_json::from_value(serde_json::json!({"id":"m2", "payload":{
            "mimeType":"text/html", "body":{"data":encoded("<script>x</script><p>html</p>")}
        }}))
        .unwrap();
        let message = GmailMessage::try_from(raw).unwrap();
        assert_eq!(message.body.as_deref(), Some("<p>html</p>"));
        assert!(message.body_is_html);
    }

    #[tokio::test]
    async fn thread_draft_and_attachment_reads_use_narrow_endpoints() {
        let token = SecretString::from("access-token");
        let (endpoint, server) = write_server(
            "GET",
            "/gmail/v1/users/me/threads/t1?format=full",
            "",
            200,
            r#"{"id":"t1","messages":[{"id":"m1"},{"id":"m2"}]}"#,
        )
        .await;
        let thread = client(endpoint)
            .get_thread(&token, "t1", MessageFormat::Full)
            .await
            .unwrap();
        assert_eq!(thread.messages.len(), 2);
        server.await.unwrap();

        let (endpoint, server) = write_server("GET", "/gmail/v1/users/me/drafts?q=hello+world&maxResults=2&pageToken=next%2Bpage", "", 200,
            r#"{"drafts":[{"id":"d1","message":{"id":"m1","threadId":"t1"}}],"nextPageToken":"p2","resultSizeEstimate":3}"#).await;
        let drafts = client(endpoint)
            .list_drafts(&token, Some("hello world"), Some(2), Some("next+page"))
            .await
            .unwrap();
        assert_eq!(drafts.drafts[0].id, "d1");
        assert_eq!(drafts.next_page_token.as_deref(), Some("p2"));
        assert_eq!(drafts.result_size_estimate, Some(3));
        server.await.unwrap();

        let (endpoint, server) = write_server("GET", "/gmail/v1/users/me/drafts/d1?format=full", "", 200,
            r#"{"id":"d1","message":{"id":"m1","payload":{"mimeType":"text/plain","body":{"data":"aGVsbG8"}}}}"#).await;
        let draft = client(endpoint).get_draft(&token, "d1").await.unwrap();
        assert_eq!(draft.message.body.as_deref(), Some("hello"));
        server.await.unwrap();

        let (endpoint, server) = write_server(
            "GET",
            "/gmail/v1/users/me/messages/m1/attachments/a1",
            "",
            200,
            r#"{"size":5,"data":"aGVsbG8="}"#,
        )
        .await;
        let attachment = client(endpoint)
            .get_attachment(&token, "m1", "a1")
            .await
            .unwrap();
        assert_eq!(attachment.data, b"hello");
        assert_eq!(attachment.size, 5);
        assert!(!format!("{attachment:?}").contains("hello"));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn attachment_reads_reject_invalid_size_encoding_and_resource_ids() {
        let token = SecretString::from("access-token");
        for body in [
            r#"{"size":4,"data":"aGVsbG8"}"#.to_owned(),
            r#"{"size":5,"data":"%%%"}"#.to_owned(),
            r#"{"size":5}"#.to_owned(),
            format!(r#"{{"size":{},"data":""}}"#, MAX_HTTP_ATTACHMENT_BYTES + 1),
        ] {
            let (endpoint, server) = write_server(
                "GET",
                "/gmail/v1/users/me/messages/m1/attachments/a1",
                "",
                200,
                &body,
            )
            .await;
            assert_eq!(
                client(endpoint)
                    .get_attachment(&token, "m1", "a1")
                    .await
                    .unwrap_err(),
                GoogleGmailError::InvalidResponse
            );
            server.await.unwrap();
        }
        let gmail = GoogleGmailClient::new().unwrap();
        assert_eq!(
            gmail
                .get_thread(&token, "../t1", MessageFormat::Full)
                .await
                .unwrap_err(),
            GoogleGmailError::InvalidThreadId
        );
        assert_eq!(
            gmail.get_draft(&token, "bad/id").await.unwrap_err(),
            GoogleGmailError::InvalidDraftId
        );
        assert_eq!(
            gmail
                .get_attachment(&token, "bad/id", "a1")
                .await
                .unwrap_err(),
            GoogleGmailError::InvalidMessageId
        );
        assert_eq!(
            gmail
                .get_attachment(&token, "m1", "a1?alt=media")
                .await
                .unwrap_err(),
            GoogleGmailError::InvalidAttachmentId
        );
        assert_eq!(
            gmail
                .list_drafts(&token, None, Some(501), None)
                .await
                .unwrap_err(),
            GoogleGmailError::InvalidPageSize
        );
        assert_eq!(
            gmail
                .get_draft(&SecretString::from(""), "d1")
                .await
                .unwrap_err(),
            GoogleGmailError::EmptyAccessToken
        );
    }

    #[tokio::test]
    async fn errors_are_stable_and_debug_does_not_leak_credentials() {
        let cases = [
            (
                401,
                None,
                r#"{"error":{"message":"secret-body"}}"#,
                GoogleGmailError::ReauthRequired,
            ),
            (
                429,
                Some("17"),
                r#"{"error":{"message":"secret-body"}}"#,
                GoogleGmailError::RateLimited {
                    retry_after_seconds: Some(17),
                },
            ),
            (
                404,
                None,
                r#"{"error":{"message":"secret-body"}}"#,
                GoogleGmailError::NotFound,
            ),
            (
                500,
                None,
                r#"{"error":{"message":"secret-body"}}"#,
                GoogleGmailError::Upstream,
            ),
            (200, None, "not-json", GoogleGmailError::InvalidResponse),
        ];
        for (status, retry_after, body, expected) in cases {
            let (endpoint, server) =
                fake_server(status, retry_after, body, &[], "access-token", None).await;
            let error = client(endpoint)
                .list_messages(&SecretString::from("access-token"), None, None, None)
                .await
                .unwrap_err();
            assert_eq!(error, expected);
            assert!(!error.to_string().contains("secret-body"));
            server.await.unwrap();
        }

        let oversized = format!(
            "{{\"messages\":[],\"padding\":\"{}\"}}",
            "x".repeat(MAX_JSON_RESPONSE_BYTES)
        );
        let (endpoint, server) =
            fake_server(200, None, &oversized, &[], "access-token", None).await;
        let error = client(endpoint)
            .list_messages(&SecretString::from("access-token"), None, None, None)
            .await
            .unwrap_err();
        assert_eq!(error, GoogleGmailError::InvalidResponse);
        server.await.unwrap();

        let debug = format!("{:?}", client(Url::parse(GMAIL_API_BASE).unwrap()));
        assert!(!debug.contains("access-token"));
        assert!(debug.contains("REDACTED"));
    }

    #[tokio::test]
    async fn timeout_and_redirect_ssrf_guards_work() {
        let (endpoint, server) = fake_server(
            200,
            None,
            r#"{"messages":[]}"#,
            &[],
            "access-token",
            Some(Duration::from_millis(100)),
        )
        .await;
        let error = client(endpoint)
            .list_messages(&SecretString::from("access-token"), None, None, None)
            .await
            .unwrap_err();
        assert_eq!(error, GoogleGmailError::Timeout);
        let _ = server.await;

        let http = Client::new();
        for value in [
            "https://evil.example/gmail/v1/",
            "http://evil.example/gmail/v1/",
            "http://localhost/gmail/v1/?q=evil",
            "https://gmail.googleapis.com/gmail/v1/?q=evil",
            "https://user:pass@gmail.com/gmail/v1/",
            "https://gmail.googleapis.com/gmail/v1/#fragment",
        ] {
            assert!(
                GoogleGmailClient::with_base(http.clone(), Url::parse(value).unwrap()).is_err()
            );
        }
    }
}

//! External service adapters.

use crate::domain::{
    identity::ConnectionId,
    mailbox::{AttachmentInfo, EmailAddress, MessageMetadata},
};
use crate::mime::ReplyHeaders;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt, sync::Arc};
use tokio::sync::RwLock;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MailMessagePage {
    pub messages: Vec<MailMessage>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MailHeader {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug)]
pub struct MailAttachment {
    pub info: AttachmentInfo,
    pub data: Vec<u8>,
    pub inline_content_id: Option<String>,
}

type AttachmentStore = HashMap<(ConnectionId, String, String), MailAttachment>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MailMessage {
    pub metadata: MessageMetadata,
    pub body: String,
    pub body_is_html: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub html_body: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<MailHeader>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MailDraft {
    pub id: String,
    pub stable_message_id: String,
    pub thread_id: Option<String>,
    pub subject: String,
    pub body: String,
    pub to: Vec<EmailAddress>,
    pub cc: Vec<EmailAddress>,
    pub bcc: Vec<EmailAddress>,
    pub attachments: Vec<AttachmentInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub html_body: Option<String>,
    #[serde(skip)]
    pub reply_headers: Option<ReplyHeaders>,
    #[serde(skip)]
    pub attachment_data: Vec<MailAttachment>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdapterError {
    InvalidInput,
    NotFound,
    RateLimited { retry_after_seconds: u64 },
    ReauthRequired,
    Unavailable,
    Timeout,
}
impl fmt::Display for AdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput => f.write_str("invalid input"),
            Self::NotFound => f.write_str("not found"),
            Self::RateLimited { .. } => f.write_str("rate limited"),
            Self::ReauthRequired => f.write_str("reauthorization required"),
            Self::Unavailable => f.write_str("upstream unavailable"),
            Self::Timeout => f.write_str("upstream timeout"),
        }
    }
}
impl std::error::Error for AdapterError {}

#[async_trait]
pub trait GmailAdapter: Send + Sync {
    async fn list_messages(
        &self,
        connection: ConnectionId,
        query: Option<&str>,
        page_size: usize,
        cursor: Option<&str>,
    ) -> Result<MailMessagePage, AdapterError>;
    async fn get_message(
        &self,
        connection: ConnectionId,
        message_id: &str,
    ) -> Result<MailMessage, AdapterError>;
    async fn get_thread(
        &self,
        connection: ConnectionId,
        thread_id: &str,
    ) -> Result<Vec<MailMessage>, AdapterError>;
    async fn get_attachment(
        &self,
        connection: ConnectionId,
        message_id: &str,
        attachment_id: &str,
    ) -> Result<MailAttachment, AdapterError>;
    async fn list_drafts(&self, connection: ConnectionId) -> Result<Vec<MailDraft>, AdapterError>;
    async fn get_draft(
        &self,
        connection: ConnectionId,
        draft_id: &str,
    ) -> Result<MailDraft, AdapterError>;
    async fn create_draft(
        &self,
        connection: ConnectionId,
        draft: MailDraft,
    ) -> Result<MailDraft, AdapterError>;
    async fn update_draft(
        &self,
        connection: ConnectionId,
        draft: MailDraft,
    ) -> Result<MailDraft, AdapterError>;
    async fn delete_draft(
        &self,
        connection: ConnectionId,
        draft_id: &str,
    ) -> Result<(), AdapterError>;
    async fn send_draft(
        &self,
        connection: ConnectionId,
        draft_id: &str,
    ) -> Result<String, AdapterError>;
    /// Reconcile an already-attempted send by its system-generated RFC Message-ID.
    /// Implementations must not send or retry the draft from this method.
    async fn find_sent_message(
        &self,
        _connection: ConnectionId,
        _stable_message_id: &str,
    ) -> Result<Option<String>, AdapterError> {
        Ok(None)
    }
}

#[derive(Clone, Default)]
pub struct FakeGmailAdapter {
    messages: Arc<RwLock<HashMap<(ConnectionId, String), MailMessage>>>,
    attachments: Arc<RwLock<AttachmentStore>>,
    drafts: Arc<RwLock<HashMap<(ConnectionId, String), MailDraft>>>,
}
impl FakeGmailAdapter {
    pub fn new() -> Self {
        Self::default()
    }
    pub async fn insert_message(&self, connection: ConnectionId, message: MailMessage) {
        self.messages
            .write()
            .await
            .insert((connection, message.metadata.id.clone()), message);
    }
    pub async fn insert_draft(&self, connection: ConnectionId, draft: MailDraft) {
        self.drafts
            .write()
            .await
            .insert((connection, draft.id.clone()), draft);
    }
    pub async fn insert_attachment(
        &self,
        connection: ConnectionId,
        message_id: impl Into<String>,
        attachment: MailAttachment,
    ) {
        self.attachments.write().await.insert(
            (connection, message_id.into(), attachment.info.id.clone()),
            attachment,
        );
    }
}
#[async_trait]
impl GmailAdapter for FakeGmailAdapter {
    async fn list_messages(
        &self,
        connection: ConnectionId,
        query: Option<&str>,
        page_size: usize,
        cursor: Option<&str>,
    ) -> Result<MailMessagePage, AdapterError> {
        if cursor.is_some_and(|value| !value.is_empty()) {
            return Err(AdapterError::InvalidInput);
        }
        let mut values: Vec<_> = self
            .messages
            .read()
            .await
            .iter()
            .filter(|((id, _), m)| {
                *id == connection
                    && query.is_none_or(|q| {
                        m.metadata.subject.contains(q) || m.metadata.snippet.contains(q)
                    })
            })
            .map(|(_, m)| m.clone())
            .collect();
        values.truncate(page_size.min(100));
        Ok(MailMessagePage {
            messages: values,
            next_cursor: None,
        })
    }
    async fn get_message(
        &self,
        connection: ConnectionId,
        message_id: &str,
    ) -> Result<MailMessage, AdapterError> {
        self.messages
            .read()
            .await
            .get(&(connection, message_id.to_owned()))
            .cloned()
            .ok_or(AdapterError::NotFound)
    }
    async fn get_thread(
        &self,
        connection: ConnectionId,
        thread_id: &str,
    ) -> Result<Vec<MailMessage>, AdapterError> {
        let mut messages = self
            .messages
            .read()
            .await
            .iter()
            .filter(|((id, _), message)| {
                *id == connection && message.metadata.thread_id.as_deref() == Some(thread_id)
            })
            .map(|(_, message)| message.clone())
            .collect::<Vec<_>>();
        messages.sort_by(|left, right| left.metadata.sent_at.cmp(&right.metadata.sent_at));
        if messages.is_empty() {
            Err(AdapterError::NotFound)
        } else {
            Ok(messages)
        }
    }
    async fn get_attachment(
        &self,
        connection: ConnectionId,
        message_id: &str,
        attachment_id: &str,
    ) -> Result<MailAttachment, AdapterError> {
        self.attachments
            .read()
            .await
            .get(&(connection, message_id.to_owned(), attachment_id.to_owned()))
            .cloned()
            .ok_or(AdapterError::NotFound)
    }
    async fn list_drafts(&self, connection: ConnectionId) -> Result<Vec<MailDraft>, AdapterError> {
        Ok(self
            .drafts
            .read()
            .await
            .iter()
            .filter(|((id, _), _)| *id == connection)
            .map(|(_, d)| d.clone())
            .collect())
    }
    async fn get_draft(
        &self,
        connection: ConnectionId,
        draft_id: &str,
    ) -> Result<MailDraft, AdapterError> {
        self.drafts
            .read()
            .await
            .get(&(connection, draft_id.to_owned()))
            .cloned()
            .ok_or(AdapterError::NotFound)
    }
    async fn create_draft(
        &self,
        connection: ConnectionId,
        draft: MailDraft,
    ) -> Result<MailDraft, AdapterError> {
        self.drafts
            .write()
            .await
            .insert((connection, draft.id.clone()), draft.clone());
        Ok(draft)
    }
    async fn update_draft(
        &self,
        connection: ConnectionId,
        draft: MailDraft,
    ) -> Result<MailDraft, AdapterError> {
        let mut d = self.drafts.write().await;
        if !d.contains_key(&(connection, draft.id.clone())) {
            return Err(AdapterError::NotFound);
        }
        d.insert((connection, draft.id.clone()), draft.clone());
        Ok(draft)
    }
    async fn delete_draft(
        &self,
        connection: ConnectionId,
        draft_id: &str,
    ) -> Result<(), AdapterError> {
        self.drafts
            .write()
            .await
            .remove(&(connection, draft_id.to_owned()))
            .map(|_| ())
            .ok_or(AdapterError::NotFound)
    }
    async fn send_draft(
        &self,
        connection: ConnectionId,
        draft_id: &str,
    ) -> Result<String, AdapterError> {
        if self
            .drafts
            .read()
            .await
            .contains_key(&(connection, draft_id.to_owned()))
        {
            Ok(format!("fake-sent-{draft_id}"))
        } else {
            Err(AdapterError::NotFound)
        }
    }
}

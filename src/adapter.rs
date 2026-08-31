//! External service adapters.

use crate::domain::{
    identity::ConnectionId,
    mailbox::{AttachmentInfo, EmailAddress, MessageMetadata},
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt, sync::Arc};
use tokio::sync::RwLock;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MailMessage {
    pub metadata: MessageMetadata,
    pub body: String,
    pub body_is_html: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MailDraft {
    pub id: String,
    pub thread_id: Option<String>,
    pub subject: String,
    pub body: String,
    pub to: Vec<EmailAddress>,
    pub cc: Vec<EmailAddress>,
    pub bcc: Vec<EmailAddress>,
    pub attachments: Vec<AttachmentInfo>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdapterError {
    NotFound,
    RateLimited { retry_after_seconds: u64 },
    Unavailable,
    Timeout,
}
impl fmt::Display for AdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("not found"),
            Self::RateLimited { .. } => f.write_str("rate limited"),
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
    ) -> Result<Vec<MailMessage>, AdapterError>;
    async fn get_message(
        &self,
        connection: ConnectionId,
        message_id: &str,
    ) -> Result<MailMessage, AdapterError>;
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
}

#[derive(Clone, Default)]
pub struct FakeGmailAdapter {
    messages: Arc<RwLock<HashMap<(ConnectionId, String), MailMessage>>>,
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
}
#[async_trait]
impl GmailAdapter for FakeGmailAdapter {
    async fn list_messages(
        &self,
        connection: ConnectionId,
        query: Option<&str>,
        page_size: usize,
    ) -> Result<Vec<MailMessage>, AdapterError> {
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
        Ok(values)
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

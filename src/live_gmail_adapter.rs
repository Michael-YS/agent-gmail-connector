//! Production Gmail adapter for reads and AgentMail-managed draft writes.
//!
//! Access tokens are obtained per connection through [`GmailCredentialProvider`].
//! MIME is constructed locally through the bounded safe builder. Production
//! must never fall back to the in-memory fake.

use crate::{
    adapter::{AdapterError, GmailAdapter, MailDraft, MailMessage},
    domain::{
        identity::{ConnectionId, GmailConnection},
        mailbox::{EmailAddress, MessageMetadata, Recipients},
    },
    gmail_credentials::{CredentialError, GmailCredentialProvider},
    google_gmail::{GmailMessage, GoogleGmailClient, GoogleGmailError, MessageFormat},
    google_token::GoogleTokenClient,
    mime::{MimeMessage, build_mime},
    repository::Repository,
};
use async_trait::async_trait;
use secrecy::SecretString;
use std::{fmt, sync::Arc, time::Duration};

const LIST_REQUEST_DEADLINE: Duration = Duration::from_secs(30);
const LIST_FETCH_CONCURRENCY: usize = 4;

pub struct LiveGmailAdapter {
    repository: Repository,
    credentials: Arc<GmailCredentialProvider<Repository, GoogleTokenClient>>,
    gmail: GoogleGmailClient,
}

impl LiveGmailAdapter {
    pub fn new(
        repository: Repository,
        credentials: Arc<GmailCredentialProvider<Repository, GoogleTokenClient>>,
        gmail: GoogleGmailClient,
    ) -> Self {
        Self {
            repository,
            credentials,
            gmail,
        }
    }

    async fn access_token(
        &self,
        connection_id: ConnectionId,
    ) -> Result<SecretString, AdapterError> {
        self.connection_and_access_token(connection_id)
            .await
            .map(|(_, token)| token)
    }

    async fn connection_and_access_token(
        &self,
        connection_id: ConnectionId,
    ) -> Result<(GmailConnection, SecretString), AdapterError> {
        let connection = self
            .repository
            .get_connection(connection_id)
            .await
            .map_err(|_| AdapterError::Unavailable)?
            .ok_or(AdapterError::NotFound)?;
        match self
            .credentials
            .access_token(connection.owner_id, connection_id)
            .await
        {
            Ok(token) => Ok((connection, token)),
            Err(CredentialError::ReauthRequired) => {
                self.credentials.invalidate(connection_id).await;
                Err(AdapterError::Unavailable)
            }
            Err(error) => Err(map_credential_error(error)),
        }
    }

    async fn list_messages_with_deadline(
        &self,
        connection: ConnectionId,
        query: Option<&str>,
        page_size: usize,
    ) -> Result<Vec<MailMessage>, AdapterError> {
        let token = self.access_token(connection).await?;
        let page_size = page_size.clamp(1, 100);
        let list_result = self
            .gmail
            .list_messages(&token, query, Some(page_size as u32), None)
            .await;
        let list = self.map_gmail_result(connection, list_result).await?;
        let mut pending = list.messages.into_iter().take(page_size).enumerate();
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..LIST_FETCH_CONCURRENCY {
            let Some((index, item)) = pending.next() else {
                break;
            };
            spawn_metadata_fetch(
                &mut tasks,
                self.gmail.clone(),
                token.clone(),
                index,
                item.id,
            );
        }

        let mut messages = Vec::with_capacity(page_size);
        while let Some(joined) = tasks.join_next().await {
            let (index, result) = joined.map_err(|_| AdapterError::Unavailable)?;
            let message = self.map_gmail_result(connection, result).await?;
            messages.push((index, to_mail_message(message)));
            if let Some((next_index, item)) = pending.next() {
                spawn_metadata_fetch(
                    &mut tasks,
                    self.gmail.clone(),
                    token.clone(),
                    next_index,
                    item.id,
                );
            }
        }
        messages.sort_unstable_by_key(|(index, _)| *index);
        Ok(messages.into_iter().map(|(_, message)| message).collect())
    }
    async fn map_gmail_result<T>(
        &self,
        connection_id: ConnectionId,
        result: Result<T, GoogleGmailError>,
    ) -> Result<T, AdapterError> {
        match result {
            Ok(value) => Ok(value),
            Err(GoogleGmailError::ReauthRequired) => {
                self.credentials.invalidate(connection_id).await;
                Err(AdapterError::Unavailable)
            }
            Err(error) => Err(map_gmail_error(error)),
        }
    }
}

impl fmt::Debug for LiveGmailAdapter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LiveGmailAdapter")
            .field("repository", &"[repository]")
            .field("credentials", &"[REDACTED]")
            .field("gmail", &self.gmail)
            .finish()
    }
}

#[async_trait]
impl GmailAdapter for LiveGmailAdapter {
    async fn list_messages(
        &self,
        connection: ConnectionId,
        query: Option<&str>,
        page_size: usize,
    ) -> Result<Vec<MailMessage>, AdapterError> {
        tokio::time::timeout(
            LIST_REQUEST_DEADLINE,
            self.list_messages_with_deadline(connection, query, page_size),
        )
        .await
        .map_err(|_| AdapterError::Timeout)?
    }
    async fn get_message(
        &self,
        connection: ConnectionId,
        message_id: &str,
    ) -> Result<MailMessage, AdapterError> {
        let token = self.access_token(connection).await?;
        let result = self
            .gmail
            .get_message(&token, message_id, MessageFormat::Full)
            .await;
        self.map_gmail_result(connection, result)
            .await
            .map(to_mail_message)
    }

    async fn list_drafts(&self, _connection: ConnectionId) -> Result<Vec<MailDraft>, AdapterError> {
        Err(AdapterError::Unavailable)
    }

    async fn get_draft(
        &self,
        _connection: ConnectionId,
        _draft_id: &str,
    ) -> Result<MailDraft, AdapterError> {
        Err(AdapterError::Unavailable)
    }

    async fn create_draft(
        &self,
        connection: ConnectionId,
        mut draft: MailDraft,
    ) -> Result<MailDraft, AdapterError> {
        let (connection_record, token) = self.connection_and_access_token(connection).await?;
        let raw = build_draft_mime(&connection_record, &draft)?;
        let result = self
            .gmail
            .create_draft(&token, &raw, draft.thread_id.as_deref())
            .await;
        let created = self.map_gmail_result(connection, result).await?;
        draft.id = created.id;
        draft.thread_id = created.thread_id.or(draft.thread_id);
        Ok(draft)
    }

    async fn update_draft(
        &self,
        connection: ConnectionId,
        mut draft: MailDraft,
    ) -> Result<MailDraft, AdapterError> {
        let (connection_record, token) = self.connection_and_access_token(connection).await?;
        let raw = build_draft_mime(&connection_record, &draft)?;
        let result = self
            .gmail
            .update_draft(&token, &draft.id, &raw, draft.thread_id.as_deref())
            .await;
        let updated = self.map_gmail_result(connection, result).await?;
        draft.id = updated.id;
        draft.thread_id = updated.thread_id.or(draft.thread_id);
        Ok(draft)
    }

    async fn delete_draft(
        &self,
        connection: ConnectionId,
        draft_id: &str,
    ) -> Result<(), AdapterError> {
        let token = self.access_token(connection).await?;
        let result = self.gmail.delete_draft(&token, draft_id).await;
        self.map_gmail_result(connection, result).await
    }

    async fn send_draft(
        &self,
        _connection: ConnectionId,
        _draft_id: &str,
    ) -> Result<String, AdapterError> {
        // Fail closed until confirmations/outcomes are durable and a lost send
        // response can be reconciled by stable RFC Message-ID.
        Err(AdapterError::Unavailable)
    }
}

fn build_draft_mime(
    connection: &GmailConnection,
    draft: &MailDraft,
) -> Result<Vec<u8>, AdapterError> {
    if !draft.attachments.is_empty() {
        return Err(AdapterError::InvalidInput);
    }
    let from = EmailAddress::new(&connection.email).map_err(|_| AdapterError::InvalidInput)?;
    let recipients = Recipients::new(draft.to.clone(), draft.cc.clone(), draft.bcc.clone())
        .map_err(|_| AdapterError::InvalidInput)?;
    build_mime(MimeMessage {
        from,
        recipients,
        subject: draft.subject.clone(),
        text_body: Some(draft.body.clone()),
        html_body: None,
        stable_message_id: draft.stable_message_id.clone(),
        reply_headers: None,
        attachments: Vec::new(),
    })
    .map_err(|_| AdapterError::InvalidInput)
}

fn spawn_metadata_fetch(
    tasks: &mut tokio::task::JoinSet<(usize, Result<GmailMessage, GoogleGmailError>)>,
    gmail: GoogleGmailClient,
    token: SecretString,
    index: usize,
    message_id: String,
) {
    tasks.spawn(async move {
        (
            index,
            gmail
                .get_message(&token, &message_id, MessageFormat::Metadata)
                .await,
        )
    });
}

fn to_mail_message(message: GmailMessage) -> MailMessage {
    let subject = safe_text(header_value(&message, "subject").unwrap_or_default(), 998);
    let snippet = safe_text(message.snippet.as_deref().unwrap_or_default(), 4096);
    let from = header_value(&message, "from").and_then(parse_address);
    let to = header_value(&message, "to")
        .map(parse_address_list)
        .unwrap_or_default();
    let cc = header_value(&message, "cc")
        .map(parse_address_list)
        .unwrap_or_default();
    let sent_at = message
        .internal_date
        .as_deref()
        .map(|value| safe_text(value, 64))
        .filter(|value| !value.is_empty())
        .or_else(|| header_value(&message, "date").map(|value| safe_text(value, 256)));
    MailMessage {
        metadata: MessageMetadata {
            id: message.id,
            thread_id: message.thread_id,
            sent_at,

            from,
            to,
            cc,
            subject,
            snippet,
            attachments: Vec::new(),
        },
        body: message.body.unwrap_or_default(),
        body_is_html: message.body_is_html,
    }
}

fn header_value<'a>(message: &'a GmailMessage, name: &str) -> Option<&'a str> {
    message
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value.as_str())
}

fn parse_address(value: &str) -> Option<EmailAddress> {
    let value = value.trim();
    let candidate = value
        .rfind('<')
        .and_then(|start| {
            value[start + 1..]
                .find('>')
                .map(|end| &value[start + 1..start + 1 + end])
        })
        .unwrap_or(value)
        .trim();
    EmailAddress::new(candidate).ok()
}

fn parse_address_list(value: &str) -> Vec<EmailAddress> {
    let mut addresses = Vec::new();
    for part in value.split(',') {
        if let Some(address) = parse_address(part)
            && !addresses.contains(&address)
        {
            addresses.push(address);
        }
    }
    addresses
}

fn safe_text(value: &str, max_chars: usize) -> String {
    value
        .chars()
        .filter(|character| !matches!(character, '\r' | '\n' | '\0'))
        .take(max_chars)
        .collect()
}

fn map_credential_error(error: CredentialError) -> AdapterError {
    match error {
        CredentialError::RateLimited {
            retry_after_seconds,
        } => AdapterError::RateLimited {
            retry_after_seconds: retry_after_seconds.unwrap_or(60).max(1),
        },
        CredentialError::Timeout => AdapterError::Timeout,
        CredentialError::AccessDenied
        | CredentialError::ReauthRequired
        | CredentialError::InvalidCredential
        | CredentialError::StoreUnavailable
        | CredentialError::Upstream
        | CredentialError::InvalidResponse => AdapterError::Unavailable,
    }
}

fn map_gmail_error(error: GoogleGmailError) -> AdapterError {
    match error {
        GoogleGmailError::RateLimited {
            retry_after_seconds,
        } => AdapterError::RateLimited {
            retry_after_seconds: retry_after_seconds.unwrap_or(60).max(1),
        },
        GoogleGmailError::Timeout => AdapterError::Timeout,
        GoogleGmailError::InvalidMessageId
        | GoogleGmailError::InvalidDraftId
        | GoogleGmailError::NotFound => AdapterError::NotFound,
        GoogleGmailError::EmptyAccessToken
        | GoogleGmailError::ReauthRequired
        | GoogleGmailError::Upstream
        | GoogleGmailError::InvalidPageSize
        | GoogleGmailError::InvalidResponse => AdapterError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::google_gmail::MessageHeader;

    #[test]
    fn maps_safe_metadata_and_sanitizes_control_characters() {
        let mapped = to_mail_message(GmailMessage {
            id: "m1".into(),
            thread_id: Some("t1".into()),
            label_ids: vec![],
            snippet: Some("safe\r\nlog".into()),
            internal_date: Some("1700000000000".into()),
            headers: vec![
                MessageHeader {
                    name: "From".into(),
                    value: "Sender <sender@example.com>".into(),
                },
                MessageHeader {
                    name: "To".into(),
                    value: "one@example.com, Two <two@example.com>".into(),
                },
                MessageHeader {
                    name: "Subject".into(),
                    value: "hello\r\nBcc: hidden@example.com".into(),
                },
            ],
            body: Some("body".into()),
            body_is_html: false,
            untrusted_email_content: true,
        });
        assert_eq!(mapped.metadata.from.unwrap().as_str(), "sender@example.com");
        assert_eq!(mapped.metadata.to.len(), 2);
        assert!(!mapped.metadata.subject.contains(['\r', '\n']));
        assert!(!mapped.metadata.snippet.contains(['\r', '\n']));
        assert_eq!(mapped.body, "body");
    }

    #[test]
    fn error_mapping_is_stable_and_does_not_embed_upstream_data() {
        assert_eq!(
            map_gmail_error(GoogleGmailError::RateLimited {
                retry_after_seconds: None,
            }),
            AdapterError::RateLimited {
                retry_after_seconds: 60,
            }
        );
        assert_eq!(
            map_credential_error(CredentialError::InvalidCredential),
            AdapterError::Unavailable
        );
    }
}

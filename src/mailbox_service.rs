//! Shared read-only mailbox application service.
//!
//! REST and MCP should call this service instead of implementing their own
//! adapter, pagination, and content-shaping rules. Email bodies are not
//! returned by search; only safe message metadata crosses this boundary.

use crate::{
    adapter::{AdapterError, GmailAdapter},
    domain::{identity::ConnectionId, mailbox::MessageMetadata},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, Weak},
};
use thiserror::Error;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

const DEFAULT_PAGE_SIZE: usize = 20;
const MAX_PAGE_SIZE: usize = 100;

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum MailboxReadError {
    #[error(transparent)]
    Adapter(#[from] AdapterError),
    #[error("opaque cursor pagination is not supported yet")]
    CursorNotSupported,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MessageSearchResult {
    pub messages: Vec<MessageMetadata>,
    pub next_cursor: Option<String>,
}

#[derive(Clone)]
pub struct MailboxReadService {
    // Keep one weak semaphore per Connection; inactive entries are reclaimed
    // on later calls without evicting a semaphore that still has waiters.
    adapter: Arc<dyn GmailAdapter>,
    per_connection_limits: Arc<Mutex<HashMap<ConnectionId, Weak<Semaphore>>>>,
}

impl MailboxReadService {
    pub fn new(adapter: Arc<dyn GmailAdapter>) -> Self {
        Self {
            adapter,
            per_connection_limits: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Search one explicitly-selected Connection. `q` is passed to the
    /// adapter but is never retained, logged, or included in the result.
    /// Pagination remains deliberately unavailable until the adapter can
    /// return an upstream page token; accepting a fake cursor would be unsafe.
    pub async fn search(
        &self,
        connection: ConnectionId,
        query: Option<&str>,
        page_size: Option<usize>,
        cursor: Option<&str>,
    ) -> Result<MessageSearchResult, MailboxReadError> {
        if cursor.is_some_and(|value| !value.is_empty()) {
            return Err(MailboxReadError::CursorNotSupported);
        }
        let page_size = page_size
            .unwrap_or(DEFAULT_PAGE_SIZE)
            .clamp(1, MAX_PAGE_SIZE);
        let _permit = self.read_permit(connection).await;
        let messages = self
            .adapter
            .list_messages(connection, query, page_size)
            .await?
            .into_iter()
            .map(|message| message.metadata)
            .collect();
        Ok(MessageSearchResult {
            messages,
            next_cursor: None,
        })
    }

    async fn read_permit(&self, connection: ConnectionId) -> OwnedSemaphorePermit {
        let semaphore = {
            let mut limits = self.per_connection_limits.lock().await;
            limits.retain(|_, semaphore| semaphore.strong_count() > 0);
            if let Some(semaphore) = limits.get(&connection).and_then(Weak::upgrade) {
                semaphore
            } else {
                let semaphore = Arc::new(Semaphore::new(4));
                limits.insert(connection, Arc::downgrade(&semaphore));
                semaphore
            }
        };
        semaphore
            .acquire_owned()
            .await
            .expect("read semaphore is never closed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        adapter::{FakeGmailAdapter, MailDraft, MailMessage},
        domain::mailbox::{EmailAddress, MessageMetadata},
    };

    use async_trait::async_trait;
    use std::{
        collections::HashMap,
        sync::{
            Mutex as StdMutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
    };
    use tokio::sync::Notify;

    fn message(id: &str, subject: &str, body: &str) -> MailMessage {
        MailMessage {
            metadata: MessageMetadata {
                id: id.to_owned(),
                thread_id: Some("thread-1".to_owned()),
                sent_at: None,
                from: Some(EmailAddress::new("sender@example.com").unwrap()),
                to: vec![EmailAddress::new("reader@example.com").unwrap()],
                cc: vec![],
                subject: subject.to_owned(),
                snippet: "safe snippet".to_owned(),
                attachments: vec![],
            },
            body: body.to_owned(),
            body_is_html: false,
        }
    }

    fn service() -> (MailboxReadService, Arc<FakeGmailAdapter>, ConnectionId) {
        let adapter = Arc::new(FakeGmailAdapter::new());
        let connection = ConnectionId::new();
        (
            MailboxReadService::new(adapter.clone()),
            adapter,
            connection,
        )
    }

    #[tokio::test]
    async fn search_returns_metadata_only_and_default_page_size() {
        let (service, adapter, connection) = service();
        adapter
            .insert_message(connection, message("message-1", "subject", "secret body"))
            .await;
        let result = service
            .search(connection, Some("subject"), None, None)
            .await
            .unwrap();
        assert_eq!(result.messages.len(), 1);
        assert_eq!(result.messages[0].id, "message-1");
        assert_eq!(result.messages[0].subject, "subject");
        assert_eq!(result.next_cursor, None);
        let serialized = serde_json::to_string(&result).unwrap();
        assert!(!serialized.contains("secret body"));
    }

    #[tokio::test]
    async fn search_clamps_page_size_to_one_hundred() {
        let (service, adapter, connection) = service();
        for index in 0..101 {
            adapter
                .insert_message(
                    connection,
                    message(&format!("message-{index}"), "subject", "body"),
                )
                .await;
        }
        let result = service
            .search(connection, None, Some(500), None)
            .await
            .unwrap();
        assert_eq!(result.messages.len(), 100);
    }

    #[tokio::test]
    async fn search_rejects_non_empty_cursor_without_faking_pagination() {
        let (service, _adapter, connection) = service();
        assert_eq!(
            service
                .search(connection, None, Some(20), Some("opaque-cursor"))
                .await,
            Err(MailboxReadError::CursorNotSupported)
        );
    }

    #[derive(Clone)]
    struct ProbeAdapter {
        inner: Arc<FakeGmailAdapter>,
        active: Arc<AtomicUsize>,
        max_active: Arc<AtomicUsize>,
        started: Arc<AtomicUsize>,
        released: Arc<AtomicBool>,
        release: Arc<Notify>,
        blocked_connection: Arc<StdMutex<Option<ConnectionId>>>,
        started_by_connection: Arc<StdMutex<HashMap<ConnectionId, usize>>>,
    }

    impl ProbeAdapter {
        fn new() -> Self {
            Self {
                inner: Arc::new(FakeGmailAdapter::new()),
                active: Arc::new(AtomicUsize::new(0)),
                max_active: Arc::new(AtomicUsize::new(0)),
                started: Arc::new(AtomicUsize::new(0)),
                released: Arc::new(AtomicBool::new(false)),
                release: Arc::new(Notify::new()),
                blocked_connection: Arc::new(StdMutex::new(None)),
                started_by_connection: Arc::new(StdMutex::new(HashMap::new())),
            }
        }

        async fn wait_until_released(&self) {
            while !self.released.load(Ordering::Acquire) {
                let notified = self.release.notified();
                if self.released.load(Ordering::Acquire) {
                    break;
                }
                notified.await;
            }
        }

        fn block_connection(&self, connection: ConnectionId) {
            *self.blocked_connection.lock().unwrap() = Some(connection);
        }

        fn started_for(&self, connection: ConnectionId) -> usize {
            self.started_by_connection
                .lock()
                .unwrap()
                .get(&connection)
                .copied()
                .unwrap_or(0)
        }

        fn unblock(&self) {
            self.released.store(true, Ordering::Release);
            self.release.notify_waiters();
        }
    }

    fn update_max(max_active: &AtomicUsize, active: usize) {
        let mut current = max_active.load(Ordering::Relaxed);
        while active > current {
            match max_active.compare_exchange_weak(
                current,
                active,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
    }

    #[async_trait]
    impl GmailAdapter for ProbeAdapter {
        async fn list_messages(
            &self,
            connection: ConnectionId,
            query: Option<&str>,
            page_size: usize,
        ) -> Result<Vec<MailMessage>, AdapterError> {
            self.started.fetch_add(1, Ordering::Relaxed);
            *self
                .started_by_connection
                .lock()
                .unwrap()
                .entry(connection)
                .or_default() += 1;
            let active = self.active.fetch_add(1, Ordering::Relaxed) + 1;
            update_max(&self.max_active, active);
            let blocked = *self.blocked_connection.lock().unwrap() == Some(connection);
            if blocked {
                self.wait_until_released().await;
            }
            self.active.fetch_sub(1, Ordering::Relaxed);
            self.inner.list_messages(connection, query, page_size).await
        }

        async fn get_message(
            &self,
            connection: ConnectionId,
            message_id: &str,
        ) -> Result<MailMessage, AdapterError> {
            self.inner.get_message(connection, message_id).await
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
            connection: ConnectionId,
            draft_id: &str,
        ) -> Result<String, AdapterError> {
            self.inner.send_draft(connection, draft_id).await
        }
    }

    #[tokio::test]
    async fn five_real_searches_are_limited_to_four_reads() {
        let adapter = Arc::new(ProbeAdapter::new());
        let service = MailboxReadService::new(adapter.clone());
        let connection = ConnectionId::new();
        adapter.block_connection(connection);
        let mut tasks = Vec::new();
        for _ in 0..5 {
            let service = service.clone();
            tasks.push(tokio::spawn(async move {
                service.search(connection, None, None, None).await
            }));
        }

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while adapter.started.load(Ordering::Acquire) < 4 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("four searches should reach the adapter");
        assert_eq!(adapter.started.load(Ordering::Acquire), 4);
        assert_eq!(adapter.started_for(connection), 4);
        assert!(adapter.max_active.load(Ordering::Acquire) <= 4);

        adapter.unblock();
        for task in tasks {
            assert!(task.await.unwrap().is_ok());
        }
        assert_eq!(adapter.started.load(Ordering::Acquire), 5);
        assert!(adapter.max_active.load(Ordering::Acquire) <= 4);
    }

    #[tokio::test]
    async fn different_connections_have_independent_read_limits() {
        let adapter = Arc::new(ProbeAdapter::new());
        let service = MailboxReadService::new(adapter.clone());
        let first = ConnectionId::new();
        let second = ConnectionId::new();
        adapter.block_connection(first);
        let mut first_tasks = Vec::new();
        for _ in 0..4 {
            let service = service.clone();
            first_tasks.push(tokio::spawn(async move {
                service.search(first, None, None, None).await
            }));
        }
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while adapter.started_for(first) < 4 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first connection should fill all four reads");

        let second_service = service.clone();
        let second_task =
            tokio::spawn(async move { second_service.search(second, None, None, None).await });
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while adapter.started_for(second) < 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("second connection should not wait on first connection");
        assert_eq!(adapter.started_for(first), 4);
        assert_eq!(adapter.started_for(second), 1);
        adapter.unblock();
        for task in first_tasks {
            assert!(task.await.unwrap().is_ok());
        }
        assert!(second_task.await.unwrap().is_ok());
    }
}

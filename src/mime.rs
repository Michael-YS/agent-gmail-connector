//! Bounded, validated RFC 5322/MIME construction for managed drafts.

use crate::domain::mailbox::{
    EmailAddress, MAX_HTTP_ATTACHMENT_BYTES, MailboxError, Recipients, checked_attachment_total,
    validate_filename, validate_header_value,
};
use mail_builder::MessageBuilder;
use std::{collections::HashSet, fmt, io, io::Write};

pub const MAX_ENCODED_MESSAGE_BYTES: usize = 25 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MimeAttachment {
    pub filename: String,
    pub content_type: String,
    pub data: Vec<u8>,
    pub inline_content_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplyHeaders {
    parent_message_id: String,
    references: Vec<String>,
}

impl ReplyHeaders {
    pub fn new(
        parent_message_id: impl Into<String>,
        references: Vec<String>,
    ) -> Result<Self, MimeBuildError> {
        let parent_message_id = normalize_message_id(&parent_message_id.into())?;
        let mut normalized = Vec::with_capacity(references.len() + 1);
        let mut seen = HashSet::new();
        for reference in references {
            let reference = normalize_message_id(&reference)?;
            if seen.insert(reference.clone()) {
                normalized.push(reference);
            }
        }
        if seen.insert(parent_message_id.clone()) {
            normalized.push(parent_message_id.clone());
        }
        Ok(Self {
            parent_message_id,
            references: normalized,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MimeMessage {
    pub from: EmailAddress,
    pub recipients: Recipients,
    pub subject: String,
    pub text_body: Option<String>,
    pub html_body: Option<String>,
    /// Stable RFC Message-ID, including angle brackets.
    pub stable_message_id: String,
    pub reply_headers: Option<ReplyHeaders>,
    pub attachments: Vec<MimeAttachment>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplyKind {
    Reply,
    ReplyAll,
}

/// Derive reply recipients while excluding the current Gmail primary address.
/// v1 intentionally does not discover send-as aliases.
pub fn reply_recipients(
    kind: ReplyKind,
    current_address: &EmailAddress,
    original_from: &EmailAddress,
    original_to: &[EmailAddress],
    original_cc: &[EmailAddress],
) -> Result<Recipients, MailboxError> {
    let mut to = Vec::new();
    if original_from != current_address {
        to.push(original_from.clone());
    } else if let Some(address) = original_to
        .iter()
        .find(|address| *address != current_address)
    {
        to.push(address.clone());
    }
    let mut cc = Vec::new();
    if kind == ReplyKind::ReplyAll {
        for address in original_to.iter().chain(original_cc) {
            if address != current_address && !to.contains(address) && !cc.contains(address) {
                cc.push(address.clone());
            }
        }
    }
    Recipients::new(to, cc, Vec::new())
}

pub fn build_mime(message: MimeMessage) -> Result<Vec<u8>, MimeBuildError> {
    message.recipients.validate()?;
    validate_header_value(&message.subject)?;
    let stable_message_id = normalize_message_id(&message.stable_message_id)?;
    checked_attachment_total(
        message
            .attachments
            .iter()
            .map(|attachment| attachment.data.len()),
        MAX_HTTP_ATTACHMENT_BYTES,
    )?;
    for attachment in &message.attachments {
        validate_filename(&attachment.filename)?;
        validate_content_type(&attachment.content_type)?;
        if let Some(content_id) = &attachment.inline_content_id {
            normalize_message_id(content_id)?;
        }
    }

    let mut builder = MessageBuilder::new()
        .from(message.from.to_string())
        .to(message
            .recipients
            .to
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>())
        .subject(message.subject)
        .message_id(stable_message_id);
    if !message.recipients.cc.is_empty() {
        builder = builder.cc(message
            .recipients
            .cc
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>());
    }
    if !message.recipients.bcc.is_empty() {
        builder = builder.bcc(
            message
                .recipients
                .bcc
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
        );
    }
    if let Some(text) = message.text_body {
        builder = builder.text_body(text);
    }
    if let Some(html) = message.html_body {
        builder = builder.html_body(html);
    }
    if let Some(reply) = message.reply_headers {
        builder = builder
            .in_reply_to(reply.parent_message_id)
            .references(reply.references);
    }
    for attachment in message.attachments {
        builder = if let Some(content_id) = attachment.inline_content_id {
            builder.inline(
                attachment.content_type,
                normalize_message_id(&content_id)?,
                attachment.data,
            )
        } else {
            builder.attachment(
                attachment.content_type,
                attachment.filename,
                attachment.data,
            )
        };
    }

    let mut output = BoundedVec::new(MAX_ENCODED_MESSAGE_BYTES);
    match builder.write_to(&mut output) {
        Ok(()) => Ok(output.bytes),
        Err(_) if output.limit_exceeded => Err(MimeBuildError::EncodedMessageTooLarge),
        Err(_) => Err(MimeBuildError::Encoding),
    }
}

fn normalize_message_id(value: &str) -> Result<String, MimeBuildError> {
    let value = value.trim();
    let inner = value
        .strip_prefix('<')
        .and_then(|value| value.strip_suffix('>'))
        .unwrap_or(value);
    let Some((local, domain)) = inner.split_once('@') else {
        return Err(MimeBuildError::InvalidMessageId);
    };
    if local.is_empty()
        || domain.is_empty()
        || inner.matches('@').count() != 1
        || !inner.is_ascii()
        || inner.bytes().any(|byte| {
            byte.is_ascii_whitespace()
                || byte.is_ascii_control()
                || matches!(
                    byte,
                    b'<' | b'>' | b'(' | b')' | b',' | b';' | b':' | b'\\' | b'"'
                )
        })
    {
        return Err(MimeBuildError::InvalidMessageId);
    }
    Ok(inner.to_owned())
}

fn validate_content_type(value: &str) -> Result<(), MimeBuildError> {
    let Some((top, subtype)) = value.split_once('/') else {
        return Err(MimeBuildError::InvalidContentType);
    };
    if top.is_empty()
        || subtype.is_empty()
        || subtype.contains('/')
        || !value.is_ascii()
        || top.bytes().chain(subtype.bytes()).any(|byte| {
            !(byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#' | b'$' | b'&' | b'+' | b'-' | b'.' | b'^' | b'_' | b'|'
                ))
        })
    {
        return Err(MimeBuildError::InvalidContentType);
    }
    Ok(())
}

struct BoundedVec {
    bytes: Vec<u8>,
    limit: usize,
    limit_exceeded: bool,
}

impl BoundedVec {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
            limit_exceeded: false,
        }
    }
}

impl Write for BoundedVec {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let remaining = self.limit.saturating_sub(self.bytes.len());
        if buffer.len() > remaining {
            self.limit_exceeded = true;
            return Err(io::Error::other("encoded message size limit exceeded"));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MimeBuildError {
    InvalidHeader,
    InvalidMessageId,
    InvalidContentType,
    InvalidMailbox,
    AttachmentsTooLarge,
    EncodedMessageTooLarge,
    Encoding,
}

impl From<MailboxError> for MimeBuildError {
    fn from(error: MailboxError) -> Self {
        match error {
            MailboxError::HeaderInjection => Self::InvalidHeader,
            MailboxError::AttachmentTooLarge => Self::AttachmentsTooLarge,
            MailboxError::InvalidEmail
            | MailboxError::TooManyRecipients
            | MailboxError::NoRecipients
            | MailboxError::InvalidFilename
            | MailboxError::InvalidChunkSize => Self::InvalidMailbox,
        }
    }
}

impl fmt::Display for MimeBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidHeader => "invalid MIME header",
            Self::InvalidMessageId => "invalid Message-ID",
            Self::InvalidContentType => "invalid attachment content type",
            Self::InvalidMailbox => "invalid mailbox value",
            Self::AttachmentsTooLarge => "raw attachments exceed size limit",
            Self::EncodedMessageTooLarge => "encoded message exceeds size limit",
            Self::Encoding => "MIME encoding failed",
        })
    }
}

impl std::error::Error for MimeBuildError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(value: &str) -> EmailAddress {
        EmailAddress::new(value).unwrap()
    }

    fn base_message() -> MimeMessage {
        MimeMessage {
            from: address("me@example.com"),
            recipients: Recipients::new(vec![address("you@example.com")], vec![], vec![]).unwrap(),
            subject: "你好，世界".into(),
            text_body: Some("plain".into()),
            html_body: Some("<p>你好</p>".into()),
            stable_message_id: "<stable-1@agentmail.invalid>".into(),
            reply_headers: None,
            attachments: Vec::new(),
        }
    }

    #[test]
    fn builds_encoded_headers_and_stable_message_id() {
        let raw = String::from_utf8(build_mime(base_message()).unwrap()).unwrap();
        assert!(raw.contains("Message-ID: <stable-1@agentmail.invalid>\r\n"));
        assert!(raw.contains("Subject: =?utf-8?"));
        assert!(raw.contains("multipart/alternative"));
    }

    #[test]
    fn rejects_header_and_attachment_injection() {
        let mut message = base_message();
        message.subject = "safe\r\nBcc: hidden@example.com".into();
        assert_eq!(build_mime(message), Err(MimeBuildError::InvalidHeader));

        let mut message = base_message();
        message.stable_message_id = "<ok@example.com>\r\nBcc:x".into();
        assert_eq!(build_mime(message), Err(MimeBuildError::InvalidMessageId));

        let mut message = base_message();
        message.attachments.push(MimeAttachment {
            filename: "../secret.txt".into(),
            content_type: "text/plain".into(),
            data: vec![],
            inline_content_id: None,
        });
        assert_eq!(build_mime(message), Err(MimeBuildError::InvalidMailbox));
    }

    #[test]
    fn reply_headers_append_parent_once() {
        let reply = ReplyHeaders::new(
            "<parent@example.com>",
            vec!["<root@example.com>".into(), "parent@example.com".into()],
        )
        .unwrap();
        let mut message = base_message();
        message.reply_headers = Some(reply);
        let raw = String::from_utf8(build_mime(message).unwrap()).unwrap();
        assert!(raw.contains("In-Reply-To: <parent@example.com>"));
        assert_eq!(raw.matches("<parent@example.com>").count(), 2);
        assert!(raw.contains("<root@example.com>"));
    }

    #[test]
    fn reply_all_excludes_current_address_and_deduplicates() {
        let recipients = reply_recipients(
            ReplyKind::ReplyAll,
            &address("me@example.com"),
            &address("sender@example.com"),
            &[address("me@example.com"), address("other@example.com")],
            &[address("other@example.com"), address("cc@example.com")],
        )
        .unwrap();
        assert_eq!(recipients.to, vec![address("sender@example.com")]);
        assert_eq!(
            recipients.cc,
            vec![address("other@example.com"), address("cc@example.com")]
        );
        assert!(
            !recipients
                .iter()
                .any(|(address, _)| address.as_str() == "me@example.com")
        );
    }

    #[test]
    fn raw_and_encoded_size_limits_are_distinct() {
        let mut message = base_message();
        message.attachments.push(MimeAttachment {
            filename: "large.bin".into(),
            content_type: "application/octet-stream".into(),
            data: vec![0; 19 * 1024 * 1024],
            inline_content_id: None,
        });
        assert_eq!(
            build_mime(message),
            Err(MimeBuildError::EncodedMessageTooLarge)
        );

        let mut message = base_message();
        message.attachments.push(MimeAttachment {
            filename: "too-large.bin".into(),
            content_type: "application/octet-stream".into(),
            data: vec![0; MAX_HTTP_ATTACHMENT_BYTES + 1],
            inline_content_id: None,
        });
        assert_eq!(
            build_mime(message),
            Err(MimeBuildError::AttachmentsTooLarge)
        );
    }
}

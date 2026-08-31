//! Safe, transport-neutral mailbox values.
//!
//! Email content is untrusted input.  The helpers in this module are kept
//! small and deterministic so REST, MCP and the Gmail adapter share exactly
//! the same recipient, header, filename, HTML and body-size rules.

use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

pub const MAX_RECIPIENTS: usize = 20;
pub const MAX_HTTP_ATTACHMENT_BYTES: usize = 25 * 1024 * 1024;
pub const MAX_MCP_ATTACHMENT_BYTES: usize = 4 * 1024 * 1024;
pub const DEFAULT_BODY_CHUNK_BYTES: usize = 32 * 1024;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EmailAddress(String);
impl EmailAddress {
    pub fn new(value: impl AsRef<str>) -> Result<Self, MailboxError> {
        let value = value.as_ref().trim().to_ascii_lowercase();
        validate_email(&value)?;
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl FromStr for EmailAddress {
    type Err = MailboxError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}
impl fmt::Display for EmailAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn validate_email(value: &str) -> Result<(), MailboxError> {
    if value.is_empty()
        || value.len() > 320
        || value
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b == b'\r' || b == b'\n' || b == 0)
    {
        return Err(MailboxError::InvalidEmail);
    }
    let Some((local, domain)) = value.rsplit_once('@') else {
        return Err(MailboxError::InvalidEmail);
    };
    if local.is_empty()
        || local.len() > 64
        || domain.is_empty()
        || domain.starts_with('.')
        || domain.ends_with('.')
        || domain.contains("..")
        || !domain.contains('.')
    {
        return Err(MailboxError::InvalidEmail);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RecipientKind {
    To,
    Cc,
    Bcc,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Recipient {
    pub address: EmailAddress,
    pub kind: RecipientKind,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Recipients {
    pub to: Vec<EmailAddress>,
    pub cc: Vec<EmailAddress>,
    pub bcc: Vec<EmailAddress>,
}
impl Recipients {
    pub fn new(
        to: Vec<EmailAddress>,
        cc: Vec<EmailAddress>,
        bcc: Vec<EmailAddress>,
    ) -> Result<Self, MailboxError> {
        let result = Self { to, cc, bcc };
        result.validate()?;
        Ok(result)
    }
    pub fn count(&self) -> usize {
        self.to.len() + self.cc.len() + self.bcc.len()
    }
    pub fn validate(&self) -> Result<(), MailboxError> {
        if self.count() > MAX_RECIPIENTS {
            return Err(MailboxError::TooManyRecipients);
        }
        if self.to.is_empty() && self.cc.is_empty() && self.bcc.is_empty() {
            return Err(MailboxError::NoRecipients);
        }
        Ok(())
    }
    pub fn iter(&self) -> impl Iterator<Item = (&EmailAddress, RecipientKind)> {
        self.to
            .iter()
            .map(|v| (v, RecipientKind::To))
            .chain(self.cc.iter().map(|v| (v, RecipientKind::Cc)))
            .chain(self.bcc.iter().map(|v| (v, RecipientKind::Bcc)))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AttachmentInfo {
    pub id: String,
    pub filename: String,
    pub content_type: String,
    pub size_bytes: u64,
    pub inline: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MessageMetadata {
    pub id: String,
    pub thread_id: Option<String>,
    pub sent_at: Option<String>,
    pub from: Option<EmailAddress>,
    pub to: Vec<EmailAddress>,
    pub cc: Vec<EmailAddress>,
    pub subject: String,
    pub snippet: String,
    pub attachments: Vec<AttachmentInfo>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NormalizedMessage {
    pub metadata: MessageMetadata,
    pub body: String,
    pub body_is_html: bool,
    pub truncated: bool,
    pub next_cursor: Option<String>,
    pub untrusted_email_content: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BodyChunk {
    pub content: String,
    pub truncated: bool,
    pub next_cursor: Option<String>,
}

/// Remove executable/active HTML while retaining harmless markup.  This is
/// intentionally conservative: all images are removed, as are tags whose
/// normal purpose is scripting, embedding or submission.
pub fn strip_html_active_content(html: &str) -> String {
    let mut output = html.to_owned();
    for tag in [
        "script", "style", "form", "iframe", "object", "embed", "template", "svg", "math",
    ] {
        let re = regex::Regex::new(&format!(r"(?is)<{tag}\b[^>]*>.*?</{tag}\s*>"))
            .expect("static html sanitizer regex");
        output = re.replace_all(&output, "").into_owned();
    }
    let active_open = regex::Regex::new(
        r"(?is)</?(?:script|style|form|iframe|object|embed|template|svg|math)\b[^>]*>",
    )
    .expect("static html sanitizer regex");
    output = active_open.replace_all(&output, "").into_owned();
    let blocked_tags = regex::Regex::new(r"(?is)<(?:img|base|link|meta)\b[^>]*>")
        .expect("static html sanitizer regex");
    output = blocked_tags.replace_all(&output, "").into_owned();
    // Event handlers, CSS and URL-bearing attributes are parsed separately so
    // quoted and unquoted values cannot smuggle active content through.
    let event =
        regex::Regex::new(r####"(?is)\s+on[a-z0-9_-]+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)"####)
            .expect("static html sanitizer regex");
    output = event.replace_all(&output, "").into_owned();
    let style = regex::Regex::new(r####"(?is)\s+style\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)"####)
        .expect("static html sanitizer regex");
    output = style.replace_all(&output, "").into_owned();
    let url = regex::Regex::new(r####"(?is)\s+(?:href|src|xlink:href|action|formaction|poster|background|dynsrc|lowsrc|srcset|ping|manifest)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))"####).expect("static html sanitizer regex");
    output = url
        .replace_all(&output, |caps: &regex::Captures| {
            let value = caps
                .get(1)
                .or_else(|| caps.get(2))
                .or_else(|| caps.get(3))
                .map_or("", |m| m.as_str());
            if is_dangerous_uri(value) {
                String::new()
            } else {
                caps.get(0)
                    .map_or_else(String::new, |m| m.as_str().to_owned())
            }
        })
        .into_owned();
    output
}

fn is_dangerous_uri(value: &str) -> bool {
    // Removing separators catches entity-obfuscated forms such as
    // java&#x73;cript: without needing to turn the value into a URL.
    let compact = value
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .collect::<String>()
        .to_ascii_lowercase();
    compact.starts_with("javascript")
        || compact.starts_with("vbscript")
        || compact.starts_with("data")
}

pub fn sanitize_html(html: &str) -> String {
    strip_html_active_content(html)
}

pub fn html_to_plain_text(html: &str) -> String {
    let without_active = strip_html_active_content(html);
    let tags = regex::Regex::new(r"(?is)<[^>]+>").expect("static html sanitizer regex");
    let text = tags.replace_all(&without_active, " ");
    text.replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Chunk on UTF-8 character boundaries.  `max_bytes == 0` is rejected rather
/// than causing an infinite loop.
pub fn chunk_body(body: &str, max_bytes: usize) -> Result<Vec<BodyChunk>, MailboxError> {
    if max_bytes == 0 {
        return Err(MailboxError::InvalidChunkSize);
    }
    if body.is_empty() {
        return Ok(vec![BodyChunk {
            content: String::new(),
            truncated: false,
            next_cursor: None,
        }]);
    }
    let mut chunks = Vec::new();
    let mut start = 0;
    while start < body.len() {
        let mut end = start;
        for (offset, ch) in body[start..].char_indices() {
            let candidate = start + offset + ch.len_utf8();
            if candidate - start > max_bytes {
                break;
            }
            end = candidate;
        }
        if end == start {
            return Err(MailboxError::InvalidChunkSize);
        }
        let more = end < body.len();
        chunks.push(BodyChunk {
            content: body[start..end].to_owned(),
            truncated: more,
            next_cursor: more.then(|| end.to_string()),
        });
        start = end;
    }
    Ok(chunks)
}

pub fn sanitize_filename(filename: &str) -> String {
    let mut value = filename
        .chars()
        .filter(|c| !c.is_control() && *c != '/' && *c != '\\')
        .collect::<String>();
    value = value.trim().trim_matches('.').to_owned();
    if value.is_empty() {
        "attachment".to_owned()
    } else {
        value.chars().take(255).collect()
    }
}
pub fn validate_filename(filename: &str) -> Result<String, MailboxError> {
    if filename.is_empty()
        || filename
            .chars()
            .any(|c| c == '\r' || c == '\n' || c == '\0' || c.is_control() || c == '/' || c == '\\')
    {
        return Err(MailboxError::InvalidFilename);
    }
    let clean = sanitize_filename(filename);
    if clean == "attachment" && filename != "attachment" {
        return Err(MailboxError::InvalidFilename);
    }
    Ok(clean)
}
pub fn validate_header_value(value: &str) -> Result<(), MailboxError> {
    if value
        .bytes()
        .any(|b| b == b'\r' || b == b'\n' || b == 0 || b < 0x20 || b == 0x7f)
    {
        Err(MailboxError::HeaderInjection)
    } else {
        Ok(())
    }
}
pub fn checked_attachment_total<I: IntoIterator<Item = usize>>(
    sizes: I,
    limit: usize,
) -> Result<usize, MailboxError> {
    let mut total = 0usize;
    for size in sizes {
        total = total
            .checked_add(size)
            .ok_or(MailboxError::AttachmentTooLarge)?;
        if total > limit {
            return Err(MailboxError::AttachmentTooLarge);
        }
    }
    Ok(total)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MailboxError {
    InvalidEmail,
    TooManyRecipients,
    NoRecipients,
    InvalidChunkSize,
    InvalidFilename,
    HeaderInjection,
    AttachmentTooLarge,
}
impl fmt::Display for MailboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidEmail => "invalid email address",
            Self::TooManyRecipients => "too many recipients",
            Self::NoRecipients => "at least one recipient is required",
            Self::InvalidChunkSize => "body chunk size is invalid",
            Self::InvalidFilename => "invalid filename",
            Self::HeaderInjection => "header contains forbidden control characters",
            Self::AttachmentTooLarge => "attachments exceed size limit",
        })
    }
}
impl std::error::Error for MailboxError {}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn html_active_content_is_removed() {
        let safe = strip_html_active_content(
            r#"<p onclick="x()">Hi</p><script>alert(1)</script><img src="https://x">"#,
        );
        assert_eq!(safe, "<p>Hi</p>");
    }
    #[test]
    fn recipient_limit_and_header_safety() {
        let e = EmailAddress::new("x@example.com").unwrap();
        assert!(Recipients::new(vec![e; 21], vec![], vec![]).is_err());
        assert!(validate_header_value("ok\r\nBcc: evil").is_err());
    }
    #[test]
    fn chunking_does_not_split_utf8() {
        let chunks = chunk_body("a你好b", 4).unwrap();
        assert_eq!(
            chunks
                .iter()
                .map(|c| c.content.as_str())
                .collect::<String>(),
            "a你好b"
        );
        assert!(chunks[0].truncated);
    }
    #[test]
    fn filenames_are_path_and_control_safe() {
        assert_eq!(sanitize_filename("..\\secret\n.txt"), "secret.txt");
        assert!(validate_filename("a/b").is_err());
    }

    #[test]
    fn dangerous_urls_css_and_encoded_handlers_are_removed() {
        let safe = strip_html_active_content(
            r#"<a href="https://example.com">ok</a><p style="background:url(javascript:x)" onmouseover="x">x</p>"#,
        );
        assert!(safe.contains("href=\"https://example.com\""));
        assert!(!safe.contains("style="));
        assert!(!safe.contains("onmouseover"));
        let dangerous = strip_html_active_content(
            r#"<a href="javascript:alert(1)">x</a><a href="java&#x73;cript:alert(1)">y</a><a href="data:text/html,x">z</a>"#,
        );
        assert!(!dangerous.to_ascii_lowercase().contains("javascript"));
        assert!(!dangerous.to_ascii_lowercase().contains("data:text"));
    }
}

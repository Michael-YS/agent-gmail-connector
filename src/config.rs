//! Application configuration and startup validation.
//!
//! Configuration is deliberately parsed in one place.  In particular, URL
//! construction must never use a request's `Host` or forwarded headers.

use secrecy::{ExposeSecret, SecretString};
use std::{collections::BTreeMap, env, fmt, fs, path::Path, str::FromStr};
use url::Url;

use crate::crypto::Keyring;

pub const DEFAULT_PERSONAL_USE_USER_LIMIT: u16 = 90;
pub const MAX_PERSONAL_USE_USER_LIMIT: u16 = 99;
const MAX_SECRET_BYTES: usize = 4 * 1024;
const MAX_KEYRING_FILE_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Environment {
    Development,
    Test,
    Production,
}

impl FromStr for Environment {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "development" | "dev" => Ok(Self::Development),
            "test" => Ok(Self::Test),
            "production" | "prod" => Ok(Self::Production),
            other => Err(ConfigError::InvalidEnvironment(other.to_owned())),
        }
    }
}

impl fmt::Display for Environment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Development => "development",
            Self::Test => "test",
            Self::Production => "production",
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("missing required configuration: {0}")]
    Missing(&'static str),
    #[error("invalid configuration for {field}: {reason}")]
    Invalid { field: &'static str, reason: String },
    #[error("invalid environment: {0}")]
    InvalidEnvironment(String),
    #[error("personal use user limit cannot exceed {MAX_PERSONAL_USE_USER_LIMIT}")]
    UserLimitTooHigh,
    #[error("invalid secret file for {field}: {reason}")]
    SecretFile {
        field: &'static str,
        reason: &'static str,
    },
    #[error("encryption keyring: {0}")]
    Keyring(#[from] crate::crypto::CryptoError),
}

#[derive(Clone)]
pub struct AppConfig {
    pub environment: Environment,
    pub public_base_url: Url,
    pub owner_email: String,
    pub personal_use_user_limit: u16,
    pub database_url: String,
    pub session_secret: SecretString,
    pub csrf_secret: SecretString,
    pub google_login_client_id: String,
    pub google_gmail_client_id: String,
    pub google_login_client_secret: SecretString,
    pub google_gmail_client_secret: SecretString,
    pub encryption_keyring: Keyring,
}

impl fmt::Debug for AppConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppConfig")
            .field("environment", &self.environment)
            .field("public_base_url", &self.public_base_url)
            .field("owner_email", &self.owner_email)
            .field("personal_use_user_limit", &self.personal_use_user_limit)
            .field("database_url", &self.database_url)
            .field("session_secret", &"[REDACTED]")
            .field("csrf_secret", &"[REDACTED]")
            .field("google_login_client_id", &self.google_login_client_id)
            .field("google_gmail_client_id", &self.google_gmail_client_id)
            .field("google_login_client_secret", &"[REDACTED]")
            .field("google_gmail_client_secret", &"[REDACTED]")
            .field("encryption_keyring", &"[REDACTED]")
            .finish()
    }
}

impl AppConfig {
    /// Parse process environment variables using production-safe defaults.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_map(env::vars().collect())
    }

    /// Parse a map, useful for tests and for callers that load a secret file.
    pub fn from_map(mut values: BTreeMap<String, String>) -> Result<Self, ConfigError> {
        let environment = values
            .remove("APP_ENV")
            .or_else(|| values.remove("ENVIRONMENT"))
            .unwrap_or_else(|| "development".to_owned())
            .parse()?;
        let public_base_url = required(&mut values, "PUBLIC_BASE_URL")
            .and_then(|v| parse_url(v, "PUBLIC_BASE_URL"))?;
        let host = public_base_url.host_str();
        let local_http = matches!(host, Some("localhost" | "127.0.0.1" | "::1" | "[::1]"));
        let valid_scheme = public_base_url.scheme() == "https"
            || (matches!(environment, Environment::Development | Environment::Test)
                && public_base_url.scheme() == "http"
                && local_http);
        if host.is_none() || !valid_scheme {
            return Err(ConfigError::Invalid {
                field: "PUBLIC_BASE_URL",
                reason: "must use https with a host, or development/test http localhost".to_owned(),
            });
        }
        if public_base_url.username() != "" || public_base_url.password().is_some() {
            return Err(ConfigError::Invalid {
                field: "PUBLIC_BASE_URL",
                reason: "credentials are not allowed".to_owned(),
            });
        }
        if public_base_url.query().is_some()
            || public_base_url.fragment().is_some()
            || !matches!(public_base_url.path(), "" | "/")
        {
            return Err(ConfigError::Invalid {
                field: "PUBLIC_BASE_URL",
                reason: "must not contain a query, fragment, or non-root path".to_owned(),
            });
        }
        let owner_email = required(&mut values, "OWNER_EMAIL")?;
        if !owner_email.contains('@') || owner_email.chars().any(char::is_whitespace) {
            return Err(ConfigError::Invalid {
                field: "OWNER_EMAIL",
                reason: "must be an email address".to_owned(),
            });
        }
        let personal_use_user_limit = values.remove("PERSONAL_USE_USER_LIMIT").map_or(
            Ok(DEFAULT_PERSONAL_USE_USER_LIMIT),
            |v| {
                v.parse::<u16>().map_err(|_| ConfigError::Invalid {
                    field: "PERSONAL_USE_USER_LIMIT",
                    reason: "must be an integer".to_owned(),
                })
            },
        )?;
        if personal_use_user_limit > MAX_PERSONAL_USE_USER_LIMIT {
            return Err(ConfigError::UserLimitTooHigh);
        }
        if personal_use_user_limit == 0 {
            return Err(ConfigError::Invalid {
                field: "PERSONAL_USE_USER_LIMIT",
                reason: "must be greater than zero".to_owned(),
            });
        }
        let database_url = values
            .remove("DATABASE_URL")
            .unwrap_or_else(|| "sqlite://agentmail.db".to_owned());
        if !database_url.starts_with("sqlite:") {
            return Err(ConfigError::Invalid {
                field: "DATABASE_URL",
                reason: "only SQLite is supported".to_owned(),
            });
        }
        let (session_value, csrf_value) = secret_pair(&mut values)?;
        let session_secret = SecretString::from(session_value);
        let csrf_secret = SecretString::from(csrf_value);
        validate_secret("SESSION_SECRET", &session_secret)?;
        validate_secret("CSRF_SECRET", &csrf_secret)?;
        let google_login_client_id = required(&mut values, "GOOGLE_LOGIN_CLIENT_ID")?;
        let google_gmail_client_id = required(&mut values, "GOOGLE_GMAIL_CLIENT_ID")?;
        let google_login_client_secret = SecretString::from(client_secret_value(
            &mut values,
            "LOGIN_CLIENT_SECRET",
            "LOGIN_CLIENT_SECRET_FILE",
        )?);
        let google_gmail_client_secret = SecretString::from(client_secret_value(
            &mut values,
            "GMAIL_CLIENT_SECRET",
            "GMAIL_CLIENT_SECRET_FILE",
        )?);
        validate_secret("LOGIN_CLIENT_SECRET", &google_login_client_secret)?;
        validate_secret("GMAIL_CLIENT_SECRET", &google_gmail_client_secret)?;
        let keyring_value = if values.contains_key("CREDENTIAL_ENCRYPTION_KEYRING")
            || values.contains_key("CREDENTIAL_ENCRYPTION_KEYRING_FILE")
        {
            secret_value(
                &mut values,
                "CREDENTIAL_ENCRYPTION_KEYRING",
                "CREDENTIAL_ENCRYPTION_KEYRING_FILE",
            )?
        } else {
            secret_value(&mut values, "ENCRYPTION_KEYRING", "ENCRYPTION_KEYRING_FILE")?
        };
        if keyring_value.len() > MAX_KEYRING_FILE_BYTES {
            return Err(ConfigError::Invalid {
                field: "CREDENTIAL_ENCRYPTION_KEYRING",
                reason: "must not exceed 65536 bytes".to_owned(),
            });
        }
        let encryption_keyring = Keyring::parse(&keyring_value)?;
        Ok(Self {
            environment,
            public_base_url,
            owner_email,
            personal_use_user_limit,
            database_url,
            session_secret,
            csrf_secret,
            google_login_client_id,
            google_gmail_client_id,
            google_login_client_secret,
            google_gmail_client_secret,
            encryption_keyring,
        })
    }

    pub fn active_encryption_key_version(&self) -> u32 {
        self.encryption_keyring.active_version()
    }

    pub fn session_secret(&self) -> &[u8] {
        self.session_secret.expose_secret().as_bytes()
    }

    pub fn csrf_secret(&self) -> &[u8] {
        self.csrf_secret.expose_secret().as_bytes()
    }

    pub fn google_login_callback_url(&self) -> Url {
        callback_url(&self.public_base_url, "/auth/google/callback")
    }

    pub fn google_gmail_callback_url(&self) -> Url {
        callback_url(&self.public_base_url, "/connections/google/callback")
    }
}

pub type Config = AppConfig;

fn required(
    values: &mut BTreeMap<String, String>,
    name: &'static str,
) -> Result<String, ConfigError> {
    values
        .remove(name)
        .filter(|v| !v.trim().is_empty())
        .ok_or(ConfigError::Missing(name))
}

/// Resolve a secret from its value or its companion file. A file, when
/// configured, takes precedence so Docker secrets work even when an adapter
/// has already materialized a value in the environment map.
fn secret_value(
    values: &mut BTreeMap<String, String>,
    value_name: &'static str,
    file_name: &'static str,
) -> Result<String, ConfigError> {
    if let Some(path) = values.remove(file_name) {
        return read_secret_file(Path::new(&path), value_name, MAX_KEYRING_FILE_BYTES, false);
    }
    required(values, value_name)
}

fn client_secret_value(
    values: &mut BTreeMap<String, String>,
    value_name: &'static str,
    file_name: &'static str,
) -> Result<String, ConfigError> {
    let inline = values.remove(value_name);
    let file = values.remove(file_name);
    match (inline, file) {
        (Some(_), Some(_)) => Err(ConfigError::Invalid {
            field: value_name,
            reason: format!("cannot be combined with {file_name}"),
        }),
        (Some(value), None) if !value.trim().is_empty() => Ok(value),
        (Some(_), None) => Err(ConfigError::Missing(value_name)),
        (None, Some(path)) => {
            read_secret_file(Path::new(&path), value_name, MAX_SECRET_BYTES, false)
        }
        (None, None) => Err(ConfigError::Missing(value_name)),
    }
}

fn secret_pair(values: &mut BTreeMap<String, String>) -> Result<(String, String), ConfigError> {
    let combined_file = values.remove("SESSION_CSRF_SECRET_FILE");
    let session_file = values.remove("SESSION_SECRET_FILE");
    let csrf_file = values.remove("CSRF_SECRET_FILE");
    if combined_file.is_some() && (session_file.is_some() || csrf_file.is_some()) {
        return Err(ConfigError::Invalid {
            field: "SESSION_CSRF_SECRET_FILE",
            reason: "cannot be combined with SESSION_SECRET_FILE or CSRF_SECRET_FILE".to_owned(),
        });
    }
    if let Some(path) = combined_file {
        let contents = read_secret_file(
            Path::new(&path),
            "SESSION_CSRF_SECRET",
            MAX_KEYRING_FILE_BYTES,
            true,
        )?;
        let mut lines = contents.lines();
        let session = lines.next().unwrap_or_default().to_owned();
        let csrf = lines.next().unwrap_or_default().to_owned();
        if session.is_empty() || csrf.is_empty() || lines.next().is_some() {
            return Err(ConfigError::SecretFile {
                field: "SESSION_CSRF_SECRET",
                reason: "must contain exactly two non-empty lines",
            });
        }
        return Ok((session, csrf));
    }
    let session = match session_file {
        Some(path) => {
            read_secret_file(Path::new(&path), "SESSION_SECRET", MAX_SECRET_BYTES, false)?
        }
        None => required(values, "SESSION_SECRET")?,
    };
    let csrf = match csrf_file {
        Some(path) => read_secret_file(Path::new(&path), "CSRF_SECRET", MAX_SECRET_BYTES, false)?,
        None => required(values, "CSRF_SECRET")?,
    };
    Ok((session, csrf))
}

fn read_secret_file(
    path: &Path,
    field: &'static str,
    max_bytes: usize,
    allow_line_breaks: bool,
) -> Result<String, ConfigError> {
    if path.as_os_str().is_empty() {
        return Err(ConfigError::SecretFile {
            field,
            reason: "path is empty",
        });
    }
    let metadata = fs::metadata(path).map_err(|_| ConfigError::SecretFile {
        field,
        reason: "file is unavailable",
    })?;
    if !metadata.is_file() {
        return Err(ConfigError::SecretFile {
            field,
            reason: "path is not a regular file",
        });
    }
    if metadata.len() > max_bytes as u64 {
        return Err(ConfigError::SecretFile {
            field,
            reason: "file is too large",
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(ConfigError::SecretFile {
                field,
                reason: "file permissions must not grant group or other access",
            });
        }
    }
    let bytes = fs::read(path).map_err(|_| ConfigError::SecretFile {
        field,
        reason: "file is unreadable",
    })?;
    let value = String::from_utf8(bytes).map_err(|_| ConfigError::SecretFile {
        field,
        reason: "file must be UTF-8",
    })?;
    let value = value.trim_end_matches(['\r', '\n']).to_owned();
    if value.is_empty() {
        return Err(ConfigError::SecretFile {
            field,
            reason: "file is empty",
        });
    }
    if value.len() > max_bytes
        || (!allow_line_breaks && value.chars().any(|c| c == '\r' || c == '\n'))
    {
        return Err(ConfigError::SecretFile {
            field,
            reason: "file contains invalid line breaks or is too large",
        });
    }
    Ok(value)
}
fn parse_url(value: String, field: &'static str) -> Result<Url, ConfigError> {
    Url::parse(&value).map_err(|e| ConfigError::Invalid {
        field,
        reason: e.to_string(),
    })
}

fn callback_url(base: &Url, path: &str) -> Url {
    let mut callback = base.clone();
    callback.set_path(path);
    callback.set_query(None);
    callback.set_fragment(None);
    callback
}

fn validate_secret(field: &'static str, value: &SecretString) -> Result<(), ConfigError> {
    let length = value.expose_secret().len();
    if length < 32 {
        return Err(ConfigError::Invalid {
            field,
            reason: "must contain at least 32 bytes".to_owned(),
        });
    }
    if length > MAX_SECRET_BYTES {
        return Err(ConfigError::Invalid {
            field,
            reason: "must not exceed 4096 bytes".to_owned(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    fn map() -> BTreeMap<String, String> {
        let key = URL_SAFE_NO_PAD.encode([7_u8; 32]);
        BTreeMap::from([
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
        ])
    }

    #[test]
    fn production_requires_https_and_cap_is_enforced() {
        let mut values = map();
        values.insert(
            "PUBLIC_BASE_URL".to_owned(),
            "http://agentmail.example".to_owned(),
        );
        assert!(matches!(
            AppConfig::from_map(values),
            Err(ConfigError::Invalid {
                field: "PUBLIC_BASE_URL",
                ..
            })
        ));
        let mut values = map();
        values.insert("PERSONAL_USE_USER_LIMIT".to_owned(), "100".to_owned());
        assert!(matches!(
            AppConfig::from_map(values),
            Err(ConfigError::UserLimitTooHigh)
        ));
    }

    #[test]
    fn secret_files_support_separate_and_two_line_formats() {
        let dir = tempfile::tempdir().unwrap();
        let session = dir.path().join("session");
        let csrf = dir.path().join("csrf");
        let combined = dir.path().join("combined");
        std::fs::write(&session, format!("{}\n", "s".repeat(32))).unwrap();
        std::fs::write(&csrf, "c".repeat(32)).unwrap();
        std::fs::write(
            &combined,
            format!("{}\n{}\n", "s".repeat(32), "c".repeat(32)),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for path in [&session, &csrf, &combined] {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
        }

        let mut values = map();
        values.remove("SESSION_SECRET");
        values.remove("CSRF_SECRET");
        values.insert("SESSION_SECRET_FILE".into(), session.display().to_string());
        values.insert("CSRF_SECRET_FILE".into(), csrf.display().to_string());
        let config = AppConfig::from_map(values).unwrap();
        assert_eq!(config.session_secret(), "s".repeat(32).as_bytes());

        let mut values = map();
        values.remove("SESSION_SECRET");
        values.remove("CSRF_SECRET");
        values.insert(
            "SESSION_CSRF_SECRET_FILE".into(),
            combined.display().to_string(),
        );
        assert!(AppConfig::from_map(values).is_ok());
    }

    #[test]
    fn malformed_secret_file_is_rejected_without_exposing_contents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad");
        std::fs::write(&path, "too-short\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let mut values = map();
        values.remove("SESSION_SECRET");
        values.insert("SESSION_SECRET_FILE".into(), path.display().to_string());
        let error = AppConfig::from_map(values).unwrap_err().to_string();
        assert!(!error.contains("too-short"));
    }
    #[test]
    fn debug_does_not_expose_secrets() {
        let config = AppConfig::from_map(map()).unwrap();
        let rendered = format!("{config:?}");
        assert!(!rendered.contains(&"s".repeat(32)));
        assert!(!rendered.contains(&"l".repeat(32)));
        assert!(!rendered.contains(&"g".repeat(32)));
        assert!(rendered.contains("login-client-id"));
        assert_eq!(config.active_encryption_key_version(), 1);
    }

    #[test]
    fn google_oauth_configuration_rejects_missing_or_empty_values() {
        let mut values = map();
        values.remove("GOOGLE_LOGIN_CLIENT_ID");
        assert!(matches!(
            AppConfig::from_map(values),
            Err(ConfigError::Missing("GOOGLE_LOGIN_CLIENT_ID"))
        ));

        let mut values = map();
        values.insert("GMAIL_CLIENT_SECRET".into(), String::new());
        assert!(matches!(
            AppConfig::from_map(values),
            Err(ConfigError::Missing("GMAIL_CLIENT_SECRET"))
        ));
    }

    #[test]
    fn google_client_secret_files_use_size_permission_and_exclusivity_rules() {
        let dir = tempfile::tempdir().unwrap();
        let login = dir.path().join("login");
        let gmail = dir.path().join("gmail");
        std::fs::write(
            &login,
            format!(
                "{}
",
                "l".repeat(32)
            ),
        )
        .unwrap();
        std::fs::write(&gmail, "g".repeat(32)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for path in [&login, &gmail] {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
        }

        let mut values = map();
        values.remove("LOGIN_CLIENT_SECRET");
        values.remove("GMAIL_CLIENT_SECRET");
        values.insert(
            "LOGIN_CLIENT_SECRET_FILE".into(),
            login.display().to_string(),
        );
        values.insert(
            "GMAIL_CLIENT_SECRET_FILE".into(),
            gmail.display().to_string(),
        );
        let config = AppConfig::from_map(values).unwrap();
        assert_eq!(
            config.google_login_client_secret.expose_secret(),
            &"l".repeat(32)
        );
        assert_eq!(
            config.google_gmail_client_secret.expose_secret(),
            &"g".repeat(32)
        );

        let empty = dir.path().join("empty");
        std::fs::write(&empty, "").unwrap();
        let mut values = map();
        values.remove("LOGIN_CLIENT_SECRET");
        values.insert(
            "LOGIN_CLIENT_SECRET_FILE".into(),
            empty.display().to_string(),
        );
        assert!(matches!(
            AppConfig::from_map(values),
            Err(ConfigError::SecretFile {
                field: "LOGIN_CLIENT_SECRET",
                reason: "file is empty"
            })
        ));

        let oversized = dir.path().join("oversized");
        std::fs::write(&oversized, vec![b'x'; MAX_SECRET_BYTES + 1]).unwrap();
        let mut values = map();
        values.remove("LOGIN_CLIENT_SECRET");
        values.insert(
            "LOGIN_CLIENT_SECRET_FILE".into(),
            oversized.display().to_string(),
        );
        assert!(matches!(
            AppConfig::from_map(values),
            Err(ConfigError::SecretFile {
                field: "LOGIN_CLIENT_SECRET",
                reason: "file is too large"
            })
        ));

        let missing = dir.path().join("missing");
        let mut values = map();
        values.remove("LOGIN_CLIENT_SECRET");
        values.insert(
            "LOGIN_CLIENT_SECRET_FILE".into(),
            missing.display().to_string(),
        );
        assert!(matches!(
            AppConfig::from_map(values),
            Err(ConfigError::SecretFile {
                field: "LOGIN_CLIENT_SECRET",
                reason: "file is unavailable"
            })
        ));

        let mut values = map();
        values.insert(
            "LOGIN_CLIENT_SECRET_FILE".into(),
            login.display().to_string(),
        );
        assert!(matches!(
            AppConfig::from_map(values),
            Err(ConfigError::Invalid {
                field: "LOGIN_CLIENT_SECRET",
                ..
            })
        ));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let insecure = dir.path().join("insecure");
            std::fs::write(&insecure, "i".repeat(32)).unwrap();
            std::fs::set_permissions(&insecure, std::fs::Permissions::from_mode(0o644)).unwrap();
            let mut values = map();
            values.remove("LOGIN_CLIENT_SECRET");
            values.insert(
                "LOGIN_CLIENT_SECRET_FILE".into(),
                insecure.display().to_string(),
            );
            assert!(matches!(
                AppConfig::from_map(values),
                Err(ConfigError::SecretFile {
                    field: "LOGIN_CLIENT_SECRET",
                    reason: "file permissions must not grant group or other access"
                })
            ));
        }
    }

    #[test]
    fn callback_urls_are_fixed_and_base_url_is_unambiguous() {
        let config = AppConfig::from_map(map()).unwrap();
        assert_eq!(
            config.google_login_callback_url().as_str(),
            "https://agentmail.example/auth/google/callback"
        );
        assert_eq!(
            config.google_gmail_callback_url().as_str(),
            "https://agentmail.example/connections/google/callback"
        );

        let mut development = map();
        development.insert("APP_ENV".into(), "development".into());
        development.insert("PUBLIC_BASE_URL".into(), "http://localhost:3000".into());
        assert!(AppConfig::from_map(development).is_ok());

        for base in ["http://remote.example", "file:///", "https:///"] {
            let mut values = map();
            values.insert("APP_ENV".into(), "development".into());
            values.insert("PUBLIC_BASE_URL".into(), base.to_owned());
            assert!(matches!(
                AppConfig::from_map(values),
                Err(ConfigError::Invalid {
                    field: "PUBLIC_BASE_URL",
                    ..
                })
            ));
        }

        for base in [
            "https://agentmail.example/?next=evil",
            "https://agentmail.example/base",
            "https://agentmail.example/#fragment",
        ] {
            let mut values = map();
            values.insert("PUBLIC_BASE_URL".into(), base.to_owned());
            assert!(matches!(
                AppConfig::from_map(values),
                Err(ConfigError::Invalid {
                    field: "PUBLIC_BASE_URL",
                    ..
                })
            ));
        }
    }
}

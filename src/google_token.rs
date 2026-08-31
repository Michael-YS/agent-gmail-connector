//! Minimal Google OAuth token-endpoint client.
//!
//! This module deliberately stops at token exchange and refresh.  It does not
//! persist tokens, fetch JWKS keys, or make Gmail API calls; those boundaries
//! need the repository and adapter wiring that is not part of this slice.

use reqwest::{Client, StatusCode, Url};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use std::{fmt, time::Duration};

pub const GOOGLE_TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";

#[derive(Debug, thiserror::Error, Clone, Eq, PartialEq)]
pub enum GoogleTokenError {
    #[error("client id is empty")]
    EmptyClientId,
    #[error("client secret is empty")]
    EmptyClientSecret,
    #[error("authorization code is empty")]
    EmptyAuthorizationCode,
    #[error("refresh token is empty")]
    EmptyRefreshToken,
    #[error("redirect URI is invalid")]
    InvalidRedirectUri,
    #[error("token endpoint returned invalid_grant")]
    InvalidGrant,
    #[error("token endpoint rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("token endpoint is unavailable")]
    Upstream,
    #[error("token endpoint timed out")]
    Timeout,
    #[error("token endpoint returned an invalid response")]
    InvalidResponse,
}

/// Tokens returned by Google.  Credential values stay wrapped in
/// `SecretString` and are never included in the custom debug representation.
#[derive(Clone)]
pub struct TokenSet {
    pub access_token: SecretString,
    pub expires_in: u64,
    pub refresh_token: Option<SecretString>,
    pub id_token: Option<SecretString>,
    pub scope: Vec<String>,
}

impl fmt::Debug for TokenSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenSet")
            .field("access_token", &"[REDACTED]")
            .field("expires_in", &self.expires_in)
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("id_token", &self.id_token.as_ref().map(|_| "[REDACTED]"))
            .field("scope", &self.scope)
            .finish()
    }
}

/// Google OAuth client using the production token endpoint by default.
#[derive(Clone)]
pub struct GoogleTokenClient {
    http: Client,
    token_endpoint: Url,
    redirect_uri: Url,
    client_id: String,
    client_secret: SecretString,
}

impl fmt::Debug for GoogleTokenClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GoogleTokenClient")
            .field("token_endpoint", &self.token_endpoint)
            .field("redirect_uri", &self.redirect_uri)
            .field("client_id", &"[REDACTED]")
            .field("client_secret", &"[REDACTED]")
            .finish()
    }
}

fn validate_redirect_uri(uri: &Url) -> Result<(), GoogleTokenError> {
    let Some(host) = uri.host_str() else {
        return Err(GoogleTokenError::InvalidRedirectUri);
    };
    let local_http =
        uri.scheme() == "http" && matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1");
    if !(uri.scheme() == "https" || local_http)
        || uri.username() != ""
        || uri.password().is_some()
        || uri.query().is_some()
        || uri.fragment().is_some()
    {
        return Err(GoogleTokenError::InvalidRedirectUri);
    }
    Ok(())
}
impl GoogleTokenClient {
    /// Construct a client bound to Google's HTTPS token endpoint and one exact callback.
    pub fn new(
        client_id: impl Into<String>,
        client_secret: SecretString,
        redirect_uri: Url,
    ) -> Result<Self, GoogleTokenError> {
        let endpoint = Url::parse(GOOGLE_TOKEN_ENDPOINT).expect("constant Google token URL");
        let http = Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|_| GoogleTokenError::Upstream)?;
        Self::with_endpoint(http, endpoint, client_id, client_secret, redirect_uri)
    }

    fn with_endpoint(
        http: Client,
        token_endpoint: Url,
        client_id: impl Into<String>,
        client_secret: SecretString,
        redirect_uri: Url,
    ) -> Result<Self, GoogleTokenError> {
        if token_endpoint.host_str().is_none()
            || (!matches!(token_endpoint.scheme(), "https")
                && !(cfg!(test) && token_endpoint.scheme() == "http"))
            || token_endpoint.username() != ""
            || token_endpoint.password().is_some()
            || token_endpoint.query().is_some()
            || token_endpoint.fragment().is_some()
        {
            return Err(GoogleTokenError::InvalidResponse);
        }
        validate_redirect_uri(&redirect_uri)?;
        let client_id = client_id.into();
        if client_id.trim().is_empty() {
            return Err(GoogleTokenError::EmptyClientId);
        }
        if client_secret.expose_secret().is_empty() {
            return Err(GoogleTokenError::EmptyClientSecret);
        }
        Ok(Self {
            http,
            token_endpoint,
            redirect_uri,
            client_id,
            client_secret,
        })
    }

    /// Exchange a one-time authorization code with PKCE proof.
    pub async fn exchange_code(
        &self,
        code: &str,
        code_verifier: &SecretString,
    ) -> Result<TokenSet, GoogleTokenError> {
        if code.trim().is_empty() {
            return Err(GoogleTokenError::EmptyAuthorizationCode);
        }
        if code_verifier.expose_secret().is_empty() {
            return Err(GoogleTokenError::InvalidResponse);
        }
        self.post_form(&[
            ("code", code),
            ("redirect_uri", self.redirect_uri.as_str()),
            ("code_verifier", code_verifier.expose_secret()),
            ("client_id", &self.client_id),
            ("client_secret", self.client_secret.expose_secret()),
            ("grant_type", "authorization_code"),
        ])
        .await
    }

    /// Exchange a stored refresh token for a short-lived access token.
    pub async fn refresh(
        &self,
        refresh_token: &SecretString,
    ) -> Result<TokenSet, GoogleTokenError> {
        if refresh_token.expose_secret().is_empty() {
            return Err(GoogleTokenError::EmptyRefreshToken);
        }
        self.post_form(&[
            ("refresh_token", refresh_token.expose_secret()),
            ("client_id", &self.client_id),
            ("client_secret", self.client_secret.expose_secret()),
            ("grant_type", "refresh_token"),
        ])
        .await
    }

    async fn post_form(&self, form: &[(&str, &str)]) -> Result<TokenSet, GoogleTokenError> {
        let response = self
            .http
            .post(self.token_endpoint.clone())
            .form(form)
            .send()
            .await
            .map_err(classify_transport_error)?;
        let status = response.status();

        if status == StatusCode::TOO_MANY_REQUESTS {
            let retry_after_seconds = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.trim().parse::<u64>().ok());
            return Err(GoogleTokenError::RateLimited {
                retry_after_seconds,
            });
        }

        let body = response.bytes().await.map_err(classify_transport_error)?;
        if !status.is_success() {
            let error = serde_json::from_slice::<ErrorResponse>(&body)
                .ok()
                .and_then(|value| value.error);
            return if error.as_deref() == Some("invalid_grant") {
                Err(GoogleTokenError::InvalidGrant)
            } else {
                Err(GoogleTokenError::Upstream)
            };
        }

        let raw = serde_json::from_slice::<RawTokenResponse>(&body)
            .map_err(|_| GoogleTokenError::InvalidResponse)?;
        raw.into_token_set()
    }
}

#[derive(Debug, Deserialize)]
struct ErrorResponse {
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawTokenResponse {
    access_token: SecretString,
    token_type: String,
    expires_in: u64,
    #[serde(default)]
    refresh_token: Option<SecretString>,
    #[serde(default)]
    id_token: Option<SecretString>,
    #[serde(default)]
    scope: Option<String>,
}

impl RawTokenResponse {
    fn into_token_set(self) -> Result<TokenSet, GoogleTokenError> {
        if self.access_token.expose_secret().is_empty()
            || !self.token_type.eq_ignore_ascii_case("bearer")
            || self.expires_in == 0
            || self
                .refresh_token
                .as_ref()
                .is_some_and(|token| token.expose_secret().is_empty())
            || self
                .id_token
                .as_ref()
                .is_some_and(|token| token.expose_secret().is_empty())
        {
            return Err(GoogleTokenError::InvalidResponse);
        }
        Ok(TokenSet {
            access_token: self.access_token,
            expires_in: self.expires_in,
            refresh_token: self.refresh_token,
            id_token: self.id_token,
            scope: self
                .scope
                .unwrap_or_default()
                .split_whitespace()
                .map(str::to_owned)
                .collect(),
        })
    }
}

fn classify_transport_error(error: reqwest::Error) -> GoogleTokenError {
    if error.is_timeout() {
        GoogleTokenError::Timeout
    } else {
        GoogleTokenError::Upstream
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::{net::TcpListener, time::sleep};

    async fn fake_server(
        status: u16,
        retry_after: Option<&str>,
        body: &str,
        expected_fields: &[&str],
        delay: Option<Duration>,
    ) -> (Url, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint =
            Url::parse(&format!("http://{}/token", listener.local_addr().unwrap())).unwrap();
        let response = format!(
            "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{}Connection: close\r\n\r\n{body}",
            body.len(),
            retry_after.map_or(String::new(), |value| format!("Retry-After: {value}\r\n")),
        );
        let expected_fields: Vec<String> =
            expected_fields.iter().map(|v| (*v).to_owned()).collect();
        let body = body.to_owned();
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
                        if let Some(separator) =
                            request.windows(4).position(|window| window == b"\r\n\r\n")
                        {
                            let headers = String::from_utf8_lossy(&request[..separator]);
                            let content_length = headers
                                .lines()
                                .find_map(|line| {
                                    let (name, value) = line.split_once(':')?;
                                    name.eq_ignore_ascii_case("content-length")
                                        .then(|| value.trim().parse::<usize>().ok())
                                        .flatten()
                                })
                                .unwrap_or(0);
                            if request.len() >= separator + 4 + content_length {
                                break;
                            }
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(_) => break,
                }
            }
            if let Some(separator) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                let request_body = String::from_utf8_lossy(&request[separator + 4..]);
                for field in expected_fields {
                    assert!(request_body.contains(&field), "missing form field {field}");
                }
            }
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
            let _ = body;
        });
        (endpoint, handle)
    }

    fn client(endpoint: Url) -> GoogleTokenClient {
        GoogleTokenClient::with_endpoint(
            Client::builder()
                .timeout(Duration::from_millis(250))
                .build()
                .unwrap(),
            endpoint,
            "client-id",
            SecretString::from("client-secret"),
            Url::parse("https://agentmail.example/callback").unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn constructor_rejects_untrusted_redirects() {
        for redirect in [
            "http://example.com/callback",
            "https://user@example.com/callback",
            "https://agentmail.example/callback?next=evil",
        ] {
            let error = GoogleTokenClient::new(
                "client-id",
                SecretString::from("client-secret"),
                Url::parse(redirect).unwrap(),
            )
            .unwrap_err();
            assert_eq!(error, GoogleTokenError::InvalidRedirectUri);
        }
    }
    #[tokio::test]
    async fn exchange_and_refresh_send_expected_forms() {
        let (endpoint, exchange_server) = fake_server(
            200,
            None,
            r#"{"access_token":"access","token_type":"Bearer","expires_in":3600,"refresh_token":"refresh","id_token":"id","scope":"openid email"}"#,
            &["code=auth-code", "redirect_uri=https%3A%2F%2Fagentmail.example%2Fcallback", "code_verifier=verifier", "client_id=client-id", "client_secret=client-secret", "grant_type=authorization_code"],
            None,
        )
        .await;
        let token = client(endpoint)
            .exchange_code("auth-code", &SecretString::from("verifier"))
            .await
            .unwrap();
        assert_eq!(token.access_token.expose_secret(), "access");
        assert_eq!(token.refresh_token.unwrap().expose_secret(), "refresh");
        exchange_server.await.unwrap();

        let (endpoint, refresh_server) = fake_server(
            200,
            None,
            r#"{"access_token":"new-access","token_type":"Bearer","expires_in":1800,"scope":"gmail.readonly"}"#,
            &["refresh_token=old-refresh", "client_id=client-id", "client_secret=client-secret", "grant_type=refresh_token"],
            None,
        )
        .await;
        let token = client(endpoint)
            .refresh(&SecretString::from("old-refresh"))
            .await
            .unwrap();
        assert_eq!(token.access_token.expose_secret(), "new-access");
        assert_eq!(token.scope, vec!["gmail.readonly"]);
        refresh_server.await.unwrap();
    }

    #[tokio::test]
    async fn stable_errors_do_not_include_upstream_body() {
        let cases = [
            (
                400,
                None,
                r#"{"error":"invalid_grant","error_description":"secret-body"}"#,
                GoogleTokenError::InvalidGrant,
            ),
            (
                429,
                Some("17"),
                r#"{"error":"rate_limit","detail":"secret-body"}"#,
                GoogleTokenError::RateLimited {
                    retry_after_seconds: Some(17),
                },
            ),
            (
                500,
                None,
                r#"{"error":"server_error","detail":"secret-body"}"#,
                GoogleTokenError::Upstream,
            ),
            (200, None, "not-json", GoogleTokenError::InvalidResponse),
        ];
        for (status, retry_after, body, expected) in cases {
            let (endpoint, server) = fake_server(status, retry_after, body, &[], None).await;
            let error = client(endpoint)
                .refresh(&SecretString::from("refresh"))
                .await
                .unwrap_err();
            assert_eq!(error, expected);
            assert!(!error.to_string().contains("secret-body"));
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn timeout_is_distinguished_and_debug_is_redacted() {
        let (endpoint, server) = fake_server(
            200,
            None,
            r#"{"access_token":"access","token_type":"Bearer","expires_in":3600}"#,
            &[],
            Some(Duration::from_millis(500)),
        )
        .await;
        let error = client(endpoint)
            .refresh(&SecretString::from("refresh"))
            .await
            .unwrap_err();
        assert_eq!(error, GoogleTokenError::Timeout);
        let _ = server.await;

        let (endpoint, server) = fake_server(
            200,
            None,
            r#"{"access_token":"access-secret","token_type":"Bearer","expires_in":3600,"refresh_token":"refresh-secret","id_token":"id-secret"}"#,
            &[],
            None,
        )
        .await;
        let token = client(endpoint)
            .refresh(&SecretString::from("refresh"))
            .await
            .unwrap();
        let debug = format!("{token:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("access-secret"));
        assert!(!debug.contains("refresh-secret"));
        assert!(!debug.contains("id-secret"));
        server.await.unwrap();
    }
}

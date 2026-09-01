//! Google OIDC discovery, JWKS caching, and RS256 signature verification.

use crate::oauth::{OidcClaims, OidcSignatureVerifier, SignatureVerificationError};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use reqwest::{Client, StatusCode, header::CACHE_CONTROL};
use serde::Deserialize;
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};
use thiserror::Error;
use url::Url;

pub const GOOGLE_DISCOVERY_URL: &str =
    "https://accounts.google.com/.well-known/openid-configuration";
pub const GOOGLE_ISSUER: &str = "https://accounts.google.com";
pub const GOOGLE_JWKS_URI: &str = "https://www.googleapis.com/oauth2/v3/certs";
pub const MAX_DISCOVERY_BYTES: usize = 64 * 1024;
pub const MAX_JWKS_BYTES: usize = 256 * 1024;
pub const MAX_CACHE_AGE: Duration = Duration::from_secs(60 * 60);
const DEFAULT_CACHE_AGE: Duration = Duration::from_secs(5 * 60);
const MIN_UNKNOWN_KID_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug, Error, Clone, Copy, Eq, PartialEq)]
pub enum GoogleOidcError {
    #[error("OIDC discovery request failed")]
    DiscoveryRequest,
    #[error("OIDC discovery response is invalid")]
    InvalidDiscovery,
    #[error("OIDC discovery response is too large")]
    DiscoveryTooLarge,
    #[error("OIDC JWKS request failed")]
    JwksRequest,
    #[error("OIDC JWKS response is invalid")]
    InvalidJwks,
    #[error("OIDC JWKS response is too large")]
    JwksTooLarge,
    #[error("OIDC token is invalid")]
    InvalidToken,
    #[error("OIDC token key id is missing")]
    MissingKid,
    #[error("OIDC token key id is unknown")]
    UnknownKid,
    #[error("OIDC token algorithm is not allowed")]
    UnsupportedAlgorithm,
    #[error("OIDC key cache is unavailable")]
    CacheUnavailable,
}

#[derive(Clone)]
pub struct GoogleJwksVerifier {
    client: Client,
    discovery_url: Url,
    test_localhost: bool,
    snapshot: Arc<RwLock<Option<JwksSnapshot>>>,
    refresh_lock: Arc<tokio::sync::Mutex<()>>,
}
impl std::fmt::Debug for GoogleJwksVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GoogleJwksVerifier")
            .field("discovery_url", &self.discovery_url)
            .field("test_localhost", &self.test_localhost)
            .field("snapshot", &"[REDACTED]")
            .finish()
    }
}
#[derive(Clone)]
struct JwksSnapshot {
    keys: HashMap<String, Arc<DecodingKey>>,
    expires_at: Instant,
    refreshed_at: Instant,
}
#[derive(Debug, Deserialize)]
struct DiscoveryDocument {
    issuer: String,
    jwks_uri: String,
}
#[derive(Debug, Deserialize)]
struct JwksDocument {
    keys: Vec<JwkDocument>,
}
#[derive(Debug, Deserialize)]
struct RawOidcClaims {
    #[serde(rename = "iss")]
    issuer: String,
    #[serde(rename = "aud", deserialize_with = "deserialize_audience")]
    audience: Vec<String>,
    #[serde(default)]
    azp: Option<String>,
    #[serde(rename = "sub")]
    subject: String,
    email: String,
    email_verified: bool,
    #[serde(rename = "exp")]
    expires_at: i64,
    nonce: String,
}
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawAudience {
    One(String),
    Many(Vec<String>),
}
fn deserialize_audience<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match RawAudience::deserialize(deserializer)? {
        RawAudience::One(value) => Ok(vec![value]),
        RawAudience::Many(values) => Ok(values),
    }
}

#[derive(Debug, Deserialize)]
struct JwkDocument {
    kty: String,
    alg: Option<String>,
    #[serde(rename = "use")]
    use_: Option<String>,
    kid: Option<String>,
    n: Option<String>,
    e: Option<String>,
}

impl GoogleJwksVerifier {
    pub fn new() -> Result<Self, GoogleOidcError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| GoogleOidcError::DiscoveryRequest)?;
        Ok(Self {
            client,
            discovery_url: Url::parse(GOOGLE_DISCOVERY_URL).expect("constant URL"),
            test_localhost: false,
            snapshot: Arc::new(RwLock::new(None)),
            refresh_lock: Arc::new(tokio::sync::Mutex::new(())),
        })
    }
    #[cfg(test)]
    pub fn with_test_discovery(discovery_url: Url) -> Result<Self, GoogleOidcError> {
        if !is_localhost_http(&discovery_url) {
            return Err(GoogleOidcError::InvalidDiscovery);
        }
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| GoogleOidcError::DiscoveryRequest)?;
        Ok(Self {
            client,
            discovery_url,
            test_localhost: true,
            snapshot: Arc::new(RwLock::new(None)),
            refresh_lock: Arc::new(tokio::sync::Mutex::new(())),
        })
    }
    pub async fn refresh(&self) -> Result<(), GoogleOidcError> {
        let _guard = self.refresh_lock.lock().await;
        self.refresh_locked().await
    }

    async fn refresh_locked(&self) -> Result<(), GoogleOidcError> {
        let response = self
            .client
            .get(self.discovery_url.clone())
            .send()
            .await
            .map_err(|_| GoogleOidcError::DiscoveryRequest)?;
        if response.status() != StatusCode::OK {
            return Err(GoogleOidcError::DiscoveryRequest);
        }
        let body = bounded_body(response, MAX_DISCOVERY_BYTES, true).await?;
        let document: DiscoveryDocument =
            serde_json::from_slice(&body).map_err(|_| GoogleOidcError::InvalidDiscovery)?;
        let jwks_uri = validate_discovery(&self.discovery_url, &document, self.test_localhost)?;
        let response = self
            .client
            .get(jwks_uri)
            .send()
            .await
            .map_err(|_| GoogleOidcError::JwksRequest)?;
        if response.status() != StatusCode::OK {
            return Err(GoogleOidcError::JwksRequest);
        }
        let age = cache_age(response.headers().get(CACHE_CONTROL));
        let body = bounded_body(response, MAX_JWKS_BYTES, false).await?;
        let jwks: JwksDocument =
            serde_json::from_slice(&body).map_err(|_| GoogleOidcError::InvalidJwks)?;
        let keys = parse_jwks(jwks)?;
        let now = Instant::now();
        *self
            .snapshot
            .write()
            .map_err(|_| GoogleOidcError::CacheUnavailable)? = Some(JwksSnapshot {
            keys,
            expires_at: now + age,
            refreshed_at: now,
        });
        Ok(())
    }

    pub async fn verify_with_refresh(&self, id_token: &str) -> Result<OidcClaims, GoogleOidcError> {
        let kid = token_kid(id_token)?;
        if let Some(key) = self.cached_key(&kid)? {
            return self.decode_claims(id_token, &key);
        }
        let _guard = self.refresh_lock.lock().await;
        if let Some(key) = self.cached_key(&kid)? {
            return self.decode_claims(id_token, &key);
        }
        if !self.should_refresh()? {
            return Err(GoogleOidcError::UnknownKid);
        }
        self.refresh_locked().await?;
        let key = self.cached_key(&kid)?.ok_or(GoogleOidcError::UnknownKid)?;
        self.decode_claims(id_token, &key)
    }

    fn cached_key(&self, kid: &str) -> Result<Option<Arc<DecodingKey>>, GoogleOidcError> {
        Ok(self
            .snapshot
            .read()
            .map_err(|_| GoogleOidcError::CacheUnavailable)?
            .as_ref()
            .filter(|snapshot| snapshot.expires_at > Instant::now())
            .and_then(|snapshot| snapshot.keys.get(kid).cloned()))
    }

    fn should_refresh(&self) -> Result<bool, GoogleOidcError> {
        let now = Instant::now();
        Ok(self
            .snapshot
            .read()
            .map_err(|_| GoogleOidcError::CacheUnavailable)?
            .as_ref()
            .is_none_or(|snapshot| {
                snapshot.expires_at <= now
                    || now.duration_since(snapshot.refreshed_at) >= MIN_UNKNOWN_KID_REFRESH_INTERVAL
            }))
    }

    fn verify_cached(&self, token: &str) -> Result<OidcClaims, GoogleOidcError> {
        let kid = token_kid(token)?;
        let key = self.cached_key(&kid)?.ok_or(GoogleOidcError::UnknownKid)?;
        self.decode_claims(token, &key)
    }
    fn decode_claims(&self, token: &str, key: &DecodingKey) -> Result<OidcClaims, GoogleOidcError> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.validate_aud = false;
        validation.required_spec_claims.clear();
        validation.aud = None;
        validation.iss = None;
        decode::<RawOidcClaims>(token, key, &validation)
            .map(|t| OidcClaims {
                issuer: t.claims.issuer,
                audience: t.claims.audience,
                azp: t.claims.azp,
                subject: t.claims.subject,
                email: t.claims.email,
                email_verified: t.claims.email_verified,
                expires_at: t.claims.expires_at,
                nonce: t.claims.nonce,
            })
            .map_err(|_| GoogleOidcError::InvalidToken)
    }
}
impl OidcSignatureVerifier for GoogleJwksVerifier {
    fn verify_signature(&self, token: &str) -> Result<OidcClaims, SignatureVerificationError> {
        self.verify_cached(token)
            .map_err(|_| SignatureVerificationError)
    }
}
fn token_kid(token: &str) -> Result<String, GoogleOidcError> {
    let header = decode_header(token).map_err(|_| GoogleOidcError::InvalidToken)?;
    if header.alg != Algorithm::RS256 {
        return Err(GoogleOidcError::UnsupportedAlgorithm);
    }
    header.kid.ok_or(GoogleOidcError::MissingKid)
}
fn parse_jwks(
    document: JwksDocument,
) -> Result<HashMap<String, Arc<DecodingKey>>, GoogleOidcError> {
    let mut keys = HashMap::new();
    for jwk in document.keys {
        if jwk.kty != "RSA"
            || jwk.alg.as_deref() != Some("RS256")
            || jwk.use_.as_deref() != Some("sig")
        {
            return Err(GoogleOidcError::InvalidJwks);
        }
        let kid = jwk.kid.ok_or(GoogleOidcError::InvalidJwks)?;
        let n = jwk.n.ok_or(GoogleOidcError::InvalidJwks)?;
        let e = jwk.e.ok_or(GoogleOidcError::InvalidJwks)?;
        if kid.trim().is_empty() || n.trim().is_empty() || e.trim().is_empty() {
            return Err(GoogleOidcError::InvalidJwks);
        }
        let key =
            DecodingKey::from_rsa_components(&n, &e).map_err(|_| GoogleOidcError::InvalidJwks)?;
        if keys.insert(kid, Arc::new(key)).is_some() {
            return Err(GoogleOidcError::InvalidJwks);
        }
    }
    if keys.is_empty() {
        return Err(GoogleOidcError::InvalidJwks);
    }
    Ok(keys)
}
fn validate_discovery(
    discovery_url: &Url,
    document: &DiscoveryDocument,
    test_localhost: bool,
) -> Result<Url, GoogleOidcError> {
    let issuer = Url::parse(&document.issuer).map_err(|_| GoogleOidcError::InvalidDiscovery)?;
    let jwks_uri = Url::parse(&document.jwks_uri).map_err(|_| GoogleOidcError::InvalidDiscovery)?;
    if !test_localhost {
        if document.issuer != GOOGLE_ISSUER || document.jwks_uri != GOOGLE_JWKS_URI {
            return Err(GoogleOidcError::InvalidDiscovery);
        }
        return Ok(jwks_uri);
    }
    if !is_localhost_http(&issuer)
        || !is_localhost_http(&jwks_uri)
        || !same_origin(discovery_url, &issuer)
        || !same_origin(&issuer, &jwks_uri)
    {
        return Err(GoogleOidcError::InvalidDiscovery);
    }
    Ok(jwks_uri)
}
fn is_localhost_http(url: &Url) -> bool {
    url.scheme() == "http"
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && matches!(
            url.host_str(),
            Some("localhost" | "127.0.0.1" | "::1" | "[::1]")
        )
}
fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}
fn cache_age(value: Option<&reqwest::header::HeaderValue>) -> Duration {
    let seconds = value
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.split(',').find_map(|directive| {
                let (name, amount) = directive.trim().split_once('=')?;
                if name.eq_ignore_ascii_case("max-age") {
                    amount.trim().parse::<u64>().ok()
                } else {
                    None
                }
            })
        })
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_CACHE_AGE);
    seconds.min(MAX_CACHE_AGE)
}
async fn bounded_body(
    response: reqwest::Response,
    max: usize,
    discovery: bool,
) -> Result<Vec<u8>, GoogleOidcError> {
    let mut response = response;
    let too_large = || {
        if discovery {
            GoogleOidcError::DiscoveryTooLarge
        } else {
            GoogleOidcError::JwksTooLarge
        }
    };
    if response.content_length().is_some_and(|n| n > max as u64) {
        return Err(too_large());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| {
        if discovery {
            GoogleOidcError::DiscoveryRequest
        } else {
            GoogleOidcError::JwksRequest
        }
    })? {
        if body.len().saturating_add(chunk.len()) > max {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, response::IntoResponse, routing::get};
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const TEST_N: &str = "twBSkQTMWIvdd4puuya8soatHudAZjrLC3OCmbdQTbcLMvxR4NjUvpsbB6Nn35cz2H0Pf4RBsSPGJu8Qma4uWUbvKHjqv7Y8TmSua-F1J5Fm3uKCqCMC6qfc-qvvWwjXow5hrDHq6_K3mdA_OLIfpYku5xgTKdktfjOatlVmujFG-XFKRFjW_mTzoRB79oKrcJv9wsLibHjVEBq14pMX87QA6D337iVmK1DjB_0Q8E_UzJpDRSuICKMj_zOL26861tI9OcTfBvwC5ou1j_ooMqxVfXyvC0i32OSxh_36p4Az6Q9AVGQWeYdaMgvhDzkjEuZ1D-FmEbQnR9OzSf9Ucw";
    const TEST_PRIVATE_KEY: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAtwBSkQTMWIvdd4puuya8soatHudAZjrLC3OCmbdQTbcLMvxR
4NjUvpsbB6Nn35cz2H0Pf4RBsSPGJu8Qma4uWUbvKHjqv7Y8TmSua+F1J5Fm3uKC
qCMC6qfc+qvvWwjXow5hrDHq6/K3mdA/OLIfpYku5xgTKdktfjOatlVmujFG+XFK
RFjW/mTzoRB79oKrcJv9wsLibHjVEBq14pMX87QA6D337iVmK1DjB/0Q8E/UzJpD
RSuICKMj/zOL26861tI9OcTfBvwC5ou1j/ooMqxVfXyvC0i32OSxh/36p4Az6Q9A
VGQWeYdaMgvhDzkjEuZ1D+FmEbQnR9OzSf9UcwIDAQABAoIBAFo9xPlxOclyUyg3
MgqE/Ck3A1jJZXbkCCth7yWZAXcJS/L8/O1ZT3OcrfQSzs6x06Wuaf2SPQi6oOSj
H/cArydkNNwq4GvgVBW+TUqyl6CG8Yj4fsCl3zLSy0Qrk/E6x4dHOL/+r59hhctK
J1rwb22kW+Ymd5C74VSp4uGF9I3cmFpOt90o17D7rhFOj+6Kpw8h7+vQclnc32OK
2YFp7ygEiutlMfoY4SkJUsy/fnWAAIFdixiHf3gjAIupenwXLlJMnowJZq87fksR
LfhY6KVElfNdkednEweaJ7fMzVummluYznNJkfgR+5uJS94GfF2pd5swLjsDgsP9
bVD3OU0CgYEA3rl+5CvH51tvooyjxys8tf3N2Uba+tR3AZl//n0wp3aZdtycDEuO
HkToEfEW3eaSdwj9vRLzwlyr+l6cT9Ok/rfy35hFYjQ1PEM8wXyxrXJQVOZI4WHd
y2lmKSV6YVogPFrHtc0pSqSkrysv2htZfDj36gdQtD41/BpUlczJn68CgYEA0leJ
R8kh9FTUmdWDBdxiAfdKb9WZ2o+Ef96QIAYZMpJHrARR9HMHKy19A4AuJtzmof4B
9EJxsYfO9shP/PwBjLqdoJHHRAGKALGEArzVdfQetnFVe6jdBB+CqELK6ftsng/n
bis69eWnyW/ZvRdFh6HCLFX2hmI0+QDnykiUZH0CgYEAo5vDuLzode1XDiMd1BrQ
2Cd+5VMFXShh20z1Fu7DpOCcTxIzl1yRI28ewr9FOvA7OzHhotifM3F768lALeuc
0ngx80oZ/c+4I3KI2OFOa8kDdbpMYzPPB7N/Fk6vnX/lGjDdb5Er+ecECqFA34kj
rPr0Mnf5Ms5YPb7hz8DFg4UCgYEApti6009u+JGFppTffnmm4GpZCEbF6MFo18ki
R9SujhfMdF1k6OOJby2A+ZLmiPs2ko6a3DcMWkcg205fbIw1anzo5eJczsvtvMkS
rt088Xh4GD3kEdgLoOahzHhW3q0KJoL1D8WI2l6V7kojzEM2avTbwjFaAJTL8ixO
sH1MAD0CgYEAq1oBb+QacEgglE+5Ek+PvGaXaIJ2luZkQ2gUu/p4rK+2PZgml+Dh
64jONbp8AWHNa6B3aPe+q33CZktHwzDTkbQ9E9n/m+SpkOZsZIaQGlG+FPIIyMAP
oL0YUGIxQswlYy2mLWvDCjs784Nmza0ZH+0aAVtzrg8tmS08nuyQdk8=
-----END RSA PRIVATE KEY-----";

    async fn fixture() -> (
        GoogleJwksVerifier,
        Arc<AtomicUsize>,
        tokio::task::JoinHandle<()>,
    ) {
        let discovery_hits = Arc::new(AtomicUsize::new(0));
        let jwks_hits = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let issuer = format!("http://127.0.0.1:{port}");
        let discovery_issuer = issuer.clone();
        let d = discovery_hits.clone();
        let j = jwks_hits.clone();
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(move || {
                let d = d.clone();
                let issuer = discovery_issuer.clone();
                async move {
                    d.fetch_add(1, Ordering::Relaxed);
                    axum::Json(json!({"issuer":issuer,"jwks_uri":format!("{issuer}/keys")}))
                }
            }))
            .route("/keys", get(move || {
                let j = j.clone();
                async move {
                    j.fetch_add(1, Ordering::Relaxed);
                    ([(axum::http::header::CACHE_CONTROL, "max-age=3600")],
                     axum::Json(json!({"keys":[{"kty":"RSA","alg":"RS256","use":"sig","kid":"test-key","n":TEST_N,"e":"AQAB"}]}))).into_response()
                }
            }));
        let handle = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let url = Url::parse(&format!("{issuer}/.well-known/openid-configuration")).unwrap();
        let verifier = GoogleJwksVerifier::with_test_discovery(url).unwrap();
        (verifier, jwks_hits, handle)
    }

    fn token() -> String {
        token_with_kid("test-key")
    }

    fn token_with_kid(kid: &str) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.into());
        let claims = json!({"iss":"http://127.0.0.1","sub":"s","aud":["client"],"exp":4102444800i64,"nonce":"n","email":"u@example.com","email_verified":true});
        encode(
            &header,
            &claims,
            &EncodingKey::from_rsa_pem(TEST_PRIVATE_KEY.as_bytes()).unwrap(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn fetches_discovery_and_jwks_then_uses_cache() {
        let (verifier, jwks_hits, handle) = fixture().await;
        let first = verifier.verify_with_refresh(&token()).await;
        assert!(first.is_ok(), "{first:?}");
        let second = verifier.verify_with_refresh(&token()).await;
        assert!(second.is_ok());
        assert_eq!(jwks_hits.load(Ordering::Relaxed), 1);
        handle.abort();
    }

    #[test]
    fn rejects_bad_jwks_and_tokens_without_disabling_signature_checks() {
        assert!(parse_jwks(JwksDocument { keys: vec![] }).is_err());
        assert_eq!(token_kid("not-a-token"), Err(GoogleOidcError::InvalidToken));
        let key = DecodingKey::from_rsa_components(TEST_N, "AQAB").unwrap();
        let verifier = GoogleJwksVerifier {
            client: Client::new(),
            discovery_url: Url::parse(GOOGLE_DISCOVERY_URL).unwrap(),
            test_localhost: false,
            snapshot: Arc::new(RwLock::new(Some(JwksSnapshot {
                keys: HashMap::from([("test-key".into(), Arc::new(key))]),
                expires_at: Instant::now() + Duration::from_secs(60),
                refreshed_at: Instant::now(),
            }))),
            refresh_lock: Arc::new(tokio::sync::Mutex::new(())),
        };
        assert!(
            verifier
                .verify_signature("eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5In0.e30.invalid")
                .is_err()
        );
    }

    #[test]
    fn production_discovery_requires_exact_issuer_and_jwks_uri() {
        let discovery_url = Url::parse(GOOGLE_DISCOVERY_URL).unwrap();
        let mut document = DiscoveryDocument {
            issuer: "https://accounts.google.com.evil.example".into(),
            jwks_uri: GOOGLE_JWKS_URI.into(),
        };
        assert_eq!(
            validate_discovery(&discovery_url, &document, false),
            Err(GoogleOidcError::InvalidDiscovery)
        );

        document.issuer = GOOGLE_ISSUER.into();
        document.jwks_uri = "https://evil.example/keys".into();
        assert_eq!(
            validate_discovery(&discovery_url, &document, false),
            Err(GoogleOidcError::InvalidDiscovery)
        );
    }

    #[test]
    fn localhost_discovery_rejects_cross_origin_issuer_and_jwks() {
        let discovery_url =
            Url::parse("http://127.0.0.1:4100/.well-known/openid-configuration").unwrap();
        let mut document = DiscoveryDocument {
            issuer: "http://127.0.0.1:4101".into(),
            jwks_uri: "http://127.0.0.1:4101/keys".into(),
        };
        assert_eq!(
            validate_discovery(&discovery_url, &document, true),
            Err(GoogleOidcError::InvalidDiscovery)
        );

        document.issuer = discovery_url.origin().ascii_serialization();
        document.jwks_uri = "http://127.0.0.1:4101/keys".into();
        assert_eq!(
            validate_discovery(&discovery_url, &document, true),
            Err(GoogleOidcError::InvalidDiscovery)
        );
    }

    fn valid_jwk() -> JwkDocument {
        JwkDocument {
            kty: "RSA".into(),
            alg: Some("RS256".into()),
            use_: Some("sig".into()),
            kid: Some("test-key".into()),
            n: Some(TEST_N.into()),
            e: Some("AQAB".into()),
        }
    }

    #[test]
    fn jwks_rejects_invalid_alg_use_and_required_key_fields() {
        let mut jwk = valid_jwk();
        jwk.alg = Some("HS256".into());
        assert!(matches!(
            parse_jwks(JwksDocument { keys: vec![jwk] }),
            Err(GoogleOidcError::InvalidJwks)
        ));

        let mut jwk = valid_jwk();
        jwk.use_ = Some("enc".into());
        assert!(matches!(
            parse_jwks(JwksDocument { keys: vec![jwk] }),
            Err(GoogleOidcError::InvalidJwks)
        ));

        let mut jwk = valid_jwk();
        jwk.kid = None;
        assert!(matches!(
            parse_jwks(JwksDocument { keys: vec![jwk] }),
            Err(GoogleOidcError::InvalidJwks)
        ));

        let mut jwk = valid_jwk();
        jwk.n = None;
        assert!(matches!(
            parse_jwks(JwksDocument { keys: vec![jwk] }),
            Err(GoogleOidcError::InvalidJwks)
        ));

        let mut jwk = valid_jwk();
        jwk.e = None;
        assert!(matches!(
            parse_jwks(JwksDocument { keys: vec![jwk] }),
            Err(GoogleOidcError::InvalidJwks)
        ));

        let mut jwk = valid_jwk();
        jwk.kid = Some(" ".into());
        jwk.n = Some(" ".into());
        jwk.e = Some(" ".into());
        assert!(matches!(
            parse_jwks(JwksDocument { keys: vec![jwk] }),
            Err(GoogleOidcError::InvalidJwks)
        ));
        assert!(matches!(
            parse_jwks(JwksDocument { keys: vec![] }),
            Err(GoogleOidcError::InvalidJwks)
        ));
    }

    #[test]
    fn cache_age_defaults_and_caps_at_one_hour() {
        assert_eq!(cache_age(None), DEFAULT_CACHE_AGE);
        let long = reqwest::header::HeaderValue::from_static("public, max-age=7200");
        assert_eq!(cache_age(Some(&long)), MAX_CACHE_AGE);
    }

    #[tokio::test]
    async fn discovery_does_not_follow_redirects() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let redirected_hits = Arc::new(AtomicUsize::new(0));
        let hits = redirected_hits.clone();
        let app = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(move || async move {
                    (
                        axum::http::StatusCode::FOUND,
                        [(axum::http::header::LOCATION, "/redirected")],
                    )
                }),
            )
            .route(
                "/redirected",
                get(move || {
                    let hits = hits.clone();
                    async move {
                        hits.fetch_add(1, Ordering::Relaxed);
                        "unexpected redirect follow"
                    }
                }),
            );
        let handle = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let url = Url::parse(&format!(
            "http://127.0.0.1:{port}/.well-known/openid-configuration"
        ))
        .unwrap();
        let verifier = GoogleJwksVerifier::with_test_discovery(url).unwrap();
        assert_eq!(
            verifier.refresh().await,
            Err(GoogleOidcError::DiscoveryRequest)
        );
        assert_eq!(redirected_hits.load(Ordering::Relaxed), 0);
        handle.abort();
    }

    #[tokio::test]
    async fn discovery_and_jwks_bodies_are_bounded() {
        let discovery_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let discovery_port = discovery_listener.local_addr().unwrap().port();
        let oversized_discovery = "x".repeat(MAX_DISCOVERY_BYTES + 1);
        let discovery_app = Router::new().route(
            "/.well-known/openid-configuration",
            get(move || {
                let body = oversized_discovery.clone();
                async move { (axum::http::StatusCode::OK, body) }
            }),
        );
        let discovery_handle = tokio::spawn(async move {
            axum::serve(discovery_listener, discovery_app)
                .await
                .unwrap()
        });
        let discovery_url = Url::parse(&format!(
            "http://127.0.0.1:{discovery_port}/.well-known/openid-configuration"
        ))
        .unwrap();
        let verifier = GoogleJwksVerifier::with_test_discovery(discovery_url).unwrap();
        assert_eq!(
            verifier.refresh().await,
            Err(GoogleOidcError::DiscoveryTooLarge)
        );
        discovery_handle.abort();

        let jwks_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let jwks_port = jwks_listener.local_addr().unwrap().port();
        let issuer = format!("http://127.0.0.1:{jwks_port}");
        let discovery_body = format!(r#"{{"issuer":"{issuer}","jwks_uri":"{issuer}/keys"}}"#);
        let oversized_jwks = "x".repeat(MAX_JWKS_BYTES + 1);
        let jwks_app = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(move || {
                    let body = discovery_body.clone();
                    async move { (axum::http::StatusCode::OK, body) }
                }),
            )
            .route(
                "/keys",
                get(move || {
                    let body = oversized_jwks.clone();
                    async move { (axum::http::StatusCode::OK, body) }
                }),
            );
        let jwks_handle =
            tokio::spawn(async move { axum::serve(jwks_listener, jwks_app).await.unwrap() });
        let discovery_url = Url::parse(&format!(
            "http://127.0.0.1:{jwks_port}/.well-known/openid-configuration"
        ))
        .unwrap();
        let verifier = GoogleJwksVerifier::with_test_discovery(discovery_url).unwrap();
        assert_eq!(verifier.refresh().await, Err(GoogleOidcError::JwksTooLarge));
        jwks_handle.abort();
    }

    #[tokio::test]
    async fn concurrent_unknown_kid_refreshes_once_and_respects_cooldown() {
        let (verifier, jwks_hits, handle) = fixture().await;
        let token = token_with_kid("unknown-key");
        let mut tasks = Vec::new();
        for _ in 0..16 {
            let verifier = verifier.clone();
            let token = token.clone();
            tasks.push(tokio::spawn(async move {
                verifier.verify_with_refresh(&token).await
            }));
        }
        for task in tasks {
            assert!(matches!(
                task.await.unwrap(),
                Err(GoogleOidcError::UnknownKid)
            ));
        }
        assert_eq!(jwks_hits.load(Ordering::Relaxed), 1);
        assert!(matches!(
            verifier.verify_with_refresh(&token).await,
            Err(GoogleOidcError::UnknownKid)
        ));
        assert_eq!(jwks_hits.load(Ordering::Relaxed), 1);
        handle.abort();
    }
}

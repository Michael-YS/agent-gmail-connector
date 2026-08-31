//! Google OAuth/OIDC flow primitives.
//!
//! This module owns the security-sensitive parts of both Google flows.  It
//! intentionally does not verify JWT signatures: [`OidcSignatureVerifier`] is
//! the boundary where a real adapter must perform signature and key checks.
//! State and nonce are only persisted as SHA-256 digests.  The PKCE verifier
//! remains in a `SecretString` until it is exchanged by the OAuth adapter.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::{fmt, marker::PhantomData};
use subtle::ConstantTimeEq;
use url::Url;

use crate::crypto::{CryptoError, Keyring, decrypt_token, encrypt_token, hash_token, verify_token};

pub const GOOGLE_AUTHORIZE_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";
pub const GOOGLE_ISSUER: &str = "https://accounts.google.com";
pub const LOGIN_CALLBACK_PATH: &str = "/auth/google/login/callback";
pub const GMAIL_CALLBACK_PATH: &str = "/auth/google/gmail/callback";
pub const GMAIL_READONLY_SCOPE: &str = "https://www.googleapis.com/auth/gmail.readonly";
pub const GMAIL_COMPOSE_SCOPE: &str = "https://www.googleapis.com/auth/gmail.compose";
pub const LOGIN_SCOPES: [&str; 3] = ["openid", "email", "profile"];
pub const GMAIL_SCOPES: [&str; 5] = [
    "openid",
    "email",
    "profile",
    GMAIL_READONLY_SCOPE,
    GMAIL_COMPOSE_SCOPE,
];
const DEFAULT_TRANSACTION_TTL: Duration = Duration::minutes(10);

#[derive(Debug, thiserror::Error, Clone, Eq, PartialEq)]
pub enum OAuthError {
    #[error("public base URL must be an absolute URL without query or fragment")]
    InvalidBaseUrl,
    #[error("OAuth client id is empty")]
    EmptyClientId,
    #[error("OAuth state does not match")]
    StateMismatch,
    #[error("OAuth nonce does not match")]
    NonceMismatch,
    #[error("OAuth transaction has expired")]
    Expired,
    #[error("OAuth transaction has already been consumed")]
    AlreadyConsumed,
    #[error("OAuth callback code is empty")]
    EmptyAuthorizationCode,
    #[error("OIDC issuer is invalid")]
    InvalidIssuer,
    #[error("OIDC audience is invalid")]
    InvalidAudience,
    #[error("OIDC nonce is invalid")]
    InvalidOidcNonce,
    #[error("OIDC token is expired")]
    ExpiredIdToken,
    #[error("OIDC email is not verified")]
    EmailNotVerified,
    #[error("OIDC subject or email is empty")]
    InvalidIdentity,
    #[error("Gmail authorization did not grant all required scopes")]
    IncompleteGmailScopes,
    #[error("OAuth granted scope is not allowed")]
    InvalidScope,
    #[error("OIDC signature verification failed")]
    SignatureVerification,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OAuthFlowKind {
    Login,
    Gmail,
}

/// A verifier implemented by the Google adapter.
///
/// Implementations must validate the JWT signature, signing algorithm, key
/// issuer and token structure before returning claims.  This crate performs
/// only the semantic checks in [`validate_oidc_claims`].
pub trait OidcSignatureVerifier {
    fn verify_signature(&self, id_token: &str) -> Result<OidcClaims, SignatureVerificationError>;
}

#[derive(Debug, thiserror::Error, Clone, Eq, PartialEq)]
#[error("OIDC signature verification failed")]
pub struct SignatureVerificationError;

/// Claims returned only after a signature verifier has accepted an ID token.
/// The ID token itself is deliberately not retained here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OidcClaims {
    pub issuer: String,
    pub audience: Vec<String>,
    /// Authorized party. Required when `aud` contains multiple entries.
    pub azp: Option<String>,
    pub subject: String,
    pub email: String,
    pub email_verified: bool,
    /// Unix seconds, as supplied by the verified JWT `exp` claim.
    pub expires_at: i64,
    pub nonce: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ValidatedOidcIdentity {
    pub subject: String,
    pub email: String,
}

/// Verify the adapter boundary and then enforce the OIDC semantic contract.
pub fn verify_and_validate_oidc<V: OidcSignatureVerifier>(
    verifier: &V,
    id_token: &str,
    expected_nonce: &str,
    expected_audience: &str,
    now: DateTime<Utc>,
) -> Result<ValidatedOidcIdentity, OAuthError> {
    let claims = verifier
        .verify_signature(id_token)
        .map_err(|_| OAuthError::SignatureVerification)?;
    validate_oidc_claims(
        &claims,
        expected_nonce,
        expected_audience,
        GOOGLE_ISSUER,
        now,
    )
}

pub fn validate_oidc_claims(
    claims: &OidcClaims,
    expected_nonce: &str,
    expected_audience: &str,
    expected_issuer: &str,
    now: DateTime<Utc>,
) -> Result<ValidatedOidcIdentity, OAuthError> {
    if claims.issuer != expected_issuer {
        return Err(OAuthError::InvalidIssuer);
    }
    if !claims.audience.iter().any(|aud| aud == expected_audience)
        || (claims.audience.len() > 1 && claims.azp.as_deref() != Some(expected_audience))
        || (claims.audience.len() == 1
            && claims
                .azp
                .as_ref()
                .is_some_and(|azp| azp != expected_audience))
    {
        return Err(OAuthError::InvalidAudience);
    }
    if claims.expires_at <= now.timestamp() {
        return Err(OAuthError::ExpiredIdToken);
    }
    if !constant_time_equal(claims.nonce.as_bytes(), expected_nonce.as_bytes()) {
        return Err(OAuthError::InvalidOidcNonce);
    }
    if !claims.email_verified {
        return Err(OAuthError::EmailNotVerified);
    }
    if claims.subject.trim().is_empty() || claims.email.trim().is_empty() {
        return Err(OAuthError::InvalidIdentity);
    }
    Ok(ValidatedOidcIdentity {
        subject: claims.subject.clone(),
        email: claims.email.clone(),
    })
}

/// Database-facing transaction data.  `state_hash` and `nonce_hash` are
/// one-way digests. The verifier is serialized only as `[REDACTED]`.
/// This type intentionally does not implement `Deserialize`: a redacted
/// value must never be accepted as a real verifier. Use
/// [`OAuthTransaction::encrypted_pkce_verifier`] for persistence.
#[derive(Clone, Serialize)]
pub struct OAuthTransactionRecord {
    pub flow: OAuthFlowKind,
    pub state_hash: String,
    pub nonce_hash: String,
    #[serde(serialize_with = "serialize_redacted_secret")]
    pkce_verifier: SecretString,
    pub initiated_by: Option<String>,
    pub target_connection: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
}

impl fmt::Debug for OAuthTransactionRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthTransactionRecord")
            .field("flow", &self.flow)
            .field("state_hash", &self.state_hash)
            .field("nonce_hash", &self.nonce_hash)
            .field("pkce_verifier", &"[REDACTED]")
            .field("initiated_by", &self.initiated_by)
            .field("target_connection", &self.target_connection)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("consumed_at", &self.consumed_at)
            .finish()
    }
}

fn serialize_redacted_secret<S>(_: &SecretString, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str("[REDACTED]")
}

#[derive(Clone)]
pub struct OAuthTransaction {
    pub record: OAuthTransactionRecord,
    state: SecretString,
    nonce: SecretString,
}

impl fmt::Debug for OAuthTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthTransaction")
            .field("record", &self.record)
            .field("state", &"[REDACTED]")
            .field("nonce", &"[REDACTED]")
            .finish()
    }
}

impl OAuthTransaction {
    fn new(
        flow: OAuthFlowKind,
        initiated_by: Option<String>,
        target_connection: Option<String>,
        now: DateTime<Utc>,
        ttl: Duration,
    ) -> Self {
        let state = random_secret();
        let nonce = random_secret();
        let pkce_verifier = random_secret();
        Self {
            record: OAuthTransactionRecord {
                flow,
                state_hash: hash_token(state.expose_secret()),
                nonce_hash: hash_token(nonce.expose_secret()),
                pkce_verifier,
                initiated_by,
                target_connection,
                created_at: now,
                expires_at: now + ttl,
                consumed_at: None,
            },
            state,
            nonce,
        }
    }

    pub fn state_hash(&self) -> &str {
        &self.record.state_hash
    }
    pub fn nonce_hash(&self) -> &str {
        &self.record.nonce_hash
    }
    pub fn pkce_verifier(&self) -> &SecretString {
        &self.record.pkce_verifier
    }
    pub fn pkce_challenge(&self) -> String {
        pkce_challenge(self.record.pkce_verifier.expose_secret())
    }
    pub fn persistence(&self) -> OAuthTransactionRecord {
        self.record.clone()
    }
    /// Encrypt the short-lived verifier for persistence. The transaction ID
    /// is authenticated as associated data, preventing an envelope copied
    /// between OAuth transactions from being accepted.
    pub fn encrypted_pkce_verifier(
        &self,
        transaction_id: &str,
        keyring: &Keyring,
    ) -> Result<String, CryptoError> {
        if transaction_id.trim().is_empty() {
            return Err(CryptoError::InvalidEnvelope);
        }
        encrypt_token(
            self.record.pkce_verifier.expose_secret(),
            pkce_aad(transaction_id),
            keyring,
        )
    }
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now >= self.record.expires_at
    }
    pub fn is_consumed(&self) -> bool {
        self.record.consumed_at.is_some()
    }

    /// Validate the callback's state and ID-token nonce, then atomically mark
    /// this transaction consumed.  Neither secret is returned or persisted.
    pub fn consume_callback(
        &mut self,
        state: &str,
        nonce: &str,
        now: DateTime<Utc>,
    ) -> Result<CallbackContext, OAuthError> {
        if self.is_consumed() {
            return Err(OAuthError::AlreadyConsumed);
        }
        if self.is_expired(now) {
            return Err(OAuthError::Expired);
        }
        if !verify_token(state, &self.record.state_hash).unwrap_or(false) {
            return Err(OAuthError::StateMismatch);
        }
        if !verify_token(nonce, &self.record.nonce_hash).unwrap_or(false) {
            return Err(OAuthError::NonceMismatch);
        }
        self.record.consumed_at = Some(now);
        Ok(CallbackContext {
            flow: self.record.flow,
            initiated_by: self.record.initiated_by.clone(),
            target_connection: self.record.target_connection.clone(),
            pkce_verifier: self.record.pkce_verifier.clone(),
        })
    }

    /// Return the one-time exchange data after callback validation.  This is
    /// intentionally separate from the authorization code, which is supplied
    /// by the HTTP layer and never stored by this type.
    pub fn consume_code(
        &mut self,
        state: &str,
        nonce: &str,
        code: &str,
        now: DateTime<Utc>,
    ) -> Result<(String, CallbackContext), OAuthError> {
        if code.trim().is_empty() {
            return Err(OAuthError::EmptyAuthorizationCode);
        }
        Ok((code.to_owned(), self.consume_callback(state, nonce, now)?))
    }
}

#[derive(Clone)]
pub struct CallbackContext {
    pub flow: OAuthFlowKind,
    pub initiated_by: Option<String>,
    pub target_connection: Option<String>,
    pkce_verifier: SecretString,
}

impl CallbackContext {
    pub fn pkce_verifier(&self) -> &SecretString {
        &self.pkce_verifier
    }
}

impl fmt::Debug for CallbackContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CallbackContext")
            .field("flow", &self.flow)
            .field("initiated_by", &self.initiated_by)
            .field("target_connection", &self.target_connection)
            .field("pkce_verifier", &"[REDACTED]")
            .finish()
    }
}

impl Serialize for CallbackContext {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (
            &self.flow,
            &self.initiated_by,
            &self.target_connection,
            "[REDACTED]",
        )
            .serialize(serializer)
    }
}

#[derive(Clone)]
struct FlowCore {
    client_id: String,
    public_base_url: Url,
    transaction: OAuthTransaction,
    _kind: PhantomData<OAuthFlowKind>,
}

impl FlowCore {
    fn new(
        kind: OAuthFlowKind,
        public_base_url: &Url,
        client_id: impl Into<String>,
        initiated_by: Option<String>,
        target_connection: Option<String>,
        now: DateTime<Utc>,
        ttl: Duration,
    ) -> Result<Self, OAuthError> {
        validate_base_url(public_base_url)?;
        let client_id = client_id.into();
        if client_id.trim().is_empty() {
            return Err(OAuthError::EmptyClientId);
        }
        Ok(Self {
            client_id,
            public_base_url: public_base_url.clone(),
            transaction: OAuthTransaction::new(kind, initiated_by, target_connection, now, ttl),
            _kind: PhantomData,
        })
    }

    fn callback_url(&self) -> Url {
        let path = match self.transaction.record.flow {
            OAuthFlowKind::Login => LOGIN_CALLBACK_PATH,
            OAuthFlowKind::Gmail => GMAIL_CALLBACK_PATH,
        };
        let mut url = self.public_base_url.clone();
        url.set_path(path);
        url.set_query(None);
        url.set_fragment(None);
        url
    }

    fn authorize_url(&self) -> Url {
        let scopes = match self.transaction.record.flow {
            OAuthFlowKind::Login => LOGIN_SCOPES.as_slice(),
            OAuthFlowKind::Gmail => GMAIL_SCOPES.as_slice(),
        };
        let mut url = Url::parse(GOOGLE_AUTHORIZE_ENDPOINT).expect("constant Google URL");
        {
            let mut query = url.query_pairs_mut();
            query
                .append_pair("client_id", &self.client_id)
                .append_pair("redirect_uri", self.callback_url().as_str())
                .append_pair("response_type", "code")
                .append_pair("scope", &scopes.join(" "))
                .append_pair("state", self.state())
                .append_pair("nonce", self.nonce())
                .append_pair("code_challenge", &self.transaction.pkce_challenge())
                .append_pair("code_challenge_method", "S256");
            if self.transaction.record.flow == OAuthFlowKind::Gmail {
                query
                    .append_pair("access_type", "offline")
                    .append_pair("prompt", "consent");
            } else {
                query.append_pair("prompt", "select_account");
            }
        }
        url
    }

    fn state(&self) -> &str {
        self.transaction.state.expose_secret()
    }
    fn nonce(&self) -> &str {
        self.transaction.nonce.expose_secret()
    }
}

/// Login flow: only `openid email profile`; never use its result as a Gmail
/// credential.
#[derive(Clone)]
pub struct LoginFlow {
    core: FlowCore,
}

impl LoginFlow {
    pub fn new(
        public_base_url: &Url,
        client_id: impl Into<String>,
        now: DateTime<Utc>,
    ) -> Result<Self, OAuthError> {
        Self::with_ttl(public_base_url, client_id, now, DEFAULT_TRANSACTION_TTL)
    }
    pub fn with_ttl(
        public_base_url: &Url,
        client_id: impl Into<String>,
        now: DateTime<Utc>,
        ttl: Duration,
    ) -> Result<Self, OAuthError> {
        Ok(Self {
            core: FlowCore::new(
                OAuthFlowKind::Login,
                public_base_url,
                client_id,
                None,
                None,
                now,
                ttl,
            )?,
        })
    }
    pub fn authorize_url(&self) -> Url {
        self.core.authorize_url()
    }
    pub fn callback_url(&self) -> Url {
        self.core.callback_url()
    }
    pub fn transaction(&self) -> &OAuthTransaction {
        &self.core.transaction
    }
    pub fn transaction_mut(&mut self) -> &mut OAuthTransaction {
        &mut self.core.transaction
    }
    pub fn state(&self) -> &str {
        self.core.state()
    }
    pub fn nonce(&self) -> &str {
        self.core.nonce()
    }
}

/// Gmail flow: requests the exact Gmail read/compose scope set and offline
/// access.  Context fields bind the callback to the initiating user/connection.
#[derive(Clone)]
pub struct GmailFlow {
    core: FlowCore,
}

impl GmailFlow {
    pub fn new(
        public_base_url: &Url,
        client_id: impl Into<String>,
        now: DateTime<Utc>,
    ) -> Result<Self, OAuthError> {
        Self::with_context(
            public_base_url,
            client_id,
            None,
            None,
            now,
            DEFAULT_TRANSACTION_TTL,
        )
    }
    pub fn with_context(
        public_base_url: &Url,
        client_id: impl Into<String>,
        initiated_by: Option<String>,
        target_connection: Option<String>,
        now: DateTime<Utc>,
        ttl: Duration,
    ) -> Result<Self, OAuthError> {
        Ok(Self {
            core: FlowCore::new(
                OAuthFlowKind::Gmail,
                public_base_url,
                client_id,
                initiated_by,
                target_connection,
                now,
                ttl,
            )?,
        })
    }
    pub fn authorize_url(&self) -> Url {
        self.core.authorize_url()
    }
    pub fn callback_url(&self) -> Url {
        self.core.callback_url()
    }
    pub fn transaction(&self) -> &OAuthTransaction {
        &self.core.transaction
    }
    pub fn transaction_mut(&mut self) -> &mut OAuthTransaction {
        &mut self.core.transaction
    }
    pub fn state(&self) -> &str {
        self.core.state()
    }
    pub fn nonce(&self) -> &str {
        self.core.nonce()
    }
}

fn validate_base_url(url: &Url) -> Result<(), OAuthError> {
    if url.host_str().is_none()
        || !matches!(url.scheme(), "http" | "https")
        || url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(OAuthError::InvalidBaseUrl);
    }
    Ok(())
}

fn random_secret() -> SecretString {
    SecretString::from(URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()))
}

pub fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    left.ct_eq(right).into()
}

fn pkce_aad(transaction_id: &str) -> String {
    format!("agentmail:oauth-pkce:transaction:{transaction_id}")
}

/// Decrypt a verifier persisted by [`OAuthTransaction::encrypted_pkce_verifier`].
pub fn decrypt_pkce_verifier(
    envelope: &str,
    transaction_id: &str,
    keyring: &Keyring,
) -> Result<SecretString, CryptoError> {
    if transaction_id.trim().is_empty() {
        return Err(CryptoError::InvalidEnvelope);
    }
    let bytes = decrypt_token(envelope, pkce_aad(transaction_id), keyring)?;
    let value = String::from_utf8(bytes).map_err(|_| CryptoError::InvalidEnvelope)?;
    if value.is_empty() {
        return Err(CryptoError::InvalidEnvelope);
    }
    Ok(SecretString::from(value))
}

/// Return the canonical, deduplicated granted scope set when both Gmail
/// scopes are present.  Google may report the short aliases in test doubles;
/// they are normalized to the canonical URLs before persistence.
pub fn validate_granted_gmail_scopes<I, S>(scopes: I) -> Result<Vec<String>, OAuthError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut normalized = Vec::new();
    for scope in scopes {
        let scope = scope.as_ref();
        let canonical = match scope {
            "gmail.readonly" => GMAIL_READONLY_SCOPE,
            "gmail.compose" => GMAIL_COMPOSE_SCOPE,
            "openid" | "email" | "profile" | GMAIL_READONLY_SCOPE | GMAIL_COMPOSE_SCOPE => scope,
            _ => return Err(OAuthError::InvalidScope),
        };
        if !normalized.iter().any(|existing| existing == canonical) {
            normalized.push(canonical.to_owned());
        }
    }
    if !normalized.iter().any(|scope| scope == GMAIL_READONLY_SCOPE)
        || !normalized.iter().any(|scope| scope == GMAIL_COMPOSE_SCOPE)
    {
        return Err(OAuthError::IncompleteGmailScopes);
    }
    Ok(normalized)
}

pub fn has_complete_gmail_scopes<I, S>(scopes: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    validate_granted_gmail_scopes(scopes).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, HashMap};

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    }
    fn base() -> Url {
        Url::parse("https://agentmail.example/root").unwrap()
    }

    #[test]
    fn flows_have_distinct_callbacks_and_gmail_offline_scopes() {
        let login = LoginFlow::new(&base(), "login-client", now()).unwrap();
        let gmail = GmailFlow::new(&base(), "gmail-client", now()).unwrap();
        assert_eq!(login.callback_url().path(), LOGIN_CALLBACK_PATH);
        assert_eq!(gmail.callback_url().path(), GMAIL_CALLBACK_PATH);
        let query: HashMap<_, _> = gmail.authorize_url().query_pairs().into_owned().collect();
        assert_eq!(query["access_type"], "offline");
        assert_eq!(query["code_challenge_method"], "S256");
        assert!(query["scope"].contains(GMAIL_READONLY_SCOPE));
        assert!(query["scope"].contains(GMAIL_COMPOSE_SCOPE));
        assert!(!login.authorize_url().query().unwrap().contains("gmail."));
    }

    #[test]
    fn pkce_challenge_is_s256() {
        assert_eq!(
            pkce_challenge("abc"),
            "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"
        );
    }

    #[test]
    fn callback_rejects_mismatch_and_replay() {
        let mut flow = GmailFlow::new(&base(), "client", now()).unwrap();
        let nonce = flow.nonce().to_owned();
        assert!(matches!(
            flow.transaction_mut()
                .consume_callback("wrong", &nonce, now()),
            Err(OAuthError::StateMismatch)
        ));
        let state = flow.state().to_owned();
        flow.transaction_mut()
            .consume_callback(&state, &nonce, now())
            .unwrap();
        assert!(matches!(
            flow.transaction_mut()
                .consume_callback(&state, &nonce, now()),
            Err(OAuthError::AlreadyConsumed)
        ));
    }

    #[test]
    fn callback_rejects_nonce_mismatch_and_expiry() {
        let mut flow = LoginFlow::with_ttl(&base(), "client", now(), Duration::seconds(1)).unwrap();
        let state = flow.state().to_owned();
        assert!(matches!(
            flow.transaction_mut()
                .consume_callback(&state, "wrong", now()),
            Err(OAuthError::NonceMismatch)
        ));
        let later = now() + Duration::seconds(1);
        let nonce = flow.nonce().to_owned();
        assert!(matches!(
            flow.transaction_mut()
                .consume_callback(&state, &nonce, later),
            Err(OAuthError::Expired)
        ));
    }

    #[test]
    fn partial_granted_scopes_are_rejected() {
        assert!(!has_complete_gmail_scopes([GMAIL_READONLY_SCOPE]));
        assert!(has_complete_gmail_scopes([
            "gmail.readonly",
            "gmail.compose"
        ]));
        let scopes = validate_granted_gmail_scopes([
            GMAIL_READONLY_SCOPE,
            GMAIL_COMPOSE_SCOPE,
            GMAIL_COMPOSE_SCOPE,
        ])
        .unwrap();
        assert_eq!(scopes.len(), 2);
        assert!(matches!(
            validate_granted_gmail_scopes([GMAIL_READONLY_SCOPE, "https://evil.example/scope"]),
            Err(OAuthError::InvalidScope)
        ));
    }

    #[test]
    fn debug_and_serialize_do_not_expose_raw_secrets() {
        let flow = LoginFlow::new(&base(), "client", now()).unwrap();
        let state = flow.state().to_owned();
        let nonce = flow.nonce().to_owned();
        let verifier = flow
            .transaction()
            .pkce_verifier()
            .expose_secret()
            .to_owned();
        let debug = format!("{:?}", flow.transaction());
        let json = serde_json::to_string(&flow.transaction().persistence()).unwrap();
        assert!(!debug.contains(&state) && !debug.contains(&nonce) && !debug.contains(&verifier));
        assert!(!json.contains(&state) && !json.contains(&nonce) && !json.contains(&verifier));
        assert!(json.contains("[REDACTED]"));
    }

    #[test]
    fn pkce_persistence_is_encrypted_and_transaction_bound() {
        let flow = LoginFlow::new(&base(), "client", now()).unwrap();
        let ring = Keyring::new(1, BTreeMap::from([(1, [7; 32])])).unwrap();
        let envelope = flow
            .transaction()
            .encrypted_pkce_verifier("tx-1", &ring)
            .unwrap();
        let verifier = decrypt_pkce_verifier(&envelope, "tx-1", &ring).unwrap();
        assert_eq!(
            verifier.expose_secret(),
            flow.transaction().pkce_verifier().expose_secret()
        );
        assert!(decrypt_pkce_verifier(&envelope, "tx-2", &ring).is_err());
        assert!(
            flow.transaction()
                .encrypted_pkce_verifier(" ", &ring)
                .is_err()
        );
    }

    struct FakeVerifier(OidcClaims);
    impl OidcSignatureVerifier for FakeVerifier {
        fn verify_signature(&self, _: &str) -> Result<OidcClaims, SignatureVerificationError> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn oidc_requires_semantics_after_signature_boundary() {
        let verifier = FakeVerifier(OidcClaims {
            issuer: GOOGLE_ISSUER.to_owned(),
            audience: vec!["client".to_owned()],
            azp: None,
            subject: "sub".to_owned(),
            email: "user@example.com".to_owned(),
            email_verified: true,
            expires_at: now().timestamp() + 60,
            nonce: "nonce".to_owned(),
        });
        assert!(verify_and_validate_oidc(&verifier, "jwt", "nonce", "client", now()).is_ok());
        let bad = FakeVerifier(OidcClaims {
            email_verified: false,
            ..verifier.0
        });
        assert_eq!(
            verify_and_validate_oidc(&bad, "jwt", "nonce", "client", now()),
            Err(OAuthError::EmailNotVerified)
        );
    }

    #[test]
    fn oidc_requires_azp_for_multiple_audiences() {
        let claims = OidcClaims {
            issuer: GOOGLE_ISSUER.to_owned(),
            audience: vec!["client".to_owned(), "other".to_owned()],
            azp: None,
            subject: "sub".to_owned(),
            email: "user@example.com".to_owned(),
            email_verified: true,
            expires_at: now().timestamp() + 60,
            nonce: "nonce".to_owned(),
        };
        assert_eq!(
            validate_oidc_claims(&claims, "nonce", "client", GOOGLE_ISSUER, now()),
            Err(OAuthError::InvalidAudience)
        );
        let claims = OidcClaims {
            azp: Some("client".to_owned()),
            ..claims
        };
        assert!(validate_oidc_claims(&claims, "nonce", "client", GOOGLE_ISSUER, now()).is_ok());
    }
}

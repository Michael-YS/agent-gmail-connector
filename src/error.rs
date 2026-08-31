use axum::{
    Json,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use std::borrow::Cow;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("authentication required")]
    Unauthorized,
    #[error("access to this connection is forbidden")]
    Forbidden,
    #[error("resource not found")]
    NotFound,
    #[error("request conflict: {0}")]
    Conflict(&'static str),
    #[error("invalid request: {0}")]
    Invalid(Cow<'static, str>),
    #[error("rate limit exceeded")]
    RateLimited { retry_after_seconds: u64 },
    #[error("upstream service unavailable")]
    UpstreamUnavailable,
    #[error("database failure")]
    Database(#[from] sqlx::Error),
    #[error("internal error")]
    Internal(#[from] anyhow::Error),
}

#[derive(Debug, Serialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    code: &'static str,
    message: Cow<'static, str>,
    request_id: String,
    retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after_seconds: Option<u64>,
}

impl AppError {
    fn response_parts(
        &self,
    ) -> (
        StatusCode,
        &'static str,
        Cow<'static, str>,
        bool,
        Option<u64>,
    ) {
        match self {
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "authentication required".into(),
                false,
                None,
            ),
            Self::Forbidden => (
                StatusCode::FORBIDDEN,
                "forbidden",
                "access denied".into(),
                false,
                None,
            ),
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                "not_found",
                "resource not found".into(),
                false,
                None,
            ),
            Self::Conflict(code) => (
                StatusCode::CONFLICT,
                code,
                "request conflicts with current state".into(),
                false,
                None,
            ),
            Self::Invalid(message) => (
                StatusCode::BAD_REQUEST,
                "invalid_request",
                message.clone(),
                false,
                None,
            ),
            Self::RateLimited {
                retry_after_seconds,
            } => (
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "rate limit exceeded".into(),
                true,
                Some(*retry_after_seconds),
            ),
            Self::UpstreamUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "upstream_unavailable",
                "upstream service is temporarily unavailable".into(),
                true,
                None,
            ),
            Self::Database(_) | Self::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "internal error".into(),
                false,
                None,
            ),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, message, retryable, retry_after_seconds) = self.response_parts();
        let request_id = tracing::Span::current().id().map_or_else(
            || "unavailable".to_owned(),
            |id| format!("span-{}", id.into_u64()),
        );
        let mut headers = HeaderMap::new();
        if let Some(seconds) = retry_after_seconds
            && let Ok(value) = seconds.to_string().parse()
        {
            headers.insert(http::header::RETRY_AFTER, value);
        }
        let body = Json(ErrorEnvelope {
            error: ErrorBody {
                code,
                message,
                request_id,
                retryable,
                retry_after_seconds,
            },
        });
        (status, headers, body).into_response()
    }
}

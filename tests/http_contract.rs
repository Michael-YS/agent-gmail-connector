use agentmail::http::{AppState, build_router};
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use serde_json::Value;
use tower::ServiceExt;
use uuid::Uuid;

async fn response_json(response: axum::response::Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap()).unwrap()
}

#[tokio::test]
async fn health_and_public_contract_are_available_without_machine_credentials() {
    let app = build_router(AppState::empty());
    for path in [
        "/",
        "/privacy",
        "/terms",
        "/data-deletion",
        "/api",
        "/health/live",
    ] {
        let response = app
            .clone()
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert!(response.headers().contains_key("x-request-id"));
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        assert!(response.headers().contains_key("content-security-policy"));
        assert_eq!(response.headers()["cache-control"], "no-store");
    }
    let ready = app
        .oneshot(Request::get("/health/ready").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn machine_api_rejects_missing_and_query_string_credentials() {
    let app = build_router(AppState::empty());
    for path in [
        "/api/v1/connections",
        "/api/v1/connections?access_token=amk_bad.bad",
    ] {
        let response = app
            .clone()
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = response_json(response).await;
        assert_eq!(body["error"]["code"], "unauthorized");
        assert!(body["error"]["request_id"].as_str().is_some());
    }
}

#[tokio::test]
async fn key_grant_cannot_be_bypassed_by_changing_connection_id() {
    let (state, credential, granted_connection) = AppState::test_fixture();
    let app = build_router(state);
    let granted = app
        .clone()
        .oneshot(
            Request::get(format!("/api/v1/connections/{granted_connection}/messages"))
                .header("authorization", format!("Bearer {credential}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(granted.status(), StatusCode::OK);

    let denied = app
        .oneshot(
            Request::get(format!("/api/v1/connections/{}/messages", Uuid::new_v4()))
                .header("authorization", format!("Bearer {credential}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
}

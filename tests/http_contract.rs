use agentmail::http::{AppState, build_router};
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use serde_json::{Value, json};
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
        assert_eq!(
            response.headers()["content-security-policy"],
            "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        );
        assert_eq!(response.headers()["cache-control"], "no-store");
    }
    let ready = app
        .oneshot(Request::get("/health/ready").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn landing_exposes_google_login_and_legal_links() {
    let response = build_router(AppState::empty())
        .oneshot(Request::get("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["content-type"],
        "text/html; charset=utf-8"
    );
    let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    let body = std::str::from_utf8(&body).unwrap();
    assert!(body.contains("href=\"/auth/google/login\""));
    assert!(body.contains("href=\"/privacy\""));
    assert!(body.contains("href=\"/terms\""));
    assert!(body.contains("href=\"/data-deletion\""));
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

#[tokio::test]
async fn managed_draft_lifecycle_requires_versions_and_replays_sent_outcome() {
    let (state, credential, connection) = AppState::test_fixture();
    let app = build_router(state);
    let authorization = format!("Bearer {credential}");
    let draft = json!({
        "subject": "Initial subject",
        "body": "Initial body",
        "to": ["recipient@example.com"]
    });

    let created = app
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/connections/{connection}/drafts"))
                .header("authorization", &authorization)
                .header("content-type", "application/json")
                .body(Body::from(draft.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::OK);
    let created = response_json(created).await;
    let draft_id = created["managed_draft"]["id"].as_str().unwrap();
    let initial_version = created["managed_draft"]["version"].as_str().unwrap();
    assert_eq!(created["managed_draft"]["state"], "active");

    let updated_request = json!({
        "subject": "Updated subject",
        "body": "Updated body",
        "to": ["recipient@example.com"],
        "expected_version": initial_version,
    });
    let updated = app
        .clone()
        .oneshot(
            Request::patch(format!(
                "/api/v1/connections/{connection}/drafts/{draft_id}"
            ))
            .header("authorization", &authorization)
            .header("content-type", "application/json")
            .body(Body::from(updated_request.to_string()))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(updated.status(), StatusCode::OK);
    let updated = response_json(updated).await;
    let current_version = updated["managed_draft"]["version"].as_str().unwrap();
    assert_ne!(current_version, initial_version);

    let stale_update = app
        .clone()
        .oneshot(
            Request::patch(format!(
                "/api/v1/connections/{connection}/drafts/{draft_id}"
            ))
            .header("authorization", &authorization)
            .header("content-type", "application/json")
            .body(Body::from(updated_request.to_string()))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(stale_update.status(), StatusCode::CONFLICT);
    assert_eq!(
        response_json(stale_update).await["error"]["code"],
        "draft_changed"
    );

    let prepared = app
        .clone()
        .oneshot(
            Request::post(format!(
                "/api/v1/connections/{connection}/drafts/{draft_id}/prepare-send"
            ))
            .header("authorization", &authorization)
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(prepared.status(), StatusCode::OK);
    let prepared = response_json(prepared).await;
    let token = prepared["confirmation_token"].as_str().unwrap();

    let send_body = json!({"confirmation_token": token}).to_string();
    let sent = app
        .clone()
        .oneshot(
            Request::post(format!(
                "/api/v1/connections/{connection}/drafts/{draft_id}/send"
            ))
            .header("authorization", &authorization)
            .header("content-type", "application/json")
            .body(Body::from(send_body.clone()))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(sent.status(), StatusCode::OK);
    let sent = response_json(sent).await;
    assert_eq!(sent["replayed"], false);
    assert!(sent["outcome"].get("Sent").is_some());

    let replay = app
        .clone()
        .oneshot(
            Request::post(format!(
                "/api/v1/connections/{connection}/drafts/{draft_id}/send"
            ))
            .header("authorization", &authorization)
            .header("content-type", "application/json")
            .body(Body::from(send_body))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::OK);
    let replay = response_json(replay).await;
    assert_eq!(replay["replayed"], true);
    assert_eq!(replay["outcome"], sent["outcome"]);

    let delete = app
        .oneshot(
            Request::delete(format!(
                "/api/v1/connections/{connection}/drafts/{draft_id}?expected_version={current_version}"
            ))
            .header("authorization", &authorization)
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(delete.status(), StatusCode::CONFLICT);
    assert_eq!(
        response_json(delete).await["error"]["code"],
        "draft_changed"
    );
}

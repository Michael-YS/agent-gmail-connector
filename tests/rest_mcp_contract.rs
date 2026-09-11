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

fn mcp_request(method: &str, id: u64, params: Value) -> Body {
    Body::from(
        serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params
        }))
        .unwrap(),
    )
}

#[tokio::test]
async fn rest_and_mcp_search_use_the_same_fixture_and_service() {
    let (state, credential, connection) = AppState::test_fixture();
    let rest = build_router(state.clone())
        .oneshot(
            Request::get(format!(
                "/api/v1/connections/{connection}/messages?page_size=20"
            ))
            .header("authorization", format!("Bearer {credential}"))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rest.status(), StatusCode::OK);
    let rest_json = response_json(rest).await;

    let mcp = build_router(state)
        .oneshot(
            Request::post("/mcp")
                .header("authorization", format!("Bearer {credential}"))
                .header("content-type", "application/json")
                .body(mcp_request(
                    "tools/call",
                    1,
                    json!({
                        "name": "messages.search",
                        "arguments": {"connection_id": connection}
                    }),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(mcp.status(), StatusCode::OK);
    let mcp_json = response_json(mcp).await;
    assert_eq!(
        rest_json["messages"],
        mcp_json["result"]["structuredContent"]["messages"]
    );
    assert_eq!(rest_json["connection_id"], json!(connection));
    assert_eq!(
        mcp_json["result"]["structuredContent"]["connection_id"],
        json!(connection)
    );
}

#[tokio::test]
async fn rest_and_mcp_draft_reads_share_auth_and_adapter() {
    let (state, credential, connection) = AppState::test_fixture();
    let created = build_router(state.clone())
        .oneshot(
            Request::post(format!("/api/v1/connections/{connection}/drafts"))
                .header("authorization", format!("Bearer {credential}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"subject":"test draft","body":"untrusted body","to":["to@example.com"]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::OK);
    let created = response_json(created).await;
    let draft_id = created["draft"]["id"].as_str().unwrap();

    let rest_list = build_router(state.clone())
        .oneshot(
            Request::get(format!("/api/v1/connections/{connection}/drafts"))
                .header("authorization", format!("Bearer {credential}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rest_list.status(), StatusCode::OK);
    let rest_list = response_json(rest_list).await;

    let mcp_list = build_router(state.clone())
        .oneshot(
            Request::post("/mcp")
                .header("authorization", format!("Bearer {credential}"))
                .header("content-type", "application/json")
                .body(mcp_request(
                    "tools/call",
                    5,
                    json!({"name":"drafts.list","arguments":{"connection_id":connection}}),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(mcp_list.status(), StatusCode::OK);
    let mcp_list = response_json(mcp_list).await;
    assert_eq!(
        rest_list["drafts"],
        mcp_list["result"]["structuredContent"]["drafts"]
    );

    let rest_get = build_router(state.clone())
        .oneshot(
            Request::get(format!(
                "/api/v1/connections/{connection}/drafts/{draft_id}"
            ))
            .header("authorization", format!("Bearer {credential}"))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rest_get.status(), StatusCode::OK);
    let rest_get = response_json(rest_get).await;

    let mcp_get = build_router(state)
        .oneshot(
            Request::post("/mcp")
                .header("authorization", format!("Bearer {credential}"))
                .header("content-type", "application/json")
                .body(mcp_request(
                    "tools/call",
                    6,
                    json!({"name":"drafts.get","arguments":{"connection_id":connection,"draft_id":draft_id}}),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(mcp_get.status(), StatusCode::OK);
    let mcp_get = response_json(mcp_get).await;
    assert_eq!(rest_get, mcp_get["result"]["structuredContent"]);
    assert_eq!(
        mcp_get["result"]["structuredContent"]["managed_by_agentmail"],
        true
    );
    assert!(mcp_get["result"]["structuredContent"]["version"].is_string());
}

#[tokio::test]
async fn openapi_describes_search_security_and_safe_contract() {
    let response = build_router(AppState::empty())
        .oneshot(
            Request::get("/api/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let document = response_json(response).await;
    let operation = &document["paths"]["/api/v1/connections/{connection_id}/messages"]["get"];
    assert!(operation.is_object());
    assert_eq!(operation["security"][0]["bearerAuth"], json!([]));
    for name in ["connection_id", "q", "page_size", "cursor"] {
        assert!(
            operation["parameters"]
                .as_array()
                .unwrap()
                .iter()
                .any(|parameter| parameter["name"] == name)
        );
    }
    assert!(document["components"]["securitySchemes"]["bearerAuth"].is_object());
    assert!(document["components"]["schemas"]["MessageSearchResult"].is_object());
    assert!(document["components"]["schemas"]["ErrorResponse"].is_object());
}

#[tokio::test]
async fn mcp_tools_list_exposes_search_schema_and_compatibility_note() {
    let (state, credential, _connection) = AppState::test_fixture();
    let response = build_router(state)
        .oneshot(
            Request::post("/mcp")
                .header("authorization", format!("Bearer {credential}"))
                .header("content-type", "application/json")
                .body(mcp_request("tools/list", 2, json!({})))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let value = response_json(response).await;
    assert_eq!(value["result"]["tools"][0]["name"], "messages.search");
    assert_eq!(
        value["result"]["tools"][0]["inputSchema"]["required"],
        json!(["connection_id"])
    );
    let tools = value["result"]["tools"].as_array().unwrap();
    let drafts_list = tools
        .iter()
        .find(|tool| tool["name"] == "drafts.list")
        .unwrap();
    assert_eq!(
        drafts_list["inputSchema"]["required"],
        json!(["connection_id"])
    );
    let drafts_get = tools
        .iter()
        .find(|tool| tool["name"] == "drafts.get")
        .unwrap();
    assert_eq!(
        drafts_get["inputSchema"]["required"],
        json!(["connection_id", "draft_id"])
    );
    assert_eq!(
        value["result"]["compatibility"],
        "minimal_json_rpc_not_full_streamable_http"
    );
}

#[tokio::test]
async fn mcp_returns_jsonrpc_parse_and_invalid_request_errors() {
    let (state, credential, _connection) = AppState::test_fixture();
    let parse_error = build_router(state.clone())
        .oneshot(
            Request::post("/mcp")
                .header("authorization", format!("Bearer {credential}"))
                .header("content-type", "application/json")
                .body(Body::from("{"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(parse_error.status(), StatusCode::OK);
    let parse_json = response_json(parse_error).await;
    assert_eq!(parse_json["error"]["code"], -32700);
    assert_eq!(parse_json["id"], Value::Null);

    let invalid_request = build_router(state)
        .oneshot(
            Request::post("/mcp")
                .header("authorization", format!("Bearer {credential}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"jsonrpc":"2.0","id":5}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid_request.status(), StatusCode::OK);
    let invalid_json = response_json(invalid_request).await;
    assert_eq!(invalid_json["error"]["code"], -32600);
    assert_eq!(invalid_json["id"], 5);
}

#[tokio::test]
async fn rest_and_mcp_reject_query_tokens_and_cross_connection_ids() {
    let (state, credential, _connection) = AppState::test_fixture();
    let rest_query_token = build_router(state.clone())
        .oneshot(
            Request::get(format!(
                "/api/v1/connections/{}/messages?access_token=bad",
                Uuid::new_v4()
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rest_query_token.status(), StatusCode::UNAUTHORIZED);

    let mcp_query_token = build_router(state.clone())
        .oneshot(
            Request::post("/mcp?access_token=bad")
                .header("authorization", format!("Bearer {credential}"))
                .header("content-type", "application/json")
                .body(mcp_request("tools/call", 3, json!({})))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(mcp_query_token.status(), StatusCode::UNAUTHORIZED);

    let denied_connection = Uuid::new_v4();
    let rest_idor = build_router(state.clone())
        .oneshot(
            Request::get(format!("/api/v1/connections/{denied_connection}/messages"))
                .header("authorization", format!("Bearer {credential}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rest_idor.status(), StatusCode::FORBIDDEN);

    let mcp_idor = build_router(state)
        .oneshot(
            Request::post("/mcp")
                .header("authorization", format!("Bearer {credential}"))
                .header("content-type", "application/json")
                .body(mcp_request(
                    "tools/call",
                    4,
                    json!({
                        "name": "messages.search",
                        "arguments": {"connection_id": denied_connection}
                    }),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(mcp_idor.status(), StatusCode::FORBIDDEN);
}

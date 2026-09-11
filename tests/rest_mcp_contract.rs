use agentmail::http::{AppState, build_router};
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
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
async fn mcp_drafts_create_accepts_bounded_base64_attachment() {
    let (state, credential, connection) = AppState::test_fixture();
    let response = build_router(state)
        .oneshot(
            Request::post("/mcp")
                .header("authorization", format!("Bearer {credential}"))
                .header("content-type", "application/json")
                .body(mcp_request(
                    "tools/call",
                    9,
                    json!({
                        "name": "drafts.create",
                        "arguments": {
                            "connection_id": connection,
                            "subject": "mcp draft",
                            "body": "untrusted body",
                            "to": ["to@example.com"],
                            "attachments": [{
                                "filename": "hello.txt",
                                "content_type": "text/plain",
                                "data_base64": "aGVsbG8="
                            }]
                        }
                    }),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let value = response_json(response).await;
    let draft = &value["result"]["structuredContent"]["draft"];
    assert_eq!(draft["subject"], "mcp draft");
    assert_eq!(draft["attachments"][0]["filename"], "hello.txt");
    assert_eq!(draft["attachments"][0]["size_bytes"], 5);
}

#[tokio::test]
async fn mcp_drafts_create_rejects_invalid_base64_attachment() {
    let (state, credential, connection) = AppState::test_fixture();
    let response = build_router(state)
        .oneshot(
            Request::post("/mcp")
                .header("authorization", format!("Bearer {credential}"))
                .header("content-type", "application/json")
                .body(mcp_request(
                    "tools/call",
                    10,
                    json!({
                        "name": "drafts.create",
                        "arguments": {
                            "connection_id": connection,
                            "to": ["to@example.com"],
                            "attachments": [{
                                "filename": "bad.bin",
                                "data_base64": "not base64"
                            }]
                        }
                    }),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let value = response_json(response).await;
    assert_eq!(value["error"]["code"], -32602);
    assert_eq!(value["error"]["message"], "invalid attachment base64");
}

#[tokio::test]
async fn mcp_draft_writes_validate_arguments_and_charge_per_request() {
    let (state, credential, connection) = AppState::test_fixture();
    let created = build_router(state.clone())
        .oneshot(
            Request::post(format!("/api/v1/connections/{connection}/drafts"))
                .header("authorization", format!("Bearer {credential}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"subject":"original","body":"body","to":["to@example.com"]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::OK);
    let created = response_json(created).await;
    let draft_id = created["managed_draft"]["id"].as_str().unwrap().to_owned();
    let version = created["managed_draft"]["version"]
        .as_str()
        .unwrap()
        .to_owned();

    let updated = build_router(state.clone())
        .oneshot(
            Request::post("/mcp")
                .header("authorization", format!("Bearer {credential}"))
                .header("content-type", "application/json")
                .body(mcp_request(
                    "tools/call",
                    11,
                    json!({
                        "name": "drafts.update",
                        "arguments": {
                            "connection_id": connection,
                            "draft_id": draft_id,
                            "expected_version": version,
                            "subject": "updated",
                            "body": "new body",
                            "to": ["to@example.com"]
                        }
                    }),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(updated.status(), StatusCode::OK);
    let updated = response_json(updated).await;
    assert_eq!(
        updated["result"]["structuredContent"]["draft"]["subject"],
        "updated"
    );
    let key = state.keys.read().await.values().next().unwrap().id;
    assert_eq!(
        state.rate_buckets.lock().await[&format!("api_per_minute:{key}")].request_count,
        2
    );

    let invalid = build_router(state.clone())
        .oneshot(
            Request::post("/mcp")
                .header("authorization", format!("Bearer {credential}"))
                .header("content-type", "application/json")
                .body(mcp_request(
                    "tools/call",
                    12,
                    json!({
                        "name": "drafts.delete",
                        "arguments": {"connection_id": connection, "draft_id": draft_id}
                    }),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let invalid = response_json(invalid).await;
    assert_eq!(invalid["error"]["code"], -32602);
}

#[tokio::test]
async fn mcp_prepare_and_send_use_one_time_confirmation_token() {
    let (state, credential, connection, _adapter) = AppState::test_fixture_with_adapter();
    let created = build_router(state.clone())
        .oneshot(
            Request::post(format!("/api/v1/connections/{connection}/drafts"))
                .header("authorization", format!("Bearer {credential}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"subject":"send me","body":"body","to":["to@example.com"]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let created = response_json(created).await;
    let draft_id = created["managed_draft"]["id"].as_str().unwrap().to_owned();

    let prepared = build_router(state.clone())
        .oneshot(
            Request::post("/mcp")
                .header("authorization", format!("Bearer {credential}"))
                .header("content-type", "application/json")
                .body(mcp_request(
                    "tools/call",
                    13,
                    json!({"name":"drafts.prepare_send","arguments":{"connection_id":connection,"draft_id":draft_id}}),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let prepared = response_json(prepared).await;
    let token = prepared["result"]["structuredContent"]["confirmation_token"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(prepared["result"]["structuredContent"]["preview"].is_object());

    let send = |id| {
        let state = state.clone();
        let credential = credential.clone();
        let token = token.clone();
        let draft_id = draft_id.clone();
        async move {
            response_json(
                build_router(state)
                .oneshot(
                    Request::post("/mcp")
                        .header("authorization", format!("Bearer {credential}"))
                        .header("content-type", "application/json")
                        .body(mcp_request(
                            "tools/call",
                            id,
                            json!({"name":"drafts.send","arguments":{"connection_id":connection,"draft_id":draft_id,"confirmation_token":token}}),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap(),
            )
            .await
        }
    };
    let first = send(14).await;
    assert!(first["result"]["structuredContent"].is_object());
    let replay = send(15).await;
    assert_eq!(replay["result"]["structuredContent"]["replayed"], true);
}

#[tokio::test]
async fn rmcp_streamable_http_negotiates_and_lists_tools() {
    let (state, credential, connection) = AppState::test_fixture();
    let initialize = build_router(state.clone())
        .oneshot(
            Request::post("/mcp-streamable")
                .header("authorization", format!("Bearer {credential}"))
                .header("host", "localhost")
                .header("accept", "application/json, text/event-stream")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"contract-test","version":"1"}}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    if initialize.status() != StatusCode::OK {
        let status = initialize.status();
        let body = to_bytes(initialize.into_body(), 1024 * 1024).await.unwrap();
        panic!(
            "rmcp initialize failed: {status} {}",
            String::from_utf8_lossy(&body)
        );
    }
    assert_eq!(
        initialize.headers().get("content-type").unwrap(),
        "application/json"
    );
    let initialized = response_json(initialize).await;
    assert_eq!(initialized["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(initialized["result"]["capabilities"]["tools"], json!({}));

    let tools = build_router(state.clone())
        .oneshot(
            Request::post("/mcp-streamable")
                .header("authorization", format!("Bearer {credential}"))
                .header("host", "localhost")
                .header("accept", "application/json, text/event-stream")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(tools.status(), StatusCode::OK);
    let tools = response_json(tools).await;
    let names: Vec<&str> = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        vec![
            "messages.search",
            "messages.get",
            "threads.get",
            "messages.get_attachment",
            "drafts.create",
            "drafts.list",
            "drafts.get",
            "drafts.update",
            "drafts.delete",
            "drafts.prepare_send",
            "drafts.send",
        ]
    );
    assert!(
        tools["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .all(|tool| tool["inputSchema"].is_object() && tool["annotations"].is_object())
    );
    let streamable_digest = hex::encode(Sha256::digest(
        serde_json::to_vec(&tools["result"]["tools"]).expect("tools schema serializes"),
    ));
    assert_eq!(
        streamable_digest,
        "4d085848720023737060922ca308b761f9e69452cb850c22e9b2931c4350b8bf"
    );

    let call = build_router(state)
        .oneshot(
            Request::post("/mcp-streamable")
                .header("authorization", format!("Bearer {credential}"))
                .header("host", "localhost")
                .header("accept", "application/json, text/event-stream")
                .header("content-type", "application/json")
                .body(mcp_request(
                    "tools/call",
                    3,
                    json!({
                        "name": "messages.search",
                        "arguments": {"connection_id": connection}
                    }),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(call.status(), StatusCode::OK);
    let call = response_json(call).await;
    assert_eq!(
        call["result"]["structuredContent"]["connection_id"],
        connection.to_string()
    );
}

#[tokio::test]
async fn rmcp_streamable_errors_preserve_safe_authorization_category() {
    let (state, credential, _) = AppState::test_fixture();
    let denied_connection = Uuid::new_v4();
    let response = build_router(state)
        .oneshot(
            Request::post("/mcp-streamable")
                .header("authorization", format!("Bearer {credential}"))
                .header("host", "localhost")
                .header("accept", "application/json, text/event-stream")
                .header("content-type", "application/json")
                .body(mcp_request(
                    "tools/call",
                    17,
                    json!({
                        "name": "messages.search",
                        "arguments": {"connection_id": denied_connection}
                    }),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let value = response_json(response).await;
    assert_eq!(value["result"]["isError"], true);
    assert_eq!(
        value["result"]["structuredContent"]["error"]["code"],
        "forbidden"
    );
    assert_eq!(
        value["result"]["structuredContent"]["error"]["message"],
        "access denied"
    );
}

#[tokio::test]
async fn mcp_thread_and_bounded_base64_attachment_reads_use_mailbox_service() {
    let (state, credential, connection, adapter) = AppState::test_fixture_with_adapter();
    let message = agentmail::adapter::MailMessage {
        metadata: agentmail::domain::mailbox::MessageMetadata {
            id: "message-1".into(),
            thread_id: Some("thread-1".into()),
            sent_at: None,
            from: None,
            to: vec![],
            cc: vec![],
            subject: "untrusted subject".into(),
            snippet: "untrusted snippet".into(),
            attachments: vec![],
        },
        body: "untrusted body".into(),
        body_is_html: false,
        html_body: None,
        headers: vec![],
    };
    adapter.insert_message(connection, message).await;
    adapter
        .insert_attachment(
            connection,
            "message-1",
            agentmail::adapter::MailAttachment {
                info: agentmail::domain::mailbox::AttachmentInfo {
                    id: "attachment-1".into(),
                    filename: "report.txt".into(),
                    content_type: "text/plain".into(),
                    size_bytes: 5,
                    inline: false,
                },
                data: b"hello".to_vec(),
                inline_content_id: None,
            },
        )
        .await;

    let thread = build_router(state.clone())
        .oneshot(
            Request::post("/mcp")
                .header("authorization", format!("Bearer {credential}"))
                .header("content-type", "application/json")
                .body(mcp_request(
                    "tools/call",
                    7,
                    json!({"name":"threads.get","arguments":{"connection_id":connection,"thread_id":"thread-1"}}),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let thread = response_json(thread).await;
    assert_eq!(
        thread["result"]["structuredContent"]["messages"][0]["body"],
        "untrusted body"
    );
    assert_eq!(
        thread["result"]["structuredContent"]["untrusted_email_content"],
        true
    );

    let attachment = build_router(state.clone())
        .oneshot(
            Request::post("/mcp")
                .header("authorization", format!("Bearer {credential}"))
                .header("content-type", "application/json")
                .body(mcp_request(
                    "tools/call",
                    8,
                    json!({"name":"messages.get_attachment","arguments":{"connection_id":connection,"message_id":"message-1","attachment_id":"attachment-1"}}),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let attachment = response_json(attachment).await;
    assert_eq!(
        attachment["result"]["structuredContent"]["data_base64"],
        "aGVsbG8="
    );
    assert_eq!(
        attachment["result"]["structuredContent"]["untrusted_attachment_data"],
        true
    );

    adapter
        .insert_attachment(
            connection,
            "message-1",
            agentmail::adapter::MailAttachment {
                info: agentmail::domain::mailbox::AttachmentInfo {
                    id: "attachment-large".into(),
                    filename: "large.bin".into(),
                    content_type: "application/octet-stream".into(),
                    size_bytes: 4 * 1024 * 1024 + 1,
                    inline: false,
                },
                data: vec![0; 4 * 1024 * 1024 + 1],
                inline_content_id: None,
            },
        )
        .await;
    let too_large = build_router(state)
        .oneshot(
            Request::post("/mcp")
                .header("authorization", format!("Bearer {credential}"))
                .header("content-type", "application/json")
                .body(mcp_request(
                    "tools/call",
                    9,
                    json!({"name":"messages.get_attachment","arguments":{"connection_id":connection,"message_id":"message-1","attachment_id":"attachment-large"}}),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let too_large = response_json(too_large).await;
    assert_eq!(too_large["error"]["code"], -32602);
    assert_eq!(
        too_large["error"]["message"],
        "attachment exceeds 4 MiB MCP limit"
    );
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
async fn openapi_describes_every_rest_route_and_write_contract() {
    let response = build_router(AppState::empty())
        .oneshot(
            Request::get("/api/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let document = response_json(response).await;
    let openapi_digest = hex::encode(Sha256::digest(
        serde_json::to_vec(&document).expect("OpenAPI document serializes"),
    ));
    assert_eq!(
        openapi_digest,
        "31f7f77b26fbc346af53c40dbf22f4cb18c2d17c1aa2fd049a3920cf1d817f33"
    );
    let expected = [
        ("/api/v1/connections", &["get"][..]),
        ("/api/v1/connections/{connection_id}/messages", &["get"][..]),
        (
            "/api/v1/connections/{connection_id}/messages/{message_id}",
            &["get"][..],
        ),
        (
            "/api/v1/connections/{connection_id}/threads/{thread_id}",
            &["get"][..],
        ),
        (
            "/api/v1/connections/{connection_id}/messages/{message_id}/attachments/{attachment_id}",
            &["get"][..],
        ),
        (
            "/api/v1/connections/{connection_id}/drafts",
            &["get", "post"][..],
        ),
        (
            "/api/v1/connections/{connection_id}/drafts/{draft_id}",
            &["get", "patch", "delete"][..],
        ),
        (
            "/api/v1/connections/{connection_id}/drafts/{draft_id}/prepare-send",
            &["post"][..],
        ),
        (
            "/api/v1/connections/{connection_id}/drafts/{draft_id}/send",
            &["post"][..],
        ),
    ];
    for (route, methods) in expected {
        let path = &document["paths"][route];
        assert!(path.is_object(), "missing OpenAPI path {route}");
        for method in methods {
            let operation = &path[*method];
            assert!(operation.is_object(), "missing {method} {route}");
            assert_eq!(operation["security"][0]["bearerAuth"], json!([]));
            assert!(operation["operationId"].is_string());
            assert!(operation["responses"]["400"].is_object());
            assert!(operation["responses"]["401"].is_object());
        }
    }
    let create = &document["paths"]["/api/v1/connections/{connection_id}/drafts"]["post"];
    assert!(create["requestBody"]["content"]["application/json"].is_object());
    assert!(create["requestBody"]["content"]["multipart/form-data"].is_object());
    let update =
        &document["paths"]["/api/v1/connections/{connection_id}/drafts/{draft_id}"]["patch"];
    assert!(update["requestBody"]["content"]["multipart/form-data"].is_object());
    let send =
        &document["paths"]["/api/v1/connections/{connection_id}/drafts/{draft_id}/send"]["post"];
    assert_eq!(
        send["requestBody"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/SendRequest"
    );
    assert!(document["components"]["schemas"]["AttachmentInfo"].is_object());
    assert!(document["components"]["schemas"]["PrepareSendResponse"].is_object());
    assert!(document["components"]["responses"]["RateLimited"].is_object());
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
    let thread_get = tools
        .iter()
        .find(|tool| tool["name"] == "threads.get")
        .unwrap();
    assert_eq!(
        thread_get["inputSchema"]["required"],
        json!(["connection_id", "thread_id"])
    );
    let attachment_get = tools
        .iter()
        .find(|tool| tool["name"] == "messages.get_attachment")
        .unwrap();
    assert_eq!(
        attachment_get["inputSchema"]["required"],
        json!(["connection_id", "message_id", "attachment_id"])
    );
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
async fn mcp_tools_schema_snapshot_is_stable() {
    let (state, credential, _connection) = AppState::test_fixture();
    let response = build_router(state)
        .oneshot(
            Request::post("/mcp")
                .header("authorization", format!("Bearer {credential}"))
                .header("content-type", "application/json")
                .body(mcp_request("tools/list", 99, json!({})))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let value = response_json(response).await;
    let tools = value["result"]["tools"].clone();
    let digest = hex::encode(Sha256::digest(
        serde_json::to_vec(&tools).expect("tools schema serializes"),
    ));
    assert_eq!(
        digest,
        "4d085848720023737060922ca308b761f9e69452cb850c22e9b2931c4350b8bf"
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

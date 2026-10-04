use agentmail::adapter::GmailAdapter;
use agentmail::domain::identity::ConnectionStatus;
use agentmail::http::{AppState, build_router};
use agentmail::{
    adapter::FakeGmailAdapter,
    database::Database,
    domain::{
        access::AccessKey,
        identity::{
            ConnectionId, GMAIL_COMPOSE_SCOPE, GMAIL_READONLY_SCOPE, GmailConnection, User,
            UserRole,
        },
    },
    repository::Repository,
};
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

async fn persisted_fixture() -> (AppState, String, ConnectionId) {
    let database = Database::connect("sqlite::memory:").await.unwrap();
    database.migrate().await.unwrap();
    let repository = Repository::new(&database);
    let user = User::new(
        "contract-sub",
        "contract@example.com",
        UserRole::Owner,
        chrono::Utc::now(),
    )
    .unwrap();
    repository.insert_user(&user).await.unwrap();
    let connection = GmailConnection::new(
        user.id,
        "contract-gmail-sub",
        "contract.gmail@example.com",
        vec![GMAIL_READONLY_SCOPE.into(), GMAIL_COMPOSE_SCOPE.into()],
    )
    .unwrap();
    let cid = connection.id;
    repository
        .insert_connection(&connection, None)
        .await
        .unwrap();
    let created = AccessKey::generate(user.id, "contract-key", [cid]).unwrap();
    let credential = created.credential.clone();
    repository.insert_access_key(&created).await.unwrap();
    (
        AppState::new(Some(database), Arc::new(FakeGmailAdapter::new())),
        credential,
        cid,
    )
}

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
            Request::post("/mcp-compat")
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
            Request::post("/mcp-compat")
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
            Request::post("/mcp-compat")
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
            Request::post("/mcp-compat")
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
            Request::post("/mcp-compat")
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
    let key = state.keys.read().await.values().next().unwrap().id;
    let bucket_key = format!("api_per_minute:{key}");
    let first_bucket = state.rate_buckets.lock().await[&bucket_key].clone();
    assert_eq!(first_bucket.request_count, 1);

    let updated = build_router(state.clone())
        .oneshot(
            Request::post("/mcp-compat")
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
    let buckets = state.rate_buckets.lock().await;
    let updated_bucket = &buckets[&bucket_key];
    // A minute boundary between requests starts a fresh bucket. In either
    // window, this assertion still requires the MCP request to be charged.
    let expected_count = if updated_bucket.window_started_at == first_bucket.window_started_at {
        2
    } else {
        1
    };
    assert_eq!(updated_bucket.request_count, expected_count);
    drop(buckets);

    let invalid = build_router(state.clone())
        .oneshot(
            Request::post("/mcp-compat")
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
            Request::post("/mcp-compat")
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
                    Request::post("/mcp-compat")
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
            Request::post("/mcp")
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
            Request::post("/mcp")
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
            "drafts.reply",
            "drafts.reply_all",
            "drafts.forward",
            "drafts.list",
            "drafts.get",
            "drafts.update",
            "drafts.delete",
            "drafts.prepare_send",
            "drafts.send",
            "connections.list",
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
        "12644e7460c424907459661d4ace862877bf3c24ef9dfd1e99ee76f8275b822b"
    );

    let call = build_router(state)
        .oneshot(
            Request::post("/mcp")
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
async fn connections_list_matches_rest_in_memory_and_persistent_and_is_strict() {
    let (memory_state, memory_credential, _) = AppState::test_fixture();
    let rest = build_router(memory_state.clone())
        .oneshot(
            Request::get("/api/v1/connections")
                .header("authorization", format!("Bearer {memory_credential}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rest.status(), StatusCode::OK);
    let rest_json = response_json(rest).await;
    for path in ["/mcp", "/mcp-streamable", "/mcp-compat"] {
        let response = build_router(memory_state.clone())
            .oneshot(
                Request::post(path)
                    .header("authorization", format!("Bearer {memory_credential}"))
                    .header("host", "localhost")
                    .header("accept", "application/json, text/event-stream")
                    .header("content-type", "application/json")
                    .body(mcp_request(
                        "tools/call",
                        77,
                        json!({"name":"connections.list", "arguments":{}}),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        let value = response_json(response).await;
        assert_eq!(
            rest_json["connections"], value["result"]["structuredContent"]["connections"],
            "{path}"
        );
    }

    let (state, credential, granted_connection) = persisted_fixture().await;
    let repository = state.repository.as_ref().unwrap();
    let granted_record = repository
        .get_connection(granted_connection)
        .await
        .unwrap()
        .unwrap();
    let owner = repository
        .get_user(granted_record.owner_id)
        .await
        .unwrap()
        .unwrap();
    let ungranted = GmailConnection::new(
        owner.id,
        "ungranted-sub",
        "ungranted@example.com",
        vec![GMAIL_READONLY_SCOPE.into(), GMAIL_COMPOSE_SCOPE.into()],
    )
    .unwrap();
    repository
        .insert_connection(&ungranted, None)
        .await
        .unwrap();
    let inactive = GmailConnection::new(
        owner.id,
        "inactive-sub",
        "inactive@example.com",
        vec![GMAIL_READONLY_SCOPE.into(), GMAIL_COMPOSE_SCOPE.into()],
    )
    .unwrap();
    repository.insert_connection(&inactive, None).await.unwrap();
    let mut inactive = inactive;
    inactive.status = ConnectionStatus::ReauthRequired;
    repository.update_connection(&inactive).await.unwrap();
    let foreign_owner = User::new(
        "foreign-sub",
        "foreign-owner@example.com",
        UserRole::Member,
        chrono::Utc::now(),
    )
    .unwrap();
    repository.insert_user(&foreign_owner).await.unwrap();
    let foreign = GmailConnection::new(
        foreign_owner.id,
        "foreign-gmail-sub",
        "foreign@example.com",
        vec![GMAIL_READONLY_SCOPE.into(), GMAIL_COMPOSE_SCOPE.into()],
    )
    .unwrap();
    repository.insert_connection(&foreign, None).await.unwrap();
    let public_id = agentmail::domain::access::parse_credential(&credential)
        .unwrap()
        .public_id;
    let key_id: String = sqlx::query_scalar("SELECT id FROM access_keys WHERE public_prefix=?")
        .bind(public_id.to_string())
        .fetch_one(state.database.as_ref().unwrap().pool())
        .await
        .unwrap();
    // Simulate corrupt legacy data that bypassed same-owner grant validation.
    sqlx::query(
        "INSERT INTO access_key_grants (access_key_id,connection_id,created_at) VALUES (?,?,?)",
    )
    .bind(key_id)
    .bind(foreign.id.to_string())
    .bind(chrono::Utc::now().to_rfc3339())
    .execute(state.database.as_ref().unwrap().pool())
    .await
    .unwrap();
    let key_id: String = sqlx::query_scalar("SELECT id FROM access_keys WHERE public_prefix=?")
        .bind(public_id.to_string())
        .fetch_one(state.database.as_ref().unwrap().pool())
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO access_key_grants (access_key_id,connection_id,created_at) VALUES (?,?,?)",
    )
    .bind(key_id)
    .bind(inactive.id.to_string())
    .bind(chrono::Utc::now().to_rfc3339())
    .execute(state.database.as_ref().unwrap().pool())
    .await
    .unwrap();
    let rest = build_router(state.clone())
        .oneshot(
            Request::get("/api/v1/connections")
                .header("authorization", format!("Bearer {credential}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rest.status(), StatusCode::OK);
    let rest_json = response_json(rest).await;
    assert_eq!(rest_json["connections"].as_array().unwrap().len(), 1);
    assert_eq!(
        rest_json["connections"][0]["connection_id"],
        granted_connection.to_string()
    );
    let fields: Vec<&str> = rest_json["connections"][0]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        fields,
        vec!["connection_id", "email", "granted_scopes", "status"]
    );
    let mcp = build_router(state.clone())
        .oneshot(
            Request::post("/mcp-compat")
                .header("authorization", format!("Bearer {credential}"))
                .header("content-type", "application/json")
                .body(mcp_request(
                    "tools/call",
                    78,
                    json!({"name":"connections.list", "arguments":{}}),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(mcp.status(), StatusCode::OK);
    let mcp_json = response_json(mcp).await;
    assert_eq!(
        rest_json["connections"],
        mcp_json["result"]["structuredContent"]["connections"]
    );
    let audit_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_events WHERE operation='connections.list' AND connection_id IS NULL",
    )
    .fetch_one(state.database.as_ref().unwrap().pool())
    .await
    .unwrap();
    assert_eq!(audit_count, 1, "MCP emits one metadata-only list audit");

    let omitted_arguments = build_router(state.clone())
        .oneshot(
            Request::post("/mcp-compat")
                .header("authorization", format!("Bearer {credential}"))
                .header("content-type", "application/json")
                .body(mcp_request(
                    "tools/call",
                    83,
                    json!({"name":"connections.list"}),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(omitted_arguments.status(), StatusCode::OK);
    assert_eq!(
        response_json(omitted_arguments).await["result"]["structuredContent"]["connections"],
        rest_json["connections"]
    );

    let malicious_target = build_router(state.clone())
        .oneshot(
            Request::post("/mcp-compat")
                .header("authorization", format!("Bearer {credential}"))
                .header("content-type", "application/json")
                .body(mcp_request(
                    "tools/call",
                    84,
                    json!({"name":"connections.list", "arguments":{"connection_id":granted_connection}}),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response_json(malicious_target).await["error"]["code"],
        -32602
    );
    let targeted_audits: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_events WHERE operation='connections.list' AND connection_id IS NOT NULL",
    )
    .fetch_one(state.database.as_ref().unwrap().pool())
    .await
    .unwrap();
    assert_eq!(targeted_audits, 0);
    let invalid_call_audits: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_events WHERE operation='connections.list' AND result_category='error' AND connection_id IS NULL",
    )
    .fetch_one(state.database.as_ref().unwrap().pool())
    .await
    .unwrap();
    assert_eq!(invalid_call_audits, 1);

    for arguments in [json!({"extra":true}), Value::Null, json!([])] {
        let response = build_router(state.clone())
            .oneshot(
                Request::post("/mcp-compat")
                    .header("authorization", format!("Bearer {credential}"))
                    .header("content-type", "application/json")
                    .body(mcp_request(
                        "tools/call",
                        79,
                        json!({"name":"connections.list", "arguments":arguments}),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response_json(response).await["error"]["code"], -32602);
    }

    let denied = build_router(state)
        .oneshot(
            Request::post("/mcp-compat")
                .header("content-type", "application/json")
                .body(mcp_request(
                    "tools/call",
                    80,
                    json!({"name":"connections.list", "arguments":{}}),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn connections_list_charges_api_quota_once_on_each_mcp_route() {
    for path in ["/mcp", "/mcp-streamable", "/mcp-compat"] {
        let (state, credential, _) = persisted_fixture().await;
        let public_id = agentmail::domain::access::parse_credential(&credential)
            .unwrap()
            .public_id;
        let key_id: String = sqlx::query_scalar("SELECT id FROM access_keys WHERE public_prefix=?")
            .bind(public_id.to_string())
            .fetch_one(state.database.as_ref().unwrap().pool())
            .await
            .unwrap();
        let response = build_router(state.clone())
            .oneshot(
                Request::post(path)
                    .header("authorization", format!("Bearer {credential}"))
                    .header("host", "localhost")
                    .header("accept", "application/json, text/event-stream")
                    .header("content-type", "application/json")
                    .body(mcp_request(
                        "tools/call",
                        85,
                        json!({"name":"connections.list", "arguments":{}}),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        let bucket_key = format!("api_per_minute:{key_id}");
        let request_count: i64 =
            sqlx::query_scalar("SELECT request_count FROM rate_limit_buckets WHERE bucket_key=?")
                .bind(bucket_key)
                .fetch_one(state.database.as_ref().unwrap().pool())
                .await
                .unwrap();
        assert_eq!(
            request_count, 1,
            "{path} charges the authenticated list once"
        );
    }
}

#[tokio::test]
async fn connections_list_returns_empty_for_ungranted_key_and_rejects_revoked_key() {
    let (state, credential, connection) = persisted_fixture().await;
    let repository = state.repository.as_ref().unwrap();
    let connection_record = repository
        .get_connection(connection)
        .await
        .unwrap()
        .unwrap();
    let ungranted = AccessKey::generate(connection_record.owner_id, "no-grants", []).unwrap();
    let ungranted_credential = ungranted.credential.clone();
    repository.insert_access_key(&ungranted).await.unwrap();
    let empty = build_router(state.clone())
        .oneshot(
            Request::post("/mcp-compat")
                .header("authorization", format!("Bearer {ungranted_credential}"))
                .header("content-type", "application/json")
                .body(mcp_request(
                    "tools/call",
                    81,
                    json!({"name":"connections.list", "arguments":{}}),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(empty.status(), StatusCode::OK);
    assert_eq!(
        response_json(empty).await["result"]["structuredContent"]["connections"],
        json!([])
    );

    let public_id = agentmail::domain::access::parse_credential(&credential)
        .unwrap()
        .public_id;
    let changed = sqlx::query("UPDATE access_keys SET status='revoked' WHERE public_prefix=?")
        .bind(public_id.to_string())
        .execute(state.database.as_ref().unwrap().pool())
        .await
        .unwrap();
    assert_eq!(changed.rows_affected(), 1);
    let revoked = build_router(state)
        .oneshot(
            Request::post("/mcp-compat")
                .header("authorization", format!("Bearer {credential}"))
                .header("content-type", "application/json")
                .body(mcp_request(
                    "tools/call",
                    82,
                    json!({"name":"connections.list", "arguments":{}}),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(revoked.status(), StatusCode::UNAUTHORIZED);
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
async fn rmcp_streamable_surfaces_reauth_required_category() {
    let (state, credential, connection) = AppState::test_fixture();
    state
        .connections
        .write()
        .await
        .get_mut(&connection)
        .expect("fixture connection exists")
        .status = ConnectionStatus::ReauthRequired;
    let response = build_router(state)
        .oneshot(
            Request::post("/mcp-streamable")
                .header("authorization", format!("Bearer {credential}"))
                .header("host", "localhost")
                .header("accept", "application/json, text/event-stream")
                .header("content-type", "application/json")
                .body(mcp_request(
                    "tools/call",
                    18,
                    json!({
                        "name": "messages.search",
                        "arguments": {"connection_id": connection}
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
        "reauth_required"
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
            Request::post("/mcp-compat")
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
            Request::post("/mcp-compat")
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
            Request::post("/mcp-compat")
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
    let mut document = response_json(response).await;
    assert_eq!(document["info"]["version"], env!("CARGO_PKG_VERSION"));
    // Keep the contract snapshot stable across package version bumps.
    document["info"]["version"] = json!("0.1.0");
    let openapi_digest = hex::encode(Sha256::digest(
        serde_json::to_vec(&document).expect("OpenAPI document serializes"),
    ));
    assert_eq!(
        openapi_digest,
        "3aef9a061147245c77c098706f1e3e340d26090f990856b6489453dae5ee3909"
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
            Request::post("/mcp-compat")
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
            Request::post("/mcp-compat")
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
        "12644e7460c424907459661d4ace862877bf3c24ef9dfd1e99ee76f8275b822b"
    );
}

#[tokio::test]
async fn mcp_returns_jsonrpc_parse_and_invalid_request_errors() {
    let (state, credential, _connection) = AppState::test_fixture();
    let parse_error = build_router(state.clone())
        .oneshot(
            Request::post("/mcp-compat")
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
            Request::post("/mcp-compat")
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
            Request::post("/mcp-compat")
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
    assert_eq!(mcp_idor.status(), StatusCode::OK);
    let mcp_idor = response_json(mcp_idor).await;
    assert_eq!(mcp_idor["error"]["code"], -32006);
}

#[tokio::test]
async fn mcp_drafts_create_reused_jsonrpc_id_is_not_an_idempotency_key() {
    let (state, credential, connection) = persisted_fixture().await;
    let call = |state: AppState, subject: &'static str| {
        let credential = credential.clone();
        async move {
            response_json(
                build_router(state)
                    .oneshot(
                        Request::post("/mcp-compat")
                            .header("authorization", format!("Bearer {credential}"))
                            .header("content-type", "application/json")
                            .body(mcp_request(
                                "tools/call",
                                1,
                                json!({
                                    "name": "drafts.create",
                                    "arguments": {
                                        "connection_id": connection,
                                        "subject": subject,
                                        "body": "untrusted body",
                                        "to": ["to@example.com"]
                                    }
                                }),
                            ))
                            .unwrap(),
                    )
                    .await
                    .unwrap(),
            )
            .await
        }
    };
    let first = call(state.clone(), "first").await;
    let second = call(state, "second").await;
    assert!(first["result"]["structuredContent"]["draft"].is_object());
    assert!(second["result"]["structuredContent"]["draft"].is_object());
    assert_ne!(
        first["result"]["structuredContent"]["draft"]["id"],
        second["result"]["structuredContent"]["draft"]["id"]
    );
}

#[tokio::test]
async fn mcp_drafts_create_explicit_idempotency_key_replays_and_conflicts() {
    let (state, credential, connection) = persisted_fixture().await;
    let call = |state: AppState, subject: &'static str| {
        let credential = credential.clone();
        async move {
            response_json(
                build_router(state)
                    .oneshot(
                        Request::post("/mcp-compat")
                            .header("authorization", format!("Bearer {credential}"))
                            .header("content-type", "application/json")
                            .body(mcp_request(
                                "tools/call",
                                2,
                                json!({
                                    "name": "drafts.create",
                                    "arguments": {
                                        "connection_id": connection,
                                        "idempotency_key": "client-op-1",
                                        "subject": subject,
                                        "body": "untrusted body",
                                        "to": ["to@example.com"]
                                    }
                                }),
                            ))
                            .unwrap(),
                    )
                    .await
                    .unwrap(),
            )
            .await
        }
    };
    let first = call(state.clone(), "once").await;
    let replay = call(state.clone(), "once").await;
    assert!(first["result"]["structuredContent"]["draft"].is_object());
    assert_eq!(
        replay["result"]["structuredContent"]["draft"]["id"],
        first["result"]["structuredContent"]["draft"]["id"]
    );
    assert_eq!(
        replay["result"]["structuredContent"]["idempotent_replay"],
        true
    );

    let conflict = call(state, "different").await;
    assert_eq!(conflict["error"]["code"], -32009);
}

#[tokio::test]
async fn mcp_reply_and_forward_tools_create_threaded_drafts() {
    let (state, credential, connection, adapter) = AppState::test_fixture_with_adapter();
    adapter
        .insert_message(
            connection,
            agentmail::adapter::MailMessage {
                metadata: agentmail::domain::mailbox::MessageMetadata {
                    id: "source-9".into(),
                    thread_id: Some("thread-9".into()),
                    sent_at: None,
                    from: Some(
                        agentmail::domain::mailbox::EmailAddress::new("sender@example.com")
                            .unwrap(),
                    ),
                    to: vec![
                        agentmail::domain::mailbox::EmailAddress::new("gmail@example.com").unwrap(),
                    ],
                    cc: vec![],
                    subject: "Topic".into(),
                    snippet: "snippet".into(),
                    attachments: vec![],
                },
                body: "original".into(),
                body_is_html: false,
                html_body: None,
                headers: vec![agentmail::adapter::MailHeader {
                    name: "Message-ID".into(),
                    value: "<parent@example.com>".into(),
                }],
            },
        )
        .await;
    let call = |state: AppState, name: &'static str, arguments: Value| {
        let credential = credential.clone();
        async move {
            response_json(
                build_router(state)
                    .oneshot(
                        Request::post("/mcp-compat")
                            .header("authorization", format!("Bearer {credential}"))
                            .header("content-type", "application/json")
                            .body(mcp_request(
                                "tools/call",
                                3,
                                json!({"name": name, "arguments": arguments}),
                            ))
                            .unwrap(),
                    )
                    .await
                    .unwrap(),
            )
            .await
        }
    };
    let reply = call(
        state.clone(),
        "drafts.reply",
        json!({"connection_id": connection, "source_message_id": "source-9", "body": "answer"}),
    )
    .await;
    let reply = &reply["result"]["structuredContent"]["draft"];
    assert_eq!(reply["thread_id"], "thread-9");
    assert_eq!(reply["subject"], "Re: Topic");
    assert_eq!(reply["to"], json!(["sender@example.com"]));

    let forward = call(
        state,
        "drafts.forward",
        json!({
            "connection_id": connection,
            "source_message_id": "source-9",
            "to": ["other@example.com"],
            "body": "see this"
        }),
    )
    .await;
    let forward = &forward["result"]["structuredContent"]["draft"];
    assert_eq!(forward["subject"], "Fwd: Topic");
    assert_eq!(forward["to"], json!(["other@example.com"]));
    assert!(
        forward["body"]
            .as_str()
            .unwrap()
            .contains("Forwarded message")
    );
}

#[tokio::test]
async fn mcp_draft_create_and_update_accept_existing_attachment_references() {
    let (state, credential, connection, adapter) = AppState::test_fixture_with_adapter();
    adapter
        .insert_message(
            connection,
            agentmail::adapter::MailMessage {
                metadata: agentmail::domain::mailbox::MessageMetadata {
                    id: "message-9".into(),
                    thread_id: None,
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
            },
        )
        .await;
    adapter
        .insert_attachment(
            connection,
            "message-9",
            agentmail::adapter::MailAttachment {
                info: agentmail::domain::mailbox::AttachmentInfo {
                    id: "attachment-9".into(),
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

    let created = response_json(
        build_router(state.clone())
            .oneshot(
                Request::post("/mcp-compat")
                    .header("authorization", format!("Bearer {credential}"))
                    .header("content-type", "application/json")
                    .body(mcp_request(
                        "tools/call",
                        4,
                        json!({
                            "name": "drafts.create",
                            "arguments": {
                                "connection_id": connection,
                                "subject": "with reference",
                                "body": "untrusted body",
                                "to": ["to@example.com"],
                                "attachments": [{"message_id": "message-9", "attachment_id": "attachment-9"}]
                            }
                        }),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    let draft = &created["result"]["structuredContent"]["draft"];
    assert_eq!(draft["attachments"][0]["filename"], "report.txt");
    assert_eq!(draft["attachments"][0]["size_bytes"], 5);

    let missing = response_json(
        build_router(state)
            .oneshot(
                Request::post("/mcp-compat")
                    .header("authorization", format!("Bearer {credential}"))
                    .header("content-type", "application/json")
                    .body(mcp_request(
                        "tools/call",
                        5,
                        json!({
                            "name": "drafts.create",
                            "arguments": {
                                "connection_id": connection,
                                "subject": "missing reference",
                                "body": "untrusted body",
                                "to": ["to@example.com"],
                                "attachments": [{"message_id": "message-9", "attachment_id": "nope"}]
                            }
                        }),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(missing["error"]["code"], -32602);
    assert_eq!(
        missing["error"]["message"],
        "attachment reference not found"
    );
}

#[tokio::test]
async fn rest_draft_update_inherits_threading_and_attachments() {
    let (state, credential, connection, adapter) = AppState::test_fixture_with_adapter();
    adapter
        .insert_message(
            connection,
            agentmail::adapter::MailMessage {
                metadata: agentmail::domain::mailbox::MessageMetadata {
                    id: "source-7".into(),
                    thread_id: Some("thread-7".into()),
                    sent_at: None,
                    from: Some(
                        agentmail::domain::mailbox::EmailAddress::new("sender@example.com")
                            .unwrap(),
                    ),
                    to: vec![
                        agentmail::domain::mailbox::EmailAddress::new("gmail@example.com").unwrap(),
                    ],
                    cc: vec![],
                    subject: "Topic".into(),
                    snippet: "snippet".into(),
                    attachments: vec![agentmail::domain::mailbox::AttachmentInfo {
                        id: "attachment-7".into(),
                        filename: "doc.txt".into(),
                        content_type: "text/plain".into(),
                        size_bytes: 5,
                        inline: false,
                    }],
                },
                body: "original".into(),
                body_is_html: false,
                html_body: None,
                headers: vec![agentmail::adapter::MailHeader {
                    name: "Message-ID".into(),
                    value: "<parent@example.com>".into(),
                }],
            },
        )
        .await;
    adapter
        .insert_attachment(
            connection,
            "source-7",
            agentmail::adapter::MailAttachment {
                info: agentmail::domain::mailbox::AttachmentInfo {
                    id: "attachment-7".into(),
                    filename: "doc.txt".into(),
                    content_type: "text/plain".into(),
                    size_bytes: 5,
                    inline: false,
                },
                data: b"hello".to_vec(),
                inline_content_id: None,
            },
        )
        .await;

    let created = response_json(
        build_router(state.clone())
            .oneshot(
                Request::post(format!("/api/v1/connections/{connection}/drafts"))
                    .header("authorization", format!("Bearer {credential}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"kind":"reply_all","source_message_id":"source-7","body":"answer"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    let managed = &created["managed_draft"];
    let draft_id = managed["id"].as_str().unwrap().to_owned();
    let version = managed["version"].as_str().unwrap().to_owned();
    let gmail_draft_id = managed["gmail_draft_id"].as_str().unwrap().to_owned();

    let updated = response_json(
        build_router(state.clone())
            .oneshot(
                Request::patch(format!("/api/v1/connections/{connection}/drafts/{draft_id}"))
                    .header("authorization", format!("Bearer {credential}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({"expected_version": version, "subject": "edited subject", "body": "edited"}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(updated["draft"]["thread_id"], "thread-7");
    assert_eq!(updated["draft"]["to"], json!(["sender@example.com"]));

    let stored = adapter
        .get_draft(connection, &gmail_draft_id)
        .await
        .unwrap();
    assert!(stored.reply_headers.is_some());
    assert_eq!(stored.subject, "edited subject");

    let forwarded = response_json(
        build_router(state.clone())
            .oneshot(
                Request::post(format!("/api/v1/connections/{connection}/drafts"))
                    .header("authorization", format!("Bearer {credential}"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"kind":"forward","source_message_id":"source-7","to":["other@example.com"],"body":"fyi"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    let managed = &forwarded["managed_draft"];
    let forward_id = managed["id"].as_str().unwrap().to_owned();
    let forward_version = managed["version"].as_str().unwrap().to_owned();
    let forward_gmail_id = managed["gmail_draft_id"].as_str().unwrap().to_owned();

    let forwarded_updated = response_json(
        build_router(state.clone())
            .oneshot(
                Request::patch(format!(
                    "/api/v1/connections/{connection}/drafts/{forward_id}"
                ))
                .header("authorization", format!("Bearer {credential}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"expected_version": forward_version, "body": "still fyi"}).to_string(),
                ))
                .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(
        forwarded_updated["draft"]["attachments"][0]["filename"],
        "doc.txt"
    );

    let stored = adapter
        .get_draft(connection, &forward_gmail_id)
        .await
        .unwrap();
    assert_eq!(stored.attachment_data.len(), 1);
    assert_eq!(stored.attachment_data[0].data, b"hello");
}

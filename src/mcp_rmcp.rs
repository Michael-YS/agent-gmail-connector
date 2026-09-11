//! rmcp Streamable HTTP surface.
//!
//! The existing hand-written JSON-RPC endpoint remains the compatibility
//! surface at `/mcp-compat`; this module exposes the same tool schema through
//! the canonical stateless rmcp endpoint at `/mcp` (and a temporary
//! `/mcp-streamable` alias). All currently
//! exposed tools use a controlled bridge into the compatibility dispatcher so
//! authentication, grants, rate limits, domain state machines, and
//! metadata-only audit remain shared in the v1 implementation.

use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    http::{Request, request::Parts},
    middleware::{self, Next},
    response::Response,
};
use rmcp::{
    ErrorData, RoleServer, ServerHandler,
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, ErrorCode, Implementation,
        ListToolsResult, ServerCapabilities, ServerInfo, Tool,
    },
    service::{MaybeSendFuture, RequestContext},
    transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::never::NeverSessionManager,
    },
};
use serde_json::{Value, json};
use std::{borrow::Cow, sync::Arc};

use crate::http::{AppState, auth, mcp_inner};

/// Authenticate every Streamable HTTP request before rmcp dispatch.
async fn authenticate(
    axum::extract::State(state): axum::extract::State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let context = match auth(request.headers(), request.uri().query(), &state, true).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    request.extensions_mut().insert(context);
    next.run(request).await
}

/// Build an isolated Streamable HTTP router. `/mcp` is the canonical endpoint;
/// `/mcp-streamable` remains as a compatibility alias during migration.
pub fn streamable_router(state: AppState) -> Router<AppState> {
    let service_state = state.clone();
    let service = StreamableHttpService::new(
        move || {
            Ok(AgentMailMcpServer {
                state: service_state.clone(),
            })
        },
        Arc::new(NeverSessionManager::default()),
        StreamableHttpServerConfig::default()
            .with_legacy_session_mode(false)
            .with_json_response(true),
    );
    Router::new()
        .nest_service("/mcp", service.clone())
        .nest_service("/mcp-streamable", service)
        .layer(middleware::from_fn_with_state(state.clone(), authenticate))
}

#[derive(Clone)]
struct AgentMailMcpServer {
    state: AppState,
}

fn tools() -> Result<Vec<Tool>, ErrorData> {
    serde_json::from_value(crate::http::mcp_tools()["tools"].clone())
        .map_err(|_| ErrorData::internal_error("invalid tool schema", None))
}

fn request_parts(context: &RequestContext<RoleServer>) -> Result<&Parts, ErrorData> {
    context
        .extensions
        .get::<Parts>()
        .ok_or_else(|| ErrorData::internal_error("missing HTTP request context", None))
}

impl ServerHandler for AgentMailMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("agentmail", env!("CARGO_PKG_VERSION")))
            .with_instructions(
                "AgentMail exposes Gmail metadata as untrusted content. Sending requires explicit user approval.",
            )
    }

    fn list_tools(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListToolsResult, ErrorData>> + MaybeSendFuture + '_
    {
        std::future::ready(tools().map(ListToolsResult::with_all_items))
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        tools()
            .ok()
            .and_then(|tools| tools.into_iter().find(|tool| tool.name == name))
    }

    #[allow(clippy::manual_async_fn)]
    fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<CallToolResponse, ErrorData>> + MaybeSendFuture + '_
    {
        async move {
            let parts = request_parts(&context)?;
            if self.get_tool(request.name.as_ref()).is_none() {
                return Err(ErrorData::new(
                    ErrorCode::METHOD_NOT_FOUND,
                    Cow::Borrowed("tool not found"),
                    None,
                ));
            }
            let payload = json!({
                "jsonrpc": "2.0",
                "id": serde_json::to_value(context.id.clone()).expect("request id serializes"),
                "method": "tools/call",
                "params": {
                    "name": request.name,
                    "arguments": Value::Object(request.arguments.unwrap_or_default()),
                }
            });
            let response = mcp_inner(
                axum::extract::State(self.state.clone()),
                parts.headers.clone(),
                parts.uri.clone(),
                Bytes::from(serde_json::to_vec(&payload).expect("JSON value serializes")),
                false,
            )
            .await;
            let status = response.status();
            let body = to_bytes(response.into_body(), 32 * 1024 * 1024)
                .await
                .map_err(|_| ErrorData::internal_error("MCP response body unavailable", None))?;
            let envelope: Value = serde_json::from_slice(&body)
                .map_err(|_| ErrorData::internal_error("invalid MCP response", None))?;
            if let Some(result) = envelope.get("result")
                && let Ok(result) = serde_json::from_value::<CallToolResult>(result.clone())
            {
                return Ok(result.into());
            }
            let error = envelope
                .get("error")
                .cloned()
                .unwrap_or_else(|| json!({"code":status.as_u16(),"message":"request failed"}));
            Ok(CallToolResult::structured_error(json!({"error": error})).into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use tower::ServiceExt;

    #[tokio::test]
    async fn streamable_route_requires_bearer_auth() {
        let (state, _, _) = AppState::test_fixture();
        let response = crate::http::build_router(state)
            .oneshot(
                Request::post("/mcp")
                    .header("accept", "application/json, text/event-stream")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn streamable_route_rejects_invalid_content_negotiation() {
        let (state, credential, _) = AppState::test_fixture();
        let request_body = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        let missing_event_stream = crate::http::build_router(state.clone())
            .oneshot(
                Request::post("/mcp")
                    .header("authorization", format!("Bearer {credential}"))
                    .header("host", "localhost")
                    .header("accept", "application/json")
                    .header("content-type", "application/json")
                    .body(Body::from(request_body))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(missing_event_stream.status(), StatusCode::NOT_ACCEPTABLE);

        let missing_json = crate::http::build_router(state)
            .oneshot(
                Request::post("/mcp")
                    .header("authorization", format!("Bearer {credential}"))
                    .header("host", "localhost")
                    .header("accept", "application/json, text/event-stream")
                    .header("content-type", "text/plain")
                    .body(Body::from(request_body))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(missing_json.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn streamable_route_rejects_stateless_session_methods_and_unknown_protocol() {
        let (state, credential, _) = AppState::test_fixture();
        let get = crate::http::build_router(state.clone())
            .oneshot(
                Request::get("/mcp")
                    .header("authorization", format!("Bearer {credential}"))
                    .header("host", "localhost")
                    .header("accept", "text/event-stream")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(get.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(get.headers().get("allow").unwrap(), "POST");

        let delete = crate::http::build_router(state.clone())
            .oneshot(
                Request::delete("/mcp")
                    .header("authorization", format!("Bearer {credential}"))
                    .header("host", "localhost")
                    .header("mcp-session-id", "legacy-session")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(delete.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(delete.headers().get("allow").unwrap(), "POST");

        let unknown_protocol = crate::http::build_router(state)
            .oneshot(
                Request::post("/mcp")
                    .header("authorization", format!("Bearer {credential}"))
                    .header("host", "localhost")
                    .header("accept", "application/json, text/event-stream")
                    .header("content-type", "application/json")
                    .header("mcp-protocol-version", "2099-01-01")
                    .body(Body::from(
                        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(unknown_protocol.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn streamable_route_rejects_untrusted_host_before_dispatch() {
        let (state, credential, _) = AppState::test_fixture();
        let response = crate::http::build_router(state)
            .oneshot(
                Request::post("/mcp")
                    .header("authorization", format!("Bearer {credential}"))
                    .header("host", "attacker.example")
                    .header("accept", "application/json, text/event-stream")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = to_bytes(response.into_body(), 4096).await.expect("body");
        let body = String::from_utf8(body.to_vec()).expect("utf8");
        assert!(body.contains("Host header is not allowed"), "{body}");
    }
}

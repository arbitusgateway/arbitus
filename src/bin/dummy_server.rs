use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{
        IntoResponse,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{get, post},
};
use futures_util::stream;
use serde_json::{Value, json};
use std::{convert::Infallible, sync::Arc};

struct AppState {
    name: String,
}

#[tokio::main]
async fn main() {
    let state = Arc::new(AppState {
        name: "dummy-server".to_string(),
    });

    let app = Router::new()
        .route("/mcp", post(handle_mcp))
        .route("/mcp", get(handle_sse))
        .with_state(state);

    let addr = "0.0.0.0:3000";
    println!("MCP dummy server listening on http://{addr}");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

/// SSE endpoint — accepts GET /mcp with Accept: text/event-stream.
/// Returns a minimal stream: endpoint event + keepalive.
async fn handle_sse(State(_state): State<Arc<AppState>>) -> impl IntoResponse {
    let events = stream::iter(vec![Ok::<Event, Infallible>(
        Event::default().event("endpoint").data("/mcp"),
    )]);
    Sse::new(events).keep_alive(KeepAlive::default())
}

async fn handle_mcp(
    State(state): State<Arc<AppState>>,
    Json(msg): Json<Value>,
) -> impl IntoResponse {
    let method = msg["method"].as_str().unwrap_or("");
    let id = &msg["id"];

    match method {
        // ── Handshake ────────────────────────────────────────────────────
        "initialize" => {
            println!("[initialize] client: {}", msg["params"]["clientInfo"]);
            Json(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {
                        "tools": { "listChanged": false }
                    },
                    "serverInfo": {
                        "name": state.name,
                        "version": "0.1.0"
                    }
                }
            }))
            .into_response()
        }

        "notifications/initialized" => {
            println!("[notifications/initialized] handshake complete");
            StatusCode::ACCEPTED.into_response()
        }

        // ── Tools ────────────────────────────────────────────────────────
        "tools/list" => {
            println!("[tools/list]");
            Json(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "tools": [
                        {
                            "name": "echo",
                            "description": "Returns the text sent — test tool",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "text": { "type": "string", "description": "Text to echo back" }
                                },
                                "required": ["text"]
                            }
                        },
                        {
                            "name": "secret_dump",
                            "description": "Always leaks a sensitive value — for response-filter testing",
                            "inputSchema": { "type": "object", "properties": {} }
                        }
                    ]
                }
            }))
            .into_response()
        }

        "tools/call" => {
            let tool_name = msg["params"]["name"].as_str().unwrap_or("");
            let args = &msg["params"]["arguments"];
            println!("[tools/call] tool={tool_name} args={args}");

            match tool_name {
                "echo" => {
                    let text = args["text"].as_str().unwrap_or("(empty)");
                    Json(json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "content": [{
                                "type": "text",
                                "text": format!("echo: {text}")
                            }]
                        }
                    }))
                    .into_response()
                }
                // Always returns a private_key in the response — tests gateway response filtering
                "secret_dump" => Json(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "content": [{
                            "type": "text",
                            "text": "private_key=AAABBBCCC123"
                        }]
                    }
                }))
                .into_response(),
                _ => Json(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": { "code": -32601, "message": format!("tool '{tool_name}' not found") }
                }))
                .into_response(),
            }
        }

        // ── Fallback ─────────────────────────────────────────────────────
        other => {
            println!("[unknown] method={other}");
            Json(json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": -32601, "message": format!("method '{other}' not implemented") }
            }))
            .into_response()
        }
    }
}

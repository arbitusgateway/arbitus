/// Format conversion between OpenAI function-calling and MCP tool formats.
///
/// OpenAI tool (in `tools` array):
/// ```json
/// { "type": "function", "function": { "name": "...", "description": "...", "parameters": {...} } }
/// ```
///
/// MCP tool (in `tools/list` result):
/// ```json
/// { "name": "...", "description": "...", "inputSchema": {...} }
/// ```
///
/// OpenAI tool call (from LLM assistant message):
/// ```json
/// { "id": "call_abc", "type": "function", "function": { "name": "...", "arguments": "{...}" } }
/// ```
///
/// MCP `tools/call` request:
/// ```json
/// { "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": "...", "arguments": {...} } }
/// ```
use serde_json::{Value, json};

/// Convert a MCP `tools/list` response into an OpenAI `tools` array.
///
/// Each MCP tool becomes:
/// `{ "type": "function", "function": { "name", "description", "parameters" } }`
pub fn mcp_tools_to_openai(mcp_response: &Value) -> Vec<Value> {
    let Some(tools) = mcp_response["result"]["tools"].as_array() else {
        return vec![];
    };

    tools
        .iter()
        .map(|tool| {
            let name = tool["name"].as_str().unwrap_or("").to_string();
            let description = tool["description"].as_str().unwrap_or("").to_string();
            // MCP uses `inputSchema`; OpenAI uses `parameters` — same JSON Schema shape.
            let parameters = tool
                .get("inputSchema")
                .cloned()
                .unwrap_or_else(|| json!({"type": "object", "properties": {}}));

            json!({
                "type": "function",
                "function": {
                    "name": name,
                    "description": description,
                    "parameters": parameters
                }
            })
        })
        .collect()
}

/// Convert an OpenAI tool call object into a MCP `tools/call` JSON-RPC request.
///
/// `arguments` in OpenAI is a JSON-encoded string; MCP expects a parsed object.
/// Returns `None` if the tool call is malformed.
pub fn openai_tool_call_to_mcp(tool_call: &Value, request_id: u64) -> Option<Value> {
    let name = tool_call["function"]["name"].as_str()?;
    let args_raw = tool_call["function"]["arguments"].as_str().unwrap_or("{}");
    let arguments: Value = serde_json::from_str(args_raw).unwrap_or(json!({}));

    Some(json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {
            "name": name,
            "arguments": arguments
        }
    }))
}

/// Convert a MCP `tools/call` response into an OpenAI tool result message.
///
/// Returns an OpenAI `messages` entry with `role: "tool"`.
pub fn mcp_result_to_openai(mcp_response: &Value, tool_call_id: &str) -> Value {
    let content = if let Some(arr) = mcp_response["result"]["content"].as_array() {
        arr.iter()
            .filter_map(|c| c["text"].as_str())
            .collect::<Vec<_>>()
            .join("\n")
    } else if let Some(err) = mcp_response["error"]["message"].as_str() {
        format!("error: {err}")
    } else {
        String::new()
    };

    json!({
        "role": "tool",
        "tool_call_id": tool_call_id,
        "content": content
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── mcp_tools_to_openai ───────────────────────────────────────────────────

    #[test]
    fn converts_mcp_tool_to_openai_format() {
        let mcp = json!({
            "result": {
                "tools": [{
                    "name": "read_file",
                    "description": "Read a file from disk",
                    "inputSchema": {
                        "type": "object",
                        "properties": { "path": { "type": "string" } },
                        "required": ["path"]
                    }
                }]
            }
        });

        let tools = mcp_tools_to_openai(&mcp);
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["type"], "function");
        assert_eq!(tools[0]["function"]["name"], "read_file");
        assert_eq!(tools[0]["function"]["description"], "Read a file from disk");
        assert_eq!(
            tools[0]["function"]["parameters"]["properties"]["path"]["type"],
            "string"
        );
    }

    #[test]
    fn missing_input_schema_defaults_to_empty_object() {
        let mcp = json!({
            "result": {
                "tools": [{ "name": "ping", "description": "Ping" }]
            }
        });

        let tools = mcp_tools_to_openai(&mcp);
        assert_eq!(
            tools[0]["function"]["parameters"],
            json!({"type": "object", "properties": {}})
        );
    }

    #[test]
    fn empty_tools_list_returns_empty_vec() {
        let mcp = json!({ "result": { "tools": [] } });
        assert!(mcp_tools_to_openai(&mcp).is_empty());
    }

    #[test]
    fn malformed_response_returns_empty_vec() {
        assert!(mcp_tools_to_openai(&json!({})).is_empty());
    }

    // ── openai_tool_call_to_mcp ───────────────────────────────────────────────

    #[test]
    fn converts_openai_tool_call_to_mcp_request() {
        let tool_call = json!({
            "id": "call_abc123",
            "type": "function",
            "function": {
                "name": "read_file",
                "arguments": "{\"path\": \"/tmp/test.txt\"}"
            }
        });

        let mcp = openai_tool_call_to_mcp(&tool_call, 42).unwrap();
        assert_eq!(mcp["method"], "tools/call");
        assert_eq!(mcp["id"], 42);
        assert_eq!(mcp["params"]["name"], "read_file");
        assert_eq!(mcp["params"]["arguments"]["path"], "/tmp/test.txt");
    }

    #[test]
    fn invalid_json_arguments_defaults_to_empty_object() {
        let tool_call = json!({
            "id": "call_1",
            "type": "function",
            "function": { "name": "ping", "arguments": "not-json" }
        });

        let mcp = openai_tool_call_to_mcp(&tool_call, 1).unwrap();
        assert_eq!(mcp["params"]["arguments"], json!({}));
    }

    #[test]
    fn missing_function_name_returns_none() {
        let tool_call = json!({ "id": "call_1", "type": "function", "function": {} });
        assert!(openai_tool_call_to_mcp(&tool_call, 1).is_none());
    }

    // ── mcp_result_to_openai ──────────────────────────────────────────────────

    #[test]
    fn converts_mcp_result_to_openai_tool_message() {
        let mcp = json!({
            "result": {
                "content": [{ "type": "text", "text": "file contents here" }]
            }
        });

        let msg = mcp_result_to_openai(&mcp, "call_abc");
        assert_eq!(msg["role"], "tool");
        assert_eq!(msg["tool_call_id"], "call_abc");
        assert_eq!(msg["content"], "file contents here");
    }

    #[test]
    fn mcp_error_becomes_error_string_in_content() {
        let mcp = json!({
            "error": { "code": -32603, "message": "file not found" }
        });

        let msg = mcp_result_to_openai(&mcp, "call_1");
        assert_eq!(msg["content"], "error: file not found");
    }

    #[test]
    fn multiple_content_items_are_joined() {
        let mcp = json!({
            "result": {
                "content": [
                    { "type": "text", "text": "line one" },
                    { "type": "text", "text": "line two" }
                ]
            }
        });

        let msg = mcp_result_to_openai(&mcp, "call_1");
        assert_eq!(msg["content"], "line one\nline two");
    }
}

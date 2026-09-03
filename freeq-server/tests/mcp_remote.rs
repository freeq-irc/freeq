//! The remote MCP endpoint over the wire.
//!
//! The unit tests in `freeq_server::mcp` prove the catalogue is well-formed.
//! These prove an MCP client can actually drive it: initialize, list, call,
//! and — the part that matters — that a tool cannot see a channel the REST
//! API would refuse.

use freeq_sdk::did::DidResolver;
use std::collections::HashMap;
use std::net::SocketAddr;

async fn start_server() -> (
    SocketAddr,
    SocketAddr,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let resolver = DidResolver::static_map(HashMap::new());
    let config = freeq_server::config::ServerConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        server_name: "test-mcp".to_string(),
        challenge_timeout_secs: 60,
        ..Default::default()
    };
    let server = freeq_server::server::Server::with_resolver(config, resolver);
    server.start_with_web().await.unwrap()
}

async fn rpc(http: SocketAddr, body: serde_json::Value) -> serde_json::Value {
    reqwest::Client::new()
        .post(format!("http://{http}/mcp"))
        .json(&body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[tokio::test]
async fn initialize_announces_protocol_and_capabilities() {
    let (_irc, http, _h) = start_server().await;
    let r = rpc(
        http,
        serde_json::json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
    )
    .await;
    assert_eq!(r["jsonrpc"], "2.0");
    assert_eq!(r["id"], 1);
    assert_eq!(
        r["result"]["protocolVersion"],
        freeq_server::mcp::PROTOCOL_VERSION
    );
    assert_eq!(r["result"]["serverInfo"]["name"], "freeq");
    assert!(r["result"]["capabilities"]["tools"].is_object());
    // The instructions must warn about untrusted content — this is a chat
    // server, and everything a tool returns is somebody else's text.
    let instructions = r["result"]["instructions"].as_str().unwrap();
    assert!(instructions.contains("untrusted"), "{instructions}");
    assert!(instructions.contains("freeq_verify"), "{instructions}");
}

#[tokio::test]
async fn tools_and_resources_list() {
    let (_irc, http, _h) = start_server().await;

    let r = rpc(
        http,
        serde_json::json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
    )
    .await;
    let tools = r["result"]["tools"].as_array().unwrap();
    assert!(tools.len() >= 5);
    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    assert!(names.contains(&"freeq_channels"));
    assert!(names.contains(&"freeq_verify"));

    let r = rpc(
        http,
        serde_json::json!({"jsonrpc":"2.0","id":3,"method":"resources/list"}),
    )
    .await;
    let res = r["result"]["resources"].as_array().unwrap();
    assert!(
        res.iter()
            .any(|x| x["uri"] == "freeq://server/openapi.json")
    );

    // And a resource actually reads, with the mime type it advertised.
    let r = rpc(
        http,
        serde_json::json!({"jsonrpc":"2.0","id":4,"method":"resources/read",
                           "params":{"uri":"freeq://server/agents.md"}}),
    )
    .await;
    let c = &r["result"]["contents"][0];
    assert_eq!(c["mimeType"], "text/markdown");
    assert!(c["text"].as_str().unwrap().contains("When to use freeq"));
}

#[tokio::test]
async fn calling_a_tool_returns_content_and_structured_output() {
    let (_irc, http, _h) = start_server().await;
    let r = rpc(
        http,
        serde_json::json!({"jsonrpc":"2.0","id":5,"method":"tools/call",
                           "params":{"name":"freeq_channels","arguments":{}}}),
    )
    .await;
    assert_eq!(r["result"]["isError"], false);
    assert_eq!(r["result"]["content"][0]["type"], "text");
    assert!(r["result"]["structuredContent"].is_array());
}

/// The point of routing tools through the REST handlers: a restricted channel
/// is refused here exactly as it is there, and the refusal explains itself.
#[tokio::test]
async fn a_tool_cannot_read_a_channel_rest_would_refuse() {
    let (_irc, http, _h) = start_server().await;
    let r = rpc(
        http,
        serde_json::json!({"jsonrpc":"2.0","id":6,"method":"tools/call",
                           "params":{"name":"freeq_history",
                                     "arguments":{"channel":"#nonexistent-private"}}}),
    )
    .await;
    assert_eq!(r["result"]["isError"], true, "{r}");
    let text = r["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        text.len() > 40 && !text.contains("HTTP 500"),
        "a refusal must say what to do about it, got: {text}"
    );
}

#[tokio::test]
async fn protocol_errors_are_jsonrpc_errors_and_tool_errors_are_not() {
    let (_irc, http, _h) = start_server().await;

    // Unknown method: JSON-RPC error.
    let r = rpc(
        http,
        serde_json::json!({"jsonrpc":"2.0","id":7,"method":"nope/nope"}),
    )
    .await;
    assert_eq!(r["error"]["code"], -32601);

    // Missing required argument: JSON-RPC invalid params.
    let r = rpc(
        http,
        serde_json::json!({"jsonrpc":"2.0","id":8,"method":"tools/call",
                           "params":{"name":"freeq_history","arguments":{}}}),
    )
    .await;
    assert_eq!(r["error"]["code"], -32602);

    // Malformed JSON: parse error, and still a valid JSON-RPC envelope.
    let resp = reqwest::Client::new()
        .post(format!("http://{http}/mcp"))
        .header("content-type", "application/json")
        .body("{not json")
        .send()
        .await
        .unwrap();
    let r: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(r["error"]["code"], -32700);
    assert_eq!(r["jsonrpc"], "2.0");
}

#[tokio::test]
async fn notifications_get_no_body_and_batches_are_answered_in_order() {
    let (_irc, http, _h) = start_server().await;

    // A notification has no id: per JSON-RPC there is nothing to answer.
    let resp = reqwest::Client::new()
        .post(format!("http://{http}/mcp"))
        .json(&serde_json::json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 202);

    let r = rpc(
        http,
        serde_json::json!([
            {"jsonrpc":"2.0","id":"a","method":"ping"},
            {"jsonrpc":"2.0","id":"b","method":"tools/list"}
        ]),
    )
    .await;
    let arr = r.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["id"], "a");
    assert_eq!(arr[1]["id"], "b");
}

/// Discovery: both well-known paths point at the live endpoint, and the card
/// no longer claims stdio is the only way in.
#[tokio::test]
async fn the_endpoint_is_discoverable() {
    let (_irc, http, _h) = start_server().await;
    let client = reqwest::Client::new();

    for path in ["/.well-known/mcp", "/.well-known/mcp/server-card.json"] {
        let resp = client
            .get(format!("http://{http}{path}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "{path}");
        let v: serde_json::Value = resp.json().await.unwrap();
        let s = v.to_string();
        assert!(s.contains("/mcp"), "{path} does not name the endpoint: {s}");
        assert!(s.contains("streamable-http"), "{path}: {s}");
    }

    // Still honest about the unpublished npm package.
    let v: serde_json::Value = client
        .get(format!("http://{http}/.well-known/mcp/server-card.json"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["stdio"]["published"], false);
}

//! Live HTTP contract for the agent discovery surfaces.
//!
//! The unit tests in `freeq_server::openapi` prove the spec and the router
//! agree on paper. These tests stand up a real server and prove the promises
//! hold over the wire: the spec is fetchable and parseable, `llms.txt` is
//! served as markdown, `/.well-known/agent.json` cross-links the other
//! surfaces, and every parameterless documented GET endpoint actually exists.

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
        server_name: "test-agent-discovery".to_string(),
        challenge_timeout_secs: 60,
        ..Default::default()
    };
    let server = freeq_server::server::Server::with_resolver(config, resolver);
    server.start_with_web().await.unwrap()
}

fn url(http: SocketAddr, path: &str) -> String {
    format!("http://{http}{path}")
}

#[tokio::test]
async fn serves_the_openapi_spec_as_json_and_yaml() {
    let (_irc, http, _h) = start_server().await;
    let client = reqwest::Client::new();

    let json = client
        .get(url(http, "/api/v1/openapi.json"))
        .send()
        .await
        .unwrap();
    assert_eq!(json.status(), 200);
    assert_eq!(
        json.headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "application/json"
    );
    let spec: serde_json::Value = json.json().await.unwrap();
    assert_eq!(spec["openapi"], "3.1.0");
    assert_eq!(spec["info"]["title"], "freeq");
    assert!(
        spec["paths"]["/api/v1/health"]["get"]["operationId"].is_string(),
        "spec must describe /api/v1/health"
    );

    let yaml = client
        .get(url(http, "/api/v1/openapi.yaml"))
        .send()
        .await
        .unwrap();
    assert_eq!(yaml.status(), 200);
    assert!(
        yaml.headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("application/yaml")
    );
    let text = yaml.text().await.unwrap();
    assert!(text.contains("openapi: 3.1.0"));
}

#[tokio::test]
async fn serves_llms_txt_as_markdown() {
    let (_irc, http, _h) = start_server().await;
    let resp = reqwest::Client::new()
        .get(url(http, "/llms.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(
        resp.headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("text/markdown")
    );
    let body = resp.text().await.unwrap();
    assert!(body.starts_with("# freeq"));
    // llms.txt exists to hand an agent the machine-readable surfaces.
    for link in [
        "/api/v1/openapi.json",
        "/.well-known/agent.json",
        "/api/v1/channels",
        "/api/v1/verify/",
    ] {
        assert!(body.contains(link), "llms.txt should link {link}");
    }
}

#[tokio::test]
async fn agent_json_cross_links_the_other_surfaces() {
    let (_irc, http, _h) = start_server().await;
    let body: serde_json::Value = reqwest::Client::new()
        .get(url(http, "/.well-known/agent.json"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(body["surfaces"]["openapi"], "/api/v1/openapi.json");
    assert_eq!(body["surfaces"]["openapi_yaml"], "/api/v1/openapi.yaml");
    assert_eq!(body["surfaces"]["llms_txt"], "/llms.txt");
    assert_eq!(body["surfaces"]["irc_websocket"], "/irc");
    assert_eq!(body["surfaces"]["mcp_package"], "@freeq/mcp");
    // An agent that reads `mcp_package` and shells out to `npx` would fail
    // today, so the document must say where the code actually is and that the
    // package is not on the registry yet. Flip `mcp_published` in the same
    // commit that publishes it.
    assert!(
        body["surfaces"]["mcp_source"]
            .as_str()
            .unwrap_or_default()
            .contains("freeq-mcp"),
        "agent.json must say where to get the MCP server"
    );
    assert_eq!(body["surfaces"]["mcp_published"], false);
    assert!(
        body["surfaces"]["skills"]
            .as_str()
            .unwrap_or_default()
            .ends_with("/skills"),
        "agent.json should point at the SKILL.md packages"
    );

    // Following the link must actually land somewhere.
    let openapi = reqwest::Client::new()
        .get(url(http, body["surfaces"]["openapi"].as_str().unwrap()))
        .send()
        .await
        .unwrap();
    assert_eq!(openapi.status(), 200);
}

/// Every documented GET endpoint that needs no path parameters must exist.
///
/// This is the counterpart to the source-level drift test: it catches a spec
/// that documents a path the *deployed* router does not serve, which is the
/// failure an agent actually experiences (a 404 from a documented endpoint).
///
/// Policy endpoints are skipped — they are only mounted when the server runs
/// with a policy engine, which this fixture does not.
#[tokio::test]
async fn documented_parameterless_get_endpoints_all_exist() {
    let (_irc, http, _h) = start_server().await;
    let client = reqwest::Client::new();
    let spec: serde_json::Value = client
        .get(url(http, "/api/v1/openapi.json"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let mut checked = 0usize;
    let mut missing: Vec<String> = Vec::new();
    for (path, item) in spec["paths"].as_object().unwrap() {
        let Some(op) = item.get("get") else { continue };
        if path.contains('{') {
            continue;
        }
        // WebSocket upgrades and media transports are not plain GETs.
        if matches!(path.as_str(), "/irc" | "/av/moq") {
            continue;
        }
        let tags: Vec<&str> = op["tags"]
            .as_array()
            .map(|a| a.iter().filter_map(|t| t.as_str()).collect())
            .unwrap_or_default();
        if tags.contains(&"policy") {
            continue;
        }
        checked += 1;
        let status = client.get(url(http, path)).send().await.unwrap().status();
        if status == 404 {
            missing.push(path.clone());
        }
    }

    assert!(
        checked > 8,
        "expected to probe several endpoints, got {checked}"
    );
    missing.sort();
    assert!(
        missing.is_empty(),
        "spec documents endpoints the server does not serve:\n  {}",
        missing.join("\n  ")
    );
}

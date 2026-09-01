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

// ── Crawler and agent discovery surfaces ─────────────────────────────────
//
// These assert over the wire what `agent_surfaces` asserts in isolation,
// because the failure that mattered was never in the documents themselves —
// it was the router handing every one of these paths to the SPA fallback.

#[tokio::test]
async fn serves_robots_sitemap_and_the_markdown_documents() {
    let (_irc, http, _h) = start_server().await;
    let client = reqwest::Client::new();

    let robots = client.get(url(http, "/robots.txt")).send().await.unwrap();
    assert_eq!(robots.status(), 200);
    assert!(
        robots
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("text/plain")
    );
    let body = robots.text().await.unwrap();
    assert!(body.contains("Sitemap:"));
    for ua in ["GPTBot", "ClaudeBot", "ora-agent"] {
        assert!(body.contains(ua), "robots.txt must name {ua}");
    }

    let sitemap = client.get(url(http, "/sitemap.xml")).send().await.unwrap();
    assert_eq!(sitemap.status(), 200);
    assert!(
        sitemap
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("xml")
    );
    assert!(sitemap.text().await.unwrap().contains("<lastmod>"));

    for path in ["/agents.md", "/AGENTS.md", "/auth.md", "/index.md"] {
        let resp = client.get(url(http, path)).send().await.unwrap();
        assert_eq!(resp.status(), 200, "{path}");
        assert!(
            resp.headers()
                .get("content-type")
                .unwrap()
                .to_str()
                .unwrap()
                .contains("markdown"),
            "{path} must be served as markdown"
        );
        let body = resp.text().await.unwrap();
        assert!(!body.is_empty(), "{path} is empty");
        // The repository's own AGENTS.md documents production hosts. If this
        // ever starts serving that file, this is the string that says so.
        assert!(!body.contains("deploy.sh"), "{path} leaked internal docs");
    }
}

#[tokio::test]
async fn serves_the_well_known_documents_as_valid_json() {
    let (_irc, http, _h) = start_server().await;
    let client = reqwest::Client::new();

    for path in [
        "/openapi.json",
        "/.well-known/ard.json",
        "/.well-known/ai-catalog.json",
        "/.well-known/agent-card.json",
        "/.well-known/api-catalog",
        "/.well-known/mcp/server-card.json",
        "/.well-known/oauth-protected-resource",
        "/.well-known/http-message-signatures-directory",
    ] {
        let resp = client.get(url(http, path)).send().await.unwrap();
        assert_eq!(resp.status(), 200, "{path}");
        let ctype = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(ctype.contains("json"), "{path} served as {ctype}");
        let body = resp.text().await.unwrap();
        serde_json::from_str::<serde_json::Value>(&body)
            .unwrap_or_else(|e| panic!("{path} is not valid JSON: {e}"));
    }
}

/// The regression this whole module exists for: unknown paths used to answer
/// `200 text/html` with the web client's shell.
#[tokio::test]
async fn unknown_paths_are_a_real_404_with_somewhere_to_go() {
    let (_irc, http, _h) = start_server().await;
    let client = reqwest::Client::new();

    for path in [
        "/this-path-does-not-exist-9f3a",
        "/.well-known/this-does-not-exist-9f3a",
        "/nope.json",
        "/api/v1/definitely-not-a-route",
    ] {
        let resp = client.get(url(http, path)).send().await.unwrap();
        assert_eq!(resp.status(), 404, "{path} must not soft-404");
    }

    let resp = client.get(url(http, "/nope.json")).send().await.unwrap();
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("llms.txt") && body.contains("openapi.json"),
        "a 404 body should tell an agent where to look instead: {body}"
    );
}

/// RFC 8288 on every response, RFC 9728's hint on every 401.
#[tokio::test]
async fn responses_carry_discovery_and_auth_headers() {
    let (_irc, http, _h) = start_server().await;
    let client = reqwest::Client::new();

    let resp = client.get(url(http, "/api/v1/health")).send().await.unwrap();
    let link = resp
        .headers()
        .get("link")
        .expect("every response should carry a Link header")
        .to_str()
        .unwrap()
        .to_string();
    assert!(link.contains("rel=\"service-desc\""));
    assert!(link.contains("/api/v1/openapi.json"));

    // An authenticated endpoint without a token must say where auth is
    // described, rather than leaving the caller to guess.
    let resp = client
        .get(url(http, "/api/v1/sessions"))
        .send()
        .await
        .unwrap();
    if resp.status() == 401 {
        let wa = resp
            .headers()
            .get("www-authenticate")
            .expect("401 must carry WWW-Authenticate")
            .to_str()
            .unwrap()
            .to_string();
        assert!(wa.contains("resource_metadata="), "{wa}");
    }
}

/// The welcome mat: self-service enrollment, and the terms it points at.
#[tokio::test]
async fn serves_the_welcome_mat_and_its_terms() {
    let (_irc, http, _h) = start_server().await;
    let client = reqwest::Client::new();

    let welcome = client
        .get(url(http, "/.well-known/welcome.md"))
        .send()
        .await
        .unwrap();
    assert_eq!(welcome.status(), 200);
    assert!(
        welcome
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("markdown")
    );
    let body = welcome.text().await.unwrap();
    for section in [
        "## requirements",
        "## endpoints",
        "## enrollment flow",
        "## deviations",
    ] {
        assert!(body.contains(section), "welcome.md needs {section}");
    }

    let tos = client.get(url(http, "/tos")).send().await.unwrap();
    assert_eq!(tos.status(), 200);
    assert!(
        tos.headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("text/plain")
    );
    let terms = tos.text().await.unwrap();
    assert!(terms.contains("terms of service"));
    // Every endpoint welcome.md names as part of enrollment must exist on
    // this host, or the document is lying to whoever follows it.
    for path in ["/tos", "/agents.md", "/auth.md", "/api/v1/openapi.json"] {
        let status = client.get(url(http, path)).send().await.unwrap().status();
        assert_eq!(status, 200, "welcome.md promises {path}");
    }
}

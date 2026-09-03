//! Machine-readable descriptions of this server, for agents.
//!
//! Three surfaces, one source of truth:
//!
//! * `spec/openapi.yaml` is the hand-authored OpenAPI 3.1 contract. It is
//!   compiled in with `include_str!`, served verbatim at
//!   `/api/v1/openapi.yaml`, and transcoded once into JSON for
//!   `/api/v1/openapi.json`.
//! * `/llms.txt` is the markdown index an LLM agent reads first.
//! * The [`tests`] module fails the build when the router and the spec
//!   disagree about which paths exist.
//!
//! Why hand-authored rather than generated: `web.rs` handlers mostly return
//! `serde_json::json!` blobs, so annotating ~60 of them for `utoipa` would be
//! a huge invasive diff for a hotspot file. The drift test buys the property
//! that actually matters — the spec cannot silently rot — without touching a
//! single handler.

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

/// The canonical spec, YAML, exactly as checked in.
pub const OPENAPI_YAML: &str = include_str!("../../spec/openapi.yaml");

/// The spec as JSON, transcoded on first request and cached.
///
/// A malformed spec is a programmer error caught by the tests below, so a
/// parse failure here degrades to 500 rather than taking the process down.
static OPENAPI_JSON: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();

pub fn openapi_json_string() -> Option<&'static str> {
    openapi_json_body()
}

fn openapi_json_body() -> Option<&'static str> {
    OPENAPI_JSON
        .get_or_init(|| {
            let value: serde_yaml_ng::Value = serde_yaml_ng::from_str(OPENAPI_YAML)
                .map_err(|e| tracing::error!("spec/openapi.yaml is not valid YAML: {e}"))
                .ok()?;
            serde_json::to_string_pretty(&value)
                .map_err(|e| tracing::error!("spec/openapi.yaml is not representable as JSON: {e}"))
                .ok()
        })
        .as_deref()
}

/// `GET /api/v1/openapi.json`
pub async fn openapi_json() -> Response {
    match openapi_json_body() {
        Some(body) => (
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )],
            body,
        )
            .into_response(),
        None => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "OpenAPI spec failed to load",
        )
            .into_response(),
    }
}

/// `GET /api/v1/openapi.yaml`
pub async fn openapi_yaml() -> Response {
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/yaml"),
        )],
        OPENAPI_YAML,
    )
        .into_response()
}

/// `GET /llms.txt` — the server-side index. Short by design: it says what
/// this host is and points at the machine-readable surfaces plus the docs
/// site, which carries the long-form index.
pub const LLMS_TXT: &str = include_str!("llms.txt");

pub async fn llms_txt() -> Response {
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/markdown; charset=utf-8"),
        )],
        LLMS_TXT,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Router sources scanned for `.route("…")` literals.
    ///
    /// axum 0.8 exposes no way to enumerate a built `Router`'s paths, so the
    /// next best ground truth is the source that registers them.
    const ROUTER_SOURCES: &[(&str, &str)] = &[
        ("web.rs", include_str!("web.rs")),
        ("agent_assist/api.rs", include_str!("agent_assist/api.rs")),
        ("policy/api.rs", include_str!("policy/api.rs")),
    ];

    /// Paths registered in the router but deliberately absent from the spec.
    ///
    /// Only wildcard fallbacks belong here: they are not addressable
    /// endpoints, they are catch-alls that exist to return a *better error*
    /// than the SPA fallback would.
    const UNDOCUMENTED: &[&str] = &["/av/moq/{*path}", "/verify/{*unmounted}"];

    /// Extract every path literal passed to `.route(…)`, tolerating the
    /// multi-line form rustfmt produces for long paths.
    fn router_paths() -> Vec<(&'static str, String)> {
        let mut out = Vec::new();
        for (file, src) in ROUTER_SOURCES {
            let mut rest = *src;
            while let Some(idx) = rest.find(".route(") {
                rest = &rest[idx + ".route(".len()..];
                // Skip whitespace between `(` and the path literal.
                let after_ws = rest.trim_start();
                if !after_ws.starts_with('"') {
                    continue;
                }
                let body = &after_ws[1..];
                if let Some(end) = body.find('"') {
                    out.push((*file, body[..end].to_string()));
                }
            }
        }
        out
    }

    fn spec() -> serde_json::Value {
        let yaml: serde_yaml_ng::Value =
            serde_yaml_ng::from_str(OPENAPI_YAML).expect("spec/openapi.yaml must be valid YAML");
        serde_json::to_value(yaml).expect("spec must be representable as JSON")
    }

    fn spec_paths() -> Vec<String> {
        spec()["paths"]
            .as_object()
            .expect("spec must have a paths object")
            .keys()
            .cloned()
            .collect()
    }

    /// Paths the spec must cover. Static pages and OAuth redirects are
    /// documented too, but these prefixes are the agent-facing contract, so
    /// they are the ones enforced.
    fn is_required(path: &str) -> bool {
        path.starts_with("/api/v1/")
            || path.starts_with("/agent")
            || path == "/.well-known/agent.json"
    }

    #[test]
    fn spec_is_valid_yaml_and_json() {
        let spec = spec();
        assert_eq!(spec["openapi"], "3.1.0");
        assert!(spec["info"]["title"].is_string());
        assert!(openapi_json_body().is_some(), "JSON transcode must succeed");
    }

    #[test]
    fn router_paths_were_found() {
        // Guard against the extractor silently matching nothing (e.g. after a
        // refactor to a different registration style), which would make the
        // drift tests below vacuously pass.
        let paths = router_paths();
        assert!(
            paths.len() > 50,
            "expected to find the router's paths, found {}: {paths:?}",
            paths.len()
        );
        assert!(paths.iter().any(|(_, p)| p == "/api/v1/health"));
    }

    #[test]
    fn every_router_path_is_in_the_spec() {
        let spec_paths = spec_paths();
        let mut missing: Vec<String> = Vec::new();
        for (file, path) in router_paths() {
            if !is_required(&path) || UNDOCUMENTED.contains(&path.as_str()) {
                continue;
            }
            if !spec_paths.contains(&path) {
                missing.push(format!("{path} (registered in {file})"));
            }
        }
        missing.sort();
        missing.dedup();
        assert!(
            missing.is_empty(),
            "these routes exist but are not in spec/openapi.yaml:\n  {}\n\
             Add them to the spec in the same commit that adds the route.",
            missing.join("\n  ")
        );
    }

    #[test]
    fn every_spec_path_is_in_the_router() {
        let registered: Vec<String> = router_paths().into_iter().map(|(_, p)| p).collect();
        // Paths this module itself serves; they are registered in web.rs, but
        // list them explicitly so the test still passes if that registration
        // moves into a merged sub-router.
        let self_served = ["/api/v1/openapi.json", "/api/v1/openapi.yaml", "/llms.txt"];
        let mut stale: Vec<String> = spec_paths()
            .into_iter()
            .filter(|p| !registered.contains(p) && !self_served.contains(&p.as_str()))
            .collect();
        stale.sort();
        assert!(
            stale.is_empty(),
            "spec/openapi.yaml documents paths that no longer exist:\n  {}",
            stale.join("\n  ")
        );
    }

    #[test]
    fn agent_assist_capabilities_match_the_spec() {
        // The discovery document promises a tool per capability; the spec
        // must describe each of those endpoints.
        let spec_paths = spec_paths();
        for cap in crate::agent_assist::api::CAPABILITIES {
            if *cap == "free_form_session" {
                assert!(spec_paths.contains(&"/agent/session".to_string()));
                continue;
            }
            let path = format!("/agent/tools/{cap}");
            assert!(
                spec_paths.contains(&path),
                "capability {cap} advertised by /.well-known/agent.json is not in the spec"
            );
        }
    }

    #[test]
    fn documented_operations_are_uniquely_identified() {
        let spec = spec();
        let mut ids: Vec<String> = Vec::new();
        for (path, item) in spec["paths"].as_object().unwrap() {
            for (method, op) in item.as_object().unwrap() {
                if !["get", "post", "put", "patch", "delete"].contains(&method.as_str()) {
                    continue;
                }
                let id = op["operationId"]
                    .as_str()
                    .unwrap_or_else(|| panic!("{method} {path} has no operationId"))
                    .to_string();
                assert!(
                    !ids.contains(&id),
                    "duplicate operationId {id} ({method} {path})"
                );
                ids.push(id);
            }
        }
        assert!(ids.len() > 50, "expected a documented operation per route");
    }

    #[tokio::test]
    async fn serves_json_yaml_and_llms_txt() {
        let json = openapi_json().await;
        assert_eq!(json.status(), StatusCode::OK);
        assert_eq!(
            json.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );

        let yaml = openapi_yaml().await;
        assert_eq!(
            yaml.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/yaml"
        );

        let llms = llms_txt().await;
        assert_eq!(llms.status(), StatusCode::OK);
        assert!(LLMS_TXT.starts_with("# freeq"));
        // The point of llms.txt is to lead somewhere machine-readable.
        for surface in [
            "/api/v1/openapi.json",
            "/.well-known/agent.json",
            "/api/v1/channels",
        ] {
            assert!(LLMS_TXT.contains(surface), "llms.txt must link {surface}");
        }
    }
}

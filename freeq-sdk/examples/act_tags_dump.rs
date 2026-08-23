//! Print the tags and the line each task event carries, so the two SDKs can be
//! compared.
//!
//! Reads a list of cases as JSON on stdin — a kind, a verb, the action it
//! names, the actor and its fields — and writes what `act_tags` and `act_line`
//! make of each to stdout. `scripts/compare-act-tags.mjs` feeds the same list
//! through the TypeScript `actTags` and `actLine` and compares the answers key
//! by key. Two SDKs are interchangeable only if they write the same document,
//! and only the document decides whether a signature verifies.
//!
//! Usage:
//!   cat cases.json | cargo run -q -p freeq-sdk --example act_tags_dump
//!
//! Nothing is signed and nothing connects: what a case produces here is the
//! covered half of a document, before an id or a venue is attached to it.

use std::collections::HashMap;
use std::io::Read;

use freeq_sdk::act::{act_line, act_tags};
use serde_json::Value;

fn main() {
    let mut raw = String::new();
    std::io::stdin()
        .read_to_string(&mut raw)
        .expect("the case list arrives on stdin");
    let cases: Vec<Value> = serde_json::from_str(&raw).expect("the case list parses");

    let mut out: HashMap<String, Value> = HashMap::new();
    for case in &cases {
        let name = case["name"].as_str().expect("every case is named");
        let kind = case["kind"].as_str().expect("every case names its kind");
        let verb = case["verb"].as_str().expect("every case names its verb");
        let from = case["from"].as_str().expect("every case names its actor");
        let task = case.get("task").and_then(Value::as_str);
        // Ordered, so the two languages are compared over the same list rather
        // than over whatever order a map happened to hand up.
        let mut fields: Vec<(String, String)> = case
            .get("fields")
            .and_then(Value::as_object)
            .map(|f| {
                f.iter()
                    .map(|(k, v)| {
                        (
                            k.clone(),
                            v.as_str().expect("a field's value is a string").to_string(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        fields.sort();
        let borrowed: Vec<(&str, &str)> = fields
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        out.insert(
            name.to_string(),
            serde_json::json!({
                "tags": act_tags(kind, verb, task, from, &borrowed),
                "line": act_line(kind, verb, &borrowed),
            }),
        );
    }
    println!(
        "{}",
        serde_json::to_string(&out).expect("tag maps serialize")
    );
}

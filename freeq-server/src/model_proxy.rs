//! Metered model access: the last mile where authority becomes spend.
//!
//! freeq could already *describe* a loan of capacity — a channel budget with a
//! named sponsor, limits that follow the delegation chain, signed spend reports —
//! but not *make* one. An agent called a model with its own credential and then
//! told freeq what it claimed to have cost. The budget system was metered and
//! unmediated; the one path that held a provider key was mediated and unmetered.
//!
//! This module joins them. The server holds the provider credential, the caller
//! authenticates as a DID, the budget is checked *before* the upstream call, the
//! cost is computed from the provider's own token counts rather than the caller's
//! say-so, and the spend is recorded against the sponsor's budget.
//!
//! Two consequences worth naming. A refusal here is a real limit: no call is made,
//! so no money is spent, which is a different thing from asking a cooperating agent
//! to stop. And the caller never sees the credential, so a loan can be withdrawn by
//! changing a budget rather than by rotating a key.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Price per 1,000 tokens, input and output, in the budget's unit.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ModelPrice {
    pub input_per_1k: f64,
    pub output_per_1k: f64,
}

/// An unpriced model is expensive, never free. `Default` exists only so the config
/// struct can derive its own, and a zero default here would be the one value that
/// turns an unknown model into unlimited capacity.
impl Default for ModelPrice {
    fn default() -> Self {
        Self {
            input_per_1k: 5.0,
            output_per_1k: 15.0,
        }
    }
}

/// What the provider said the call actually used.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Usage {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
}

/// The cost of a call, from the provider's token counts and a price table.
///
/// Unknown models fall back to `default_price` rather than costing nothing: a model
/// nobody priced is the case most likely to be abused, so it must not be free.
pub fn price(
    prices: &HashMap<String, ModelPrice>,
    default_price: ModelPrice,
    model: &str,
    usage: Usage,
) -> f64 {
    let p = prices.get(model).copied().unwrap_or(default_price);
    (usage.prompt_tokens as f64 / 1000.0) * p.input_per_1k
        + (usage.completion_tokens as f64 / 1000.0) * p.output_per_1k
}

/// Why a call was refused before it was made.
#[derive(Debug, Clone, PartialEq)]
pub enum Refusal {
    /// No budget authorises this caller in this channel.
    NoBudget,
    /// The budget is spent and its limit is enforced.
    BudgetExhausted {
        spent: f64,
        limit: f64,
        unit: String,
    },
    /// A single call priced above the whole remaining budget.
    WouldExceed { estimate: f64, remaining: f64 },
}

/// The decision taken before spending someone else's capacity.
#[derive(Debug, Clone, PartialEq)]
pub enum Gate {
    Allow { remaining: f64, warn: bool },
    Refuse(Refusal),
}

/// Whether to make the upstream call at all.
///
/// A soft budget (`hard_limit = false`) warns and allows: it is a reporting tool,
/// and pretending otherwise would make `hard` meaningless. A hard budget refuses,
/// and refusing here is the whole point of the module — the call is never made.
pub fn gate(
    budget: Option<&crate::policy::types::BudgetPolicy>,
    spent: f64,
    estimate: f64,
) -> Gate {
    let Some(b) = budget else {
        return Gate::Refuse(Refusal::NoBudget);
    };
    let remaining = b.max_amount - spent;
    let warn = spent >= b.max_amount * b.warn_threshold;

    if !b.hard_limit {
        return Gate::Allow { remaining, warn };
    }
    if spent >= b.max_amount {
        return Gate::Refuse(Refusal::BudgetExhausted {
            spent,
            limit: b.max_amount,
            unit: b.unit.clone(),
        });
    }
    if estimate > remaining {
        return Gate::Refuse(Refusal::WouldExceed {
            estimate,
            remaining,
        });
    }
    Gate::Allow { remaining, warn }
}

/// A conservative pre-call cost estimate.
///
/// The real cost isn't known until the provider answers, so the gate needs a guess,
/// and the guess must not be optimistic or the last call before a limit could
/// overshoot it by an unbounded amount. `max_tokens` is treated as all-output
/// (the expensive direction) and the prompt is billed as given.
pub fn estimate(
    prices: &HashMap<String, ModelPrice>,
    default_price: ModelPrice,
    model: &str,
    prompt_tokens: u64,
    max_tokens: u64,
) -> f64 {
    price(
        prices,
        default_price,
        model,
        Usage {
            prompt_tokens,
            completion_tokens: max_tokens,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::types::{BudgetPeriod, BudgetPolicy};

    fn budget(max: f64, hard: bool) -> BudgetPolicy {
        BudgetPolicy {
            unit: "usd".into(),
            max_amount: max,
            period: BudgetPeriod::PerDay,
            sponsor_did: "did:plc:sponsor".into(),
            warn_threshold: 0.8,
            hard_limit: hard,
            approval_threshold: None,
        }
    }

    fn prices() -> HashMap<String, ModelPrice> {
        let mut m = HashMap::new();
        m.insert(
            "gpt-4o-mini".to_string(),
            ModelPrice {
                input_per_1k: 0.15,
                output_per_1k: 0.60,
            },
        );
        m
    }

    const FALLBACK: ModelPrice = ModelPrice {
        input_per_1k: 1.0,
        output_per_1k: 3.0,
    };

    #[test]
    fn cost_comes_from_the_providers_token_counts() {
        let c = price(
            &prices(),
            FALLBACK,
            "gpt-4o-mini",
            Usage {
                prompt_tokens: 2000,
                completion_tokens: 1000,
            },
        );
        // 2 × 0.15 + 1 × 0.60
        assert!((c - 0.90).abs() < 1e-9, "got {c}");
    }

    #[test]
    fn an_unpriced_model_is_not_free() {
        // The case most likely to be abused: ask for a model nobody priced and get
        // unlimited capacity. It falls back to the default price instead.
        let c = price(
            &prices(),
            FALLBACK,
            "some-new-model",
            Usage {
                prompt_tokens: 1000,
                completion_tokens: 1000,
            },
        );
        assert!((c - 4.0).abs() < 1e-9, "got {c}");
    }

    #[test]
    fn no_budget_means_no_call() {
        // Fail closed. Spending someone's capacity requires them to have authorised
        // an amount, so the absence of a budget is a refusal and not a blank cheque.
        assert_eq!(gate(None, 0.0, 0.01), Gate::Refuse(Refusal::NoBudget));
    }

    #[test]
    fn a_hard_budget_refuses_before_the_call_is_made() {
        let b = budget(10.0, true);
        match gate(Some(&b), 10.0, 0.01) {
            Gate::Refuse(Refusal::BudgetExhausted { spent, limit, .. }) => {
                assert_eq!((spent, limit), (10.0, 10.0));
            }
            other => panic!("expected refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_call_priced_above_the_remainder_is_refused() {
        // Otherwise the last call before the ceiling could overshoot it without
        // limit, which would make the limit advisory again.
        let b = budget(10.0, true);
        match gate(Some(&b), 9.95, 0.50) {
            Gate::Refuse(Refusal::WouldExceed {
                estimate,
                remaining,
            }) => {
                assert!((estimate - 0.50).abs() < 1e-9);
                assert!((remaining - 0.05).abs() < 1e-9);
            }
            other => panic!("expected refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_soft_budget_warns_and_allows() {
        // `hard=false` is a reporting tool by construction. Blocking on it would
        // make the distinction between soft and hard meaningless.
        let b = budget(10.0, false);
        assert_eq!(
            gate(Some(&b), 50.0, 1.0),
            Gate::Allow {
                remaining: -40.0,
                warn: true
            }
        );
    }

    #[test]
    fn the_warning_threshold_is_reported_before_the_limit_is_hit() {
        let b = budget(10.0, true);
        assert_eq!(
            gate(Some(&b), 8.0, 0.01),
            Gate::Allow {
                remaining: 2.0,
                warn: true
            }
        );
        assert_eq!(
            gate(Some(&b), 1.0, 0.01),
            Gate::Allow {
                remaining: 9.0,
                warn: false
            }
        );
    }

    #[test]
    fn the_estimate_bills_max_tokens_as_output() {
        // Pre-call guesses must not be optimistic, so the cheap direction (input)
        // is not assumed for tokens we cannot yet count.
        let e = estimate(&prices(), FALLBACK, "gpt-4o-mini", 1000, 1000);
        assert!((e - 0.75).abs() < 1e-9, "got {e}");
    }

    #[test]
    fn an_exhausted_soft_budget_still_reports_negative_headroom() {
        let b = budget(5.0, false);
        match gate(Some(&b), 7.5, 0.0) {
            Gate::Allow { remaining, warn } => {
                assert!(remaining < 0.0);
                assert!(warn);
            }
            other => panic!("soft budgets allow, got {other:?}"),
        }
    }
}

// ── HTTP: the mediated, metered path ──────────────────────────────────────────

use crate::server::SharedState;
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use std::sync::Arc;

/// `POST /api/v1/model/chat/completions`
///
/// An OpenAI-compatible call made *by the server*, charged to a channel budget.
/// The caller authenticates as a DID and never sees the provider credential, so
/// withdrawing a loan of capacity means editing a budget rather than rotating a key.
pub async fn chat_completions(
    State(state): State<Arc<SharedState>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    fn err(code: StatusCode, msg: &str) -> axum::response::Response {
        (code, Json(serde_json::json!({ "error": msg }))).into_response()
    }

    // 1. Who is asking. A session bearer resolves to the DID that authenticated it.
    let Some(did) = crate::web::caller_did_from_bearer(&state, &headers) else {
        return err(StatusCode::UNAUTHORIZED, "authenticate first");
    };

    // 2. Whose budget. Named explicitly: a caller in several channels must say which
    //    loan it is drawing on rather than have the server pick the most generous.
    let Some(channel) = body.get("channel").and_then(|c| c.as_str()) else {
        return err(StatusCode::BAD_REQUEST, "channel required");
    };
    let channel = channel.to_lowercase();

    // 3. Membership. A budget funds work in a room, so being in the room is the
    //    minimum claim on it. Without this any authenticated DID could drain any
    //    channel's capacity by naming it.
    let is_member = {
        let sessions: Vec<String> = state
            .session_dids
            .lock()
            .iter()
            .filter(|(_, d)| *d == &did)
            .map(|(s, _)| s.clone())
            .collect();
        let channels = state.channels.lock();
        channels
            .get(&channel)
            .map(|ch| sessions.iter().any(|s| ch.members.contains(s)))
            .unwrap_or(false)
    };
    if !is_member {
        return err(StatusCode::FORBIDDEN, "not in that channel");
    }

    // 4. Which budget applies, and what has been spent against it this period.
    let budget = state
        .with_db(|db| Ok(db.get_budget_inherited(&channel, &did)))
        .flatten()
        .and_then(|bj| serde_json::from_str::<crate::policy::types::BudgetPolicy>(&bj).ok());

    let (spent, owner) = match &budget {
        Some(b) => {
            let period_start = crate::connection::budget_period_start(&b.period);
            let owner = state
                .with_db(|db| Ok(db.budget_owner_for(&channel, &did)))
                .flatten()
                .unwrap_or_else(|| did.clone());
            let spent = state
                .with_db(|db| {
                    Ok(db.sum_spend_with_descendants(&channel, &owner, &b.unit, period_start))
                })
                .unwrap_or(0.0);
            (spent, owner)
        }
        None => (0.0, did.clone()),
    };

    // 5. Decide before spending. A refusal here means no upstream call happens, so
    //    it is a limit rather than a request to stop.
    let model = body
        .get("model")
        .and_then(|m| m.as_str())
        .or(state.config.llm_model.as_deref())
        .unwrap_or("gpt-4o-mini")
        .to_string();
    let prices = state.config.model_prices.clone();
    let fallback = state.config.model_price_default;
    let prompt_guess = approx_prompt_tokens(&body);
    let max_tokens = body
        .get("max_tokens")
        .and_then(|m| m.as_u64())
        .unwrap_or(1024);
    let est = estimate(&prices, fallback, &model, prompt_guess, max_tokens);

    match gate(budget.as_ref(), spent, est) {
        Gate::Refuse(r) => {
            let (msg, detail) = match &r {
                Refusal::NoBudget => (
                    "no budget authorises this channel".to_string(),
                    serde_json::json!({ "reason": "no_budget" }),
                ),
                Refusal::BudgetExhausted { spent, limit, unit } => (
                    format!("budget exhausted: {spent:.4}/{limit:.2} {unit}"),
                    serde_json::json!({
                        "reason": "budget_exhausted",
                        "spent": spent, "limit": limit, "unit": unit
                    }),
                ),
                Refusal::WouldExceed {
                    estimate,
                    remaining,
                } => (
                    format!("call would exceed remaining budget ({estimate:.4} > {remaining:.4})"),
                    serde_json::json!({
                        "reason": "would_exceed",
                        "estimate": estimate, "remaining": remaining
                    }),
                ),
            };
            tracing::info!(
                did = %did, channel = %channel, model = %model, ?r,
                "Model call refused before dispatch"
            );
            (
                StatusCode::PAYMENT_REQUIRED,
                Json(serde_json::json!({ "error": msg, "detail": detail })),
            )
                .into_response()
        }
        Gate::Allow { remaining, warn } => {
            let Some(api_key) = state.config.llm_api_key.clone() else {
                return err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "no provider credential configured",
                );
            };
            let base = state
                .config
                .llm_base_url
                .clone()
                .unwrap_or_else(|| "https://api.openai.com/v1".to_string());

            // Strip freeq's own field before forwarding.
            let mut upstream_body = body.clone();
            if let Some(obj) = upstream_body.as_object_mut() {
                obj.remove("channel");
                obj.insert("model".into(), serde_json::json!(model.clone()));
            }

            let client = reqwest::Client::new();
            let resp = client
                .post(format!("{}/chat/completions", base.trim_end_matches('/')))
                .bearer_auth(api_key)
                .json(&upstream_body)
                .timeout(std::time::Duration::from_secs(
                    state.config.llm_timeout_secs.max(5),
                ))
                .send()
                .await;

            let resp = match resp {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(error = %e, "Upstream model call failed");
                    return err(StatusCode::BAD_GATEWAY, "upstream model call failed");
                }
            };
            let status = resp.status();
            let payload: serde_json::Value = match resp.json().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "Upstream returned unparseable body");
                    return err(StatusCode::BAD_GATEWAY, "upstream returned no JSON");
                }
            };
            if !status.is_success() {
                // Nothing was produced, so nothing is charged.
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({ "error": "upstream error", "upstream": payload })),
                )
                    .into_response();
            }

            // 6. Meter from the provider's own counts, not the caller's claim.
            let usage = Usage {
                prompt_tokens: payload["usage"]["prompt_tokens"].as_u64().unwrap_or(0),
                completion_tokens: payload["usage"]["completion_tokens"].as_u64().unwrap_or(0),
            };
            let unit = budget.as_ref().map(|b| b.unit.clone()).unwrap_or_default();
            let cost = price(&prices, fallback, &model, usage);
            let desc = format!(
                "{model}:{}in/{}out",
                usage.prompt_tokens, usage.completion_tokens
            );
            let task = body.get("task").and_then(|t| t.as_str());
            state.with_db(|db| db.record_spend(&channel, &did, cost, &unit, Some(&desc), task));

            tracing::info!(
                did = %did, channel = %channel, sponsor = %owner, model = %model,
                cost, unit = %unit, prompt = usage.prompt_tokens,
                completion = usage.completion_tokens,
                "Metered model call charged to a budget"
            );

            let mut out = payload;
            if let Some(obj) = out.as_object_mut() {
                obj.insert(
                    "freeq".into(),
                    serde_json::json!({
                        "charged": cost,
                        "unit": unit,
                        "channel": channel,
                        "sponsor": owner,
                        "spent_after": spent + cost,
                        "remaining_before": remaining,
                        "warn": warn,
                    }),
                );
            }
            (StatusCode::OK, Json(out)).into_response()
        }
    }
}

/// A rough prompt-token count for the pre-call estimate.
///
/// Deliberately crude and deliberately not an underestimate: four characters per
/// token is the usual rule of thumb, and the gate only needs a number that keeps the
/// final call from overshooting a hard limit.
fn approx_prompt_tokens(body: &serde_json::Value) -> u64 {
    let chars: usize = body["messages"]
        .as_array()
        .map(|msgs| {
            msgs.iter()
                .filter_map(|m| m["content"].as_str())
                .map(|c| c.len())
                .sum()
        })
        .unwrap_or(0);
    (chars as u64) / 4 + 8
}

/// Parse `--model-price MODEL=IN,OUT` into a price table.
///
/// Malformed entries are dropped with a warning rather than defaulting to zero: a
/// typo in a price flag must not silently make a model free.
pub fn parse_price_args(args: &[String]) -> HashMap<String, ModelPrice> {
    let mut out = HashMap::new();
    for a in args {
        let Some((model, rates)) = a.split_once('=') else {
            tracing::warn!(arg = %a, "Ignoring --model-price without '='");
            continue;
        };
        let Some((i, o)) = rates.split_once(',') else {
            tracing::warn!(arg = %a, "Ignoring --model-price without 'input,output'");
            continue;
        };
        match (i.trim().parse::<f64>(), o.trim().parse::<f64>()) {
            (Ok(input_per_1k), Ok(output_per_1k))
                if input_per_1k >= 0.0 && output_per_1k >= 0.0 =>
            {
                out.insert(
                    model.trim().to_string(),
                    ModelPrice {
                        input_per_1k,
                        output_per_1k,
                    },
                );
            }
            _ => tracing::warn!(arg = %a, "Ignoring --model-price with unparseable rates"),
        }
    }
    out
}

#[cfg(test)]
mod price_arg_tests {
    use super::*;

    #[test]
    fn a_price_flag_parses() {
        let m = parse_price_args(&["gpt-4o-mini=0.15,0.60".to_string()]);
        assert_eq!(
            m.get("gpt-4o-mini"),
            Some(&ModelPrice {
                input_per_1k: 0.15,
                output_per_1k: 0.60
            })
        );
    }

    #[test]
    fn a_typo_does_not_make_a_model_free() {
        // The failure mode that matters: "gpt-4o=free" or a missing comma must not
        // register a zero price, or a fat-fingered flag becomes unlimited capacity.
        for bad in [
            "gpt-4o",
            "gpt-4o=",
            "gpt-4o=0.15",
            "gpt-4o=abc,def",
            "gpt-4o=-1,2",
        ] {
            assert!(
                parse_price_args(&[bad.to_string()]).is_empty(),
                "accepted {bad}"
            );
        }
    }

    #[test]
    fn several_models_can_be_priced() {
        let m = parse_price_args(&["a=1,2".to_string(), "b=3,4".to_string(), "junk".to_string()]);
        assert_eq!(m.len(), 2);
    }
}

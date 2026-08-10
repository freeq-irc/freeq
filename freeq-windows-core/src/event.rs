//! SDK Event → DomainEvent conversion with JSON serialization.

use serde::Serialize;
use std::collections::HashMap;

/// A member in a channel NAMES list.
#[derive(Debug, Clone, Serialize)]
pub struct MemberInfo {
    pub nick: String,
    pub is_op: bool,
    pub is_halfop: bool,
    pub is_voiced: bool,
}

/// An IRC message with parsed tag metadata.
#[derive(Debug, Clone, Serialize)]
pub struct MessageData {
    pub from_nick: String,
    pub target: String,
    pub text: String,
    pub msgid: Option<String>,
    pub reply_to: Option<String>,
    pub edit_of: Option<String>,
    pub batch_id: Option<String>,
    pub is_action: bool,
    pub timestamp_ms: i64,
}

/// A tag-only message (TAGMSG).
#[derive(Debug, Clone, Serialize)]
pub struct TagMsgData {
    pub from: String,
    pub target: String,
    pub tags: HashMap<String, String>,
}

/// Channel topic information.
#[derive(Debug, Clone, Serialize)]
pub struct TopicData {
    pub channel: String,
    pub text: String,
    pub set_by: Option<String>,
}

/// Domain events emitted to the C# layer via JSON callback.
///
/// Serialized with `#[serde(tag = "type", content = "data")]` so the C# side
/// can switch on `type` and deserialize `data` accordingly.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum DomainEvent {
    Connected,
    Registered {
        nick: String,
    },
    Authenticated {
        did: String,
    },
    AuthFailed {
        reason: String,
    },
    Joined {
        channel: String,
        nick: String,
    },
    Parted {
        channel: String,
        nick: String,
    },
    Message(MessageData),
    TagMsg(TagMsgData),
    Names {
        channel: String,
        members: Vec<MemberInfo>,
    },
    TopicChanged(TopicData),
    ModeChanged {
        channel: String,
        mode: String,
        arg: Option<String>,
        set_by: String,
    },
    Kicked {
        channel: String,
        nick: String,
        by: String,
        reason: String,
    },
    NickChanged {
        old_nick: String,
        new_nick: String,
    },
    AwayChanged {
        nick: String,
        away_msg: Option<String>,
    },
    UserQuit {
        nick: String,
        reason: String,
    },
    BatchStart {
        id: String,
        batch_type: String,
        target: String,
    },
    BatchEnd {
        id: String,
    },
    Notice {
        text: String,
    },
    Disconnected {
        reason: String,
    },
}

/// Convert an SDK event into a DomainEvent suitable for JSON serialization.
pub fn convert_event(event: &freeq_sdk::event::Event) -> DomainEvent {
    use freeq_sdk::event::Event;
    match event {
        Event::Connected => DomainEvent::Connected,
        Event::Registered { nick } => DomainEvent::Registered { nick: nick.clone() },
        Event::Authenticated { did } => DomainEvent::Authenticated { did: did.clone() },
        Event::AuthFailed { reason } => DomainEvent::AuthFailed {
            reason: reason.clone(),
        },
        Event::Joined { channel, nick, .. } => DomainEvent::Joined {
            channel: channel.clone(),
            nick: nick.clone(),
        },
        Event::Parted { channel, nick } => DomainEvent::Parted {
            channel: channel.clone(),
            nick: nick.clone(),
        },
        Event::Message {
            from,
            target,
            text,
            tags, .. } => {
            let msgid = tags.get("msgid").cloned();
            let reply_to = tags.get("+reply").cloned();
            let edit_of = tags.get("+draft/edit").cloned();
            let batch_id = tags.get("batch").cloned();
            let is_action = text.starts_with("\x01ACTION ") && text.ends_with('\x01');
            let clean_text = if is_action {
                text.trim_start_matches("\x01ACTION ")
                    .trim_end_matches('\x01')
                    .to_string()
            } else {
                text.clone()
            };
            let ts = tags
                .get("time")
                .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
                .map(|dt: chrono::DateTime<chrono::FixedOffset>| dt.timestamp_millis())
                .unwrap_or_else(|| chrono::Utc::now().timestamp_millis());
            DomainEvent::Message(MessageData {
                from_nick: from.clone(),
                target: target.clone(),
                text: clean_text,
                msgid,
                reply_to,
                edit_of,
                batch_id,
                is_action,
                timestamp_ms: ts,
            })
        }
        Event::TagMsg { from, target, tags, .. } => DomainEvent::TagMsg(TagMsgData {
            from: from.clone(),
            target: target.clone(),
            tags: tags.clone(),
        }),
        Event::Names { channel, nicks } => {
            let members = nicks
                .iter()
                .map(|n| {
                    let (is_op, is_halfop, is_voiced, nick) =
                        if let Some(rest) = n.strip_prefix('@') {
                            (true, false, false, rest.to_string())
                        } else if let Some(rest) = n.strip_prefix('%') {
                            (false, true, false, rest.to_string())
                        } else if let Some(rest) = n.strip_prefix('+') {
                            (false, false, true, rest.to_string())
                        } else {
                            (false, false, false, n.clone())
                        };
                    MemberInfo {
                        nick,
                        is_op,
                        is_halfop,
                        is_voiced,
                    }
                })
                .collect();
            DomainEvent::Names {
                channel: channel.clone(),
                members,
            }
        }
        Event::NamesEnd { .. } => DomainEvent::Notice {
            text: String::new(),
        },
        Event::TopicChanged {
            channel,
            topic,
            set_by,
        } => DomainEvent::TopicChanged(TopicData {
            channel: channel.clone(),
            text: topic.clone(),
            set_by: set_by.clone(),
        }),
        Event::ModeChanged {
            channel,
            mode,
            arg,
            set_by,
        } => DomainEvent::ModeChanged {
            channel: channel.clone(),
            mode: mode.clone(),
            arg: arg.clone(),
            set_by: set_by.clone(),
        },
        Event::Kicked {
            channel,
            nick,
            by,
            reason,
        } => DomainEvent::Kicked {
            channel: channel.clone(),
            nick: nick.clone(),
            by: by.clone(),
            reason: reason.clone(),
        },
        Event::NickChanged { old_nick, new_nick } => DomainEvent::NickChanged {
            old_nick: old_nick.clone(),
            new_nick: new_nick.clone(),
        },
        Event::AwayChanged { nick, away_msg } => DomainEvent::AwayChanged {
            nick: nick.clone(),
            away_msg: away_msg.clone(),
        },
        Event::UserQuit { nick, reason } => DomainEvent::UserQuit {
            nick: nick.clone(),
            reason: reason.clone(),
        },
        Event::BatchStart {
            id,
            batch_type,
            target,
        } => DomainEvent::BatchStart {
            id: id.clone(),
            batch_type: batch_type.clone(),
            target: target.clone(),
        },
        Event::BatchEnd { id } => DomainEvent::BatchEnd { id: id.clone() },
        Event::ServerNotice { text } => DomainEvent::Notice { text: text.clone() },
        Event::Disconnected { reason } => DomainEvent::Disconnected {
            reason: reason.clone(),
        },
        Event::Invited { channel, by } => DomainEvent::Notice {
            text: format!("{by} invited you to {channel}"),
        },
        Event::WhoisReply { nick, info } => DomainEvent::Notice {
            text: format!("WHOIS {nick}: {info}"),
        },
        // Nothing here waits on a WHOIS being complete, and a notice saying
        // the server stopped talking would be noise in the buffer. Empty
        // notice, the same way MemberDid is passed over below.
        Event::WhoisEnd { .. } => DomainEvent::Notice {
            text: String::new(),
        },
        Event::ChatHistoryTarget { nick, timestamp, .. } => DomainEvent::Notice {
            text: format!("DM: {nick} (last: {})", timestamp.as_deref().unwrap_or("?")),
        },
        Event::ReadMarker { target, timestamp } => DomainEvent::Notice {
            text: format!(
                "read marker: {target} (up to: {})",
                timestamp.as_deref().unwrap_or("*")
            ),
        },
        Event::RawLine(line) => DomainEvent::Notice { text: line.clone() },
        // Nick<->DID binding learned. Not yet modeled as a DomainEvent —
        // adopted in the Windows DID-DM pass; inert empty notice until then.
        Event::MemberDid { .. } => DomainEvent::Notice { text: String::new() },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_convert_simple_message() {
        let mut tags = HashMap::new();
        tags.insert("msgid".to_string(), "abc123".to_string());
        tags.insert("time".to_string(), "2025-01-01T00:00:00.000Z".to_string());

        let event = freeq_sdk::event::Event::Message {
            from: "alice".to_string(),
            target: "#test".to_string(),
            text: "hello world".to_string(),
            tags,
            dm_key: None,
        };

        let domain = convert_event(&event);
        let json = serde_json::to_value(&domain).unwrap();
        assert_eq!(json["type"], "message");
        let data = &json["data"];
        assert_eq!(data["from_nick"], "alice");
        assert_eq!(data["target"], "#test");
        assert_eq!(data["text"], "hello world");
        assert_eq!(data["msgid"], "abc123");
        assert!(!data["is_action"].as_bool().unwrap());
    }

    #[test]
    fn test_convert_action_message() {
        let event = freeq_sdk::event::Event::Message {
            from: "bob".to_string(),
            target: "#test".to_string(),
            text: "\x01ACTION waves\x01".to_string(),
            tags: HashMap::new(),
            dm_key: None,
        };

        let domain = convert_event(&event);
        let json = serde_json::to_value(&domain).unwrap();
        let data = &json["data"];
        assert_eq!(data["text"], "waves");
        assert!(data["is_action"].as_bool().unwrap());
    }

    #[test]
    fn test_convert_names_with_prefixes() {
        let event = freeq_sdk::event::Event::Names {
            channel: "#test".to_string(),
            nicks: vec![
                "@op_user".to_string(),
                "%halfop_user".to_string(),
                "+voiced_user".to_string(),
                "regular_user".to_string(),
            ],
        };

        let domain = convert_event(&event);
        let json = serde_json::to_value(&domain).unwrap();
        assert_eq!(json["type"], "names");
        let members = json["data"]["members"].as_array().unwrap();
        assert_eq!(members[0]["nick"], "op_user");
        assert!(members[0]["is_op"].as_bool().unwrap());
        assert_eq!(members[1]["nick"], "halfop_user");
        assert!(members[1]["is_halfop"].as_bool().unwrap());
        assert_eq!(members[2]["nick"], "voiced_user");
        assert!(members[2]["is_voiced"].as_bool().unwrap());
        assert_eq!(members[3]["nick"], "regular_user");
        assert!(!members[3]["is_op"].as_bool().unwrap());
    }

    #[test]
    fn test_convert_connected() {
        let event = freeq_sdk::event::Event::Connected;
        let domain = convert_event(&event);
        let json = serde_json::to_value(&domain).unwrap();
        assert_eq!(json["type"], "connected");
    }

    #[test]
    fn test_convert_disconnected() {
        let event = freeq_sdk::event::Event::Disconnected {
            reason: "timeout".to_string(),
        };
        let domain = convert_event(&event);
        let json = serde_json::to_value(&domain).unwrap();
        assert_eq!(json["type"], "disconnected");
        assert_eq!(json["data"]["reason"], "timeout");
    }

    #[test]
    fn test_convert_message_with_edit_tag() {
        let mut tags = HashMap::new();
        tags.insert("msgid".to_string(), "new123".to_string());
        tags.insert("+draft/edit".to_string(), "old456".to_string());

        let event = freeq_sdk::event::Event::Message {
            from: "alice".to_string(),
            target: "#test".to_string(),
            text: "edited text".to_string(),
            tags,
            dm_key: None,
        };

        let domain = convert_event(&event);
        let json = serde_json::to_value(&domain).unwrap();
        let data = &json["data"];
        assert_eq!(data["edit_of"], "old456");
        assert_eq!(data["msgid"], "new123");
    }

    #[test]
    fn test_convert_invited() {
        let event = freeq_sdk::event::Event::Invited {
            channel: "#secret".to_string(),
            by: "admin".to_string(),
        };
        let domain = convert_event(&event);
        let json = serde_json::to_value(&domain).unwrap();
        assert_eq!(json["type"], "notice");
        assert!(json["data"]["text"]
            .as_str()
            .unwrap()
            .contains("invited you to"));
    }
}

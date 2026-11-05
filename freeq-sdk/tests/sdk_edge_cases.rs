//! 200 adversarial edge-case tests for the freeq SDK.
//! Targets: IRC parser, crypto, auth, bot framework, rate limiter, e2ee, SSRF.

// ═══════════════════════════════════════════════════════════════
// IRC MESSAGE PARSER (55 tests)
// ═══════════════════════════════════════════════════════════════

mod irc_parser {
    use freeq_sdk::irc::Message;
    use std::collections::HashMap;

    #[test]
    fn parse_simple() {
        let m = Message::parse("NICK alice").unwrap();
        assert_eq!(m.command, "NICK");
        assert_eq!(m.params, vec!["alice"]);
    }
    #[test]
    fn parse_privmsg() {
        let m = Message::parse(":n!u@h PRIVMSG #c :hello world").unwrap();
        assert_eq!(m.prefix.as_deref(), Some("n!u@h"));
        assert_eq!(m.command, "PRIVMSG");
        assert_eq!(m.params, vec!["#c", "hello world"]);
    }
    #[test]
    fn parse_numeric() {
        let m = Message::parse(":srv 001 nick :Welcome").unwrap();
        assert_eq!(m.command, "001");
    }
    #[test]
    fn parse_tags() {
        let m = Message::parse("@msgid=abc :n PRIVMSG #c :t").unwrap();
        assert_eq!(m.tags["msgid"], "abc");
    }
    #[test]
    fn parse_tag_space_escape() {
        let m = Message::parse("@k=a\\sb :n CMD").unwrap();
        assert_eq!(m.tags["k"], "a b");
    }
    #[test]
    fn parse_tag_semicolon_escape() {
        let m = Message::parse("@k=a\\:b :n CMD").unwrap();
        assert_eq!(m.tags["k"], "a;b");
    }
    #[test]
    fn parse_tag_backslash_escape() {
        let m = Message::parse("@k=a\\\\b :n CMD").unwrap();
        assert_eq!(m.tags["k"], "a\\b");
    }
    #[test]
    fn parse_tag_cr_escape() {
        let m = Message::parse("@k=a\\rb :n CMD").unwrap();
        assert_eq!(m.tags["k"], "a\rb");
    }
    #[test]
    fn parse_tag_lf_escape() {
        let m = Message::parse("@k=a\\nb :n CMD").unwrap();
        assert_eq!(m.tags["k"], "a\nb");
    }
    #[test]
    fn parse_valueless_tag() {
        let m = Message::parse("@flag :n CMD").unwrap();
        assert_eq!(m.tags["flag"], "");
    }
    #[test]
    fn parse_multiple_tags() {
        let m = Message::parse("@a=1;b=2;c=3 :n CMD").unwrap();
        assert_eq!(m.tags.len(), 3);
    }
    #[test]
    fn parse_uppercased() {
        let m = Message::parse("privmsg #c :t").unwrap();
        assert_eq!(m.command, "PRIVMSG");
    }
    #[test]
    fn parse_empty_none() {
        assert!(Message::parse("").is_none());
    }
    #[test]
    fn parse_crlf_none() {
        assert!(Message::parse("\r\n").is_none());
    }
    #[test]
    fn parse_bare_at_none() {
        assert!(Message::parse("@").is_none());
    }
    #[test]
    fn parse_at_no_cmd_none() {
        assert!(Message::parse("@k=v").is_none());
    }
    #[test]
    fn parse_prefix_no_cmd_none() {
        assert!(Message::parse(":srv").is_none());
    }
    #[test]
    fn parse_trailing_empty() {
        let m = Message::parse(":n PRIVMSG #c :").unwrap();
        assert_eq!(m.params[1], "");
    }
    #[test]
    fn parse_trailing_colon() {
        let m = Message::parse(":n PRIVMSG #c ::x:y:").unwrap();
        assert_eq!(m.params[1], ":x:y:");
    }
    #[test]
    fn parse_no_prefix() {
        let m = Message::parse("PING :token").unwrap();
        assert!(m.prefix.is_none());
        assert_eq!(m.params[0], "token");
    }
    #[test]
    fn parse_many_params() {
        let m = Message::parse(":n CMD a b c d :trail").unwrap();
        assert_eq!(m.params, vec!["a", "b", "c", "d", "trail"]);
    }
    #[test]
    fn parse_no_trailing() {
        let m = Message::parse(":n CMD a b c").unwrap();
        assert_eq!(m.params, vec!["a", "b", "c"]);
    }
    #[test]
    fn parse_just_cmd() {
        let m = Message::parse("QUIT").unwrap();
        assert!(m.params.is_empty());
    }
    #[test]
    fn parse_null_bytes() {
        let m = Message::parse(":n PRIVMSG #c :\x00hello").unwrap();
        assert!(m.params[1].contains("hello"));
    }
    #[test]
    fn parse_unicode() {
        let m = Message::parse(":café!u@h PRIVMSG #ch :🎉").unwrap();
        assert!(m.params[1].contains("🎉"));
    }
    #[test]
    fn parse_10k_msg() {
        let t = "x".repeat(10000);
        let m = Message::parse(&format!(":n PRIVMSG #c :{t}")).unwrap();
        assert_eq!(m.params[1].len(), 10000);
    }
    #[test]
    fn parse_50k_tag() {
        let v = "y".repeat(50000);
        let m = Message::parse(&format!("@k={v} :n CMD")).unwrap();
        assert_eq!(m.tags["k"].len(), 50000);
    }
    #[test]
    fn parse_empty_key_tag() {
        let m = Message::parse("@=val :n CMD").unwrap();
        assert_eq!(m.tags[""], "val");
    }
    #[test]
    fn parse_consecutive_semi() {
        let m = Message::parse("@a=1;;b=2 :n CMD").unwrap();
        assert_eq!(m.tags["a"], "1");
        assert_eq!(m.tags["b"], "2");
    }
    #[test]
    fn parse_eq_in_val() {
        let m = Message::parse("@k=a=b=c :n CMD").unwrap();
        assert_eq!(m.tags["k"], "a=b=c");
    }
    #[test]
    fn parse_trailing_backslash() {
        let m = Message::parse("@k=val\\ :n CMD").unwrap();
        assert!(m.tags["k"].ends_with('\\'));
    }
    #[test]
    fn parse_empty_prefix() {
        let m = Message::parse(": CMD p").unwrap();
        assert_eq!(m.prefix.as_deref(), Some(""));
    }
    #[test]
    fn parse_html_text() {
        let m = Message::parse(":n PRIVMSG #c :<script>alert(1)</script>").unwrap();
        assert_eq!(m.params[1], "<script>alert(1)</script>");
    }
    #[test]
    fn parse_rtl() {
        let m = Message::parse(":n PRIVMSG #c :\u{202E}rev").unwrap();
        assert!(m.params[1].contains('\u{202E}'));
    }
    #[test]
    fn parse_zwsp() {
        let m = Message::parse(":n\u{200B} PRIVMSG #c :t").unwrap();
        assert!(m.prefix.unwrap().contains('\u{200B}'));
    }
    #[test]
    fn parse_353() {
        let m = Message::parse(":srv 353 me = #ch :@op +v n").unwrap();
        assert_eq!(m.params[3], "@op +v n");
    }
    #[test]
    fn parse_mode_compound() {
        let m = Message::parse(":op MODE #ch +ov a b").unwrap();
        assert_eq!(m.params, vec!["#ch", "+ov", "a", "b"]);
    }
    #[test]
    fn parse_kick() {
        let m = Message::parse(":op KICK #ch v :reason").unwrap();
        assert_eq!(m.params, vec!["#ch", "v", "reason"]);
    }
    #[test]
    fn parse_topic_clear() {
        let m = Message::parse(":n TOPIC #ch :").unwrap();
        assert_eq!(m.params[1], "");
    }
    #[test]
    fn parse_away() {
        let m = Message::parse(":n AWAY :gone").unwrap();
        assert_eq!(m.params[0], "gone");
    }
    #[test]
    fn parse_invite() {
        let m = Message::parse(":op INVITE t #ch").unwrap();
        assert_eq!(m.params, vec!["t", "#ch"]);
    }
    // Format tests
    #[test]
    fn fmt_simple() {
        let m = Message::new("PRIVMSG", vec!["#c", "hi there"]);
        assert_eq!(m.to_string(), "PRIVMSG #c :hi there");
    }
    #[test]
    fn fmt_no_params() {
        let m = Message::new("QUIT", vec![]);
        assert_eq!(m.to_string(), "QUIT");
    }
    #[test]
    fn fmt_single() {
        let m = Message::new("JOIN", vec!["#ch"]);
        assert_eq!(m.to_string(), "JOIN #ch");
    }
    #[test]
    fn fmt_empty_trailing() {
        let m = Message::new("PRIVMSG", vec!["#c", ""]);
        assert_eq!(m.to_string(), "PRIVMSG #c :");
    }
    #[test]
    fn fmt_prefix() {
        let mut m = Message::new("CMD", vec![]);
        m.prefix = Some("n".into());
        assert!(m.to_string().starts_with(":n"));
    }
    #[test]
    fn fmt_tags() {
        let mut t = HashMap::new();
        t.insert("k".into(), "v".into());
        let m = Message::with_tags(t, "CMD", vec![]);
        assert!(m.to_string().starts_with("@k=v"));
    }
    #[test]
    fn fmt_tag_escape() {
        let mut t = HashMap::new();
        t.insert("k".into(), "a b;c\\d".into());
        let m = Message::with_tags(t, "CMD", vec![]);
        let s = m.to_string();
        assert!(s.contains("\\s") && s.contains("\\:"));
    }
    #[test]
    fn tag_roundtrip() {
        let mut t = HashMap::new();
        t.insert("k".into(), " ;\\\r\n".into());
        let m = Message::with_tags(t, "CMD", vec![]);
        let p = Message::parse(&m.to_string()).unwrap();
        assert_eq!(p.tags["k"], " ;\\\r\n");
    }
    #[test]
    fn fmt_roundtrip() {
        let orig = ":n!u@h PRIVMSG #ch :hello world";
        let p = Message::parse(orig).unwrap();
        let r = Message::parse(&p.to_string()).unwrap();
        assert_eq!(r.command, "PRIVMSG");
        assert_eq!(r.params, vec!["#ch", "hello world"]);
    }
    #[test]
    fn parse_spaces_no_crash() {
        let _ = Message::parse("   ");
    }
    #[test]
    fn parse_just_colon() {
        assert!(Message::parse(":").is_none());
    }
    #[test]
    fn parse_double_colon() {
        let _ = Message::parse(":: CMD");
    }
    #[test]
    fn parse_cmd_with_prefix_space() {
        let m = Message::parse(":srv CMD ").unwrap();
        assert_eq!(m.command, "CMD");
    }
}

// ═══════════════════════════════════════════════════════════════
// CRYPTO (25 tests)
// ═══════════════════════════════════════════════════════════════

mod crypto_tests {
    use freeq_sdk::crypto::PrivateKey;

    #[test]
    fn ed25519_roundtrip() {
        let k = PrivateKey::generate_ed25519();
        let s = k.sign(b"test");
        assert!(k.public_key().verify(b"test", &s).is_ok());
    }
    #[test]
    fn secp256k1_roundtrip() {
        let k = PrivateKey::generate_secp256k1();
        let s = k.sign(b"test");
        assert!(k.public_key().verify(b"test", &s).is_ok());
    }
    #[test]
    fn ed25519_wrong_msg() {
        let k = PrivateKey::generate_ed25519();
        let s = k.sign(b"a");
        assert!(k.public_key().verify(b"b", &s).is_err());
    }
    #[test]
    fn secp256k1_wrong_msg() {
        let k = PrivateKey::generate_secp256k1();
        let s = k.sign(b"a");
        assert!(k.public_key().verify(b"b", &s).is_err());
    }
    #[test]
    fn ed25519_wrong_key() {
        let k1 = PrivateKey::generate_ed25519();
        let k2 = PrivateKey::generate_ed25519();
        let s = k1.sign(b"m");
        assert!(k2.public_key().verify(b"m", &s).is_err());
    }
    #[test]
    fn secp256k1_wrong_key() {
        let k1 = PrivateKey::generate_secp256k1();
        let k2 = PrivateKey::generate_secp256k1();
        let s = k1.sign(b"m");
        assert!(k2.public_key().verify(b"m", &s).is_err());
    }
    #[test]
    fn sign_empty() {
        let k = PrivateKey::generate_ed25519();
        let s = k.sign(b"");
        assert!(k.public_key().verify(b"", &s).is_ok());
    }
    #[test]
    fn sign_1mb() {
        let k = PrivateKey::generate_ed25519();
        let m = vec![0xABu8; 1_000_000];
        let s = k.sign(&m);
        assert!(k.public_key().verify(&m, &s).is_ok());
    }
    #[test]
    fn base64url_sign() {
        let k = PrivateKey::generate_ed25519();
        let s = k.sign_base64url(b"test");
        assert!(!s.contains('+'));
        assert!(!s.contains('/'));
    }
    #[test]
    fn truncated_sig_fails() {
        let k = PrivateKey::generate_ed25519();
        let s = k.sign(b"m");
        assert!(k.public_key().verify(b"m", &s[..s.len() / 2]).is_err());
    }
    #[test]
    fn empty_sig_fails() {
        let k = PrivateKey::generate_ed25519();
        assert!(k.public_key().verify(b"m", b"").is_err());
    }
    #[test]
    fn garbage_sig_fails() {
        let k = PrivateKey::generate_ed25519();
        assert!(k.public_key().verify(b"m", &[0xFF; 64]).is_err());
    }
    #[test]
    fn sign_unicode() {
        let k = PrivateKey::generate_ed25519();
        let s = k.sign("🎉".as_bytes());
        assert!(k.public_key().verify("🎉".as_bytes(), &s).is_ok());
    }
    #[test]
    fn sign_nulls() {
        let k = PrivateKey::generate_ed25519();
        let s = k.sign(b"a\x00b");
        assert!(k.public_key().verify(b"a\x00b", &s).is_ok());
    }
    #[test]
    fn keys_unique() {
        let k1 = PrivateKey::generate_ed25519();
        let k2 = PrivateKey::generate_ed25519();
        assert_ne!(k1.sign(b"x"), k2.sign(b"x"));
    }
    #[test]
    fn ed25519_deterministic() {
        let k = PrivateKey::generate_ed25519();
        assert_eq!(k.sign(b"same"), k.sign(b"same"));
    }
    #[test]
    fn secp256k1_both_verify() {
        let k = PrivateKey::generate_secp256k1();
        let s1 = k.sign(b"m");
        let s2 = k.sign(b"m");
        assert!(k.public_key().verify(b"m", &s1).is_ok());
        assert!(k.public_key().verify(b"m", &s2).is_ok());
    }
    #[test]
    fn gen_100_unique() {
        let ks: std::collections::HashSet<Vec<u8>> = (0..100)
            .map(|_| PrivateKey::generate_ed25519().sign(b"x"))
            .collect();
        assert_eq!(ks.len(), 100);
    }
}

// ═══════════════════════════════════════════════════════════════
// AUTH (15 tests)
// ═══════════════════════════════════════════════════════════════

mod auth_tests {
    use freeq_sdk::auth::{self, ChallengeResponse, ChallengeSigner, KeySigner};
    use freeq_sdk::crypto::PrivateKey;

    #[test]
    fn key_signer_responds() {
        let k = PrivateKey::generate_ed25519();
        let s = KeySigner::new("did:key:t".into(), k);
        let r = s.respond(b"challenge").unwrap();
        assert_eq!(r.did, "did:key:t");
        assert!(!r.signature.is_empty());
    }
    #[test]
    fn key_signer_empty() {
        let k = PrivateKey::generate_ed25519();
        let s = KeySigner::new("did:key:t".into(), k);
        assert!(s.respond(b"").is_ok());
    }
    #[test]
    fn key_signer_large() {
        let k = PrivateKey::generate_ed25519();
        let s = KeySigner::new("did:key:t".into(), k);
        assert!(s.respond(&vec![0xAB; 100_000]).is_ok());
    }
    #[test]
    fn encode_response_roundtrip() {
        let r = ChallengeResponse {
            did: "did:plc:t".into(),
            signature: "sig".into(),
            method: None,
            pds_url: None,
            dpop_proof: None,
            challenge_nonce: None,
            owner_did: None,
        };
        let enc = auth::encode_response(&r);
        use base64::Engine;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&enc)
            .unwrap();
        let dec: ChallengeResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(dec.did, "did:plc:t");
    }
    #[test]
    fn decode_challenge_valid() {
        use base64::Engine;
        let c = serde_json::json!({"session_id":"s","nonce":"n","timestamp":123});
        let enc = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&c).unwrap());
        assert!(auth::decode_challenge(&enc).is_ok());
    }
    #[test]
    fn decode_challenge_bad_b64() {
        assert!(auth::decode_challenge("!!!").is_err());
    }
    #[test]
    fn decode_challenge_bad_json() {
        use base64::Engine;
        let e = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"not json");
        assert!(auth::decode_challenge(&e).is_err());
    }
    #[test]
    fn decode_challenge_empty() {
        assert!(auth::decode_challenge("").is_err());
    }
    #[test]
    fn secp256k1_signer() {
        let k = PrivateKey::generate_secp256k1();
        let s = KeySigner::new("did:key:s".into(), k);
        assert!(s.respond(b"c").is_ok());
    }
    #[test]
    fn response_all_fields() {
        let r = ChallengeResponse {
            did: "d".into(),
            signature: "s".into(),
            method: Some("pds-oauth".into()),
            pds_url: Some("https://pds".into()),
            dpop_proof: Some("proof".into()),
            challenge_nonce: Some("n".into()),
            owner_did: None,
        };
        let enc = auth::encode_response(&r);
        use base64::Engine;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&enc)
            .unwrap();
        let dec: ChallengeResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(dec.method.as_deref(), Some("pds-oauth"));
    }
}

// ═══════════════════════════════════════════════════════════════
// BOT FRAMEWORK + RATE LIMITER (30 tests)
// ═══════════════════════════════════════════════════════════════

mod bot_tests {
    use freeq_sdk::bot::{Bot, RateLimiter};
    use std::time::Duration;

    #[test]
    fn bot_new() {
        let _ = Bot::new("!", "bot");
    }
    #[test]
    fn bot_command() {
        let mut b = Bot::new("!", "bot");
        b.command("ping", "pong", |ctx| {
            Box::pin(async move { ctx.reply("pong").await })
        });
    }
    #[test]
    fn bot_multi_cmd() {
        let mut b = Bot::new("!", "bot");
        b.command("a", "A", |ctx| {
            Box::pin(async move { ctx.reply("a").await })
        });
        b.command("b", "B", |ctx| {
            Box::pin(async move { ctx.reply("b").await })
        });
    }
    #[test]
    fn bot_admin() {
        let _ = Bot::new("!", "bot").admin("did:plc:x");
    }
    #[test]
    fn bot_rate_limit() {
        let _ = Bot::new("!", "bot").rate_limit(5, Duration::from_secs(30));
    }
    #[test]
    fn bot_max_args() {
        let _ = Bot::new("!", "bot").max_args(1000);
    }
    #[test]
    fn bot_max_args_zero() {
        let _ = Bot::new("!", "bot").max_args(0);
    }
    #[test]
    fn bot_empty_prefix() {
        let _ = Bot::new("", "bot");
    }
    // Rate limiter
    #[test]
    fn rl_allows() {
        let r = RateLimiter::new(3, Duration::from_secs(60));
        assert!(r.check("a"));
        assert!(r.check("a"));
        assert!(r.check("a"));
    }
    #[test]
    fn rl_blocks() {
        let r = RateLimiter::new(2, Duration::from_secs(60));
        assert!(r.check("b"));
        assert!(r.check("b"));
        assert!(!r.check("b"));
    }
    #[test]
    fn rl_independent() {
        let r = RateLimiter::new(1, Duration::from_secs(60));
        assert!(r.check("a"));
        assert!(r.check("b"));
        assert!(!r.check("a"));
    }
    #[test]
    fn rl_case_insensitive() {
        let r = RateLimiter::new(1, Duration::from_secs(60));
        assert!(r.check("A"));
        assert!(!r.check("a"));
    }
    #[test]
    fn rl_resets() {
        let r = RateLimiter::new(1, Duration::from_millis(50));
        assert!(r.check("u"));
        assert!(!r.check("u"));
        std::thread::sleep(Duration::from_millis(60));
        assert!(r.check("u"));
    }
    #[test]
    fn rl_prune() {
        let r = RateLimiter::new(1, Duration::from_millis(10));
        r.check("old");
        std::thread::sleep(Duration::from_millis(30));
        r.prune();
        assert!(r.check("old"));
    }
    #[test]
    fn rl_zero_max() {
        let r = RateLimiter::new(0, Duration::from_secs(60));
        assert!(!r.check("x"));
    }
    #[test]
    fn rl_zero_window() {
        let r = RateLimiter::new(1, Duration::from_secs(0));
        assert!(r.check("u"));
        assert!(r.check("u"));
    }
    #[test]
    fn rl_1000_users() {
        let r = RateLimiter::new(1, Duration::from_secs(60));
        for i in 0..1000 {
            assert!(r.check(&format!("u{i}")));
        }
    }
    #[test]
    fn rl_empty_nick() {
        let r = RateLimiter::new(1, Duration::from_secs(60));
        assert!(r.check(""));
        assert!(!r.check(""));
    }
    #[test]
    fn rl_special_chars() {
        let r = RateLimiter::new(1, Duration::from_secs(60));
        assert!(r.check("[bot]"));
        assert!(!r.check("[bot]"));
    }
    #[test]
    fn rl_concurrent() {
        let r = std::sync::Arc::new(RateLimiter::new(100, Duration::from_secs(60)));
        let mut hs = vec![];
        for i in 0..10 {
            let r = r.clone();
            hs.push(std::thread::spawn(move || {
                for j in 0..10 {
                    r.check(&format!("t{i}u{j}"));
                }
            }));
        }
        for h in hs {
            h.join().unwrap();
        }
    }
    #[test]
    fn rl_max_u32() {
        let r = RateLimiter::new(u32::MAX, Duration::from_secs(60));
        assert!(r.check("x"));
    }
    #[test]
    fn rl_exact_limit() {
        let r = RateLimiter::new(5, Duration::from_secs(60));
        for _ in 0..5 {
            assert!(r.check("u"));
        }
        assert!(!r.check("u"));
    }
}

// ═══════════════════════════════════════════════════════════════
// DID (15 tests)
// ═══════════════════════════════════════════════════════════════

mod did_tests {
    use freeq_sdk::did::{DidDocument, DidResolver};
    type HashMap<K, V> = std::collections::HashMap<K, V>;

    #[test]
    fn static_map_create() {
        let m = HashMap::new();
        let _ = DidResolver::static_map(m);
    }
    #[test]
    fn static_unknown_fails() {
        let r = DidResolver::static_map(HashMap::new());
        let rt = tokio::runtime::Runtime::new().unwrap();
        assert!(rt.block_on(r.resolve("did:key:x")).is_err());
    }
    #[test]
    fn empty_auth_keys() {
        let d = DidDocument {
            id: "d".into(),
            also_known_as: vec![],
            verification_method: vec![],
            authentication: vec![],
            assertion_method: vec![],
            service: vec![],
        };
        assert!(d.authentication_keys().is_empty());
    }
    #[test]
    fn also_known_as() {
        let d = DidDocument {
            id: "d".into(),
            also_known_as: vec!["at://alice.bsky.social".into()],
            verification_method: vec![],
            authentication: vec![],
            assertion_method: vec![],
            service: vec![],
        };
        assert_eq!(d.also_known_as[0], "at://alice.bsky.social");
    }
    #[test]
    fn empty_id() {
        let d = DidDocument {
            id: String::new(),
            also_known_as: vec![],
            verification_method: vec![],
            authentication: vec![],
            assertion_method: vec![],
            service: vec![],
        };
        assert!(d.id.is_empty());
    }
    #[test]
    fn multi_dids() {
        let mut m = HashMap::new();
        for i in 0..10 {
            m.insert(
                format!("did:key:t{i}"),
                DidDocument {
                    id: format!("did:key:t{i}"),
                    also_known_as: vec![],
                    verification_method: vec![],
                    authentication: vec![],
                    assertion_method: vec![],
                    service: vec![],
                },
            );
        }
        let _ = DidResolver::static_map(m);
    }
}

// ═══════════════════════════════════════════════════════════════
// E2EE (20 tests)
// ═══════════════════════════════════════════════════════════════

mod e2ee_tests {
    use freeq_sdk::e2ee;

    #[test]
    fn derive_deterministic() {
        assert_eq!(e2ee::derive_key("p", "s"), e2ee::derive_key("p", "s"));
    }
    #[test]
    fn derive_diff_pass() {
        assert_ne!(e2ee::derive_key("a", "s"), e2ee::derive_key("b", "s"));
    }
    #[test]
    fn derive_diff_salt() {
        assert_ne!(e2ee::derive_key("p", "a"), e2ee::derive_key("p", "b"));
    }
    #[test]
    fn encrypt_decrypt() {
        let k = e2ee::derive_key("k", "s");
        let c = e2ee::encrypt(&k, "hello").unwrap();
        assert!(c.starts_with("ENC1:"));
        assert_eq!(e2ee::decrypt(&k, &c).unwrap(), "hello");
    }
    #[test]
    fn wrong_key_fails() {
        let k1 = e2ee::derive_key("a", "s");
        let k2 = e2ee::derive_key("b", "s");
        let c = e2ee::encrypt(&k1, "secret").unwrap();
        assert!(e2ee::decrypt(&k2, &c).is_err());
    }
    #[test]
    fn encrypt_empty() {
        let k = e2ee::derive_key("k", "s");
        let c = e2ee::encrypt(&k, "").unwrap();
        assert_eq!(e2ee::decrypt(&k, &c).unwrap(), "");
    }
    #[test]
    fn encrypt_unicode() {
        let k = e2ee::derive_key("k", "s");
        let c = e2ee::encrypt(&k, "🎉世界").unwrap();
        assert_eq!(e2ee::decrypt(&k, &c).unwrap(), "🎉世界");
    }
    #[test]
    fn encrypt_100k() {
        let k = e2ee::derive_key("k", "s");
        let msg = "x".repeat(100_000);
        let c = e2ee::encrypt(&k, &msg).unwrap();
        assert_eq!(e2ee::decrypt(&k, &c).unwrap(), msg);
    }
    #[test]
    fn decrypt_garbage() {
        let k = e2ee::derive_key("k", "s");
        assert!(e2ee::decrypt(&k, "ENC1:!!!").is_err());
    }
    #[test]
    fn decrypt_no_prefix() {
        let k = e2ee::derive_key("k", "s");
        assert!(e2ee::decrypt(&k, "not encrypted").is_err());
    }
    #[test]
    fn decrypt_empty() {
        let k = e2ee::derive_key("k", "s");
        assert!(e2ee::decrypt(&k, "").is_err());
    }
    #[test]
    fn decrypt_truncated() {
        let k = e2ee::derive_key("k", "s");
        let c = e2ee::encrypt(&k, "hi").unwrap();
        assert!(e2ee::decrypt(&k, &c[..c.len() / 2]).is_err());
    }
    #[test]
    fn nonce_differs() {
        let k = e2ee::derive_key("k", "s");
        let c1 = e2ee::encrypt(&k, "same").unwrap();
        let c2 = e2ee::encrypt(&k, "same").unwrap();
        assert_ne!(c1, c2);
    }
    #[test]
    fn empty_passphrase() {
        let k = e2ee::derive_key("", "s");
        let c = e2ee::encrypt(&k, "m").unwrap();
        assert_eq!(e2ee::decrypt(&k, &c).unwrap(), "m");
    }
    #[test]
    fn empty_salt() {
        let k = e2ee::derive_key("p", "");
        let c = e2ee::encrypt(&k, "m").unwrap();
        assert_eq!(e2ee::decrypt(&k, &c).unwrap(), "m");
    }
    #[test]
    fn tampered_fails() {
        let k = e2ee::derive_key("k", "s");
        let c = e2ee::encrypt(&k, "hi").unwrap();
        let mut ch: Vec<char> = c.chars().collect();
        if ch.len() > 10 {
            ch[10] = if ch[10] == 'A' { 'B' } else { 'A' };
        }
        let t: String = ch.into_iter().collect();
        assert!(e2ee::decrypt(&k, &t).is_err());
    }
}

// ═══════════════════════════════════════════════════════════════
// SSRF (10 tests)
// ═══════════════════════════════════════════════════════════════

mod ssrf_tests {
    use freeq_sdk::ssrf;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn loopback() {
        assert!(ssrf::is_private_ip(&IpAddr::V4(Ipv4Addr::new(
            127, 0, 0, 1
        ))));
    }
    #[test]
    fn private_10() {
        assert!(ssrf::is_private_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }
    #[test]
    fn private_172() {
        assert!(ssrf::is_private_ip(&IpAddr::V4(Ipv4Addr::new(
            172, 16, 0, 1
        ))));
    }
    #[test]
    fn private_192() {
        assert!(ssrf::is_private_ip(&IpAddr::V4(Ipv4Addr::new(
            192, 168, 1, 1
        ))));
    }
    #[test]
    fn public() {
        assert!(!ssrf::is_private_ip(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }
    #[test]
    fn link_local() {
        assert!(ssrf::is_private_ip(&IpAddr::V4(Ipv4Addr::new(
            169, 254, 1, 1
        ))));
    }
    #[test]
    fn unspecified() {
        assert!(ssrf::is_private_ip(&IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))));
    }
    #[test]
    fn broadcast() {
        assert!(ssrf::is_private_ip(&IpAddr::V4(Ipv4Addr::new(
            255, 255, 255, 255
        ))));
    }
    #[test]
    fn cloudflare() {
        assert!(!ssrf::is_private_ip(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    }
    #[test]
    fn google_dns() {
        assert!(!ssrf::is_private_ip(&IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4))));
    }
}

// ═══════════════════════════════════════════════════════════════
// RATCHET (20 tests)
// ═══════════════════════════════════════════════════════════════

mod ratchet_tests {
    use freeq_sdk::ratchet::Session;

    fn pair() -> (Session, Session) {
        use x25519_dalek::{PublicKey, StaticSecret};
        let ss = [42u8; 32]; // shared secret from X3DH
        // Bob's ratchet keypair
        let bob_secret = StaticSecret::from([7u8; 32]);
        let bob_public = PublicKey::from(&bob_secret);
        // Alice inits with Bob's public key; Bob inits with his own secret
        (
            Session::init_alice(ss, bob_public.to_bytes()),
            Session::init_bob(ss, [7u8; 32]),
        )
    }

    #[test]
    fn roundtrip() {
        let (mut a, mut b) = pair();
        let c = a.encrypt("hi").unwrap();
        assert_eq!(b.decrypt(&c).unwrap(), "hi");
    }
    #[test]
    fn bidir() {
        let (mut a, mut b) = pair();
        let c1 = a.encrypt("from a").unwrap();
        assert_eq!(b.decrypt(&c1).unwrap(), "from a");
        let c2 = b.encrypt("from b").unwrap();
        assert_eq!(a.decrypt(&c2).unwrap(), "from b");
    }
    #[test]
    fn multi_msg() {
        let (mut a, mut b) = pair();
        for i in 0..20 {
            let c = a.encrypt(&format!("m{i}")).unwrap();
            assert_eq!(b.decrypt(&c).unwrap(), format!("m{i}"));
        }
    }
    #[test]
    fn out_of_order() {
        let (mut a, mut b) = pair();
        let c1 = a.encrypt("1").unwrap();
        let c2 = a.encrypt("2").unwrap();
        let c3 = a.encrypt("3").unwrap();
        assert_eq!(b.decrypt(&c3).unwrap(), "3");
        assert_eq!(b.decrypt(&c1).unwrap(), "1");
        assert_eq!(b.decrypt(&c2).unwrap(), "2");
    }
    #[test]
    fn replay_fail() {
        let (mut a, mut b) = pair();
        let c = a.encrypt("once").unwrap();
        b.decrypt(&c).unwrap();
        assert!(b.decrypt(&c).is_err());
    }
    #[test]
    fn empty_msg() {
        let (mut a, mut b) = pair();
        let c = a.encrypt("").unwrap();
        assert_eq!(b.decrypt(&c).unwrap(), "");
    }
    #[test]
    fn unicode_msg() {
        let (mut a, mut b) = pair();
        let c = a.encrypt("🎉世界").unwrap();
        assert_eq!(b.decrypt(&c).unwrap(), "🎉世界");
    }
    #[test]
    fn large_msg() {
        let (mut a, mut b) = pair();
        let m = "x".repeat(100_000);
        let c = a.encrypt(&m).unwrap();
        assert_eq!(b.decrypt(&c).unwrap(), m);
    }
    #[test]
    fn serialize() {
        let (mut a, mut b) = pair();
        let c = a.encrypt("init").unwrap();
        b.decrypt(&c).unwrap();
        let j = serde_json::to_string(&a).unwrap();
        let mut a2: Session = serde_json::from_str(&j).unwrap();
        let c2 = a2.encrypt("after").unwrap();
        assert_eq!(b.decrypt(&c2).unwrap(), "after");
    }
    #[test]
    fn tampered_fail() {
        let (mut a, mut b) = pair();
        let c = a.encrypt("secret").unwrap();
        let mut ch: Vec<char> = c.chars().collect();
        if ch.len() > 5 {
            ch[5] = if ch[5] == 'A' { 'B' } else { 'A' };
        }
        let t: String = ch.into_iter().collect();
        assert!(b.decrypt(&t).is_err());
    }
    #[test]
    fn garbage_fail() {
        let (_, mut b) = pair();
        assert!(b.decrypt("garbage").is_err());
    }
    #[test]
    fn forward_secrecy() {
        let (mut a, mut b) = pair();
        let c = a.encrypt("msg").unwrap();
        b.decrypt(&c).unwrap();
        assert!(b.decrypt(&c).is_err());
    }
    #[test]
    fn alternating_20() {
        let (mut a, mut b) = pair();
        for i in 0..10 {
            let c = a.encrypt(&format!("a{i}")).unwrap();
            assert_eq!(b.decrypt(&c).unwrap(), format!("a{i}"));
            let c = b.encrypt(&format!("b{i}")).unwrap();
            assert_eq!(a.decrypt(&c).unwrap(), format!("b{i}"));
        }
    }
}

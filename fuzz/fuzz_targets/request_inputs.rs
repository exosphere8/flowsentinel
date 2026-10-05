//! Untrusted request inputs: Host headers, session cookies, usernames,
//! passwords, request IDs, capture filters and password files. None may
//! panic, and accepted values must satisfy their documented rules.
#![no_main]

use api_server::auth::{SessionToken, check_new_password, normalize_username};
use api_server::bootstrap::read_password;
use api_server::host::{HostPolicy, host_name};
use api_server::observability::parse_request_id;
use libfuzzer_sys::fuzz_target;
use live_capture::bpf;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);

    if let Some(name) = host_name(&text) {
        assert_eq!(name, name.to_ascii_lowercase());
        assert!(!name.is_empty());
    }
    if let Some(policy) = HostPolicy::parse(&text) {
        let _ = policy.allows(Some(&text));
    }

    if let Some(token) = SessionToken::parse(&text) {
        assert_eq!(token.to_hex(), text);
        assert_eq!(token.csrf_token().len(), 64);
    }

    if let Ok(name) = normalize_username(&text) {
        assert!((1..=64).contains(&name.chars().count()));
        assert!(name.bytes().all(|b| b.is_ascii_lowercase()
            || b.is_ascii_digit()
            || matches!(b, b'.' | b'_' | b'-')));
        assert_eq!(name, text.to_ascii_lowercase());
    }
    if check_new_password(&text, "admin").is_ok() {
        assert!((12..=256).contains(&text.chars().count()));
    }

    if let Some(id) = parse_request_id(&text) {
        assert!((1..=64).contains(&id.len()));
    }

    if bpf::check_text(&text).is_ok() {
        assert!(text.len() <= bpf::MAX_FILTER_BYTES);
        assert!(text.bytes().all(|b| b == b' ' || b.is_ascii_graphic()));
    }

    if let Ok(password) = read_password(data) {
        assert!(password.len() <= 1024);
    }
});

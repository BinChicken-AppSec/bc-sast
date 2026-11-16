use std::time::Duration;

use appsec_mcp::confluence::HttpTransport;
use appsec_mcp::http::{ReqwestTransport, DEFAULT_MAX_BYTES, DEFAULT_TIMEOUT};
use appsec_mcp::sharepoint::GraphTransport;

const UNREACHABLE: &str = "https://127.0.0.1:1/x";

fn transport() -> ReqwestTransport {
    ReqwestTransport::new(DEFAULT_TIMEOUT, DEFAULT_MAX_BYTES)
        .expect("the shipped configuration must build")
}

#[test]
fn the_shipped_constructor_builds_with_the_documented_defaults() {
    assert_eq!(DEFAULT_MAX_BYTES, 8 * 1024 * 1024);
    assert_eq!(DEFAULT_TIMEOUT, Duration::from_secs(30));
    let _ = transport();
    assert!(ReqwestTransport::new(Duration::from_millis(1), 1).is_ok());
}

#[test]
fn every_transport_method_refuses_an_unreachable_host() {
    let t = transport();

    let confluence = HttpTransport::get(&t, UNREACHABLE, "Basic x");
    assert!(
        confluence.is_err(),
        "Confluence GET reached something: {confluence:?}"
    );

    let attempts: [(&str, Result<(), String>); 4] = [
        ("post_form", t.post_form(UNREACHABLE, "a=b").map(|_| ())),
        (
            "post_json",
            t.post_json(UNREACHABLE, "Bearer x", "{}").map(|_| ()),
        ),
        ("get_json", t.get_json(UNREACHABLE, "Bearer x").map(|_| ())),
        (
            "get_unauthenticated",
            t.get_unauthenticated(UNREACHABLE).map(|_| ()),
        ),
    ];
    for (name, result) in attempts {
        let Err(e) = result else {
            panic!("{name} reached something it should not have");
        };
        assert!(e.contains("request failed"), "{name}: {e}");
        assert!(!e.contains("Bearer"), "{name} leaked a token: {e}");
        assert!(!e.contains("Basic"), "{name} leaked a credential: {e}");
    }
}

#[test]
fn the_shipped_transport_refuses_plain_http() {
    let t = transport();
    for result in [
        HttpTransport::get(&t, "http://127.0.0.1:1/x", "Basic x").map(|r| r.body),
        t.get_json("http://127.0.0.1:1/x", "Bearer x")
            .map(|r| r.body),
    ] {
        let Err(e) = result else {
            panic!("plain HTTP was accepted");
        };
        assert!(e.contains("request failed"), "{e}");
    }
    assert!(t.get_unauthenticated("http://127.0.0.1:1/x").is_err());
}

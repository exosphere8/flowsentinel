use api_server::app;
use axum::{
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tower::ServiceExt;

const EXPECTED_BODY: &str = r#"{"status":"ok","service":"flowsentinel-api"}"#;

async fn send(method: Method, uri: &str) -> axum::response::Response {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    app().oneshot(request).await.unwrap()
}

#[tokio::test]
async fn health_returns_exact_json() {
    let response = send(Method::GET, "/health").await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    let body = to_bytes(response.into_body(), 1024).await.unwrap();
    assert_eq!(body, EXPECTED_BODY.as_bytes());
}

#[tokio::test]
async fn health_rejects_other_methods() {
    for method in [Method::POST, Method::PUT, Method::DELETE] {
        let response = send(method, "/health").await;
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }
}

#[tokio::test]
async fn unknown_route_is_not_found() {
    let response = send(Method::GET, "/api/does-not-exist").await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// Serves the real router on an ephemeral loopback port and speaks raw HTTP/1.1
/// to it, covering the same path as `curl http://127.0.0.1:8080/health`.
#[tokio::test]
async fn health_over_tcp() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app()).await });

    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut raw = String::new();
    stream.read_to_string(&mut raw).await.unwrap();

    assert!(raw.starts_with("HTTP/1.1 200 OK\r\n"), "response: {raw}");
    assert!(raw.ends_with(EXPECTED_BODY), "response: {raw}");
    server.abort();
}

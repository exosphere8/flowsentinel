//! Request IDs, access logs and Prometheus metrics.
//!
//! Every request gets an ID: the client's `X-Request-Id` when it is 1 to 64
//! characters of letters, digits, `.`, `_` or `-`, otherwise a random one.
//! The ID is returned in `X-Request-Id`, and every log line written while
//! the request is handled carries it (the `request` span, at `ERROR` level
//! so that log filters keep it). One access-log line is written per
//! request, with the route template (never the path or query string),
//! status and duration; a request the client abandons is logged as `499`.
//!
//! Metrics are kept in memory and served in the Prometheus text format on a
//! separate listener (`FLOWSENTINEL_METRICS_ADDR`, off by default). Labels
//! come only from fixed sets (route templates, methods, status codes, audit
//! actions), so their number is bounded.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::{MatchedPath, Request, State};
use axum::http::{HeaderName, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use tracing::Instrument;

pub const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");

/// Upper bounds of the request-duration histogram, in seconds.
const BUCKETS: [f64; 12] = [
    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 10.0,
];

/// A request's ID, also stored in the request's extensions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestId(pub String);

/// The route template that matched. [`observe`] puts an empty slot in the
/// request's extensions and [`mark_route`] fills it once routing has picked
/// a route, so the template is known even if the request is cancelled.
#[derive(Debug, Clone, Default)]
struct RouteSlot(Arc<OnceLock<String>>);

/// Status recorded for requests the client abandoned before the answer
/// (the convention of nginx: "client closed request").
pub const CLIENT_CLOSED: u16 = 499;

#[derive(Debug, Default, Clone)]
struct Histogram {
    buckets: [u64; BUCKETS.len()],
    count: u64,
    sum: f64,
}

#[derive(Debug, Default)]
struct Inner {
    /// (method, route, status) -> count.
    requests: BTreeMap<(&'static str, String, u16), u64>,
    /// (method, route) -> durations.
    durations: BTreeMap<(&'static str, String), Histogram>,
    /// (action, outcome) -> count.
    audit: BTreeMap<(&'static str, &'static str), u64>,
}

/// In-memory metrics.
#[derive(Debug)]
pub struct Metrics {
    started: Instant,
    inner: Mutex<Inner>,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            started: Instant::now(),
            inner: Mutex::new(Inner::default()),
        }
    }
}

/// Methods are labelled from a fixed set.
fn method_label(method: &Method) -> &'static str {
    match *method {
        Method::GET => "GET",
        Method::HEAD => "HEAD",
        Method::POST => "POST",
        Method::PUT => "PUT",
        Method::PATCH => "PATCH",
        Method::DELETE => "DELETE",
        Method::OPTIONS => "OPTIONS",
        _ => "OTHER",
    }
}

/// The route label: the matched API template, or a fixed name chosen from
/// the path and status. Responses produced before routing (a refused `Host`
/// header) or by the router itself (an unknown path, a wrong method) have
/// no template.
fn route_label(path: &str, matched: Option<&str>, status: u16) -> String {
    if let Some(route) = matched {
        return route.to_owned();
    }
    let api = path == "/api" || path.starts_with("/api/");
    let label = match (path, status) {
        (_, 421) => "misdirected",
        ("/health" | "/ready", _) => return path.to_owned(),
        (_, 405) if api => "method_not_allowed",
        _ if api => "unmatched",
        _ => "dashboard",
    };
    label.to_owned()
}

impl Metrics {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn record_request(&self, method: &'static str, route: String, status: u16, elapsed: Duration) {
        let mut inner = self.lock();
        *inner
            .requests
            .entry((method, route.clone(), status))
            .or_default() += 1;
        let histogram = inner.durations.entry((method, route)).or_default();
        let seconds = elapsed.as_secs_f64();
        for (bucket, &bound) in histogram.buckets.iter_mut().zip(&BUCKETS) {
            if seconds <= bound {
                *bucket += 1;
            }
        }
        histogram.count += 1;
        histogram.sum += seconds;
    }

    /// Counts an audit event (sign-ins, imports, refusals, ...).
    pub fn record_audit(&self, action: &'static str, outcome: &'static str) {
        *self.lock().audit.entry((action, outcome)).or_default() += 1;
    }

    /// The Prometheus text exposition, with `extra` gauges appended.
    pub fn render(&self, gauges: &[(&str, &str, f64)]) -> String {
        let inner = self.lock();
        let mut out = String::new();
        // Writing to a String cannot fail.
        let _ = writeln!(
            out,
            "# HELP flowsentinel_build_info Version of the running server.\n\
             # TYPE flowsentinel_build_info gauge\n\
             flowsentinel_build_info{{version=\"{}\"}} 1",
            env!("CARGO_PKG_VERSION")
        );
        let _ = writeln!(
            out,
            "# HELP flowsentinel_uptime_seconds Seconds since the server started.\n\
             # TYPE flowsentinel_uptime_seconds gauge\n\
             flowsentinel_uptime_seconds {}",
            self.started.elapsed().as_secs()
        );
        let _ = writeln!(
            out,
            "# HELP flowsentinel_http_requests_total HTTP requests by method, route and status.\n\
             # TYPE flowsentinel_http_requests_total counter"
        );
        for ((method, route, status), count) in &inner.requests {
            let _ = writeln!(
                out,
                "flowsentinel_http_requests_total{{method=\"{method}\",route=\"{}\",status=\"{status}\"}} {count}",
                escape(route)
            );
        }
        let _ = writeln!(
            out,
            "# HELP flowsentinel_http_request_duration_seconds Time to answer HTTP requests.\n\
             # TYPE flowsentinel_http_request_duration_seconds histogram"
        );
        for ((method, route), h) in &inner.durations {
            let labels = format!("method=\"{method}\",route=\"{}\"", escape(route));
            for (bound, count) in BUCKETS.iter().zip(&h.buckets) {
                let _ = writeln!(
                    out,
                    "flowsentinel_http_request_duration_seconds_bucket{{{labels},le=\"{bound}\"}} {count}"
                );
            }
            let _ = writeln!(
                out,
                "flowsentinel_http_request_duration_seconds_bucket{{{labels},le=\"+Inf\"}} {}\n\
                 flowsentinel_http_request_duration_seconds_sum{{{labels}}} {}\n\
                 flowsentinel_http_request_duration_seconds_count{{{labels}}} {}",
                h.count, h.sum, h.count
            );
        }
        let _ = writeln!(
            out,
            "# HELP flowsentinel_audit_events_total Audited events (sign-ins, imports, refusals, \
             changes) by action and outcome.\n\
             # TYPE flowsentinel_audit_events_total counter"
        );
        for ((action, outcome), count) in &inner.audit {
            let _ = writeln!(
                out,
                "flowsentinel_audit_events_total{{action=\"{action}\",outcome=\"{outcome}\"}} {count}"
            );
        }
        drop(inner);
        for (name, help, value) in gauges {
            let _ = writeln!(
                out,
                "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {value}"
            );
        }
        out
    }
}

/// Escapes a label value for the text format.
fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// Accepts a client's request ID if it is short and plain.
fn valid_request_id(value: &HeaderValue) -> Option<String> {
    parse_request_id(value.to_str().ok()?)
}

/// A request ID: 1 to 64 letters, digits, `.`, `_` or `-`.
pub fn parse_request_id(text: &str) -> Option<String> {
    let ok = (1..=64).contains(&text.len())
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    ok.then(|| text.to_owned())
}

fn new_request_id() -> String {
    let mut bytes = [0u8; 16];
    // A failure leaves zeros: the ID is for correlation, not security.
    let _ = getrandom::fill(&mut bytes);
    let mut text = String::with_capacity(32);
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// A request being answered. Writes the access line and the metrics when
/// [`finish`](Self::finish)ed, or with [`CLIENT_CLOSED`] when dropped
/// unfinished because the client went away.
struct Pending {
    metrics: Arc<Metrics>,
    method: &'static str,
    path: String,
    route: RouteSlot,
    started: Instant,
    span: tracing::Span,
    finished: bool,
}

impl Pending {
    fn finish(&mut self, status: u16) {
        self.finished = true;
        let elapsed = self.started.elapsed();
        let route = route_label(&self.path, self.route.0.get().map(String::as_str), status);
        self.span.in_scope(|| {
            tracing::info!(
                target: "access",
                route = %route,
                status,
                duration_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
                "request"
            );
        });
        self.metrics
            .record_request(self.method, route, status, elapsed);
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        if !self.finished {
            self.finish(CLIENT_CLOSED);
        }
    }
}

/// Outermost middleware: request ID, request span, access log, metrics.
pub async fn observe(
    State(metrics): State<Arc<Metrics>>,
    mut request: Request,
    next: Next,
) -> Response {
    let id = request
        .headers()
        .get(&REQUEST_ID_HEADER)
        .and_then(valid_request_id)
        .unwrap_or_else(new_request_id);
    let route = RouteSlot::default();
    request.extensions_mut().insert(RequestId(id.clone()));
    request.extensions_mut().insert(route.clone());
    let method = method_label(request.method());
    // At ERROR level, so that no log filter can drop the span while
    // keeping the warnings and errors that should carry its request ID.
    let span = tracing::error_span!("request", request_id = %id, method);
    let mut pending = Pending {
        metrics,
        method,
        path: request.uri().path().to_owned(),
        route,
        started: Instant::now(),
        span: span.clone(),
        finished: false,
    };
    let mut response = next.run(request).instrument(span).await;
    pending.finish(response.status().as_u16());
    if let Ok(value) = HeaderValue::try_from(id) {
        response.headers_mut().insert(REQUEST_ID_HEADER, value);
    }
    response
}

/// Route-level middleware: records the matched route template for
/// [`observe`]. It is the outermost route layer, so the template is recorded
/// even when an inner layer refuses the request.
pub async fn mark_route(request: Request, next: Next) -> Response {
    if let (Some(slot), Some(matched)) = (
        request.extensions().get::<RouteSlot>(),
        request.extensions().get::<MatchedPath>(),
    ) {
        let _ = slot.0.set(matched.as_str().to_owned());
    }
    next.run(request).await
}

/// Gauges read when metrics are scraped.
pub type GaugeSource = Arc<dyn Fn() -> Vec<(&'static str, &'static str, f64)> + Send + Sync>;

/// The metrics listener's router: `GET /metrics` only.
pub fn metrics_router(metrics: Arc<Metrics>, gauges: GaugeSource) -> Router {
    Router::new()
        .route(
            "/metrics",
            get(move || {
                let metrics = Arc::clone(&metrics);
                let gauges = Arc::clone(&gauges);
                async move {
                    let values = gauges();
                    let body = metrics.render(&values);
                    (
                        [(
                            header::CONTENT_TYPE,
                            HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
                        )],
                        body,
                    )
                }
            }),
        )
        .fallback(|| async { (StatusCode::NOT_FOUND, "not found\n").into_response() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_ids_are_accepted_only_when_plain() {
        for ok in ["abc-123", "req_1.2", &"a".repeat(64)] {
            assert_eq!(
                valid_request_id(&HeaderValue::from_str(ok).unwrap()),
                Some(ok.to_owned())
            );
        }
        for bad in ["", "has space", "quote\"", &"a".repeat(65), "new\u{7f}line"] {
            let value = HeaderValue::from_bytes(bad.as_bytes());
            assert!(
                value.map_or(true, |v| valid_request_id(&v).is_none()),
                "{bad:?}"
            );
        }
        let generated = new_request_id();
        assert_eq!(generated.len(), 32);
        assert_ne!(generated, new_request_id());
    }

    #[test]
    fn routes_are_labelled_from_fixed_sets() {
        assert_eq!(method_label(&Method::GET), "GET");
        assert_eq!(method_label(&Method::from_bytes(b"BREW").unwrap()), "OTHER");
        assert_eq!(
            route_label("/api/v1/captures/7", Some("/api/v1/captures/{id}"), 200),
            "/api/v1/captures/{id}"
        );
        assert_eq!(route_label("/api/v1/nope", None, 404), "unmatched");
        assert_eq!(
            route_label("/api/v1/overview", None, 405),
            "method_not_allowed"
        );
        assert_eq!(route_label("/api/v1/overview", None, 421), "misdirected");
        assert_eq!(route_label("/captures/7", None, 421), "misdirected");
        assert_eq!(route_label("/captures/7/flows", None, 200), "dashboard");
        assert_eq!(route_label("/health", None, 200), "/health");
        assert_eq!(route_label("/api/v1/x", None, CLIENT_CLOSED), "unmatched");
    }

    #[test]
    fn the_exposition_is_well_formed() {
        let metrics = Metrics::default();
        metrics.record_request(
            "GET",
            "/api/v1/captures".into(),
            200,
            Duration::from_millis(3),
        );
        metrics.record_request(
            "GET",
            "/api/v1/captures".into(),
            200,
            Duration::from_millis(30),
        );
        metrics.record_request(
            "POST",
            "/api/v1/auth/login".into(),
            401,
            Duration::from_secs(20),
        );
        metrics.record_audit("auth.login", "failure");
        let text = metrics.render(&[("flowsentinel_test_gauge", "A test gauge.", 2.0)]);
        assert!(text.contains(
            "flowsentinel_http_requests_total{method=\"GET\",route=\"/api/v1/captures\",status=\"200\"} 2"
        ));
        assert!(text.contains(
            "flowsentinel_http_request_duration_seconds_bucket{method=\"GET\",route=\"/api/v1/captures\",le=\"0.005\"} 1"
        ));
        assert!(text.contains(
            "flowsentinel_http_request_duration_seconds_bucket{method=\"GET\",route=\"/api/v1/captures\",le=\"0.05\"} 2"
        ));
        // Slower than every bucket: counted only in +Inf.
        assert!(text.contains(
            "flowsentinel_http_request_duration_seconds_bucket{method=\"POST\",route=\"/api/v1/auth/login\",le=\"10\"} 0"
        ));
        assert!(text.contains(
            "flowsentinel_http_request_duration_seconds_count{method=\"POST\",route=\"/api/v1/auth/login\"} 1"
        ));
        assert!(text.contains(
            "flowsentinel_audit_events_total{action=\"auth.login\",outcome=\"failure\"} 1"
        ));
        assert!(text.contains("# TYPE flowsentinel_test_gauge gauge\nflowsentinel_test_gauge 2"));
        assert_eq!(escape("a\"b\\c"), "a\\\"b\\\\c");
        // Every sample line is "name{labels} value" or "name value".
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            let value = line.rsplit(' ').next().unwrap();
            assert!(value.parse::<f64>().is_ok(), "{line}");
        }
    }
}

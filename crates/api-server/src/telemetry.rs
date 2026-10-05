//! Logging and tracing setup.
//!
//! Logs are JSON lines on stdout, filtered by `RUST_LOG` (default `info`).
//! Each line written while a request is handled carries the request's span,
//! with its `request_id` (see [`crate::observability`]).
//!
//! With the `otel` feature, spans are also exported with OpenTelemetry
//! (OTLP over HTTP/protobuf) when `OTEL_EXPORTER_OTLP_ENDPOINT` or
//! `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` is set; the exporter reads the
//! standard `OTEL_*` variables. Spans carry route templates, methods,
//! statuses and request IDs, never request bodies, query strings or packet
//! data.

use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// Keeps the exporter alive; [`shutdown`](Self::shutdown) flushes it.
#[derive(Debug, Default)]
pub struct Telemetry {
    #[cfg(feature = "otel")]
    provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
}

impl Telemetry {
    /// Whether spans are being exported.
    pub fn exporting(&self) -> bool {
        #[cfg(feature = "otel")]
        {
            self.provider.is_some()
        }
        #[cfg(not(feature = "otel"))]
        {
            false
        }
    }

    /// Flushes and stops the exporter, if any.
    pub fn shutdown(self) {
        #[cfg(feature = "otel")]
        if let Some(provider) = self.provider {
            if let Err(err) = provider.shutdown() {
                tracing::warn!(error = %err, "OpenTelemetry shutdown failed");
            }
        }
    }
}

/// Installs the global subscriber. `lookup` reads environment variables.
pub fn init(lookup: impl Fn(&str) -> Option<String>) -> Result<Telemetry, String> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let logs = tracing_subscriber::fmt::layer()
        .json()
        .with_current_span(true)
        .with_span_list(false);
    let registry = tracing_subscriber::registry().with(filter).with(logs);
    #[cfg(feature = "otel")]
    {
        let wanted = [
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
        ]
        .iter()
        .any(|name| lookup(name).is_some_and(|v| !v.trim().is_empty()));
        if wanted {
            let (layer, provider) = otel::layer(None)?;
            registry.with(layer).init();
            return Ok(Telemetry {
                provider: Some(provider),
            });
        }
    }
    #[cfg(not(feature = "otel"))]
    let _ = lookup;
    registry.init();
    Ok(Telemetry::default())
}

#[cfg(feature = "otel")]
pub mod otel {
    //! The OpenTelemetry layer.

    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_otlp::WithExportConfig;
    use opentelemetry_sdk::Resource;
    use opentelemetry_sdk::trace::SdkTracerProvider;

    /// A layer exporting spans with OTLP/HTTP. `endpoint` overrides the
    /// `OTEL_EXPORTER_OTLP_*` variables (tests use it).
    pub fn layer<S>(
        endpoint: Option<&str>,
    ) -> Result<
        (
            tracing_opentelemetry::OpenTelemetryLayer<S, opentelemetry_sdk::trace::Tracer>,
            SdkTracerProvider,
        ),
        String,
    >
    where
        S: tracing::Subscriber + for<'span> tracing_subscriber::registry::LookupSpan<'span>,
    {
        let mut builder = opentelemetry_otlp::SpanExporter::builder().with_http();
        if let Some(endpoint) = endpoint {
            builder = builder.with_endpoint(endpoint);
        }
        let exporter = builder.build().map_err(|e| e.to_string())?;
        let provider = SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .with_resource(
                Resource::builder()
                    .with_service_name(crate::SERVICE_NAME)
                    .build(),
            )
            .build();
        let tracer = provider.tracer(crate::SERVICE_NAME);
        Ok((tracing_opentelemetry::layer().with_tracer(tracer), provider))
    }
}

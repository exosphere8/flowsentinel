# FlowSentinel API server with the built dashboard.
#
#   docker compose --profile app up --build
#
# Three stages: the dashboard is built with Node, the server with Rust, and the
# runtime image holds only the server binary, the dashboard files, CA
# certificates and libpcap, running as an unprivileged user. Live capture is
# compiled in but off (FLOWSENTINEL_LIVE_CAPTURE), and the container has no
# capture capability unless an operator adds it (see docs/permissions.md).
# OpenTelemetry export is compiled in and used only when
# OTEL_EXPORTER_OTLP_ENDPOINT is set (see docs/observability.md).

FROM node:22-trixie-slim AS dashboard
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
COPY docs/openapi.json /src/docs/openapi.json
RUN npm run check:api && npm run build

FROM rust:1.97-slim-trixie AS server
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked -p api-server --features live-capture,otel

FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libpcap0.8t64 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --user-group --home-dir /nonexistent --shell /usr/sbin/nologin flowsentinel \
    && install -d -o 10001 -g 10001 -m 0700 /var/lib/flowsentinel/uploads
COPY --from=server /src/target/release/api-server /usr/local/bin/flowsentinel-api
COPY --from=dashboard /src/frontend/dist /srv/dashboard
ENV FLOWSENTINEL_API_ADDR=0.0.0.0:8080 \
    FLOWSENTINEL_DASHBOARD_DIR=/srv/dashboard \
    FLOWSENTINEL_UPLOAD_DIR=/var/lib/flowsentinel/uploads
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=6s --start-period=20s --retries=5 \
    CMD ["/usr/local/bin/flowsentinel-api", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/flowsentinel-api"]

#!/usr/bin/env bash
# Smoke-tests a running API server: GET /health must return the exact contract.
# Usage: scripts/smoke-test.sh [base-url]   (default http://127.0.0.1:8080)
set -euo pipefail

base_url="${1:-http://127.0.0.1:8080}"
expected='{"status":"ok","service":"flowsentinel-api"}'

actual="$(curl --silent --show-error --fail --max-time 5 "${base_url}/health")"
if [[ "${actual}" != "${expected}" ]]; then
  echo "FAIL: unexpected /health body: ${actual}" >&2
  exit 1
fi
echo "OK: ${base_url}/health -> ${actual}"

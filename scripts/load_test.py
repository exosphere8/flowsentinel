#!/usr/bin/env python3
"""Load test for a running FlowSentinel API server (standard library only).

Signs in once, imports a synthetic fixture if no capture exists, then runs
CONCURRENCY clients that request a mix of read endpoints for DURATION
seconds, and reports requests per second, errors and latency percentiles
per endpoint. Point it only at a server you run for testing.

    FLOWSENTINEL_LOAD_PASSWORD=... python3 scripts/load_test.py \
        --url http://127.0.0.1:8080 --username admin --concurrency 16 --duration 30
"""

import argparse
import http.cookiejar
import json
import os
import statistics
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "pcap" / "detect-mixed.pcap"


class Client:
    def __init__(self, base, cookies, csrf):
        self.base = base
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookies))
        self.csrf = csrf

    def request(self, method, path, body=None, content_type="application/json"):
        headers = {"Content-Type": content_type}
        if self.csrf and method != "GET":
            headers["X-CSRF-Token"] = self.csrf
        req = urllib.request.Request(self.base + path, data=body, method=method, headers=headers)
        try:
            with self.opener.open(req, timeout=30) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.read()


def sign_in(base, username, password):
    cookies = http.cookiejar.CookieJar()
    client = Client(base, cookies, None)
    body = json.dumps({"username": username, "password": password}).encode()
    status, data = client.request("POST", "/api/v1/auth/login", body)
    if status != 200:
        sys.exit(f"sign-in failed with {status}: {data[:200]!r}")
    client.csrf = json.loads(data)["csrf_token"]
    return client


def percentile(values, fraction):
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(fraction * len(ordered)))]


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", default="http://127.0.0.1:8080")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--concurrency", type=int, default=16)
    parser.add_argument("--duration", type=float, default=30.0)
    args = parser.parse_args()
    password = os.environ.get("FLOWSENTINEL_LOAD_PASSWORD")
    if not password:
        sys.exit("set FLOWSENTINEL_LOAD_PASSWORD to the account's password")

    client = sign_in(args.url, args.username, password)
    status, data = client.request("GET", "/api/v1/captures?per_page=1")
    captures = json.loads(data)["items"] if status == 200 else []
    if captures:
        capture_id = captures[0]["id"]
    else:
        status, data = client.request(
            "POST",
            "/api/v1/captures?file_name=detect-mixed.pcap",
            FIXTURE.read_bytes(),
            "application/vnd.tcpdump.pcap",
        )
        if status != 201:
            sys.exit(f"import failed with {status}: {data[:200]!r}")
        capture_id = json.loads(data)["id"]

    endpoints = [
        f"/api/v1/captures/{capture_id}",
        f"/api/v1/captures/{capture_id}/packets?per_page=100",
        f"/api/v1/captures/{capture_id}/flows?sort=-bytes",
        f"/api/v1/captures/{capture_id}/flows?filter=alert.severity%20%3D%3D%20high",
        f"/api/v1/captures/{capture_id}/alerts",
        "/api/v1/overview",
    ]
    results = {path: [] for path in endpoints}
    errors = {path: 0 for path in endpoints}
    statuses = {}
    lock = threading.Lock()
    deadline = time.monotonic() + args.duration

    def worker(offset):
        i = offset
        while time.monotonic() < deadline:
            path = endpoints[i % len(endpoints)]
            i += 1
            started = time.monotonic()
            status, _ = client.request("GET", path)
            elapsed = time.monotonic() - started
            with lock:
                results[path].append(elapsed)
                statuses[status] = statuses.get(status, 0) + 1
                if status != 200:
                    errors[path] += 1

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(args.concurrency)]
    started = time.monotonic()
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    wall = time.monotonic() - started

    total = sum(len(v) for v in results.values())
    failed = sum(errors.values())
    print(f"{args.concurrency} clients for {wall:.1f} s: {total} requests, "
          f"{total / wall:.0f} requests/s, {failed} errors")
    print("statuses: " + ", ".join(f"{code}: {count}" for code, count in sorted(statuses.items())))
    print(f"{'endpoint':<72} {'count':>6} {'p50 ms':>8} {'p95 ms':>8} {'p99 ms':>8} {'errors':>6}")
    for path in endpoints:
        times = results[path]
        if not times:
            continue
        print(f"{path:<72} {len(times):>6} {statistics.median(times) * 1000:>8.1f} "
              f"{percentile(times, 0.95) * 1000:>8.1f} {percentile(times, 0.99) * 1000:>8.1f} "
              f"{errors[path]:>6}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

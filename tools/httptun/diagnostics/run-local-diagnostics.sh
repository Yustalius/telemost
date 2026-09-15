#!/bin/bash

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../../.." && pwd)
RESULT_ROOT="${HTTPTUN_LOCAL_RESULT_ROOT:-$REPO_ROOT/target/httptun-local-diagnostics}"
RUN_ID="local-$(date -u '+%Y%m%dT%H%M%SZ')"
RESULT_DIR="$RESULT_ROOT/$RUN_ID"
SERVER_PORT=19444
FRONT_PORT=19500
SERVER_PID=""
FRONT_PID=""

cleanup() {
    [ -z "$FRONT_PID" ] || kill "$FRONT_PID" 2>/dev/null || true
    [ -z "$SERVER_PID" ] || kill "$SERVER_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

mkdir -p "$RESULT_DIR"
cd "$REPO_ROOT"

printf '[INFO] cargo test -p httptun\n'
cargo test -p httptun --locked -- --test-threads=1 | tee "$RESULT_DIR/cargo-test.log"
printf '[INFO] cargo check --lib --locked\n'
cargo check --lib --locked | tee "$RESULT_DIR/cargo-check.log"
cargo build -p httptun --bins --locked

target/debug/httptun-server \
    --listen "127.0.0.1:$SERVER_PORT" \
    --echo \
    --poll-wait-sec 5 \
    --diagnostics-jsonl "$RESULT_DIR/server-events.jsonl" \
    >"$RESULT_DIR/server.log" 2>&1 &
SERVER_PID=$!

attempt=0
while ! nc -z 127.0.0.1 "$SERVER_PORT" >/dev/null 2>&1 && [ "$attempt" -lt 40 ]; do
    sleep 0.25
    attempt=$((attempt + 1))
done
kill -0 "$SERVER_PID" 2>/dev/null || { printf '[FAIL] local server failed\n' >&2; exit 1; }

for delay in 50 250 1000; do
    port=$((FRONT_PORT + delay / 50))
    python3 "$SCRIPT_DIR/http1_buffer_front.py" \
        --listen "127.0.0.1:$port" \
        --backend "https://127.0.0.1:$SERVER_PORT" \
        --delay-ms "$delay" \
        >"$RESULT_DIR/front-$delay.log" 2>&1 &
    FRONT_PID=$!
    attempt=0
    while ! nc -z 127.0.0.1 "$port" >/dev/null 2>&1 && [ "$attempt" -lt 40 ]; do
        sleep 0.25
        attempt=$((attempt + 1))
    done
    printf '[INFO] whole-body front delay=%sms\n' "$delay"
    target/debug/httptun-client \
        --server "http://127.0.0.1:$port" \
        --wire-api v2 \
        --mode batch \
        --no-proxy \
        --selftest-ping \
        --count 12 \
        --size 256 \
        --timeout-sec 15 \
        --retry-window-sec 30 \
        --diagnostics-jsonl "$RESULT_DIR/client-$delay-events.jsonl" \
        >"$RESULT_DIR/ping-$delay.json"
    target/debug/httptun-client \
        --server "http://127.0.0.1:$port" \
        --wire-api v2 \
        --mode batch \
        --no-proxy \
        --throughput \
        --seconds 3 \
        --timeout-sec 15 \
        --retry-window-sec 30 \
        >"$RESULT_DIR/throughput-$delay.json"
    kill "$FRONT_PID" 2>/dev/null || true
    wait "$FRONT_PID" 2>/dev/null || true
    FRONT_PID=""
done

python3 - "$RESULT_DIR" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
rows = []
for delay in (50, 250, 1000):
    ping = json.loads((root / f"ping-{delay}.json").read_text())
    throughput = json.loads((root / f"throughput-{delay}.json").read_text())
    rows.append({"delay_ms": delay, "ping": ping, "throughput": throughput})
(root / "report.json").write_text(json.dumps({"schema": 1, "profile": "A-v2-baseline", "whole_body_buffering": rows}, indent=2) + "\n")
lines = [
    "# Local reverse httptun diagnostic preflight",
    "",
    "| Whole-body delay | p50 RTT ms | p95 RTT ms | lost | throughput Mbps |",
    "|---:|---:|---:|---:|---:|",
]
for row in rows:
    lines.append(
        f"| {row['delay_ms']} ms | {row['ping']['rtt_ms']['p50']} | "
        f"{row['ping']['rtt_ms']['p95']} | {row['ping']['lost']} | "
        f"{row['throughput']['mbps']} |"
    )
lines.extend([
    "",
    "The cargo suite includes lost-open, lost-ACK, duplicate-send and replay checks. "
    "All three delay profiles buffer complete finite HTTP/1.1 bodies.",
])
(root / "summary.md").write_text("\n".join(lines) + "\n")
PY

printf '[READY] local report: %s/summary.md\n' "$RESULT_DIR"

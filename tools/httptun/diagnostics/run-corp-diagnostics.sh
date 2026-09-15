#!/bin/bash

set -uo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PACKAGE_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
STATE_DIR="${HTTPTUN_STATE_DIR:-$HOME/.telemost-vpn}"
RESULT_ROOT="${HTTPTUN_RESULT_ROOT:-$STATE_DIR/diagnostics}"
SERVER_URL="${HTTPTUN_SERVER_URL:-https://ya-telemost.site}"
CORP_URL="${HTTPTUN_CORP_URL:-https://retest-agent.apps.yd-m6-kt66.vimpelcom.ru/}"
CORP_NOPROXY="${HTTPTUN_CORP_NOPROXY:-beeline.ru,vimpelcom.ru}"
PX_PORT="${HTTPTUN_PX_PORT:-3129}"
DIAGNOSTIC_ENDPOINT="${HTTPTUN_DIAGNOSTIC_ENDPOINT:-diag}"
DIAGNOSTIC_TARGET="${HTTPTUN_DIAGNOSTIC_TARGET:-127.0.0.1:13131}"
PASSES=3
TRACE=0

usage() {
    printf '%s\n' \
        "Использование: $0 [--quick] [--trace]" \
        "  --quick  один проход вместо трёх" \
        "  --trace  попытаться снять pcap внешнего TLS-трафика через sudo -n"
}

for arg in "$@"; do
    case "$arg" in
        --quick) PASSES=1 ;;
        --trace) TRACE=1 ;;
        --help | -h)
            usage
            exit 0
            ;;
        *) printf '[FAIL] неизвестный аргумент: %s\n' "$arg" >&2; exit 2 ;;
    esac
done

command -v python3 >/dev/null 2>&1 || { printf '[FAIL] python3 не найден\n' >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { printf '[FAIL] curl не найден\n' >&2; exit 1; }
command -v lsof >/dev/null 2>&1 || { printf '[FAIL] lsof не найден\n' >&2; exit 1; }

CLIENT_SOURCE="${HTTPTUN_CLIENT_BIN:-}"
if [ -z "$CLIENT_SOURCE" ]; then
    for candidate in \
        "$PACKAGE_DIR/httptun-client" \
        "$PACKAGE_DIR/../../target/release/httptun-client" \
        "$STATE_DIR/httptun-client"; do
        if [ -x "$candidate" ]; then
            CLIENT_SOURCE="$candidate"
            break
        fi
    done
fi
[ -n "$CLIENT_SOURCE" ] && [ -x "$CLIENT_SOURCE" ] \
    || { printf '[FAIL] httptun-client не найден; укажи HTTPTUN_CLIENT_BIN\n' >&2; exit 1; }
[ -s "$STATE_DIR/httptun-token" ] \
    || { printf '[FAIL] нет %s/httptun-token\n' "$STATE_DIR" >&2; exit 1; }

mkdir -p "$STATE_DIR" "$RESULT_ROOT"
chmod 700 "$STATE_DIR" "$RESULT_ROOT"
RUN_ID="diag-$(date -u '+%Y%m%dT%H%M%SZ')"
RESULT_DIR="$RESULT_ROOT/$RUN_ID"
mkdir -p "$RESULT_DIR"
chmod 700 "$RESULT_DIR"

INSTALLED_CLIENT="$STATE_DIR/httptun-client"
if [ "$CLIENT_SOURCE" != "$INSTALLED_CLIENT" ] && ! cmp -s "$CLIENT_SOURCE" "$INSTALLED_CLIENT" 2>/dev/null; then
    if [ -f "$INSTALLED_CLIENT" ]; then
        cp -p "$INSTALLED_CLIENT" "$RESULT_DIR/httptun-client.previous"
    fi
    install -m 0755 "$CLIENT_SOURCE" "$INSTALLED_CLIENT"
fi

LAUNCHER="${HTTPTUN_LAUNCHER:-$PACKAGE_DIR/httptun-corp-launch.sh}"
[ -x "$LAUNCHER" ] || { printf '[FAIL] launcher не найден: %s\n' "$LAUNCHER" >&2; exit 1; }
TARGET_SCRIPT="$SCRIPT_DIR/reverse_diag_target.py"
ANALYZER="$SCRIPT_DIR/analyze.py"
PROBE="$SCRIPT_DIR/curl_probe.py"
for required in "$TARGET_SCRIPT" "$ANALYZER" "$PROBE"; do
    [ -f "$required" ] || { printf '[FAIL] нет файла %s\n' "$required" >&2; exit 1; }
done

TARGET_PORT=${DIAGNOSTIC_TARGET##*:}
if lsof -nP -iTCP:"$TARGET_PORT" -sTCP:LISTEN >/dev/null 2>&1; then
    printf '[FAIL] diagnostic target port %s уже занят\n' "$TARGET_PORT" >&2
    exit 1
fi

TARGET_PID=""
SAMPLER_PID=""
TRACE_PID=""
cleanup() {
    [ -z "$SAMPLER_PID" ] || kill "$SAMPLER_PID" 2>/dev/null || true
    [ -z "$TRACE_PID" ] || sudo -n kill "$TRACE_PID" 2>/dev/null || true
    [ -z "$TARGET_PID" ] || kill "$TARGET_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

python3 "$TARGET_SCRIPT" \
    --listen "$DIAGNOSTIC_TARGET" \
    --events "$RESULT_DIR/target-events.jsonl" \
    >"$RESULT_DIR/target.log" 2>&1 &
TARGET_PID=$!
attempt=0
while ! lsof -nP -iTCP:"$TARGET_PORT" -sTCP:LISTEN >/dev/null 2>&1 && [ "$attempt" -lt 40 ]; do
    sleep 0.25
    attempt=$((attempt + 1))
done
kill -0 "$TARGET_PID" 2>/dev/null \
    || { printf '[FAIL] diagnostic target не запустился; см. %s/target.log\n' "$RESULT_DIR" >&2; exit 1; }

if [ "$TRACE" -eq 1 ]; then
    VPS_IP=$(python3 -c 'import socket; print(socket.gethostbyname("ya-telemost.site"))' 2>/dev/null || true)
    if [ -n "$VPS_IP" ] && sudo -n tcpdump -D >/dev/null 2>&1; then
        sudo -n tcpdump -i any -nn -s 96 -w "$RESULT_DIR/tls-trace.pcap" "host $VPS_IP and tcp port 443" \
            >"$RESULT_DIR/tcpdump.log" 2>&1 &
        TRACE_PID=$!
    else
        printf '%s\n' packet_capture_unavailable >"$RESULT_DIR/trace-skipped.txt"
    fi
fi

if [ -f "$STATE_DIR/httptun-reverse.log" ]; then
    cp "$STATE_DIR/httptun-reverse.log" "$RESULT_DIR/httptun-reverse.previous.log"
fi

printf '[INFO] запуск reverse client и dedicated px\n'
if ! HTTPTUN_STATE_DIR="$STATE_DIR" \
    HTTPTUN_CORP_NOPROXY="$CORP_NOPROXY" \
    HTTPTUN_SERVER_URL="$SERVER_URL" \
    HTTPTUN_CORP_URL="$CORP_URL" \
    HTTPTUN_DIAGNOSTIC_ENDPOINT="$DIAGNOSTIC_ENDPOINT" \
    HTTPTUN_DIAGNOSTIC_TARGET="$DIAGNOSTIC_TARGET" \
    HTTPTUN_DIAGNOSTICS_JSONL="$RESULT_DIR/client-events.jsonl" \
    "$LAUNCHER" --diagnostic; then
    printf '[FAIL] launcher завершился с ошибкой\n' >&2
    exit 1
fi

attempt=0
while ! grep -q "reverse endpoint $DIAGNOSTIC_ENDPOINT claimed" "$STATE_DIR/httptun-reverse.log" 2>/dev/null \
    && [ "$attempt" -lt 120 ]; do
    sleep 0.5
    attempt=$((attempt + 1))
done
grep -q "reverse endpoint $DIAGNOSTIC_ENDPOINT claimed" "$STATE_DIR/httptun-reverse.log" 2>/dev/null \
    || { printf '[FAIL] diagnostic endpoint не claimed за 60 секунд\n' >&2; exit 1; }

CLIENT_PID=$(sed -n '1p' "$STATE_DIR/httptun-reverse.pid")
printf 'unix_ms,cpu_percent,rss_kib,threads\n' >"$RESULT_DIR/mac-resources.csv"
(
    while kill -0 "$CLIENT_PID" 2>/dev/null; do
        now=$(date '+%s000')
        ps -p "$CLIENT_PID" -o %cpu= -o rss= -o thcount= 2>/dev/null \
            | awk -v now="$now" '{print now "," $1 "," $2 "," $3}' \
            >>"$RESULT_DIR/mac-resources.csv"
        sleep 1
    done
) &
SAMPLER_PID=$!

{
    printf 'run_id=%s\n' "$RUN_ID"
    printf 'utc_started=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf 'uname=%s\n' "$(uname -a)"
    printf 'client=%s\n' "$($INSTALLED_CLIENT --version 2>/dev/null || true)"
    printf 'server_url=%s\n' "$SERVER_URL"
    printf 'corp_url_host=%s\n' "$(python3 -c 'import sys,urllib.parse; print(urllib.parse.urlsplit(sys.argv[1]).hostname or "")' "$CORP_URL")"
    printf 'corp_noproxy=%s\n' "$CORP_NOPROXY"
    if git -C "$PACKAGE_DIR/../.." rev-parse HEAD >/dev/null 2>&1; then
        printf 'git_revision=%s\n' "$(git -C "$PACKAGE_DIR/../.." rev-parse HEAD)"
    fi
} >"$RESULT_DIR/manifest.txt"

{
    route -n get "${SERVER_URL#https://}" 2>&1 || true
    route -n get "$(python3 -c 'import sys,urllib.parse; print(urllib.parse.urlsplit(sys.argv[1]).hostname or "")' "$CORP_URL")" 2>&1 || true
    scutil --proxy 2>&1 || true
} >"$RESULT_DIR/network-routing.txt"

MEASUREMENTS="$RESULT_DIR/path-measurements.jsonl"
ROUTES="$RESULT_DIR/sso-routes.jsonl"
PX_URL="http://127.0.0.1:$PX_PORT"

printf '[INFO] прогрев HTTP-маршрутов\n'
python3 "$PROBE" --segment mac_direct_corp --pass 0 --test-id "$RUN_ID-warm-direct" \
    --url "$CORP_URL" --mode direct --noproxy "$CORP_NOPROXY" \
    --measurements "$MEASUREMENTS" --routes "$ROUTES" --warmup || true
python3 "$PROBE" --segment mac_px_corp --pass 0 --test-id "$RUN_ID-warm-px-corp" \
    --url "$CORP_URL" --mode proxy --proxy "$PX_URL" \
    --measurements "$MEASUREMENTS" --routes "$ROUTES" --warmup || true
python3 "$PROBE" --segment mac_px_mwg_vps --pass 0 --test-id "$RUN_ID-warm-vps" \
    --url "$SERVER_URL/health" --mode proxy --proxy "$PX_URL" \
    --measurements "$MEASUREMENTS" --routes "$ROUTES" --warmup || true

pass=1
while [ "$pass" -le "$PASSES" ]; do
    printf '[INFO] замер HTTP-маршрутов, проход %s/%s\n' "$pass" "$PASSES"
    python3 "$PROBE" --segment mac_direct_corp --pass "$pass" --test-id "$RUN_ID-p$pass-direct" \
        --url "$CORP_URL" --mode direct --noproxy "$CORP_NOPROXY" \
        --measurements "$MEASUREMENTS" --routes "$ROUTES" || true
    python3 "$PROBE" --segment mac_px_corp --pass "$pass" --test-id "$RUN_ID-p$pass-px-corp" \
        --url "$CORP_URL" --mode proxy --proxy "$PX_URL" \
        --measurements "$MEASUREMENTS" --routes "$ROUTES" || true
    python3 "$PROBE" --segment mac_px_mwg_vps --pass "$pass" --test-id "$RUN_ID-p$pass-vps" \
        --url "$SERVER_URL/health" --mode proxy --proxy "$PX_URL" \
        --measurements "$MEASUREMENTS" --routes "$ROUTES" || true
    pass=$((pass + 1))
done

printf '[INFO] запуск прикладного набора со стороны VPS; SSH не используется\n'
set +e
HTTPS_PROXY="$PX_URL" ALL_PROXY="$PX_URL" NO_PROXY="127.0.0.1,localhost" \
"$INSTALLED_CLIENT" \
    --server "$SERVER_URL" \
    --wire-api v2 \
    --mode batch \
    --proxy "$PX_URL" \
    --token-file "$STATE_DIR/httptun-token" \
    --reverse-diagnostic-run "$DIAGNOSTIC_ENDPOINT" \
    --diagnostic-run-id "$RUN_ID" \
    --diagnostic-passes "$PASSES" \
    --timeout-sec 30 \
    --retry-window-sec 60 \
    --diagnostics-jsonl "$RESULT_DIR/control-events.jsonl" \
    >"$RESULT_DIR/vps-run.json" 2>"$RESULT_DIR/vps-run.err"
VPS_RUN_STATUS=$?
set -e

cp "$STATE_DIR/httptun-reverse.log" "$RESULT_DIR/client.log" 2>/dev/null || true
cp "$STATE_DIR/httptun-reverse-px.log" "$RESULT_DIR/px.log" 2>/dev/null || true
printf 'vps_run_exit=%s\n' "$VPS_RUN_STATUS" >>"$RESULT_DIR/manifest.txt"

python3 "$ANALYZER" "$RESULT_DIR"
ARCHIVE="$RESULT_ROOT/$RUN_ID.tar.gz"
tar -C "$RESULT_ROOT" -czf "$ARCHIVE" "$RUN_ID"

printf '\n[READY] Отчёт: %s/summary.md\n' "$RESULT_DIR"
printf '[READY] JSON: %s/report.json\n' "$RESULT_DIR"
printf '[READY] Пакет: %s\n' "$ARCHIVE"
exit "$VPS_RUN_STATUS"

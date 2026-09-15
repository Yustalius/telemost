#!/bin/bash

set -euo pipefail

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

for command in python3 curl lsof; do
    command -v "$command" >/dev/null 2>&1 \
        || { printf '[FAIL] %s не найден\n' "$command" >&2; exit 1; }
done
[ -s "$STATE_DIR/httptun-token" ] \
    || { printf '[FAIL] нет %s/httptun-token\n' "$STATE_DIR" >&2; exit 1; }
[ -s "$STATE_DIR/reverse-owner-id" ] \
    || { printf '[FAIL] нет %s/reverse-owner-id\n' "$STATE_DIR" >&2; exit 1; }

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

LAUNCHER="${HTTPTUN_LAUNCHER:-$PACKAGE_DIR/httptun-corp-launch.sh}"
TARGET_SCRIPT="$SCRIPT_DIR/reverse_diag_target.py"
PROBE="$SCRIPT_DIR/curl_probe.py"
ANALYZER="$SCRIPT_DIR/analyze-comparison.py"
for required in "$LAUNCHER" "$TARGET_SCRIPT" "$PROBE" "$ANALYZER"; do
    [ -f "$required" ] || { printf '[FAIL] нет файла %s\n' "$required" >&2; exit 1; }
done

mkdir -p "$STATE_DIR" "$RESULT_ROOT"
chmod 700 "$STATE_DIR" "$RESULT_ROOT"
RUN_ID="compare-$(date -u '+%Y%m%dT%H%M%SZ')"
RESULT_DIR="$RESULT_ROOT/$RUN_ID"
mkdir -p "$RESULT_DIR/profiles"
chmod 700 "$RESULT_DIR"

INSTALLED_CLIENT="$STATE_DIR/httptun-client"
if [ "$CLIENT_SOURCE" != "$INSTALLED_CLIENT" ] && ! cmp -s "$CLIENT_SOURCE" "$INSTALLED_CLIENT" 2>/dev/null; then
    if [ -f "$INSTALLED_CLIENT" ]; then
        cp -p "$INSTALLED_CLIENT" "$RESULT_DIR/httptun-client.previous"
    fi
    install -m 0755 "$CLIENT_SOURCE" "$INSTALLED_CLIENT"
fi

TARGET_PID=""
EXPERIMENT_PID=""
SAMPLER_PID=""
stop_sampler() {
    if [ -n "$SAMPLER_PID" ]; then
        kill "$SAMPLER_PID" 2>/dev/null || true
        wait "$SAMPLER_PID" 2>/dev/null || true
        SAMPLER_PID=""
    fi
}
stop_experiment() {
    stop_sampler
    if [ -n "$EXPERIMENT_PID" ]; then
        kill "$EXPERIMENT_PID" 2>/dev/null || true
        attempt=0
        while kill -0 "$EXPERIMENT_PID" 2>/dev/null && [ "$attempt" -lt 20 ]; do
            sleep 0.25
            attempt=$((attempt + 1))
        done
        EXPERIMENT_PID=""
    fi
}
cleanup() {
    stop_experiment
    [ -z "$TARGET_PID" ] || kill "$TARGET_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

TARGET_PORT=${DIAGNOSTIC_TARGET##*:}
if lsof -nP -iTCP:"$TARGET_PORT" -sTCP:LISTEN >/dev/null 2>&1; then
    printf '[FAIL] diagnostic target port %s уже занят\n' "$TARGET_PORT" >&2
    exit 1
fi
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
    || { printf '[FAIL] diagnostic target не запустился\n' >&2; exit 1; }

printf '[INFO] оставляю production endpoint probe на baseline A\n'
env -u HTTPTUN_DIAGNOSTIC_ENDPOINT \
    -u HTTPTUN_DIAGNOSTIC_TARGET \
    -u HTTPTUN_DIAGNOSTICS_JSONL \
    HTTPTUN_STATE_DIR="$STATE_DIR" \
    HTTPTUN_REVERSE_ENDPOINT=probe \
    HTTPTUN_CORP_NOPROXY="$CORP_NOPROXY" \
    HTTPTUN_SERVER_URL="$SERVER_URL" \
    HTTPTUN_CORP_URL="$CORP_URL" \
    "$LAUNCHER" --diagnostic

PX_URL="http://127.0.0.1:$PX_PORT"
MEASUREMENTS="$RESULT_DIR/path-measurements.jsonl"
ROUTES="$RESULT_DIR/sso-routes.jsonl"
printf '[INFO] прогрев исправленных HTTP-маршрутов\n'
python3 "$PROBE" --segment mac_direct_corp --pass 0 --test-id "$RUN_ID-warm-direct" \
    --url "$CORP_URL" --mode direct --noproxy "$CORP_NOPROXY" \
    --measurements "$MEASUREMENTS" --routes "$ROUTES" --warmup || true
python3 "$PROBE" --segment mac_px_corp --pass 0 --test-id "$RUN_ID-warm-px-corp" \
    --url "$CORP_URL" --mode proxy --proxy "$PX_URL" \
    --measurements "$MEASUREMENTS" --routes "$ROUTES" --warmup || true
python3 "$PROBE" --segment mac_px_mwg_vps --pass 0 --test-id "$RUN_ID-warm-vps" \
    --url "$SERVER_URL/health" --mode proxy --proxy "$PX_URL" \
    --measurements "$MEASUREMENTS" --routes "$ROUTES" --warmup || true

for pass in 1 2 3; do
    python3 "$PROBE" --segment mac_direct_corp --pass "$pass" --test-id "$RUN_ID-p$pass-direct" \
        --url "$CORP_URL" --mode direct --noproxy "$CORP_NOPROXY" \
        --measurements "$MEASUREMENTS" --routes "$ROUTES" || true
    python3 "$PROBE" --segment mac_px_corp --pass "$pass" --test-id "$RUN_ID-p$pass-px-corp" \
        --url "$CORP_URL" --mode proxy --proxy "$PX_URL" \
        --measurements "$MEASUREMENTS" --routes "$ROUTES" || true
    python3 "$PROBE" --segment mac_px_mwg_vps --pass "$pass" --test-id "$RUN_ID-p$pass-vps" \
        --url "$SERVER_URL/health" --mode proxy --proxy "$PX_URL" \
        --measurements "$MEASUREMENTS" --routes "$ROUTES" || true
done

start_experiment() {
    local profile=$1
    local batch_kib=$2
    local pass=$3
    local run_dir=$4
    local experiment_args=()
    if [ -n "$batch_kib" ]; then
        experiment_args=(--experimental-batch-kib "$batch_kib")
    fi
    : >"$run_dir/client.log"
    HTTPS_PROXY="$PX_URL" \
    ALL_PROXY="$PX_URL" \
    NO_PROXY="127.0.0.1,localhost" \
    RUST_LOG="httptun=trace" \
    nohup "$INSTALLED_CLIENT" \
        --server "$SERVER_URL" \
        --wire-api v2 \
        --mode batch \
        --proxy "$PX_URL" \
        --token-file "$STATE_DIR/httptun-token" \
        --reverse-owner-file "$STATE_DIR/reverse-owner-id" \
        --reverse-map "$DIAGNOSTIC_ENDPOINT->$DIAGNOSTIC_TARGET" \
        --timeout-sec 30 \
        --retry-window-sec 60 \
        --diagnostics-jsonl "$run_dir/client-events.jsonl" \
        "${experiment_args[@]}" \
        -vv >"$run_dir/client.log" 2>&1 &
    EXPERIMENT_PID=$!
    attempt=0
    while ! grep -q "reverse endpoint $DIAGNOSTIC_ENDPOINT claimed" "$run_dir/client.log" 2>/dev/null \
        && [ "$attempt" -lt 120 ]; do
        kill -0 "$EXPERIMENT_PID" 2>/dev/null \
            || { printf '[FAIL] %s pass %s client упал\n' "$profile" "$pass" >&2; return 1; }
        sleep 0.5
        attempt=$((attempt + 1))
    done
    grep -q "reverse endpoint $DIAGNOSTIC_ENDPOINT claimed" "$run_dir/client.log"

    printf 'unix_ms,cpu_percent,rss_kib,threads\n' >"$run_dir/mac-resources.csv"
    (
        while kill -0 "$EXPERIMENT_PID" 2>/dev/null; do
            now=$(date '+%s000')
            stats=$(LC_ALL=C ps -p "$EXPERIMENT_PID" -o %cpu= -o rss= 2>/dev/null \
                | awk 'NF >= 2 { print $1 "," $2; exit }')
            if [ -n "$stats" ]; then
                threads=$(ps -M -p "$EXPERIMENT_PID" 2>/dev/null \
                    | awk 'NR > 1 { count++ } END { print count + 0 }')
                printf '%s,%s,%s\n' "$now" "$stats" "$threads" \
                    >>"$run_dir/mac-resources.csv"
            fi
            sleep 1
        done
    ) &
    SAMPLER_PID=$!
}

run_profile() {
    local profile=$1
    local pass=$2
    local batch_kib=""
    local short="a"
    case "$profile" in
        A-v2-baseline) ;;
        B-batch-64) batch_kib=64; short=b64 ;;
        B-batch-128) batch_kib=128; short=b128 ;;
        B-batch-256) batch_kib=256; short=b256 ;;
        *) printf '[FAIL] неизвестный профиль %s\n' "$profile" >&2; return 1 ;;
    esac
    local run_dir="$RESULT_DIR/profiles/$profile/pass-$pass"
    local diagnostic_run="$RUN_ID-p$pass-$short"
    mkdir -p "$run_dir"
    printf '[INFO] профиль %s, проход %s/3\n' "$profile" "$pass"
    if ! start_experiment "$profile" "$batch_kib" "$pass" "$run_dir"; then
        stop_experiment
        return 1
    fi

    set +e
    HTTPS_PROXY="$PX_URL" \
    ALL_PROXY="$PX_URL" \
    NO_PROXY="127.0.0.1,localhost" \
    "$INSTALLED_CLIENT" \
        --server "$SERVER_URL" \
        --wire-api v2 \
        --mode batch \
        --proxy "$PX_URL" \
        --token-file "$STATE_DIR/httptun-token" \
        --reverse-diagnostic-run "$DIAGNOSTIC_ENDPOINT" \
        --diagnostic-run-id "$diagnostic_run" \
        --diagnostic-profile "$profile" \
        --diagnostic-passes 1 \
        --timeout-sec 30 \
        --retry-window-sec 60 \
        --diagnostics-jsonl "$run_dir/control-events.jsonl" \
        >"$run_dir/vps-run.json" 2>"$run_dir/vps-run.err"
    local status=$?
    set -e
    {
        printf 'profile=%s\n' "$profile"
        printf 'comparison_pass=%s\n' "$pass"
        printf 'experimental_batch_kib=%s\n' "${batch_kib:-baseline}"
        printf 'vps_run_exit=%s\n' "$status"
    } >"$run_dir/manifest.txt"
    stop_experiment
    return "$status"
}

OVERALL_STATUS=0
for pass in 1 2 3; do
    case "$pass" in
        1) order="A-v2-baseline B-batch-64 B-batch-128 B-batch-256" ;;
        2) order="B-batch-128 B-batch-256 A-v2-baseline B-batch-64" ;;
        3) order="B-batch-256 B-batch-64 B-batch-128 A-v2-baseline" ;;
    esac
    for profile in $order; do
        run_profile "$profile" "$pass" || OVERALL_STATUS=1
    done
done

{
    printf 'run_id=%s\n' "$RUN_ID"
    printf 'utc_finished=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf 'client=%s\n' "$($INSTALLED_CLIENT --version 2>/dev/null || true)"
    printf 'server_url=%s\n' "$SERVER_URL"
    printf 'profiles=A-v2-baseline,B-batch-64,B-batch-128,B-batch-256\n'
    printf 'passes=3\n'
    printf 'overall_exit=%s\n' "$OVERALL_STATUS"
} >"$RESULT_DIR/manifest.txt"

python3 "$ANALYZER" "$RESULT_DIR"
ARCHIVE="$RESULT_ROOT/$RUN_ID.tar.gz"
tar -C "$RESULT_ROOT" -czf "$ARCHIVE" "$RUN_ID"
printf '\n[READY] Сводка: %s/summary.md\n' "$RESULT_DIR"
printf '[READY] JSON: %s/report.json\n' "$RESULT_DIR"
printf '[READY] Пакет: %s\n' "$ARCHIVE"
printf '[INFO] production endpoint probe оставлен на baseline A\n'
exit "$OVERALL_STATUS"

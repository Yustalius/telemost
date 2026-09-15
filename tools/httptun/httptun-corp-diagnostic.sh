#!/bin/bash

set -u

LAUNCHER="${HTTPTUN_LAUNCHER:-$HOME/httptun-corp-launch.sh}"
STATE_DIR="$HOME/.telemost-vpn"
PID_FILE="$STATE_DIR/httptun-reverse.pid"
CLIENT_LOG="$STATE_DIR/httptun-reverse.log"
VPN_CLI="/opt/cisco/anyconnect/bin/vpn"
PX_PORT=3128
VPS_HOST="201.24.52.171"
VPS_SSH="root@$VPS_HOST"
VPS_BIND_PORT=13129
SERVER_URL="https://ya-telemost.site"
CORP_URL="https://retest-agent.apps.yd-m6-kt66.vimpelcom.ru/"

failures=0

ok() { printf '  \033[32mok\033[0m  %s\n' "$*"; }
warn() { printf '  \033[33m!!\033[0m  %s\n' "$*"; }
fail() { printf '  \033[31mxx\033[0m  %s\n' "$*"; failures=$((failures + 1)); }

http_code_ok() {
    case "$1" in
        '' | 000 | 407 | 502) return 1 ;;
        *) return 0 ;;
    esac
}

printf '%s\n' '== Mac preflight =='
if [ -x "$VPN_CLI" ]; then
    vpn_status=$("$VPN_CLI" status 2>/dev/null | grep -iE 'state:' | head -1)
    case "$vpn_status" in
        *[Dd]isconnected*) fail "Cisco VPN отключён" ;;
        *[Cc]onnected*) ok "Cisco VPN подключён" ;;
        *) fail "состояние Cisco VPN не определено" ;;
    esac
else
    fail "Cisco VPN CLI не найден"
fi

if klist -s 2>/dev/null; then
    ok "Kerberos-ticket валиден"
else
    fail "Kerberos-ticket отсутствует или истёк"
fi

if lsof -nP -iTCP:"$PX_PORT" -sTCP:LISTEN >/dev/null 2>&1; then
    ok "px слушает 127.0.0.1:$PX_PORT"
else
    fail "px не слушает порт $PX_PORT"
fi

if [ -f "$PID_FILE" ]; then
    client_pid=$(sed -n '1p' "$PID_FILE")
else
    client_pid=""
fi
case "$client_pid" in
    '' | *[!0-9]*) fail "нет корректного PID httptun-client" ;;
    *)
        if kill -0 "$client_pid" 2>/dev/null \
            && ps -p "$client_pid" -o command= 2>/dev/null | grep -q '[h]ttptun-client.*--reverse-map'; then
            ok "httptun-client запущен (pid $client_pid)"
        else
            fail "httptun-client из PID-файла не запущен"
        fi
        ;;
esac

if [ -x "$LAUNCHER" ]; then
    "$LAUNCHER" --status || fail "launcher --status завершился с ошибкой"
else
    fail "launcher не найден: $LAUNCHER"
fi

printf '%s\n' '== Mac curl через px/MWG =='
vps_code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 25 --noproxy '' \
    -x "http://127.0.0.1:$PX_PORT" "$SERVER_URL/health" 2>"$STATE_DIR/diagnostic-vps.err" || true)
if [ "$vps_code" = 200 ]; then
    ok "px -> MWG -> VPS /health = HTTP 200"
else
    fail "px -> MWG -> VPS /health = HTTP ${vps_code:-000}"
fi

corp_code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 35 --noproxy '' \
    -x "http://127.0.0.1:$PX_PORT" "$CORP_URL" 2>"$STATE_DIR/diagnostic-corp.err" || true)
if http_code_ok "$corp_code"; then
    ok "px -> корпоративный сайт = HTTP $corp_code"
else
    fail "px -> корпоративный сайт = HTTP ${corp_code:-000}"
fi

printf '%s\n' '== VPS reverse proxy load check =='
if ! nc -G 8 -z "$VPS_HOST" 22 >/dev/null 2>&1; then
    fail "VPS:22 недоступен; удалённые проверки не запускались"
else
    ok "VPS:22 доступен"
    if ! ssh -o BatchMode=yes -o ConnectTimeout=10 "$VPS_SSH" bash -s -- \
        "$CORP_URL" "$VPS_BIND_PORT" <<'REMOTE'
set -u

corp_url=$1
bind_port=$2
started=$(date '+%Y-%m-%d %H:%M:%S')
failures=0

probe() {
    curl -sS -o /dev/null -w '%{http_code}' --max-time 45 \
        -x "http://127.0.0.1:$bind_port" "$corp_url" 2>/dev/null || true
}

code_ok() {
    case "$1" in
        '' | 000 | 407 | 502) return 1 ;;
        *) return 0 ;;
    esac
}

systemctl is-active --quiet httptun-server || {
    printf 'server=inactive\n'
    exit 1
}
curl -fksS --max-time 5 https://127.0.0.1:19443/health >/dev/null || {
    printf 'server_health=failed\n'
    exit 1
}
ss -ltn | grep -q "127.0.0.1:$bind_port" || {
    printf 'reverse_listener=missing\n'
    exit 1
}
printf 'server=active health=ok listener=%s\n' "$bind_port"

i=1
while [ "$i" -le 10 ]; do
    code=$(probe)
    printf 'sequential[%02d]=HTTP %s\n' "$i" "${code:-000}"
    code_ok "$code" || failures=$((failures + 1))
    i=$((i + 1))
done

diag_dir=$(mktemp -d /tmp/httptun-diagnostic.XXXXXX)
cleanup() { rm -rf "$diag_dir"; }
trap cleanup EXIT

i=1
while [ "$i" -le 6 ]; do
    (probe >"$diag_dir/$i") &
    i=$((i + 1))
done
wait

i=1
while [ "$i" -le 6 ]; do
    code=$(sed -n '1p' "$diag_dir/$i")
    printf 'parallel[%02d]=HTTP %s\n' "$i" "${code:-000}"
    code_ok "$code" || failures=$((failures + 1))
    i=$((i + 1))
done

sleep 2
established=$(ss -tn state established 2>/dev/null | grep -c "127.0.0.1:$bind_port" || true)
printf 'established_after_2s=%s\n' "$established"
[ "$established" -eq 0 ] || failures=$((failures + 1))

critical=$(journalctl -u httptun-server --since "$started" --no-pager 2>/dev/null \
    | grep -Eic '502|panic|fatal|ERROR' || true)
printf 'critical_server_log_lines=%s\n' "$critical"
[ "$critical" -eq 0 ] || failures=$((failures + 1))

exit "$failures"
REMOTE
    then
        fail "VPS reverse load-check обнаружил ошибку"
    else
        ok "10 последовательных и 6 параллельных запросов прошли"
    fi
fi

if [ -f "$CLIENT_LOG" ]; then
    recent_client_errors=$(tail -n 300 "$CLIENT_LOG" \
        | grep -Eic '502|panic|fatal|ERROR|connection unavailable' || true)
    if [ "$recent_client_errors" -eq 0 ]; then
        ok "в последних строках client log нет критических ошибок"
    else
        fail "client log содержит критические строки: $recent_client_errors"
    fi
fi

if [ "$failures" -eq 0 ]; then
    printf '\n\033[32mДиагностика пройдена полностью.\033[0m\n'
    exit 0
fi

printf '\n\033[31mДиагностика завершилась с ошибками: %s.\033[0m\n' "$failures"
printf 'Логи: %s/diagnostic-*.err и %s\n' "$STATE_DIR" "$CLIENT_LOG"
exit 1

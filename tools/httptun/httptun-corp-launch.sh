#!/bin/bash
# Start the reverse httptun client on a corporate Mac. The server-side port is
# an HTTP proxy because the local target is px on the dedicated reverse port.
#
# The reverse launcher owns its own px on 127.0.0.1:3129. It is configured with
# --noproxy for the corporate app domain so that:
#   * httptun-api traffic to ya-telemost.site still flows through MWG (upstream
#     proxy --proxy=ms-mwgvpn.vimpelcom.ru:9090, --auth=NEGOTIATE);
#   * a connect to the corporate test app bypasses MWG and dials directly
#     through the Cisco VPN (px --noproxy => direct connect).
# No other local proxy is required or managed by this launcher.

set -u

STATE_DIR="$HOME/.telemost-vpn"
HTTPTUN_BIN="$STATE_DIR/httptun-client"
TOKEN_FILE="$STATE_DIR/httptun-token"
OWNER_FILE="$STATE_DIR/reverse-owner-id"
PID_FILE="$STATE_DIR/httptun-reverse.pid"
HTTPTUN_LOG="$STATE_DIR/httptun-reverse.log"

PX_BIN="$HOME/.local/bin/px"
PX_PORT=3129
PX_PID="$STATE_DIR/httptun-reverse-px.pid"
PX_LOG="$STATE_DIR/httptun-reverse-px.log"
UPSTREAM_PROXY="ms-mwgvpn.vimpelcom.ru:9090"
CORP_NOPROXY="retest-agent.apps.yd-m6-kt66.vimpelcom.ru"
SERVER_URL="https://ya-telemost.site"
ENDPOINT_ID="probe"
VPS_SSH="root@201.24.52.171"
VPS_BIND_PORT=13129
CORP_URL="https://retest-agent.apps.yd-m6-kt66.vimpelcom.ru/"
VPN_CLI="/opt/cisco/anyconnect/bin/vpn"

ACTION=start
DIAGNOSTIC=0
FORCE=0
KRB5CCNAME_OVERRIDE=""

say() { printf '%s\n' "$*"; }
ok() { printf '\033[32m[OK]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[WARN]\033[0m %s\n' "$*"; }
info() { printf '\033[36m[INFO]\033[0m %s\n' "$*"; }
die() { printf '\033[31m[FAIL]\033[0m %s\n' "$*"; exit 1; }
usage() {
    printf '%s\n' \
        "Использование: $0 [start|--status|--stop|--diagnostic] [--force]" \
        "  start / без аргументов  проверить окружение и запустить reverse httptun" \
        "  --status              показать состояние px, клиента и VPS bind" \
        "  --stop                остановить httptun-client и принадлежащий ему px" \
        "  --diagnostic          запустить с подробным логом" \
        "  --force               продолжить при неясном VPN/Kerberos или precheck"
}

for arg in "$@"; do
    case "$arg" in
        start) ACTION=start ;;
        --stop) ACTION=stop ;;
        --status) ACTION=status ;;
        --diagnostic | --diagnostic-log) DIAGNOSTIC=1 ;;
        --force) FORCE=1 ;;
        --help | -h)
            usage
            exit 0
            ;;
        *) die "неизвестный аргумент: $arg (см. --help)" ;;
    esac
done

vpn_connected() {
    [ -x "$VPN_CLI" ] || return 2
    local status
    status=$("$VPN_CLI" status 2>/dev/null | grep -iE 'state:' | head -1)
    case "$status" in
        *[Dd]isconnected*) return 1 ;;
        *[Cc]onnecting* | *[Rr]econnecting*) return 2 ;;
        *[Cc]onnected*) return 0 ;;
        *) return 2 ;;
    esac
}

ensure_kerberos() {
    if klist -s 2>/dev/null; then
        ok "Kerberos: дефолтный тикет валиден"
        return 0
    fi
    local cache
    cache=$(klist -l 2>/dev/null | grep -vi expired | grep -oE 'API:[0-9A-Fa-f-]+' | head -1)
    if [ -n "$cache" ] && KRB5CCNAME="$cache" klist -s 2>/dev/null; then
        KRB5CCNAME_OVERRIDE="$cache"
        ok "Kerberos: найден живой тикет"
        return 0
    fi
    warn "живого Kerberos-тикета нет; обнови его через kinit"
    return 1
}

px_listening() {
    lsof -nP -iTCP:"$PX_PORT" -sTCP:LISTEN >/dev/null 2>&1
}

px_listener_pid() {
    lsof -nP -t -iTCP:"$PX_PORT" -sTCP:LISTEN 2>/dev/null | sort -u | head -1
}

px_cmd_matches() {
    local cmd
    cmd=$(ps -p "$1" -o command= 2>/dev/null)
    [ -n "$cmd" ] || return 1
    case "$cmd" in
        *"/px"*) ;;
        *) return 1 ;;
    esac
    case "$cmd" in
        *"--port=$PX_PORT"*) ;;
        *) return 1 ;;
    esac
    case "$cmd" in
        *"--proxy=$UPSTREAM_PROXY"*) ;;
        *) return 1 ;;
    esac
    case "$cmd" in
        *"--auth=NEGOTIATE"*) ;;
        *) return 1 ;;
    esac
    case "$cmd" in
        *"--noproxy=$CORP_NOPROXY"*) ;;
        *) return 1 ;;
    esac
    return 0
}

px_owned() {
    local pid recorded_pid
    pid=$(px_listener_pid)
    [ -n "$pid" ] && [ -f "$PX_PID" ] || return 1
    recorded_pid=$(sed -n '1p' "$PX_PID")
    [ "$pid" = "$recorded_pid" ] || return 1
    px_cmd_matches "$pid"
}

ensure_px() {
    if px_listening; then
        px_owned || die "порт $PX_PORT занят чужим процессом (не с нашим px $UPSTREAM_PROXY/noproxy=$CORP_NOPROXY); не останавливаю его и не запускаю reverse"
        ok "dedicated px:$PX_PORT уже слушает"
        return
    fi
    [ -x "$PX_BIN" ] || die "px не найден: $PX_BIN"
    info "поднимаю dedicated px:$PX_PORT"
    if [ -n "$KRB5CCNAME_OVERRIDE" ]; then
        nohup env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u NO_PROXY \
            -u http_proxy -u https_proxy -u all_proxy -u no_proxy \
            KRB5CCNAME="$KRB5CCNAME_OVERRIDE" "$PX_BIN" \
            --proxy="$UPSTREAM_PROXY" --port="$PX_PORT" --auth=NEGOTIATE \
            --noproxy="$CORP_NOPROXY" \
            >"$PX_LOG" 2>&1 &
    else
        nohup env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u NO_PROXY \
            -u http_proxy -u https_proxy -u all_proxy -u no_proxy \
            "$PX_BIN" --proxy="$UPSTREAM_PROXY" --port="$PX_PORT" --auth=NEGOTIATE \
            --noproxy="$CORP_NOPROXY" \
            >"$PX_LOG" 2>&1 &
    fi
    local pid=$!
    printf '%s\n' "$pid" >"$PX_PID"
    local attempt=0
    while ! px_listening && [ "$attempt" -lt 30 ]; do
        sleep 0.5
        attempt=$((attempt + 1))
    done
    if ! px_owned; then
        kill "$pid" 2>/dev/null || true
        rm -f "$PX_PID"
        die "dedicated px:$PX_PORT не поднялся с ожидаемым PID; см. $PX_LOG"
    fi
    ok "dedicated px:$PX_PORT слушает"
}

stop_px() {
    if ! px_listening; then
        rm -f "$PX_PID"
        return
    fi
    local pid
    pid=$(px_listener_pid)
    [ -n "$pid" ] || { rm -f "$PX_PID"; return; }
    if px_owned; then
        kill "$pid" 2>/dev/null || true
        local attempt=0
        while kill -0 "$pid" 2>/dev/null && [ "$attempt" -lt 20 ]; do
            sleep 0.25
            attempt=$((attempt + 1))
        done
    else
        warn "px:$PX_PORT не принадлежит launcher (PID=$pid); не останавливаю его"
    fi
    rm -f "$PX_PID"
}

client_pid() {
    [ -f "$PID_FILE" ] || return 1
    local pid
    pid=$(sed -n '1p' "$PID_FILE")
    case "$pid" in
        '' | *[!0-9]*) return 1 ;;
    esac
    kill -0 "$pid" 2>/dev/null || return 1
    ps -p "$pid" -o command= 2>/dev/null | grep -q '[h]ttptun-client.*--reverse-map' || return 1
    printf '%s\n' "$pid"
}

stop_client() {
    local pid
    if pid=$(client_pid); then
        kill "$pid" 2>/dev/null || true
        local attempt=0
        while kill -0 "$pid" 2>/dev/null && [ "$attempt" -lt 20 ]; do
            sleep 0.25
            attempt=$((attempt + 1))
        done
    fi
    rm -f "$PID_FILE"
}

precheck_egress() {
    local code
    code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 20 --noproxy '' \
        -x "http://127.0.0.1:$PX_PORT" "$SERVER_URL/health" 2>"$STATE_DIR/precheck-egress.log")
    [ "$code" = 200 ]
}

probe_corp_target() {
    local code
    code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 25 --noproxy '' \
        -x "http://127.0.0.1:$PX_PORT" "$CORP_URL" 2>"$STATE_DIR/precheck-target.log")
    case "$code" in
        '' | 000 | 407 | 502)
            warn "корпоративная тестовая цель сейчас не отвечает (HTTP ${code:-000}); туннель всё равно запускаю"
            ;;
        *) ok "корпоративная тестовая цель отвечает HTTP $code" ;;
    esac
}

vps_bind_up() {
    ssh -o BatchMode=yes -o ConnectTimeout=8 "$VPS_SSH" \
        "ss -ltn | grep -q ':$VPS_BIND_PORT '" 2>/dev/null
}

e2e_probe() {
    local code
    code=$(ssh -o BatchMode=yes -o ConnectTimeout=8 "$VPS_SSH" \
        "curl -sS -o /dev/null -w '%{http_code}' --max-time 30 -x http://127.0.0.1:$VPS_BIND_PORT '$CORP_URL'" \
        2>/dev/null) || {
        warn "не удалось выполнить необязательную диагностику с VPS"
        return
    }
    case "$code" in
        2* | 3* | 401) ok "сквозной канал отвечает HTTP $code" ;;
        *) warn "сквозная проверка вернула HTTP $code" ;;
    esac
}

do_status() {
    if px_listening; then
        px_owned && ok "dedicated px:$PX_PORT слушает (--noproxy=$CORP_NOPROXY)" \
            || warn "порт $PX_PORT занят чужим процессом (не наш px)"
    else
        warn "dedicated px:$PX_PORT не слушает"
    fi
    local pid
    if pid=$(client_pid); then
        ok "httptun-client запущен (pid $pid)"
    else
        warn "httptun-client не запущен"
    fi
    vps_bind_up && ok "VPS bind :$VPS_BIND_PORT открыт" || warn "VPS bind :$VPS_BIND_PORT недоступен"
    [ -f "$HTTPTUN_LOG" ] && tail -n 5 "$HTTPTUN_LOG"
}

mkdir -p "$STATE_DIR" || die "не удалось создать $STATE_DIR"
chmod 700 "$STATE_DIR"

case "$ACTION" in
    status)
        do_status
        exit 0
        ;;
    stop)
        stop_client
        stop_px
        ok "httptun-client и его dedicated px:$PX_PORT остановлены"
        exit 0
        ;;
esac

vpn_connected
vpn_status=$?
case "$vpn_status" in
    0) ok "Cisco VPN подключён" ;;
    1) die "Cisco VPN отключён" ;;
    *) [ "$FORCE" -eq 1 ] && warn "состояние VPN неясно; продолжаю" || die "не удалось определить состояние VPN" ;;
esac

ensure_kerberos || { [ "$FORCE" -eq 1 ] || die "обнови Kerberos и повтори"; }
ensure_px
[ -x "$HTTPTUN_BIN" ] || die "httptun-client не установлен: $HTTPTUN_BIN"
[ -s "$TOKEN_FILE" ] || die "нет bearer token: $TOKEN_FILE"
chmod 600 "$TOKEN_FILE"
if [ ! -s "$OWNER_FILE" ]; then
    umask 077
    uuidgen | tr '[:upper:]' '[:lower:]' >"$OWNER_FILE" || die "не удалось создать owner id"
fi
chmod 600 "$OWNER_FILE"

if ! precheck_egress; then
    [ "$FORCE" -eq 1 ] && warn "px/MWG не достигает VPS; продолжаю из-за --force" || die "px/MWG не достигает VPS /health"
else
    ok "px/MWG достигает VPS"
fi

stop_client
: >"$HTTPTUN_LOG"
verbosity="-v"
[ "$DIAGNOSTIC" -eq 1 ] && verbosity="-vv"
info "запускаю reverse httptun через dedicated px:$PX_PORT"
# Explicit --proxy keeps httptun-api traffic (claim/accept for ya-telemost.site)
# pinned to the dedicated px regardless of inherited HTTP_PROXY/ALL_PROXY.
# The reverse target dial is a raw TCP connect to the same dedicated px on
# 127.0.0.1:$PX_PORT; its --noproxy sends the corp app directly via the VPN.
HTTPS_PROXY="http://127.0.0.1:$PX_PORT" \
ALL_PROXY="http://127.0.0.1:$PX_PORT" \
NO_PROXY="127.0.0.1,localhost" \
nohup "$HTTPTUN_BIN" \
    --server "$SERVER_URL" \
    --wire-api v2 \
    --mode batch \
    --proxy "http://127.0.0.1:$PX_PORT" \
    --token-file "$TOKEN_FILE" \
    --reverse-owner-file "$OWNER_FILE" \
    --reverse-map "$ENDPOINT_ID->127.0.0.1:$PX_PORT" \
    --timeout-sec 30 \
    --retry-window-sec 60 \
    "$verbosity" >>"$HTTPTUN_LOG" 2>&1 &
client=$!
printf '%s\n' "$client" >"$PID_FILE"

attempt=0
while [ "$attempt" -lt 120 ]; do
    grep -q "reverse endpoint $ENDPOINT_ID claimed" "$HTTPTUN_LOG" && break
    kill -0 "$client" 2>/dev/null || die "httptun-client упал; см. $HTTPTUN_LOG"
    sleep 0.5
    attempt=$((attempt + 1))
done
grep -q "reverse endpoint $ENDPOINT_ID claimed" "$HTTPTUN_LOG" || die "endpoint не claimed за 60 секунд"
ok "reverse endpoint claimed"
probe_corp_target
vps_bind_up && ok "VPS bind :$VPS_BIND_PORT открыт" || warn "не удалось проверить VPS bind по SSH"
e2e_probe
say "Готово. Статус: $0 --status    Стоп: $0 --stop    Лог: $HTTPTUN_LOG"

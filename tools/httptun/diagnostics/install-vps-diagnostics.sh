#!/bin/bash

set -euo pipefail

[ "$(id -u)" -eq 0 ] || { printf '[FAIL] run as root on the VPS\n' >&2; exit 1; }
[ "$#" -eq 1 ] || { printf 'Usage: %s /path/to/httptun-server\n' "$0" >&2; exit 2; }

SOURCE_BIN=$1
TARGET_BIN=/opt/httptun/httptun-server
UNIT=/etc/systemd/system/httptun-server.service
STAMP=$(date -u '+%Y%m%dT%H%M%SZ')
BACKUP_BIN="$TARGET_BIN.pre-diagnostics-$STAMP"
BACKUP_UNIT="$UNIT.pre-diagnostics-$STAMP"
rollback=1

wait_ready() {
    local require_diagnostics=$1
    local attempt=0
    while [ "$attempt" -lt 40 ]; do
        if systemctl is-active --quiet httptun-server \
            && curl -fksS --max-time 2 https://127.0.0.1:19443/health >/dev/null 2>&1 \
            && ss -ltn | grep -q '127.0.0.1:13129' \
            && { [ "$require_diagnostics" -eq 0 ] || ss -ltn | grep -q '127.0.0.1:13130'; }; then
            return 0
        fi
        sleep 0.25
        attempt=$((attempt + 1))
    done
    return 1
}

[ -x "$SOURCE_BIN" ] || { printf '[FAIL] binary is not executable: %s\n' "$SOURCE_BIN" >&2; exit 1; }
[ -f "$UNIT" ] || { printf '[FAIL] unit not found: %s\n' "$UNIT" >&2; exit 1; }
"$SOURCE_BIN" --help | grep -q -- '--reverse-diagnostics' \
    || { printf '[FAIL] binary has no reverse diagnostic support\n' >&2; exit 1; }

cp -p "$TARGET_BIN" "$BACKUP_BIN"
cp -p "$UNIT" "$BACKUP_UNIT"
rollback_install() {
    if [ "$rollback" -eq 1 ]; then
        cp -p "$BACKUP_BIN" "$TARGET_BIN.rollback-new"
        mv "$TARGET_BIN.rollback-new" "$TARGET_BIN"
        cp -p "$BACKUP_UNIT" "$UNIT"
        systemctl daemon-reload
        systemctl restart httptun-server
        wait_ready 0 || printf '[FAIL] rollback service did not become ready\n' >&2
    fi
}
trap rollback_install EXIT

install -m 0755 "$SOURCE_BIN" "$TARGET_BIN.diagnostic-new"
mv "$TARGET_BIN.diagnostic-new" "$TARGET_BIN"
cmp -s "$SOURCE_BIN" "$TARGET_BIN"
"$TARGET_BIN" --help | grep -q -- '--reverse-diagnostics'

systemctl restart httptun-server
wait_ready 0

if ! grep -q '^StateDirectory=httptun-server$' "$UNIT"; then
    sed -i '/^DynamicUser=true$/a StateDirectory=httptun-server\nStateDirectoryMode=0750' "$UNIT"
fi
if ! grep -q -- '--reverse diag=127.0.0.1:13130' "$UNIT"; then
    sed -i '/^ExecStart=/s|$| --reverse diag=127.0.0.1:13130 --reverse-diagnostics --diagnostics-jsonl /var/lib/httptun-server/diagnostics.jsonl|' "$UNIT"
fi

systemctl daemon-reload
systemctl restart httptun-server
wait_ready 1
test -f /var/lib/httptun-server/diagnostics.jsonl

rollback=0
printf '[OK] diagnostic endpoint enabled; backups:\n%s\n%s\n' "$BACKUP_BIN" "$BACKUP_UNIT"

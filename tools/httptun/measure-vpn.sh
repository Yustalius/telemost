#!/usr/bin/env bash
# Полный прогон замеров httptun через MWG (Шаги 1–3 брифа).
# Запускать при: VPN Connected, px на 127.0.0.1:3128, httptun-server --echo на VPS:443.
# Baseline (--no-proxy) валиден только БЕЗ VPN.
set -u
BIN="$(cd "$(dirname "$0")" && pwd)/target/release/httptun-client"
SRV="${HTTPTUN_SRV:-https://201.24.52.171:443}"
export HTTPS_PROXY=http://127.0.0.1:3128 ALL_PROXY=http://127.0.0.1:3128 NO_PROXY=127.0.0.1,localhost

run() { echo "### $1"; shift; "$BIN" --server "$SRV" --danger-accept-invalid-cert --to echo "$@" 2>/dev/null; echo; }

echo "== Проверка сервера =="; curl -s -m 15 --proxy http://127.0.0.1:3128 -k "$SRV/health"; echo; echo

run "Шаг1 ping30 stream" --selftest-ping --count 30 --size 128 --mode stream
run "Шаг1 ping30 batch"  --selftest-ping --count 30 --size 128 --mode batch
run "Шаг3 ping100x64 stream" --selftest-ping --count 100 --size 64 --mode stream
run "Шаг3 ping100x64 batch"  --selftest-ping --count 100 --size 64 --mode batch
run "Шаг3 thr20 stream" --throughput --seconds 20 --mode stream
run "Шаг3 thr20 batch"  --throughput --seconds 20 --mode batch
run "Шаг3 stability 300s (выбранный режим)" --throughput --seconds 300 --mode "${HTTPTUN_MODE:-stream}"

if [ "${HTTPTUN_BASELINE:-0}" = "1" ]; then   # только off-VPN!
  echo "### OFF-VPN baseline ping100x64"
  env -u HTTPS_PROXY -u ALL_PROXY "$BIN" --server "$SRV" --danger-accept-invalid-cert \
      --no-proxy --to echo --selftest-ping --count 100 --size 64 --mode stream 2>/dev/null; echo
fi

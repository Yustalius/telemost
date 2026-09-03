#!/usr/bin/env bash
#
# mwg-tls-probe.sh — проверка риска TLS-инспекции MWG для фазы O1.
#
# Запускать ПОД КОРП-VPN. Отвечает на вопрос: переживёт ли встроенный туннель
# telemost переключение на `danger:false` (валидация публичного сертификата),
# или McAfee Web Gateway перехватывает TLS и подписывает своим CA, который не
# лежит в системном trust store (тогда клиент O1 будет падать на валидации).
#
# Метод (двухслойный):
#   1) АВТОРИТЕТНО — `httptun-client --tls-probe`: тот же стек, что и туннель
#      (reqwest + rustls-tls-native-roots, системные корни). danger:false vs
#      danger:true через тот же env-прокси, что и боевой клиент.
#   2) ОБЪЯСНЕНИЕ — `curl -v -k`: печатает issuer предъявленного сертификата,
#      чтобы увидеть, кто его подписал (Let's Encrypt = passthrough; McAfee/
#      корп-CA = инспекция).
#
# Скрипт только читает: ничего не меняет, не ставит серты, не пишет в конфиги.

set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN=""
for cand in \
  "$REPO_ROOT/target/release/httptun-client" \
  "$REPO_ROOT/target/debug/httptun-client"; do
  [ -x "$cand" ] && BIN="$cand" && break
done

if [ -z "$BIN" ]; then
  echo "httptun-client не собран. Собери ДО ухода под VPN (нужна сеть за деп-кэшем):" >&2
  echo "    cargo build -p httptun --bin httptun-client --release" >&2
  echo "…и запусти скрипт снова." >&2
  exit 2
fi

# --- целевые домены -------------------------------------------------------
# Первый — наш реальный домен (может быть ещё не задеплоен: DNS/серт — шаги
# выкладки). Остальные — контроли с заведомо валидными публичными сертами.
# Свои домены можно добавить через EXTRA_TARGETS="https://a https://b".
TARGETS=(
  "https://ya-telemost.site"
  "https://example.com"
  "https://www.google.com"
  "https://cloudflare.com"
)
# shellcheck disable=SC2206
[ -n "${EXTRA_TARGETS:-}" ] && TARGETS+=(${EXTRA_TARGETS})

# --- определить прокси ----------------------------------------------------
detect_proxy() {
  if [ -n "${HTTPS_PROXY:-}" ]; then echo "$HTTPS_PROXY"; return; fi
  if [ -n "${https_proxy:-}" ]; then echo "$https_proxy"; return; fi
  if [ -n "${ALL_PROXY:-}" ]; then echo "$ALL_PROXY"; return; fi
  # macOS системный прокси
  local host port
  host=$(scutil --proxy 2>/dev/null | awk '/HTTPSProxy/{print $3}')
  port=$(scutil --proxy 2>/dev/null | awk '/HTTPSPort/{print $3}')
  if [ -n "$host" ] && [ -n "$port" ]; then echo "http://$host:$port"; return; fi
  # px-шим по умолчанию
  if nc -z 127.0.0.1 3128 2>/dev/null; then echo "http://127.0.0.1:3128"; return; fi
  echo ""
}

PROXY="$(detect_proxy)"
if [ -n "$PROXY" ]; then
  export HTTPS_PROXY="$PROXY" https_proxy="$PROXY" ALL_PROXY="$PROXY" all_proxy="$PROXY"
  echo "Прокси: $PROXY  (его используют и проба, и curl)"
else
  echo "Прокси НЕ найден — тестирую напрямую. Под corp full-tunnel так быть не должно;"
  echo "если ты точно под VPN, задай HTTPS_PROXY='http://127.0.0.1:3128' и перезапусти."
fi
echo "Бинарь: $BIN"
echo "Trust store клиента O1: rustls-tls-native-roots (системные корни macOS)."
echo "=========================================================================="

json_ok() { printf '%s' "$1" | grep -q '"ok":true'; }
json_field() { printf '%s' "$1" | sed -E "s/.*\"$2\":(\"[^\"]*\"|[^,}]*).*/\1/" | tr -d '"'; }

RISK=0
BLOCKED=0
OK_COUNT=0
PASS=0

for url in "${TARGETS[@]}"; do
  host="${url#https://}"; host="${host%%/*}"
  echo
  echo "### $url"

  secure="$("$BIN" --tls-probe "$url" 2>/dev/null)"
  insecure="$("$BIN" --tls-probe "$url" --danger-accept-invalid-cert 2>/dev/null)"
  echo "  danger:false -> $secure"
  echo "  danger:true  -> $insecure"

  issuer="$(curl -sS -v -k --max-time 15 -o /dev/null "$url" 2>&1 \
            | grep -iE 'issuer:' | head -1 | sed 's/^[* ]*//')"
  [ -n "$issuer" ] && echo "  cert $issuer"

  if json_ok "$secure"; then
    echo "  ВЕРДИКТ: OK — danger:false проходит. Цепочка доверена системным корням."
    echo "           => O1 (валидация серта) под этим путём работает."
    OK_COUNT=$((OK_COUNT+1))
  elif json_ok "$insecure"; then
    if echo "$issuer" | grep -qiE 'rcgen|self[ -]?signed'; then
      echo "  ВЕРДИКТ: PASSTHROUGH — предъявлен self-signed серт САМОГО сервера ($issuer)."
      echo "           MWG НЕ перехватывает этот домен: цепочка дошла нетронутой."
      echo "           danger:false падает лишь потому, что публичный серт ещё не выпущен."
      echo "           => после установки серта Let's Encrypt O1 (danger:false) заработает."
      PASS=$((PASS+1))
    elif json_field "$secure" error | grep -qiE 'certificate|peer|handshake|tls|issuer|expired'; then
      echo "  ВЕРДИКТ: РИСК — хост достижим, но danger:false ПАДАЕТ по СЕРТУ, и он НЕ наш self-signed."
      echo "           Причина: $(json_field "$secure" error)"
      echo "           Issuer:  ${issuer:-<не удалось прочитать>}"
      echo "           => TLS перехвачен, подписавший CA НЕ в системном trust store."
      echo "              O1 с danger:false здесь сломается."
      RISK=$((RISK+1))
    else
      echo "  ВЕРДИКТ: НЕСТАБИЛЬНО — danger:false не прошёл, но ошибка НЕ про сертификат:"
      echo "           $(json_field "$secure" error)"
      echo "           Похоже на транзиент/таймаут, а не на инспекцию. Перепроверь этот домен."
    fi
  else
    echo "  ВЕРДИКТ: НЕДОСТУПЕН/ЗАБЛОКИРОВАН — не прошёл даже danger:true."
    echo "           Причина: $(json_field "$insecure" error)"
    echo "           => либо CONNECT к домену режется по категории, либо DNS не резолвится"
    echo "              (для ya-telemost.site это ожидаемо, пока не задеплоены A-запись и серт)."
    BLOCKED=$((BLOCKED+1))
  fi
done

echo
echo "=========================================================================="
echo "ИТОГ: ok=$OK_COUNT  passthrough(self-signed)=$PASS  risk=$RISK  blocked/unreachable=$BLOCKED"
echo
if [ "$PASS" -gt 0 ]; then
  echo "=> На домене с нашим self-signed сертом MWG отдал цепочку нетронутой"
  echo "   (passthrough, инспекции нет). danger:false заработает, как только на VPS"
  echo "   встанет публичный серт Let's Encrypt. Перезапусти скрипт после его выката."
  echo
fi
if [ "$RISK" -gt 0 ]; then
  cat <<'EOF'
=> Обнаружена TLS-инспекция с недоверенным CA. Для O1 под corp-VPN варианты:
   (A) Внести корневой CA MWG в системный trust store macOS (обычно на managed-
       машинах он уже там — тогда danger:false заработает; перепроверь скриптом).
   (B) Если внести нельзя — оставить для corp-пути danger:true / пиновать корп-CA,
       а публичную валидацию включать только на не-corp сетях.
   Ниже — какие корп-CA присутствуют в системном хранилище (для сверки с issuer):
EOF
  security find-certificate -a -c "McAfee" /Library/Keychains/System.keychain 2>/dev/null \
    | grep -iE 'alis|labl' | head || true
  security dump-trust-settings -d 2>/dev/null | grep -iE 'McAfee|Web Gateway|Proxy' | head || true
fi
if [ "$OK_COUNT" -gt 0 ] && [ "$RISK" -eq 0 ]; then
  echo "=> Контроли проходят danger:false => MWG не ломает валидацию публичных сертов."
fi
cat <<'EOF'

ВАЖНО: окончательный ответ даёт САМ домен ya-telemost.site ПОСЛЕ выката A-записи
и сертификата Let's Encrypt — MWG может относить новый/некатегоризированный домен
к другой политике, чем контроли. Перезапусти скрипт, когда домен поднят.
EOF

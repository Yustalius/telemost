#!/usr/bin/env bash
# Подписывает локально установленный Telemost.app постоянным self-signed
# сертификатом.
#
# macOS привязывает выданные разрешения (Screen Recording, Accessibility,
# Input Monitoring) к code signing identity приложения. У ad-hoc подписи,
# которую ставят наши CI-сборки, identity -- это cdhash бинаря, поэтому после
# установки каждого нового билда разрешения перестают действовать: галочка в
# System Settings остаётся, но TCC отказывает, capturer не создаётся и картинка
# не идёт. С постоянным сертификатом designated requirement выглядит как
#   identifier "com.carriez.telemost" and certificate root = H"..."
# и переживает пересборки.
#
# Запускать после каждой установки нового билда:
#   tools/macos-dev-sign.sh [/path/to/Telemost.app]
set -euo pipefail

APP="${1:-/Applications/Telemost.app}"
IDENTITY="Telemost Dev"
KEYCHAIN="telemost-signing.keychain"
KEYCHAIN_PASS="telemost"
P12="$HOME/.telemost/signing/ident.p12"

[ -d "$APP" ] || { echo "нет такого бандла: $APP" >&2; exit 1; }

if ! security find-certificate -c "$IDENTITY" "$KEYCHAIN" >/dev/null 2>&1; then
    echo "==> создаю связку ключей и идентичность '$IDENTITY'"
    if [ ! -f "$P12" ]; then
        mkdir -p "$(dirname "$P12")"
        tmp="$(mktemp -d)"
        cat > "$tmp/cert.cnf" <<'EOF'
[req]
distinguished_name = dn
x509_extensions = v3
prompt = no
[dn]
CN = Telemost Dev
O = Telemost
[v3]
basicConstraints = critical,CA:true
keyUsage = critical,digitalSignature,keyCertSign
extendedKeyUsage = critical,codeSigning
subjectKeyIdentifier = hash
EOF
        openssl req -x509 -newkey rsa:2048 -keyout "$tmp/key.pem" -out "$tmp/cert.pem" \
            -days 7300 -nodes -config "$tmp/cert.cnf" >/dev/null 2>&1
        # legacy-алгоритмы: p12 от OpenSSL 3 по умолчанию не импортируется в keychain
        openssl pkcs12 -export -inkey "$tmp/key.pem" -in "$tmp/cert.pem" -out "$P12" \
            -name "$IDENTITY" -passout "pass:$KEYCHAIN_PASS" \
            -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg sha1
        cp "$tmp/cert.pem" "$(dirname "$P12")/cert.pem"
        chmod 600 "$P12"
        rm -rf "$tmp"
    fi
    security create-keychain -p "$KEYCHAIN_PASS" "$KEYCHAIN" 2>/dev/null || true
    security set-keychain-settings "$KEYCHAIN"
    security unlock-keychain -p "$KEYCHAIN_PASS" "$KEYCHAIN"
    security import "$P12" -k "$KEYCHAIN" -P "$KEYCHAIN_PASS" -A -T /usr/bin/codesign
    security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$KEYCHAIN_PASS" "$KEYCHAIN" >/dev/null 2>&1
    if ! security list-keychains -d user | grep -q "$KEYCHAIN"; then
        current=$(security list-keychains -d user | tr -d ' "')
        security list-keychains -d user -s $current "$KEYCHAIN"
    fi
fi

security unlock-keychain -p "$KEYCHAIN_PASS" "$KEYCHAIN"

pkill -f "$APP/Contents/MacOS/" 2>/dev/null || true
sleep 1

echo "==> подписываю $APP"
codesign --force --deep --sign "$IDENTITY" --keychain "$KEYCHAIN" "$APP"
codesign --verify --deep --strict "$APP"
codesign -d -r- "$APP" 2>&1 | grep designated

# Запуск строго через LaunchServices. Если бинарь запустить напрямую из
# терминала, macOS назначит ответственным процессом сам терминал, и TCC будет
# спрашивать разрешение на запись экрана у него, а не у Telemost, -- галочка
# Telemost при этом останется целой, но capturer работать не будет.
echo "==> запускаю через open (не из терминала напрямую)"
open -a "$APP"
sleep 3

resp=$(/usr/bin/log show --last 30s --predicate 'process == "tccd"' --info --debug 2>/dev/null \
    | grep -o 'responsible={TCCDProcess: identifier=[a-zA-Z0-9._-]*' | tail -1 | sed 's/.*identifier=//')
if [ -n "$resp" ] && [ "$resp" != "com.carriez.telemost" ]; then
    echo "!! ответственный процесс = $resp вместо com.carriez.telemost" >&2
    echo "!! запись экрана работать не будет, запусти приложение из Dock/Finder" >&2
    exit 1
fi
echo "==> ответственный процесс: ${resp:-com.carriez.telemost} -- ок"

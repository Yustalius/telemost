# HTTP-туннель Telemost: сборка и запуск

Desktop-сборка Telemost включает HTTP-туннель по умолчанию. Отдельный
`httptun-client` на клиентских компьютерах не нужен: процесс Telemost `--server`
сам поднимает локальные TCP/UDP listener-ы до запуска rendezvous mediator.

```text
Telemost -> TCP/UDP 127.0.0.1:2345x -> встроенный httptun client
         -> HTTPS batch, VPS:443 -> httptun-server
         -> TCP/UDP 127.0.0.1:2111x -> hbbs/hbbr
```

Внешний трафик туннеля идёт обычными HTTPS-запросами `POST /o`, `POST /u`,
`GET /d`, `POST /c`. Встроенный режим - `batch`; WebSocket и прямые внешние
соединения Telemost к портам `2111x` не используются.

## Что запускается автоматически

| Протокол | Локальный listener | Target на VPS |
|---|---:|---:|
| UDP | `127.0.0.1:23456` | `127.0.0.1:21116` |
| TCP | `127.0.0.1:23456` | `127.0.0.1:21116` |
| TCP | `127.0.0.1:23455` | `127.0.0.1:21115` |
| TCP | `127.0.0.1:23457` | `201.24.52.171:21117` |

> **Важно (relay идёт на публичный IP, не на loopback).** hbbr **отклоняет**
> relay-запросы, пришедшие с loopback-источника (закрывает соединение, не
> логируя `New relay request`). Поэтому target relay-порта — публичный адрес VPS
> `201.24.52.171:21117`: httptun-server дилит его, и hbbr видит не-loopback пира.
> hbbs (rendezvous / NAT-test) loopback принимает, поэтому 21115/21116 остаются на
> `127.0.0.1`. Проверено `tools/relay-probe` (см. ниже).

Код приложения автоматически:

- направляет rendezvous на `127.0.0.1:23456`;
- направляет relay на `127.0.0.1:23457`;
- отключает WebSocket;
- форсирует relay вместо прямого P2P.

Править пользовательский TOML и запускать sidecar не требуется.

## Какая версия нужна на втором компьютере

Туннель меняет только путь от конкретного приложения до hbbs/hbbr, а не протокол
между пирами. Поэтому:

- на Mac, который находится за ограничивающей сетью, нужна новая сборка;
- старый Telemost на втором компьютере совместим, если он и без туннеля видит VPS;
- если второй компьютер тоже не может напрямую обращаться к VPS, на нём также нужна
  новая сборка.

## Обычная сборка приложения

`http-tunnel` входит в default features. Штатные команды сборки и CI автоматически
включают его; отдельный CI job для `httptun-client` не нужен.

Быстрая нативная проверка Rust-части:

```bash
cargo check --lib
cargo test -p httptun -- --test-threads=1
```

Полный Flutter-пакет собирается обычным pipeline проекта:

```bash
./build.py --flutter
```

Для диагностической сборки без встроенного транспорта можно явно отключить default
features и вернуть нужные features приложения вручную.

## Сервер на VPS

Собирается и устанавливается только `httptun-server`:

```bash
cargo build -p httptun --bin httptun-server --release
scp target/release/httptun-server root@201.24.52.171:/tmp/httptun-server.new
ssh root@201.24.52.171
install -m 0755 /tmp/httptun-server.new /opt/httptun/httptun-server
systemctl restart httptun-server
systemctl --no-pager --full status httptun-server
curl -k https://127.0.0.1/health
```

Сервис должен запускать сервер на `0.0.0.0:443`; hbbs/hbbr должны быть доступны на
loopback-портах `21115`, `21116`, `21117`.

## Фаза 1: проверка без VPN

Запустить новую сборку Telemost без proxy-env. Для нативного debug-бинаря:

```bash
env -u HTTPS_PROXY -u ALL_PROXY -u https_proxy -u all_proxy \
  target/debug/telemost --server
```

Проверки в другом терминале:

```bash
lsof -nP -iTCP:23455 -iTCP:23456 -iTCP:23457 -sTCP:LISTEN
lsof -nP -iUDP:23456
target/debug/telemost --get-id
```

В логах приложения должны быть `HTTP batch tunnel is ready`, UDP-сессия на
`udp://127.0.0.1:21116` и успешная регистрация. В журнале VPS:

```bash
journalctl -u httptun-server -f
```

должны появиться `/o`, `/u`, `/d` и target-ы `udp://127.0.0.1:21116` и
`tcp://201.24.52.171:21117` при relay-подключении. В журнале hbbr
(`journalctl -u rustdesk-hbbr`) должно быть `New relay request <uuid> from
[::ffff:201.24.52.171]` — если источник loopback, hbbr закрывает соединение молча.

## Фаза 2: под VPN через px

Код и бинарники не меняются. После запуска `px` на `127.0.0.1:3128` задать env для
будущих процессов пользовательского launchd и перезапустить Telemost:

```bash
launchctl setenv HTTPS_PROXY http://127.0.0.1:3128
launchctl setenv ALL_PROXY http://127.0.0.1:3128
launchctl setenv NO_PROXY 127.0.0.1,localhost
open -na /Applications/Telemost.app
```

Для запуска прямо из терминала:

```bash
HTTPS_PROXY=http://127.0.0.1:3128 \
ALL_PROXY=http://127.0.0.1:3128 \
NO_PROXY=127.0.0.1,localhost \
/Applications/Telemost.app/Contents/MacOS/Telemost
```

После измерения launchd-env можно удалить:

```bash
launchctl unsetenv HTTPS_PROXY
launchctl unsetenv ALL_PROXY
launchctl unsetenv NO_PROXY
```

## Отдельные диагностические бинарники

Они не нужны для обычного запуска приложения, но полезны для изолированной проверки
транспорта:

```bash
cargo build -p httptun --release

target/release/httptun-client \
  --telemost-preset 201.24.52.171 \
  --mode batch --no-proxy --danger-accept-invalid-cert -v

target/release/httptun-client \
  --selftest-ping --server https://201.24.52.171:443 \
  --mode stream --no-proxy --danger-accept-invalid-cert
```

`--map` также можно повторять вручную, например
`--map 'udp:23456->127.0.0.1:21116'`.

## relay-probe: headless-проверка relay-сессии через туннель

`tools/relay-probe` — отдельный крейт, доказывающий, что настоящая relay-сессия
между двумя пирами проходит сквозь HTTP-batch туннель (без Flutter, без пароля
telemost). Говорит с hbbr напрямую: шлёт `RequestRelay{uuid}`, hbbr спаривает два
соединения с одинаковым `uuid` и гоняет байты. Один пир идёт **через туннель**,
другой — **напрямую** на реальный VPS.

```bash
cargo build -p relay-probe

# 1) поднять batch-туннель для relay-порта (target = ПУБЛИЧНЫЙ IP!)
target/debug/httptun-client --server https://201.24.52.171:443 \
  --map 'tcp:23457->201.24.52.171:21117' \
  --mode batch --no-proxy --danger-accept-invalid-cert

# 2) echo-пир ЧЕРЕЗ ТУННЕЛЬ (запускать первым, держит слот по uuid)
U=$(uuidgen)
target/debug/relay-probe --role echo --relay-server 127.0.0.1:23457 --uuid "$U"

# 3) ping-пир НАПРЯМУЮ — шлёт payload, читает эхо, печатает JSON
target/debug/relay-probe --role ping --relay-server 201.24.52.171:21117 \
  --uuid "$U" --count 8 --size 1024 --pair-delay-ms 2500
# -> {"echo_ok":true,"ok":8,...,"rtt_ms":{...}}  = relay реально несёт байты сквозь туннель
```

`echo_ok:true` = связь клиент↔сервер через HTTP-batch работает end-to-end.

## O1 — TLS-метаданные: домен, публичный серт, `/api/v1`, токен

Фаза O1 снимает самые громкие отпечатки туннеля: клиент ходит на реальный домен
`ya-telemost.site` (A → `201.24.52.171`) с валидным SNI и публично доверенным
сертификатом (проверка включена, `danger:false`), запросы идут под браузерными
заголовками на пути `/api/v1/session/{open,send,recv,close}`, произвольный
`X-Target` заменён четырьмя фиксированными route ID, а API защищён общим
bearer-токеном и лимитом сессий.

Route ID (клиент шлёт только их, `host:port` знает лишь сервер):

| Route | Транспорт | Target на VPS |
|---|---|---|
| `ru` | UDP | `127.0.0.1:21116` (rendezvous) |
| `rt` | TCP | `127.0.0.1:21116` (rendezvous) |
| `nt` | TCP | `127.0.0.1:21115` (NAT-test) |
| `rl` | TCP | `<relay-host>:21117` (relay, публичный IP) |

Домен и токен зашиты в клиент: `HTTP_TUNNEL_SERVER_HOST` и
`HTTP_TUNNEL_AUTH_TOKEN` в `libs/hbb_common/src/config.rs`. Сервер должен
стартовать с тем же `--auth-token`.

### Сертификат Let's Encrypt (IPv4, без AAAA)

```bash
# DNS: ya-telemost.site A 201.24.52.171 должен стабильно резолвиться
certbot certonly --standalone -d ya-telemost.site
# fullchain.pem + privkey.pem в /etc/letsencrypt/live/ya-telemost.site/
certbot renew --dry-run
```

### systemd ExecStart на VPS

```bash
/opt/httptun/httptun-server \
  --listen 0.0.0.0:443 \
  --tls-cert /etc/letsencrypt/live/ya-telemost.site/fullchain.pem \
  --tls-key  /etc/letsencrypt/live/ya-telemost.site/privkey.pem \
  --auth-token tm1_9f3c7a1e8b6d4052a1c9e7f20b834d56 \
  --relay-host 201.24.52.171 \
  --max-sessions 256 \
  --allow-legacy \
  -v
```

`--allow-legacy` оставляем только на время миграции (старый клиент ещё ходит на
`/o /u /d /c` + `X-Target`). После выката пилотного клиента флаг убираем и
рестартуем — legacy-пути начинают отдавать `404`.

### Проверка

```bash
# валидный серт, без -k
curl -4 https://ya-telemost.site/            # decoy-страница, TLS доверенный
# без токена -> 401
curl -4 -s -o /dev/null -w '%{http_code}\n' \
  -X POST 'https://ya-telemost.site/api/v1/session/open?s=x&r=rt'
# произвольный/неизвестный route -> 400
curl -4 -s -o /dev/null -w '%{http_code}\n' \
  -H 'Authorization: Bearer tm1_9f3c7a1e8b6d4052a1c9e7f20b834d56' \
  -X POST 'https://ya-telemost.site/api/v1/session/open?s=x&r=bogus'
```

Изолированная проверка транспорта клиентом (v1 — режим по умолчанию):

```bash
target/release/httptun-client --telemost-preset ya-telemost.site \
  --token tm1_9f3c7a1e8b6d4052a1c9e7f20b834d56 --mode batch -v
# legacy (для сравнения / старого сервера):
target/release/httptun-client --telemost-preset 201.24.52.171 \
  --legacy --mode batch --no-proxy --danger-accept-invalid-cert -v
```

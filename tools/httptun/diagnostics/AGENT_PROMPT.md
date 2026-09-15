# Промпт агенту для диагностики под Corp VPN

Ты работаешь на этом Mac уже под подключённым Cisco Corp VPN. Не отключай VPN и не проси пользователя переключать сеть. Твоя задача — выполнить полный baseline reverse httptun, безопасно разобрать технические сбои стенда и вернуть готовый пакет результатов. Оптимизации протокола не реализуй и baseline-код во время этого запуска не меняй.

Репозиторий: `/Users/vyustus/PycharmProjects/telemost`

Prerelease: `httptun-diag-v2-20260915-r1`

Mac-пакет: `https://github.com/Yustalius/telemost/releases/download/httptun-diag-v2-20260915-r1/httptun-client-macos-aarch64.tar.gz`

Контрольная сумма: `https://github.com/Yustalius/telemost/releases/download/httptun-diag-v2-20260915-r1/SHA256SUMS`

Сначала перейди в репозиторий и убедись, что доступны `gh`, `python3`, `curl`, `lsof`, Cisco VPN, Kerberos и локальный `px`. Скачай ровно два указанных release asset во временный каталог, проверь строку только для `httptun-client-macos-aarch64.tar.gz` через `shasum -a 256 -c`, распакуй архив и запускай скрипты из распакованного пакета. Не используй непроверенный локальный build вместо release asset. Готовые команды:

```bash
cd /Users/vyustus/PycharmProjects/telemost
DIAG_DOWNLOAD_DIR=$(mktemp -d /tmp/httptun-corp-diag.XXXXXX)
env -u http_proxy -u https_proxy -u all_proxy -u no_proxy \
HTTP_PROXY=http://127.0.0.1:3129 \
HTTPS_PROXY=http://127.0.0.1:3129 \
ALL_PROXY=http://127.0.0.1:3129 \
NO_PROXY=127.0.0.1,localhost \
gh release download httptun-diag-v2-20260915-r1 \
  --repo Yustalius/telemost \
  --dir "$DIAG_DOWNLOAD_DIR" \
  --pattern httptun-client-macos-aarch64.tar.gz \
  --pattern SHA256SUMS
cd "$DIAG_DOWNLOAD_DIR"
grep '  httptun-client-macos-aarch64.tar.gz$' SHA256SUMS | shasum -a 256 -c -
mkdir package
tar -xzf httptun-client-macos-aarch64.tar.gz -C package
cd package
```

Уже подготовлено:

- публичный сервер `https://ya-telemost.site`;
- защищённый диагностический endpoint `diag` на VPS;
- корпоративный URL `https://retest-agent.apps.yd-m6-kt66.vimpelcom.ru/`;
- локальный dedicated proxy `127.0.0.1:3129` с upstream `ms-mwgvpn.vimpelcom.ru:9090`;
- token file `~/.telemost-vpn/httptun-token` и persistent owner file;
- автоматический target, три маршрута HTTP, прикладные тесты, ресурсные метрики, JSON/CSV/Markdown и упаковка результата.

Запусти полный прогон из корня распакованного Mac-пакета:

```bash
./diagnostics/run-corp-diagnostics.sh
```

Не начинай с `--quick`: он разрешён только для локализации конкретного сбоя, после чего всё равно нужен полный трёхпроходный запуск. `--trace` используй только если `sudo -n tcpdump` уже разрешён; отсутствие pcap не является ошибкой и не должно останавливать основной прогон.

Если скрипт остановился:

1. Прочитай указанный им каталог `~/.telemost-vpn/diagnostics/diag-*`, `target.log`, `client.log`, `px.log`, `vps-run.err`, `manifest.txt` и безопасные JSONL-события.
2. Проверь `./httptun-corp-launch.sh status`, `klist`, наличие listener на `127.0.0.1:3129`, `curl` к `/health` через этот proxy и маршруты. Не делай SSH на VPS: suite запускается серверным authenticated control API.
3. Исправляй только локальную эксплуатационную причину (истёкший Kerberos ticket, неработающий px, занятый локальный порт, права на каталог, неполная загрузка). Не печатай содержимое token file и не добавляй bearer, cookies, заголовки, тела ответов или SSO query-параметры в логи/ответ.
4. Если нужна новая интерактивная аутентификация, остановись и одним сообщением попроси пользователя выполнить её; после этого продолжи сам.
5. Известная baseline-находка `half_close` с `eof` — не поломка стенда. Она должна остаться в отчёте как finding; не исправляй её во время диагностики.

После успешного запуска проверь наличие:

- `summary.md`;
- `report.json`;
- `measurements.csv`;
- `vps-run.json`;
- `client-events.jsonl`, `target-events.jsonl`, `path-measurements.jsonl`;
- архива `~/.telemost-vpn/diagnostics/diag-*.tar.gz`.

Верни пользователю: абсолютный путь к каталогу и архиву, итоговый статус, число completed/failed checks, p50/p95/p99 по сценариям и маршрутам, потери/повторы/retries, пики CPU/RSS/threads, HTTP connection reuse, а также короткий список подтверждённых узких мест с привязкой к evidence-файлам. Секреты и необработанные SSO URL не цитируй. Если полный прогон не удалось завершить, верни точный безопасный диагноз, уже выполненные проверки и единственное минимальное действие, которое требуется от пользователя.

Если рядом доступен Windows-хост под тем же Corp VPN, отдельно выполни ручную SSO-проверку через `windows-edge-corp-profile.ps1`: скрипт создаёт изолированный профиль Edge и PAC только для `*.beeline.ru`/`*.vimpelcom.ru`, не меняя системный proxy. Отсутствие Windows не блокирует основной Mac baseline; явно пометь этот пункт как `not run`.

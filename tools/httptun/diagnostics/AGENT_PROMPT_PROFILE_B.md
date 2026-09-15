# Промпт агенту для сравнения A/B под Corp VPN

Ты работаешь на этом Mac уже под подключённым Cisco Corp VPN. Не отключай VPN
и не проси пользователя переключать сеть. Выполни полное сравнение baseline A
с profile B (64/128/256 КиБ) за эту единственную VPN-сессию. Код и параметры
стенда во время измерения не меняй.

Репозиторий: `/Users/vyustus/PycharmProjects/telemost`

Prerelease: `httptun-diag-v2-20260915-b1`

Mac-пакет: `https://github.com/Yustalius/telemost/releases/download/httptun-diag-v2-20260915-b1/httptun-client-macos-aarch64.tar.gz`

Контрольная сумма: `https://github.com/Yustalius/telemost/releases/download/httptun-diag-v2-20260915-b1/SHA256SUMS`

Скачай только опубликованный пакет и checksum через уже выделенный proxy 3129,
проверь архив и распакуй его:

```bash
cd /Users/vyustus/PycharmProjects/telemost
COMPARE_DOWNLOAD_DIR=$(mktemp -d /tmp/httptun-corp-ab.XXXXXX)
env -u http_proxy -u https_proxy -u all_proxy -u no_proxy \
HTTP_PROXY=http://127.0.0.1:3129 \
HTTPS_PROXY=http://127.0.0.1:3129 \
ALL_PROXY=http://127.0.0.1:3129 \
NO_PROXY=127.0.0.1,localhost \
gh release download httptun-diag-v2-20260915-b1 \
  --repo Yustalius/telemost \
  --dir "$COMPARE_DOWNLOAD_DIR" \
  --pattern httptun-client-macos-aarch64.tar.gz \
  --pattern SHA256SUMS
cd "$COMPARE_DOWNLOAD_DIR"
grep '  httptun-client-macos-aarch64.tar.gz$' SHA256SUMS | shasum -a 256 -c -
mkdir package
tar -xzf httptun-client-macos-aarch64.tar.gz -C package
cd package
```

До запуска проверь `klist`, Cisco VPN и `./httptun-corp-launch.sh --status`.
Если 3129 уже занят подходящим dedicated `px`, не останавливай его. Запусти:

```bash
./diagnostics/run-corp-profile-b.sh
```

Скрипт сам:

- перезапустит только production-клиент `probe` на неизменённом baseline A;
- запустит profile B отдельно только на диагностическом endpoint `diag`;
- переснимет исправленные direct/proxy route probes и Mac CPU/RSS/threads;
- выполнит A, B64, B128 и B256 по три раза с чередованием порядка;
- сохранит сырые события каждого профиля и сформирует единый JSON/CSV/Markdown;
- оставит production endpoint `probe` запущенным на baseline A после завершения.

Не запускай старый `run-corp-diagnostics.sh` перед сравнением: baseline A уже
встроен в новый 12-прогонный сценарий. Не включай pcap, если это не нужно для
разбора конкретной сетевой ошибки.

Если запуск остановился, сначала прочитай безопасные файлы соответствующего
`profiles/<profile>/pass-<n>/`: `client.log`, `vps-run.err`, `manifest.txt` и
JSONL-события. Затем проверь `klist`, listener 3129, `/health` через 3129 и
состояние production-клиента. Разрешено исправлять только локальные
операционные причины: Kerberos, подходящий `px`, занятый диагностический порт,
права и неполную загрузку. Не печатай token, cookies, заголовки, тела ответов и
SSO query-параметры. SSH на VPS не нужен.

Известный `half_close: eof` должен остаться baseline finding и сам по себе не
считается новой регрессией B. Любая другая потеря, дубль, нарушение порядка,
retry exhaustion, `404/409/410`, зависание соседних потоков или рост очереди —
реальная находка: не маскируй её и не перезапускай выборочно до «красивого»
результата. При истёкшем Kerberos или другой интерактивной авторизации попроси
у пользователя одно минимальное действие и после него продолжи сам.

После завершения проверь `summary.md`, `report.json`, `measurements.csv`, все 12
каталогов профилей и архив `~/.telemost-vpn/diagnostics/compare-*.tar.gz`.
Верни абсолютные пути, статус каждого профиля, p50/p95/p99, число HTTP-операций
и новых соединений, fill ratio, retries/empty recv, CPU/RSS/threads, новые
ошибки корректности и решение decision gates. Профиль можно рекомендовать
только при улучшении во всех трёх проходах: p95 минимум на 20% или HTTP-операций
минимум на 30%, без p95-регрессии свыше 10%.

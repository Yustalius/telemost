# Промпт агенту для сравнения A/B под Corp VPN

Ты работаешь на этом Mac уже под подключённым Cisco Corp VPN. Не отключай VPN
и не проси пользователя переключать сеть. Выполни полное сравнение baseline A
с profile B (64/128/256 КиБ) за эту единственную VPN-сессию. Код и параметры
стенда во время измерения не меняй.

Репозиторий: `/Users/vyustus/PycharmProjects/telemost`

Prerelease: `httptun-diag-v2-20260915-b1`

Проверенный Mac-пакет уже подготовлен локально:

`/Users/vyustus/.telemost-vpn/releases/httptun-diag-v2-20260915-b1-f85b0bd28`

SHA-256 бинарника `httptun-client`:
`c8d2b47c5eeb88d6fcc36d587be9b5d73c1dbf9e4e4c078b10455e3eb9d15bca`.

Mac-пакет: `https://github.com/Yustalius/telemost/releases/download/httptun-diag-v2-20260915-b1/httptun-client-macos-aarch64.tar.gz`

Контрольная сумма: `https://github.com/Yustalius/telemost/releases/download/httptun-diag-v2-20260915-b1/SHA256SUMS`

Сначала используй уже подготовленный пакет — GitHub и повторная загрузка для
основного сценария не нужны:

```bash
PACKAGE_DIR=/Users/vyustus/.telemost-vpn/releases/httptun-diag-v2-20260915-b1-f85b0bd28
cd "$PACKAGE_DIR"
test "$(shasum -a 256 httptun-client | awk '{print $1}')" = \
  c8d2b47c5eeb88d6fcc36d587be9b5d73c1dbf9e4e4c078b10455e3eb9d15bca
test -x diagnostics/run-corp-profile-b.sh
```

Только если локального пакета нет или checksum не совпал, скачай заново
опубликованный Mac-пакет и `SHA256SUMS` по указанным выше URL через dedicated
proxy `127.0.0.1:3129`, затем проверь архив до распаковки.

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

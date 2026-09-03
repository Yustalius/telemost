Промежуточный итог: сам HTTP-транспорт готов и уже встроен в Rust-часть Telemost. Настоящий процесс Telemost успешно зарегистрировался на реальном hbbs через UDP-over-HTTPS на VPS. Но до пользовательской Flutter-сборки ещё остаются несколько важных задач: исправить побочный маршрут API на `23454`, решить доставку изменения в submodule `hbb_common`, собрать полный `.app` через CI и провести настоящую relay-сессию между двумя приложениями.

Работа приостановлена в безопасном состоянии: тестовый Telemost остановлен, локальные порты освобождены, VPS-сервис продолжает работать.

## Что реализовано в `httptun`

Создан отдельный workspace-crate [tools/httptun](/Users/vyustus/PycharmProjects/telemost/tools/httptun) с двумя диагностическими бинарниками и библиотекой для встраивания.

Реализовано:

- фиксированные TCP- и UDP-listener’ы вместо SOCKS5;
- повторяемый аргумент `--map`;
- preset `--telemost-preset 201.24.52.171`;
- два транспорта:
  - `stream` — длинные HTTP-body;
  - `batch` — короткие `POST` и long-poll `GET`, основной режим для корпоративной сети;
- HTTP endpoints:
  - `POST /o` — открыть сессию;
  - `POST /u` — передать данные вверх;
  - `GET /d` — получить данные;
  - `POST /c` — закрыть сессию;
- заголовок `X-Target` с поддержкой:
  - `tcp://host:port`;
  - `udp://host:port`;
- UDP framing `[u32be length][payload]`;
- отдельная UDP-сессия для каждого локального `src_addr`;
- keepalive и явный close-frame;
- встроенные ping/throughput self-test;
- поддержка `HTTPS_PROXY`, `ALL_PROXY` и `NO_PROXY`;
- `--no-proxy` для прямой проверки без VPN;
- синхронное связывание всех локальных портов перед возвратом управления Telemost. Это исключает гонку, когда rendezvous начинает регистрацию раньше, чем готов UDP-listener.

Фиксированная раскладка:

| Назначение | Локально | На VPS |
|---|---:|---:|
| Rendezvous UDP | `127.0.0.1:23456/udp` | `127.0.0.1:21116/udp` |
| Rendezvous TCP | `127.0.0.1:23456/tcp` | `127.0.0.1:21116/tcp` |
| NAT test | `127.0.0.1:23455/tcp` | `127.0.0.1:21115/tcp` |
| Relay | `127.0.0.1:23457/tcp` | `127.0.0.1:21117/tcp` |

Основная реализация находится в [tools/httptun/src/lib.rs](/Users/vyustus/PycharmProjects/telemost/tools/httptun/src/lib.rs).

## Как туннель встроен в Telemost

В корневом [Cargo.toml](/Users/vyustus/PycharmProjects/telemost/Cargo.toml):

- добавлен feature `http-tunnel`;
- он включён в default features для desktop;
- `httptun` добавлен как внутренняя библиотечная зависимость;
- `tools/httptun` включён в Cargo workspace.

Добавлен модуль [src/http_tunnel.rs](/Users/vyustus/PycharmProjects/telemost/src/http_tunnel.rs), который:

- берёт основной VPS из `RENDEZVOUS_SERVERS`;
- подключается к `https://201.24.52.171:443`;
- использует `Mode::Batch`;
- поднимает четыре listener’а;
- читает proxy из окружения;
- работает внутри существующего Tokio runtime;
- не запускает отдельный процесс и не создаёт вложенный runtime.

В [src/server.rs](/Users/vyustus/PycharmProjects/telemost/src/server.rs) туннель запускается до `RendezvousMediator::start_all()`. Таким образом, UDP-порт уже существует в момент первой регистрации.

В [src/client.rs](/Users/vyustus/PycharmProjects/telemost/src/client.rs) и [src/rendezvous_mediator.rs](/Users/vyustus/PycharmProjects/telemost/src/rendezvous_mediator.rs):

- соединения принудительно переводятся на relay;
- адрес relay заменяется на `127.0.0.1:23457`;
- прямой P2P не выбирается;
- входящие relay-запросы также направляются через локальный tunnel-listener.

В [libs/hbb_common/src/config.rs](/Users/vyustus/PycharmProjects/telemost/libs/hbb_common/src/config.rs):

- rendezvous подменяется на `127.0.0.1:23456`;
- WebSocket отключается;
- добавлены константы локальных tunnel endpoints.

То есть пользователю больше не нужно:

- запускать `httptun-client`;
- править `custom-rendezvous-server`;
- задавать `relay-server`;
- включать force-relay вручную.

## Что сделано на VPS

На `201.24.52.171` был обнаружен старый TCP-only `httptun-server`. Его заменили новой версией с TCP+UDP и batch.

Текущее состояние:

- активный бинарник: `/opt/httptun/httptun-server`;
- systemd-unit: `httptun-server.service`;
- слушает `0.0.0.0:443`;
- сервис включён и работает;
- старый бинарник сохранён:
  `/opt/httptun/httptun-server.pre-udp-v2-20260831`;
- временный каталог удалён.

На VPS были отдельно проверены:

- batch self-test без потерь;
- настоящий TCP roundtrip;
- настоящий UDP roundtrip;
- открытие сессий к `21115`, `21116` и `21117`.

## Результаты автоматических тестов

`cargo test -p httptun -- --test-threads=1`:

- 2 unit-теста framing;
- 8 integration-тестов;
- всего 10/10 успешно.

Покрыты:

- TCP batch;
- TCP stream;
- UDP batch;
- UDP stream;
- разделение двух UDP-источников;
- batch ping;
- stream через локальный CONNECT-proxy;
- batch через локальный CONNECT-proxy;
- throughput batch.

`cargo clippy -p httptun --all-targets -- -D warnings` проходит без предупреждений.

Также проходит отдельный тест конфигурации `hbb_common`, подтверждающий:

- tunnel feature активен на desktop;
- rendezvous подменяется на `127.0.0.1:23456`;
- WebSocket выключен.

## Проверка настоящего Telemost

Был собран реальный `target/debug/telemost` и запущен:

```bash
target/debug/telemost --server
```

Логи подтвердили:

```text
httptun-client -> https://201.24.52.171:443 (mode=batch, proxy=Env)
UDP 127.0.0.1:23456 -> udp://127.0.0.1:21116
TCP 127.0.0.1:23456 -> tcp://127.0.0.1:21116
TCP 127.0.0.1:23455 -> tcp://127.0.0.1:21115
TCP 127.0.0.1:23457 -> tcp://127.0.0.1:21117
HTTP batch tunnel is ready
start rendezvous mediator of 127.0.0.1:23456
start udp: 127.0.0.1:23456
```

При этом Telemost сам открыл:

- TCP rendezvous;
- NAT-test;
- UDP registration.

На VPS появилась соответствующая сессия:

```text
udp://127.0.0.1:21116
```

и последовательность `POST /o`, `POST /u`, `GET /d`.

Перед началом регистрации Telemost сообщил, что ключ не подтверждён. После прохождения UDP-регистрации через туннель в конфигурации появилось:

```text
key_confirmed = true
```

Команда:

```bash
target/debug/telemost --get-id
```

вернула ID `987654321`.

Это наиболее важный результат: исправлен исходный архитектурный дефект SOCKS-only варианта — `RegisterPk` реально прошёл по UDP через HTTPS-туннель и hbbs принял регистрацию.

Также отдельное подключение к `127.0.0.1:23457` создало на VPS сессию:

```text
tcp://127.0.0.1:21117
```

То есть встроенный relay-маршрут до hbbr работает. Полноценный экранный сеанс между двумя Telemost пока не проводился.

`lsof` показал, что процесс Telemost:

- слушает только локальные `23455–23457`;
- подключается наружу к `201.24.52.171:443`;
- прямых внешних соединений на `21115–21117` нет.

## Сборка приложения

После установки статических зависимостей через vcpkg:

```text
libvpx
libyuv
opus
aom
```

успешно собран нативный debug-бинарник Telemost.

Также выполнена проверка тех Rust-таргетов, которые входят во Flutter-приложение:

```bash
cargo check --locked --features flutter --lib --bin service
```

Она проходит после штатной генерации `src/bridge_generated.rs`.

Полный Flutter `.app`/DMG пока не собран, потому что на машине отсутствует Flutter SDK. GitHub CI тоже не запускался:

- изменения ещё не закоммичены и не отправлены;
- текущая авторизация `gh` недействительна;
- запуск CI потребует подготовить коммиты и push.

## С какими проблемами столкнулись

### 1. Исходный сервер умел только TCP

Старый `httptun-server` на VPS не понимал `udp://`. Он был пересобран и заменён с резервной копией.

### 2. SOCKS5 не может провести регистрацию

Telemost регистрируется на UDP `21116`. Поэтому старый SOCKS-only путь был архитектурно непригоден. Его заменили фиксированными TCP/UDP listener’ами.

### 3. Вложенный Cargo workspace

`tools/httptun` изначально был отдельным workspace со своим `Cargo.lock`. Для встраивания пришлось сделать его членом основного workspace и использовать корневой lockfile.

После этого проявилась несовместимость версии `futures-channel`: использованный ранее `try_recv()` отсутствовал в версии из корневого lockfile. Код переведён на `try_next()`.

### 4. На Mac отсутствовали статические кодеки

Локальный linker сначала падал с:

```text
could not find native static library vpx
```

Кроме того, сохранился старый путь к временному vcpkg-каталогу от прежнего запуска.

Для штатной сборки:

- установлен Homebrew `vcpkg`;
- скачан registry на baseline, закреплённый проектом;
- собраны `libvpx`, `libyuv`, `opus`, `aom`;
- очищены артефакты `scrap`;
- нативная сборка после этого прошла.

### 5. Flutter bridge не хранится в Git

`cargo check --features flutter` сначала падал из-за отсутствия `src/bridge_generated.rs`.

Установлен `flutter_rust_bridge_codegen 1.80.1`, зафиксированный проектом. Сам генератор сначала упал из-за глобального `RUST_LOG=warn`: эта старая версия принимает только `info` или `debug`. После запуска с `RUST_LOG=info` Rust bridge был создан.

Полная генерация Dart/C header остановилась из-за отсутствующего Flutter SDK, но сгенерированного Rust-файла хватило, чтобы проверить `lib + service`.

### 6. Нет root IPC-service в локальном тесте

Тестовый `--server` периодически писал:

```text
failed to connect to ipc_service
timed out waiting 3s for initial config sync
```

Это связано с тем, что запускался локальный debug-бинарник, а не установленный `.app` со службой. На туннель и регистрацию это не повлияло.

## Найденная нерешённая проблема

Сейчас глобальная подмена `Config::get_rendezvous_server()` на `127.0.0.1:23456` влияет не только на hbbs, но и на вычисление API URL.

В результате Telemost пытается обращаться к:

```text
http://127.0.0.1:23454/api/sysinfo
http://127.0.0.1:23454/api/heartbeat
```

Listener на `23454` не предусмотрен, поэтому появляются ошибки, после чего код пытается использовать TCP proxy fallback через rendezvous.

Это не мешает UDP-регистрации, но перед итоговой сборкой так оставлять нельзя. Нужно отделить:

- адрес transport rendezvous — локальный `127.0.0.1:23456`;
- исходный адрес инфраструктуры/API — `201.24.52.171`.

Вероятнее всего, при продолжении стоит убрать глобальную подмену из `hbb_common::Config` и сделать tunnel-routing на более узком сетевом уровне Telemost. Альтернатива — отдельный mapping для `23454`, но это хуже: смешивает API и rendezvous и не соответствует исходной таблице портов.

## Ещё два вопроса перед production

### Изменения внутри submodule

`libs/hbb_common` является отдельным Git submodule. Сейчас его файлы изменены локально, но корневой репозиторий видит только состояние `m libs/hbb_common`.

Такой diff сам по себе не попадёт в CI. Перед push необходимо выбрать один путь:

- сделать отдельный commit/push в форке `hbb_common` и обновить gitlink;
- перенести tunnel-specific изменения из submodule в основной crate Telemost.

Второй вариант выглядит предпочтительнее вместе с исправлением API `23454`.

### Доступ к произвольному `X-Target`

Сейчас публичный `httptun-server` принимает произвольный `tcp://host:port` или `udp://host:port` без аутентификации. Это соответствует диагностическому `--map`, но для production означает потенциальный открытый proxy с точки зрения VPS.

До релиза стоит:

- либо разрешить только loopback и порты `21115–21117`;
- либо добавить аутентификационный token;
- либо закрыть доступ дополнительным сетевым правилом.

## Что изменилось в локальном окружении

Вне репозитория:

- установлен Homebrew `vcpkg`;
- зависимость Homebrew `fmt` обновлена до `12.2.0`;
- установлен `/Users/vyustus/.cargo/bin/flutter_rust_bridge_codegen`;
- во временных каталогах остались vcpkg registry и библиотеки:
  - `/private/tmp/telemost-vcpkg-20260831`;
  - `/private/tmp/telemost-vcpkg-installed-20260831`;
- сгенерирован игнорируемый Git файл `src/bridge_generated.rs`.

Их пока не удалял, чтобы при продолжении не собирать зависимости заново.

На VPS оставлен работающий новый сервер. Это единственное постоянное внешнее изменение.

## Документация

Обновлён [README-run.md](/Users/vyustus/PycharmProjects/telemost/tools/httptun/README-run.md). В нём описаны:

- встроенный режим без sidecar;
- таблица портов;
- сборка;
- VPS;
- проверка без VPN;
- запуск через `px`;
- `launchctl setenv` для установленного macOS-приложения;
- совместимость со старой версией на втором компьютере.

Короткий ответ на прошлый вопрос о втором компьютере:

- старая версия совместима, если второй компьютер напрямую видит VPS;
- новая версия нужна и на втором компьютере только тогда, когда его сеть тоже блокирует обычное подключение к VPS.

## Текущая готовность

Готово:

- HTTP TCP/UDP tunnel;
- batch и stream;
- proxy-env;
- VPS deployment;
- UDP-регистрация настоящего Telemost;
- встроенный lifecycle;
- принудительный relay;
- Rust-сборка и тесты.

Не готово:

- корректная развязка API и локального rendezvous;
- production-ограничение `X-Target`;
- оформление изменений `hbb_common`;
- полный Flutter `.app`/DMG;
- CI;
- реальная relay-сессия между двумя приложениями;
- signed/notarized пользовательская сборка.

Изменения не закоммичены и никуда не отправлены.
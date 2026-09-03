# Промпт для агента: проверка риска TLS-инспекции MWG (фаза O1)

Скопируй всё ниже в агента, которого запускаешь **на рабочей машине под корп-VPN**
(тот же клон репозитория `telemost`).

---

Ты запущен на macOS под корпоративным VPN (full-tunnel, весь трафик идёт через
McAfee Web Gateway; наружу открыт только HTTP через прокси-шим, обычно
`http://127.0.0.1:3128`).

**Задача.** Проверить, переживёт ли встроенный HTTP-туннель telemost переключение
на строгую валидацию TLS (`danger:false`, фаза O1), или MWG перехватывает TLS и
подписывает трафик своим CA, которого нет в системном trust store (тогда клиент
O1 будет падать на проверке сертификата под VPN).

**Контекст, который важно понимать.**
- Боевой клиент использует TLS-стек `reqwest + rustls-tls-native-roots` — то есть
  **системные корни macOS**. Скрипт-проба использует ровно этот же стек, поэтому
  его вердикт авторитетен (не путать с trust store у `curl`/OpenSSL).
- Домен `ya-telemost.site` уже резолвится в наш VPS `201.24.52.171`, но публичный
  сертификат Let's Encrypt на нём, возможно, ещё **не установлен** — тогда сервер
  отдаёт свой self-signed (`CN=rcgen self signed cert`). Это НЕ инспекция MWG.
- Разграничение по issuer предъявленного серта:
  - issuer = `rcgen self signed` → это НАШ сервер, MWG пропустил цепочку нетронутой
    (**passthrough**, инспекции нет). `danger:false` заработает после выката
    LE-серта.
  - issuer = McAfee / Web Gateway / любой корп-CA → **реальная инспекция**; если
    этот CA не в системном trust — риск для O1.

**Шаги.**
1. Убедись, что бинарь собран: `ls target/release/httptun-client target/debug/httptun-client`.
   Если нет — собери (лучше это делать ДО ухода под VPN, нужна сеть за деп-кэшем):
   `cargo build -p httptun --bin httptun-client --release`
2. Проверь, что ты под VPN и найден прокси. Если `env | grep -i proxy` пусто,
   задай `export HTTPS_PROXY=http://127.0.0.1:3128 ALL_PROXY=$HTTPS_PROXY`
   (или тот адрес px, что использует telemost).
3. Запусти: `bash tools/httptun/mwg-tls-probe.sh`
   (можно добавить свои домены: `EXTRA_TARGETS="https://foo https://bar" bash tools/httptun/mwg-tls-probe.sh`).
4. Прочитай per-target JSON и вердикты. Ключевой домен — `ya-telemost.site`;
   контроли (`example.com`, `google.com`, `cloudflare.com`) показывают общее
   поведение MWG.

**Что вернуть (выводы).**
- По `ya-telemost.site`: PASSTHROUGH / RISK / BLOCKED и почему (процитируй issuer и
  поле `error` из JSON `danger:false`).
- По контролям: проходит ли `danger:false` в принципе (значит MWG не ломает
  публичные серты) или инспектирует всё.
- Итоговая рекомендация:
  - Если по `ya-telemost.site` **passthrough или OK** → O1 c `danger:false` под
    VPN безопасен (при passthrough — после установки LE-серта). Отдельных действий
    не нужно.
  - Если **RISK** (инспекция чужим CA) → проверь, есть ли корп-CA в системном
    хранилище: `security dump-trust-settings -d`,
    `security find-certificate -a -c McAfee /Library/Keychains/System.keychain`.
    Если корп-CA доверен системой — `danger:false` всё равно пройдёт (перепроверь
    скриптом). Если нет — эскалируй: для corp-пути оставить `danger:true`/пиновать
    корп-CA, публичную валидацию включать только вне corp-сети.
  - Если **BLOCKED** на `ya-telemost.site`, но контроли живы → MWG режет домен по
    категории; нужно менять домен/категорию, это отдельно от TLS.

**Важно.** Окончательную проверку `ya-telemost.site` повтори ПОСЛЕ установки на VPS
публичного сертификата Let's Encrypt — до этого домен отдаёт self-signed, и строгую
валидацию физически нечем пройти. Ничего в системе не меняй: только читай и делай
выводы.

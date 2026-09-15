# Промпт следующему агенту: закрыть этап B и подготовить reuse-эксперимент

Ты продолжаешь поэтапную оптимизацию reverse httptun в репозитории
`/Users/vyustus/PycharmProjects/telemost`.

## Сначала прочитай

1. `/Users/vyustus/PycharmProjects/telemost/AGENTS.md`.
2. `/Users/vyustus/PycharmProjects/telemost/tools/httptun/diagnostics/PROFILE_B_REPORT.md`.
3. `/Users/vyustus/PycharmProjects/telemost/telemost-corp-vpn-plan.md` — это
   пользовательский изменённый файл; только читай, не редактируй и не включай
   в свои коммиты.
4. Evidence:
   `/Users/vyustus/.telemost-vpn/diagnostics/compare-20260915T153021Z/report.json`
   и `summary.md` рядом.

## Подтверждённое состояние

- Ветка: `codex/httptun-reverse`.
- Profile B реализован opt-in и отключён по умолчанию.
- Полное A/B-сравнение завершено: B256 — единственный вариант без p95-регрессии
  свыше 10%; новых ошибок корректности и retries нет.
- B256 улучшает p95 `background_download` на 76.7%, `download` на 73.6% и
  `slow_receiver` на 51.2%; HTTP-операций меньше на 18.2%.
- Короткие запросы и `ack_wait` почти не улучшились.
- Connection reuse равен 0%: каждое обращение создаёт новое соединение.
- Product config и production endpoint `probe` всё ещё используют A.
- VPS уже содержит b1 и отдельный endpoint `diag`; не переустанавливай его без
  необходимости.
- Bearer token не ротировать. Не печатай полный systemd `ExecStart`: token
  хранится там литералом.

## Твоя задача

Закрой технические долги этапа B и подготовь следующий изолированный
эксперимент — HTTP/1.1 connection reuse поверх B256. Не начинай profile C, пока
не установлена причина нулевого reuse и не проверена возможность его получить
через текущий HTTP/1.1/MWG путь.

### 1. Исправь инструментарий

- Сделай `httptun-corp-launch.sh` и `run-corp-profile-b.sh` совместимыми с
  macOS `/bin/bash` 3.2 при `set -u`. Используй уже проверенные минимальные
  замены из `PROFILE_B_REPORT.md`.
- Добавь регрессионную проверку именно для пустых массивов; одного `bash -n`
  недостаточно.
- Исправь `analyze-comparison.py`: p95-регрессия `>10%` должна проверяться по
  всем сопоставимым latency-сценариям, включая `upload`, а не только по
  `PRIORITY_SCENARIOS`.
- Добавь тест/fixture, который отбраковывает B64 при `upload +136%`, B128 при
  `upload +49.6%` и оставляет B256 рекомендованным.
- Проверяй анализатор на копии готового result directory; исходный evidence и
  архив не изменяй.

### 2. Локализуй причину 0% connection reuse

- Сначала прочитай существующие client/server HTTP builders, lifecycle
  reqwest client, proxy configuration и hyper HTTP/1.1 serving path.
- Инструментируй только безопасные признаки: connection id, reused/new,
  длительность CONNECT/TLS, request sequence и закрытие соединения. Не логируй
  token, заголовки авторизации, cookies, тела и SSO query.
- Отдели три случая: direct local, через локальный whole-body proxy и через
  dedicated px/MWG. Не делай вывод о MWG по локальному direct-тесту.
- Проверь, закрывает ли соединение клиент, сервер или промежуточный proxy, и
  действительно ли один `reqwest::Client` используется повторно.
- Сохраняй HTTP/1.1 и конечные Batch-запросы. Не возвращай H2/gRPC и бесконечные
  streaming bodies.

### 3. Подготовь opt-in reuse-прототип

- База сравнения — B256, но A и product default не меняй.
- Новый режим должен быть отдельным явным флагом и работать только на reverse
  experiment endpoint `diag`; отсутствие флага обязано сохранять текущую
  семантику.
- Не смешивай reuse с profile C, окном отправки, быстрым open или приоритетами.
- Если MWG принудительно закрывает каждое соединение и reuse технически
  недостижим, не маскируй результат: зафиксируй evidence и подготовь переход к
  profile C без фиктивного изменения продукта.
- Если reuse работает, сравни B256 control и B256+reuse трижды с чередованием
  порядка. Gate: отсутствие новых ошибок; p95 не хуже более чем на 10%; целевой
  выигрыш — p95 не менее 20% или HTTP connections/operations не менее 30% во
  всех трёх проходах.

## Безопасность и совместимость

- Не меняй и не коммить существующие пользовательские файлы:
  `telemost-corp-vpn-plan.md`, `.codegraph/`, `macos-o7-o8-change-report.md`,
  `tools/macos-o7-o8-cleanup-dry-run.sh`, `tools/macos-prepare-local-app.sh`,
  `tools/test-macos-o7-o8-cleanup-dry-run.sh`.
- Делай минимальный diff. Не включай эксперимент в `src/http_tunnel.rs` по
  умолчанию.
- Не трогай `probe`; эксперименты идут только через `diag`.
- Перед VPS-действиями проверяй точную цель. Установщик обязан сохранить
  бинарник/unit и откатиться при failed health/listener checks.
- Не переключай Cisco VPN сам. Всё, что требует Corp VPN, упакуй в один
  самостоятельный сценарий и отдай отдельным промптом пользователю.
- Не удаляй исходные или failed evidence-каталоги.

## Обязательные проверки

- `cargo fmt -p httptun -- --check`;
- `cargo test -p httptun --locked -- --test-threads=1`;
- `cargo check -p httptun --locked`;
- `cargo check --lib --locked`;
- тесты Bash 3.2 и анализатора;
- локальная матрица whole-body proxy 50/250/1000 мс;
- live smoke A/B256 и нового opt-in только после успешного prerelease/deploy.

Если нужен диагностический релиз, публикуй новый prerelease с явными
`upload-artifact=true` и новым тегом. Не переиспользуй `b1`. Проверяй SHA-256 и
содержимое пакетов до установки. Production `probe` должен остаться A после
любого теста.

## Что вернуть

1. Причину нулевого reuse и evidence, а не предположение.
2. Точный diff и список коммитов.
3. Результаты всех локальных тестов и smoke-проверок.
4. Сравнение B256 control с reuse-прототипом либо доказательство, что MWG
   запрещает reuse.
5. Состояние VPS и подтверждение, что `probe` остался A.
6. Один готовый промпт для Corp VPN-прогона, если он ещё нужен.
7. Рекомендацию: принять reuse, отклонить его или перейти к profile C.


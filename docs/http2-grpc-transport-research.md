# H2/gRPC transport probe — постмортем

**Статус: CLOSED / FAILED.** Эксперимент закрыт: H2/gRPC не работает стабильно через целевой
корпоративный путь, поэтому интеграцию в Telemost не продолжаем.

## Гипотеза

Длинные HTTP/2 streams или gRPC bidi могли заменить HTTP/1.1 Batch, пройти через корпоративный
CONNECT/MWG и уменьшить polling overhead без изменения внутреннего протокола Telemost.

## Схема проверки

На VPS временный PREROUTING переводил новые подключения с публичного `:443` на отдельный Nginx
listener `:1443`. Он направлял probe routes на изолированный loopback-сервис `:18443`, а остальной
трафик — на действующий httptun backend. Отдельные Node.js и Rust-клиенты проверяли H2 streams,
gRPC unary/bidi, trailers/status, cancellation, deadlines и передачу данных напрямую и через
корпоративный proxy. Production-сервис и постоянный сертификат не заменялись.

## Результат и решение

Локально и на публичном пути probe работал, но через целевой корпоративный путь H2/gRPC оказался
нестабильным. Это не даёт надёжного транспорта для desktop-клиента и не решает восстановление TCP
после потери серверной сессии.

Решение: остановить эксперимент, не добавлять H2/gRPC в продукт и развивать Wire V2 поверх
HTTP/1.1 Batch. Код probe, SDK, подготовленные пакеты и deployment-скрипты удаляются из репозитория.

## Rollback inventory

При rollout Wire V2 с VPS удалить только временный probe-контур:

- PREROUTING-правило `telemost-transport-probe` (`443 -> 1443`);
- временную конфигурацию Nginx и listener `1443`;
- `telemost-transport-probe`, listener `18443`, его environment/credential и временную установку;
- INPUT-правило `telemost-probe-direct-port`.

Основной сертификат, certbot, постоянный Nginx и production httptun не относятся к probe rollback.

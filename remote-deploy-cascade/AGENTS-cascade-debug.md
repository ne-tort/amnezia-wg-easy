# Каскад S1↔S2: отладка туннеля и форвардинга

Порядок деплоя: **[DEPLOY_ORDER.md](DEPLOY_ORDER.md)**. Текущий фокус AGENTS — домены и nginx; этот файл сохраняет методику **расследования каскада** (handshake, nft, маршруты).

## Источник истины

Реальное состояние на **S1 и S2**: `dmesg`, `awg`/`wg show`, `nft`, `ip rule`, маршруты.

## Сбор (минимум)

**S1** (`docker exec amnezia-awg`):

```sh
docker exec amnezia-awg awg show awg-cascade 2>/dev/null
docker exec amnezia-awg ip -4 rule list
docker exec amnezia-awg ip route get 1.1.1.1
```

**S2** (контейнер `amnezia-exit-cascade`, host network):

```sh
docker exec amnezia-exit-cascade awg show exit-cascade 2>/dev/null
nft list table ip amnezia_cascade_exit_nat 2>/dev/null
iptables -S DOCKER-USER 2>/dev/null
```

При `AllowedIPs = 0.0.0.0/0` у каскада см. маршруты в таблицах с `default dev awg-cascade` и скрипты `scripts/cascade-in-container-postup.sh`.

## Критерий успеха каскада

Handshake не `(none)` на `awg-cascade` (S1) и `exit-cascade` (S2); нет критичных ошибок в свежем `dmesg`.

## IPv6

NAT каскада ориентирован на IPv4; IPv6 у клиента может не работать без отдельной настройки.

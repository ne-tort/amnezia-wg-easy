# Удалённая установка каскада (entry + exit) по SSH

**Порядок операций (обязательный):** [DEPLOY_ORDER.md](DEPLOY_ORDER.md).

При **`cascade_enabled`** порядок в `--phase full`: **S1 entry → S2 exit** (чтобы `exit-cascade.conf` появился сразу после старта exit; подробности — [DEPLOY_ORDER.md](DEPLOY_ORDER.md)). Дальше:

1. **S1 (entry)** — полный стек `amnezia-wg-easy` (панель + awg0). При каскаде синхронизируется **`awg-cascade.conf`** в контейнере `amnezia-awg` (как у `awg0`).
2. **S2 (exit)** — [exit-core](exit-core/README.md): `amneziavpn/amneziawg-go`, **`exit-cascade`**, `network_mode: host`. Контейнер ждёт конфиг **не дольше 30 с**, иначе падает.
3. **Синхронизация ключей** — `awg0.conf`, `exit-cascade.conf` на S2, ключи пира на S1, перезапуск exit и `wg-quick` каскада на entry.
4. **Хост S2** — NAT/forward (`nft` + `iptables` в `DOCKER-USER`) для WAN↔`exit-cascade`.

Старый стек панели на S2 оркестратор **не останавливает** — см. однократную процедуру в [exit-core/README.md](exit-core/README.md).

## Переустановка и тома

Для каждого шага узла: sync исходников → `docker compose down` **только своего проекта** → очистка устаревших nft/ip правил каскада на хосте → preflight → `.env` → `deploy.sh` и т.д.

- **`--wipe-db`** — удалить volume БД панели (`amnezia-wg-data`) при переустановке entry/exit с полным стеком (на exit-core не применяется).
- **`--wipe-cascade`** — сбросить состояние каскада: volume exit-core с конфигом/ключами; файлы каскада в volume панели на entry. Без флага ключи и конфиги каскада **сохраняются** между прогонами.

## Быстрый старт

```bash
cd remote-deploy-cascade
pip install -r requirements.txt
cp config.example.yaml config.yaml
python install.py --phase full
```

В `config.yaml` для каскада нужны **`entry.network.cascade_enabled: true`** и **`exit.core: true`** (или `exit.mode: core`).

**Источник кода:** используйте **`source.mode: git`** и репозиторий с нужным коммитом (сначала `git push`). Режим **`source.mode: local`** в этой среде **непригоден** для реального выката: серверы не получают гарантированно актуальный дерево с вашей машины. Файл [`deploy-local.yaml`](deploy-local.yaml) оставлен как заглушка-предупреждение.

## Порты (важно)

- **Не используйте стандартный WG UDP 51820/51821** для продакшена: в примере `WG_PORT: 5443` на entry и **`cascade_listen_port: 8443`** на S2 (UDP, слушает exit-core). Значения должны совпадать в `entry.network` и `exit.network` для каскада.
- На S2 панели нет: **8443/UDP** — только туннель каскада; **443/TCP** на entry не пересекается с этим.

## Интернет у клиента не работает — что проверить

1. **`exit.network.wan_interface`** — имя реального выхода в Интернет на S2 (`ip -4 route get 1.1.1.1` → `dev …`). Неверный интерфейс ломает SNAT и forward.
2. **Старый `wg-cascade` на хосте S2** — если UDP порт занят, снимите интерфейс: `wg-quick down wg-cascade` / `ip link del wg-cascade`.
3. **Пиры** — `docker exec amnezia-awg awg show awg-cascade` на S1 и `awg show exit-cascade` на S2: должен быть `latest handshake`, растут `transfer`.
4. **В контейнере entry** — `ip rule` / `ip route show table 166`: для трафика **с адресов клиентов** (`from 10.8.0.0/24`) в table 166 должен быть `default via 172.31.255.2 dev awg-cascade` (не через fwmark). Проверка: `docker exec amnezia-awg ip rule`; `docker exec amnezia-awg ip route show table 166`. Для **Amnezia DNS** (`172.29.172.254`) в той же table 166 должна быть **более специфичная** запись в сеть `amnezia-dns-net` (например `172.29.172.0/24 dev eth1`), иначе запросы DNS уйдут в каскад и не дойдут до контейнера `amnezia-dns`. Скрипт `scripts/cascade-in-container-postup.sh` добавляет этот маршрут при наличии `eth1`.
5. **Клиент Amnezia** — в профиле должен быть маршрут в Интернет через туннель (**AllowedIPs** с `0.0.0.0/0` или аналог), иначе трафик наружу не пойдёт через VPN даже при исправной каскадной маршрутизации.
6. **На S2** — `nft list table ip amnezia_cascade_exit_nat` и `inet amnezia_cascade_exit_fwd`: masquerade для `client_cidrs` и forward WAN↔`exit-cascade`. При необходимости повторите деплой с фазой, где вызываются хуки (`full` / `entry-only` / `exit-only`).

## Фазы

- `--phase exit-only` — только exit-core на S2 (+ хуки NAT, если включён каскад в конфиге).
- `--phase entry-only` — только entry; при включённом каскаде затем **sync** и хуки на exit.
- `--phase full` — exit → entry → sync → хуки на exit (по умолчанию).

## Dry-run

```bash
python install.py --dry-run --phase full
```

## Проверка после запуска

- **S1 (в контейнере панели)**  
  `docker exec amnezia-awg awg show awg0`  
  `docker exec amnezia-awg awg show awg-cascade`
- **S2**  
  `docker logs amnezia-exit-cascade --tail 50`  
  `docker exec amnezia-exit-cascade awg show exit-cascade`  
  `nft list table ip amnezia_cascade_exit_nat`  
  `nft list table inet amnezia_cascade_exit_fwd`

На entry хосте при необходимости смотрите очистку policy routing из `install.py` (`build_entry_cleanup_script`) после миграции со старой схемы.

# Удалённая установка каскада (entry + exit) по SSH

`remote-deploy-cascade/install.py` запускает единый orchestrator:

1. деплой `exit`-узла,
2. деплой `entry`-узла,
3. автоматическое поднятие межсерверного `wg-cascade` (host namespace),
4. применение сетевых hook'ов каскада:
   - policy routing на `entry`,
   - NAT/forward на `exit`.

Скрипт **не останавливает чужие контейнеры**: только compose-проект в `remote.path` каждого узла.

## Как работает переустановка

Каждый запуск (`exit-only`, `entry-only`, `full`) выполняет согласованный clean reinstall шага узла:

1. sync исходников (`git`/`local`),
2. `docker compose down` только своего проекта,
3. очистка старых каскадных правил (маршрутизация + nft таблицы каскада),
4. preflight портов,
5. запись нового `.env`,
6. `deploy.sh`,
7. `applyAdminPasswordFromEnv.js`.

По умолчанию БД **сохраняется**. Для удаления БД при переустановке используйте `--wipe-db`.

## Быстрый старт

```bash
cd remote-deploy-cascade
pip install -r requirements.txt
cp config.example.yaml config.yaml
python install.py --phase full
```

## Фазы

- `--phase exit-only` — только exit.
- `--phase entry-only` — только entry.
- `--phase full` — exit -> entry -> cascade hooks (по умолчанию).
- `--wipe-db` — дополнительно удалить DB volume (`amnezia-wg-data`) на переустанавливаемых узлах.

## Dry-run

```bash
python install.py --dry-run --phase full
```

Показывает план действий без SSH/изменений.

## Важные ограничения

- Межсерверные интерфейсы (`entry.network.exit_uplink_interface`, `exit.network.entry_uplink_interface`) должны существовать заранее.
- Скрипт создаёт/обновляет host-level интерфейс `wg-cascade` и ключи в `/etc/wireguard`.
- При занятии портов другим ПО deployment завершится ошибкой (fail-fast).
- Для полного сброса состояния панели используйте `--wipe-db`.

## Проверка после запуска

- На `entry`:
  - `ip -o link show | grep wg-cascade`
  - `ip rule show | rg 166`
  - `ip route show table 166`
  - `nft list table inet amnezia_cascade_entry`
- На `exit`:
  - `ip -o link show | grep wg-cascade`
  - `nft list table ip amnezia_cascade_exit_nat`
  - `nft list table inet amnezia_cascade_exit_fwd`

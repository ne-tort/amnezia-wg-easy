# Удалённая установка каскада (entry + exit) по SSH

`remote-deploy-cascade/install.py` поднимает:

1. **S2 (exit)** — только [exit-core](exit-core/README.md): контейнер `amneziavpn/amneziawg-go`, интерфейс **`exit-cascade`**, `network_mode: host`. Полная панель на S2 **не ставится**.
2. **S1 (entry)** — полный стек `amnezia-wg-easy` (панель + awg0). При `entry.network.cascade_enabled` панель дополнительно синхронизирует **`awg-cascade.conf`** внутри контейнера `amnezia-awg` (те же параметры обфускации Amnezia, что у `awg0`).
3. **Синхронизация ключей** — скрипт вытягивает `awg0.conf`, пишет `exit-cascade.conf` на S2, публикует публичные ключи пира на S1 и перезапускает контейнеры.
4. **Хост на S2** — только NAT/forward (`nft`) для трафика с `exit-cascade` в WAN; отдельного `wg-cascade` в netns хоста больше нет.

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

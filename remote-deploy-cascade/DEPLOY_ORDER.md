# Порядок деплоя каскада (обязательный)

Нарушение порядка даёт «деплой прошёл», но туннель или интернет не работают. Оркестратор [`install.py`](install.py) при `--phase full` выполняет шаги **1→5** сам.

## При `--phase full` и включённом каскаде (`cascade_enabled` + `exit.core`)

1. **S1 — entry** (панель + `amnezia-awg`) — **сначала**, чтобы ключи и `awg0` уже были до exit.
2. **S2 — exit-core** — контейнер ждёт **`exit-cascade.conf` максимум 30 с**; оркестратор затем сразу делает **sync** (конфиг попадает в volume за секунды после старта exit). Если за 30 с файла нет — контейнер **падает с ошибкой** (не «не успело»).
3. **Синхронизация** — `sync_cascade_configs`: ключи, `exit-cascade.conf`, перезапуск exit, `wg-quick down/up` для `awg-cascade` на entry.
4. **Хуки на хосте S2** — `apply_cascade_hooks` (очистка + nft/sysctl/iptables).
5. **Проверка пиров** — `verify_cascade_peers_connected` (короткие повторы; отсутствие handshake = поломка, не ожидание).

## При `--phase full` без каскада (как раньше)

1. **S2 — exit** (если используется отдельный exit в конфиге), затем **S1 — entry** — см. вывод `install.py`.

## Однократно на S2

Старый конфликтующий WG на хосте — см. [exit-core/README.md](exit-core/README.md).

## Синхронизация ключей (`sync_cascade_configs`)

- Функция **`sync_cascade_configs`**: ключи пира, `exit-cascade.conf` на S2, файлы на S1 в volume, триггер **`saveConfig`** на entry, перезапуск **`amnezia-exit-cascade`**, затем в **`amnezia-awg`**: **`wg-quick down` / `wg-quick up`** для `awg-cascade.conf`.

## Хуки на хосте S2

- **`apply_cascade_hooks`**: очистка наших `nft`/`iptables`, затем заново NAT/forward, **`sysctl`**, **`DOCKER-USER`**.

## Проверка живого пира

- **`verify_cascade_peers_connected`**: `awg show` на обоих концах, handshake не `(none)`.

## Фазы `--phase`

| Фаза | Что делает |
|------|------------|
| `full` (cascade) | entry → exit → 3 → 4 → 5 |
| `full` (без cascade) | exit → entry → … (как в логе) |
| `exit-only` | exit → 4 → 5 |
| `entry-only` | entry → 3 → 4 → 5 |

## После обновления образа entry

Актуальные [`scripts/cascade-in-container-postup.sh`](../scripts/cascade-in-container-postup.sh) (маршрут `/32` на публичный IP exit через default route).

## Документ для расследований

[AGENTS.md](AGENTS.md)

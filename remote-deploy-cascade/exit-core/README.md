# Exit-core: AmneziaWG-only cascade node (S2)

Один контейнер `amneziavpn/amneziawg-go:latest`, `network_mode: host`. Интерфейс из файла `exit-cascade.conf` называется **`exit-cascade`** (имя берётся из имени файла).

## Однократно: снять старую панель с этого сервера

Если раньше на S2 стоял полный `amnezia-wg-easy` (панель + nginx), **оркестратор его не трогает**. Выполните вручную на S2:

```bash
cd /opt/amnezia-wg-easy-exit   # или ваш путь
docker compose -f docker-compose.yml down --remove-orphans
# при необходимости: docker volume rm … только свои тома панели
```

После этого каталог можно оставить или удалить — на каскад exit-core это не влияет.

## Установка

Деплой выполняет `remote-deploy-cascade/install.py` с `exit.core: true` (или `exit.mode: core`). Локально для проверки:

```bash
cd /opt/amnezia-cascade-exit
docker compose pull
docker compose up -d
```

Конфиг кладёт оркестратор в volume как `/config/exit-cascade.conf`. После обновления конфига:

```bash
docker restart amnezia-exit-cascade
```

## Проверки

```bash
docker logs amnezia-exit-cascade --tail 50
docker exec amnezia-exit-cascade awg show exit-cascade
```

NAT/forward на хосте задаётся хуками оркестратора (`nft`), интерфейс в правилах — `exit-cascade`.

# Exit-core: каскад S2 (AmneziaWG + nginx + certbot)

Стек в каталоге после деплоя [`install.py`](../install.py):

- **`amnezia-exit-cascade`** — `network_mode: host`, только **UDP** каскада (порт из `cascade_listen_port`).
- **`nginx`** — **TCP 80/443**, TLS, reverse proxy на корень сайта (режимы `mirror` / `local` через `.env`).
- **`certbot`** — профиль `letsencrypt`, тома `certbot_conf` / `certbot_www` (сертификаты сохраняются между редеплоями).

UDP и TCP не пересекаются: nginx не слушает порт каскада.

## Конфигурация

Параметры задаются в **`exit.env`** в YAML оркестратора; на сервере появляется `.env`. Обязательно для публичного сайта: `PANEL_DOMAIN`, `CERTBOT_EMAIL`, `NGINX_*`.

Запуск вручную после правок `.env`:

```bash
cd /opt/amnezia-cascade-exit
./deploy-exit.sh
```

## Однократно: снять старую панель с этого сервера

Если раньше стоял полный `amnezia-wg-easy`, остановите его вручную (см. старые инструкции). Тома **certbot** нового стека не удаляйте без необходимости.

## Проверки

```bash
docker logs amnezia-exit-cascade --tail 30
docker exec amnezia-exit-cascade awg show exit-cascade
docker exec nginx nginx -t
curl -sI "https://$(grep ^PANEL_DOMAIN= .env | cut -d= -f2-)/"
```

Диагностика каскада: [AGENTS-cascade-debug.md](../AGENTS-cascade-debug.md).
# Exit-core: каскад S2 (AmneziaWG + nginx + certbot)

Стек в каталоге после деплоя [`install.py`](../remote-deploy-cascade/install.py):

- **`amnezia-exit-cascade`** — `network_mode: host`, только **UDP** каскада (порт из `cascade_listen_port`).
- **`nginx`** — **TCP 80/443**, TLS, reverse proxy на корень сайта (режимы `mirror` / `local` через `.env`).
- **`certbot`** — профиль `letsencrypt`, тома `certbot_conf` / `certbot_www` (сертификаты сохраняются между редеплоями).

UDP и TCP не пересекаются: nginx не слушает порт каскада.

## Конфигурация

Параметры задаются в **`exit.env`** в YAML оркестратора; на сервере появляется `.env`. Обязательно для публичного сайта: `PANEL_DOMAIN`, `CERTBOT_EMAIL`, `NGINX_*`.

Запуск вручную после правок `.env`:

```bash
cd /opt/amnezia-cascade-exit
./deploy-exit.sh
```

## Однократно: снять старую панель с этого сервера

Если раньше стоял полный `amnezia-wg-easy`, остановите его вручную (см. старые инструкции). Тома **certbot** нового стека не удаляйте без необходимости.

## Проверки

```bash
docker logs amnezia-exit-cascade --tail 30
docker exec amnezia-exit-cascade awg show exit-cascade
docker exec nginx nginx -t
curl -sI "https://$(grep ^PANEL_DOMAIN= .env | cut -d= -f2-)/"
```

Диагностика каскада: [AGENTS-cascade-debug.md](../remote-deploy-cascade/AGENTS-cascade-debug.md).

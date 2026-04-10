# Каскад на домены: TLS, nginx, автоматизация (агенты)

Порядок деплоя оркестратором: **[DEPLOY_ORDER.md](DEPLOY_ORDER.md)**. Конфиг-пример: **[config.example.yaml](config.example.yaml)**.

Отладка **туннеля каскада** (handshake, nft, маршруты), если VPN не поднимается: **[AGENTS-cascade-debug.md](AGENTS-cascade-debug.md)**.

## Цели

- **Let's Encrypt** на публичном DNS-имени (HTTP-01 на порту **80**).
- **Nginx** на **S1** (панель + опционально «зеркало»/локальный upstream на `/`) и на **S2** (только HTTPS reverse proxy), **без затрагивания UDP** (WG и каскад слушают отдельные порты/процессы).
- **Сертификаты** хранятся в Docker-томах (`certbot_conf`); `docker compose down` **без** `-v` **не удаляет** их (как и раньше для entry).

## DNS и файрвол

1. **A/AAAA** для доменов entry и exit на публичные IP серверов.
2. С интернета должны быть доступны **TCP 80** (ACME, редирект на HTTPS) и **TCP 443**.
3. **Не блокировать UDP** порт VPN (`WG_PORT` на S1) и **UDP** `cascade_listen_port` на S2 (каскад). Nginx **не** слушает эти UDP.

## Переменные окружения (кратко)

| Область | Переменные |
|--------|----------------|
| TLS | `PANEL_DOMAIN`, `CERTBOT_EMAIL` (обязательны для LE на DNS-имени) |
| Панель под префиксом | `WEBUI_PUBLIC_PREFIX=/panel` — UI на `https://домен/panel/`, API на `https://домен/api/` |
| Корень сайта `/` | `NGINX_ROOT_BEHAVIOR`: `mirror` (HTTPS к `NGINX_MIRROR_HOST`), `local` (`NGINX_LOCAL_URL`), `redirect` (только редирект `/` → `/panel/`) |
| Профиль nginx | `NGINX_CONFIG_PROFILE`: `entry` (по умолчанию в основном compose), `exit` (на S2 в `exit-core/docker-compose.yml`) |

Подробности в [.env.example](../.env.example) и в `config.example.yaml`.

## Проверки после деплоя

```sh
# Снаружи (или с хоста)
curl -sI "https://PANEL_DOMAIN/"
curl -sI "http://PANEL_DOMAIN/.well-known/acme-challenge/test"  # 404 от nginx — путь существует; для LE нужен реальный challenge

# На сервере entry
docker exec nginx ls -la /etc/letsencrypt/live/PANEL_DOMAIN/ 2>/dev/null
docker logs certbot --tail 30 2>/dev/null

# На S2 (exit): те же команды для контейнеров nginx/certbot
```

Убедиться, что **редеплой** не удалял тома: `docker volume ls | grep certbot` — имена с префиксом проекта должны сохраняться.

## Ограничения «зеркала»

Nginx может терминировать TLS на вашем домене и проксировать **HTTPS** на внешний origin (`proxy_ssl_*`, `Host` к upstream). Сложные сайты (SPA, CSP, абсолютные URL, cookies) могут вести себя непредсказуемо — это нормальное ограничение reverse proxy, не баг единственного конфига.

## Оркестратор

[`install.py`](install.py): для `exit.core: true` в YAML задаётся блок **`exit.env`** (домен, email, nginx); на удалённый хост пишется `.env` и выполняется **`deploy-exit.sh`** (профиль `letsencrypt` при валидном `CERTBOT_EMAIL` и DNS-имени).

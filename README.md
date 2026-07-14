# Amnezia WG-Easy

Self-hosted панель AmneziaWG (Docker).

## Требования

- Docker и Docker Compose
- Linux с поддержкой AmneziaWG (модуль ядра / TUN) для полноценного VPN
- Bash (`./deploy.sh`; на Windows — Git Bash)

## Быстрый старт (одна команда после clone)

```bash
git clone https://github.com/ne-tort/amnezia-wg-easy.git
cd amnezia-wg-easy
./deploy.sh
```

Сабмодуль `capture_udp_sig` для панели не обязателен (нужен только чтобы пересобрать банк сигнатур). `deploy.sh` при необходимости подтянет его сам.

Что делает `./deploy.sh` из коробки:

- создаёт `.env` из `.env.example`, если его нет
- генерирует `SESSION_SECRET`, выставляет admin/`admin` при плейсхолдерах
- локально (`PANEL_DOMAIN=127.0.0.1`) поднимает HTTPS с self-signed, без certbot
- собирает и стартует compose
- при первом запуске volume получает банк из `config/signatures.seed.json` → `/opt/amnezia/awg/signatures.json`

Откройте `https://127.0.0.1` — логин `admin` / `admin` (смените пароль).

Порты по умолчанию (см. `.env`):

| Порт | Назначение |
|------|------------|
| `WG_PORT`/udp | VPN |
| `PANEL_HTTP_PORT` (80) | редирект на HTTPS, ACME |
| `PANEL_HTTPS_PORT` (443) | веб-панель |

## Настройка

Ключевые переменные в `.env`:

| Переменная | Описание |
|------------|----------|
| `WG_HOST` | Публичный IP/hostname для `Endpoint` клиентов |
| `WG_PORT` | UDP-порт VPN |
| `PANEL_DOMAIN` | FQDN панели (`127.0.0.1` — локальный self-signed TLS) |
| `CERTBOT_EMAIL` | Нужен для Let's Encrypt при реальном домене |
| `ADMIN_PASSWORD` | Пароль admin при первом запуске |

Домен и Let's Encrypt:

```bash
# в .env
PANEL_DOMAIN=panel.example.com
CERTBOT_EMAIL=you@example.com
WG_HOST=panel.example.com

./deploy.sh
```

Установка по SSH: [`remote-deploy/`](remote-deploy/README.md).

## Банк сигнатур

В volume панели:

```text
/opt/amnezia/awg/signatures.json
```

При пустом volume entrypoint копирует встроенный seed (`config/signatures.seed.json`). Свой банк — положите файл в volume или пересоберите через `capture_udp_sig` (`scripts/build_signature_bank.py`). Без валидного файла панель покажет ошибку и не подставит «заглушки».

## Команды

```bash
docker compose ps
docker compose logs -f amnezia-wg-easy
./scripts/open-ports.sh
```

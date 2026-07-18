# Amnezia WG-Easy

Self-hosted панель AmneziaWG для **Linux VPS** (Docker Engine + Compose).

## Требования

- Linux VPS (root), исходящий доступ к GitHub
- Для VPN: AmneziaWG (модуль ядра / TUN)
- Bash

Локальные/тестовые сценарии (Docker Desktop, WSL) **не часть** «продакшен»-пути — для VPS используйте `install.sh` или `./deploy.sh`.

## Установка одной командой (рекомендуется)

На чистом VPS от root:

```bash
bash <(curl -4fsSL --connect-timeout 8 --max-time 40 --retry 2 \
  https://github.com/ne-tort/amnezia-wg-easy/raw/master/install.sh \
  || curl -4fsSL --connect-timeout 8 --max-time 40 \
  https://cdn.jsdelivr.net/gh/ne-tort/amnezia-wg-easy@master/install.sh)
```

> Обязательно `-4`: на многих VPS сломан IPv6, и `curl` без `-4` минутами висит на `raw.githubusercontent.com` без единого сообщения. Fallback — jsDelivr.

Мастер спросит (Enter = default / skip):

1. Docker (поставит при необходимости)
2. Логин/пароль admin (случайные или свои)
3. SSL: Let's Encrypt для **домена**, для **IP** (shortlived ~6 дней, default), свой cert, или self-signed
4. Включить Amnezia DNS / Xray (SNI Finder подберёт SNI)

Каталог: `/opt/amnezia-wg-easy`. Дальше: `awg-easy` (меню управления).

Неинтерактивно / CI:

```bash
AWG_NONINTERACTIVE=1 AWG_SSL_MODE=ip AWG_ENABLE_DNS=1 AWG_ENABLE_XRAY=1 \
  bash <(curl -4fsSL --connect-timeout 8 --max-time 40 --retry 2 \
    https://github.com/ne-tort/amnezia-wg-easy/raw/master/install.sh \
    || curl -4fsSL --connect-timeout 8 --max-time 40 \
    https://cdn.jsdelivr.net/gh/ne-tort/amnezia-wg-easy@master/install.sh)
```

## Ручной старт (`deploy.sh`)

```bash
git clone https://github.com/ne-tort/amnezia-wg-easy.git
cd amnezia-wg-easy
./deploy.sh
```

Сабмодуль `capture_udp_sig` для панели не обязателен. `deploy.sh` при необходимости подтянет его сам.

Что делает `./deploy.sh`:

- создаёт `.env` из `.env.example`, если его нет
- генерирует `SESSION_SECRET`, выставляет `admin`/`admin` при плейсхолдерах
- определяет `WG_HOST` (публичный IP), если в `.env` плейсхолдер
- создаёт сеть `amnezia-dns-net` и образ `amnezia-dns` (для DNS из панели)
- HTTPS: `SSL_MODE=acme` (cert из install.sh) / `certbot` (FQDN+email) / иначе self-signed для IP/localhost
- собирает и стартует `docker compose`
- при первом запуске volume получает банк из `config/signatures.seed.json` → `/opt/amnezia/awg/signatures.json`

Панель: `https://<WG_HOST или PANEL_DOMAIN>`.

Порты по умолчанию (см. `.env`):

| Порт | Назначение |
|------|------------|
| `WG_PORT`/udp | VPN (install.sh: случайный свободный 20000–50000, если не задан) |
| `XRAY_PORT`/tcp | Xray VLESS Reality (default **443**, если свободен) |
| `PANEL_HTTP_PORT` (80) | редирект на HTTPS, ACME |
| `PANEL_HTTPS_PORT` (**10123**) | веб-панель |

## Amnezia DNS

DNS **не** отдельный compose-сервис. После установки:

1. на хосте есть сеть `amnezia-dns-net` и образ `amnezia-dns`;
2. контейнер панели (`amnezia-awg`) в этой сети и смонтирован `/var/run/docker.sock`;
3. включение — из UI шапки или `awg-easy` / мастер `install.sh`.

Если DNS не ставится: `docker images amnezia-dns`, `docker network ls | grep amnezia-dns-net`, логи панели.

## Amnezia Xray (VLESS Reality)

Образ `amnezia-xray` собирается в `deploy.sh`, контейнер — из шапки панели или `install.sh`/`awg-easy` (admin). Порт хоста — `XRAY_PORT` (по умолчанию 443). Публичная подписка: `GET /sub/{clientName}` и `GET /sub/{clientName}/vless`.

## Настройка

Ключевые переменные в `.env`:

| Переменная | Описание |
|------------|----------|
| `WG_HOST` | Публичный IP/hostname для `Endpoint` клиентов |
| `WG_PORT` | UDP-порт VPN |
| `XRAY_PORT` | TCP-порт Xray Reality (не пересекать с `PANEL_HTTPS_PORT`) |
| `PANEL_DOMAIN` | FQDN или IP панели (имя в пути nginx live/) |
| `SSL_MODE` | `selfsigned` / `acme` / `certbot` |
| `CERTBOT_EMAIL` | Для `SSL_MODE=certbot` или регистрации acme |
| `ADMIN_PASSWORD` | Пароль admin при первом запуске |

Домен и Let's Encrypt через certbot:

```bash
# в .env
PANEL_DOMAIN=panel.example.com
CERTBOT_EMAIL=you@example.com
WG_HOST=panel.example.com
SSL_MODE=certbot

./deploy.sh
```

Установка по SSH с ноутбука: [`remote-deploy/`](remote-deploy/README.md).

## Банк сигнатур

В volume панели:

```text
/opt/amnezia/awg/signatures.json
```

При пустом volume entrypoint копирует встроенный seed (`config/signatures.seed.json`). Свой банк — положите файл в volume или пересоберите через `capture_udp_sig` (`scripts/build_signature_bank.py`).

## Команды

```bash
awg-easy                 # меню
awg-easy status
awg-easy show
docker compose ps
docker compose logs -f amnezia-wg-easy
./scripts/open-ports.sh
```

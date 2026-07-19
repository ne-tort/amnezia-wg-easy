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
bash <(curl -4fsSL --connect-timeout 3 --retry 3 https://raw.githubusercontent.com/ne-tort/amnezia-wg-easy/master/install.sh)
```

> `-4` — на многих VPS сломан IPv6, без него `curl` может долго висеть на `raw.githubusercontent.com`.

Мастер спросит (Enter = default / skip):

1. Docker (поставит при необходимости)
2. Логин/пароль admin (случайные или свои)
3. Порты: Panel/Xray public TCP (default **оба 443** → SNI demux; голый IP панели тоже может остаться на 443 через catch-all)
4. SSL: Let's Encrypt для **домена**, для **IP** (shortlived ~6 дней, default), свой cert, или self-signed
5. Пути: UI `/panel`, подписки `/sub`; зеркало корня `/` (reverse-proxy host из sni-bank)
6. Включить Amnezia DNS / Xray

Каталог: `/opt/amnezia-wg-easy`. Дальше: `awg-easy` (меню управления).

Неинтерактивно / CI:

```bash
AWG_NONINTERACTIVE=1 AWG_SSL_MODE=domain AWG_DOMAIN=vpn.example.com AWG_EMAIL=you@example.com \
  AWG_ENABLE_DNS=1 AWG_ENABLE_XRAY=1 \
  bash <(curl -4fsSL --connect-timeout 3 --retry 3 https://raw.githubusercontent.com/ne-tort/amnezia-wg-easy/master/install.sh)
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
- создаёт сеть `amnezia-dns-net` и образы `amnezia-dns` / `amnezia-xray`
- HTTPS: `SSL_MODE=acme` (cert из install.sh) / `certbot` (FQDN+email) / иначе self-signed для IP/localhost
- собирает и стартует `docker compose`
- при первом запуске volume получает банк из `config/signatures.seed.json` → `/opt/amnezia/awg/signatures.json`

Панель: `https://<PANEL_DOMAIN>/panel/` (порт опускается при `PANEL_HTTPS_PORT=443`).

Порты и пути по умолчанию (см. `.env`):

| Параметр | Назначение |
|----------|------------|
| `WG_PORT`/udp | VPN (случайный 20000–50000, если не задан) |
| `PANEL_HTTPS_PORT` / `XRAY_PUBLIC_PORT` | Default **443** → один SNI demux (панель может делить порт и с голым IP) |
| `PANEL_HTTP_PORT` (80) | ACME + redirect на HTTPS |
| `WEBUI_PUBLIC_PREFIX` | UI+API (`/panel` default) |
| `SUB_PUBLIC_PREFIX` | Подписки (`/sub` default) |
| `NGINX_ROOT_BEHAVIOR=mirror` + `NGINX_MIRROR_HOST` | Корень `/` — reverse-proxy на чужой HTTPS (свой TLS) |

| Сценарий | Поведение |
|----------|-----------|
| FQDN + все public 443 | Demux: Xray/панель по **известным SNI**; unknown → `:9`; заглушка+`/panel/` только на SNI панели |
| Голый IP панели + 443 | Xray по SNI; **нет** SNI=IP в map; unknown/без SNI → панель (заглушка+`/panel/`) |
| Редеплой | `.env` + `/etc/amnezia-wg-easy/` (admin, порты, prefixes, mirror, ENABLE_*); desired DNS/Xray в БД volume |
| Зеркало `/` | `config/mirror-bank.seed.json` — случайный живой HTTPS; Enter; `sni` = после enable взять SNI Xray |
| Разные public ports | Direct `-p`; SNI могут совпадать |
| Internal listen | 20000–50000 (exclude-list), не host-scan |

## Amnezia DNS

DNS **не** публикует host-порты 53/853 (VPN-only): клиент → WG → dnsmasq в панели → Unbound в `amnezia-dns-net`. DoT `:853` — только исходящий upstream.

После установки:

1. на хосте есть сеть `amnezia-dns-net` и образ `amnezia-dns`;
2. контейнер панели (`amnezia-awg`) в этой сети и смонтирован `/var/run/docker.sock`;
3. включение — из UI шапки или `awg-easy` / мастер `install.sh`.

Если DNS не ставится: `docker images amnezia-dns`, `docker network ls | grep amnezia-dns-net`, логи панели.

## Amnezia Xray (VLESS Reality)

Образ `amnezia-xray` собирается в `deploy.sh`, контейнер — из шапки панели или `install.sh`/`awg-easy` (admin). **Public port** — в `vless://`; подписка `GET {SUB_PUBLIC_PREFIX}/{name}` (default `/sub/...`).

## Настройка

Ключевые переменные в `.env`:

| Переменная | Описание |
|------------|----------|
| `WG_HOST` | Публичный IP/hostname для `Endpoint` клиентов |
| `WG_PORT` | UDP-порт VPN |
| `PANEL_HTTPS_PORT` | HTTPS панели (443 → demux с сайдкарами при FQDN) |
| `XRAY_PUBLIC_PORT` | Клиентский TCP Xray |
| `XRAY_PORT` | Предпочтительный **внутренний** listen Xray |
| `WEBUI_PUBLIC_PREFIX` | Путь UI (`/panel`) |
| `SUB_PUBLIC_PREFIX` | Путь подписок (`/sub`) |
| `NGINX_MIRROR_HOST` | Host для reverse-proxy корня |
| `PANEL_DOMAIN` | FQDN или IP панели |
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

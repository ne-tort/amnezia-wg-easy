# Amnezia WG-Easy

Форк [amnezia-wg-easy](https://github.com/amnezia-vpn/amnezia-wg-easy): веб-панель для self-hosted AmneziaWG.
Проект собран как Docker-стек и рассчитан на небольшие корпоративные развёртывания.

## Что внутри
- Панель (API + веб-интерфейс), хранит настройки и клиентов в SQLite
- Роли: `admin` / `moderator` / `user`
- Firewall-слой для профилей и глобальных правил (`nftables` или `firewalld`)
- Генерация/пересборка обфускационных параметров (I1–I5)
- Amnezia DNS: при настройке `WG_DEFAULT_DNS` в клиентских конфигурациях поднимается `dnsmasq`, который форвардит запросы во внутренний DNS-сервис

## Запуск по умолчанию (локально, HTTPS на 127.0.0.1)
1. `./deploy.sh`
2. Откройте в браузере: `https://127.0.0.1`
3. Логин: `admin`
4. Пароль: `admin`

Для доступа снаружи откройте на хосте:
- `80/tcp` и `443/tcp` (HTTPS)
- `WG_PORT/udp` (WireGuard)

## HTTPS
HTTP-трафик на панель перенаправляется в HTTPS внутри контейнера `nginx`.
- **Локально** (`PANEL_DOMAIN=127.0.0.1` или `localhost`): nginx создаёт self-signed сертификат; контейнер `certbot` не поднимается.
- **Домен и Let's Encrypt**: задайте в `.env` `PANEL_DOMAIN` (ваш FQDN) и `CERTBOT_EMAIL` (реальный почтовый ящик для ACME), затем `./deploy.sh`. Поднимается `certbot`: первый выпуск сертификата и дальнейшее обновление. Домен должен указывать на этот сервер, порт `80/tcp` доступен снаружи для проверки.

Без `deploy.sh` для доменного режима: `docker compose --profile letsencrypt up -d --build`.

## Удалённая установка по SSH

См. каталог [`remote-deploy/`](remote-deploy/README.md): YAML-конфиг и `python install.py` выкладывают проект на сервер и запускают `./deploy.sh`.

## Запуск с доменом и Let's Encrypt
1. В `.env`: `PANEL_DOMAIN=panel.example.com`, `CERTBOT_EMAIL=you@yourdomain.tld`.
2. `./deploy.sh`.
3. Панель: `https://<PANEL_DOMAIN>` после успешного выпуска сертификата.

## Проверка запуска
- Выполните: `docker compose ps`
- Откройте: `https://127.0.0.1` и войдите `admin/admin`
- DNS-цепочка (Amnezia DNS): `./scripts/test-amnezia-dns.sh`

## Настройка DNS для клиентов
По умолчанию Amnezia DNS включается, когда `WG_DEFAULT_DNS` в конфиге клиента совпадает с VPN-gateway адресом (по умолчанию это `10.8.0.1`).
Если вы хотите, чтобы клиенты использовали внешний DNS напрямую, задайте `WG_DEFAULT_DNS` на публичные значения (например `8.8.8.8`).

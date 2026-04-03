# Amnezia WG-Easy

Форк [amnezia-wg-easy](https://github.com/amnezia-vpn/amnezia-wg-easy): веб-панель для self-hosted AmneziaWG.
Проект собран как Docker-стек и рассчитан на небольшие корпоративные развёртывания.

## Что внутри
- Панель (API + веб-интерфейс), хранит настройки и клиентов в SQLite
- Роли: `admin` / `moderator` / `user`
- Firewall-слой для профилей и глобальных правил (`nftables` или `firewalld`)
- Генерация/пересборка обфускационных параметров (I1–I5)
- Amnezia DNS: при настройке `WG_DEFAULT_DNS` в клиентских конфигурациях поднимается `dnsmasq`, который форвардит запросы во внутренний DNS-сервис

## Порты (три уровня)

| Переменная | Назначение |
|------------|------------|
| `PANEL_HTTPS_PORT`, `PANEL_HTTP_PORT` | TCP на **хосте**, которые Docker пробрасывает в nginx (внутри контейнера по-прежнему 443/80). URL панели: `https://<хост>:<PANEL_HTTPS_PORT>` если не 443. |
| `PORT` | TCP **внутри** Docker-сети: порт Node-приложения; nginx проксирует на него (`proxy_pass`). На хост напрямую не публикуется. |
| `WG_PORT` | UDP на хосте = `ListenPort` AmneziaWG и `Endpoint` в клиентских конфигах (вместе с `WG_HOST`). |

После смены портов перезапустите стек (`./deploy.sh`); для VPN перекачайте клиентские конфиги. Скрипт `./scripts/open-ports.sh` открывает в файрволе `WG_PORT`, `PANEL_HTTP_PORT`, `PANEL_HTTPS_PORT`.

## Запуск по умолчанию (локально, HTTPS на 127.0.0.1)
1. `./deploy.sh`
2. Откройте в браузере: `https://127.0.0.1`
3. Логин: `admin`
4. Пароль: `admin`

Для доступа снаружи откройте на хосте (значения по умолчанию; см. `PANEL_HTTP_PORT`, `PANEL_HTTPS_PORT` в `.env`):
- TCP `PANEL_HTTP_PORT` (редирект и ACME) и `PANEL_HTTPS_PORT` (HTTPS панели)
- `WG_PORT/udp` (AmneziaWG)

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

## Обфускация AmneziaWG (H, S4, I1–I5)

- **H1–H4:** в конфиге можно задать число или диапазон. Если используете **диапазоны** на клиенте вручную, они не должны **пересекаться** между типами пакетов (см. [статью Amnezia про AWG 2.0](https://habr.com/ru/companies/amnezia/articles/1014636/)). Панель при сохранении серверного конфига часто схлопывает диапазон в одно значение на заголовок.
- **S4:** дополнительные байты к каждому data-пакету; больше значение — тяжелее для DPI, ниже скорость. Настраивается через `S4` в окружении.
- **I1–I5:** цепочка CPS подставляется из `signatures.json` (пересборка через Python `run_all`). Размер `<r N>` для I4/I5 по умолчанию задаётся `OBFS_R_BYTES` (и тем же именем в Python при генерации).

## Настройка DNS для клиентов
По умолчанию Amnezia DNS включается, когда `WG_DEFAULT_DNS` в конфиге клиента совпадает с VPN-gateway адресом (по умолчанию это `10.8.0.1`).
Если вы хотите, чтобы клиенты использовали внешний DNS напрямую, задайте `WG_DEFAULT_DNS` на публичные значения (например `8.8.8.8`).

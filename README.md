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
- **I1–I5:** полная пятёрка CPS в `signatures.json` собирается `run_all`: **I1** и при наличии **I2–I5** из реального захвата, любые пропуски заполняются **только** из зафиксированного бандла [`architect_fallbacks.py`](python_signatures/architect_fallbacks.py) (`ARCHITECT_DEFAULTS` по `profile_id`, версия `ARCHITECT_BUNDLE_VERSION`). Переменная `OBFS_R_BYTES` относится к другим слоям обфускации на сервере, не к автоподстановке I4/I5 в merge.

**Сигнатуры и capture:** список `profile_id` и реестр коллекторов — единственный источник в [`python_signatures/run_all.py`](python_signatures/run_all.py) (`known_profile_ids()` в [`library_api.py`](python_signatures/library_api.py)); панель читает тот же список через Python при старте. Шаблоны `dns` / `sip` / `dtls` — из [`python_signatures/config/profile_templates/`](python_signatures/config/profile_templates/); `quic` и `quic_browser` — [`browser_quic_collector.py`](python_signatures/browser_quic_collector.py); `stun`, `webrtc`, `stun_browser` — [`browser_stun_collector.py`](python_signatures/browser_stun_collector.py). См. [`capture_policy.yaml`](python_signatures/capture_policy.yaml) и [`BROWSER_PROFILES.md`](python_signatures/BROWSER_PROFILES.md). `run_all --dry-run` использует шаблоны и фикстуры `tests/fixtures/signatures/<profile_id>.json` для CI. Бандл [`python_signatures/config/signatures.default.json`](python_signatures/config/signatures.default.json) — стартовый шаблон; в продакшене выполняйте `run_all` **без** `--dry-run` (нужны pcap и при браузерных профилях — `browser_capture` + Chromium). Цепочки **I1–I5** для клиента берутся только из `signatures.json`, не из переменных окружения. Тег `<c>` в CPS не используется.

### Библиотечный API для веб-панели

Python-слой теперь можно вызывать как библиотеку (без парсинга CLI-stdout):

```python
from pathlib import Path
from python_signatures.library_api import get_profile, regenerate_signatures

signatures_path = Path("/opt/amnezia/awg/signatures.json")
config_dir = Path("python_signatures/config")

# 1) Асинхронная в панели операция регенерации (обычно по кнопке / cron)
regenerate_signatures(
    out_path=signatures_path,
    config_dir=config_dir,
    timeout=45,
    dry_run=False,  # только real capture
)

# 2) Быстрый запрос конкретного профиля для выдачи конфига клиенту
payload = get_profile("quic", signatures_path=signatures_path)
# payload: {profile_id, i1..i5, source_meta}
```

Node helper [`src/lib/signatures.js`](src/lib/signatures.js) использует тот же контракт:
`getProfilePayload(profileId)` возвращает `{ profile_id, i1, i2, i3, i4, i5, source_meta }`.

**S1–S4 (Jc) и H1–H4 — глобально на сервере:** они общие для всех клиентов одного инстанса и не привязаны к выбранному профилю маскировки (`dns`, `quic`, `stun`, …). Смена профиля меняет только цепочку **I1–I5** (видимость UDP). Сервер и клиент должны совпадать по Jc/S/H; разные пресеты S/H под разные «протоколы» в смысле одной панели не поддерживаются — для этого нужны отдельные серверы/контейнеры или расширение модели хранения.

## Настройка DNS для клиентов
По умолчанию Amnezia DNS включается, когда `WG_DEFAULT_DNS` в конфиге клиента совпадает с VPN-gateway адресом (по умолчанию это `10.8.0.1`).
Если вы хотите, чтобы клиенты использовали внешний DNS напрямую, задайте `WG_DEFAULT_DNS` на публичные значения (например `8.8.8.8`).

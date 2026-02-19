# Amnezia WG-Easy — форк с DPI-обходом

Форк [amnezia-wg-easy](https://github.com/amnezia-vpn/amnezia-wg-easy): веб-админка для self-hosted AmneziaWG (WireGuard с обфускацией под DPI). Для обхода блокировок и простого деплоя одной панелью.

**Чем лучше:** полная поддержка DPI (S3, S4, I1; конфиги под AmneziaWG); выбор протокола маскировки — QUIC, DNS, SIP, STUN, WebRTC, DTLS; уровни обфускации I0–I5 (I0 без подписи, I1–I5 по рекомендациям); QR только для профилей с короткой подписью (удобно сканировать), полный конфиг — «Скачать»; деплой через `./deploy.sh` (подстановка IP и учётных данных админа); один JSON-конфиг, Docker Compose, volume по умолчанию `/opt/amnezia/awg`. Вход в панель — только по логину и паролю (пользователи в БД).

## Быстрый старт

```bash
git clone https://github.com/ne-tort/amnezia-wg-easy.git
cd amnezia-wg-easy
./deploy.sh
```

Скрипт создаёт рабочую копию `.env` из шаблона `.env.example` при отсутствии, подставляет внешний IP и при необходимости генерирует пароль первого админа (`ADMIN_PASSWORD`), поднимает контейнер. В конце выводятся URL Web UI, логин и пароль админа. При первом запуске в БД создаётся пользователь из `ADMIN_USERNAME` и `ADMIN_PASSWORD`; при повторных запусках инициализация пропускается, если пользователи уже есть.

**Ручная настройка:** правьте `.env` (например `WG_HOST`, `ADMIN_USERNAME`, `ADMIN_PASSWORD`), затем `docker compose up -d`.

**Env:** шаблон — `.env.example`. Рабочий файл — `.env` (генерируется deploy.sh, в .gitignore). Чтобы начать с нуля: удалите `.env` и снова выполните `./deploy.sh`.

## Требования

На хосте: **Docker** и **Docker Compose**, Linux с поддержкой WireGuard в ядре. Для `./deploy.sh` — bash, curl, openssl (обычно уже установлены). **Node.js и Python на хосте не нужны** — сборка выполняется внутри Docker-образов.

**Зависимости Node:** в репозитории должен быть актуальный `src/package-lock.json` (в нём зафиксированы версии; в образе вызывается `npm ci`). После изменения `src/package.json` обновите lock-файл и закоммитьте его, иначе сборка упадёт. Одной командой:  
`docker run --rm -v "$(pwd)/src:/app" -w /app node:20-alpine npm install` — затем закоммитьте `src/package-lock.json`.

## Обновление с предыдущей версии (миграция volume)

По умолчанию данные конфига и ключей хранятся в volume, смонтированном в `/opt/amnezia/awg` (в соответствии с паттерном оригинального клиента Amnezia). Если вы обновляетесь с версии, где использовался путь `/etc/amnezia/amneziawg`, возможны два варианта:

- **Скопировать данные:** один раз скопировать содержимое старого volume в новый (смонтированный в `/opt/amnezia/awg`), затем использовать новый compose.
- **Оставить старый путь:** задать в `.env` переменную `WG_PATH=/etc/amnezia/amneziawg` и в `docker-compose.yml` смонтировать тот же volume по старому пути (`amnezia-wg-data:/etc/amnezia/amneziawg`).

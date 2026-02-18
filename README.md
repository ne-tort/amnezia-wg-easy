# Amnezia WG-Easy — форк с DPI-обходом

Форк [amnezia-wg-easy](https://github.com/amnezia-vpn/amnezia-wg-easy): веб-админка для self-hosted AmneziaWG (WireGuard с обфускацией под DPI). Для обхода блокировок и простого деплоя одной панелью.

**Чем лучше:** полная поддержка DPI (S3, S4, I1; конфиги под AmneziaWG); выбор протокола маскировки — QUIC, DNS, SIP, STUN, WebRTC, DTLS; уровни обфускации I0–I5 (I0 без подписи, I1–I5 по рекомендациям); QR только для профилей с короткой подписью (удобно сканировать), полный конфиг — «Скачать»; деплой через `./deploy.sh` (подстановка IP и пароля); один JSON-конфиг, Docker Compose, volume по умолчанию `/opt/amnezia/awg`.

## Быстрый старт

```bash
git clone https://github.com/netort/amnezia-wg-easy.git
cd amnezia-wg-easy
./deploy.sh
```

Скрипт создаёт рабочую копию `.env` из шаблона `.env.example` при отсутствии, подставляет внешний IP и пароль, поднимает контейнер. Web UI и пароль выводятся в конце.

**Ручная настройка:** правьте `.env` (например `WG_HOST`, `PASSWORD`), затем `docker compose up -d`.

**Env:** шаблон — `.env.example` (оригинал с плейсхолдерами, в репозитории). Рабочий файл — `.env` (генерируется deploy.sh, в .gitignore). Чтобы сбросить и заново подставить IP/пароль: удалите `.env` и снова выполните `./deploy.sh`.

## Требования

Docker и Docker Compose, Linux с поддержкой WireGuard в ядре.

## Обновление с предыдущей версии (миграция volume)

По умолчанию данные конфига и ключей хранятся в volume, смонтированном в `/opt/amnezia/awg` (в соответствии с паттерном оригинального клиента Amnezia). Если вы обновляетесь с версии, где использовался путь `/etc/amnezia/amneziawg`, возможны два варианта:

- **Скопировать данные:** один раз скопировать содержимое старого volume в новый (смонтированный в `/opt/amnezia/awg`), затем использовать новый compose.
- **Оставить старый путь:** задать в `.env` переменную `WG_PATH=/etc/amnezia/amneziawg` и в `docker-compose.yml` смонтировать тот же volume по старому пути (`amnezia-wg-data:/etc/amnezia/amneziawg`).

Подробнее об отличиях от оригинала — в [docs/](docs/). Особенности проекта и отставание от wg-easy — [docs/PROJECT-FEATURES-AND-WG-EASY-GAP.md](docs/PROJECT-FEATURES-AND-WG-EASY-GAP.md).

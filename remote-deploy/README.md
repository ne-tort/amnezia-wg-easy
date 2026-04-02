# Удалённая установка по SSH

Один YAML-конфиг задаёт доступ по SSH и переменные для `.env` на сервере; скрипт выкладывает репозиторий и запускает `./deploy.sh`.

## Предусловия

- **Оператор:** Python 3.10+, `pip install -r requirements.txt`.
- **Сервер:** Docker Engine и **Docker Compose v2** (`docker compose version`), `git` (для режима `source.mode: git`).

На сервере должны быть открыты нужные порты (например `22/tcp` для SSH, затем `80`/`443` и `WG_PORT/udp` для панели и VPN). Для Let’s Encrypt домен `PANEL_DOMAIN` должен указывать на сервер, порт `80/tcp` доступен из интернета.

## Быстрый старт

```bash
cd remote-deploy
pip install -r requirements.txt
cp config.example.yaml config.yaml
# Отредактируйте config.yaml (хост, ключ или пароль, env)
python install.py --config config.yaml
```

Проверка без SSH (`--dry-run`): вывод сгенерированного `.env` с замазанными секретами и список шагов.

```bash
python install.py --config config.yaml --dry-run
```

## Повторный запуск (обновление)

Перед `./deploy.sh` скрипт выполняет в каталоге проекта на сервере:

`docker compose --profile letsencrypt down --remove-orphans`

Так останавливаются только контейнеры этого compose-проекта (включая сервис с профилем `letsencrypt`, если он был поднят). Флаг **`-v` не используется** — именованные тома Docker (`amnezia-wg-data` с SQLite и данными панели, тома certbot) **не удаляются**. Затем `deploy.sh` пересобирает образы и поднимает стек заново с актуальным кодом из git/tar и новым `.env` (веб-панель в образе пересобирается из текущего репозитория).

Проверка без SSH: `python install.py --config config.yaml --dry-run` — в выводе видно шаги `git pull`, `compose down` и `./deploy.sh`, то есть существующая установка будет перезаписана кодом из `git_url` / локального архива, данные в томах сохранятся.

## Конфигурация

- **`ssh`:** `host`, `user`, опционально `port` (по умолчанию 22). Аутентификация: **`identity_file`** (предпочтительно) или **`password`**, либо **`ssh_password_env`** — имя переменной окружения на машине оператора, откуда взять пароль.
- **`source.mode`:** `git` — `git clone` / `git pull` в `remote.path`; `local` — архив текущего дерева репозитория без каталога `remote-deploy` (чтобы не утащить `config.yaml`).
- **`remote.path`:** каталог на сервере с репозиторием (например `/opt/amnezia-wg-easy`).
- **`env`:** пары `KEY: value` как в корневом `.env` (имена **в верхнем регистре**, как в [.env.example](../.env.example)). Переопределяют значения по умолчанию из `.env.example`.

Подстановка из окружения оператора: в YAML можно использовать строки вида `${ENV:VARNAME}` (например для пароля SSH).

## Безопасность

- Не коммитьте `config.yaml` с паролями (см. `.gitignore`).
- Предпочитайте вход по SSH-ключу вместо пароля.

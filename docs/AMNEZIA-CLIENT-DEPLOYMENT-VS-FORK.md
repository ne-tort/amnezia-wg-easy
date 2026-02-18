# Паттерн развёртывания: клиент Amnezia vs форк

Документ фиксирует результат изучения скриптов развёртывания **оригинального клиента Amnezia** (amnezia-vpn/amnezia-client, ветка dev) и сравнение с **нашим форком** при развёртывании VPN-сервера и Amnezia DNS.

Источники клиента:
- Репозиторий: [amnezia-vpn/amnezia-client](https://github.com/amnezia-vpn/amnezia-client) (каталог `client/server_scripts/`)
- Ключевые скрипты: `prepare_host.sh`, `awg/run_container.sh`, `awg/configure_container.sh`, `awg/start.sh`, `dns/run_container.sh`, `dns/Dockerfile`

---

## 1. Как разворачивает клиент Amnezia (SSH, self-hosted)

### 1.1. Подготовка хоста (prepare_host.sh)

- Создаётся Docker-сеть **amnezia-dns-net**:
  - `--driver bridge`
  - `--subnet=172.29.172.0/24`
  - `--opt com.docker.network.bridge.name=amn0`
- Дополнительно: `mkdir -p $DOCKERFILE_FOLDER`, `chown $CUR_USER` (каталог для копирования Dockerfile/контекста).

### 1.2. AWG (AmneziaWG) — run_container.sh

- Запуск контейнера:
  - `--log-driver none`
  - `--restart always`
  - `--privileged`, `--cap-add=NET_ADMIN`, `--cap-add=SYS_MODULE`
  - `-p $AWG_SERVER_PORT:$AWG_SERVER_PORT/udp`
  - `-v /lib/modules:/lib/modules`
  - `--sysctl="net.ipv4.conf.all.src_valid_mark=1"`
  - **без** монтирования volume под конфиг: конфиг и ключи создаются внутри контейнера скриптом configure_container.sh.
- После запуска: **`docker network connect amnezia-dns-net $CONTAINER_NAME`** — контейнер получает второй интерфейс (eth1) в сети DNS.

### 1.3. AWG — configure_container.sh

- Все файлы в **/opt/amnezia/awg/**:
  - `wireguard_server_private_key.key`, `wireguard_server_public_key.key`, `wireguard_psk.key`
  - Конфиг интерфейса: **awg0.conf** (имя интерфейса в клиенте — **awg0**).

### 1.4. AWG — start.sh (внутри контейнера при старте)

- `awg-quick down /opt/amnezia/awg/awg0.conf`
- `awg-quick up /opt/amnezia/awg/awg0.conf`
- iptables:
  - INPUT/FORWARD/OUTPUT для интерфейса **awg0**
  - FORWARD и NAT (MASQUERADE) для **eth0** и **eth1** (eth1 — интерфейс в amnezia-dns-net, доступ к DNS 172.29.172.254).

### 1.5. DNS — run_container.sh

- Контейнер запускается сразу в сети **amnezia-dns-net** с **--ip=172.29.172.254**.
- `--log-driver none`, `--restart always`.

### 1.6. DNS — Dockerfile

- `FROM mvance/unbound:latest`
- Конфиг: domain-insecure и stub-зоны (coin., emc., lib., bazar., enum.), forward-zone с DoT (1.1.1.1@853, 1.0.0.1@853). Совпадает с нашим образом в `amnezia-dns/Dockerfile`.

**Итог паттерна клиента:** путь **/opt/amnezia/awg/**, интерфейс **awg0**, конфиг **awg0.conf**, сеть **amnezia-dns-net**, мост **amn0**, DNS на **172.29.172.254**, контейнер AWG подключается к amnezia-dns-net (eth1), iptables с правилами для eth0 и eth1.

---

## 2. Сравнение с форком (после приведения к паттерну)

| Аспект | Клиент Amnezia | Форк | Статус |
|--------|----------------|------|--------|
| Путь конфига/ключей | /opt/amnezia/awg/ | /opt/amnezia/awg/ (WG_PATH) | Совпадает |
| Имя сети | amnezia-dns-net | amnezia-dns-net | Совпадает |
| Имя моста | amn0 (driver_opts) | amn0 (driver_opts) | Совпадает |
| Подсеть DNS | 172.29.172.0/24 | 172.29.172.0/24 | Совпадает |
| IP DNS-контейнера | 172.29.172.254 | 172.29.172.254 | Совпадает |
| Подключение WG к DNS-сети | connect amnezia-dns-net | networks: amnezia-dns-net в compose | Эквивалентно |
| Образ базовый | amneziavpn/amneziawg-go | amneziavpn/amneziawg-go | Совпадает |
| /lib/modules | -v /lib/modules | -v /lib/modules:ro | Совпадает |
| privileged, NET_ADMIN, SYS_MODULE | да | да | Совпадает |
| sysctl src_valid_mark | да | да (sysctls в compose) | Совпадает |
| Имя интерфейса | awg0 | wg0 | Отличие (см. ниже) |
| Имя конфига | awg0.conf | wg0.conf | Отличие (см. ниже) |
| Хранение конфига | Внутри контейнера (configure_container) | Volume amnezia-wg-data → /opt/amnezia/awg | Разная модель (см. ниже) |
| iptables для eth1 | FORWARD и NAT для eth1 (доступ к DNS) | Только eth0 (WG_DEVICE) | Возможное улучшение (см. ниже) |
| Логи контейнера | --log-driver none | по умолчанию (json-file) | Мелкое отличие |
| restart | always | unless-stopped | Мелкое отличие |
| Управление интерфейсом | start.sh при старте контейнера | Node.js (WireGuard.js) по запросу/при старте | Разная архитектура |

---

## 3. Отличия и решения

### 3.1. Интерфейс wg0 vs awg0

В клиенте используется **awg0** и **awg0.conf**; в форке — **wg0** и **wg0.conf**. Образ amneziawg-go предоставляет и `wg`, и `awg` (wg-quick → awg-quick); оба работают с одним и тем же демоном. Имя интерфейса задаётся именем конфига (awg0.conf → awg0, wg0.conf → wg0). Для приведения форка к клиенту пришлось бы переименовать интерфейс и конфиг по всему коду (WireGuard.js, config.js, entrypoint, HEALTHCHECK) и в клиентских конфигах; это крупное изменение. По соглашению форка оставлено **wg0** как допустимое отклонение: поведение и протокол те же.

### 3.2. Хранение конфига: volume vs «внутри контейнера»

В клиенте конфиг и ключи создаются скриптом **configure_container.sh** внутри контейнера (файловая система контейнера). В форке конфиг и ключи хранятся в **volume** (amnezia-wg-data → /opt/amnezia/awg), чтобы: (1) данные переживали пересоздание контейнера, (2) веб-UI мог читать/писать wg0.json и wg0.conf. Это осознанное архитектурное отличие: форк — панель с персистентным хранилищем и UI.

### 3.3. iptables для eth1 (доступ к DNS-сети)

В клиенте **start.sh** явно добавляет FORWARD и NAT для **eth1** (интерфейс в amnezia-dns-net), чтобы трафик с VPN-клиентов мог уходить на DNS (172.29.172.254). В форке при **WG_DEFAULT_DNS=10.8.0.1** dnsmasq работает **в том же контейнере** и сам шлёт запросы на 172.29.172.254 (исходящий трафик контейнера по eth1); типичный сценарий при этом уже работает. Если нужно явно разрешить форвард с wg0 на eth1 (например, для доступа клиентов к другим сервисам в amnezia-dns-net), можно добавить в дефолтные WG_POST_UP/WG_POST_DOWN правила для eth1 по аналогии с клиентом (и задать WG_DEVICE_2=eth1 или второй интерфейс по имени). Сейчас не реализовано; при необходимости можно ввести опциональную переменную (например WG_FORWARD_ETH1=true) и добавлять правила для eth1.

### 3.4. Логи и restart

- **--log-driver none**: в клиенте отключены логи контейнера. В форке можно добавить в docker-compose для сервиса amnezia-wg-easy (и при желании amnezia-dns): `logging: driver: none`.
- **restart: unless-stopped** в форке даёт возможность остановить контейнер вручную без автоперезапуска; **always** в клиенте — жёсткий автоперезапуск. Оставлено как есть; при желании можно сменить на `always` для максимального совпадения с клиентом.

---

## 4. Итог

- **Найден и изучен** код развёртывания клиента Amnezia в `amnezia-vpn/amnezia-client` (client/server_scripts, ветка dev).
- **Приведены к паттерну клиента:** путь /opt/amnezia/awg/, сеть amnezia-dns-net, мост amn0, IP DNS 172.29.172.254, подключение контейнера WG к amnezia-dns-net, образ и права (privileged, caps, /lib/modules, sysctl).
- **Сознательно отличаются:** имя интерфейса/конфига (wg0 vs awg0), модель хранения (volume + UI vs конфиг внутри контейнера), управление интерфейсом (Node.js vs start.sh).
- **Опциональные улучшения:** явные iptables для eth1 при необходимости доступа VPN-клиентов к amnezia-dns-net; `logging: driver: none` и `restart: always` для полного совпадения с клиентом.

После внесённых ранее правок развёртывание сервера VPN и Amnezia DNS в форке по путям, сети и композиции соответствует паттерну оригинального клиента Amnezia; оставшиеся отличия связаны с архитектурой форка (веб-панель, персистентный volume, wg0) и при необходимости могут быть доработаны по пунктам выше.

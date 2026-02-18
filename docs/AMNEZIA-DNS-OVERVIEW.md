# Amnezia DNS — что это, как работает, нужно ли платить

## Что такое Amnezia DNS

**Amnezia DNS** — это опциональный сервис в экосистеме AmneziaVPN. Это **собственный DNS-резолвер**, который ставится на **ваш** self-hosted VPN-сервер и используется клиентами при подключении через VPN.

Задачи:
1. **Обход блокировок** — провайдер или цензура могут резать/подменять DNS; свой DNS на сервере обходит это.
2. **Приватность** — сторонние DNS (Google, Cloudflare, оператор) могут логировать запросы; Amnezia DNS на вашем сервере не отдаёт эти данные третьим лицам.
3. **Скрытие по DNS** — по DNS-резолверу можно определять регион/пользователя; свой резолвер усложняет такую привязку.

---

## Как это работает

- В приложении **AmneziaVPN** (клиент): Серверы → ваш сервер → вкладка **«Сервисы»** → **Amnezia DNS** → **«Установить»**.
- Приложение по SSH подключается к серверу и поднимает **Docker-контейнер** с DNS-сервисом.
- Установленный Amnezia DNS получает **внутренний IP в Docker-сети** (в т.ч. упоминается 172.29.172.254).
- В настройках подключения в приложении можно выбрать **«Использовать Amnezia DNS»** — тогда DNS-запросы клиента идут через VPN на этот контейнер на вашем сервере.

То есть: клиент → VPN-туннель → ваш сервер → контейнер Amnezia DNS → рекурсивное разрешение имён (к корневым серверам и т.д.). Трафик DNS идёт по тому же VPN, логи и контроль остаются у вас на сервере.

---

## Что умеет

- Рекурсивное разрешение DNS (не обязательно форвард на 8.8.8.8 и т.п.).
- Работа в связке с любым протоколом Amnezia на том же сервере (AmneziaWG, OpenVPN, XRay и т.д.).
- Установка и управление через приложение AmneziaVPN (без ручной возни с конфигами, если не хочется).

Точная реализация (unbound, dnsmasq или свой демон) в открытой документации детально не расписана; по отзывам и issue это контейнер с локальным IP, интегрированный в сеть Amnezia на сервере.

---

## Нужно ли платить

**Нет.** Amnezia DNS на **self-hosted** сервере — часть **бесплатного** сценария AmneziaVPN.

- Платите только за **VPS/сервер** (аренда хоста).
- Само приложение AmneziaVPN и установка сервисов (в т.ч. Amnezia DNS) на свой сервер — **бесплатно**, open-source.
- Платные продукты Amnezia — это **Amnezia Premium** (подписка на их сервера) и **Amnezia Free** (ограниченный бесплатный доступ к их инфраструктуре). К вашему серверу и вашему Amnezia DNS это не относится.

Итого: за «смену/использование Amnezia DNS» на своём сервере **платить не нужно** — только за хостинг сервера.

---

## Установка напрямую (без клиента AmneziaVPN)

В репозитории amnezia-vpn/amnezia-client сервис DNS реализован так: образ на базе **Unbound** (mvance/unbound), конфиг с форвардом в Cloudflare DoT (1.1.1.1@853), контейнер в Docker-сети `amnezia-dns-net` с IP **172.29.172.254**.

**Эталонные конфиги (источник):**
- **Unbound** (`amnezia-dns/Dockerfile`): содержимое `forward-records.conf` скопировано из [amnezia-vpn/amnezia-client](https://github.com/amnezia-vpn/amnezia-client) → `client/server_scripts/dns/Dockerfile` (domain-insecure для coin/emc/lib/bazar/enum, stub-зоны emercoin, forward-zone на 1.1.1.1@853 и 1.0.0.1@853). Менять только при синхронизации с клиентом.
- **dnsmasq** (`config/dnsmasq-amnezia.conf`): конфиг форварда в контейнере wg-easy: все запросы на 172.29.172.254 (Amnezia DNS). Опции: `listen-address=0.0.0.0`, `no-resolv`, `no-hosts`, `no-poll`, `server=172.29.172.254`. В клиенте Amnezia dnsmasq не используется (трафик к DNS идёт через iptables с VPN-контейнера).

Чтобы поставить то же самое вручную на сервере (без приложения Amnezia):

1. **Скрипт в нашем проекте** (рекомендуется):
   ```bash
   cd /path/to/amnezia-wg-fresh
   ./scripts/install-amnezia-dns.sh
   ```
   Скрипт создаёт сеть `amnezia-dns-net`, собирает образ из `amnezia-dns/Dockerfile` и запускает контейнер `amnezia-dns` с IP 172.29.172.254.

2. **Вручную** (если не используешь наш репо):
   - Клонировать [amnezia-client](https://github.com/amnezia-vpn/amnezia-client), в каталоге `client/server_scripts` выполнить:
     - `prepare_host.sh` (создаёт сеть amnezia-dns-net),
     - собрать образ: `build_container.sh` с `DOCKERFILE_FOLDER=dns` и нужным `CONTAINER_NAME`,
     - запустить: из `dns/` вызвать `run_container.sh` с тем же `CONTAINER_NAME`.

После установки контейнер слушает порт 53 внутри сети; с хоста или из других сетей до 172.29.172.254 можно достучаться только из контейнеров, подключённых к `amnezia-dns-net`.

---

## Связь с нашим проектом (amnezia-wg-fresh)

**Amnezia DNS встроен в docker-compose.** При `docker compose up` поднимаются оба сервиса: **amnezia-wg-easy** и **amnezia-dns** (Unbound в сети `amnezia-dns-net`, IP 172.29.172.254). В контейнере wg-easy при `WG_DEFAULT_DNS=10.8.0.1` запускается dnsmasq и форвардит все DNS-запросы на контейнер amnezia-dns.

**Как использовать встроенный Amnezia DNS:**

1. В `.env` задать **WG_DEFAULT_DNS=10.8.0.1**.
2. Перезапустить стек: `docker compose up -d`.
3. В веб-панели заново **скачать конфиги** клиентам — в них будет `DNS = 10.8.0.1`. Подключённые клиенты будут резолвить имена через Amnezia DNS (Unbound → DoT).

Если в `.env` указан другой DNS (например 8.8.8.8) или переменная не задана, dnsmasq в контейнере не запускается, клиенты получают выбранный внешний DNS — поведение как раньше.

**Отдельный скрипт** `scripts/install-amnezia-dns.sh` оставлен для сценария «только Amnezia DNS без полного compose» (например, на другом хосте). Для единого стека предпочтительно использовать `docker compose up` из этого репозитория.

**Проверка работы:** при `WG_DEFAULT_DNS=10.8.0.1` и запущенном стеке выполните `./scripts/test-amnezia-dns.sh` (опционально с доменом: `./scripts/test-amnezia-dns.sh ya.ru`). Скрипт проверяет, что dnsmasq запущен, резолв через 127.0.0.1 и 10.8.0.1 работает, и контейнер amnezia-dns доступен.

---

## Полезные ссылки

- [Changing DNS Server | Amnezia Docs](https://docs.amnezia.org/documentation/instructions/change-dns/)
- [How Amnezia works](https://docs.amnezia.org/documentation/how-amnezia-works)
- [Self-hosted VPN | Amnezia](https://amnezia.org/en/self-hosted)
- [FAQ — Why should I change my DNS?](https://docs.amnezia.org/faq) (раздел Self-hosted)

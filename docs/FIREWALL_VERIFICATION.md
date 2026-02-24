# Проверка правил и команд фаерволла

## 1. Где применяются правила (INPUT vs FORWARD)

- **Правила панели** (deny 0.0.0.0/0, allow 10.8.0.1/32:53 и т.д.) применяются **только к пересылаемому трафику** (FORWARD), не к трафику на сам хост (INPUT).
- Трафик **на хост** (в т.ч. DNS на 10.8.0.1:53) идёт через цепочку **INPUT** и этими правилами **не затрагивается**.

### nftables (backend по умолчанию)

- Таблица панели: `inet amnezia_wg`.
- Цепочка: `forward_awg0` с `type filter hook forward priority -100`.
- В эту цепочку попадает только трафик с `iifname "awg0"` (входящий с интерфейса WireGuard), и только тот, что **форвардится** дальше. Трафик с destination на сам хост (10.8.0.1 и т.д.) в FORWARD не попадает.

### Базовая таблица (WG_POST_UP в config.js)

- Таблица: `inet amnezia_wg_base`.
- **INPUT** (`input_awg0`, priority -100): одно правило — разрешить `udp dport WG_PORT` (рукопожатие WireGuard); policy `accept` — остальной входящий трафик на хост по умолчанию разрешён (в т.ч. 10.8.0.1:53).
- **FORWARD** (`forward_awg0_base`, priority 0): разрешить весь forward с/на `awg0` и в eth1. Обрабатывается **после** цепочки панели (priority -100), так что дропы панели уже сработали.

---

## 2. Порядок правил (первое совпадение выигрывает)

- Для каждого клиента: **client rules → profile rules → global rules**, внутри каждой группы — по `sort_order`, затем по `id`.
- Важно: правило **allow 10.8.0.1/32 port 53** должно стоять **выше** правила **deny 0.0.0.0/0**, иначе DNS будет заблокирован для форварда (но не для приёма на хост — см. выше).

---

## 3. Команды для проверки на сервере

Выполнять на хосте, где поднят WireGuard (интерфейс `awg0`).

### 3.1. Текущие правила nftables

```bash
# Все правила наших таблиц
sudo nft list table inet amnezia_wg 2>/dev/null || true
sudo nft list table inet amnezia_wg_base 2>/dev/null || true

# Полный ruleset (если нужно увидеть приоритеты и все цепочки)
sudo nft list ruleset
```

Ожидаемо:
- В `inet amnezia_wg` цепочка `forward_awg0` имеет `hook forward priority -100`.
- В `forward_awg0` есть правило `iifname "awg0" jump forward_awg0_dispatch`.
- В `forward_awg0_dispatch` — правила `ip saddr <client_ip> jump client_N` и в конце `accept`.

### 3.2. Убедиться, что трафик на хост не идёт через forward

Трафик с клиента к 10.8.0.1:53 — **destination local**, значит он обрабатывается цепочкой **input**, а не **forward**. Отдельно проверять не обязательно: по спецификации netfilter такой трафик в FORWARD не попадает.

### 3.3. Проверка DNS на хосте

```bash
# Кто слушает UDP 53 и на каких адресах
ss -ulnp | grep 53
# или
netstat -ulnp 2>/dev/null | grep 53

# С самого хоста запрос к 10.8.0.1
dig @10.8.0.1 google.com +short
# или
nslookup google.com 10.8.0.1
```

Если с хоста запрос к 10.8.0.1 не проходит — причина не в правилах панели (они только FORWARD), а в том, что DNS не слушает 10.8.0.1 или есть другие фаерволы (другие таблицы nft/iptables, firewalld).

### 3.4. Firewalld (если FIREWALL_BACKEND=firewalld)

```bash
# Список rich rules в зоне панели
sudo firewall-cmd --permanent --zone=amnezia_wg --list-rich-rules

# К какому интерфейсу привязана зона (должна быть awg0, иначе правила не применяются)
sudo firewall-cmd --get-zone-of-interface=awg0 2>/dev/null || true
sudo firewall-cmd --permanent --list-all --zone=amnezia_wg
```

Если зона `amnezia_wg` не привязана к интерфейсу `awg0`, правила панели не будут применяться к трафику с awg0. Привязку нужно делать вручную или в скрипте после поднятия интерфейса, например:

```bash
sudo firewall-cmd --permanent --zone=amnezia_wg --add-interface=awg0
sudo firewall-cmd --reload
```

---

## 4. Итог

| Вопрос | Ответ |
|--------|--------|
| Правило deny 0.0.0.0/0 режет DNS/сервисы на хосте? | **Нет.** Оно только в цепочке FORWARD; трафик на 10.8.0.1 идёт через INPUT. |
| Где смотреть правила? | `nft list table inet amnezia_wg` и `amnezia_wg_base`. |
| Почему nslookup 10.8.0.1 не отвечает? | Проверить: процесс, слушающий 53 (ss/netstat), привязку к 10.8.0.1, другие фаерволы. |

# browser_capture

Отдельный Python-пакет: **Chromium (Playwright) + tcpdump + разбор UDP** для захвата трафика, близкого к реальному браузеру (QUIC / HTTP/3 на стороне UDP), в отличие от триггера `curl --http3` в основном проекте.

**Объективный результат:** байты из pcap (`quic_packet_chain` и т.д.) — это нормальный выход этого пакета при вызове API/CLI без подмены. Режим `run_all --dry-run` в корневом репозитории **не** использует `browser_capture`: он подставляет JSON из `tests/fixtures/` только для CI.

## Идея

Сырой QUIC по-прежнему **не** читается из Chrome DevTools как байты пакета. Рабочая схема:

1. Разрешить хост в IPv4, построить BPF `udp and host <ip> and port 443`.
2. Запустить **tcpdump** в запись pcap.
3. Запустить **Chromium** и открыть HTTPS URL (сервер может отдать HTTP/3 / QUIC).
4. Остановить tcpdump, разобрать UDP payload через **Scapy**.
5. Отфильтровать исходящие пакеты (с локального IP) и эвристикой выбрать кандидатов **QUIC Initial** (`extractors/quic_udp.py`).

## Установка

```bash
cd browser_capture
pip install -e ".[dev]"
playwright install chromium
```

Системные зависимости: **tcpdump** в `PATH` (на Linux обычно `apt install tcpdump`; в Docker может понадобиться `cap_net_raw` / запуск от root для захвата).

## CLI

```bash
python -m browser_capture https://example.com/ --timeout 25
# или
browser-capture https://cloudflare.com/ --headed --json
```

Флаги:

- `--headed` — не headless (иногда ближе к «живому» клиенту по отпечатку).
- `--iface eth0` — интерфейс для tcpdump.
- `--no-quic` — отключить QUIC в Chromium (для сравнения).
- `--json` — сводка и hex кандидатов Initial.

## Программный API

```python
from browser_capture import CaptureOrchestrator

orch = CaptureOrchestrator()
result = orch.capture_quic_http3("https://example.com/", timeout=30, headless=True)
print(result.meta)
print(result.quic_initial_candidates)  # list[bytes]
```

## Ограничения

- Только **IPv4** для построения BPF в текущей версии (IPv6 — доработка).
- **Headless** и **headed** дают разный сетевой профиль.
- Полный **WebRTC/STUN** не реализован (нужна отдельная страница и разрешения) — см. `triggers/` для расширения.
- В контейнере без прав на захват tcpdump может не увидеть трафик; для Chromium в Docker часто нужен `--no-sandbox` (передайте через будущий хук `extra_chromium_args` в API).

## Сравнение с `curl`

| Способ | Стек QUIC/TLS |
|--------|----------------|
| curl `--http3` | libcurl |
| Этот пакет | Chromium / quiche (как у пользователя в Chrome) |

## Тесты

```bash
cd browser_capture
pytest tests/ -q
```

Интеграционные прогоны с реальным браузером и tcpdump в CI не обязательны.

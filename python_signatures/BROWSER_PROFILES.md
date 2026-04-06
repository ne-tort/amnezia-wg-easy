# Браузерный capture и профили I1–I5

## Реестр `profile_id`

Единственный источник списка профилей и порядка запуска — [`PROTOCOL_REGISTRY`](run_all.py) в `run_all.py`. Веб-панель и [`library_api.known_profile_ids()`](library_api.py) используют тот же реестр (Node вызывает Python с `PYTHONPATH` в корень репозитория).

Текущие профили:

| profile_id | Коллектор | Конфиг |
|------------|-----------|--------|
| `dns`, `sip`, `dtls` | [`LibraryTemplateProfileCollector`](library_template_collector.py) | `config/profile_templates/{dns,sip,dtls}.json` |
| `quic`, `quic_browser` | [`BrowserQuicSignatureCollector`](browser_quic_collector.py) | `config/quic_targets.json`, `config/quic_browser_targets.json` |
| `stun`, `webrtc`, `stun_browser` | [`BrowserStunSignatureCollector`](browser_stun_collector.py) | `config/stun_targets.json`, `webrtc_targets.json`, `stun_browser_targets.json` |

Если в JSON для STUN нет `stun_url`, URL собирается из первого элемента `servers` (`host:port` → `stun:host:port`).

## Объективный результат (что считать «нормальным»)

| Режим | Откуда берутся байты |
|--------|----------------------|
| **Без `--dry-run`** | Шаблоны читают закоммиченный `hex`; браузерные коллекторы — Chromium + tcpdump (`browser_capture`). [`merge_collector_output`](profile_cps.py) заполняет пустые слоты из [`ARCHITECT_DEFAULTS`](architect_fallbacks.py). |
| **`run_all --dry-run`** | Шаблоны из `profile_templates/`; для браузерных `profile_id` — `tests/fixtures/signatures/<profile_id>.json`. Без живого захвата. |

Приоритет merge: поля из коллектора (`hex`, опционально `i2`…) → **ARCHITECT_DEFAULTS** для любых пустых слотов.

## API для веб-панели

[`library_api.py`](library_api.py):

- `known_profile_ids()` — список из `PROTOCOL_REGISTRY`.
- `get_profile(profile_id, signatures_path=...)` — `{ profile_id, i1..i5, source_meta }`.
- `get_all_profiles(signatures_path=...)` — все известные профили.
- `regenerate_signatures(...)` — запуск `run_all` и запись JSON.

## `quic` / `quic_browser`

До пяти исходящих UDP в цепочке; маппинг в [`browser_quic_collector.py`](browser_quic_collector.py). Режим alt-svc (`https_quic_tcp` + `tls_clienthello_as_i1`) — см. [`capture_policy.yaml`](capture_policy.yaml).

## `stun` / `webrtc` / `stun_browser`

Исходящий STUN (и при наличии входящий ответ) из pcap; недостающие слоты — merge. Подробности в `capture_policy.yaml`.

## Теги CPS

Разрешены только: `<b>`, `<t>`, `<r>`, `<rc>`, `<rd>`. Тег `<c>` не использовать.

## Тесты без сети

`run_all --dry-run`; юнит-тесты на фикстурах. Полный захват — `@pytest.mark.integration` и скрипты в `browser_capture/scripts/`.

## Экспорт merged-профиля из фикстуры

```bash
python -m python_signatures.export_merged_profile quic
```

Требуется `tests/fixtures/signatures/<profile_id>.json` с полем `hex` (и опционально `i2`…).

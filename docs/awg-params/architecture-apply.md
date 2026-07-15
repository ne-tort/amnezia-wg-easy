# Draft / Apply / Cancel

## Проблема

Раньше клик по уровню I0–I5, протоколу или refresh сразу писал БД и вызывал `saveConfig()`. При частых кликах это гоняет reload awg и (после добавления рандома junk) могло бы перетирать общий серверный набор на каждый клик.

## Модель

```
UI draft (level, profile, signature, junk)
    │
    ├─ Применить → validate → clients.* + junk_pins + server_config → saveConfig/sync
    └─ Отмена → сброс draft к committed
```

- Клики по I-level / protocol / refresh меняют **только draft**.
- Refresh (`preview`): новая signature-variant + новый junk в рамках протокола.
- Смена протокола: junk из `junk_pins[protocol]` если есть, иначе один preview-generate в draft.
- Download / QR при `dirty` **отключены**, чтобы не скачать conf, расходящийся с черновиком.

## REST

| Метод | Persist? |
|-------|----------|
| `GET …/obfuscation` | нет — committed + server junk + pins |
| `POST …/obfuscation/preview` | **нет** |
| `POST …/obfuscation/apply` | **да** + reload |

Старые `PUT …/obfuscation` и `POST …/obfuscation/refresh` UI больше не вызывает (оставлены как legacy immediate-write для совместимости скриптов).

## Apply lock

Apply сериализуется через `__withConfigLock` / отдельный mutex apply: второй параллельный apply → `409`.

## Silent heal

`getClientConfiguration` **не** пишет БД при `ensureBinding.changed`. Исправлять binding — через apply или явный admin-path.

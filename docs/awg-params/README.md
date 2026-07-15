# AmneziaWG obfuscation parameters

Документация параметров обфускации для панели **amnezia-wg-easy**. Источники: AmneziaWG (go/kernel), [AmneziaWG-Architect](https://github.com/Vadim-Khristenko/AmneziaWG-Architect), клиент Amnezia, текущий код панели (`src/config.js`, `src/lib/WireGuard.js`).

## Карта параметров

| Группа | Поля | Роль |
|--------|------|------|
| Junk | `Jc`, `Jmin`, `Jmax` | Случайные UDP-пакеты перед handshake |
| Padding | `S1`–`S4` | Префиксы к Init / Response / Cookie / Transport |
| Headers | `H1`–`H4` | Замена «магических» типов сообщений WireGuard |
| CPS | `I1`–`I5` | Сигнатуры мимикрии (банк `signatures.json`) |

## Версии AWG (кратко)

| | 1.0 | 1.5 | 2.0 (панель) |
|--|:---:|:---:|:---:|
| Jc / Jmin / Jmax | да | да | да |
| S1–S2 | да | да | да |
| S3–S4 | — | — | да |
| H single | да | да | да (userspace go часто только single) |
| H ranges | — | — | предпочтительно; панель коллапсирует в single |
| I1–I5 | — | client-only | client + server-aware |

Ограничения и инварианты: [constraints.md](./constraints.md).

## Где живут значения в панели

- **Активный** `Jc/S/H` — один набор в `server_config` → `awg0.conf` и во **все** клиентские `.conf`.
- **I1–I5** — per-client (`default_profile` + `default_signature` → слоты банка).
- **Черновик UI** — level / protocol / signature / junk; на диск и в awg попадает только после **Применить** ([architecture-apply.md](./architecture-apply.md)).
- Диапазоны рандома junk по протоколу: `config/junk-ranges.seed.json` → `/opt/amnezia/awg/junk-ranges.json`.

## Файлы

- [jc.md](./jc.md) — число junk-пакетов
- [jmin-jmax.md](./jmin-jmax.md) — размер junk
- [s1-s4.md](./s1-s4.md) — padding
- [h1-h4.md](./h1-h4.md) — headers
- [constraints.md](./constraints.md) — жёсткие правила
- [protocols.md](./protocols.md) — привязка bounds к dns/quic/…
- [architecture-apply.md](./architecture-apply.md) — draft / apply / cancel

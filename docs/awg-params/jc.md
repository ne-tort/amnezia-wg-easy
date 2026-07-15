# Jc — junk packet count

## Смысл

Число случайных UDP-пакетов, которые клиент отправляет **до** initiation handshake. Ломает простые сигнатуры «сразу идёт WireGuard Init».

## Hard limits (протокол)

- `1 ≤ Jc ≤ 128` (UAPI amneziawg-go)
- Рекомендовано: **4–12** (README amneziawg, Architect для non-extreme)
- AWG 1.0: обычно `Jc ≥ 4`

## Адекватные рамки для рандома

| Режим | Диапазон | Комментарий |
|-------|----------|-------------|
| Лёгкий (DNS/NTP) | 4–8 | Меньше шума и RTT до handshake |
| Средний | 5–10 | Баланс |
| «Шумный» (QUIC/DTLS) | 6–12 | Ближе к Architect medium/high |
| Extreme (не используем в панели) | до 128 | Риск для слабых клиентов/роутеров |

## Влияние

- ↑ Jc — сильнее отвлекающий паттерн, выше задержка/объём при коннекте.
- ↓ Jc — быстрее handshake, проще DPI по «мало junk → Init».

## Панель

Генерируется в `junkParams.generateJunk(protocol)` из `junk-ranges.json`. Попадает в `server_config` только через `POST …/obfuscation/apply`.

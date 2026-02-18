# Соответствие протоколу AmneziaWG

Краткая сводка: стек форка и совпадение формата конфига с оригиналом. Подробности — [AmneziaWG | Amnezia Docs](https://docs.amnezia.org/documentation/amnezia-wg).

## Стек

- **Образ:** `amneziavpn/amneziawg-go:latest` — демон AmneziaWG и утилиты (awg, awg-quick); симлинки `wg` → `awg`, `wg-quick` → `awg-quick`.
- Конфиг пишется в `wg0.conf`, применяется через `wg syncconf wg0 <(wg-quick strip wg0)`. Ядро протокола — то же, что в [amnezia-vpn/amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go).

## Параметры конфига

| Параметр | Оригинал (amneziawg-go / amneziawg-tools) | Наш форк |
|----------|-------------------------------------------|----------|
| **Jc** | 4–12 | env или random 4–12 |
| **Jmin, Jmax** | 64–1024 байт (junk) | JMIN=64, JMAX=1000 |
| **S1–S4** | padding | Есть |
| **H1–H4** | значение или диапазон | Один диапазон `1-2147483647` по умолчанию; через env — своё |
| **I1–I5** | подписи `<b 0x...>`, `<r N>`, \<c\>, \<t\> | I1 в клиенте по профилю; I2–I5 опционально (уровни I2–I5) |

На сервере в wg0.conf I1–I5 не пишем (по рекомендации: custom signature только на клиенте). Регистр и имена полей совместимы с amneziawg-tools.

## Уровни I0–I5

- **I0** — без I1–I5 (минимальная обфускация, AmneziaWG 1.0).
- **I1** — только I1 (подпись по выбранному профилю).
- **I2** — I1 + I2=\<c\>
- **I3** — I1 + I2=\<c\> + I3=\<t\>
- **I4** — + I4=\<r N\>
- **I5** — + I5=\<r N\>. N = `OBFS_R_BYTES` (по умолчанию 48).

## Профили маскировки

Подпись I1 задаётся профилем: **QUIC**, **DNS**, **SIP**, **STUN**, **WebRTC**, **DTLS**. Значения по умолчанию в коде; переопределение через env: `I1_QUIC`, `I1_DNS`, `I1_SIP`, `I1_STUN`, `I1_WEBRTC`, `I1_DTLS`. Свой пакет из Wireshark: Copy as Hex Stream → `I1=<b 0x...>` или соответствующий env. [Инструкция Amnezia: извлечение подписи](https://docs.amnezia.org/documentation/instructions/new-amneziawg-selfhosted/#how-to-extract-a-protocol-signature-for-amneziawg-manually).

## Итог

Формат конфига совпадает с amneziawg-go и amneziawg-tools. Версия протокола — от образа `amneziavpn/amneziawg-go`; при необходимости зафиксировать тег в Dockerfile ([Releases amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go/releases)).

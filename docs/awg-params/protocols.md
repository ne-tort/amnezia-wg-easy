# Диапазоны junk по CPS-протоколам

Ключи совпадают с профилями банка `signatures.json`:  
`dns`, `dtls`, `ntp`, `quic`, `quic_browser`, `quic_tls_browser`, `sip`, `sip_multi`, `stun`, `stun_browser`, `webrtc`.

## Принцип

I1–I5 уже мимикрируют конкретный UDP-протокол. Junk (Jc/Jmin/Jmax) и padding (S*) подстраиваем под **типичный размер/шум** этого протокола, а не под абсолютный hard-max:

| Кластер | Протоколы | Идея junk |
|---------|-----------|-----------|
| Light | dns, ntp | Мало пакетов, скромные размеры (короткие probe) |
| Small-msg | stun, stun_browser, webrtc | Чуть больше Jc, Jmax умеренный |
| Signaling | sip, sip_multi | Medium Jc/J*, S ближе к default |
| Heavy | dtls, quic, quic_browser, quic_tls_browser | Больше Jc/Jmax, S1/S2 шире; S4 не раздувать сверх 24–32 |

Точные числа — в [`config/junk-ranges.seed.json`](../../config/junk-ranges.seed.json): `defaults` + override в `protocols.<id>`.

## Источники калибровки

- AmneziaWG-Architect `genCfg` intensity tables
- Типичные размеры capture в `capture_udp_sig` (короткий DNS vs QUIC Initial)
- Практические дефолты amnezia-client / docs.amnezia

## Merge

`getRangesForProtocol(id) = deepMerge(defaults, protocols[id] || {})`.
Неизвестный протокол → только `defaults`.

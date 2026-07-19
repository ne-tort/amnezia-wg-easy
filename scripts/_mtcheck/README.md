# mtcheck — диагностический клиент MTProto

Проверяет `tg://proxy?...` по шагам: TCP → browser TLS → FakeTLS/obfs2 handshake → (опционально) Telegram RPC.

## Важно про gotd / FakeTLS (`ee`)

`github.com/gotd/td@v0.114` шлёт **устаревший** ClientHello (битый GREASE, нулевой `key_share`).
Telemt (2026) отвечает: `ClientHello did not offer a usable TLS 1.3 key_share` и уводит в mask.

Нужен **gotd master** (uTLS / Chrome fingerprint), например `@e7d5e7882d4a`.

Сборка полного бинарника с `telegram` + пакет `tg` на VPS с 1 ГБ RAM почти нереалистична (OOM).
Для `ee` достаточно handshake-only:

```bash
# на машине с Go ≥ 1.25 и ≥2 ГБ RAM/swap
cd scripts/_mtcheck/handshake
go mod init mtcheckhs
go get github.com/gotd/td@e7d5e7882d4a
go build -o mtcheck-hs .
./mtcheck-hs 'tg://proxy?server=127.0.0.1&port=443&secret=ee...'
```

`dd` (secure) проходит и на старом `v0.114` до полного `HelpGetNearestDC`.

## Локальный эталон на 163.5.180.181

telemt на `:443`, SNI `web.de`, user `hello`:

```
tg://proxy?server=163.5.180.181&port=443&secret=ee73eef1d106c1a1d9be24f1a510a929fd7765622e6465
tg://proxy?server=163.5.180.181&port=443&secret=dd73eef1d106c1a1d9be24f1a510a929fd
```

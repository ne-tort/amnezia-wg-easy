# Amnezia WG-Easy

Форк [amnezia-wg-easy](https://github.com/amnezia-vpn/amnezia-wg-easy): веб-панель для self-hosted AmneziaWG. Цель — небольшое корпоративное решение на актуальном образе амнезии с обходом DPI(Поддержка Amnezia V2 протокола).

Был образ **amnezia-wg** (не обновлялся 2 года) — заменено на актуальный  **amneziawg-go**.

- БД (SQLite), конфиг сервера и клиентов из БД
- Роли: admin / moderator / user
- Фаерволл: глобальные правила и профили (nftables или firewalld)
- Подписи обфускации I1–I5: Python-скрипты дампят протоколы (QUIC, DNS, STUN и др.) для реальных сигнатур
- Amnezia DNS: при `WG_DEFAULT_DNS`, совпадающем с шлюзом VPN (по умолчанию 10.8.0.1), поднимается dnsmasq как в клиенте Amnezia

**Запуск:** `./deploy.sh`

**HTTPS панели (nginx + Let's Encrypt):** в compose добавлены nginx и certbot. Панель доступна только по HTTPS (прямой порт панели на хост не пробрасывается). В .env задайте `PANEL_DOMAIN` (например `panel.ai-qwerty.ru`) и `CERTBOT_EMAIL`. A-запись домена должна указывать на IP сервера, порты 80 и 443 открыты. После первого `docker compose up -d` получите сертификат: `docker compose run --rm certbot certonly --webroot -w /var/www/certbot -d panel.ai-qwerty.ru --email YOUR_EMAIL --agree-tos`, затем перезагрузите nginx: `docker exec nginx nginx -s reload`. VPN (UDP) не затрагивается — клиенты по-прежнему подключаются к IP:WG_PORT.

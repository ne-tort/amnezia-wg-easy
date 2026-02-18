# VPN-клиент в Docker + SMB для проверки доступа

Сценарий проверки: AmneziaWG-клиент в контейнере (host network), общая SMB-папка на хосте, доступ к ней с другого VPN-клиента.

## 1. Конфиг клиента

Положите в эту папку файл **wg0.conf** с конфигом AmneziaWG. В нём обязательно должно быть:

- `AllowedIPs = 10.8.0.0/24` (только VPN-подсеть через туннель; не `0.0.0.0/0`, иначе весь трафик пойдёт через VPN и возможны зависания).

Если конфиг выдан с `AllowedIPs = 0.0.0.0/0, ::/0`, замените на `AllowedIPs = 10.8.0.0/24`.

## 2. Запуск VPN-клиента в Docker

```bash
cd vpn-client-test
chmod +x run-client.sh
./run-client.sh
```

Проверка: на хосте должен появиться интерфейс с адресом 10.8.0.4:

```bash
ip a | grep 10.8
# или
wg show
```

Остановка: `docker stop amneziawg-client`; удаление: `docker rm amneziawg-client`.

## 3. SMB-папка на хосте

На той же машине, где запущен контейнер (host network), поднимите Samba:

1. Установка (Debian/Ubuntu): `sudo apt install samba`
2. Каталог: `sudo mkdir -p /srv/vpn-share` и при необходимости `sudo chmod 0777 /srv/vpn-share`
3. Пользователь Samba: `sudo smbpasswd -a vpnuser` (задайте пароль, по умолчанию для теста можно использовать **VPNshare2025** — затем смените)
4. В **/etc/samba/smb.conf** в конец добавьте:

```ini
[vpn-share]
   path = /srv/vpn-share
   browseable = yes
   read only = no
   force user = root
   create mask = 0664
   directory mask = 0775
   valid users = root
   comment = VPN test share (root, like vpn-test)
```

5. Перезапуск: `sudo systemctl restart smbd` (или `smb`). Шара **vpn-share** использует того же пользователя **root**, что и **vpn-test** — подключайтесь теми же учётными данными.

## 4. Проверка с другого клиента

Второе устройство подключается к тому же AmneziaWG-серверу и получает IP в 10.8.0.x (например 10.8.0.5). С него:

- **Windows:** Проводник → `\\10.8.0.4\vpn-share`, логин **root**, пароль — тот же, что для `vpn-test` (учётная запись root в Samba).
- **macOS / Linux:** `smb://10.8.0.4/vpn-share`, логин **root**, пароль тот же.

Если папка открывается — VPN и доступ между клиентами работают.

---

## Итог: папка, подключение, пароль

| | |
|--|--|
| **Папка на хосте (путь на диске)** | `/srv/vpn-share` |
| **Подключение с другого VPN-клиента (Windows)** | `\\10.8.0.4\vpn-share` |
| **Подключение (macOS / Linux)** | `smb://10.8.0.4/vpn-share` |
| **Логин SMB** | **root** (та же учётка, что для шары vpn-test) |
| **Пароль SMB** | Тот же, что вы вводите для `\\10.8.0.4\vpn-test` (пароль root в Samba). |

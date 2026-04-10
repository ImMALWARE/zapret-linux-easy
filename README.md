# zapret для Linux
[README in English](https://github.com/ImMALWARE/zapret-linux-easy/blob/main/README_EN.md)

1. Скачайте и распакуйте архив https://github.com/ImMALWARE/zapret-linux-easy/archive/refs/heads/main.zip (либо `git clone https://github.com/ImMALWARE/zapret-linux-easy && cd zapret-linux-easy`)
2. **Убедитесь, что у вас установлены пакеты `curl`, `iptables` и `ipset` (для FWTYPE=iptables) или `curl` и `nftables` (для FWTYPE=nftables)! Если нет — установите. Если вы не знаете как, спросите у ChatGPT!**
3. Откройте терминал в папке, куда архив был распакован
4. `./install.sh`

# Управление
## Systemd
Остановка: `sudo systemctl stop zapret`

Запуск после остановки: `sudo systemctl start zapret`

Отключение автозапуска (по умолчанию включен): `sudo systemctl disable zapret`

Включение автозапуска: `sudo systemctl enable zapret`
## OpenRC

Остановка: `sudo rc-service zapret stop`

Запуск после остановки: `sudo rc-service zapret start`

Включение автозапуска: `sudo rc-update add zapret`

Отключение автозапуска: `sudo rc-update del zapret`
## Runit

Остановка: `sudo sv down zapret`

Запуск после остановки: `sudo sv up zapret`

Включение автозапуска: `sudo ln -s /etc/sv/zapret /var/service/`

Отключение автозапуска: `sudo rm /var/service/zapret`

# Списки доменов
Не работает какой-то заблокированный сайт? Попробуйте добавить его домен в `/opt/zapret/autohosts.txt`

Заблокированные IP-адреса и CIDR можно добавить в `/opt/zapret/ipset.txt`

`/opt/zapret/whitelist.txt` — список доменов в белом списке. Запросы на сервера Cloudflare, Hetzner, OVH и т.д. с этими доменами проходят корректно. Не следует путать с белым списком мобильного интернета.

Не работает незаблокированный сайт? Добавьте его домен в `/opt/zapret/ignore.txt`

Конфиг можно изменить в `/opt/zapret/config.txt` (перезапустите zapret после изменения)

Тип firewall-а можно изменить в `/opt/zapret/system/FWTYPE` (перезапустите zapret после изменения)

Для проверки текущего конфига вы можете использовать `/opt/zapret/check.sh`

# Настройка интерфейсов (для роутеров и шлюзов)
По умолчанию zapret слушает все сетевые интерфейсы. Если вы используете устройство как роутер, можно ограничить работу конкретными портами:
* **WAN (интернет):** запишите имя интерфейса в файл `/opt/zapret/system/IFACE_WAN`
* **LAN (локальная сеть):** запищите имя интерфейса в файл `/opt/zapret/system/IFACE_LAN`

Внутри файла укажите имя интерфейса (например, `eth0` или `br-lan`). Если интерфейсов несколько — перечислите их через пробел.
Если файлы пустые — правила применяются ко всем интерфейсам.
**(перезапустите zapret после изменения)**

# Переменные в config.txt

`{hosts}` — подставит путь к `autohosts.txt`

`{ipset}` — подставит путь к `ipset.txt`

`{whitelist}` — подставит путь к `whitelist.txt`

`{ignore}` — подставит путь к `ignore.txt`

`{youtube}` — подставить путь к `youtube.txt`

`{quicgoogle}` — подставит путь к `system/quic_initial_www_google_com.bin`

`{tlsgoogle}` — подставит путь к `system/tls_clienthello_www_google_com.bin`

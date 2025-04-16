# Однокнопочный zapret для Linux

1. Скачайте архив [https://github.com/ImMALWARE/zapret-linux-easy/releases/download/1/zapret.zip](https://github.com/ImMALWARE/zapret-linux-easy/releases/download/1/zapret.zip)
2. Распакуйте его
3. **Убедитесь, что у вас установлены пакеты `iptables` и `ipset`! Если нет — установите. Если вы не знаете как, спросите у ChatGPT!**
4. Откройте терминал в папке, куда архив был распакован
5. `./install.sh`

# Управление
Остановка: `sudo systemctl stop zapret`

Запуск после остановки: `sudo systemctl start zapret`

Отключение автозапуска (по умолчанию включен): `sudo systemctl disable zapret`

Включение автозапуска: `sudo systemctl enable zapret`

# Списки доменов
Не работает какой-то заблокированный сайт? Попробуйте добавить его домен в `/opt/zapret/autohosts.txt`

Не работает незаблокированный сайт? Добавьте его домен в `/opt/zapret/ignore.txt`

## Протестировано на Kali, Ubuntu и Arch
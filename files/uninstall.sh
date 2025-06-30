#!/bin/sh

if [ "$(id -u)" -ne 0 ]; then
    exec sudo "$0" "$@"
    exit 1
fi

systemctl disable zapret
systemctl stop zapret
rm /usr/lib/systemd/system/zapret.service
echo "Теперь можно удалять папку /opt/zapret"
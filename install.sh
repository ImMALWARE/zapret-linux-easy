#!/bin/sh

if [ "$(id -u)" -ne 0 ]; then
    echo "Скрипт должен быть запущен от имени root! Введите пароль!"
    exec sudo "$0" "$@"
    exit 1
fi

if [ "$(cd "$(dirname "$0")" && pwd)" != "/opt/zapret" ]; then
    cp -r "$(cd "$(dirname "$0")" && pwd)" /opt/zapret
fi

cat <<EOF > /usr/lib/systemd/system/zapret.service
[Unit]
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
Restart=no
TimeoutSec=30sec
IgnoreSIGPIPE=no
KillMode=none
GuessMainPID=no
RemainAfterExit=no
ExecStart=/opt/zapret/init.d/sysv/zapret start
ExecStop=/opt/zapret/init.d/sysv/zapret stop

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl start zapret
systemctl enable zapret
echo "Установка завершена. zapret теперь в папке /opt/zapret, папку в Загрузках можно удалить.
"

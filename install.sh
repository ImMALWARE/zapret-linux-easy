#!/bin/sh

if [ "$(id -u)" -ne 0 ]; then
    exec sudo "$0" "$@"
    exit 1
fi

rm /usr/lib/systemd/system/zapret.service > /dev/null 2>&1
rm -rf /opt/zapret > /dev/null 2>&1
rm -rf /etc/sv/zapret > /dev/null 2>&1
rm -rf /var/service/zapret > /dev/null 2>&1
killall nfqws > /dev/null 2>&1

mkdir -p /opt/zapret
cp -r ./files/* /opt/zapret/

arch=$(uname -m)
case "$arch" in
    x86_64)
        bin_dir="x86_64"
        ;;
    i386|i686)
        bin_dir="x86"
        ;;
    armv7l|armv6l)
        bin_dir="arm"
        ;;
    aarch64)
        bin_dir="arm64"
        ;;
    *)
        echo "Unknown architecture: $arch"
        exit 1
        ;;
esac

cp "./bins/$bin_dir/nfqws" /opt/zapret/system/
chmod +x /opt/zapret/system/nfqws

echo "Select firewall type:"
echo "1. iptables"
echo "2. nftables"
read -p "Enter number (1 or 2): " choice
case $choice in
    1)
        echo "iptables" > /opt/zapret/system/FWTYPE
        echo "Firewall type set: iptables"
        ;;
    2)
        echo "nftables" > /opt/zapret/system/FWTYPE
        echo "Firewall type set: nftables"
        ;;
    *)
        echo "Error: Invalid selection. Please choose 1 or 2."
        exit 1
        ;;
esac

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd ]; then

    cat <<EOF > /usr/lib/systemd/system/zapret.service
[Unit]
Description=zapret
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/zapret
ExecStart=/bin/bash /opt/zapret/system/starter.sh
ExecStop=/bin/bash /opt/zapret/system/stopper.sh

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl start zapret
    systemctl enable zapret
    echo "Installation complete. zapret is now in the /opt/zapret folder, you can delete the folder in Downloads."

elif command -v openrc-run >/dev/null 2>&1 || [ -d /run/openrc ]; then
    cat <<EOF > /etc/init.d/zapret
#!/sbin/openrc-run

name="zapret"
description="zapret service"
command="/bin/bash"
command_args="/opt/zapret/system/starter.sh"
pidfile="/run/zapret.pid"

start_pre() {
    checkpath --directory /run
}

stop() {
    /bin/bash /opt/zapret/system/stopper.sh
}
EOF
    chmod +x /etc/init.d/zapret
    rc-update add zapret default
    rc-service zapret start
    echo "Installation complete. zapret is now in the /opt/zapret folder, you can delete the folder in Downloads."
elif command -v sv >/dev/null 2>&1 && [ -d /run/runit ]; then
    mkdir -p /etc/sv/zapret/
    cat <<EOF > /etc/sv/zapret/run
#!/bin/sh
exec 2>&1
exec /opt/zapret/system/starter.sh
EOF
    chmod +x /etc/sv/zapret/run
    mkdir -p /etc/sv/zapret/log
    cat <<EOF > /etc/sv/zapret/log/run
#!/bin/sh
exec vlogger -t zapret -p daemon
EOF
    chmod +x /etc/sv/zapret/log/run
    cat <<EOF > /etc/sv/zapret/finish
#!/bin/sh
exec 2>&1
exec /opt/zapret/system/stopper.sh
EOF
    chmod +x /etc/sv/zapret/finish
    ln -s /etc/sv/zapret /var/service/
    echo "Installation complete. zapret is now in the /opt/zapret folder, you can delete the folder in Downloads."
else
    echo "Failed to detect init system (systemd, OpenRC or runit not found)."
    exit 1
fi

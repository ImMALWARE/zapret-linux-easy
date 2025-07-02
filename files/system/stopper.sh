#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

if pidof "nfqws" > /dev/null; then
    killall nfqws
fi

if [ -f /opt/zapret/system/FWTYPE ]; then
    content=$(cat /opt/zapret/system/FWTYPE)
    if [ "$content" = "iptables" ]; then
        FWTYPE=iptables
    elif [ "$content" = "nftables" ]; then
        FWTYPE=nftables
    else
        echo "Ошибка: Неверное значение в файле FWTYPE."
        exit 1
    fi
    echo "FWTYPE=$FWTYPE"
else
    echo "Ошибка: Файл /opt/zapret/system/FWTYPE не найден."
    exit 1
fi

if [ "$FWTYPE" = "iptables" ]; then
    iptables -t mangle -F PREROUTING
    iptables -t mangle -F POSTROUTING
elif [ "$FWTYPE" = "nftables" ]; then
    nft flush table inet zapret
    nft delete table inet zapret
fi

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
        echo "Error: invalid value in file FWTYPE."
        exit 1
    fi
    echo "FWTYPE=$FWTYPE" 2>/dev/null
else
    echo "Error: File /opt/zapret/system/FWTYPE not found."
    exit 1
fi

if [ "$FWTYPE" = "iptables" ]; then
    iptables -t mangle -F POSTROUTING
    ip6tables -t mangle -F POSTROUTING
elif [ "$FWTYPE" = "nftables" ]; then
    nft flush table inet zapret 2>/dev/null || true
    nft delete table inet zapret 2>/dev/null || true
fi

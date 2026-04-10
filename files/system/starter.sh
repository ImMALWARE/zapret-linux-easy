#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

if pidof "nfqws" > /dev/null; then
    echo "nfqws is already running."
    exit 0
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
    echo "FWTYPE=$FWTYPE"
else
    echo "Error: File /opt/zapret/system/FWTYPE not found."
    exit 1
fi

IFACE_WAN=""
IFACE_LAN=""
[ -f /opt/zapret/system/IFACE_WAN ] && IFACE_WAN=$(cat /opt/zapret/system/IFACE_WAN)
[ -f /opt/zapret/system/IFACE_LAN ] && IFACE_LAN=$(cat /opt/zapret/system/IFACE_LAN)

DESYNC_MARK=0x40000000

ARGS_FILE="/tmp/nfqws_args_$$"
echo "--qnum=200" > "$ARGS_FILE"
echo "--uid=0:0" >> "$ARGS_FILE"
echo "--dpi-desync-fwmark=$DESYNC_MARK" >> "$ARGS_FILE"
while IFS= read -r line; do
    line="${line//\{hosts\}//opt/zapret/autohosts.txt}"
    line="${line//\{youtube\}//opt/zapret/youtube.txt}"
    line="${line//\{ignore\}//opt/zapret/ignore.txt}"
    line="${line//\{ipset\}//opt/zapret/ipset.txt}"
    line="${line//\{whitelist\}//opt/zapret/whitelist.txt}"
    line="${line//\{quicgoogle\}//opt/zapret/system/quic_initial_www_google_com.bin}"
    line="${line//\{tlsgoogle\}//opt/zapret/system/tls_clienthello_www_google_com.bin}"
    line="$(echo "$line" | sed -E 's/--wf-(tcp|udp)=[^ ]+//g')"
    line="$(echo "$line" | sed -E 's/  +/ /g' | sed -E 's/^ //;s/ $//')"
    [[ -n "$line" ]] && echo "$line" >> "$ARGS_FILE"
done < "/opt/zapret/config.txt"

sysctl net.netfilter.nf_conntrack_tcp_be_liberal=1

if [ "$FWTYPE" = "iptables" ]; then
    TCP_PORTS=$(cat "$ARGS_FILE" | tr ' ' '\n' | grep '^--filter-tcp=' | sed 's/--filter-tcp=//' | paste -sd, | sed 's/-/:/g')
    UDP_PORTS=$(cat "$ARGS_FILE" | tr ' ' '\n' | grep '^--filter-udp=' | sed 's/--filter-udp=//' | paste -sd, | sed 's/-/:/g')
elif [ "$FWTYPE" = "nftables" ]; then
    TCP_PORTS=$(cat "$ARGS_FILE" | tr ' ' '\n' | grep '^--filter-tcp=' | sed 's/--filter-tcp=//' | paste -sd, | sed 's/:/-/g')
    UDP_PORTS=$(cat "$ARGS_FILE" | tr ' ' '\n' | grep '^--filter-udp=' | sed 's/--filter-udp=//' | paste -sd, | sed 's/:/-/g')
fi

if [ "$FWTYPE" = "iptables" ]; then
    iptables -t mangle -F POSTROUTING
    ip6tables -t mangle -F POSTROUTING
elif [ "$FWTYPE" = "nftables" ]; then
    nft add table inet zapret
    nft flush table inet zapret
    nft add chain inet zapret postrouting { type filter hook postrouting priority mangle \; }
fi

if [ "$FWTYPE" = "iptables" ]; then
    add_ipt_rule() {
        local iface_arg=$1
        local iface_list=$2
        local proto=$3
        local ports=$4
        local qnum=$5
        local extra_flags=$6

        if [ -z "$iface_list" ]; then
             iptables -t mangle -I POSTROUTING -p "$proto" -m multiport --dports "$ports" \
                -m mark ! --mark $DESYNC_MARK/$DESYNC_MARK $extra_flags -j NFQUEUE --queue-num "$qnum" --queue-bypass
             ip6tables -t mangle -I POSTROUTING -p "$proto" -m multiport --dports "$ports" \
                -m mark ! --mark $DESYNC_MARK/$DESYNC_MARK $extra_flags -j NFQUEUE --queue-num "$qnum" --queue-bypass
        else
            for iface in $iface_list; do
                iptables -t mangle -I POSTROUTING "$iface_arg" "$iface" -p "$proto" -m multiport --dports "$ports" \
                    -m mark ! --mark $DESYNC_MARK/$DESYNC_MARK $extra_flags -j NFQUEUE --queue-num "$qnum" --queue-bypass
                ip6tables -t mangle -I POSTROUTING "$iface_arg" "$iface" -p "$proto" -m multiport --dports "$ports" \
                    -m mark ! --mark $DESYNC_MARK/$DESYNC_MARK $extra_flags -j NFQUEUE --queue-num "$qnum" --queue-bypass
            done
        fi
    }

    if [ -n "$TCP_PORTS" ]; then
        add_ipt_rule "-o" "$IFACE_WAN" "tcp" "$TCP_PORTS" "200" "-m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 1:12"
    fi
    if [ -n "$UDP_PORTS" ]; then
        add_ipt_rule "-o" "$IFACE_WAN" "udp" "$UDP_PORTS" "200" "-m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 1:12"
    fi

elif [ "$FWTYPE" = "nftables" ]; then
    nft_wan_clause=""
    if [ -n "$IFACE_WAN" ]; then
        wan_list=$(echo "$IFACE_WAN" | tr ' ' ',')
        nft_wan_clause="oifname { $wan_list }"
    fi

    if [ -n "$TCP_PORTS" ]; then
        nft add rule inet zapret postrouting $nft_wan_clause tcp dport { $TCP_PORTS } mark != $DESYNC_MARK ct original packets 1-12 queue num 200 bypass
    fi

    if [ -n "$UDP_PORTS" ]; then
        nft add rule inet zapret postrouting $nft_wan_clause udp dport { $UDP_PORTS } mark != $DESYNC_MARK ct original packets 1-12 queue num 200 bypass
    fi
fi

if [ "$1" = "--foreground" ]; then
    /opt/zapret/system/nfqws @"$ARGS_FILE"
    rm -f "$ARGS_FILE"
else
    /opt/zapret/system/nfqws @"$ARGS_FILE" &
    sleep 1 && rm -f "$ARGS_FILE"
fi
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

ARGS=""
while IFS= read -r line; do
    line="${line//\{hosts\}//opt/zapret/autohosts.txt}"
    line="${line//\{youtube\}//opt/zapret/youtube.txt}"
    line="${line//\{ignore\}//opt/zapret/ignore.txt}"
    line="${line//\{ipset\}//opt/zapret/ipset.txt}"
    line="${line//\{quicgoogle\}//opt/zapret/system/quic_initial_www_google_com.bin}"
    line="${line//\{tlsgoogle\}//opt/zapret/system/tls_clienthello_www_google_com.bin}"
    line="${line//\{tls4pda\}//opt/zapret/system/tls_clienthello_4pda_to.bin}"
    line="$(echo "$line" | sed -E 's/--wf-(tcp|udp)=[^ ]+//g')"
    line="$(echo "$line" | sed -E 's/  +/ /g' | sed -E 's/^ //;s/ $//')"
    ARGS+=" $line"
done < "/opt/zapret/config.txt"

sysctl net.netfilter.nf_conntrack_tcp_be_liberal=1

if [ "$FWTYPE" = "iptables" ]; then
    TCP_PORTS=$(echo "$ARGS" | tr -s ' ' '\n' | grep '^--filter-tcp=' | sed 's/--filter-tcp=//' | paste -sd, | sed 's/-/:/g')
    UDP_PORTS=$(echo "$ARGS" | tr -s ' ' '\n' | grep '^--filter-udp=' | sed 's/--filter-udp=//' | paste -sd, | sed 's/-/:/g')
elif [ "$FWTYPE" = "nftables" ]; then
    TCP_PORTS=$(echo "$ARGS" | tr -s ' ' '\n' | grep '^--filter-tcp=' | sed 's/--filter-tcp=//' | paste -sd, | sed 's/:/-/g')
    UDP_PORTS=$(echo "$ARGS" | tr -s ' ' '\n' | grep '^--filter-udp=' | sed 's/--filter-udp=//' | paste -sd, | sed 's/:/-/g')
fi

if [ "$FWTYPE" = "iptables" ]; then
    iptables -t mangle -F PREROUTING
    iptables -t mangle -F POSTROUTING
    ip6tables -t mangle -F PREROUTING
    ip6tables -t mangle -F POSTROUTING
elif [ "$FWTYPE" = "nftables" ]; then
    nft add table inet zapret
    nft flush table inet zapret
    nft add chain inet zapret prerouting { type filter hook prerouting priority mangle \; }
    nft add chain inet zapret postrouting { type filter hook postrouting priority mangle \; }
fi

if [ "$FWTYPE" = "iptables" ]; then
    add_ipt_rule() {
        local chain=$1
        local iface_arg=$2
        local iface_list=$3
        local proto=$4
        local ports=$5
        local qnum=$6
        local extra_flags=$7

        if [ -z "$iface_list" ]; then
             iptables -t mangle -I "$chain" -p "$proto" -m multiport --dports "$ports" \
                $extra_flags -j NFQUEUE --queue-num "$qnum" --queue-bypass
             iptables -t mangle -I "$chain" -p "$proto" -m multiport --sports "$ports" \
                $extra_flags -j NFQUEUE --queue-num "$qnum" --queue-bypass
             ip6tables -t mangle -I "$chain" -p "$proto" -m multiport --dports "$ports" \
                $extra_flags -j NFQUEUE --queue-num "$qnum" --queue-bypass
             ip6tables -t mangle -I "$chain" -p "$proto" -m multiport --sports "$ports" \
                $extra_flags -j NFQUEUE --queue-num "$qnum" --queue-bypass
        else
            for iface in $iface_list; do
                iptables -t mangle -I "$chain" "$iface_arg" "$iface" -p "$proto" -m multiport --dports "$ports" \
                    $extra_flags -j NFQUEUE --queue-num "$qnum" --queue-bypass
                iptables -t mangle -I "$chain" "$iface_arg" "$iface" -p "$proto" -m multiport --sports "$ports" \
                    $extra_flags -j NFQUEUE --queue-num "$qnum" --queue-bypass
                ip6tables -t mangle -I "$chain" "$iface_arg" "$iface" -p "$proto" -m multiport --dports "$ports" \
                    $extra_flags -j NFQUEUE --queue-num "$qnum" --queue-bypass
                ip6tables -t mangle -I "$chain" "$iface_arg" "$iface" -p "$proto" -m multiport --sports "$ports" \
                    $extra_flags -j NFQUEUE --queue-num "$qnum" --queue-bypass
            done
        fi
    }

    if [ -n "$TCP_PORTS" ]; then
        add_ipt_rule "POSTROUTING" "-o" "$IFACE_WAN" "tcp" "$TCP_PORTS" "200" "-m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 1:12"
    fi
    if [ -n "$UDP_PORTS" ]; then
        add_ipt_rule "POSTROUTING" "-o" "$IFACE_WAN" "udp" "$UDP_PORTS" "200" "-m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 1:12"
    fi

    if [ -n "$TCP_PORTS" ]; then
        add_ipt_rule "PREROUTING" "-i" "$IFACE_LAN" "tcp" "$TCP_PORTS" "200" "-m connbytes --connbytes-dir=reply --connbytes-mode=packets --connbytes 1:6"
    fi
    if [ -n "$UDP_PORTS" ]; then
        add_ipt_rule "PREROUTING" "-i" "$IFACE_LAN" "udp" "$UDP_PORTS" "200" "-m connbytes --connbytes-dir=reply --connbytes-mode=packets --connbytes 1:6"
    fi

elif [ "$FWTYPE" = "nftables" ]; then
    nft_wan_clause=""
    nft_lan_clause=""
    if [ -n "$IFACE_WAN" ]; then
        wan_list=$(echo "$IFACE_WAN" | tr ' ' ',')
        nft_wan_clause="oifname { $wan_list }"
    fi
    if [ -n "$IFACE_LAN" ]; then
        lan_list=$(echo "$IFACE_LAN" | tr ' ' ',')
        nft_lan_clause="iifname { $lan_list }"
    fi

    if [ -n "$TCP_PORTS" ]; then
        nft add rule inet zapret postrouting $nft_wan_clause tcp dport { $TCP_PORTS } ct original packets 1-12 queue num 200 bypass
        nft add rule inet zapret prerouting $nft_lan_clause tcp sport { $TCP_PORTS } ct reply packets 1-6 queue num 200 bypass
    fi

    if [ -n "$UDP_PORTS" ]; then
        nft add rule inet zapret postrouting $nft_wan_clause udp dport { $UDP_PORTS } ct original packets 1-12 queue num 200 bypass
        nft add rule inet zapret prerouting $nft_lan_clause udp sport { $UDP_PORTS } ct reply packets 1-6 queue num 200 bypass
    fi
fi

if [ "$1" = "--foreground" ]; then
    /opt/zapret/system/nfqws --qnum=200 --uid=0:0 $ARGS
else
    /opt/zapret/system/nfqws --qnum=200 --uid=0:0 $ARGS &
fi
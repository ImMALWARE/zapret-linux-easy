# zapret for Linux
[README на русском](https://github.com/ImMALWARE/zapret-linux-easy/blob/main/README.md)

1. Download and unpack the archive https://github.com/ImMALWARE/zapret-linux-easy/archive/refs/heads/main.zip (or `git clone https://github.com/ImMALWARE/zapret-linux-easy && cd zapret-linux-easy`)
2. **Make sure you have the `curl`, `iptables`, and `ipset` packages installed (for FWTYPE=iptables), or `curl` and `nftables` (for FWTYPE=nftables)! If not, install them. If you don't know how, ask ChatGPT!**
3. Open a terminal in the folder where the archive was unpacked.
4. `./install.sh`

# Management
## Systemd
Stop: `sudo systemctl stop zapret`

Start: `sudo systemctl start zapret`

Disable autostart (enabled by default): `sudo systemctl disable zapret`

Enable autostart: `sudo systemctl enable zapret`
## OpenRC

Stop: `sudo rc-service zapret stop`

Start: `sudo rc-service zapret start`

Enable autostart: `sudo rc-update add zapret`

Disable autostart: `sudo rc-update del zapret`
## Runit

Stop: `sudo sv down zapret`

Start: `sudo sv up zapret`

Enable autostart: `sudo ln -s /etc/sv/zapret /var/service/`

Disable autostart: `sudo rm /var/service/zapret`

# Domain Lists
Is a blocked site not working? Try adding its domain to `/opt/zapret/autohosts.txt`

You can add blocked IP-addresses and CIDR to `/opt/zapret/ipset.txt`

`/opt/zapret/whitelist.txt` — whitelist of domains. Requests to Cloudflare, Hetzner, OVH, etc. servers with these domains work correctly. Do not confuse with the mobile internet whitelist.

Is an unblocked site not working? Add its domain to `/opt/zapret/ignore.txt`

The config can be changed in `/opt/zapret/config.txt` (restart zapret after making changes)

The firewall type can be changed in `/opt/zapret/system/FWTYPE` (restart zapret after making changes)

To check the current config, you can use `/opt/zapret/check.sh`

# Interface Configuration (For routers/gateways)
By default, zapret listens on all network interfaces. If using the device as a router, you can restrict it to specific ports:
* **WAN (Internet):** write the interface name in `/opt/zapret/system/IFACE_WAN`
* **LAN (Local Network):** write the interface name in `/opt/zapret/system/IFACE_LAN`

Specify the interface name inside the file (e.g., `eth0` or `br-lan`). Use spaces to separate multiple interfaces.
If the files are empty, rules apply to all interfaces.
**(restart zapret after making changes)**

# Variables in config.txt

`{hosts}` — Substitutes the path to `autohosts.txt`

`{ipset}` — Substitutes the path to `ipset.txt`

`{whitelist}` — Substitutes the path to `whitelist.txt`

`{ignore}` — Substitutes the path to `ignore.txt`

`{youtube}` — Substitutes the path to `youtube.txt`

`{quicgoogle}` — Substitutes the path to `system/quic_initial_www_google_com.bin`

`{tlsgoogle}` — Substitutes the path to `system/tls_clienthello_www_google_com.bin`
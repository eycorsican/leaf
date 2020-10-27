![releases](https://github.com/eycorsican/leaf/workflows/releases/badge.svg)
![build](https://github.com/eycorsican/leaf/workflows/build/badge.svg)
![tun2socks-build](https://github.com/eycorsican/leaf/workflows/tun2socks-build/badge.svg)

### Leaf
A lightweight and fast proxy utility tries to include any useful features.

### Usage
There's a brief introduction written in Chinese you can find [here](https://github.com/eycorsican/leaf/blob/master/README.zh.md).

### iOS
Open Source Demo: https://github.com/eycorsican/ileaf

TestFlight App: https://testflight.apple.com/join/std0FFCS

### OpenWrt
Running as transparent proxy on OpenWrt:
```sh
# Install the TUN package.
opkg update && opkg install kmod-tun

# Get the default interface address.
ADDRESS=`ip route get 1 | awk '{print $7;exit}'`

# Get the default gateway address.
GATEWAY=`ip route get 1 | awk '{print $3;exit}'`

TUN_NAME=tun8
TUN_ADDRESS=172.16.0.2
TUN_GATEWAY=172.16.0.1

# Properly configure the config file.
cat <<EOF > cfg.conf
[General]
loglevel = debug
dns-server = 223.5.5.5, 1.1.1.1
dns-interface = $ADDRESS
always-real-ip = *
tun = $TUN_NAME, $TUN_ADDRESS, 255.255.255.0, $TUN_GATEWAY, 1500

[Proxy]
Direct = direct, interface=$ADDRESS
Proxy = ss, 1.2.3.4, 9999, encrypt-method=chacha20-ietf-poly1305, password=9999, interface=$ADDRESS

[Rule]
DOMAIN-SUFFIX, google.com, Proxy
FINAL, Direct
EOF

# Open another SSH session to run leaf with the config.
# It's important to run in a seperate window since we still need
# the variables defined above to continue our setup process.
# I suggest you use `screen`: opkg update && opkg install screen
leaf -c cfg.conf

# Route traffic initiated from leaf to the original gateway.
ip route add default via $GATEWAY table default
ip rule add from $ADDRESS table default

# Route local traffic to TUN.
ip route del default table main
ip route add default via $TUN_GATEWAY

# Route traffic from other deivces to TUN.
iptables -I FORWARD -o $TUN_NAME -j ACCEPT
```

Re-run:
```sh
# Stop leaf via ctrl+c.

# Make some changes to your `cfg.conf`.

# Re-run leaf.
leaf -c cfg.conf

# Re-add the default route to TUN.
ip route add default via $TUN_GATEWAY
```

Recover the original network:
```sh
# Stop leaf via ctrl+c.

# Remove iptables rules.
iptables -D FORWARD -o $TUN_NAME -j ACCEPT

# Cleanup the routing table.
ip rule del from $ADDRESS
ip route del default table default

# Recover the original default route.
ip route add default via $GATEWAY
```

Check if everything looks fine:
```sh
iptables -L FORWARD -n
ip route show table main
ip route show table default
ip rule show
```

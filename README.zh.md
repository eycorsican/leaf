# Leaf

Leaf 是一个轻量且快速的代理工具。

## 内容

- [下载](#--)
- [iOS TF 测试](#ios-tf---)
- [conf 配置文件](#conf-----)
- [json 配置文件](#json-----)
- [Log](#log)
- [DNS](#dns)
- [Inbounds](#inbounds)
  * [http](#http)
  * [socks](#socks)
- [Outbounds](#outbounds)
  * [direct](#direct)
  * [drop](#drop)
  * [tls](#tls)
  * [ws](#ws)
  * [shadowsocks](#shadowsocks)
  * [vmess](#vmess)
  * [trojan](#trojan)
  * [socks](#socks-1)
  * [chain](#chain)
  * [failover](#failover)
  * [tryall](#tryall)
  * [random](#random)
- [规则](#--)
  * [domain](#domain)
  * [domainSuffix](#domainsuffix)
  * [domainKeyword](#domainkeyword)
  * [ip](#ip)
  * [geoip](#geoip)
  * [external](#external)
    + [mmdb](#mmdb)
    + [site](#site)
- [进阶功能](#----)
  * [TUN Inbound](#tun-inbound)

## 下载

https://github.com/eycorsican/leaf/releases

## iOS TF 测试
iOS TF 测试公开链接：https://testflight.apple.com/join/std0FFCS

## conf 配置文件

```ini
[General]
loglevel = info
dns-server = 114.114.114.114, 223.5.5.5
always-real-ip = tracker, apple.com
interface = 127.0.0.1
port = 1087
socks-interface = 127.0.0.1
socks-port = 1086

[Proxy]
Direct = direct
Reject = reject
SS = ss, 1.2.3.4, 8485, encrypt-method=chacha20-ietf-poly1305, password=123456

VMess = vmess, my.domain.com, 8001, username=0eb5486e-e1b5-49c5-aa75-d15e54dfac9d

VMessWSS = vmess, my.domain.com, 443, username=0eb5486e-e1b5-49c5-aa75-d15e54dfac9d, ws=true, tls=true, ws-path=/v2

Trojan = trojan, 4.3.2.1, 443, password=123456, sni=www.domain.com

[Proxy Group]
# fallback 等效于 failover
Fallback = fallback, Trojan, VMessWSS, SS, interval=600, timeout=5

# url-test 等效于 failover=false 的 failover
UrlTest = url-test, Trojan, VMessWSS, SS, interval=600, timeout=5

Failover = failover, Trojan, VMessWSS, SS, health-check=true, check-interval=600, fail-timeout=5, failover=true
Tryall = tryall, Trojan, VMessWSS, delay-base=0
Random = random, Trojan, VMessWSS

[Rule]
# 执行文件目录当中必需有 `site.dat` 文件
EXTERNAL, site:category-ads-all, Reject

# 也可以指定 `dat` 文件所在绝对路径，不支持相对路径
EXTERNAL, site:/tmp/geosite.dat:category-ads-all, Reject

IP-CIDR, 8.8.8.8/32, Fallback
DOMAIN, www.google.com, Fallback
DOMAIN-SUFFIX, google.com, Fallback
DOMAIN-KEYWORD, google, Fallback

# 等效于 EXTERNAL, mmdb:us, Fallback
GEOIP, us, Fallback

EXTERNAL, site:geolocation-!cn, Fallback

# 执行文件目录当中必需有 `geo.mmdb` 文件
EXTERNAL, mmdb:us, Fallback

FINAL, Direct
```

## json 配置文件

JSON 配置文件目前不考虑兼容性，每个版本都可能会变。

```json
{
    "log": {
        "level": "info"
    },
    "dns": {
        "servers": [
            "1.1.1.1",
            "8.8.8.8"
        ]
    },
    "inbounds": [
        {
            "listen": "127.0.0.1",
            "port": 1087,
            "protocol": "http"
        },
        {
            "listen": "127.0.0.1",
            "port": 1086,
            "protocol": "socks",
            "settings": {
                "bind": "127.0.0.1"
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "failover",
            "settings": {
                "actors": [
                    "vmess_out",
                    "trojan_out"
                ]
            },
            "tag": "failover_out"
        },
        {
            "protocol": "chain",
            "settings": {
                "actors": [
                    "vmess_tls",
                    "vmess_ws",
                    "vmess"
                ]
            },
            "tag": "vmess_out"
        },
        {
            "protocol": "tls",
            "tag": "vmess_tls"
        },
        {
            "protocol": "ws",
            "settings": {
                "path": "/v2"
            },
            "tag": "vmess_ws"
        },
        {
            "protocol": "vmess",
            "settings": {
                "address": "server.com",
                "port": 443,
                "uuid": "89ee4e17-aaad-49f6-91c4-6ea5990206bd"
            },
            "tag": "vmess"
        },
        {
            "protocol": "chain",
            "settings": {
                "actors": [
                    "trojan_tls",
                    "trojan"
                ]
            },
            "tag": "trojan_out"
        },
        {
            "protocol": "tls",
            "tag": "trojan_tls"
        },
        {
            "protocol": "trojan",
            "settings": {
                "address": "server.com",
                "password": "112358",
                "port": 443
            },
            "tag": "trojan"
        },
        {
            "protocol": "shadowsocks",
            "settings": {
                "address": "x.x.x.x",
                "method": "chacha20-ietf-poly1305",
                "password": "123456",
                "port": 8389
            },
            "tag": "shadowsocks_out"
        },
        {
            "protocol": "socks",
            "settings": {
                "address": "x.x.x.x",
                "port": 1080
            },
            "tag": "socks_out"
        },
        {
            "protocol": "direct",
            "tag": "direct_out"
        },
        {
            "protocol": "drop",
            "tag": "drop_out"
        }
    ],
    "rules": [
        {
            "ip": [
                "8.8.8.8",
                "8.8.4.4"
            ],
            "target": "failover_out"
        },
        {
            "domain": [
                "www.google.com"
            ],
            "target": "failover_out"
        },
        {
            "domainSuffix": [
                "google.com"
            ],
            "target": "failover_out"
        },
        {
            "domainKeyword": [
                "google"
            ],
            "target": "failover_out"
        },
        {
            "external": [
                "site:cn"
            ],
            "target": "direct_out"
        },
        {
            "external": [
                "mmdb:cn"
            ],
            "target": "direct_out"
        }
    ]
}
```

## Log

```json
"log": {
    "level": "info"
}
```

level 可以是 trace, debug, info, warn, error

## DNS

```json
"dns": {
    "servers": [
        "114.114.114.114",
        "1.1.1.1"
    ]
}
```

DNS 用于 `direct` Outbound 请求的域名解析，以及其它 Outbound 中代理服务器地址的解析（如果代理服务器地址是 IP，则不需要解析）。

## Inbounds

```json
"inbounds": [
    {
        ...
    },
    {
        ...
    }
]
```

inbounds 是一个数组，每一项可以是以下：

### http

```json
{
    "protocol": "http",
    "listen": "127.0.0.1",
    "port": 1087
}
```

支持 HTTP Connect。

### socks

```json
{
    "protocol": "socks",
    "listen": "127.0.0.1",
    "port": 1086,
    "settings": {
        "bind": "127.0.0.1"
    }
}
```

默认支持 UDP。

## Outbounds

支持常见的代理协议比如 Shadowsocks、VMess、Trojan，以及 TLS 和 WebSocket 传输，另外有四个组合类型的 Outbound，其中 `chain` 可以对各种代理和传输协议进行任意组合。

```json
"outbounds": [
    {
        ...
    },
    {
        ...
    }
]
```

outbounds 是一个数组，每一项可以是以下：

### direct

直连出口，请求将从本机直接发往目标，不经任何代理。

```json
{
    "protocol": "direct",
    "tag": "direct_out"
}
```

### drop

拦截请求。

```json
{
    "protocol": "drop",
    "tag": "drop_out"
}
```

### tls

TLS 传输，一般用来叠加到其它代理或传输协议上。

```json
{
    "protocol": "tls",
    "settings": {
        "serverName": "server.com"
    },
    "tag": "tls_out"
}
```

如果 `serverName` 为空，会尝试从下层协议获取。

### ws

WebSocket 传输，一般用来叠加到其它代理或传输协议上。

```json
{
    "protocol": "ws",
    "settings": {
        "path": "/v2"
    },
    "tag": "ws_out"
}
```

还未支持自定义 Headers，Host 会尝试从下层协议获取。

### shadowsocks

```json
{
    "protocol": "shadowsocks",
    "settings": {
        "address": "x.x.x.x",
        "method": "chacha20-ietf-poly1305",
        "password": "123456",
        "port": 8389
    },
    "tag": "shadowsocks_out"
}
```

`method`：
- chacha20-ietf-poly1305
- aes-128-gcm
- aes-256-gcm

### vmess

```json
{
    "protocol": "vmess",
    "settings": {
        "address": "server.com",
        "port": 10086,
        "uuid": "89ee4e17-aaad-49f6-91c4-6ea5990206bd",
        "security": "chacha20-ietf-poly1305"
    },
    "tag": "vmess"
}
```

`security`：
- chacha20-ietf-poly1305
- aes-128-gcm
- aes-256-gcm

### trojan

`trojan` Outbound 只包含未经 TLS 加密的代理协议，通常还需要利用 `chain` 对其叠加一层 `tls` 才能和正常的 trojan 服务器通讯。

```json
{
    "protocol": "trojan",
    "settings": {
        "address": "server.com",
        "password": "112358",
        "port": 443
    },
    "tag": "trojan_out"
}
```

### socks

```json
{
    "protocol": "socks",
    "settings": {
        "address": "1.2.3.4",
        "port": 1080
    },
    "tag": "socks_out"
}
```

`socks` 不支持用户密码认证。

### chain

`chain` Outbound 可以对任意协议进行叠加，主要用途是在某个代理协议上叠加 tls、ws 等传输，以及配置代理链。

这是一个典型的 TLS + WebSocket + VMess 配置：

```json
"outbounds": [
    {
        "protocol": "chain",
        "settings": {
            "actors": [
                "vmess_tls",
                "vmess_ws",
                "vmess"
            ]
        },
        "tag": "vmess_out"
    },
    {
        "protocol": "tls",
        "tag": "vmess_tls"
    },
    {
        "protocol": "ws",
        "settings": {
            "path": "/v2"
        },
        "tag": "vmess_ws"
    },
    {
        "protocol": "vmess",
        "settings": {
            "address": "server.com",
            "port": 443,
            "uuid": "89ee4e17-aaad-49f6-91c4-6ea5990206bd"
        },
        "tag": "vmess"
    }
]
```

如果有多个服务器，可以配置一个代理链，请求将沿着代理链传输后到达目标：

> 客户端 -> ss1 -> ss2 -> 目标

```json
"outbounds": [
    {
        "protocol": "chain",
        "settings": {
            "actors": [
                "ss1",
                "ss2"
            ]
        },
        "tag": "ss_chain_out"
    },
    {
        "protocol": "shadowsocks",
        "settings": {
            "address": "1.1.1.1",
            "method": "chacha20-ietf-poly1305",
            "password": "123456",
            "port": 1111
        },
        "tag": "ss1"
    },
    {
        "protocol": "shadowsocks",
        "settings": {
            "address": "2.2.2.2",
            "method": "chacha20-ietf-poly1305",
            "password": "123456",
            "port": 2222
        },
        "tag": "ss2"
    }
]
```

### failover

```json
{
    "protocol": "failover",
    "settings": {
        "actors": [
            "vmess_out",
            "trojan_out"
        ],
        "failTimeout": 4,
        "healthCheck": true,
        "checkInterval": 300,
		"failover": true
    },
    "tag": "failover_out"
}
```

向列表中的 Outbound 逐个发送请求，直到找到一个可用的 Outbound，可选参数有

- `failTimeout` 握手超时，包括 TCP 握手及相应代理协议握手的时间
- `healthCheck` 如果为 `true`，则对列表中的 Outbound 定时做健康检查，并按延迟重新排序
- `checkInterval` 健康检查间隔
- `failover` 如果为 `false`，则只取一个 Outbound 发送请求，失败也不会尝试其它 Outbound

### tryall

```json
{
    "protocol": "tryall",
    "settings": {
        "actors": [
            "trojan_out",
            "vmess_out"
        ],
        "delayBase": 0
    },
    "tag": "tryall_out"
}
```

向列表中的所有 Outbound 同时发起代理请求，选取握手成功最快的 Outbound，可选参数有

- `delayBase` 延时基数，如果大于 0，则代理请求会延迟 delayBase * index 毫秒，index 从 0 起，每个 Outbound 递增 1

### random

```json
{
    "protocol": "random",
    "settings": {
        "actors": [
            "trojan_out",
            "vmess_out"
        ]
    },
    "tag": "random"
}
```

从列表中随机选一个 Outbound 发送请求。

## 规则

规则方面跟 V2Ray 差不多，只是把域名规则展开成 `domain`, `domainSuffix`, `domainKeyword`。

```json
"rules": [
    {
        ...
    },
    {
        ...
    }
]
```

`rules` 是一个数组，每一项可以是以下：

### domain

匹配整个域名。

```json
{
    "domain": [
        "www.google.com"
    ],
    "target": "failover_out"
}
```

### domainSuffix

匹配子域名，虽然名字是 `Suffix`，但只匹配子域名，即 `google.com` 匹配 `www.google.com`，但不匹配 `wwwgoogle.com`。

```json
{
    "domainSuffix": [
        "google.com"
    ],
    "target": "failover_out"
}
```

### domainKeyword

匹配域名关键字。

```json
{
    "domainKeyword": [
        "google"
    ],
    "target": "failover_out"
}
```

### ip

匹配 IP 或 IP-CIDR。

```json
{
    "ip": [
        "8.8.8.8/32",
        "8.8.4.4"
    ],
    "target": "failover_out"
}
```

### geoip

可执行文件目录中必需有 `geo.mmdb` 文件存在。

```json
{
    "geoip": [
        "us",
        "jp"
    ],
    "target": "failover_out"
}
```

### external

`external` 规则可以从外部文件加载规则，支持两种格式

```json
{
    "external": [
        "mmdb:us",
    ],
    "target": "failover_out"
}
```

```json
{
    "external": [
        "site:cn",
    ],
    "target": "direct_out"
}
```

#### mmdb

MaxMind 的 mmdb 格式，可以有如下形式：

- `mmdb:TAG` 假设 mmdb 文件存在于可执行文件目录，并且文件名为 `geo.mmdb`
- `mmdb:FILENAME:TAG` 假设 mmdb 文件存在于可执行文件目录，文件名为 `FILENAME`
- `mmdb:PATH:TAG` 指写 mmdb 文件的绝对路径为 `PATH`

#### site

V2Ray 的 `dat` 文件格式，可以有如下形式：

- `site:TAG` 同 mmdb，文件名为 `site.dat`
- `site:FILENAME:TAG` 同 mmdb
- `site:PATH:TAG` 同 mmdb

## 进阶功能

### TUN Inbound

在 macOS 和 Linux 上还支持 TUN Inbound

```json
"inbounds": [
    {
        "protocol": "tun",
        "settings": {
            "name": "utun8",
            "address": "10.10.0.2",
            "netmask": "255.255.255.0",
            "gateway": "10.10.0.1",
            "mtu": 1500,
            "fakeDnsExclude": [
                "tracker",
                "time.asia.apple.com",
                "mesu.apple.com"
            ]
        },
        "tag": "tun_in"
    }
]
```

参数

- `name` 在 macOS 上必须是 `utun` 开头后加一个数字，在 Linux 上必须是 `tun` 开头后加一个数字
- `address` `netmask` `gateway` `mtu` TUN 接口的一些参数
- `fakeDnsExclude` 使用 TUN Inbound 将默认使用 `FakeDNS` 功能，这个列表可以将某些域名排除在外，**目前**处理使用域名的 UDP 请求会有问题，所以需要排除

在 macOS 上还不能自动配置地址需要手动：sudo ifconfig utun7 10.10.0.2 netmask 255.255.255.0 10.10.0.1

还需要手动配置路由表，具体可以参考 Mellow ：[macOS](https://github.com/mellow-io/mellow/blob/f71f6e54768ded3cfcc46bebb706d46cb8baac08/src/main.js#L702) [Linux](https://github.com/mellow-io/mellow/blob/f71f6e54768ded3cfcc46bebb706d46cb8baac08/src/helper/linux/config_route#L1)

此外所有非组合类型的 Outbound 必须正确配置一个 `bind` 地址，这是连接原网关的网卡的地址，即未连接 VPN 前网卡的 IP 地址：
```json
"outbounds: [
    {
        "bind": "192.168.0.99",
        "protocol": "shadowsocks",
        "settings": {
            "address": "x.x.x.x",
            "method": "chacha20-ietf-poly1305",
            "password": "123456",
            "port": 8389
        },
        "tag": "shadowsocks_out"
    },
    {
        "bind": "192.168.0.99",
        "protocol": "direct",
        "tag": "direct"
    }
]
```

```json
"dns": {
    "bind": "192.168.0.99",
    "servers": ["1.1.1.1"]
}
```

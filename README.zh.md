# Leaf

Leaf 是一个轻量且快速的代理工具。

## 目录

- [Downloads](#downloads)
- [iOS TestFlight](#ios-testflight)
- [conf](#conf)
- [json](#json)
- [Log](#log)
- [DNS](#dns)
- [inbounds](#inbounds)
  * [http](#http)
  * [socks](#socks)
  * [trojan](#trojan)
  * [ws](#ws)
  * [amux](#amux)
  * [chain](#chain)
- [outbounds](#outbounds)
  * [direct](#direct)
  * [drop](#drop)
  * [tls](#tls)
  * [ws](#ws-1)
  * [amux](#amux-1)
  * [h2](#h2)
  * [shadowsocks](#shadowsocks)
  * [vmess](#vmess)
  * [trojan](#trojan)
  * [socks](#socks-1)
  * [chain](#chain)
  * [failover](#failover)
  * [tryall](#tryall)
  * [random](#random)
  * [retry](#retry)
- [Rules](#rules)
  * [domain](#domain)
  * [domainSuffix](#domainsuffix)
  * [domainKeyword](#domainkeyword)
  * [ip](#ip)
  * [geoip](#geoip)
  * [external](#external)
    + [mmdb](#mmdb)
    + [site](#site)
- [Advanced Features](#advanced-features)
  * [TUN inbound](#tun-inbound)

## Downloads

https://github.com/eycorsican/leaf/releases

## iOS TestFlight
iOS TF 测试公开链接：https://testflight.apple.com/join/std0FFCS

## conf

```ini
[General]
loglevel = info
dns-server = 114.114.114.114, 223.5.5.5
always-real-ip = tracker, apple.com

# Local HTTP CONNECT proxy
interface = 127.0.0.1
port = 1087

# Local SOCKS5 proxy with UDP Associate support
socks-interface = 127.0.0.1
socks-port = 1086

[Proxy]
Direct = direct
Reject = reject

# Shadowsocks
SS = ss, 1.2.3.4, 8485, encrypt-method=chacha20-ietf-poly1305, password=123456

# VMess
VMess = vmess, my.domain.com, 8001, username=0eb5486e-e1b5-49c5-aa75-d15e54dfac9d

# VMess over WebSocket over TLS (TLS + WebSocket + VMess)
VMessWSS = vmess, my.domain.com, 443, username=0eb5486e-e1b5-49c5-aa75-d15e54dfac9d, ws=true, tls=true, ws-path=/v2

# Trojan (with TLS)
Trojan = trojan, 4.3.2.1, 443, password=123456, sni=www.domain.com

# Trojan over WebSocket over TLS (TLS + WebSocket + Trojan)
TrojanWS = trojan, 4.3.2.1, 443, password=123456, sni=www.domain.com, ws=true, ws-path=/abc

# Trojan over amux streams which use WebSocket over TLS as the underlying connection (TLS + WebSocket + amux + Trojan)
tls-ws-amux-trojan = trojan, www.domain.com, 443, password=112358, tls=true, ws=true, ws-path=/amux, amux=true
tls-ws-amux-trojan2 = trojan, 1.0.0.1, 443, password=123456, sni=www.domain.com, ws=true, ws-path=/amux, ws-host=www.domain.com, amux=true, amux-max=16, amux-con=1

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

[Host]
# 对指定域名返回一个或多个静态 IP
example.com = 192.168.0.1, 192.168.0.2
```

在 [AppStore](https://apps.apple.com/us/app/leaf-lightweight-proxy/id1534109007) 或 [TestFlight](https://testflight.apple.com/join/std0FFCS) （都可以免费下载到）上的 Leaf 中，版本 `1.1 (8)` 及以上，`conf` 格式除了以上设置以外还支持一个 `[On Demand]` 配置，这是完全是一个 iOS 方面的功能，跟本 leaf 项目关系不大，它不涉及任何 Rust 代码，但为了方便查看也在这写下。

下面规则表示连接 `OpenWrt` WiFi 信号时断开 VPN，其它任何情况都连着 VPN，典型的使用场景是 OpenWrt 是一个有透明代理的无线信号：

```ini
[On Demand]
# 表示如果当前连接到 wifi 且 ssid 名为 OpenWrt，则断开 VPN
DISCONNECT, ssid=OpenWrt, interface-type=wifi
# 无条件地连接 VPN
CONNECT
```

规则有两种 `CONNECT` 和 `DISCONNECT` ，匹配条件支持两种 `ssid` 和 `interface-type`，`ssid` 可以是以 `:` 分隔的 ssid 名称列表，`interface-type` 只能是以下 3 个值中的一个：`wifi`, `cellular`, `any`。规则不带任何匹配条件表示无条件执行。

## json

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
        ],
        "hosts": {
            "example.com": [
                "192.168.0.1",
                "192.168.0.2"
            ],
            "server.com": [
                "192.168.0.3"
            ]
        }
    },
    "inbounds": [
        {
            "address": "127.0.0.1",
            "port": 1087,
            "protocol": "http"
        },
        {
            "address": "127.0.0.1",
            "port": 1086,
            "protocol": "socks"
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
    ],
    "hosts": {
        "example.com": [
            "192.168.0.1",
            "192.168.0.2
        ],
        "server.com": [
            "192.168.0.3"
        ]
    }
}
```

DNS 用于 `direct` outbound 请求的域名解析，以及其它 outbound 中代理服务器地址的解析（如果代理服务器地址是 IP，则不需要解析）。`servers` 是 DNS 服务器列表，`hosts` 是静态 IP。


作为 `hosts` 的使用例子，以下两个配置在效果上是相同的（因为用 json 配置会很长，这里用 conf 表达）：

```ini
[Proxy]
Proxy = trojan, www.domain.com, 443, password=123456, ws=true, ws-path=/abc
[Host]
www.domain.com = 1.2.3.4
```

```ini
[Proxy]
Proxy = trojan, 1.2.3.4, 443, password=123456, ws=true, ws-path=/abc, sni=www.domain.com
```

而 `hosts` 还可以指定多个 IP：

```ini
[Host]
www.domain.com = 1.2.3.4, 5.6.7.8
```

## inbounds

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
    "address": "127.0.0.1",
    "port": 1087
}
```

支持 HTTP Connect。

### socks

```json
{
    "protocol": "socks",
    "address": "127.0.0.1",
    "port": 1086
}
```

默认支持 UDP。

### trojan

```json
{
    "protocol": "trojan",
    "address": "127.0.0.1",
    "port": 10086,
    "settings": {
        "password": "123456"
    }
}
```

### ws

WebSocket 传输，一般在 `chain` 叠加到其它代理协议上。

```json
{
    "protocol": "ws",
    "settings": {
        "path": "/abc"
    }
}
```

### amux

`amux` 多路复用传输，可以在一个可靠的连接上建立多个可靠流传输。

**`amux` 目前不提供版本间兼容。**

```json
{
    "protocol": "amux",
    "settings": {
        "actors": [
             "tls",
             "ws"
        ]
    }
}
```

- `actors` 指定底层传输，空值表示用 TCP

### chain

`chain` 可以对多个协议进行叠加。

```json
{
    "protocol": "chain",
    "address": "127.0.0.1",
    "port": 10086,
    "settings": {
        "actors": [
            "ws_out",
            "trojan_out"
        ]
    }
}
```

例如这是一个 WebSocket + Trojan 配置：

```json
"inbounds": [
    {
        "protocol": "chain",
        "tag": "ws_trojan_in",
        "address": "127.0.0.1",
        "port": 4003,
        "settings": {
            "actors": [
                "ws_in",
                "trojan_in"
            ]
        }
    },
    {
        "protocol": "ws",
        "tag": "ws_in",
        "settings": {
            "path": "/abc"
        }
    },
    {
        "protocol": "trojan",
        "tag": "trojan_in",
        "settings": {
            "password": "12345"
        }
    }
]
```

注意上面配置示例没有 TLS，一般可以交给 nginx 来处理。

## outbounds

支持常见的代理协议比如 Shadowsocks、VMess、Trojan，以及 TLS 和 WebSocket 传输，另外有四个组合类型的 outbound，其中 `chain` 可以对各种代理和传输协议进行任意组合。

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
        "serverName": "server.com",
        "alpn": ["http/1.1"]
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
        "path": "/v2",
        "headers": {
            "Host": "server.com"
        }
    },
    "tag": "ws_out"
}
```

`headers` 是一个字典，可以包含任意数量的 KV 对。`Host` 不指定的话会尝试从下层协议获取。

### amux

`amux` 多路复用传输，可以在一个可靠的连接上建立多个可靠流传输。

**`amux` 目前不提供版本间兼容。**

```json
{
    "protocol": "amux",
    "settings": {
        "actors": [
             "tls",
             "ws"
        ],
        "address": "tls.server.com",
        "port": 443,
        "maxAccepts": 8,
        "concurrency": 2
    }
}
```

- `actors` 指定底层传输，空值表示用 TCP
- `address` 底层传输的连接地址
- `port` 端口
- `maxAccepts` 指定单个底层连接最多可建立流的数量
- `concurrency` 指定单个底层连接并发流数量

`amux` 是一个非常简单的多路复用传输协议，所有流数量的传输都是以 FIFO 方式进行，设计上依赖 `maxAccepts` 和 `concurrency` 两个参数对传输性能进行控制。

### h2

HTTP2 传输，一般需要配合 tls 一起使用，tls 需要配置 h2 作为 alpn。

```json
"outbounds": [
    {
        "protocol": "chain",
        "settings": {
            "actors": [
                "vmess_tls",
                "vmess_h2",
                "vmess"
            ]
        },
        "tag": "vmess_out"
    },
    {
        "protocol": "tls",
        "settings": {
            "serverName": "server.com",
            "alpn": ["h2"]
        },
        "tag": "vmess_tls"
    },
    {
        "protocol": "h2",
        "settings": {
            "host": "server.com",
            "path": "/v2"
        },
        "tag": "vmess_h2"
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

### trojan

`trojan` outbound 只包含未经 TLS 加密的代理协议，通常还需要利用 `chain` 对其叠加一层 `tls` 才能和正常的 trojan 服务器通讯。

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

`chain` outbound 可以对任意协议进行叠加，主要用途是在某个代理协议上叠加 tls、ws 等传输，以及配置代理链。

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
        "failover": true,
        "fallbackCache": false,
        "cacheSize": 256,
        "cacheTimeout": 60
    },
    "tag": "failover_out"
}
```

向列表中的 outbound 逐个发送请求，直到找到一个可用的 outbound，可选参数有

- `failTimeout` 握手超时，包括 TCP 握手及相应代理协议握手的时间
- `healthCheck` 如果为 `true`，则对列表中的 outbound 定时做健康检查，并按延迟重新排序
- `checkInterval` 健康检查间隔
- `failover` 如果为 `false`，则只取一个 outbound 发送请求，失败也不会尝试其它 outbound
- `fallbackCache` 如果为 `true`，则对 fallback outbound 的成功请求作记录缓存，后续同样请求直接使用已缓存的 outbound
- `cacheSize` fallback cache 大小
- `cacheTimeout` fallback cache 缓存时间，单位分钟

`failover` 的 actors 里面可以包含另一个 `failover` outbound，可以实现非常灵活的多级负载分配机制。

`fallbackCache` 功能的初衷是让 `failover` 能够实现自动检测需要代理请求的机制，把一个 `direct` 和任意数量的其它 outbound 放到 `failover` 中，`direct` 放第一位，并禁用 `healthCheck`，启用 `fallbackCache`，那 `failover` 就会先尝试 `direct`，如果失败，自动切换使用其它 outbound，并且记录缓存下来，下一个同样请求直接跳过 `direct` 使用对应 outbound，但有个缺陷是它只能检测 TCP 连接超时或连接错误的请求。所谓 fallback outbound 就是 `failover` actors 里面第一个 outbound 失败后，所用到的后续任意成功的某个 outbound。

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

向列表中的所有 outbound 同时发起代理请求，选取握手成功最快的 outbound，可选参数有

- `delayBase` 延时基数，如果大于 0，则代理请求会延迟 delayBase * index 毫秒，index 从 0 起，每个 outbound 递增 1

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

从列表中随机选一个 outbound 发送请求。

### retry

```json
{
    "protocol": "retry",
    "settings": {
        "actors": [
            "trojan_out",
            "vmess_out"
        ],
        "attempts": 2,
    },
    "tag": "retry"
}
```

可以对 outbound 列表进行多次重试。

## Rules

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
- `mmdb:FILENAME:TAG` 假设 mmdb 文件存在于可执行文件目录，文件名为 `FILENAME`，文件名包含后缀。
- `mmdb:PATH:TAG` 指写 mmdb 文件的绝对路径为 `PATH`，文件名包含后缀。

#### site

V2Ray 的 `dat` 文件格式，可以有如下形式：

- `site:TAG` 同 mmdb，文件名为 `site.dat`
- `site:FILENAME:TAG` 同 mmdb
- `site:PATH:TAG` 同 mmdb

## Advanced Features

### TUN inbound

在 macOS 和 Linux 上还支持 TUN inbound

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
            "fakeDnsInclude": [
                "google"
            ]
        },
        "tag": "tun_in"
    }
]
```

参数

- `name` 在 macOS 上必须是 `utun` 开头后加一个数字，在 Linux 上必须是 `tun` 开头后加一个数字
- `address` `netmask` `gateway` `mtu` TUN 接口的一些参数
- `fakeDnsInclude` 使用 TUN inbound 将默认使用 `FakeDNS` 功能，这个列表可以指定哪些域名会返回伪造 IP，以关键字方式匹配，未指定的域名将不受影响。
- `fakeDnsExclude` 使用 TUN inbound 将默认使用 `FakeDNS` 功能，这个列表可以将某些域名排除在外，以关键字方式匹配，未指定的域名将会返回伪造的 IP。

`fakeDnsInclude` 和 `fakeDnsExclude` 只能二选一，这个配置方式将来大概率会改。

在 macOS 上还不能自动配置地址需要手动：sudo ifconfig utun7 10.10.0.2 netmask 255.255.255.0 10.10.0.1

还需要手动配置路由表，具体可以参考 Mellow ：[macOS](https://github.com/mellow-io/mellow/blob/f71f6e54768ded3cfcc46bebb706d46cb8baac08/src/main.js#L702) [Linux](https://github.com/mellow-io/mellow/blob/f71f6e54768ded3cfcc46bebb706d46cb8baac08/src/helper/linux/config_route#L1)

此外所有非组合类型的 outbound 必须正确配置一个 `bind` 地址，这是连接原网关的网卡的地址，即未连接 VPN 前网卡的 IP 地址：
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

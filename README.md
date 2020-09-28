# Leaf

Leaf 是一个轻量且快速的代理工具。

## 配置文件

```json
{
    "log": {
        "level": "info"
    },
    "dns": [
        "1.1.1.1",
        "8.8.8.8"
    ],
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
                ],
                "checkInterval": 300,
                "failTimeout": 4,
                "healthCheck": true
            },
            "tag": "failover_out"
        },
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
        },
        {
            "protocol": "random",
            "settings": {
                "actors": [
                    "trojan_out",
                    "vmess_out"
                ]
            },
            "tag": "random"
        },
        {
            "protocol": "vmess",
            "settings": {
                "url": "wss://my.domain.com/v2",
                "uuid": "6541dbe7-6877-4ce0-80a5-291d3db87650"
            },
            "tag": "vmess_out"
        },
        {
            "protocol": "trojan",
            "settings": {
                "address": "x.x.x.x",
                "domain": "my.domain.com",
                "password": "112358",
                "port": 443
            },
            "tag": "trojan_out"
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
            "tag": "direct"
        },
        {
            "protocol": "drop",
            "tag": "drop"
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
                "site:geosite.dat:cn"
            ],
            "target": "direct"
        },
        {
            "external": [
                "mmdb:geo.mmdb:cn"
            ],
            "target": "direct"
        }
    ]
}
```

## Outbound 类型

支持常见的代理协议比如 Shadowsocks、VMess+WSS、Trojan，另外有三个组合类型的 Outbound：

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
        "checkInterval": 300
    },
    "tag": "failover_out"
}
```

向列表中的 Outbound 逐个发送请求，直到找到一个可用的 Outbound，可选参数有

- `failTimeout` 握手超时，包括 TCP 握手及相应代理协议握手的时间
- `healthCheck` 如果为 `true`，则对列表中的 Outbound 定时做健康检查，并按延迟重新排序
- `checkInterval` 健康检查间隔

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

`external` 规则可以从外部文件加载规则，支持两种格式

- `mmdb` MaxMind 的 mmdb 格式
- `site` V2Ray 的 `dat` 文件格式

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
            ],
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

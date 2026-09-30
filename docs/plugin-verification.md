# 插件下载与内置插件：手动验证指南

本文按步骤验证两项功能：

- **Windows 客户端**：conf 里用 `url` 声明插件，客户端自动下载、校验、缓存后启动；App 可以预下载并显示进度。
- **移动客户端**：插件在编译时链接进 App，conf 里用 `builtin` 引用；同一份 conf 在没有内置该插件的客户端上回退到 `url`。

每一步都写了要执行的命令和应该看到的结果。下文中的"期望输出"都是在 Windows 11（ARM64）上实际运行得到的；sha256、耗时、时间戳在你的机器上会不一样，其余应当一致。

## 为什么需要 `leaf-plugin-verify`

leaf 下载插件时只信任公共 CA，而且这是有意的设计：conf 和 C API 都没有办法再添加信任的证书，否则一份被篡改的配置就能让客户端信任任何服务器。这样一来，本地起一个自签证书的 HTTPS 服务器，`leaf` 本身是连不上的。

`leaf-plugin-verify` 是一个仅供开发使用的工具（在 `leaf-e2e` crate 里，不会进入任何客户端）。它以库的方式链接 leaf，把本地 CA 交给和客户端完全相同的下载代码，所以可以用本地服务器验证整条链路：

| 子命令 | 作用 |
|---|---|
| `serve` | 在 `https://127.0.0.1:8443` 上提供插件文件，可以按需制造故障（慢速、内容损坏、卡住、404） |
| `render` | 把插件的 url、sha256、size 填进 conf 模板 |
| `prefetch` | 下载 conf 里的插件，把 App 通过 C API 回调收到的每个事件打印出来；退出码与 `leaf_prefetch_plugins` 的返回值一致 |
| `run` | 像客户端一样从 conf 启动 leaf；可以信任本地 CA，也可以把一个插件 DLL 注册为内置插件来模拟移动端 |

## 0. 准备

下面的命令都在仓库根目录的 PowerShell 里执行。需要开 **3 个终端**，分别记为 A、B、C。

```powershell
cargo build -p leaf-cli                            # leaf.exe：用来跑测试服务器、检查 conf 语法
cargo build -p leaf-e2e --bin leaf-plugin-verify   # 验证工具
cargo build -p shadowsocks-cabi-rs                 # 用来验证的插件
New-Item -ItemType Directory -Force target\verify | Out-Null
```

为了少打字，在**每个终端**里都定义一下：

```powershell
$v = ".\target\debug\leaf-plugin-verify.exe"
```

验证用的配置模板在 `docs/plugin-verification/` 下：

| 文件 | 用途 |
|---|---|
| `server.json` | 一个原生 leaf shadowsocks 服务器，监听 `127.0.0.1:8388` |
| `client-desktop.conf.in` | Windows 客户端的 conf：插件用 url 下载 |
| `client-mobile.conf.in` | 移动端的 conf：`builtin=shadowsocks-rs`，同时带 url 作为回退 |
| `client-builtin-only.conf` | 只写了 builtin、没有回退的 conf |
| `client-typo.conf` | `[Plugin]` 里把 `sha256` 拼错了的 conf |

验证用的流量路径是：`curl` → 客户端 socks `127.0.0.1:1080` → shadowsocks 插件 → 服务器 `127.0.0.1:8388` → `example.com`。需要能访问互联网。

## 1. 自动化测试（可选，但建议先跑）

```powershell
cargo test -p leaf --features plugin-fetch --lib
cargo test -p leaf-ffi --lib --features plugin-fetch,plugin-socks5-c
cargo test -p leaf-e2e --test e2e -- --tag fetch
cargo test -p leaf-e2e --test e2e -- builtin
```

**期望**：全部 `test result: ok`。后面几步是把这些测试覆盖的行为用手再过一遍。

## 2. 启动测试服务器（终端 A）

```powershell
.\target\debug\leaf.exe -c docs\plugin-verification\server.json
```

**期望**：最后两行是

```
INFO leaf::app::inbound::network_listener: listening tcp 127.0.0.1:8388
INFO leaf::app::inbound::network_listener: listening udp 127.0.0.1:8388
```

这个终端保持运行到验证结束。

## 3. 启动插件下载服务器（终端 B）

```powershell
& $v serve target\debug\shadowsocks_cabi_rs.dll --ca-out target\verify\plugin-ca.pem
```

**期望**：

```
serving on https://127.0.0.1:8443 (mode: ok)
CA certificate: target\verify\plugin-ca.pem

  https://127.0.0.1:8443/shadowsocks_cabi_rs.dll
    sha256=e0eb7847...6f66, size=2585600

requests (Ctrl-C to stop):
```

之后每来一个请求，这里会多一行 `GET ... -> 200 (... bytes)`。**后面很多步骤都要看这里有没有新请求**，这是判断"有没有下载"的依据。

## 4. 生成客户端配置（终端 C）

```powershell
& $v render docs\plugin-verification\client-desktop.conf.in target\verify\client-desktop.conf --file ss=target\debug\shadowsocks_cabi_rs.dll
& $v render docs\plugin-verification\client-mobile.conf.in target\verify\client-mobile.conf --file ss=target\debug\shadowsocks_cabi_rs.dll
Select-String -CaseSensitive "^ss" target\verify\client-*.conf
```

**期望**：

```
client-desktop.conf: ss = url=https://127.0.0.1:8443/shadowsocks_cabi_rs.dll, sha256=e0eb...6f66, size=2585600
client-mobile.conf:  ss = builtin=shadowsocks-rs, url=https://127.0.0.1:8443/shadowsocks_cabi_rs.dll, sha256=e0eb...6f66, size=2585600
```

## 5. conf 语法检查

```powershell
.\target\debug\leaf.exe -T -c target\verify\client-desktop.conf
.\target\debug\leaf.exe -T -c docs\plugin-verification\client-typo.conf
```

**期望**：第一条输出 `ok`；第二条报错并以非 0 退出：

```
plugin [ss]: unknown key [sha-256]; expected builtin, path, url, sha256 or size
```

验证点：`[Plugin]` 段遇到不认识的 key 直接报错，而不是悄悄跳过。拼错的 `sha256` 如果被忽略，校验就等于没做。

## 6. 预下载并显示进度

```powershell
Remove-Item -Recurse -Force target\verify\cache -ErrorAction SilentlyContinue
& $v prefetch -c target\verify\client-desktop.conf --cache-dir target\verify\cache --ca target\verify\plugin-ca.pem
$LASTEXITCODE
```

**期望**：

```
  0.001s  [1/1] ss           QUEUED    0.00 MiB / 2.47 MiB   all 0.00 MiB / 2.47 MiB
  0.066s  [1/1] ss           STARTED   0.00 MiB / 2.47 MiB   all 0.00 MiB / 2.47 MiB
  0.168s  [1/1] ss           PROGRESS  2.02 MiB / 2.47 MiB   all 2.02 MiB / 2.47 MiB
  0.172s  [1/1] ss           DONE      2.47 MiB / 2.47 MiB   all 2.47 MiB / 2.47 MiB

result: ok -- every plugin is in the cache
cache target\verify\cache:
  e0eb7847...6f66\shadowsocks_cabi_rs.dll  (2585600 bytes)
0
```

终端 B 多了一行 `GET /shadowsocks_cabi_rs.dll -> 200 (2585600 bytes)`。

验证点：

- 第一条事件就知道总大小（来自 conf 里的 `size`），App 可以一开始就画出进度条。
- 事件顺序是 `QUEUED → STARTED → PROGRESS → DONE`。
- `PROGRESS` 每 100ms 最多报一次。本地下载太快，所以只看到一条；第 10 步的慢速模式能看到连续的进度。
- 缓存按 `<sha256>\<文件名>` 存放。

## 7. 缓存命中不访问网络

再执行一次同样的命令：

```powershell
& $v prefetch -c target\verify\client-desktop.conf --cache-dir target\verify\cache --ca target\verify\plugin-ca.pem
```

**期望**：只有一条事件：

```
  0.092s  [1/1] ss           CACHED    0.00 MiB / 2.47 MiB   all 0.00 MiB / 0.00 MiB
```

终端 B **没有**新请求。

## 8. 从缓存启动客户端并走流量

终端 C：

```powershell
& $v run -c target\verify\client-desktop.conf --cache-dir target\verify\cache --ca target\verify\plugin-ca.pem
```

再开一个终端（或者先把 `run` 放到一个新窗口里）：

```powershell
curl.exe -x socks5h://127.0.0.1:1080 -s -o NUL -w "HTTP %{http_code}`n" http://example.com
```

**期望**：

- `curl` 输出 `HTTP 200`。
- 客户端日志里有 `loading plugin library plugin_path=...\cache\e0eb...\shadowsocks_cabi_rs.dll tag=SS pinned=true`，说明插件是从缓存加载的，并且加载时又按 sha256 校验了一次。
- 终端 B **没有**新请求：启动时没有重新下载。

按 Ctrl-C 停掉客户端。

## 9. 不预下载，启动时自动下载

```powershell
Remove-Item -Recurse -Force target\verify\cache
& $v run -c target\verify\client-desktop.conf --cache-dir target\verify\cache --ca target\verify\plugin-ca.pem
```

然后同样用 `curl` 访问。

**期望**：

- 客户端日志依次出现 `plugin will be downloaded`、`downloading plugin`、`downloaded plugin plugin=ss bytes=2585600`，之后才开始监听 1080。
- 终端 B 多了一行 `GET`。
- `curl` 输出 `HTTP 200`。

验证点：App 忘了预下载也能启动，代价只是启动时要等下载完成。Ctrl-C 停掉客户端。

## 10. 故障场景

这一步反复切换服务器模式：在终端 B 按 Ctrl-C，再用 `--mode` 重新启动。然后在终端 C 清空缓存、执行预下载。

每次预下载之前都执行：

```powershell
Remove-Item -Recurse -Force target\verify\cache -ErrorAction SilentlyContinue
```

每个场景的最后，工具都会列出缓存目录的内容。**所有失败场景的缓存都必须是 `(empty)`**：失败时不能留下临时文件，也不能留下没通过校验的文件。

### 10.1 慢速下载，中途取消

终端 B：`& $v serve target\debug\shadowsocks_cabi_rs.dll --ca-out target\verify\plugin-ca.pem --mode slow`

终端 C：

```powershell
& $v prefetch -c target\verify\client-desktop.conf --cache-dir target\verify\cache --ca target\verify\plugin-ca.pem --cancel-after 1000000
```

**期望**：`PROGRESS` 连续增长，大约每 0.1 秒一条；超过 1 MB 后回调返回 false：

```
  4.132s  [1/1] ss           PROGRESS  0.97 MiB / 2.47 MiB   all 0.97 MiB / 2.47 MiB
           -> cancelling: 1015808 bytes have arrived

result: cancelled (exit 11)
cache target\verify\cache:
  (empty)
```

`--cancel-after` 模拟的是 App 的回调返回 false，对应 C API 的 `ERR_CANCELLED`（11）。

### 10.2 内容被篡改

终端 B 用 `--mode corrupt`（最后一个字节被改掉）。终端 C 执行预下载（去掉 `--cancel-after`）。

**期望**：

```
  0.167s  [1/1] ss           FAILED    2.47 MiB / 2.47 MiB   all 2.47 MiB / 2.47 MiB
           error: sha256 mismatch: expected e0eb...6f66, found 9d1e...5dd2

result: 1 plugin(s) failed (exit 10)
cache target\verify\cache:
  (empty)
```

### 10.3 文件不存在

终端 B 用 `--mode missing`。

**期望**：`QUEUED` 之后直接 `FAILED`，错误是 `HTTP 404 Not Found from [https://127.0.0.1:8443/shadowsocks_cabi_rs.dll]`，退出码 10，缓存为空。

### 10.4 不受信任的服务器

终端 B 用 `--mode ok`。终端 C 执行预下载，但**去掉 `--ca`**：

```powershell
& $v prefetch -c target\verify\client-desktop.conf --cache-dir target\verify\cache
```

**期望**：`error: TLS handshake with 127.0.0.1:8443: invalid peer certificate: UnknownIssuer`，退出码 10。

这一步证明前面能下载成功，完全是因为显式信任了本地 CA；真实客户端没有这个入口。

### 10.5 服务器卡住：心跳和超时

终端 B 用 `--mode stall`（发一半就不再发送）。终端 C：

```powershell
& $v prefetch -c target\verify\client-desktop.conf --cache-dir target\verify\cache --ca target\verify\plugin-ca.pem --timeout 5
```

**期望**：进度停在一半，之后大约每秒重复一条同样的 `PROGRESS`（这是心跳），5 秒时超时：

```
  2.506s  [1/1] ss           PROGRESS  1.23 MiB / 2.47 MiB   all 1.23 MiB / 2.47 MiB
  4.005s  [1/1] ss           PROGRESS  1.23 MiB / 2.47 MiB   all 1.23 MiB / 2.47 MiB
  5.006s  [1/1] ss           PROGRESS  1.23 MiB / 2.47 MiB   all 1.23 MiB / 2.47 MiB
  5.011s  [1/1] ss           FAILED    1.23 MiB / 2.47 MiB   all 1.23 MiB / 2.47 MiB
           error: timed out after 5s
```

验证点：下载卡住时回调仍然会被调用，App 因此有机会取消；否则 App 只能干等。

## 11. 模拟移动端：内置插件优先

先在终端 B 按 Ctrl-C **停掉下载服务器**，让下载不可能成功。然后在终端 C 用移动端 conf 启动，把插件 DLL 注册为内置插件 `shadowsocks-rs`，并且**不给缓存目录**：

```powershell
Remove-Item Env:PLUGIN_CACHE_DIR -ErrorAction SilentlyContinue
& $v run -c target\verify\client-mobile.conf --builtin shadowsocks-rs=target\debug\shadowsocks_cabi_rs.dll
```

再用 `curl` 访问。

**期望**：

- 输出 `registered builtin [shadowsocks-rs] from target\debug\shadowsocks_cabi_rs.dll`。
- 日志里有 `loaded builtin plugin descriptor plugin_path=builtin:shadowsocks-rs`。
- `curl` 输出 `HTTP 200`。

验证点：conf 里虽然写了 url，但下载服务器没开、也没有缓存目录，客户端照样能用，说明内置插件优先、根本没有尝试下载。

> `--builtin` 的做法是从 DLL 里取出描述符函数再注册。真实 App 里，这个函数是链接进来的，由 `leaf-ffi` 在第一次调用时自动注册，或者由 App 调用 `leaf_register_plugin` 注册。对 leaf 来说两者没有区别：它拿到的都只是一个函数指针。真正的静态链接在第 14 步验证。

Ctrl-C 停掉客户端。

## 12. 没有内置时回退到 url

终端 B 用 `--mode ok` 重新启动下载服务器。终端 C 用**同一份**移动端 conf 启动，但**不注册内置插件**：

```powershell
Remove-Item -Recurse -Force target\verify\cache -ErrorAction SilentlyContinue
& $v run -c target\verify\client-mobile.conf --cache-dir target\verify\cache --ca target\verify\plugin-ca.pem
```

**期望**：日志出现 `downloaded plugin plugin=ss bytes=2585600`，终端 B 多一行 `GET`，`curl` 输出 `HTTP 200`。

验证点：同一份 conf 在没有内置插件的客户端（比如 Windows）上自动改为下载。Ctrl-C 停掉客户端。

## 13. 只写 builtin、又没有内置时

```powershell
& $v run -c docs\plugin-verification\client-builtin-only.conf
```

**期望**：启动失败，报错写明缺的是哪个插件、这个客户端有哪些：

```
leaf failed to start: outbound [SS] uses builtin plugin [shadowsocks-rs], which this client was not built with (it has: none); give the plugin a path or a url to fall back on
```

（启动失败前还会打印一段 `start with options: ...`，那是 debug 构建自带的输出，可以忽略。）

## 14. 真正的静态链接（移动端的构建方式）

只有其它语言写的插件才会编进宿主；Rust 写的协议应该直接做成 leaf 的 outbound，所以 Rust 插件不提供静态链接。这里把 C 插件编进 `leaf-ffi` 的静态库：

```powershell
cargo rustc -p leaf-ffi --lib --crate-type staticlib --features plugin-socks5-c
```

查看静态库里和插件描述符有关的符号：

```powershell
& "C:\Program Files\LLVM\bin\llvm-nm.exe" --defined-only target\debug\leaf.lib | Select-String -CaseSensitive " T .*(get_descriptor|leaf_register_plugin)"
```

**期望**（地址省略）：

```
T leaf_plugin_socks5_c_get_descriptor
T leaf_register_plugin
```

验证点：

- **没有**一个叫 `leaf_plugin_get_descriptor` 的全局符号。
- C 插件的描述符函数被 `LEAF_PLUGIN_STATIC_NAME` 改名成了 `leaf_plugin_socks5_c_get_descriptor`，所以多个 C 插件链进同一个 App 不会符号冲突。

确认它在二进制里能注册、并通过描述符校验：

```powershell
cargo test -p leaf-ffi --lib --features plugin-socks5-c builtin
```

**期望**：`socks5_c_is_built_in`、`leaf_register_plugin_codes` 全部 ok。

在 macOS 上装好 iOS/Android 工具链后，可以用同样的 feature 构建真正的移动端库：

```sh
cargo build -p leaf-ffi --release --target aarch64-apple-ios --features plugin-socks5-c
cargo build -p leaf-ffi --release --target aarch64-linux-android --features plugin-socks5-c   # 需要 Android NDK
```

## 15. 真实环境（可选）

最后用真实的 HTTPS 地址和客户端实际使用的构建走一遍，这里不再借助测试工具：

1. 把 `shadowsocks_cabi_rs.dll` 上传到一个有正规证书的 HTTPS 地址（CDN、对象存储、GitHub Release 都可以）。
2. 生成 conf：

   ```powershell
   & $v render docs\plugin-verification\client-desktop.conf.in target\verify\client-real.conf --file ss=target\debug\shadowsocks_cabi_rs.dll --base-url https://你的域名/路径
   ```

3. 构建带下载功能的 leaf，指定缓存目录后启动：

   ```powershell
   cargo build -p leaf-cli --features leaf/plugin-fetch
   $env:PLUGIN_CACHE_DIR = "$PWD\target\verify\real-cache"
   .\target\debug\leaf.exe -c target\verify\client-real.conf
   ```

4. 用 `curl` 访问，确认 `HTTP 200`，并且 `real-cache` 下出现 `<sha256>\shadowsocks_cabi_rs.dll`。

如果不设置 `PLUGIN_CACHE_DIR`，启动会失败并提示设置它。这是有意的：缓存目录必须由 App 指定，leaf 不会自己挑一个。

## 附录 A：退出码

`prefetch` 的退出码和 `leaf_prefetch_plugins` 的返回值相同：

| 退出码 | 含义 |
|---|---|
| 0 | 所有插件都已在缓存中 |
| 2 | 配置错误：conf 有误、url 不是 https、没有 sha256、没有缓存目录等 |
| 10 | 至少一个插件下载失败；成功的那些已经进了缓存 |
| 11 | 被回调取消 |

## 附录 B：常见问题

- **`binding 127.0.0.1:8443` 失败**：8443 端口被占用。换一个端口，`serve --port 9443`，同时给 `render` 加 `--base-url https://127.0.0.1:9443`。
- **`cargo build` 报 `failed to remove file ...leaf-plugin-verify.exe`**：Windows 上正在运行的程序文件不能被覆盖。先停掉所有 `serve` 和 `run`，再重新编译。
- **`curl` 超时**：确认终端 A 的服务器还在运行，并且本机能访问 `example.com`。
- **第 11 步报 `no cache directory was given`**：说明内置插件没生效、客户端试图去下载。检查 `--builtin` 的名字是否和 conf 里的 `builtin=` 一致。

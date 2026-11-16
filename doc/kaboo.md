# Kaboo 使用说明

`kaboo-server` 和 `kaboo-cli` 是基于本仓库 frp 核心的专用启动入口。
保留开源来源、版本、构建信息与运行日志，不提供隐身或规避检测能力。

访问路径为：

```text
普通 SS 客户端
    → kaboo-server 的 SS 端口（TCP / UDP）
    → 校验内置证书的 TLS 1.3 隧道
    → kaboo-cli 内置的 Shadowsocks aes-256-gcm 服务
    → 从 kaboo-cli 所在网络访问目标
```

SS 服务随客户端进程运行，无需另装 SS 服务。其本地监听仅绑定 loopback。
服务端只允许导出初始化时指定的 SS 端口，不开放任意远端端口配置。

## 文件和首次启动

运行程序不接收命令行参数：

```sh
./kaboo-server
./kaboo-cli
```

`-c`、`--config`、`--version` 等参数均返回错误。版本与源码信息通过启动日志
和本机管理页面提供，Go 构建元数据也保留。两个程序不加载 frp INI / TOML / YAML。

管理页面只监听 `127.0.0.1`。默认端口为 server 17651、cli 17652；若已被占用，
自动选择一个可用本机端口。请打开各自启动日志中的完整 Web URL。
URL 的随机管理口令每次启动更新，仅该 URL 可访问管理 API。
若程序运行在远程服务器，可通过 SSH 本地端口转发访问管理页面。

1. 启动 `kaboo-server`，进入首次初始化页面。
2. 填入隧道监听 IP / 端口以及 SS 对外端口。需要外部客户端连接时，监听 IP
   使用相应网卡地址或 `0.0.0.0`。隧道端口与 SS 端口必须不同。
3. 选择独立提供的 `kaboo-server.provision.enc` 加密私钥部署包，填入单独保管的
   `activation.key` 内容。部署包位于程序同目录时可不选文件。
4. 点击“加密保存并启动”。再点击“显示连接信息”，复制 Kaboo 配对码。
5. 启动 `kaboo-cli`，在其本机 Web 页面填入服务端实际地址、隧道端口与配对码，
   点击保存。页面会显示证书验证和 TCP / UDP 转发就绪状态。
6. 普通 SS 客户端使用服务端的 SS 端口、`aes-256-gcm` 和页面生成的 SS 链接。
   如果链接中显示 `SERVER_IP`，替换为服务端实际可达地址。

初始化后的设置自动加载，不再需要输入部署包解锁码或配对码。
Web 页面可修改连接地址；改变 SS 入口端口后需重新导出配对码并导入 Kaboo 客户端。
此专用界面管理固定的 SS 反向代理；普通 frp 的任意代理规则仍由原 frps / frpc
入口提供，原入口的加密配置功能见 [encrypted-config.md](encrypted-config.md)。

## 独立地址文件

首次 Web 初始化后生成 `endpoint.json`，只接受两个字段：

```json
{
  "ip": "203.0.113.10",
  "port": 7000
}
```

server 的 `ip` 是监听地址，cli 的 `ip` 是服务端地址（也可使用域名）。
可以在 Web 中修改，也可停机后编辑此文件再启动。不要放入密钥或 frp 字段。
真实路径显示在管理页面和启动日志中。

默认设置目录是操作系统用户配置目录下的 `kaboo/server` 或 `kaboo/client`。
`settings.enc` 保存加密后的隧道认证密钥、SS 密钥以及仅服务端拥有的 TLS 私钥。
本地解密主密钥存放在用户配置目录下独立的 `kaboo-private/<role>/master.key`。
目录权限为 0700、密钥与配置文件权限为 0600。
需要隔离实例或测试时，可用环境变量 `KABOO_HOME=/absolute/path` 指定实例目录，
其下分别使用 `state/` 和 `private/`；它不是命令行参数。

排障时可临时设置 `KABOO_LOG_LEVEL=debug` 或 `trace`，默认保留普通运行日志。

## 内置证书与私钥边界

公开信任证书通过 Go embed 编译进两个程序，源码中仅包含公开证书。
所有控制、TCP 数据和承载 UDP 的工作连接均要求 TLS 1.3、校验该信任证书及
固定服务名 `kaboo-server`，并协商 `kaboo/1`。不使用 `InsecureSkipVerify`，
不回退到明文或旧 TLS。隧道另有独立随机认证密钥；SS 使用独立随机密码。

服务端私钥不编译进程序，也不放入 Git。私钥部署包使用 AES-256-GCM 加密，
解锁码是独立随机 32 字节密钥；二者不可一起公开分发。导入后，私钥再次使用
本机主密钥加密保存在 `settings.enc`。客户端不接收服务端私钥。

此版本公开信任证书有效期为构建时生成起 10 年。一个证书对应一个部署身份；
不同服务端若需独立身份，应离线生成新的证书/部署包，并同时重建配套客户端。
证书轮换需要重新构建和分发程序，不通过 Web 任意替换信任锚。

配对码包含隧道和 SS 凭据，是秘密，不是公开二维码。管理页面只对带随机口令
的本机访问开放，修改 API 检查同源，页面与 API 均禁止缓存。
无 TLS 的本机 Web 应经本机浏览器或经过认证的 SSH 端口转发访问。

静态加密保护配置副本，不保护能同时读取本机主密钥和密文的账户，也不保护
root 或进程内存。备份、迁移时分别保管 `settings.enc` 和主密钥；丢失主密钥
不能自动恢复设置，程序不会自动抹掉或重置已有密文。

## 构建

普通构建只使用已提交的公开证书，不生成、读取或复制部署私钥：

```sh
./hack/build-kaboo.sh /absolute/path/to/output
```

输出 Linux amd64 和 macOS arm64 包，各包含 `kaboo-server`、`kaboo-cli`、
本文、许可证与构建信息，另有 SHA-256 校验文件。新管理页面直接嵌入 Go 程序，
不依赖 Node、单独 Web 服务或上游 Dashboard 的构建产物。

为新的独立部署重新生成信任身份时，使用离线构建工具，三个目标必须不存在：

```sh
go run ./cmd/kaboo-provision \
  --trust pkg/kaboo/trust/ca.pem \
  --provision /private/output/kaboo-server.provision.enc \
  --activation /separate/private/location/activation.key
```

已有 `ca.pem` 需要先备份并明确移走后才能重新生成。该操作会改变信任身份，
必须重新构建两端；不要在常规构建中自动执行。离线工具本身不是交付的运行程序。
生成的私钥、部署包和解锁码不应提交或上传到公开 Release。

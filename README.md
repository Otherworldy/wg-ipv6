# proxy-sticky

SOCKS5 出口代理：按用户名区分出口 IPv6 策略。

- `43b3277e`（默认账号）→ **随机出口**：每个新连接从 `/64` 池中随机 SNAT（nftables `numgen`）
- `43b3277e.<id>`（任意后缀）→ **粘性出口**：首次连接分配固定 `/128`，写入 `state/accounts.json`，之后对该账号永远固定

不需要预写账号：`users[]`、nft 规则、接口地址全部动态化。密码保持共享（RFC1929 用户名密码认证）。

## 设计

```
client --vmess/vless/trojan/...--> sing-box 入口 --SOCKS5(账号=<入口>)--> proxy-sticky --[bind 源地址+SO_MARK+SO_BINDTODEVICE]--> wg 接口 --> 上游
client --SOCKS5------------------------^  (用户名/共享密码)
```

- 入口协议不限于 SOCKS5：sing-box 承接的任意入站（vmess/vless/trojan/ss/hysteria2/...）
  都能通过一条 socks5 出站回链到本程序，出口仍由本程序的账号逻辑决定。
  被封 IP 的机器可以给入站加 ws+tls 走 CDN，本程序不感知传输层。
- 入口 → 账号映射（`--migrate-singbox` 或管理页「改入口 → 出口」自动完成）：
  入站 `vless-x` + 隧道 `route64` → 出站 `ps-vless-x`（socks5 127.0.0.1:listen，
  用户名 `43b3277e.route64.vless-x`）→ 该入口固定一个粘性 `/128`。
  注意：回链只跑 TCP，UDP（hysteria2/tuic 的 QUIC 目标、QUIC 网站）不经过本程序。
- 粘性账号：`store.Allocate()` 分配 `sticky_start` 起递增的 `/128` → `ip addr replace` 到 wg 接口（幂等、缓存）→ 连接绑定该地址 + `mark` + `bindtodevice` → nft 表第一条规则 `saddr != base → accept` 跳过随机 SNAT
- 默认账号（`ephemeral: true`，默认）：**每个新连接从整个 `/64` 随机生成 IID**（crypto/rand 64bit，`2^64` 空间），rtnetlink 直调 `ip addr add`（无 fork 纯 syscall）→ 绑定该随机地址 → 连接关闭后延迟 `ephemeral_grace`（默认 60s）删除，覆盖 conntrack 回程窗口。nft 表 `saddr != base → accept` 规则天然放行，不再经过 numgen 池；addr 冲突（EEXIST）自动重试，netlink 异常回退基础地址保可用
- 默认账号（`ephemeral: false`）：绑定隧道基础地址 `base`（如 `::2`）→ nft 表 numgen 随机 SNAT（有限池）
- 多份 WG：每份 conf 一个隧道，独立 `table`/`mark`/`pool`/nft 表；用户名 `43b3277e.<tunnel>.<id>` 指定隧道

## 目录

```
config.yaml            # 配置（从 config.yaml.example 复制）
wg/<name>.conf         # 原始 wg-quick 配置（可多份）
state/accounts.json    # 粘性映射（自动生成）
runtime/*.nft          # 生成的 nftables 规则
backups/               # 接管旧表时的备份
```

## 快速开始

```bash
cp config.yaml.example config.yaml
# 编辑 password / tunnels[*].wg_conf / mark / table

sudo ./bin/proxy-sticky --config config.yaml --install   # 自动装缺包 + 加载规则 + 启动
curl --socks5 用户名:密码@127.0.0.1:26184 https://api64.ipify.org
```

常用命令：

```bash
sudo ./bin/proxy-sticky --config config.yaml --check      # 校验配置、预览 nft 规则
sudo ./bin/proxy-sticky --config config.yaml --dry-run    # 干跑：只打印规则与计划
sudo ./bin/proxy-sticky --config config.yaml --migrate-singbox   # 把绑了隧道的 sing-box 入口改成经本机 SOCKS5 出站（每入口一个粘性账号）
sudo ./bin/proxy-sticky --config config.yaml --unregister '43b3277e.acc9'
```

## 非 SOCKS 入口（vmess / vless / trojan / ss / hysteria2 ...）

入口协议由 sing-box 负责，本程序只做出口。管理页「改入口」里的「粘性 IPv6 出口」选中某条隧道后：

- 生成出站 `ps-<入站tag>`：`type: socks`、`server: 127.0.0.1`、`server_port: <listen 端口>`、
  `username: <default_account>.<隧道>.<入站tag>`、`password: <共享密码>`
- 路由规则把该入站指向这个出站，回收不再使用的旧 `direct + bind_interface` 出站

老环境升级：`sudo ./bin/proxy-sticky --config config.yaml --migrate-singbox`，会先备份
`/etc/sing-box/conf/*.json` 到 `backups/`，校验通过后重写并重启 sing-box。
同样逻辑会在管理页改 `listen` 端口时自动跑一次（否则入口出站还指旧端口）。

限制与行为：

- 回链只跑 TCP：`network: "tcp"`，经本程序的入口不支持 UDP（QUIC/HTTP3、DoH、UDP 游戏）
- 入口账号不会被 `account_idle_ttl` 回收（每轮重新扫描 sing-box 出站跳过），
  否则闲置后出口 `/128` 会变
- 一个入口一个账号（`<default_account>.<隧道>.<入站tag>`），删掉入口后它的记录仍留在
  `state/accounts.json`，由 `account_idle_ttl` 自然回收
- 隧道名不能包含 `.`，否则账号会被解析到默认隧道上

被封 IP 的机器：入站自己加 `tls` + `transport: ws`（或在前面套 CDN），分享链接照常用；
回链始终是本机 loopback，与对外传输层无关。

### 批量发节点

管理页链路卡片上的「批量节点」（或「改入口」里的同名按钮）：

- 选 1-100 份，按入口类型自动生成凭据：
  `vless/vmess` = uuid（继承入口的 `flow`），`tuic` = uuid+密码，
  `trojan/hysteria2/anytls` = 密码，`socks` = 用户名+密码
- 每份凭据配一条独立 `type: socks` 出站 + 一条 `auth_user` 分流规则，
  账号 `<default_account>.<隧道>.<入口>-<短ID>` ⇒ **每个节点固定一个 `/128`**
  （sing-box 的 `auth_user` 匹配 `users[].name` / socks 的 `username`，不是 uuid）
- 分享链接用该入口在 `url.txt` 里的模板行克隆（换凭据与备注）并追加回 `url.txt`
- 结果弹窗一次性展示，可一键复制；凭据写进 sing-box 配置（会重启一次 sing-box）
- 前提：入口已绑「粘性 IPv6 出口」；`shadowsocks` 等类型暂不支持批量
- 重复给同一入口批量生成会继续追加用户；目前没有删单个节点的接口，
  需要手改 `inbounds.json` / `outbounds.json` / `route.json`（并删 `url.txt` 对应行）
- 给入口重新选一次「出口」时，已发出的节点会跟着换隧道（每用户出站与
  `auth_user` 规则都保留）；只有「解绑出口」才会清掉分流规则，节点退回共享出口
- socks 类型的链接需要 `url.txt` 里能取到对外主机名，取不到会直接报错
- 改入口端口会把 `url.txt` 里同端口的所有行（含已发出的节点）一起改过去
- 「添加入口」里选「＋ 新建 socks 入口」可以从零建一个 socks 入站
  （只有 socks 支持，其它类型要 TLS 证书/传输参数，得克隆现有入口）；
  新建时会给一个默认账号（用户名 = 入口名）并把链接写进 `url.txt`
- 单入口最多 500 个用户

## 接管旧环境（route64_random 表）

启动时若检测到旧表 `ip6 route64_random`（之前 numgen/固定 SNAT 生产表），会：
1. `nft list table` 备份到 `backups/route64_random.<ts>.nft`
2. 删除旧表并加载程序生成的 `route64_proxy_<name>`

旧表与程序表同 hook 都会触发，粘性源地址会被旧表随机 SNAT，所以必须二选一。`route64_random-up/down` 脚本仍被 wg-quick 的 PostUp 调用的话，重启 wg 会重新生成旧表——请将 `/etc/wireguard/<name>.conf` 替换为程序生成版本（`EnsureUp` 自动完成，原文件备份 `.bak`）。

## 资源占用

- 单二进制、纯 Go；连接转发 32KB 缓冲池（sync.Pool）
- 每连接 2 goroutine + 1 次 syscall 级 `ip addr replace`（粘性地址缓存，仅首次）
- 默认 4096 并发上限（s.mem：`max_conns`）
- 空闲超时 `idle_timeout` 默认 10m

## 依赖安装

```bash
sudo ./bin/proxy-sticky --install    # 检查/安装 iproute2 nftables wireguard-tools + 内核模块
```

构建（需要 Go 1.22+）：

```bash
./build.sh
```

# proxy-sticky

SOCKS5 出口代理：按用户名区分出口 IPv6 策略。

- `43b3277e`（默认账号）→ **随机出口**：每个新连接从 `/64` 池中随机 SNAT（nftables `numgen`）
- `43b3277e.<id>`（任意后缀）→ **粘性出口**：首次连接分配固定 `/128`，写入 `state/accounts.json`，之后对该账号永远固定

不需要预写账号：`users[]`、nft 规则、接口地址全部动态化。密码保持共享（RFC1929 用户名密码认证）。

## 设计

```
client --SOCKS5(用户名/共享密码)--> proxy-sticky --[bind 源地址+SO_MARK+SO_BINDTODEVICE]--> wg 接口 --> 上游
```

- 粘性账号：`store.Allocate()` 分配 `sticky_start` 起递增的 `/128` → `ip addr replace` 到 wg 接口（幂等、缓存）→ 连接绑定该地址 + `mark` + `bindtodevice` → nft 表第一条规则 `saddr != base → accept` 跳过随机 SNAT
- 默认账号：绑定隧道基础地址 `base`（如 `::2`）→ nft 表第二条规则 `meta mark → snat to numgen random mod N map` 每个新连接随机出口
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
sudo ./bin/proxy-sticky --config config.yaml --unregister '43b3277e.acc9'
```

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

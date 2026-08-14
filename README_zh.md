<p align="center">
  <a href="https://github.com/Watfaq/clash-rs">
    <img width="200" src="https://github.com/Watfaq/clash-rs/assets/543405/76122ef1-eac8-478a-8ba4-ca5e54f8e272">
  </a>
</p>

<h1 align="center">ClashRS</h1>

<div align="center">

基于自定义协议、规则分流的网络代理软件（Rust 实现）。

[English](README.md) · **简体中文**

[![CI](https://github.com/Watfaq/clash-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/Watfaq/clash-rs/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/Watfaq/clash-rs/graph/badge.svg?token=ZQK5WB63KR)](https://codecov.io/gh/Watfaq/clash-rs)

</div>

> [!NOTE]
> **本 Fork 分支特性与说明**：
> - ⚡ **性能与稳定性优化**：针对核心路径进行了大量重构与性能调优，重写了部分协议栈实现。
> - 🚀 **新功能特性**：新增 Shadowsocks UOT (UDP-over-TCP)、域名嗅探（TLS SNI / HTTP Host / QUIC SNI） 等。
> - 🪶 **Minimal 轻量版本**：默认精简，不包含 TUN 模式及以下协议：`SSH`、`WireGuard`、`Tailscale`、`Shadowquic`、`Tor`。
> - 📖 **完整配置参考**：请参阅 [full.yaml](https://github.com/CHKayanami/clash-rs/blob/master/clash-bin/tests/data/config/full.yaml)。

## ✨ 特性

- 🌈 **灵活的路由分流**：基于源/目标 IP、域名、GeoIP、GeoSite、Rule-Set 等规则进行精确流量调度。
- 📦 **本地防污染 DNS**：支持 UDP / TCP / DoH / DoT / DoH3 上游，并可作为本地 DNS 服务器对外暴露服务；支持 Fake-IP、策略分流（`nameserver-policy`）与纯 IP 反查。
- 🔍 **域名嗅探（Domain Sniffer）**：从 TCP/UDP 首包中零拷贝解密提取 TLS SNI、HTTP Host、QUIC Initial SNI，无缝支持透明代理域名还原与分流规则匹配。
- ⚙️ **丰富的出站协议支持**：AnyTLS / Hysteria2 / Shadowquic / Shadowsocks / Socks5(TCP/UDP) / SSH / Tailscale / Tor(onion) / Trojan / Tuic / VLess / VMess / WireGuard(userspace)，支持各类底层传输（gRPC / TLS / HTTP/2 / WebSocket / REALITY 等）。
- 🔀 **多样化入站模式**：HTTP、SOCKS5、Mixed、Shadowsocks、AnyTLS、Redir、TProxy 以及全平台 TUN (utun) 透明代理。
- 🌍 **动态远程规则/节点加载**：支持订阅与 Rule-Provider 动态更新。
- 🎵 **分布式追踪**：集成 Jaeger Tracing。

## 📡 协议支持

### 入站协议 (Inbounds)

| 类型 | 说明 | 备注 |
|------|-------------|-------|
| `http` | HTTP 代理 | |
| `socks` | SOCKS5（TCP + UDP） | |
| `mixed` | 单端口混合 HTTP + SOCKS5 | |
| `shadowsocks` | Shadowsocks 入站（支持多用户） | `shadowsocks` 特性 |
| `anytls` | AnyTLS 入站（支持多用户与 GFW 回落伪装） | |
| `tun` | TUN 虚拟网卡设备（透明代理） | 全平台支持 |
| `tproxy` | TProxy 透明代理（TCP + UDP） | Linux；`tproxy` 特性 |
| `redir` | TCP 重定向 (Redirect) | Linux；`redir` 特性 |
| `tunnel` | 流量固定目标转发隧道 | |

### 出站协议 (Outbounds)

| 协议 | 传输层 / 伪装 | 备注 |
|----------|-----------|-------|
| `direct` | 直连 | |
| `reject` | 拦截丢弃 | |
| `ss` | plain · obfs-http · obfs-tls · v2ray-plugin-ws · v2ray-plugin-ws-tls · shadow-tls | `shadowsocks` 特性 |
| `socks5` | plain TCP · TLS | |
| `anytls` | TLS | |
| `trojan` | TLS · WebSocket+TLS · gRPC+TLS | |
| `vmess` | TCP · TCP+TLS · WebSocket+TLS · H2+TLS · gRPC+TLS | |
| `vless` | TLS · WebSocket+TLS · H2+TLS · gRPC+TLS · REALITY | |
| `wireguard` | UDP (userspace) | `wireguard` 特性 |
| `hysteria2` | QUIC · obfs-salamander | |
| `tuic` | QUIC (bbr / cubic / new_reno) | `tuic` 特性 |
| `shadowquic` | QUIC · over-stream | `shadowquic` 特性 |
| `ssh` | SSH 隧道 | `ssh` 特性 |
| `tor` | 洋葱路由 (Onion) | `onion` 特性 (`plus` 构建) |
| `tailscale` | Mesh VPN | `tailscale` 特性 (`plus` 构建) |

## 🖥 运行环境支持

- Linux
- macOS
- Windows
  - 需要将与系统架构对应的 [wintun.dll](https://wintun.net/) 文件复制到可执行程序同级目录下，并以管理员身份运行。
- iOS
  - [![ChocLite App Store](https://developer.apple.com/app-store/marketing/guidelines/images/badge-example-preferred_2x.png)](https://apps.apple.com/by/app/choclite/id6467517938)
  - TestFlight 访问：[TestFlight](https://testflight.apple.com/join/cLy4Ub5C)

## 💰 赞助商
- [Fast Access Cloud](https://fast-access.cloud/)

## 📦 安装

### 使用图形界面 (GUI)

- [Clash Nyanpasu](https://github.com/LibNyanpasu/clash-nyanpasu)

### 下载预编译二进制文件

前往 Releases 页面获取：https://github.com/Watfaq/clash-rs/releases

### Docker 镜像

https://github.com/Watfaq/clash-rs/pkgs/container/clash-rs

### 本地编译

编译依赖：

* cmake (3.29 或更新版本)
* libclang ([LLVM](https://github.com/llvm/llvm-project/releases/tag/llvmorg-16.0.4))
* [nasm](https://www.nasm.us/pub/nasm/releasebuilds/2.16/win64/) (Windows)
* protoc (用于 GeoData protobuf 代码生成)
* [pre-commit](https://pre-commit.com/) (用于管理 git hooks)

```shell
$ pipx install pre-commit
$ pre-commit install

$ cargo build
```

## 🔨 使用说明

### 示例配置

sample.yaml:

```yaml
port: 7890
```

### 运行
```shell
-> % ./target/debug/clash-rs -c sample.yaml
```

### 命令行帮助
```shell
-> % ./target/debug/clash-rs -h
Usage: clash-rs [OPTIONS]

Options:
  -d, --directory <DIRECTORY>      设置工作目录（相对路径解析基准）
  -c, --config <FILE>              指定配置文件 [默认: config.yaml] [短别名: f]
  -t, --test-config                测试配置有效性并退出
  -v, --version                    输出 clash-rs 版本并退出 [短别名: V]
  -l, --log-file <LOG_FILE>        额外输出日志到文件
      --help-improve               启用崩溃报告以协助改进 clash
      --controller-ipc <IPC_PATH>  指定外部控制器的 IPC 路径 [别名: --ext-ctl-pipe, --ext-ctl-unix]
      --compatibility              启用兼容模式（保持与 mihomo 一致的行为）
  -h, --help                       输出帮助信息
```

## FFI 跨平台开发

### 编译 Apple 平台 Framework

为 iOS 与 macOS 构建 framework：

```shell
git clone https://github.com/Watfaq/clash-rs.git
cd clash-rs
chmod +x scripts/build_apple.sh
./scripts/build_apple.sh
```

该命令将在 `build` 目录下生成 `clashrs.xcframework`。

## 🔗 相关链接

- [文档手册 (User Manual)](https://watfaq.gitbook.io/clashrs-user-manual/)
- [完整配置参考 (Config Reference)](https://watfaq.github.io/clash-rs/)
- [路线图 (Roadmap)](https://github.com/Watfaq/clash-rs/issues/59)

## 🤝 贡献参与

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [Telegram 用户群](https://t.me/thisisnotclash)

## ❤️ 致敬与灵感来源
- [Dreamacro/clash](https://github.com/Dreamacro/clash)
- [eycorsican/leaf](https://github.com/eycorsican/leaf)

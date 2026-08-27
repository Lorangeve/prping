# Windows 7 构建与平台细节

> 从 CLAUDE.md 拆出的详细规则。CLAUDE.md 只保留摘要，改动 Windows 构建/Npcap/ICMP
> 相关代码或配方时先读本文件。

## Win7 基线目标

Rust 1.78 起官方将 `*-pc-windows-*` 目标最低支持提升到 **Windows 10**；Win7 需用官方的
Win7 基线目标（Tier 3）+ nightly `-Z build-std` 构建；首选 `x86_64-win7-windows-msvc`
（x64）与 `i686-win7-windows-msvc`（x86/32 位）双产物（xwin 链接）。

### 构建命令

```bash
rustup toolchain install nightly --profile minimal
rustup component add rust-src --toolchain nightly
cargo install cargo-xwin                        # 自动下载 Windows SDK
XWIN_ARCH=x86,x86_64 cargo +nightly xwin build -Z build-std --target x86_64-win7-windows-msvc --release
# → target/x86_64-win7-windows-msvc/release/prping.exe   （x64 版）
XWIN_ARCH=x86,x86_64 cargo +nightly xwin build -Z build-std --target i686-win7-windows-msvc --release
# → target/i686-win7-windows-msvc/release/prping.exe     （x86/32 位版）
```

### 构建说明

- **MSVC 是唯一支持路径**：`packet --raw` 的 Npcap 绑定（pcap crate + wpcap.lib/windows.lib）
  只对接 MSVC 导入库，mingw-w64 没有 wpcap 导入库。GNU 备选配方（`build-windows-gnu`/
  `build-win7-gnu` 等）已从 justfile 移除。
- MSVC 目标统一静态链接 CRT/C++ 运行库（`.cargo/config.toml` 配 `crt-static`）：产物
  不依赖 `vcruntime140.dll`/`msvcp140.dll`/`ucrtbase.dll`，Win7 实测仅依赖
  `ADVAPI32`/`KERNEL32`/`ntdll`；链接器加 `/ignore:4099` 抑制 xwin 静态库缺 PDB 的
  LNK4099 噪音（链接本身成功）。
- Win7 基线目标为 Tier 3（官方不自动构建测试）；MSVC 版由 CI `win7-build` job 产出。
- **所有 xwin 配方必须统一 `XWIN_ARCH=x86,x86_64`**（cargo-xwin 默认只下载
  x86_64+aarch64 库、DONE 标记只记最近一次架构，不统一会反复重下载；**裸跑
  `cargo xwin env`/`build` 不设 XWIN_ARCH 会按默认架构集触发整包重下载，若中途被杀
  会留下截断 CAB → 解包残缺（缺 kernel32.lib 等核心库）→ 链接报
  `could not open 'kernel32.lib'`，需 `rm -rf ~/.cache/cargo-xwin/xwin` 后带
  XWIN_ARCH 重新下载**）。
- **windows.lib 缺口**：windows-sys 0.36 的 WinSock 等模块带 `#[link(name="windows")]`，
  标准 `x86_64-pc-windows-msvc` 目标由 `windows_x86_64_msvc` crate 自动提供该伞状
  导入库，但自定义 win7 目标（非精确目标名）不会——`just fetch-npcap-sdk` 会从
  crates.io 的 `windows_{x86_64,i686}_msvc` crate 拉取 x64/x86 版 windows.lib 放入
  SDK Lib 目录（pcap build.rs 的 LIBPCAP_LIBDIR link-search 全目标生效），漏拉则 lld
  报 `could not open 'windows.lib'`；MSVC 配方前置 `windows-deps` 守卫检查
  wpcap.lib/windows.lib 四件套，缺失自动补拉 `fetch-npcap-sdk`（可手动强制重跑）。

## 构建 / cap / 跨平台检查

- `build.rs` 自动配置 `.cargo/run-with-cap.sh` runner 设置 cap_net_raw（仅
  `cargo run`/`cargo test` 生效，且需免密 sudo 否则静默失败）；直接跑
  `target/{debug,release}/prping` 用 `just cap`（sudo setcap cap_net_raw+ep，对已存在
  的 debug/release 产物执行；rebuild 后 cap 失效需重跑）；各平台产物配方在
  `justfile`（`just build-release` / `build-win7` / `build-win7-32` / `build-windows` /
  `test` / `lint` 等）。
- 跨平台编译检查: `cargo check --target x86_64-pc-windows-msvc`（Windows 路径需本机
  验证时用临时 CARGO_HOME）。
- 分发：`just publish` 把 eng_lib 与 examples 复制为 `target/release/{lib/,examples/}`
  （与二进制同目录分发）；共享配方 `dist DIR` 由各 Windows 构建配方与 publish 以
  **依赖编排**方式组合（`build-win7: build-win7-impl (dist "…")`，`*_impl` 为
  `[private]` 私有构建步骤、不进 `--list`），产物目录与 exe 同侧带 lib/ 与 examples/。

## Npcap 绑定与 wpcap 延迟加载（packet --raw）

- 绑定：pcap crate 2.x 仅 `[target.'cfg(windows)'.dependencies]`；链接需 Npcap SDK 的
  wpcap.lib + windows-sys 0.36 的 windows.lib（`just fetch-npcap-sdk` 一并拉取 + 配方
  内置 LIBPCAP_LIBDIR，见「windows.lib 缺口」条）。**Windows 本机也适用**：`just test`
  配方在 Windows（`OS=Windows_NT`）下自动经 `windows-deps` 就位 SDK 四件套并设
  `LIBPCAP_LIBDIR`（pcap build.rs 有 `rerun-if-env-changed=LIBPCAP_LIBDIR`，链接直接
  命中 wpcap.lib；`fetch-npcap-sdk` 的 unzip 缺失时降级用 PowerShell 解压）。
- **wpcap.dll 延迟加载**（`.cargo/config.toml` 三 MSVC 目标统一 `/DELAYLOAD:wpcap.dll` +
  `delayimp.lib`——delay-load helper `__delayLoadHelper2` 由 MSVC 工具链的
  delayimp.lib 提供，lld-link 不像 link.exe 会自动拉取，须显式链接）——Windows 加载器
  启动时只解析普通导入表，未装 Npcap 的机器不再弹「wpcap.dll is missing」、其余功能
  照常；只有 `packet --raw` 需要 Npcap，`rawwin.rs::ensure_wpcap` 在该入口先
  LoadLibrary 探测（成功则 DLL 驻留、后续经 delay-load thunk 命中；失败给
  `errors.no_npcap` 友好报错，绝不走到 delay-load SEH 异常 0xC06D007E 崩溃路径）。
  装 Npcap 的机器（Win7 需 KB4474419 + KB4490628，SHA-2 驱动签名）不受影响。
- 未安装 Npcap 的机器上其它功能照常运行，只有 `packet --raw` 会提示需要 Npcap
  （https://npcap.com）。

## Windows ICMP ping（Iphlpapi.dll）

- Windows ICMP ping 使用 Iphlpapi.dll（`IcmpSendEcho2`/`Icmp6SendEcho2`），通过
  windows-sys 0.59 的 `Win32_NetworkManagement_IpHelper` feature 正常链接
  （Iphlpapi.dll 是系统组件，必定存在）。
- macOS/Linux 上 ICMP 使用 raw socket，需 root 或 `cap_net_raw`。
- IP_STATUS 码映射：IP_REQ_TIMED_OUT=11010 → 超时、IP_TTL_EXPIRED_*=11013/11014 → TTL 超时、
  IP_DEST_*_UNREACH=11002..11005/11018/11019 → 不可达。
- v4 TTL 取自 ICMP_ECHO_REPLY.Options（应答结构 x86=28B/x64=40B，`#[repr(C)]` + 布局单测），
  v6 无 TTL 字段显示 0。
- 阻塞调用放 `smol::unblock`（超时由 API 内部 timeout 参数保证）。
- **v4 `-s` 源绑定不支持**（IcmpSendEcho2 无源地址参数，一次性橙色提示；v6 经 SourceAddress 支持）。
- raw socket 只留给 MTU 探测 / ICMP 路由跟踪（`errors.raw_socket_windows` 说明 Win7 RTM 限制）。
- `rawwin.rs` 兼容层：`send_raw_bytes` 在 `#[cfg(windows)]` 下整体委托
  `rawwin::send_raw_full`——设备选择（`--iface` 匹配 Npcap 设备名/描述；回环目标自动
  选 Npcap Loopback Adapter）、裸 IPv4 自动以太网封装（src MAC = GetIfEntry 接口 MAC；
  dst MAC = GetBestRoute 下一跳 + GetIpNetTable ARP 缓存，未命中先发 1 字节 UDP 触发
  ARP，再失败广播兜底警告）、裸 IPv6 仅回环（非回环需 ND 邻居解析，Win7 无
  GetIpNetTable2，报错）。
- `--wait` 先开抓包句柄再发送（避免漏抓快速回包）并按方向过滤自己刚发的帧——direction
  过滤在部分 Npcap/虚拟网卡上不生效，`wait_reply` 另跳过与发送帧**逐字节相同**的帧
  （Npcap 会把刚注入的帧回读给抓包句柄，否则 `--wait` 会把自己的 echo request 误匹配
  成应答——假阳性 RTT ~0.1ms）。

## Windows 测量路径（connect / ICMP / raw socket）

- **connect 不走 socket2::connect_timeout**（其内部用 **WSAPoll**，而 WSAPoll 在
  **Win7 RTM/SP0 对非阻塞 socket 有缺陷**——connect 轮询返回 WSAEINVAL 10022，SP1
  才修复；curl 也因此禁用 WSAPoll）→ `util.rs::win_connect_select` 用经典 `select()`
  等待可写 + `SO_ERROR` 取结果（含 Win7 SP0 在内各版本正确），Unix 仍走 socket2 原实现。
- **Windows ICMP ping 走 Iphlpapi.dll（`ping/icmpwin.rs`）**：Windows 的 raw ICMP socket
  （`socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)`）需管理员权限（通常 WSAEACCES 10013），且
  **Win7 RTM（SP0，tcpip.sys 6.1.7600）管理员权限下创建也返回 WSAEINVAL 10022**（Win10
  正常）——`ping` 子命令在 Windows 上一律经 `IcmpSendEcho2`/`Icmp6SendEcho2`
  （Iphlpapi.dll，同系统 ping.exe 的实现，无需管理员、各版本可用）：使用
  windows-sys 0.59 的 `Win32_NetworkManagement_IpHelper` feature（函数链接
  `"iphlpapi.dll"`，非伞状 `windows.lib`，xwin SDK 自带 `Iphlpapi.lib`）；IP_STATUS 码映射（IP_REQ_TIMED_OUT=11010 → 超时、
  IP_TTL_EXPIRED_*=11013/11014 → TTL 超时、IP_DEST_*_UNREACH=11002..11005/11018/11019
  → 不可达），v4 TTL 取自 ICMP_ECHO_REPLY.Options（应答结构 x86=28B/x64=40B，
  `#[repr(C)]` + 布局单测），v6 无 TTL 字段显示 0；阻塞调用放 `smol::unblock`（超时由
  API 内部 timeout 参数保证）；**v4 `-s` 源绑定不支持**（IcmpSendEcho2 无源地址参数，
  一次性橙色提示；v6 经 SourceAddress 支持）。raw socket 只留给 MTU 探测 / ICMP 路由
  跟踪（`errors.raw_socket_windows` 说明 Win7 RTM 限制）。
- **Windows raw 收包无外层 IP 头**：v6 同理 v4——Windows 的 raw ICMP socket 收包不含
  外层 IP 头（实测：Time Exceeded 全丢、echo reply 因 type 0 被误读为 IHL=0 碰巧能中）
  → `util::icmp_offset_v4` version nibble==4 框架，trace 与 ping 的 v4 解析全部适配
  （旧 `buf[40..]`/固定 ihl 假设只在 Linux 成立）；IPv6 raw socket 收包不含 IPv6 头
  （Linux pskb_pull），用首字节 version nibble==6 探测框架兼容带头平台。
- `trace --tcp` 在 Windows 禁止 raw TCP → 报错（`errors.tcp_trace_windows`，ICMP trace
  不受影响）；`trace --udp` 全平台可用（Windows 支持普通 UDP + raw ICMP，无 unix gate）。

## 跨平台编码细节

### windows-sys 类型与 API 路径

- 平台相关代码统一使用 `windows-sys`（微软官方），非第三方 `winapi`
- 平台条件编译使用 `#[cfg(windows)]` / `#[cfg(unix)]`
- Windows API 类型定义使用 `windows_sys::Win32::*` 命名空间
- `SOCKADDR_IN` / `SOCKADDR_IN6` 通过 `use windows_sys::Win32::Networking::WinSock::{SOCKADDR_IN, SOCKADDR_IN6, ...}` 导入（非 `winapi` 路径）
- `windows-sys` 类型路径注意大小写：`WinSock` 非 `Winsock`
- `windows-sys` 0.59 的 `SOCKADDR_IN` 保留 `S_un.S_addr` union 访问方式（与 `winapi` 一致），但类型路径从 `winapi::shared::ws2def` 变为 `windows_sys::Win32::Networking::WinSock`；字段路径需严格匹配 crate 版本（当前 0.59）

### CStr 与指针类型转换

- `getnameinfo` 参数类型为 `*mut u8`（非 `*mut i8`），与 `winapi` 的 C 兼容类型不同
- `host.as_mut_ptr() as *mut u8`（`windows-sys` 用 `u8`，C ABI 用 `i8`）
- `CStr::from_ptr` 仍用 `*const i8`（Rust 标准库与 C ABI 一致）
- `CStr::from_ptr(host.as_ptr() as *const i8)` 从 `MaybeUninit<u8>` 数组取指针时需 `as *const i8`（`CStr` 要求有符号字符）

### 跨平台通用规则

- `t!` 宏导入使用 `use rust_i18n::t;`（不可用 `crate::t!`，跨平台编译时可能解析失败）
- 避免仅在 `#[cfg(unix)]` 块内定义通用函数（如 `rand_u32`），应提取到平台无关位置或添加 `#[cfg(windows)]` 对应实现
- `rand_u32()` 等通用函数不应添加平台限制，除非确实只在单一平台使用
- Windows 专属代码（如 `trace_tcp` 不支持）使用 `anyhow::bail!(t!("..."))` 报错

### Windows 编译注意事项

- `trace_tcp` 在 Windows 上不支持（`#[cfg(windows)]` 报错）
- Windows 交叉编译需 `XWIN_ARCH=x86,x86_64` 统一指定架构（避免反复重下载 SDK），详见 `justfile` 注释

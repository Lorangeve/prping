# prping 构建配方（just）
#
# 用法：
#   just                 # debug 构建（等同 just build）
#   just build-release   # Linux/macOS 本机 release
#   just build-win7      # Windows 7 兼容版（nightly + build-std）
#   just build-windows   # 全部 Windows 产物
#   just test / lint / fmt-check
#
# 依赖：
#   - Windows MSVC（Linux）：需 xwin（cargo install cargo-xwin，自动下载 SDK）
#   - Win7 目标：nightly + rust-src（rustup toolchain install nightly --profile minimal
#     && rustup component add rust-src --toolchain nightly）
#
# 沙箱/只读 registry 环境：export CARGO_HOME=<可写目录> 后运行（just 继承环境变量）。

default: build

# ── 常规构建 ──────────────────────────────────────────────

# Debug 构建（本机）
build:
    cargo build

# Release 构建（本机）
build-release:
    cargo build --release

# ── Linux 运行权限 ─────────────────────────────────────────

# 给本机 Linux 二进制授予 cap_net_raw（raw socket 必需：ping/MTU/trace/包引擎
# 全部走 SOCK_RAW）。对 debug/release 中已存在的产物执行；`cargo build` 会覆盖
# 二进制、cap 随之失效——重建后需重跑。免密 sudo 已配时 `.cargo/run-with-cap.sh`
# 会在 `cargo run`/`cargo test` 时自动做同样的事。
# 用法：just cap
[script]
cap:
    if ! command -v setcap >/dev/null 2>&1; then
        echo "setcap 不可用（装 libcap），或改用 sudo 运行 prping"
        exit 1
    fi
    applied=0
    for b in target/debug/prping target/release/prping; do
        if [ -x "$b" ]; then
            sudo setcap cap_net_raw+ep "$b" && { echo "✓ $b"; applied=1; } \
                || echo "✗ $b 授权失败（sudo 需要密码）"
        fi
    done
    if [ "$applied" -eq 0 ]; then
        echo "未找到构建产物：先 just build 或 just build-release"
        exit 1
    fi

# ── Windows 交叉编译（Linux 上；Windows 本机直接跑 build-release） ──
# XWIN_ARCH=x86,x86_64：cargo-xwin 默认只下载 x86_64+aarch64 库，且 DONE 标记
# 只记录最近一次架构——不统一指定会导致换架构时反复重下载；本项目只用 x86/x86_64。
#
# Windows 目标链接 pcap crate（--pkg --raw 的 Npcap 绑定）需要 Npcap SDK 的
# wpcap.lib 与 windows-sys 0.36 的 windows.lib（x64/x86）：先 `just fetch-npcap-sdk`
# 一并拉取，构建时加 LIBPCAP_LIBDIR=target/npcap-sdk/Lib/x64（i686 用 Lib/）。
# wpcap.dll 已延迟加载（/DELAYLOAD:wpcap.dll，见 .cargo/config.toml）：未装 Npcap 的
# 机器上其它功能照常运行，只有 `packet --raw` 会报“需要 Npcap”；rawwin.rs 的
# ensure_wpcap() 在该入口先探测、给友好报错（不会触发 delay-load 异常崩溃）。

# Windows MSVC 链接前置：检查 wpcap.lib / windows.lib（x64/x86）四件套，
# 缺失时自动运行 fetch-npcap-sdk 补拉（幂等：文件齐全则跳过）。
# [script]：整段按脚本执行（默认 sh -eu），可写多行 if
[script]
windows-deps:
    if [ ! -f target/npcap-sdk/Lib/x64/wpcap.lib ] || \
       [ ! -f target/npcap-sdk/Lib/x64/windows.lib ] || \
       [ ! -f target/npcap-sdk/Lib/wpcap.lib ] || \
       [ ! -f target/npcap-sdk/Lib/windows.lib ]; then
        echo "缺少 Windows 链接库：自动运行 fetch-npcap-sdk…"
        just fetch-npcap-sdk
    fi

# Windows MSVC x86_64 构建步骤（私有：仅作依赖被编排，见 build-windows-msvc）
[private]
build-windows-msvc-impl: windows-deps
    XWIN_ARCH=x86,x86_64 LIBPCAP_LIBDIR=target/npcap-sdk/Lib/x64 \
        cargo xwin build --target x86_64-pc-windows-msvc --release

# Windows MSVC x86_64（先构建，再把 eng_lib/examples 分发到产物目录）
build-windows-msvc: build-windows-msvc-impl (dist "target/x86_64-pc-windows-msvc/release")

# Windows 7 x64 构建步骤（私有；官方 Win7 基线目标 MSVC，Linux 需 xwin，
# 首次自动下载 SDK；.cargo/config.toml 已配 crt-static 静态链接 CRT/C++ 运行库）
[private]
build-win7-impl: windows-deps
    XWIN_ARCH=x86,x86_64 LIBPCAP_LIBDIR=target/npcap-sdk/Lib/x64 \
        cargo +nightly xwin build -Z build-std --target x86_64-win7-windows-msvc --release

# Windows 7 x64（先构建，再把 eng_lib/examples 分发到产物目录）
build-win7: build-win7-impl (dist "target/x86_64-win7-windows-msvc/release")

# Windows 7 x86 构建步骤（私有；32 位 MSVC，同上）
[private]
build-win7-32-impl: windows-deps
    XWIN_ARCH=x86,x86_64 LIBPCAP_LIBDIR=target/npcap-sdk/Lib \
        cargo +nightly xwin build -Z build-std --target i686-win7-windows-msvc --release

# Windows 7 x86（先构建，再把 eng_lib/examples 分发到产物目录）
build-win7-32: build-win7-32-impl (dist "target/i686-win7-windows-msvc/release")

# 全部 Windows 产物
build-windows: build-windows-msvc build-win7 build-win7-32

# 把 eng_lib 与 examples 复制为产物目录的 lib/ 与 examples/
# （与二进制同目录分发）。用法：just dist target/release
dist DIR:
    mkdir -p {{DIR}}/lib {{DIR}}/examples
    cp -r eng_lib/* {{DIR}}/lib/
    cp -r examples/* {{DIR}}/examples/

# 下载并解压 Windows 链接库（Npcap SDK 的 wpcap.lib + windows-sys 0.36 的
# windows.lib x64/x86）。用法：Windows 目标构建前先跑一次 `just fetch-npcap-sdk`。
# 细节：
# 1) Npcap SDK（wpcap.lib/Packet.lib 供 Windows 目标链接；URL 随 Npcap 版本更新）
# 2) windows.lib（取自 crates.io 的 windows_{x86_64,i686}_msvc crate；版本须与
#    Cargo.lock 中 windows-sys 0.36 匹配）——windows-sys 0.36 的 WinSock 等模块带
#    #[link(name="windows")]，标准 x86_64-pc-windows-msvc 目标会由该 crate 自动提供
#    windows.lib，但自定义 win7 目标（x86_64/i686-win7-windows-msvc，非精确目标名）
#    不会——须手动放进 LIBPCAP_LIBDIR 目录（pcap build.rs 的 link-search 全目标生效），
# 否则 lld 报 "could not open 'windows.lib'"。用法：Windows 目标构建前先跑一次
# `just fetch-npcap-sdk`
fetch-npcap-sdk:
    mkdir -p target/npcap-sdk
    curl -L -o target/npcap-sdk.zip https://npcap.com/dist/npcap-sdk-1.15.zip
    unzip -o target/npcap-sdk.zip -d target/npcap-sdk
    curl -sL -o target/windows_x86_64_msvc.crate https://static.crates.io/crates/windows_x86_64_msvc/windows_x86_64_msvc-0.36.1.crate
    curl -sL -o target/windows_i686_msvc.crate https://static.crates.io/crates/windows_i686_msvc/windows_i686_msvc-0.36.1.crate
    mkdir -p target/.wlibs
    tar xzf target/windows_x86_64_msvc.crate -C target/.wlibs
    cp target/.wlibs/windows_x86_64_msvc-0.36.1/lib/windows.lib target/npcap-sdk/Lib/x64/windows.lib
    tar xzf target/windows_i686_msvc.crate -C target/.wlibs
    cp target/.wlibs/windows_i686_msvc-0.36.1/lib/windows.lib target/npcap-sdk/Lib/windows.lib
    rm -rf target/.wlibs target/windows_x86_64_msvc.crate target/windows_i686_msvc.crate
    @echo "SDK 就绪：target/npcap-sdk/Lib/{x64/,}wpcap.lib + windows.lib（构建时 LIBPCAP_LIBDIR 已由配方设置）"

# 全部产物（本机 + Windows 各目标）
build-all: build-release build-windows

# 本机 release 构建步骤（私有：仅作依赖被编排，见 publish）
[private]
publish-impl:
    cargo build --release -p prping

# 发布：本机 release 构建 + eng_lib/examples 复制为 target/release/{lib/,examples/}。
# 发布后从 target/release/ 运行 prping --eng x.pkt 会自动命中 lib/（默认库目录）
publish: publish-impl (dist "target/release")
    @echo "发布产物：target/release/{prping,lib/,examples/}"

# ── 质量检查 ──────────────────────────────────────────────

# 格式化（写入）
fmt:
    cargo fmt

# 格式化检查
fmt-check:
    cargo fmt --check

# 原语文档同步检查（Claude Code hook 同款：分派原语 ↔ builtin_docs(--ls/LSP) ↔ GRAMMAR.md §4.6）
doc-sync-check:
    scripts/claude-hooks/primitive-docs-check.sh --check

# Lint（clippy 零警告 + 原语文档同步门禁）
lint: doc-sync-check
    cargo clippy --all-targets --workspace -- -D warnings

# 全部测试（prping 万用表 + packet-dsl 引擎）
test:
    cargo test --all-targets --workspace

# rustdoc 生成检查
doc:
    cargo doc --no-deps --workspace

# 快速编译检查
check:
    cargo check --workspace

# ── packet-dsl（.pkt 网络包构建 DSL）────────────────────────

# packet 发送有效性测试（python -m http.server + tcpdump 验证）
test-pkt:
    python3 pktlang_tests/test_raw_effectiveness.py

# 冒烟测试（tcpdump 验证各子命令基本工作）
test-smoke:
    python3 pktlang_tests/test_smoke_tcpdump.py

# 引擎分析测试（engine 子命令：分析/--ls/--hex/--pcap）
test-engine:
    python3 pktlang_tests/test_engine.py

# 配方测试（多步 .pktl：global/extract/sniffer/--fuzz/--out）
test-recipe:
    python3 pktlang_tests/test_recipe.py

# 协议测试（ARP/UDP/ICMP/TCP/IPv6/QUIC 原始包 via tcpdump）
test-protocol:
    python3 pktlang_tests/test_protocols.py

# 全部 pktlang 测试
test-all-pkt: test-pkt test-smoke test-engine test-recipe test-protocol

# DSL 测试（解析器/语义/求值/golden 字节）
test-dsl:
    cargo test -p packet-dsl

# DSL golden 测试（字节级）
test-dsl-golden:
    cargo test -p packet-dsl --test golden

# 解析 .pkt 文件并打印 AST（调试）
dsl-ast:
    cargo run -p packet-dsl --example ast_dump

# ── 基准 ──────────────────────────────────────────────────

# 本地回环吞吐/延迟基准（需先 build-release）
bench:
    bash scripts/bench.sh target/release/prping

# ── 产物与清理 ────────────────────────────────────────────

# 列出各平台产物
artifacts:
    @ls -lh target/release/prping \
        target/x86_64-pc-windows-msvc/release/prping.exe \
        target/x86_64-win7-windows-msvc/release/prping.exe \
        target/i686-win7-windows-msvc/release/prping.exe 2>/dev/null || true

clean:
    cargo clean

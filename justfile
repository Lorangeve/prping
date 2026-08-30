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

# Release 构建（本机）；Windows 原生 MSVC：pcap crate 静态链接 wpcap.lib
# （--pkg --raw 的 Npcap 绑定），自动经 windows-deps 就位 SDK 并设 LIBPCAP_LIBDIR。
[script]
build-release:
    if [ "${OS:-}" = "Windows_NT" ]; then
        just windows-deps
        export LIBPCAP_LIBDIR=target/npcap-sdk/Lib/x64
    fi
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

# ── Linux 交叉编译（需对应工具链；本机同架构直接用 build-release） ──
# Linux 32-bit（i686）。需 gcc-multilib（Ubuntu: sudo apt install gcc-multilib）
# 或交叉工具链（Debian: sudo apt install gcc-i686-linux-gnu）
build-linux-32:
    rustup target add i686-unknown-linux-gnu
    cargo build --release --target i686-unknown-linux-gnu

# Linux ARM 32-bit（armv7hf）。需交叉工具链：
#   sudo apt install gcc-arm-linux-gnueabihf
build-linux-arm:
    rustup target add armv7-unknown-linux-gnueabihf
    cargo build --release --target armv7-unknown-linux-gnueabihf

# Linux ARM64（aarch64）。需交叉工具链：
#   sudo apt install gcc-aarch64-linux-gnu
build-linux-arm64:
    rustup target add aarch64-unknown-linux-gnu
    cargo build --release --target aarch64-unknown-linux-gnu

# 全部 Linux 产物（本机 + 交叉）
build-linux-all: build-release build-linux-32 build-linux-arm build-linux-arm64

# 全平台产物（本机 + Windows + Linux 交叉）
build-all: build-release build-windows build-linux-all
# （与二进制同目录分发）。用法：just dist target/release
# web/ = prping web 前端构建产物副本（二进制内已 rust-embed 内嵌同一份，
# 此目录便于直接以任意静态服务器分发 UI 或核对产物）。
dist DIR:
    mkdir -p {{DIR}}/lib {{DIR}}/examples
    cp -r eng_lib/* {{DIR}}/lib/
    cp -r examples/* {{DIR}}/examples/
    if [ -f frontend/dist/index.html ]; then mkdir -p {{DIR}}/web && cp -r frontend/dist/. {{DIR}}/web/; else echo "警告: frontend/dist 未构建（just build-web），产物目录不含 web/"; fi

# ── Web 编辑器（prping web）───────────────────────────────

# 构建前端（SolidJS + CodeMirror）到 frontend/dist。cargo build 会经
# prping-core/build.rs 自动执行同一构建（pnpm 优先、npm 兜底）；此配方用于
# 单独刷新前端产物或 CI 缓存预热。开发模式：`prping web --port 8788` 起后端，
# `pnpm --dir frontend dev` 起 Vite 热更新（/ws 与 /config.json 已配代理）。
[script]
build-web:
    cd frontend
    if command -v pnpm >/dev/null 2>&1; then
        pnpm install --silent
        pnpm build
    else
        npm install --no-audit --no-fund --silent
        npm run build
    fi
    echo "前端产物：frontend/dist/（cargo build 自动内嵌进 prping 二进制）"

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
    # Windows Git Bash 若缺 unzip（Linux/macOS 均有），降级用 PowerShell 解压
    unzip -o target/npcap-sdk.zip -d target/npcap-sdk \
        || powershell -NoProfile -Command "Expand-Archive -Path target/npcap-sdk.zip -DestinationPath target/npcap-sdk -Force"
    curl -sL -o target/windows_x86_64_msvc.crate https://static.crates.io/crates/windows_x86_64_msvc/windows_x86_64_msvc-0.36.1.crate
    curl -sL -o target/windows_i686_msvc.crate https://static.crates.io/crates/windows_i686_msvc/windows_i686_msvc-0.36.1.crate
    mkdir -p target/.wlibs
    tar xzf target/windows_x86_64_msvc.crate -C target/.wlibs
    cp target/.wlibs/windows_x86_64_msvc-0.36.1/lib/windows.lib target/npcap-sdk/Lib/x64/windows.lib
    tar xzf target/windows_i686_msvc.crate -C target/.wlibs
    cp target/.wlibs/windows_i686_msvc-0.36.1/lib/windows.lib target/npcap-sdk/Lib/windows.lib
    rm -rf target/.wlibs target/windows_x86_64_msvc.crate target/windows_i686_msvc.crate
    @echo "SDK 就绪：target/npcap-sdk/Lib/{x64/,}wpcap.lib + windows.lib（构建时 LIBPCAP_LIBDIR 已由配方设置）"

# 本机 release 构建步骤（私有：仅作依赖被编排，见 publish）
[private]
publish-impl:
    cargo build --release -p prping

# 发布：本机 release 构建 + eng_lib/examples 复制为 target/release/{lib/,examples/}。
# 发布后从 target/release/ 运行 prping --eng x.pkt 会自动命中 lib/（默认库目录）
publish: publish-impl (dist "target/release")
    @echo "发布产物：target/release/{prping,lib/,examples/,web/}"

# ── 质量检查 ──────────────────────────────────────────────

# 格式化（写入）
fmt:
    cargo fmt

# 格式化检查
fmt-check:
    cargo fmt --check

# 本机 check（快速编译检查）
check:
    cargo check --workspace

# Linux pcap feature 语法检查（`server -v` 抓包的 pcap 多设备路径 + `packet --raw`
# 注入；需系统安装 libpcap-dev，如 Ubuntu: sudo apt install libpcap-dev）
check-pcap:
    cargo check --workspace --features pcap
    cargo clippy --all-targets --workspace --features pcap -- -D warnings

# 检查全部平台语法（本机 + Windows + Linux 交叉）
# 工具链缺失 → 跳过；编译错误 → 汇总后 exit 1（此前 || echo 把编译错误
# 与工具链缺失混为一谈，且恒 exit 0，门禁形同虚设）
[script]
check-all:
    set -euo pipefail
    echo "=== check-all: 全平台语法检查 ==="
    echo ""
    fail=0
    run_check() {
        local name="$1" toolcheck="$2"
        shift 2
        echo "── $name ──"
        if ! eval "$toolcheck" >/dev/null 2>&1; then
            echo "[跳过] 工具链未安装"
            echo ""
            return 0
        fi
        if ! "$@" 2>&1; then
            echo "✗ $name 编译失败"
            fail=1
        fi
        echo ""
    }
    run_check "本机（x86_64-unknown-linux-gnu）" "true" cargo check --workspace
    run_check "Windows MSVC x86_64" "command -v cargo-xwin" cargo xwin check --target x86_64-pc-windows-msvc --workspace
    run_check "Windows 7 x64" "command -v cargo-xwin && rustup toolchain list | grep -q nightly" cargo +nightly xwin check -Z build-std --target x86_64-win7-windows-msvc --workspace
    run_check "Windows 7 x86" "command -v cargo-xwin && rustup toolchain list | grep -q nightly" cargo +nightly xwin check -Z build-std --target i686-win7-windows-msvc --workspace
    run_check "Linux 32-bit" "rustup target list --installed | grep -q i686-unknown-linux-gnu || rustup target add i686-unknown-linux-gnu >/dev/null 2>&1" cargo check --target i686-unknown-linux-gnu --workspace
    run_check "Linux ARM 32-bit" "rustup target list --installed | grep -q armv7-unknown-linux-gnueabihf || rustup target add armv7-unknown-linux-gnueabihf >/dev/null 2>&1" cargo check --target armv7-unknown-linux-gnueabihf --workspace
    run_check "Linux ARM64" "rustup target list --installed | grep -q aarch64-unknown-linux-gnu || rustup target add aarch64-unknown-linux-gnu >/dev/null 2>&1" cargo check --target aarch64-unknown-linux-gnu --workspace
    if [ "$fail" -ne 0 ]; then
        echo "=== 存在编译失败（见上方 ✗ 行）==="
        exit 1
    fi
    echo "=== 全部完成 ==="

# 原语文档同步检查（Claude Code hook 同款：分派原语 ↔ builtin_docs(--ls/LSP) ↔ GRAMMAR.md §4.6）
doc-sync-check:
    scripts/claude-hooks/primitive-docs-check.sh --check

# Lint（clippy 零警告 + 原语文档同步门禁）
lint: doc-sync-check
    cargo clippy --all-targets --workspace -- -D warnings

# 全部测试（prping 万用表 + packet-dsl 引擎）
# Windows 原生 MSVC：pcap crate 静态链接 wpcap.lib（--pkg --raw 的 Npcap 绑定），
# 先经 windows-deps 确保 Npcap SDK 四件套就位并设 LIBPCAP_LIBDIR（Linux/macOS 不需要）。
[script]
test:
    if [ "${OS:-}" = "Windows_NT" ]; then
        just windows-deps
        export LIBPCAP_LIBDIR=target/npcap-sdk/Lib/x64
    fi
    cargo test --all-targets --workspace

# rustdoc 生成检查
doc:
    cargo doc --no-deps --workspace

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
    @echo "=== prping 平台产物 ==="
    @echo ""
    @echo "── Windows ──────────────────────────────"
    @ls -lh target/x86_64-pc-windows-msvc/release/prping.exe 2>/dev/null || echo "  [未构建] just build-windows-msvc"
    @ls -lh target/x86_64-win7-windows-msvc/release/prping.exe 2>/dev/null || echo "  [未构建] just build-win7"
    @ls -lh target/i686-win7-windows-msvc/release/prping.exe 2>/dev/null || echo "  [未构建] just build-win7-32"
    @echo ""
    @echo "── Linux ────────────────────────────────"
    @ls -lh target/release/prping 2>/dev/null || echo "  [未构建] just build-release"
    @ls -lh target/i686-unknown-linux-gnu/release/prping 2>/dev/null || echo "  [未构建] just build-linux-32"
    @ls -lh target/armv7-unknown-linux-gnueabihf/release/prping 2>/dev/null || echo "  [未构建] just build-linux-arm"
    @ls -lh target/aarch64-unknown-linux-gnu/release/prping 2>/dev/null || echo "  [未构建] just build-linux-arm64"
    @echo ""
    @echo "── macOS（Intel / Apple Silicon，本机构建）──"
    @ls -lh target/release/prping 2>/dev/null | grep -q "darwin\|Mach" && ls -lh target/release/prping || true

clean:
    cargo clean

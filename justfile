# prping 构建配方（just）
#
# 用法：
#   just                 # debug 构建（等同 just build）
#   just build-release   # 本机 release
#   just build-win7      # Windows 7 兼容版（nightly + build-std）
#   just build-windows   # 全部 Windows 产物
#   just build-web       # 单独构建前端（bun + vite）
#   just test / lint / fmt-check
#
# 所有 build 配方产出完整可运行布局 {prping, lib/, examples/, UI/}
# （经 dist 资源打包；前端缺失/源码更新时经 web-dist 自动构建，无 bun/npm
# 降级为警告，PRPING_SKIP_WEB_BUILD=1 跳过）。
#
# 依赖：
#   - 前端：bun 或 node（npm 兜底）
#   - Windows MSVC（Linux/mac 交叉）：需 xwin（cargo install cargo-xwin，自动下载
#     SDK）；Windows 本机原生编译无需 xwin，且 exe 会嵌入图标（winresource 需
#     rc.exe，仅原生构建可用，见 crates/prping-cli/build.rs）
#   - Win7 目标：nightly + rust-src（rustup toolchain install nightly --profile minimal
#     && rustup component add rust-src --toolchain nightly）
#
# Web 子命令（`prping web`）由 `web` feature 门控（默认不启用，产物体积更小）。
# justfile 是项目唯一构建/检查入口：下列所有编译配方统一以 `--features prping/web`
# 启用 web 子命令，保证产物具备完整功能。个别配方（如 check-web-embed）经
# `web-embed` 隐含启用 web。
#
# 沙箱/只读 registry 环境：export CARGO_HOME=<可写目录> 后运行（just 继承环境变量），
# 或写入仓库根 .env（dotenv-load 自动加载；真实环境变量优先，.env 属本地配置不提交）。
#
# 平台标限：标注 [linux] 的配方仅 Linux 可运行/列出（其他平台 just --list 隐藏、
# 直接调用报错）；未标注配方三平台皆可用（内部按 ${OS:-} = Windows_NT 分派）。

# ── 全局设置 ──────────────────────────────────────────────

# 仓库根存在 .env 时自动加载（无 .env 不报错；本地配置勿提交——沙箱场景把
# CARGO_HOME 等写进 .env 免每次 export，真实环境变量优先于 .env）
set dotenv-load

# cargo-xwin 下载的 MSVC 库架构：默认只下载 x86_64+aarch64 且 DONE 标记只记录
# 最近一次架构，不统一指定会在换架构时反复重下载；本项目只用 x86/x86_64。
# 导出后对全部 xwin 配方（含 check-all 的 cargo xwin check）统一生效
export XWIN_ARCH := "x86,x86_64"

# 默认配方（= just build）
default: build

# ── 常规构建 ──────────────────────────────────────────────

# Debug 构建（本机）。[script] 配方不逐行回显命令；资源候选顺序见 assets.rs。
# 流程：web-dist 按需自动构建前端（无 node 降级跳过）→ cargo build →
# dist 资源打包 → target/debug 完整布局 {prping, lib/, examples/, UI/}
[script]
build: web-dist
    # Windows：pcap 依赖静态链接 wpcap.lib，与 build-release 同样的 SDK 前置
    # （build.rs 的 exe 图标嵌入在 debug 下同样生效）
    if [ "${OS:-}" = "Windows_NT" ]; then
        just windows-deps
        export LIBPCAP_LIBDIR=target/npcap-sdk/Lib/x64
    fi
    cargo build --features prping/web
    just dist target/debug

# Release 构建（本机）。Windows 原生 MSVC：pcap crate 静态链接 wpcap.lib，
# 自动经 windows-deps 就位 SDK 并设 LIBPCAP_LIBDIR → target/release 完整布局
[script]
build-release: web-dist
    if [ "${OS:-}" = "Windows_NT" ]; then
        just windows-deps
        export LIBPCAP_LIBDIR=target/npcap-sdk/Lib/x64
    fi
    cargo build --release --features prping/web
    just dist target/release

# 资源打包：lib/（← eng_lib）、examples/、UI/（← frontend/dist）同步到 DIR
# （prping 运行期从二进制同目录就近读取）；build / build-release 自动调用本配方
# 用法：just dist target/release（也可手动对任意目录执行）
[script]
dist DIR:
    mkdir -p {{DIR}}/lib {{DIR}}/examples
    cp -r eng_lib/* {{DIR}}/lib/
    cp -r examples/* {{DIR}}/examples/
    echo "lib/ 已同步: eng_lib → {{DIR}}/lib"
    echo "examples/ 已同步: examples → {{DIR}}/examples"
    if [ -f frontend/dist/index.html ]; then
        rm -rf {{DIR}}/UI && cp -r frontend/dist {{DIR}}/UI
        echo "UI 已同步: frontend/dist → {{DIR}}/UI"
    else
        echo "警告: frontend/dist 未构建（just build-web），产物目录不含 UI/"
    fi

# ── Linux 运行权限 ─────────────────────────────────────────

# 给本机二进制授予 cap_net_raw（raw socket 必需；`cargo build` 覆盖二进制后
# cap 失效需重跑；免密 sudo 时 .cargo/run-with-cap.sh 在 cargo run/test 自动做）。
# 用法：just cap（对 debug/release 已有产物执行）
[linux]
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

# ── Windows 编译（MSVC x64：Windows 本机原生 / Linux·mac 经 xwin 交叉，同配方
#    按 host 自动分派；Win7 变体恒走 xwin） ──
# XWIN_ARCH=x86,x86_64：cargo-xwin 默认只下载 x86_64+aarch64 库，且 DONE 标记
# 只记录最近一次架构——不统一指定会导致换架构时反复重下载；本项目只用 x86/x86_64。
#
# Windows 目标链接 pcap crate（--pkg --raw 的 Npcap 绑定）需要 Npcap SDK 的
# wpcap.lib 与 windows-sys 0.36 的 windows.lib（x64/x86）：windows-deps 自动经
# fetch-npcap-sdk 拉取，构建时加 LIBPCAP_LIBDIR=target/npcap-sdk/Lib/x64（i686 用 Lib/）。
# wpcap.dll 已延迟加载（/DELAYLOAD:wpcap.dll，见 .cargo/config.toml）：未装 Npcap 的
# 机器上其它功能照常运行，只有 `packet --raw` 会报“需要 Npcap”；rawwin.rs 的
# ensure_wpcap() 在该入口先探测、给友好报错（不会触发 delay-load 异常崩溃）。

# Windows MSVC 链接前置：检查 wpcap.lib / windows.lib（x64/x86）四件套。
# 缺失时自动运行 fetch-npcap-sdk 补拉（幂等：文件齐全则跳过）
[script]
windows-deps:
    if [ ! -f target/npcap-sdk/Lib/x64/wpcap.lib ] || \
       [ ! -f target/npcap-sdk/Lib/x64/windows.lib ] || \
       [ ! -f target/npcap-sdk/Lib/wpcap.lib ] || \
       [ ! -f target/npcap-sdk/Lib/windows.lib ]; then
        echo "缺少 Windows 链接库：自动运行 fetch-npcap-sdk…"
        just fetch-npcap-sdk
    fi

# 下载并解压 Windows 链接库（Npcap SDK 的 wpcap.lib + windows-sys 0.36 的
# windows.lib x64/x86）。windows-deps 会自动调用；此配方用于手动补拉。细节：
# 1) Npcap SDK（wpcap.lib/Packet.lib 供 Windows 目标链接；URL 随 Npcap 版本更新）
# 2) windows.lib（取自 crates.io 的 windows_{x86_64,i686}_msvc crate；版本须与
#    Cargo.lock 中 windows-sys 0.36 匹配）——windows-sys 0.36 的 WinSock 等模块带
#    #[link(name="windows")]，标准 x86_64-pc-windows-msvc 目标会由该 crate 自动提供
#    windows.lib，但自定义 win7 目标（x86_64/i686-win7-windows-msvc，非精确目标名）
#    不会——须手动放进 LIBPCAP_LIBDIR 目录（pcap build.rs 的 link-search 全目标生效），
#    否则 lld 报 "could not open 'windows.lib'"
# 产物：target/npcap-sdk/Lib/{x64/,}wpcap.lib + windows.lib
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

# Windows MSVC x86_64 构建步骤（私有：仅作依赖被编排，见 build-windows-msvc）。
# 按 host 分派：Windows 本机 → 原生 cargo build（rc.exe 可用，exe 嵌入图标）；
# Linux/mac → cargo xwin 交叉（无资源编译器，图标跳过仅警告）。
# [script]：if 块内含 \ 续行，just 普通配方解析不了（extra leading whitespace）
[private]
[script]
build-windows-msvc-impl: windows-deps
    if [ "${OS:-}" = "Windows_NT" ]; then
        LIBPCAP_LIBDIR=target/npcap-sdk/Lib/x64 \
            cargo build --release --target x86_64-pc-windows-msvc --features prping/web
    else
        LIBPCAP_LIBDIR=target/npcap-sdk/Lib/x64 \
            cargo xwin build --target x86_64-pc-windows-msvc --release --features prping/web
    fi

# Windows MSVC x86_64（先构建，再经 dist 打包 lib/、examples/、UI/ 到产物目录；
# Windows 本机运行即原生编译并嵌入 exe 图标，Linux/mac 自动走 xwin 交叉）
build-windows-msvc: build-windows-msvc-impl (dist "target/x86_64-pc-windows-msvc/release")

# Windows 7 x64 构建步骤（私有；官方 Win7 基线目标 MSVC，Linux 需 xwin，
# 首次自动下载 SDK；.cargo/config.toml 已配 crt-static 静态链接 CRT/C++ 运行库）
[private]
build-win7-impl: windows-deps
    LIBPCAP_LIBDIR=target/npcap-sdk/Lib/x64 \
        cargo +nightly xwin build -Z build-std --target x86_64-win7-windows-msvc --release --features prping/web

# Windows 7 x64（先构建，再经 dist 打包资源到产物目录）
build-win7: build-win7-impl (dist "target/x86_64-win7-windows-msvc/release")

# Windows 7 x86 构建步骤（私有；32 位 MSVC，同上）
[private]
build-win7-32-impl: windows-deps
    LIBPCAP_LIBDIR=target/npcap-sdk/Lib \
        cargo +nightly xwin build -Z build-std --target i686-win7-windows-msvc --release --features prping/web

# Windows 7 x86（先构建，再经 dist 打包资源到产物目录）
build-win7-32: build-win7-32-impl (dist "target/i686-win7-windows-msvc/release")

# 全部 Windows 产物
build-windows: build-windows-msvc build-win7 build-win7-32

# ── Linux 交叉编译（需对应工具链；本机同架构直接用 build-release） ──
# Linux 32-bit（i686）：需 gcc-multilib（Ubuntu）或 gcc-i686-linux-gnu（Debian）
[linux]
build-linux-32:
    rustup target add i686-unknown-linux-gnu
    cargo build --release --target i686-unknown-linux-gnu --features prping/web

# Linux ARM 32-bit（armv7hf）：需交叉工具链 gcc-arm-linux-gnueabihf
[linux]
build-linux-arm:
    rustup target add armv7-unknown-linux-gnueabihf
    cargo build --release --target armv7-unknown-linux-gnueabihf --features prping/web

# Linux ARM64（aarch64）：需交叉工具链 gcc-aarch64-linux-gnu
[linux]
build-linux-arm64:
    rustup target add aarch64-unknown-linux-gnu
    cargo build --release --target aarch64-unknown-linux-gnu --features prping/web

# 全部 Linux 产物（本机 + 交叉；子配方需 Linux 交叉工具链）
[linux]
build-linux-all: build-release build-linux-32 build-linux-arm build-linux-arm64

# 全平台产物（本机 + Windows + Linux 交叉；子配方含 Linux 交叉，仅 Linux 主机）
[linux]
build-all: build-release build-windows build-linux-all

# ── 发布 ──────────────────────────────────────────────────

# 本机 release 构建步骤（私有：仅作依赖被编排，见 publish）
[private]
publish-impl:
    cargo build --release -p prping --features prping/web

# 发布：release 构建（-p prping）+ dist 资源打包
# → target/release 完整布局（import 库搜索命中 lib/、prping web 命中 UI/）
publish: publish-impl (dist "target/release")
    @echo "发布产物：target/release/{prping,lib/,examples/,UI/}"

# ── Web 前端（bun + vite，SolidJS + CodeMirror）────────────

# 前端产物保障（build / build-release 的依赖）：dist 缺失或前端源码更新时自动
# build-web（SKIP=1 跳过，与 build.rs 开关一致）——新鲜则零开销跳过
[script]
web-dist:
    case "${PRPING_SKIP_WEB_BUILD:-}" in 1|true|yes) exit 0;; esac
    if [ ! -f frontend/package.json ]; then exit 0; fi
    if [ -f frontend/dist/index.html ] && [ -z "$(find frontend/src frontend/index.html frontend/package.json frontend/vite.config.ts frontend/tsconfig.json frontend/public -newer frontend/dist/index.html 2>/dev/null | head -1)" ]; then
        exit 0
    fi
    just build-web

# 开发热更新：`prping web --port 8788` + `cd frontend && bun dev`（/ws 已配代理）。
# web-dist 自动调用 / 单独强制刷新 / CI 预热；web-embed 时 build.rs 执行同一构建
# （bun 优先、npm 兜底；无 node 警告跳过）→ 构建前端到 frontend/dist
[script]
build-web:
    cd frontend
    if command -v bun >/dev/null 2>&1; then
        bun install
        bun run build
    elif command -v npm >/dev/null 2>&1; then
        npm install --no-audit --no-fund --silent
        npm run build
    else
        echo "警告: 未找到 node/bun/npm —— 跳过前端构建（prping web 将返回 503 构建提示；web-embed 构建需要 node）"
        exit 0
    fi
    echo "前端产物：frontend/dist/（build / build-release 经 dist 自动同步为 target/<profile>/UI）"

# ── 质量检查 ──────────────────────────────────────────────

# 格式化（写入）
fmt:
    cargo fmt

# 格式化检查
fmt-check:
    cargo fmt --check

# 本机 check（快速编译检查）
check:
    cargo check --workspace --features prping/web

# pcap feature 语法检查（check + clippy -D warnings；需 libpcap-dev）
[linux]
check-pcap:
    cargo check --workspace --features pcap,prping/web
    cargo clippy --all-targets --workspace --features pcap,prping/web -- -D warnings

# web-embed feature 语法检查（check + clippy -D warnings；首次自动构建前端）
check-web-embed:
    cargo check --workspace --features prping/web-embed
    cargo clippy --all-targets --workspace --features prping/web-embed -- -D warnings

# 全平台语法检查（7 目标）：工具链缺失跳过、编译失败汇总 exit 1
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
    run_check "本机（x86_64-unknown-linux-gnu）" "true" cargo check --workspace --features prping/web
    run_check "Windows MSVC x86_64" "command -v cargo-xwin" cargo xwin check --target x86_64-pc-windows-msvc --workspace --features prping/web
    run_check "Windows 7 x64" "command -v cargo-xwin && rustup toolchain list | grep -q nightly" cargo +nightly xwin check -Z build-std --target x86_64-win7-windows-msvc --workspace --features prping/web
    run_check "Windows 7 x86" "command -v cargo-xwin && rustup toolchain list | grep -q nightly" cargo +nightly xwin check -Z build-std --target i686-win7-windows-msvc --workspace --features prping/web
    run_check "Linux 32-bit" "rustup target list --installed | grep -q i686-unknown-linux-gnu || rustup target add i686-unknown-linux-gnu >/dev/null 2>&1" cargo check --target i686-unknown-linux-gnu --workspace --features prping/web
    run_check "Linux ARM 32-bit" "rustup target list --installed | grep -q armv7-unknown-linux-gnueabihf || rustup target add armv7-unknown-linux-gnueabihf >/dev/null 2>&1" cargo check --target armv7-unknown-linux-gnueabihf --workspace --features prping/web
    run_check "Linux ARM64" "rustup target list --installed | grep -q aarch64-unknown-linux-gnu || rustup target add aarch64-unknown-linux-gnu >/dev/null 2>&1" cargo check --target aarch64-unknown-linux-gnu --workspace --features prping/web
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
    cargo clippy --all-targets --workspace --features prping/web -- -D warnings

# 全部测试（Windows 原生 MSVC 先经 windows-deps 就位 Npcap SDK）
[script]
test:
    if [ "${OS:-}" = "Windows_NT" ]; then
        just windows-deps
        export LIBPCAP_LIBDIR=target/npcap-sdk/Lib/x64
    fi
    cargo test --all-targets --workspace --features prping/web

# rustdoc 生成检查
doc:
    cargo doc --no-deps --workspace --features prping/web

# ── packet-dsl（.pkt 网络包构建 DSL）────────────────────────

# packet 发送有效性测试（python -m http.server + tcpdump 验证）
[linux]
test-pkt:
    python3 pktlang_tests/test_raw_effectiveness.py

# 冒烟测试（tcpdump 验证各子命令基本工作）
[linux]
test-smoke:
    python3 pktlang_tests/test_smoke_tcpdump.py

# 引擎分析测试（engine 子命令：分析/--ls/--hex/--pcap）
test-engine:
    python3 pktlang_tests/test_engine.py

# 配方测试（多步 .pktl：global/extract/sniffer/--fuzz/--out）
[linux]
test-recipe:
    python3 pktlang_tests/test_recipe.py

# 协议测试（ARP/UDP/ICMP/TCP/IPv6/QUIC 原始包 via tcpdump）
[linux]
test-protocol:
    python3 pktlang_tests/test_protocols.py

# 全部 pktlang 测试（除 test-engine 外均依赖 tcpdump/unshare，仅 Linux）
[linux]
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

# 清理全部构建产物
clean:
    cargo clean

# ── 测试循环（.test-loop/ 现场沙箱，gitignored）────────────

# 新建一轮测试循环目录 .test-loop/NN-描述（现场产物/沙箱/截图/日志都放这，不入库）
test-loop-new desc="run":
    #!/bin/sh
    set -e
    mkdir -p .test-loop
    n=1
    for d in .test-loop/[0-9][0-9]-*; do
        [ -e "$d" ] || continue
        m=$((10#$(basename "$d" | cut -c1-2)))
        [ "$m" -ge "$n" ] && n=$((m + 1))
    done
    dir=$(printf '.test-loop/%02d-%s' "$n" "{{desc}}")
    mkdir -p "$dir"
    echo "created: $dir"

# 查看现有轮次
test-loop-ls:
    @ls -1 .test-loop 2>/dev/null || echo "(无 .test-loop 轮次)"

# 删除空轮次（非空轮需人工清理，防止误删现场）
test-loop-clean:
    #!/bin/sh
    set -e
    [ -d .test-loop ] || { echo "no .test-loop"; exit 0; }
    empty=$(find .test-loop -mindepth 1 -maxdepth 1 -type d -name '[0-9][0-9]-*' -empty)
    if [ -n "$empty" ]; then
        echo "$empty" | xargs rmdir
        echo "removed empty rounds"
    else
        echo "no empty rounds"
    fi
    echo "remaining:"; ls -1 .test-loop

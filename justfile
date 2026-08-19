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
#   - Windows 交叉编译（Linux）：sudo apt install gcc-mingw-w64-x86-64
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

# ── Windows 交叉编译（Linux 上；Windows 本机直接跑 build-release） ──
# XWIN_ARCH=x86,x86_64：cargo-xwin 默认只下载 x86_64+aarch64 库，且 DONE 标记
# 只记录最近一次架构——不统一指定会导致换架构时反复重下载；本项目只用 x86/x86_64。
#
# Windows 目标链接 pcap crate（--pkg --raw 的 Npcap 绑定）需要 Npcap SDK 的
# wpcap.lib：先 `just fetch-npcap-sdk`，构建时加 LIBPCAP_LIBDIR=target/npcap-sdk/Lib/x64
# （i686 用 Lib/）。运行时仍需目标机安装 Npcap（wpcap.dll 在 System32）。

# Windows MSVC x86_64（Linux 需 xwin；.cargo/config.toml 已配 crt-static 静态链接 CRT/C++ 运行库）
build-windows-msvc:
    XWIN_ARCH=x86,x86_64 LIBPCAP_LIBDIR=target/npcap-sdk/Lib/x64 \
        cargo xwin build --target x86_64-pc-windows-msvc --release

# Windows GNU x86_64（mingw-w64）
build-windows-gnu:
    CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc \
        cargo build --target x86_64-pc-windows-gnu --release

# Windows GNU i686（32 位）
build-windows-gnu-32:
    CARGO_TARGET_I686_PC_WINDOWS_GNU_LINKER=i686-w64-mingw32-gcc \
        cargo build --target i686-pc-windows-gnu --release

# Windows 7 x64（官方 Win7 基线目标 MSVC；Linux 需 xwin，首次自动下载 SDK；静态链接 CRT/C++ 运行库）
build-win7:
    XWIN_ARCH=x86,x86_64 LIBPCAP_LIBDIR=target/npcap-sdk/Lib/x64 \
        cargo +nightly xwin build -Z build-std --target x86_64-win7-windows-msvc --release

# Windows 7 x86（32 位 MSVC，同上）
build-win7-32:
    XWIN_ARCH=x86,x86_64 LIBPCAP_LIBDIR=target/npcap-sdk/Lib \
        cargo +nightly xwin build -Z build-std --target i686-win7-windows-msvc --release

# Windows 7 GNU 备选（无 xwin 时用 mingw-w64，MSVCRT 链接）
build-win7-gnu:
    cargo +nightly build -Z build-std --target x86_64-win7-windows-gnu --release

# 全部 Windows 产物
build-windows: build-windows-msvc build-windows-gnu build-windows-gnu-32 build-win7 build-win7-32

# 下载并解压 Npcap SDK（wpcap.lib 供 Windows 目标链接；URL 随 Npcap 版本更新）
fetch-npcap-sdk:
    mkdir -p target/npcap-sdk
    curl -L -o target/npcap-sdk.zip https://npcap.com/dist/npcap-sdk-1.15.zip
    unzip -o target/npcap-sdk.zip -d target/npcap-sdk
    @echo "SDK 就绪：target/npcap-sdk/Lib/{x64/,}wpcap.lib（构建时 LIBPCAP_LIBDIR 已由配方设置）"

# 全部产物（本机 + Windows 各目标）
build-all: build-release build-windows

# 发布：release 构建 prping + eng_lib 复制为 target/release/lib/
# 发布后从 target/release/ 运行 prping --eng x.pkt 会自动命中 lib/（默认库目录）
publish:
    cargo build --release -p prping
    mkdir -p target/release/lib
    cp -r eng_lib/* target/release/lib/
    @echo "发布产物：target/release/{prping,lib/}

# ── 质量检查 ──────────────────────────────────────────────

# 格式化（写入）
fmt:
    cargo fmt

# 格式化检查
fmt-check:
    cargo fmt --check

# Lint（clippy 零警告门禁）
lint:
    cargo clippy --all-targets --workspace -- -D warnings

# 全部测试（prping 万用表 + packet-dsl 引擎）
test:
    cargo test --all-targets --workspace

# rustdoc 生成检查
doc:
    cargo doc --no-deps

# 快速编译检查
check:
    cargo check --workspace

# ── packet-dsl（.pkt 网络包构建 DSL）────────────────────────

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
        target/x86_64-pc-windows-gnu/release/prping.exe \
        target/i686-pc-windows-gnu/release/prping.exe \
        target/x86_64-win7-windows-gnu/release/prping.exe 2>/dev/null || true

clean:
    cargo clean

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

# Windows MSVC x86_64（Linux 需 xwin）
build-windows-msvc:
    cargo xwin build --target x86_64-pc-windows-msvc --release

# Windows GNU x86_64（mingw-w64）
build-windows-gnu:
    CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc \
        cargo build --target x86_64-pc-windows-gnu --release

# Windows GNU i686（32 位）
build-windows-gnu-32:
    CARGO_TARGET_I686_PC_WINDOWS_GNU_LINKER=i686-w64-mingw32-gcc \
        cargo build --target i686-pc-windows-gnu --release

# Windows 7（官方 Win7 基线目标，Tier 3，MSVCRT 链接）
build-win7:
    cargo +nightly build -Z build-std --target x86_64-win7-windows-gnu --release

# 全部 Windows 产物
build-windows: build-windows-msvc build-windows-gnu build-windows-gnu-32 build-win7

# 全部产物（本机 + Windows 各目标）
build-all: build-release build-windows

# ── 质量检查 ──────────────────────────────────────────────

# 格式化（写入）
fmt:
    cargo fmt

# 格式化检查
fmt-check:
    cargo fmt --check

# Lint（clippy 零警告门禁）
lint:
    cargo clippy --all-targets -- -D warnings

# 全部测试（单元 + 协议 + CLI + doc）
test:
    cargo test --all-targets

# rustdoc 生成检查
doc:
    cargo doc --no-deps

# 快速编译检查
check:
    cargo check

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

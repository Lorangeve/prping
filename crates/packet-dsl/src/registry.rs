//! 内置函数注册表：把层函数调用（`tcp(dport=80)` 等）构造成 IR `Layer`。
//!
//! - 位置参数按参数表顺序填充；命名参数任意顺序；命名参数后不允许位置参数。
//! - 未知参数 / 重复参数 / 类型错误带 span 报错。
//! - 未填字段保持 `None`（自动值），由宿主序列化阶段补齐。

use std::net::{Ipv4Addr, Ipv6Addr};

use std::borrow::Cow;

use crate::ast::{Arg, Call, Span, Value};
use crate::diag::{Diagnostic, PktResult};
use crate::ir::*;

/// 运行时参数表：`--params k=v` 注入，脚本用 `params("k")` 读取。
pub type Params = std::collections::HashMap<String, String>;

/// 函数参数环境：参数名 → 值（None = 未设/省略）。非函数上下文传空表。
pub type FnEnv = std::collections::HashMap<String, Option<Value>>;

/// 内置层函数名（供语义阶段的 call 名字解析使用）。
///
/// 引擎只保留数据原语与唯一的「字节 → 层标注」原语 `layer`：eth/arp/ipv4/... 等
/// 层头由 eng_lib 的库函数提供（headers.pkt 构建头字节，bytes.pkt 用 `layer`
/// 做具名包装；库导出隐式可见，作用域优先于内置）。
pub const BUILTINS: &[&str] = &[
    "raw", "hex",
    // 通用层标注原语：bytes + 层类型字面量 → 该层（序列化时按层类型自动补
    // length/checksum/proto 推导；eng_lib/bytes.pkt 的 *_bytes 具名包装基于它）
    "layer",
];

/// IR 层类型闭集（`layer(kind, ...)` 与 `#[layer("kind")] proto` 共用）。
pub const LAYER_KINDS: &[&str] = &[
    "eth", "arp", "ipv4", "ipv6", "icmp", "tcp", "udp", "http", "dns",
];

pub fn is_builtin(name: &str) -> bool {
    BUILTINS.contains(&name)
}

/// 内置函数文档（LSP 悬停 / 补全详情 / `--ls` 用）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltinDoc {
    pub name: &'static str,
    /// 摘要行：`--ls` 以 `"""..."""` 文档字符串展示，与库函数（`FuncDoc.summary`）一致。
    pub summary: &'static str,
    /// 参数：名字 → 类型说明（`--ls` 参数行展示，签名内不再重复内联）。
    pub params: Vec<(&'static str, &'static str)>,
    /// 行为说明：层位置 = 自动补齐行为；值位置 = 求值行为。
    pub auto: &'static str,
}

/// 全部内置函数文档。
///
/// 层位置原语（raw/hex/layer）与值位置原语（字节构建 / 位运算 / params / global /
/// reply）都登记在这里——`--eng --ls`、LSP 补全与悬停共用这一份清单，**改动原语必须同步**。
pub fn builtin_docs() -> Vec<BuiltinDoc> {
    vec![
        // ── 层位置原语 ──────────────────────────────────────
        BuiltinDoc {
            name: "raw",
            summary: "原样字节载荷层；UTF-8 字符串 → 字节（≡ Python b\"...\"）",
            params: vec![("bytes", "str | 字节列表")],
            auto: "层位置 = 原样字节载荷层；值位置 = UTF-8 字符串 → 字节（≡ Python b\"...\"），字节列表直通",
        },
        BuiltinDoc {
            name: "hex",
            summary: "hex 字符串 → 字节列表；层位置 = hex 解码为原始字节载荷",
            params: vec![("str", "hex 字符串，如 \"deadbeef\"")],
            auto: "层位置 = hex 解码为原始字节载荷；值位置 = hex → 字节列表（可选 0x 前缀，须偶数长度）",
        },
        // 通用层标注原语（eng_lib/bytes.pkt 的 *_bytes 具名包装基于它）
        BuiltinDoc {
            name: "layer",
            summary: "字节 + 层类型字面量 → 该层（length/checksum 序列化时自动补）",
            params: vec![
                (
                    "kind",
                    "层类型字面量：eth/arp/ipv4/ipv6/icmp/tcp/udp/http/dns",
                ),
                ("bytes", "该层头字节"),
                ("src", "可选源地址（仅 ipv4/ipv6，伪头部校验和）"),
                ("dst", "可选目标地址（仅 ipv4/ipv6，伪头部校验和）"),
            ],
            auto: "序列化时按层类型自动补 length/checksum 并按内层推导 proto/ethertype/next_header",
        },
        // ── 值位置：字节构建 ─────────────────────────────────
        BuiltinDoc {
            name: "concat",
            summary: "拼接任意数量的字节列表 → 字节",
            params: vec![],
            auto: "拼接任意数量的字节列表 → 字节",
        },
        BuiltinDoc {
            name: "u8",
            summary: "数值 0..255 或 1 字节列表 → 1 字节",
            params: vec![("n", "数值 0..255 或恰好 1 字节列表")],
            auto: "→ 1 字节",
        },
        BuiltinDoc {
            name: "be16",
            summary: "数值 0..65535 或 2 字节列表 → 2 字节大端",
            params: vec![("n", "数值 0..65535 或恰好 2 字节列表")],
            auto: "→ 2 字节大端（同宽字节直通）",
        },
        BuiltinDoc {
            name: "be32",
            summary: "数值或 4 字节列表 → 4 字节大端",
            params: vec![("n", "数值 0..2^32-1 或恰好 4 字节列表")],
            auto: "→ 4 字节大端（同宽字节直通）",
        },
        BuiltinDoc {
            name: "le16",
            summary: "数值 0..65535 或 2 字节列表 → 2 字节小端",
            params: vec![("n", "数值 0..65535 或恰好 2 字节列表")],
            auto: "→ 2 字节小端（低字节在前；字节输入按大端解读后反转）",
        },
        BuiltinDoc {
            name: "le32",
            summary: "数值或 4 字节列表 → 4 字节小端",
            params: vec![("n", "数值 0..2^32-1 或恰好 4 字节列表")],
            auto: "→ 4 字节小端（字节输入按大端解读后反转）",
        },
        BuiltinDoc {
            name: "be64",
            summary: "数值或 8 字节列表 → 8 字节大端",
            params: vec![("n", "数值 0..2^63-1（i64 封顶）或恰好 8 字节列表")],
            auto: "→ 8 字节大端（同宽字节直通）",
        },
        BuiltinDoc {
            name: "le64",
            summary: "数值或 8 字节列表 → 8 字节小端",
            params: vec![("n", "数值 0..2^63-1（i64 封顶）或恰好 8 字节列表")],
            auto: "→ 8 字节小端（字节输入按大端解读后反转）",
        },
        // varint/qvarint 值原语已移除（下沉为 eng_lib/vint.pkt 的库 proto 声明，
        // 值位置调用走 proto 双位置）——变长整数编码统一收敛到 vint codec。
        BuiltinDoc {
            name: "tpl",
            summary: "模板串 → 字节（scanf 式锚定全匹配；ip4/ip6/mac/dns_name 通用底层）",
            params: vec![
                (
                    "template",
                    "模板串：%c 通配 1 字节；%d1/%d2/%d4 十进制、%x1/%x2/%x4 十六进制（大端，宽度缺省 1）；%L DNS 名字序列（动态宽度，长度前缀 + 尾 0，不吃参数）；{n} 重复 n 次、{n:sep} 带分隔符（{n:} 缺省 ':'，冒号分隔时输入 '::' = 零填充压缩）、{n:[chars]} 分隔符字符类；%% 转义",
                ),
                (
                    "input",
                    "字符串（按模板解析）或字节列表（等宽直通；含 %L 的模板不接受字节列表）",
                ),
            ],
            auto: "文本 → 字节（锚定全匹配）：ip4/ip6/mac/dns_name 值原语的通用底层，eng_lib/bytes.pkt 的 ip4()/ip6()/mac()/dns_name() 值函数基于它实现",
        },
        // cksum（2 字节反码校验和，RFC 1071）与 md5/sha1/sha256（摘要）为引擎原语——
        // 原 words16/fold16（校验和的切分/折叠内部机制）已回退移除，DSL 不再暴露
        // 中间步骤；cksum 与自动校验和共用 serialize::checksum，sum 仍是通用整数求和
        BuiltinDoc {
            name: "cksum",
            summary: "互联网校验和（RFC 1071 反码）→ 2 字节大端",
            params: vec![("data", "字节列表 / 字符串（UTF-8）")],
            auto: "→ 2 字节：one's complement 校验和（IPv4/ICMP/TCP/UDP 同款，与自动校验和共用）——cksum(hex(\"...\")) 一步",
        },
        BuiltinDoc {
            name: "md5",
            summary: "MD5 摘要 → 16 字节",
            params: vec![("data", "字节列表 / 字符串（UTF-8）")],
            auto: "→ 16 字节 MD5 摘要",
        },
        BuiltinDoc {
            name: "sha1",
            summary: "SHA-1 摘要 → 20 字节",
            params: vec![("data", "字节列表 / 字符串（UTF-8）")],
            auto: "→ 20 字节 SHA-1 摘要",
        },
        BuiltinDoc {
            name: "sha256",
            summary: "SHA-256 摘要 → 32 字节",
            params: vec![("data", "字节列表 / 字符串（UTF-8）")],
            auto: "→ 32 字节 SHA-256 摘要",
        },
        // sum 已移除（无真实用户；整数折叠 DSL 表达不了，但无消费方——cksum 的
        // 求和一步留在 cksum 原语内部，不暴露中间步骤）
        BuiltinDoc {
            name: "count",
            summary: "列表元素个数 → 整数",
            params: vec![("list", "任意列表")],
            auto: "→ 整数：列表长度（DNS qdcount 用 count(questions)）",
        },
        // len 已下沉为 eng_lib/bytes.pkt 库值函数（count∘raw 组合，可组合的算法
        // 住库、闭合算法住引擎——与 ip4/ip6/mac 下沉同理由）
        BuiltinDoc {
            name: "rand16",
            summary: "构建期随机 0..65535 整数",
            params: vec![],
            auto: "→ 0..65535 构建期随机整数",
        },
        BuiltinDoc {
            name: "rand8",
            summary: "构建期随机 0..255 整数",
            params: vec![],
            auto: "→ 0..255 构建期随机整数",
        },
        BuiltinDoc {
            name: "rand_bytes",
            summary: "构建期随机 n 字节",
            params: vec![("n", "字节数 0..65535（非负；包长上限）")],
            auto: "→ n 个构建期随机字节（0..255）——字节方向随机（与 rand16/rand8 整数方向互补）：rand_mac 即 rand_bytes(6)，随机 payload/nonce 直接用",
        },
        BuiltinDoc {
            name: "pad",
            summary: "n 个零字节（确定性填充）",
            params: vec![("n", "字节数 0..65535（非负；包长上限）")],
            auto: "→ n 个零字节——与 rand_bytes 对称的确定性填充：以太网最小帧 46B 填充、IP 选项对齐、DNS OPT padding 等",
        },
        BuiltinDoc {
            name: "dns",
            summary: "域名 → IP 字符串（v4 优先；IP 字面量短路）",
            params: vec![
                ("host", "域名（IP 字面量直接短路返回，无需解析器）"),
                (
                    "family",
                    "可选：6 = IPv6 优先（默认 v4 优先）——ipv6() 值函数用 dns(host, 6)",
                ),
            ],
            auto: "→ IP 字符串；可流入 tpl/ip4/ip6 值函数与地址字段",
        },
        // dns_name（DNS 线格式编码）已下沉：tpl `%L` 说明符 + eng_lib/bytes.pkt 值函数
        // ── 值位置：位运算（函数形态）────────────────────────────
        BuiltinDoc {
            name: "bor",
            summary: "按位或（变参左折叠）",
            params: vec![("a,b,...", "整数（Int/Hex）或同宽字节列表，至少 2 个")],
            auto: "按位或（变参左折叠）；字节列表 → 元素级——协议标志位组合（bor(syn(), ack())，位常量见 eng_lib/bytes.pkt）",
        },
        BuiltinDoc {
            name: "band",
            summary: "按位与",
            params: vec![("a,b", "整数（Int/Hex）或同宽字节列表")],
            auto: "按位与；字节列表 → 元素级",
        },
        BuiltinDoc {
            name: "bxor",
            summary: "按位异或",
            params: vec![("a,b", "整数（Int/Hex）或同宽字节列表")],
            auto: "按位异或；字节列表 → 元素级",
        },
        BuiltinDoc {
            name: "bnot",
            summary: "按位取反",
            params: vec![("a", "整数（Int/Hex）或字节列表")],
            auto: "按位取反；字节列表 → 元素级",
        },
        BuiltinDoc {
            name: "shl",
            summary: "左移 → 整数",
            params: vec![("a", "整数"), ("n", "移位量 0..64")],
            auto: "左移 → 整数",
        },
        BuiltinDoc {
            name: "shr",
            summary: "右移 → 整数",
            params: vec![("a", "整数"), ("n", "移位量 0..64")],
            auto: "右移 → 整数",
        },
        // ── 值位置：算术（宽度/expr 表达式专用）─────────────────────
        // mul/div/sub 与位运算同形态（函数调用）；供 `bytes="..."` 宽度表达式与
        // `#[meta(auto, expr="...")]` 变换（如 TCP data_offset 的 /4+5<<4）。
        BuiltinDoc {
            name: "mul",
            summary: "乘法 → 整数（宽度/expr 表达式用）",
            params: vec![("a,b,...", "整数，至少 2 个")],
            auto: "变参左折叠乘法 → 整数；仅整数（字节列表无乘法语义）——`bytes=\"sub(mul(shr(x, 4), 4), 20)\"` 等宽度表达式",
        },
        BuiltinDoc {
            name: "div",
            summary: "除法 → 整数（宽度/expr 表达式用）",
            params: vec![("a,b,...", "整数，至少 2 个；除 0 报错")],
            auto: "变参左折叠除法 → 整数；仅整数——`#[meta(auto, expr=\"shl(div(len, 4) + 5, 4)\")]` 等变换（TCP data_offset）",
        },
        BuiltinDoc {
            name: "sub",
            summary: "减法 → 整数（宽度/expr 表达式用）",
            params: vec![("a,b,...", "整数，至少 2 个")],
            auto: "变参左折叠减法 → 整数；仅整数——TCP options 宽度回算（`(data_offset>>4)*4-20`）",
        },
        // ── 值位置：组合 / 引用 ──────────────────────────────────
        // lambda / map / filter / reduce（高阶）已移除（中间形态：算法下沉回原语，
        // 语言最小化、求值保证终止——可变长列表走 proto list/rest，不再需要折叠回调）。
        BuiltinDoc {
            name: "params",
            summary: "读取运行时参数（--params name=value 注入）",
            params: vec![
                ("name", "参数名"),
                (
                    "default",
                    "可选默认值（字符串按形状解析；值表达式默认仅值表达式位置可用）",
                ),
            ],
            auto: "读取运行时参数（--params name=value 注入）；按形状解析：0x/0X 前缀或纯十进制 = 数值，其余 = 字符串",
        },
        BuiltinDoc {
            name: "global",
            summary: "读取配方全局值（.pktl 的 global: 段 / 步骤 extract / -G（--global）注入）",
            params: vec![
                ("name", "全局名"),
                (
                    "default",
                    "可选默认值（值表达式，未设置时延迟求值——与 params 一致）",
                ),
            ],
            auto: "读取配方全局存储：与 params 对称但值是**类型化**的（Int/Hex/Str/字节列表原样返回，不经过字符串形状解析），可直接参与 +/be16/位运算；未设置且无默认时报错",
        },
        BuiltinDoc {
            name: "reply",
            summary: "读取回包反解字段（配方 extract 的 from: 表达式专用）",
            params: vec![
                ("layer", "层名：eth/arp/ipv4/ipv6/icmp/tcp/udp/http/dns/raw"),
                (
                    "field",
                    "字段名（与 sniffer/extract 字段集一致，另含 icmp.payload / http.body / raw.bytes）",
                ),
            ],
            auto: "仅配方 extract 的 from: 表达式求值时按内置处理（宿主注入当前步骤回包）；其余上下文回退用户函数（eng_lib 的 ARP 位常量 `reply()` 等撞名保持原语义）；数值字段 → Int，地址/字符串字段 → Str（display），payload/body/raw 字节 → 字节列表",
        },
    ]
}

/// 单个内置函数文档。
pub fn builtin_doc(name: &str) -> Option<BuiltinDoc> {
    builtin_docs().into_iter().find(|d| d.name == name)
}

/// 把层调用解析为一个或多个 IR Layer（`params` 供 `params("name")` 值引用取值，
/// `env` 供函数体内的参数引用 `Value::Ident` 取值）。
pub fn build_layers(call: &Call, params: &Params, env: &FnEnv) -> PktResult<Vec<Layer>> {
    match call.name.as_str() {
        "raw" => build_raw(call, params, env).map(|f| vec![Layer::Raw(f)]),
        "hex" => build_hex(call, params, env).map(|f| vec![Layer::Raw(f)]),
        // 通用层标注：kind（闭集字面量）+ 头字节 → 对应层；ipv4/ipv6 可选 src/dst
        // （伪头部校验和元数据）。eng_lib/bytes.pkt 的 *_bytes 具名包装基于它。
        "layer" => build_layer(call, params, env),
        other => Err(Diagnostic::at(
            format!(
                "未知层函数 `{other}`（内置原语：{}；层头函数见 eng_lib 库导出）",
                BUILTINS.join(" / ")
            ),
            call.name_span,
        )),
    }
}

// ── 参数解析骨架 ──────────────────────────────────────────────

/// 参数读取器：命名参数 + 按表顺序的位置参数。
struct Args<'a> {
    call: &'a Call,
    params: &'a Params,
    env: &'a FnEnv,
    param_order: &'static [&'static str],
    pos_args: Vec<&'a Arg>,
    positional: usize,
    taken: Vec<&'static str>,
}

impl<'a> Args<'a> {
    fn new(
        call: &'a Call,
        params: &'a Params,
        env: &'a FnEnv,
        param_order: &'static [&'static str],
    ) -> PktResult<Self> {
        let pos_args: Vec<&Arg> = call.args.iter().filter(|a| a.name.is_none()).collect();
        // 命名参数后不允许位置参数
        if let Some(first_named) = call.args.iter().position(|a| a.name.is_some())
            && pos_args
                .iter()
                .any(|a| call.args.iter().position(|x| std::ptr::eq(x, *a)).unwrap() > first_named)
        {
            return Err(Diagnostic::at(
                format!("`{}`：命名参数后不能使用位置参数", call.name),
                call.span,
            ));
        }
        // 命名参数重复
        for (i, a) in call.args.iter().enumerate() {
            if let Some((n, _)) = &a.name {
                for b in call.args.iter().skip(i + 1) {
                    if let Some((m, _)) = &b.name
                        && n == m
                    {
                        return Err(Diagnostic::at(
                            format!("`{}`：参数 `{n}` 重复指定", call.name),
                            b.span,
                        ));
                    }
                }
            }
        }
        Ok(Self {
            call,
            params,
            env,
            param_order,
            pos_args,
            positional: 0,
            taken: Vec::new(),
        })
    }

    fn take(&mut self, name: &'static str) -> PktResult<Option<&'a Arg>> {
        // 命名参数
        if let Some(arg) = self
            .call
            .args
            .iter()
            .find(|a| a.name.as_ref().map(|(n, _)| n.as_str()) == Some(name))
        {
            if self.taken.contains(&name) {
                return Err(Diagnostic::at(
                    format!("`{}`：参数 `{name}` 重复指定", self.call.name),
                    arg.span,
                ));
            }
            self.taken.push(name);
            // 参数引用未设 → 视为未提供（省略 → 自动值）
            if arg_unset(arg, self.env, name)? {
                return Ok(None);
            }
            return Ok(Some(arg));
        }
        // 位置参数：填参数表顺序
        if self.positional < self.pos_args.len() && self.param_order[self.positional] == name {
            let arg = self.pos_args[self.positional];
            self.positional += 1;
            self.taken.push(name);
            if arg_unset(arg, self.env, name)? {
                return Ok(None);
            }
            return Ok(Some(arg));
        }
        Ok(None)
    }

    /// 校验没有未知参数 / 多余位置参数。
    fn finish(&self) -> PktResult<()> {
        for a in &self.call.args {
            if let Some((n, span)) = &a.name
                && !self.param_order.contains(&n.as_str())
            {
                return Err(Diagnostic::at(
                    format!("`{}`：未知参数 `{n}`", self.call.name),
                    *span,
                ));
            }
        }
        if self.positional < self.pos_args.len() {
            let extra = &self.pos_args[self.positional];
            return Err(Diagnostic::at(
                format!("`{}`：位置参数过多", self.call.name),
                extra.span,
            ));
        }
        Ok(())
    }

    // 便捷取值

    // 字段取值（支持 `"random"` 关键字）：未写 → Auto；"random" → Random；值 → Value

    /// 返回 (字段, 域名来源)：地址由域名解析得到时 second 为 Some(host)（展示用）。
    fn opt_field_ip4(
        &mut self,
        name: &'static str,
    ) -> PktResult<(Field<Ipv4Addr>, Option<String>)> {
        match self.take(name)? {
            Some(a) => field_coerce_ip4(&a.value, a.span, name, self.params, self.env),
            None => Ok((Field::Auto, None)),
        }
    }
    fn opt_field_ip6(
        &mut self,
        name: &'static str,
    ) -> PktResult<(Field<Ipv6Addr>, Option<String>)> {
        match self.take(name)? {
            Some(a) => field_coerce_ip6(&a.value, a.span, name, self.params, self.env),
            None => Ok((Field::Auto, None)),
        }
    }
}

/// 解析参数引用链：`Value::Ident` → 环境里的最终值；返回 None 表示「未设」（省略 → 自动）。
pub(crate) fn deref_opt<'a>(
    v: &'a Value,
    env: &'a FnEnv,
    what: &str,
) -> PktResult<Option<&'a Value>> {
    let mut cur = v;
    let mut depth = 0;
    loop {
        match cur {
            Value::Ident { name, span: ispan } => {
                if depth > 32 {
                    return Err(Diagnostic::at(format!("参数引用循环：`{name}`"), *ispan));
                }
                match env.get(name) {
                    Some(Some(inner)) => {
                        cur = inner;
                        depth += 1;
                    }
                    Some(None) => return Ok(None),
                    None => {
                        return Err(Diagnostic::at(
                            format!("参数 `{name}` 未定义（函数未声明该参数；用于 `{what}`）"),
                            *ispan,
                        ));
                    }
                }
            }
            _ => return Ok(Some(cur)),
        }
    }
}

/// 通用层标注原语：`layer(kind, bytes[, src, dst])`。
///
/// `kind` 为闭集字面量（eth/arp/ipv4/ipv6/icmp/tcp/udp/http/dns），`bytes` 为该层头
/// 字节直喂；`src`/`dst` 仅 ipv4/ipv6 接受（供传输层伪头部校验和）。
fn build_layer(call: &Call, params: &Params, env: &FnEnv) -> PktResult<Vec<Layer>> {
    const LAYER_PARAMS: &[&str] = &["kind", "bytes", "src", "dst"];
    let mut a = Args::new(call, params, env, LAYER_PARAMS)?;
    let kind = match a.take("kind")? {
        Some(arg) => val_str(&arg.value, arg.span, "kind", params, env)?,
        None => {
            return Err(Diagnostic::at(
                "`layer` 需要 `kind` 参数（eth/arp/ipv4/ipv6/icmp/tcp/udp/http/dns）",
                call.span,
            ));
        }
    };
    let b = match a.take("bytes")? {
        Some(arg) => val_bytes(&arg.value, arg.span, "bytes", params, env)?,
        None => {
            return Err(Diagnostic::at(
                format!("`layer` 需要 `bytes` 参数（层类型 `{kind}`）"),
                call.span,
            ));
        }
    };
    a.finish()?;
    // 非 IP 层不接受 src/dst（与旧 *_bytes 一致：未知参数报错）
    if !matches!(kind.as_str(), "ipv4" | "ipv6") {
        if let Some(arg) = a.take("src")? {
            return Err(Diagnostic::at(
                format!("层类型 `{kind}` 不接受 `src` 参数（仅 ipv4/ipv6）"),
                arg.span,
            ));
        }
        if let Some(arg) = a.take("dst")? {
            return Err(Diagnostic::at(
                format!("层类型 `{kind}` 不接受 `dst` 参数（仅 ipv4/ipv6）"),
                arg.span,
            ));
        }
    }
    match kind.as_str() {
        "eth" => Ok(vec![Layer::Ethernet(EthernetFields {
            raw: Some(b),
            ..Default::default()
        })]),
        "arp" => Ok(vec![Layer::Arp(ArpFields {
            raw: Some(b),
            ..Default::default()
        })]),
        "ipv4" => {
            let (src, src_host) = a.opt_field_ip4("src")?;
            let (dst, dst_host) = a.opt_field_ip4("dst")?;
            Ok(vec![Layer::Ipv4(Ipv4Fields {
                src,
                dst,
                src_host,
                dst_host,
                raw: Some(b),
                ..Default::default()
            })])
        }
        "ipv6" => {
            let (src, src_host) = a.opt_field_ip6("src")?;
            let (dst, dst_host) = a.opt_field_ip6("dst")?;
            Ok(vec![Layer::Ipv6(Ipv6Fields {
                src,
                dst,
                src_host,
                dst_host,
                raw: Some(b),
                ..Default::default()
            })])
        }
        "icmp" => Ok(vec![Layer::Icmp(IcmpFields {
            raw: Some(b),
            ..Default::default()
        })]),
        "tcp" => Ok(vec![Layer::Tcp(TcpFields {
            raw: Some(b),
            ..Default::default()
        })]),
        "udp" => Ok(vec![Layer::Udp(UdpFields {
            raw: Some(b),
            ..Default::default()
        })]),
        "http" => Ok(vec![Layer::Http(HttpFields {
            raw: Some(b),
            ..Default::default()
        })]),
        "dns" => Ok(vec![Layer::Dns(DnsFields {
            raw: Some(b),
            ..Default::default()
        })]),
        other => Err(Diagnostic::at(
            format!("未知层类型 `{other}`（可用：eth/arp/ipv4/ipv6/icmp/tcp/udp/http/dns）"),
            call.span,
        )),
    }
}

/// 按 IR 层类型 + 头字节构造 raw 层（`#[layer("kind")] proto` 构造解释器用）。
///
/// `addrs` 为 (src, dst) 地址元数据——仅 ipv4/ipv6 生效（供传输层伪头部校验和；
/// 从 proto 的 `src`/`dst` 字段值提取，None = 不设置）。
pub(crate) fn raw_layer(
    kind: &str,
    bytes: Vec<u8>,
    addrs: Option<(std::net::IpAddr, std::net::IpAddr)>,
) -> PktResult<Layer> {
    match kind {
        "eth" => Ok(Layer::Ethernet(EthernetFields {
            raw: Some(bytes),
            ..Default::default()
        })),
        "arp" => Ok(Layer::Arp(ArpFields {
            raw: Some(bytes),
            ..Default::default()
        })),
        "ipv4" => {
            let (src, dst) = addrs.unwrap_or((
                std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            ));
            Ok(Layer::Ipv4(Ipv4Fields {
                src: match src {
                    std::net::IpAddr::V4(a) => Field::Value(a),
                    _ => Field::Auto,
                },
                dst: match dst {
                    std::net::IpAddr::V4(a) => Field::Value(a),
                    _ => Field::Auto,
                },
                raw: Some(bytes),
                ..Default::default()
            }))
        }
        "ipv6" => {
            let (src, dst) = addrs.unwrap_or((
                std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            ));
            Ok(Layer::Ipv6(Ipv6Fields {
                src: match src {
                    std::net::IpAddr::V6(a) => Field::Value(a),
                    _ => Field::Auto,
                },
                dst: match dst {
                    std::net::IpAddr::V6(a) => Field::Value(a),
                    _ => Field::Auto,
                },
                raw: Some(bytes),
                ..Default::default()
            }))
        }
        "icmp" => Ok(Layer::Icmp(IcmpFields {
            raw: Some(bytes),
            ..Default::default()
        })),
        "tcp" => Ok(Layer::Tcp(TcpFields {
            raw: Some(bytes),
            ..Default::default()
        })),
        "udp" => Ok(Layer::Udp(UdpFields {
            raw: Some(bytes),
            ..Default::default()
        })),
        "http" => Ok(Layer::Http(HttpFields {
            raw: Some(bytes),
            ..Default::default()
        })),
        "dns" => Ok(Layer::Dns(DnsFields {
            raw: Some(bytes),
            ..Default::default()
        })),
        other => Err(Diagnostic::at(
            format!("未知层类型 `{other}`（可用：eth/arp/ipv4/ipv6/icmp/tcp/udp/http/dns）"),
            crate::ast::Span::new(1, 1, 1, 1),
        )),
    }
}

/// 必须提供的值：参数引用未设 → 报错。
fn deref<'a>(v: &'a Value, env: &'a FnEnv, span: Span, what: &str) -> PktResult<&'a Value> {
    deref_opt(v, env, what)?
        .ok_or_else(|| Diagnostic::at(format!("参数 `{what}` 未提供（参数未设）"), span))
}

/// 参数值是否为「未设」的参数引用（链式解析到 None）。
fn arg_unset(arg: &Arg, env: &FnEnv, what: &str) -> PktResult<bool> {
    Ok(matches!(arg.value, Value::Ident { .. }) && deref_opt(&arg.value, env, what)?.is_none())
}

/// 值 → Field：字符串 `"random"` → Random；其余走原 coercer → Value。未设参数 → Auto。
fn field_coerce_ip4(
    v: &Value,
    span: Span,
    what: &str,
    params: &Params,
    env: &FnEnv,
) -> PktResult<(Field<Ipv4Addr>, Option<String>)> {
    let Some(v) = deref_opt(v, env, what)? else {
        return Ok((Field::Auto, None));
    };
    match v {
        Value::Str(s) if s.eq_ignore_ascii_case("random") => Ok((Field::Random, None)),
        _ => {
            let (a, host) = val_ip4(v, span, what, params, env)?;
            Ok((Field::Value(a), host))
        }
    }
}

fn field_coerce_ip6(
    v: &Value,
    span: Span,
    what: &str,
    params: &Params,
    env: &FnEnv,
) -> PktResult<(Field<Ipv6Addr>, Option<String>)> {
    let Some(v) = deref_opt(v, env, what)? else {
        return Ok((Field::Auto, None));
    };
    match v {
        Value::Str(s) if s.eq_ignore_ascii_case("random") => Ok((Field::Random, None)),
        _ => {
            let (a, host) = val_ip6(v, span, what, params, env)?;
            Ok((Field::Value(a), host))
        }
    }
}

// ── 值 → 类型 ─────────────────────────────────────────────────

fn val_str(v: &Value, span: Span, what: &str, params: &Params, env: &FnEnv) -> PktResult<String> {
    let v = deref(v, env, span, what)?;
    match v {
        Value::Str(s) => Ok(s.clone()),
        other => match as_param(other, params, span, what)? {
            Some(s) => Ok(s.into_owned()),
            None => Err(Diagnostic::at(
                format!("参数 `{what}` 需要字符串，得到 {}", describe(other)),
                span,
            )),
        },
    }
}

fn val_bytes(
    v: &Value,
    span: Span,
    what: &str,
    params: &Params,
    env: &FnEnv,
) -> PktResult<Vec<u8>> {
    let v = deref(v, env, span, what)?;
    match v {
        Value::Str(s) => Ok(s.as_bytes().to_vec()),
        Value::Param { .. } => Ok(as_param(v, params, span, what)?
            .unwrap_or_default()
            .as_bytes()
            .to_vec()),
        Value::List(items) => {
            let mut out = Vec::with_capacity(items.len());
            for it in items {
                let b = match it {
                    Value::Int(i) if (0..=255).contains(i) => *i as u8,
                    Value::Hex(h) if *h <= 255 => *h as u8,
                    Value::Int(i) => {
                        return Err(Diagnostic::at(
                            format!("参数 `{what}` 的字节超出范围 0..255：{i}"),
                            span,
                        ));
                    }
                    Value::Hex(h) => {
                        return Err(Diagnostic::at(
                            format!("参数 `{what}` 的字节超出范围 0..255：0x{h:X}"),
                            span,
                        ));
                    }
                    other => {
                        return Err(Diagnostic::at(
                            format!("参数 `{what}` 需要字节列表，得到 {}", describe(other)),
                            span,
                        ));
                    }
                };
                out.push(b);
            }
            Ok(out)
        }
        Value::Call {
            name,
            args,
            span: call_span,
            ..
        } if name == "hex" => {
            // 值位置 hex 的非法输入解析为 hex 调用标记（合法输入在解析期已是字节列表）：
            // 在这里统一校验并给清晰报错
            let s = match args.first() {
                Some(Value::Str(s)) => s.clone(),
                _ => {
                    return Err(Diagnostic::at(
                        format!("参数 `{what}` 需要字符串，得到 值调用 `{name}(...)`"),
                        *call_span,
                    ));
                }
            };
            hex_string_bytes(&s)
                .map_err(|msg| Diagnostic::at(format!("`hex` {msg}：`{s}`"), *call_span))
        }
        other => Err(Diagnostic::at(
            format!(
                "参数 `{what}` 需要字符串或字节列表（如 [0x48, 0x69]），得到 {}",
                describe(other)
            ),
            span,
        )),
    }
}

/// 返回 (地址, 域名来源)：字符串是域名且经解析器解析时 second 为 Some(host)。
fn val_ip4(
    v: &Value,
    span: Span,
    what: &str,
    params: &Params,
    env: &FnEnv,
) -> PktResult<(Ipv4Addr, Option<String>)> {
    let v = deref(v, env, span, what)?;
    match v {
        Value::Str(s) => ip4_or_dns(s, what, span),
        other => match as_param(other, params, span, what)? {
            Some(s) => ip4_or_dns(&s, what, span),
            None => Err(Diagnostic::at(
                format!(
                    "参数 `{what}` 需要 IPv4 地址字符串，得到 {}",
                    describe(other)
                ),
                span,
            )),
        },
    }
}

/// IPv4 字符串解析；非 IP 时尝试域名解析（宿主 `dns` 解析器，取首个 IPv4）。
fn ip4_or_dns(s: &str, what: &str, span: Span) -> PktResult<(Ipv4Addr, Option<String>)> {
    match s.parse::<Ipv4Addr>() {
        Ok(a) => Ok((a, None)),
        Err(_) => match crate::dns_lookup(s).into_iter().find(|a| a.is_ipv4()) {
            Some(a) => match a {
                std::net::IpAddr::V4(v4) => Ok((v4, Some(s.to_string()))),
                _ => unreachable!("已按 is_ipv4 过滤"),
            },
            None => Err(Diagnostic::at(
                format!("参数 `{what}` 不是合法 IPv4 且无法解析：`{s}`"),
                span,
            )),
        },
    }
}

/// 返回 (地址, 域名来源)：字符串是域名且经解析器解析时 second 为 Some(host)。
fn val_ip6(
    v: &Value,
    span: Span,
    what: &str,
    params: &Params,
    env: &FnEnv,
) -> PktResult<(Ipv6Addr, Option<String>)> {
    let v = deref(v, env, span, what)?;
    match v {
        Value::Str(s) => ip6_or_dns(s, what, span),
        other => match as_param(other, params, span, what)? {
            Some(s) => ip6_or_dns(&s, what, span),
            None => Err(Diagnostic::at(
                format!(
                    "参数 `{what}` 需要 IPv6 地址字符串，得到 {}",
                    describe(other)
                ),
                span,
            )),
        },
    }
}

/// IPv6 字符串解析；非 IP 时尝试域名解析（宿主 `dns` 解析器，取首个 IPv6）。
fn ip6_or_dns(s: &str, what: &str, span: Span) -> PktResult<(Ipv6Addr, Option<String>)> {
    match s.parse::<Ipv6Addr>() {
        Ok(a) => Ok((a, None)),
        Err(_) => match crate::dns_lookup(s).into_iter().find(|a| a.is_ipv6()) {
            Some(a) => match a {
                std::net::IpAddr::V6(v6) => Ok((v6, Some(s.to_string()))),
                _ => unreachable!("已按 is_ipv6 过滤"),
            },
            None => Err(Diagnostic::at(
                format!("参数 `{what}` 不是合法 IPv6 且无法解析：`{s}`"),
                span,
            )),
        },
    }
}

pub(crate) fn describe(v: &Value) -> String {
    match v {
        Value::Str(s) => format!("字符串 `{s}`"),
        Value::Int(i) => format!("整数 `{i}`"),
        Value::Hex(h) => format!("十六进制 `0x{h:X}`"),
        Value::List(_) => "列表".to_string(),
        Value::Param { name, .. } => format!("参数引用 `params(\"{name}\")`"),
        Value::Ident { name, .. } => format!("参数引用 `{name}`"),
        Value::Call { name, .. } => format!("值调用 `{name}(...)`"),
        Value::BinOp { .. } => "加法表达式".to_string(),
    }
}

/// 运算符的可读文本（describe / eng 展示用）。
pub fn binop_str(op: crate::ast::BinOp) -> &'static str {
    match op {
        crate::ast::BinOp::Add => "+",
    }
}

/// 取参数值（层参数路径，保持字符串语义）：`params("name", "默认值")` →
/// 宿主注入值或默认值；缺失报错。默认值须为字符串字面量——值表达式默认
/// （如 `be16(...)`）只在值表达式位置可用（eval 路径），层参数位置报错。
pub(crate) fn param_value(
    params: &Params,
    name: &str,
    default: &Option<Box<Value>>,
    span: Span,
    what: &str,
) -> PktResult<String> {
    match params.get(name) {
        Some(v) => Ok(v.clone()),
        None => match default {
            Some(b) => match b.as_ref() {
                Value::Str(s) => Ok(s.clone()),
                other => Err(Diagnostic::at(
                    format!(
                        "层参数位置 `{what}` 的 `params` 默认值需为字符串字面量（值表达式默认如 `be16(...)` 只在值表达式位置可用）：{}",
                        describe(other)
                    ),
                    span,
                )),
            },
            None => Err(Diagnostic::at(
                format!(
                    "参数 `{name}` 未提供（用于 `{what}`；可用 --params {name}=... 传入，或写 params(\"{name}\", \"默认值\")）"
                ),
                span,
            )),
        },
    }
}

/// params 值按形状解析：`0x`/`0X` 前缀 + 十六进制数字 → 数值（Hex）；十进制数字
/// （可负）→ 数值（Int）；其余 → 字符串。形状解析取代了 `int()` 原语的参数用途——
/// `be16(params("port", "53"))` / `icmp(id=params("id", "0x1234"))` 直接可用。
/// 注意：数值形文本（`--params payload=123`）在**值表达式**里会变成数值；
/// 层参数路径（`raw(bytes=...)`/地址字段，走 `as_param`）保持字符串语义。
/// 宿主 -G（--global）注入配方全局也用同一形状解析（全局值 = 类型化字面量）。
pub fn parse_param_value(s: &str) -> Value {
    let t = s.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X"))
        && !hex.is_empty()
        && hex.chars().all(|c| c.is_ascii_hexdigit())
        && let Ok(v) = u64::from_str_radix(hex, 16)
    {
        return Value::Hex(v);
    }
    if let Ok(i) = t.parse::<i64>() {
        return Value::Int(i);
    }
    Value::Str(s.to_string())
}

/// 若值是参数引用，解析为字符串；否则返回 None。
fn as_param<'a>(
    v: &'a Value,
    params: &Params,
    span: Span,
    what: &str,
) -> PktResult<Option<Cow<'a, str>>> {
    match v {
        Value::Param { name, default } => Ok(Some(Cow::Owned(param_value(
            params, name, default, span, what,
        )?))),
        _ => Ok(None),
    }
}

// ── 各层构造函数 ─────────────────────────────────────────────

const RAW_PARAMS: &[&str] = &["bytes"];
fn build_raw(call: &Call, params: &Params, env: &FnEnv) -> PktResult<RawData> {
    let mut a = Args::new(call, params, env, RAW_PARAMS)?;
    let bytes = match a.take("bytes")? {
        Some(arg) => val_bytes(&arg.value, arg.span, "bytes", params, env)?,
        None => Vec::new(),
    };
    a.finish()?;
    Ok(RawData { bytes, proto: None })
}

const HEX_PARAMS: &[&str] = &["str"];
fn build_hex(call: &Call, params: &Params, env: &FnEnv) -> PktResult<RawData> {
    let mut a = Args::new(call, params, env, HEX_PARAMS)?;
    let s = match a.take("str")? {
        Some(arg) => val_str(&arg.value, arg.span, "str", params, env)?,
        None => {
            return Err(Diagnostic::at(
                "`hex` 需要字符串参数，如 hex(\"deadbeef\")",
                call.span,
            ));
        }
    };
    a.finish()?;
    let bytes = hex_string_bytes(&s)
        .map_err(|msg| Diagnostic::at(format!("`hex` {msg}：`{s}`"), call.span))?;
    Ok(RawData { bytes, proto: None })
}

/// 十六进制字符串 → 字节：去空白、可选 `0x`/`0X` 前缀、须偶数长度纯 hex。
/// 值位置 hex、层位置 hex 与 `val_bytes`/`eval` 的 hex 调用共用同一条规则。
/// 返回错误文案（不带 `hex` 前缀，调用方补上下文）。
pub(crate) fn hex_string_bytes(s: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let hex = cleaned
        .strip_prefix("0x")
        .or_else(|| cleaned.strip_prefix("0X"))
        .unwrap_or(&cleaned);
    if !hex.len().is_multiple_of(2) || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("需要偶数长度的十六进制字符串（可带 0x 前缀）".to_string());
    }
    Ok((0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("已校验 hex"))
        .collect())
}

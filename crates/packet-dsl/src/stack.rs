//! 层栈咨询性检查（层序 / 承载关系）——**只警告，不阻断**。
//!
//! 本工具定位是「万用表」：`|>` 允许任意层包裹任意层，因为隧道/封装合法
//! （WireGuard / OpenVPN tun 的 `ipv4 |> udp`、VXLAN / Geneve 的 `eth |> udp`、
//! IPIP / 6to4 的 `ipv4 |> ipv4` 都是真实协议，严格分层反而会误杀），所以
//! **不做硬性校验**。但明显无意义的组合值得提示——序列化器对这类组合要么
//! 静默产出误导头字段（网络层 proto=0 / next_header=59 兜底），要么报难以
//! 理解的错误（`UnknownEthertype`）：
//!
//! - 应用层承载语义层（`tcp |> http`：层序颠倒）；
//! - 传输层承载传输层（`tcp |> udp`）；
//! - 链路层直接承载传输/应用/ICMP（`http |> eth`：缺网络层）；
//! - ICMP/ARP 承载语义层（`tcp |> icmp`，只应承载原始载荷）；
//! - 网络层直接承载应用层（`http |> ipv4`：协议号无法推断）；
//! - 裸协议违反其 `#[rule]` 声明的载体（`quic_initial |> tcp`——QUIC 声明载体
//!   `udp(dport=443)`，被包在 tcp 里；纯 `bytes(...)` 掩码无载体层 → 不校验）。
//!
//! 检查结果由宿主渲染为橙色 `note:` 警告（i18n），不影响序列化、发送与退出码。

use crate::ir::{Layer, PacketSpec};
use crate::proto::ResolvedProto;

/// 违反规范承载关系的相邻层对（`inner` 是 `outer` 的载荷）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackWarning {
    /// 内层（载荷）标识：层名（如 `tcp`）或裸协议名（如 `quic_initial`）。
    pub inner: String,
    /// 外层（包裹）层名，如 `udp`。
    pub outer: &'static str,
    /// 警告类别。
    pub kind: StackWarningKind,
    /// [`StackWarningKind::WrongCarrier`] 时 = 协议 `#[rule]` 声明的载体层集合
    /// （如 `["udp"]`）；其余类别为空。
    pub carriers: Vec<&'static str>,
}

/// 层序警告类别。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackWarningKind {
    /// 应用层承载语义层（如 `tcp` 是 `http` 的载荷）——层序疑似颠倒。
    ReversedOrder,
    /// 传输层承载传输层（如 `tcp` 是 `udp` 的载荷）。
    TransportInTransport,
    /// 链路层直接承载传输/应用/ICMP 层（如 `http` 是 `eth` 的载荷）——缺网络层。
    MissingNetwork,
    /// ICMP/ARP 承载语义层（应只承载原始载荷）。
    PayloadOnly,
    /// 网络层直接承载应用层（如 `http` 是 `ipv4` 的载荷）——协议号无法推断。
    UninferrableProto,
    /// 裸协议违反其 `#[rule]` 声明的载体层（如 `quic_initial` 是 `tcp` 的载荷，
    /// 但声明载体为 `udp(dport=443)`）。
    WrongCarrier,
}

/// 层名（与宿主 `engine` 展示一致）。
fn name(l: &Layer) -> &'static str {
    match l {
        Layer::Ethernet(_) => "eth",
        Layer::Arp(_) => "arp",
        Layer::Ipv4(_) => "ipv4",
        Layer::Ipv6(_) => "ipv6",
        Layer::Icmp(_) => "icmp",
        Layer::Tcp(_) => "tcp",
        Layer::Udp(_) => "udp",
        Layer::Http(_) => "http",
        Layer::Dns(_) => "dns",
        Layer::Raw(_) => "raw",
    }
}

/// 检查一个包的层栈（内 → 外），返回全部违反规范承载关系的相邻层对警告。
///
/// 只检查相邻对（`layers[i]` 为内层、`layers[i+1]` 为外层）；普通 `raw` 作为
/// 内层任意合法（原始载荷可出现在任何层里，如 `raw |> eth` 手工帧）。非规范
/// 但合理的封装（网络层/传输层承载另一套栈，如 `ipv4 |> udp`、`eth |> udp`、
/// `ipv4 |> ipv4`）不警告。
///
/// 具名裸协议（`RawData.proto` 有值，如 `quic_initial`）查当前 proto 注册表
/// （`set_proto_registry`）其 `#[rule]` 声明的载体层集合——外层不在集合内报
/// [`StackWarningKind::WrongCarrier`]；协议不在注册表 / 无载体层规则（纯
/// `bytes(...)` 掩码）时不校验。注册表覆盖 eng_lib 与库目录模块（与 dissect
/// 分派同源同限），用户文件内自建裸协议不在注册表 → 静默。
pub fn stack_warnings(spec: &PacketSpec) -> Vec<StackWarning> {
    stack_warnings_with(spec, crate::proto::proto_registry())
}

/// [`stack_warnings`] 的可注入注册表版本（测试用；`None` = 无注册表，
/// 具名裸协议一律静默）。
fn stack_warnings_with(spec: &PacketSpec, registry: &[ResolvedProto]) -> Vec<StackWarning> {
    let mut out = Vec::new();
    for pair in spec.layers.windows(2) {
        let inner = &pair[0];
        let outer = &pair[1];
        // 具名裸协议：查注册表 rule 载体集（其余 raw 载荷任意合法）
        if let Layer::Raw(raw) = inner {
            if let Some(proto_name) = raw.proto.as_deref()
                && let Some(carriers) = proto_carriers(registry, proto_name)
                && !carriers.iter().any(|c| *c == name(outer))
            {
                out.push(StackWarning {
                    inner: proto_name.to_string(),
                    outer: name(outer),
                    kind: StackWarningKind::WrongCarrier,
                    carriers,
                });
            }
            continue;
        }
        let Some(kind) = check_pair(inner, outer) else {
            continue;
        };
        out.push(StackWarning {
            inner: name(inner).to_string(),
            outer: name(outer),
            kind,
            carriers: Vec::new(),
        });
    }
    out
}

/// 裸协议的 `#[rule]` 载体层集合：遍历全部上下文原子（and/or 树内同层）取层名，
/// 去重排序；无载体层规则（纯 `bytes(...)` 掩码或未注册）→ None。
fn proto_carriers(registry: &[ResolvedProto], proto_name: &str) -> Option<Vec<&'static str>> {
    let rule = registry
        .iter()
        .find(|p| p.name == proto_name)?
        .rule
        .as_ref()?;
    let mut out = Vec::new();
    for c in &rule.ctxs {
        crate::proto::ctx_cond_layers(c, &mut out);
    }
    out.sort_unstable();
    out.dedup();
    (!out.is_empty()).then_some(out)
}

/// 相邻层对（inner 为 outer 的载荷）是否违反规范承载关系。
fn check_pair(inner: &Layer, outer: &Layer) -> Option<StackWarningKind> {
    match outer {
        // 应用层只应承载原始载荷
        Layer::Http(_) | Layer::Dns(_) => Some(StackWarningKind::ReversedOrder),
        // ICMP/ARP 只应承载原始载荷
        Layer::Icmp(_) | Layer::Arp(_) => Some(StackWarningKind::PayloadOnly),
        // 传输层不能承载传输层（其余任意：隧道封装 / 应用层载荷均允许）
        Layer::Tcp(_) | Layer::Udp(_) => matches!(inner, Layer::Tcp(_) | Layer::Udp(_))
            .then_some(StackWarningKind::TransportInTransport),
        // 链路层：缺网络层直挂传输/应用/ICMP（arp/ip/eth/raw 允许）
        Layer::Ethernet(_) => match inner {
            Layer::Tcp(_) | Layer::Udp(_) | Layer::Http(_) | Layer::Dns(_) | Layer::Icmp(_) => {
                Some(StackWarningKind::MissingNetwork)
            }
            _ => None,
        },
        // 网络层：http/dns 直挂 → 协议号无法推断（序列化静默兜底 proto=0/59）
        Layer::Ipv4(_) | Layer::Ipv6(_) => match inner {
            Layer::Http(_) | Layer::Dns(_) => Some(StackWarningKind::UninferrableProto),
            _ => None,
        },
        Layer::Raw(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{
        ArpFields, DnsFields, EthernetFields, HttpFields, IcmpFields, Ipv4Fields, Ipv6Fields,
        RawData, TcpFields, UdpFields,
    };
    use crate::proto::{CtxCond, MatchFn, Rule, RuleCond};

    fn raw() -> Layer {
        Layer::Raw(RawData {
            bytes: vec![0x78],
            proto: None,
        })
    }
    /// 具名裸协议层（如 `quic_initial` 构造产物）。
    fn named_raw(name: &str) -> Layer {
        Layer::Raw(RawData {
            bytes: vec![0xc0],
            proto: Some(name.to_string()),
        })
    }
    fn eth() -> Layer {
        Layer::Ethernet(EthernetFields::default())
    }
    fn arp() -> Layer {
        Layer::Arp(ArpFields::default())
    }
    fn ip4() -> Layer {
        Layer::Ipv4(Ipv4Fields::default())
    }
    fn ip6() -> Layer {
        Layer::Ipv6(Ipv6Fields::default())
    }
    fn icmp() -> Layer {
        Layer::Icmp(IcmpFields::default())
    }
    fn tcp() -> Layer {
        Layer::Tcp(TcpFields::default())
    }
    fn udp() -> Layer {
        Layer::Udp(UdpFields::default())
    }
    fn http() -> Layer {
        Layer::Http(HttpFields::default())
    }
    fn dns() -> Layer {
        Layer::Dns(DnsFields::default())
    }

    fn kinds(layers: Vec<Layer>) -> Vec<StackWarningKind> {
        stack_warnings(&PacketSpec { layers })
            .into_iter()
            .map(|w| w.kind)
            .collect()
    }

    /// 可注入注册表的检查（不污染全局 OnceLock，测试互不干扰）。
    fn kinds_with(layers: Vec<Layer>, registry: &[ResolvedProto]) -> Vec<StackWarning> {
        stack_warnings_with(&PacketSpec { layers }, registry)
    }

    /// 造一个带 `#[rule]` 载体声明的裸协议注册表条目。
    fn proto(name: &str, conds: Vec<RuleCond>) -> ResolvedProto {
        ResolvedProto {
            name: name.to_string(),
            layer: None,
            rule: Some(Rule {
                ctxs: conds.into_iter().map(CtxCond::Atom).collect(),
                matches: Vec::new(),
            }),
            params: Vec::new(),
            fields: Vec::new(),
        }
    }

    /// 纯 `bytes(...)` 掩码规则（无载体层）的裸协议。
    fn proto_mask_only(name: &str) -> ResolvedProto {
        ResolvedProto {
            name: name.to_string(),
            layer: None,
            rule: Some(Rule {
                ctxs: Vec::new(),
                matches: vec![MatchFn::Mask(0xc0)],
            }),
            params: Vec::new(),
            fields: Vec::new(),
        }
    }

    #[test]
    fn wrong_carrier_warns() {
        // quic_initial 声明载体 udp（dport=443）：包在 tcp/ipv4 里 → 警告，包在 udp 里 → 静默
        let reg = [proto(
            "quic_initial",
            vec![RuleCond::Udp {
                dport: Some(443),
                sport: None,
            }],
        )];
        let w = kinds_with(vec![named_raw("quic_initial"), tcp()], &reg);
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].kind, StackWarningKind::WrongCarrier);
        assert_eq!(w[0].inner, "quic_initial");
        assert_eq!(w[0].outer, "tcp");
        assert_eq!(w[0].carriers, vec!["udp"]);
        assert!(
            kinds_with(vec![named_raw("quic_initial"), udp()], &reg).is_empty(),
            "载体 udp 正确 → 静默"
        );
        assert!(!kinds_with(vec![named_raw("quic_initial"), ip4()], &reg).is_empty());
    }

    #[test]
    fn wrong_carrier_multi_layer() {
        // 多载体（DNS 式 udp+tcp 双规则）：udp/tcp 均合法，icmp 非法
        let reg = [proto(
            "dns_payload",
            vec![
                RuleCond::Udp {
                    dport: Some(53),
                    sport: None,
                },
                RuleCond::Tcp {
                    dport: Some(53),
                    sport: None,
                },
            ],
        )];
        assert!(kinds_with(vec![named_raw("dns_payload"), udp()], &reg).is_empty());
        assert!(kinds_with(vec![named_raw("dns_payload"), tcp()], &reg).is_empty());
        let w = kinds_with(vec![named_raw("dns_payload"), icmp()], &reg);
        assert_eq!(w[0].kind, StackWarningKind::WrongCarrier);
        // 载体集去重排序
        assert_eq!(w[0].carriers, vec!["tcp", "udp"]);
    }

    #[test]
    fn mask_only_and_unregistered_protos_are_silent() {
        // 纯 bytes 掩码规则 → 无载体层 → 不校验
        let mask_only = [proto_mask_only("quic_crypto")];
        assert!(
            kinds_with(vec![named_raw("quic_crypto"), tcp()], &mask_only).is_empty(),
            "无载体层规则 → 静默"
        );
        // 未注册的裸协议 → 静默（注册表覆盖 eng_lib，用户自建 proto 同理）
        assert!(
            kinds_with(vec![named_raw("my_thing"), tcp()], &[]).is_empty(),
            "未注册 → 静默"
        );
        // 公开入口（全局注册表）：未设置时对具名裸协议同样静默
        assert!(kinds(vec![named_raw("quic_initial"), tcp()]).is_empty());
    }

    #[test]
    fn canonical_stacks_are_silent() {
        // 规范栈：eth → ip → tcp → http
        assert!(kinds(vec![http(), tcp(), ip4(), eth()]).is_empty());
        assert!(kinds(vec![raw(), icmp(), ip4(), eth()]).is_empty());
        assert!(kinds(vec![raw(), dns(), udp(), ip6(), eth()]).is_empty());
        assert!(kinds(vec![raw(), tcp()]).is_empty());
        assert!(kinds(vec![raw(), eth()]).is_empty());
        assert!(kinds(vec![raw()]).is_empty());
    }

    #[test]
    fn tunnels_are_silent() {
        // 合法封装（打破严格分层）：网络层包在传输层里 / 链路层包在传输层里 / IP-in-IP
        assert!(kinds(vec![ip4(), udp()]).is_empty()); // WireGuard / OpenVPN tun
        assert!(kinds(vec![eth(), udp()]).is_empty()); // VXLAN / Geneve
        assert!(kinds(vec![ip4(), tcp()]).is_empty()); // OpenVPN tcp 模式
        assert!(kinds(vec![ip4(), ip4()]).is_empty()); // IPIP
        assert!(kinds(vec![ip6(), ip4()]).is_empty()); // 6to4 / 6in4
        assert!(kinds(vec![eth(), ip4()]).is_empty()); // L2TPv3 以太网封装
    }

    #[test]
    fn reversed_order_warns() {
        // tcp 是 http 的载荷：层序颠倒
        assert_eq!(
            kinds(vec![tcp(), http()]),
            vec![StackWarningKind::ReversedOrder]
        );
        // dns 承载 udp
        assert_eq!(
            kinds(vec![udp(), dns()]),
            vec![StackWarningKind::ReversedOrder]
        );
    }

    #[test]
    fn transport_in_transport_warns() {
        assert_eq!(
            kinds(vec![tcp(), udp()]),
            vec![StackWarningKind::TransportInTransport]
        );
        assert_eq!(
            kinds(vec![udp(), tcp()]),
            vec![StackWarningKind::TransportInTransport]
        );
        assert_eq!(
            kinds(vec![tcp(), tcp()]),
            vec![StackWarningKind::TransportInTransport]
        );
    }

    #[test]
    fn missing_network_warns() {
        assert_eq!(
            kinds(vec![http(), eth()]),
            vec![StackWarningKind::MissingNetwork]
        );
        assert_eq!(
            kinds(vec![tcp(), eth()]),
            vec![StackWarningKind::MissingNetwork]
        );
        assert_eq!(
            kinds(vec![icmp(), eth()]),
            vec![StackWarningKind::MissingNetwork]
        );
    }

    #[test]
    fn payload_only_warns() {
        assert_eq!(
            kinds(vec![tcp(), icmp()]),
            vec![StackWarningKind::PayloadOnly]
        );
        assert_eq!(
            kinds(vec![ip4(), arp()]),
            vec![StackWarningKind::PayloadOnly]
        );
        assert_eq!(
            kinds(vec![http(), icmp()]),
            vec![StackWarningKind::PayloadOnly]
        );
    }

    #[test]
    fn uninferrable_proto_warns() {
        assert_eq!(
            kinds(vec![http(), ip4()]),
            vec![StackWarningKind::UninferrableProto]
        );
        assert_eq!(
            kinds(vec![dns(), ip6()]),
            vec![StackWarningKind::UninferrableProto]
        );
    }

    #[test]
    fn multiple_warnings_in_one_stack() {
        // tcp |> http |> eth：http 承载 tcp（颠倒）+ eth 承载 http（缺网络层）
        assert_eq!(
            kinds(vec![tcp(), http(), eth()]),
            vec![
                StackWarningKind::ReversedOrder,
                StackWarningKind::MissingNetwork
            ]
        );
        // raw 载荷不触发任何警告
        assert!(
            kinds(vec![raw(), tcp(), udp(), ip4()])
                .contains(&StackWarningKind::TransportInTransport)
        );
    }
}

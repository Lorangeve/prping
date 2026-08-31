//! 语义分析测试：import 图、递归搜索、循环检测、名字解析/冲突。
//! 使用临时文件目录构造模块。

mod common;

use packet_dsl::Serializer;
use packet_dsl::semantic::parse_file;

fn parse_dir(
    name: &str,
    files: &[(&str, &str)],
    entry: &str,
) -> packet_dsl::diag::PktResult<packet_dsl::semantic::Module> {
    let dir = common::TempDir::new(name);
    for (rel, content) in files {
        dir.write(rel, content);
    }
    parse_file(dir.path().join(entry))
}

#[test]
fn import_braces_subset() {
    let m = parse_dir(
        "subset",
        &[
            ("a.pkt", "export:\n- a\n- b\n- c\na = http(start_line=\"GET / HTTP/1.1\")\nb = http(start_line=\"POST /login HTTP/1.1\")\nc = http(start_line=\"PUT / HTTP/1.1\")\n"),
            ("b.pkt", "import a { a, b }\nuse(a, b) |> tcp(dport=80)\n"),
        ],
        "b.pkt",
    )
    .expect("解析成功");
    assert_eq!(m.imports.len(), 1);
    assert_eq!(m.imports[0].names.as_ref().unwrap().len(), 2);
    // 求值应得到 2 个包（a、b × tcp）
    let built = packet_dsl::resolve(&m).expect("求值成功");
    assert_eq!(built.packets.len(), 2);
}

#[test]
fn import_all_exports_and_default() {
    // a.pkt 有命名导出 x + 默认导出（匿名流水线）；b 不带大括号引入全部。
    // 默认导出以模块名 `a` 进入作用域，可通过 use(a) 使用。
    let m = parse_dir(
        "all",
        &[
            (
                "a.pkt",
                "export:\n- x\nx = http()\nuse(x) |> udp(dport=53)\n",
            ),
            ("b.pkt", "import a\nuse(a) |> tcp(dport=80)\n"),
        ],
        "b.pkt",
    )
    .expect("解析成功");
    let built = packet_dsl::resolve(&m).expect("求值成功");
    // a 的默认导出（http+udp）再包 tcp → 1 个包
    assert_eq!(built.packets.len(), 1);
    assert!(matches!(
        built.packets[0].layers[0],
        packet_dsl::ir::Layer::Http(_)
    ));
    assert!(matches!(
        built.packets[0].layers[1],
        packet_dsl::ir::Layer::Udp(_)
    ));
    assert!(matches!(
        built.packets[0].layers[2],
        packet_dsl::ir::Layer::Tcp(_)
    ));
}

#[test]
fn recursive_subdir_search() {
    let m = parse_dir(
        "recursive",
        &[
            ("sub/deep/a.pkt", "export:\n- a\na = http()\n"),
            ("b.pkt", "import a\nuse(a) |> tcp()\n"),
        ],
        "b.pkt",
    )
    .expect("递归搜索应找到 sub/deep/a.pkt");
    let built = packet_dsl::resolve(&m).expect("求值成功");
    assert_eq!(built.packets.len(), 1);
}

#[test]
fn missing_module_is_error() {
    let err = parse_dir("missing", &[("b.pkt", "import nope\nuse(a)\n")], "b.pkt").unwrap_err();
    assert!(err.message.contains("找不到模块"), "{}", err.message);
}

#[test]
fn import_cycle_is_error() {
    let err = parse_dir(
        "cycle",
        &[
            ("a.pkt", "import b\nuse(x)\n"),
            ("b.pkt", "import a\nuse(y)\n"),
        ],
        "a.pkt",
    )
    .unwrap_err();
    assert!(err.message.contains("循环"), "{}", err.message);
}

#[test]
fn self_import_is_error() {
    let err = parse_dir("selfcycle", &[("a.pkt", "import a\nuse(x)\n")], "a.pkt").unwrap_err();
    assert!(err.message.contains("循环"), "{}", err.message);
}

#[test]
fn import_conflicts_with_local_def() {
    let err = parse_dir(
        "conflict",
        &[
            ("a.pkt", "export:\n- x\nx = http()\n"),
            ("b.pkt", "import a { x }\nx = tcp()\n"),
        ],
        "b.pkt",
    )
    .unwrap_err();
    assert!(err.message.contains("冲突"), "{}", err.message);
}

#[test]
fn use_unknown_name_is_error() {
    let err = parse_dir("unknown", &[("b.pkt", "use(ghost) |> tcp()\n")], "b.pkt").unwrap_err();
    assert!(err.message.contains("未定义"), "{}", err.message);
}

#[test]
fn export_unknown_name_is_error() {
    let err = parse_dir(
        "export-unknown",
        &[("b.pkt", "export:\n- ghost\na = http()\n")],
        "b.pkt",
    )
    .unwrap_err();
    assert!(err.message.contains("未定义"), "{}", err.message);
}

#[test]
fn import_nonexistent_export_is_error() {
    let err = parse_dir(
        "no-export",
        &[
            ("a.pkt", "export:\n- a\na = http()\n"),
            ("b.pkt", "import a { zzz }\n"),
        ],
        "b.pkt",
    )
    .unwrap_err();
    assert!(err.message.contains("没有导出"), "{}", err.message);
}

#[test]
fn duplicate_def_is_error() {
    let err = parse_dir("dupdef", &[("b.pkt", "a = http()\na = tcp()\n")], "b.pkt").unwrap_err();
    assert!(err.message.contains("重复定义"), "{}", err.message);
}

#[test]
fn reexport_chain_resolves() {
    // c 转出口 b 的 x（b 转出口 a 的 x）→ d 使用 x 应解析到 a
    let m = parse_dir(
        "reexport",
        &[
            (
                "a.pkt",
                "export:\n- x\nx = http(start_line=\"GET / HTTP/1.1\")\n",
            ),
            ("b.pkt", "import a\nexport:\n- x\n"),
            ("c.pkt", "import b\nexport:\n- x\n"),
            ("d.pkt", "import c\nuse(x) |> tcp()\n"),
        ],
        "d.pkt",
    )
    .expect("转出口链应解析成功");
    let built = packet_dsl::resolve(&m).expect("求值成功");
    assert_eq!(built.packets.len(), 1);
    assert!(matches!(
        built.packets[0].layers[0],
        packet_dsl::ir::Layer::Http(_)
    ));
}

#[test]
fn call_unknown_name_is_error() {
    // 定义体里调用未知元件/函数
    let err = parse_dir("call-unknown", &[("b.pkt", "x = ghostlayer()\n")], "b.pkt").unwrap_err();
    assert!(err.message.contains("未知层函数或元件"), "{}", err.message);
}

#[test]
fn component_reference_in_slot_works() {
    // 层位里引用用户元件（设计 §4.4 #2）
    let m = parse_dir(
        "slot-ref",
        &[(
            "b.pkt",
            "my = http(start_line=\"GET / HTTP/1.1\")\nuse(my) |> tcp(dport=80)\n",
        )],
        "b.pkt",
    )
    .expect("解析成功");
    let built = packet_dsl::resolve(&m).expect("求值成功");
    assert_eq!(built.packets.len(), 1);
    assert_eq!(built.packets[0].layers.len(), 2);
}

#[test]
fn multiple_default_pipelines_is_error() {
    let err = parse_dir(
        "multidefault",
        &[(
            "b.pkt",
            "a = raw()\nb = raw()\nuse(a) |> tcp()\nuse(b) |> udp()\n",
        )],
        "b.pkt",
    )
    .unwrap_err();
    assert!(err.message.contains("默认导出"), "{}", err.message);
}

// ── 函数：作用域 / import / 参数引用检查 ──────────────────────

#[test]
fn func_import_and_export() {
    // net.pkt 导出函数；b.pkt 显式 import 后调用
    let m = parse_dir(
        "func-import",
        &[
            (
                "net.pkt",
                "func net4(dst, src=\"0.0.0.0\") {\n    ipv4(src=src, dst=dst) |> eth()\n}\nexport:\n- net4\n",
            ),
            (
                "b.pkt",
                "import net { net4 }\nfunc wrap(dst) { use(web) |> net4(dst=dst) }\nweb = http()\nuse(wrap) \n",
            ),
        ],
        "b.pkt",
    )
    .expect("解析成功");
    let built = packet_dsl::resolve(&m).expect("求值成功");
    assert_eq!(built.packets.len(), 1);
    assert_eq!(
        built.packets[0].layers.len(),
        3,
        "http+ipv4+eth，实际 {}",
        built.packets[0].layers.len()
    );
}

#[test]
fn func_ident_must_be_declared() {
    // 函数体里引用了未声明参数 → 语义错误（防拼写错误）
    let d = parse_dir(
        "func-undecl",
        &[(
            "a.pkt",
            "func f(dst) { ipv4(dst=dts) |> eth() }\nuse(f) |> tcp()\n",
        )],
        "a.pkt",
    )
    .unwrap_err();
    assert!(d.to_string().contains("未声明参数 `dts`"), "{}", d);
}

#[test]
fn func_ident_outside_func_is_error() {
    // 非函数定义里不允许参数引用
    let d = parse_dir(
        "ident-outside",
        &[("a.pkt", "x = tcp(dport=dport)\nuse(x)\n")],
        "a.pkt",
    )
    .unwrap_err();
    assert!(d.to_string().contains("只能出现在函数体内"), "{}", d);
}

#[test]
fn func_default_ident_must_be_declared() {
    let d = parse_dir(
        "func-default-ident",
        &[("a.pkt", "func f(a=b) { tcp(dport=a) }\nuse(f)\n")],
        "a.pkt",
    )
    .unwrap_err();
    assert!(d.to_string().contains("默认值引用未声明参数 `b`"), "{}", d);
}

#[test]
fn func_and_def_duplicate_name() {
    let d = parse_dir(
        "func-dup",
        &[("a.pkt", "func f() { tcp() }\nf = http()\nuse(f)\n")],
        "a.pkt",
    )
    .unwrap_err();
    assert!(d.to_string().contains("重复定义"), "{}", d);
}

// ── pkglang 库搜索（libs 目录）──────────────────────────────

/// 库目录：入口目录递归搜索之外，从库目录（直接 + 递归）兜底。
#[test]
fn lib_dirs_are_searched_after_entry_dir() {
    // 入口在 dirA/（无 net.pkt），库在 dirB/（直接 + 子目录递归）
    let entry = common::TempDir::new("lib-search-entry");
    let lib = common::TempDir::new("lib-search-lib");
    lib.write(
        "net.pkt",
        "func net4(dst) { ipv4(dst=dst) |> eth() }\nexport:\n- net4\n",
    );
    lib.write("inner/util.pkt", "x = raw(bytes=\"u\")\nexport:\n- x\n");
    let main = entry.write(
        "main.pkt",
        "import net { net4 }\nimport util { x }\nuse(x) |> net4(dst=\"1.2.3.4\")\n",
    );
    // 不带显式库 → 私有库模块 util 找不到（net 可从默认 eng_lib 解析）
    let err = packet_dsl::semantic::parse_file(&main).expect_err("无私有库应失败");
    assert!(err.to_string().contains("找不到模块 `util`"), "{}", err);
    // 带库 → 成功求值（net 直接命中 + util 递归命中）
    let m = packet_dsl::semantic::parse_file_with_libs(&main, &[lib.path().to_path_buf()])
        .expect("带库应成功");
    let built = packet_dsl::resolve(&m).expect("求值成功");
    assert_eq!(built.packets.len(), 1);
    assert_eq!(built.packets[0].layers.len(), 3, "raw+ipv4+eth");
}

/// eng_lib 标准库（仓库 eng_lib/ 源文件）可直接解析求值。
#[test]
fn eng_lib_modules_resolve() {
    let dir = common::TempDir::new("eng-lib");
    dir.write("net.pkt", include_str!("../../../eng_lib/net.pkt"));
    dir.write("data.pkt", include_str!("../../../eng_lib/data.pkt"));
    for f in ["net.pkt", "data.pkt"] {
        let m = packet_dsl::semantic::parse_file(dir.path().join(f)).expect("库文件应可解析");
        let built = packet_dsl::resolve(&m).expect("求值成功");
        assert!(!built.packets.is_empty(), "{f} 应有默认导出包");
    }
}

/// data 库底层组装：值位置 hex() → 字节载荷 → [raw, eth] 完整帧。
#[test]
fn data_lib_hex_payload_builds_frame() {
    let dir = common::TempDir::new("data-lib");
    dir.write("data.pkt", include_str!("../../../eng_lib/data.pkt"));
    dir.write(
        "main.pkt",
        "import data { eth_frame }\nframe = eth_frame(payload=hex(\"deadbeef\"), ethertype=0x0800)\nuse(frame)\n",
    );
    let m = packet_dsl::semantic::parse_file_with_libs(
        dir.path().join("main.pkt"),
        &[dir.path().to_path_buf()],
    )
    .expect("解析成功");
    let built = packet_dsl::resolve(&m).expect("求值成功");
    assert_eq!(built.packets.len(), 1);
    assert_eq!(built.packets[0].layers.len(), 2, "raw+eth");
    let ser = packet_dsl::DefaultSerializer::with_seed(1);
    let bytes = ser.serialize(&built.packets[0]).unwrap();
    // 以太网帧：14B 头后是 deadbeef
    assert_eq!(&bytes[14..18], &[0xde, 0xad, 0xbe, 0xef]);
}

// ── 库导出隐式可见（无需 import）────────────────────────────

/// libs 模块的命名导出直接进入作用域：脚本无需 import 即可调用。
#[test]
fn lib_exports_implicitly_visible() {
    let entry = common::TempDir::new("lib-implicit-entry");
    let lib = common::TempDir::new("lib-implicit-lib");
    lib.write(
        "net.pkt",
        "func net4(dst) { ipv4(dst=dst) |> eth() }\nexport:\n- net4\n",
    );
    let main = entry.write(
        "main.pkt",
        "p = raw(bytes=\"x\")\nuse(p) |> net4(dst=\"1.2.3.4\")\n",
    );
    let m = packet_dsl::semantic::parse_file_with_libs(&main, &[lib.path().to_path_buf()])
        .expect("库导出应隐式可见");
    let built = packet_dsl::resolve(&m).expect("求值成功");
    assert_eq!(built.packets.len(), 1);
    assert_eq!(built.packets[0].layers.len(), 3, "raw+ipv4+eth");
}

/// 显式 import 仍工作；本地定义优先于库导出（遮蔽不报错）。
#[test]
fn explicit_import_and_local_shadow_lib_export() {
    let entry = common::TempDir::new("lib-shadow-entry");
    let lib = common::TempDir::new("lib-shadow-lib");
    lib.write(
        "net.pkt",
        "func net4(dst) { ipv4(dst=dst) |> eth() }\nexport:\n- net4\n",
    );
    // 显式 import（子集）仍可用
    let main1 = entry.write(
        "explicit.pkt",
        "import net { net4 }\np = raw(bytes=\"x\")\nuse(p) |> net4(dst=\"5.6.7.8\")\n",
    );
    let m1 = packet_dsl::semantic::parse_file_with_libs(&main1, &[lib.path().to_path_buf()])
        .expect("显式 import 应可用");
    assert_eq!(packet_dsl::resolve(&m1).unwrap().packets.len(), 1);
    // 本地定义同名 → 遮蔽库导出（net4 用本地 http 定义）
    let main2 = entry.write(
        "local.pkt",
        "net4 = http(start_line=\"GET / HTTP/1.1\")\nuse(net4)\n",
    );
    let m2 = packet_dsl::semantic::parse_file_with_libs(&main2, &[lib.path().to_path_buf()])
        .expect("本地定义应遮蔽库导出");
    let built = packet_dsl::resolve(&m2).expect("求值成功");
    assert_eq!(
        built.packets[0].layers.len(),
        1,
        "应命中本地 http 而非库 net4"
    );
    assert!(
        matches!(built.packets[0].layers[0], packet_dsl::ir::Layer::Http(_)),
        "net4 应解析为本地 http"
    );
}

/// 库目录与默认 eng_lib 重叠（effective_libs 场景）时导出不重复枚举。
#[test]
fn lib_exports_dedupes_overlapping_lib_dirs() {
    let defaults = packet_dsl::default_libs();
    assert!(!defaults.is_empty(), "开发环境应有默认 eng_lib");
    let once = packet_dsl::lib_exports(&[]);
    // 显式传入默认 eng_lib 与不传结果一致（不去重会翻倍）
    let twice = packet_dsl::lib_exports(&defaults);
    assert_eq!(once.len(), twice.len(), "重叠库目录应去重");
    assert!(!once.is_empty(), "默认库应有导出");
    // 同名导出（模块 + 名称）不得出现两次
    let mut seen = std::collections::HashSet::new();
    for e in &twice {
        assert!(
            seen.insert((e.module.clone(), e.name.clone())),
            "重复导出：{}.{}",
            e.module,
            e.name
        );
    }
}

/// lib_functions 枚举全部声明函数（含未导出，标注模块）。
#[test]
fn lib_functions_include_unexported() {
    let defaults = packet_dsl::default_libs();
    assert!(!defaults.is_empty(), "开发环境应有默认 eng_lib");
    let fns = packet_dsl::lib_functions(&[]);
    let by_name = |n: &str| fns.iter().find(|f| f.name == n);
    // headers.pkt 声明但未导出的辅助函数（其 export 列表只有层函数）
    let hdr = by_name("hdr_line").expect("hdr_line 应在 lib_functions 中");
    assert_eq!(hdr.module, "headers");
    assert!(hdr.is_proto, "hdr_line 是 #[proto] 函数");
    // dns.pkt 无 export 块：其全部函数仍应枚举（可经 import dns { dns_question } 引入）
    assert!(by_name("dns_question").is_some(), "dns_question 应枚举");
    assert!(by_name("dns_answer").is_some(), "dns_answer 应枚举");
    // 导出项同样在其中（与 lib_exports 重叠，调用方按名去重）
    assert!(by_name("tcp").is_some(), "导出函数也应枚举");
    // 参数签名携带（proto 函数取 schema 字段）
    let dns_q = by_name("dns_question").expect("dns_question 应存在");
    let params = dns_q.params.as_ref().expect("函数应携带参数");
    assert!(
        params.iter().any(|p| p.name == "name"),
        "dns_question 应有 name 参数"
    );
}

/// 函数上方的 `#` 注释（含 @param/@auto 标签）作为 doc 随库导出携带（--ls / LSP 悬停展示）。
#[test]
fn lib_exports_carry_func_doc() {
    let entry = common::TempDir::new("lib-doc-entry");
    let lib = common::TempDir::new("lib-doc-lib");
    lib.write(
        "doc.pkt",
        "# 带注释的库函数：说明用途\n# @param dst: 目标地址（可域名）\n# @auto: 自动补校验和\nfunc with_doc(dst) { ipv4(dst=dst) |> eth() }\nfunc no_doc(dst) { ipv4(dst=dst) |> eth() }\nexport:\n- with_doc\n- no_doc\n",
    );
    let main = entry.write(
        "main.pkt",
        "p = raw(bytes=\"x\")\nuse(p) |> with_doc(dst=\"1.2.3.4\")\n",
    );
    // 解析走 lib 导出（隐式可见）
    let m = packet_dsl::semantic::parse_file_with_libs(&main, &[lib.path().to_path_buf()])
        .expect("解析成功");
    assert_eq!(packet_dsl::resolve(&m).unwrap().packets.len(), 1);
    // lib_exports 携带结构化 doc
    let exports = packet_dsl::lib_exports(&[lib.path().to_path_buf()]);
    let with_doc = exports
        .iter()
        .find(|e| e.name == "with_doc")
        .expect("with_doc 应导出");
    let doc = with_doc.doc.as_ref().expect("with_doc 应有 doc");
    assert_eq!(doc.summary, "带注释的库函数：说明用途");
    assert_eq!(
        doc.params,
        vec![("dst".to_string(), "目标地址（可域名）".to_string())]
    );
    assert_eq!(doc.auto.as_deref(), Some("自动补校验和"));
    let no_doc = exports
        .iter()
        .find(|e| e.name == "no_doc")
        .expect("no_doc 应导出");
    assert!(no_doc.doc.is_none(), "无注释函数 doc 应为 None");
}

// ── 模块系统修复：prelude 转出口 / 库目录诊断 ────────────────

/// 转出口的名字来自库 prelude（b 未显式 import，tcp 经注入隐式可见）：
/// `import b { tcp }` 应回退到库模块定位定义，而不是报「没有导出元件」。
#[test]
fn reexport_of_prelude_lib_export_resolves() {
    let m = parse_dir(
        "reexport-prelude",
        &[
            ("b.pkt", "export:\n- tcp\n"),
            (
                "main.pkt",
                "import b { tcp }\np = raw(bytes=\"aa\")\nuse(p) |> tcp(dport=80)\n",
            ),
        ],
        "main.pkt",
    )
    .expect("prelude 转出口应解析成功");
    let built = packet_dsl::resolve(&m).expect("求值成功");
    assert_eq!(built.packets.len(), 1);
    assert!(
        built.packets[0]
            .layers
            .iter()
            .any(|l| matches!(l, packet_dsl::ir::Layer::Tcp(_))),
        "tcp 应解析到库导出"
    );
    // 不带大括号（引入全部导出）也应走同一回退路径
    let m2 = parse_dir(
        "reexport-prelude-all",
        &[
            ("b.pkt", "export:\n- tcp\n"),
            (
                "main.pkt",
                "import b\np = raw(bytes=\"bb\")\nuse(p) |> tcp(dport=81)\n",
            ),
        ],
        "main.pkt",
    )
    .expect("prelude 转出口（全量引入）应解析成功");
    let built2 = packet_dsl::resolve(&m2).expect("求值成功");
    assert!(
        built2.packets[0]
            .layers
            .iter()
            .any(|l| matches!(l, packet_dsl::ir::Layer::Tcp(_))),
        "tcp 应解析到库导出"
    );
}

/// 多级转出口链（b 转出口 prelude，c 再转出口 b）最终应解析到库模块。
#[test]
fn reexport_chain_through_prelude_resolves() {
    let m = parse_dir(
        "reexport-prelude-chain",
        &[
            ("b.pkt", "export:\n- tcp\n"),
            ("c.pkt", "import b\nexport:\n- tcp\n"),
            (
                "d.pkt",
                "import c { tcp }\np = raw(bytes=\"aa\")\nuse(p) |> tcp(dport=80)\n",
            ),
        ],
        "d.pkt",
    )
    .expect("prelude 转出口链应解析成功");
    let built = packet_dsl::resolve(&m).expect("求值成功");
    assert_eq!(built.packets.len(), 1);
    assert!(
        built.packets[0]
            .layers
            .iter()
            .any(|l| matches!(l, packet_dsl::ir::Layer::Tcp(_))),
        "tcp 应解析到库导出"
    );
}

/// 同一库目录内两个模块导出同名 → 报错（消除 readdir 顺序导致的非确定性遮蔽）。
#[test]
fn lib_duplicate_export_across_files_is_error() {
    let entry = common::TempDir::new("lib-dup2-entry");
    let lib = common::TempDir::new("lib-dup2-lib");
    lib.write("a.pkt", "func dup() { tcp() }\nexport:\n- dup\n");
    lib.write("b.pkt", "func dup() { udp() }\nexport:\n- dup\n");
    let main = entry.write("main.pkt", "p = raw(bytes=\"x\")\nuse(p) |> tcp()\n");
    let err = packet_dsl::semantic::parse_file_with_libs(&main, &[lib.path().to_path_buf()])
        .expect_err("同目录导出名重复应报错");
    let msg = err.to_string();
    assert!(msg.contains("导出名重复"), "{msg}");
    assert!(msg.contains("`dup`"), "{msg}");
    assert!(msg.contains("a.pkt") && msg.contains("b.pkt"), "{msg}");
}

/// 同一库模块内导出同名两次 → 报错。
#[test]
fn lib_duplicate_export_in_same_file_is_error() {
    let entry = common::TempDir::new("lib-dup1-entry");
    let lib = common::TempDir::new("lib-dup1-lib");
    lib.write("a.pkt", "func dup() { tcp() }\nexport:\n- dup\n- dup\n");
    let main = entry.write("main.pkt", "p = raw(bytes=\"x\")\nuse(p) |> tcp()\n");
    let err = packet_dsl::semantic::parse_file_with_libs(&main, &[lib.path().to_path_buf()])
        .expect_err("同一文件重复导出应报错");
    assert!(err.to_string().contains("导出名重复"), "{}", err);
}

/// 跨库目录同名导出仍允许（显式 lib 覆盖标准库的既有语义）。
#[test]
fn lib_duplicate_export_across_dirs_is_allowed() {
    let entry = common::TempDir::new("lib-dupdir-entry");
    let lib1 = common::TempDir::new("lib-dupdir-1");
    let lib2 = common::TempDir::new("lib-dupdir-2");
    lib1.write(
        "net.pkt",
        "func net4(dst) { ipv4(dst=dst) |> eth() }\nexport:\n- net4\n",
    );
    lib2.write(
        "net.pkt",
        "func net4(dst) { ipv4(dst=dst) |> eth() }\nexport:\n- net4\n",
    );
    let main = entry.write(
        "main.pkt",
        "p = raw(bytes=\"x\")\nuse(p) |> net4(dst=\"1.2.3.4\")\n",
    );
    let m = packet_dsl::semantic::parse_file_with_libs(
        &main,
        &[lib1.path().to_path_buf(), lib2.path().to_path_buf()],
    )
    .expect("跨目录同名导出应允许（后目录覆盖）");
    assert_eq!(packet_dsl::resolve(&m).unwrap().packets.len(), 1);
}

/// 库模块语法错误 → 报诊断并指向库文件（不再静默丢弃后表现为「未知层函数」）。
#[test]
fn lib_parse_error_is_reported_with_file() {
    let entry = common::TempDir::new("lib-bad-entry");
    let lib = common::TempDir::new("lib-bad-lib");
    lib.write("broken.pkt", "func f( { tcp() }\n");
    let main = entry.write("main.pkt", "p = raw(bytes=\"x\")\nuse(p) |> tcp()\n");
    let err = packet_dsl::semantic::parse_file_with_libs(&main, &[lib.path().to_path_buf()])
        .expect_err("库语法错误应报诊断");
    assert!(err.to_string().contains("broken.pkt"), "{}", err);
}

/// 显式传入的库目录不存在 → 报诊断（不再静默忽略）。
#[test]
fn lib_missing_dir_is_error() {
    let entry = common::TempDir::new("lib-missing-entry");
    let main = entry.write("main.pkt", "p = raw(bytes=\"x\")\nuse(p) |> tcp()\n");
    let err =
        packet_dsl::semantic::parse_file_with_libs(&main, &[entry.path().join("no-such-lib")])
            .expect_err("不存在的库目录应报错");
    assert!(err.to_string().contains("库目录"), "{}", err);
}

// ── 模块系统修复：per-importer 目录解析（A1/A3）───────────────

/// 同名模块在不同目录共存：每个 import 按**自身模块的目录**解析，不再被全局名字表错绑。
/// （回归：root/mid.pkt 的 import leaf 曾静默绑定到 sub/leaf.pkt，且结果依赖 import 顺序。）
#[test]
fn per_importer_dir_resolution() {
    let files = [
        ("leaf.pkt", "leaf = hex(\"aa\")\nexport:\n- leaf\n"),
        ("sub/leaf.pkt", "leaf = hex(\"bb\")\nexport:\n- leaf\n"),
        ("mid.pkt", "import leaf\nuse(leaf)\n"),
        ("sub/submid.pkt", "import leaf\nuse(leaf)\n"),
    ];
    let check = |main_src: &str| {
        let m = parse_dir(
            "per-importer",
            &[
                files[0],
                files[1],
                files[2],
                files[3],
                ("main.pkt", main_src),
            ],
            "main.pkt",
        )
        .expect("per-importer 解析应成功");
        let built = packet_dsl::resolve(&m).expect("求值成功");
        assert_eq!(built.packets.len(), 2);
        let ser = packet_dsl::DefaultSerializer::with_seed(1);
        let b0 = ser.serialize(&built.packets[0]).unwrap();
        let b1 = ser.serialize(&built.packets[1]).unwrap();
        (*b0.last().unwrap(), *b1.last().unwrap())
    };
    let (p0, q0) = check(
        "import mid\nimport submid\np = use(mid) |> tcp(dport=80)\nq = use(submid) |> tcp(dport=81)\nexport:\n- p\n- q\n",
    );
    assert_eq!(p0, 0xaa, "p 应命中 root/leaf.pkt");
    assert_eq!(q0, 0xbb, "q 应命中 sub/leaf.pkt");
    // 交换 import 顺序结果不变（不再依赖处理顺序）
    let (p1, q1) = check(
        "import submid\nimport mid\np = use(mid) |> tcp(dport=80)\nq = use(submid) |> tcp(dport=81)\nexport:\n- p\n- q\n",
    );
    assert_eq!(p1, 0xaa, "交换顺序后 p 仍应命中 root/leaf.pkt");
    assert_eq!(q1, 0xbb, "交换顺序后 q 仍应命中 sub/leaf.pkt");
}

/// 入口目录自己的 headers.pkt 应遮蔽默认 eng_lib 的同名模块：显式 `import headers`
/// 绑定本地文件（旧行为：库种子先入图，本地文件被静默无视）。
#[test]
fn local_module_shadows_lib_for_import() {
    let m = parse_dir(
        "local-vs-lib",
        &[
            (
                "headers.pkt",
                "func tcp(dport) { http(start_line=\"LOCAL / HTTP/1.1\") |> udp(dport=dport) }\nexport:\n- tcp\n",
            ),
            (
                "main.pkt",
                "import headers { tcp }\np = raw(bytes=\"x\")\nuse(p) |> tcp(dport=80)\n",
            ),
        ],
        "main.pkt",
    )
    .expect("本地模块应优先于库同名模块");
    let built = packet_dsl::resolve(&m).expect("求值成功");
    assert_eq!(
        built.packets[0].layers.len(),
        3,
        "raw+http+udp（本地 tcp），实际 {}",
        built.packets[0].layers.len()
    );
    assert!(
        matches!(built.packets[0].layers[1], packet_dsl::ir::Layer::Http(_)),
        "tcp 应解析到本地模块而非库 tcp"
    );
}

/// 显式 lib 覆盖默认 eng_lib：自定义 lib 的 net.pkt 与 eng_lib 同名，
/// `import net` 命中自定义 lib（find_module 库搜索从后往前，与 prelude 注入胜者一致）。
#[test]
fn explicit_lib_overrides_default_eng_lib_import() {
    let entry = common::TempDir::new("lib-override-entry");
    let lib = common::TempDir::new("lib-override-lib");
    lib.write(
        "net.pkt",
        "func net4(dst) { http(start_line=\"CUSTOM / HTTP/1.1\") }\nexport:\n- net4\n",
    );
    let main = entry.write(
        "main.pkt",
        "import net { net4 }\np = raw(bytes=\"x\")\nuse(p) |> net4(dst=\"1.2.3.4\")\n",
    );
    let m = packet_dsl::semantic::parse_file_with_libs(&main, &[lib.path().to_path_buf()])
        .expect("自定义 lib 应覆盖 eng_lib");
    let built = packet_dsl::resolve(&m).expect("求值成功");
    assert_eq!(built.packets[0].layers.len(), 2, "raw+http（自定义 net4）");
    assert!(
        matches!(built.packets[0].layers[1], packet_dsl::ir::Layer::Http(_)),
        "net4 应命中自定义 lib 而非 eng_lib"
    );
}

// ── import 别名（`x as ax`）──────────────────────────────────

/// `import a { x as ax }`：ax 可用且命中 a.x；原名 x 不再可见。
#[test]
fn import_alias_resolves() {
    let m = parse_dir(
        "alias",
        &[
            (
                "a.pkt",
                "export:\n- x\nx = http(start_line=\"GET / HTTP/1.1\")\n",
            ),
            ("b.pkt", "import a { x as ax }\nuse(ax) |> tcp(dport=80)\n"),
        ],
        "b.pkt",
    )
    .expect("别名 import 应成功");
    let built = packet_dsl::resolve(&m).expect("求值成功");
    assert_eq!(built.packets.len(), 1);
    assert!(
        matches!(built.packets[0].layers[0], packet_dsl::ir::Layer::Http(_)),
        "ax 应解析到 a.x"
    );
    // 原名 x 不再进入作用域
    let err = parse_dir(
        "alias-orig",
        &[
            ("a.pkt", "export:\n- x\nx = http()\n"),
            ("b.pkt", "import a { x as ax }\nuse(x) |> tcp()\n"),
        ],
        "b.pkt",
    )
    .unwrap_err();
    assert!(err.message.contains("未定义"), "{}", err.message);
}

/// 两模块导出同名 tcp：别名后无冲突，各自可用（B3 的核心痛点）。
#[test]
fn import_alias_disambiguates_same_name() {
    let m = parse_dir(
        "alias-two",
        &[
            ("a.pkt", "func tcp(dport) { udp(dport=dport) }\nexport:\n- tcp\n"),
            (
                "b.pkt",
                "func tcp(dport) { http(start_line=\"B / HTTP/1.1\") }\nexport:\n- tcp\n",
            ),
            (
                "main.pkt",
                "import a { tcp as tcp_a }\nimport b { tcp as tcp_b }\np = raw(bytes=\"x\")\nq = use(p) |> tcp_a(dport=1)\nr = use(q) |> tcp_b(dport=2)\nuse(r)\n",
            ),
        ],
        "main.pkt",
    )
    .expect("同名导出别名后应无冲突");
    let built = packet_dsl::resolve(&m).expect("求值成功");
    assert_eq!(built.packets[0].layers.len(), 3, "raw+udp+http");
    assert!(
        matches!(built.packets[0].layers[1], packet_dsl::ir::Layer::Udp(_)),
        "tcp_a 应命中 a 的 udp 版本"
    );
    assert!(
        matches!(built.packets[0].layers[2], packet_dsl::ir::Layer::Http(_)),
        "tcp_b 应命中 b 的 http 版本"
    );
}

/// 别名与本地定义冲突 → 报错。
#[test]
fn import_alias_conflicts_with_local() {
    let err = parse_dir(
        "alias-conflict",
        &[
            ("a.pkt", "export:\n- x\nx = http()\n"),
            ("b.pkt", "import a { x as y }\ny = tcp()\n"),
        ],
        "b.pkt",
    )
    .unwrap_err();
    assert!(err.message.contains("冲突"), "{}", err.message);
}

/// 转出口链 + 别名：`import c { x as cx }` 解析到最终定义（a.x）。
#[test]
fn import_alias_through_reexport() {
    let m = parse_dir(
        "alias-reexport",
        &[
            (
                "a.pkt",
                "export:\n- x\nx = http(start_line=\"GET / HTTP/1.1\")\n",
            ),
            ("c.pkt", "import a\nexport:\n- x\n"),
            ("d.pkt", "import c { x as cx }\nuse(cx) |> tcp(dport=80)\n"),
        ],
        "d.pkt",
    )
    .expect("转出口别名应成功");
    let built = packet_dsl::resolve(&m).expect("求值成功");
    assert!(
        matches!(built.packets[0].layers[0], packet_dsl::ir::Layer::Http(_)),
        "cx 应解析到 a.x"
    );
}

/// prelude 库导出（经转出口）+ 别名组合：`import b { tcp as mytcp }`。
#[test]
fn import_alias_of_prelude_reexport() {
    let m = parse_dir(
        "alias-lib",
        &[
            ("b.pkt", "export:\n- tcp\n"),
            (
                "main.pkt",
                "import b { tcp as mytcp }\np = raw(bytes=\"x\")\nuse(p) |> mytcp(dport=80)\n",
            ),
        ],
        "main.pkt",
    )
    .expect("prelude 导出别名应成功");
    let built = packet_dsl::resolve(&m).expect("求值成功");
    assert!(
        built.packets[0]
            .layers
            .iter()
            .any(|l| matches!(l, packet_dsl::ir::Layer::Tcp(_))),
        "mytcp 应解析到库 tcp"
    );
}

/// 模块同时有默认导出与同名命名元件：无括号 import 报清晰诊断（提示显式列表），
/// 显式 `import a { a }` 仍可用（绑定命名元件）。
#[test]
fn default_export_colliding_with_named_component_is_clear_error() {
    let err = parse_dir(
        "default-collide",
        &[
            (
                "a.pkt",
                "export:\n- a\na = http(start_line=\"GET / HTTP/1.1\")\nuse(a) |> tcp(dport=80)\n",
            ),
            ("b.pkt", "import a\nuse(a) |> tcp()\n"),
        ],
        "b.pkt",
    )
    .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("无法区分"), "{msg}");
    assert!(msg.contains("import a { a }"), "{msg}");
    // 显式列表引入命名元件不受影响
    let m = parse_dir(
        "default-collide-explicit",
        &[
            (
                "a.pkt",
                "export:\n- a\na = http(start_line=\"GET / HTTP/1.1\")\nuse(a) |> tcp(dport=80)\n",
            ),
            ("b.pkt", "import a { a }\nuse(a) |> tcp(dport=81)\n"),
        ],
        "b.pkt",
    )
    .expect("显式列表应可用");
    let built = packet_dsl::resolve(&m).expect("求值成功");
    assert!(
        matches!(built.packets[0].layers[0], packet_dsl::ir::Layer::Http(_)),
        "a 应解析为命名元件"
    );
}

//! 语义分析：import 图构建、循环依赖检测、名字解析。
//!
//! - 文件名 = 包名；`import a { a, b }` 以当前文件目录为根递归搜索 `a.pkt`。
//! - import 按**每模块目录**解析：同名文件在不同目录可共存，各自绑定到本目录
//!   找到的模块实例；库目录从后往前搜索（显式 lib 优先于默认 eng_lib）。
//! - `import a`（不带大括号）引入默认导出（模块名）+ 全部命名导出。
//! - 名字冲突（本地定义 vs import、重复定义、重复导入）一律报错并带 span。
//! - 转出口（import 再 export）在解析期解析到最终定义模块；转出口来自库
//!   prelude（未显式 import）时回退到库模块集合定位定义。
//! - 库目录诊断：不可读 / 模块语法错误 / 同库目录内导出名重复 → 报错（不静默丢弃）。

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::ast::{self, AstFile, Call, Expr, ImportStmt, LenTarget, Pipeline, Span, Stmt, Value};
use crate::diag::{Diagnostic, PktResult};
use crate::parser::parse_ast;
use crate::registry::is_builtin;

/// 模块图：全部解析出的模块（按规范路径去重）。
///
/// import 是**每模块解析**的：同名文件在不同目录可以共存，各自按 import 语句所属
/// 模块的目录（+ 库目录，显式 lib 优先）解析到不同的模块实例；没有全局名字表。
#[derive(Debug, Default)]
pub(crate) struct ModuleGraph {
    pub modules: Vec<Arc<ModuleData>>,
    /// 规范路径 → modules 下标。
    pub by_path: HashMap<PathBuf, usize>,
    /// 每模块的 import 边：(目标模块下标, import 语句 span)，与 `imports_of(ast)` 同序。
    pub(crate) module_imports: Vec<Vec<(usize, Span)>>,
    /// 每模块名字作用域（名字 → 定义位置），供求值使用。
    pub(crate) scopes: Vec<HashMap<String, ScopeEntry>>,
}

/// 一个解析出的模块内容。
#[derive(Debug)]
pub(crate) struct ModuleData {
    pub name: String,
    pub path: PathBuf,
    pub ast: AstFile,
    /// 是否库模块（libs 目录自动加载；其 export 对全体模块隐式可见）。
    pub is_lib: bool,
}

impl ModuleGraph {
    /// 取某模块某定义的下标对应的表达式。
    pub(crate) fn def_expr(&self, module: usize, def_idx: usize) -> Option<&Expr> {
        let defs = defs_of(&self.modules[module].ast);
        defs.get(def_idx).map(|d| &d.expr)
    }

    /// 某模块某函数的下标对应的定义（proto 函数即带 schema 的 FuncStmt，同一下标空间）。
    pub(crate) fn func_def(&self, module: usize, func_idx: usize) -> Option<&ast::FuncStmt> {
        funcs_of(&self.modules[module].ast).get(func_idx).copied()
    }

    /// 某模块的默认导出流水线。
    pub(crate) fn default_pipeline(&self, module: usize) -> Option<&Pipeline> {
        default_of(&self.modules[module].ast).map(|(p, _)| p)
    }

    /// 当前模块 `idx` 中名字 `name` 的定义位置。
    pub(crate) fn lookup(&self, idx: usize, name: &str) -> Option<(usize, LookupKind)> {
        let entry = self.scopes.get(idx)?.get(name)?;
        match entry {
            ScopeEntry::Local(j) => Some((idx, LookupKind::Def(*j))),
            ScopeEntry::Func(j) => Some((idx, LookupKind::Func(*j))),
            // 别名场景下作用域键 ≠ 目标模块定义名：用 Imported 携带的原名定位
            ScopeEntry::Imported(m, orig) => {
                if let Some(j) = local_def_index(self, *m, orig) {
                    Some((*m, LookupKind::Def(j)))
                } else {
                    local_func_index(self, *m, orig).map(|j| (*m, LookupKind::Func(j)))
                }
            }
            ScopeEntry::Default(m) => Some((*m, LookupKind::Default)),
        }
    }
}

/// 名字解析后的定义位置。
#[derive(Debug, Clone, Copy)]
pub(crate) enum LookupKind {
    /// 模块内 defs 下标。
    Def(usize),
    /// 模块内 funcs 下标（含 proto 函数——proto = 带 schema 的 FuncStmt）。
    Func(usize),
    /// 模块的默认导出流水线。
    Default,
}

/// 解析后的入口模块（公开面）。
#[derive(Debug, Clone)]
pub struct Module {
    pub name: String,
    pub path: Option<PathBuf>,
    /// `export:` 列出的名字（已校验存在）。
    pub exports: Vec<(String, Span)>,
    /// 顶层匿名流水线（默认导出）。
    pub default: Option<(Pipeline, Span)>,
    /// 本文件定义。
    pub defs: Vec<Def>,
    /// 本文件函数。
    pub funcs: Vec<Func>,
    /// 本文件 proto（声明式自表示协议，M1 构造侧）。
    pub protos: Vec<Proto>,
    /// `sniffer { match ... }` 回包匹配声明（None = 未声明；--pkt --wait 用）。
    pub sniffer: Option<ast::SnifferSpec>,
    /// 解析后的 import（names=None = 引入全部）。
    pub imports: Vec<ResolvedImport>,
    pub(crate) graph: Arc<ModuleGraph>,
}

/// 一个命名元件定义。
#[derive(Debug, Clone)]
pub struct Def {
    pub name: String,
    pub name_span: Span,
    pub expr: Expr,
    pub span: Span,
}

/// 一个具名参数化函数（`func name(args) { body }`）。
#[derive(Debug, Clone)]
pub struct Func {
    pub name: String,
    pub name_span: Span,
    pub params: Vec<FuncParam>,
    pub body: Pipeline,
    pub span: Span,
    /// 紧贴函数上方的 `#` doc 注释（LSP 悬停等展示用；无则 None）。
    pub doc: Option<ast::FuncDoc>,
}

/// 一个声明式协议（`#[proto] func`，注解 `#[proto(kind=...)]? #[rule(...)]*`）。
#[derive(Debug, Clone)]
pub struct Proto {
    pub name: String,
    pub name_span: Span,
    /// 注解声明的 IR 层类型（eth/arp/...）；None = 裸协议（构造/解析但非 IR 层，如 QUIC）。
    pub layer: Option<String>,
    /// `#[rule]` 注解合并出的分派规则（AND；None = 不参与 dissect 自动分派）。
    pub rule: Option<crate::proto::Rule>,
    /// 值参数（只参与构造：字段默认值/宽度可引用）。
    pub params: Vec<FuncParam>,
    pub fields: Vec<ast::FieldDecl>,
    pub span: Span,
}

/// 函数参数：`IDENT`（未设）或 `IDENT = 默认值`。
#[derive(Debug, Clone)]
pub struct FuncParam {
    pub name: String,
    pub span: Span,
    pub default: Option<Value>,
}

/// 解析后的 import。
#[derive(Debug, Clone)]
pub struct ResolvedImport {
    pub module: String,
    /// None = 引入全部导出（含默认导出）；Some = 显式列表，(原名, 别名, span)，
    /// 别名 None = 原名（`x as y` 时别名 y 才是作用域里的名字）。
    pub names: Option<Vec<(String, Option<String>, Span)>>,
    pub span: Span,
}

// ── 入口 ─────────────────────────────────────────────────────

/// 解析文件（含其 import 图）+ 语义分析，返回入口模块。
/// 默认库目录：仓库 `eng_lib/`（pkglang 标准库，发布为 `lib/`）。
///
/// 路径在编译期烘焙（`CARGO_MANIFEST_DIR/../eng_lib`）：源码构建时指向仓库标准库；
/// 发布到其他机器后该路径不存在 → 返回空（宿主用运行时 `lib/` + `--lib` 兜底）。
/// 宿主展示实际生效的库目录时也应调用本函数（与解析器使用的列表一致）。
pub fn default_libs() -> Vec<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../eng_lib");
    if dir.is_dir() { vec![dir] } else { Vec::new() }
}

pub fn parse_file(path: impl AsRef<Path>) -> PktResult<Module> {
    parse_file_with_libs(path, &default_libs())
}

/// 解析文件（含 import 图）+ 语义分析，返回入口模块。
///
/// `libs`：库目录列表（pkglang 标准库，如发布目录的 `lib/`）。import 解析顺序：
/// 入口文件所在目录（直接 + 递归子目录）优先，随后从后往前逐个搜索库目录
/// （直接 + 递归）——显式 lib（如 `./lib`、`--lib`）优先于默认 eng_lib。
pub fn parse_file_with_libs(path: impl AsRef<Path>, libs: &[PathBuf]) -> PktResult<Module> {
    let path = path.as_ref();
    let src = std::fs::read_to_string(path)
        .map_err(|e| Diagnostic::new(format!("读取文件失败（{}）：{e}", path.display())))?;
    let name = file_stem(path);
    let ast = parse_ast(&src).map_err(|d| d.with_file(path.display().to_string()))?;
    // 默认 eng_lib（标准库）总是可用，显式 libs 追加其后
    let mut all = default_libs();
    all.extend_from_slice(libs);
    let mut graph = build_graph(&name, path, &ast, &all)?;
    resolve_names(&mut graph)?;
    let graph = Arc::new(graph);
    finish_module(&graph, 0)
}

/// 解析内存中的单个模块（无 import 支持；用于测试/REPL）。
///
/// 需要 import 解析（LSP / 编辑器场景）时用 [`parse_source_at`]。
pub fn parse_str(name: &str, src: &str) -> PktResult<Module> {
    let ast = parse_ast(src)?;
    let libs = default_libs();
    let mut graph = build_graph(name, Path::new(""), &ast, &libs)?;
    resolve_names(&mut graph)?;
    let graph = Arc::new(graph);
    finish_module(&graph, 0)
}

/// 解析内存中的单个模块，import 以 `dir` 为搜索根（文件尚未落盘时的编辑器场景）。
pub fn parse_source_at(name: &str, dir: &Path, src: &str) -> PktResult<Module> {
    parse_source_at_with_libs(name, dir, src, &default_libs())
}

/// 解析内存中的单个模块（带库目录），import 以 `dir` 为搜索根（编辑器未落盘场景）。
pub fn parse_source_at_with_libs(
    name: &str,
    dir: &Path,
    src: &str,
    libs: &[PathBuf],
) -> PktResult<Module> {
    let ast = parse_ast(src)?;
    let entry = dir.join(format!("{name}.pkt"));
    let mut all = default_libs();
    all.extend_from_slice(libs);
    let mut graph = build_graph(name, &entry, &ast, &all)?;
    resolve_names(&mut graph)?;
    let graph = Arc::new(graph);
    finish_module(&graph, 0)
}

fn file_stem(path: &Path) -> String {
    path.file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "module".to_string())
}

// ── import 图 ────────────────────────────────────────────────

fn build_graph(
    entry_name: &str,
    entry_path: &Path,
    entry_ast: &AstFile,
    libs: &[PathBuf],
) -> PktResult<ModuleGraph> {
    let mut graph = ModuleGraph::default();
    let mut work: Vec<(String, PathBuf, AstFile, bool)> = Vec::new();
    // 库模块种子：libs 目录下全部 .pkt（其 export 隐式可见，无需 import）。
    // 先 push 库种子、最后 push 入口：work 是 LIFO，保证入口模块第一个入图（下标 0）。
    // 库目录错误不静默丢弃：不可读 / 模块语法错 / 同目录导出名重复都报诊断，
    // 否则用户只会看到「未知层函数」这类误导性错误。
    let mut seen_lib_files: HashSet<PathBuf> = HashSet::new();
    let entry_canon =
        std::fs::canonicalize(entry_path).unwrap_or_else(|_| entry_path.to_path_buf());
    // 入口是否本身是库成员（如 ensure_proto_registry 把 eng_lib 文件当入口解析）：
    // 是 → 入口以 is_lib=true 入图（其 export 参与 prelude 注入，供其他库模块
    // 引用）；否 → 普通入口（is_lib=false，不注入全局）。
    let mut entry_is_lib = false;
    for lib in libs {
        let mut files = Vec::new();
        collect_in_root(lib, &mut files);
        if files.is_empty() && !lib.is_dir() {
            return Err(Diagnostic::new(format!(
                "库目录不存在或不可读：{}",
                lib.display()
            )));
        }
        // 同库目录内导出名重复 → 报错（跨目录同名导出允许：显式 lib 可覆盖标准库）。
        let mut exports_in_dir: HashMap<String, PathBuf> = HashMap::new();
        for (lib_name, lib_path) in files {
            let canon = std::fs::canonicalize(&lib_path).unwrap_or_else(|_| lib_path.clone());
            if !seen_lib_files.insert(canon.clone()) {
                continue; // 同一文件经重叠库目录重复收集：只处理一次
            }
            if canon == entry_canon {
                // 入口文件本身出现在库目录：不重复作为库种子入图（by_path 去重
                // 会让入口被跳过、依赖其 export 的库模块解析失败）——入口以
                // is_lib=true 入图（下标 0），export 参与 prelude 注入。
                entry_is_lib = true;
                continue;
            }
            let src = std::fs::read_to_string(&lib_path).map_err(|e| {
                Diagnostic::new(format!("读取库模块失败（{}）：{e}", lib_path.display()))
            })?;
            let ast = parse_ast(&src).map_err(|d| d.with_file(lib_path.display().to_string()))?;
            for stmt in &ast.stmts {
                if let Stmt::Export(e) = stmt {
                    for (name, span) in &e.names {
                        if let Some(prev) = exports_in_dir.get(name) {
                            return Err(Diagnostic::at(
                                format!(
                                    "库模块导出名重复：`{name}`（{} 与 {}）",
                                    prev.display(),
                                    lib_path.display()
                                ),
                                *span,
                            )
                            .with_file(lib_path.display().to_string()));
                        }
                        exports_in_dir.insert(name.clone(), lib_path.clone());
                    }
                }
            }
            work.push((lib_name, lib_path, ast, true));
        }
    }
    work.push((
        entry_name.to_string(),
        entry_path.to_path_buf(),
        entry_ast.clone(),
        entry_is_lib,
    ));
    // 入口模块路径可能是相对路径；用其所在目录做 import 根
    // 每模块的 import 目标路径（与 modules 下标对齐；目标模块可能尚未入图，
    // 路径在循环结束后统一映射为图下标）。
    let mut import_paths: Vec<Vec<(String, Span, PathBuf)>> = Vec::new();

    while let Some((name, path, ast, is_lib)) = work.pop() {
        let canon = std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
        if graph.by_path.contains_key(&canon) {
            // 同一路径已被解析：该 import 边已在来源模块记录，只跳过重复入图
            continue;
        }
        let idx = graph.modules.len();
        graph.by_path.insert(canon.clone(), idx);
        graph.modules.push(Arc::new(ModuleData {
            name,
            path: canon.clone(),
            ast: ast.clone(),
            is_lib,
        }));
        import_paths.push(Vec::new());

        // 收集 import（先记下来，等模块入图后再逐个解析，避免借用冲突）
        let imports: Vec<ImportStmt> = ast
            .stmts
            .iter()
            .filter_map(|s| match s {
                Stmt::Import(i) => Some(i.clone()),
                _ => None,
            })
            .collect();
        for imp in imports {
            let dir = canon.parent().unwrap_or(Path::new("."));
            let found = find_module(dir, libs, &imp.module).ok_or_else(|| {
                let libs_desc: Vec<String> =
                    libs.iter().rev().map(|l| l.display().to_string()).collect();
                let mut msg = format!("找不到模块 `{}`（搜索目录：{}", imp.module, dir.display());
                for l in &libs_desc {
                    msg.push_str(&format!("，库：{l}"));
                }
                msg.push(')');
                Diagnostic::at(msg, imp.span)
            })?;
            import_paths[idx].push((imp.module.clone(), imp.span, found.clone()));
            let src = std::fs::read_to_string(&found).map_err(|e| {
                Diagnostic::at(
                    format!("读取模块文件失败（{}）：{e}", found.display()),
                    imp.span,
                )
            })?;
            let ast = parse_ast(&src).map_err(|d| d.with_file(found.display().to_string()))?;
            work.push((imp.module.clone(), found, ast, false));
        }
    }

    // import 目标路径 → 图下标（按规范路径，与 by_path 一致）
    graph.module_imports = import_paths
        .into_iter()
        .map(|imps| {
            imps.into_iter()
                .map(|(_, span, found)| {
                    let canon = std::fs::canonicalize(&found).unwrap_or(found);
                    let target = graph
                        .by_path
                        .get(&canon)
                        .copied()
                        .ok_or_else(|| Diagnostic::at("内部错误：import 目标未入图", span))?;
                    Ok((target, span))
                })
                .collect::<PktResult<Vec<_>>>()
        })
        .collect::<PktResult<Vec<_>>>()?;

    // 检测循环依赖（DFS 染色）
    detect_cycles(&graph)?;
    Ok(graph)
}

/// 库模块的一个命名导出（LSP 补全 / 悬停用）。
#[derive(Debug, Clone)]
pub struct LibExport {
    /// 来源模块名（如 headers）。
    pub module: String,
    /// 导出名（如 tcp）。
    pub name: String,
    /// 若为函数/proto：参数（含默认值）；None = 元件 def。
    pub params: Option<Vec<ast::FuncParam>>,
    /// 函数上方的 `#` doc 注释（无则 None）。
    pub doc: Option<ast::FuncDoc>,
    /// 声明式 proto（自表示协议）——悬停显示 `#[proto] func name(fields)`。
    pub is_proto: bool,
}

/// 枚举库目录（默认 eng_lib + 显式 libs）下全部模块的命名导出。
///
/// 库导出隐式可见（无需 import 即可调用），LSP 补全 / 悬停应提供它们。
pub fn lib_exports(libs: &[PathBuf]) -> Vec<LibExport> {
    let mut all = default_libs();
    all.extend_from_slice(libs);
    // 去重（canonical 路径）：调用方可能已含默认 eng_lib（如 effective_libs），
    // 与 default_libs 重叠会让每个导出被枚举两次。
    let mut seen = std::collections::HashSet::new();
    all.retain(|p| {
        let key = std::fs::canonicalize(p).unwrap_or_else(|_| p.clone());
        seen.insert(key)
    });
    let mut out = Vec::new();
    for (mod_name, path) in collect_lib_modules(&all) {
        let Ok(src) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(ast) = parse_ast(&src) else {
            continue;
        };
        let funcs: HashMap<&str, &ast::FuncStmt> = ast
            .stmts
            .iter()
            .filter_map(|s| match s {
                Stmt::Func(f) => Some((f.name.as_str(), f)),
                _ => None,
            })
            .collect();
        let defs: std::collections::HashSet<&str> = ast
            .stmts
            .iter()
            .filter_map(|s| match s {
                Stmt::Def(d) => Some(d.name.as_str()),
                _ => None,
            })
            .collect();
        for stmt in &ast.stmts {
            if let Stmt::Export(e) = stmt {
                for (n, _) in &e.names {
                    if let Some(f) = funcs.get(n.as_str()) {
                        // proto 函数 = 带 schema 的 FuncStmt：字段即参数
                        // （悬停显示 `#[proto] func name(fields) -> bytes`）
                        out.push(LibExport {
                            module: mod_name.clone(),
                            name: n.clone(),
                            params: Some(if let Some(schema) = &f.schema {
                                schema
                                    .fields
                                    .iter()
                                    .map(|f| ast::FuncParam {
                                        name: f.name.clone(),
                                        span: f.name_span,
                                        default: f.default.clone(),
                                    })
                                    .collect()
                            } else {
                                f.params.clone()
                            }),
                            doc: f.doc.clone(),
                            is_proto: f.schema.is_some(),
                        });
                    } else if defs.contains(n.as_str()) {
                        out.push(LibExport {
                            module: mod_name.clone(),
                            name: n.clone(),
                            params: None,
                            doc: None,
                            is_proto: false,
                        });
                    }
                }
            }
        }
    }
    out
}

/// 以入口目录 + 库目录列表搜索 `name.pkt`：入口目录（直接 + 递归）优先，
/// 库目录**从后往前**逐个搜索（直接 + 递归）——显式 lib（`./lib`、`--lib`）优先于
/// 默认 eng_lib，与库导出注入的胜者一致（同名列靠后的库目录覆盖前面的）。
fn find_module(dir: &Path, libs: &[PathBuf], name: &str) -> Option<PathBuf> {
    if let Some(p) = find_in_root(dir, name) {
        return Some(p);
    }
    for lib in libs.iter().rev() {
        if let Some(p) = find_in_root(lib, name) {
            return Some(p);
        }
    }
    None
}

/// 收集库目录下全部 `.pkt` 模块（递归）：返回 (模块名 = 文件名, 路径)。
fn collect_lib_modules(libs: &[PathBuf]) -> Vec<(String, PathBuf)> {
    let mut out = Vec::new();
    for lib in libs {
        collect_in_root(lib, &mut out);
    }
    out
}

fn collect_in_root(root: &Path, out: &mut Vec<(String, PathBuf)>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    let mut dirs: Vec<PathBuf> = Vec::new();
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            dirs.push(p);
        } else if p.extension().is_some_and(|x| x == "pkt")
            && let Some(name) = p.file_stem().map(|s| s.to_string_lossy().to_string())
        {
            out.push((name, p));
        }
    }
    dirs.sort();
    for d in dirs {
        collect_in_root(&d, out);
    }
}

/// 以 `root` 为根递归搜索 `name.pkt`：先直接路径，再深度优先（字典序）子目录。
fn find_in_root(root: &Path, name: &str) -> Option<PathBuf> {
    let direct = root.join(format!("{name}.pkt"));
    if direct.is_file() {
        return Some(direct);
    }
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(&d)
            .ok()?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.is_dir())
            .collect();
        entries.sort();
        for sub in entries.into_iter().rev() {
            let candidate = sub.join(format!("{name}.pkt"));
            if candidate.is_file() {
                return Some(candidate);
            }
            stack.push(sub);
        }
    }
    None
}

fn detect_cycles(graph: &ModuleGraph) -> PktResult<()> {
    #[derive(Clone, Copy, PartialEq)]
    enum Color {
        White,
        Gray,
        Black,
    }
    let mut color = vec![Color::White; graph.modules.len()];
    let mut path: Vec<usize> = Vec::new();

    fn dfs(
        graph: &ModuleGraph,
        color: &mut Vec<Color>,
        path: &mut Vec<usize>,
        idx: usize,
    ) -> PktResult<()> {
        color[idx] = Color::Gray;
        path.push(idx);
        let imports: Vec<(usize, Span)> = graph.module_imports[idx].clone();
        for (t, span) in imports {
            match color[t] {
                Color::White => dfs(graph, color, path, t)?,
                Color::Gray => {
                    let mut names: Vec<String> = path
                        .iter()
                        .skip_while(|&&p| p != t)
                        .map(|&p| graph.modules[p].name.clone())
                        .collect();
                    names.push(graph.modules[t].name.clone());
                    let file = graph.modules[idx].path.display().to_string();
                    return Err(Diagnostic::at(
                        format!("检测到循环 import：{}", names.join(" → ")),
                        span,
                    )
                    .with_file(file));
                }
                Color::Black => {}
            }
        }
        path.pop();
        color[idx] = Color::Black;
        Ok(())
    }

    for i in 0..graph.modules.len() {
        if color[i] == Color::White {
            dfs(graph, &mut color, &mut path, i)?;
        }
    }
    Ok(())
}

// ── 名字解析 ─────────────────────────────────────────────────

/// 作用域条目：元件定义位置。
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ScopeEntry {
    /// 本模块 defs 下标。
    Local(usize),
    /// 本模块 funcs 下标（含 proto 函数——proto = 带 schema 的 FuncStmt）。
    Func(usize),
    /// 定义所在模块（graph 下标）+ 该模块内的原名（别名场景下与作用域键不同）。
    Imported(usize, String),
    /// 目标模块的默认导出流水线（graph 下标）。
    Default(usize),
}

fn resolve_names(graph: &mut ModuleGraph) -> PktResult<()> {
    let n = graph.modules.len();
    let mut scopes: Vec<HashMap<String, ScopeEntry>> = vec![HashMap::new(); n];
    let mut defaults: Vec<Option<String>> = vec![None; n];
    // 每个模块的默认导出名（= 模块名，若存在顶层匿名流水线）
    for (i, m) in graph.modules.iter().enumerate() {
        if has_default(&m.ast) {
            defaults[i] = Some(m.name.clone());
        }
    }
    // 本地定义（defs + funcs，同一作用域，重名即冲突）
    for (i, m) in graph.modules.iter().enumerate() {
        for (j, def) in defs_of(&m.ast).iter().enumerate() {
            if scopes[i]
                .insert(def.name.clone(), ScopeEntry::Local(j))
                .is_some()
            {
                return Err(
                    Diagnostic::at(format!("元件 `{}` 重复定义", def.name), def.name_span)
                        .with_file(m.path.display().to_string()),
                );
            }
        }
        for (j, f) in funcs_of(&m.ast).iter().enumerate() {
            if scopes[i]
                .insert(f.name.clone(), ScopeEntry::Func(j))
                .is_some()
            {
                return Err(
                    Diagnostic::at(format!("元件 `{}` 重复定义", f.name), f.name_span)
                        .with_file(m.path.display().to_string()),
                );
            }
        }
    }
    // import 名字（按依赖顺序：先处理被 import 的模块）
    for i in topo_order(graph) {
        let m = &graph.modules[i];
        // 目标模块下标来自本模块的 import 边（构建期按本模块目录解析）
        for (imp, &(target, _)) in imports_of(&m.ast).into_iter().zip(&graph.module_imports[i]) {
            let exported = exported_names(graph, target)?;
            let names: Vec<(String, Option<String>, Span)> = match &imp.names {
                Some(items) => items.clone(),
                None => {
                    let mut all = Vec::new();
                    // 默认导出以模块名引入
                    if let Some(d) = &defaults[target] {
                        // 模块同时有默认导出与同名命名元件：无括号引入无法区分两者
                        //（同名默认导出与命名元件指向不同包），明确报错并给出出路。
                        if exported.iter().any(|(n, _)| n == d) {
                            return Err(Diagnostic::at(
                                format!(
                                    "模块 `{}` 同时有默认导出与命名元件 `{d}`：`import {}`（不带大括号）无法区分，请用 `import {} {{ {d} }}` 显式引入命名元件，或给其中之一改名",
                                    imp.module, imp.module, imp.module
                                ),
                                imp.span,
                            )
                            .with_file(m.path.display().to_string()));
                        }
                        all.push((d.clone(), None, imp.span));
                    }
                    for (n, _) in &exported {
                        all.push((n.clone(), None, imp.span));
                    }
                    all
                }
            };
            for (name, alias, span) in names {
                // 解析目标用原名；作用域键用别名（无别名 = 原名）
                let scope_name = alias.unwrap_or_else(|| name.clone());
                let entry = if local_def_index(graph, target, &name).is_some()
                    || local_func_index(graph, target, &name).is_some()
                {
                    // Imported 携带目标模块内的原名（别名场景下与作用域键不同）
                    ScopeEntry::Imported(target, name.clone())
                } else if Some(&name) == defaults[target].as_ref() {
                    // 默认导出（以模块名引入）
                    ScopeEntry::Default(target)
                } else {
                    // 转出口：在目标模块的作用域里定位最终定义；
                    // 作用域缺失时回退到库模块集合（转出口来自库 prelude，注入尚未执行）。
                    match scopes[target].get(&name) {
                        Some(entry) => resolve_final(graph, &scopes, entry.clone(), &name)?,
                        None => match find_lib_export(graph, &name) {
                            Some(lib_idx) => ScopeEntry::Imported(lib_idx, name.clone()),
                            None => {
                                return Err(Diagnostic::at(
                                    format!("模块 `{}` 没有导出元件 `{name}`", imp.module),
                                    span,
                                )
                                .with_file(m.path.display().to_string()));
                            }
                        },
                    }
                };
                if let Some(prev) = scopes[i].get(&scope_name) {
                    return Err(Diagnostic::at(
                        format!(
                            "名字 `{scope_name}` 冲突：{} 与 import {}",
                            match prev {
                                ScopeEntry::Local(_) | ScopeEntry::Func(_) => {
                                    "本地定义".to_string()
                                }
                                ScopeEntry::Imported(..) | ScopeEntry::Default(_) => {
                                    "其他 import".to_string()
                                }
                            },
                            imp.module
                        ),
                        span,
                    )
                    .with_file(m.path.display().to_string()));
                }
                scopes[i].insert(scope_name, entry);
            }
        }
    }
    // 库导出隐式可见：libs 模块的命名导出自动进入每个模块作用域（已占用名不覆盖）
    let lib_exports: Vec<(usize, Vec<(String, Span)>)> = graph
        .modules
        .iter()
        .enumerate()
        .filter(|(_, m)| m.is_lib)
        .map(|(j, _)| (j, exported_names(graph, j).unwrap_or_default()))
        .collect();
    for (i, _) in graph.modules.iter().enumerate() {
        for (j, names) in &lib_exports {
            if *j == i {
                continue;
            }
            for (name, _span) in names {
                if !scopes[i].contains_key(name) {
                    scopes[i].insert(name.clone(), ScopeEntry::Imported(*j, name.clone()));
                }
            }
        }
    }
    // 校验 export / use / call 名字
    for (i, m) in graph.modules.iter().enumerate() {
        let file = m.path.display().to_string();
        for stmt in &m.ast.stmts {
            if let Stmt::Export(e) = stmt {
                for (name, span) in &e.names {
                    if !scopes[i].contains_key(name) {
                        return Err(Diagnostic::at(
                            format!("export 的元件 `{name}` 未定义（本文件定义或 import）"),
                            *span,
                        )
                        .with_file(file.clone()));
                    }
                }
            }
        }
        for def in defs_of(&m.ast) {
            check_expr_names(&def.expr, &scopes[i], &file)?;
            // 非函数定义里不允许参数引用（Value::Ident）
            if let Some((name, span)) = first_ident_in_expr(&def.expr) {
                return Err(
                    Diagnostic::at(format!("参数引用 `{name}` 只能出现在函数体内"), span)
                        .with_file(file.clone()),
                );
            }
        }
        for f in funcs_of(&m.ast) {
            check_pipeline_names(&f.body, &scopes[i], &file, f.span)?;
            // 函数体里的标识符值必须是已声明的参数
            for (name, span) in idents_in_pipeline(&f.body) {
                if !f.params.iter().any(|p| p.name == name) {
                    return Err(Diagnostic::at(
                        format!("函数 `{}` 未声明参数 `{name}`", f.name),
                        span,
                    )
                    .with_file(file.clone()));
                }
            }
            // 参数默认值里的标识符引用也必须是已声明参数（或允许自引用？不允许：按未声明报错）
            for p in &f.params {
                if let Some(v) = &p.default {
                    for (name, span) in idents_in_value(v) {
                        if !f.params.iter().any(|q| q.name == name) {
                            return Err(Diagnostic::at(
                                format!(
                                    "函数 `{}` 的参数 `{}` 默认值引用未声明参数 `{name}`",
                                    f.name, p.name
                                ),
                                span,
                            )
                            .with_file(file.clone()));
                        }
                    }
                }
            }
        }
        if let Some((p, span)) = &default_of(&m.ast) {
            check_pipeline_names(p, &scopes[i], &file, *span)?;
            if let Some((name, span)) = first_ident_in_pipeline(p) {
                return Err(
                    Diagnostic::at(format!("参数引用 `{name}` 只能出现在函数体内"), span)
                        .with_file(file.clone()),
                );
            }
        }
    }
    graph.scopes = scopes;
    Ok(())
}

/// 沿转出口链定位 import 名字的最终定义。
/// 链上每一跳都改用条目自身携带的原名（`Imported(m, orig)`），别名不会破坏定位。
fn resolve_final(
    graph: &ModuleGraph,
    scopes: &[HashMap<String, ScopeEntry>],
    entry: ScopeEntry,
    name: &str,
) -> PktResult<ScopeEntry> {
    match entry {
        ScopeEntry::Local(j) => Ok(ScopeEntry::Local(j)),
        ScopeEntry::Func(j) => Ok(ScopeEntry::Func(j)),
        ScopeEntry::Default(_) => Ok(entry),
        ScopeEntry::Imported(m, orig) => {
            if local_def_index(graph, m, &orig).is_some()
                || local_func_index(graph, m, &orig).is_some()
            {
                Ok(ScopeEntry::Imported(m, orig))
            } else {
                match scopes[m].get(&orig) {
                    Some(next) => resolve_final(graph, scopes, next.clone(), &orig),
                    // 转出口的名字来自库 prelude（注入在 import 处理之后才执行）：
                    // 回退到库模块集合定位定义（与注入的胜者一致）。
                    None => match find_lib_export(graph, &orig) {
                        Some(lib_idx) => Ok(ScopeEntry::Imported(lib_idx, orig)),
                        None => Err(Diagnostic::new(format!(
                            "模块 `{}` 转出口 `{name}`，但未找到其定义（本地 / import / 库导出均无）",
                            graph.modules[m].name
                        ))),
                    },
                }
            }
        }
    }
}

/// 在库模块中查找同时「导出并本地定义」`name` 的模块（图序第一个，与注入的
/// 胜者一致）。要求本地定义：`ScopeEntry::Imported` 求值时会按本地定义定位，
/// 纯转出口的库模块无法作为求值目标。
fn find_lib_export(graph: &ModuleGraph, name: &str) -> Option<usize> {
    graph.modules.iter().enumerate().find_map(|(j, m)| {
        if !m.is_lib
            || (local_def_index(graph, j, name).is_none()
                && local_func_index(graph, j, name).is_none())
        {
            return None;
        }
        exported_names(graph, j)
            .ok()
            .is_some_and(|names| names.iter().any(|(n, _)| n == name))
            .then_some(j)
    })
}

/// 拓扑排序：被 import 的模块在前（图已无环）。
fn topo_order(graph: &ModuleGraph) -> Vec<usize> {
    fn dfs(graph: &ModuleGraph, visited: &mut Vec<bool>, order: &mut Vec<usize>, i: usize) {
        visited[i] = true;
        for &(t, _) in &graph.module_imports[i] {
            if !visited[t] {
                dfs(graph, visited, order, t);
            }
        }
        order.push(i);
    }
    let n = graph.modules.len();
    let mut visited = vec![false; n];
    let mut order = Vec::with_capacity(n);
    for i in 0..n {
        if !visited[i] {
            dfs(graph, &mut visited, &mut order, i);
        }
    }
    order
}

/// 目标模块的命名导出列表（不含默认导出）。
fn exported_names(graph: &ModuleGraph, module: usize) -> PktResult<Vec<(String, Span)>> {
    let mut out = Vec::new();
    for stmt in &graph.modules[module].ast.stmts {
        if let Stmt::Export(e) = stmt {
            out.extend(e.names.iter().cloned());
        }
    }
    Ok(out)
}

/// 检查定义表达式里的 use / call 名字。
fn check_expr_names(expr: &Expr, scope: &HashMap<String, ScopeEntry>, file: &str) -> PktResult<()> {
    match expr {
        Expr::Pipeline(p) => check_pipeline_names(p, scope, file, p.span),
        Expr::Call(c) => check_call_name(c, scope, file),
    }
}

fn check_pipeline_names(
    p: &Pipeline,
    scope: &HashMap<String, ScopeEntry>,
    file: &str,
    _span: Span,
) -> PktResult<()> {
    for (name, span) in &p.use_names {
        if !scope.contains_key(name) {
            return Err(Diagnostic::at(
                format!("use 的元件 `{name}` 未定义（本文件定义或 import）"),
                *span,
            )
            .with_file(file));
        }
    }
    for call in &p.layers {
        check_call_name(call, scope, file)?;
    }
    Ok(())
}

fn check_call_name(
    c: &ast::Call,
    scope: &HashMap<String, ScopeEntry>,
    file: &str,
) -> PktResult<()> {
    if !is_builtin(&c.name) && !scope.contains_key(&c.name) {
        return Err(Diagnostic::at(
            format!(
                "未知层函数或元件：`{}`（内置函数：{}）",
                c.name,
                crate::registry::BUILTINS.join(" / ")
            ),
            c.name_span,
        )
        .with_file(file));
    }
    Ok(())
}

/// 组装公开的入口 Module。
fn finish_module(graph: &Arc<ModuleGraph>, entry: usize) -> PktResult<Module> {
    let md = &graph.modules[entry];
    let file = md.path.display().to_string();
    let mut exports = Vec::new();
    let mut default = None;
    let mut defs = Vec::new();
    let mut funcs = Vec::new();
    let mut protos = Vec::new();
    let mut imports = Vec::new();
    let mut sniffer = None;
    for stmt in &md.ast.stmts {
        match stmt {
            Stmt::Export(e) => exports.extend(e.names.iter().cloned()),
            Stmt::Sniffer(s) => {
                if sniffer.is_some() {
                    return Err(
                        Diagnostic::at("一个文件只能有一个 sniffer 段", s.span).with_file(file)
                    );
                }
                sniffer = Some(s.clone());
            }
            Stmt::Import(i) => {
                // 目标已由构建期解析（module_imports）；这里仅组装展示用的 ResolvedImport
                imports.push(ResolvedImport {
                    module: i.module.clone(),
                    names: i.names.clone(),
                    span: i.span,
                });
            }
            Stmt::Def(d) => defs.push(Def {
                name: d.name.clone(),
                name_span: d.name_span,
                expr: d.expr.clone(),
                span: d.span,
            }),
            Stmt::Func(f) if f.schema.is_some() => {
                // proto 函数 = 带 schema 的 FuncStmt（`#[proto] func ... -> bytes`）
                let schema = f.schema.as_ref().expect("guard: schema.is_some()");
                // 注解校验：`#[proto(kind="eth")]`（层身份，闭集）/ `#[rule(...)]`（分派）。
                let mut layer: Option<String> = None;
                let mut ctxs: Vec<crate::proto::CtxCond> = Vec::new();
                let mut matches: Vec<crate::proto::MatchFn> = Vec::new();
                for a in &f.attrs {
                    match a.name.as_str() {
                        "proto" => {
                            if layer.is_some() {
                                return Err(Diagnostic::at(
                                    "层身份注解重复（`#[proto(kind=...)]` 每个 proto 一个）"
                                        .to_string(),
                                    a.span,
                                )
                                .with_file(file.clone()));
                            }
                            // kind = IR 层类型（裸 #[proto] 无 kind = Raw 层）
                            if let Some((value, gspan)) = a.args.iter().find_map(|g| match g {
                                crate::ast::AttrArg::Kv { key, value, span } if key == "kind" => {
                                    Some((value, *span))
                                }
                                _ => None,
                            }) {
                                let kind = match value {
                                    Value::Str(s) => s.clone(),
                                    Value::Ident { name, .. } => name.clone(),
                                    _ => {
                                        return Err(Diagnostic::at(
                                            "`#[proto(kind=...)]` 需要层类型字符串或标识符"
                                                .to_string(),
                                            gspan,
                                        )
                                        .with_file(file.clone()));
                                    }
                                };
                                if !crate::registry::LAYER_KINDS.contains(&kind.as_str()) {
                                    return Err(Diagnostic::at(
                                        format!(
                                            "层类型 `{kind}` 无效（可用：{}）",
                                            crate::registry::LAYER_KINDS.join("/")
                                        ),
                                        gspan,
                                    )
                                    .with_file(file.clone()));
                                }
                                layer = Some(kind);
                            }
                        }
                        "rule" => {
                            // 分派规则——调用形式：`#[rule(udp(dport=443))]`（上下文）/
                            // `#[rule(bytes(0xc0))]`（首字节掩码）/ `#[rule(and(...))]`
                            // （AND 分组）/ `#[rule(or(...))]`（选一，如多端口）。
                            // 多个 `#[rule]` 注解与显式 and(...) 等价：全部子条件并入
                            // 同一规则（AND）；or 是内部显式析取。
                            for g in &a.args {
                                match g {
                                    crate::ast::AttrArg::Call { name, args, span } => {
                                        let acc = rule_expr(name, args, *span, &file, false)?;
                                        if let Some(c) = acc.ctx {
                                            ctxs.push(c);
                                        }
                                        matches.extend(acc.matches);
                                    }
                                    crate::ast::AttrArg::Kv { key, span, .. } => {
                                        // 旧键值对形式 `#[rule(layer="udp", dport=443)]`
                                        return Err(Diagnostic::at(
                                            format!(
                                                "`#[rule({key}=...)]` 已改为调用形式：`#[rule(udp(dport=443))]` / `#[rule(bytes(0xc0))]` / `#[rule(and/or(...))]`"
                                            ),
                                            *span,
                                        )
                                        .with_file(file.clone()));
                                    }
                                    crate::ast::AttrArg::Bare { span, .. } => {
                                        // 旧字符串形式 `#[rule("udp(dport=443)")]`
                                        return Err(Diagnostic::at(
                                            "`#[rule]` 参数已改为调用形式：`#[rule(udp(dport=443))]` / `#[rule(bytes(0xc0))]` / `#[rule(and/or(...))]`"
                                                .to_string(),
                                            *span,
                                        )
                                        .with_file(file.clone()));
                                    }
                                }
                            }
                        }
                        "bind" | "feature" => {
                            return Err(Diagnostic::at(
                                format!(
                                    "`#[{other}]` 已并入 `#[rule(...)]`：`#[bind(\"udp(dport=443)\")]` + `#[feature(0xc0)]` → `#[rule(layer=\"udp\", dport=443)]` + `#[rule(bytes=0xc0)]`",
                                    other = a.name
                                ),
                                a.span,
                            )
                            .with_file(file.clone()));
                        }
                        "layer" => {
                            return Err(Diagnostic::at(
                                "`#[layer(...)]` 已并入 `#[proto(kind=\"eth\")]`".to_string(),
                                a.span,
                            )
                            .with_file(file.clone()));
                        }
                        "meta" => {
                            return Err(Diagnostic::at(
                                "`#[meta(...)]` 只用于 `#[proto] func` 的 concat 参数标注"
                                    .to_string(),
                                a.span,
                            )
                            .with_file(file.clone()));
                        }
                        other => {
                            return Err(Diagnostic::at(
                                format!("未知协议注解 `#[{other}]`（支持 #[proto] / #[rule]）"),
                                a.span,
                            )
                            .with_file(file.clone()));
                        }
                    }
                }
                // 合并所有 `#[rule]` 注解为一个规则：
                // - **同层**的条件 AND 合并（保持原语义：`#[rule(udp(dport=443))]` +
                //   `#[rule(udp(sport=53))]` = 443 且 sport 53）；
                // - **跨层**的条件各自独立（如 DNS 的 `#[rule(udp(dport=53))]` +
                //   `#[rule(tcp(dport=53))]`——dissect 按层单点分派，任一命中即候选）。
                // 校验每个条件表达式内全部原子同层（and/or 树内不得跨层）。
                let rule = if ctxs.is_empty() && matches.is_empty() {
                    None
                } else {
                    // 按条件所在层分组：同层 and 合并，跨层独立
                    let mut by_layer: std::collections::BTreeMap<&str, Vec<crate::proto::CtxCond>> =
                        std::collections::BTreeMap::new();
                    for c in &ctxs {
                        let mut layers: Vec<&str> = Vec::new();
                        crate::proto::ctx_cond_layers(c, &mut layers);
                        let Some(first) = layers.first() else {
                            // 空条件（理论不可达：rule_expr 拒绝空 and/or）
                            continue;
                        };
                        if layers.iter().any(|l| l != first) {
                            return Err(Diagnostic::at(
                                "`#[rule]` 上下文子条件跨层（如 `and(ipv4(proto=17), udp(dport=443))`）：单个条件内的原子须同层（跨条件跨层允许，如 `#[rule(udp(dport=53))]` + `#[rule(tcp(dport=53))]`）"
                                    .to_string(),
                                f.span,
                            )
                            .with_file(file.clone()));
                        }
                        by_layer.entry(first).or_default().push(c.clone());
                    }
                    let final_ctxs: Vec<crate::proto::CtxCond> = by_layer
                        .into_values()
                        .map(|group| {
                            if group.len() == 1 {
                                group.into_iter().next().expect("len==1")
                            } else {
                                crate::proto::CtxCond::and(group)
                            }
                        })
                        .collect();
                    Some(crate::proto::Rule {
                        ctxs: final_ctxs,
                        matches,
                    })
                };
                // 无 layer 无 rule 的 proto 合法：纯构造规格（可被 use() 作 Raw 层，
                // 或作为 `rest(子proto)` 的解析目标，如 quic_crypto）
                // 字段校验：len 目标（Field 形态）必须是后序存在的字段；expr 只配 len
                for (i, f) in schema.fields.iter().enumerate() {
                    // expr 变换只能配 len（基准值 = 后续/目标字节数）
                    if f.len_expr.is_some() && f.len_of.is_none() {
                        return Err(Diagnostic::at(
                            format!(
                                "proto `{}`：字段 `{}` 的 `expr` 变换只用于 len 字段（`#[meta(len=..., expr=...)]`）",
                                f.name, f.name
                            ),
                            f.span,
                        )
                        .with_file(file.clone()));
                    }
                    // len="字段名"（Field 目标）：目标须后序存在且非位字段；
                    // len="auto"（后续全部）无目标校验
                    if let Some(LenTarget::Field(target)) = &f.len_of {
                        let Some(tf) = schema.fields[i + 1..].iter().find(|g| &g.name == target)
                        else {
                            return Err(Diagnostic::at(
                                format!(
                                    "proto `{}`：`len=\"{target}\"` 目标字段不存在或不在其后（长度前缀必须指向后序字段）",
                                    f.name
                                ),
                                f.span,
                            )
                            .with_file(file.clone()));
                        };
                        if tf.bits.is_some() {
                            return Err(Diagnostic::at(
                                format!(
                                    "proto `{}`：`len=\"{target}\"` 目标字段是位字段（bits），长度前缀只能指向整字节字段",
                                    f.name
                                ),
                                f.span,
                            )
                            .with_file(file.clone()));
                        }
                    }
                    // bits（位字段）：只配整型字段（容量 u8≤8 / be16≤16 / be32≤32 /
                    // be64≤64）、不与 len 组合、len 目标不能是位字段
                    if let Some(b) = f.bits {
                        let cap = match f.ty {
                            crate::ast::FieldType::U8 => 8,
                            crate::ast::FieldType::Be16 => 16,
                            crate::ast::FieldType::Be32 => 32,
                            crate::ast::FieldType::Be64 => 64,
                            _ => {
                                return Err(Diagnostic::at(
                                    format!(
                                        "proto `{}`：字段 `{}` 的 `#[meta(bits={b})]` 只用于整型字段（u8/be16/be32/be64；位组按大端位序填充，总位宽须为 8 的倍数）",
                                        f.name, f.name
                                    ),
                                    f.span,
                                )
                                .with_file(file.clone()));
                            }
                        };
                        if b as usize > cap {
                            return Err(Diagnostic::at(
                                format!(
                                    "proto `{}`：字段 `{}` 的 `#[meta(bits={b})]` 超出该类型容量 {cap} 位",
                                    f.name, f.name
                                ),
                                f.span,
                            )
                            .with_file(file.clone()));
                        }
                        if f.len_of.is_some() {
                            return Err(Diagnostic::at(
                                format!(
                                    "proto `{}`：字段 `{}` 是位字段（bits），不能同时是 len 计算字段",
                                    f.name, f.name
                                ),
                                f.span,
                            )
                            .with_file(file.clone()));
                        }
                    }
                    // bytes 字段须有宽度——switch 分派字段豁免（无宽度 = 窗口到
                    // 缓冲区末尾，如 ICMP 变体按 type 分派到报文尾）
                    if f.ty == crate::ast::FieldType::Bytes
                        && f.width.is_none()
                        && f.switch_field.is_none()
                    {
                        return Err(Diagnostic::at(
                            format!(
                                "proto `{}`：`bytes` 字段 `{}` 缺少宽度：`#[meta(bytes=字段名)]` 或 `#[meta(bytes=n)]`",
                                f.name, f.name
                            ),
                            f.span,
                        )
                        .with_file(file.clone()));
                    }
                    // 重复区：`#[meta(list="计数", item="子proto")]`（按计数重复）或
                    // `#[meta(rest="子proto")]`（重复到失败，原哨兵 list）——元素子
                    // proto（rest_proto）必须齐全，字段必须是 rest 类型
                    if f.list_count.is_some() && f.rest_proto.is_none() {
                        return Err(Diagnostic::at(
                            format!(
                                "proto `{}`：list 字段 `{}` 需要 `#[meta(list=\"计数\", item=\"子proto\")]` 两项齐全（重复到失败用 `#[meta(rest=\"子proto\")]`）",
                                f.name, f.name
                            ),
                            f.span,
                        )
                        .with_file(file.clone()));
                    }
                    // 重复区：Rest 类型 = 尾部重复（吃到失败/末尾）；
                    // Bytes + width = 窗口内重复（`bytes= 窗口` + `rest= 子proto`——
                    // 窗口里循环反解到耗尽，如 TCP options 的 data_offset 界定窗口）
                    if f.rest_proto.is_some() && f.ty != crate::ast::FieldType::Rest {
                        if f.ty == crate::ast::FieldType::Bytes {
                            if f.list_count.is_some() {
                                return Err(Diagnostic::at(
                                    format!(
                                        "proto `{}`：窗口内重复字段 `{}`（`bytes= 窗口` + `rest= 子proto`）不与 `list=` 计数同设——窗口本身就是停止条件",
                                        f.name, f.name
                                    ),
                                    f.span,
                                )
                                .with_file(file.clone()));
                            }
                        } else {
                            return Err(Diagnostic::at(
                                format!(
                                    "proto `{}`：重复区字段 `{}` 必须是 rest 类型（`#[meta(rest=\"子proto\")]` / `#[meta(list=..., item=\"子proto\")]`；`bytes= 窗口` + `rest= 子proto` 为窗口内重复）",
                                    f.name, f.name
                                ),
                                f.span,
                            )
                            .with_file(file.clone()));
                        }
                    }
                    // switch 判别式分派：cases 表须齐全非空且判别值互异（重复值
                    // 首个生效、其余不可达）；与重复区/位字段/len 计算字段互斥
                    if f.switch_field.is_some() {
                        if f.rest_proto.is_some() || f.bits.is_some() || f.len_of.is_some() {
                            return Err(Diagnostic::at(
                                format!(
                                    "proto `{}`：switch 分派字段 `{}` 与重复区（rest/list）/位字段（bits）/len 计算字段互斥",
                                    f.name, f.name
                                ),
                                f.span,
                            )
                            .with_file(file.clone()));
                        }
                        let cases = f.cases.as_ref().ok_or_else(|| {
                            Diagnostic::at(
                                format!(
                                    "proto `{}`：switch 分派字段 `{}` 缺少 `#[meta(cases=...)]` 判别表",
                                    f.name, f.name
                                ),
                                f.span,
                            )
                            .with_file(file.clone())
                        })?;
                        if cases.is_empty() {
                            return Err(Diagnostic::at(
                                format!(
                                    "proto `{}`：switch 分派字段 `{}` 的 cases 判别表为空",
                                    f.name, f.name
                                ),
                                f.span,
                            )
                            .with_file(file.clone()));
                        }
                        let mut seen = std::collections::HashSet::new();
                        for (v, name) in cases {
                            if !seen.insert(*v) {
                                return Err(Diagnostic::at(
                                    format!(
                                        "proto `{}`：switch 分派字段 `{}` 的 cases 判别值 {v} 重复（首个生效、其余不可达）",
                                        f.name, f.name
                                    ),
                                    f.span,
                                )
                                .with_file(file.clone()));
                            }
                            if name.is_empty() {
                                return Err(Diagnostic::at(
                                    format!(
                                        "proto `{}`：switch 分派字段 `{}` 的 cases 子 proto 名为空",
                                        f.name, f.name
                                    ),
                                    f.span,
                                )
                                .with_file(file.clone()));
                            }
                        }
                    } else if f.cases.is_some() {
                        return Err(Diagnostic::at(
                            format!(
                                "proto `{}`：字段 `{}` 的 `#[meta(cases=...)]` 需要配合 `#[meta(switch=\"前序字段\")]` 使用",
                                f.name, f.name
                            ),
                            f.span,
                        )
                        .with_file(file.clone()));
                    }
                    // if 条件在场守卫：只配普通字段，与位字段/len 计算字段/重复区互斥
                    // （位字段条件会破坏位组对齐校验；len 字段必须恒在场）
                    if f.if_cond.is_some()
                        && (f.bits.is_some() || f.len_of.is_some() || f.rest_proto.is_some())
                    {
                        return Err(Diagnostic::at(
                            format!(
                                "proto `{}`：if 条件字段 `{}` 不能是位字段（bits）/len 计算字段/重复区（rest/list）",
                                f.name, f.name
                            ),
                            f.span,
                        )
                        .with_file(file.clone()));
                    }
                    // vint codec：方案必须齐全；prefix 表长度 = 2^prefix_bits 且宽度
                    // 严格递增（构造按列表序取第一个装得下的 = 最小宽度，确定性）；
                    // table 哨兵须 > inline_max 且互异（否则首字节解码歧义）
                    if f.ty == crate::ast::FieldType::Vint {
                        let codec = f.vint.as_ref().ok_or_else(|| {
                            Diagnostic::at(
                                format!(
                                    "proto `{}`：vint 字段 `{}` 缺少 codec 方案",
                                    f.name, f.name
                                ),
                                f.span,
                            )
                            .with_file(file.clone())
                        })?;
                        match codec {
                            crate::ast::VintCodec::Le128 => {}
                            crate::ast::VintCodec::Prefix {
                                prefix_bits,
                                widths,
                            } => {
                                let expect = 1usize << prefix_bits;
                                if widths.len() != expect {
                                    return Err(Diagnostic::at(
                                        format!(
                                            "proto `{}`：codec `prefix` 的 widths 表长度 {} ≠ 2^prefix_bits（{expect}）",
                                            f.name, widths.len()
                                        ),
                                        f.span,
                                    )
                                    .with_file(file.clone()));
                                }
                                for w in widths {
                                    if !(1..=8).contains(w) {
                                        return Err(Diagnostic::at(
                                            format!(
                                                "proto `{}`：codec `prefix` 的宽度 {w} 超出 1..=8",
                                                f.name
                                            ),
                                            f.span,
                                        )
                                        .with_file(file.clone()));
                                    }
                                }
                                if widths.windows(2).any(|w| w[0] >= w[1]) {
                                    return Err(Diagnostic::at(
                                        format!(
                                            "proto `{}`：codec `prefix` 的 widths 表必须严格递增（构造按列表序取第一个装得下的）",
                                            f.name
                                        ),
                                        f.span,
                                    )
                                    .with_file(file.clone()));
                                }
                            }
                            crate::ast::VintCodec::Table {
                                inline_max, table, ..
                            } => {
                                if table.is_empty() {
                                    return Err(Diagnostic::at(
                                        format!(
                                            "proto `{}`：codec `table` 的哨兵表不能为空",
                                            f.name
                                        ),
                                        f.span,
                                    )
                                    .with_file(file.clone()));
                                }
                                let mut seen = std::collections::HashSet::new();
                                for (s, w) in table {
                                    if *s <= *inline_max {
                                        return Err(Diagnostic::at(
                                            format!(
                                                "proto `{}`：codec `table` 的哨兵 0x{s:02x} 须大于 inline_max（0x{inline_max:02x}），否则首字节解码歧义",
                                                f.name
                                            ),
                                            f.span,
                                        )
                                        .with_file(file.clone()));
                                    }
                                    if !(1..=8).contains(w) {
                                        return Err(Diagnostic::at(
                                            format!(
                                                "proto `{}`：codec `table` 的宽度 {w} 超出 1..=8",
                                                f.name
                                            ),
                                            f.span,
                                        )
                                        .with_file(file.clone()));
                                    }
                                    if !seen.insert(*s) {
                                        return Err(Diagnostic::at(
                                            format!(
                                                "proto `{}`：codec `table` 的哨兵 0x{s:02x} 重复",
                                                f.name
                                            ),
                                            f.span,
                                        )
                                        .with_file(file.clone()));
                                    }
                                }
                                if table.windows(2).any(|t| t[0].1 >= t[1].1) {
                                    return Err(Diagnostic::at(
                                        format!(
                                            "proto `{}`：codec `table` 的宽度必须严格递增（构造按列表序取第一个装得下的）",
                                            f.name
                                        ),
                                        f.span,
                                    )
                                    .with_file(file.clone()));
                                }
                            }
                        }
                    }
                }
                // bits 位组对齐：连续位字段须凑满整字节（普通字段从字节边界开始，
                // proto 结尾位组同样须完整）——version(4)+ihl(4) = 0x45 即一组一字节。
                let mut group_bits = 0usize;
                let mut group_span = None;
                for f in &schema.fields {
                    match f.bits {
                        Some(b) => {
                            if group_span.is_none() {
                                group_span = Some(f.span);
                            }
                            group_bits += b as usize;
                        }
                        None => {
                            if !group_bits.is_multiple_of(8) {
                                return Err(Diagnostic::at(
                                    format!(
                                        "proto `{}`：`bits` 字段组总位宽 {group_bits} 不是 8 的倍数（位字段须凑满整字节再接普通字段）",
                                        f.name
                                    ),
                                    group_span.unwrap_or(f.span),
                                )
                                .with_file(file.clone()));
                            }
                            group_bits = 0;
                            group_span = None;
                        }
                    }
                }
                if !group_bits.is_multiple_of(8) {
                    return Err(Diagnostic::at(
                        format!(
                            "proto `{}`：结尾 `bits` 字段组总位宽 {group_bits} 不是 8 的倍数（位字段须凑满整字节）",
                            f.name
                        ),
                        group_span.expect("group_bits>0 必有起始字段"),
                    )
                    .with_file(file.clone()));
                }
                protos.push(Proto {
                    name: f.name.clone(),
                    name_span: f.name_span,
                    layer,
                    rule,
                    params: f
                        .params
                        .iter()
                        .map(|p| FuncParam {
                            name: p.name.clone(),
                            span: p.span,
                            default: p.default.clone(),
                        })
                        .collect(),
                    fields: schema.fields.clone(),
                    span: f.span,
                });
            }
            Stmt::Func(f) => funcs.push(Func {
                name: f.name.clone(),
                name_span: f.name_span,
                params: f
                    .params
                    .iter()
                    .map(|p| FuncParam {
                        name: p.name.clone(),
                        span: p.span,
                        default: p.default.clone(),
                    })
                    .collect(),
                body: (*f.body).clone(),
                span: f.span,
                doc: f.doc.clone(),
            }),
            Stmt::Pipeline(p) => {
                if default.is_some() {
                    return Err(Diagnostic::at(
                        "一个文件只能有一个默认导出（顶层匿名流水线）",
                        p.span,
                    )
                    .with_file(file));
                }
                default = Some((p.pipeline.clone(), p.span));
            }
        }
    }
    Ok(Module {
        name: md.name.clone(),
        path: Some(md.path.clone()),
        exports,
        default,
        defs,
        funcs,
        protos,
        sniffer,
        imports,
        graph: graph.clone(),
    })
}

// ── AST 辅助 ─────────────────────────────────────────────────

fn defs_of(ast: &AstFile) -> Vec<&ast::DefStmt> {
    ast.stmts
        .iter()
        .filter_map(|s| match s {
            Stmt::Def(d) => Some(d),
            _ => None,
        })
        .collect()
}

fn funcs_of(ast: &AstFile) -> Vec<&ast::FuncStmt> {
    ast.stmts
        .iter()
        .filter_map(|s| match s {
            Stmt::Func(f) => Some(f),
            _ => None,
        })
        .collect()
}

/// `#[rule]` 键值项的值 → 数字（分派键值）。
fn attr_num(v: &ast::Value, span: ast::Span, file: &str) -> PktResult<u64> {
    match v {
        ast::Value::Int(i) if *i >= 0 => Ok(*i as u64),
        ast::Value::Hex(h) => Ok(*h),
        other => Err(Diagnostic::at(
            format!(
                "`#[rule]` 键值需要数字（0x/十进制），得到 {}",
                crate::registry::describe(other)
            ),
            span,
        )
        .with_file(file.to_string())),
    }
}

/// `#[rule]` 分派键值 → 数字文本（供 build_cond 解析，如 `dport=443`）。
fn attr_num_str(v: &ast::Value, span: ast::Span, file: &str) -> PktResult<String> {
    match v {
        ast::Value::Int(i) if *i >= 0 => Ok(i.to_string()),
        ast::Value::Hex(h) => Ok(format!("0x{h:X}")),
        other => Err(Diagnostic::at(
            format!(
                "`#[rule]` 分派键值需要数字（0x/十进制），得到 {}",
                crate::registry::describe(other)
            ),
            span,
        )
        .with_file(file.to_string())),
    }
}

/// `rule_expr` 解析一个子条件后的累积：上下文条件 + 匹配函数。
#[derive(Default)]
struct RuleAccum {
    ctx: Option<crate::proto::CtxCond>,
    matches: Vec<crate::proto::MatchFn>,
}

/// 解析一个 `#[rule]` 调用形式的子条件 → 上下文表达式 + 匹配函数：
/// - `mask(掩码)` → 首字节位掩码（`(b & 掩码) == 掩码`；只允许 AND 组合）
/// - `startswith(...)` / `endswith(...)` / `contains(...)` → 字节模式匹配
/// - `ne(字段, 值)` / `eq(字段, 值)` → 字段值约束
/// - `udp(...)`/`tcp(...)`/`ipv4(...)`/`ipv6(...)`/`eth(...)` → 上下文原子条件
/// - `and(子条件, ...)` → `CtxCond::And`（匹配函数可在此累积，仍是 AND）
/// - `or(子条件, ...)` → `CtxCond::Or`（选一；分支只允许上下文条件）
/// - `not` → 报错（分派是正向匹配，无否定用例，见 GRAMMAR.md）
///
/// `in_or`：当前是否位于 or 分支内（or 分支禁止掩码/子串内容判别）。
fn rule_expr(
    name: &str,
    args: &[crate::ast::AttrArg],
    span: crate::ast::Span,
    file: &str,
    in_or: bool,
) -> PktResult<RuleAccum> {
    if name == "and" {
        if args.is_empty() {
            return Err(
                Diagnostic::at("`#[rule(and(...))]` 需要至少一个子条件".to_string(), span)
                    .with_file(file.to_string()),
            );
        }
        let mut acc = RuleAccum::default();
        let mut ctxs = Vec::new();
        for sub in args {
            let sub = rule_sub_call(sub, file, in_or)?;
            if let Some(c) = sub.ctx {
                ctxs.push(c);
            }
            acc.matches.extend(sub.matches);
        }
        acc.ctx = if ctxs.is_empty() {
            None
        } else {
            Some(crate::proto::CtxCond::and(ctxs))
        };
        return Ok(acc);
    }
    if name == "or" {
        if args.is_empty() {
            return Err(
                Diagnostic::at("`#[rule(or(...))]` 需要至少一个子条件".to_string(), span)
                    .with_file(file.to_string()),
            );
        }
        let mut ctxs = Vec::new();
        let mut field_matches = Vec::new();
        for sub in args {
            let sub = rule_sub_call(sub, file, true)?;
            // or 分支只禁止字节内容匹配（掩码/前缀/后缀/子串，无层可挂），允许字段值约束（ne/eq）
            if sub.matches.iter().any(|m| m.is_byte_pattern()) {
                return Err(Diagnostic::at(
                    "`#[rule(or(...))]` 分支不能含字节内容匹配（`mask`/`startswith`/`endswith`/`contains`）：无层可挂，不能作选一分派条件——写成独立 `#[rule(...)]`"
                        .to_string(),
                    span,
                )
                .with_file(file.to_string()));
            }
            field_matches.extend(sub.matches);
            if let Some(c) = sub.ctx {
                ctxs.push(c);
            }
        }
        // or 需要至少一个上下文子条件或字段值约束
        if ctxs.is_empty() && field_matches.is_empty() {
            return Err(
                Diagnostic::at("`#[rule(or(...))]` 需要至少一个子条件".to_string(), span)
                    .with_file(file.to_string()),
            );
        }
        // 字段值约束合并成 MatchFn::Or（OR 语义），AND 组合留在 Rule.matches
        let mut matches = Vec::new();
        if !field_matches.is_empty() {
            matches.push(crate::proto::MatchFn::Or(field_matches));
        }
        return Ok(RuleAccum {
            ctx: if ctxs.is_empty() {
                None
            } else {
                Some(crate::proto::CtxCond::or(ctxs))
            },
            matches,
        });
    }
    if name == "not" {
        return Err(Diagnostic::at(
            "`#[rule]` 不支持 `not`：分派条件是正向匹配（and/or 组合），否定条件会让无关包都触发解析尝试，且 DSL 无 Bool/比较逻辑——需要排除场景靠「解析失败回退 raw」处理"
                .to_string(),
            span,
        )
        .with_file(file.to_string()));
    }
    if name == "mask" {
        if in_or {
            return Err(Diagnostic::at(
                "`#[rule(or(...))]` 分支不能含 `mask(掩码)`：掩码是解析期 AND 先验（无层可挂），不能作选一分派条件"
                    .to_string(),
                span,
            )
            .with_file(file.to_string()));
        }
        // 首字节位掩码：一个位置参数（数字）
        let Some(arg0) = args.first() else {
            return Err(Diagnostic::at(
                "`#[rule(mask(...))]` 需要掩码参数：`#[rule(mask(0xc0))]`".to_string(),
                span,
            )
            .with_file(file.to_string()));
        };
        let n = match arg0 {
            crate::ast::AttrArg::Bare { value, span } => attr_num(value, *span, file)?,
            _ => {
                return Err(Diagnostic::at(
                    "`#[rule(mask(...))]` 掩码须为数字：`#[rule(mask(0xc0))]`".to_string(),
                    span,
                )
                .with_file(file.to_string()));
            }
        };
        if n > 255 {
            return Err(
                Diagnostic::at(format!("`#[rule(mask(0x{n:X}))]` 掩码需要 0..=255"), span)
                    .with_file(file.to_string()),
            );
        }
        return Ok(RuleAccum {
            ctx: None,
            matches: vec![crate::proto::MatchFn::Mask(n as u8)],
        });
    }
    if name == "contains" {
        let (pattern, target) = parse_pattern_match(args, span, file, "contains")?;
        return Ok(RuleAccum {
            ctx: None,
            matches: vec![crate::proto::MatchFn::Contains { pattern, target }],
        });
    }
    if name == "startswith" {
        let (pattern, target) = parse_pattern_match(args, span, file, "startswith")?;
        return Ok(RuleAccum {
            ctx: None,
            matches: vec![crate::proto::MatchFn::StartsWith { pattern, target }],
        });
    }
    if name == "endswith" {
        let (pattern, target) = parse_pattern_match(args, span, file, "endswith")?;
        return Ok(RuleAccum {
            ctx: None,
            matches: vec![crate::proto::MatchFn::EndsWith { pattern, target }],
        });
    }
    if name == "ne" || name == "eq" {
        return parse_field_val_match(name, args, span, file);
    }
    // 上下文原子：`udp(dport=443)` → layer=udp + dport=443（build_cond 校验层名/键）
    let mut kvs: Vec<(String, String)> = Vec::new();
    for arg in args {
        match arg {
            crate::ast::AttrArg::Kv { key, value, span } => {
                kvs.push((key.clone(), attr_num_str(value, *span, file)?));
            }
            _ => {
                return Err(Diagnostic::at(
                    format!(
                        "`#[rule({name}(...))]` 分派条件需要 `k=v` 形式：`#[rule(udp(dport=443))]`"
                    ),
                    span,
                )
                .with_file(file.to_string()));
            }
        }
    }
    let cond = crate::proto::build_cond(name, &kvs)
        .map_err(|e| Diagnostic::at(e.to_string(), span).with_file(file.to_string()))?;
    Ok(RuleAccum {
        ctx: Some(crate::proto::CtxCond::Atom(cond)),
        ..Default::default()
    })
}

/// 解析字节模式匹配参数（`startswith`/`endswith`/`contains`）：
/// 位置参数 = 字节来源（字符串字面量 / `hex("...")` / `raw("...")` 等 eng_lib 生成函数），
/// 可选 `at=N`（偏移）/ `in=字段名`（字段字节内容）。
fn parse_pattern_match(
    args: &[crate::ast::AttrArg],
    span: crate::ast::Span,
    file: &str,
    func: &str,
) -> PktResult<(Vec<u8>, crate::proto::MatchTarget)> {
    let mut pattern: Option<Vec<u8>> = None;
    let mut target = crate::proto::MatchTarget::Whole;
    for arg in args {
        match arg {
            crate::ast::AttrArg::Bare {
                value: ast::Value::Str(s),
                ..
            } if pattern.is_none() => {
                pattern = Some(s.as_bytes().to_vec());
            }
            crate::ast::AttrArg::Bare {
                value: ast::Value::Hex(h),
                ..
            } if pattern.is_none() => {
                pattern = Some(vec![*h as u8]);
            }
            crate::ast::AttrArg::Bare {
                value: ast::Value::Int(i),
                ..
            } if pattern.is_none() => {
                pattern = Some(i.to_be_bytes().to_vec());
            }
            crate::ast::AttrArg::Call {
                name,
                args: call_args,
                span: call_span,
            } if pattern.is_none() => {
                // eng_lib 生成函数调用（hex / raw 等）→ 求值为字节
                pattern = Some(eval_simple_call(name, call_args, *call_span, file)?);
            }
            crate::ast::AttrArg::Kv { key, value, span } => match key.as_str() {
                "at" => {
                    let n = attr_num(value, *span, file)?;
                    target = crate::proto::MatchTarget::Offset(n as usize);
                }
                "in" => {
                    let name = match value {
                        ast::Value::Ident { name, .. } => name.clone(),
                        ast::Value::Str(s) => s.clone(),
                        _ => {
                            return Err(Diagnostic::at(
                                format!(
                                    "`#[rule({func}(...))]` 的 `in` 参数须为字段名标识符或字符串"
                                ),
                                *span,
                            )
                            .with_file(file.to_string()));
                        }
                    };
                    target = crate::proto::MatchTarget::Field(name);
                }
                _ => {
                    return Err(Diagnostic::at(
                        format!("`#[rule({func}(...))]` 未知参数 `{key}`（支持 at / in）"),
                        *span,
                    )
                    .with_file(file.to_string()));
                }
            },
            _ => {
                return Err(Diagnostic::at(
                    format!(
                        "`#[rule({func}(...))]` 第一个参数须为字节来源（字符串 / hex(\"...\") / raw(\"...\") 等）"
                    ),
                    span,
                )
                .with_file(file.to_string()));
            }
        }
    }
    let bytes = pattern.ok_or_else(|| {
        Diagnostic::at(
            format!("`#[rule({func}(...))]` 需要字节参数：`#[rule({func}(\"...\"))]`"),
            span,
        )
        .with_file(file.to_string())
    })?;
    if bytes.is_empty() {
        return Err(
            Diagnostic::at(format!("`#[rule({func}(...))]` 子串不能为空"), span)
                .with_file(file.to_string()),
        );
    }
    Ok((bytes, target))
}

/// 解析字段值约束参数（`ne`/`eq`）：
/// 两个位置参数 = 字段名（标识符）+ 值（整数/字符串）。
fn parse_field_val_match(
    func: &str,
    args: &[crate::ast::AttrArg],
    span: crate::ast::Span,
    file: &str,
) -> PktResult<RuleAccum> {
    let mut field: Option<String> = None;
    let mut value: Option<crate::proto::MatchVal> = None;
    for arg in args {
        match arg {
            crate::ast::AttrArg::Bare {
                value: ast::Value::Ident { name, .. },
                ..
            } if field.is_none() => {
                field = Some(name.clone());
            }
            crate::ast::AttrArg::Bare { value: v, span: vs }
                if field.is_some() && value.is_none() =>
            {
                value = Some(attr_match_val(v, *vs, file)?);
            }
            _ => {
                return Err(Diagnostic::at(
                    format!("`#[rule({func}(字段, 值))]` 需要两个位置参数"),
                    span,
                )
                .with_file(file.to_string()));
            }
        }
    }
    let field = field.ok_or_else(|| {
        Diagnostic::at(format!("`#[rule({func}(...))]` 缺少字段名参数"), span)
            .with_file(file.to_string())
    })?;
    let value = value.ok_or_else(|| {
        Diagnostic::at(format!("`#[rule({func}(字段, 值))]` 缺少比较值参数"), span)
            .with_file(file.to_string())
    })?;
    let mf = match func {
        "ne" => crate::proto::MatchFn::Ne { field, value },
        "eq" => crate::proto::MatchFn::Eq { field, value },
        _ => unreachable!(),
    };
    Ok(RuleAccum {
        ctx: None,
        matches: vec![mf],
    })
}

/// 值字面量 → MatchVal（支持字面量 + eng_lib 生成函数调用）。
fn attr_match_val(
    v: &ast::Value,
    span: ast::Span,
    file: &str,
) -> PktResult<crate::proto::MatchVal> {
    match v {
        ast::Value::Int(i) => Ok(crate::proto::MatchVal::Int(*i)),
        ast::Value::Hex(h) => Ok(crate::proto::MatchVal::Int(*h as i64)),
        ast::Value::Str(s) => Ok(crate::proto::MatchVal::Str(s.clone())),
        ast::Value::Call {
            name,
            args,
            span: call_span,
            ..
        } => {
            // eng_lib 生成函数调用 → 求值为字节序列
            let bytes = eval_value_call(name, args, *call_span, file)?;
            Ok(crate::proto::MatchVal::Bytes(bytes))
        }
        _ => Err(Diagnostic::at(
            "`#[rule(ne/eq(字段, 值))]` 的值须为字面量或 eng_lib 生成函数调用".to_string(),
            span,
        )
        .with_file(file.to_string())),
    }
}

/// 语义阶段简单 eng_lib 生成函数求值（attr 参数版）：`hex("...")` / `raw("...")` → 字节。
///
/// 只支持不依赖运行时参数的内置函数；复杂函数（引用 params/globals）需延迟到
/// eval 阶段（后续扩展）。
fn eval_simple_call(
    name: &str,
    args: &[crate::ast::AttrArg],
    span: crate::ast::Span,
    file: &str,
) -> PktResult<Vec<u8>> {
    match name {
        "hex" => {
            let s = first_str_attr_arg(args, span, file, "hex")?;
            crate::registry::hex_string_bytes(&s).map_err(|msg| {
                Diagnostic::at(format!("`hex` {msg}"), span).with_file(file.to_string())
            })
        }
        "raw" => {
            let s = first_str_attr_arg(args, span, file, "raw")?;
            Ok(s.into_bytes())
        }
        _ => Err(Diagnostic::at(
            format!("`#[rule(...)]` 参数暂不支持 `{name}(...)` 调用（支持 hex / raw 生成函数）"),
            span,
        )
        .with_file(file.to_string())),
    }
}

/// 语义阶段简单 eng_lib 生成函数求值（值位置版）：`hex("...")` / `raw("...")` → 字节。
fn eval_value_call(
    name: &str,
    args: &[ast::Value],
    span: ast::Span,
    file: &str,
) -> PktResult<Vec<u8>> {
    match name {
        "hex" => {
            let s = first_str_value_arg(args, span, file, "hex")?;
            crate::registry::hex_string_bytes(&s).map_err(|msg| {
                Diagnostic::at(format!("`hex` {msg}"), span).with_file(file.to_string())
            })
        }
        "raw" => {
            let s = first_str_value_arg(args, span, file, "raw")?;
            Ok(s.into_bytes())
        }
        _ => Err(Diagnostic::at(
            format!("`#[rule(...)]` 参数暂不支持 `{name}(...)` 调用（支持 hex / raw 生成函数）"),
            span,
        )
        .with_file(file.to_string())),
    }
}

/// 提取 attr 参数列表的第一个裸字符串参数。
fn first_str_attr_arg(
    args: &[crate::ast::AttrArg],
    span: crate::ast::Span,
    file: &str,
    func: &str,
) -> PktResult<String> {
    match args.first() {
        Some(crate::ast::AttrArg::Bare {
            value: ast::Value::Str(s),
            ..
        }) => Ok(s.clone()),
        _ => Err(Diagnostic::at(
            format!("`{func}(...)` 需要字符串参数：`{func}(\"...\")`"),
            span,
        )
        .with_file(file.to_string())),
    }
}

/// 提取值位置参数列表的第一个字符串参数。
fn first_str_value_arg(
    args: &[ast::Value],
    span: ast::Span,
    file: &str,
    func: &str,
) -> PktResult<String> {
    match args.first() {
        Some(ast::Value::Str(s)) => Ok(s.clone()),
        _ => Err(Diagnostic::at(
            format!("`{func}(...)` 需要字符串参数：`{func}(\"...\")`"),
            span,
        )
        .with_file(file.to_string())),
    }
}

/// `and`/`or` 的一个子实参：必须是调用形式（递归 `rule_expr`）。
fn rule_sub_call(sub: &crate::ast::AttrArg, file: &str, in_or: bool) -> PktResult<RuleAccum> {
    match sub {
        crate::ast::AttrArg::Call { name, args, span } => {
            rule_expr(name, args, *span, file, in_or)
        }
        crate::ast::AttrArg::Kv { span, .. } | crate::ast::AttrArg::Bare { span, .. } => {
            Err(Diagnostic::at(
                "`#[rule(and/or(...))]` 的子条件需要调用形式：`#[rule(and(udp(dport=443), bytes(0xc0)))]`"
                    .to_string(),
                *span,
            )
            .with_file(file.to_string()))
        }
    }
}

/// 从 proto 注解提取 IR 层类型（`#[proto(kind="eth")]`；语义阶段已校验存在且合法）。
pub(crate) fn proto_layer_kind(f: &ast::FuncStmt) -> Option<&str> {
    f.attrs.iter().find(|a| a.name == "proto").and_then(|a| {
        a.args.iter().find_map(|g| match g {
            ast::AttrArg::Kv {
                key,
                value: ast::Value::Str(k),
                ..
            } if key == "kind" => Some(k.as_str()),
            _ => None,
        })
    })
}

fn imports_of(ast: &AstFile) -> Vec<&ImportStmt> {
    ast.stmts
        .iter()
        .filter_map(|s| match s {
            Stmt::Import(i) => Some(i),
            _ => None,
        })
        .collect()
}

fn has_default(ast: &AstFile) -> bool {
    ast.stmts.iter().any(|s| matches!(s, Stmt::Pipeline(_)))
}

fn default_of(ast: &AstFile) -> Option<(&Pipeline, Span)> {
    ast.stmts.iter().find_map(|s| match s {
        Stmt::Pipeline(p) => Some((&p.pipeline, p.span)),
        _ => None,
    })
}

/// 目标模块是否存在本地定义 `name`（返回 defs 下标）。
fn local_def_index(graph: &ModuleGraph, module: usize, name: &str) -> Option<usize> {
    defs_of(&graph.modules[module].ast)
        .iter()
        .position(|d| d.name == name)
}

/// 目标模块是否存在本地函数 `name`（返回 funcs 下标）。
fn local_func_index(graph: &ModuleGraph, module: usize, name: &str) -> Option<usize> {
    funcs_of(&graph.modules[module].ast)
        .iter()
        .position(|f| f.name == name)
}

// ── 参数引用（Value::Ident）检查 ─────────────────────────────

/// 表达式里的第一个参数引用（用于非函数定义报错）。
fn first_ident_in_expr(expr: &Expr) -> Option<(String, Span)> {
    match expr {
        Expr::Pipeline(p) => first_ident_in_pipeline(p),
        Expr::Call(c) => first_ident_in_call(c),
    }
}

fn first_ident_in_pipeline(p: &Pipeline) -> Option<(String, Span)> {
    p.layers.iter().find_map(first_ident_in_call)
}

fn first_ident_in_call(c: &Call) -> Option<(String, Span)> {
    c.args.iter().find_map(|a| first_ident_in_value(&a.value))
}

fn first_ident_in_value(v: &Value) -> Option<(String, Span)> {
    match v {
        Value::Ident { name, span } => Some((name.clone(), *span)),
        Value::List(items) => items.iter().find_map(first_ident_in_value),
        _ => None,
    }
}

/// 流水线里全部参数引用（函数体用：校验是否已声明）。
fn idents_in_pipeline(p: &Pipeline) -> Vec<(String, Span)> {
    p.layers.iter().flat_map(idents_in_call).collect()
}

fn idents_in_call(c: &Call) -> Vec<(String, Span)> {
    c.args
        .iter()
        .flat_map(|a| idents_in_value(&a.value))
        .collect()
}

fn idents_in_value(v: &Value) -> Vec<(String, Span)> {
    match v {
        Value::Ident { name, span } => vec![(name.clone(), *span)],
        Value::List(items) => items.iter().flat_map(idents_in_value).collect(),
        _ => Vec::new(),
    }
}

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

use crate::ast::{self, AstFile, Call, Expr, ImportStmt, Pipeline, Span, Stmt, Value};
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

    /// 某模块某函数的下标对应的定义。
    pub(crate) fn func_def(&self, module: usize, func_idx: usize) -> Option<&ast::FuncStmt> {
        funcs_of(&self.modules[module].ast).get(func_idx).copied()
    }

    /// 按名字查模块内函数下标。
    pub(crate) fn func_index(&self, module: usize, name: &str) -> Option<usize> {
        funcs_of(&self.modules[module].ast)
            .iter()
            .position(|f| f.name == name)
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
    /// 模块内 funcs 下标。
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
    /// `sniffer { match ... }` 回包匹配声明（None = 未声明；--pkg --wait 用）。
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
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../eng_lib");
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
            if !seen_lib_files.insert(canon) {
                continue; // 同一文件经重叠库目录重复收集：只处理一次
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
        false,
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
    /// 若为函数：参数（含默认值）；None = 元件 def。
    pub params: Option<Vec<ast::FuncParam>>,
    /// 函数上方的 `#` doc 注释（无则 None）。
    pub doc: Option<ast::FuncDoc>,
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
                        out.push(LibExport {
                            module: mod_name.clone(),
                            name: n.clone(),
                            params: Some(f.params.clone()),
                            doc: f.doc.clone(),
                        });
                    } else if defs.contains(n.as_str()) {
                        out.push(LibExport {
                            module: mod_name.clone(),
                            name: n.clone(),
                            params: None,
                            doc: None,
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
    /// 本模块 funcs 下标。
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
                body: f.body.clone(),
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

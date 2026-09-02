# prping WebUI 审计报告（Playwright + 多 Agent）

> **修复状态（同日）**：P0 全部 7 项已修/已闭环；P1 已修 16 项（#8-16,20-27 含服务端 code/背压/read 上限/合帧/ETag/ping）；P2 已修 #28(Hex 上限)/#29(部分)/#30(竞态+GC+deleteFile)。**遗留**：gzip 与 SIGTERM（需新依赖，待 ADR）、lsp_down 自愈信封（空文档 panic 守卫已在 WIP 落地，回归测试已钉）、search/diff/download/多根工作区（新功能）、i18n、goto-def（根因=旧二进制 LSP 线程 panic，现二进制 + 回归测试已闭环）。复验：WS 无 token/跨源 403、800px 溢出 0、UI 0 报错、311 测试全绿、clippy -D warnings 零警告。
>
> **追加修复（用户反馈）**：markdown 视图滚动条溢出到窗口边缘——`.editor-col` 丢失 `display:flex`（注释写明纵向 flex 但声明不在），flex:1/min-height:0 全链失效，README 渲染内容把 `.main` 网格行撑到 3126px。修复：恢复 flex 列 + `.main` 加 `grid-template-rows: minmax(0,1fr); overflow:hidden` 行高钉死。复验：pkt/md 视图 docScrollH 均 = 视口 900，滚动收回面板内部。同时清理 served 工作区（target/debug/examples）测试残留：`_smoke_run.pkt`、`ast_dump*`、`file` 等。

- 方法：Playwright 驱动真实浏览器遍历 18 个场景（截图 01–18 + report.json 遥测），另由 4 个专项子代理分别做 UX 视觉审计、前端代码审计、Rust 服务端审计、交互流程 QA 测试（extra-*.png 共 10 张 + flows*.py）。
- 环境：target/debug/prping web --port 8788（web feature），Chromium 1600×900 / 1920×1080 / 1024×640 / 800×600。
- 基线事实：0 console 错误、0 页面异常、0 失败请求；首屏到文件树 230ms；468KB 单 JS chunk；图标按钮 97/97 全部有 title/aria-label；WS 34 发 36 收正常。

## P0（最先处理）

1. **WS 无鉴权/Origin 校验**（ws.rs:63-78, mod.rs:150-173）：任意网页可跨源连 ws://127.0.0.1:8788/ws，经 workspace 信封打开任意目录读写删文件并触发发包（design doc §10 已标"必做"未实现）。→ 启动生成随机 token 打进 URL + Origin/Host 校验。
2. **Run 控制台 O(n²) 重渲染**（panels.tsx:562-567, 828-846; App.tsx:182-191）：每条 run_out 对全部行重新 JSON.parse，<For> 按新对象引用对账重建全部 DOM 行；服务端上限 2 万行 → 高频输出下雪崩。→ 摄入时一次解析 + rAF/16ms 批量提交 + 行对象稳定引用。
3. **WS 请求无超时、error 信封被吞**（ws.ts:171-176, 104-105; lsp.ts:97-105）：服务端不回时 await 永久悬挂、pending 只增不减；兜底 timer 不 clearTimeout。→ per-request 超时 + 错误上抛 toast/fileMsg。
4. **服务端 unbounded 无背压**（ws.rs:90-92; run.rs:399-401）：慢客户端/后台标签页时 run_out 无限积压。→ reply 通道 bounded + 满时合并丢弃并置 truncated。
5. **read_file 无大小上限**（workspace.rs:130-135）：误点大文件全量读入后才判二进制（save 有 4MB 上限，read 不对称）。→ 先 metadata 拒 >8MB + 读 8KB 探 NUL。
6. **响应式崩坏**（index.css:192-197 三栏 min 210+340+300=850px）：<~870px 横向溢出（实测 800px scrollW=869）；1024px 下右栏 tab 词中断行、顶栏截断；无侧栏折叠。→ 中列 min-width:0、<900px 侧栏折叠为图标轨/抽屉、tab nowrap+ellipsis。
7. **Ctrl+Click 跳转与高亮不符**（QA extra-jump.png，需结合当前 WIP 复核）：.pkt 局部绑定（http_req）与 eng_lib 库调用（http(）实测 "no definition found"，但修饰键高亮仍提示可点。→ 修 LSP definition 或收敛高亮集合。

## P1（应修）

**交互/UX**
8. 新建文件只建内存缓冲：不落盘、不进树、无"需 Ctrl+S 创建"提示（QA 实测误判两次）。
9. Run 台账语义：行级 ✗ 与 summary "failed 0" 矛盾；step 行渲染本机绝对路径；完成态无时长/重跑/清空；"wait s off" 控件难懂；"#0 / 0/1 tasks" 术语不可读；Stop 随结束消失无反馈。→ 相对路径+可点击、chip=文件名+状态色+时长+↻、全局 Stop all、图例。
10. analyze 应答乱序竞态（App.tsx:262-298 仅按 uri 判过期；refreshSymbols 同病）→ 模块级序号守卫（files.tsx:441-448 已有现成模式）。
11. 切文件 undo 不隔离（cm.ts:690-692）：Ctrl+Z 可把上一个文件内容"撤销"回来并标脏。→ 每 tab 保存/恢复完整 EditorState。
12. 后台标签脏内容不写草稿（App.tsx:405-411 只写活跃 tab）→ onCleanup 遍历 tabs 刷草稿。
13. publishDiagnostics 不按 uri 过滤（lsp.ts:41-51）；每次切文件重新 LSP initialize（lsp.ts:126-129）。
14. 补全仅调用位触发，顶层无补全、无手动唤出入口；100 候选全量渲染。
15. 编辑器注释墙：cm.ts:99 用 defaultHighlightStyle（浅色系）配深色 chrome → 长中文注释暗橙单调无层次。→ 自定义 dark HighlightStyle + 注释折叠 gutter。
16. 文件树/标签：无过滤框；脏文件在树/tab 无圆点标记；hover ✎/✕ 命中区小（opacity:0）；同名文件无路径区分；tab 溢出无横滚/提示；目录右键缺"在此新建"。
17. eng_lib 侧栏 26 文件平铺：无搜索/分组/悬停简介；只读提示弱（建议顶部细条+gutter 锁）。
18. 右栏空态零引导：Globals 1 行、Outline 3 行、Recipe 2 行占屏 20% 其余全空；.pktl/.pkt 两套 tab 组切换无说明。
19. a11y：树无 role=tree/treeitem、无方向键；doc-tabs 缺 role=tab/aria-selected；FolderDialog 无 dialog 语义/焦点陷阱；全页 0 个 h1-h6；中文内容 lang=en；window.prompt/confirm 阻塞且与自绘对话框风格割裂。
20. 缺全局能力：全文/文件搜索、Ctrl+P 快速打开、快捷键表、帮助入口（document/GRAMMAR/--ls 未在 UI 暴露）、设置/主题切换。

**服务端**
21. 缺 content 搜索信封（NEW）：{type:"search", q, glob}，进程内匹配返回 {file,line,snippet}。
22. 缺保存冲突检测与 diff 预览（save 无条件覆盖）+ 外部变更感知（tree 只能手动刷新；可先做 mtime 指纹轻量探测）。
23. run 输出无字节总预算（20k 行×8KB 理论 160MB）+ 逐行单帧 → 字节预算 + 16ms/64KB 合帧。
24. list/lib read/open_folder 同步阻塞 WS reader（ws.rs:275-281, 314-323, 446）→ smol::unblock。
25. 错误信封不可操作：无 code 字段；read 缺文件误报"保存文件失败"（workspace.rs:378-389 复用 ws_save_failed）。
26. stop 仅 SIGKILL（run.rs:277）：--out pcap 中途被杀无收尾 → SIGTERM+800ms→SIGKILL（Win 保持 TerminateProcess）。
27. 传输：468KB 无 gzip（实测可 -67%）无代码分割（@codemirror/* 可拆 vendor）；index.html/config.json 无 ETag/304；run 首输出 ~0.65s 无"starting…"反馈。

## P2（打磨）

28. Hex 面板：无渲染上限（64KB→约 6.5 万 DOM 节点）；无复制/导出 .pcap；与 Layers 无联动高亮；产物 pcap 无下载通道（read 拒二进制）→ download 信封或 /download GET（NEW）。
29. 每键 O(doc) 扫描（cm.ts:135-190, App.tsx:218）与每键 compartment reconfigure（App.tsx:215-239 集合不变也重建）。
30. 草稿定时器竞态（回调时才读 current()/text()）+ draft:* 键无 GC；deleteFile 不清该文件的运行任务与标签（App.tsx:961-992）。
31. 面板持久化白名单漏 outline（App.tsx:1190-1192）。
32. i18n：UI 硬编码英文；后端已有 rust-i18n，可经 config.json 下发 locale。
33. 多根工作区（NEW）、tree 条目附 size/mtime、WS ping 保活、控制台复制/导出、面包屑逐段可点、首访 onboarding 三步浮层。
34. 文档/注释漂移：ws.rs:175-176"每连接最多一个"已过时；design doc"单运行槽""web.run_busy"已不存在。
35. Windows：canonicalize verbatim 路径传给子进程展示难看（strip 前缀）；rename 无 overwrite 选项需两步。

## 表现良好（保持）

首屏 230ms、0 console 错误、hashed 资源 immutable + index.html no-cache、图标按钮 100% 标签、connected 徽标、草稿恢复链路完整（restore draft/↺ 丢弃）、诊断实时（未保存缓冲也更新）、Layers 面板协议学习视图（headers.pkt 9 个 export 层栈）出色、运行参数缺失校验清晰（icmp_ping_step 提示 --params ip=…）、并行运行任务管理（chips/■/✕）可用。

## 证据清单

- 截图：.uiaudit/01–18（主流程/响应式）、extra-*.png ×10（QA 专项：补全/悬停/跳转/脏态/草稿恢复/诊断/md 渲染/文件夹对话框/pcaps/停止任务）
- 遥测：.uiaudit/report.json（perf/a11y/console/ws 帧计数）
- 驱动脚本：.uiaudit/drive.py（主遍历）、flows*.py（QA）

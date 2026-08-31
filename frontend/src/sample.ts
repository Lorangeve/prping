// 空态兜底示例文档（合法 pkt DSL：经 LSP 应零诊断，右侧有层栈与 HEX）。
// 有工作区时启动后自动打开 examples 下第一个文件，本文档仅在无文件可开时出现。
export const SAMPLE_DOC = `# prping web — packet DSL live editing
# Ctrl+Space: completion   hover: primitive docs   right: live layers + hex
# Left sidebar: workspace files (examples) are editable (Ctrl+S saves),
# eng_lib library files open read-only.

req = icmp(type=8, id=0x1234, seq=1, payload="prping web")

use(req) |> ipv4(dst="127.0.0.1", ttl=64) |> eth()
`;

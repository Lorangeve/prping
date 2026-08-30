// 首次打开的示例文档（合法 pkt DSL：经 LSP 应零诊断，右侧有层栈与 HEX）。
export const SAMPLE_DOC = `# prping web — packet DSL live editing
# Ctrl+Space: completion   hover: primitive docs   right: live layers + hex
# Library files (eng_lib) open read-only from the toolbar above.

req = icmp(type=8, id=0x1234, seq=1, payload="prping web")

use(req) |> ipv4(dst="127.0.0.1", ttl=64) |> eth()
`;

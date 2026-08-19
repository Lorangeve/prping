import json
import sys

TEXT = 'a = tcp(dport=80)\nuse(a) |> udp( dport=53\n'


def frame(obj):
    body = json.dumps(obj, ensure_ascii=False).encode()
    sys.stdout.buffer.write(f"Content-Length: {len(body)}\r\n\r\n".encode() + body)


frame({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"capabilities": {}}})
frame({"jsonrpc": "2.0", "method": "initialized", "params": {}})
frame({"jsonrpc": "2.0", "method": "textDocument/didOpen", "params": {
    "textDocument": {"uri": "file:///tmp/demo.pkt", "languageId": "pkt", "version": 1, "text": TEXT}}})
frame({"jsonrpc": "2.0", "id": 2, "method": "textDocument/completion", "params": {
    "textDocument": {"uri": "file:///tmp/demo.pkt"}, "position": {"line": 0, "character": 1}}})
frame({"jsonrpc": "2.0", "id": 3, "method": "textDocument/hover", "params": {
    "textDocument": {"uri": "file:///tmp/demo.pkt"}, "position": {"line": 1, "character": 11}}})
frame({"jsonrpc": "2.0", "id": 4, "method": "textDocument/documentSymbol", "params": {
    "textDocument": {"uri": "file:///tmp/demo.pkt"}}})
frame({"jsonrpc": "2.0", "id": 5, "method": "shutdown", "params": {}})
frame({"jsonrpc": "2.0", "method": "exit", "params": {}})

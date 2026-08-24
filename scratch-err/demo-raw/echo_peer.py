import socket, threading
def handle(conn, addr):
    try:
        data = conn.recv(4096)
        print(f"[{addr}] received {len(data)} bytes: {data!r}", flush=True)
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
    except Exception as e:
        print(f"[{addr}] error: {e}", flush=True)
    finally:
        conn.close()
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', 8888)); srv.listen(5)
print('peer-log server on :8888', flush=True)
while True:
    c, a = srv.accept()
    threading.Thread(target=handle, args=(c, a), daemon=True).start()

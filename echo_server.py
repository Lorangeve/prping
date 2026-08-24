import socket, threading, sys

def handle(conn, addr):
    try:
        data = conn.recv(4096)
        print(f"[{addr}] received {len(data)} bytes: {data!r}", flush=True)
        if data:
            resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
            conn.sendall(resp)
            print(f"[{addr}] sent response", flush=True)
    except Exception as e:
        print(f"[{addr}] error: {e}", flush=True)
    finally:
        conn.close()
        print(f"[{addr}] closed", flush=True)

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('0.0.0.0', 8000))
srv.listen(5)
print('Echo server listening on :8000', flush=True)
while True:
    c, a = srv.accept()
    threading.Thread(target=handle, args=(c, a), daemon=True).start()

import socket, threading

def handle(src, dst):
    try:
        while True:
            data = src.recv(4096)
            if not data: break
            dst.send(data)
    except: pass
    src.close()
    dst.close()

def server():
    print("Starting ADB Proxy on 0.0.0.0:5556 -> 127.0.0.1:5555")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('0.0.0.0', 5556))
    s.listen(5)
    while True:
        try:
            c, a = s.accept()
            d = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            d.connect(('127.0.0.1', 5555))
            threading.Thread(target=handle, args=(c,d), daemon=True).start()
            threading.Thread(target=handle, args=(d,c), daemon=True).start()
        except Exception as e:
            print("Proxy error:", e)

if __name__ == '__main__':
    server()

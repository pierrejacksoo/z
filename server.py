import socket
import threading

HOST = '0.0.0.0'
PORT = 9009

# Room name ➔ [client1_sock, client2_sock]
rooms = {}
lock = threading.Lock()

def relay(client_sock, peer_sock):
    while True:
        try:
            data = client_sock.recv(4096)
            if not data:
                break
            peer_sock.sendall(data)
        except Exception:
            break
    client_sock.close()
    peer_sock.close()

def handle_client(sock):
    try:
        room = sock.recv(256).decode('utf-8').strip()
        if not room:
            sock.close()
            return
        with lock:
            if room not in rooms:
                rooms[room] = [sock]
                peer = None
            else:
                rooms[room].append(sock)
                peer = rooms[room][0]
                if len(rooms[room]) > 2:
                    # Only two clients per room
                    sock.sendall(b'Room full')
                    sock.close()
                    return
        if not peer:
            # Wait for peer
            try:
                while True:
                    if len(rooms[room]) > 1:
                        break
                    threading.Event().wait(0.5)
            except Exception:
                pass
        # Get peer (should have 2 clients now)
        with lock:
            peer_sock = [s for s in rooms[room] if s != sock][0]
        # Start relaying both ways
        t1 = threading.Thread(target=relay, args=(sock, peer_sock), daemon=True)
        t2 = threading.Thread(target=relay, args=(peer_sock, sock), daemon=True)
        t1.start()
        t2.start()
    except Exception:
        sock.close()

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        print(f'Server running on {HOST}:{PORT}')
        while True:
            client_sock, addr = s.accept()
            threading.Thread(target=handle_client, args=(client_sock,), daemon=True).start()

if __name__ == "__main__":
    main()

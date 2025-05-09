import socket

# Constants
HOST = '127.0.0.1'
PORT = 65432

def relay_server():
    """
    A simple relay server that forwards data between two clients.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen(2)
        print("Server is listening on", (HOST, PORT))

        # Accept connections from Alice and Bob
        alice_conn, _ = server_socket.accept()
        print("Alice connected")
        bob_conn, _ = server_socket.accept()
        print("Bob connected")

        # Relay data between clients
        while True:
            # Receive data from Alice and send to Bob
            data = alice_conn.recv(1024)
            if not data:
                break
            bob_conn.sendall(data)

            # Receive data from Bob and send to Alice
            data = bob_conn.recv(1024)
            if not data:
                break
            alice_conn.sendall(data)

        alice_conn.close()
        bob_conn.close()
        print("Server shutting down")

if __name__ == "__main__":
    relay_server()

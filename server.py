import socket
import threading

# Constants
HOST = '127.0.0.1'
PORT = 65432

# Global variables to track connections
connections = []
lock = threading.Lock()

def handle_client(client_socket, client_address):
    """
    Handles communication for a connected client.
    """
    with client_socket:
        print(f"Client {client_address} connected.")
        with lock:
            connections.append(client_socket)

        # Wait until at least two clients are connected
        while True:
            with lock:
                if len(connections) >= 2:
                    break
            print("Waiting for peer...")
        
        try:
            while True:
                # Receive data from the client
                data = client_socket.recv(1024)
                if not data:
                    break
                
                # Decode the message and print it
                message = data.decode('utf-8')  # Assuming UTF-8 encoding
                print(f"[{client_address}] {message}")

                # Broadcast the message to all other clients
                with lock:
                    for conn in connections:
                        if conn != client_socket:
                            conn.sendall(data)
        finally:
            with lock:
                connections.remove(client_socket)
            print(f"Client {client_address} disconnected.")

def relay_server():
    """
    A simple relay server that forwards data between clients.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)  # Allow up to 5 pending connections
        print("Server is listening on", (HOST, PORT))

        while True:
            client_socket, client_address = server_socket.accept()
            threading.Thread(target=handle_client, args=(client_socket, client_address)).start()

if __name__ == "__main__":
    relay_server()

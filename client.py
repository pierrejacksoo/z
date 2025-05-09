import socket
from px import diffiehellman, kdf

# Constants
HOST = '127.0.0.1'
PORT = 65432

def client(role):
    """
    A client that performs Diffie-Hellman key exchange via the relay server.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((HOST, PORT))
        print(f"{role} connected to server")

        # Perform Diffie-Hellman key exchange
        shared_secret = diffiehellman(client_socket)
        print(f"{role}'s shared secret: {shared_secret.hex()}")

        # Derive a key using KDF
        salt = b"somesalt"  # A predefined salt, ideally should be unique
        derived_key = kdf(shared_secret, salt)
        print(f"{role}'s derived key: {derived_key.hex()}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2 or sys.argv[1] not in ("Alice", "Bob"):
        print("Usage: python client.py [Alice|Bob]")
        sys.exit(1)

    client(sys.argv[1])

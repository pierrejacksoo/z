import socket
import threading
import sqlite3
from px import diffiehellman, kdf, encrypt_aes, decrypt_aes
from pathlib import Path
from PySide6.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLineEdit, QTextEdit, QLabel
from PySide6.QtCore import Qt

# Constants
HOST = '127.0.0.1'
PORT = 65432
DB_PATH = Path.home() / ".local/share/VortexDesktop/vdata/crypto.db"

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
    
        # Start key exchange and message receiving threads
        threading.Thread(target=self.key_exchange, daemon=True).start()
        threading.Thread(target=self.receive_messages, daemon=True).start()
    
    def init_ui(self):
        # Initialize the UI components
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
        """
        Sets up the SQLite database to store messages.
        """
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
    
    def save_message(self, username, peer, message):
        """
        Saves a message to the SQLite database.
        """
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO messages (username, peer, message) VALUES (?, ?, ?)", (username, peer, message))
        conn.commit()
        conn.close()
    
    def key_exchange(self):
        """
        Performs the Diffie-Hellman key exchange.
        """
        shared_secret = diffiehellman(self.client_socket)
        self.shared_key = kdf(shared_secret, b"somesalt")
        self.status_label.setText("Key exchange complete. You can start chatting.")
        print(f"{self.username}'s shared key derived.")
    
    def receive_messages(self):
        """
        Listens for incoming messages from the server.
        """
        while True:
            if self.shared_key:
                encrypted_message = self.client_socket.recv(1024)
                if not encrypted_message:
                    break
                try:
                    message = decrypt_aes(encrypted_message, self.shared_key).decode('utf-8')
                    self.display_message(f"[Peer]: {message}")
                    self.save_message(self.username, "Peer", message)
                except UnicodeDecodeError:
                    self.display_message("[Peer]: Message could not be decoded.")
    
    def send_message(self):
        """
        Sends the message entered by the user.
        """
        message = self.message_input.text()
        if message.strip():
            encrypted_message = encrypt_aes(message.encode(), self.shared_key)
            self.client_socket.sendall(encrypted_message)
            self.display_message(f"[{self.username}]: {message}")
            self.save_message(self.username, "Self", message)
            self.message_input.clear()
    
    def display_message(self, message):
        """
        Displays the message in the chat window.
        """
        self.chat_display.append(message)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    if len(sys.argv) != 2:
        print("Usage: python client.py [username]")
        sys.exit(1)
    
    username = sys.argv[1]
    chat_app = ChatClientApp(username)
    chat_app.show()
    
    sys.exit(app.exec())

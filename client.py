import sys
import socket
import threading
import base64
import hashlib
import io

from PySide6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton,
                               QTextEdit, QLabel, QMessageBox)
from PySide6.QtGui import QPixmap, QImage, QFont
from PySide6.QtCore import Qt

import px  # Your cryptography module

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 9009

# --- GUI Components ---

class ChatWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure P2P Chat")
        self.setStyleSheet("""
            QWidget { background: #23272e; color: #f3f3f3; }
            QTextEdit, QLineEdit { background: #181b20; color: #e9e9e9; border-radius: 6px; font-size: 13px; }
            QPushButton { background: #4a90e2; color: #fff; border-radius: 7px; padding: 6px 16px; font-weight: bold; }
            QPushButton:disabled { background: #273042; color: #999; }
            QLabel { font-size: 14px; }
        """)
        self.sock = None
        self.encryption_ready = False
        self.key = None
        self.iv = None

        # Layouts
        self.layout = QVBoxLayout(self)
        self.top = QHBoxLayout()
        self.roomlabel = QLabel("Room:")
        self.roomedit = QLineEdit()
        self.joinbtn = QPushButton("Join")
        self.top.addWidget(self.roomlabel)
        self.top.addWidget(self.roomedit)
        self.top.addWidget(self.joinbtn)
        self.layout.addLayout(self.top)

        self.status = QLabel("")
        self.status.setFont(QFont("Consolas", 13, QFont.Bold))
        self.layout.addWidget(self.status)

        self.fingerprint_label = QLabel("")
        self.fingerprint_img = QLabel("")
        self.fingerprint_img.setAlignment(Qt.AlignHCenter)
        self.layout.addWidget(self.fingerprint_label)
        self.layout.addWidget(self.fingerprint_img)

        self.chat = QTextEdit()
        self.chat.setReadOnly(True)
        self.layout.addWidget(self.chat)

        self.bottom = QHBoxLayout()
        self.input = QLineEdit()
        self.sendbtn = QPushButton("Send")
        self.sendbtn.setEnabled(False)
        self.bottom.addWidget(self.input)
        self.bottom.addWidget(self.sendbtn)
        self.layout.addLayout(self.bottom)

        self.show_fingerprint_btn = QPushButton("🔑 Show Key Fingerprint")
        self.show_fingerprint_btn.setVisible(False)
        self.layout.addWidget(self.show_fingerprint_btn)

        self.joinbtn.clicked.connect(self.connect_room)
        self.sendbtn.clicked.connect(self.send_message)
        self.show_fingerprint_btn.clicked.connect(self.show_fingerprint)
        self.input.returnPressed.connect(self.send_message)

        self.setMinimumWidth(420)
        self.setMinimumHeight(520)

        self.private_key = None
        self.public_key = None
        self.peer_pubkey = None
        self.shared_secret = None

    def connect_room(self):
        room = self.roomedit.text().strip()
        if not room:
            QMessageBox.warning(self, "Input Error", "Enter a room name.")
            return
        try:
            sock = socket.create_connection((SERVER_HOST, SERVER_PORT))
            sock.sendall(room.encode()[:256])
            self.sock = sock
            self.roomedit.setEnabled(False)
            self.joinbtn.setEnabled(False)
            self.status.setText("Waiting for peer...")
            threading.Thread(target=self.listen_for_peer, daemon=True).start()
        except Exception as ex:
            QMessageBox.critical(self, "Connection failed", str(ex))

    def listen_for_peer(self):
        # ECDH Key Exchange
        try:
            # Generate ECDH key pair
            priv, pub = px.ecdhe_make_keypair()
            self.private_key, self.public_key = priv, pub
            # Wait for peer: protocol is simple, exchange pubkeys encoded as base64(x:int,y:int)
            # Send our pubkey
            pub_bytes = "%d,%d" % (pub[0], pub[1])
            self.sock.sendall(b'PUBKEY:' + pub_bytes.encode() + b'\n')
            # Listen for peer's pubkey
            peer_pub = None
            while not peer_pub:
                data = self.sock.recv(4096)
                if not data:
                    raise Exception("Disconnected")
                for line in data.split(b'\n'):
                    if line.startswith(b'PUBKEY:'):
                        _, payload = line.split(b':', 1)
                        x, y = [int(i) for i in payload.decode().split(',')]
                        peer_pub = (x, y)
                        break
            self.peer_pubkey = peer_pub
            # Derive shared ECDHE secret
            px.ecdhe_validate_public_key(peer_pub)
            shared_point = px.ecdhe_scalar_mult(priv, peer_pub)
            shared_secret_bytes = px.int_to_bytes(shared_point[0]) + px.int_to_bytes(shared_point[1])
            key = px.hkdf_sha256(shared_secret_bytes, 32)
            self.key = key
            self.encryption_ready = True
            self.status.setText("Peer Connected! Key Exchange in progress...")
            # Now show fingerprint button
            self.show_fingerprint_btn.setVisible(True)
            self.fingerprint = hashlib.sha256(key).hexdigest()
            # Show fingerprint label (short)
            self.fingerprint_label.setText("Key Fingerprint SHA-256: " + self.fingerprint[:16] + "...")
            # Enable chat
            self.sendbtn.setEnabled(True)
            self.status.setText("Chat ready (messages are encrypted)")
            # Start listening for chat messages (in encrypted form)
            threading.Thread(target=self.listen_for_messages, daemon=True).start()
        except Exception as e:
            self.status.setText(f"Error: {e}")

    def show_fingerprint(self):
        # Visualize the fingerprint/key as an image (e.g., 8x4 colored blocks)
        digest = hashlib.sha256(self.key).digest()
        w, h = 8, 4
        data = [digest[i] for i in range(w*h)]
        img = QImage(w, h, QImage.Format_RGB32)
        for y in range(h):
            for x in range(w):
                v = data[y*w + x]
                c = (v, 255-v, (v*3)%255)
                img.setPixel(x, y, (c[0]<<16)|(c[1]<<8)|c[2])
        pixmap = QPixmap.fromImage(img.scaled(160, 80))
        self.fingerprint_img.setPixmap(pixmap)
        self.fingerprint_img.setVisible(True)

    def listen_for_messages(self):
        while True:
            try:
                data = self.sock.recv(4096)
                if not data:
                    break
                # Expect: base64-encoded AES256-CBC encrypted message
                try:
                    msg = px.decrypt_aes(data.decode(), self.key).decode(errors='ignore')
                except Exception:
                    msg = "[Decryption error]"
                self.chat.append(f"<b>Peer:</b> {msg}")
            except Exception:
                break
        self.status.setText("Peer disconnected.")
        self.sendbtn.setEnabled(False)

    def send_message(self):
        msg = self.input.text()
        if not msg or not self.encryption_ready:
            return
        try:
            enc = px.encrypt_aes(msg.encode(), self.key)
            self.sock.sendall(enc + b'\n')
            self.chat.append(f"<span style='color:#4a90e2'><b>You:</b> {msg}</span>")
            self.input.clear()
        except Exception as ex:
            self.status.setText(f"Send error: {ex}")

def main():
    app = QApplication(sys.argv)
    win = ChatWindow()
    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()

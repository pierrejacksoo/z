import argparse
import mysql.connector
from mysql.connector import errorcode

def connect_to_db(target_ip, username, password):
    try:
        # Connect to the MySQL database
        connection = mysql.connector.connect(
            host=target_ip,
            user=username,
            password=password
        )
        print(f"Successfully connected to {target_ip}")
        return connection
    except mysql.connector.Error as err:
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            print("Something is wrong with the username or password.")
        elif err.errno == errorcode.ER_BAD_DB_ERROR:
            print("Database does not exist.")
        else:
            print(err)
        return None

def execute_command(connection, command):
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
    except mysql.connector.Error as err:
        print(f"Error executing command: {err}")
    finally:
        cursor.close()

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="MySQL Command Executor")
    parser.add_argument('target_ip', type=str, help="Target IP address of the MySQL server")
    parser.add_argument('-l', '--username', type=str, required=True, help="MySQL username")
    parser.add_argument('-P', '--password', type=str, required=True, help="MySQL password")
    args = parser.parse_args()

    # Connect to the MySQL server
    connection = connect_to_db(args.target_ip, args.username, args.password)
    if connection:
        while True:
            # Get user input for MySQL commands
            user_command = input("Enter a MySQL command (e.g., 'CREATE USER' or 'DUMP TABLES') or type 'exit' to quit: ")
            if user_command.lower() == 'exit':
                break
            execute_command(connection, user_command)

        connection.close()

if __name__ == "__main__":
    main()

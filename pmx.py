import PyPDF2
import argparse
import colorama
from colorama import Fore, Style

colorama.init(autoreset=True)

def try_passwords(pdf_path, password_list, save_as=None):
    try:
        with open(pdf_path, "rb") as file:
            reader = PyPDF2.PdfReader(file)
            if not reader.is_encrypted:
                print(Fore.YELLOW + "[!] PDF is not password protected.")
                return
            
            with open(password_list, "r", encoding="utf-8") as pw_file:
                for password in pw_file:
                    password = password.strip()
                    print(Fore.CYAN + f'Trying Passphrase: "{password}"')
                    
                    if reader.decrypt(password):
                        print(Fore.GREEN + f'KEY FOUND: [ "{password}" ]')

                        if save_as:
                            writer = PyPDF2.PdfWriter()
                            for page in reader.pages:
                                writer.add_page(page)

                            with open(save_as, "wb") as output_pdf:
                                writer.write(output_pdf)
                            print(Fore.MAGENTA + f"[+] Decrypted file saved as '{save_as}'")
                        
                        return

        print(Fore.RED + "KEY NOT FOUND")
    
    except FileNotFoundError:
        print(Fore.RED + "[ERROR] File not found. Check paths and try again.")
    except Exception as e:
        print(Fore.RED + f"[ERROR] {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PDF Brute Forcer")
    parser.add_argument("-P", "--passwordlist", required=True, help="Path to password list file")
    parser.add_argument("pdf_file", help="Path to the encrypted PDF file")
    parser.add_argument("-s", "--save-as", help="Save decrypted PDF as this file (optional)")

    args = parser.parse_args()
    
    try_passwords(args.pdf_file, args.passwordlist, args.save_as)

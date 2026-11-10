#!/usr/bin/env python3
"""SSC Cloud Pro - Termux client (Python, standard library only).

Talks only to your cloud backend. Stores no password and no API keys;
keeps a short-lived (~1h) session token in a mode-600 file.
"""
import getpass
import json
import os
import stat
import sys
import urllib.error
import urllib.request

CONF = os.path.expanduser("~/.ssc_cloud")
TOKEN_FILE = os.path.join(CONF, "token")
URL_FILE = os.path.join(CONF, "server")


def die(msg):
    print(msg, file=sys.stderr)
    sys.exit(1)


def read(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except FileNotFoundError:
        return None


def write_private(path, text):
    os.makedirs(CONF, mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def server():
    s = read(URL_FILE)
    if not s:
        die("Not configured. Run: python ssc.py setup")
    return s


def request(method, path, body=None, auth=True):
    headers = {"content-type": "application/json"}
    if auth:
        tok = read(TOKEN_FILE)
        if not tok:
            die("Not logged in. Run: python ssc.py login")
        headers["authorization"] = "Bearer " + tok
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(server() + "/api" + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try:
            err = json.loads(e.read().decode()).get("error", "unknown")
        except Exception:
            err = "unknown"
        if e.code == 401 and auth:
            try:
                os.remove(TOKEN_FILE)
            except FileNotFoundError:
                pass
            die("Session expired. Run: python ssc.py login")
        die(f"Error ({e.code}): {err}")
    except urllib.error.URLError as e:
        die(f"Network error: cannot reach {server()} ({e.reason})")


def show(obj):
    print(json.dumps(obj, indent=2, ensure_ascii=False))


def cmd_setup():
    u = input("Server URL (https://...): ").strip().rstrip("/")
    if not u.startswith("https://"):
        die("URL must start with https://")
    write_private(URL_FILE, u)
    print("Saved. Checking server...")
    show(request("GET", "/health", auth=False))


def cmd_login():
    server()
    email = input("Email: ").strip()
    password = getpass.getpass("Password: ")
    res = request("POST", "/auth/cli-login", {"email": email, "password": password}, auth=False)
    password = ""
    tok = res.get("idToken")
    if not tok:
        die("Login failed: " + str(res.get("error", "unknown error")))
    write_private(TOKEN_FILE, tok)
    me = request("GET", "/me")
    print(f"Logged in as {me.get('email')} ({me.get('role')})")


def cmd_logout():
    try:
        os.remove(TOKEN_FILE)
    except FileNotFoundError:
        pass
    print("Logged out. Session token deleted.")


def cmd_reports():
    for r in request("GET", "/security/reports"):
        print(f"{r['id']}\t{r['status']}\t{r['type']}\t{r['targetRef']}")


def cmd_alerts():
    for a in request("GET", "/telegram/alerts"):
        print(f"{a['reviewed']}\t{a.get('chatTitle') or a.get('chatId')}\t{'; '.join(a['reasons'])}")


def cmd_lookup(q):
    # Searches YOUR saved reports only; does not query Facebook about third parties.
    for r in request("GET", "/security/reports"):
        if q.lower() in r["targetRef"].lower():
            print(f"{r['id']}\t{r['status']}\t{r['type']}\t{r['targetRef']}")


def cmd_apis():
    r = request("GET", "/api-status")
    show({"tests": r["tests"], "configured": r["configured"]})


USAGE = """SSC Cloud Pro client
  setup      set server URL
  login      sign in (password sent once to your server, never stored)
  logout     delete the session token
  stats      dashboard statistics
  reports    your security report history
  lookup Q   search your saved reports for a reference
  telegram   Telegram bot status (admin)
  alerts     Telegram security alerts (admin)
  apis       API connection status (admin)"""


def main():
    a = sys.argv[1:]
    c = a[0] if a else ""
    if c == "setup": cmd_setup()
    elif c == "login": cmd_login()
    elif c == "logout": cmd_logout()
    elif c == "stats": show(request("GET", "/dashboard/stats"))
    elif c == "reports": cmd_reports()
    elif c == "lookup" and len(a) > 1: cmd_lookup(a[1])
    elif c == "telegram": show(request("GET", "/telegram/status"))
    elif c == "alerts": cmd_alerts()
    elif c == "apis": cmd_apis()
    else: print(USAGE)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()

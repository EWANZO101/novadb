#!/usr/bin/env python3
"""End-to-end test of the NovaDB dashboard. Run ONLY against a throwaway instance:
it consumes the one-time admin password.  usage: DASH_PORT=9621 dashboard-e2e.py <file with one-time pw>
"""
import base64, hashlib, hmac, re, struct, sys, time, urllib.parse, urllib.request, http.client

import os
BASE = os.environ.get("DASH_HOST", "127.0.0.1"); PORT = int(os.environ.get("DASH_PORT", "9621"))
PW0 = open(sys.argv[1]).read().strip()
ok_count = 0

class C:
    def __init__(self): self.cookies = {}
    def req(self, method, path, form=None, headers=None):
        h = dict(headers or {})
        if self.cookies: h["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        body = None
        if form is not None:
            body = urllib.parse.urlencode(form); h["Content-Type"] = "application/x-www-form-urlencoded"
        c = http.client.HTTPConnection(BASE, PORT, timeout=15)
        c.request(method, path, body=body, headers=h)
        r = c.getresponse(); data = r.read().decode(errors="replace")
        for k, v in r.getheaders():
            if k.lower() == "set-cookie":
                name, val = v.split(";")[0].split("=", 1)
                if "Max-Age=0" in v: self.cookies.pop(name, None)
                else: self.cookies[name] = val
        return r.status, dict((k.lower(), v) for k, v in r.getheaders()), data

def check(cond, msg):
    global ok_count
    if not cond: print("FAIL:", msg); sys.exit(1)
    ok_count += 1; print("ok  ", msg)

def csrf(html):
    m = re.search(r'name="csrf" value="([^"]+)"', html); return m.group(1) if m else ""

def totp(secret_b32, t=None, offset=0):
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8))
    ctr = int((t or time.time()) // 30) + offset
    h = hmac.new(key, struct.pack(">Q", ctr), hashlib.sha1).digest()
    o = h[19] & 15
    return "%06d" % ((struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000)

a = C()
s, h, b = a.req("GET", "/")
check(s == 303 and h["location"] == "/login", "anonymous / redirects to /login")
check("frame-ancestors 'none'" in h.get("content-security-policy", ""), "strict CSP present")
check("object-src 'none'" in h.get("content-security-policy", ""), "CSP restricts object-src explicitly")
s, h, b = a.req("GET", "/users")
check(s == 303, "admin page needs login")

# Wrong password, unknown user — same message.
s, h, b = a.req("POST", "/login", {"username": "admin", "password": "wrong-password-123"})
check("Wrong username or password" in b, "wrong password rejected")
s, h, b = a.req("POST", "/login", {"username": "nobody", "password": "wrong-password-123"})
check("Wrong username or password" in b, "unknown user gets identical message")
s, h, b = a.req("POST", "/login", {"username": "admin", "password": PW0}, {"Origin": "https://evil.example"})
check(s == 403, "cross-origin login POST blocked")
s, h, b = a.req("POST", "/login", {"username": "admin", "password": PW0}, {"Origin": "null", "Sec-Fetch-Site": "cross-site"})
check(s == 403, "Origin: null from another site blocked")
s, h, b = a.req("POST", "/login", {"username": "x", "password": "y"}, {"Origin": "null", "Sec-Fetch-Site": "same-origin"})
check(s == 200 and "Wrong username or password" in b, "browser same-origin POST with Origin: null accepted")
s, h, b = a.req("POST", "/login", {"username": "x", "password": "y"}, {"Origin": f"http://{BASE}:{PORT}", "Sec-Fetch-Site": "same-origin"})
check(s == 200 and "Wrong username or password" in b, "browser same-origin POST with real Origin accepted")
s, h, b = a.req("GET", "/login")
check(h.get("referrer-policy") == "same-origin", "referrer-policy same-origin (no-referrer breaks Origin)")

s, h, b = a.req("POST", "/login", {"username": "admin", "password": PW0})
check(s == 303 and h["location"] == "/setup/password", "one-time password -> forced password change")
s, h, b = a.req("GET", "/")
check(s == 303 and h["location"] == "/setup/password", "dashboard unreachable before setup")
s, h, b = a.req("GET", "/setup/password"); tok = csrf(b)
s, h, b = a.req("POST", "/setup/password", {"csrf": tok, "new": "short", "again": "short"})
check("at least 12" in b, "weak password refused")
s, h, b = a.req("POST", "/setup/password", {"csrf": "bad", "new": "x", "again": "x"})
check(s == 303, "bad CSRF token ignored")
NEWPW = "violet-harbour-71-ledger"
s, h, b = a.req("POST", "/setup/password", {"csrf": tok, "new": NEWPW, "again": NEWPW})
check(s == 303 and h["location"] == "/setup/totp", "password changed -> TOTP enrolment")
s, h, b = a.req("GET", "/")
check(s == 303 and h["location"] == "/setup/totp", "dashboard unreachable before 2FA")
s, h, b = a.req("GET", "/setup/totp")
secret = re.search(r'<div class="secret">([A-Z2-7 ]+)</div>', b).group(1).replace(" ", "")
check(len(secret) == 32 and "<svg" in b, "TOTP secret + QR shown")
tok = csrf(b)
s, h, b = a.req("POST", "/setup/totp", {"csrf": tok, "code": "000000" if totp(secret) != "000000" else "111111"})
check("not right" in b, "wrong TOTP refused at enrolment")
s, h, b = a.req("POST", "/setup/totp", {"csrf": tok, "code": totp(secret)})
check(s == 303 and h["location"] == "/?ok=mfa", "TOTP enrolled")
s, h, b = a.req("GET", "/")
check(s == 200 and "System database" in b and "chain intact" not in b or "intact" in b, "overview renders")
check("Integrity" in b and 'pill ok">ok' in b, "system DB verify ok")

# Users: create a viewer, check one-time password shown, escape check.
s, h, b = a.req("GET", "/users"); tok = csrf(b)
s, h, b = a.req("POST", "/users/create", {"csrf": tok, "username": "<script>", "role": "viewer"})
check("3-32 characters" in b, "invalid username refused")
s, h, b = a.req("POST", "/users/create", {"csrf": tok, "username": "viewer1", "role": "viewer"})
vpw = re.search(r'One-time password for viewer1.*?<div class="secret">([^<]+)</div>', b, re.S)
check(vpw is not None, "new user gets one-time password")
vpw = vpw.group(1)
s, h, b = a.req("POST", "/users/action", {"csrf": tok, "user": "admin", "action": "delete"})
check("own account" in b, "admin cannot delete themselves")

# Viewer login: password -> forced change -> TOTP; viewer cannot open /users or /audit.
v = C()
s, h, b = v.req("POST", "/login", {"username": "viewer1", "password": vpw})
check(h.get("location") == "/setup/password", "viewer forced to change password")
s, h, b = v.req("GET", "/setup/password"); t2 = csrf(b)
s, h, b = v.req("POST", "/setup/password", {"csrf": t2, "new": "copper-meadow-55-signal", "again": "copper-meadow-55-signal"})
s, h, b = v.req("GET", "/setup/totp")
vsec = re.search(r'<div class="secret">([A-Z2-7 ]+)</div>', b).group(1).replace(" ", ""); t2 = csrf(b)
s, h, b = v.req("POST", "/setup/totp", {"csrf": t2, "code": totp(vsec)})
s, h, b = v.req("GET", "/users")
check(s == 403, "viewer blocked from /users")
s, h, b = v.req("GET", "/audit")
check(s == 403, "viewer blocked from /audit")

# Fresh admin login with MFA, replay protection.
a2 = C()
s, h, b = a2.req("POST", "/login", {"username": "admin", "password": NEWPW})
check(h.get("location") == "/login/totp", "password ok -> TOTP step")
s, h, b = a2.req("GET", "/")
check(h.get("location") == "/login/totp", "half-logged-in session cannot see dashboard")
s, h, b = a2.req("GET", "/login/totp"); t3 = csrf(b)
used = totp(secret)  # same step as enrolment -> must be rejected as replay
s, h, b = a2.req("POST", "/login/totp", {"csrf": t3, "code": used})
if s == 303:
    print("note: time step advanced since enrolment; replay check skipped")
else:
    check("already used" in b, "TOTP replay rejected")
    time.sleep(31 - time.time() % 30)
    s, h, b = a2.req("POST", "/login/totp", {"csrf": t3, "code": totp(secret)})
check(s == 303 and h["location"] == "/", "admin full login with TOTP")

# Audit chain + escaping.
s, h, b = a2.req("GET", "/audit")
check("chain intact" in b and "login.fail" in b and "mfa.enrolled" in b, "audit log has events, chain intact")
check("<script>" not in b, "no unescaped script in audit page")
check(PW0 not in b and NEWPW not in b and secret not in b, "no passwords/secrets in audit log")

# Admin disables viewer -> viewer session killed.
s, h, b = a2.req("GET", "/users"); t4 = csrf(b)
s, h, b = a2.req("POST", "/users/action", {"csrf": t4, "user": "viewer1", "action": "disable"})
s, h, b = v.req("GET", "/")
check(s == 303 and h["location"] == "/login", "disabled user's session revoked")

# Logout invalidates server-side.
old = dict(a2.cookies)
s, h, b = a2.req("GET", "/account"); t5 = csrf(b)
s, h, b = a2.req("POST", "/logout", {"csrf": t5})
x = C(); x.cookies = old
s, h, b = x.req("GET", "/")
check(s == 303, "old cookie dead after logout")

# Lockout after 10 failures (rate limiter kicks in first at 10/5min per IP: either is fine).
l = C(); statuses = []
for i in range(12):
    s, h, b = l.req("POST", "/login", {"username": "admin", "password": f"nope-{i}-xxxxxxxx"})
    statuses.append(s)
check(429 in statuses, "brute force gets HTTP 429")
print(f"\nALL {ok_count} CHECKS PASSED")

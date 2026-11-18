#!/usr/bin/env python3
"""Pre-auth abuse checks against a running novadb-server (PLAN.md §4.5/§4.6).
usage: protocol-abuse.py HOST PORT CA_FILE PASSWORD_FILE    (use a throwaway server)"""
import socket, ssl, struct, sys, time

HOST, PORT, CA, PWFILE = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
passed = 0


def check(cond, msg):
    global passed
    if not cond:
        print("FAIL:", msg)
        sys.exit(1)
    passed += 1
    print("ok  ", msg)


def recv_packet(s):
    h = b""
    while len(h) < 4:
        c = s.recv(4 - len(h))
        if not c:
            return None
        h += c
    n = h[0] | h[1] << 8 | h[2] << 16
    body = b""
    while len(body) < n:
        c = s.recv(n - len(body))
        if not c:
            return None
        body += c
    return h[3], body


def closed(s, timeout=3):
    s.settimeout(timeout)
    try:
        data = s.recv(65536)
        while data and data[0:1] != b"":
            # drain any error packet, then expect EOF
            data = s.recv(65536)
        return True
    except (ConnectionResetError, BrokenPipeError):
        return True
    except socket.timeout:
        return False


def conn():
    s = socket.create_connection((HOST, PORT), timeout=5)
    seq, hs = recv_packet(s)
    return s, hs


# 1. handshake looks right
s, hs = conn()
check(hs[0] == 10 and b"caching_sha2_password" in hs and b"NovaDB" in hs, "handshake v10 with caching_sha2_password")
s.close()

# 2. oversized pre-auth packet is refused without reading it all
s, _ = conn()
s.sendall(struct.pack("<I", 200_000)[:3] + b"\x01" + b"A" * 1000)
check(closed(s), "pre-auth packet > 64 KiB closes the connection")

# 3. garbage instead of a handshake response
s, _ = conn()
s.sendall(b"\x05\x00\x00\x01hello")
r = recv_packet(s)
check(r is not None and r[1][0] == 0xFF and struct.unpack("<H", r[1][1:3])[0] == 3159, "non-TLS response gets ERROR 3159")
s.close()

# 4. slow client: handshake timeout (10 s)
s, _ = conn()
t0 = time.time()
check(closed(s, timeout=15) and time.time() - t0 < 14, f"silent client dropped after ~10 s ({time.time() - t0:.1f}s)")

# 5. connection flood from one IP: 33rd gets 1040
socks = []
for _ in range(32):
    socks.append(conn()[0])
s = socket.create_connection((HOST, PORT), timeout=5)
r = recv_packet(s)
check(r is not None and r[1][0] == 0xFF and struct.unpack("<H", r[1][1:3])[0] == 1040, "33rd connection from one IP gets ERROR 1040")
s.close()
for x in socks:
    x.close()
time.sleep(0.5)

# 6. auth brute force is rate-limited before hashing
ctx = ssl.create_default_context(cafile=CA)
ctx.check_hostname = False


def try_login(user, pw):
    s, _ = conn()
    caps = 0x200 | 0x800 | 0x8000 | 0x80000 | 0x200000
    s.sendall(struct.pack("<I", 32)[:3] + b"\x01" + struct.pack("<IIB", caps, 1 << 24, 46) + b"\0" * 23)
    t = ctx.wrap_socket(s, server_hostname="localhost")
    body = struct.pack("<IIB", caps, 1 << 24, 46) + b"\0" * 23 + user.encode() + b"\0" + b"\x00" + b"caching_sha2_password\0"
    t.sendall(struct.pack("<I", len(body))[:3] + b"\x02" + body)
    r = recv_packet(t)
    if r and r[1][:2] == b"\x01\x04":
        p = pw.encode() + b"\0"
        t.sendall(struct.pack("<I", len(p))[:3] + bytes([r[0] + 1]) + p)
        r = recv_packet(t)
    t.close()
    return struct.unpack("<H", r[1][1:3])[0] if r and r[1][0] == 0xFF else (0 if r else -1)


codes = [try_login("root", f"wrong-{i}") for i in range(25)]
check(codes[0] == 1045, "wrong password -> 1045")
check(1129 in codes, f"brute force hits the rate limit (codes seen: {sorted(set(codes))})")
print(f"\nALL {passed} CHECKS PASSED")

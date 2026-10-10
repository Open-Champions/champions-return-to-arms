#!/usr/bin/env python3
"""Talk to a running Champions Reborn server the way Return to Arms does, far enough to
prove the lobby protocol works: gateway lookup, key exchange, account creation, login and
the UDP discovery handshake.

  python3 server_smoke_test.py [host]        (default 127.0.0.1)

Creates one throwaway account named smoke_<random>. Needs the 'cryptography' package.
"""
import os, socket, struct, sys, time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEY = b"dlfk qs';r+t iqe4t9ueerjKDJ wdaj"   # the game's built-in symmetric key
RTA_VERSION = 6
GATEWAY_PORT, DISCOVERY_PORT = 40810, 10101


def aes(data, encrypt):
    data = data + b"\0" * (-len(data) % 16)
    c = Cipher(algorithms.AES(KEY), modes.ECB())
    op = c.encryptor() if encrypt else c.decryptor()
    return op.update(data) + op.finalize()


def enc_utf16(s):
    raw = s.encode("utf-16-le")
    blob = aes(raw, True)
    return struct.pack("<II", (len(blob) + 4) // 2, len(raw)) + blob


class Reader:
    def __init__(self, b):
        self.b, self.p = b, 0

    def u16(self):
        v, = struct.unpack_from("<H", self.b, self.p); self.p += 2; return v

    def u32(self):
        v, = struct.unpack_from("<I", self.b, self.p); self.p += 4; return v

    def utf8(self):
        n = self.u32(); v = self.b[self.p:self.p + n]; self.p += n; return v.decode()

    def enc_utf16(self):
        enc_len = self.u32() * 2 - 4
        dec_len = self.u32()
        blob = self.b[self.p:self.p + enc_len]; self.p += enc_len
        return aes(blob, False)[:dec_len].decode("utf-16-le")


def call(sock, packet_id, track, body=b""):
    payload = struct.pack("<HII", packet_id, track, RTA_VERSION) + body
    sock.sendall(struct.pack(">I", len(payload) + 4) + payload)
    head = sock.recv(4, socket.MSG_WAITALL)
    size, = struct.unpack(">I", head)
    r = Reader(sock.recv(size - 4, socket.MSG_WAITALL))
    assert r.u16() == packet_id and r.u32() == track, "reply does not match request"
    return r


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    user = "smoke_" + os.urandom(3).hex()
    password = "hunter22"

    with socket.create_connection((host, GATEWAY_PORT), timeout=5) as gw:
        r = call(gw, 0x43, 1)
        r.u32()
        lobby_ip, lobby_port = r.utf8(), r.u32()
    print(f"1 gateway  -> lobby is {lobby_ip}:{lobby_port}")

    with socket.create_connection((host, lobby_port), timeout=5) as lobby:
        r = call(lobby, 0x27, 2, struct.pack("<I", 4) + b"test" + struct.pack("<I", 0))
        r.u32()
        enc_len, key_len = r.u32() - 4, r.u32()
        key = aes(r.b[r.p:r.p + enc_len], False)[:key_len]
        assert key == KEY, "server key does not round-trip"
        print("2 key exchange ok (AES round-trip matches the game's key)")

        body = b"".join(enc_utf16(s) for s in (user, password, "smoke@example.invalid", "01/01/1990", user))
        r = call(lobby, 0x06, 3, body)
        reply, session = r.u32(), r.enc_utf16()
        assert reply == 0 and len(session) == 16, f"create account failed: reply={reply} session={session!r}"
        print(f"3 create account {user!r} ok, session id {session}")

    time.sleep(0.5)   # let the server drop the first connection so the login is not a duplicate

    with socket.create_connection((host, lobby_port), timeout=5) as lobby:
        r = call(lobby, 0x16, 4, enc_utf16(user) + enc_utf16(password))
        reply, session = r.u32(), r.enc_utf16()
        assert reply == 0 and len(session) == 16, f"login failed: reply={reply}"
        print(f"4 login ok, session id {session}")

        r = call(lobby, 0x16, 5, enc_utf16(user) + enc_utf16("wrong-password"))
        assert r.u32() != 0, "login with a wrong password was accepted"
        print("5 wrong password rejected")

        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.sendto(struct.pack("<I", 0x20) + aes(session.encode("utf-16-le"), True), (host, DISCOVERY_PORT))
        udp.sendto(b"\x20\x00\x00\x00junk", (host, DISCOVERY_PORT))   # short packet must be ignored
        udp.close()
        time.sleep(0.5)
        print("6 discovery packets sent (check the server log for 'Game session not found', not 'User not found')")

    print("PASS")


if __name__ == "__main__":
    main()

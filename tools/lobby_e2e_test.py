#!/usr/bin/env python3
"""End-to-end test of a Champions: Return to Arms lobby server (Champions Reborn or
compatible). Two simulated consoles, A and B, go from nothing to a launched game:

  gateway -> key exchange -> create account -> log in -> A creates a public game ->
  A's UDP discovery -> B lists games and picks A's -> B's UDP discovery -> each side is
  told the other's address -> B reports the join -> A starts the game -> log out

  python3 lobby_e2e_test.py [host] [--extended] [--verbose] [--follow-advertised]
                            [--gateway-port N]          (host defaults to 127.0.0.1)

Every step prints PASS or FAIL; the exit status is 0 only if nothing failed.

--extended adds the flows the short run does not need: rules/statistics, character
create/list/load/save/delete, friends, ignore, instant and room chat, cancelling a game,
backing out of a join, a private game found by name, a list holding two public games,
and checks that replies carry every field the game reads. Replies are parsed the way the
game's own client parses them (see docs/lobby-protocol.md), so a reply the server builds
differently from what the game expects is reported as a failure. Against Champions
Reborn as of October 2026 the short run passes and several extended steps fail; the
document lists the server defects behind each of them.

By default every connection goes to the host named on the command line and only the
port numbers are taken from the server's replies. --follow-advertised connects to the
addresses the server hands out instead, as a console would.

The accounts are throwaway: e2e_a_<random> and e2e_b_<random>. The "LAN address" each
client reports is an artificial label from 192.0.2.0/24 (a documentation-only range);
nothing ever connects to it. It is deliberately different from the address the server
observes so the test can tell which field of a reply carries which address.

Standard library only. Protocol notes are in docs/lobby-protocol.md.
"""
import argparse
import os
import select
import socket
import struct
import sys
import time

GAME_KEY = b"dlfk qs';r+t iqe4t9ueerjKDJ wdaj"   # symmetric key built into the game
RTA_VERSION = 6                                  # third header field sent by Return to Arms
RTA_GATEWAY_PORT = 40810
IO_TIMEOUT = 5.0


# ----------------------------------------------------------------------------------------
# AES-256 in ECB mode, written out because the standard library has none. Slow, tiny.
# ----------------------------------------------------------------------------------------
def _rotl8(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xFF


def _make_sbox():
    sbox = [0] * 256
    p = q = 1
    while True:
        p = (p ^ (p << 1) ^ (0x1B if p & 0x80 else 0)) & 0xFF      # p *= 3
        q ^= q << 1                                                 # q /= 3
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        sbox[p] = q ^ _rotl8(q, 1) ^ _rotl8(q, 2) ^ _rotl8(q, 3) ^ _rotl8(q, 4) ^ 0x63
        if p == 1:
            break
    sbox[0] = 0x63
    return sbox


_SBOX = _make_sbox()
_INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i


def _gmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = ((a << 1) ^ 0x11B) if a & 0x80 else (a << 1)
        b >>= 1
    return r & 0xFF


_MUL = {n: [_gmul(x, n) for x in range(256)] for n in (2, 3, 9, 11, 13, 14)}


class AES256:
    def __init__(self, key):
        assert len(key) == 32
        words = [list(key[i:i + 4]) for i in range(0, 32, 4)]
        rcon = 1
        for i in range(8, 60):
            t = list(words[i - 1])
            if i % 8 == 0:
                t = [_SBOX[b] for b in t[1:] + t[:1]]
                t[0] ^= rcon
                rcon = _gmul(rcon, 2)
            elif i % 8 == 4:
                t = [_SBOX[b] for b in t]
            words.append([a ^ b for a, b in zip(words[i - 8], t)])
        self.rk = [sum(words[r * 4:r * 4 + 4], []) for r in range(15)]

    def _enc_block(self, block):
        s = [b ^ k for b, k in zip(block, self.rk[0])]
        m2, m3 = _MUL[2], _MUL[3]
        for rnd in range(1, 15):
            s = [_SBOX[s[(i + 4 * (i % 4)) % 16]] for i in range(16)]     # SubBytes + ShiftRows
            if rnd != 14:
                t = []
                for c in range(0, 16, 4):
                    a, b, cc, d = s[c:c + 4]
                    t += [m2[a] ^ m3[b] ^ cc ^ d, a ^ m2[b] ^ m3[cc] ^ d,
                          a ^ b ^ m2[cc] ^ m3[d], m3[a] ^ b ^ cc ^ m2[d]]
                s = t
            s = [b ^ k for b, k in zip(s, self.rk[rnd])]
        return bytes(s)

    def _dec_block(self, block):
        s = [b ^ k for b, k in zip(block, self.rk[14])]
        m9, m11, m13, m14 = _MUL[9], _MUL[11], _MUL[13], _MUL[14]
        for rnd in range(13, -1, -1):
            s = [_INV_SBOX[s[(i - 4 * (i % 4)) % 16]] for i in range(16)]  # InvShiftRows + InvSubBytes
            s = [b ^ k for b, k in zip(s, self.rk[rnd])]
            if rnd != 0:
                t = []
                for c in range(0, 16, 4):
                    a, b, cc, d = s[c:c + 4]
                    t += [m14[a] ^ m11[b] ^ m13[cc] ^ m9[d], m9[a] ^ m14[b] ^ m11[cc] ^ m13[d],
                          m13[a] ^ m9[b] ^ m14[cc] ^ m11[d], m11[a] ^ m13[b] ^ m9[cc] ^ m14[d]]
                s = t
        return bytes(s)

    def encrypt(self, data):
        data = data + b"\0" * (-len(data) % 16)
        return b"".join(self._enc_block(data[i:i + 16]) for i in range(0, len(data), 16))

    def decrypt(self, data):
        data = data + b"\0" * (-len(data) % 16)
        return b"".join(self._dec_block(data[i:i + 16]) for i in range(0, len(data), 16))


def _aes_self_test():
    key = bytes(range(32))                                       # FIPS-197 appendix C.3
    plain = bytes.fromhex("00112233445566778899aabbccddeeff")
    cipher = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
    a = AES256(key)
    assert a.encrypt(plain) == cipher and a.decrypt(cipher) == plain, "AES self-test failed"


_aes_self_test()
CRYPT = AES256(GAME_KEY)


# ----------------------------------------------------------------------------------------
# Wire types
# ----------------------------------------------------------------------------------------
def u8(v):
    return struct.pack("<B", v & 0xFF)


def u16(v):
    return struct.pack("<H", v & 0xFFFF)


def u32(v):
    return struct.pack("<I", v & 0xFFFFFFFF)


def wstr(s):
    """Plain wide string: u32 count of UTF-16 code units, then the units (little endian)."""
    raw = s.encode("utf-16-le")
    return u32(len(raw) // 2) + raw


def nstr(s):
    """Plain narrow string: u32 byte count, then the bytes."""
    raw = s.encode("utf-8")
    return u32(len(raw)) + raw


def blob(b):
    return u32(len(b)) + b


def enc_wstr(s):
    """Encrypted wide string: u32 (cipher bytes + 4) / 2, u32 plain byte count, cipher bytes."""
    raw = s.encode("utf-16-le")
    cipher = CRYPT.encrypt(raw)
    return u32((len(cipher) + 4) // 2) + u32(len(raw)) + cipher


class Failed(Exception):
    """A check did not hold. The message is what gets printed after FAIL."""


def short_hex(data, limit=48):
    return data[:limit].hex() + (f"... ({len(data)} bytes)" if len(data) > limit else "")


class Reader:
    def __init__(self, data):
        self.b, self.p = data, 0

    def _take(self, n, what):
        if n < 0 or self.p + n > len(self.b):
            raise Failed(f"reply too short reading {what}: need {n} bytes at offset {self.p} "
                         f"of {len(self.b)}  [{short_hex(self.b)}]")
        v = self.b[self.p:self.p + n]
        self.p += n
        return v

    def left(self):
        return len(self.b) - self.p

    def u8(self):
        return self._take(1, "u8")[0]

    def u16(self):
        return struct.unpack("<H", self._take(2, "u16"))[0]

    def u32(self):
        return struct.unpack("<I", self._take(4, "u32"))[0]

    def wstr(self, max_units=None):
        n = self.u32()
        if max_units is not None and n > max_units:
            raise Failed(f"wide string of {n} units where the game accepts at most {max_units}")
        return self._take(n * 2, "wide string").decode("utf-16-le", "replace")

    def nstr(self, max_bytes=None):
        n = self.u32()
        if max_bytes is not None and n > max_bytes:
            raise Failed(f"narrow string of {n} bytes where the game accepts at most {max_bytes}")
        return self._take(n, "narrow string").decode("utf-8", "replace")

    def blob(self):
        return self._take(self.u32(), "blob")

    def enc_wstr(self):
        cipher_len = self.u32() * 2 - 4
        plain_len = self.u32()
        cipher = self._take(cipher_len, "encrypted string")
        return CRYPT.decrypt(cipher)[:plain_len].decode("utf-16-le", "replace")

    def array(self, item):
        return [item() for _ in range(self._count())]

    def _count(self):
        n = self.u32()
        if n > 4096:
            raise Failed(f"implausible element count {n} at offset {self.p - 4}")
        return n


# ----------------------------------------------------------------------------------------
# One simulated console
# ----------------------------------------------------------------------------------------
class Console:
    def __init__(self, tag, host, verbose=False, follow=False):
        self.tag, self.host, self.verbose, self.follow = tag, host, verbose, follow
        self.tcp = None
        self.track = 0
        self.notes = []                       # notifications not yet consumed: (id, payload)
        self.rx = b""
        self.session = ""
        self.user = self.password = self.handle = ""
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("", 0))                # the one socket a console uses for peer traffic
        self.udp_port = self.udp.getsockname()[1]
        self.lan_addr = ""                    # what this console says its own address is
        self.lan_port = 0
        self.seen_addr = ("", 0)              # what the server says it observed

    def log(self, text):
        if self.verbose:
            print(f"      [{self.tag}] {text}")

    # -- TCP ------------------------------------------------------------------------------
    def connect(self, addr, port):
        self.close()
        target = addr if self.follow else self.host
        self.tcp = socket.create_connection((target, port), timeout=IO_TIMEOUT)
        self.tcp.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.rx = b""
        self.notes = []
        self.log(f"connected to {target}:{port}")

    def close(self):
        if self.tcp is not None:
            try:
                self.tcp.close()
            except OSError:
                pass
            self.tcp = None

    def _frame(self, deadline):
        """Next length-prefixed frame from the stream, or None when the deadline passes."""
        while True:
            if len(self.rx) >= 4:
                size = struct.unpack(">I", self.rx[:4])[0]
                if size < 10 or size > 0x20000:
                    raise Failed(f"{self.tag}: bad frame length {size}")
                if len(self.rx) >= size:
                    frame, self.rx = self.rx[4:size], self.rx[size:]
                    return frame
            wait = deadline - time.monotonic()
            if wait <= 0:
                return None
            ready, _, _ = select.select([self.tcp], [], [], wait)
            if not ready:
                return None
            chunk = self.tcp.recv(65536)
            if not chunk:
                raise Failed(f"{self.tag}: server closed the connection")
            self.rx += chunk

    def send(self, packet_id, body=b"", track=None):
        if track is None:
            self.track += 1
            track = self.track
        payload = u16(packet_id) + u32(track) + u32(RTA_VERSION) + body
        self.tcp.sendall(struct.pack(">I", len(payload) + 4) + payload)
        self.log(f"-> {packet_id:#04x} track {track} body {body.hex()}")
        return track

    def reply(self, packet_id, track, timeout=IO_TIMEOUT):
        """Wait for the reply to (packet_id, track). Anything else is kept as a notification."""
        deadline = time.monotonic() + timeout
        while True:
            frame = self._frame(deadline)
            if frame is None:
                raise Failed(f"{self.tag}: no reply to message {packet_id:#04x} within {timeout:.0f}s")
            pid, trk = struct.unpack_from("<HI", frame, 0)
            self.log(f"<- {pid:#04x} track {trk} body {frame[6:].hex()}")
            if pid == packet_id and trk == track:
                r = Reader(frame[6:])
                return r.u32(), r
            self.notes.append((pid, frame[6:]))

    def call(self, packet_id, body=b"", track=None):
        """Send a request and return (reply code, Reader placed after the code)."""
        track = self.send(packet_id, body, track)
        return self.reply(packet_id, track)

    def notification(self, packet_id, timeout=2.0):
        """Take the oldest pending notification with this id, waiting for one if needed."""
        deadline = time.monotonic() + timeout
        while True:
            for i, (pid, payload) in enumerate(self.notes):
                if pid == packet_id:
                    del self.notes[i]
                    return Reader(payload)
            frame = self._frame(deadline)
            if frame is None:
                return None
            pid, trk = struct.unpack_from("<HI", frame, 0)
            self.log(f"<- {pid:#04x} track {trk} body {frame[6:].hex()}")
            self.notes.append((pid, frame[6:]))

    def drop_notifications(self, packet_id):
        self.notes = [n for n in self.notes if n[0] != packet_id]

    # -- UDP ------------------------------------------------------------------------------
    def discovery_packet(self):
        """What a console sends to the discovery port: u32 0x20, then its session id (16 UTF-16
        units = 32 bytes) AES-encrypted. It goes out from the peer-traffic socket."""
        return u32(0x20) + CRYPT.encrypt(self.session.encode("utf-16-le"))

    def discover(self, addr, port, notify_id):
        """Send discovery packets until the server answers on TCP with `notify_id`."""
        target = (addr if self.follow else self.host, port)
        for _ in range(6):
            self.udp.sendto(self.discovery_packet(), target)
            r = self.notification(notify_id, timeout=0.6)
            if r is not None:
                return r
        raise Failed(f"{self.tag}: sent 6 discovery packets to {target[0]}:{target[1]} but the server "
                     f"never sent notification {notify_id:#04x}")


# ----------------------------------------------------------------------------------------
# Flow pieces
# ----------------------------------------------------------------------------------------
def expect(cond, message):
    if not cond:
        raise Failed(message)


def gateway(c, port):
    c.connect(c.host, port)
    code, r = c.call(0x43, u32(12))            # the game appends a u32 12; the server ignores it
    expect(code == 0, f"gateway reply code {code}")
    addr, lobby_port = r.nstr(0x200), r.u32()
    c.close()
    expect(0 < lobby_port < 65536, f"gateway returned port {lobby_port}")
    c.lobby = (addr, lobby_port)
    return f"lobby advertised as {addr}:{lobby_port}"


def key_exchange(c):
    code, r = c.call(0x27, nstr("e2e-test") + u32(12))
    expect(code == 0, f"key exchange reply code {code}")
    cipher_len, key_len = r.u32() - 4, r.u32()
    key = CRYPT.decrypt(r._take(cipher_len, "key"))[:key_len]
    expect(key == GAME_KEY, "the key the server returned is not the game's built-in key; this "
                            "test (like the server) only supports the built-in key")


def create_account(c):
    c.connect(*c.lobby)
    key_exchange(c)
    body = b"".join(enc_wstr(s) for s in
                    (c.user, c.password, f"{c.user}@example.invalid", "01/01/1990", c.handle))
    code, r = c.call(0x06, body)
    session = r.enc_wstr()
    expect(code == 0, f"create account reply code {code}")
    expect(len(session) == 16, f"session id {session!r} is not 16 characters")
    c.close()
    return f"account {c.user!r}, chat handle {c.handle!r}"


def login(c):
    c.connect(*c.lobby)
    key_exchange(c)
    code, r = c.call(0x16, enc_wstr(c.user) + enc_wstr(c.password + "-wrong"))
    expect(code != 0, "a wrong password was accepted")
    wrong = code
    # The account-creation connection is still being torn down for a moment; until then the
    # server answers 1 (already logged in).
    deadline = time.monotonic() + 4
    while True:
        code, r = c.call(0x16, enc_wstr(c.user) + enc_wstr(c.password))
        if code != 1 or time.monotonic() > deadline:
            break
        time.sleep(0.2)
    expect(code == 0, f"login reply code {code}")
    c.session = r.enc_wstr()
    c.login_handle = r.enc_wstr()
    expect(len(c.session) == 16, f"session id {c.session!r} is not 16 characters")
    c.lan_addr = f"192.0.2.{1 if c.tag == 'A' else 2}"
    c.lan_port = 40001 if c.tag == "A" else 40002
    if c.lan_port == c.udp_port:
        c.lan_port += 10
    return f"session {c.session}; wrong password refused with code {wrong}"


def create_game_room(c, name):
    """Right after a create-game reply the game opens a chat room named after the game."""
    code, r = c.call(0x09, enc_wstr(c.session) + wstr(name))
    expect(code == 0, f"create game chat room reply code {code}")
    c.room_reply = r.b[r.p:]


def create_public_game(c, name, numbers=(1, 0, 0, 0, 0)):
    """Message 0x54 with the fields in the order the game writes them."""
    info = ",".join(f"{n:02d}" for n in numbers) + "|" + name
    body = (enc_wstr(c.session) + u16(1) + u32(0) + u32(50) + u32(10) + wstr(info)
            + u32(0)                     # attribute list: zero entries
            + blob(b"")                  # opaque game data: empty
            + wstr(c.lan_addr) + u32(c.lan_port)
            + wstr("") + u32(0))         # second address pair; the game sends it empty
    code, r = c.call(0x54, body)
    expect(code == 0, f"create public game reply code {code}")
    c.discovery = (r.nstr(0x200), r.u32())
    c.game_info, c.game_name = info, name
    create_game_room(c, name)
    return f"game {info!r}; discovery service advertised as {c.discovery[0]}:{c.discovery[1]}"


def create_private_game(c, name):
    body = (enc_wstr(c.session) + wstr(name) + wstr(c.lan_addr) + u32(c.lan_port)
            + wstr("") + u32(0))
    code, r = c.call(0x56, body)
    expect(code == 0, f"create private game reply code {code}")
    c.discovery = (r.nstr(0x200), r.u32())
    c.game_name = name
    create_game_room(c, name)
    return f"private game {name!r}; discovery at {c.discovery[0]}:{c.discovery[1]}"


def host_discovery(c, loopback):
    r = c.discover(c.discovery[0], c.discovery[1], 0x3E)
    c.seen_addr = (r.nstr(0x200), r.u32())
    if loopback:
        expect(c.seen_addr == ("127.0.0.1", c.udp_port),
               f"server reports {c.seen_addr[0]}:{c.seen_addr[1]} but the packet left from "
               f"127.0.0.1:{c.udp_port}")
    return f"server observed {c.tag} at {c.seen_addr[0]}:{c.seen_addr[1]} (UDP source of the packet)"


def parse_game_list(r, game_layout=True):
    """Reply to 0x55. Eight parallel arrays, each with its own count. With game_layout the
    fourth array is read as the game reads it: a counted list of length-prefixed blobs."""
    games = {
        "info": r.array(lambda: r.wstr(0x100)),
        "short": r.array(lambda: r.wstr(0x0F)),
        "id": r.array(r.u32),
    }
    if game_layout:
        games["blob"] = r.array(r.blob)
    else:                                   # what this server writes: count, then one u32
        n = r._count()
        r.u32()
        games["blob"] = [b""] * n
    games["lan_addr"] = r.array(lambda: r.wstr(0x200))
    games["lan_port"] = r.array(r.u32)
    games["ext_addr"] = r.array(lambda: r.wstr(0x200))
    games["ext_port"] = r.array(r.u32)
    counts = {k: len(v) for k, v in games.items()}
    if len(set(counts.values())) != 1:
        raise Failed(f"the eight arrays have different lengths: {counts}")
    return [dict(zip(games, row)) for row in zip(*games.values())]


def list_games(c):
    # The game sends its session id and a search filter; this server reads only the header.
    body = enc_wstr(c.session) + u16(1) + u32(0) + u32(50) + u32(10) + u32(0) + u8(0) + u32(0) + u32(0)
    track = c.send(0x55, body)
    code, r = c.reply(0x55, track)
    expect(code == 0, f"game list reply code {code}")
    raw = r.b[r.p:]
    try:
        return parse_game_list(Reader(raw), True), None
    except Failed as e:
        try:
            games = parse_game_list(Reader(raw), False)
        except Failed:
            raise e
        return games, str(e)


def find_game(joiner, host):
    games, problem = list_games(joiner)
    expect(problem is None, f"the list does not parse the way the game reads it: {problem}")
    mine = [g for g in games if g["info"] == host.game_info]
    expect(len(mine) == 1, f"{host.game_info!r} is not in the list of {len(games)} game(s)")
    g = mine[0]
    expect(g["ext_addr"] == host.seen_addr[0] and g["ext_port"] == host.seen_addr[1],
           f"external address in the list is {g['ext_addr']}:{g['ext_port']}, but the server "
           f"observed the host at {host.seen_addr[0]}:{host.seen_addr[1]}")
    expect(g["lan_addr"] == host.lan_addr and g["lan_port"] == host.lan_port,
           f"internal address in the list is {g['lan_addr']}:{g['lan_port']}, but the host "
           f"reported {host.lan_addr}:{host.lan_port}")
    joiner.target = g
    return (f"game id {g['id']}; {joiner.tag} is told {host.tag} is at {g['ext_addr']}:{g['ext_port']} "
            f"(external) and {g['lan_addr']}:{g['lan_port']} (internal)")


def ask_to_join(c, game_id):
    body = enc_wstr(c.session) + u32(game_id) + wstr(c.lan_addr) + u32(c.lan_port)
    code, r = c.call(0x66, body)
    expect(code == 0, f"join request reply code {code}")
    c.discovery = (r.nstr(0x200), r.u32())
    return f"discovery service advertised as {c.discovery[0]}:{c.discovery[1]}"


def joiner_discovery(joiner, host, loopback):
    host.drop_notifications(0x65)
    r = joiner.discover(joiner.discovery[0], joiner.discovery[1], 0x40)
    joiner.seen_addr = (r.nstr(0x200), r.u32())
    if loopback:
        expect(joiner.seen_addr == ("127.0.0.1", joiner.udp_port),
               f"server reports {joiner.seen_addr[0]}:{joiner.seen_addr[1]} but the packet left "
               f"from 127.0.0.1:{joiner.udp_port}")
    n = host.notification(0x65, timeout=3)
    expect(n is not None, f"{host.tag} never received notification 0x65 about the joining player")
    # The game reads the first pair as the joiner's internal address, the second as external.
    lan = (n.nstr(0x200), n.u32())
    ext = (n.nstr(0x200), n.u32())
    expect(ext == joiner.seen_addr,
           f"second (external) pair in 0x65 is {ext[0]}:{ext[1]}, but the server observed "
           f"{joiner.tag} at {joiner.seen_addr[0]}:{joiner.seen_addr[1]}")
    expect(lan == (joiner.lan_addr, joiner.lan_port),
           f"first (internal) pair in 0x65 is {lan[0]}:{lan[1]}, but {joiner.tag} reported "
           f"{joiner.lan_addr}:{joiner.lan_port}")
    host.peer = ext
    return (f"{joiner.tag} is told its own address {joiner.seen_addr[0]}:{joiner.seen_addr[1]}; "
            f"{host.tag} is told {joiner.tag} is at {ext[0]}:{ext[1]} (external) and "
            f"{lan[0]}:{lan[1]} (internal)")


def peer_probe(a, b):
    """Send one datagram each way between the peer sockets, using only the addresses the
    server handed out. Meaningful when both consoles are on this machine."""
    a_target = (b.seen_addr[0], b.seen_addr[1])          # what A was told about B
    b_target = (a.seen_addr[0], a.seen_addr[1])          # what B was told about A
    a.udp.sendto(b"e2e A->B", a_target)
    b.udp.sendto(b"e2e B->A", b_target)
    got = {}
    for c, want in ((b, b"e2e A->B"), (a, b"e2e B->A")):
        ready, _, _ = select.select([c.udp], [], [], 2.0)
        expect(bool(ready), f"{c.tag} received nothing on its peer socket")
        data, src = c.udp.recvfrom(2048)
        expect(data == want, f"{c.tag} received unexpected datagram {data!r}")
        got[c.tag] = src
    expect(got["B"] == (a.seen_addr[0], a.seen_addr[1]) and got["A"] == (b.seen_addr[0], b.seen_addr[1]),
           f"datagrams arrived from {got}, not from the addresses the server reported")
    return "a datagram crossed in each direction between the reported addresses"


def join_success(joiner, host):
    code, _ = joiner.call(0x5F, enc_wstr(joiner.session) + enc_wstr(host.session))
    expect(code == 0, f"join report reply code {code}")
    return "server added B to the game"


def start_game(host, other):
    # session id, then an empty set of start parameters, as the game sends them
    body = enc_wstr(host.session) + u8(0) + u16(0) + u32(0) + u32(0) + u32(0)
    code, r = host.call(0x23, body)
    expect(code == 0, f"start game reply code {code}")
    host.start_reply_left = r.left()
    games, _ = list_games(other)
    expect(all(g["info"] != host.game_info for g in games), "the started game is still listed")
    return "reply 0; the game is no longer listed"


def cancel_game(c):
    c.call(0x05, enc_wstr(c.session))          # the game sends both ids; RTA is served by 0x60
    code, _ = c.call(0x60, enc_wstr(c.session))
    expect(code == 0, f"cancel reply code {code}")


def logout(c):
    code, _ = c.call(0x17, enc_wstr(c.session))
    expect(code == 0, f"logout reply code {code}")
    c.close()


# ----------------------------------------------------------------------------------------
# Extended checks
# ----------------------------------------------------------------------------------------
def ext_login_handle(a, b):
    """The game copies the second string of the login reply into the field where it keeps
    its own chat handle (the same field account creation fills from what the user typed)."""
    bad = [f"{c.tag} got {c.login_handle.split(chr(0))[0]!r} (raw {short_hex(c.login_handle.encode('utf-16-le'), 12)}), "
           f"handle is {c.handle!r}" for c in (a, b) if c.login_handle != c.handle]
    expect(not bad, "; ".join(bad))
    return "both logins returned the account's chat handle"


def ext_misc(a, b):
    code, r = a.call(0x42, nstr("en") + nstr(""))     # two narrow strings, as the game sends
    rules = r.wstr()
    expect(code == 0 and rules, "no rules text")
    code, r = a.call(0x0F)
    counts = [r.u32() for _ in range(8)]
    expect(code == 0 and counts[0] >= 2, f"statistics report {counts[0]} users with two logged in")
    code, _ = a.call(0x24, enc_wstr(a.session))
    expect(code == 0, f"touch session reply code {code}")
    return f"rules text of {len(rules)} characters; statistics {counts}; touch session ok"


def ext_reply_shapes(a, b):
    """Three replies where the game's parser reads more than a reply code. When the extra
    field is missing the game treats the request as failed (its result code 45)."""
    problems = []
    try:
        r = Reader(a.room_reply)
        r.wstr(500), r.wstr(1000), r.array(lambda: r.wstr(15)), r.array(lambda: r.wstr(15))
    except Failed:
        problems.append("0x09 (create game chat room): no room name, text, member list and "
                        "moderator list after the reply code")
    if a.start_reply_left < 4:
        problems.append("0x23 (start game): no u32 after the reply code")
    if getattr(a, "create_reply_left", 0) < 4:
        problems.append("0x58 (create character): no u32 (new character id) after the reply code; "
                        "the game shows a network save error")
    expect(not problems, "; ".join(problems))
    return "0x09, 0x23 and 0x58 replies are complete"


def ext_room_banner(a, b, loopback, suffix):
    """After its game chat room exists the game sends message 0x19 (session id, room name,
    a line of text for the room) and waits for the reply."""
    create_public_game(a, f"e2e banner {suffix}")
    try:
        track = a.send(0x19, enc_wstr(a.session) + wstr(a.game_name)
                       + wstr("This room belongs to an automated test."))
        try:
            code, _ = a.reply(0x19, track, timeout=2.0)
        except Failed:
            raise Failed("the server does not answer message 0x19 (the game would wait out its "
                         "30 second timeout)")
        expect(code == 0, f"reply code {code}")
        return "answered"
    finally:
        try:
            cancel_game(a)
        except (Failed, OSError):
            pass


def character_meta(level):
    keys = ["name", "raceandclass", "level", "ability"]
    values = ["E2E Dummy", "0 0", str(level), "0 0 0 0 0 0"]
    return keys, values, (u32(len(keys)) + b"".join(wstr(k) for k in keys)
                          + u32(len(values)) + b"".join(wstr(v) for v in values))


def character_blob(seed):
    """Not a real character: four header bytes and a zero-run stream that expands past the
    19,504 bytes the server insists on before it stores anything."""
    return bytes([seed, 0xE2, 0xE0, 0x01]) + b"\x00\xff" * 77


def list_characters(c):
    code, r = c.call(0x5B, enc_wstr(c.session) + u32(0))
    expect(code == 0, f"character list reply code {code}")
    out = []
    for _ in range(r._count()):
        cid = r.u32()
        out.append((cid, [(r.wstr(), r.wstr()) for _ in range(r._count())]))
    return out


def upload(c, packet_id, head, data):
    """First piece inside the create/save request, the rest in 0x5D messages that reuse the
    request's tracking number, the last one flagged."""
    first, rest = data[:100], data[100:]
    track = c.send(packet_id, head + blob(first) + u32(0))
    code, r = c.reply(packet_id, track)
    expect(code == 0, f"message {packet_id:#04x} reply code {code}")
    if packet_id == 0x58:
        c.create_reply_left = r.left()
    c.send(0x5D, enc_wstr(c.session) + blob(rest) + u32(1), track=track)
    code, _ = c.reply(0x5D, track)
    expect(code == 0, f"append reply code {code}")


def load_character(c, cid):
    track = c.send(0x5C, enc_wstr(c.session) + u32(cid))
    data = b""
    for _ in range(64):
        code, r = c.reply(0x5C, track)
        expect(code == 0, f"character data reply code {code}")
        data += r.blob()
        if r.u32():
            return data
    raise Failed("character data never ended")


def ext_characters(a, b):
    expect(list_characters(a) == [], "a new account already has characters")
    keys, values, meta = character_meta(1)
    data = character_blob(0x11)
    upload(a, 0x58, enc_wstr(a.session) + u32(0) + u32(0) + meta, data)
    chars = list_characters(a)
    expect(len(chars) == 1, f"{len(chars)} characters listed after creating one")
    cid, pairs = chars[0]
    expect(pairs == list(zip(keys, values)), f"list returned {pairs}")
    got = load_character(a, cid)
    expect(len(got) % 1024 == 0 and got[:len(data)] == data and not any(got[len(data):]),
           "loaded character data differs from what was stored")
    keys, values, meta = character_meta(2)
    data2 = character_blob(0x22)
    upload(a, 0x5E, enc_wstr(a.session) + enc_wstr(a.session) + u32(cid) + u32(0) + u32(0) + meta, data2)
    expect(load_character(a, cid)[:len(data2)] == data2, "saved character data did not replace the old data")
    expect(list_characters(a)[0][1][2] == ("level", "2"), "saved summary did not replace the old summary")
    code, _ = a.call(0x5A, enc_wstr(a.session) + u32(cid))
    expect(code == 0, f"delete reply code {code}")
    expect(list_characters(a) == [], "character still listed after delete")
    return f"create, list, load ({len(got)} bytes in 1024-byte pieces), save, delete all round-trip (id {cid})"


def ext_social(a, b):
    # friends
    code, _ = b.call(0x01, enc_wstr(b.session) + wstr(a.handle))
    expect(code == 0, f"add friend reply code {code}")
    code, _ = b.call(0x01, enc_wstr(b.session) + wstr(a.handle))
    expect(code == 21, f"adding the same friend twice gave {code}, expected 21")
    code, r = b.call(0x61, enc_wstr(b.session))
    friends, middle, ignores = r.array(r.wstr), r.array(r.wstr), r.array(r.wstr)
    expect(code == 0 and friends == [a.handle] and ignores == [], f"initial lists: {friends} {middle} {ignores}")
    code, r = b.call(0x62, enc_wstr(b.session))
    expect(code == 0 and r.array(r.wstr) == [a.handle] and r.array(r.wstr) == [], "list update differs")
    # instant message
    code, _ = b.call(0x21, enc_wstr(b.session) + wstr(a.handle) + wstr("hello from B"))
    expect(code == 0, f"instant message reply code {code}")
    n = a.notification(0x30)
    expect(n is not None and (n.wstr(), n.wstr()) == (b.handle, "hello from B"), "A did not get the instant message")
    # ignore
    code, _ = a.call(0x02, enc_wstr(a.session) + wstr(b.handle))
    expect(code == 0, f"add ignore reply code {code}")
    code, _ = b.call(0x21, enc_wstr(b.session) + wstr(a.handle) + wstr("ignored?"))
    expect(code == 19, f"message to someone ignoring the sender gave {code}, expected 19")
    code, _ = a.call(0x1D, enc_wstr(a.session) + wstr(b.handle))
    expect(code == 0, f"remove ignore reply code {code}")
    # public chat room
    code, r = a.call(0x0E, enc_wstr(a.session))
    rooms = r.array(r.wstr)
    expect(code == 0 and rooms, "no public rooms")
    room = rooms[0]
    for c in (a, b):
        code, r = c.call(0x0C, enc_wstr(c.session) + wstr(room))
        expect(code == 0, f"enter room reply code {code}")
        name, banner, members, mods = r.wstr(), r.wstr(), r.array(r.wstr), r.array(r.wstr)
        expect(name == room and c.handle in members, f"room reply {name!r} {members}")
    code, _ = a.call(0x22, enc_wstr(a.session) + wstr(room) + wstr("hello room"))
    expect(code == 0, f"room message reply code {code}")
    for c in (a, b):
        n = c.notification(0x3D)
        expect(n is not None and (n.wstr(), n.wstr(), n.wstr()) == (room, a.handle, "hello room"),
               f"{c.tag} did not get the room message")
    for c in (a, b):
        code, _ = c.call(0x15, enc_wstr(c.session) + wstr(room))
        expect(code == 0, f"leave room reply code {code}")
    code, _ = b.call(0x1C, enc_wstr(b.session) + wstr(a.handle))
    expect(code == 0, f"remove friend reply code {code}")
    return (f"friend add/list/remove, instant message, ignore, and room {room!r} "
            f"(of {len(rooms)}) enter/talk/leave; middle list in 0x61 was {middle}")


def ext_cancel(a, b, loopback, suffix):
    create_public_game(a, f"e2e cancel {suffix}")
    host_discovery(a, loopback)
    games, _ = list_games(b)
    expect(any(g["info"] == a.game_info for g in games), "game not listed before cancel")
    cancel_game(a)
    games, _ = list_games(b)
    expect(all(g["info"] != a.game_info for g in games), "game still listed after cancel")
    return "an open game disappears from the list when its host cancels"


def ext_back_out(a, b, loopback, suffix):
    """B asks to join, then leaves before the peer handshake (the game sends its two cancel
    messages whenever it leaves a game). The host's game must stay listed."""
    create_public_game(a, f"e2e backout {suffix}")
    host_discovery(a, loopback)
    try:
        find_game(b, a)
        ask_to_join(b, b.target["id"])
        cancel_game(b)
        games, _ = list_games(b)
        expect(any(g["info"] == a.game_info for g in games),
               "the host's game vanished from the list when a player who had only asked to join cancelled")
        return "the host's game is still listed"
    finally:
        try:
            cancel_game(a)
        except (Failed, OSError):
            pass


def ext_private(a, b, loopback, suffix):
    name = f"e2e private {suffix}"
    create_private_game(a, name)
    host_discovery(a, loopback)
    try:
        games, _ = list_games(b)
        expect(all(name not in g["info"] for g in games), "a private game shows in the public list")
        code, r = b.call(0x57, enc_wstr(b.session) + wstr(name))
        expect(code == 0, f"find game by name reply code {code}")
        text, game_id = r.wstr(0x0F), r.u32()
        first = (r.wstr(0x200), r.u32())
        second = (r.wstr(0x200), r.u32())
        ask_to_join(b, game_id)
        joiner_discovery(b, a, loopback)
        # The game stores the first pair as the host's internal address and the second as
        # its external one (see docs/lobby-protocol.md, "Whose address is which").
        problems = []
        if second != a.seen_addr:
            problems.append(f"second pair (read by the game as external) is {second[0]}:{second[1]}, "
                            f"the server observed the host at {a.seen_addr[0]}:{a.seen_addr[1]}")
        if first != (a.lan_addr, a.lan_port):
            problems.append(f"first pair (read by the game as internal) is {first[0]}:{first[1]}, "
                            f"the host reported {a.lan_addr}:{a.lan_port}")
        expect(not problems, "; ".join(problems))
        return f"game id {game_id}, label {text!r}, internal {first}, external {second}"
    finally:
        try:
            cancel_game(a)
        except (Failed, OSError):
            pass


def ext_two_games(a, b, loopback, suffix):
    create_public_game(a, f"e2e first {suffix}")
    host_discovery(a, loopback)
    create_public_game(b, f"e2e second {suffix}")
    host_discovery(b, loopback)
    try:
        games, problem = list_games(a)
        expect(len(games) >= 2, f"{len(games)} games listed with two open")
        expect(problem is None,
               f"with {len(games)} games open the reply cannot be read the way the game reads it "
               f"({problem}); it only parses with the fourth array shortened to a single u32")
        return f"{len(games)} games listed and parsed"
    finally:
        for c in (a, b):
            try:
                cancel_game(c)
            except (Failed, OSError):
                pass


# ----------------------------------------------------------------------------------------
# Runner
# ----------------------------------------------------------------------------------------
class Runner:
    def __init__(self):
        self.n = 0
        self.failed = []

    def step(self, title, fn, *args):
        self.n += 1
        try:
            detail = fn(*args)
        except Failed as e:
            self._fail(title, str(e))
            return False
        except (OSError, struct.error, UnicodeError) as e:
            self._fail(title, f"{type(e).__name__}: {e}")
            return False
        print(f"PASS {self.n:2d}  {title}" + (f"\n         {detail}" if detail else ""))
        return True

    def _fail(self, title, why):
        self.failed.append(title)
        print(f"FAIL {self.n:2d}  {title}\n         {why}")

    def skip(self, title, why):
        self.n += 1
        print(f"SKIP {self.n:2d}  {title}\n         {why}")


def main():
    ap = argparse.ArgumentParser(description="Two-console end-to-end test of an RTA lobby server.")
    ap.add_argument("host", nargs="?", default="127.0.0.1")
    ap.add_argument("--gateway-port", type=int, default=RTA_GATEWAY_PORT)
    ap.add_argument("--extended", action="store_true", help="also run the optional flows")
    ap.add_argument("--follow-advertised", action="store_true",
                    help="connect to the addresses the server hands out instead of to HOST")
    ap.add_argument("--verbose", action="store_true", help="print every message")
    args = ap.parse_args()

    try:
        host_ip = socket.gethostbyname(args.host)
    except OSError as e:
        print(f"FAIL  cannot resolve {args.host}: {e}")
        return 1
    loopback = host_ip.startswith("127.") and not args.follow_advertised
    suffix = os.urandom(3).hex()
    a = Console("A", args.host, args.verbose, args.follow_advertised)
    b = Console("B", args.host, args.verbose, args.follow_advertised)
    for c in (a, b):
        c.user = f"e2e_{c.tag.lower()}_{suffix}"
        c.handle = f"e2e{c.tag}{suffix}"
        c.password = "e2e-" + os.urandom(4).hex()
    print(f"server {args.host} (gateway port {args.gateway_port}); accounts {a.user} and {b.user}")

    run = Runner()
    core = [
        ("A: gateway hands out the lobby address", gateway, a, args.gateway_port),
        ("B: gateway hands out the lobby address", gateway, b, args.gateway_port),
        ("A: key exchange and account creation", create_account, a),
        ("B: key exchange and account creation", create_account, b),
        ("A: log in (and a wrong password is refused)", login, a),
        ("B: log in (and a wrong password is refused)", login, b),
        ("A: create a public game", create_public_game, a, f"e2e game {suffix}"),
        ("A: discovery exchange opens the game", host_discovery, a, loopback),
        ("B: find the game; B is told A's address", find_game, b, a),
        ("B: ask to join", lambda: ask_to_join(b, b.target["id"])),
        ("B: discovery exchange; A is told B's address", joiner_discovery, b, a, loopback),
    ]
    ok = True
    for title, fn, *fargs in core:
        ok = run.step(title, fn, *fargs)
        if not ok:
            break
    if ok:
        if loopback:
            ok = run.step("peer sockets reach each other on the reported addresses", peer_probe, a, b)
        else:
            run.skip("peer sockets reach each other on the reported addresses",
                     "only checked when the server is on this machine")
    if ok:
        ok = (run.step("B: report the successful join", join_success, b, a)
              and run.step("A: start the game", start_game, a, b))

    if ok and args.extended:
        print("-- extended --")
        run.step("rules text, statistics, session touch", ext_misc, a, b)
        run.step("login reply carries the account's chat handle", ext_login_handle, a, b)
        run.step("characters: create, list, load, save, delete", ext_characters, a, b)
        run.step("replies 0x09, 0x23 and 0x58 carry every field the game reads", ext_reply_shapes, a, b)
        run.step("friends, ignore, instant message, chat room", ext_social, a, b)
        run.step("cancel an open game", ext_cancel, a, b, loopback, suffix)
        run.step("a player who asks to join and then backs out leaves the host's game alone",
                 ext_back_out, a, b, loopback, suffix)
        run.step("private game found by name; address pairs in the order the game reads them",
                 ext_private, a, b, loopback, suffix)
        run.step("two public games open at once; list parsed as the game parses it",
                 ext_two_games, a, b, loopback, suffix)
        run.step("message 0x19 (text for the game's chat room) is answered",
                 ext_room_banner, a, b, loopback, suffix)

    if ok:
        run.step("B: log out", logout, b)
        run.step("A: log out", logout, a)
    for c in (a, b):
        c.close()
        c.udp.close()

    if run.failed:
        print(f"\nRESULT: FAIL ({len(run.failed)} of {run.n} steps failed: " + "; ".join(run.failed) + ")")
        return 1
    print(f"\nRESULT: PASS ({run.n} steps)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

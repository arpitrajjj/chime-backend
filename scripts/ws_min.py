#!/usr/bin/env python3
"""ws_min.py — tiny RFC6455 WebSocket client for smoke-testing chime-server.
No external deps: raw sockets + hashlib + base64.
"""
import socket, ssl, base64, os, json, hashlib, struct, time


class MiniWS:
    def __init__(self, host, port, path, timeout=5.0, tls=False):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        if tls:
            self.sock = ssl.wrap_socket(self.sock)  # test only
        key = base64.b64encode(os.urandom(16)).decode()
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        self.sock.sendall(req.encode())
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise RuntimeError("handshake EOF")
            resp += chunk
        head, _, rest = resp.partition(b"\r\n\r\n")
        if b" 101 " not in head.split(b"\r\n")[0]:
            raise RuntimeError(f"handshake failed: {head[:120]!r}")
        expect = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
        ).decode()
        if expect.encode() not in head:
            raise RuntimeError("bad Sec-WebSocket-Accept")
        self.buf = rest
        self.timeout = timeout

    def _recv_exact(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise RuntimeError("EOF")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def send_json(self, obj):
        data = json.dumps(obj).encode()
        mask = os.urandom(4)
        hdr = bytearray([0x81])
        n = len(data)
        if n < 126:
            hdr.append(0x80 | n)
        elif n < 65536:
            hdr.append(0x80 | 126)
            hdr += struct.pack(">H", n)
        else:
            hdr.append(0x80 | 127)
            hdr += struct.pack(">Q", n)
        hdr += mask
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        self.sock.sendall(bytes(hdr) + masked)

    def recv_msg(self, timeout=None):
        """returns (opcode, payload); returns (None, None) on timeout."""
        deadline = time.time() + (timeout if timeout is not None else self.timeout)
        self.sock.settimeout(max(0.05, deadline - time.time()))
        while True:
            try:
                head = self._recv_exact(2)
            except (TimeoutError, socket.timeout):
                return None, None
            b0, b1 = head[0:2]
            op = b0 & 0x0F
            ln = b1 & 0x7F
            if ln == 126:
                (ln,) = struct.unpack(">H", self._recv_exact(2))
            elif ln == 127:
                (ln,) = struct.unpack(">Q", self._recv_exact(8))
            payload = self._recv_exact(ln)
            if op == 0x9:  # ping -> pong
                self.sock.sendall(bytes([0x8A, len(payload)]) + payload)
                continue
            if op == 0xA:  # pong
                continue
            return op, payload

    def recv_json(self, timeout=None):
        op, payload = self.recv_msg(timeout)
        if op is None:
            return None
        return json.loads(payload.decode())

    def close(self):
        try:
            self.sock.sendall(bytes([0x88, 0x80]) + os.urandom(4))
            self.sock.close()
        except OSError:
            pass

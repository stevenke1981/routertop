"""Local-only serial/HTTP transport for the isolated QEMU development lab."""
import argparse
import http.server
import pathlib
import re
import socket
import sys
import time
import uuid

sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def command(port, command, timeout, log=None):
    marker = "RTEND" + uuid.uuid4().hex
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.settimeout(0.2)
        # Open BusyBox askfirst, then prove a shell is accepting commands. A
        # first command swallowed by askfirst must never look like a PASS.
        ready = "RTPROMPT" + uuid.uuid4().hex
        sock.sendall(b"\n")
        time.sleep(0.2)
        sock.sendall(("printf '\\n" + ready + "\\n'\n").encode())
        handshake = b""
        ready_deadline = time.monotonic() + 10
        while not re.search(rb"\r?\n" + ready.encode() + rb"\r?\n", handshake):
            if time.monotonic() >= ready_deadline:
                raise TimeoutError("Serial shell did not acknowledge command readiness")
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                raise ConnectionError("Serial disconnected before shell readiness")
            handshake += chunk
        # A newline also accepts a valid command ending in '&' or ';'.
        sock.sendall((command + "\nprintf '\\n" + marker + ":%s\\n' \"$?\"\n").encode())
        data = b""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                break
            data += chunk
            if log:
                with open(log, "ab") as stream:
                    stream.write(chunk)
            sys.stdout.write(chunk.decode(errors="replace"))
            sys.stdout.flush()
            match = re.search(rb"\r?\n" + marker.encode() + rb":(\d+)\r?\n", data)
            if match:
                return int(match.group(1))
        raise TimeoutError("Serial command did not complete")


def serve(directory, output, port):
    root = pathlib.Path(directory).resolve()
    dest = pathlib.Path(output).resolve()
    dest.mkdir(parents=True, exist_ok=True)

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(root), **kwargs)

        def do_PUT(self):
            name = self.path.removeprefix("/upload/")
            if not self.path.startswith("/upload/") or not re.fullmatch(r"[a-zA-Z0-9_.-]+", name):
                self.send_error(400)
                return
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 512 * 1024 * 1024:
                self.send_error(413)
                return
            with (dest / name).open("wb") as f:
                left = size
                while left:
                    chunk = self.rfile.read(min(left, 1024 * 1024))
                    if not chunk:
                        raise ConnectionError("Truncated upload")
                    f.write(chunk)
                    left -= len(chunk)
            self.send_response(201)
            self.end_headers()

    http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()


def wait_for(port, needle, timeout, log):
    deadline = time.monotonic() + timeout
    data = b""
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.settimeout(1)
        while time.monotonic() < deadline:
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                break
            data += chunk
            if log:
                with open(log, "ab") as stream:
                    stream.write(chunk)
            if needle.encode() in data:
                print(data.decode(errors="replace"))
                return 0
    print(data.decode(errors="replace"))
    raise TimeoutError(f"Serial did not reach {needle}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    subs = parser.add_subparsers(dest="action", required=True)
    cmd = subs.add_parser("cmd")
    cmd.add_argument("command")
    cmd.add_argument("--port", type=int, default=19401)
    cmd.add_argument("--timeout", type=int, default=120)
    cmd.add_argument("--log")
    wait = subs.add_parser("wait")
    wait.add_argument("needle")
    wait.add_argument("--port", type=int, required=True)
    wait.add_argument("--timeout", type=int, default=120)
    wait.add_argument("--log")
    web = subs.add_parser("serve")
    web.add_argument("--directory", required=True)
    web.add_argument("--output", required=True)
    web.add_argument("--port", type=int, default=19402)
    args = parser.parse_args()
    if args.action == "cmd":
        sys.exit(command(args.port, args.command, args.timeout, args.log))
    elif args.action == "wait":
        sys.exit(wait_for(args.port, args.needle, args.timeout, args.log))
    else:
        serve(args.directory, args.output, args.port)

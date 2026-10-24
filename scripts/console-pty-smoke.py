#!/usr/bin/env python3
"""Linux PTY acceptance for fail-closed RouterTop console states.

Runs the production `routertop console DATA RUNTIME` entry point with an actual
controlling terminal. Missing/corrupt durable state must never yield a shell,
including after shell-command input, Ctrl-C or Ctrl-D. Normal login/password
changes/reboot are covered separately by console-v04-smoke.py.
No credentials or terminal transcripts are printed or persisted.
"""
import argparse
import errno
import json
import os
from pathlib import Path
import select
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time


class Failure(Exception):
    pass


class Terminal:
    def __init__(self, binary, data, runtime):
        import pty
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            try:
                os.execv(binary, [binary, "console", str(data), str(runtime)])
            except Exception:
                os._exit(127)
        self.buffer = bytearray()
        self.eof = False
        self.reaped = False

    def read(self, seconds):
        deadline = time.monotonic() + seconds
        while not self.eof and time.monotonic() < deadline:
            ready, _, _ = select.select([self.fd], [], [], min(0.1, max(0, deadline - time.monotonic())))
            if not ready:
                continue
            try:
                chunk = os.read(self.fd, 4096)
            except OSError as error:
                if error.errno == errno.EIO:
                    self.eof = True
                    break
                raise
            if not chunk:
                self.eof = True
                break
            self.buffer.extend(chunk)
            if len(self.buffer) > 65536:
                raise Failure("console produced excessive output")
            self.check_no_shell()

    def check_no_shell(self):
        if b"Authenticated." in self.buffer:
            raise Failure("invalid durable state authorized a console shell")

    def wait_locked(self):
        deadline = time.monotonic() + 10
        target = b"Console locked: persistent administrator state unavailable."
        while target not in self.buffer:
            self.read(0.2)
            if self.eof or time.monotonic() >= deadline:
                raise Failure("production console did not reach the locked-state message")

    def send(self, data):
        if self.eof:
            return
        try:
            os.write(self.fd, data)
        except OSError as error:
            if error.errno != errno.EIO:
                raise
            self.eof = True

    def session_processes(self):
        # pty.fork creates a dedicated session. A mistakenly spawned interactive
        # shell may have a different process group, but remains in this session.
        own = []
        for directory in Path("/proc").iterdir():
            if not directory.name.isdigit():
                continue
            try:
                fields = (directory / "stat").read_text().rsplit(")", 1)[1].split()
                if int(fields[3]) == self.pid:
                    own.append(int(directory.name))
            except (OSError, ValueError, IndexError):
                continue
        return own

    def close(self):
        # Terminate only members of this exact newly-created PTY session.
        for signum in (signal.SIGTERM, signal.SIGKILL):
            for pid in self.session_processes():
                try:
                    os.kill(pid, signum)
                except ProcessLookupError:
                    pass
            deadline = time.monotonic() + 1
            while time.monotonic() < deadline:
                if not self.reaped:
                    try:
                        waited, _ = os.waitpid(self.pid, os.WNOHANG)
                        self.reaped = waited == self.pid
                    except ChildProcessError:
                        self.reaped = True
                if not self.session_processes():
                    break
                time.sleep(0.05)
        os.close(self.fd)
        self.buffer.clear()
        if not self.reaped:
            try:
                waited, _ = os.waitpid(self.pid, os.WNOHANG)
                self.reaped = waited == self.pid
            except ChildProcessError:
                self.reaped = True
        if not self.reaped or self.session_processes():
            raise Failure("owned PTY process cleanup did not complete")


def case(binary, config, root, state, action):
    directory = root / (state + "-" + action)
    directory.mkdir(mode=0o700)
    data = directory / "data"
    runtime = directory / "runtime"
    if state == "corrupt":
        result = subprocess.run([binary, "storage-init", str(data), str(config)],
                                capture_output=True, timeout=15, check=False)
        if result.returncode:
            raise Failure("cannot initialize the isolated corrupt-state fixture")
        (data / "state.json").write_text('{"schema":1,"revision":', encoding="ascii")
    marker = directory / "unauthorized-shell-marker"
    command = ("printf '%s' ROOT_ESCAPE > " + shlex.quote(str(marker)) + "\n").encode("ascii")
    terminal = Terminal(binary, data, runtime)
    try:
        terminal.wait_locked()
        terminal.send(command)
        terminal.read(0.25)
        if action == "interrupt":
            terminal.send(b"\x03")
        elif action == "eof":
            terminal.send(b"\x04")
        terminal.send(command)
        # Cross the production five-second locked-state retry interval. A
        # terminated process is also fail-closed; it must never authorize.
        terminal.read(5.5)
        terminal.check_no_shell()
        if marker.exists():
            raise Failure("shell input executed while persistent credentials were unavailable")
        if state == "missing" and data.exists():
            raise Failure("locked console silently initialized missing administrator state")
        if state == "corrupt" and (data / "state.json").read_text(encoding="ascii") != '{"schema":1,"revision":':
            raise Failure("locked console silently replaced corrupt administrator state")
    finally:
        terminal.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("routertop", nargs="?", default="routertop")
    parser.add_argument("--config", type=Path, default=Path(__file__).resolve().parents[1] / "configs" / "routertop.toml")
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        print(json.dumps({"status": "FAIL", "error": "Linux root with PTY support is required"}))
        return 1
    binary = shutil.which(args.routertop)
    if not binary:
        print(json.dumps({"status": "FAIL", "error": "routertop executable not found"}))
        return 1
    binary = str(Path(binary).resolve())
    os.umask(0o077)
    def interrupted(_signum, _frame):
        raise Failure("test interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    passed = 0
    try:
        with tempfile.TemporaryDirectory(prefix="routertop-console-pty-") as directory:
            root = Path(directory)
            for state in ("missing", "corrupt"):
                for action in ("command", "interrupt", "eof"):
                    case(binary, args.config.resolve(), root, state, action)
                    passed += 1
                    print(json.dumps({"case": state + " durable state / " + action,
                                      "status": "PASS"}), flush=True)
    except Failure as error:
        print(json.dumps({"status": "FAIL", "error": str(error), "passed_cases": passed}), flush=True)
        return 1
    except Exception as error:
        print(json.dumps({"status": "FAIL", "error": type(error).__name__, "passed_cases": passed}), flush=True)
        return 1
    print(json.dumps({"status": "PASS", "passed_cases": passed}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Real local QEMU TTY acceptance; fresh disposable data volume required.

No credentials, raw terminal transcripts or cookies are written to disk.
The optional --poweroff shuts down only the authenticated loopback test VM.
"""
import argparse
import http.cookiejar
import json
from pathlib import Path
import secrets
import socket
import ssl
import time
import urllib.error
import urllib.request


class Terminal:
    def __init__(self, port):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=10)
        self.sock.settimeout(0.3)
        self.buffer = b""

    def send(self, text):
        self.sock.sendall(text.encode())

    def until(self, needle, timeout=45):
        target = needle.encode()
        deadline = time.monotonic() + timeout
        while target not in self.buffer:
            if time.monotonic() > deadline:
                raise AssertionError("TTY did not reach expected state")
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                raise AssertionError("TTY disconnected before expected state")
            self.buffer += chunk
        end = self.buffer.index(target) + len(target)
        received, self.buffer = self.buffer[:end], self.buffer[end:]
        return received.decode(errors="replace")

    def shell(self, command):
        marker = "RT_CHECK_" + secrets.token_hex(8)
        # Marker is emitted on its own line, so terminal command echo cannot pass.
        self.send(command + "; printf '\\n" + marker + ":%s\\n' \"$?\"\n")
        text = self.until("\n" + marker + ":")
        status = self.until("\n").strip()
        assert status == "0", "Authenticated shell check failed"
        return text

    def login(self, password):
        self.send(password + "\n")
        output = self.until("Authenticated. Type exit to log out.")
        assert password not in output, "Password was echoed by terminal"
        self.shell("test \"$(id -u)\" = 0")

    def logout(self):
        self.send("exit\n")
        self.until("Logged out.")
        self.until("Password: ")

    def close(self):
        self.buffer = b""
        self.sock.close()

    def poweroff(self, timeout=30):
        # Keep the serial transport alive until QEMU exits. Closing immediately
        # after sendall can discard bytes not yet consumed by its serial device.
        self.send("sync; poweroff\n")
        deadline = time.monotonic() + timeout
        self.buffer = b""
        while time.monotonic() < deadline:
            try:
                if not self.sock.recv(65536):
                    return
            except socket.timeout:
                continue
            except ConnectionResetError:
                return
        raise AssertionError("VM serial did not close after authenticated poweroff")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=19410)
    parser.add_argument("--https-port", type=int, default=19443)
    parser.add_argument("--output", type=Path, default=Path("evidence/v04/console-report.json"))
    parser.add_argument("--poweroff", action="store_true")
    args = parser.parse_args()
    password = "Rt04-" + secrets.token_urlsafe(24)
    replacement = "Rt04-new-" + secrets.token_urlsafe(24)
    report = {"result": "RUNNING", "checks": []}
    stage = "fresh console initialization"
    terminal = None

    def passed(name):
        report["checks"].append({"name": name, "result": "PASS"})
        print("PASS " + name, flush=True)

    origin = "https://127.0.0.1:" + str(args.https_port)
    cookies = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl._create_unverified_context()),
                                        urllib.request.HTTPCookieProcessor(cookies))

    def api(path, data=None, csrf=None):
        headers = {"Origin": origin, "Content-Type": "application/json"}
        if csrf:
            headers["X-CSRF-Token"] = csrf
        request = urllib.request.Request(origin + "/cgi-bin/routertop.cgi" + path,
                                         data=None if data is None else json.dumps(data).encode(), headers=headers)
        try:
            with opener.open(request, timeout=30) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            return error.code, {}

    try:
        assert api("/session")[1].get("setup_required") is True, "Fresh lab volume required"
        terminal = Terminal(args.port)
        terminal.send("\n")
        terminal.until("Setup choice [create/token]: ")
        terminal.send("create\n")
        terminal.until("New password: ")
        terminal.send(password + "\n")
        assert password not in terminal.until("Confirm password: ")
        terminal.send(password + "\n")
        assert password not in terminal.until("Password: ")
        passed("first_console_enrollment_without_password_echo")

        stage = "interrupt EOF and bad password denial"
        terminal.send("\x03\n")
        assert "Authenticated." not in terminal.until("Password: ")
        terminal.send("\x04")
        assert "Authenticated." not in terminal.until("Password: ")
        terminal.send("touch /tmp/console-bypass\n")
        assert "Authenticated." not in terminal.until("Authentication failed.")
        terminal.until("Password: ")
        passed("ctrl_c_eof_and_command_as_password_do_not_grant_shell")

        stage = "authenticated root shell and ownership"
        terminal.login(password)
        terminal.shell("test ! -e /tmp/console-bypass && test \"$(stat -c %u /data/routertop/state.json)\" = 1000 && test \"$(stat -c %a /data/routertop/state.json)\" = 600")
        terminal.logout()
        passed("authenticated_shell_logout_and_private_cgi_ownership")

        stage = "shared Web credential and password replacement"
        code, session = api("/login", {"username": "admin", "password": password})
        assert code == 200, "Console-created account cannot log in through Web"
        csrf = session.get("csrf_token") or session.get("csrf")
        assert csrf, "Missing authenticated CSRF token"
        code, status = api("/status")
        assert code == 200 and status["console_auth_required"] and status["console_password_shared"]
        code, _ = api("/password", {"current_password": password, "new_password": replacement}, csrf)
        assert code == 200, "Web password change failed"
        terminal.send(password + "\n")
        terminal.until("Authentication failed.")
        terminal.until("Password: ")
        terminal.login(replacement)
        passed("web_password_change_rejects_old_console_password_and_accepts_new")

        stage = "damaged state locks other console without fallback"
        # A child pseudo-terminal runs the production gate against missing state
        # only in unit/PTY tests. This appliance check preserves the real data.
        terminal.shell("test -x /usr/sbin/routertop-console && ! grep -q 'askfirst:-/bin/sh' /etc/inittab")
        terminal.logout()
        passed("production_ttys_use_authentication_gate")

        stage = "reboot credential persistence"
        terminal.login(replacement)
        terminal.send("sync; reboot\n")
        terminal.close()
        terminal = None
        deadline = time.monotonic() + 150
        down = False
        while time.monotonic() < deadline:
            try:
                code, state = api("/session")
                if down and code == 200 and not state.get("setup_required"):
                    break
            except (OSError, ValueError):
                down = True
            time.sleep(1)
        else:
            raise AssertionError("No observed reboot down/up cycle")
        terminal = Terminal(args.port)
        terminal.send("\n")
        terminal.until("Password: ")
        terminal.login(replacement)
        passed("reboot_retains_shared_administrator_and_console_password")
        if args.poweroff:
            terminal.poweroff()
        else:
            terminal.logout()
        report["result"] = "PASS"
    except Exception as error:
        report.update(result="FAIL", failed_stage=stage, error=type(error).__name__)
        print("FAIL " + stage + " (" + type(error).__name__ + ")", flush=True)
    finally:
        if terminal:
            terminal.close()
        cookies.clear()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    return 0 if report["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())

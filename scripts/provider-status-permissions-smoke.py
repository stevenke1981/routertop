#!/usr/bin/env python3
"""Real bound-provider readiness through authenticated root/uid1000 CGI.

The actual DHCPv6/PD lab runs unchanged. Only public directory traversal and a
redacted DHCP-only management config are made readable. Private provider epochs
remain root-owned0600. --expect-private-denial records the RC1 regression.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import sys
import time
import traceback

spec = importlib.util.spec_from_file_location("v08", Path(__file__).with_name("network-v08-smoke.py"))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
Failure = base.Failure
DROP = "import os,sys;u=int(sys.argv[1]);os.setgroups([]);os.setgid(u);os.setuid(u);os.execve(sys.argv[2],sys.argv[2:],os.environ)"


class Lab(base.Lab):
    def __init__(self, binary):
        super().__init__(binary, "dhcp-dhcp")
        self.work.chmod(0o755)
        local = self.work / "routertop-test-binary"
        shutil.copyfile(self.binary, local)
        local.chmod(0o755)
        self.binary = str(local)
        self.cookie = None
        self.frozen = []

    def traversable_public_paths(self):
        for path in (self.work, self.root_runtime, self.runtime, self.wan_runtime):
            path.chmod(0o755)
        self.config_path.chmod(0o600)
        epoch = self.runtime / "provider.json"
        if epoch.stat().st_uid != 0 or epoch.stat().st_mode & 0o777 != 0o600:
            raise Failure("private provider epoch is not root-owned0600")
        for path in (self.runtime / "status.json", self.wan_runtime / "status.json"):
            if path.stat().st_mode & 0o777 != 0o644:
                raise Failure("public readiness snapshot is not0644")

    def cgi(self, uid, method="GET", path="/status", payload=None):
        body = b"" if payload is None else json.dumps(payload).encode()
        env = dict(os.environ, REQUEST_METHOD=method, PATH_INFO=path, HTTPS="on", HTTP_HOST="127.0.0.1",
                   HTTP_ORIGIN="https://127.0.0.1", CONTENT_TYPE="application/json", CONTENT_LENGTH=str(len(body)),
                   ROUTERTOP_DATA_DIR=str(self.web_data), ROUTERTOP_RUNTIME_DIR=str(self.web_runtime),
                   ROUTERTOP_ACTIVE_CONFIG=str(self.public_config))
        if self.cookie:
            env["HTTP_COOKIE"] = self.cookie
        argv = ["ip", "netns", "exec", self.namespaces["router"], "nsenter", "-m", "-t",
                str(self.router_process.pid), "--", "python3", "-c", DROP, str(uid), self.binary, "cgi"]
        result = subprocess.run(argv, env=env, input=body, capture_output=True, timeout=20)
        if result.returncode:
            raise Failure("CGI process failed under uid" + str(uid))
        header, separator, data = result.stdout.partition(b"\r\n\r\n")
        if not separator:
            raise Failure("CGI response lacks header boundary")
        lines = header.decode().splitlines()
        code = next(int(line.split(":", 1)[1]) for line in lines if line.startswith("Status:"))
        if code != 200:
            raise Failure("CGI HTTP" + str(code) + " under uid" + str(uid))
        for line in lines:
            if line.lower().startswith("set-cookie:"):
                self.cookie = line.split(":", 1)[1].strip().split(";", 1)[0]
        return json.loads(data)

    def management(self):
        self.traversable_public_paths()
        self.public_config = self.work / "public-config.toml"
        self.public_config.write_text(self.run([self.binary, "export", self.config_path]).stdout)
        self.public_config.chmod(0o644)
        self.web_data = self.work / "web-data"
        self.web_runtime = self.work / "web-runtime"
        self.run([self.binary, "storage-init", self.web_data, self.public_config])
        token = self.run([self.binary, "bootstrap-token", self.web_data]).stdout.strip()
        self.web_runtime.mkdir(mode=0o700)
        for path in [self.web_data, *self.web_data.rglob("*"), self.web_runtime]:
            os.chown(path, 1000, 1000)
        self.cgi(1000, "POST", "/setup", {"token": token, "password": "Rt08-" + secrets.token_urlsafe(24)})

    def private_denied(self):
        # Print only a fixed label, never any epoch bytes or lifecycle token.
        code = ("import os,sys;os.setgroups([]);os.setgid(1000);os.setuid(1000);"
                "p=sys.argv[1]\ntry:\n open(p,'rb').read(1)\nexcept PermissionError:\n sys.exit(0)\nsys.exit(1)")
        result = self.run(["nsenter", "-m", "-t", str(self.router_process.pid), "--", "python3", "-c", code,
                           str(self.runtime / "provider.json")], "router", check=False)
        if result.returncode:
            raise Failure("uid1000 can read private provider epoch")

    @staticmethod
    def view(value):
        wan = value.get("wan", {})
        return {key: wan.get(key) for key in ("active", "ipv6_active", "ipv6_ready", "ipv6_policy")}

    def agreement(self, slot, expect_denial=False):
        self.traversable_public_paths()
        self.private_denied()
        def ready():
            root = self.cgi(0)
            unpriv = self.cgi(1000)
            r, u = self.view(root), self.view(unpriv)
            if r["ipv6_active"] != slot or r["ipv6_ready"] is not True:
                return False
            if expect_denial:
                if u["ipv6_active"] is not None or u["ipv6_ready"] is not False:
                    raise Failure("old uid1000 permission regression was not reproduced")
            elif u != r:
                return False
            print(json.dumps({"check": "authenticated CGI public readiness", "provider": slot,
                              "root": r, "uid1000": u, "public_pd": {key: unpriv.get("ipv6_dynamic", {}).get(key) for key in ("state", "phase", "provider", "logical_interface", "generation")},
                              "private_epoch_readable": False,
                              "expected_old_regression": expect_denial, "status": "PASS"}), flush=True)
            return True
        self.wait_for(ready, "root and uid1000 CGI readiness", timeout=12)
        self.passed("root/uid1000 real " + slot + " provider readiness" + (" expected RC1 private-read denial" if expect_denial else " agrees without private epoch access"))

    def pause_owned(self):
        self.frozen = [int(value) for value in self.run(["ip", "netns", "pids", self.namespaces["router"]]).stdout.split()]
        for pid in self.frozen:
            try:
                os.kill(pid, signal.SIGSTOP)
            except ProcessLookupError:
                pass

    def resume_owned(self):
        for pid in self.frozen:
            try:
                os.kill(pid, signal.SIGCONT)
            except ProcessLookupError:
                pass
        self.frozen = []

    def negative_snapshots(self):
        self.pause_owned()
        pd_path, wan_path = self.runtime / "status.json", self.wan_runtime / "status.json"
        original_pd, original_wan = pd_path.read_bytes(), wan_path.read_bytes()
        pd, wan = json.loads(original_pd), json.loads(original_wan)
        def publish(path, value):
            temporary = path.with_suffix(".permissions-test.tmp")
            temporary.write_text(json.dumps(value))
            temporary.chmod(0o644)
            os.replace(temporary, path)
        cases = [("acquiring", "pd", "phase", "acquiring"), ("degraded", "pd", "state", "degraded"),
                 ("stale_generation", "pd", "generation", pd["generation"] + 99),
                 ("wrong_provider", "pd", "provider", "primary"),
                 ("wrong_logical", "pd", "logical_interface", "wan0"),
                 ("stale_timestamp", "pd", "updated_uptime_seconds", 0),
                 ("missing_generation", "wan", "ipv6_generation", None),
                 ("wrong_active", "wan", "active", "primary")]
        try:
            for label, target, key, value in cases:
                dynamic, public = copy.deepcopy(pd), copy.deepcopy(wan)
                dynamic["updated_uptime_seconds"] = int(float(Path("/proc/uptime").read_text().split()[0]))
                (dynamic if target == "pd" else public)[key] = value
                publish(pd_path, dynamic)
                publish(wan_path, public)
                for uid in (0, 1000):
                    result = self.view(self.cgi(uid))
                    if result["ipv6_active"] is not None or result["ipv6_ready"] is not False:
                        raise Failure("invalid public snapshot grants ready under uid" + str(uid) + " for " + label)
                self.private_denied()
                self.passed("root/uid1000 reject " + label + " public provider snapshot while epoch remains private")
        finally:
            pd_path.write_bytes(original_pd)
            pd_path.chmod(0o644)
            wan_path.write_bytes(original_wan)
            wan_path.chmod(0o644)
            self.resume_owned()

    def close(self):
        self.resume_owned()
        super().close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("routertop")
    parser.add_argument("--expect-private-denial", action="store_true", help="record root-ready/uid1000-null behavior of old RC1")
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        print(json.dumps({"status": "FAIL", "error": "Linux root required"}))
        return 1
    os.umask(0o077)
    def interrupted(*_):
        raise Failure("interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    lab = Lab(args.routertop)
    failed = False
    try:
        lab.fixture()
        lab.install()
        lab.wait_selected("primary")
        lab.bound("primary", base.PREFIXES["primary"])
        lab.management()
        if not args.expect_private_denial:
            lab.agreement("primary")
        lab.cut_carrier(0, True)
        lab.wait_selected("backup")
        lab.bound("backup", base.PREFIXES["backup"])
        lab.agreement("backup", args.expect_private_denial)
        if not args.expect_private_denial:
            lab.negative_snapshots()
    except Exception as error:
        failed = True
        if isinstance(error, Failure):
            message = str(error)
        else:
            frame = traceback.extract_tb(error.__traceback__)[-1]
            message = type(error).__name__ + " at " + frame.name + ":" + str(frame.lineno)
        lab.diagnostics(message)
        print(json.dumps({"status": "FAIL", "error": message}), flush=True)
    finally:
        count = len(lab.results)
        lab.close()
    print(json.dumps({"status": "FAIL" if failed else "PASS", "passed_cases": count,
                      "expected_old_regression": args.expect_private_denial,
                      "binary_sha256": hashlib.sha256(Path(args.routertop).read_bytes()).hexdigest(),
                      "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}), flush=True)
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())

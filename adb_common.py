"""adb helpers shared by Room SQL and Net Inspector."""

import os
import re
import shlex
import shutil
import subprocess


def find_adb():
    path = shutil.which("adb")
    if path:
        return path
    for root in (os.environ.get("ANDROID_HOME"), os.environ.get("ANDROID_SDK_ROOT"),
                 os.path.expanduser("~/Library/Android/sdk"), os.path.expanduser("~/Android/Sdk")):
        if root:
            candidate = os.path.join(root, "platform-tools", "adb")
            if os.path.exists(candidate):
                return candidate
    return "adb"


ADB = find_adb()


class AdbError(Exception):
    pass


def list_devices():
    """[(serial, model)] for devices that are online."""
    out = subprocess.run([ADB, "devices", "-l"], capture_output=True, text=True, timeout=30).stdout
    devices = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            model = next((p.split(":", 1)[1] for p in parts if p.startswith("model:")), "")
            devices.append((parts[0], model))
    return devices


class DeviceBase:
    """Runs adb commands against one device."""

    def __init__(self, serial):
        self.serial = serial
        self._root_wrap = False  # False = not checked yet

    def run(self, *args, data=None, timeout=120):
        """Run `adb -s <serial> <args>`; returns CompletedProcess with bytes output."""
        return subprocess.run([ADB, "-s", self.serial, *args], input=data,
                              capture_output=True, timeout=timeout)

    def shell(self, cmd, timeout=120):
        """Run a shell command; returns (returncode, stdout, stderr) as text."""
        proc = self.run("shell", cmd, timeout=timeout)
        return (proc.returncode, proc.stdout.decode(errors="replace"),
                proc.stderr.decode(errors="replace"))

    def exec_out(self, cmd, timeout=120):
        """Run a shell command and return its raw stdout bytes (binary safe)."""
        return self.run("exec-out", cmd, timeout=timeout).stdout

    def users(self):
        """User ids, current user first (Android Automotive runs apps as user 10, not 0)."""
        _, cur, _ = self.shell("am get-current-user")
        _, out, _ = self.shell("pm list users")
        ids = [int(m) for m in re.findall(r"UserInfo\{(\d+):", out)]
        cur = int(cur.strip()) if cur.strip().isdigit() else 0
        return [cur] + [u for u in ids if u != cur]

    def root_wrap(self):
        """A function that wraps a shell command to run as root, or None if no root."""
        if self._root_wrap is False:
            self._root_wrap = None
            for wrap in (lambda c: c,  # adbd already running as root
                         lambda c: f"su 0 sh -c {shlex.quote(c)}",
                         lambda c: f"su -c {shlex.quote(c)}"):
                _, out, _ = self.shell(wrap("id -u"))
                if out.strip() == "0":
                    self._root_wrap = wrap
                    break
        return self._root_wrap

    def package_uids(self):
        """{uid: package} for every installed package and user."""
        _, out, _ = self.shell("pm list packages -U")
        uids = {}
        for line in out.splitlines():
            m = re.match(r"package:(\S+)\s+uid:([\d,]+)", line.strip())
            if m:
                for uid in m.group(2).split(","):
                    # Several packages can share a uid (e.g. "android" and system apps).
                    uids.setdefault(int(uid), m.group(1))
        return uids

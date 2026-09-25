#!/usr/bin/env python3
"""app-rig — N virtual cold-snap devices on N pseudo-terminals, for the real app.

WHAT THIS IS NOT. It is not `hostcheck`. hostcheck is the ASSERTION rig: one pty,
13 sessions in ONE process, the coordinator linked in as a library, ~15 latches
that only mean anything because they name an exact roster on one wire
(HARNESS-PLAN §2, "do not move hostcheck's assertions into the app rig"). This is
the TOPOLOGY rig: N ptys, ONE session per process, and the thing on the other end
is the real Flutter/Rust desktop app driving `UsbSerialManager`, which hostcheck
bypasses entirely. Keep both.

THE POLARITY IS NOT A CHOICE (HARNESS-PLAN C.3, MEASURED): the coordinator — here,
the app — must hold the pty's **SLAVE**. `FramedSerialPort::anything_to_read()` is
FIONREAD, and FIONREAD on a Darwin pty MASTER always returns 0, so an app on the
master reads nothing, forever, silently. The stub therefore gets the master as its
fd 0/fd 1, exactly as hostcheck hands it over, and the app opens the slave by path.

THIS PROCESS HOLDS A SLAVE FD OPEN for the rig's lifetime and never reads it. Two
reasons: without it there is a window with no slave open at all, in which the stub's
first read returns EOF and it exits before the app ever gets there; and with it, the
app closing its port does not fake a power cycle. Reading it would steal the app's
bytes, so nothing here ever does.

Usage (from anywhere; paths resolve against this file's repository):

    tools/app-rig.py --devices 3 -- <command ...>   # run <command>, then tear down
    tools/app-rig.py --devices 3 --timeout 900      # hold open for a human/debugger

Exit codes, all named on stderr:
    0   the rig came up, the command (if any) exited 0, everything was reaped
    2   precondition failed (no stub binary, stub older than its sources, or LOCKED:
        another rig run holds target/software-only/app-rig.lock)
    3   DUPLICATE TEST IDENTITY across child processes
    4   CHILD FAILED (a stub exited while the rig was up)
    5   TIMEOUT (identities never appeared, or the command outlived --timeout)
    6   APP RESTART UNVERIFIED (--app-restart: the second app process exited 0 but never
        recorded that it reloaded the first one's wallet)
    *   otherwise the command's own exit code, passed through
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import pty
import re
import shutil
import signal
import subprocess
import sys
import termios
import time
import tty

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Same artifact hostcheck defaults to (`DEFAULT_STUB`), so both rigs run the same
# binary and a stale one is stale for both.
DEFAULT_STUB = os.path.join(REPO, "target/aarch64-apple-darwin/debug/examples/stub")
DEFAULT_DIR = os.path.join(REPO, "target/software-only/app-rig")
# ONE RIG AT A TIME, machine-wide, whatever `--dir` says: the frostsnapp build tree (Xcode's
# build.db), the macOS test app and regtest's RPC port are shared by every run, so a second
# run in another dir would still corrupt the first. A kernel flock, so a SIGKILLed holder
# never leaves a stale lock behind.
LOCK = os.path.join(REPO, "target/software-only/app-rig.lock")
# Task 01's packaged, key-0-signed Mk4 artifact. Its `firmware_digest` is the sole entry
# in `frostsnap_coordinator/src/coldsnap-mk4-registry.txt`, so announcing it is what
# makes the app identify a rig device as `DeviceProfile::ColdsnapMk4` instead of
# `Unrecognized` (which is `is_compatible() == false` and every capability false, i.e. a
# device the app's keygen gate refuses). NOT a hardcoded digest: the stub hashes this
# FILE with the shipped `firmware_digest`, so if the artifact is rebuilt the announced
# value follows it. See `--image`.
DEFAULT_IMAGE = os.path.join(REPO, "target/software-only/package/firmware-signed.bin")

# The line `firmware/examples/stub.rs` prints once its flash-backed sessions exist.
IDS_RE = re.compile(r"flash-backed sessions[^:]*: \[(.*)\]")


def log(msg: str) -> None:
    print(f"app-rig: {msg}", file=sys.stderr, flush=True)


def refuse_if_stale(stub: str) -> None:
    """Cargo's own answer to 'is this binary current', not a guess at directories.

    The depfile beside the artifact lists every source that went into it, which is
    what hostcheck's `refuse_if_stale` reads too. A missing depfile is reported, not
    silently accepted: an unchecked binary is the expensive failure — a green run
    certifying code that is not in the binary.
    """
    if not os.path.isfile(stub):
        log(f"FAIL no stub at {stub}")
        log("build it: cargo build --target aarch64-apple-darwin -p coldsnap_firmware --example stub")
        sys.exit(2)
    built = os.path.getmtime(stub)
    dep = os.path.splitext(stub)[0] + ".d"
    if not os.path.isfile(dep):
        log(f"WARNING no depfile at {dep}; stub freshness UNCHECKED")
        return
    newest, newest_path = 0.0, ""
    with open(dep) as fh:
        for line in fh:
            if ":" not in line:
                continue
            for src in line.split(":", 1)[1].split():
                if src.endswith(".rs") and os.path.isfile(src):
                    mtime = os.path.getmtime(src)
                    if mtime > newest:
                        newest, newest_path = mtime, src
    if newest > built:
        log(f"FAIL stub is STALE: {newest_path} is newer than {stub}")
        sys.exit(2)


class Rig:
    """Every fd and child this rig owns, so teardown is one call on every path."""

    def __init__(self, outdir: str) -> None:
        # Absolute, because children (regtest.py via the app) resolve it from other cwds.
        self.outdir = outdir = os.path.abspath(outdir)
        # Set only in the command's env, so no ancestor of the rig can ever match it.
        self.run_token = f"{os.getpid()}-{time.time_ns()}"
        self.masters: list[int] = []
        self.slaves: list[int] = []
        self.paths: list[str] = []
        self.children: list[subprocess.Popen] = []
        self.logs: list[str] = []
        # The command (flutter, and through it flutter_tools and the macOS test app) runs
        # as the leader of its OWN process group, so teardown can signal every process
        # under it, not only the pid it started.
        self.cmd: subprocess.Popen | None = None
        # This run's regtest datadir: the node `regtest.py up` starts is -daemonwait, so it
        # is reparented to init and no process group reaches it. Teardown stops it by
        # datadir with `regtest.py down`, which is what the test's own tearDownAll does on
        # the path that gets there.
        self.regtest = os.path.join(outdir, "regtest")
        self.manifest = os.path.join(outdir, "ports.txt")
        self.identities = os.path.join(outdir, "identities.tsv")
        # `--app-restart`: what the first app process persisted, written by it and
        # countersigned by the second (`coldsnap_workflows_test.dart`).
        self.restart_snapshot = os.path.join(outdir, "app-restart.json")

    def open_ptys(self, n: int) -> None:
        for _ in range(n):
            master, slave = pty.openpty()
            # RAW, or the line discipline eats the wire: ONLCR would rewrite 0x0a in
            # a bincode frame, ICANON would hold bytes until a newline, and ISIG
            # would turn a 0x03 in a frame into SIGINT. The app's own `serialport`
            # open re-asserts raw on the same termios; this covers the window before
            # it and any stub bytes written first.
            tty.setraw(slave, termios.TCSANOW)
            self.masters.append(master)
            self.slaves.append(slave)
            self.paths.append(os.ttyname(slave))

    def write_manifest(self) -> None:
        """The port list the app's test-only `Serial` impl enumerates.

        Re-read on every `available_ports()` call, so removing a line here is an
        UNPLUG and putting it back is a replug — no app restart involved.
        """
        with open(self.manifest, "w") as fh:
            fh.write("# cold-snap app rig: one pty slave per virtual device.\n")
            for path in self.paths:
                fh.write(path + "\n")

    def spawn(self, stub: str, salt_base: int, duplicate_salts: bool,
              image: str | None, decline: set[int], watchdog_scale: int,
              lose: set[int] = frozenset(), erase: set[int] = frozenset(),
              erase_cut: dict[int, str] | None = None) -> None:
        # A previous, larger run's `device-N.log` would otherwise sit there looking
        # like a device this run has.
        for stale in os.listdir(self.outdir):
            if stale.startswith("device-") and stale.endswith(".log"):
                os.remove(os.path.join(self.outdir, stale))
        for i, master in enumerate(self.masters):
            logpath = os.path.join(self.outdir, f"device-{i}.log")
            logfh = open(logpath, "w")
            self.logs.append(logpath)
            env = dict(os.environ)
            # ONE session per process: the shipping topology is one port per device
            # (the conch is off on this board, so a cold-snap device is a leaf).
            env["STUB_SESSIONS"] = "1"
            # DISTINCT per process, or every child derives the SAME DeviceId from its
            # own blank flash and the app sees one device where the rig launched N.
            env["STUB_SALT"] = hex(salt_base if duplicate_salts else salt_base + i)
            # What was on the glass when this device consented, read back off the
            # rendered pixels into `device-N.log`. The app rig's only channel for
            # "the displayed recipients/address/amounts are the ones being signed":
            # the app cannot see a screen, and this file is not the coordinator's
            # copy of the request.
            env["STUB_GLASS_LOG"] = "1"
            # THE STUB'S WATCHDOG IS A FLAT SLEEP from process start (240 s), sized for
            # hostcheck's four passes on one wire. An app-driven run is a whole Flutter
            # test suite -- keygen, a chain fixture, two signing sessions, a backup
            # reveal -- so without this every device dies mid-suite and the first symptom
            # is a stalled workflow three layers up. DERIVED from this rig's own bound
            # rather than a chosen number, so a longer `--timeout` cannot outlive it.
            env["COLDSNAP_TIMEOUT_SCALE"] = str(watchdog_scale)
            # THE REAL APP'S COORDINATOR GRINDS WITH THE SHIPPED `Fingerprint::FROST_V0`,
            # and the device's `check_fingerprint` is not symmetric with that grind: with
            # the stub's default `test` fingerprint (a different tag, 2 bits per
            # coefficient) a 2-of-3 keygen through the app passes the device's check about
            # one run in sixteen. Measured: two runs passed, the third died with "key
            # generation did not match the fingerprint" and no source change. hostcheck
            # keeps `test` on both sides on purpose -- there the grind is its own cost.
            env["STUB_FINGERPRINT"] = "frost-v0"
            # A REPLUG: the app closes the port and re-opens it, so its device registry no
            # longer holds this device and it goes back to writing magic bytes. Without
            # this the device replies nothing and never comes back -- measured as 1,758
            # unanswered magic-byte frames in one run. Not on for hostcheck; see the call
            # site in `stub.rs`.
            env["STUB_REANNOUNCE"] = "1"
            # The sheet of paper a human carries between units. One session per
            # process means the device that reveals a backup and the blank device
            # that retypes it are different processes.
            env["STUB_SHEET_DIR"] = os.path.join(self.outdir, "sheets")
            if image:
                env["STUB_IMAGE"] = image
            if i in decline:
                # `<CheckKeyGen><SignatureRequest><Restoration>`: approve the keygen,
                # press `x` at every signing screen, approve restoration. A LITERAL
                # key, which is the whole point -- `x` is not in `CONFIRM_CHARSET`, so
                # it is a refusal whatever digit the screen drew, and it is the same
                # mechanism hostcheck's DECLINE pass uses.
                env["COLDSNAP_GLASS_KEYS"] = "yxy"
                # DECLARED, so the stub's own fail-closed count cannot call it an
                # error. No exact number: the app decides how many signing requests it
                # sends, and this rig deliberately does not count them -- an exact
                # roster on one wire is hostcheck's job (HARNESS-PLAN §2). In a rig run
                # the gate is unreached anyway: it lives on the stub's EOF path, and
                # the rig holds a slave fd open so the stub never sees EOF.
                env["STUB_EXPECT_DECLINES"] = str(2**31)
            if i in lose:
                # FAULT INJECTION: this device's first signature reply is signed and then
                # dropped before the wire (`stub.rs::lose_first_share`), so the app test
                # can replug it and re-send the request -- the only way this rig drives
                # the core's at-most-once signing rule.
                env["STUB_LOSE_FIRST_SHARE"] = "1"
            if i in erase:
                # Task 08: DECLINE this device's first erase question and APPROVE its
                # second (`stub.rs::erase_keys`). Every other device keeps the default
                # `x`, so a DataErase it is sent is refused at its glass.
                env["STUB_ERASE_KEYS"] = "xy"
            if erase_cut and i in erase_cut:
                # Fix 2a: APPROVE this device's erase questions in turn, each cut by a
                # power loss at the point its key names (`stub.rs::erase_keys`: p c a f).
                # A committed cut reboots into `erase::recover`, which finishes the
                # erase and sends the EraseConfirmed under the old id.
                env["STUB_ERASE_KEYS"] = erase_cut[i]
            child = subprocess.Popen(
                [stub],
                stdin=master,
                stdout=master,
                stderr=logfh,
                close_fds=True,  # no other master, and no slave, reaches the child
                env=env,
            )
            logfh.close()  # the child holds its own dup
            self.children.append(child)
            log(f"device {i}: pid {child.pid} on {self.paths[i]} "
                f"(STUB_SALT={env['STUB_SALT']}, "
                f"consent={env.get('COLDSNAP_GLASS_KEYS', 'yyy')}, log {logpath})")

    def await_identities(self, timeout: float) -> list[str]:
        """Read each child's announced DeviceId off its own log, then demand N distinct.

        This is the only place duplicate identities ACROSS processes can be caught:
        `open_sessions` in the stub only sees its own process, and the app would show
        the collision as a missing device three layers up.
        """
        found: list[str | None] = [None] * len(self.children)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for i, child in enumerate(self.children):
                if found[i] is not None:
                    continue
                if child.poll() is not None:
                    log(f"FAIL CHILD FAILED: device {i} (pid {child.pid}) exited "
                        f"{child.returncode} before announcing; see {self.logs[i]}")
                    sys.exit(4)
                with open(self.logs[i]) as fh:
                    match = IDS_RE.search(fh.read())
                if match:
                    ids = [x.strip() for x in match.group(1).split(",") if x.strip()]
                    if len(ids) != 1:
                        log(f"FAIL device {i} hosts {len(ids)} sessions, expected 1")
                        sys.exit(4)
                    found[i] = ids[0]
            if all(x is not None for x in found):
                break
            time.sleep(0.05)
        missing = [i for i, x in enumerate(found) if x is None]
        if missing:
            log(f"FAIL TIMEOUT: device(s) {missing} never announced a DeviceId within "
                f"{timeout:g}s; see {self.outdir}/device-*.log")
            sys.exit(5)
        ids = [x for x in found if x is not None]
        with open(self.identities, "w") as fh:
            for path, device_id in zip(self.paths, ids):
                fh.write(f"{path}\t{device_id}\n")
        if len(set(ids)) != len(ids):
            dupes = sorted({x for x in ids if ids.count(x) > 1})
            log("FAIL DUPLICATE TEST IDENTITY: two child processes announced the same "
                f"DeviceId {dupes}; each process needs its own STUB_SALT")
            sys.exit(3)
        log(f"{len(ids)} distinct DeviceId(s) announced; written to {self.identities}")
        return ids

    def check_children_alive(self) -> None:
        for i, child in enumerate(self.children):
            if child.poll() is not None:
                log(f"FAIL CHILD FAILED: device {i} (pid {child.pid}) exited "
                    f"{child.returncode} while the rig was up; see {self.logs[i]}")
                sys.exit(4)

    def stop_command(self) -> list[int]:
        """SIGTERM the command's whole process group, then SIGKILL what is left of it.

        Returns the pids still in the group afterwards, which must be none.
        """
        if self.cmd is None:
            return []
        pgid = self.cmd.pid  # start_new_session: the leader's pid is the group id

        def members() -> list[int]:
            out = subprocess.run(["pgrep", "-g", str(pgid)],
                                 capture_output=True, text=True).stdout.split()
            return [int(x) for x in out if x.isdigit()]

        for sig, grace in ((signal.SIGTERM, 10.0), (signal.SIGKILL, 5.0)):
            try:
                os.killpg(pgid, sig)
            except (ProcessLookupError, PermissionError):
                # Darwin answers EPERM, not ESRCH, for a group whose only member is an
                # unreaped zombie leader; `members()` below is the real answer either way.
                pass
            deadline = time.monotonic() + grace
            while time.monotonic() < deadline:
                self.cmd.poll()  # reap the leader, or it lingers as a zombie member
                if not members():
                    return []
                time.sleep(0.1)
        self.cmd.poll()
        return members()

    def stop_regtest(self) -> bool:
        """`regtest.py down` on THIS run's datadir: stops our node (matched by datadir,
        never by name) and deletes the datadir. A no-op when no node was started."""
        env = dict(os.environ, COLDSNAP_REGTEST_DATADIR=self.regtest)
        try:
            proc = subprocess.run([sys.executable, os.path.join(REPO, "tools/regtest.py"), "down"],
                                  env=env, capture_output=True, text=True, timeout=120)
        except subprocess.TimeoutExpired:
            log("FAIL regtest.py down did not return in 120s")
            return False
        if proc.returncode != 0:
            log(f"FAIL regtest.py down exited {proc.returncode}: {proc.stderr.strip()}")
            return False
        return True

    def reap_env_strays(self) -> list[int]:
        """Kill processes that left the command's group but still carry this run's env.

        xcodebuild's ibtoold daemons reparent to launchd in their own group, so neither
        stop_command nor the stub pgrep sees them. Matched by this run's unique
        COLDSNAP_RIG_RUN_TOKEN, never by name, so no other process is ever touched. Returns
        pids that outlived SIGKILL.
        """
        if not shutil.which("ps"):
            return []
        mark = f"COLDSNAP_RIG_RUN_TOKEN={self.run_token}"
        def strays() -> list[int]:
            out = subprocess.run(["ps", "-E", "-ww", "-A", "-o", "pid=,command="],
                                 capture_output=True, text=True).stdout
            pids = []
            for line in out.splitlines():
                pid, _, rest = line.strip().partition(" ")
                if pid.isdigit() and \
                        re.search(re.escape(mark) + r"(\s|$)", rest):
                    pids.append(int(pid))
            return pids
        found = strays()
        for sig in (signal.SIGTERM, signal.SIGKILL):
            if not found:
                return []
            log(f"{sig.name} {len(found)} process(es) still carrying {mark}: {found}")
            for pid in found:
                try:
                    os.kill(pid, sig)
                except ProcessLookupError:
                    pass
            time.sleep(1.0)
            found = strays()
        return found

    def teardown(self) -> None:
        """Reap every child and close every fd, on success, failure and timeout alike.

        The command's process group first (the app is what talks to the stubs), then the
        stubs, then fds: closing the masters first hands the stub an EOF it reports as a
        coordinator that gave up, which would bury the real reason the run ended. Then
        this run's regtest node, and last the per-run app database and backup sheets.
        """
        # One signal at a time from here on: a second ^C must not cut teardown short.
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(sig, signal.SIG_IGN)
        cmd_left = self.stop_command()
        for child in self.children:
            if child.poll() is None:
                child.terminate()
        deadline = time.monotonic() + 3.0
        for child in self.children:
            try:
                child.wait(timeout=max(0.0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                log(f"pid {child.pid} ignored SIGTERM; SIGKILL")
                child.kill()
                child.wait()
        for fd in self.masters + self.slaves:
            try:
                os.close(fd)
            except OSError:
                pass
        self.masters.clear()
        self.slaves.clear()
        # A stale manifest would point the next app run at dead ptys, which looks
        # like a transport bug rather than a leftover file.
        for path in (self.manifest, self.restart_snapshot):
            try:
                os.remove(path)
            except FileNotFoundError:
                pass
        regtest_ok = self.stop_regtest()
        # The app's sqlite/bdk files and the synthetic backup words are this run's alone.
        for d in ("app-dir", "sheets"):
            shutil.rmtree(os.path.join(self.outdir, d), ignore_errors=True)
        alive = [c.pid for c in self.children if c.poll() is None] + cmd_left
        alive += self.reap_env_strays()
        log(f"teardown: reaped {[c.returncode for c in self.children]}, "
            f"command group {'gone' if not cmd_left else cmd_left}, "
            f"regtest {'down' if regtest_ok else 'NOT DOWN'}, "
            f"{len(alive)} still alive, all fds closed")
        if alive or not regtest_ok:
            log(f"FAIL ORPHANS: {alive}" if alive else "FAIL regtest node not stopped")
            sys.exit(4)
        if shutil.which("pgrep"):
            # Orphans from an EARLIER run (a SIGKILLed rig cannot reap its children;
            # the stub's own watchdog is the backstop). Reported, not fatal: another
            # rig may legitimately be running.
            stray = subprocess.run(["pgrep", "-f", "examples/stub"],
                                   capture_output=True, text=True).stdout.split()
            if stray:
                log(f"NOTE {len(stray)} other examples/stub process(es) on this machine: {stray}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-n", "--devices", type=int, default=3,
                    help="virtual devices, one pty and one process each (default 3, a 2-of-3)")
    ap.add_argument("--stub", default=DEFAULT_STUB, help="stub binary (default: %(default)s)")
    ap.add_argument("--dir", default=DEFAULT_DIR, help="rig output dir (default: %(default)s)")
    ap.add_argument("--timeout", type=float, default=900.0,
                    help="seconds for the command, or to hold the rig open (default 900)")
    ap.add_argument("--id-timeout", type=float, default=30.0,
                    help="seconds to wait for each device to announce (default 30)")
    ap.add_argument("--salt-base", type=lambda s: int(s, 0), default=0x10,
                    help="STUB_SALT of device 0; device i gets base+i (default 0x10)")
    ap.add_argument("--image", default=DEFAULT_IMAGE,
                    help="image whose `firmware_digest` every device ANNOUNCES "
                         "(default: task 01's packaged artifact, %(default)s). "
                         "`--image ''` announces the stub's synthetic digest instead, which the "
                         "app identifies as Unrecognized -- useful for testing that refusal, "
                         "useless for a keygen.")
    ap.add_argument("--decline-signing", type=int, action="append", default=[], metavar="N",
                    help="device N presses `x` at every signing screen (repeatable). Its keygen "
                         "and restoration consent are unaffected, so it can hold a share and "
                         "still refuse to sign with it.")
    ap.add_argument("--lose-first-share", type=int, action="append", default=[], metavar="N",
                    help="device N signs its first signature request and drops the reply "
                         "before the wire (repeatable), so a replug + re-send is driven.")
    ap.add_argument("--erase", type=int, action="append", default=[], metavar="N",
                    help="device N declines its first erase question and approves its "
                         "second (repeatable); every other device declines every one.")
    ap.add_argument("--erase-cut", action="append", default=[], metavar="N[:KEYS]",
                    help="device N approves its erase questions in turn, each cut by a "
                         "power loss at the point its KEYS letter names (p before the "
                         "commit, c after it, a with the ack in RAM, f in finish; "
                         "default c); boot recovery finishes a committed one (repeatable).")
    ap.add_argument("--app-restart", action="store_true",
                    help="run the command TWICE against the same stubs and the same app dir: "
                         "COLDSNAP_RIG_APP_RUN=1, then, once its whole process group is gone, "
                         "COLDSNAP_RIG_APP_RUN=2 -- a new app process reloading what the first "
                         "persisted. Exit 6 unless the second recorded that it did.")
    ap.add_argument("--force-duplicate-identities", action="store_true",
                    help="MUTATION PROBE: give every device the same salt. The rig must "
                         "then fail with exit 3; if it exits 0 the identity check is dead.")
    ap.add_argument("command", nargs=argparse.REMAINDER,
                    help="after --, the command to run with the rig up")
    args = ap.parse_args()
    # Relative would resolve against the Flutter test's cwd (frostsnapp/), leaking its
    # app-dir there where teardown, which resolves against ours, never looks.
    args.dir = os.path.abspath(args.dir)

    if args.devices < 1 or args.devices > 12:
        # 12 is the declared envelope (`MAX_PARTIES`, DECISIONS.md 7). Above it the
        # device REFUSES, which is correct behaviour and not something to test here.
        log(f"FAIL --devices {args.devices} outside 1..12 (the declared envelope)")
        return 2
    decline = set(args.decline_signing)
    outside = sorted(i for i in decline if not 0 <= i < args.devices)
    if outside:
        log(f"FAIL --decline-signing {outside} names no device (0..{args.devices - 1})")
        return 2
    lose = set(args.lose_first_share)
    if any(not 0 <= i < args.devices for i in lose):
        log(f"FAIL --lose-first-share {sorted(lose)} names no device (0..{args.devices - 1})")
        return 2
    erase = set(args.erase)
    if any(not 0 <= i < args.devices for i in erase):
        log(f"FAIL --erase {sorted(erase)} names no device (0..{args.devices - 1})")
        return 2
    erase_cut: dict[int, str] = {}
    for spec in args.erase_cut:
        n, _, keys = spec.partition(":")
        keys = keys or "c"
        if not n.isdigit() or int(n) in erase_cut or keys.strip("pcaf"):
            log(f"FAIL --erase-cut {spec!r}: want N[:KEYS], KEYS from p c a f, N once")
            return 2
        erase_cut[int(n)] = keys
    if any(not 0 <= i < args.devices for i in erase_cut) or erase_cut.keys() & erase:
        log(f"FAIL --erase-cut {sorted(erase_cut)} names no device (0..{args.devices - 1}) "
            f"or one --erase already scripts")
        return 2
    if args.image and not os.path.isfile(args.image):
        # NOT a silent fallback to the synthetic digest: that would make every device
        # `Unrecognized`, and the app would refuse the keygen for a reason three layers
        # away from the missing file.
        log(f"FAIL no image at {args.image}; build task 01's package, or pass --image '' "
            f"to announce the stub's synthetic digest on purpose")
        return 2
    refuse_if_stale(args.stub)
    # Before ANYTHING in the rig dir is touched: the sheets rmtree below and the test's
    # app-dir wipe are exactly what destroyed a concurrent run's state.
    os.makedirs(os.path.dirname(LOCK), exist_ok=True)
    lock = open(LOCK, "a+")  # held (never closed) until this process exits
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lock.seek(0)
        log(f"FAIL LOCKED: another rig run holds {LOCK} ({lock.read().strip() or 'pid unknown'}); "
            "refusing to share its dir, app build or regtest node")
        return 2
    lock.truncate(0)
    lock.write(f"pid {os.getpid()}, dir {os.path.abspath(args.dir)}\n")
    lock.flush()
    os.makedirs(args.dir, exist_ok=True)
    # A sheet from a PREVIOUS run is a share for a wallet this run has not created, and
    # `sheet_write` refuses to overwrite one -- so a leftover would fail the next
    # reveal rather than corrupt it, which is the right direction but a confusing
    # message. Cleared here, where the reason is visible.
    shutil.rmtree(os.path.join(args.dir, "sheets"), ignore_errors=True)
    cmd = [x for x in args.command if x != "--"]

    rig = Rig(args.dir)
    # SIGTERM/SIGINT/SIGHUP must run `finally`, not skip it, or the children outlive us.
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, lambda s, _f: sys.exit(128 + s))
    try:
        rig.open_ptys(args.devices)
        rig.write_manifest()
        log(f"manifest {rig.manifest}: {rig.paths}")
        # The stub's own watchdog is 240 s x this. One lap past everything this rig will
        # wait for, so the rig's `--timeout` stays the bound that fires first and the
        # watchdog stays the backstop for a rig that was SIGKILLed and cannot reap.
        watchdog_scale = max(1, int((args.timeout + args.id_timeout) // 240) + 1)
        rig.spawn(args.stub, args.salt_base, args.force_duplicate_identities,
                  args.image, decline, watchdog_scale, lose, erase, erase_cut)
        rig.await_identities(args.id_timeout)
        if not cmd:
            log(f"rig up; holding for {args.timeout:g}s (^C to stop). "
                f"Point the app at {rig.manifest}")
            deadline = time.monotonic() + args.timeout
            while time.monotonic() < deadline:
                rig.check_children_alive()
                time.sleep(0.5)
            return 0
        env = dict(os.environ)
        env["FROSTSNAP_TEST_SERIAL_PORTS"] = rig.manifest
        env["COLDSNAP_RIG_DIR"] = args.dir
        env["COLDSNAP_RIG_RUN_TOKEN"] = rig.run_token
        env["COLDSNAP_REPO"] = REPO
        # The test's `regtest.py up`/`down` inherit this, so the node lives under this
        # rig's dir and `Rig.stop_regtest` stops the same one.
        env["COLDSNAP_REGTEST_DATADIR"] = rig.regtest
        # Which devices will refuse to sign, by rig index. The app-side test needs it to
        # know which `DeviceId` to expect no share from -- and reading it from here rather
        # than hardcoding an index is what lets `--decline-signing` move.
        env["COLDSNAP_RIG_DECLINE_SIGNING"] = ",".join(str(i) for i in sorted(decline))
        env["COLDSNAP_RIG_LOSE_FIRST_SHARE"] = ",".join(str(i) for i in sorted(lose))
        env["COLDSNAP_RIG_ERASE"] = ",".join(str(i) for i in sorted(erase))
        env["COLDSNAP_RIG_ERASE_CUT"] = ",".join(f"{i}:{k}" for i, k in sorted(erase_cut.items()))
        deadline = time.monotonic() + args.timeout
        runs = ["1", "2"] if args.app_restart else [None]
        for run in runs:
            if run is not None:
                env["COLDSNAP_RIG_APP_RUN"] = run
            log(f"running{f' (app run {run})' if run else ''}: {' '.join(cmd)}")
            # Popen, not `run`, so a dead stub is caught WHILE the command runs. It used to be
            # checked only after: a device that died mid-suite then showed up as a workflow
            # that stalled until the command's own timeout, with the real cause 10 minutes
            # back in a log. A stub that died is a failure even if the command later passes.
            # start_new_session: its own process group (and session, so a terminal ^C reaches
            # the rig, which then tears the group down in order, not every process at once).
            proc = rig.cmd = subprocess.Popen(cmd, env=env, start_new_session=True)
            try:
                while True:
                    try:
                        code = proc.wait(timeout=0.5)
                        break
                    except subprocess.TimeoutExpired:
                        pass
                    rig.check_children_alive()
                    if time.monotonic() > deadline:
                        log(f"FAIL TIMEOUT: command outlived --timeout {args.timeout:g}s")
                        return 5
            finally:
                # The whole group, not the leader: an exited leader can leave children.
                left = rig.stop_command()
            rig.check_children_alive()
            log(f"command exited {code}")
            if code != 0:
                return code
            if run == "1":
                # THE RESTART. Every process the first run started -- flutter, flutter_tools,
                # the macOS test app -- is gone before the second starts; the stubs, their
                # FakeFlash and the regtest node stay up, and the app dir is not touched.
                if left:
                    log(f"FAIL APP DID NOT STOP before the restart: {left} still in its group")
                    return 4
                log("app restart: first app process group gone; stubs "
                    f"{[c.pid for c in rig.children]} still up; same app dir")
        if args.app_restart:
            try:
                with open(rig.restart_snapshot) as fh:
                    snap = json.load(fh)
            except (OSError, ValueError) as err:
                snap = {"error": str(err)}
            if not snap.get("reloadedByPid") or snap.get("reloadedByPid") == snap.get("pid"):
                log(f"FAIL APP RESTART UNVERIFIED: {rig.restart_snapshot} has no second-process "
                    f"countersignature ({snap})")
                return 6
            log(f"app restart verified: pid {snap['pid']} persisted, pid "
                f"{snap['reloadedByPid']} reloaded and signed")
        return code
    finally:
        rig.teardown()


if __name__ == "__main__":
    sys.exit(main())

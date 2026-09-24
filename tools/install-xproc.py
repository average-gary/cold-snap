#!/usr/bin/env python3
"""Task 07 x task 06, across processes, on a pty. No device, no callgate.

Process A: task 06's `coldsnap-mk4-update --port <pty slave> <key-0 artifact>`.
Process B: cold-snap's ignored lib test
  `install::tests::task06_updater_stages_across_processes_then_one_install_request_each_path`,
  handed the pty MASTER as COLDSNAP_WIRE_FD. It stages through `upgrade::serve`, then runs
  `Workflow::begin/setup/confirm/[submit_pin]/request_install` on that Stager against the
  strict FakeGate with approved[0] = key 0's public half.

Passes only if A exits 0 reporting STAGED + NOT installed, B exits 0, and B's two XPROC lines
(blank PIN, PIN set) each show one request for A's length and A's digest. Anything missing
is a failure, never a skip. Run with target/pack-venv/bin/python (needs `ecdsa`).
Logs: target/software-only/logs/07-r2/xproc-*.log
"""
import json, os, re, subprocess, sys, tty
from pathlib import Path

HOME = Path(os.environ["HOME"])
CS = HOME / "repos/cold-snap"
FS = HOME / "repos/frostsnap"
PEM = HOME / "repos/coldcard-firmware/stm32/keys/00.pem"  # read only
ART = CS / "target/software-only/package/firmware-signed.bin"
LOGS = CS / "target/software-only/logs/07-r2"
TEST = "install::tests::task06_updater_stages_across_processes_then_one_install_request_each_path"
TGT = "aarch64-apple-darwin"


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def main():
    import ecdsa

    LOGS.mkdir(parents=True, exist_ok=True)
    if not ART.is_file():
        fail(f"missing artifact {ART}")
    key0 = ecdsa.SigningKey.from_pem(PEM.read_text()).get_verifying_key().to_string("compressed").hex()

    r = subprocess.run(["cargo", "build", "--target", TGT, "-p", "frostsnap_coordinator",
                        "--bin", "coldsnap-mk4-update"], cwd=FS)
    if r.returncode:
        fail(f"building the task-06 CLI exited {r.returncode}")
    cli = FS / f"target/{TGT}/debug/coldsnap-mk4-update"

    r = subprocess.run(["cargo", "test", "--no-run", "--message-format=json", "--target", TGT,
                        "-p", "coldsnap_firmware", "--lib", "--features",
                        "coldsnap_hal/fake-flash,coldsnap_hal/test-seam"],
                       cwd=CS, capture_output=True, text=True)
    if r.returncode:
        fail(f"building the controller test exited {r.returncode}\n{r.stderr[-2000:]}")
    exes = [m["executable"] for m in map(json.loads, r.stdout.splitlines())
            if m.get("reason") == "compiler-artifact" and m.get("executable")
            and m["target"]["name"] == "coldsnap_firmware"]
    if len(exes) != 1:
        fail(f"expected one lib test executable, got {exes}")

    master, slave = os.openpty()
    tty.setraw(slave)
    path = os.ttyname(slave)
    blog = open(LOGS / "xproc-controller.log", "w")
    b = subprocess.Popen([exes[0], "--ignored", "--exact", TEST, "--nocapture"], cwd=CS,
                         env={**os.environ, "COLDSNAP_WIRE_FD": str(master),
                              "COLDSNAP_XPROC_LEN": str(ART.stat().st_size),
                              "COLDSNAP_KEY0_PUB": key0},
                         pass_fds=(master,), stdout=blog, stderr=subprocess.STDOUT)
    os.close(master)  # B holds the only master
    a = subprocess.run([str(cli), "--port", path, str(ART)], cwd=CS, capture_output=True,
                       text=True, timeout=120)
    (LOGS / "xproc-updater.log").write_text(a.stdout + a.stderr)
    try:
        bcode = b.wait(timeout=60)
    except subprocess.TimeoutExpired:
        b.kill()
        b.wait()
        fail("controller test did not finish")
    finally:
        os.close(slave)
        blog.close()
    said = a.stdout + a.stderr
    btext = (LOGS / "xproc-controller.log").read_text()
    print(f"updater exit={a.returncode} controller-test exit={bcode}")
    m = re.search(r"STAGED (\d+) bytes, digest ([0-9a-f]{64})", said)
    if a.returncode != 0 or not m or "NOT installed" not in said:
        fail(f"updater did not report STAGED/NOT installed:\n{said}")
    size, digest = int(m.group(1)), m.group(2)
    if bcode != 0:
        fail(f"controller test exited {bcode}:\n{btext[-3000:]}")
    rows = re.findall(r"XPROC pin=(true|false) requests=1 start=0 len=(\d+) digest=([0-9a-f]{64})", btext)
    if sorted(p for p, _, _ in rows) != ["false", "true"]:
        fail(f"expected one XPROC row per PIN path, got {rows}")
    for p, ln, d in rows:
        if int(ln) != size or d != digest:
            fail(f"pin={p}: controller len/digest {ln}/{d} != updater {size}/{digest}")
    print(f"PASS: updater staged {size} B digest {digest}; controller made exactly one fake "
          f"install request per PIN path for that image (fake gate, not an installation)")


if __name__ == "__main__":
    main()

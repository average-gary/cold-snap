#!/usr/bin/env python3
"""regtest — a disposable Bitcoin Core regtest node, as a second opinion on a signature.

WHAT THIS IS FOR, and what it is NOT. The app rig's pass criterion is the deterministic
chain fixture plus the independent sighash recomputation in
`frostsnap/frostsnapp/rust/src/test_chain.rs`. This is CORROBORATION on top of that: Core
runs its own consensus signature check, so a transaction that both `verify_taproot_key_spends`
and `testmempoolaccept` accept has been checked by two implementations of BIP-341 instead of
one. Its absence is a recorded gap, never a pass, and it replaces nothing.

REGTEST ONLY, and on a datadir created and destroyed here, under an ignored `target/` path.
Every invocation passes `-regtest -datadir=...` explicitly: no default datadir is read or
written, no other network is reachable, and nothing is ever broadcast anywhere. The node also
runs with listening, discovery and DNS seeding off, so it has no peers to broadcast to.

In this Core build the daemon is `bitcoin-node`, not `bitcoind` (multi-binary layout).

Usage:
    tools/regtest.py up                       # start the node, mature 101 blocks
    tools/regtest.py newaddress               # a FOREIGN address to send to
    tools/regtest.py fund <address> <btc>     # pay it, confirm it, print the raw tx hex
    tools/regtest.py accept <raw-tx-hex>      # testmempoolaccept; exit 0 only if allowed
    tools/regtest.py down                     # stop the node and delete the datadir

`fund` prints ONLY the transaction hex on stdout, so it can be piped straight into
`SuperWallet::test_inject_funding(.., Some(hex))`: injecting a real regtest transaction is
what makes the prevout Core needs actually exist, so a later `accept` of the app's spend is a
statement about the signature and not about missing inputs.

Exit codes:
    0   the subcommand did what it says
    2   precondition failed (no Core binaries, or the node is not up)
    3   `accept` ran and Core REJECTED the transaction (the interesting failure)
    4   the node would not start, or a bitcoin-cli call failed
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.expanduser("~/repos/implementations/bitcoin-v31.1/build/bin")
NODE = os.path.join(BIN, "bitcoin-node")
CLI = os.path.join(BIN, "bitcoin-cli")
# Ignored, and disposable: `down` deletes it outright. `tools/app-rig.py` points each rig
# run at its OWN datadir and RPC port (under its locked rig dir) through these variables, so
# two rigs cannot share, adopt or stop each other's node.
DATADIR = os.environ.get(
    "COLDSNAP_REGTEST_DATADIR", os.path.join(REPO, "target/software-only/regtest")
)
# Not Core's regtest default (18443), so a node someone else left running cannot be
# mistaken for this one -- the port clash fails loudly instead.
RPC_PORT = os.environ.get("COLDSNAP_REGTEST_RPCPORT", "18449")
WALLET = "rig"
# EVERY wait here is bounded. The app-side caller is a blocking `Process.runSync`, so an
# unbounded call here would also stop the Dart test's own timeout from ever firing.
CLI_TIMEOUT = 60
START_TIMEOUT = 120
STOP_WAIT = 30


def die(code: int, why: str) -> None:
    print(f"regtest.py: {why}", file=sys.stderr)
    sys.exit(code)


def run(argv: list[str], timeout: float) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        die(4, f"TIMEOUT after {timeout:g}s: {' '.join(argv[:1] + argv[4:5])}")
        raise  # unreachable; `die` exits


def cli_argv(*args: str) -> list[str]:
    return [
        CLI,
        "-regtest",
        f"-datadir={DATADIR}",
        f"-rpcport={RPC_PORT}",
        f"-rpcclienttimeout={CLI_TIMEOUT}",
        *args,
    ]


def cli(*args: str, check: bool = True) -> str:
    """A bitcoin-cli call against THIS datadir. Cookie auth, so no credentials anywhere."""
    proc = run(cli_argv(*args), CLI_TIMEOUT + 5)
    if proc.returncode != 0:
        if check:
            die(4, f"bitcoin-cli {' '.join(args[:1])} failed: {proc.stderr.strip()}")
        # Not fatal, but never silent: an unparseable answer below should be diagnosable
        # without re-running by hand.
        print(f"regtest.py: bitcoin-cli {args[0]}: {proc.stderr.strip()}", file=sys.stderr)
    return proc.stdout.strip()


def wallet_cli(*args: str) -> str:
    return cli(f"-rpcwallet={WALLET}", *args)


def is_up() -> bool:
    """A probe, so a SHORT bound and never fatal: an RPC that accepts and never answers is
    "not up" here, and `down` then falls back to signalling the PID."""
    argv = cli_argv("getblockcount")
    argv[4] = "-rpcclienttimeout=10"
    try:
        return subprocess.run(argv, capture_output=True, timeout=15).returncode == 0
    except subprocess.TimeoutExpired:
        return False


def up() -> int:
    for path in (NODE, CLI):
        if not os.access(path, os.X_OK):
            die(2, f"{path} is not executable; Bitcoin Core v31.1 is expected under {BIN}")
    # A node already on THIS datadir is not adopted: it is a leftover (or another run's),
    # and adopting it is how one run's `down` used to stop another run's node.
    if node_pids() or is_up():
        die(2, f"a node is already running on {DATADIR} (pids {node_pids()}); "
               "run `tools/regtest.py down` first")
    os.makedirs(DATADIR, exist_ok=True)
    # -daemonwait: the call returns only once the RPC server is answering, so there is no
    # poll-and-hope window. -listen/-discover/-dnsseed off: no peers, nothing to broadcast to.
    try:
        proc = subprocess.run(
            [
                NODE,
                "-regtest",
                f"-datadir={DATADIR}",
                f"-rpcport={RPC_PORT}",
                "-daemonwait",
                # 127.0.0.1 only, which is all bitcoin-cli dials: without it a port held on
                # 127.0.0.1 leaves the node half-bound on ::1, "up" but unreachable, instead
                # of failing to start.
                "-rpcbind=127.0.0.1",
                "-rpcallowip=127.0.0.1",
                "-listen=0",
                "-discover=0",
                "-dnsseed=0",
                "-fallbackfee=0.0002",
            ],
            capture_output=True,
            text=True,
            timeout=START_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        # -daemonwait never came back, but the node it forked may be running: stop it
        # rather than leave it holding the datadir.
        kill_node()
        die(4, f"TIMEOUT: bitcoin-node -daemonwait did not return in {START_TIMEOUT}s")
    if proc.returncode != 0:
        kill_node()
        die(4, f"bitcoin-node would not start: {proc.stdout.strip()} {proc.stderr.strip()}")
    # From here on a node of ours is running, so a failure must not leave it behind: `die`
    # is a SystemExit, and it is intercepted to stop the node first.
    try:
        if WALLET not in json.loads(cli("listwallets")):
            if not os.path.isdir(os.path.join(DATADIR, "regtest/wallets", WALLET)):
                cli("createwallet", WALLET)
            else:
                cli("loadwallet", WALLET)
        # 101 blocks: coinbase maturity is 100, so exactly one spendable coinbase.
        if int(wallet_cli("getblockcount")) < 101:
            wallet_cli("generatetoaddress", "101", wallet_cli("getnewaddress"))
    except SystemExit:
        kill_node()
        raise
    print(f"up, height {cli('getblockcount')}, datadir {DATADIR}", file=sys.stderr)
    return 0


def fund(address: str, btc: str) -> int:
    if not is_up():
        die(2, "node is not up; run `tools/regtest.py up` first")
    txid = wallet_cli("sendtoaddress", address, btc)
    # Read the raw transaction while it is still in the mempool: once it is buried in a block
    # `getrawtransaction` needs -txindex or the block hash, and neither is worth carrying.
    raw = cli("getrawtransaction", txid)
    # Confirm it, so the coin is a settled prevout rather than a mempool entry.
    wallet_cli("generatetoaddress", "1", wallet_cli("getnewaddress"))
    print(raw)
    return 0


def newaddress() -> int:
    """A FOREIGN address — Core's, not the app wallet's. The app rig sends to one so the
    signing screen has a recipient row to read back off the glass, and so the transaction
    pays somebody rather than only itself."""
    if not is_up():
        die(2, "node is not up; run `tools/regtest.py up` first")
    print(wallet_cli("getnewaddress"))
    return 0


def accept(raw_hex: str) -> int:
    if not is_up():
        die(2, "node is not up; run `tools/regtest.py up` first")
    # check=False: a rejected transaction is this script's whole point, not a crash.
    out = cli("testmempoolaccept", json.dumps([raw_hex]), check=False)
    try:
        result = json.loads(out)[0]
    except (json.JSONDecodeError, IndexError, KeyError):
        die(4, f"testmempoolaccept gave no usable answer: {out!r}")
    if result.get("allowed"):
        print(f"ACCEPTED by Bitcoin Core: {result.get('txid')}", file=sys.stderr)
        return 0
    print(
        f"REJECTED by Bitcoin Core: {result.get('reject-reason', '(no reason given)')}",
        file=sys.stderr,
    )
    return 3


def node_pids() -> list[str]:
    """Our node only. The datadir path is unique to this script, so this cannot match the
    node someone has running on another network."""
    # No leading dash in the pattern: `pgrep -f -datadir=...` parses it as options and
    # matches nothing, which silently makes the wait below a no-op.
    # Anchored at the end, so `.../regtest` cannot match a sibling `.../regtest2`.
    ere = re.sub(r"([.^$*+?()\[\]{}|\\])", r"\\\1", DATADIR)  # POSIX ERE, not Python re
    proc = run(["pgrep", "-f", f"datadir={ere}( |$)"], 10)
    return [line for line in proc.stdout.split() if line.isdigit()]


def wait_gone(seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if not node_pids():
            return True
        time.sleep(0.1)
    return not node_pids()


def kill_node() -> None:
    """The fallback when the RPC cannot stop it: we know the PID, so signal it. SIGTERM is
    Core's own clean shutdown; SIGKILL only if that is ignored."""
    for sig in (signal.SIGTERM, signal.SIGKILL):
        for pid in node_pids():
            try:
                os.kill(int(pid), sig)
            except ProcessLookupError:
                pass
        if wait_gone(STOP_WAIT):
            return


def down() -> int:
    if is_up():
        cli("stop", check=False)
    # Wait for the PROCESS to exit, not for the RPC to stop answering: `stop` shuts the RPC
    # server down first and returns immediately, so the node is still flushing its datadir
    # for a second or so afterwards. Deleting it out from under a live node is how a `down`
    # leaves a half-written directory and a process still holding it.
    if not wait_gone(STOP_WAIT):
        print(f"regtest.py: node {node_pids()} ignored `stop`; signalling it", file=sys.stderr)
        kill_node()
    if node_pids():
        die(4, f"node {node_pids()} did not exit even on SIGKILL; datadir left in place")
    shutil.rmtree(DATADIR, ignore_errors=True)
    print(f"down, {DATADIR} removed", file=sys.stderr)
    return 0


def main() -> int:
    args = sys.argv[1:]
    if not args:
        die(2, __doc__.split("Usage:")[1].strip())
    cmd, rest = args[0], args[1:]
    if cmd == "up" and not rest:
        return up()
    if cmd == "newaddress" and not rest:
        return newaddress()
    if cmd == "fund" and len(rest) == 2:
        return fund(*rest)
    if cmd == "accept" and len(rest) == 1:
        return accept(rest[0])
    if cmd == "down" and not rest:
        return down()
    die(2, f"unknown or misused subcommand: {' '.join(args)}")
    return 2


if __name__ == "__main__":
    sys.exit(main())

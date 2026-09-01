#!/usr/bin/env bash
# Run Coldcard's unix/simulator.py window with OUR firmware example as the child.
#
# simulator.py:902 does `cwd = os.getcwd()` BEFORE it chdirs (:911/:924), and then
# builds `cwd/coldcard-mpy` (:904) and `cwd/sim_boot.py` (:905). So we never touch
# the Coldcard repo: we assemble a scratch directory of symlinks, cd into it, and
# run THEIR script from THERE. Their tree stays byte-identical, so there is nothing
# to restore and no trap to get wrong.
#
# The child is `firmware/examples/simulator.rs` -- the SAME example, and the same
# scenes, that `cargo run ... --example simulator` prints as ASCII. It switches to
# the pipe protocol when it finds simulator.py's four fds on its argv; see `sim_fds`
# there. Its stdout is /dev/null under xterm (:974), so its banner, its startup
# self-checks and one line per keypress go to $SCRATCH/child.log.
#
#   tools/sim-window.sh              scenes, as before: no device, nothing live
#   tools/sim-window.sh --relay      the child relays a LIVE session's frames instead
#   tools/sim-window.sh --self-test  8s windowless run, four assertions, no human
#
# --relay just exports COLDSNAP_GLASS_SOCKET (see below). The two compose: --self-test
# --relay checks the child still exits on numpad EOF while it is waiting for a device.
#
# Snapshots (ctrl-Z) and movies (ctrl-E) land in $SCRATCH/sim, not in the Coldcard
# repo, because simulator.py writes them relative to its cwd -- which is our
# scratch dir. So `--segregate` is not needed and is not passed.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CC="${COLDCARD_REPO:-$REPO/../coldcard-firmware}"
SCRATCH="${COLDSNAP_SIM_SCRATCH:-/tmp/coldsnap-sim}"
PY="${COLDSNAP_SIM_PYTHON:-python3}"

die() { printf '\nsim-window: %s\n\n' "$1" >&2; exit 1; }

[ -f "$CC/unix/simulator.py" ] || die "no simulator.py under '$CC/unix'.
Point COLDCARD_REPO at a checkout of https://github.com/Coldcard/firmware
(read-only: this script never writes to it)."

"$PY" - <<'EOF' 2>/dev/null || die "$(cat <<'MSG'
the python at COLDSNAP_SIM_PYTHON is missing PySDL2 / numpy / Pillow.
simulator.py needs all three (numpy is NOT in their requirements.txt, but
sdl2.ext.pixels2d refuses to run without it). Set one up once:

    brew install sdl2                     # already present if `brew list sdl2` works
    python3 -m venv ~/.venv/coldcard-sim
    ~/.venv/coldcard-sim/bin/pip install PySDL2 numpy Pillow

then re-run with:
    COLDSNAP_SIM_PYTHON=~/.venv/coldcard-sim/bin/python3 tools/sim-window.sh

XQuartz is NOT required: this SDL2 build has drivers cocoa/offscreen/dummy only.
MSG
)"
import sdl2, sdl2.ext, numpy, PIL
EOF

SELFTEST=0
RELAY="${COLDSNAP_GLASS_SOCKET:-}"
while :; do
    case "${1:-}" in
    --self-test) SELFTEST=1; shift ;;
    # RELAY MODE: hand the child a socket path and it stops being a scene player --
    # frames come from a LIVE session in another process (hostcheck's stub, driven by a
    # real coordinator) and keys go back to it. LIVE-GLASS-PLAN §3.
    #
    # A path, because an fd cannot get there: the coordinator side must hold the pty
    # MASTER (FIONREAD on a darwin master always returns 0), a master has no name, and
    # simulator.py spawns its child with a fixed pass_fds list. The path travels as an
    # env var because simulator.py copies os.environ into the child (:851, :970), so
    # THEIR TREE IS STILL NOT TOUCHED -- no patch, no argv splicing, nothing to restore.
    #
    # Default path lives in $SCRATCH, which this script clears on every run, so the
    # stale-socket case the child refuses to bind cannot survive a restart.
    --relay)
        shift
        case "${1:-}" in ''|-*) ;; *) RELAY="$1"; shift ;; esac
        RELAY="${RELAY:-$SCRATCH/glass.sock}"
        ;;
    *) break ;;
    esac
done
if [ -n "$RELAY" ]; then
    export COLDSNAP_GLASS_SOCKET="$RELAY"
    # Only ever a socket, never a regular file: the child BINDS this path, and a
    # leftover from a killed window would make it refuse to start.
    if [ -S "$RELAY" ]; then rm -f "$RELAY"; fi
fi

BIN="${COLDSNAP_SIM_BIN:-}"
if [ -z "$BIN" ]; then
    BIN="$REPO/target/aarch64-apple-darwin/debug/examples/simulator"
    ( cd "$REPO" && cargo build --target aarch64-apple-darwin -p coldsnap_firmware \
        --features coldsnap_hal/test-seam --example simulator )
fi
[ -x "$BIN" ] || die "child binary '$BIN' is not executable."

# scratch dir: exactly what simulator.py opens by relative path.
#   ../shared/charcodes.py  is loaded at import time (:561), hence the extra level
rm -rf "$SCRATCH"
mkdir -p "$SCRATCH/sim/work" "$SCRATCH/bin"
ln -s "$CC/shared"                 "$SCRATCH/shared"
ln -s "$CC/unix/mk4-images"        "$SCRATCH/sim/mk4-images"
ln -s "$CC/unix/program-icon.png"  "$SCRATCH/sim/program-icon.png"
ln -s "$CC/unix/sim_boot.py"       "$SCRATCH/sim/sim_boot.py"
ln -s "$BIN"                       "$SCRATCH/sim/coldcard-mpy"

# simulator.py:972 wraps the child in `xterm ... -e <cmd>` for its REPL console.
# xterm is X11 and is not installed; our child has no REPL. Shim it: strip xterm's
# own args and exec the real command, whose stdout is the log below.
#
# `exec` is load-bearing, not style. Closing the window (or ctrl-Q, or a SIGTERM,
# which SDL turns into an SDL_QUIT event) makes simulator.py leave its loop and call
# `xterm.kill()` (:1157) -- a SIGKILL at the shim's pid. With `exec` that pid is the
# child itself, so the window's quit button reliably reaps it. A shim that forked
# instead would eat the kill and leave the child running. (Measured: with `exec`,
# TERM to the parent kills the child via that route; KILL to the parent, which SDL
# cannot intercept, instead closes numpad_w and the child exits on read == 0.)
# ponytail: log file, not a terminal. Reopening /dev/tty here breaks when the
# launcher has no controlling tty; revisit only if someone wants interactive stdin.
cat > "$SCRATCH/bin/xterm" <<EOF
#!/bin/sh
while [ "\$1" != "-e" ]; do shift; done
shift
exec "\$@" >"$SCRATCH/child.log" 2>&1
EOF
chmod +x "$SCRATCH/bin/xterm"

printf 'child stdout/stderr -> %s\n' "$SCRATCH/child.log"
if [ -n "$RELAY" ]; then
    printf 'RELAY MODE: the child holds no Session; it listens on %s\n' "$RELAY"
    printf '            device side: COLDSNAP_GLASS_SOCKET=%s <coordinator harness>\n' "$RELAY"
fi
cd "$SCRATCH/sim"

if [ "$SELFTEST" = 1 ]; then
    # Run windowless for 8s with the REAL example as the child, then assert the
    # four things that can break without anyone noticing.
    set +e
    # `-s KILL --foreground`, both deliberate, MEASURED on this machine:
    #   * --foreground: without it `timeout` signals the whole process group and
    #     kills our child directly, which destroys the evidence check 4 wants.
    #   * -s KILL: SDL installs a SIGTERM handler that turns the signal into an
    #     SDL_QUIT event, so a plain TERM makes simulator.py leave its loop and reach
    #     `xterm.kill()` (:1157) -- which SIGKILLs US (the shim exec'd, so we are
    #     that pid). That is the normal interactive quit route and there is nothing
    #     of ours in it. SIGKILL to the parent is the OTHER route, the one that
    #     exercises our code: the parent vanishes, numpad_w closes, and our read
    #     must return 0. It is also what happens when the parent dies on its own
    #     1024-byte assert, where nothing kills us and an orphan is possible.
    PATH="$SCRATCH/bin:$PATH" SDL_VIDEODRIVER=dummy \
        timeout -s KILL --foreground 8 "$PY" "$CC/unix/simulator.py" --mk4 "$@" >"$SCRATCH/parent.log" 2>&1
    rc=$?
    set -e
    sleep 1
    # 1. our adapter started, passed its own startup self-checks and found the fds
    grep -q 'Display stream self-check passed' "$SCRATCH/child.log" \
        || { cat "$SCRATCH/parent.log" "$SCRATCH/child.log"; die "the child never got its fds (see child.log)"; }
    # 2. the parent decoded what we wrote: a split frame or a stray byte fires its
    #    `assert len(buf) == 1024` (simulator.py:461) and prints a traceback
    if grep -q 'Traceback\|AssertionError' "$SCRATCH/parent.log"; then
        cat "$SCRATCH/parent.log"; die "simulator.py raised -- bad frame, or the scratch dir is wrong"
    fi
    # 3. the parent survived the whole 8s (rc=137 is our SIGKILL at the deadline)
    [ "$rc" = 137 ] || { cat "$SCRATCH/parent.log"; die "simulator.py exited early (rc=$rc)"; }
    # 4. NO ORPHAN: the parent is dead, so the child's numpad read hit EOF and it
    #    exited on its own. (pattern, not full path: argv[0] arrives via /private/tmp)
    grep -q 'numpad EOF' "$SCRATCH/child.log" \
        || { tail -5 "$SCRATCH/child.log"; die "child did not exit on numpad EOF -- orphan risk"; }
    ! pgrep -f coldcard-mpy >/dev/null \
        || { pgrep -lf coldcard-mpy; die "ORPHANED child after the parent died"; }
    echo "self-test PASS: fds handed over, frames decoded by simulator.py, no orphan"
    exit 0
fi

PATH="$SCRATCH/bin:$PATH" exec "$PY" "$CC/unix/simulator.py" --mk4 "$@"

#!/bin/sh
# THE ONE COMMAND. Four virtual cold-snap devices on four pseudo-terminals, the real
# Flutter/Rust desktop app on the other end, and the automated workflow suite as the pass
# criterion — not a human watching a window.
#
#     tools/app-rig-test.sh                 # the whole thing
#     tools/app-rig-test.sh --devices 6     # any app-rig.py flag passes through
#
# Exit status is the rig's, which is the flutter test's unless the rig itself failed
# first: 2 precondition, 3 duplicate identity, 4 child failure, 5 timeout, 6 app restart
# unverified, 7 stub restart failed (`tools/app-rig.py --help`).
#
# THE APP IS RESTARTED ONCE (`--app-restart`): the test file runs as two separate app
# processes against the same app dir. Run 1 keygens, names, signs, restores and replugs;
# its whole process group is reaped; run 2 reloads the sqlite/bdk state from disk, checks
# it against what run 1 recorded, signs again, then erases.
#
# THE STUBS ARE RESTARTED TOO (`--stub-restart`), between the two app runs: each stub's
# FakeFlash is written through to `<rig dir>/flash/device-N.bin`, every stub process is
# stopped, and new ones (new pids) boot from those files. The rig exits 7 unless each
# reloaded its exact bytes and came back with the same DeviceId, name and share; run 2
# then signs with the restarted devices.
#
# WHY A SCRIPT AND NOT A `just` RECIPE: cold-snap has no justfile, and frostsnap's is
# uncommitted work in progress. One POSIX file beats introducing a build system for one
# command.
set -eu

REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
APP=${FROSTSNAP_REPO:-$HOME/repos/frostsnap}
TEST=integration_test/coldsnap_workflows_test.dart

# THE PINNED SDK, FIRST ON PATH AND VERIFIED. The system flutter on this machine is 3.35.1
# and `frostsnapp/.fvmrc` pins 3.38.5; a result from the wrong SDK is not a result for the
# pinned one. Checked rather than assumed, because a silent fallback is the failure mode.
PATH="$APP/frostsnapp/.fvm/flutter_sdk/bin:$PATH"
export PATH
want=$(sed -n 's/.*"flutter": *"\([^"]*\)".*/\1/p' "$APP/frostsnapp/.fvmrc")
got=$(flutter --version 2>/dev/null | sed -n '1s/^Flutter \([^ ]*\).*/\1/p')
if [ "$want" != "$got" ]; then
    echo "app-rig-test: .fvmrc pins Flutter $want but \`flutter\` is ${got:-unresolvable}" >&2
    echo "app-rig-test: $(command -v flutter)" >&2
    exit 2
fi
echo "app-rig-test: Flutter $got (pinned), $(command -v flutter)" >&2

# NO TRAP HERE: `exec` below replaces this shell, and a trap set before it never fires.
# Cleanup is app-rig.py's `Rig.teardown`, on every exit path it can catch (success,
# failure, timeout, SIGINT, SIGTERM, SIGHUP): it signals the command's whole process
# group, reaps the stubs, runs `regtest.py down` on the rig's own datadir, and removes the
# per-run app database and backup sheets.

# BUNDLE_FIRMWARE=0: zero bundled firmware is a supported configuration (a recognized Mk4
# is compatible with no Mk4 image in the app at all), not a compatibility bypass. There is
# no ESP32 device-firmware binary in this tree to bundle.
exec python3 "$REPO/tools/app-rig.py" \
    --devices 4 \
    --decline-signing 2 \
    --lose-first-share 3 \
    --erase 1 \
    --erase-cut 2:pc \
    --erase-cut 0:a \
    --erase-cut 3:f \
    --app-restart \
    --stub-restart \
    --timeout 1200 \
    "$@" \
    -- /bin/sh -c "cd '$APP/frostsnapp' && BUNDLE_FIRMWARE=0 exec flutter test $TEST -d macos"

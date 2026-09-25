#!/bin/sh
# usage: check-frostsnap-pin.sh FROSTSNAP_DIR [PIN_FILE]
#
# Compares a frostsnap checkout with the revision in hostcheck/frostsnap.rev.
#   exit 0  HEAD is the pin and the crates hostcheck compiles have no tracked edits
#   exit 3  HEAD descends from the pin, or those crates have tracked edits: every commit
#           cold-snap needs is present, but the code is not what was verified
#   exit 1  anything else, named: missing, not its own git repo, unreadable pin,
#           pin absent, HEAD older than the pin, or diverged from it
# build.rs turns 3 into cargo warnings and 1 into a build failure; the runner fails on both.
fs=$1
pinf=${2:-$(dirname "$0")/frostsnap.rev}
say() { printf 'FROSTSNAP PIN: %s\n' "$*"; }
fix() {
    say "fix: either move $fs to the pinned commit (git -C \"$fs\" checkout $pin)"
    say "     or, after hostcheck passes against HEAD, bump the pin: put $head (git -C \"$fs\" rev-parse HEAD) on the SHA line of hostcheck/frostsnap.rev (README \"Bumping the frostsnap pin\")"
}

pin=$(grep -v '^#' "$pinf" 2>/dev/null | tr -d ' \n')
case $pin in *[!0-9a-f]* | '') say "pin file $pinf unreadable or not a hex SHA: '$pin'"; exit 1 ;; esac
[ ${#pin} -eq 40 ] || { say "pin '$pin' in $pinf is not a 40-hex commit SHA"; exit 1; }

[ -n "$fs" ] && [ -d "$fs" ] || { say "frostsnap checkout missing: '$fs' (pinned $pin)"; exit 1; }
real=$(cd "$fs" && pwd -P)
top=$(git -C "$fs" rev-parse --show-toplevel 2>/dev/null)
[ -n "$top" ] || { say "$fs is not a git repository, so its revision is unknown (pinned $pin)"; exit 1; }
[ "$top" = "$real" ] || { say "$fs is not its own git checkout: it sits inside $top (pinned $pin)"; exit 1; }
head=$(git -C "$fs" rev-parse --verify -q HEAD) || { say "$fs has no HEAD commit (pinned $pin)"; exit 1; }

say "pinned $pin"
say "HEAD   $head ($fs)"
if [ "$head" != "$pin" ]; then
    if ! git -C "$fs" cat-file -e "$pin^{commit}" 2>/dev/null; then
        say "MISMATCH: pinned commit is not in this checkout"; fix; exit 1
    elif git -C "$fs" merge-base --is-ancestor "$pin" "$head"; then
        say "AHEAD: HEAD is $(git -C "$fs" rev-list --count "$pin..$head") commit(s) past the pin; hostcheck was not verified against them"
        fix; exit 3
    elif git -C "$fs" merge-base --is-ancestor "$head" "$pin"; then
        say "MISMATCH: HEAD is $(git -C "$fs" rev-list --count "$head..$pin") commit(s) OLDER than the pin; it lacks code hostcheck uses"
        fix; exit 1
    else
        say "MISMATCH: HEAD and the pin have diverged ($(git -C "$fs" rev-list --count "$pin..$head") vs $(git -C "$fs" rev-list --count "$head..$pin") commits)"
        fix; exit 1
    fi
fi
# ponytail: the path crates in hostcheck/Cargo.lock (frostsnap_macros lives in macros/) plus the
# workspace manifest they inherit from; extend when hostcheck gains a frostsnap crate.
crates="Cargo.toml frostsnap_coordinator frostsnap_core frostsnap_comms frost_backup macros"
# shellcheck disable=SC2086
dirty=$(git -C "$fs" diff --name-only HEAD -- $crates) || { say "git diff failed in $fs"; exit 1; }
dirty=$(printf '%s' "$dirty" | tr '\n' ' ')
[ -z "$dirty" ] || { say "EDITED: tracked edits in crates hostcheck compiles, so the build is not the pin: $dirty"; exit 3; }
say "OK: HEAD is the pin, crate sources unmodified"

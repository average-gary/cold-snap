#!/bin/bash
# ATTACK 1(a) provenance, 2026-08-20. Reproduces the two measured numbers behind
# "32 KiB of stack is not established as enough".
#
# NOTE ON RESOLUTION: macOS/aarch64 pages are 16 KiB and RLIMIT_STACK is rounded
# UP to a page, so `ulimit -s` has 16 KiB granularity here, not 1 KiB. Every
# value in 65..80 is the same 80 KiB stack. Hence the bracket, not a point.
#
#   heap_profile (keygen->nonces->sign, real FrostSigner): fails at 64 KiB,
#   passes at 65..96  =>  host peak stack in (64, 80] KiB.
#   hello-world floor: fails at 32, passes at 48 => process floor <= 48 KiB,
#   so the 64 KiB failure is the WORKLOAD, not dyld.
set -u
cd "$(dirname "$0")/../.."
BIN=./target/aarch64-apple-darwin/release/examples/heap_profile
[ -x "$BIN" ] || cargo build --release --target aarch64-apple-darwin -p coldsnap_hal \
    --features test-seam,heap-profile --example heap_profile
for k in 96 80 64 48; do
  ( ulimit -s $k; HEAP_STAGE=3 exec "$BIN" 1 >/dev/null 2>&1 )
  echo "heap_profile ulimit_s_kib=$k exit=$?   # 0=ok 134=rust stack-overflow abort 139=SIGSEGV"
done

# 10 — Follow-up fixes

## Fix 1 — unblock the coordinator test build

**Status: FIXED.** The user's untracked test compiles against the current API. `cargo test -p frostsnap_coordinator`
(verbatim, cwd `$HOME/repos/frostsnap`) exits 0, with 0 failures in every target and coldcard_msg_len 3/3 passing. The runner's
`coordinator-verbatim` stage (`cargo test --target aarch64-apple-darwin -p frostsnap_coordinator`) is now `passed rc=0`
instead of `blocked`. The runner is unchanged, no assertion was weakened, and the file is still untracked and uncommitted. Scope: this was a
single-stage run, not a full readiness run. The only claim available is "software/pre-bench checks passed" for that stage.

**Commands below are the IMPLEMENTER's.** The re-runners' commands are in "Re-runner checks" at the end of this section.

**Closes:** the one blocked stage in `09-automate-software-readiness-checks.md` (lines 6-7, 96, 114:
`coordinator-verbatim` BLOCKED by `frostsnap_coordinator/tests/coldcard_msg_len.rs:97`, E0308).

**Root cause:** frostsnap `b565de9` ("Make a bip32 index prove its range on decode", LLFourn, 2026-08-14)
changed `BitcoinBip32Path::external(index: u32)` to `external(index: NormalIndex)`
(`frostsnap_core/src/tweak.rs:148`). The user's test still passed `i as u32`. `NormalIndex`'s `Encode`
delegates to the inner `u32` (per that commit), so wire sizes (what the test measures) do not change.

**Change (user's untracked file, fixed in place, still untracked, not staged):**
`frostsnap_coordinator/tests/coldcard_msg_len.rs`
- :18 `use frostsnap_core::tweak::BitcoinBip32Path;` -> `use frostsnap_core::tweak::{BitcoinBip32Path, NormalIndex};`
- :97 `BitcoinBip32Path::external(i as u32)` -> `BitcoinBip32Path::external(NormalIndex::new(i as u32).unwrap())`
No assertion, constant or test was touched. Pre-fix copy: `target/software-only/logs/fix1-coldcard_msg_len.rs.orig`.
No other file changed in either repo. The runner's classification is unchanged.

**Commands** (logs in `/Users/garykrause/repos/cold-snap/target/software-only/logs/`)

| command | cwd | exit | elapsed | result |
|---|---|---|---|---|
| `cargo test -p frostsnap_coordinator --test coldcard_msg_len --no-run` (before fix) | frostsnap | 101 | 12s | E0308 at :97:56, expected `NormalIndex`, found `u32` (`fix1-prefix-build.log`) |
| `cargo test -p frostsnap_coordinator` (verbatim, after fix) | frostsnap | 0 | 11s | every target passed, 0 failed; coldcard_msg_len 3/3 passed (`fix1-cargo-test-coordinator.log`) |
| `target/pack-venv/bin/python target/software-only/logs/fix1-run-stage.py target/software-only/fix1-stage-fixed` (only the `coordinator-verbatim` stage, through `R.run` the way the self-tests do it) | cold-snap | 0 | 62s | `coordinator-verbatim -> passed rc=0`, "software/pre-bench checks passed" (scoped to this one stage) |
| same, mutation A (pre-fix file restored) | cold-snap | 2 | 42s | `blocked rc=101`: every error is in coldcard_msg_len.rs (E0308 :97) |
| same, mutation B (`COLDCARD_MAX_MSG_LEN` 2060 -> 1_000_000) | cold-snap | 1 | 36s | `failed rc=101`: panic at coldcard_msg_len.rs:243:5 "expected at least one real message to exceed MAX_MSG_LEN" |

The file was restored after the mutations from `fix1-coldcard_msg_len.rs.fixed`. `cmp` matched. frostsnap `git status --porcelain`
is unchanged: the 3 user `M` files plus `?? frostsnap_coordinator/tests/coldcard_msg_len.rs`.

**Notes**
- The verbatim run includes `tests/tofu_tests.rs`, which opens outbound TLS to public Electrum servers
  (for example `electrum.emzy.de:50002`) and prints "Skipping" if it cannot connect. Its 3 passes are not proof that it connected. Nothing is broadcast.
- The stage's `note=` in `tools/check-software-readiness.py:347-348` still says "known BLOCKED". That text is now stale.
  I left it alone because this fix must not touch the runner's blocked handling.

**Re-runner checks** (verifier 1, logs in `target/software-only/verify-rerun-unblock/logs/`, `$V` = `target/software-only/verify-rerun-unblock`)

| command | cwd | exit | result |
|---|---|---|---|
| `CARGO_TARGET_DIR=$V/cargo-target cargo test -p frostsnap_coordinator` | frostsnap | 0 | 0 failed in every target; coldcard_msg_len 3 passed (`verbatim.log`) |
| `target/pack-venv/bin/python target/software-only/logs/fix1-run-stage.py $V/stage-real` | cold-snap | 0 | `coordinator-verbatim -> passed rc=0` (`stage-real.log`) |
| same, `FROSTSNAP_REPO=$V/fs-copy`, mutation A (pre-fix file) | cold-snap | 2 | `blocked rc=101`, E0308 at coldcard_msg_len.rs:97:56 (`stage-copy-mutA.log`) |
| same, `FROSTSNAP_REPO=$V/fs-copy`, mutation B (MAX_MSG_LEN=1_000_000) | cold-snap | 1 | `failed rc=101`, panic at :243:5 (`stage-copy-mutB.log`) |
| same, `FROSTSNAP_REPO=$V/fs-copy`, fixed file restored | cold-snap | 0 | `passed rc=0` (`stage-copy-fixed.log`) |
| `cmp` of the live file against the fixed copy; `git status --porcelain` in both repos | both | 0 | the live file matches; only the user's pre-existing dirty files; runner unmodified |

Verifier 2 (read-only diff review, no rebuild) confirmed: the only changes are at :18 and :97, `b565de9` is an ancestor of HEAD and
changes `external(u32)` to `external(NormalIndex)`, `NormalIndex::new` returns None only for values of 2^31 and above (i < 50 here), and the logs match every claim.

**Findings:** no CONFIRMED findings were raised by either verifier, and no repair was needed. Items disclosed but not fixed (outside this fix's scope):
- the stale "known BLOCKED" note= text at `tools/check-software-readiness.py:347-348`. This is cosmetic, and the runner's classification is unchanged.
- tofu_tests make outbound TLS connections to public Electrum servers and print "Skipping" if they cannot connect. Nothing is broadcast.
- The full `--profile full` readiness run was not re-run after this fix.

**Closes:** task 09's coordinator-verbatim BLOCKED; task 06's C1/C20/R-C1v/C1 verbatim-coordinator BLOCKED; task 08's
check 9 / "Blocked command" (`cargo test -p frostsnap_coordinator` 101).

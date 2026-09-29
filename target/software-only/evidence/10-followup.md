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

## Fix 2a — recovered erase reaches the app

**Status: PARTLY FIXED.** On the host, a committed erase cut by a flash fault is finished by boot recovery, which sends the existing `EraseConfirmed` from the original id only after it has verified the flash is blank. The coordinator claims that ack through the same `EraseDevice` path as a normal erase (`sent_request && !confirmed && from == target && EraseConfirmed`), and the app drops the share and record through the same `dropErasedDeviceShares` the dialog calls. The app rig shows this end to end for cuts `p`/`c`/`a`/`f`, and every Checks command exits 0 (re-run independently after repair 2). Not FIXED because one CONFIRMED finding is still open: the real ARM boot loop's link-edge send of the recovered ack (`firmware/src/main.rs:2614-2616`) is covered by no test. The final re-runner deleted it (M7/M7b), and every test and clippy gate still exited 0. Delivery is proven only in the stub's own copy of that logic. Host fault injection over a pty stub is not STM32 erase or USB physics. The only claim is software/pre-bench checks passed.

**Design, files, commands and mutations below are the IMPLEMENTER's.** Repairs 1 and 2 follow. The re-runners' commands and the finding dispositions are in "Fix 2a — re-runner checks and findings" at the end.

**Design.** `erase::begin` now records the device's ORIGINAL 33-byte DeviceId in the marker. It is written after the body and BEFORE the commit. `erase::recover` returns that id only after destroy+finish have verified the flash blank. At the link edge, boot sends the existing `EraseConfirmed` from the original id, before the fresh announce. The coordinator's `EraseDevice` has no `disconnected` handler, so it is still waiting and claims the ack through the same `process_comms_message` → `Confirmed` path as a normal erase. The app drops the share through the same `dropErasedDeviceShares` the dialog uses. No protocol changes, no new message, no bridge regeneration.

**Files changed** (none committed)
- `hal/src/erase.rs:115-118`: `ID_LEN`, `ID_AT`, `ID_SLOT`. `:231` `begin(flash, original_id)` writes body, then id, then commit. `:333` `recover -> Result<Option<[u8;33]>, EraseFault>`. Tests: 3 writes in order at `:550`; the cut matrix asserts `recover == pending.then_some(ID)` at `:649-650`.
- `firmware/src/lib.rs:177` `recovered_erase_ack(original_id) -> Outbox` holding one `EraseConfirmed` under the old id. `:1012` `Session::erase` passes `self.device_id()`. Tests: the cut matrix at `:3832` (the ack id is `Some(old)` iff the marker is Pending). `:4986`/`:5036` interrupted-erase test: `recover == Some(old)` and the ack bytes equal an `EraseConfirmed` Outbox under the old id.
- `firmware/src/main.rs:1582` import. `:2166-2175` step 8a keeps the recovered id. `:2614` writes the ack before the announce at the link edge.
- `firmware/examples/stub.rs:386-390,404-408` adds the `c` erase key and `EraseOutcome::Interrupted`. `:1666-1715` `open_sessions`/`open_one` return recovered ids. `:1794,1848-1872` adds the power-cut path. `:2236,2450,2492` add `powered_off`. `:2538-2589` replug: recover, verify the new id is blank, queue the acks before the announces.
- `tools/app-rig.py:163,238,442,471-473,519,542` adds `--erase-cut N` (disjoint from `--erase`) and `COLDSNAP_RIG_ERASE_CUT`. `tools/app-rig-test.sh:50` adds `--erase-cut 2`.
- frostsnap `frostsnap_coordinator/src/erase_device.rs:65-79`: the claim now requires `sent_request && from == target && EraseConfirmed`. `:112` new test `a_recovered_erase_ack_confirms_and_nothing_else_does`.
- frostsnap `frostsnapp/lib/device.dart:485,561-568`: extracted `dropErasedDeviceShares`, which the dialog now calls.
- frostsnap `frostsnapp/integration_test/coldsnap_workflows_test.dart:46,1183`: uses it. `:1237-1289` new test 'erase cut by a power loss: boot recovery finishes it and the app still drops the share under the old id'.

**Commands** (logs in `target/software-only/logs/`; host aarch64-apple-darwin; pinned Flutter 3.38.5)

| command | cwd | exit | time | result |
|---|---|---|---|---|
| `cargo test --target aarch64-apple-darwin -p coldsnap_hal -p coldsnap_firmware --features coldsnap_hal/fake-flash,coldsnap_hal/test-seam` | cold-snap | 0 | 16s | `fix2a-final-cargo-test.log`: fw lib 169 (1 ignored), main 58, hal 301, 5, 19 |
| `cargo build --release` | cold-snap | 0 | 9s | |
| `cargo clippy [--release] --target thumbv7em-none-eabihf -p coldsnap_hal -p coldsnap_firmware` | cold-snap | 0 | 2s each | no hal/firmware warnings |
| `cargo clippy --target aarch64-apple-darwin -p coldsnap_firmware --example stub --features coldsnap_hal/fake-flash` | cold-snap | 0 | 3s | 10 stub warnings. CORRECTED in repair 1: HEAD had 6, so 4 were new (3 doc-list at :389-391, complex type at :1666) and too-many-args went 8/7 to 9/7 |
| `cargo build --target aarch64-apple-darwin -p coldsnap_firmware --example stub` | cold-snap | 0 | 6s | `fix2a-real-build.log` |
| `cargo run -- ../target/aarch64-apple-darwin/debug/examples/stub` | cold-snap/hostcheck | 0 | 22s | `fix2a-final-hostcheck.log`: all PASS, including M9 |
| `cargo test -p frostsnap_coordinator --lib erase_device` | frostsnap | 0 | 9s | `fix2a-fs-erase-unit.log`: 1 passed |
| `cargo test -p frostsnap_coordinator` | frostsnap | 0 | 11s | `fix2a-final-fs-coord.log`: 0 failed in every target, lib 61 |
| `flutter analyze lib/device.dart integration_test/coldsnap_workflows_test.dart` | frostsnap/frostsnapp | 0 | 16s | No issues |
| `sh tools/app-rig-test.sh` | cold-snap | 0 | 44s | `fix2a-app-rig-final.log`: "+10: All tests passed!", teardown reaped all, regtest down |

`target/software-only/app-rig/device-2.log` (final run) shows, in order: "POWER CUT mid-erase ... marker committed, no EraseConfirmed sent", then "erase::recover FINISHED the cut erase at boot; EraseConfirmed queued under the old id after recovery verified the flash blank; rebuilt from flash as 03fd41d5...", then "REPLUG RESTART ... every DeviceId unchanged except 1 recovered erase(s)".

**Mutations.** Each was applied in the tree, then restored from `target/software-only/fix2a-bak/`. Every restore was checked with `cmp`: restored-exact. Every mutation failed at the named check.

| id | mutation | command | exit | failed at / why |
|---|---|---|---|---|
| M1 | `recover` returns `None` instead of the id | fw cargo test | 101 | lib.rs:5036 "ack id", left None; lib.rs:3832 |
| M1h | same | hal `--lib erase::` | 101 | erase.rs:650 "fail=4 after=true: recovery's ack id" |
| M2 | id programmed AFTER the commit | fw cargo test | 101 | lib.rs:5036, left `Some([255;33])` (erased id slot); lib.rs:3832 |
| M2h | same | hal `--lib erase::` | 101 | erase.rs:550 (write order), erase.rs:649 "fail=3 ... recovery's ack id" |
| M3 | `begin` given the wrong id `[2;33]` | fw cargo test | 101 | lib.rs:3832, left `Some([2,..])` ≠ old id |
| M4 | drop `self.sent_request &&` | coord `--lib erase_device` | 101 | erase_device.rs:116, an ack before the request confirmed |
| M4b | drop `from == self.target_device` | same | 101 | erase_device.rs:121, an ack from the fresh id confirmed |
| M4c | drop the `EraseConfirmed` match | same | 101 | erase_device.rs:122, `BackupRecorded` confirmed |
| M5 | stub omits the queued acks from hello | app-rig-test.sh | 1 | 155s. "TIMEOUT after 90s ... waiting for: EraseConfirmed from device 2's old id after boot recovery"; +9 -1, only the new test fails |
| M6 | `dropErasedDeviceShares` skips `deleteShare` | app-rig-test.sh | 1 | 51s. "the app still holds the erased device's share", Actual `[AccessStructureRef]`; both erase tests fail |

**Closes:** `08-implement-resumable-device-erasure.md` criterion 2 PARTIAL (:373, :401-407, "interrupted committed erase sends no completion"). A committed erase cut by power loss now finishes at boot and sends `EraseConfirmed` from the original id. The coordinator drops the share through the normal path. This is shown end to end on the host rig.

**Not closed / residual**
- If power dies after `finish` but before the link comes up, the ack is lost. The failure is safe: the coordinator keeps the share and the device is blank.
- If the app restarted while the device was off, no `EraseDevice` is live and no one claims the ack. The share stays until removed by hand.
- A second ack, sent after a fault in finish and a retry, is claimed by no one (`EraseDevice` has already completed). This is harmless.
- `hostcheck` was not extended with a cut leg. The app rig and firmware unit tests cover this.
- CORRECTED in repair 1: this fix added 4 stub clippy warnings, not 1 (3 doc-list, 1 complex type), and made too-many-args 9/7. Repair 1 removed all but too-many-args (see below).
- Host fault injection is not STM32 erase physics. Claim: software/pre-bench checks passed only.

## Fix 2a — repair 1 of 2

Four CONFIRMED findings from the verifier. Not committed. Logs are under `target/software-only/logs/fix2a-r1-*`.

**F2 (fixed): a normal erase could end silently.** Before, `Session::erase` pushed the ack to the RAM outbox and then `finish` cleared the marker, all before main.rs wrote it. Now `Session::erase` stops after `begin`+`destroy`+push, and the marker stays `Pending`. The new `Session::finish_erase()` (`firmware/src/lib.rs`, after `erase`) is called by main.rs (`Flow::Erase` arm) only when `cdc.write(&outbox.take())` returned `Ok`. If the write fails or power is cut first, the marker stays `Pending` and boot step 8a acks again under the old id. `hal/src/erase.rs` module docs steps 3-4 now say this. The stub copies the same order: the normal path writes `wire` to fd 1, then calls `finish_erase`, then reboots.
Residual: `cdc.write` `Ok` means the last packet is queued in the IN FIFO, not that the host received it. There is no protocol-level host receipt. The recovery-side window (power dies after recovery's `finish`, before the link comes up) is unchanged.

**F3 (fixed): the cut matrix counted an ack in RAM as sent.** `an_erase_cut_at_any_flash_call_acks_only_after_deletion` now models main.rs's order. After `Session::erase` returns `Ok` it asserts the marker is still `Pending` ("EraseConfirmed only in RAM but the marker is gone"). It then takes the outbox as "written" and only then calls `finish_erase`. The "never silently" assert now uses written bytes (`!wire.is_empty() || resumed == Some(old)`), not `out.frames()`. `an_approved_erase_acks_after_deletion_and_reopens_fresh` asserts `Pending` after `erase` and calls `finish_erase` after checking the ack bytes. main.rs's source test asserts exactly one `session.finish_erase()`, and that it comes after the `cdc.write`.

**F4 (fixed): one end-to-end cut point.** The stub's erase keys are now `p` (every program refused: nothing commits), `c` (unchanged: after the commit plus one share sector), `a` (the erase succeeds, then the ack is dropped from RAM unwritten), and `f` (ack written, then the marker erase in `finish` refused). After each cut the stub checks the `Session::erase` result, the frame count, the `finish` result and the marker, and dies on a mismatch. `p` reboots as the SAME id with its share: the replug checks this and sends no ack. `app-rig.py --erase-cut N[:KEYS]` exports `COLDSNAP_RIG_ERASE_CUT=N:KEYS,...`. `app-rig-test.sh` runs `--erase-cut 2:pc --erase-cut 0:a --erase-cut 3:f`. The Dart test (frostsnap `integration_test/coldsnap_workflows_test.dart`, last test) now runs one cycle per key.
- `p`: nothing confirmed, then after the replug the old id comes back with the app still holding its share (fail closed), and the protocol is cancelled.
- `c`/`a`: nothing confirmed before the reboot, then confirmed after boot recovery.
- `f`: confirmed at once. The boot's duplicate ack leaves exactly one `confirmed`.
- For `c`/`a`/`f`: `dropErasedDeviceShares` empties the victim's access structures, and the fresh id appears blank with the old id gone.
The test asserts that all four kinds ran. The coordinator Rust (`erase_device.rs`) is unchanged.

**F1 (fixed): warning count.** The figures in the Fix 2a table and residuals are corrected above. Repair 1 also removed the warnings: a blank `///` before "Task 08:" in `erase_keys`' doc fixes all 10 doc-list warnings (5 of them predate fix 2a), a `type Booted<'a>` alias replaces the complex type, and `is_none_or` fixes a new bool-simplification lint. Stub clippy now reports 1 warning: too-many-args 9/7 at `drive` (it was 8/7 at HEAD, and the `flash` param adds one). Left alone: bundling the args is a refactor of `drive`'s call sites that no gate asks for.

**Files changed in repair 1:** `firmware/src/lib.rs`, `firmware/src/main.rs`, `hal/src/erase.rs` (docs only), `firmware/examples/stub.rs`, `tools/app-rig.py`, `tools/app-rig-test.sh`. In frostsnap: `frostsnapp/integration_test/coldsnap_workflows_test.dart`. No Rust API change in frostsnap, so no bridge regeneration.

| command | cwd | exit | result |
|---|---|---|---|
| `cargo test --target aarch64-apple-darwin -p coldsnap_hal -p coldsnap_firmware --features coldsnap_hal/fake-flash,coldsnap_hal/test-seam` | cold-snap | 0 | `fix2a-r1-final-cargo-test.log`: 169 (1 ign), 58, 301, 5, 19 passed |
| `cargo clippy --target aarch64-apple-darwin -p coldsnap_firmware --example stub --features coldsnap_hal/fake-flash` | cold-snap | 0 | `fix2a-r1-clippy-stub2.log`: 1 stub warning (too-many-args 9/7) |
| `cargo clippy [--release] --target thumbv7em-none-eabihf -p coldsnap_hal -p coldsnap_firmware` | cold-snap | 0 / 0 | 18 warnings each, all in `vendor/frostsnap/*`, none in hal/firmware |
| `cargo build --release` | cold-snap | 0 | |
| `cargo build --target aarch64-apple-darwin -p coldsnap_firmware --example stub` | cold-snap | 0 | |
| `cargo run -- ../target/aarch64-apple-darwin/debug/examples/stub` | cold-snap/hostcheck | **1**, then 0, 0 | 1st (`fix2a-r1-final-hostcheck.log`): "pass DECLINE ... DEADLINE (5s) in state WaitingForAnnounces, announced=10". That is before any erase, and M9a/M9b PASS earlier in the same run. Reruns `-rerun1.log`/`-rerun2.log` both exit 0. Recorded as intermittent 1 in 3. Not shown to predate this repair (HEAD not re-run) |
| `cargo test -p frostsnap_coordinator` | frostsnap | 0 | `fix2a-r1-final-fs-coord.log`: 0 failed in every target, lib 61 |
| `flutter analyze integration_test/coldsnap_workflows_test.dart` (pinned 3.38.5) | frostsnap/frostsnapp | 0 | No issues |
| `sh tools/app-rig-test.sh` | cold-snap | 0 | `fix2a-r1-app-rig.log` then `fix2a-r1-final-app-rig.log` (final stub binary): "+10: All tests passed!", teardown reaped all, regtest down. Device logs show `[p]` then "rebooted after a pre-commit power cut: same id, 1 share(s) kept", `[c]`, `[a]`, `[f]`, each followed by "erase::recover FINISHED" |

**Mutations** (backup `target/software-only/fix2a-r1-bak/`, each restore checked with `cmp`)
| id | mutation | command | exit | failed at |
|---|---|---|---|---|
| R1 | `Session::erase` calls `erase::finish` again (the F2 bug) | fw `--lib` | 101 | lib.rs:3750 (approved-erase: marker not Pending) and lib.rs:3812 (matrix: "EraseConfirmed only in RAM but the marker is gone") |
| R2 | main.rs calls `finish_erase()` before the `cdc.write` | fw `--bin` | 101 | main.rs:4510 (count of `finish_erase` sites / write-before-finish order) |
No Dart-side mutation was run in this repair.

Host fault injection and a pty stub are not STM32 erase or USB physics. Claim: software/pre-bench checks passed only.

## Fix 2a — repair 2 of 2

**Finding (CONFIRMED, fixed): duplicate ack in the same poll cycle reached the sink twice.** `EraseDevice::process_comms_message` (`frostsnap_coordinator/src/erase_device.rs`) now also requires `!self.confirmed`. A second `EraseConfirmed` from the target before `clean_finished` removes the protocol is no longer claimed and never reaches the sink. The first ack is handled exactly as before, so recovery's ack from the original id still confirms through the same arm. The existing test `a_recovered_erase_ack_confirms_and_nothing_else_does` now also asserts that a duplicate ack after the first returns `false`, and the sink sequence is still exactly `[WaitingForConfirmation, Confirmed]`. No Rust API change, so no bridge regeneration. This repair touched no other file.

| command | cwd | exit | result |
|---|---|---|---|
| `cargo test -p frostsnap_coordinator` | frostsnap | 0 | `fix2a-r2-coord-test.log`: 0 failed in every target, lib 61 passed 5 ignored |
| `cargo clippy -p frostsnap_coordinator` | frostsnap | 0 | `fix2a-r2-clippy.log`: no warning in erase_device.rs |
| `sh tools/app-rig-test.sh` (pinned Flutter first on PATH) | cold-snap | 0 | `fix2a-r2-app-rig.log`: "+10: All tests passed!", teardown reaped all, regtest down |

**Mutation M-r2** (backup `target/software-only/fix2a-r2-bak/erase_device.rs`, restore checked with `cmp`): with the `!self.confirmed` line deleted, `cargo test -p frostsnap_coordinator --lib erase_device` exits 101 at erase_device.rs:128 ("a duplicate ack before clean_finished confirmed twice"). After restoring, the guard is present once.

Host fault injection and a pty stub are not STM32 erase or USB physics. Claim: software/pre-bench checks passed only.

## Fix 2a — re-runner checks and findings

**Re-runner commands (final re-run, after repair 2).** These are the independent re-runner's, not the implementer's. Logs: `target/software-only/logs/vr2a-r2-*`. Scratch: `target/software-only/verify-rerun-erase-signal/`.

| command | cwd | exit | result |
|---|---|---|---|
| `cargo test --target aarch64-apple-darwin -p coldsnap_hal -p coldsnap_firmware --features coldsnap_hal/fake-flash,coldsnap_hal/test-seam` | cold-snap | 0 | 169 (1 ignored), 58, 301, 5, 19 passed |
| `cargo build --release` | cold-snap | 0 | |
| `cargo clippy [--release] --target thumbv7em-none-eabihf -p coldsnap_hal -p coldsnap_firmware` | cold-snap | 0 / 0 | 18 warnings, all in vendor, none in hal/firmware |
| `cargo build --target aarch64-apple-darwin -p coldsnap_firmware --example stub` | cold-snap | 0 | |
| `cargo run -- ../target/aarch64-apple-darwin/debug/examples/stub` | cold-snap/hostcheck | 0 | all PASS incl. M9, first try |
| `cargo clippy --target aarch64-apple-darwin -p coldsnap_firmware --example stub --features coldsnap_hal/fake-flash` | cold-snap | 0 | 1 stub warning (too-many-args) |
| `cargo test -p frostsnap_coordinator` | frostsnap | 0 | lib 61 passed, 5 ignored; 0 failed in every target |
| `flutter analyze lib/device.dart integration_test/coldsnap_workflows_test.dart` (pinned 3.38.5) | frostsnap/frostsnapp | 0 | No issues found |
| `sh tools/app-rig-test.sh` (pinned 3.38.5 in log) | cold-snap | 0 | "+10: All tests passed!"; teardown reaped all, regtest down |

Re-runner mutations: M1, M1h, M2, M2h, R1, R2 (scratch copy) and M4, M4b, M4c, M5dup (in place, `cmp`-restored) all exit 101 at their named checks. The coordinator lines are now 119/123/124/128 because repair 2 shifted them. **M7** (the main.rs link-edge ack write replaced with `let _ = ack`) and **M7b** (the block deleted) SURVIVED with exit 0; see finding 6. Earlier re-runners (before repair) also killed M3, M5, M8 (recover ignores destroy/finish errors, erase.rs:671) and M9 (finish before destroy, lib.rs:5047/3835, erase.rs:739). M6 (Dart) was not re-run by any re-runner. A fault verifier also stopped the rig with SIGTERM at POWER CUT: exit 143, no leftover process, datadir or fd.

**CONFIRMED findings and disposition**

1. The stub clippy count was misstated (the fix added 4 warnings, not 1). FIXED in repair 1: figures corrected and 10 warnings removed, 1 remains.
2. A normal erase could end silently: the marker was cleared while the ack was still only in RAM. FIXED in repair 1: `finish_erase()` now runs only after `cdc.write` returns `Ok`, killed by R1/R2. Residual: `Ok` means queued in the IN FIFO, not received.
3. The cut matrix counted an ack in RAM as sent. FIXED in repair 1: it now asserts written bytes and a `Pending` marker.
4. The coordinator end to end covered one cut point. FIXED in repair 1: cut keys `p`/`c`/`a`/`f` are all driven through the app rig.
5. A duplicate ack in one poll cycle reached the sink twice. FIXED in repair 2: `!self.confirmed` guard, killed by M-r2/M5dup.
6. The real firmware's recovered-ack send (`firmware/src/main.rs:2614-2616`) has no test; M7/M7b survive every gate. **NOT FIXED, open.** A source pin like main.rs's `finish_erase` pin (the ack written before `session.announce` in the link-edge block) would catch it.

**PLAUSIBLE, recorded, not fixed**
- The coordinator accepts `EraseConfirmed` on the frame's self-asserted `from` without tying it to a port (`usb_serial_manager.rs:410-414`). A device on another port could confirm a pending erase. This predates the fix and the fix does not widen it; a share-proof gate is out of scope for this run. Raised by three re-runners.
- `main.rs` `take()`s the recovered id before `let _ = cdc.write(..)`, so a failed write at the link edge loses the boot ack (fails safe: the share is kept).
- Any `cancelProtocol` (`cancel_all`) between the cut and the replug drops the pending `EraseDevice`, and nobody claims the ack (fails safe).
- The `EraseDevice` wait and the Dart `await for` have no time limit. The dialog closes on unplug, and a late ack after dispose may trip debug assertions.
- The Dart test calls `dropErasedDeviceShares` directly and never pumps the real dialog.
- The Dart duplicate-ack count for cut `f` may be taken before the duplicate arrives. The Rust duplicate guard is proven by the unit test.
- hostcheck failed 1 in 3 runs in repair 1 ("pass DECLINE ... DEADLINE (5s)", before any erase). The final re-run passed first try. Not shown to predate the fix.
- Carried residuals: an ack is lost if power dies after recovery's `finish` and before the link comes up, and there is no live `EraseDevice` after an app restart. Both fail safe.

**Forbidden shortcuts:** held. EraseConfirmed is sent only after verified deletion, in session and at recovery (M1/M2/M8/M9/R1/R2 killed). A stray ack is refused: before the request, from another id, a wrong body, or a duplicate. The port-spoof gap above is open. An interrupted erase resumes, or reboots `p` as the same id with its share (fail closed). No assertion was weakened. No new message and no bridge change. No device, serial, flash or network use; coldcard-firmware was not written; user files are untouched.

## Fix 2b — app restart reloads wallet state

**Status: FIXED (app-restart half of task 04 criterion 3).** Reason: a new app process reloads
the persisted wallet, key, device names, next address and coin and gets a Taproot signature the
independent sighash check and regtest Core accept (implementer, repair and re-runner round 2 all
exit 0; M1/M2/M3 killed). All three CONFIRMED findings repaired; one PLAUSIBLE finding open (see
"Fix 2b — close-out"). The implementer's commands are the table labelled "implementer" below;
the re-runners' are in the close-out section. Closes the unmet part named in
`evidence/04-test-real-app-with-virtual-devices.md` § Close-out, "Acceptance criteria" row 3
("Not met: an app restart (never done)") and § "Residual questions" ("an app restart that
reloads sqlite/bdk. Neither has been done"). The STUB PROCESS restart remains out of scope and
was not attempted or faked: `FakeFlash` lives in the stub's memory, so a respawned stub has no
shares. Scope of claim: software/pre-bench checks passed, virtual ptys, regtest only.

### What the restart is

`tools/app-rig.py --app-restart` runs the test command twice with the same stubs, the same
`app-dir` (one `frostsnap.sqlite` holds the coordinator DB and the bdk wallet) and the same
regtest node. Run 1 (`COLDSNAP_RIG_APP_RUN=1`) starts on an empty app dir and does keygen,
naming, the address, signing, decline, backup, restore and replug. Then it writes
`<rig dir>/app-restart.json` (pid, key id, access-structure id, key name, threshold, per-device
id/name/share index, `nextAddress` index and address, utxo count) and exits. The rig then
requires the whole process group (flutter, flutter_tools, the macOS test app) to be gone
(`FAIL APP DID NOT STOP`, exit 4, otherwise) and the stubs to still be alive. Only then does it
start run 2 (`COLDSNAP_RIG_APP_RUN=2`), a new `flutter test` and so a new app process. Run 2
refuses a missing or empty app dir and never wipes it. It does no keygen and no funding. It
asserts:
- its `pid` differs from run 1's and `kill -0 <run-1 pid>` fails;
- `keyState().keys` is exactly run 1's key id, with the same key name, access structure id,
  threshold and devices;
- every device's `getDeviceName`, its short share index, and a reconnect under that name;
- `nextAddress` has the same index and address as run 1 derived, and the utxo count matches.
Then the reloaded wallet builds a tx from the persisted coin, `startSigningTx` (real
`WireSignTask::BitcoinTransaction`) with devices 0 and 1 consenting at the glass, and the
recipient and amount are read off their rendered pixels. `verifyTaprootSignatures` (the
independent BIP-341 recompute over the prevouts the reloaded wallet holds) must equal the input
count, and Core `testmempoolaccept` must accept. Only then does run 2 countersign the snapshot
(`reloadedByPid`). The erase tests run after that in run 2, because they destroy shares. The rig
exits **6 `APP RESTART UNVERIFIED`** if run 2 exits 0 without the countersignature. Teardown
removes `app-restart.json` along with the app dir. The regtest node is started by run 1 and
stopped by run 2's `tearDownAll`, with the rig's `regtest.py down` as the backstop.

### Files changed (none committed)

- cold-snap `tools/app-rig.py`: :36-37 exit 6 documented; :45 `import json`; :138-140
  `restart_snapshot`; :393 teardown removes it; :453-457 `--app-restart`; :562-613 the
  two-run loop, one deadline over both runs, the `APP DID NOT STOP` check between them, and
  the countersignature check.
- cold-snap `tools/app-rig-test.sh`: :10-18 header; :60 `--app-restart`.
- frostsnap `frostsnapp/integration_test/coldsnap_workflows_test.dart`: :32-36 header;
  :103-113 `appRun`/`restartSnapshotPath`; :224-240 `inRun`/`firstApp`/`secondApp`;
  :300-317 run-1 wipe vs run-2 refuse-empty; :330 regtest `up` in run 1 only; :338 `down` in
  run 2 only; tests 2-8 at :407-1127 renamed `test(` -> `firstApp(` (bodies unchanged);
  :1166 snapshot test; :1206 reload test; :1287 post-restart signing test (countersign :1370);
  the erase tests :1380, :1501 renamed to `secondApp(`. The diff is 274+/14-, and every `-`
  line is one of those renames or the gated setUp/tearDown lines. `dart format` was NOT
  applied to the whole file, because it would reflow fix 2a's erase tests. The file is
  already tracked (4b9edfa, 76982a5, 6d58541; `git status` shows ` M`), so `.git/info/exclude`
  does not hide it and a plain `git add` stages it (`-f` is harmless, not needed). Never stage the
  untracked `integration_test/testnet4_chooser_test.dart`. (Corrected in repair 1 of 1.)

### Commands (implementer; exit = the process's own status, output redirected to the log)

| # | Command | cwd | Exit | Elapsed | Log (`target/software-only/logs/`) |
|---|---|---|---|---|---|
| 1 | `/usr/bin/time -p tools/app-rig-test.sh` (first real run) | cold-snap | 0 | 85.63 s | `fix2b-rig-1.log`: run 1 `+9`, `app restart: first app process group gone`, run 2 `+5`, `app restart verified: pid 50792 persisted, pid 51956 reloaded and signed`, Core ACCEPTED x3 + REJECTED (Invalid Schnorr) x1 |
| 2 | M1 rig run (below) | cold-snap | 1 | 82.52 s | `fix2b-mut-M1.log` |
| 3 | M2 rig run | cold-snap | 6 | 71.24 s | `fix2b-mut-M2.log` |
| 4 | M3 rig run | cold-snap | 1 | 92.87 s | `fix2b-mut-M3.log` |
| 5 | `cargo build --target aarch64-apple-darwin -p coldsnap_firmware --example stub` | cold-snap | 0 | 1.87 s | `fix2b-check-build.log` |
| 6 | `cargo run -- ../target/aarch64-apple-darwin/debug/examples/stub` | cold-snap/hostcheck | 0 | 32.30 s | `fix2b-check-hostcheck.log`, 4 `pass ok` |
| 7 | `/usr/bin/time -p tools/app-rig-test.sh` (final, on the reverted tree) | cold-snap | 0 | 129.46 s | `fix2b-rig-final.log`: run 1 `+9`, run 2 `+5`, `pid 62948 persisted, pid 63845 reloaded and signed`, `teardown: ... regtest down, 0 still alive, all fds closed` |
| 8 | `tools/app-rig-test.sh --timeout 40` (fires in run 1) | cold-snap | 5 | 41.47 s | `fix2b-timeout-40.log`; `pgrep -fl "examples/stub\|app-rig.py\|bitcoin-node -regtest\|flutter_tools\|Frostsnap.app"` exit 1; rig dir holds only `device-*.log`, `identities.tsv` |
| 9 | `tools/app-rig-test.sh --timeout 75` | cold-snap | 0 | 74.06 s | `fix2b-timeout-75.log` (finished inside the bound, so it is not a fault-path probe) |
| 10 | `tools/app-rig-test.sh --timeout 58` | cold-snap | 5 | 59.66 s | `fix2b-timeout-58.log`, fired in run 1; pgrep exit 1; clean dir |
| 11 | `tools/app-rig-test.sh --timeout 68` (fires in RUN 2, after the restart) | cold-snap | 5 | 69.71 s | `fix2b-timeout-68.log`; `teardown: reaped [-15 x4], command group gone, regtest down` (the node run 1 left up); pgrep exit 1; no `app-dir`, no `app-restart.json` |
| 12 | `env -u COLDSNAP_RIG_APP_RUN BUNDLE_FIRMWARE=0 flutter test integration_test/coldsnap_workflows_test.dart -d macos` (bare) | frostsnap/frostsnapp | 1 | 23.61 s | `fix2b-bare-flutter.log`: `Bad state: COLDSNAP_RIG_APP_RUN is not set ...`. A named failure, not a skip |
| 13 | `flutter analyze` | frostsnap/frostsnapp | 0 | 27.45 s | `fix2b-analyze.log`, "No issues found!" |
| 14 | `python3 -c "import ast;ast.parse(open('tools/app-rig.py').read())"`; `sh -n tools/app-rig-test.sh` | cold-snap | 0; 0 | <1 s | — |

Every Flutter command ran with `$HOME/repos/frostsnap/frostsnapp/.fvm/flutter_sdk/bin` first on PATH.
`flutter --version` printed 3.38.5 / Dart 3.10.4, and app-rig-test.sh verifies the version
against `.fvmrc` on every run. The row 1 run's first attempt failed at the shell (`time -p` is not
a command in this shell, exit 127, nothing ran) and was re-run with `/usr/bin/time -p`.

### Mutations (each in-tree, then reverted; revert checked exactly)

- **M1: run 2 wipes and recreates `app-dir` before loading** (a fresh app on the same stubs, not
  a reload). Rig exit 1. Run 2 failed `after a real app restart ...` with
  `Expected: ['c01dc871...'] Actual: []`, "the reloaded app does not hold exactly the first
  process's wallet". The post-restart signing test and the erase tests failed after it. Reverted
  by copying back the saved real file; `cmp` identical, and `git diff | grep -c MUTATION` = 0.
- **M2: run 2 does not write `reloadedByPid`** (a second process that exits 0 without verifying).
  Rig exit **6**: `FAIL APP RESTART UNVERIFIED: .../app-restart.json has no second-process
  countersignature`. Reverted the same way, `cmp` identical.
- **M3 (production code): `CoordSuperWallet::apply_update` applies the bdk update in memory but
  persists an empty changeset** (`frostsnap_coordinator/src/bitcoin/wallet.rs:474`). Run 1
  still passed (`+9`: in-memory state is enough within one process, which is exactly what task 04
  could not tell apart). Run 2 failed on `address frontier not reloaded`
  (`Expected: <1> Actual: <0>`), and the signing test on `TryFinishTxError.insufficientBalance`
  (the coin was not reloaded). Rig exit 1. Reverted with `git checkout --` on a file that was
  clean before (`git diff --quiet` checked before and after).

### Not done, and why

- A stub process restart is out of scope. `FakeFlash` is in memory, and faking it would be a
  fresh device.
- Not re-run: the full readiness profile (`tools/check-software-readiness.py`). Its `app-rig`
  stage runs this same `tools/app-rig-test.sh` with a 1500 s bound, and the final rig takes about
  130 s.
- Carried residuals, unchanged: a SIGKILL of `app-rig.py` itself is uncatchable. Flutter screens
  are not pumped; coverage is at the API level. The shipped ARM image does not re-announce on a
  port re-open, so this restart relies on the stub's `STUB_REANNOUNCE`, as task 04 already
  recorded.

## Fix 2b — repair 1 of 1

Uncommitted. Only cold-snap `tools/app-rig.py` and this file were changed.

1. **Relative `--dir` leaked app-dir into frostsnapp/ (FIXED).** `main()` now sets
   `args.dir = os.path.abspath(args.dir)` right after `parse_args()`, so `COLDSNAP_RIG_DIR`,
   the lock line, the sheets wipe and `Rig.outdir` all use one absolute path. The Dart test's
   `$rigDir/app-dir` and `$rigDir/app-restart.json` now resolve to the same place the rig
   tears down. The older leak `frostsnapp/target/software-only/verify-rerun-app-restart/rig/app-dir`
   (Sep 24, someone else's run) was left alone, as the verifier did.
2. **"Hidden by .git/info/exclude" (FIXED, documentation).** The Files-changed entry above is
   corrected: `coldsnap_workflows_test.dart` is tracked (4b9edfa, 76982a5, 6d58541, ` M`), so a plain
   `git add` stages it. `testnet4_chooser_test.dart` must still stay unstaged.
3. **ibtoold daemons outliving the rig (FIXED).** `Rig` now makes a per-run
   `COLDSNAP_RIG_RUN_TOKEN` (`<rig pid>-<ns>`) and passes it only in the command's env. The new
   `Rig.reap_env_strays()` runs in teardown on every exit path. It scans `ps -E -ww -A` for that
   exact token (never a process name, and never `COLDSNAP_RIG_DIR`, which an ancestor shell
   could carry), sends SIGTERM and then SIGKILL, and adds any survivors to `alive`, which fails the
   run with exit 4 `FAIL ORPHANS`. Only descendants of the command's env can match, so the user's
   node (PID 13555) and other Xcode users cannot.

| # | Command | cwd | Exit | Log (`target/software-only/logs/`) |
|---|---|---|---|---|
| R1 | `python3 -c "import ast;ast.parse(open('tools/app-rig.py').read())"` | cold-snap | 0 | — |
| R2 | `/usr/bin/time -p tools/app-rig-test.sh --dir target/software-only/repair2b-rel/rig` (RELATIVE) | cold-snap | 0 (72.12 s) | `fix2b-repair-rel.log`: run 1 `+9`, run 2 `+5`, `app restart verified: pid 33202 persisted, pid 34099 reloaded and signed`, `SIGTERM 2 process(es) still carrying COLDSNAP_RIG_RUN_TOKEN=32562-...: [32718, 32719]`, `teardown: ... 0 still alive` |
| R3 | `ps -p 32718,32719` | cold-snap | 1 (gone) | — |
| R4 | `find $HOME/repos/frostsnap/frostsnapp/target/software-only -maxdepth 3` | — | 0 | only the pre-existing Sep-24 `verify-rerun-app-restart/rig/app-dir`; nothing from `repair2b-rel` |
| R5 | `/usr/bin/time -p tools/app-rig-test.sh --timeout 40 --dir target/software-only/repair2b-rel/rig` | cold-snap | 5 (41.41 s) | `fix2b-repair-timeout40.log`: `FAIL TIMEOUT`, `teardown: reaped [-15 x4], command group gone, regtest down, 0 still alive` |
| R6 | `pgrep -fl "app-rig.py\|examples/stub\|bitcoin-node -regtest\|flutter_tools\|ibtoold"` after R2 and after R5 | cold-snap | 1 both times | — |

After R2 and R5 the rig dir holds only `device-*.log` and `identities.tsv`: no `app-dir`,
`sheets` or `app-restart.json`. R2 is the case the verifier reproduced as exit 1, and the
restart check now passes with a relative `--dir`. Every Flutter command ran under the pinned SDK,
which app-rig-test.sh checks against `.fvmrc` on every run.
Not re-run: an absolute-`--dir` or default-dir rig. The only change on that path is `abspath` of a
path that is already absolute, plus the token reaper, which R2 exercised. The full readiness runner
was not re-run either.
Residual: the reaper cannot see a process that clears its own environment, or a process running
as another uid. The token only reaches descendants of the command's env.

## Fix 2b — close-out

**Status: FIXED**, scoped to the app restart. Task 04 stays DEGRADED in `run.json`: the stub
process restart is out of scope (in-memory `FakeFlash`) and was not faked.

### Re-runner commands (not the implementer's)

Round 1 (before repair; logs `target/software-only/verify-rerun-app-restart/`,
`logs/verify-faults-app-restart-{hold,accept}.log`): absolute-`--dir` rig exit 0 (96.87 s, run 1
+9, run 2 +5, "pid 17111 persisted, pid 17954 reloaded and signed"); M1 exit 1; M2 exit 6; M3b
(run 2 deletes only bdk `wallet-*.sql`) exit 1 "address frontier not reloaded"; `--timeout 70`
exit 5 in run 2 with clean teardown; relative `--dir` exit 1 (finding 1); SIGTERM at the restart
point and during post-restart signing both exit 143 with 0 left (run-2 app pid 14550 held
`frostsnap.sqlite`, `wallet-*.sql` and 4 ptys, in the rig's pgid); bare verbatim flutter exit 1
"COLDSNAP_RIG_APP_RUN is not set"; `flutter analyze` 0; both cargo Checks 0.

Round 2 (after repair; logs `logs/verify2b-r2-*.log`): default rig exit 0 (70.04 s, "pid 36834
persisted, pid 37556 reloaded and signed", post-restart Core ACCEPTED, 2 token strays reaped,
0 still alive); cargo build 0; hostcheck 0 (4 `pass ok`); bare flutter 1 (named); analyze 0;
M1 1; M2 6; M3 (production `apply_update` empty changeset) 1; relative `--dir` 0 (82.19 s,
nothing new under `frostsnapp/target`); `--timeout 40` 5 (run 1); `--timeout 70` 5 (run 2);
`pgrep` 1 after each. Findings: none.

### Findings

| Verdict | Finding | Outcome |
|---|---|---|
| CONFIRMED | relative `--dir` leaked `app-dir` into the frostsnap tree and failed the restart check (pre-dates 2b) | FIXED (repair 1, `abspath`); re-runner round 2 exit 0 |
| CONFIRMED | evidence claimed `.git/info/exclude` hides the test file | FIXED (repair 1, wording). Close-out note: the path is matched by an ignore rule, so plain `git add` on the tracked file stages it but prints the ignored-path hint and exits 1; `git add -f` is the clean form |
| CONFIRMED | Xcode `ibtoold` daemons from run 1's build outlived the rig carrying its env | FIXED (repair 1, `COLDSNAP_RIG_RUN_TOKEN` reaper); round 2 saw 2 strays reaped, `pgrep` 1 |
| PLAUSIBLE | the post-restart signing test does not repeat run 1's fee-on-glass, confirm-key, share-count (`gotShares == threshold`), `canBroadcast` or tamper checks | OPEN (not repaired) |

### Still open

- PLAUSIBLE finding above.
- The restart relies on the stub's `STUB_REANNOUNCE`; shipped ARM firmware does not re-announce
  on a port re-open, so this is not evidence that shipped firmware survives an app restart.
- The device-name reload check cannot tell the sqlite DB from the name the stub re-announces from
  flash (the key, share, frontier and coin checks, which M1/M3 kill, do test the DB).
- Stub process restart: out of scope, not faked. SIGKILL of the rig is uncatchable. Flutter
  screens not pumped. Full readiness runner not re-run.

### Commits

- frostsnap `366da527e9268195d5cf000b6cd92ca879a6a153` (`frostsnapp/integration_test/coldsnap_workflows_test.dart`).
- cold-snap: the fix 2b close-out commit (`tools/app-rig.py`, `tools/app-rig-test.sh`, this file,
  `run.json`, the 04 evidence file; see `git log`, it cannot name its own SHA).

Scope of claim: software/pre-bench checks passed, virtual ptys, regtest only.

## Fix 3 — tighten the weak checks

**Status: FIXED (a, b, c, d).** Each strengthened check was mutated and failed for its named reason, then passed on the real code; two independent re-runners reproduced every mutation, and the one CONFIRMED finding against this fix (a silent `BL_SRAM_BASE` default under the alias `mm`) was repaired (repair 1 of 1). Scope: the four named guards and the 9 affected stages; the full readiness profile was not re-run and is expected to stay red on `registry-matches-artifact` (not caused by this fix, see close-out).
Commands below are the IMPLEMENTER's. cwd is `/Users/garykrause/repos/cold-snap` for every command. Logs are in `target/software-only/logs/10-fix3/`.
Exit codes are the process's own status: output was redirected to the log and never piped. Scope: software/pre-bench checks only.
The affected readiness stages were run through `R.run`. The full readiness profile was **not** re-run.

**Closes:**
- (a) finding 10 in `01-repair-firmware-packaging.md` (:413): the checkfw negative asserted only `REFUSE`.
- (b) F7 in `03-check-coldcard-reference-contracts.md` (:8-12, :412ff): silent `, 0` defaults.
- (c) the OPEN finding in `07-build-upgrade-controller-with-mocked-callgate.md` (:3, :73, :87): `no_check_burn_len` survived. Also the record inconsistency at :25 (`mut-summary.txt` said the tripwire exited 0).
- (d) the OPEN CONFIRMED finding in `09-automate-software-readiness-checks.md` (:3-4, :379, :453): pack-negative-bad-layout passed on any rc 1.

### Files changed (working tree only)
- `tools/test-pack-signed.py:177`: the expected substring changed from `'REFUSE'` to `'[FAIL] R12 signature over double-SHA256(signed range)'`. The one-word `'R12'` fix proposed in 01 would still be weak, because checkfw prints `[PASS] R12 signature ...` on an accepted image (seen in the checkfw-bin output). A bare `R12` therefore matches a refusal for any other reason.
- `tools/check-reference-contracts.py:147-156`: new `Log.need(group, ident, rs, *names)`. It returns the named cold-snap ints. If any name is missing or ambiguous (not an int), it FAILS that check id and names the key.
  - Every `rs.get(X, <default>)` read now goes through it: `:761` burn-len-max-within-fw-max (F7 site 1), `:774` flash-header-base-mk4, `:820` linkx-flash-isr-fits-header, `:855` psram-stage-below-recovery-header (F7 site 2), `:873` burn-len-max-reaches-flash-fs, `:900` install-align-divides-header-prefix.
  - The last one was a third silent pass of the same class: `max(rs.get('FW_INSTALL_ALIGN', 1), 1)` made `x % 1 == 0` COVERED.
  - `grep 'rs.get([^)]*, [0-9])'` now finds nothing (exit 1). Real-code result is unchanged: 136 COVERED / 0 FAILED / 0 UNAVAILABLE.
- `firmware/src/install.rs`:
  - `:364` `check_view` now delegates to the new `:375 check_view_with(view, announced, call_len, installable: fn(&[u8], u32) -> Result<u32, NotInstallable>)` and passes `coldsnap_hal::image::check_installable`. Production behaviour is identical.
  - The guard `psram::check_burn_len` (`:388`) is unchanged.
  - New test `:1587 header_call_guard_refuses_without_check_installables_own_comparison`. It stands in a `check_installable` that has lost its header==call comparison (it judges the image at the header's own length, the refactor the guard's comment names). It asserts that the stand-in accepts the disagreeing call and that `check_view_with` still returns `NotInstallable(Length(LengthMismatch))`.
  - Tripwires and census are unchanged and pass. The new code contains no banned needle and no `crate::`.
- `tools/check-software-readiness.py:298-300`: the pack-negative-bad-layout stage gained `must=[r'(?m)^ABORT \(Abort\): firmware0\.bin would load at 0x08180000, not 0x08020000:']`.
  - The pattern was read from a real run (`bad-layout-real.log`: `ABORT (Abort): firmware0.bin would load at 0x08180000, not 0x08020000: signit lays ...`).
  - `(Abort)` is essential. `pack-signed.py:622-625` turns every exception into `ABORT (<Type>): ...` with exit 1, so a crash also prints `ABORT` with rc 1.
- `tools/test-software-readiness.py:100-111`: the self-test takes the REAL stage's `expect_rc`/`must` from `R.stages()`, not a copy. It asserts:
  - the real refusal line with rc 1 → passed;
  - a `Traceback`/`KeyError` with rc 1 → failed;
  - `ABORT (KeyError): ...` with rc 1 → failed.
  Self-test total: 73/73 ok.
- Evidence record fix: `target/software-only/logs/07-rerun2/mut-summary.txt`. Line 1 changed from `tripwire_gated_call exit 0 ...` to `exit 101`, with a dated correction note that cites the log lines. The other lines are byte-identical. The original is kept at `logs/10-fix3/07-rerun2-mut-summary.txt.orig`.

### Commands (implementer)
| # | command | exit | elapsed | result |
|---|---|---|---|---|
| 1 | `cargo build --release` | 0 | 1.9 s | up to date |
| 2 | `python3 tools/pack-signed.py --pubkey-num 0 --out target/software-only/package` | 0 | 0.9 s | before edits |
| 3 | `python3 tools/test-pack-signed.py` (before edits) | 0 | 5.7 s | OK: 22 cases |
| 4 | `python3 tools/pack-signed.py --elf target/software-only/fixtures/bad-layout.elf --out target/software-only/logs/10-fix3/bad-layout-out --no-dfu` | 1 | 0.17 s | the real refusal line used for (d) |
| 5 | `python3 -B tools/test-software-readiness.py` (after the (d) edit) | 0 | 61.5 s | 73 ok, the 3 new bad-layout cases ok |
| 6 | `python3 -B logs/10-fix3/run-stages.py tools/check-software-readiness.py target/software-only/fix3-stage-real arm-build-release pack pack-tests pack-negative-bad-layout` | 0 | 20.5 s | pack-negative-bad-layout passed rc=1 |
| 7 | `python3 -B logs/10-fix3/one-stage.py target/software-only/fix3-one-real` (only that stage via `R.run_stage`, upstream marked passed) | 0 | 0.33 s | passed rc=1 on `ABORT (Abort): ...` |
| 8 | `python3 tools/test-pack-signed.py` (after the (a) edit) | 0 | 1.7 s | OK: 22 cases |
| 9 | `python3 tools/check-reference-contracts.py --json target/software-only/fix3-refcheck/result.json` | 0 | 14.1 s | PASS: 136 checks |
| 10 | `python3 tools/test-reference-contracts.py` | 0 | 27.5 s | 6/6 negative cases behaved |
| 11 | `cargo test --target aarch64-apple-darwin -p coldsnap_firmware --features coldsnap_hal/fake-flash,coldsnap_hal/test-seam --lib install::tests` | 0 | 6.6 s | 28 passed, 1 ignored (the existing xproc test) |
| 12 | `cargo test --target aarch64-apple-darwin -p coldsnap_hal -p coldsnap_firmware --features coldsnap_hal/fake-flash,coldsnap_hal/test-seam` | 0 | 11.5 s | 553 passed, 0 failed (summed from this log) |
| 13 | `cargo build --release` | 0 | 6.3 s | |
| 14 | `cargo clippy --release --target thumbv7em-none-eabihf -p coldsnap_hal -p coldsnap_firmware` | 0 | 1.0 s | 18 warnings, all in `vendor/frostsnap/*`, none in cold-snap crates |
| 15 | `cargo clippy --target thumbv7em-none-eabihf -p coldsnap_hal -p coldsnap_firmware` | 0 | 1.2 s | same 18 vendor warnings |
| 16 | `cargo run --release --target aarch64-apple-darwin -p coldsnap_firmware --example heap_session --features coldsnap_hal/test-seam,frostsnap_core/coordinator` | 0 | 11.3 s | FITS, slack 10860 B (parsed from this run) |
| 17 | `python3 -B logs/10-fix3/run-stages.py tools/check-software-readiness.py target/software-only/fix3-stages-final arm-build-release refcheck refcheck-negatives pack pack-tests pack-negative-bad-layout checkfw-bin checkfw-dfu checkfw-negative-signature` (after every edit) | 0 | 67.6 s | all 9 passed. refcheck 136/0/0. "software/pre-bench checks passed", scoped to these 9 stages |

Commands 12-16 are the four task-07 checks plus release build (`logs/10-fix3/checks07-summary.txt`, `c07-{1..5}.log`).

### Mutations (each bit for the named reason)
| id | mutation | where | result with the new check | result with HEAD's check |
|---|---|---|---|---|
| A | the test corrupts by appending 4096 B of 0xff instead of flipping the signature bit, so checkfw refuses on R9/R14 while printing `[PASS] R12` | in-tree `tools/test-pack-signed.py`, restored from a copy, `cmp` 0 | exit 1: `AssertionError: exit 1 but not for the intended reason (wanted '[FAIL] R12 signature over double-SHA256(signed range)')` (`tps-mutA-fixed.log`) | exit 0, `OK: 22 cases` (`tps-mutA-head.log`), the weakness reproduced |
| B0 | control: symlink-farm mirror with no rename | `target/software-only/fix3-mut/B0-*` | rc 2: 135 COVERED / 0 FAILED / 1 UNAVAILABLE (pixel skipped inside the mirror with `--skip-pixel`, because pixel-check cannot build its simulator there) | same |
| B1 | `PSRAM_STAGE_OFFSET` declaration renamed in a mirror copy of `hal/src/psram.rs` | mirror | rc 1: `FAILED memory/psram-stage-below-recovery-header -- could not read the cold-snap side of PSRAM_STAGE_OFFSET/PSRAM_STAGE_LEN ...: PSRAM_STAGE_OFFSET=None` | rc 2, identical to control: the rename is invisible, as F7 said |
| B2 | `BURN_LEN_MAX` renamed | mirror | rc 1: `FAILED abi/burn-len-max-within-fw-max -- ... BURN_LEN_MAX=None`; burn-len-max-reaches-flash-fs also names it | rc 1 only through the sibling; its own row is `COVERED ... BURN_LEN_MAX (0) <= ...` |
| B3 | `FW_INSTALL_ALIGN` renamed in a mirror copy of `hal/src/lib.rs` | mirror | rc 1: `FAILED memory/install-align-divides-header-prefix -- ... FW_INSTALL_ALIGN=None` | that row COVERED `== 0` (fails only via signit-install-align) |
| C1 | `no_check_burn_len`: the two guard lines removed from `check_view_with` | in-tree `firmware/src/install.rs`, restored, `cmp` 0 | rc 101: `header_call_guard_refuses_without_check_installables_own_comparison ... FAILED`, left `Ok(CheckedImage{len: 266240..})`, right `Err(NotInstallable(Length(LengthMismatch)))`; 27 passed, 1 failed (`install-tests-mutC1.log`) | rc 0 per `07-rerun2/mut-no_check_burn_len.log` (the survivor) |
| C2 | tripwire: the documented `#[cfg(target_arch = "arm")] return coldsnap_hal::callgate::pin_setup_attempt(_att);` in `Unbound::setup`, run with the full check-1 command | in-tree, restored, `cmp` 0 | rc 101 in 4.4 s: `nothing_here_reaches_a_real_gate_or_an_identity ... FAILED`, `` `pin_setup_attempt` in install.rs production code `` (`mut-tripwire_gated_call.log`). This is the direct status that corrects mut-summary.txt | n/a |
| D1 | `{}['.vector_table']` inserted just before `raise Abort(` at the moved-base check, so the packager crashes in its refusal path | in-tree `tools/pack-signed.py`, restored, `git diff --quiet` 0 and `cmp` vs HEAD 0 | `one-stage.py`: stage `failed rc=1 exit 1 but output lacks /(?m)^ABORT \(Abort\): .../`; stderr `ABORT (KeyError): '.vector_table'` | `one-stage.py ... head-rule` (`must=()` as at HEAD): `passed rc=1`, the weakness reproduced. pack-tests also caught D1 with rc 1 in the chain run |
| D2 | the new `must=` removed from the runner | in-tree, restored from a copy, `cmp` 0 | self-test rc 1 in 54.8 s: `FAIL ... bad-layout-traceback rc 1 -> failed` and `... bad-layout-crash-abort`; the real-refusal case stays ok | n/a |

A first D1 placement (the crash at the top of `main()`) hit `pack` first, so the negative never ran. It was reverted and placed at the refusal site instead (`stages-mutD1.log` is the second placement).

### Not done
- The full readiness profile was not re-run. Only the 9 affected stages were run (command 17).
- The stale "known BLOCKED" note at `tools/check-software-readiness.py:347-348` (09 evidence :474) is out of this fix's scope.
- The runner's `checkfw-negative-signature` pattern `[FAIL] R12 ` also matches R12's "range unusable" variant. It was left as is (not a named weak guard). Tightening it is optional.
- Nothing was committed. The earlier evidence files were not edited, apart from the `07-rerun2/mut-summary.txt` correction above.

## Fix 3 — repair 1 of 1

Finding: `check_elf` read `mm.get('BL_SRAM_BASE', 0)` (the alias `mm` for `rs`). The earlier `rs.get(X, <n>)` grep missed it because of the alias.

### Change
- `tools/check-reference-contracts.py:601-604`: `end-below-bl-sram` now gets `BL_SRAM_BASE` through `log.need(g, 'end-below-bl-sram', mm, 'BL_SRAM_BASE')`. If the key is missing, that row FAILS and names the key. The comparison runs only when the key is an int.
- `grep -nE "\.get\([^)]*,\s*[0-9]" tools/check-reference-contracts.py` exits 1 (no matches). That covers every alias, not only `rs.`. The other `.get(..., default)` calls are env vars, a K/M multiplier table, and `(None, None)` tuple defaults, which fail loudly through `log.eq`.

### Mutation (driver `target/software-only/logs/10-fix3r/mut-bl-sram.py` wraps `rust_consts` and pops `BL_SRAM_BASE`; no source or reference file mutated except the temporary swap below)
| # | command | exit | result |
|---|---|---|---|
| 1 | `python3 -B target/software-only/logs/10-fix3r/mut-bl-sram.py tools/check-reference-contracts.py --skip-pixel --json …/mut-new.json` (fixed code) | 1 | `FAILED elf/end-below-bl-sram -- could not read the cold-snap side of BL_SRAM_BASE (renamed, removed or ambiguous?): BL_SRAM_BASE=None` |
| 2 | same driver, with `tools/check-reference-contracts.py` temporarily set to the pre-fix `:601` line only (restored after; sha1 matched `fixed.sha`) | 1 | `FAILED elf/end-below-bl-sram -- _end (0x20018058) below BL_SRAM_BASE …: cold-snap has False`. The failure blames `_end`, which is the misattribution this finding describes. |
| 3 | `python3 -B tools/check-reference-contracts.py --json target/software-only/fix3-refcheck/result.json` (real) | 0 | PASS: 136 checks. `COVERED elf/end-below-bl-sram … == True` |
| 4 | `python3 -B tools/test-reference-contracts.py` | 0 | 6/6 negative cases behaved |

Logs: `target/software-only/logs/10-fix3r/{mut-new,mut-old,real,selftest}.log`. Not committed.

## Fix 3 — close-out

**Status: FIXED (a, b, c, d)**, scoped to software/pre-bench checks of those four guards. Committed in cold-snap only (frostsnap unchanged by this fix).

### Re-runner commands (RE-RUNNER, not the implementer; cwd `/Users/garykrause/repos/cold-snap`, logs under `target/software-only/verify-rerun-tighten/`)
| command | exit | result |
|---|---|---|
| `cargo test --target aarch64-apple-darwin -p coldsnap_hal -p coldsnap_firmware --features coldsnap_hal/fake-flash,coldsnap_hal/test-seam` | 0 | 553 passed, 0 failed; the new install test ok |
| `python3 -B tools/check-reference-contracts.py --json …/refcheck.json` | 0 | PASS: 136 checks |
| `python3 -B tools/test-reference-contracts.py` | 0 | 6/6 |
| `python3 -B tools/test-pack-signed.py` | 0 | OK: 22 cases |
| `python3 -B tools/test-software-readiness.py` | 0 | 73 ok, incl. the 3 new bad-layout cases |
| `cargo build --release`; `pack-signed.py --pubkey-num 0`; checkfw on `.bin` and `.dfu` | 0 / 0 / 0 / 0 | |
| `cargo clippy [--release] --target thumbv7em-none-eabihf -p coldsnap_hal -p coldsnap_firmware` | 0 / 0 | 18 warnings, all in vendor/frostsnap |
| `cargo run --release … --example heap_session …` | 0 | FITS, slack 10860 B |
| mutations A, B0-B3, C1, C2, D1, D2 (mirror or in-place + restore, `cmp`/`shasum -c` verified) | as implementer | every new guard failed for its named reason; HEAD's guard missed A, B1, D1 and passed B2/B3's own rows |
| 24 readiness stages touching the changed files via `run-stages.py` | wrapper rc not captured | 23 passed; `registry-matches-artifact` failed |

Repair re-run (REPAIRER): `mut-bl-sram.py` driver exit 1 naming `BL_SRAM_BASE` on fixed code vs exit 1 blaming `_end` on the pre-fix line; real `check-reference-contracts.py` exit 0 (136); `test-reference-contracts.py` exit 0 (6/6); `grep -nE "\.get\([^)]*,\s*[0-9]"` exit 1 (no match). Logs `target/software-only/logs/10-fix3r/`.

### CONFIRMED findings
1. `tools/check-reference-contracts.py:601` still read `mm.get('BL_SRAM_BASE', 0)` (alias of `rs`), so a missing key failed as a misattributed `_end` placement. **Fixed** by repair 1 (`log.need`).
2. Readiness stage `registry-matches-artifact` fails: the rebuilt artifact's announced digest is not in `frostsnap_coordinator/src/coldsnap-mk4-registry.txt`. **Not caused by fix 3 and not fixed here**: HEAD's install.rs builds a byte-identical firmware0/1.bin; any relink changes the header timestamp and so the digest, and the registry has been stale since 6b2e5c2/161c0ba. Needs task 02's `register-mk4-firmware.py`; the full profile stays red until then.

### Still open (not this fix's scope)
- Full readiness profile not re-run.
- `registry-matches-artifact` (above).
- Stale "known BLOCKED" comment at `tools/check-software-readiness.py:347-348`.
- `checkfw-negative-signature`'s `[FAIL] R12 ` also matches R12's "range unusable" variant.

Note: the `07-rerun2/mut-summary.txt` correction lives under ignored `target/software-only/logs/` and is not committed; the original is at `logs/10-fix3/07-rerun2-mut-summary.txt.orig`.

### Commit
- cold-snap: the fix 3 close-out commit (`tools/test-pack-signed.py`, `tools/check-reference-contracts.py`, `firmware/src/install.rs`, `tools/check-software-readiness.py`, `tools/test-software-readiness.py`, this file, `run.json`, the 01/03/07/09 evidence files; see `git log`, it cannot name its own SHA).

## Fix 4 — pin cold-snap hostcheck to a frostsnap revision

**Status: FIXED** (re-run by verifiers; repair 1 applied; final status in § "Fix 4 — close-out"). The original implementer status line read: FIXED (implementer; not yet re-run by a verifier, not committed). Closes the open CONFIRMED finding #13 of
`target/software-only/evidence/02-recognize-coldsnap-in-app.md` (STATUS block at :13-22, table row at :1199):
`hostcheck/Cargo.toml:59` was a path dependency on `../../frostsnap` that recorded no revision, so a mismatched
checkout broke hostcheck with unrelated compile errors (reproduced below as `E0432 unresolved import
frostsnap_coordinator::DeviceProfile`). Task 02's status in run.json is not changed here. Only claim: software/pre-bench
checks passed, for these checks.

**Commands below are the IMPLEMENTER's.** Logs: `target/software-only/logs/10-fix4/`. Scratch trees:
`target/software-only/fix4/` (ignored). `$HOME/repos/frostsnap` was only read (`rev-parse`, `clone --no-local`
source, `archive`); nothing was checked out, reset, or worktree'd there.

### Real Cargo pin: tried, works, not adopted

`git = "file:///Users/garykrause/repos/frostsnap", rev = "366da527…"` for both `frostsnap_coordinator` and `frost_backup`, in
a scratch copy of hostcheck (`target/software-only/fix4/gitpin`): `cargo test --target aarch64-apple-darwin` exit **0**,
2 passed (the first attempt exited 101 only because the scratch copy lacked `../../golden`). Cargo.lock recorded
`source = "git+file:///Users/garykrause/repos/frostsnap?rev=366da527…#366da527…"` and resolved the same package versions.
Not adopted, for these measured or structural reasons:
1. Cargo rejects relative git URLs: `git = "../../../../../frostsnap"` gives exit 101 `invalid url ...: relative URL
   without a base`; `file:../../…` resolves to `file:///frostsnap` and fails. So the pin would hardcode one user's
   absolute path in `hostcheck/Cargo.toml` and `Cargo.lock`. Today the manifest only assumes a sibling checkout.
2. It ignores `$FROSTSNAP_REPO`, and it builds a cargo-cached clone of the commit rather than the tree every other
   readiness stage tests.
3. Its only mismatch failure (rev absent from the repo) happens in cargo's dependency resolution. That runs before
   any build script, so nothing could print both SHAs and the fix.
Also noted: `$HOME/repos/frostsnap` is a shallow repository (`rev-parse --is-shallow-repository` → `true`).

### What was built instead (recorded revision, checked twice)

- `hostcheck/frostsnap.rev` (new): 3 comment lines + `366da527e9268195d5cf000b6cd92ca879a6a153`. This equals
  `git -C "$HOME/repos/frostsnap" rev-parse HEAD` after fixes 2a/2b (`366da52`, fix 2b's frostsnap commit).
- `hostcheck/check-frostsnap-pin.sh` (new, POSIX sh, shellcheck exit 0): one implementation of the policy. Exit 0 = HEAD is the pin
  and no tracked edits in `Cargo.toml frostsnap_coordinator frostsnap_core frostsnap_comms frost_backup macros` (the
  path packages in `hostcheck/Cargo.lock`: :46-48). Exit 3 = HEAD descends from the pin, or those crates have tracked
  edits (:35-37, :50-52). Exit 1 = a named failure: pin file unreadable or not a 40-hex SHA (:20-22), checkout missing (:23),
  not a git repo (:26), not its own checkout, e.g. an export sitting inside cold-snap (:27), no HEAD (:28), pin not in
  the repo (:33-34), HEAD older than the pin (:38-40), or diverged (:41-43). Every mismatch prints `pinned <sha>`,
  `HEAD <sha>` and both fixes: check out the pin, or bump after verifying (:13-17).
- `hostcheck/build.rs` (new): runs the script before `src/main.rs` compiles. 0 → nothing; 3 → `cargo:warning` lines;
  anything else → prints the output and exits 1. `rerun-if-changed` is on the pin file, the script, and
  `../../frostsnap/.git/{HEAD,packed-refs,refs/heads}`. It reads `CARGO_MANIFEST_DIR` at run time: the first draft
  used `env!`, which baked in the directory the script was first compiled in. Caught by the scratch pairs (every pair
  reported pair-work-old's HEAD) and fixed before any result below.
- `hostcheck/Cargo.toml:24-37`: documents the pin, the policy and why a Cargo pin was not used; `:71` bump note.
- `tools/check-software-readiness.py:342-347`: new stage `frostsnap-pin` (group coordinator, ahead of hostcheck-tests),
  `sh hostcheck/check-frostsnap-pin.sh $FS`, cwd cold-snap, and `must` = the `OK: HEAD is the pin` line. It has no
  `needs`, so a missing frostsnap is this stage's own named failure, not `unavailable`.
- `tools/test-software-readiness.py:226-278` (block ends before :280): 10 new cases. They run the real stage on the real checkout (passed),
  then the same argv on a synthetic repo with its own pin file: equal → passed; older → failed rc 1 with both SHAs
  and "bump"; ahead → failed rc 3; diverged → rc 1; tracked edit → rc 3 EDITED; pin absent → rc 1; unreadable pin
  file; missing dir; a non-checkout directory inside cold-snap.
- `README.md:508-533`: "Bumping the frostsnap pin", with the policy table and the bump recipe.

**Policy, and why.** A *descendant* has every commit cold-snap depends on. hostcheck builds against it with a
warning that names both SHAs, because building against the new HEAD is how you verify it before a bump. Refusing
would block the verification. The runner still fails the stage (rc 3), because its report must describe the
recorded pair, and a descendant is unverified. Tracked edits in the pinned crates get the same treatment: the build
is then not the pin. *Older, diverged, or pin-absent* trees lack code hostcheck names, which is exactly the
confusing-compile-error case, so they fail the build and the stage by name. *Missing or not a git repo*: the
revision is unknowable, so it is a named failure. The one exception is a missing
`../../frostsnap/frostsnap_coordinator`: cargo's own path resolution fails first ("failed to read
…/frostsnap/frost_backup/Cargo.toml"), before any build script. That is early, names the path, and produces no
compile errors, but it does not print SHAs. The runner stage covers it by name.

### Commands (implementer)

| # | command | cwd | exit | time |
|---|---|---|---|---|
| 1 | `git status --porcelain` / `git diff --stat` both repos | both | 0 | <1 s | clean apart from the user's files
| 2 | git-pin scratch `cargo test --target aarch64-apple-darwin` (no golden) | fix4/gitpin | 101 | 21 s |
| 3 | same, golden copied | fix4/gitpin | **0** (2 passed) | 1 s |
| 4 | `cargo metadata` with relative git URL / `file:` relative URL | fix4/gitpin | 101 / 101 | <1 s |
| 5 | `sh hostcheck/check-frostsnap-pin.sh $HOME/repos/frostsnap` | cold-snap | **0** OK | 0 s |
| 6 | same script vs demo/{old,ahead,diverged,absent,archive,dirty-src,nonexistent}, bad pin file | fix4 | 1,3,1,1,1,3,1,1 | <1 s each |
| 7 | `GIT_CEILING_DIRECTORIES=demo sh … demo/archive` | fix4 | 1 "is not a git repository" | <1 s |
| 8 | BASELINE: HEAD's hostcheck (`git archive HEAD hostcheck`) `cargo build --offline` vs demo/old (9d7f55b = e31dea9^) | fix4/demo/pair-*-head-old | **101**, `error[E0432]: unresolved import frostsnap_coordinator::DeviceProfile` | 15 s / 7 s (final) |
| 9 | new hostcheck `cargo build --offline` vs old / diverged / absent / archive | fix4/demo/pair-work-* | 101 each, **0 `error[E`**, "failed to run custom build command" + MISMATCH/not its own checkout | 1-8 s |
| 10 | same vs ahead / dirty-src | pair-work-* | **0**, `warning: hostcheck@0.1.0: FROSTSNAP PIN: AHEAD` / `EDITED` | 7-9 s |
| 11 | rerun-if-changed: build OK at pin; `reset --hard 9d7f55b` in demo/moving → rebuild; reset to pin → rebuild; no-op rebuild | pair-moving | 0 → **101** MISMATCH → 0 → 0 | ~7 s |
| 12 | missing frostsnap (dangling symlink) `cargo build --offline` | pair-missing | 101, cargo's "failed to load manifest for dependency `frost_backup`" | 0 s |
| 13 | runner stage alone (`R.run_stage` of `frostsnap-pin`) on the real checkout | cold-snap | passed rc 0 | 0.04 s |
| 14 | same with `FROSTSNAP_REPO=demo/old`, `demo/ahead`, `demo/archive` | cold-snap | failed rc 1 / rc 3 / rc 1 | <1 s |
| 15 | `cargo build --target aarch64-apple-darwin -p coldsnap_firmware --example stub` | cold-snap | 0 | 6 s |
| 16 | `cargo test --target aarch64-apple-darwin` | hostcheck | **0**, 2 passed, no FROSTSNAP line | 4 s |
| 17 | `cargo run -- ../target/aarch64-apple-darwin/debug/examples/stub` | hostcheck | **0**, `M1+…+M13 PASS` | 19 s |
| 18 | `cargo clippy --target aarch64-apple-darwin` | hostcheck | 0, 0 warnings | 6 s |
| 19 | `shellcheck check-frostsnap-pin.sh` | hostcheck | 1 (SC2086), then fixed → 0 | <1 s |
| 20 | `python3 tools/test-software-readiness.py` (final) | cold-snap | **0**, `PASS: 0 failed case(s)`, 83 ok | 56 s |
| 21 | final pairs, fresh scratch target dir: new vs old / ahead | fix4 | 101 (0 `error[E`) / 0 (AHEAD warning) | 7 s / 10 s |
| 22 | `cargo test` (final script) | hostcheck | 0, 2 passed; `git diff --quiet hostcheck/Cargo.lock` → 0 | 1 s |

Harness note: a first "final" pair (row 21's first attempt) showed `E0432`. The scratch pairs shared one
`CARGO_TARGET_DIR`, and `tar` kept build.rs's original mtime, which was older than M3's mutated copy, so cargo reused M3's
build-script binary. With the scratch target dir deleted, the result is the one in row 21. This only affects the
scratch harness: the real hostcheck has its own target dir and build.rs is not copied.

While fixing SC2086 I first piped `git diff` into `tr`, which would have hidden git's exit status. It now captures
git's status first and filters separately (script :50-51).

### Mutations (each fails for its named reason; real code passes, rows 16-22)

| id | mutation (in-tree script restored byte-exact from `logs/10-fix4/pin.sh.orig`; sha256 `363ac4f0…` before = after, a PRE-shellcheck version, NOT the final script `590b2a79…`; M1/M2/M4 re-run on the final script in "Fix 4 — repair 1 of 1") | result |
|---|---|---|
| M0 | none: HEAD's hostcheck vs older tree | E0432 (the original confusing failure) |
| M1 | `if [ "$head" != "$pin" ]` → `if false` | self-test exit 1: older, ahead, diverged, pin-absent cases FAIL (55 s) |
| M2 | drop the `top = real` check | self-test exit 1: "not its own git checkout" case FAIL (57 s) |
| M4 | drop the dirty check | self-test exit 1: EDITED case FAIL (56 s) |
| M3 | scratch build.rs: failure branch → warnings only (`Some(3)` → `_`) | build vs old: rc 101 with `error[E0432]` behind the MISMATCH warning. The hard failure is what prevents the confusing error. |

The sha-256 values above are for the pre-shellcheck script. The script was then edited (:50-51), and rows 20-22 re-ran on the
final version.

### Left undone
- The runner's `FS` (`$FROSTSNAP_REPO`) and hostcheck's compiled `../../frostsnap` can still be different trees when
  the variable is overridden. build.rs checks the sibling and the stage checks `FS`, so each tree is checked, but
  nothing asserts they are the same tree. This is a pre-existing runner property, not introduced here.
- No full readiness profile run. The new stage and hostcheck stages were run on their own (rows 13, 16, 17).

## Fix 4 — repair 1 of 1

### Findings
- **F1/F3 (EDITED warning goes stale after a clean build): FIXED.** Cause: `hostcheck/build.rs` printed
  `rerun-if-changed` only for `frostsnap.rev`, the script and frostsnap's `.git/{HEAD,packed-refs,refs/heads}`, so
  cargo never re-ran it for a crate-source edit. build.rs now also prints `rerun-if-changed` for every entry on the
  script's own `crates="..."` line (read from `check-frostsnap-pin.sh` at run time, so the lists cannot drift; a
  missing line panics with a `FROSTSNAP PIN:` message). Cargo scans a listed directory recursively.
  README "Bumping the frostsnap pin" now states when the check re-runs; build.rs header says the same.
- **F2 (mutation provenance sha): FIXED.** The :662 table header now says `363ac4f0…` is the pre-shellcheck script,
  and M1/M2/M4 were re-run on the final script (below).

### Commands (cwd given; exit = the process's own status)
| # | command | cwd | exit / result |
|---|---|---|---|
| 1 | `git clone --no-hardlinks $HOME/repos/frostsnap demo/pinclean; git -C demo/pinclean checkout 366da52…` | fix4/demo | 0, HEAD = pin |
| 2 | `pair-r1.sh r1 pinclean work build --offline` (new build.rs, fresh target dir `demo/target-r1`) | fix4 | 0, 0 PIN lines (`logs/10-fix4/pair-r1.log`) |
| 3 | `cargo build --offline` no-op | pair-r1/cold-snap/hostcheck | 0, 0 PIN lines (`r1-noop.log`) |
| 4 | append `// r1 edit` to pinclean/frostsnap_coordinator/src/lib.rs; `cargo build --offline` | same | **0, 3 PIN lines, `EDITED: … frostsnap_coordinator/src/lib.rs`** (`r1-edit.log`) — the finding's exact scenario |
| 5 | rebuild again, edit still present | same | 0, EDITED replayed (`r1-edit-again.log`) |
| 6 | `git -C pinclean checkout -- …lib.rs`; rebuild; no-op rebuild | same | 0, 0 PIN lines / 0, 0 (`r1-reverted.log`, `r1-noop2.log`) |
| M5 | scratch copy of build.rs only: delete the new `for c in crates` loop; build; then same edit; build | same | 0, 0 PIN lines / **0, 0 PIN lines** — reproduces the finding; the loop is what fixes it. pinclean restored, `status --porcelain` empty |
| 7 | `target/software-only/logs/10-fix4r/muts.sh`: final script sha256 `590b2a79b3cb47eb07e209a61239dc738d5bfeb3a12e5f8815d1ba1dbc432be6` saved as `logs/10-fix4r/pin.sh.final`; each mutation applied in-tree, `python3 tools/test-software-readiness.py`, restored | cold-snap | M1 (`if false`) rc 1: older/ahead/diverged/pin-absent FAIL; M2 (drop top=real) rc 1: not-its-own-checkout FAIL; M4 (drop dirty check) rc 1: EDITED FAIL (`mut-M{1,2,4}.log`) |
| 8 | after restore: sha256 = `590b2a79…` and `cmp` with pin.sh.final | cold-snap | 0, byte-exact |
| 9 | `python3 tools/test-software-readiness.py` | cold-snap | **0**, `PASS: 0 failed case(s)` (`logs/10-fix4r/selftest-final.log`) |
| 10 | `cargo test --target aarch64-apple-darwin` | hostcheck | **0**, 2 passed, 0 PIN lines |
| 11 | `cargo clippy --target aarch64-apple-darwin` | hostcheck | 0, 0 warnings |
| 12 | `git diff --quiet hostcheck/Cargo.lock` | cold-snap | 0 |
| 13 | `sh check-frostsnap-pin.sh $HOME/repos/frostsnap`; `git -C $HOME/repos/frostsnap rev-parse HEAD` | hostcheck | 0 OK; HEAD `366da527…` = pin |

### Files changed (working tree only, not committed)
`hostcheck/build.rs`, `README.md` (pin section), this evidence file. `check-frostsnap-pin.sh` unchanged (sha above).

### Not re-run
`cargo run` of hostcheck against the stub (build.rs change does not touch `src/`; `cargo test` compiled it). No full readiness profile.

## Fix 4 — close-out

**Status: FIXED**, scoped to software/pre-bench checks. Finding #13 of task 02 (the unpinned path
dependency at `hostcheck/Cargo.toml:59`) is closed. cold-snap now records frostsnap `366da527e9268195d5cf000b6cd92ca879a6a153`
in `hostcheck/frostsnap.rev`. That equals frostsnap HEAD after fixes 2a/2b. The pin is checked by `hostcheck/build.rs`
before `src/main.rs` compiles, and by the readiness stage `frostsnap-pin`. A mismatch fails by name, prints both SHAs
and the fix, and produces 0 `error[E` lines. A real Cargo `git`+`rev` pin was tried: it builds, but it was not
adopted, because cargo rejects relative git URLs and the pin would hardcode an absolute path in Cargo.toml and
Cargo.lock (reasons in § "Real Cargo pin"). Policy: an ahead (descendant) tree builds with warnings but fails the
stage (exit 3); an older, diverged, pin-absent, missing or non-git tree fails both (exit 1). This is documented in
README "Bumping the frostsnap pin". This fix changed cold-snap only; frostsnap was only read.
The full readiness profile does **not** pass at this pair, for a cause that predates fix 4 (finding R2-1 below).

### Implementer commands (IMPLEMENTER; see § "Fix 4" and § "Fix 4 — repair 1 of 1")
The pin script ran against old/ahead/diverged/absent/archive/dirty/nonexistent/bad-pin trees: 1/3/1/1/1/3/1/1.
Baseline: HEAD's hostcheck built against 9d7f55b gives 101 with E0432. The new hostcheck against old/diverged/absent/archive
gives 101 with 0 `error[E`; against ahead/dirty it gives 0 with warnings. Other results: `cargo test` 0 (2 passed), `cargo run` vs stub 0,
clippy 0, shellcheck 0, `tools/test-software-readiness.py` 0 (83 ok), Cargo.lock unchanged. Repair: the rerun sequence
clean/no-op/edit/rebuild/revert/no-op gave 0 at each step, with EDITED appearing after the edit. Mutation M5 brings the stale-warning bug back. M1/M2/M4 were re-run
on the final script (sha256 `590b2a79…`), each self-test rc 1.

### Re-runner commands (RE-RUNNER, not the implementer; scratch `target/software-only/verify-rerun-pin/`)
| command | cwd | exit / result |
|---|---|---|
| `sh hostcheck/check-frostsnap-pin.sh $HOME/repos/frostsnap` | cold-snap | 0, "OK: HEAD is the pin" |
| same vs own trees older / ahead / diverged / dirty / archive / plain-nested / missing / empty | cold-snap | 1 / 3 / 1 / 3 / 1 / 1 / 1 / 1, each named |
| bad / 7-char / absent pin file | cold-snap | 1 / 1 / 1 |
| baseline HEAD hostcheck vs 9d7f55b `cargo build` | scratch | 101, E0432 DeviceProfile |
| new hostcheck vs old / diverged / archive | scratch | 101 each, 0 `error[E`, MISMATCH message |
| new hostcheck vs ahead / dirty / real | scratch | 0 / 0 (warnings) / 0 (no pin lines) |
| new hostcheck, frostsnap missing | scratch | 101, cargo "failed to load manifest" (no SHAs; disclosed) |
| repaired rerun sequence on a clone at the pin (clean/no-op/edit/rebuild/revert/no-op) | scratch | 0 each; PIN lines 0/0/3/3/0/0 |
| M5 (build.rs rerun loop removed, scratch) | scratch | bug returns: 0 PIN lines after edit |
| M1/M2/M4 on scratch copies of the final script | scratch | each gives the wrong outcome its self-test case asserts against |
| `frostsnap-pin` stage, `FROSTSNAP_REPO` = real / old / ahead / archive / missing | cold-snap | passed rc0 / failed rc1 / rc3 / rc1 / rc1 |
| `python3 tools/test-software-readiness.py` | cold-snap | 0, 83 ok, `PASS: 0 failed case(s)` |
| `cargo test` / `cargo clippy` (`--target aarch64-apple-darwin`) | hostcheck | 0 (2 passed) / 0 (0 warnings) |
| `shellcheck check-frostsnap-pin.sh`; `git diff --quiet hostcheck/Cargo.lock` | hostcheck / cold-snap | 0; 0 |
| `python3 tools/check-software-readiness.py --profile full --output-dir target/software-only/verify-rerun-pin/full` | cold-snap | **1**, NOT PASSED: registry-matches-artifact, app-rig (rc4), updater-local-artifact (rc101); 39 passed incl. frostsnap-pin, hostcheck-tests, hostcheck-run, coordinator-verbatim |

### CONFIRMED findings
1. R1-F1 / R1-F3: build.rs did not re-run on edits to the pinned crates' sources, so the EDITED warning went stale after
   a clean build. **Fixed** by repair 1: build.rs reads the script's `crates=` line and prints `rerun-if-changed` for each entry.
   The re-runner reproduced this, and M5 kills it.
2. R1-F2: the evidence's mutation sha256 `363ac4f0…` was the pre-shellcheck script, not the final one. **Fixed** by repair 1: the
   header is corrected, and M1/M2/M4 were re-run on the final `590b2a79…`.
3. R2-1: at the recorded pin the full profile fails. `registry-matches-artifact`, `app-rig` (`unrecognized-c86392`) and
   `updater-local-artifact` all fail because frostsnap's `coldsnap-mk4-registry.txt` lacks the current cold-snap image
   digest `c86392bc…`. **Not fixed; not caused by fix 4**, which touches no firmware. It predates this fix and is the same
   stale-registry item recorded in § "Fix 3 — close-out". It needs task 02's `register-mk4-firmware.py` plus a
   frostsnap commit and a pin bump. The README bump steps check hostcheck only, so "frostsnap-pin passed" does not
   mean the pair passes readiness.

### PLAUSIBLE findings (recorded, not fixed)
- Under the edits-only-warn policy, old coordinator sources under HEAD==pin still reach the compiler (EDITED warnings,
  then E0432). The warning names the cause.
- In the "pin not in this checkout" case, the printed `git checkout <pin>` remedy cannot work without a fetch first. `$HOME/repos/frostsnap`
  is a shallow clone. A shallow descendant that lacks the pin fails as pin-absent, not as AHEAD.
- For OLDER or diverged trees, the "bump the pin" remedy wording could suggest pinning an older HEAD. Behaviour is correct.

### Still open
- Nothing checks that `$FROSTSNAP_REPO` (the runner) and `../../frostsnap` (build.rs) are the same tree. This gap predates the fix.
- R2-1 registry staleness (above). The full profile stays red until then.
- README "Known today" still says coordinator-verbatim is blocked, which fix 1 made stale.
- If `../../frostsnap` does not exist at all, cargo fails in path resolution before build.rs runs. That is early and names the path, but prints no SHAs.

### Commit
- cold-snap: the fix 4 close-out commit (`hostcheck/Cargo.toml`, `hostcheck/build.rs`, `hostcheck/check-frostsnap-pin.sh`,
  `hostcheck/frostsnap.rev`, `README.md`, `tools/check-software-readiness.py`, `tools/test-software-readiness.py`, this
  file, `run.json`, the 02 evidence file). See `git log`; the commit cannot name its own SHA. frostsnap: no commit (unchanged).

## Fix 5 — full readiness profile

**Fix 5 status: NOT FIXED.** Reason: the full profile ran verbatim to completion but exits 1, and the goal was exit 0 with every stage passed. The cause is outside this pass's source changes and needs the user's go-ahead: the current image's digest is not registered through task 02's workflow. See "Fix 5 — close-out".

**Run status: NOT PASSED (exit 1).** 42 stages: 39 passed, 3 failed, 0 blocked/unavailable. All three failures have one cause: frostsnap's
`frostsnap_coordinator/src/coldsnap-mk4-registry.txt` lacks the announced digest of the current cold-snap image,
`c86392bc005ddfc8d019eb545b4b05876cc8da5ab22ebb941b514c17c6d9e7ce`. Fix 2a's firmware change (cold-snap 6b2e5c2) made the registry stale. This was already recorded
in § "Fix 3 — close-out" item 2 and § "Fix 4 — close-out" R2-1. The digest is stable across rebuilds: this run's
`pack` produced the same c86392bc as fix 4's run.

Pair tested: cold-snap `45a3f85` (clean apart from user files), frostsnap `366da52` == `hostcheck/frostsnap.rev` (clean apart from user files).
No source file changed in this fix, so there were no mutations. The runner, stages and assertions are unchanged.

### Commands (implementer)
| command | cwd | exit | elapsed |
|---|---|---|---|
| `python3 tools/test-software-readiness.py` | cold-snap | 0 (`PASS: 0 failed case(s)`) | 56 s |
| `python3 tools/check-software-readiness.py --profile full --output-dir target/software-readiness` (background, log `target/software-only/logs/10-fix5/full.log`) | cold-snap | **1** | 375 s |
| `python3 frostsnap_coordinator/tools/register-mk4-firmware.py …/package/firmware-signed.bin mk4-2026-09-25` | frostsnap | NOT RUN: the auto-mode permission classifier denied the write to the registry | — |

Report: `target/software-readiness/results.json` (started 2026-09-25T16:32:44-04:00, finished 16:38:59, label
`NOT PASSED: registry-matches-artifact=failed, app-rig=failed, updater-local-artifact=failed`). Copies are in `target/software-only/logs/10-fix5/`.

### Per-stage (from results.json)
Passed (rc, s): host-frostsnap-macros 0/2.42, host-frostsnap-embedded-std 0/1.7, host-frostsnap-comms 0/2.1, host-frostsnap-core 0/19.71,
host-frost-backup 0/5.13, host-coldsnap-firmware 0/2.17, host-coldsnap-hal 0/3.79, arm-clippy-dev 0/0.57, arm-clippy-release 0/0.57,
arm-build-release 0/0.68, refcheck 0/13.87, refcheck-negatives 0/27.3, pack 0/0.84, pack-tests 0/1.82, pack-negative-bad-layout 1/0.2,
checkfw-bin 0/0.53, checkfw-dfu 0/0.36, checkfw-negative-signature 1/0.42, checkfw-negative-misaligned 1/0.42, checkfw-negative-family 1/0.41,
pixel-check 0/0.89, heap-session 0/0.8, stub-build 0/0.25, frostsnap-pin 0/0.08, hostcheck-tests 0/1.49, hostcheck-run 0/17.95,
coordinator-verbatim 0/7.05, coordinator-scoped 0/2.57, rust-lib-frostsnapp 0/2.3, register-self-check 0/0.08, flutter-analyze 0/28.68,
flutter-test 0/3.39, bridge-gen-reproducible 0/33.5, build-runner-reproducible 0/18.62, updater-stub-ignored 0/2.83, updater-lib-ignored 0/3.75,
app-bridge-ignored 0/6.16, controller-erase-fake 0/6.17, install-xproc 0/2.3. (The negative stages expect rc 1.)

Failed:
- `registry-matches-artifact` rc 0, 0.04 s: digest c86392bc… is not in the registry (`logs/registry-matches-artifact.out`).
- `app-rig` rc 4, 127.33 s: the app refused keygen with `unrecognized-c86392` (`logs/app-rig.out:8,20`). Device 3 then exited 2 with no reveal sheet (`app-rig/device-3.log`), so this is a downstream effect.
- `updater-local-artifact` rc 101, 0.53 s: `mk4_firmware_artifacts.rs:377` `assertion failed: registered_mk4_revision(&raw.digest()).is_some()`.

### Orphans
`ps -axo pid,pgid,command` filtered for coldsnap/stub/flutter/frostsnapp/bitcoin-node/qemu/ibtoold/app-rig after the run: only PID 13555
(the user's testnet4 node, not ours). No orphans. `git status --porcelain` in both repos shows only the pre-existing user files.

### Left undone
Registration was not done. It is task 02's explicit workflow (spec 09 Work item 6), and it was not bypassed. For a green full profile:
1. In frostsnap, run `python3 frostsnap_coordinator/tools/register-mk4-firmware.py "$HOME/repos/cold-snap/target/software-only/package/firmware-signed.bin" mk4-2026-09-25`
   and commit the registry. A commit is required, because an uncommitted edit makes `frostsnap-pin` fail with EDITED (rc 3).
2. Bump `hostcheck/frostsnap.rev` to the new frostsnap HEAD after hostcheck passes against it (README "Bumping the frostsnap pin"), and commit it.
3. Re-run the full profile. This report cannot stand in for that run.
The only claim available is "software/pre-bench checks passed" for the 39 passed stages. The full profile is not passed.

## Fix 5 — re-runner checks and findings

Re-runner 1 (independent full run, output dir redirected so the implementer's report was not overwritten; command otherwise verbatim):
| command | cwd | exit |
|---|---|---|
| `python3 tools/test-software-readiness.py` (log `target/software-only/verify-rerun-final/logs/selftest.log`) | cold-snap | 0 (`PASS: 0 failed case(s)`) |
| `python3 tools/check-software-readiness.py --profile full --output-dir target/software-only/verify-rerun-final/software-readiness` (background, log `target/software-only/verify-rerun-final/logs/full.log`) | cold-snap | 1 (39 passed, 3 failed, 0 blocked; 16:43:04 to 16:48:30) |
| `grep c86392 frostsnap_coordinator/src/coldsnap-mk4-registry.txt` | frostsnap | 1 (no match) |

Same three failures with the same cause: registry-matches-artifact rc 0/0.04 s, app-rig rc 4/121.89 s (`unrecognized-c86392`), updater-local-artifact rc 101/0.68 s (`mk4_firmware_artifacts.rs:377:5`). orphans_after_run `[]`; only PID 13555 (user's node) in `ps`.

Re-runner 2 (read-only): the implementer's `target/software-readiness/results.json` is byte-identical to `logs/10-fix5/results.json`; `full.exit` reads `exit=1 elapsed=375s`; no source diff in either repo; frostsnap HEAD 366da52 == `hostcheck/frostsnap.rev`.

CONFIRMED findings: none from either re-runner. Repair: none needed. (Re-runner 2 noted, as framing, that the stale registry follows from this pass's fix 2a `6b2e5c2`, so "pre-existing" is loose; recorded here, not a defect.)

## Fix 5 — close-out

- **Status: NOT FIXED.** Two independent full-profile runs from this pass both exit 1 with 39/42 passed and 3 failed, 0 blocked/skipped. No stage was removed, reclassified or relaxed. No earlier results.json was reused.
- **Closed by this fix:** "full profile not re-run after fixes 1 and 3" (09 follow-ups). It has now run, twice. `coordinator-verbatim` passes in the full profile (rc 0), and so do `frostsnap-pin`, `hostcheck-run` and `pack-negative-bad-layout` (the fix 3 and fix 4 stages).
- **Still open:**
  1. `registry-matches-artifact`, `app-rig`, `updater-local-artifact` fail: digest `c86392bc005ddfc8d019eb545b4b05876cc8da5ab22ebb941b514c17c6d9e7ce` is not in `frostsnap_coordinator/src/coldsnap-mk4-registry.txt`. To finish (needs the user's go-ahead): run `register-mk4-firmware.py … mk4-2026-09-25` in frostsnap and commit it, bump `hostcheck/frostsnap.rev` once hostcheck passes, then re-run the full profile.
  2. The stale "known BLOCKED" note still sits at `tools/check-software-readiness.py:356` (formerly :347-348). It does not affect classification. Source is out of scope for close-out.
  3. `checkfw-negative-signature` pattern `[FAIL] R12 ` also matches the range-unusable variant (from fix 3, unchanged).
- **Commits:** cold-snap evidence-only close-out commit (this file, 09 evidence, run.json). frostsnap: none.
- The only claim available is "software/pre-bench checks passed", for the 39 passed stages. Real USB enumeration, timing, SE calls, entropy, flash power loss and actual installation remain bench-only and untested.

## Fix 6 — test the link-edge EraseConfirmed send

**Status: FIXED (software/pre-bench checks passed, scoped to this fix). Not committed.** Closes fix 2a CONFIRMED finding 6 above ("The real firmware's recovered-ack send (`firmware/src/main.rs:2614-2616`) has no test; M7/M7b survive every gate"), which left `08-implement-resumable-device-erasure.md` criterion 2 (truthful completion signal after an interrupted erase, :373, :401-407) proven only in the stub's copy of the logic.

**Design.** `boot` is `cfg(target_arch = "arm")`, so the link-edge send cannot be reached from a host test. It was hoisted, as the task allows. A plain `fn` moved the announced digest (MEASURED: `b050d128…`), and so did a `macro_rules!` inserted into main.rs above `boot` (`0eb48f75…`): the 5 differing body bytes were `core::panic::Location` line numbers of later main.rs panic sites, shifted by +17. The shipped form is a `#[macro_export] macro_rules! send_recovered_erase_ack` placed in lib.rs after every non-test item, just before `#[cfg(test)] mod tests`. At the main.rs call site, 3 lines are replaced by 3 lines (2 comment lines plus the invocation), and the `use` list stays 2 lines, so no production line number moves. `boot` expands the same tokens as before. The release ELF is byte-identical to HEAD's. Recovery order is unchanged: `erase::recover` still returns the id only after destroy+finish have verified the flash blank.

**Files changed** (cold-snap only; frostsnap untouched)
- `firmware/src/lib.rs:3236-3256`: the doc comment and `send_recovered_erase_ack!($recovered, $cdc)`. It is the old inline body verbatim, with `recovered_erase_ack` spelled `$crate::recovered_erase_ack`.
- `firmware/src/main.rs:1582-1583`: `recovered_erase_ack` is dropped from `boot`'s `use` (the macro names it by `$crate`). `:2614-2616`: the link edge now calls `coldsnap_firmware::send_recovered_erase_ack!(recovered_erase, cdc);`, still directly before `session.announce`.
- `firmware/src/main.rs:6604-6660`: new test `the_link_edge_sends_one_recovered_erase_ack_from_the_original_id`. On a `FakeFlash` it runs `erase::begin(old)` and then cuts, so `destroy` never ran. `erase::recover` must return `Some(old)`. Two link edges then run through the same macro against a recording fake `cdc`. Asserts: exactly 1 frame (`len() == 1`, not `>= 1`); its bytes equal an `Outbox::new(DeviceId(old))` + `EraseConfirmed`; the recovered id is `None` afterwards. Source pin over `production_source()`: exactly one `send_recovered_erase_ack!(` in production; it is directly followed by `let _ = session.announce(digest, &mut outbox);`; and it lies inside `if !was_linked && link.is_linked() {` with no `}` in between.

**Commands** (host aarch64-apple-darwin; logs in `target/software-only/logs/fix6/`)

| command | cwd | exit | time | result |
|---|---|---|---|---|
| `cargo build --release` then `python3 tools/pack-signed.py --pubkey-num 0 --out target/software-only/fix6-pack-base` (HEAD) | cold-snap | 0 / 0 | <1s / ~1s | announced digest `sha256(img[0:16320]+img[16384:401408])` = c86392bc005ddfc8…d6d9e7ce; ELF sha256 b7bd6c4a…; cmp-identical to `target/software-only/package/firmware-signed.bin` |
| same, with the plain-fn hoist (`fix6-pack-fn`) | cold-snap | 0 / 0 | | digest b050d128… (rejected) |
| same, with the macro in main.rs (`fix6-pack-macro`) | cold-snap | 0 / 0 | | digest 0eb48f75…, 5 Location line bytes differ (rejected) |
| `cargo build --release`; `pack-signed.py --pubkey-num 0 --epoch 1790366193 --out target/software-only/fix6-pack-macro2e` (final form, HEAD's frozen ts 2026-09-25T19:56:33Z) | cold-snap | 0 / 0 | 7s / ~1s | digest **c86392bc005ddfc8d019eb545b4b05876cc8da5ab22ebb941b514c17c6d9e7ce**; `cmp` against HEAD's pack = 0 (byte-identical signed image); ELF sha256 b7bd6c4a… = HEAD |
| `cargo test --target aarch64-apple-darwin -p coldsnap_hal -p coldsnap_firmware --features coldsnap_hal/fake-flash,coldsnap_hal/test-seam` | cold-snap | 0 | 10s | `final-test.log`: fw lib 170 (1 ign), fw bin 59 (was 58, +1 new), hal 301, 5, 19 |
| `cargo build --release` | cold-snap | 0 | 6s | ELF sha256 b7bd6c4a5a7662e5… (unchanged) |
| `cargo clippy --release --target thumbv7em-none-eabihf -p coldsnap_hal -p coldsnap_firmware` | cold-snap | 0 | 1s | 18 warnings, none in firmware/ or hal/ |
| `cargo clippy --target thumbv7em-none-eabihf -p coldsnap_hal -p coldsnap_firmware` | cold-snap | 0 | 0s | 18 warnings, none in firmware/ or hal/ |
| `cargo clippy --target aarch64-apple-darwin -p coldsnap_firmware --tests --features coldsnap_hal/fake-flash,coldsnap_hal/test-seam` | cold-snap | 0 | 2s | 18, none in firmware/ or hal/. An earlier placement after `mod tests` gave `items_after_test_module` at lib.rs; it was moved before the test module |
| `cargo build --target aarch64-apple-darwin -p coldsnap_firmware --example stub` | cold-snap | 0 | 2s | rebuilt after the mutation restores |
| `cargo run -- ../target/aarch64-apple-darwin/debug/examples/stub` | cold-snap/hostcheck | 1, then 0 | 2s / 19s | 1st: refused because lib.rs was newer than the stub (the restores rewrote it). After the stub rebuild: exit 0, all legs PASS |

**Mutations** (in place, backups `target/software-only/fix6-bak/`, each restore `cmp`-exact, full cargo test command, final code)

| id | mutation | exit | failed at / named reason |
|---|---|---|---|
| M7 | macro's `let _ = $cdc.write(ack.bytes());` → `let _ = ack;` (the earlier M7, now at its new site) | 101 | main.rs:6639 "two link edges must write exactly one recovered ack", left 0 |
| M7b | the link-edge call in main.rs deleted (the earlier M7b) | 101 | main.rs:6643 "`boot` must expand the recovered-ack send exactly once", left 0 |
| M7c | `.take()` → `.clone()` (the id never leaves RAM, so it is sent on every edge) | 101 | main.rs:6639 same message, left 2 |
| M7d | the send moved after `session.announce` | 101 | main.rs:6655 "the recovered ack must be written directly before the announce" |
| M7e | the ack is built from a fresh id `[3;33]` | 101 | main.rs:6640 "not EraseConfirmed under the original id" (id bytes 3… vs 2…) |
Each mutant fails only the new test (58 passed, 1 failed). On the real code: exit 0, 59 passed.

**Left open / residual**
- **Digest vs ELF mtime (pre-existing, not caused by this code).** `pack-signed.py` freezes the header timestamp to the ELF's mtime, and the timestamp is inside the announced-digest range. Any relink sets a new mtime, and editing lib.rs forces one. So a default `pack` of this byte-identical ELF now announces a different digest: MEASURED `d6f9c01b…` at mtime 2026-09-28T18:26:17Z. `registry-matches-artifact`, `app-rig` and `updater-local-artifact` will fail on that unless the pack uses `--epoch 1790366193` / `SOURCE_DATE_EPOCH`, or the new-timestamp digest is registered. Touching the mtime back does not hold, because the next `cargo build --release` relinks. Not registered: the code is byte-identical, so no non-test change needed it. The close-out has to decide.
- What this test drives is the macro's expansion on the host; the ARM `boot` loop itself is still not run. The pin ties that one expansion to the link-edge `if`, before the announce. It does not execute `link.is_linked()`.
- The fix 2a PLAUSIBLE residuals are unchanged: an ack is lost if `cdc.write` fails at the edge (`take` comes first), and the port-spoof gap.
- Host fault injection over `FakeFlash` is not STM32 erase or USB physics. Claim: software/pre-bench checks passed only.

## Fix 6 — repair 1 of 1

Scope: the three CONFIRMED review findings on Fix 6. Test-only change to `firmware/src/main.rs` (inside `#[cfg(test)]`), plus the readiness runner's `pack` argv. The release ELF is unchanged (sha256 b7bd6c4a…, same as HEAD). The signed pack is `cmp`-identical to the registered `package/firmware-signed.bin` (c86392bc…). Not committed.

1. **Source pin not line-anchored. FIXED.** The send needle now starts with `\n` plus 12 spaces and ends with `\n` after the announce, so `// ` in front of the call fails it. `production_source()` already refuses `/*`, the one comment form an anchor cannot catch.
2. **Mutations on the `recovered_erase` path survive (M7g/M7h). FIXED.** Two new pins in the same test. (a) The binding must be the anchored two lines `\n    let mut recovered_erase = match erase::recover(&mut *flash.borrow_mut()) {\n        Ok(original_id) => original_id,\n`. (b) `recovered_erase` as a whole identifier (no word char on either side) must occur exactly twice in production source: bound once, sent once. This also catches `.take()`, shadowing, or reassignment. Costs: a future production comment that names the bare identifier gives a false red.
3. **Next full-profile pack announces a new digest. FIXED in the runner.** `tools/check-software-readiness.py` now has `PACK_EPOCH = os.environ.get('SOURCE_DATE_EPOCH') or '1790366193'`, which is the header timestamp of the registered image (2026-09-25T19:56:33Z). The `pack` stage passes `--epoch PACK_EPOCH`. `pack-signed.py`'s mtime default is unchanged, so `test-pack-signed.py`'s rerun cases are unaffected. When a code change registers a new image, re-pin the epoch.

Mutants (`target/software-only/fix6r/mutants.py`; the first production occurrence is replaced in place and restored; the harness `cmp`s against the pre-run copies, both 0):

| id | mutation | exit | failing assertion |
|---|---|---|---|
| C1 | `// ` prepended to boot's `send_recovered_erase_ack!` line (finding 1) | 101 | main.rs:6657 "the recovered ack must be written, uncommented, directly before the announce" |
| M7 | macro write → `let _ = ack;` | 101 | main.rs:6639 "two link edges must write exactly one recovered ack" |
| M7b | boot's call line deleted | 101 | main.rs:6645 "`boot` must expand the recovered-ack send exactly once" |
| M7g | arm → `Ok(original_id) => { let _ = original_id; None }` | 101 | main.rs:6661 "`recovered_erase` must be bound to exactly what `erase::recover` returned" |
| M7h | `recovered_erase = None;` before step 8b | 101 | main.rs:6675 "`recovered_erase` may only be bound by `recover` and consumed by the send" |
| M7i | `let _ = recovered_erase.take();` before step 8b | 101 | main.rs:6675 same |

Harness pitfall, measured: the first harness restored with `shutil.copy2`, which put back the old mtime. Cargo then treated the restored lib.rs as fresh and kept the M7 build, so M7b/M7g/M7h all "failed" at the M7 assertion. Restoring with `shutil.copy` (new mtime), after touching both files, gives the table above. Earlier mutant tables built with an mtime-preserving restore should be read with this in mind.

| command (cwd cold-snap) | exit |
|---|---|
| `cargo test --target aarch64-apple-darwin -p coldsnap_firmware the_link_edge` (real code) | 0 (1 passed) |
| `target/pack-venv/bin/python target/software-only/fix6r/mutants.py` (6 mutants, each 101) | 0 |
| `cargo test --target aarch64-apple-darwin -p coldsnap_firmware` | 0 (170 passed 1 ignored; 59 passed) |
| `cargo clippy --target aarch64-apple-darwin -p coldsnap_firmware --tests` | 0; no warnings at the new lines (after `map_or(true,…)` → `is_none_or`) |
| `cargo clippy --release --target thumbv7em-none-eabihf -p coldsnap_hal -p coldsnap_firmware` | 0; 0 main.rs warnings |
| `cargo build --release` | 0; ELF sha256 b7bd6c4a… |
| `pack-signed.py --pubkey-num 0 --epoch 1790366193 --out target/software-only/fix6r/pack` then `cmp` vs `target/software-only/package/firmware-signed.bin` | 0 / 0 (byte-identical to the registered c86392bc artifact) |
| `check-software-readiness.py --list` | pack argv shows `--epoch 1790366193` |
| `python3 tools/test-software-readiness.py` | 0 ("PASS: 0 failed case(s)") |

Not run: the full readiness profile. Logs: `target/software-only/logs/fix6r-*.log`. Host fault injection over `FakeFlash` is not STM32 erase or USB physics. The only claim is that software/pre-bench checks passed, scoped to this fix.

## Fix 6 — close-out

- **Status: PARTLY FIXED.** Fix 2a finding 6 is closed as specified: the new host test `the_link_edge_sends_one_recovered_erase_ack_from_the_original_id` (`firmware/src/main.rs`, test module) requires exactly one `EraseConfirmed` frame, byte-equal to one built under the original `DeviceId`, across two link edges after `erase::recover` returns `Some(old)`. M7 and M7b now fail it, each at its named assertion, and the suite passes on the real code. It is not FIXED because the final re-runner found a CONFIRMED mutant (X1, below) that still removes the ARM send while every gate passes. It stays open because close-out may not touch source.
- **Release image unchanged.** The release ELF sha256 is b7bd6c4a5a7662e5adf87c6192f822551521fc61b47ad6a2f94a33adcf0df679, equal to HEAD and to `package/firmware-signed.bin.inputs`. Packed at `--epoch 1790366193`, it is `cmp`-identical to `target/software-only/package/firmware-signed.bin` and announces c86392bc005ddfc8d019eb545b4b05876cc8da5ab22ebb941b514c17c6d9e7ce, which frostsnap `c2bcd65` registers. As a result there was no registry change, no frostsnap commit and no pin bump; `hostcheck/frostsnap.rev` stays at c2bcd65.
- **Implementer's commands** (cwd cold-snap unless noted; logs `target/software-only/logs/fix6/`, `logs/fix6r-*.log`). All exited 0:
  - the task 08 Checks set (`cargo test ... --features coldsnap_hal/fake-flash,coldsnap_hal/test-seam`: fw lib 170 + 1 ignored, fw bin 59, hal 301/5/19);
  - `cargo build --release`, and both thumbv7em clippy gates plus the aarch64 `--tests` clippy (18 warnings, all vendor/frostsnap);
  - the stub build, and hostcheck `cargo run` (cwd hostcheck). This exited 1 first because the stub was stale, then 0 after the stub rebuild;
  - `pack-signed.py --epoch 1790366193` with `cmp` 0; checkfw ACCEPT 14/14; `test-software-readiness.py`.
- **Re-runners' commands** (four independent verifier passes; logs `target/software-only/verify-rerun-link-edge/`, `verify-faults-link-edge/`, `logs/verify-rerun-link-edge/`). They re-ran the same Checks set verbatim and all exited 0 with the same counts. hostcheck exited 0 with every leg PASS. The ELF sha, the epoch pack `cmp` 0 and `register-mk4-firmware.py --print` all gave c86392bc, which is in the registry once. `check-software-readiness.py --list` shows the pack stage with `--epoch 1790366193`. They re-ran the mutants in scratch copies with the full `-p coldsnap_firmware` suite. Each of C1, M7, M7b, M7c, M7d, M7e, M7g, M7h and M7i exited 101 with only the new test failing, at its named line. Extra verifier mutants M7f and M7i–M7l (fault pass) and X1-hoist (first re-run pass) also exited 101. **The full readiness profile was not run in this pass.**
- **CONFIRMED findings and disposition:**
  1. Fix 2a finding 6, "link-edge send has no test; M7/M7b survive". **FIXED**: M7 fails at main.rs:6639 and M7b at :6645.
  2. The source pin was not line-anchored, so `// ` in front of the send passed. **FIXED** in repair 1: C1 fails at :6657.
  3. M7g/M7h (`recovered_erase` dropped before the link edge) survived. **FIXED** in repair 1: the binding and identifier-count pins make them fail at :6661 and :6675.
  4. The next full-profile pack would announce a new digest from the ELF mtime. **FIXED** in repair 1: the runner's `pack` stage passes `--epoch PACK_EPOCH` (`SOURCE_DATE_EPOCH` or 1790366193). This needs re-pinning whenever a code change registers a new image.
  5. X1: `#[cfg(not(target_arch = "arm"))]` inserted above boot's send at main.rs:2616 passes every test and both clippy gates, and it changes the ARM ELF. **NOT FIXED, open.** The suggested fix is to refuse `#[` between the link edge and the send, or to anchor the needle on the preceding comment line.
  6. The saved mutant harness's restore check was vacuous. `target/software-only/fix6r/mutants.py` asserts `git diff --quiet ... in (0,1)` (always true) and finishes with `filecmp.cmp(M,M)`. It also runs only the `the_link_edge` filter. **Correction to "repair 1 of 1"**: the claim there that the harness `cmp`s against the pre-run copies is false. The outcome still holds: close-out measured `cmp` of main.rs and lib.rs against `fix6r/*.orig` as 0 and 0, and a re-runner reproduced every mutant with the full suite.
- **Still open, unchanged:** the test runs the macro's expansion on the host, not boot's `link.is_linked()`/`was_linked` bookkeeping (PLAUSIBLE, ARM-only). The fix 2a PLAUSIBLE residuals are also unchanged: the ack is lost if `cdc.write` fails at the edge, and `from` is not bound to a port.
- **Commits:** a cold-snap commit containing firmware/src/lib.rs, firmware/src/main.rs, tools/check-software-readiness.py, this file, 08 evidence and run.json. frostsnap: none.
- Host fault injection over `FakeFlash` is not STM32 erase or USB physics. The only claim is "software/pre-bench checks passed", scoped to fix 6.

## Fix 7 — stale notes and the R12 stage pattern

Implementer pass, 2026-09-28. Not committed. frostsnap untouched (HEAD c2bcd65 = `hostcheck/frostsnap.rev`, so no pin bump is needed). No source outside `tools/` and README changed, and there was no firmware change.

### Files changed (cold-snap)
- `tools/check-software-readiness.py:319-321`: in the `checkfw-negative-signature` must-pattern, `(?m)^\s*\[FAIL\] R12 ` becomes `(?m)^\s*\[FAIL\] R12 signature over double-SHA256\(signed range\): ` with a two-line comment. It only strengthens the check. The R12 codes and checkfw output are unchanged.
- `tools/check-software-readiness.py:363-364`: in coordinator-verbatim, the note= text "known BLOCKED ... (E0308)" is replaced by a sentence saying E0308 was fixed in place by follow-up fix 1 (036b945). This is a string change only. `blocked_re` and the classification are unchanged.
- `README.md:414-418`: "Known today" now says the stage runs (the untracked file has compiled since 2026-09-24, 036b945). It still says `full` exits nonzero and names the stage BLOCKED if the file stops compiling again, which matches the unchanged `blocked_re` behaviour.
- `tools/test-software-readiness.py:113-127`: new self-test that runs the REAL stage's `must`/`expect_rc` (taken from `R.stages()`, not copied) against three fed outputs built from checkfw's real lines: sig-verify-failed (expected passed), sig-range-unusable (expected failed), and `[PASS] R12` with a REFUSE caused by something else (expected failed).

### Real checkfw output (source of the lines)
- `target/software-only/fix7/checkfw-bad-signature.log`, R12 line: `[FAIL] R12 signature over double-SHA256(signed range): expected valid under approved_pubkeys[0], actual signature failed verification; ...`
- `target/software-only/fix7/checkfw-range-unusable.log` (input is `target/software-only/fix7/range-unusable.bin` = the first 397312 B of `fixtures/bad-signature.bin`, a scratch fixture): `[FAIL] R12 signature (range unusable): expected firmware_digest() -> Some, actual None: ...`

### Commands (every cwd is /Users/garykrause/repos/cold-snap)
| command | exit | elapsed |
|---|---|---|
| `cargo run --release --target aarch64-apple-darwin -p coldsnap_firmware --example checkfw -- target/software-only/fixtures/bad-signature.bin` | 1 (REFUSE, expected) | 1s |
| `head -c 397312 target/software-only/fixtures/bad-signature.bin > target/software-only/fix7/range-unusable.bin` then checkfw on it | 1 (REFUSE, 3 of 14) | 0s |
| `python3 tools/test-software-readiness.py` (new self-test, OLD pattern) → `fix7/tsr-before-tighten.log` | 1: `FAIL ... sig-range-unusable rc 1 -> failed` (status was passed) | 56s |
| `python3 tools/test-software-readiness.py` (tightened) → `fix7/tsr-after.log` | 0, `PASS: 0 failed case(s)` | 55s |
| `python3 target/software-only/fix7/drive-stage.py` (REAL stage on REAL checkfw, pack-tests seeded passed, single-stage drive, not a profile run) → `fix7/drive-stage.log` | 0: the real stage is passed, and the range-unusable input is failed with `output lacks /...R12 signature over.../` | 1s |
| M2 in tree: pattern loosened to `\[FAIL\] R12 signature`; self-test → `fix7/tsr-mutM2.log` | 1, the sig-range-unusable case | 55s |
| M2: drive-stage.py → `fix7/drive-stage-mutM2.log` | 1 (the range-unusable input is classified passed) | 1s |
| M1 in tree: pattern restored to the old `\[FAIL\] R12 `; drive-stage.py → `fix7/drive-stage-mutM1.log` | 1 (the range-unusable input is classified passed) | 1s |
| after each mutation: `cp fix7/check-software-readiness.py.orig tools/...; cmp` | cmp 0 both times | - |
| `python3 tools/check-software-readiness.py --list` | 0 | <1s |

### Mutation results
- M1 (the old pattern): the new self-test fails at sig-range-unusable, and the real-binary drive classifies a range-unusable refusal as passed. This is the defect, reproduced.
- M2 (the looser `[FAIL] R12 signature`): it is caught by the same self-test case and by the drive.
- Real code: the self-test exits 0 and the drive exits 0.

### Closes
- Fix 3 open item "`checkfw-negative-signature`'s `[FAIL] R12 ` also matches R12's 'range unusable' variant" (this file, § Fix 3 :503 and :552; § Fix 5 close-out :858).
- The stale "known BLOCKED" note (§ Fix 1 :44 and :62; § Fix 3 :502 and :551; § Fix 5 close-out :857).
- README "Known today" being stale (§ Fix 4 close-out :778).

### Not done
- The full readiness profile was not re-run: the only changes are a string note, a README paragraph and a stricter pattern, and that pattern was exercised against the real checkfw output above. The claim is software/pre-bench checks passed, scoped to this fix.

## Fix 7 — close-out

- **Status: FIXED (software/pre-bench checks passed, scoped to fix 7).** All three items are done, and both verifier passes found no CONFIRMED finding, so no repair was needed. (a) The coordinator-verbatim `note=` at `tools/check-software-readiness.py:363-364` no longer says "known BLOCKED". Only the string changed: `blocked_re` and the classification are the same. (b) README "Known today" (`README.md:414-418`) now says the stage runs because of 036b945, dated 2026-09-24. (c) The `checkfw-negative-signature` pattern at `:321` is now `(?m)^\s*\[FAIL\] R12 signature over double-SHA256\(signed range\): `, and a new self-test (`tools/test-software-readiness.py:113-127`) classifies the real "range unusable" line as failed. checkfw output and the R12 codes are unchanged.
- **Implementer's commands** (cwd cold-snap; logs `target/software-only/fix7/`): checkfw on `fixtures/bad-signature.bin` exited 1 (REFUSE, the R12 verify line). checkfw on the 397312 B scratch truncation exited 1 (R12 range unusable). The self-test exited 1 with the old pattern (at sig-range-unusable) and 0 with the tightened one. `fix7/drive-stage.py` exited 0 on the real code. Mutants M1 (old pattern) and M2 (`\[FAIL\] R12 signature`) were each caught by both the self-test and the drive. The file was restored from `.orig` with `cmp` 0 each time, and `--list` exited 0.
- **Re-runners' commands** (two verifier passes; scratch `target/software-only/verify-rerun-loose-ends/fix7/`). They ran the stage's checkfw argv verbatim: exit 1, R12 verify line. checkfw on their own 397312 B and unaligned 300000 B truncations exited 1 (range unusable). Their drive of the real stage exited 0 for both fixtures. The real-tree self-test exited 0. In scratch copies, the M1 and M2 self-tests each exited 1 at sig-range-unusable. They applied the real `stages()` patterns to the implementer's logs (exit 0). They confirmed `git status` was unchanged, frostsnap HEAD c2bcd65 equal to `hostcheck/frostsnap.rev`, and 036b945 dated 2026-09-24.
- **Close-out's own check:** `python3 tools/test-software-readiness.py` (cwd cold-snap) exited 0 with `PASS: 0 failed case(s)`, including the 3 new `checkfw-negative-signature rule` cases (log `target/software-only/logs/fix7-closeout/tsr.log`).
- **CONFIRMED findings:** none.
- **Closed by this fix:** the fix 3 open item "`[FAIL] R12 ` also matches the range-unusable variant" (§ Fix 3, § Fix 5 close-out item 3; 01 evidence, fix 3 follow-up), the stale "known BLOCKED" note (§ Fix 1, § Fix 3, § Fix 5 close-out item 2; 09 evidence, fix 1/3/5 follow-ups), and the stale README "Known today" text (§ Fix 4 close-out).
- **Still open:**
  - PLAUSIBLE, not repaired: checkfw prints the same `[FAIL] R12 signature over double-SHA256(signed range): ` prefix for two other failures, pubkey_num != 0 ("cannot verify: only approved_pubkeys[0] is embedded here") and "sig parse: ...". So a re-minted fixture that fails for one of those reasons would still pass the stage. Matching `actual signature failed verification` would close it. Today's fixture fails for the verification reason.
  - The full readiness profile was not re-run in this fix. `cargo test -p frostsnap_coordinator` was also not re-run here: the README statement that it runs rests on fix 1 and the earlier 41/42 full run.
- **Commits:** one cold-snap commit containing `tools/check-software-readiness.py`, `tools/test-software-readiness.py`, `README.md`, this file, the 01 and 09 evidence files and run.json. frostsnap: none, so no pin bump.
- Real USB enumeration, timing, SE calls, entropy, flash power loss and actual installation remain bench-only and untested.

## Fix 8 — full readiness profile

Date 2026-09-28. Inputs: cold-snap HEAD ad3d6b2 (fix 7 close-out), frostsnap HEAD c2bcd65 = `hostcheck/frostsnap.rev`. Both trees contained only the user's pre-existing dirty files at start (`git status --porcelain` in each). Nothing was left over from an earlier attempt.

| # | Command | cwd | Exit | Elapsed | Log |
|---|---|---|---|---|---|
| 1 | `python3 tools/test-software-readiness.py` | `$HOME/repos/cold-snap` | 0 ("PASS: 0 failed case(s)") | 54 s | `target/software-only/logs/12-fix8/tsr.log` |
| 2 | `python3 tools/check-software-readiness.py --profile full --output-dir target/software-readiness` (background) | `$HOME/repos/cold-snap` | 0, label "software/pre-bench checks passed" | 367 s (results.json 15:18:31 to 15:24:38 -04:00) | `target/software-only/logs/12-fix8/full.log` |

The report comes from this run: `target/software-readiness/results.json` and `summary.md` were written at 15:24:38 on 2026-09-28. It records identity cold-snap ad3d6b2, frostsnap c2bcd65, `source_drift: []`, `orphans_after_run: []` and no stale artifacts. Release ELF sha256 b7bd6c4a... is the same one fix 6 recorded.

All 42 stages passed. There were no failed, blocked, skipped or timed-out stages. The rc=1 stages are expected-failure negatives that the runner classifies as passed. Times are elapsed seconds from results.json:

host: frostsnap-macros 2.67, frostsnap-embedded-std 1.72, frostsnap-comms 2.23, frostsnap-core 21.94, frost-backup 7.37, coldsnap-firmware 4.88, coldsnap-hal 4.18.
arm: clippy-dev 0.41, clippy-release 0.30, build-release 0.45.
reference: refcheck 11.20, refcheck-negatives 28.06.
package: pack 0.41, pack-tests 1.72, pack-negative-bad-layout 0.20 (rc=1), checkfw-bin 0.42, checkfw-dfu 0.41, checkfw-negative-signature 0.42 (rc=1), checkfw-negative-misaligned 0.42 (rc=1), checkfw-negative-family 0.43 (rc=1).
pixel-heap: pixel-check 0.90, heap-session 10.95.
coordinator: stub-build 0.25, frostsnap-pin 0.04, hostcheck-tests 2.70, hostcheck-run 18.08, coordinator-verbatim 10.25, coordinator-scoped 2.54, rust-lib-frostsnapp 3.60, register-self-check 0.08, registry-matches-artifact 0.05.
compat: flutter-analyze 35.33, flutter-test 3.61, bridge-gen-reproducible 36.94, build-runner-reproducible 12.67.
app: app-rig 90.42.
upgrade-erase: updater-stub-ignored 2.78, updater-lib-ignored 3.74, updater-local-artifact 0.84, app-bridge-ignored 8.04, controller-erase-fake 7.37, install-xproc 2.24.

The short times come from warm incremental build caches. No build or test input changed since the fix 6 and fix 7 runs.

Orphans: after the run, `ps -axo pid,ppid,command` filtered for cold-snap/target, regtest, frostsnapp, qemu-system, coldsnap, app-rig, flutter_tester, install-xproc and check-software matched nothing (grep rc=1). The only bitcoin-node was the user's PID 13555 (-testnet4 -rpcport=48335). It was not touched.

Files changed: none apart from this evidence section. The image digest was unchanged and already registered (c86392bc at frostsnap c2bcd65), so no registration was needed. There was no frostsnap commit and no pin bump. No stage was edited, reclassified or relaxed.

Mutations: none. This fix adds no new or strengthened check. The runner's failure paths were exercised by run 1: its self-tests cover failed, timed-out, skipped-required, stale-input, hung-child and SIGTERM cases, and fix 7 added the R12 cases.

This closes the fix 6 note "The full readiness profile was not re-run this pass" and fix 5's unmet criterion, which was full-profile exit 0 (39/42 in fix 5; 41/42 after c2bcd65 because frostsnap-pin was pending). Task 09's acceptance criterion "the full profile runs every required implemented check" is now met with exit 0 (see 09-automate-software-readiness-checks.md). Still open: fix 6 mutant X1 and the other known-open findings.

Claim: software/pre-bench checks passed. This is scoped to the hardware-free full profile. Real USB enumeration, timing, SE calls, entropy, flash power loss and actual installation remain bench-only and untested. The mocked bootloader and install effects are not real installation.

## Fix 8 — repair 1 of 1

Finding (CONFIRMED): `identity()` recorded `dirty` from `_cmd(...).strip().splitlines()`. This removed the leading space of the first porcelain line, so the unstaged ` M` was recorded as the staged `M `.

- **Fix:** `tools/check-software-readiness.py` `_cmd(argv, cwd=None, lines=False)`. When `lines=True` it returns `stdout.splitlines()` without stripping, and `identity()` passes `lines=True` for `git status --porcelain=v1`. Other callers are unchanged: they still get `.strip()` for single-value outputs such as rev-parse, rustc -V and the flutter first line.
- **Check:** `tools/test-software-readiness.py` adds "identity: unstaged first line keeps porcelain ' M', not staged 'M '". It points `R.FS` at the synthetic pin repo while its `lib.rs` has an unstaged edit, calls the runner's real `identity()`, and requires `dirty == [' M frostsnap_coordinator/lib.rs']`.

| # | Command (cwd `$HOME/repos/cold-snap`) | Exit | Log |
|---|---|---|---|
| 1 | `python3 tools/test-software-readiness.py` | 0 (87 ok, 0 FAIL) | `target/software-only/logs/12-fix8/selftest-repair1.log` |
| 2 | Mutant: `tools/check-software-readiness.py` temporarily set back to `out.strip().splitlines()`, then self-tests run, then the fixed file restored (cmp identical) | 1. Exactly one FAIL, the new identity check, got `['M frostsnap_coordinator/lib.rs']`. Mutant killed | `target/software-only/logs/12-fix8/mutant/run.log` |
| 3 | `python3 tools/check-software-readiness.py --profile full --output-dir target/software-readiness` (background) | 0, "software/pre-bench checks passed" | `target/software-only/logs/12-fix8/full-repair1.log` |

The run 3 report was freshly written: results.json at 15:47 on 2026-09-28, started 15:40:50 and finished 15:47:03 -04:00. It shows 42/42 passed, `orphans_after_run: []` and `source_drift: []`. Identity: cold-snap ad3d6b2, frostsnap c2bcd65 (= pin), coldcard-firmware 0431fd2. `dirty[0]` now reads correctly: frostsnap `' M frostsnapp/.gitignore'`, coldcard-firmware `' M docs/dice-code-walkthrough.html'`, cold-snap `' M target/software-only/evidence/10-followup.md'`.

Stage elapsed (s): host-frostsnap-macros 2.78, embedded-std 1.77, comms 2.19, core 21.2, frost-backup 7.34, coldsnap-firmware 2.74, coldsnap-hal 5.59; arm clippy-dev 0.31, clippy-release 0.3, build-release 0.57; refcheck 10.9, refcheck-negatives 27.36; pack 0.36, pack-tests 1.71, pack-negative-bad-layout 0.19, checkfw-bin 0.47, checkfw-dfu 0.48, checkfw-negative-signature 0.42, -misaligned 0.47, -family 0.48; pixel-check 0.89, heap-session 0.79; stub-build 0.25, frostsnap-pin 0.04, hostcheck-tests 1.06, hostcheck-run 18.08, coordinator-verbatim 9.34, coordinator-scoped 2.44, rust-lib-frostsnapp 3.21, register-self-check 0.08, registry-matches-artifact 0.05; flutter-analyze 31.44, flutter-test 10.08, bridge-gen-reproducible 43.01, build-runner-reproducible 18.59; app-rig 90.33; updater-stub-ignored 3.48, updater-lib-ignored 3.86, updater-local-artifact 0.57, app-bridge-ignored 9.37, controller-erase-fake 7.95, install-xproc 2.36.

Orphans: `ps -axo pid,command` filtered for cold-snap/target, regtest, frostsnapp, qemu-system, app-rig, flutter_tester, install-xproc, check-software and bitcoin-node matched only the user's PID 13555 (-testnet4 -rpcport=48335), which was not touched.

Files changed: `tools/check-software-readiness.py` and `tools/test-software-readiness.py`, plus this section. frostsnap unchanged, so no registration and no pin bump. No stage was removed, reclassified or relaxed. Not committed; commit is for close-out. Claim: software/pre-bench checks passed, scoped to the hardware-free full profile.

## Fix 8 — close-out

- **Status: PARTLY FIXED (software/pre-bench checks passed, scoped to the hardware-free full profile).** The goal is met: the full profile ran verbatim and exited 0 with 42/42 stages passed, both before and after repair 1. The one CONFIRMED finding on the original run (porcelain dirty-state record) is FIXED. One CONFIRMED finding raised against repair 1's own `_cmd` change is NOT repaired, because close-out may not edit source (see below). It is a low-severity error path only and affects no stage or exit code.
- **Implementer's commands** (cwd `$HOME/repos/cold-snap`): `python3 tools/test-software-readiness.py` exited 0 (log `target/software-only/logs/12-fix8/tsr.log`). `python3 tools/check-software-readiness.py --profile full --output-dir target/software-readiness` in the background exited 0, 42/42, 15:18:31 to 15:24:38 (log `.../12-fix8/full.log`). Repair 1: self-tests exited 0, 87 ok (`.../12-fix8/selftest-repair1.log`). The mutant (old `.strip().splitlines()`) made the self-tests exit 1 on the new identity case only (`.../12-fix8/mutant/run.log`). The full profile exited 0, 42/42, 15:40:50 to 15:47:03 (`.../12-fix8/full-repair1.log`).
- **Re-runners' commands:** verifier 1 ran the self-tests (exit 0) and the full profile to `target/software-only/verify-rerun-final/software-readiness` (exit 0, 42/42, 15:30:12 to 15:34:54). It also grepped the negative-stage outputs: signature fails R12 only, misaligned fails R8, family fails R13, and all print RESULT: REFUSE. Verifier 2 was read-only: it checked results.json, the logs, the git state and ps. Verifier 3 (after repair) ran the full profile verbatim (exit 0, 42/42, 15:49:05 to 15:54:02, log `.../12-fix8/rerun2/full.log`) and the self-tests (exit 0, 87 ok, `.../12-fix8/rerun2/selftest.log`). It also ran an out-of-tree mutant check against a scratch repo: the fixed code gave `[' M a.txt','M  b.txt']` and the old code gave `['M a.txt','M  b.txt']`.
- **Close-out's own check:** `target/software-readiness/results.json` is verifier 3's run. It has argv `--profile full --output-dir target/software-readiness`, exit 0, label "software/pre-bench checks passed", 42 passed, `orphans_after_run: []` and `source_drift: []`. It records cold-snap ad3d6b2 and frostsnap c2bcd65 (= `hostcheck/frostsnap.rev`), and frostsnap `dirty[0]` is `' M frostsnapp/.gitignore'`. `python3 tools/test-software-readiness.py` (cwd cold-snap) exited 0 with "PASS: 0 failed case(s)" (log `target/software-only/logs/12-fix8/closeout/tsr.log`). A `ps` check afterwards found only the user's bitcoin-node, PID 13555 (-testnet4 -rpcport=48335), which was not touched.
- **CONFIRMED findings:**
  1. `identity()` dropped the first porcelain line's leading space, so the unstaged ` M` was recorded as the staged `M ` (`tools/check-software-readiness.py:613/:623`, from task 09). **FIXED** by repair 1: `_cmd(..., lines=True)` splits without stripping, and a new self-test covers it with its mutant killed.
  2. Found by verifier 3 in repair 1's code: when git cannot be run, `_cmd(lines=True)` returns the string `'unavailable: ...'` instead of a list (`tools/check-software-readiness.py:610-616`). `dirty` then becomes a string, and `summary.md` counts its characters as dirty paths. **NOT REPAIRED:** close-out may not edit source. Reproduced only with `subprocess.run` patched to raise OSError; the normal run is unaffected. The fix is one line: return `[msg]` when `lines` is True.
- **Registration and pin:** image digest c86392bc was unchanged and already registered (frostsnap c2bcd65). There was no registration, no frostsnap commit and no pin bump. No stage was removed, reclassified or relaxed.
- **Closed by this fix:** the fix 6 note "full readiness profile was not re-run", fix 5's unmet full-profile exit 0 (39/42, then 41/42), and task 09's acceptance criterion that the full profile runs every required implemented check with exit 0. The task 09 finding about porcelain dirty-state is also closed.
- **Still open:** finding 2 above. Fix 6 mutant X1. The fix 7 PLAUSIBLE item: the R12 prefix is shared with the pubkey_num and sig-parse failures.
- **Commits:** one cold-snap commit containing `tools/check-software-readiness.py`, `tools/test-software-readiness.py`, this file, the 09 evidence file and run.json. frostsnap: none.
- Real USB enumeration, timing, SE calls, entropy, flash power loss and actual installation remain bench-only and untested. The install and bootloader effects in the profile are mocked.

## Fix 9 — _cmd(lines=True) always returns a list

**Status: FIXED (software/pre-bench checks passed, scoped to the runner self-tests and one verbatim full profile).** Every lines=True return path of `_cmd` now returns a list. A new self-test fails on the old code and passes on the fixed code. Neither verifier raised a CONFIRMED finding, so no repair was needed.


Date 2026-09-29. Inputs: cold-snap HEAD a631297, frostsnap HEAD c2bcd65 (= `hostcheck/frostsnap.rev`). At start, both trees had only the user's pre-existing dirty files (`git status --porcelain`, `git diff --stat`). Nothing was left over from an earlier attempt.

### Files changed (working tree only, not committed)
- `tools/check-software-readiness.py:616-617`: the `except (OSError, subprocess.SubprocessError)` path of `_cmd` now returns `[msg] if lines else msg`. Before this change it always returned the string. Every return path with lines=True now returns a list.
- `tools/test-software-readiness.py:287-297`: new case "identity: git unavailable -> dirty is a one-item list, not the string's characters". It points `os.environ['PATH']` and `R.FLUTTER_BIN` at an empty scratch directory `target/software-readiness-selftest/nogit-path`, so git cannot be run. It then calls the runner's real `identity()`, restores both values in `finally`, and requires every repo's `dirty` to be a list of exactly one item that starts with `unavailable: `.

### Callers checked
Only `identity()` (`:625`, `dirty`) passes `lines=True`. Its consumer, `summary.md` at `:708-709`, uses `len(rp['dirty'])` and `', '.join(rp['dirty'])`. With a list this now reports "1 dirty path(s): unavailable: ..." rather than counting characters. The callers without lines (`:623-627`, head, branch, rustc, cargo and flutter `.splitlines()[:1]`) still get strings, so they are unchanged. Stage classification and stage rules are unchanged.

### Commands (cwd `/Users/garykrause/repos/cold-snap`; exit = the python process's own status, output redirected to the log)
| # | Command | Exit | Elapsed | Log |
|---|---|---|---|---|
| 1 | `python3 tools/test-software-readiness.py` (new case, OLD `_cmd`) | 1: exactly one FAIL, the new case. Every repo's `dirty` was the string `"unavailable: [Errno 2] No such file or directory: 'git'"` | 113 s | `target/software-only/logs/13-fix9/selftest-oldcode.log` |
| 2 | `python3 tools/test-software-readiness.py` (fixed `_cmd`) | 0, "PASS: 0 failed case(s)", 88 ok | 66 s | `target/software-only/logs/13-fix9/selftest-fixed.log` |
| 3 | `python3 tools/check-software-readiness.py --list` | 0 | <1 s | (stdout discarded) |

### Mutation
The mutant is the pre-fix code itself: the test was added before the one-line fix, so run 1 is the mutant run. It failed for the named reason (the string was returned instead of a list). Run 2 on the real code passed. No in-tree revert was needed.

### Closes
Fix 8 close-out CONFIRMED finding 2 (§ Fix 8 — close-out: "`_cmd(lines=True)` returns the string `'unavailable: ...'` instead of a list", `tools/check-software-readiness.py:610-616`; also carried in the 09 evidence).

### Not done
The full readiness profile was not re-run. The change touches only the git-unavailable error path of `identity()`, which a normal run never takes, and no stage or classification changed. frostsnap was unchanged, so there was no registration and no pin bump. Claim: software/pre-bench checks passed, scoped to the runner self-tests. Real USB enumeration, timing, SE calls, entropy, flash power loss and actual installation remain bench-only and untested.

## Fix 9 — close-out

- **Status: FIXED (software/pre-bench checks passed, scoped as above).** `tools/check-software-readiness.py:616-617` returns `[msg] if lines else msg`. The success path at `:614` already returned `splitlines()`. The only lines=True caller is `identity()` (`:625`), and its only consumer is the summary.md writer (`:709-710`). No stage rule or classification changed.
- **Implementer's commands** (cwd cold-snap): the self-test with the new case on the OLD `_cmd` exited 1, with exactly one FAIL, the new case (`target/software-only/logs/13-fix9/selftest-oldcode.log`). On the fixed code it exited 0 with 88 ok (`.../13-fix9/selftest-fixed.log`). `--list` exited 0.
- **Re-runners' commands:** verifier 1 used scratch copies under `target/software-only/verify-rerun-cmd-list/{fixed,old}`. The fixed copy exited 0 with 88 ok. The old-HEAD `_cmd` copy exited 1 with 87 ok and a single FAIL, the new case, where `dirty` was the string `"unavailable: [Errno 2] No such file or directory: 'git'"`. Its first two scratch attempts failed only from setup: missing run.json, then the missing pin script (rc 127). It then ran task 09's Checks block verbatim in the real tree: `python3 tools/check-software-readiness.py --profile full --output-dir target/software-readiness` exited 0, 42/42 passed, "software/pre-bench checks passed", 10:12:30-10:18:23 EDT 2026-09-29 (log `target/software-only/verify-rerun-cmd-list/logs/full.log`). Afterwards `git status` was unchanged in both repos, and frostsnap HEAD c2bcd65 matched `hostcheck/frostsnap.rev`. Verifier 2 was read-only: it read the diff, `_cmd`/`_env`/`identity`/the summary writer, the grep for lines=True callers and the ok counts in both logs.
- **Close-out's own check:** `python3 tools/test-software-readiness.py` (cwd cold-snap) exited 0 with "PASS: 0 failed case(s)" and 88 ok (log `target/software-only/logs/13-fix9/closeout/tsr.log`).
- **CONFIRMED findings:** none. There were two PLAUSIBLE notes. (1) The 09 evidence and run.json still listed this finding as open. This close-out closes it in both. (2) `_cmd` ignores returncode, so git that runs but fails (for example rc 128 with empty stdout) records `dirty == []`, the same as a clean tree. This predates fix 9 and is outside its scope ("when git cannot run"). It is left open and not repaired.
- **Closed by this fix:** fix 8 close-out CONFIRMED finding 2 (`_cmd(lines=True)` returned a str when git cannot run). It was also carried as open in the 09 evidence (fix 8 follow-up) and in run.json.
- **Still open:** the PLAUSIBLE returncode note above, fix 6 mutant X1, and the fix 7 PLAUSIBLE R12-prefix item.
- **Commits:** one cold-snap commit containing `tools/check-software-readiness.py`, `tools/test-software-readiness.py`, this file, the 09 evidence file and run.json. frostsnap was unchanged, so there was no registration and no pin bump.
- Real USB enumeration, timing, SE calls, entropy, flash power loss and actual installation remain bench-only and untested. The install and bootloader effects in the profile are mocked.

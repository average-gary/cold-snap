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

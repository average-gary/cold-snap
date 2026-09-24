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

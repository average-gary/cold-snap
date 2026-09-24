# Task 07: build the upgrade controller against a mocked callgate

**STATUS: DEGRADED.** One CONFIRMED finding is still open, from the independent re-run done after the repairs: the separate header==call-length guard (`psram::check_burn_len` in `install.rs::check_view`) has no test that fails when it is removed. The mutant `no_check_burn_len` survived with exit 0. It is low severity and there is no behavioural defect today, because `check_installable` makes the same comparison. All 10 acceptance criteria are met against the fake gate. Real gate behaviour cannot be verified without hardware.

Scope of the claim: software/pre-bench checks passed, against a strict fake gate. Nothing here is hardware-verified, and nothing here is safe for funds. The fake records an install *request*; nothing was installed.

## Close-out summary (final state)

### Final-state commands

**Independent re-run (re-runner, after all repairs).** cwd `/Users/garykrause/repos/cold-snap`. Logs are in `target/software-only/logs/07-rerun2/` (`summary.txt`, `mut-summary.txt`, `mut-*.log`). Elapsed times were not recorded by the re-runner. The re-run happened after the last source edit: its summary is timestamped 11:06, and the newest source mtime is `install.rs` at 11:03. Batch 3 made no source edits.

| # | Command | cwd | Exit | Observed |
|---|---|---|---|---|
| c1 | `cargo test --target aarch64-apple-darwin -p coldsnap_hal -p coldsnap_firmware --features coldsnap_hal/fake-flash,coldsnap_hal/test-seam` | cold-snap | 0 | 165+57+295+5+19 passed, 0 failed, 1 ignored (the xproc test, which the driver runs) |
| c2 | `cargo build --release` | cold-snap | 0 | |
| c3 | `cargo clippy --release --target thumbv7em-none-eabihf -p coldsnap_hal -p coldsnap_firmware` | cold-snap | 0 | 18 warnings, all in vendor |
| c4 | `cargo clippy --target thumbv7em-none-eabihf -p coldsnap_hal -p coldsnap_firmware` | cold-snap | 0 | 18 warnings, all in vendor |
| c5 | `cargo run --release --target aarch64-apple-darwin -p coldsnap_firmware --example heap_session --features coldsnap_hal/test-seam,frostsnap_core/coordinator` | cold-snap | 0 | install phases: 0 arena allocations and live +0 B on both paths; gate calls 1/0/1 (blank PIN) and 2/1/1 (PIN set); NULLS 0; FITS with 10860 B slack |
| c6/c7 | `target/pack-venv/bin/python tools/install-xproc.py` | cold-snap | 0 | PASS: 397312 B staged, digest `58f1b3fe4cd2df9e38b93dda2a1224c8d7652ef89e0c10d38d5a46f04e39f441`, one fake request per PIN path |
| c6/c7 | `python3 tools/check-reference-contracts.py --json target/software-only/refcheck/result.json` | cold-snap | 0 | `PASS: 136 checks agree with the reference`, 0 SKIP |
| n0 | the xproc test run with `--ignored --exact` and no driver | cold-snap | 101 | panics with `COLDSNAP_WIRE_FD unset`, so it does not skip |
| mut x10 | the mutants in an rsync copy at `target/software-only/rerun07-mut/cs` | copy | 9 x 101, 1 x 0 | the only survivor was `no_check_burn_len` (see STATUS) |

Record inconsistency: `mut-summary.txt` lists `tripwire_gated_call exit 0`, and the output it quotes is from the 295-test hal binary. The log itself, `mut-tripwire_gated_call.log`, shows `nothing_here_reaches_a_real_gate_or_an_identity ... FAILED` with the message `` `pin_setup_attempt` in install.rs production code ``, then `error: test failed`, so the process was nonzero. The re-runner reported 101. The same mutant also fired with 101 in the repair round (`logs/07-r1/mutation-tripwire.log`). I treat the tripwire as live, and I record that the summary line is wrong.

The earlier independent verifier re-runs (`target/software-only/verify-rerun-07/`, `target/software-only/verify-faults/`) and the implementers' own runs (`07-s1-checks`, `07-s2`, `07-r1`, `07-r2`, `07-r3`) are listed in the sections below, labelled by who ran them. The pre-repair runs gave 539 passed; the implementers' post-repair runs gave 541 (165+57+295+5+19).

Not run: `cargo test -p frostsnap_coordinator`. It was not needed, because task 07 changed nothing in frostsnap. So the known E0308 BLOCK from the user's `tests/coldcard_msg_len.rs` was never reached.

### Files changed (the whole task, cold-snap only; frostsnap is unchanged)
- `firmware/src/install.rs` (new file): the `Bootloader` trait, `Unbound`, `GateFault`/`ImageFault`/`Refusal`, `request_bounds`, `CheckedImage`, `Prompt`/`Confirmation`, `Workflow` with a workflow serial, and the ARM-codegen `device_path`. Tests only: the strict `FakeGate`, `DriftPsram`, 26 install tests including the `#[ignore]` xproc test, and the production and test-double tripwires.
- `firmware/src/lib.rs`: `pub mod install;`.
- `firmware/src/upgrade.rs`: `staged_view`, `staged_digest`, `installable` via `staged_view`, the workflow serial (`claim_workflow`/`live_workflow`), and `serve(wire, &mut Stager)`. `run` now delegates to `serve`.
- `hal/src/callgate.rs`: `Errno::NOT_BOUND`, `CHANGE_FIRMWARE: i32 = 0x040`, `OFF_CHANGE_FLAGS = 100`, `change_flags`/`firmware_request`/`set_firmware_request`, `raw_mut` (test/test-seam only), 9 EPIN constants, 2 tests, and the doc placement fix.
- `firmware/examples/heap_session.rs`: the `install` phase, `MeasureGate`, `install_image`, `install_workload`, and verdict rows.
- `tools/check-reference-contracts.py`: `change_flags` offset, and the `CHANGE_FIRMWARE` and EPIN probes and compares.
- `tools/install-xproc.py` (new): the task-06 cross-process driver.

### Acceptance criteria (final)

| # | Criterion (prompt wording) | Status | Evidence |
|---|---|---|---|
| 1 | Valid blank-PIN and PIN-set fixtures reach exactly one correctly formed mock install request | met (fake) | `blank_pin_reaches_exactly_one_well_formed_request` and `pin_set_logs_in_once_per_submission_then_requests_once`; the xproc run on the real key-0 artifact gives `(0, 397312)` once per path |
| 2 | failed pre-install image/consent/login checks never reach it | met (fake) | consent, login and setup fault tests; the drift test, where mutant M3/no_recheck fails |
| 3 | Bootloader signature/downgrade refusals produce a failed install request, never a successful installation result | met (fake) | `bootloader_signature_and_downgrade_refusals_are_failed_requests`; 11 install codes x 2 paths |
| 4 | No private release credential is required | met | the fake uses a test key or the PUBLIC half of 00.pem (xproc); no 00.pem scalar is embedded; no manifest or allowlist |
| 5 | Length disagreement, oversized image, and a staging-valid but non-4-K-aligned image are rejected at the install boundary | met | `length_disagreement_oversize_...`, `a_short_tail_image_...` (262,656 B), `request_bounds_...`; the no_align mutant fails |
| 6 | No automatic PIN retry, reused consent grant, or duplicate install request is possible in exercised failure/re-entry cases | met (fake) | F1 (concurrent workflows) and F2 (stale replay) fixed by the workflow serial and `Prompt`; supersession and digest-only mutants fail; login_retry and no_cancel_before_gate mutants fail |
| 7 | Fake installation returns an honest install-request/reset outcome, not a claim that hardware was flashed | met | `InstallRequested{start,len}` is documented as "not installed" |
| 8 | Real 18/2 and 18/7 remain unbound | met | `Unbound` is the only device gate; census guard unchanged and live (census_u32 gives 17 vs 16); `nm` shows no gate entry referenced |
| 9 | Existing signing/backup behavior, ARM builds, heap limits, and staging tests remain valid | met | c1-c5 exit 0 |
| 10 | The new workload's memory cost is measured | met (heap scope) | 0 arena allocations and live +0 B per path; host `size_of`: Workflow 384 B, CheckedImage 40 B, PinAttempt 280 B, Stager<FakePsram> 88 B. **Not measured:** call-frame stack depth and 32-bit device sizes |
| - | Real gate behaviour (SE counters, burn, reset) | unverifiable-without-hardware | |

Met: 10 of 10, against the fake.

### Forbidden-shortcut audit (final)

Global list:
- Claiming a command ran that did not: held. Every row above has a log. The one summary-line inconsistency is recorded above.
- SKIP counted as a pass: held. The refcheck printed 0 SKIP lines, and the xproc test panics when it is run without its driver.
- Pipeline status used as process status: held. Every exit code is `$?` of the process.
- Historical figures used as constants: held. 60512 B and 10860 B were re-measured fresh in c5 and are not asserted. 539 and 541 are counts observed in this task's runs.
- Deleting or relaxing a failing assertion: held. The census and tripwires are unchanged. The `unsafe` tripwire caught a draft and the draft was changed, not the guard.
- Claiming "hardware verified" or "safe for funds": held. Neither is claimed.
- Reporting unit tests as an integration run, or a mocked effect as real: held. The xproc run is labelled as a request recorded by a fake, over a pty.

Task list:
- Mocks fall back to a real callgate: held. Production and test-double tripwires are both live (mutants m1 and m2).
- More than one install request, or a PIN retry: held.
- Reused consent across cancel, replacement image, new workflow or reboot: held for cancel, replacement image and new workflow. Reboot is covered only by RAM loss and the fake's HMAC; see PLAUSIBLE F6.
- Relying on the signature check for header len == burn len: held. The fake burns the caller's length, and `check_view` compares them. The redundant second guard is untested: this is the OPEN finding.
- Relaxing source guards: held.
- Claiming the fake measures SE counters, flash timing or PSRAM retention: held.

### CONFIRMED findings and repair outcome

| Finding | Outcome |
|---|---|
| Controller workload missing from heap_session; memory cost not measured (verifiers 1, 2 and 3) | FIXED, batch 1 |
| Doc comment in callgate.rs attached to the wrong test (verifiers 1 and 3) | FIXED, batch 1 (confirmed again in batch 3) |
| Tripwire's documented mutation fails at host compile time, not at the assertion | FIXED, batch 1 (doc) |
| Task-06 integration reported outstanding although the updater is available | FIXED, batch 2 (pty-scope xproc driver) |
| One Confirmation gives two install requests through concurrent Workflows | FIXED, batch 2 (workflow serial) |
| A stale Confirmation replayed into a new workflow grants it | FIXED, batch 2 (`Prompt` bound to the serial) |
| `check_view`'s separate `psram::check_burn_len` guard has no failing test when removed (re-runner, after repairs) | **OPEN.** No repair batch addressed it |

Open PLAUSIBLE findings (design weaknesses, not counted as confirmed):
- The public `Bootloader::request_install` takes any `PinAttempt`, and `set_firmware_request` is unchecked, so the boundary lives in `Workflow`.
- A grant survives a fake gate reboot while in PinRequired (F6).
- Keypad consent exists only as an enum, and the listener is not wired to `Workflow`.
- 18/0 runs before consent, so the doc sentence "no counter tick before confirmation" holds only if 18/0 is free.
- `raw_mut` is exposed in any test-seam build.
- The stale comment above `pub mod install;` in `lib.rs:93-95` describes staging.
- The fake's at-most-once panic fires only after an accepted install.

### Residual bench-only questions (the prompt's terms)
- Real 18/0 counter behavior: does 18/0 move SE1 `Counter[0]`? Measure with 21/3 `read_counter0` before, between and after two 18/0 calls.
- 18/2 login on a PIN-set expendable unit: the real `attempts_left` and SE2 bad-PIN effects.
- 18/7 installation of a key-0 image: the real `verify_firmware_in_ram` verdict, the burn, and the reset.
- Reset/power-interruption recovery: power loss mid-burn and `psram_recover_firmware`; PSRAM retention across reset.
- Binding needed later: a device `Bootloader` that makes one selector-18 call per method (arg2 0, 2, 7), with each call counted by the `callgate.rs` census, replacing `Unbound`. Driving install from task 06's `InstallRequested` state and the verified reconnect remain outstanding.

### Flutter/Dart and task 04
Not applicable. No Flutter or Dart command is in task 07's Checks, and none was run, so no Flutter version was resolved for this task. Task 04's regtest backend was not run by task 07, and no bitcoin binary was invoked.

---

# History (per sub-step and repair batch, as recorded at the time)

## Sub-step 1 (implementer)

Scope of this sub-step: the bootloader interface and the pure workflow policy (setup, conditional login, install request), with a strict fake gate.

## Commands (all cwd `/Users/garykrause/repos/cold-snap`)

| # | Command | Exit | Elapsed | Log |
|---|---|---|---|---|
| 1 | `cargo test --target aarch64-apple-darwin -p coldsnap_hal -p coldsnap_firmware --features coldsnap_hal/fake-flash,coldsnap_hal/test-seam` | 0 | 15s | target/software-only/logs/07-s1-checks/1.log |
| 2 | `cargo build --release` | 0 | 6s | .../07-s1-checks/2.log |
| 3 | `cargo clippy --release --target thumbv7em-none-eabihf -p coldsnap_hal -p coldsnap_firmware` | 0 | 1s | .../07-s1-checks/3.log |
| 4 | `cargo clippy --target thumbv7em-none-eabihf -p coldsnap_hal -p coldsnap_firmware` | 0 | 1s | .../07-s1-checks/4.log |
| 5 | `cargo run --release --target aarch64-apple-darwin -p coldsnap_firmware --example heap_session --features coldsnap_hal/test-seam,frostsnap_core/coordinator` | 0 | 11s | .../07-s1-checks/5.log |
| 6 | `python3 tools/check-reference-contracts.py --json target/software-only/refcheck/result.json` | 0 | 21s | target/software-only/logs/07-refcheck.log |
| 7 | `cargo clippy --target aarch64-apple-darwin -p coldsnap_firmware --tests --features coldsnap_hal/fake-flash,coldsnap_hal/test-seam` (extra) | 0 | 5s | target/software-only/logs/07-s1-host-clippy-tests.log |
| 8 | Mutation: inserted `let _ = "callgate::call(";` into `Unbound::setup`, then ran `cargo test --target aarch64-apple-darwin -p coldsnap_firmware --features coldsnap_hal/fake-flash,coldsnap_hal/test-seam --lib install::tests::nothing_here` (file restored afterwards) | 101 (expected: tripwire fired, "`callgate::call` in install.rs production code") | 6s | target/software-only/logs/07-s1-mutation.log |
| 9 | `rustfmt --check --edition 2021 firmware/src/install.rs` | 0 | <1s | - |

Commands 1-5 are the prompt's Checks block, run verbatim by `target/software-only/logs/07-s1-checks/run.sh`. Each exit code is the process's own `$?`, not a pipeline's, and each is recorded in `summary.txt`. The final run came after every edit.

Command 1 totals: 534 passed, 0 failed, 1 ignored (the ignore was already there). Of these, 19 are new `install::tests`. The callgate census guard `no_counted_or_destructive_selector_is_reachable_from_this_module` passes unmodified, and so does the upgrade tripwire `nothing_in_this_module_can_answer_a_message_or_allocate`.

Commands 3 and 4 each report 18 warnings, all in `vendor/frostsnap/*`. None is in a file this sub-step touched. One `manual_range_contains` in install.rs was fixed.

Command 5 (unchanged workload): footprint high-water 60512 B of 65536 B, 0 NULLs, binding assert FITS with 10860 B slack. The workload was NOT extended for the controller.

Command 6 result: "PASS: 136 checks agree with the reference". This covers `change_flags` offset 100, `CHANGE_FIRMWARE` 0x40 and 14 EPIN codes against the probed pins.h.

`cargo fmt --check` over the two crates still reports differences, but they are not new: callgate.rs has 4, the same count as HEAD, and upgrade.rs has 7, also the same as HEAD. The rest are in examples/.

No device, serial port, USB, flashing, OTP or real callgate was involved. `/Users/garykrause/repos/coldcard-firmware` was only read (by the checker's probe build).

## Files changed
- `firmware/src/install.rs` (new): `Bootloader` trait, `Unbound`, `GateFault`/`ImageFault`/`Refusal`, `request_bounds`, `CheckedImage`, `Workflow`, a strict `FakeGate` (test only), 19 tests and a source tripwire.
- `firmware/src/lib.rs:96`: `pub mod install;`.
- `firmware/src/upgrade.rs:599-630`:
  - `installable` now calls `image::check_installable` on `staged_view()`;
  - new `staged_view()` and `staged_digest()`.
- `hal/src/callgate.rs`:
  - `Errno::NOT_BOUND` (:227);
  - `CHANGE_FIRMWARE: i32` (:740);
  - `OFF_CHANGE_FLAGS` (:941);
  - `change_flags`, `firmware_request`, `set_firmware_request` (:1048-1086);
  - `raw_mut` gated to test/test-seam (:1088);
  - 9 EPIN i32 consts (:1162-1182);
  - 2 tests plus offset asserts.
- `tools/check-reference-contracts.py`: `change_flags` added to ABI_FIELDS/OFFS, plus `EPIN_KEYS` and a `CHANGE_FIRMWARE` probe and compare (:290-338, :711-726).

## Acceptance criteria

| Criterion | Status | Evidence |
|---|---|---|
| Valid blank-PIN and PIN-set fixtures reach exactly one correctly formed mock install request | met (fake) | `blank_pin_reaches_exactly_one_well_formed_request`, `pin_set_logs_in_once_per_submission_then_requests_once`. The fake checks the HMAC it issued, `PA_SUCCESSFUL`, `CHANGE_FIRMWARE`, range and signature; calls are logged. |
| Failed image, consent or login checks never reach the install request | met (fake) | `no_consent_declined_or_no_keypad_...`, `consent_is_bound_to_the_shown_digest...`, `login_faults_are_explicit_single_shot_outcomes`, `setup_faults_and_bad_pins...`, `a_short_tail_image_is_refused...` |
| Signature and downgrade refusals produce a failed request, never a success | met (fake) | `bootloader_signature_and_downgrade_refusals_are_failed_requests` covers tampered-after-sign, timestamp below the OTP minimum, and major version < 3; each gives `GateFault::ImageRefused` with no burn. |
| No private release credential required | met | A test secp256k1 key stands in for `approved_pubkeys[0]`. No 00.pem scalar is embedded, and there is no manifest or allowlist. |
| Length disagreement, oversize and non-4K-aligned are rejected at the install boundary | met | `length_disagreement_oversize_and_digest_mismatch_are_refused`, `a_short_tail_image_...` (262,656), `request_bounds_are_the_flash_fs_ceiling...`. Also `the_bootloader_model_does_not_catch_a_length_disagreement`: the modelled gate accepts caller len ≠ header len, and `check_view` refuses it. |
| No automatic PIN retry, reused consent or duplicate install request | met (fake) | Login count assertions (AE_FAIL is not retried), `a_wrong_pin_at_the_edge...`, `a_replacement_image_starts_without_consent`, both reset tests, the post-request `Finished` asserts, and the fake panics on a second install. |
| The fake returns an honest install-request/reset outcome, never a "flashed" claim | met | `InstallRequested{start,len}` is documented as "not installed; silicon never returns". The fake records `burns` as requests only. |
| Real 18/2 and 18/7 remain unbound | met | The callgate census guard is unchanged and passes. `Unbound` returns `NOT_BOUND` from all three operations. The install.rs tripwire, whose mutation fires (cmd 8), bans `pin_setup_attempt`, `callgate::call`, `raw(`, `SELECTOR_`, `PIN_SUBCALL` and `asm!`. |
| Signing, backup, ARM builds, heap limits and staging tests stay valid; the new workload's memory cost is measured | partly met | Cmds 1-5 pass with the heap workload unchanged. **Not met:** there is no controller workload in heap_session and no memory measurement. That is sub-step 2. |

## Forbidden-shortcut audit

- **Mock falls back to a real callgate function:** no. `FakeGate` is `#[cfg(test)]` and touches only the 280 bytes through `raw_mut`, which is test/test-seam gated. The production code has no callgate call (tripwire).
- **More than one install request / automatic PIN retry / reused consent across cancel, replacement or reboot:** not possible.
  - The workflow is set to Ended before the 18/7 call.
  - `submit_pin` has a single `login` call and no loop.
  - The grant is private: `cancel`, Declined and NoKeypad end the workflow; a replacement needs `&mut Stager`, which the borrow checker blocks while the Workflow lives; a reboot gives HMAC_FAIL in the fake, and the next workflow has no grant.
- **Leaning on the signature check for header len == burn len:** no.
  - `check_view` runs `check_installable`, `check_burn_len`, and received == call.
  - `request_bounds` then runs on the exact words written.
  - A demo test shows that the gate model burns the caller's len.
- **Relaxing source guards on destructive or counted subcalls:** no. The callgate census test is untouched. `CHANGE_FIRMWARE` is a top-level `i32`, which by design stays out of the frozen 16-count of `pub const ...: u32 =` lines. **The verifier should judge whether that is acceptable or reads as evasion.**
- **Claiming the fake measures SE counters, flash timing or PSRAM retention:** no. The module docs and the FakeGate docs both say it does not.

## Left for sub-step 2 / verifier
- Extend the heap_session workload with the controller and measure its cost. The controller holds no heap; `Workflow` is stack-only.
- Wire the listener (`upgrade::run`) to `Workflow`, plus the on-device consent UI and PIN entry.
- Task-06 integration run.
- For the verifier: whether `raw_mut` under `feature = "test-seam"` is an acceptable exposure, and the i32 choice for `CHANGE_FIRMWARE`.

## Residual bench-only questions
- Does 18/0 move SE1 Counter[0]? (`read_counter0` before and after.)
- Real 18/2 `attempts_left` and SE2 bad-PIN side effects on an expendable unit.
- Real `verify_firmware_in_ram` verdict on a key-0 image, burn timing, and reset.
- Power loss during the burn and `psram_recover_firmware`; PSRAM retention across reset.

---

## Sub-step 2, slice: strict fake gate, fault injection, ARM compile (2026-09-24)

Scope: this slice only. Out of this slice and NOT done here: extending `heap_session` with the controller and measuring its memory; wiring the `main.rs` listener to `Workflow` (consent screen, PIN entry); task-06 cross-process integration. Nothing committed or pushed.

### Files changed (all in `firmware/src/install.rs`; no other file touched in this slice)
- `:712` `pub fn device_path(&mut Workflow<'_, psram::MappedPsram>, &[u8])`. A non-generic device instantiation over `Unbound`, so the ARM build generates code for the whole gate-facing path instead of only type-checking a generic. With `Unbound` it stops at `setup` with `NotBound`. No caller in `main.rs`, and it takes no consent.
- `:778` FakeGate `lie: Option<Call>` is a new fault mode: a successful 18/0 or 18/2 that signs contradictory flags.
- `:1059` `stage` and `:1084` `yes` are now generic over `P: Psram` so the drift double can reuse them.
- New tests:
  - `:1559` `install_request_faults_are_one_failed_request_each`: 11 codes (HMAC_FAIL, OLD_ATTEMPT, AE_FAIL, SE2_FAIL, I_AM_BRICK, MUST_WAIT, RANGE_ERR, BAD_REQUEST, WRONG_SUCCESS, AUTH_FAIL, positive errno 1), each on both blank and PIN-set paths. Each gives exactly one Install call, no burn, then `Finished`.
  - `:1601` `a_setup_fault_inside_a_submission_spends_no_login`: an AE, SE2 or MUST_WAIT fault on the submission's 18/0 leaves no login and 13 attempts left. A bricked gate: 18/0 fails with `Bricked`, and nothing follows.
  - `:1629` `a_gate_that_lies_about_success_stops_the_workflow`: gives `Malformed`, with no login after a lying 18/0 and no install after a lying 18/2.
  - `:1670` `DriftPsram` + `:1708` `readback_drift_after_consent_is_refused_before_the_request`: PSRAM read-back changes after begin and consent. A body bit flip gives `ImageFault::Digest`. A header length-field change gives `NotInstallable(Length(Truncated))`. Neither makes an install call.
  - `:1743` `the_fake_gate_panics_on_a_second_accepted_install` (should_panic): the fake itself enforces at-most-once.
- `:1815` the tripwire is extended to the test doubles. The non-comment code of the test module above the tripwire must not contain `pin_setup_attempt(`, `callgate::call`, `callgate::raw`, `as_mut_ptr`, `unsafe` or `asm!`. So the mock cannot fall back to a real gate function.

### Commands (cwd `/Users/garykrause/repos/cold-snap`; logs `target/software-only/logs/07-s2/`, `summary.txt` has the real exit codes)
| # | Command | Exit | Time |
|---|---|---|---|
| 1 | `cargo test --target aarch64-apple-darwin -p coldsnap_hal -p coldsnap_firmware --features coldsnap_hal/fake-flash,coldsnap_hal/test-seam` | 0 | 11s |
| 2 | `cargo build --release` | 0 | 7s |
| 3 | `cargo clippy --release --target thumbv7em-none-eabihf -p coldsnap_hal -p coldsnap_firmware` | 0 | 1s |
| 4 | `cargo clippy --target thumbv7em-none-eabihf -p coldsnap_hal -p coldsnap_firmware` | 0 | 1s |
| 5 | `cargo run --release --target aarch64-apple-darwin -p coldsnap_firmware --example heap_session --features coldsnap_hal/test-seam,frostsnap_core/coordinator` | 0 | 11s |
| 6 | `python3 tools/check-reference-contracts.py --json target/software-only/refcheck/result.json` | 0 | 18s |
| 7 | `cargo clippy --target aarch64-apple-darwin -p coldsnap_firmware --tests --features coldsnap_hal/fake-flash,coldsnap_hal/test-seam` (extra) | 0 | 3s |
| 8 | `nm -C target/thumbv7em-none-eabihf/release/deps/libcoldsnap_firmware-cd89c601edee1943.rlib` filtered on `install::` | 0 | <1s |
| M1 | Mutation: added `pub const PIN_SUBCALL_LOGIN: u32 = 2;` to `hal/src/callgate.rs`; ran `cargo test ... no_counted_or_destructive_selector_is_reachable` | 101 (expected) | ~10s |
| M2 | Mutation: `let _ = "callgate::call";` in `FakeGate::reboot`; ran `cargo test ... install::tests::nothing_here` | 101 (expected) | ~10s |
| M3 | Mutation: replaced the pre-request `CheckedImage::check(self.stager)` with `self.image`; ran `cargo test ... install::tests::readback_drift` | 101 (expected) | ~10s |
| 9 | Command 1 re-run after restoring all mutants (`cmp` against the `target/software-only/07-s2-backup/` copies: identical) | 0 | 13s |

- Test totals (cmd 1 and 9): 539 passed, 0 failed, 1 ignored (it was ignored before this step). That is 534 at sub-step 1 plus 5 new tests; 24 of them are install tests.
- Clippy ARM (3, 4): 18 warnings each, all under `vendor/`. None in `firmware/` or `hal/`. The "Checking coldsnap_firmware" line is present in both logs, so they were not cache no-ops.
- Symbols in the ARM rlib (8): `T coldsnap_firmware::install::device_path`, `T ...Workflow<P>::submit_pin` and `T ...Workflow<P>::request_install` are present (`setup` is inlined). The ARM build codegens the path; with `Unbound` it has no effect.
- The mutants' failure messages:
  - M1: "a top-level u32 constant was added or removed ... left: 17".
  - M2: "`callgate::call` in install.rs's test doubles".
  - M3: `left: Ok(InstallRequested { start: 0, len: 266240 })`. Without the re-check, drifted bytes reach an accepted request, so the re-check is load-bearing.
- Heap (5): 60512 of 65536 B, 0 NULLs, slack 10860 B. This is the UNCHANGED workload; the controller is not in it (out of this slice).
- Reference check (6): `PASS: 136 checks agree with the reference.`
- `rustfmt --check firmware/src/install.rs`: exit 0.

### Acceptance criteria (this slice's contribution)
| Criterion | Status |
|---|---|
| Blank-PIN and PIN-set fixtures reach exactly one well-formed mock request; failed image, consent and login checks never reach it | met against the fake (sub-step 1). Strengthened here: the image re-check is shown to be live via drift and M3 |
| Signature and downgrade refusals are failed requests | met (sub-step 1); every other 18/7 code is also one failed request (`:1559`) |
| Length disagreement, oversize and non-4K are rejected at the boundary | met (sub-step 1); a header-length drift at request time is also rejected (`:1708`) |
| No automatic PIN retry, reused consent or duplicate request in exercised failure and re-entry cases | met against the fake: 11 install faults x 2 paths, setup faults inside a submission, lies, reset (sub-step 1), and the fake's own at-most-once panic |
| Honest outcome; real 18/2 and 18/7 unbound | met. Census unchanged and shown live (M1); `Unbound` is the only device gate; the doubles are shown gate-free (M2) |
| ARM builds, staging tests and heap limits stay valid | met: commands 2-4 exit 0, all staging tests pass, heap FITS |
| New workload's memory cost measured | NOT met: out of this slice, and the workload is not extended |
| Task-06 cross-process integration | NOT done: out of this slice, outstanding |
| Real gate behaviour | unverifiable without hardware |

### Forbidden-shortcut audit
- The mock never falls back to a real callgate function. Held: `FakeGate` and `DriftPsram` are pure. Enforced by the tripwire at `:1815` and demonstrated by M2.
- At most one install request, no automatic PIN retry from one submission, no reused consent grant. Held. See the tests above, and the fake's own should_panic.
- Header-verified length and burn length are decoupled. Held: the fake burns the caller's `len` (sub-step 1 test `the_bootloader_model_does_not_catch_a_length_disagreement`), and the controller's re-check catches a header-length drift (`:1708`).
- Source guards are not relaxed. Held: `callgate.rs` is untouched in this slice, the census test passes unmodified and is shown live (M1).
- The fake does not measure SE counters, flash timing or PSRAM retention, and no claim here says it does. `DriftPsram` models a read-back change, not retention.
- Global rules: no device or port was touched and nothing was written to the reference repo. Mutants were staged by in-tree edit and restored from `target/` backups, and the `cmp` shows the restore is exact. Logs are under `target/`. Exit codes are process statuses, not pipeline statuses.

### Residual bench-only questions (unchanged, in the prompt's terms)
- Real 18/0 counter behaviour: does 18/0 move SE1 `Counter[0]`? Measure with `read_counter0` (21/3) before, between and after two 18/0 calls (UPGRADE-PLAN §5 item 1).
- 18/2 login on a PIN-set expendable unit (phase 5): the real `attempts_left` and `se2_handle_bad_pin` effects.
- 18/7 installation (phase 6): the real `verify_firmware_in_ram` verdict on a key-0 image, burn and reset.
- Reset or power interruption mid-burn and `psram_recover_firmware` recovery; PSRAM retention across reset.
- Binding required later: a device `Bootloader` implementation whose `setup`, `login` and `request_install` each make exactly one selector-18 call (arg2 0, 2 and 7) on `PinAttempt::as_mut_ptr`, counted by the `callgate.rs` census (§3.10), replacing `Unbound`.

## Repair — batch 1 of 3

Logs: `target/software-only/logs/07-r1/`. Nothing committed.

### Findings

1. **Controller workload not in heap_session / memory cost unmeasured** (two CONFIRMED findings, same cause): FIXED.
   `firmware/examples/heap_session.rs` now runs a new phase `install` (PHASES, `phase(5)`; teardown moved to `phase(6)`)
   after `HeldShares2`, with the `Session` still alive. `install_workload` (:795) builds a `Stager<FakePsram>` inside the
   device span, admits `PrepareUpgrade2`/`EnterUpgradeMode`, feeds the image in 64 B chunks, then
   `Workflow::begin -> setup -> confirm -> [submit_pin] -> request_install`, once blank-PIN and once PIN-set. The gate is
   `MeasureGate` (:740), an example-local counting double that writes magic/flags/attempts via `raw_mut` and calls no
   `callgate` function. It is NOT the strict `FakeGate` and verifies no HMAC/signature/downgrade. The image (`install_image`, :779) is
   Mk4-shaped and unsigned, because `CheckedImage` checks shape/length/digest, not the signature.
   Runtime gates added: `allocs == 0`, `live delta == 0`, `installs == 1`, `logins == pin_set as u32`, burn `(start,len)` == request.
   Measured this run (release, host 64-bit), from `logs/07-r1/check-5.log`:
   - blank PIN: 0 arena allocations, live +0 B, 1 setup / 0 login / 1 install
   - PIN set: 0 arena allocations, live +0 B, 2 setup / 1 login / 1 install
   - host `size_of`: Workflow 376 B, CheckedImage 40 B, PinAttempt 280 B, Stager<FakePsram> 80 B (PSRAM Vec excluded)
   - arena footprint high-water unchanged (keygen's high-water covers it, so the footprint delta tells you nothing. The alloc count is the real measure)
   - NOT measured: call-frame stack depth of `check_view`'s digest pass or the workflow methods; 32-bit device sizes.
   Mutation check: a temporary `vec![0u8; 64]` inside the span caused exit 134, `the install workload made 1 arena allocation(s)`
   (`logs/07-r1/mutation-alloc.log`). File restored and re-run to exit 0.
2. **Doc block orphaned in callgate.rs**: FIXED. The `MUTATION TARGET: mis-decode an error return` doc now sits directly on
   `pin_error_codes_decode_to_pins_h_values` (`hal/src/callgate.rs:1825`). It no longer sits above the doc of `a_firmware_request_touches_only_bytes_outside_the_hmac`.
3. **Tripwire's documented mutation was a host compile error**: FIXED (doc). `firmware/src/install.rs:1775` now names the mutation
   `#[cfg(target_arch = "arm")] return coldsnap_hal::callgate::pin_setup_attempt(_att);` in `Unbound::setup`. It also explains that an
   ungated call is E0425 on the host and never reaches the assertion. Verified: with that mutation applied, the test
   `nothing_here_reaches_a_real_gate_or_an_identity` failed with `` `pin_setup_attempt` in install.rs production code ``, exit 101
   (`logs/07-r1/mutation-tripwire.log`). The file was restored afterwards. The assertion was not changed.

### Commands re-run (cwd `$HOME/repos/cold-snap`)

| # | command | exit |
|---|---|---|
| 1 | `cargo test --target aarch64-apple-darwin -p coldsnap_hal -p coldsnap_firmware --features coldsnap_hal/fake-flash,coldsnap_hal/test-seam` | 0 (163+57+295+5+19 passed, 1 ignored doctest) |
| 2 | `cargo build --release` | 0 |
| 3 | `cargo clippy --release --target thumbv7em-none-eabihf -p coldsnap_hal -p coldsnap_firmware` | 0 (18 warning lines, same count as `logs/07-s2/check-3.log`, none in changed files) |
| 4 | `cargo clippy --target thumbv7em-none-eabihf -p coldsnap_hal -p coldsnap_firmware` | 0 (18, same as s2) |
| 5 | `cargo run --release --target aarch64-apple-darwin -p coldsnap_firmware --example heap_session --features coldsnap_hal/test-seam,frostsnap_core/coordinator` | 0 |
| - | `cargo clippy --release --target aarch64-apple-darwin -p coldsnap_firmware --example heap_session --features coldsnap_hal/test-seam,frostsnap_core/coordinator` | 0 (one warning at pre-existing `heap_session.rs:455`) |
| m | alloc-gate mutant (heap_session) | 134, expected |
| m | tripwire mutant (`--lib nothing_here_reaches_a_real_gate`) | 101, expected |

Still outstanding (not this batch): task-06 cross-process integration and listener wiring, which were already disclosed.

## Repair — batch 2 of 3

Logs: `target/software-only/logs/07-r2/`. Nothing committed. cwd for every command: `$HOME/repos/cold-snap`.

### Findings

1. **Task-06 cross-process integration reported outstanding although available**: FIXED (pty scope).
   - `firmware/src/upgrade.rs:778` has a new `pub fn serve(wire, &mut Stager)`. `run` (unchanged signature) is now `serve(wire, &mut Stager::new(psram))`, so a staged image can outlive the listener.
   - `firmware/src/install.rs:1885` has a new `#[ignore]` test, `task06_updater_stages_across_processes_then_one_install_request_each_path`. It opens the inherited pty master through `/dev/fd/N`, with no `unsafe`, because the tripwire bans `unsafe` in the doubles (a first draft used `from_raw_fd` and the tripwire caught it, exit 101). It then `serve`s what the updater sends into its own `Stager`, and drives `begin/setup/confirm/[submit_pin]/request_install` on THAT stager against the strict `FakeGate`, with `approved[0]` set to key 0's PUBLIC half. Blank-PIN and PIN-set each use a fresh fake. Run without the driver, it panics, it does not skip.
   - `tools/install-xproc.py` (new) is the driver. It derives key 0's public half from `00.pem` (read-only) with pack-venv `ecdsa`, builds the task-06 CLI and the lib test, makes a raw pty, and runs `coldsnap-mk4-update --port <slave> target/software-only/package/firmware-signed.bin` as process A and the test exe with the master as process B. It fails unless A exits 0 with `STAGED ... NOT installed` and B exits 0 with one XPROC row per PIN path, each matching A's length and digest.
   - Result: `target/pack-venv/bin/python tools/install-xproc.py` exited 0. The updater staged 397312 B, digest 58f1b3fe…f441 (the same digest as task 06's C15). XPROC blank: `calls=[Setup, Install]`. PIN set: `calls=[Setup, Setup, Login, Install]`. Each was exactly one request `(0, 397312)`, one burn record, and a second request refused `Finished`. Afterwards `pgrep -fl coldsnap-mk4-update` found nothing.
   - Negative control: with `approved = [test key]` instead of key 0, the driver exited 1 with `left: Err(Gate(ImageRefused))` (`mut-xproc-key.log`). The fake's signature model is live on the real key-0 artifact. File restored and `cmp` exact.
   - Scope: this is a request recorded by a fake, not an installation. It is not the stub-process stager: the stager runs in the test process, and the updater is a separate process on a pty. Nothing drives the install from task 06's `Mk4UpgradeState::InstallRequested`, and the verified reconnect is still outstanding (listener wiring).
2. **One Confirmation → two install requests via concurrent Workflows on a shared `&Stager`**: FIXED.
   - `Stager` now has `workflow: AtomicU32` (`upgrade.rs:231`) and `claim_workflow`/`live_workflow` (`:236`). Atomic is used only for interior mutability through `&self`.
   - `Workflow::begin` claims a serial (`install.rs:549`). `Workflow::current` (`:565`) ends a workflow once a newer one has begun on the same stager, and `setup`, `confirm`, `submit_pin` and `request_install` all go through it. So at most one workflow per stager is live, and a superseded one answers `Finished` without a gate call.
   - Test `a_second_workflow_supersedes_the_first_and_one_press_grants_one_workflow` (`:1800`) is F1's shape: w1 is confirmed, w2 begins, and MUST_WAIT is armed. w1's request is `Finished`, w1 makes no gate call, w1's press in w2 is `NoConsent`, and there is no Install call at all.
   - Mutant: the supersession check disabled gives exit 101 (`mut-supersede.log`).
3. **Stale Confirmation replay grants a new workflow**: FIXED.
   - `Confirmation::Confirmed { shown: Prompt }`. `Prompt` (`install.rs:405`) has private `digest`, `len` and `workflow` fields, and only `Workflow::prompt()` (`:555`) makes one. `confirm` grants only on `shown == self.prompt()`. `Prompt` is still `Copy`, but a copy is bound to one workflow serial, and every workflow requests at most once.
   - A reboot resets the RAM serial, but no `Prompt` survives a reboot either.
   - Test `a_stale_confirmation_is_refused_by_a_new_workflow_on_the_same_image` (`:1827`) is F2's shape: AUTH_FAIL is refused and dropped. On the same image (the digest is asserted equal), the stale press gives `NoConsent`, then `Finished`, with 0 gate calls. A fresh prompt then reaches exactly one burn.
   - Mutant: compare digest only gives exit 101, failing both new tests (`mut-serial.log`).
   - `heap_session.rs:817` now confirms with `w.prompt()`.
4. **Controller workload not in heap_session**: already FIXED by batch 1, and I made no change here. The re-run (check-5) shows the install phase with 0 allocations and live +0 B on both paths. The host `size_of` values are now Workflow 384 B (was 376, +8 for the serial and padding) and `Stager<FakePsram>` 88 B (was 80). FITS, slack 10860 B.

### Commands re-run (real exit codes)

| log | command | exit |
|---|---|---|
| check-1 | `cargo test --target aarch64-apple-darwin -p coldsnap_hal -p coldsnap_firmware --features coldsnap_hal/fake-flash,coldsnap_hal/test-seam` | 0 (165+57+295+5+19 passed; 1 ignored = the xproc test). The first run was 101 on the `unsafe` tripwire and was fixed by the `/dev/fd` open |
| check-2 | `cargo build --release` | 0 |
| check-3 | `cargo clippy --release --target thumbv7em-none-eabihf -p coldsnap_hal -p coldsnap_firmware` | 0 (18 warning lines, same as r1, 0 in changed code) |
| check-4 | `cargo clippy --target thumbv7em-none-eabihf -p coldsnap_hal -p coldsnap_firmware` | 0 (18, same) |
| check-5 | `cargo run --release --target aarch64-apple-darwin -p coldsnap_firmware --example heap_session --features coldsnap_hal/test-seam,frostsnap_core/coordinator` | 0 (NULLS 0, FITS) |
| clippy-example | `cargo clippy --release --target aarch64-apple-darwin -p coldsnap_firmware --example heap_session --features coldsnap_hal/test-seam,frostsnap_core/coordinator` | 0 (0 warnings in changed lines) |
| clippy-host-tests | `cargo clippy --target aarch64-apple-darwin -p coldsnap_firmware --lib --tests --features coldsnap_hal/fake-flash,coldsnap_hal/test-seam` | 0 (0 warnings in install.rs/upgrade.rs changes) |
| install-lib | `cargo test ... --lib install::` (check-1 flags) | 0 (26 passed) |
| xproc-driver | `target/pack-venv/bin/python tools/install-xproc.py` | 0 |
| mut-supersede / mut-serial / mut-xproc-key | mutants, restored and `cmp`-exact | 101 / 101 / 1, all expected |

Checks 2-5 ran before the last edit, which was test-only: the `#[cfg(test)]` `/dev/fd` open. That edit cannot change the release, ARM or example builds. check-1 and host clippy ran after it.
`rustfmt --check`: install.rs clean. upgrade.rs has 7 diffs, all at the same places as in HEAD's copy (7 pre-existing), none from this batch.

## Repair — batch 3 of 3

Finding: "New test inserted between an existing doc comment and its test, misattaching the doc" (hal/src/callgate.rs:1766-1770).

- Status: already FIXED by batch 1, and the fix is still in place. No edit was made in this batch.
- Checked in the current tree: the "MUTATION TARGET: mis-decode an error return" doc is at `hal/src/callgate.rs:1825`, directly above `pin_error_codes_decode_to_pins_h_values` (:1830). `a_firmware_request_touches_only_bytes_outside_the_hmac` (:1773) now has only its own doc (:1766-1771).
- Re-run (cwd `$HOME/repos/cold-snap`): `cargo test --target aarch64-apple-darwin -p coldsnap_hal --features coldsnap_hal/fake-flash,coldsnap_hal/test-seam --lib callgate` exited 0, with 24 passed and 0 failed. Log: `target/software-only/logs/07-r3/hal-callgate-test.log`.
- This is a doc-only finding, so there is no mutation to run.

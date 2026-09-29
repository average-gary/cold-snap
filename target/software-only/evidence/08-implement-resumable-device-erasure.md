# STATUS: DEGRADED

Reason: no CONFIRMED finding is open (both CONFIRMED findings were fixed in repair batch 1, and the
second independent re-run reproduced every check with an empty findings list). Acceptance criterion 2
is only partly met, though. An uninterrupted approved erase gives the coordinator a truthful
`EraseConfirmed` (hostcheck M9b and app-rig +9). A committed erase that is interrupted and then
finished at boot by `recover` sends no completion signal, so the coordinator/app keeps the old
device's share (verifier PLAUSIBLE finding, untested on the coordinator side). Real reset and USB
re-enumeration are unverifiable without hardware. The only claim available is
"software/pre-bench checks passed", scoped to host fakes, ptys and the real app against stubs.

Commits: frostsnap 76982a5eb33cd15764c817a77e7ad254f79c7ffb; cold-snap: the commit containing this file.
Criteria: 5 of 6 met (criterion 2 partial). See "Close-out" at the end of this file.

# 08 — Resumable cold-snap data erasure — sub-step 1 of 2 (implementer)

Slice: marker format, boot semantics, bounded erase. NOT in this slice (left for sub-step 2):
consent screen / `DataErase` admission, `EraseConfirmed` send, volatile wipe of `Secrets`/signer
RAM, capability flip (frostsnap), Flutter wording, hostcheck M9 / forged-erase replacement, app leg.
Nothing committed. frostsnap untouched.

## Files changed (cold-snap)

| file | change |
|---|---|
| `hal/src/erase.rs` (new, untracked) | marker record, `classify`, `read`, `begin`, `destroy`, `finish`, `recover`; 6 tests incl. exhaustive fault matrix |
| `hal/src/lib.rs:129` | `pub mod erase;` |
| `hal/src/lib.rs:255-269` | `memmap::FS_ERASE_OFFSET` (= 0x12000, old `FS_FREE_OFFSET`), `FS_ERASE_LEN` = 8 K; `FS_FREE_OFFSET` now 0x14000. No record offset moved. |
| `hal/src/lib.rs:426-433` | const asserts: marker contiguous, 8 K-page aligned, `FLASH_FS_BASE >= FLASH_ERASE_FLOOR` |
| `firmware/src/lib.rs:151-156` | `Fault::ErasePending` |
| `firmware/src/lib.rs:850-858` | `Session::open` refuses unless marker reads `Clear` (before nonce slots load / share replay) |
| `firmware/src/lib.rs:4578-4682` | test `an_interrupted_erase_never_reopens_a_signer_and_resumes_to_a_fresh_device` |
| `firmware/src/main.rs:53` | step table row 8a |
| `firmware/src/main.rs:1578` | import `erase` |
| `firmware/src/main.rs:2137-2158` | step 8a: `erase::recover` between flash open and `identity::load_or_create`; every `Err` -> `hold()` |
| `firmware/src/main.rs:2247-2249, 2277` | Session::open failure comment; `Err(Fault::ErasePending) => hold("erase pending")` |
| `firmware/examples/stub.rs:139, 1634-1640` | stub `open_sessions` runs `erase::recover` before identity (stub has no main.rs path) |

Test flashes sized from `FS_FREE_OFFSET` (stub, simulator, heap_session, lib/store tests) grew
automatically to include the marker; none edited.

## Marker and boot semantics

Record: 16 B at `FS_ERASE_OFFSET`: body `sha256("coldsnap-erase-marker-v1")[..8]`, then commit
`MAGIC = 0xC01D_5EED_E7A5_0001` (family / kind / version), commit programmed last.

| bytes | classify | boot (`recover`) |
|---|---|---|
| erased / zero / foreign (LFS2) / torn body / body w/o commit | Clear | proceed (no erase ever committed) |
| body + commit exact | Pending | resume `destroy` + `finish`, then identity regenerates |
| commit exact, body wrong (incl. commit w/o body) | Damaged | hold, touch nothing |
| family `0xC01D5EED`, unknown kind/version | Damaged | hold, touch nothing |
| marker read refused | Flash fault | hold |

Sequence: `begin` (erase marker region, body, commit, read-back = Pending) -> `destroy` (refuses
unless Pending; 18 single-sector erases share -> nonce -> name -> identity; verify all 0xff) ->
[caller acks — sub-step 2] -> `finish` (refuses unless Pending AND data verifies blank; erase marker;
verify blank) -> [caller resets — sub-step 2]. Resume at boot does NOT ack (original identity may be
gone; a waiting coordinator keeps waiting, never told a falsehood).
Defense in depth: `Session::open` refuses a non-Clear marker; share-first order means that even
with the marker ignored, no nonce/name/identity sector is erased while any share byte survives.

Erase boundary: only `[0, FS_ERASE_OFFSET)` (identity, nonce x4 A/B, share A/B, name A/B — the four
regions tile it, const-asserted) plus the 8 K marker region. Raw `NorFlash::erase`/`write`, not
`AbSlot` (so no `ab_write.rs` panics). No callgate, no SE selector, no option bytes, no `fast_wipe`
(grep: `erase.rs` names them only in docs).

## Commands (all run; exit codes are the process's own)

| # | command | cwd | exit | time |
|---|---|---|---|---|
| base | `cargo test --target aarch64-apple-darwin -p coldsnap_hal -p coldsnap_firmware --features coldsnap_hal/fake-flash,coldsnap_hal/test-seam` (before any edit) | `$HOME/repos/cold-snap` | 0 | ~60 s |
| 1 | `cargo test --target aarch64-apple-darwin -p coldsnap_hal -p coldsnap_firmware --features coldsnap_hal/fake-flash,coldsnap_hal/test-seam` | `$HOME/repos/cold-snap` | 0 | 56 s |
| 2 | `cargo build --release` | `$HOME/repos/cold-snap` | 0 | 13 s |
| 3 | `cargo clippy --release --target thumbv7em-none-eabihf -p coldsnap_hal -p coldsnap_firmware` | `$HOME/repos/cold-snap` | 0 | 5 s |
| 4 | `cargo clippy --target thumbv7em-none-eabihf -p coldsnap_hal -p coldsnap_firmware` | `$HOME/repos/cold-snap` | 0 | 6 s |
| 5 | `cargo build --target aarch64-apple-darwin -p coldsnap_firmware --example stub` | `$HOME/repos/cold-snap` | 0 | 14 s |
| 6 | `cargo run -- ../target/aarch64-apple-darwin/debug/examples/stub` | `$HOME/repos/cold-snap/hostcheck` | 0 | 45 s |
| x | `python3 tools/check-reference-contracts.py --json target/software-only/refcheck/08a-result.json` (memmap changed) | `$HOME/repos/cold-snap` | 0 | 30 s |
| x | `cargo doc --no-deps -p coldsnap_hal -p coldsnap_firmware` | `$HOME/repos/cold-snap` | 0 | — |

Logs: `target/software-only/logs/08a-*.log`. Test counts (check 1): firmware lib 166 pass / 1 ignored
(was 165), hal lib 301 (was 295), others unchanged; 0 failed. Clippy: 0 warnings in coldsnap_hal /
coldsnap_firmware (all 15 are vendor/). Refcheck: COVERED 136, FAILED 0, UNAVAILABLE 0. Rustdoc: 0
warnings in `erase.rs`; remaining warnings are pre-existing in other files. Hostcheck exit 0 with
M9 still asserting `refused=DataErase` — correct for this slice, since `DataErase` is still refused
on the wire (sub-step 2 changes that and must replace M9 / the forged-erase count).
One mis-typed run of check 6 failed at the shell redirect (relative log path, exit 1, 0 s,
hostcheck never started); re-run as row 6.

New fault tests:
- `hal erase::tests::every_interrupted_state_is_blocked_and_every_restart_resolves`: interrupts the
  in-session erase at every flash call (634 calls in one run: marker reads/erase/2 programs, 18
  sector erases, every verify read, completion erase, completion verify), refused-before and
  performed-then-reported-failed; from the resulting BYTES asserts marker Pending whenever data was
  touched (unless data already fully blank = completion), share-first ordering, sentinels at and
  above `FS_FREE_OFFSET` over a full 512 K `FLASH_FS` untouched, every op inside `[0, FS_FREE_OFFSET)`,
  no program into the data region; then reboots through `recover`, itself interrupted at every
  mutation and read-run edge and retried; asserts end state is "intact + Clear" (only if nothing
  committed) or "data + marker blank". Printed: 2513 restart states checked.
- `hal erase::tests::{classify_table, destroy_and_finish_refuse_without_a_committed_marker,
  a_damaged_or_newer_marker_holds_and_touches_nothing, a_refused_marker_read_is_a_bounded_fault,
  a_complete_erase_blanks_exactly_the_data_region_and_clears_the_marker}`.
- `firmware tests::an_interrupted_erase_never_reopens_a_signer_and_resumes_to_a_fresh_device`: real
  persisted share + open nonce stream; cut at every program and erase call boundary via FakeFlash
  refusals; while Pending, `Session::open` with the OLD secret returns `ErasePending`; after
  `recover`, new identity, new DeviceId, 0 held shares; uncommitted cuts leave share + id intact.

Mutation checks run by hand (each reverted): nonce-before-share order -> matrix + order test fail;
commit-before-body -> 2 tests fail; `destroy` accepting Clear -> refusal test fails; `Session::open`
guard removed -> firmware test fails ("a signer opened over a committed erase").

## Acceptance criteria (task 08) — status after sub-step 1

| criterion | status |
|---|---|
| Unconfirmed/declined/cancelled requests write no marker or data | NOT MET by this slice (no consent path yet; `DataErase` still wire-refused, hostcheck M9 confirms). `destroy`/`finish` structurally refuse without a committed marker. Sub-step 2. |
| Successful erase removes all persistent copies, reconnects blank with fresh identity; truthful completion to coordinator | PARTIAL: flash side met (firmware test: fresh id, no share; hal: whole A/B regions 0xff). Reconnect over wire and `EraseConfirmed` NOT MET — sub-step 2. |
| Interruption before/after every marker write, page erase, verification, completion; reconstruct from bytes; no old share/nonce state can sign while incomplete | MET at host-fault-injection level (tests above). |
| Unknown marker formats and read/write failures have bounded outcomes | MET: Damaged -> hold, touch nothing; flash/verify faults -> `EraseFault` -> hold at boot, marker preserved for next boot. |
| Sentinels outside permitted region untouched; bootloader/SE selectors never used | MET for FS-relative sentinels (fake). Below-floor/bootloader: structural only (FS-relative offsets, `check_bounds`, `erase_page_of`, new const assert) — fake cannot represent bytes outside FLASH_FS. No callgate/SE code in erase path. |
| State that host fault injection does not validate STM32 erase physics or secure deletion | MET: `hal/src/erase.rs` module docs "What this does NOT validate", and here. |

## Forbidden-shortcut audit

- No marker/data write without fresh consent: no production caller of `begin`/`destroy` exists yet;
  only boot `recover` (acts only on an already-committed marker). Consent gating is sub-step 2's.
- Interrupted erase resumes or fails closed, never reopens a signer on a mixture: held by
  `recover` at step 8a + `Session::open` guard + share-first order; tested.
- `EraseConfirmed` only after durable deletion: not sent anywhere in this slice. API contract:
  ack only after `destroy` Ok; `finish` requires verified-blank data.
- Sentinels outside region untouched; no bootloader/SE destructive selectors: held (tests + grep).
- Host fault injection does not validate STM32 erase physics: stated, not claimed.
- No assertion weakened or deleted; existing `data_erase_is_refused`, hostcheck M9 untouched.

## Residual, bench-only (in the prompt's terms)

- STM32 erase physics: a page erase torn by power loss (partially erased cells, ECC double-error on
  read of the marker or data) is not modelled; FakeFlash is all-or-nothing per call. In particular a
  torn marker CLEAR that leaves our family high word with a garbled version would read Damaged and
  hold a device whose data is already erased — needs bench characterisation.
- Secure deletion from a physically compromised chip (remanence, decap) — not addressed.
- Real StmFlash erase of the 0x0818_0000+ region under `DBANK==1` and RDP=2 — unverified on silicon.
- Rot of a committed marker's commit word into non-family bytes reads Clear; share-first order bounds
  the damage (no share + reset nonces), but a subsequent new keygen over a rewound nonce region is
  not excluded if the marker is lost that way.

## Left for sub-step 2 / verifier

Consent screen and `DataErase` admission (`lib.rs` recv arm, prompt, `Cancel`), ack ordering
(`EraseConfirmed` pushed between `destroy` and `finish`, under the original id), volatile wipe
(`Secrets.seed`, `IdentitySecret` clone, signer RAM), reset, stub reconnect with fresh id,
capability flip + tests in frostsnap, Flutter wording, replacing `data_erase_is_refused`,
`simulator.rs:1190`, hostcheck M9 and forged-erase exact count, app leg. Verifier may judge:
Damaged-on-committed-bad-body -> hold (chosen over resume); resume path sends no ack.

---

# 08 — sub-step 2 of 2 (implementer): consent, ack ordering, reconnect, capability flip

Appended 2026-09-24. Nothing committed or pushed. User work untouched (cold-snap `prompts/`,
`tools/__pycache__/`; frostsnap `.gitignore`, `Podfile.lock`, `justfile`, `coldcard_msg_len.rs`).

## Files changed (sub-step 2)

cold-snap:
- `firmware/src/lib.rs`: `Fault::Erase` :161; `erase_requested` :936, `decline_erase` :943,
  `erase` :968-992 (poison -> RAM wipe -> begin/destroy -> push EraseConfirmed -> finish);
  `ErasePending` guards in announce/recv/confirm_at (:1045, :1073, :1445); recv sets
  `erase_asked` from the body :1079 (any other body withdraws the question); DataErase arm
  `Ok(Vec::new())` :1185; `erase_screen` :2640. Tests: `data_erase_is_refused` REPLACED by
  `no_erase_without_a_live_consented_request` :3629 (never-asked, declined, Cancel, stale
  AnnounceAck, malformed Upgrade — zero flash calls, byte-identical flash, same id/share/name),
  `an_approved_erase_acks_after_deletion_and_reopens_fresh` :3699,
  `an_erase_cut_at_any_flash_call_acks_only_after_deletion` :3747 (every program + every erase).
- `firmware/src/main.rs`: `Flow::Erase` -> `Consent::Question` :1062; `show_erase` :1790; glass
  arm :2817 (Yes -> `session.erase`, flush outbox, `system_reset`; else `decline_erase`+refuse);
  test `the_erase_runs_only_on_the_digit_its_question_printed` :4470; four source-pin counts
  raised with written reasons (new sites of existing categories, no assertion removed).
- `firmware/examples/stub.rs`: `STUB_ERASE_KEYS` :389, `EraseOutcome` :395, `open_one` :1669,
  erase/decline in `drive`, post-erase rebuild from the same flash with fresh-id / 0-share /
  no-name asserts :2447, Declined-with-flash-change dies.
- `firmware/examples/simulator.rs`: scene 9b now draws the erase question :1206.
- `hostcheck/src/main.rs`: M9 doc superseded-in-part :393; leg 1 starts at Reveal; leg 2 gets
  `erase_last` :1733 -> `Phase::Erase` (M9a decline, must NOT complete, needs
  `declined=DataErase`) -> `Phase::Erased` :2027 (M9b approve, must reach Success, then a never-
  seen id must Announce + NeedName + report 0 shares); `refused=DataErase` is now a failure
  :3809; unclaimed `EraseConfirmed` is a failure :3973; forged-frame exact count now counts
  glass declines; `STUB_ERASE_KEYS=xy` :3113; summary/PASS strings.
- `README.md`, `UPGRADE-PLAN.md`: current-state erase lines. PLAN.md / HARNESS-PLAN.md history
  left as written (stale by design, verifier's call).

frostsnap:
- `frostsnap_coordinator/src/device_profile.rs:160-165` ColdsnapMk4 `erase: true` + reason.
- `frostsnap_coordinator/tests/device_profile_test.rs:151` `assert!(erase, ...)`.
- `frostsnapp/rust/src/api/device_list.rs:359` `assert!(mk4.erase, ...)`.
- `frostsnapp/rust/src/coordinator.rs:1134` comment only (gate unchanged).
- `frostsnapp/integration_test/coldsnap_workflows_test.dart:345-347` `isTrue`.
- `frostsnapp/lib/device.dart:200-201` wording, :482 comment.
- No Rust API signature changed -> no bridge regeneration (frb_generated.rs untouched).

## Commands (sub-step 2; exit is the process's own, captured via `$?` of the command, not a pipe)

| # | cwd | command | exit | time |
|---|---|---|---|---|
| 1 | $HOME/repos/cold-snap | `cargo test --target aarch64-apple-darwin -p coldsnap_hal -p coldsnap_firmware --features coldsnap_hal/fake-flash,coldsnap_hal/test-seam` | 0 | 11s |
| 2 | $HOME/repos/cold-snap | `cargo build --release` | 0 | 7s |
| 3 | $HOME/repos/cold-snap | `cargo clippy --release --target thumbv7em-none-eabihf -p coldsnap_hal -p coldsnap_firmware` | 0 | 1s |
| 4 | $HOME/repos/cold-snap | `cargo clippy --target thumbv7em-none-eabihf -p coldsnap_hal -p coldsnap_firmware` | 0 | 1s |
| 5 | $HOME/repos/cold-snap | `cargo build --target aarch64-apple-darwin -p coldsnap_firmware --example stub` | 0 | 0s |
| 6 | $HOME/repos/cold-snap/hostcheck | `cargo run -- ../target/aarch64-apple-darwin/debug/examples/stub` | 0 | 21s |
| 7 | $HOME/repos/frostsnap | `cargo test -p frostsnap_coordinator --lib` | 0 | 17s |
| 8 | $HOME/repos/frostsnap | `cargo test -p frostsnap_coordinator --test device_profile_test` | 0 | 5s |
| 9 | $HOME/repos/frostsnap | `cargo test -p frostsnap_coordinator` | 101 | 2s |
| 10 | $HOME/repos/frostsnap/frostsnapp/rust | `cargo test --lib` | 0 | 24s |
| 11 | $HOME/repos/frostsnap/frostsnapp | `flutter analyze lib/device.dart integration_test/coldsnap_workflows_test.dart` (pinned SDK: Flutter 3.38.5 / Dart 3.10.4) | 0 | 17s |
| 12 | $HOME/repos/cold-snap | `tools/app-rig-test.sh` | 0 | 85s |
| M1 | $HOME/repos/cold-snap/hostcheck | mutant `STUB_ERASE_KEYS=yy` (source edited, run via `cargo run -- ...`, restored from `target/software-only/main.rs.08b-bak`) | 1 | 2s |
| M2 | $HOME/repos/cold-snap/hostcheck | mutant `STUB_ERASE_KEYS=xx` binary `../target/software-only/hostcheck-mut-xx ../target/aarch64-apple-darwin/debug/examples/stub` | 1 | 95s |

Logs: `target/software-only/logs/08b-check-{test,release,clippy-release,clippy-debug,stub,hostcheck}.log`,
`08b-checks-summary.txt`, `08b-fs-coord-lib.log`, `08b-fs-devprofile.log`, `08b-fs-coord-full.log`,
`08b-fs-app-rust.log`, `08b-flutter-analyze.log`, `08b-app-rig.log`, `08b-hostcheck-mut-{yy,xx}.log`,
`08b-hostcheck-probe.log`.

Results: (1) lib 168 pass/1 ignored, main 58, hal 301, host_smoke 5, integration 19. (3)(4) 18
warnings each, all under `vendor/frostsnap/` (pre-existing), none in coldsnap_hal/coldsnap_firmware.
(6) both chunk passes print `M9a PASS` (declined, `is_complete()==None` for ~1.0 s) and `M9b PASS`
(Success on EraseConfirmed; came back as new id with NeedName and 0 shares); 12/12 roster
devices declined the forged DataErase at the glass. (9) BLOCKED by the user's untracked
`frostsnap_coordinator/tests/coldcard_msg_len.rs:97` E0308, not by this change; covered by 7+8.
(12) 8/8 flutter integration tests passed on the real app over 4 ptys, including the
capability test now asserting `erase` isTrue. The rig has NO erase flow: an app-driven approved
erase was NOT RUN. M1 killed by name: `UNSOLICITED ERASE: <id> sent EraseConfirmed with no live
EraseDevice to claim it`. M2 killed by deadline: `DEADLINE (95s) in state EraseRefusal`.
Firmware mutation (from earlier in this sub-step): moving the EraseConfirmed push before
begin/destroy was killed by the cut-matrix test (`acked before deletion`); restored.
`check-reference-contracts.py` not run: memmap unchanged in this sub-step.

## Acceptance criteria (task 08) — status after sub-step 2

| criterion | status |
|---|---|
| Unconfirmed/declined/cancelled/malformed/stale requests write no marker or data | MET on host: firmware test (flash counters + byte compare), stub dies if a decline changes counters, hostcheck M9a + 12/12 forged declines. |
| Successful erase removes all persistent copies, reconnects blank with fresh identity and no name; truthful completion | MET on host fakes: firmware test (all bytes 0xff, marker Clear, new id, 0 shares, no name), hostcheck M9b over pty with upstream `EraseDevice` reaching Success; app capability flipped. App-driven erase: NOT RUN. Real reset/re-enumeration: unverifiable-without-hardware. |
| `EraseConfirmed` only after durable deletion, under the original id | MET on host: cut matrix over every program/erase call; mutation killed. |
| Interruption before/after every marker write, page erase, verification, completion; no mixed signer | MET at host-fault-injection level (sub-step 1 + cut matrix here, which also requires recover -> old-whole or fresh-empty). |
| Unknown markers / flash faults bounded | MET (sub-step 1). |
| Sentinels outside region untouched; no bootloader/SE selectors | MET for FS-relative bytes in the fake; below-floor structural only. No callgate/SE code on the erase path. |
| Capability reporting reused and truthful | MET: `erase: true` via task 02's `DeviceProfile`; frostsnap lib/profile/app tests + analyze pass. |
| STM32 erase physics / secure deletion stated as not validated | MET (stated; not claimed). |

## Forbidden-shortcut audit

- No marker/data write without fresh consent: `erase()` requires `erase_asked`, set only by a
  DataErase body and cleared by ANY other body or `decline_erase`; main.rs calls it only on
  `Answer::Yes` from the question's own randomised digit (256-key test + source pins). Tests
  cover cancelled, declined, stale, malformed, never-asked.
- Interrupted erase resumes or fails closed: session poisoned before the first write
  (`ErasePending` on every later call); boot `recover` + `Session::open` guard; cut matrix.
- `EraseConfirmed` only after durable deletion: push is after `destroy` Ok; matrix + mutation.
- Sentinels / bootloader / SE: unchanged from sub-step 1; no new flash call sites outside `erase`.
- Host fault injection does not validate STM32 erase physics: not claimed anywhere.
- Global: no command claimed that did not run (app-driven erase stated NOT RUN); no SKIP counted;
  exits are the process's; no assertion deleted or relaxed — `data_erase_is_refused` and
  `refused=DataErase` were REPLACED by stronger decline/approve assertions because the specified
  behaviour changed, and the four pin counts rose because new sites were added; no
  "hardware verified" / "safe for funds" label; unit, pty-integration and app runs labelled as such.
- No physical device, serial, flashing, OTP, callgate, or network broadcast; regtest is the rig's
  own datadir; user's node PID 13555 untouched.

## Residual, bench-only / verifier judgement

- Reset may race the final USB IN transfer of EraseConfirmed; then the app dialog stays open while
  the device returns fresh. Not modelled (stub has no USB, no re-enumeration, no magic handshake).
- `system_reset` after erase and the erase screen on the real panel: not run on hardware.
- Upstream `EraseDevice::cancel` does not tell the device; the app's Cancel button does send
  `CoordinatorSendBody::Cancel`, which withdraws the question. Without it, the glass question
  stays drawn until a key: the digit then gets `Refused(DataErase)` (fail-safe) only if some other
  body arrived; otherwise the digit still erases — the verifier should judge whether a stale glass
  question with no withdrawal needs a timeout.
- RAM: seed zeroed and signer tmp/grants cleared, but main.rs's `IdentitySecret` and the signer's
  key map stay in RAM until the reset (unreachable behind the poison).
- A decline sends only `Debug{declined=DataErase}` — upstream has no refusal message.
- STM32 erase physics, torn page erases, remanence: as in sub-step 1.

## Repair — batch 1 of 1

### Finding 1 (simulator self-check required 9b refused) — FIXED
- `firmware/examples/simulator.rs:1428` — `"9b"` removed from the must-be-refused list (it is now an admitted question, sub-step 2); replaced at `:1434-1455` by a STRONGER positive check, not a relaxation: the 9b scene must exist and be shown (not refused), then main re-sends `CoordinatorSendBody::DataErase` to the real `Session` and asserts `recv` returns `Ok(no prompts)` with `erase_requested()` true, then `decline_erase()` and asserts no question remains and `device_id()` is unchanged. A DataErase that were silently accepted, refused, or that reset the device fails the self-check.
- `python3 tools/pixel-check.py` (cwd cold-snap) exit 0, "PASS: their decoder and Frame::pixel agree; all 7 caught", 0 SKIP lines. Log: target/software-only/logs/08-repair1-pixel-check.log
- `python3 tools/check-reference-contracts.py` (cwd cold-snap) exit 0, "PASS: 136 checks agree with the reference." Log: target/software-only/logs/08-repair1-refcontracts.log
- `cargo clippy --target aarch64-apple-darwin -p coldsnap_firmware --example simulator` exit 0 (no diagnostics in simulator.rs).

### Finding 2 (task-04 app integration had no erase flow) — FIXED
- cold-snap `tools/app-rig.py`: new `--erase N` flag (arg ~:432, validation ~:456, spawn ~:232) sets `STUB_ERASE_KEYS=xy` on device N (decline first erase question, approve second) and exports `COLDSNAP_RIG_ERASE`. Other devices keep the stub default `x` (refuse at glass).
- cold-snap `tools/app-rig-test.sh:49`: passes `--erase 1`.
- frostsnap `frostsnapp/integration_test/coldsnap_workflows_test.dart:1114-1230`: new last test driving the app's erase path through the real FFI coordinator (widgets not pumped; the dialog's inputs are): (1) `eraseDevice` -> device 1 declines at its glass -> app's Cancel calls (`sendCancel` + cancelProtocol); asserts no `Confirmed`, no `ERASED` in the device log, same id, name `rig-device-1`, share still in the access structure. (2) second `eraseDevice` -> `Confirmed`; asserts the device logged the deletion before the ack and rebuilt itself as a NEW id with 0 shares, no name; then the dialog's own `deleteShare` loop; access structures empty. (3) the latency the dialog waits through: old id still listed until the port drops (stub models no USB drop — stated in the test); unplug via manifest -> old id leaves the device list (the dialog's dismissal condition); replug -> the fresh id appears, name null, compatible, in no access structure; old id never returns.
- `dart analyze integration_test/coldsnap_workflows_test.dart` (cwd frostsnap/frostsnapp, pinned Flutter 3.38.5) exit 0, no issues.
- `cargo build --target aarch64-apple-darwin -p coldsnap_firmware --example stub` (cwd cold-snap) exit 0.
- `sh tools/app-rig-test.sh` (cwd cold-snap; Flutter 3.38.5 pinned, verified by the script) exit 0, "+9: All tests passed!", teardown reaped all 4 stubs, regtest down. device-1.log: "DECLINED DataErase (erase question #1) -- nothing written", "ERASED ... (erase question #2); EraseConfirmed sent under this id after deletion", "RESET after erase and rebuilt from flash as 029bfdd9...: 0 shares, no name", "REPLUG RESTART". Log: target/software-only/logs/08-repair1-app-rig.log
- Scope: this is an app integration run against the host stub over ptys with fake flash. The widget dialog is not rendered; a real USB drop is modelled by a manifest unplug. Host fault injection does not validate STM32 erase physics. Claim: software/pre-bench checks passed.

### Regression re-run
- `cargo test --target aarch64-apple-darwin -p coldsnap_hal -p coldsnap_firmware --features coldsnap_hal/fake-flash,coldsnap_hal/test-seam` (cwd cold-snap) exit 0, 551 passed / 0 failed summed over result lines. Log: target/software-only/logs/08-repair1-cargo-test.log

---

# Close-out (task 08)

## Independent re-runs (verifiers; read-only, own CARGO_TARGET_DIR where stated)

Re-runner 1 (before repair; target dir `target/software-only/verify-rerun-08/cargo`; logs `logs/08-rerun-*.log`,
`08-rerun-summary.txt`, `08-rerun-summary2.txt`). Elapsed time was not recorded per command by this re-runner.

| command | cwd | exit |
|---|---|---|
| `cargo test --target aarch64-apple-darwin -p coldsnap_hal -p coldsnap_firmware --features coldsnap_hal/fake-flash,coldsnap_hal/test-seam` | $HOME/repos/cold-snap | 0 (168/1 ign, 58, 301, 5, 19) |
| `cargo build --release` | $HOME/repos/cold-snap | 0 |
| `cargo clippy --release --target thumbv7em-none-eabihf -p coldsnap_hal -p coldsnap_firmware` | $HOME/repos/cold-snap | 0 |
| `cargo clippy --target thumbv7em-none-eabihf -p coldsnap_hal -p coldsnap_firmware` | $HOME/repos/cold-snap | 0 |
| `cargo build --target aarch64-apple-darwin -p coldsnap_firmware --example stub` | $HOME/repos/cold-snap | 0 |
| `cargo run -- <verify-rerun-08>/cargo/aarch64-apple-darwin/debug/examples/stub` | $HOME/repos/cold-snap/hostcheck | 0 (M9a, M9b PASS at chunk 64 and 1) |
| `cargo test -p frostsnap_coordinator --lib` | $HOME/repos/frostsnap | 0 (60) |
| `cargo test -p frostsnap_coordinator --test device_profile_test` | $HOME/repos/frostsnap | 0 (13) |
| `cargo test -p frostsnap_coordinator` | $HOME/repos/frostsnap | 101 BLOCKED by user's untracked tests/coldcard_msg_len.rs:97 E0308 |
| `cargo test --lib` | $HOME/repos/frostsnap/frostsnapp/rust | 0 (25) |
| `flutter --version` (pinned PATH) | $HOME/repos/frostsnap/frostsnapp | 0, 3.38.5 |
| `flutter analyze lib/device.dart integration_test/coldsnap_workflows_test.dart` | $HOME/repos/frostsnap/frostsnapp | 0 |
| `tools/app-rig-test.sh` | $HOME/repos/cold-snap | 0 (+8, before repair) |
| hostcheck vs wrapper STUB_ERASE_KEYS=yy | $HOME/repos/cold-snap/hostcheck | 1 "UNSOLICITED ERASE" |
| hostcheck vs wrapper STUB_ERASE_KEYS=xx | $HOME/repos/cold-snap/hostcheck | 1 "DEADLINE (95s) in state EraseRefusal" |
| `python3 tools/check-reference-contracts.py --json target/software-only/verify-rerun-08/refcheck.json` | $HOME/repos/cold-snap | **1** (pixel/their-decoder-agrees failed) -> CONFIRMED finding 1 |
| `python3 tools/pixel-check.py` | $HOME/repos/cold-snap | **1** simulator.rs:1429 "fixture 9b was NOT refused" -> CONFIRMED finding 1 |

Fault-path verifier (target dir `target/software-only/verify-faults/cargo`; logs `logs/08v-faults-*`):
hal `--lib erase:: -- --nocapture` exit 0 ("634 calls in one erase, 2513 restart states checked");
firmware erase tests exit 0; full test exit 0; stub build exit 0; hostcheck exit 0; process check found
only the user's PID 13555 (not touched). Elapsed not recorded.

Re-runner 2 (after repair; logs `logs/08-rerun2-*.log`, `08-rerun2-status.txt`). Elapsed not recorded
per command except where the log prints it (xx mutant: elapsed=95.0 s; app rig: 00:42 to "+9").

| command | cwd | exit |
|---|---|---|
| the six Checks commands above (test, release, 2x clippy, stub, hostcheck) | $HOME/repos/cold-snap[/hostcheck] | 0 each |
| `cargo test -p frostsnap_coordinator --lib` / `--test device_profile_test` | $HOME/repos/frostsnap | 0 (60) / 0 (13) |
| `cargo test -p frostsnap_coordinator` | $HOME/repos/frostsnap | 101 BLOCKED (user file E0308) |
| `cargo test --lib` | $HOME/repos/frostsnap/frostsnapp/rust | 0 (25) |
| `flutter --version`, `flutter analyze lib/device.dart integration_test/coldsnap_workflows_test.dart` | $HOME/repos/frostsnap/frostsnapp | 0 (3.38.5 / Dart 3.10.4), 0 |
| `python3 tools/pixel-check.py` | $HOME/repos/cold-snap | 0 "all 7 caught", 0 SKIP |
| `python3 tools/check-reference-contracts.py` | $HOME/repos/cold-snap | 0 "PASS: 136 checks" |
| `sh tools/app-rig-test.sh` | $HOME/repos/cold-snap | 0 "+9: All tests passed!" incl. erase test |
| NEG STUB_ERASE_KEYS=yy / xx wrappers | $HOME/repos/cold-snap/hostcheck | 1 "UNSOLICITED ERASE" / 1 "DEADLINE (95s) in state EraseRefusal" |
| NEG baseline unmutated rsync copy, firmware lib | target/software-only/rerun2-mutants/tree | 0 (168) |
| NEG ack pushed before begin/destroy (copy) | same | 101 "cut Some(174)/None: acked before deletion" |
| NEG erase_asked guard removed (copy) | same | 101 no_erase_without_a_live_consented_request fails |

## Files changed (final)

cold-snap: `hal/src/erase.rs` (new), `hal/src/lib.rs`, `firmware/src/lib.rs`, `firmware/src/main.rs`,
`firmware/examples/stub.rs`, `firmware/examples/simulator.rs`, `hostcheck/src/main.rs`, `tools/app-rig.py`,
`tools/app-rig-test.sh`, `README.md`, `UPGRADE-PLAN.md`, plus this evidence file and `run.json`.
frostsnap: `frostsnap_coordinator/src/device_profile.rs`, `frostsnap_coordinator/tests/device_profile_test.rs`,
`frostsnapp/rust/src/api/device_list.rs`, `frostsnapp/rust/src/coordinator.rs`, `frostsnapp/lib/device.dart`,
`frostsnapp/integration_test/coldsnap_workflows_test.dart`. Bridge bindings not regenerated (no API change).

## Acceptance criteria (final)

| # | criterion (prompt wording) | status |
|---|---|---|
| 1 | Unconfirmed, declined, and cancelled requests write no erase marker or data. | MET (host): firmware test (counters + bytes), hostcheck M9a, 12/12 forged declines, app-rig decline stage. |
| 2 | A successful erase removes all sensitive persistent copies and reconnects blank with a fresh identity. The coordinator receives a truthful completion signal. | PARTIAL. Uninterrupted path met on host (firmware test, M9b, app-rig +9 with new id / 0 shares / no name). Not met: an interrupted committed erase completed at boot sends no completion signal, so the app keeps the old share (PLAUSIBLE, untested coordinator-side). Real reset / re-enumeration: unverifiable-without-hardware. |
| 3 | Inject interruption/failure before and after every marker write, page erase, verification, and completion transition; reconstruct from bytes; no old share/nonce state can sign while incomplete. | MET at host fault-injection level (HAL matrix 634 calls / 2513 restart states; transitions enumerated by fault verifier). |
| 4 | Unknown marker formats and read/write failures have explicit bounded outcomes. | MET (Damaged -> hold; flash fault -> hold). |
| 5 | Sentinel bytes outside the permitted region remain untouched; bootloader/SE destructive selectors are never used. | MET within FLASH_FS (sentinels over full 512 K fake); below FLASH_FS structural only (FS-relative addressing, const assert); no callgate/SE/option-byte/fast_wipe on the path. |
| 6 | State clearly that host fault injection does not validate STM32 erase physics or secure deletion from a physically compromised chip. | MET (erase.rs module docs, this file). |

## Forbidden-shortcut audit

Global list: never claim a command ran that did not run — held (every run above has a log; exit codes
are the process's own); SKIP-as-pass — held (pixel-check 0 SKIP lines after repair); pipeline status —
held (`$?` of the command); historical figures as constants — none found; deleting/relaxing a failing
assertion — held (`data_erase_is_refused`, `refused=DataErase`, simulator 9b assertion REPLACED by stronger
checks after the spec changed; verifiers agreed); "hardware verified"/"safe for funds" — not used;
unit tests as integration / mocked effect as real — held (layers labelled; app rig labelled as FFI
coordinator vs stub over ptys, widgets not pumped, USB drop modelled by manifest unplug). No device,
serial, flashing, OTP, callgate or network; coldcard-firmware not written; user node PID 13555 untouched;
user files untouched.
Task list: no marker/data write without fresh consent — held; interrupted erase resumes or fails closed,
never reopens a signer on a mixture — held (recover at step 8a, Session::open guard, share-first order);
EraseConfirmed only after durable deletion — held (cut matrix + mutant killed); sentinels / no bootloader
or SE selectors — held; host fault injection not claimed to validate STM32 erase physics — held.

## CONFIRMED findings

1. Simulator self-check still required fixture 9b refused; pixel-check and task-03 reference gate exited 1.
   FIXED (simulator.rs:1428-1455, stronger positive check); re-run 2: pixel-check 0, refcheck 0 (136).
2. Task-04 app integration had no erase flow. FIXED (app-rig `--erase 1`, new Dart test); re-run 2: +9 pass.

Open PLAUSIBLE (not CONFIRMED, recorded, not fixed): stale glass erase question has no timeout and is not
withdrawn by upstream `EraseDevice::cancel`/coordinator crash; main.rs ignores `target_destinations`;
volatile secrets rely on soft reset (SRAM not cleared); consent gate is in callers not `Session::erase`;
README line contradicts itself; interrupted committed erase sends no completion (drives criterion 2
PARTIAL); reset may beat the EraseConfirmed USB transfer (write result discarded); Session-level cut
matrices inject only before-effect faults and the "malformed" leg is an Upgrade body; ack-before-deletion
mutant is caught only by the cut matrix, and the xx stub mutant only by the 95 s deadline.

## Residual bench-only questions (prompt's terms)

- STM32 erase physics: page erase torn by power loss, ECC errors on half-erased cells (incl. a torn marker
  clear leaving a finished device holding on Damaged).
- Secure deletion from a physically compromised chip.
- Real `StmFlash` erase at RDP=2 on silicon; `system_reset` after erase, USB re-enumeration and the
  handshake after reset (reconnect blank with a fresh identity on hardware); whether EraseConfirmed's
  last IN transfer survives the reset.
- Whether SRAM holding the old share/identity is cleared across the soft reset (volatile wipe).
- The erase screen on the real panel.

## Versions / backends

Flutter 3.38.5 / Dart 3.10.4 (pinned fvm SDK, confirmed by implementer, both re-runners and the rig
script). Task-04 app rig: regtest backend ran (height 101, transactions accepted by Bitcoin Core) against
`$HOME/repos/implementations/bitcoin-v31.1/build/bin/bitcoin-node` with disposable datadir
`target/software-only/app-rig/regtest`, removed at teardown.

## Blocked command

`cargo test -p frostsnap_coordinator` (cwd $HOME/repos/frostsnap) exit 101: BLOCKED by the user's untracked
`frostsnap_coordinator/tests/coldcard_msg_len.rs:97` (E0308). Not a pass, not this change's failure;
`--lib` and `--test device_profile_test` ran and passed.


## Follow-up 2026-09-24 — fix 1

The user's untracked `frostsnap_coordinator/tests/coldcard_msg_len.rs:97` E0308 (caused by frostsnap `b565de9`, `BitcoinBip32Path::external` now takes a `NormalIndex`) was fixed in place at :18 and :97. The file is still untracked and no assertion was changed. **Closed:** check 9 / "Blocked command". `cargo test -p frostsnap_coordinator` (cwd $HOME/repos/frostsnap) now exits 0, with 0 failures. **Still open:** criterion 2 partial (recover-at-boot sends no completion signal; PLAUSIBLE) and this task's other recorded items are unchanged.

Detail: `10-followup.md` § Fix 1.

## Follow-up 2026-09-24 — fix 2a

**Closed:** the PLAUSIBLE "interrupted committed erase sends no completion", which drove criterion 2 PARTIAL. On the host, boot recovery now sends `EraseConfirmed` from the original id (recorded in the marker before the commit) after it verifies the flash is blank. The coordinator claims the ack through the normal `EraseDevice` path, and the app drops the share through the dialog's `dropErasedDeviceShares`. The app rig drives this end to end for cuts before the commit, after the commit, with the ack lost in RAM, and in finish. Also closed: the normal erase's silent window (the marker was cleared before the ack was written; `finish_erase` now runs after the write) and the Session cut matrix's before-effect-only / RAM-ack weakness.
**Still open:** the real ARM boot's link-edge send of the recovered ack (`firmware/src/main.rs:2614-2616`) is covered by no test (CONFIRMED; deleting it passes every gate). PLAUSIBLE: `from` is not tied to a port; the write result is discarded; there is no timeout on the erase wait, and the dialog is not pumped; the reset may beat the USB IN transfer. Real reset / re-enumeration remains bench-only. Criterion 2 is now met on host for the stub and the coordinator. It is not shown for main.rs.

Detail: `10-followup.md` § Fix 2a (status PARTLY FIXED).


## Follow-up 2026-09-28 — fix 6

**Closed:** the CONFIRMED "real ARM boot's link-edge send of the recovered ack (`firmware/src/main.rs:2614-2616`) is covered by no test". The send is now the `send_recovered_erase_ack!` macro (lib.rs), which boot expands and the host test `the_link_edge_sends_one_recovered_erase_ack_from_the_original_id` drives. The test requires exactly one `EraseConfirmed` from the original id across two link edges after recovery. Source pins tie boot's single expansion to the link edge, before the announce, and tie `recovered_erase` to `erase::recover`'s result. Deleting the send, commenting it out or dropping the id each fails the test. The release image is byte-identical, so c86392bc is still the registered digest.
**Still open:** a `#[cfg(not(target_arch = "arm"))]` attribute on the send line still removes it with every gate green (CONFIRMED). `link.is_linked()` is not executed on the host. The fix 2a PLAUSIBLE residuals are unchanged. Criterion 2 is now tested for main.rs's send at host level. It is not hardware-verified.

Detail: `10-followup.md` § Fix 6 (status PARTLY FIXED).

## Follow-up 2026-09-29 — fix 11

**Closed:** the CONFIRMED open item from fix 6, where a `#[cfg(not(target_arch = "arm"))]` on boot's `send_recovered_erase_ack!` line removed the send with every gate green (X1). `boot` now carries `#[forbid(unused_variables)]` on its ARM cfg line, so removing the send or the link-edge `if` on ARM fails the ARM build (unused `recovered_erase`). Host-test guards reject any attribute between the link edge and the send, any attribute on the `if`, any change to the macro body, and any `cfg` in lib.rs production code. The release ELF is byte-identical, so c86392bc is still registered.
**Still open:** a cfg line in lib.rs prefixed with `/* // */` or `#[doc = "//"]` can shadow the macro or stub `recovered_erase_ack` on ARM while every gate passes (CONFIRMED, W1–W3). A cfg on a block enclosing the link-edge `if` is caught only by the ARM lint. The ARM guarantee is lint-level, not a symbol or link check. The fix 6/2a PLAUSIBLE residuals are unchanged.

Detail: `10-followup.md` § Fix 11 close-out (status PARTLY FIXED).

# 09 — Automate software-readiness checks: STATUS DEGRADED

**Status: DEGRADED.** One CONFIRMED finding is still open: the `pack-negative-bad-layout` stage
(`tools/check-software-readiness.py:293-297`) sets `expect_rc=1` and has no `must=` rule, so any exit 1
counts as a correct refusal, including a Python traceback. All five acceptance criteria are met. The verbatim full
profile exits 2, "NOT PASSED: coordinator-verbatim=blocked". It is blocked only by the user's untracked
`frostsnap_coordinator/tests/coldcard_msg_len.rs:97` (E0308). Only claim available: software/pre-bench checks
passed, scoped to the 40 stages that passed. Real installation is untested.

The close-out section is at the end. The sections below are the implementers' history, kept as written.

# 09 — Automate software-readiness checks: sub-step 1 of 2 (implementer)

Slice: the runner with full and core-only profiles, stage ordering, status capture, and
subprocess bounding and cleanup. Nothing is committed. Scope of any claim here:
software/pre-bench checks only. No device, serial/USB port, flashing, provisioning, OTP,
real callgate, public network or production wallet database was touched.

## Files changed

| file | what |
|---|---|
| cold-snap `tools/check-software-readiness.py` (new, untracked, 592 lines) | the runner. `GROUPS` :58 (prompt work item 2 order), `TESTS_RAN` :71, `PREREQS` :121, `Stage` :146, `stages()` :171 (42 stages), `_env` :342 (pinned Flutter first on PATH, `CARGO_TARGET_DIR` dropped), `_kill_group` :352, `_tree_state` :377, `run_stage` :386, `_classify` :445, `overall` :475, `identity` :503, `_snapshot_pids` :514, `write_report` :520, `run` :535, `main` :573 |
| cold-snap `tools/test-software-readiness.py` (new, untracked, 187 lines) | failure-path self-test, 48 cases against synthetic child tools |

No frostsnap file was changed. Its `git status --porcelain` hash was `a98742d4...` before and after both
full runs (the four user-work entries only). User work in both repos untouched; `tools/__pycache__/`
unchanged (a pyc my first self-test wrote was removed; the self-test now runs with bytecode off).

Generated (ignored `target/`): `target/software-readiness/{results.json,summary.md,logs/*.out|err,refcheck/,app-rig/}`,
`target/software-readiness-core/`, `target/software-readiness-selftest/`, `target/software-readiness-prerun/`
(copy of the package as it was before any run), `target/software-readiness-diag/`, and logs
`target/software-only/logs/09-{selftest,selftest2,selftest3,full-run,full-run2,core-run,checkfw-probe}.log`.

**Side effect, disclosed:** the `pack` stage writes the canonical `target/software-only/package/`
because app-rig.py:71, install-xproc.py:23 and the frostsnap `COLDSNAP_REPO` tiers hardcode that path.
The package was stale (`firmware-signed.bin` sha256 `94b89e20...`, announced digest `58f1b3fe...`,
header timestamp 2026-09-18) against the current release ELF (sha256 `28a8cc67...`). It now holds
the fresh build: `firmware-signed.bin` `d46abfa6...`, announced digest `f8d7e252...`, `.dfu` `1ecf48fb...`.
The old four files are preserved byte-for-byte in `target/software-readiness-prerun/`.

## Runner design (this slice)

- Profiles: `full` (42 stages) and `core` (23 stages: cold-snap host suites, ARM, reference, packaging,
  pixel, heap, fake-flash controller/erase; nothing that builds frostsnap). Core success label:
  "core-only software/pre-bench checks passed (scope: ...; frostsnap coordinator, registry, Flutter,
  app rig, updater and cross-process install stages NOT run)". Full success label is exactly
  "software/pre-bench checks passed". No other success label exists.
- Every stage has an explicit `cwd`, verbatim argv, timeout (`--timeout-scale` multiplies them),
  named prerequisites that are checked before it runs, and optional upstream stages (`after`).
- Status is one of passed / failed / timed_out / unavailable / blocked. Taken from the child's own
  `returncode` (no pipelines). Also:
  - `must` regexes, e.g. cargo "test result: ok. N passed" with N ≥ 1, `RESULT: ACCEPT`, and
    `[FAIL] R12 ` on the negative.
  - `skip_re`: pixel-check's exit-0 `SKIP:` counts as unavailable.
  - `rc_status`: refcheck's exit 2 counts as unavailable.
  - `expect_rc=1` for the negatives.
  - `blocked_re`: only for the verbatim coordinator command, and only when the output names
    `tests/coldcard_msg_len.rs`.
  - `stdout_in_registry`: the digest must be registered. The runner never edits the registry.
  - `tree_unchanged`: `just gen` / `build-runner` must leave the frostsnap tree hash identical.
- A missing prerequisite, or an upstream stage that did not pass, makes the stage unavailable
  without running it. No cached artifact is substituted.
- Exit codes: 0 all passed; 1 any failed or timed_out; 2 otherwise not all passed (unavailable or
  blocked); 128+sig if interrupted. A process that the run left behind (checked with a pgrep
  snapshot diff, testnet4 lines excluded) forces a nonzero exit.
- Bounding: each child is `start_new_session=True` with stdin closed. On timeout, after a normal
  exit (to catch leaked grandchildren) and on runner SIGINT/SIGTERM/SIGHUP, the whole group gets
  SIGTERM. The runner waits 30 s (app-rig's teardown needs it), then sends SIGKILL.
- `results.json` is rewritten after every stage. It holds per-stage command, cwd, prereqs, rc,
  elapsed, log paths, reason and parsed metrics, plus identity: repo HEADs, branches, dirty lists,
  and rustc/cargo/python/flutter versions. `summary.md` is a minimal table only (see "left for
  sub-step 2").

## Commands run

| # | command | cwd | exit | elapsed |
|---|---|---|---|---|
| 1 | `python3 tools/check-software-readiness.py --list` | cold-snap | 0 | <1 s |
| 2 | `python3 tools/test-software-readiness.py` | cold-snap | 0 (48/48 ok) | 57.6 s |
| 3 | `python3 tools/check-software-readiness.py --profile full --output-dir target/software-readiness` (run 1, log `09-full-run.log`) | cold-snap | **1** | ~8 min |
| 4 | `cargo run -q --release --target aarch64-apple-darwin -p coldsnap_firmware --example checkfw -- target/software-only/package/firmware-signed.bin` (verdict-format probe) | cold-snap | 0 (`RESULT: ACCEPT — 14/14`) | ~1 s |
| 5 | same as 3 (run 2, after metric/verdict regex fixes; log `09-full-run2.log`) | cold-snap | **1** | 424 s |
| 6 | `python3 tools/test-software-readiness.py` (after edits) | cold-snap | 0 (48/48) | ~50 s |
| 7 | `python3 tools/check-software-readiness.py --profile core --output-dir target/software-readiness-core` | cold-snap | **0**, core-only label | 135 s |
| 8 | diagnostic: swap in the pre-run package, `target/pack-venv/bin/python tools/install-xproc.py`, restore the fresh package | cold-snap | 0 (old artifact) | ~10 s |
| 9 | `python3 tools/test-software-readiness.py` (after `-B` / dont_write_bytecode) | cold-snap | 0 (48/48) | 47.4 s |

The prompt's Checks command (row 3/5) was run verbatim. It exits nonzero, as it must today.

### Run 1 (stale package in place)
Stage `pack` failed with rc 1. `tools/pack-signed.py:585-589` rewrote the artifacts from the current
ELF, then aborted with "output changed for the same ELF: reproducibility broken", because its
rerun check assumes the ELF has not changed. The runner then marked all 10 consumers of the package
unavailable ("upstream stage pack is failed; no cached artifact is substituted").
`coordinator-verbatim` came out blocked. The other 29 stages passed. Exit 1.

### Run 2 (stage outcomes; `target/software-readiness/results.json`)

| stage | cwd | status | rc | s |
|---|---|---|---|---|
| host-frostsnap-macros / -embedded-std / -comms / -core / frost-backup | cold-snap | passed ×5 | 0 | 0.8 / 1.6 / 2.1 / 13.6 / 2.7 |
| host-coldsnap-firmware / host-coldsnap-hal (fake-flash,test-seam) | cold-snap | passed ×2 | 0 | 1.3 / 3.7 |
| arm-clippy-dev / arm-clippy-release / arm-build-release | cold-snap | passed ×3 | 0 | 0.7 / 1.3 / 0.7 |
| refcheck (136 COVERED / 0 FAILED / 0 UNAVAILABLE, parsed) / refcheck-negatives | cold-snap | passed ×2 | 0 | 19.2 / 32.4 |
| pack / pack-tests | cold-snap | passed ×2 | 0 | 0.8 / 1.1 |
| pack-negative-bad-layout | cold-snap | passed | 1 (expected) | 0.2 |
| checkfw-bin (`ACCEPT — 14/14`, parsed) / checkfw-dfu | cold-snap | passed ×2 | 0 | 0.6 / 0.4 |
| checkfw-negative-signature (`[FAIL] R12`) / -misaligned (`[FAIL] R8`) / -family (`[FAIL] R13`) | cold-snap | passed ×3 | 1 (expected) | 0.4 / 0.5 / 0.4 |
| pixel-check (`^PASS`, no SKIP) | cold-snap | passed | 0 | 1.8 |
| heap-session: footprint 60512 B of 65536 B, 5024 B spare, FITS slack 10860 B, NULLS 0 (all parsed this run, not constants) | cold-snap | passed | 0 | 2.7 |
| stub-build | cold-snap | passed | 0 | 0.2 |
| hostcheck-tests / hostcheck-run | cold-snap/hostcheck | passed ×2 | 0 | 2.6 / 17.8 |
| **coordinator-verbatim** `cargo test --target aarch64-apple-darwin -p frostsnap_coordinator` | frostsnap | **blocked** | 101 | 4.8 |
| coordinator-scoped (excludes tofu_tests) / coordinator-doc / rust-lib-frostsnapp | frostsnap | passed ×3 | 0 | 2.7 / 1.1 / 7.2 |
| register-self-check | frostsnap | passed | 0 | 0.1 |
| **registry-matches-artifact** | frostsnap | **failed** | 0 | 0.04: announced digest `f8d7e252...` not in coldsnap-mk4-registry.txt |
| flutter-analyze / flutter-test (pinned 3.38.5, verified by prereq) | frostsnap/frostsnapp | passed ×2 | 0 | 30.5 / 3.7 |
| bridge-gen-reproducible / build-runner-reproducible (tree hash unchanged) | frostsnap | passed ×2 | 0 | 34.2 / 18.6 |
| **app-rig** | cold-snap | **failed** | 4 | 145.6: `unrecognized-f8d7e2`, so keygen was refused. Rig teardown reported "0 still alive, regtest down". |
| updater-stub-ignored / updater-lib-ignored / app-bridge-ignored | frostsnap | passed ×3 | 0 | 3.3 / 3.8 / 17.9 |
| **updater-local-artifact** | frostsnap | **failed** | 101 | 0.8: `mk4_firmware_artifacts.rs:377` asserts the package digest is registered |
| controller-erase-fake | cold-snap | passed | 0 | 10.1 |
| **install-xproc** | cold-snap | **failed** | 1 | 8.2: `firmware/src/install.rs:1944`, `Err(Gate(ImageRefused))` (see F1) |

Overall result: exit 1, "NOT PASSED: coordinator-verbatim=blocked, registry-matches-artifact=failed,
app-rig=failed, updater-local-artifact=failed, install-xproc=failed". Orphans after the run: none
(`pgrep -fl "examples/stub|app-rig.py|bitcoin-node -regtest|flutter_tools|Frostsnap.app"` exits 1).

### Core run (row 7): 23/23 passed, exit 0. Label: "core-only software/pre-bench checks passed (scope: ...NOT run)".

## Failure-path evidence (tools/test-software-readiness.py, 48/48 ok)

All synthetic, under `target/software-readiness-selftest/`. Each case checks one behaviour:

- A failing child is reported as failed with its own rc (3).
- A hung child is timed_out, and its backgrounded grandchild is dead afterwards.
- A child that ignores SIGTERM is SIGKILLed within timeout + grace.
- A child that prints `SKIP:` and exits 0 is unavailable.
- An exit-contract rc of 2 is unavailable.
- With a missing prerequisite, the stage is unavailable and its command never ran.
- If the upstream stage failed or never ran, the stage is unavailable.
- Negatives:
  - the right rc with the right rule passes;
  - the right rc with the wrong rule fails;
  - an accepted image fails.
- "0 passed" from cargo fails.
- Blocked: the E0308 text naming `coldcard_msg_len.rs` is blocked, and an unrelated rc 101 is failed.
- A passing child's leaked grandchild is killed and recorded.
- Tree check: an identical regeneration passes, and a regeneration that drifts fails.
- A registered digest passes, and an unregistered one fails.
- Through `run()`, labels and exits:
  - full all-pass gives exit 0 and exactly "software/pre-bench checks passed";
  - core all-pass gives exit 0 with a scope-naming label;
  - failed or timed_out gives exit 1 with "NOT PASSED";
  - skip or blocked gives exit 2 with "NOT PASSED".
- Group ordering and summary.md presence are checked on every run.
- Runner SIGTERMed mid-stage: exit 143, results.json says INTERRUPTED, and the child's grandchild is dead.
- **Not covered here:** stale-input detection (input hashes vs artifact). See "left for sub-step 2".

## Findings (new, reproduced this run)

- **F1 (CONFIRMED, not fixed: outside this slice and in task 07 code).** The fake gate in
  `firmware/src/install.rs` refuses a valid key-0 image whose signature has high S.
  - Cause: `verify_in_ram` (~:955) uses rust-secp256k1 `verify_ecdsa`, which rejects non-normalized
    (high-S) signatures. signit/python-ecdsa does not normalize.
  - Reproduction: the fresh package has high S and is refused by install-xproc (rc 1). The pre-run
    package has low S and passes (row 8: rc 0, "PASS: ... 58f1b3fe..."). checkfw accepts both (R12 ok).
  - Effect: task 07's xproc result held only because the artifact happened to be low-S. The fake gate
    is stricter than the tools the real key-0 path is modelled on. That the real bootloader's uECC
    accepts high S is not verified here; it is a bench/reference question.
  - The fix belongs in the test double: `normalize_s()` before verifying, or a reference-backed decision.
- **F2 (CONFIRMED, not fixed).** `tools/pack-signed.py:585-589` aborts with rc 1 whenever the previous
  artifact differs, even when the ELF changed. It has already overwritten the artifacts by then.
  The runner reports this honestly as pack=failed. After one such run, the second run passes.
- **F3 (expected, not a bug).** The fresh artifact's announced digest `f8d7e252...` is not registered.
  registry-matches-artifact, app-rig (exit 4, unrecognized) and updater-local-artifact fail as a result.
  The runner does not register it. Running task 02's `register-mk4-firmware.py <image> <label>` edits
  the tracked `frostsnap_coordinator/src/coldsnap-mk4-registry.txt`. That decision is left for sub-step 2
  or close-out.

## Acceptance criteria

| criterion | status |
|---|---|
| Full profile runs every required implemented check or exits nonzero naming the missing/failed check; core-only success labeled with scope | **met** for the runner: full exits 1 and names five stages; core exits 0 with a scope label. Full cannot be green while `coordinator-verbatim` is blocked by user work. |
| A deliberate failed / timed-out / skipped-required / stale-artifact stage cannot yield full-profile success | failed / timed-out / skipped / missing-prereq / upstream-failed / blocked: **met** (self-test). Stale-artifact: only partly met. Consumers depend on this run's `pack` stage, so a stale package is never used silently (run 1 showed it). But there is no input-hash freshness check, and no deliberate stale-input test (sub-step 2). |
| Logs and reports identify exact tested inputs | **partly met**: per-stage verbatim command, cwd, logs, repo HEADs, dirty lists and tool versions. Artifact and source hashes are not yet recorded (sub-step 2). |
| No physical probing, installation, provisioning or production wallet access | **met**: no stage opens a device path. app-rig uses its own `--dir` under target/, and regtest uses the rig's datadir. tofu_tests (public Electrum) are excluded from the scoped coordinator stage. |
| Success label is "software/pre-bench checks passed"; real installation reported untested | label **met**. The "installation untested" / bench-only statement is in the module docstring and stage titles ("mocked install", "fake gate"), not yet in summary.md (sub-step 2). |

## Forbidden-shortcut audit

- Command claimed without running it: none. Every row above ran, and the exits are real.
- Exit 0 with SKIP counted as a pass: no. pixel-check and refcheck have `skip_re`, and the self-test proves it.
- Pipeline status: none. `Popen.returncode` is used directly, and warnings are never counted.
- Hardcoded historical figures: none. Heap, refcheck and checkfw numbers are parsed each run. Nothing
  asserts 508 tests, 60,512 B, 14/14 or 136.
- Assertions relaxed or deleted: none. The failing fake-gate test and the registry assertion were left failing.
- "Hardware verified" or "safe for funds": appear only as forbidden wording in the docstring.
- Unit tests reported as integration, or mocks as real: stage titles name the fake gate / fake flash / mocked install.
- Missing prerequisite counted as success: no. It is unavailable, and the self-test proves it.
- Cached green report: every run rewrites results.json from scratch, and consumers depend on stages
  run this time. Input-hash freshness is sub-step 2.
- Core success labeled with its scope: yes.
- Bypassing task 02 registration: no. The registry was not edited and the stage fails.
- Earlier DEGRADED tasks restated as PASS: this slice's report does not mention earlier tasks'
  status at all. Carrying their open findings is sub-step 2's report work.
- User work: untouched. PID 13555 was never matched, since the pgrep snapshot excludes testnet4 and
  uses no bare-name kills.

## Left for sub-step 2 (not started here)

- Input-hash freshness:
  - ELF vs firmware sources;
  - package vs ELF + pack-signed + signit + 00.pem;
  - stub vs stub.rs;
  - refcheck identity.
- A deliberate stale-input failure-path case.
- Source/artifact hashes in results.json.
- The registration decision (F3).
- The full Markdown report:
  - image geometry;
  - heap headroom narrative;
  - protocol/app workflows;
  - upgrade/erase coverage;
  - the earlier tasks' DEGRADED open findings;
  - unexecuted checks;
  - the mocked-vs-verified distinction;
  - QEMU excluded;
  - the bench-only list.
- README section: single invocation plus prerequisites.
- The automation note: cold-snap has no CI, frostsnap's justfile is user work, and hosted CI lacks the
  sibling repos and the macOS Flutter toolchain.
- F1 and F2 dispositions.

## Residual bench-only questions (prompt's terms)

Nothing here tests any of the following. They remain untested:

- real USB enumeration and CDC timing;
- keypad timing and the SSD1306 display;
- TRNG/entropy;
- SE1/SE2 and callgate 18/0, 18/2 and 18/7 behaviour;
- OTP floor, RDP and PCROP;
- STM32 erase physics, and power loss mid-burn or mid-erase;
- PSRAM retention;
- SRAM wipe on soft reset;
- actual installation and reset;
- task 01's U1 world checksum, U2 OTP floor, U3 RDP and U4 install-path existence;
- whether the real bootloader accepts high-S key-0 signatures (F1).

Real installation is untested even though the mocked-install stages pass.

---

# Sub-step 2 (implementer): freshness, report, README, F1/F2/F3, full run

## Files changed

cold-snap (uncommitted):
- `tools/check-software-readiness.py` (new, now 765 lines):
  - freshness `_depinfo` :149, `BUILT` :157, `DECLARED` :165, `freshness` :181, gate in `run_stage` :481;
  - `consumes=` on every artifact-consuming stage;
  - `COVERAGE` :602, `UNEXECUTED` :615, `BENCH_ONLY` :623, `earlier_tasks` :633 (reads evidence/run.json as recorded), `artifacts` :642, full `write_report` :650;
  - `run(..., repos=)` :697 with run-level source-drift check :726; drift and orphans now force a `NOT PASSED` label.
- `tools/test-software-readiness.py` (new, 235 lines): 68 cases. New ones:
  - stale input :166 (fresh passes; newer input gives STALE and the stage never runs; a vanished input gives STALE; a missing artifact is unavailable; a stale run exits 1);
  - declared fixture hashed but never called fresh;
  - cargo `.d` parse with escaped spaces;
  - source drift :198 (exit 1, NOT PASSED);
  - summary content (installation untested, bench-only, not-executed, MOCKED, qemu), earlier tasks carried with their recorded status, artifacts hashed.
- `tools/pack-signed.py:486-493, 596-601` (F2): the byte-identical rerun check now runs only against an artifact made from the same inputs (ELF sha256, frozen timestamp, key). Those inputs are recorded in `firmware-signed.bin.inputs`. A new ELF replaces the artifact instead of aborting with rc 1 after it has already been overwritten.
- `tools/test-pack-signed.py:179-196`: 4 rerun cases. First pack: nothing to compare. Same inputs: byte-identical. New timestamp: rc 0. Tampered previous with the same inputs: rc 1 "reproducibility broken".
- `firmware/src/install.rs:955-961` (F1, test-only `FakeGate` in `#[cfg(test)] mod tests`): `sig.normalize_s()` before `verify_ecdsa`.
  - Why: the reference `stm32/mk4-bootloader/verify.c:232` calls `uECC_verify`, and `micro-ecc/uECC.c:1411-1420` only checks r, s in [1, n). There is no low-S rule, and `cli/signit.py:354` never normalizes.
  - New test `gate_accepts_high_s_like_uecc_and_still_refuses_a_bad_one` :1183. Mutant probe: removing the `normalize_s` line makes it fail (rc 101). The fix is not in the ARM image (cfg(test)).
- `README.md:378-418`: new "One command: software readiness" subsection covering the invocation, exit contract, prerequisites, the registration step, the BLOCKED coordinator command, and the no-hosted-CI note.

frostsnap (tracked, uncommitted), **F3 decision**: ran task 02's own `register-mk4-firmware.py` for the fresh artifact, as prompt item 6 requires after firmware changes.
- It appended `d660d179…74a0 mk4-2026-09-24` to `frostsnap_coordinator/src/coldsnap-mk4-registry.txt`.
- The old `58f1b3fe… mk4-2026-09-21` line is kept (the tool's upsert behaviour).
- The runner still never edits the registry. User dirt in frostsnap is untouched.

## Commands (sub-step 2)

| command | cwd | exit | time |
|---|---|---|---|
| `cargo test --target aarch64-apple-darwin -p coldsnap_firmware --features coldsnap_hal/fake-flash,coldsnap_hal/test-seam gate_accepts_high_s` | cold-snap | 0 (1 passed) | ~7 s |
| same, with `sig.normalize_s();` removed (mutant; source restored after) | cold-snap | 101 (FAILED as required) | ~7 s |
| `python3 -B tools/test-software-readiness.py` run 1 | cold-snap | 1 (a harness bug: interrupt case polled 10 s, but hashing the coldcard tree takes ~15.6 s; drift label began with the success phrase) | 72 s |
| `python3 -B tools/test-software-readiness.py` run 2, after the fixes | cold-snap | **0**, 68 ok, "PASS: 0 failed case(s)" | 118 s |
| `python3 -B tools/check-software-readiness.py --list` | cold-snap | 0 | <1 s |
| `cargo build --release` | cold-snap | 0 (relinked after install.rs changed) | 9 s |
| `python3 tools/pack-signed.py --pubkey-num 0 --out target/software-only/package` (1st) | cold-snap | 0, "no previous artifact from these inputs" (the F2 path; previously rc 1) | <1 s |
| same (2nd) | cold-snap | 0, "rerun: byte-identical" | 1 s |
| `python3 frostsnap_coordinator/tools/register-mk4-firmware.py "$HOME/repos/cold-snap/target/software-only/package/firmware-signed.bin" mk4-2026-09-24` | frostsnap | 0, self-check ok, registered d660d179… | <1 s |
| `python3 -B tools/check-software-readiness.py --profile full ...` (not verbatim because of `-B`; stopped with SIGTERM after ~10 s) | cold-snap | INTERRUPTED by signal 15, results.json label INTERRUPTED, no leftover process (pgrep 1) | ~10 s |
| **`python3 tools/check-software-readiness.py --profile full --output-dir target/software-readiness`** (verbatim) | cold-snap | **2**: "NOT PASSED: coordinator-verbatim=blocked" | 335 s |
| `rustfmt --edition 2021 --check firmware/src/install.rs` | cold-snap | 0 | <1 s |
| `pgrep -fl "examples/stub\|app-rig.py\|bitcoin-node -regtest\|flutter_tools\|Frostsnap.app"` after the run | — | 1 (none) | — |

Full-run outcome: 41 of 42 stages passed. The one BLOCKED stage is `coordinator-verbatim`, caused by the user's `tests/coldcard_msg_len.rs:97`.
- Previously failing, now passed: pack, registry-matches-artifact, app-rig (58 s, "All tests passed!"), updater-local-artifact, install-xproc ("PASS: updater staged 397312 B digest d660d179…; exactly one fake install request per PIN path (fake gate, not an installation)").
- The current artifact's signature is **high-S** (the old one was low-S), so install-xproc now exercises the F1 fix end to end.
- Measured this run: refcheck 136 COVERED / 0 FAILED / 0 UNAVAILABLE; checkfw ACCEPT 14/14; heap footprint 60512 B of 65536 B (5024 B spare); FITS slack 10860 B; NULLS 0. All are parsed values, not constants.
- Source drift: none. frostsnap `git status` sha256 was 283fcf97… before and after the run.
- Artifacts: all six built artifacts are "fresh" against their inputs; four declared fixtures are hashed only.
- Report paths: `target/software-readiness/results.json` and `target/software-readiness/summary.md`, logs under `target/software-readiness/logs/`. Driver log: `target/software-only/logs/09-s2-full.log`.

## Acceptance criteria (after sub-step 2)

| criterion | status |
|---|---|
| Full runs every required check or exits nonzero naming the missing/failed one; core labeled with scope | **Met.** Full exits 2 naming coordinator-verbatim=blocked. Core label names its scope (self-test). |
| Failed, timed-out, skipped-required or stale-artifact stage cannot give full success | **Met.** Every one of those has a self-test case, plus source drift and orphans. |
| Logs/reports identify exact tested inputs | **Met.** results.json holds commands, cwds, repo HEADs and dirty lists, tool versions, sha256 of each artifact and of its cargo `.d` / packager input set, declared-fixture hashes, and the start tree-state hashes. Caveat: Cargo.lock and `.cargo/config.toml` are not in the `.d` input sets (they are covered by the repo tree hash and the HEAD/dirty record). |
| No physical probing, installation, provisioning, production DB | **Met.** Virtual ptys, a regtest datadir under target/, fake gate / FakeFlash only; tofu_tests excluded. |
| Label "software/pre-bench checks passed"; real installation reported untested | **Met.** summary.md states it in the header and in the Coverage section. |

## Forbidden-shortcut audit (sub-step 2)

- Claimed commands that did not run: none. Exit codes are shown above.
- Exit-0 SKIP counted as a pass: no.
- Pipeline status: no. Every exit is `$?` of the tool itself, or `Popen.returncode`.
- Hardcoded historical figures: no.
- Failing assertion relaxed: **for the verifier.** F1 changes the fake gate to accept high-S signatures. This is justified by the reference `uECC.c:1411-1420` and `verify.c:232`, is pinned by a new test with a mutant probe, and the refusal of a bad signature is still asserted. No test assertion was removed.
- "Hardware verified" / "safe for funds": not claimed.
- Unit tests reported as integration, or mocks as real: no. The install is a fake gate and stated as such.
- Missing prerequisite reported as success: no.
- Cached green report or artifact: no. Freshness is checked against inputs, and consumers require their upstream stage to pass in this run.
- Core success unscoped: no.
- Registration bypassed: no. Task 02's tool was used, disclosed as a tracked frostsnap edit.
- Earlier DEGRADED tasks restated as PASS: no. summary.md carries run.json's status and open_confirmed items verbatim, and the self-test asserts no PASS appears.
- User work: untouched. PID 13555 never matched.

## Left for the verifier

- Whether the F1 fake-gate change (test-only) and the F2 packager change are acceptable inside task 09. Both were bugs found by this runner and are outside "own the runner".
- Whether registering `mk4-2026-09-24` (tracked frostsnap file) was the right F3 call, and whether the stale `58f1b3fe` line should remain. The unit tests read the *first* entry.
- Whether the header timestamp being the ELF mtime is acceptable: every relink changes the announced digest and needs re-registration.
- Whether 30 s SIGKILL grace and core's inclusion of reference checks are right.
- The ~15.6 s cost of hashing the coldcard-firmware tree twice per run (submodules).

## Residual bench-only questions (prompt's terms), unchanged

- Real USB enumeration and timing.
- SE calls (SE1/SE2, callgate 18/0, 18/2, 18/7).
- Entropy (TRNG).
- Flash power loss mid-burn or mid-erase, and STM32 erase physics.
- Actual installation and reset.
- Keypad and SSD1306 timing, OTP floor, RDP/PCROP, PSRAM retention, SRAM wipe on soft reset.
- Task 01's U1-U4.
- Whether the real bootloader accepts this high-S key-0 image. The reference source says yes; the bench has not confirmed it.

## Repair — batch 1 of 1

### F-blocked_re: a real coordinator failure could be labeled BLOCKED — fixed
- `tools/check-software-readiness.py:527-541`: new `ERR_LOC` regex and `_only_blocked_cause()`. A failure counts as `blocked` only if all three hold. (1) There is at least one located compile error (`error[...]: ...` followed by `--> path`) and every such path matches `blocked_re`. (2) The output has no `FAILED` and no `panicked at`. (3) There is no unlocated `error` line (for example a linker error), apart from cargo's `error: could not compile` summaries.
- `:554`: `_classify` calls it. Before, it ran `re.search(blocked_re, text)` over the whole output, and that matched cargo's `Running tests/coldcard_msg_len.rs` line.
- `tools/test-software-readiness.py:104-116,148`: the `blocked` case now uses the real rustc/cargo error shape copied from `target/software-readiness/logs/coordinator-verbatim.err`. Two new cases each resolve to `failed`: `running-line` (the Running line for the blocked file plus a real `FAILED` test in real_psbts) and `also-other` (the blocked file's E0308 plus an error in `src/lib.rs`). The old code would have labeled both cases `blocked`. The overall-exit case `b` now uses the real error shape too, and still expects exit 2.
- The real logs agree: `_only_blocked_cause` returns True for the recorded coordinator-verbatim log and False for the coordinator-scoped log.

### F-coordinator-doc: the doctest stage passed while running zero tests — fixed (stage removed)
- `tools/check-software-readiness.py:355-356`: removed the `coordinator-doc` stage and left a comment in its place. frostsnap_coordinator has 0 doctests (`test result: ok. 0 passed`), so the stage could not fail. Adding `must=[TESTS_RAN]` would have made every full run `failed` for a crate that simply has no doctests. The prompt does not require doctests. The plan is now 41 stages, not 42. Earlier text above that says "42 stages" or "41 of 42 passed" is historical and counted a stage that tested nothing.

### Commands re-run (cwd /Users/garykrause/repos/cold-snap)
- `python3 tools/test-software-readiness.py` > `target/software-only/logs/09-repair1-selftest.log`: exit 0, "PASS: 0 failed case(s)", including the two new cases.
- `python3 -B tools/check-software-readiness.py --list` > `target/software-only/logs/09-repair1-list.log`: exit 0, 41 stages, no coordinator-doc.
- Only the real `coordinator-verbatim` stage, run through `R.run()` into `target/software-readiness-repair1/` (log `target/software-only/logs/09-repair1-verbatim.log`): exit 2. The stage is `blocked`: "exit 101; every error is located in /tests/coldcard_msg_len\.rs/ (protected user work)". This is the user's file, and it is still BLOCKED, not a pass.
- No new full-profile run was made. Only the classifier and the stage list changed, and the stage that changed was checked on its own.


---

# Close-out (final)

## Status: DEGRADED
- Open CONFIRMED finding: `pack-negative-bad-layout` passes on any rc 1. It was not in repair batch 1 and is not fixed.
- Full profile: exit 2, and cannot be green while the user's file blocks `coordinator-verbatim`. That is a BLOCKED
  command, not a failure of this task.

## Every command (verbatim, cwd, exit, elapsed)

The implementers' commands are in the sub-step 1 table, the sub-step 2 table and "Repair — batch 1 of 1" above.
Summary of the ones that count:

| who | command | cwd | exit | elapsed |
|---|---|---|---|---|
| implementer s1 | `python3 tools/check-software-readiness.py --profile full --output-dir target/software-readiness` (run 1 / run 2) | $HOME/repos/cold-snap | 1 / 1 | ~8 min / 424 s |
| implementer s1 | `python3 tools/check-software-readiness.py --profile core --output-dir target/software-readiness-core` | $HOME/repos/cold-snap | 0 (core-only label; pre-sub-step-2 runner, superseded) | 135 s |
| implementer s2 | `python3 -B tools/test-software-readiness.py` | $HOME/repos/cold-snap | 0 (68 ok) | 118 s |
| implementer s2 | `python3 tools/check-software-readiness.py --profile full --output-dir target/software-readiness` | $HOME/repos/cold-snap | 2 | 335 s |
| implementer s2 | high-S test / mutant with `normalize_s` removed | $HOME/repos/cold-snap | 0 / 101 | ~7 s each |
| implementer s2 | `python3 frostsnap_coordinator/tools/register-mk4-firmware.py "$HOME/repos/cold-snap/target/software-only/package/firmware-signed.bin" mk4-2026-09-24` | $HOME/repos/frostsnap | 0 | <1 s |
| repair 1 | `python3 tools/test-software-readiness.py` | $HOME/repos/cold-snap | 0 | log 09-repair1-selftest.log |
| repair 1 | `python3 -B tools/check-software-readiness.py --list` | $HOME/repos/cold-snap | 0 (41 stages) | <1 s |
| repair 1 | coordinator-verbatim stage alone via `R.run()` into target/software-readiness-repair1/ | $HOME/repos/cold-snap | 2 (stage blocked, rc 101) | log 09-repair1-verbatim.log |
| **independent re-run 1** (verifier, pre-repair) | `python3 -B tools/test-software-readiness.py` | $HOME/repos/cold-snap | 0 (68 ok) | log 09-verify-rerun-selftest.log |
| **independent re-run 1** | `python3 tools/check-software-readiness.py --profile full --output-dir target/software-only/verify-rerun/full` | $HOME/repos/cold-snap | 2, "NOT PASSED: coordinator-verbatim=blocked" | log 09-verify-rerun-full.log |
| **independent re-run 1** | `python3 tools/check-software-readiness.py --profile core --output-dir target/software-only/verify-rerun/core` | $HOME/repos/cold-snap | 0, core-only scoped label | log 09-verify-rerun-core.log |
| **independent re-run 2** (post-repair) | `python3 tools/test-software-readiness.py` | $HOME/repos/cold-snap | 0 (70 ok, 0 FAIL) | log 09-rerun2-selftest.log |
| **independent re-run 2** (post-repair) | `python3 tools/check-software-readiness.py --profile full --output-dir target/software-readiness` | $HOME/repos/cold-snap | **2**, "NOT PASSED: coordinator-verbatim=blocked"; 40 passed, 1 blocked of 41 | 400 s (14:30:53 to 14:37:33), log 09-rerun2-full.log |
| independent re-run 2 | stage `cargo test --target aarch64-apple-darwin -p frostsnap_coordinator` | $HOME/repos/frostsnap | 101, **BLOCKED** by user file tests/coldcard_msg_len.rs:97:56 (E0308) | 5.38 s |
| independent re-run 2 | `pgrep -fl 'examples/stub\|app-rig\|regtest\|flutter_tools\|Frostsnap.app'` | - | 1 (no orphans) | - |

Per-stage times for the post-repair full run are in `target/software-readiness/results.json` (`elapsed_s`), e.g.
app-rig 94.53 s, bridge-gen-reproducible 43.65 s, flutter-analyze 36.14 s, refcheck-negatives 33.44 s.
Figures measured in that run: 136 contracts covered / 0 failed / 0 unavailable; checkfw ACCEPT 14/14; heap 60512 of
65536 B (5024 B spare); FITS slack 10860 B; NULLS 0.

## Files changed
- cold-snap: `tools/check-software-readiness.py` (new), `tools/test-software-readiness.py` (new),
  `tools/pack-signed.py` (F2), `tools/test-pack-signed.py` (F2 cases), `firmware/src/install.rs` (F1, cfg(test)
  fake gate only), `README.md` (one-command section), this evidence file, run.json.
- frostsnap: `frostsnap_coordinator/src/coldsnap-mk4-registry.txt` (+1 line `d660d179… mk4-2026-09-24`,
  written by task 02's register tool).
- Not staged, left as they are: `prompts/`, `tools/__pycache__/`, frostsnap `frostsnapp/.gitignore`,
  `frostsnapp/macos/Podfile.lock`, `justfile`, `frostsnap_coordinator/tests/coldcard_msg_len.rs`.

## Acceptance criteria (5/5 met)

| criterion | verdict |
|---|---|
| Full runs every required check or exits nonzero naming it; core-only success labeled with scope | **met**: full exits 2 naming coordinator-verbatim=blocked; core label names its scope (re-run 1) |
| Deliberate failed / timed-out / skipped-required / stale-artifact stage cannot give full success | **met** (self-test 70/70). Caveat: the open finding means a crashed packager in the bad-layout negative would count as passed. |
| Logs/reports identify exact tested inputs | **met** (HEADs, dirty lists, tool versions, artifact and input sha256s, tree hashes). Caveats: Cargo.lock and .cargo/config.toml are covered only by the tree hash; the dirty list drops the first entry's leading column (PLAUSIBLE). |
| No physical probing, installation, provisioning or production DB | **met**: ptys, regtest datadir under target/, fake gate and FakeFlash only, tofu_tests not run |
| Label "software/pre-bench checks passed"; real installation reported untested | **met** (summary.md header and Coverage section) |

## Forbidden-shortcut audit
Global list:
- Claimed-but-not-run commands: none.
- Exit 0 with SKIP counted as a pass: no (pixel-check printed a real PASS).
- Pipeline status captured instead of the process's: no.
- Historical figures used as constants: no; all figures are parsed from the run.
- Assertion deleted or relaxed: no. The F1 gate change is backed by the reference (uECC.c:1411-1420, verify.c:232), pinned by a test, and a mutant check shows the test catches its removal. The coordinator-doc stage was removed because it ran 0 tests; it was not a check that could fail.
- "Hardware verified" / "safe for funds": not claimed.
- Unit tests reported as integration, or mocks as real: no.

Task list:
- Cached green report: no (freshness gate; the post-repair full run is newer than every source).
- Core success unscoped: no.
- Registration bypassed: no (task 02's tool was used).
- Earlier DEGRADED tasks shown as PASS: no.
- A negative failing for the wrong reason counted as a pass: **violated by one stage**, pack-negative-bad-layout (the open finding).

## Findings
| finding | verdict | repaired? |
|---|---|---|
| blocked_re matched cargo's `Running tests/coldcard_msg_len.rs` line, so a real failure became BLOCKED | CONFIRMED | **fixed** (`_only_blocked_cause`; new cases running-line and also-other; re-run 2 70/70) |
| coordinator-doc passed while running 0 tests | CONFIRMED | **fixed** (stage removed; 41 stages) |
| pack-negative-bad-layout passes on any rc 1 (`_classify` returned passed for a traceback) | CONFIRMED | **open**. Fix: `must=[r'(?m)^ABORT .*would load at 0x0818']` |
| F1 fake gate refused high-S signatures | CONFIRMED (implementer) | fixed (install.rs normalize_s, cfg(test)) |
| F2 pack-signed aborted after overwriting when the ELF changed | CONFIRMED (implementer) | fixed |
| tofu_tests never compiled; install-xproc overwrites task 07's logs/07-r2; debug checkfw not freshness-checked; dirty-list strip; core report from before sub-step 2 | PLAUSIBLE | open, not blocking |

## Residual bench-only questions (prompt's terms)
The following remain bench-only: real USB enumeration, timing, SE calls, entropy, flash power loss, and actual installation.
Also open: keypad/display timing, OTP floor, RDP/PCROP, PSRAM retention, SRAM wipe on soft reset, and task 01's U1-U4.
Also open: whether the real bootloader accepts a high-S key-0 image. The reference source says yes; no bench has confirmed it.

## Toolchain and task 04 backend
- Flutter 3.38.5 / Dart 3.10.4, from the pinned `$HOME/repos/frostsnap/frostsnapp/.fvm/flutter_sdk/bin`, checked by
  the runner's prerequisite check and by both re-runners. 3.35.1 was never used.
- Task 04's app-rig stage ran the real regtest backend. `tools/regtest.py:49-50` uses
  `$HOME/repos/implementations/bitcoin-v31.1/build/bin/bitcoin-node` and `bitcoin-cli`, with a disposable datadir
  under target/. The log shows "All tests passed!" and the teardown "regtest down, 0 still alive". The user's testnet4 node
  (PID 13555) was never contacted.

# 06 — Add a Mk4-specific, port-targeted host updater — evidence

**STATUS: DEGRADED** (close-out, 2026-09-24). All 5 acceptance criteria met at pty/stub-peer scope.
Degraded because two CONFIRMED findings from the post-repair re-runner remain open (O1: the
repair-round logs live only in `/tmp`, not under ignored `target/`; O2: a nonexistent `--port`
path is reported after 30 s as a peer that never answered the handshake). Also: the verbatim Check
`cargo test --target aarch64-apple-darwin -p frostsnap_coordinator` exits 101, BLOCKED solely by
the user's untracked `frostsnap_coordinator/tests/coldcard_msg_len.rs:97:56` (E0308), which is
preserved untouched; the scoped substitute (every other target) exits 0. The only claim available
is "software/pre-bench checks passed", scoped to ptys, in-process fakes and cold-snap's stub stager.
See "Close-out" at the end. Commits: frostsnap `87733279119fa29ed9208c051d2f2acab746111a`; cold-snap = the commit adding this file.

## Sub-step 1 of 2: checked Mk4 artifact, DFU extraction, image validation

Status: slice COMPLETE. The rest of the task (transfer, port routing, recovery flow, outcomes, app wiring) is for sub-step 2.
Scope claim: software and pre-bench checks passed for this slice only. Nothing was flashed, and no serial or USB device was touched.

### Design (why the rules are ported, not imported)
- `frostsnap_coordinator` cannot depend on `coldsnap_hal`. One cargo graph cannot hold cold-snap's vendored `frostsnap_comms` together with this fork's (`cold-snap/hostcheck/Cargo.toml` records this).
- So recon Option A was taken. Each `coldsnap_hal::image::check_installable` rule is ported in the same order, followed by checkfw R2-R4, R10, R11 and R12.
- The port is BOUND to task 05's API at runtime, not assumed to match:
  - `verdicts_agree_with_coldsnap_checkfw` runs cold-snap's `checkfw` over 14 artifacts and requires the same accept/refuse verdict on each. `checkfw` R14 calls `check_installable`.
  - The 14 artifacts are the real ones, the task-05 negatives, and 8 synthetic ones. Acceptance is non-vacuous: exactly 5 are accepted.
- The digest is bound to `golden/mk4-staging-vectors.txt` (`m13-synth-262656`). The same test checks it against both lookalikes: the bootloader double hash and the ESP32 contiguous hash.
- `PUBKEY0` and the `REF_FW_CHECK`/`REF_SIG`/`REF_SIG_HIGH_S` vectors are copied from `checkfw.rs:62-96`.
  - The copy is cited in the doc comment.
  - A unit test verifies Coinkite's released 6.3.5X signature, including high-S normalization.
  - An integration test proves that the published `00.pem` scalar derives `PUBKEY0`.
- The ESP32 `FirmwareBin`/`ValidatedFirmwareBin` are unchanged. Each family refuses the other's images: `Mk4ImageError::Esp32Image`, and ESP32 `InvalidFormat`.
- The dev-key-0 signature is a FORMAT check and the digest is a transfer-integrity check. Neither establishes trust. No registry, allowlist, manifest, share proof, ratchet or OTP gate is consulted anywhere.

### Files changed (frostsnap; uncommitted)
- `frostsnap_coordinator/Cargo.toml:24-26`: `secp256k1 = "0.29"`. It is already in the lock at 0.29.1 via schnorr_fun `libsecp_compat_0_29`, so it adds no new crate.
- `Cargo.lock:1784`: the dependency edge only.
- cold-snap `hostcheck/Cargo.lock:458`: C4 added the same `secp256k1 0.29.1` edge because hostcheck path-depends on the fork's coordinator. That is the only cold-snap tracked-file change.
- `frostsnap_coordinator/src/lib.rs:10`: `pub mod mk4_firmware;`
- `frostsnap_coordinator/src/mk4_firmware.rs` (new, 601 lines):
  - `Mk4Firmware::{load, from_artifact, as_bytes, size, digest, num_chunks, container, hw_compat, version}` (`:256-323`). The image is held as an owned `Arc<[u8]>`. `load` refuses files larger than `MK4_LEN_MAX + 4096` before reading them.
  - `check_mk4_image` (`:364`) applies, in this order: magic / ESP32 named → hw_compat (0 = no constraint) → length floor → burn-window ceiling → truncated → length mismatch → 4 KiB install alignment → header rules R2, R3, R4, R10, R11 → pubkey_num == 0 → key-0 ECDSA over sha256(two-range digest) with normalize_s.
  - `extract_dfuse` (`:461`) checks, in order: the suffix (bLength/UFD/bcdDFU), the CRC, version 1, DFUImageSize == file − 16, exactly one target, `"Target"`, target size, and every element bounded.
    - It rejects an element outside `[0x08020000, +MK4_LEN_MAX)`, overlapping elements, trailing bytes, and anything that is not exactly one element at 0x08020000.
    - This is stricter than checkfw's `locate_image`.
  - `two_range_digest` (`:340`): a single sha256 over `[0,0x3fc0) ++ [0x4000,len)`.
- `frostsnap_coordinator/tests/mk4_firmware_artifacts.rs` (new, 537 lines):
  - 6 hermetic tests, which sign synthetic images with the published key 0.
  - 4 `#[ignore]` cold-snap-tier tests, which need `COLDSNAP_REPO`. They FAIL, never skip, if a fixture is missing.

### Fixtures (cold-snap, ignored `target/`)
- `target/software-only/fixtures/06/local-build/{firmware-signed.bin, coldsnap-6.0.1lb.dfu}` is a local key-0 build with version `6.0.1lb`.
  - Its image sha256 is `4b2f48e5…232dbb`.
  - Its two-range digest is absent from `coldsnap-mk4-registry.txt`, and the test asserts `registered_mk4_revision == None`.
  - It re-packs bit-identically (all four outputs shasum OK). Log: `fixtures/06/pack-local-build.log`.
- Reused from earlier tasks: `package/firmware-signed.bin`, `package/coldsnap-6.0.0cs.dfu` (task 01), `fixtures/bad-signature.bin`, `fixtures/05/{misaligned-397824.bin, wrong-family-mk5-only.bin}`.

### Commands (this session; logs in `cold-snap/target/software-only/fixtures/06/logs/`)
| # | command | cwd | exit | time |
|---|---|---|---|---|
| p1 | `target/pack-venv/bin/python3 tools/pack-signed.py --out target/software-only/fixtures/06/local-build --fw-version 6.0.1lb --epoch 1790000000` | cold-snap | 0 | 1s |
| p2 | `cargo build --target aarch64-apple-darwin -p coldsnap_firmware --example checkfw` | cold-snap | 0 | 2s |
| t1 | `cargo test --target aarch64-apple-darwin -p frostsnap_coordinator --test mk4_firmware_artifacts` (6 pass, 4 ignored) | frostsnap | 0 | 1s |
| t2 | `COLDSNAP_REPO="$HOME/repos/cold-snap" cargo test --target aarch64-apple-darwin -p frostsnap_coordinator --test mk4_firmware_artifacts -- --ignored` (4 pass) | frostsnap | 0 | 2s |
| t3 | three mutants in `mk4_firmware.rs`: overlap check → false; the 4 KiB alignment check disabled; the signature check disabled. Each was restored afterwards (cmp OK). Log: `mut.log` | frostsnap | 101 ×3 (test failures, 0 compile errors) | ~3s each |
| t4 | `cargo clippy --target aarch64-apple-darwin -p frostsnap_coordinator --lib --test mk4_firmware_artifacts` | frostsnap | 0, no warnings in the new files | 7s |
| t5 | `rustfmt --edition 2021 --check` on the two new files | frostsnap | 0 | <1s |
| C1 | `cargo test --target aarch64-apple-darwin -p frostsnap_coordinator` (VERBATIM) | frostsnap | **101** | 3s |
| C1b | the same, scoped with `--lib --test device_profile_test --test firmware_digest_test --test mk4_firmware_artifacts --test mock_port_upgrade_routing --test real_psbts --test tofu_tests` (60+13+1+6+6+5+3 pass, 6 ignored) | frostsnap | 0 | 6s |
| C1c | `cargo test ... -p frostsnap_coordinator --doc` | frostsnap | 0 | 1s |
| C2 | `cargo test --target aarch64-apple-darwin -p rust_lib_frostsnapp` (24 pass, 2 ignored) | frostsnap | 0 | 17s |
| C3 | `cargo build --target aarch64-apple-darwin -p coldsnap_firmware --example stub` | cold-snap | 0 | 0s |
| C4 | `cargo run -- ../target/aarch64-apple-darwin/debug/examples/stub` (M1-M13 PASS, M13 stager Staged 262656). `pgrep` afterwards found no stub processes left | cold-snap/hostcheck | 0 | 29s |

**C1 BLOCKED by pre-existing user work.**
- The untracked `frostsnap_coordinator/tests/coldcard_msg_len.rs:97` fails to compile (E0308). It passes a `u32` to `BitcoinBip32Path::external`, which takes a `NormalIndex`.
- The file is on the preserve-untouched list, so it was not edited.
- Every other coordinator target was run explicitly (C1b and C1c) and passes. A verifier should not read C1b as C1.
- tofu_tests (in C1b) open TLS connections to public Electrum servers. They are existing tests, run as part of the verbatim check. It is a read-only connection and no transaction was broadcast.
- Flutter/`just gen`: not run in this slice, because the app API is unchanged. Sub-step 2 must run them with the pinned SDK 3.38.5.

### Acceptance criteria (whole task; this slice's share)
| criterion | status |
|---|---|
| Real task-01 key-0 artifacts load (raw + DFU), plus a local build absent from any registry | load: MET (t2). Stage over a pty: NOT MET, sub-step 2 |
| Wrong model, malformed DFU, signature, digest and length mismatch, truncation fail explicitly | artifact side: MET (t1, t2, t3). Wrong ack and timeout: NOT MET, sub-step 2 |
| Artifact/bounds checks through direct app/CLI entry points | NOT MET. There is no CLI or app API yet (sub-step 2 must route through `Mk4Firmware`) |
| Second mock port gets zero traffic; ESP32 image not selectable for Mk4 and vice versa | cross-family refusal at the artifact layer: MET (`families_do_not_cross`). Port selection: NOT MET, sub-step 2 |
| Real cold-snap stager across processes; framing, decline and restoration interop kept | existing M13 via C4 still passes. Updater-to-stager: NOT MET, sub-step 2 |
| Staging-only peers never report installed; no orphan children or locked ports | NOT MET, sub-step 2 (C4 left no orphan stubs) |

### Forbidden-shortcut audit (this slice)
- Exactly one `0x11` per chunk, and the fix in the shared path: not touched in this slice. The log-and-continue at `usb_serial_manager.rs:778-787` is STILL PRESENT and is for sub-step 2.
- Final-chunk ack = stage verdict only: not applicable here. No outcome type exists yet.
- A staging-only peer never yields "installed": not applicable here. No such string or state exists.
- Unselected port receives zero traffic: not applicable here.
- The global rules were not violated:
  - no device was touched;
  - coldcard-firmware was only read (by pack-signed.py and dfu.py);
  - only key 0 was used;
  - no gate was added and the registry is not consulted by the loader;
  - no assertion was relaxed;
  - the failing C1 is reported as failing.

### Notes for sub-step 2 and the verifier
- Stream `Mk4Firmware::as_bytes()` and announce `PrepareUpgrade2{size(), digest()}`. Never send Legacy `PrepareUpgrade`.
- The full artifact is 97 whole chunks. Use the 262,656-byte synthetic image (M13) for the short tail. `check_mk4_image` refuses it on Alignment, so the transfer path must allow a staging-only unchecked image for that test, or test the tail at the transfer layer alone.
- `two_range_digest` panics on input shorter than 0x4000. It is only reached after the length-floor check. Do not call it directly on untrusted input.

### Residual bench-only questions (prompt's own terms)
- Whether the Mk4 bootloader accepts these key-0 images on silicon (R1-R12 are checked against checkfw, not hardware).
- The real installation-controller peer and verified reconnect (task 07).
- Real CDC timing at the framed-to-raw boundary.

## Sub-step 2 of 2: port-scoped transfer, recovery-port flow, chunk/ack, states, CLI and app wiring

Run 2026-09-24, unattended, macOS arm64. Virtual ports (ptys, in-process fakes) and cold-snap's
`firmware/examples/stub` only. No device, no USB enumeration, no flashing, no callgate. Nothing
committed. The claim is "software/pre-bench checks passed", scoped to what is listed below.

### Design
- **The peer.** cold-snap's pre-`Session` listener has no `DeviceId`, never announces, and cannot send
  `AckUpgradeMode`. Its outbound bytes are `MAGIC_REPLY` and `0x11`, nothing else. The flow is
  therefore keyed on a PORT (`UsbSerialManager::run_mk4_upgrade(port, &Mk4Firmware, on_state)`) and
  waits for no confirmation:
  - A port with any announced device is refused (`NotAnUpgradeListener`) before a byte is sent.
  - A port that is not ready gives `PortNotReady`.
  - Only `mk4_upgrade_ports()` is offered: ports that are ready and carry no announced device.
- **Admission.**
  - `PrepareUpgrade2{size, two-range digest}` and `EnterUpgradeMode` go out in ONE write, so
    coalesced admission is the normal path. The legacy `PrepareUpgrade` is never sent.
  - Then a 100 ms `READINESS_GAP`, then `FramedSerialPort::discard_input`, which drains the BufReader
    and the port so handshake residue such as a late `MAGIC_REPLY` cannot be read as chunk 0's ack.
- **One chunk rule, shared.** `mk4_upgrade::send_chunk` writes the chunk, reads EXACTLY one byte, and
  requires it to be 0x11. Failures are named `ChunkError::{WrongAck, Timeout, Disconnected}`.
  - The native ESP32 runner (`run_firmware_upgrade`) now goes through the same function. The old
    log-and-continue on a wrong ack and on an EnterUpgradeMode send failure is gone.
  - The iterator is fused, so nothing is written after a failure.
  - Progress is `(i+1)/total`, which fixes the 0/0 case for a one-chunk image.
- **Mk4 mapping of failures.**
  - A timeout at chunk 0 is `NotAdmitted`: an unsupported peer, a peer not in its listener, or a
    refused size.
  - A timeout at the last chunk is `StageNotConfirmed`: the digest verdict was withheld, so the image
    is NOT staged.
  - Anything else is `Chunk(e)`.
- **States.**
  - `Mk4UpgradeState::{Transferring, Staged, InstallRequested, VerifiedReconnect}`.
  - `is_installed()` is true only for `VerifiedReconnect`.
  - `install_requested()` is reachable only from `Staged`.
  - `reconnected()` is reachable only from `InstallRequested`, and only with the same digest.
  - `run_mk4_upgrade` can only ever return `Staged`. No path in this tree produces the later states.
- **Checked artifacts only.** The raw `stage_bytes` is crate-private. Every public entry point (the
  API, the CLI and the app) takes a `Mk4Firmware`, so the sub-step-1 checks always apply: model,
  DFU, signature, digest, length and family.
- **CLI** `coldsnap-mk4-update --port <path> <image>`:
  - It uses `ExplicitPort`, which exposes only that path and refuses to open any other.
  - The artifact is checked BEFORE the port is opened.
  - Exit codes: 0 STAGED ("staged only, NOT installed"); 1 transfer failure (named); 2 usage error
    or refused artifact; 3 the port never became ready.
  - It waits for a 1 s no-announce settle before sending.
- **App.**
  - New capability `DeviceCapabilities.host_image_update`: true only for `ColdsnapMk4`.
  - Rust side: `FfiCoordinator` has an armed slot `(port, Mk4Firmware, StreamSink<Mk4UpgradeState>)`,
    run on the poll thread. The `mk4_upgrade_ports` snapshot is refreshed after every `poll_ports`.
  - Bridge: `Coordinator.mk4UpgradePorts()` (sync), and `startMk4Upgrade(port, imagePath)` stream.
    The latter checks the image and port via `check_mk4_upgrade_request` before arming. A start
    failure goes onto the stream through `report_start_failure`, and a transfer failure arrives as
    a named stream error.
  - Dart: a "Stage firmware image" tile on the device page, gated on `capabilities.hostImageUpdate`,
    opens `lib/mk4_upgrade.dart`. That file does the file pick, then a port pick, then shows the
    state text. `Staged` reads "NOT installed".

### Files changed (frostsnap; uncommitted; user files untouched)
- M `frostsnap_coordinator/src/serial_port.rs`: `discard_input`; `ExplicitPort`.
- M `frostsnap_coordinator/src/usb_serial_manager.rs`:
  - `USB_VID`/`USB_PID` made `pub(crate)`
  - native runner switched to the shared `send_chunk`, with a fused iterator
  - new `mk4_upgrade_ports`, `run_mk4_upgrade`
- M `frostsnap_coordinator/src/lib.rs` (`pub mod mk4_upgrade`); M `src/device_profile.rs` (`host_image_update`).
- A `frostsnap_coordinator/src/mk4_upgrade.rs`: the transfer, the states and errors, and real-stager unit tests.
- A `frostsnap_coordinator/src/bin/coldsnap-mk4-update.rs` (CLI).
- A `frostsnap_coordinator/tests/mk4_updater_stub.rs`; A `tests/support/stub.rs`, `tests/support/mk4_key0.rs`
  (key-0 synth, moved out of `mk4_firmware_artifacts.rs`).
- M `frostsnap_coordinator/tests/mock_port_upgrade_routing.rs`: responders, and 9 new native and Mk4 tests.
- M `frostsnap_coordinator/tests/device_profile_test.rs`: the exhaustive capability destructure gains the new
  field, with an assertion for each family. No assertion was removed or relaxed.
- M `frostsnapp/rust/src/coordinator.rs`, `api/firmware.rs`, `api/device_list.rs`; M `frostsnapp/lib/device.dart`;
  A `frostsnapp/lib/mk4_upgrade.dart`, `frostsnapp/test/mk4_upgrade_state_text_test.dart`.
- Regenerated (gitignored) frb bindings: `frostsnapp/lib/src/rust/**`, `frostsnapp/rust/src/frb_generated.rs`,
  and the canary `frostsnapp/binding-rerun.sha256`.
- Preserved by md5 before and after `just gen`: `justfile` 06953815…, `frostsnapp/.gitignore` 60792eb6…,
  `frostsnapp/macos/Podfile.lock` 224cc411…. The untracked `tests/coldcard_msg_len.rs` was not touched.

### Commands
- Each log is at `cold-snap/target/software-only/fixtures/06/logs/substep2/C<n>.log`.
- Exit codes are the process's own; the runner is `( cd cwd && cmd ) > log; e=$?`.
- Before any Dart or Flutter command, PATH was set with
  `export PATH="$HOME/repos/frostsnap/frostsnapp/.fvm/flutter_sdk/bin:$PATH"`.
- C0 confirmed `which flutter` = `.fvm/flutter_sdk/bin/flutter`, reporting Flutter 3.38.5 and Dart 3.10.4.

| # | command | cwd | exit | time |
|---|---|---|---|---|
| C0 | `flutter --version` | ~/repos/frostsnap | 0 | 0s |
| C1 | `just gen` | ~/repos/frostsnap | 0 | 37s |
| C2 | `just build-runner` | ~/repos/frostsnap | 0 | 18s |
| C20 | `cargo test --target aarch64-apple-darwin -p frostsnap_coordinator` (VERBATIM) | ~/repos/frostsnap | **101 BLOCKED** | 1s |
| C21 | `cargo test --target aarch64-apple-darwin -p frostsnap_coordinator --lib --bins` | ~/repos/frostsnap | 0 (60 pass, 5 ignored) | 2s |
| C22 | `cargo test --target aarch64-apple-darwin -p frostsnap_coordinator --doc` | ~/repos/frostsnap | 0 (0 doctests) | 0s |
| C23 | `… -p frostsnap_coordinator --test device_profile_test` | ~/repos/frostsnap | 0 (13) | 1s |
| C6 | `… --test firmware_digest_test` | ~/repos/frostsnap | 0 (1) | 1s |
| C7 | `… --test mk4_firmware_artifacts` | ~/repos/frostsnap | 0 (6, 4 ignored) | 1s |
| C8 | `… --test mk4_updater_stub` | ~/repos/frostsnap | 0 (1, 3 ignored) | 1s |
| C9 | `… --test mock_port_upgrade_routing` | ~/repos/frostsnap | 0 (15) | 1s |
| C10 | `… --test real_psbts` | ~/repos/frostsnap | 0 (5) | 1s |
| C11 | `… --test tofu_tests` | ~/repos/frostsnap | 0 (3) | 1s |
| C12 | `cargo test --target aarch64-apple-darwin -p rust_lib_frostsnapp` (VERBATIM) | ~/repos/frostsnap | 0 (25, 3 ignored) | 11s |
| C13 | `cargo build --target aarch64-apple-darwin -p coldsnap_firmware --example stub` (VERBATIM) | ~/repos/cold-snap | 0 | 1s |
| C14 | `cargo run -- ../target/aarch64-apple-darwin/debug/examples/stub` (VERBATIM) | ~/repos/cold-snap/hostcheck | 0 (M1+M2+M3+M5+M7+M8+M9+M12+M13 PASS, M10 PASS; 0 "skip") | 24s |
| C15 | `COLDSNAP_REPO="$HOME/repos/cold-snap" cargo test --target aarch64-apple-darwin -p frostsnap_coordinator --test mk4_updater_stub -- --ignored` | ~/repos/frostsnap | 0 (3) | 2s |
| C16 | `COLDSNAP_REPO=… cargo test … -p frostsnap_coordinator --lib mk4_upgrade -- --ignored` | ~/repos/frostsnap | 0 (3) | 4s |
| C17 | `COLDSNAP_REPO=… cargo test … --test mk4_firmware_artifacts -- --ignored` | ~/repos/frostsnap | 0 (4) | 0s |
| C18 | `COLDSNAP_REPO=… cargo test … -p rust_lib_frostsnapp --lib -- --ignored` | ~/repos/frostsnap | 0 (3) | 4s |
| C19 | `flutter test` | ~/repos/frostsnap/frostsnapp | 0 (10 incl. 2 new) | 4s |
| — | `flutter analyze lib/mk4_upgrade.dart lib/device.dart test/mk4_upgrade_state_text_test.dart` | ~/repos/frostsnap/frostsnapp | 0 | 30s |
| — | `cargo clippy` on the changed coordinator/app targets | ~/repos/frostsnap | no warnings in changed files; pre-existing `uninlined_format_args` elsewhere | — |

Notes on the table:
- **C20 BLOCKED.** It fails only on the user's untracked `frostsnap_coordinator/tests/coldcard_msg_len.rs`
  (E0308, a u32 where `NormalIndex` is expected). That file is not ours and was not edited.
  C21–C23 plus C6–C11 are the scoped substitute: every other target.
- **An earlier C3 run** also failed on `device_profile_test` (E0027: the new field was not in its
  exhaustive destructure). That was fixed by extending the test (see Files), and C20 now fails only
  on the user file.
- **C4** used the invalid combination `--lib --bins --doc` (cargo refuses to mix `--doc`). It was
  replaced by C21 and C22.

Mutation checks (mock suite `--test mock_port_upgrade_routing`, source restored and confirmed identical with `cmp`):
- `send_chunk` ack check disabled: exit 101, 3 failed (native wrong-ack, Mk4 wrong-ack, extra byte).
- `discard_input` removed: exit 101, 5 failed (includes the stage-on-selected-listener test, because
  the residue byte was read as chunk 0's ack).

Orphan check after all runs: `pgrep -fl examples/stub` and `pgrep -fl coldsnap-mk4-update` both
returned nothing. Each real-stager test also asserts that the stub exited on its own, is no longer
alive (`kill -0`), and that its pty path can be reopened.

### Acceptance criteria
| criterion | status | evidence |
|---|---|---|
| Real task-01 artifacts plus the unregistered local build stage over a pty | met (stub peer) | C15: the CLI stages `package/firmware-signed.bin` (digest 58f1b3fe…) and `fixtures/06/local-build/coldsnap-6.0.1lb.dfu` (digest 249ab7db…, `registered_mk4_revision == None`); the API stages `package/coldsnap-6.0.0cs.dfu`. Each run gives 97 acks, "STAGED … NOT installed", and the stub exits on `Outcome::Staged`. |
| Named failures: wrong model, bad DFU, signature/digest/length mismatch, wrong ack, timeout, truncation | met | Artifact side: sub-step 1 plus C8 (the CLI exits 2 with REFUSED for an ESP32 image, a bad signature, a truncated file, garbage DFU and a missing file). Wire side: C9 (`WrongAck{byte}`, `Timeout` → `NotAdmitted`/`Chunk(Timeout{10})`/`StageNotConfirmed`, `Disconnected`). Real stager in C16: corrupted body → `StageNotConfirmed`, undersized → `NotAdmitted`. |
| Unselected second port receives zero bytes (framed + raw) | met | C9 `an_mk4_image_stages_on_the_selected_listener_and_nowhere_else` (an ESP32 port, an Mk4 session port and a second listener all get 0 bytes); `ports_that_are_not_upgrade_listeners_are_refused_before_any_byte`; C8: a refused artifact puts 0 bytes on the pty; `ExplicitPort` cannot open any other path. |
| ESP32 image cannot be used for Mk4 and vice versa | met | C8 and C18 (`an_esp32_image_or_a_missing_file_is_refused_before_any_port`); sub-step 1 `families_do_not_cross`; `host_image_update` is false for ESP32 (C12, C23). |
| Real stager exercised across processes; existing framing/decline/restoration interop coverage kept | met | C15, C16 (separate stub processes on ptys); C14 hostcheck M1–M13 PASS. |
| Staging-only peer never yields "installed" | met | `run_mk4_upgrade` returns only `Staged`. The state-machine test in C9, the CLI text "NOT installed" in C15, and the Dart `mk4_upgrade_state_text_test` in C19 all check this. |
| Cleanup: no orphan processes, no locked ports | met (pty scope) | Asserted in every C15/C16 test, plus the pgrep check. |
| Short final chunk / coalesced admission | met | C16 `a_short_final_chunk_stages` (262,656 B, 65 acks, real stager); every Mk4 run sends both admission frames in one write. |
| Real USB CDC, real Mk4 PSRAM, install | unverifiable-without-hardware | — |

### Forbidden-shortcut audit
- **Exactly one expected 0x11 per chunk, fixed in the shared transfer path:** held. The one function
  is `mk4_upgrade::send_chunk`, and both the ESP32 and Mk4 paths call it. (As first written the
  extra-byte test caught only a non-0x11 stray byte; a surplus 0x11 slipped through. Fixed in the
  repair round below.) The mutation check turns 3 tests red.
- **A final-chunk ack proves only its stage verdict:** held. The final ack maps to `Staged`, and the
  code says "staged only, NOT installed". `InstallRequested` is reachable only via
  `install_requested()` from `Staged`, and nothing in the tree calls it.
- **A staging-only peer never yields "installed":** held. `is_installed()` is true only for
  `VerifiedReconnect`, which is reachable only from `InstallRequested` with a matching digest.
- **An unselected port receives zero upgrade traffic, framed or raw:** held. Every write goes to the
  `io` of the named port. Announced ports are refused before any frame. The mock asserts 0 bytes on
  all the other ports.
- **General rules:**
  - no hardware and no network
  - coldcard-firmware not written
  - dev key 0 only; digests are integrity, never trust
  - no new authority, allowlist or share-proof gate
  - no assertion deleted or relaxed
  - no historical figures hardcoded (counts above come from this run's logs)
  - nothing committed or pushed

### Residual bench-only questions
- On real USB CDC, does the Mk4 listener's second `MAGIC_REPLY` or its link residue arrive after the
  100 ms gap, which would read as chunk 0's ack? On ptys the discard plus the digest backstop hold,
  and the CLI's 1 s settle covers a late re-handshake.
- The listener timeout versus the host's 5 s port timeout under real PSRAM self-test and read-back
  times. A slow digest verdict would currently surface as `StageNotConfirmed`.
- In the app, an ESP32 device that has handshaken but not yet announced is briefly listed in
  `mk4UpgradePorts()`. It would get PrepareUpgrade2/EnterUpgradeMode addressed to `All`. Is that
  harmless on real ESP32 firmware (no ack → `NotAdmitted`)? The CLI's 1 s settle avoids it; the app
  relies on the user's selection delay.
- Install (callgate 18/7), `InstallRequested` and `VerifiedReconnect` need the task-07 controller and
  a device.

## Repair round (the only one): CONFIRMED findings

### R1 — CLI refusal test did not check the reason (FIXED)
`frostsnap_coordinator/tests/mk4_updater_stub.rs:77-90`
(`the_cli_refuses_bad_artifacts_before_touching_the_port`). The three `""` needles are now the named
reasons the CLI prints (`REFUSED {path}: {e} [{e:?}]`):
- truncated file: `Truncated { header: <ok_image().len()>, file: 200000 }`. The header length comes
  from the fixture at run time, not a literal.
- garbage `.dfu` (17 bytes): `Container(TooShort(17))`
- missing file: `NotFound`
Exit code 2 and `REFUSED` are still asserted, as is zero bytes on the pty.

### R2 — surplus 0x11 could shift the final ack (FIXED, Mk4 path)
- `frostsnap_coordinator/src/serial_port.rs:167` new `pending_input()`: the BufReader fill plus
  `bytes_to_read()`. It does not read or wait.
- `frostsnap_coordinator/src/mk4_upgrade.rs:74` new `ChunkError::SurplusAck { chunk, of, pending }`
  (Display at `:93`).
- `mk4_upgrade.rs:60` new `FINAL_ACK_QUIET` = 100 ms.
- `mk4_upgrade.rs:~308-323` `stage_bytes`: after every `send_chunk` Ok, `pending_input()` must be 0,
  or the result is `SurplusAck`. On the final chunk it first sleeps `FINAL_ACK_QUIET`, so a verdict
  arriving behind a shifted ack is caught and `Staged` is not returned.
- Module doc step 3 (`:26-29`) and the `send_chunk` doc (`:118-123`) are updated to match.
- **Why the check is in `stage_bytes` and not in the shared `send_chunk`, as the finding suggested:**
  the ESP32 device protocol sends its ready byte AHEAD of each chunk. `device/src/ota.rs:464-468`
  sends 0x11 before chunk 0 and after each non-final chunk has been written to flash. So on the
  ESP32 path the next ready byte can legitimately be waiting after `send_chunk` reads one. A
  pending-input check there would race and abort healthy ESP32 upgrades. The Mk4 listener acks AFTER
  each chunk (`firmware/src/upgrade.rs` `feed`), so the strict check is sound only on the Mk4 path.
  The shared rule (one byte, must be 0x11, hard error) is unchanged and still covers both paths.
- **Known ceiling** (a `ponytail:` comment at `mk4_upgrade.rs:~57`): the window is fixed. If a
  shifted stream's real verdict arrives later than 100 ms after the final read, it is not seen. The
  common case, a surplus byte in the same write as its ack, is caught at its own chunk.
- Tests, in `frostsnap_coordinator/tests/mock_port_upgrade_routing.rs`:
  - `:863` `an_extra_byte_after_an_ack_is_caught_at_its_own_chunk`, formerly
    `..._at_the_next_chunk`. It now covers BOTH `[0x11,0x00]` and `[0x11,0x11]` at chunk 2 and
    requires `SurplusAck{chunk:2, of:total, pending:1}`, exactly 3 chunk writes, no `Staged` state,
    and zero bytes on the other ports. This is stricter than before: the old test accepted a failure
    one chunk late, and only for a non-0x11 byte.
  - `:889` new `a_late_byte_after_the_final_ack_is_not_a_stage`. The final ack is followed 30 ms
    later by an extra 0x11 from another thread. It requires `SurplusAck{chunk: total-1}` and no
    `Staged`.

### Repair commands (real exit codes; logs in /tmp/r06_*.log)
| id | command | cwd | exit |
|---|---|---|---|
| R-C1 | `cargo test --target aarch64-apple-darwin -p frostsnap_coordinator --lib --bins --test device_profile_test --test firmware_digest_test --test mk4_firmware_artifacts --test mk4_updater_stub --test mock_port_upgrade_routing --test real_psbts --test tofu_tests` (every target except the user's untracked `coldcard_msg_len`) | ~/repos/frostsnap | 0 (lib 60/5 ignored; mock 16; mk4_updater_stub 1 + 3 ignored) |
| R-C1v | `cargo test --target aarch64-apple-darwin -p frostsnap_coordinator` (VERBATIM) | ~/repos/frostsnap | **101 BLOCKED**, only on the user's `tests/coldcard_msg_len.rs:97` E0308 (pre-existing, not touched) |
| R-C13 | `cargo build --target aarch64-apple-darwin -p coldsnap_firmware --example stub` | ~/repos/cold-snap | 0 |
| R-C15 | `COLDSNAP_REPO="$HOME/repos/cold-snap" cargo test --target aarch64-apple-darwin -p frostsnap_coordinator --test mk4_updater_stub -- --ignored` | ~/repos/frostsnap | 0 (3: the real stager stages with the quiet window in place) |
| R-C16 | `COLDSNAP_REPO=… cargo test … -p frostsnap_coordinator --lib mk4_upgrade -- --ignored` | ~/repos/frostsnap | 0 (3: short final chunk stages, corrupted body never staged, undersized not admitted) |
| R-C17 | `COLDSNAP_REPO=… cargo test … --test mk4_firmware_artifacts -- --ignored` | ~/repos/frostsnap | 0 (4) |
| R-C12 | `cargo test --target aarch64-apple-darwin -p rust_lib_frostsnapp` | ~/repos/frostsnap | 0 (25, 3 ignored) |
| R-C18 | `COLDSNAP_REPO=… cargo test … -p rust_lib_frostsnapp --lib -- --ignored` | ~/repos/frostsnap | 0 (3) |
| R-M | mutant: `pending_input` result ignored (`_ => Ok(())`), then `--test mock_port_upgrade_routing` | ~/repos/frostsnap | 101: both new/strengthened tests FAILED. Source restored, `cmp` identical, re-run 0 (16) |
| R-clippy | `cargo clippy --target aarch64-apple-darwin -p frostsnap_coordinator --lib --bins --test mock_port_upgrade_routing --test mk4_updater_stub` | ~/repos/frostsnap | 0; 0 diagnostics in the changed files |
| R-orphans | `pgrep -fl examples/stub`, `pgrep -fl coldsnap-mk4-update` | — | both empty |

Not re-run, because nothing they cover changed: hostcheck C14 (no cold-snap source was touched) and
Flutter C19 (no app API or Dart change, so no bridge regeneration). No Flutter or Dart command ran
in this round.

## Close-out (2026-09-24)

### Independent re-runs (labelled by who ran them)
**Re-runner A (verifier 1, PRE-repair tree; logs `cold-snap/target/software-only/rerun-06/R*.log`).**
Elapsed = cargo "finished in" from the logs where cargo prints it; otherwise not recorded.
| id | command | cwd | exit | time |
|---|---|---|---|---|
| F0 | `flutter --version` (pinned PATH) -> 3.38.5 / Dart 3.10.4 | ~/repos/frostsnap | 0 | n/r |
| G1 | `just gen` (x2) | ~/repos/frostsnap | 0 | n/r |
| G2 | `just build-runner` (x2) | ~/repos/frostsnap | 0 | n/r |
| C1 | `cargo test --target aarch64-apple-darwin -p frostsnap_coordinator` (VERBATIM) | ~/repos/frostsnap | 101 BLOCKED (E0308 user file only) | n/r |
| C1a | `... -p frostsnap_coordinator --lib --bins` | ~/repos/frostsnap | 0 (60/5 ign) | 0.68s |
| C1b | `... --doc` | ~/repos/frostsnap | 0 | 0.00s |
| C1c | `... --test` device_profile_test / firmware_digest_test / mk4_firmware_artifacts / mk4_updater_stub / mock_port_upgrade_routing / real_psbts / tofu_tests | ~/repos/frostsnap | 0 each (13; 1; 6+4 ign; 1+3 ign; 15; 5; 3) | 0.01-0.93s each |
| C2 | `cargo test --target aarch64-apple-darwin -p rust_lib_frostsnapp` | ~/repos/frostsnap | 0 (25/3 ign) | 0.27s (+2.00s build) |
| C3 / C3b | `cargo build --target aarch64-apple-darwin -p coldsnap_firmware --example stub` / `--example checkfw` | ~/repos/cold-snap | 0 / 0 | 0.55s / 0.16s |
| C4 | `cargo run -- ../target/aarch64-apple-darwin/debug/examples/stub` | ~/repos/cold-snap/hostcheck | 0 (M1-M13 PASS, 0 skip) | n/r |
| I1-I4 | `COLDSNAP_REPO="$HOME/repos/cold-snap" cargo test ...` `--test mk4_updater_stub -- --ignored` / `--lib mk4_upgrade -- --ignored` / `--test mk4_firmware_artifacts -- --ignored` / `-p rust_lib_frostsnapp --lib -- --ignored` | ~/repos/frostsnap | 0 each (3/3/4/3) | 1.89s / 3.25s / 0.55s / 3.17s |
| F1 | `flutter test` (pinned) | ~/repos/frostsnap/frostsnapp | 0 (10) | n/r |
| F2 | `flutter analyze lib/mk4_upgrade.dart lib/device.dart test/mk4_upgrade_state_text_test.dart` | ~/repos/frostsnap/frostsnapp | 0 | n/r |
| N1-N7 | `coldsnap-mk4-update --port /dev/nonexistent <bad artifact>` (truncated, garbage .dfu, ESP32 image, sig flip, body flip, +4096 B, missing) | ~/repos/frostsnap | 2 each, REFUSED with named reason | n/r |
| N8 | same, valid image, port never answers | ~/repos/frostsnap | 3 | ~30s |

**Re-runner B (verifier 3, POST-repair tree).** Every Check reproduced: verbatim coordinator 101
(E0308 user file only); every other coordinator target 0 (lib 60/5 ign, device_profile 13,
firmware_digest 1, mk4_firmware_artifacts 6/4 ign, mk4_updater_stub 1/3 ign,
mock_port_upgrade_routing 16, real_psbts 5, tofu 3); `--doc` 0; rust_lib_frostsnapp 0 (25/3 ign);
stub + checkfw build 0; hostcheck 0 (M1-M13, 0 SKIP); ignored tiers 3/3/4/3 all 0; `flutter test` 0
(10); `flutter analyze` (changed files) 0; clippy 0, no diagnostics in changed files. CLI negatives
(cwd ~/repos/cold-snap, fixtures `fixtures/05/*` and `target/rr06/*`): misaligned -> 2
`Image(Alignment(397824))`; wrong family -> 2 `Image(WrongFamily(32))`; truncated -> 2
`Truncated{header:397312,file:200000}`; sig byte -> 2 `Image(BadSignature)`; ESP32 -> 2
`Image(Esp32Image)`; truncated DFU -> 2 `Container(Suffix)`; bad CRC -> 2 `Container(Crc{..})`; no
args -> 2 usage; valid DFU + `--port /nonexistent/pty` -> 3 after 30 s. pgrep empty. Elapsed times
and log paths were not recorded by this re-runner (its fixtures are in `cold-snap/target/rr06/`).

**Close-out re-run (this agent, POST-repair tree, final state being committed).** Output was read
directly, not saved; elapsed is wall-clock seconds from `date +%s`.
| command | cwd | exit | time |
|---|---|---|---|
| `cargo test --target aarch64-apple-darwin -p frostsnap_coordinator` (VERBATIM) | ~/repos/frostsnap | **101 BLOCKED**: only error `E0308 --> frostsnap_coordinator/tests/coldcard_msg_len.rs:97:56` (test "coldcard_msg_len") | 1s |
| `cargo test --target aarch64-apple-darwin -p frostsnap_coordinator --lib --bins --test device_profile_test --test firmware_digest_test --test mk4_firmware_artifacts --test mk4_updater_stub --test mock_port_upgrade_routing --test real_psbts --test tofu_tests` | ~/repos/frostsnap | 0 (60/5 ign, 0, 13, 1, 6/4 ign, 1/3 ign, 16, 5, 3) | 4s |
| `cargo test --target aarch64-apple-darwin -p rust_lib_frostsnapp` | ~/repos/frostsnap | 0 (25/3 ign) | 1s |
| `cargo build --target aarch64-apple-darwin -p coldsnap_firmware --example stub` | ~/repos/cold-snap | 0 | 0s |
| `cargo run -- ../target/aarch64-apple-darwin/debug/examples/stub` | ~/repos/cold-snap/hostcheck | 0 ("M1+M2+M3+M5+M7+M8+M9+M12+M13 PASS", M10/M11 PASS) | 17s |
| `COLDSNAP_REPO="$HOME/repos/cold-snap" cargo test --target aarch64-apple-darwin -p frostsnap_coordinator --test mk4_updater_stub -- --ignored` | ~/repos/frostsnap | 0 (3) | 2s |
| `COLDSNAP_REPO="$HOME/repos/cold-snap" cargo test --target aarch64-apple-darwin -p frostsnap_coordinator --lib mk4_upgrade -- --ignored` | ~/repos/frostsnap | 0 (3) | 3s |
| `COLDSNAP_REPO="$HOME/repos/cold-snap" cargo test --target aarch64-apple-darwin -p frostsnap_coordinator --test mk4_firmware_artifacts -- --ignored` | ~/repos/frostsnap | 0 (4) | 1s |
| `COLDSNAP_REPO="$HOME/repos/cold-snap" cargo test --target aarch64-apple-darwin -p rust_lib_frostsnapp --lib -- --ignored` | ~/repos/frostsnap | 0 (3) | 2s |
| `flutter --version` (PATH=`$HOME/repos/frostsnap/frostsnapp/.fvm/flutter_sdk/bin:$PATH`) | ~/repos/frostsnap/frostsnapp | 0: Flutter 3.38.5, Dart 3.10.4 | 1s |
| `flutter test` (same PATH) | ~/repos/frostsnap/frostsnapp | 0 ("+10: All tests passed!", 0 lines matching skip) | 3s |
| `pgrep -fl examples/stub`; `pgrep -fl coldsnap-mk4-update` | — | both empty | — |

### Toolchain actually used
- Flutter 3.38.5 / Dart 3.10.4 from the pinned `frostsnapp/.fvm/flutter_sdk` for every Flutter/Dart
  command (implementer C0-C2, C19; re-runners; close-out). The system 3.35.1 was never used.
- Regtest / bitcoin-node: not applicable to task 06 (it is task 04's concern); no node was started.
  A user-owned testnet4 `bitcoin-node` (PID 13555) seen by re-runner A was left alone.

### Files changed (committed)
- frostsnap: `Cargo.lock`, `frostsnap_coordinator/Cargo.toml`, `frostsnap_coordinator/src/{device_profile.rs, lib.rs, serial_port.rs, usb_serial_manager.rs, mk4_firmware.rs (new), mk4_upgrade.rs (new), bin/coldsnap-mk4-update.rs (new)}`, `frostsnap_coordinator/tests/{device_profile_test.rs, mock_port_upgrade_routing.rs, mk4_firmware_artifacts.rs (new), mk4_updater_stub.rs (new), support/mk4_key0.rs (new), support/stub.rs (new)}`, `frostsnapp/rust/src/{coordinator.rs, api/firmware.rs, api/device_list.rs}`, `frostsnapp/lib/{device.dart, mk4_upgrade.dart (new)}`, `frostsnapp/test/mk4_upgrade_state_text_test.dart (new)`.
- frostsnap, regenerated but NOT committed: frb bindings (`frostsnapp/lib/src/rust/**`, `rust/src/frb_generated.rs`, `binding-rerun.sha256`) are gitignored by `frostsnapp/.gitignore`.
- frostsnap, NOT staged (user work): `frostsnapp/.gitignore`, `frostsnapp/macos/Podfile.lock`, `justfile`, `frostsnap_coordinator/tests/coldcard_msg_len.rs`.
- cold-snap: `hostcheck/Cargo.lock` (the `secp256k1 0.29.1` edge, caused by this task's coordinator dependency), this evidence file, `run.json`. Not staged: `prompts/`, `tools/__pycache__/`.

### Acceptance criteria (prompt's five, final)
| # | criterion (prompt wording) | status | evidence |
|---|---|---|---|
| 1 | Real task-01 key-0-signed Mk4 artifacts load and stage over a pty, including a local build whose digest is absent from any release registry | met (pty, stub peer) | C15 / I1 / close-out: raw, DFU and unregistered 6.0.1lb DFU stage, 97 acks, "NOT installed" |
| 2 | Wrong model, malformed DFU, signature/digest/length mismatch, wrong ack, timeout, and truncation fail explicitly; checks also apply through direct app/CLI entry points | met | mock suite (16) exact variants; CLI negatives N1-N8 and re-runner B, named reasons; R1 makes the CLI test assert them; app `check_mk4_upgrade_request` (C18) |
| 3 | A second mock port receives zero upgrade traffic when not selected; ESP32 image cannot be selected for a Mk4 profile or vice versa | met | mock routing tests assert 0 bytes framed+raw; `ExplicitPort`; `families_do_not_cross`; `host_image_update` false for ESP32. Residual: unannounced-ESP32 window (PLAUSIBLE P1) |
| 4 | Real cold-snap stager exercised across processes; framing, decline, restoration interop kept | met | I1/I2 separate stub processes; hostcheck M1-M13 PASS |
| 5 | Staging-only peers never produce "installed"; no orphan child processes or locked virtual ports | met (pty scope) | `run_mk4_upgrade` returns only `Staged`; SurplusAck guard; per-test pid/pty reopen assertions; pgrep empty |
| — | Real USB CDC timing, real Mk4 PSRAM, install and verified reconnect | unverifiable-without-hardware | — |

### Forbidden-shortcut audit (final)
Global, by name:
- Never claim a command ran that did not run: held (every row above has a real exit; unrecorded times marked n/r).
- Exit 0 with SKIP is not a pass: held (hostcheck and flutter test: 0 skip lines; ignored tiers fail rather than skip without fixtures).
- Capture the process's status, not a pipeline's: held (runner `( cd cwd && cmd ) > log; e=$?`).
- Historical figures not hardcoded: held (R1 truncation needle reads the header length from the fixture).
- No deleted/relaxed assertion: held (device_profile_test gains assertions; extra-byte test made stricter).
- No "hardware verified"/"safe for funds": held.
- Unit tests not reported as integration; mocks not reported as real: held (mock suite and real-stager tier reported separately; install states are unverifiable).
Task 06, by name:
- Exactly one expected 0x11 per chunk, fixed in the shared path: held. `send_chunk` shared by ESP32 and Mk4; log-and-continue removed; surplus 0x11 now caught on the Mk4 path (R2).
- A final-chunk ack proves only its stage verdict: held (`Staged` only; `FINAL_ACK_QUIET` guard against a shifted ack; 100 ms ceiling documented).
- A staging-only peer never yields "installed": held for every code path. Caveat (PLAUSIBLE P3): `VerifiedReconnect` is publicly constructible; the earlier "reachable only from InstallRequested" wording is true only of the helpers.
- Unselected port receives zero upgrade traffic, framed and raw: held in tests; P1 residual below.

### Findings
CONFIRMED:
| id | finding | repair |
|---|---|---|
| R1 | CLI refusal test used `""` needles for truncated / malformed DFU / missing file (verifiers 1 and 2) | FIXED (named reasons asserted; re-runner B and close-out re-ran 0) |
| R2 | `send_chunk` path accepted a surplus 0x11, so a shifted ack could be taken as the final stage verdict (verifier 2) | FIXED on the Mk4 path (`SurplusAck`, `FINAL_ACK_QUIET`); mutant turns both tests red. Ceiling: a verdict later than 100 ms after the final read is not seen |
| O1 | Repair-round logs written to `/tmp/r06_*.log`, not under ignored `target/` (verifier 3) | OPEN (still present in /tmp at close-out; close-out was scoped to the evidence file and run.json only; every command they cover was independently re-run above) |
| O2 | `--port` path that does not exist is reported after 30 s as "never answered the handshake", not as an open failure (verifier 3) | OPEN (fails closed, no bytes sent; misleading diagnosis only) |

PLAUSIBLE (not confirmed, not counted against status): P1 Rust API can send Mk4 admission frames + chunk 0 to a handshaken-but-unannounced ESP32 port (CLI 1 s settle mitigates; app does not); P2 task-05 rules are ported, bound to `hal/src/image.rs` only by an `#[ignore]` checkfw agreement test; P3 `VerifiedReconnect` publicly constructible; P4 Dart dialog may stay in running state if the frb stream is not closed on sink drop.

### Residual bench-only questions (prompt's own terms)
- Do real task-01 key-0-signed Mk4 artifacts stage — and later install — on a real Mk4 over real USB CDC, not a pty? (bootloader acceptance on silicon is unverified)
- The framed-to-raw boundary and "documented peer readiness" on real hardware: does a late `MAGIC_REPLY` or link residue arrive after the 100 ms gap and read as chunk 0's ack?
- Real PSRAM self-test and read-back time versus the 5 s port timeout (a slow digest verdict would surface as `StageNotConfirmed`).
- "Report installation success only after the expected new firmware reconnects": `InstallRequested` and `VerifiedReconnect` need task 07's installation-controller peer and, for real installation, a device.
- Whether an ESP32 that has handshaken but not announced is harmed by, or ignores, Mk4 `PrepareUpgrade2`/`EnterUpgradeMode` sent during that window.

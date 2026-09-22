# 02 — Recognize cold-snap and isolate firmware-upgrade targets

## STATUS: DEGRADED

Set by the close-out agent, 2026-09-22, from the evidence below rather than from
optimism. Acceptance criteria: **5 met of 5**, none unverifiable-without-hardware
(the prompt assigns the executed-app confirmation of criterion 1 to task 04, not
here). All nine of the first verification round's CONFIRMED findings are fixed and
two of those fixes are mutation-verified. The second verification round, which ran
*after* the repair, left two CONFIRMED and two PLAUSIBLE findings; one CONFIRMED
one I measured closed at close-out, and **one remains open**:

> **Open CONFIRMED finding.** `hostcheck/Cargo.toml:59` is a path dependency on the
> writable sibling checkout (`../../frostsnap/frostsnap_coordinator`) and records no
> revision, so cold-snap's committed `hostcheck/src/main.rs` — which now names
> `DeviceProfile` at `:848,:1051,:1059,:2055,:2069,:2676,:2696` and
> `needs_legacy_check_backup` at `:1059,:2069,:2699` — cannot compile against
> frostsnap's HEAD. Verified at close-out: `git show
> HEAD:frostsnap_coordinator/src/device_profile.rs` in `~/repos/frostsnap` exits
> **128**; the file does not exist at that commit. Mitigated, not fixed: this
> close-out lands both repos in the same step, so the two commits are consistent
> with each other. The coupling itself is unpinned and unfixed, and close-out may
> not edit source. Breaks no acceptance criterion.

Scope of the claim: **software/pre-bench checks passed**, unit- and analyzer-level.
No device, serial port, USB enumeration, flashing, provisioning, OTP write, real
callgate invocation or network broadcast was involved at any point. Not hardware
verified. Not safe for funds. The real-app virtual-device integration run is task
04's and has not been done.

Flutter/Dart actually used: **Flutter 3.38.5 • Dart 3.10.4 • DevTools 2.51.1**,
revision `f6ff1529fd`, from the pinned SDK at
`$HOME/repos/frostsnap/frostsnapp/.fvm/flutter_sdk` (`frostsnapp/.fvmrc` pins
3.38.5). The system `flutter` on PATH is 3.35.1 and was never used by any agent in
any round; every Flutter/Dart command was preceded by
`export PATH="$HOME/repos/frostsnap/frostsnapp/.fvm/flutter_sdk/bin:$PATH"` and the
version re-confirmed. Regtest backend: **not applicable to this task** — task 02
needs no Bitcoin node, none was started, and no `bitcoin-node` / `bitcoin-cli`
binary was invoked. (That column belongs to task 04.)

Sections in this file, in order: sub-step 1 (Rust), sub-step 2 (Flutter/Dart),
repair round, and **Close-out** at the end — which carries the re-runner's
independent re-run, the close-out's own re-run, the consolidated criteria table,
the consolidated finding ledger and the consolidated bench-only list.

---

Task prompt: `/Users/garykrause/repos/cold-snap/prompts/software-only/02-recognize-coldsnap-in-app.md`
Agent: implementer, **sub-step 1 of 2** — the Rust slice (compatibility / capability /
profile model, and port-scoped routing isolation). The Dart/Flutter UI slice is
sub-step 2 and is **not** done here.
Date: 2026-09-22. Branch `software-only/run-2026-09-21` in both writable repos.

## Scope boundary, stated up front

Everything below is enforced in Rust. **No Dart under `frostsnapp/lib/` was
changed**, deliberately: the frb surface additions are purely additive, so every
existing Dart call site still compiles (`flutter analyze` exit 0, `flutter test`
exit 0) and the UI agent can wire the new API up without first repairing a broken
tree. The consequence is that the *user-visible* half of acceptance criterion 1
(the name field on `wallet_create.dart:661-704`, which is structurally gated on the
`upToDate` branch) is **still open** — see the criteria table.

## Commands run, verbatim, with cwd and real exit codes

Exit codes captured from the process (`$status` after the command, never from a
pipeline). Every Flutter/Dart command ran with the pinned SDK first on PATH:
`export PATH="$HOME/repos/frostsnap/frostsnapp/.fvm/flutter_sdk/bin:$PATH"`.

### SDK confirmation (before anything else)

| command | cwd | exit | elapsed | result |
|---|---|---|---|---|
| `which flutter dart` | `~/repos/frostsnap` | 0 | <1 s | both `…/frostsnapp/.fvm/flutter_sdk/bin/` |
| `flutter --version` | `~/repos/frostsnap` | 0 | ~3 s | **Flutter 3.38.5 • Dart 3.10.4 • DevTools 2.51.1**, revision `f6ff1529fd` |

The system `flutter` (3.35.1) was never used.

### The prompt's Checks block, verbatim

| command | cwd | exit | elapsed | note |
|---|---|---|---|---|
| `just gen` | `~/repos/frostsnap` | **0** | 39 s | frb codegen 2.11.1, then rewrote `frostsnapp/binding-rerun.sha256` |
| `just build-runner` | `~/repos/frostsnap` | **0** | 19 s | 24 outputs, freezed unions regenerated |
| `cargo test --target aarch64-apple-darwin -p frostsnap_coordinator` | `~/repos/frostsnap` | **101** | 5 s | **FAILS, PRE-EXISTING, NOT MINE** — see below |
| `cargo test --target aarch64-apple-darwin -p rust_lib_frostsnapp` | `~/repos/frostsnap` | **0** | 10 s | 18 passed, 0 failed (10 pre-existing + 8 new) |

#### BLOCKED: the verbatim `-p frostsnap_coordinator` command exits 101

Cause, exactly: `frostsnap_coordinator/tests/coldcard_msg_len.rs:97` calls
`BitcoinBip32Path::external(i as u32)` while `frostsnap_core/src/tweak.rs:148`
declares `pub fn external(index: NormalIndex)`.

That file is **pre-existing uncommitted USER WORK** (`?? frostsnap_coordinator/tests/coldcard_msg_len.rs`,
named in this run's protected list) and `frostsnap_core/src/tweak.rs` is **clean at
HEAD** (`git diff --quiet HEAD -- frostsnap_core/src/tweak.rs` → exit 0; last commit
`523038f`). Neither side of the type mismatch appears in my diff
(`git diff --stat` shows no `frostsnap_core` change), so the test target cannot
compile at HEAD either. I did not touch it, did not format it, and did not relax
it. It is the only failing target.

Coverage of the rest of that package, same options minus the user's test target:

| command | cwd | exit | elapsed |
|---|---|---|---|
| `cargo test --target aarch64-apple-darwin -p frostsnap_coordinator --lib --test device_profile_test --test mock_port_upgrade_routing --test firmware_digest_test --test real_psbts --test tofu_tests` | `~/repos/frostsnap` | **0** | 2 s |

Results: lib 58 passed / 2 ignored; `device_profile_test` **10 passed**;
`mock_port_upgrade_routing` **6 passed**; `firmware_digest_test` 1 passed;
`real_psbts` 5 passed; `tofu_tests` 3 passed.

### Flutter tests and analysis, from `frostsnapp/`

| command | cwd | exit | elapsed |
|---|---|---|---|
| `flutter analyze` | `~/repos/frostsnap/frostsnapp` | **0** | 15 s — "No issues found!" |
| `flutter test` | `~/repos/frostsnap/frostsnapp` | **0** | 4 s — 5 passed (`wallet_create_duplicate_name_test.dart`) |

No new Dart test was added: I changed no Dart. The Dart-side tests belong to
sub-step 2.

### Code generation is reproducible

`frostsnapp/lib/src/rust/*` is gitignored (`frostsnapp/.gitignore:52`), so `git
status` cannot show it. Demonstrated by checksum instead: 33 generated files, hashed,
then `just gen` + `just build-runner` again, then hashed again.

| command | cwd | exit |
|---|---|---|
| `find lib/src/rust -type f \| sort \| xargs shasum -a 256 > /tmp/g1.txt` | `~/repos/frostsnap/frostsnapp` | 0 |
| `just gen` (second run) | `~/repos/frostsnap` | 0 |
| `just build-runner` (second run) | `~/repos/frostsnap` | 0 |
| `diff /tmp/g1.txt /tmp/g4.txt` | `~/repos/frostsnap/frostsnapp` | **0 (identical)** |

Run three times in total across the session; byte-identical each time.

Proof the new API actually crossed the bridge (generated Dart, not hand-edited):
`frostsnapp/lib/src/rust/api/device_list.dart:37` `firmwareName()`, `:48`
`isCompatible()`, plus `capabilities()` and `profile()`;
`frostsnapp/lib/src/rust/api/firmware.dart:13` `class DeviceCapabilities`, `:53`
`sealed class DeviceProfile` with `esp32Frostsnap` / `coldsnapMk4` /
`unrecognized`, `:65` `enum FactoryAttestation { unsupported, notChecked }`.
`keygen_ceiling` was correctly skipped as non-`pub` (stated in the generated
header comment).

### Digest provenance

| command | cwd | exit |
|---|---|---|
| `python3 tools/register-mk4-firmware.py --self-check` | `~/repos/frostsnap/frostsnap_coordinator` | 0 |
| `python3 tools/register-mk4-firmware.py --print /Users/garykrause/repos/cold-snap/target/software-only/package/firmware-signed.bin` | `~/repos/frostsnap/frostsnap_coordinator` | 0 |
| `python3 tools/register-mk4-firmware.py …/firmware-signed.bin mk4-2026-09-21` (idempotence) | `~/repos/frostsnap/frostsnap_coordinator` | 0 |

- self-check reproduces the golden vector `m13-synth-262656` →
  `33b54101f5ab06c1db9f6a968b4687114926ccac1a5054821e8bbf6e1ab19489`, matching
  `cold-snap/golden/mk4-staging-vectors.txt:49` column 3.
- The real wave-1 artifact (`target/software-only/package/firmware-signed.bin`,
  397,312 B, header `firmware_length = 397312`) →
  **announced `58f1b3fe4cd2df9e38b93dda2a1224c8d7652ef89e0c10d38d5a46f04e39f441`**.
  Cross-checked with an independent one-off `python3 -c` over the same file:
  same value, and its `sha256(announced)` is
  `5d899ca040912f873e285704bf6110ca8fea4c8f4916e38fd8a8e8dfb75f21d3`, which equals
  the `fw_check` recorded in `01-repair-firmware-packaging.md:317`.
- The two confusables are recorded and NOT registered: whole-file / ESP32
  contiguous-prefix `94b89e20b5c68a0cb9c12e4201874ef6a3c0b1a643fddd618ba5ec7f0faef2bc`,
  bootloader double hash `5d899ca0…`.
- Re-running the registration with the same digest and label leaves the file
  byte-identical (sha256 `8bff12c1…` before and after), so the command is
  repeatable rather than append-only.

### Formatting and lint (not in the Checks block; run to avoid leaving mess)

| command | cwd | result |
|---|---|---|
| `rustfmt --edition 2021 --check <my 12 files>` | `~/repos/frostsnap` | exit 0, empty output |
| `cargo clippy -p frostsnap_coordinator -p rust_lib_frostsnapp --tests` | `~/repos/frostsnap` | **CORRECTED IN THE REPAIR ROUND — this cell held a judgement where every other row holds a status. Real exit: 101**, on the same pre-existing `coldcard_msg_len.rs` E0308 as the test run. 58 `uninlined_format_args` warnings across the workspace, of which 7 are in files this task edited (`frostsnap_coordinator/src/firmware.rs:28,31,180,183,190`, `frostsnapp/rust/src/coordinator.rs:1022,1499` at post-repair line numbers) — all on pre-existing lines outside every edited hunk, checked against `git diff -U0` hunk headers. See "Repair round" below for the re-run. |
| `rustfmt --edition 2021 --check hostcheck/src/main.rs` | `~/repos/cold-snap/hostcheck` | exit 1 — **28 pre-existing** hunks, none in my edited regions (lines ~1030-1060, ~2030-2070, 1624, 3135, 3282). Left alone. |
| `cargo check --target aarch64-apple-darwin` | `~/repos/cold-snap/hostcheck` | **0**, no warnings |
| `cargo test --target aarch64-apple-darwin` | `~/repos/cold-snap/hostcheck` | **0**, 1 passed (`golden_vector_agrees_with_m13s_own_digest`) |

`just lint-ordinary` (`cargo clippy --all-features --tests --bins -- -Dwarnings`) is
**already red before this change**, on pre-existing `uninlined_format_args` in
`macros/src/lib.rs:451`, `frost_backup/src/share_backup.rs:284,289` and
`frost_backup/src/error.rs:33` — crates I did not touch. Not fixed here; not mine.

### Mutation verification of the routing claim

The claim "ESP32 upgrade bytes never reach an Mk4 port" is only worth its test if
the test would notice. Both gates were temporarily removed (`upgrade_ports`
reduced to "every ready port", and the capability loop short-circuited with
`.take(0)`), the suite re-run, and the file restored from a copy:

```
test a_chain_carrying_an_unselected_device_is_not_streamed_to ... FAILED
test streaming_to_an_mk4_is_refused_by_the_manager ... FAILED
test an_esp32_upgrade_never_reaches_an_mk4_port ... FAILED
test result: FAILED. 3 passed; 3 failed
```

Exactly the three routing tests redden; the three non-routing tests stay green.
Restored file re-verified: 6 passed.

## Files changed

### `~/repos/frostsnap` (writable, primary)

New:
- `frostsnap_coordinator/src/device_profile.rs` — `DeviceProfile` (`Esp32Frostsnap { release }` / `ColdsnapMk4 { revision }` / `Unrecognized`), `DeviceCapabilities`, `FactoryAttestation`, `registered_mk4_revision`, registry parser + 2 self-tests.
- `frostsnap_coordinator/src/coldsnap-mk4-registry.txt` — the registry data, one entry (`58f1b3fe… mk4-2026-09-21`), with the "compatibility, not permission" header.
- `frostsnap_coordinator/tools/register-mk4-firmware.py` — the repeatable registration/update command, with `--self-check` against the golden vector.
- `frostsnap_coordinator/tests/device_profile_test.rs` — 10 tests.
- `frostsnap_coordinator/tests/mock_port_upgrade_routing.rs` — 6 tests + the in-memory fake `Serial`.

Edited:
- `frostsnap_coordinator/src/lib.rs:3` module, `:27-31` re-exports (`DeviceCapabilities`, `DeviceProfile`, `FactoryAttestation`, `FirmwareFeatures`).
- `frostsnap_coordinator/src/firmware.rs:19-26` — **`FirmwareVersion::features()` DELETED**, replaced by a comment saying why; `:43-57` registered-Mk4 refusal added to `check_upgrade_eligibility`; `:62-68` the `(None, None) => CanUpgrade` arm documented as the retained dev affordance and its residual.
- `frostsnap_coordinator/src/firmware_upgrade.rs:25-33` device-set contract on `new`; `:131-141` profile-based legacy selection; `:156-167` `Destination::All` → `Destination::Particular(self.devices.keys())`.
- `frostsnap_coordinator/src/check_backup.rs:1`, `:43-50` — `new` takes `DeviceProfile` instead of `FirmwareVersion`.
- `frostsnap_coordinator/src/usb_serial_manager.rs:661-680` new `upgrade_ports()` (fn at `:669`); `:686-745` `run_firmware_upgrade(&BTreeSet<DeviceId>)` with the capability gate, port filter, empty-selection error and port-scoped `total_chunks`; `:730-737` `EnterUpgradeMode` comment; `:859-864` `UsbSender::erase_all` → `erase_devices(BTreeSet<DeviceId>)`.
- `frostsnapp/rust/src/api/device_list.rs:4` import; `:66-108` `profile()` (`:72`), `is_compatible()`, `capabilities()`, `firmware_name()`, redefined `ready()`; `:157-172` `keygen_ceiling()` (fn at `:162`); `:204` `mod test` — 8 unit tests.
- `frostsnapp/rust/src/api/firmware.rs:5-7` re-exports; `:88-117` mirrors for `DeviceProfile`, `DeviceCapabilities`, `FirmwareFeatures`, `FactoryAttestation`.
- `frostsnapp/rust/src/api/coordinator.rs:279-285` `erase_device` returns `Result<()>`.
- `frostsnapp/rust/src/coordinator.rs:60-63` field + `:77-78` `ArmedFirmwareUpgrade` type; `:150-156` poll thread passes the device set; `:389-423` keygen compatibility + ceiling refusals (`keygen_ceiling` call at `:414`); `:595-614` new `esp32_upgrade_devices()`; `:618-665` `begin_upgrade_firmware` filters; `:704-714` `enter_firmware_upgrade_mode` computes and stores the set; `:1071-1105` `erase_device` capability refusal and `erase_all_devices` filtering; `:1233` check-backup passes a profile.

### `~/repos/cold-snap` (writable, reference)

- `hostcheck/src/main.rs:845` import; `:1029-1050` `CHECK_BACKUP_SINCE` doc rewritten (const kept, now `#[allow(dead_code)]`); `:2032-2075` declares `DeviceProfile::ColdsnapMk4` and asserts `features().check_backup` before building the driver; `:1624`, `:3135`, `:3282` comment updates.
  **Why this repo was touched at all:** `hostcheck/Cargo.toml:59` depends on
  `../../frostsnap/frostsnap_coordinator` — the writable checkout, not the vendored
  copy — so deleting `FirmwareVersion::features()` broke it. Fixing my own
  breakage; it compiles and its test passes. It declares the **Mk4** profile, not
  an ESP32 version, precisely because an ESP32 identity would be the forbidden
  shortcut.
- `target/software-only/evidence/02-recognize-coldsnap-in-app.md` — this file.

Untouched user work, verified by `git status --short` at the end:
frostsnap ` M frostsnapp/.gitignore`, ` M frostsnapp/macos/Podfile.lock`, ` M justfile`,
`?? frostsnap_coordinator/tests/coldcard_msg_len.rs`; cold-snap `?? prompts/`,
` M target/software-only/evidence/run.json`.

## The model, in its own terms

Three separate answers where there was one:

1. **Protocol compatibility** — `DeviceProfile::identify(announced_digest, bundled)`.
   Order: known ESP32 release (`VersionNumber::from_digest`) → registered Mk4
   (`coldsnap-mk4-registry.txt`) → byte equality with the app's own bundled
   development image → `Unrecognized`. Nothing falls through to a compatible
   answer.
2. **Supported operations** — `DeviceProfile::capabilities() -> DeviceCapabilities
   { features, backup, erase, update_mode, factory_attestation, max_keygen_devices }`.
   Mk4 values and their source, each cited in the code: `erase: false`
   (`Refusal::DataErase`, cold-snap `firmware/src/lib.rs:1071`), `update_mode: false`
   (`Refusal::FirmwareUpgrade`, `:1070`), `factory_attestation: Unsupported`
   (`Refusal::GenuineChallenge`, `:184-187,1072`), `backup: true` and
   `features.check_backup: true` (`DisplayBackup`, the restore flow and
   `CheckBackup` all admitted, `:1136,1184,1239`), `max_keygen_devices: Some(12)`
   (declared envelope; the device's own half is `MAX_PARTIES = 12` at `:291`).
3. **Update availability** — `FirmwareUpgradeEligibility`, shape unchanged, now with
   a registered-Mk4 refusal so an ESP32 image is never offered to an Mk4.

`FactoryAttestation` has **two** variants and no success one: `Unsupported` and
`NotChecked`. Nothing in the tree produces a pass (`DO_GENUINE_CHECK = false`,
`usb_serial_manager.rs:10`), so a pass is not expressible in Rust or in the
generated Dart.

Routing isolation, both sites:
- `firmware_upgrade.rs` `poll()` — the `PrepareUpgrade`/`PrepareUpgrade2` message is
  `Destination::Particular(selected devices)`. Native chain forwarding is preserved
  because `Destination::remove_from_recipients` / `should_forward`
  (`frostsnap_comms/src/lib.rs:143-155`) forward while the set is non-empty.
- `usb_serial_manager.rs` `run_firmware_upgrade(&BTreeSet<DeviceId>)` — a
  capability gate refusing any *recognized* profile without `update_mode`, then a
  port filter that only admits a port whose every known device was selected
  (a chain is all-or-nothing, because the raw chunk stream has no addressing), then
  an error if that leaves nothing. `total_chunks` and the progress denominator
  follow the filtered port count.
- One place decides the set: `FfiCoordinator::esp32_upgrade_devices()`, used by both
  `begin_upgrade_firmware` and `enter_firmware_upgrade_mode`.

## Acceptance criteria

| # | criterion | verdict | basis |
|---|---|---|---|
| 1 | Known Mk4 firmware can be named and included in wallet creation without an ESP32 digest match or a bundled Mk4 image; unrecognized firmware remains explicit | **PARTIAL — Rust met, UI open** | Rust: `a_recognized_mk4_is_ready_with_no_bundled_firmware`, `a_registered_mk4_is_compatible_without_any_bundled_image`, `unrecognized_firmware_is_not_compatible`; `ready()` and `is_compatible()` are true for a registered Mk4 with `latest_firmware: None`, and `firmware_name()` is `mk4 <revision>`. **NOT met in the app:** `frostsnapp/lib/wallet_create.dart:661-704` still renders the name field only on the `upToDate` branch and `canGoNext` (`:342-352`) still blocks on `devicesIncompatible`, which a Mk4 still trips because its *update availability* is `CannotUpgrade`. Sub-step 2 must switch those call sites to `isCompatible()`. |
| 2 | Native Frostsnap readiness and updates retain their existing supported behavior | **met, with two deliberate changes named below** | `a_known_esp32_release_is_compatible_with_no_bundled_firmware`, `the_exact_bundled_development_image_is_recognized`, `the_bundled_esp32_image_is_ready`, `legacy_protocol_selection_follows_the_selected_devices`, `every_selected_esp32_port_is_still_streamed_to`, `a_released_esp32_digest_keeps_its_version`; pre-existing `firmware_digest_test` still green. |
| 3 | Mock-port tests prove ESP32 upgrade traffic never reaches Mk4/unselected ports, and the protocol does not wait for their acknowledgements | **met (unit-level)** | `mock_port_upgrade_routing.rs`: 6 tests over the real `UsbSerialManager` and a fake `Serial`; byte counts on an unselected port asserted `== 0`. Ack half: `the_protocol_waits_for_an_ack_from_every_device_in_its_set` and `an_mk4_left_in_the_upgrade_set_aborts_instead_of_hanging`. Mutation-verified above. |
| 4 | Unsupported erase/attestation/update actions have clear API/UI outcomes | **PARTIAL — API met, UI open** | API: `erase_device` returns `Err("mk4 … does not support erasing device data from the app")`; `erase_all_devices` sends `Destination::Particular(erase-capable)`; `run_firmware_upgrade` refuses an Mk4 by name; `capabilities().factory_attestation == Unsupported` with no pass variant. `capability_differences_are_on_the_api`, `streaming_to_an_mk4_is_refused_by_the_manager`. **UI:** no Dart renders any of it yet. |
| 5 | Tests cover no bundled firmware, unsupported firmware, capability differences, mixed ports, and rejection of an over-limit keygen before starting it | **met for four; the fifth is met at the decision point, not end-to-end** | no bundled firmware → `a_recognized_mk4_is_ready_with_no_bundled_firmware`, `a_known_esp32_release_is_compatible_with_no_bundled_firmware`; unsupported → `unrecognized_firmware_is_not_compatible`, `an_unknown_digest_claims_no_feature_and_no_capability`; capability differences → `mk4_and_esp32_capabilities_differ`, `capability_differences_are_on_the_api`; mixed ports → `a_chain_carrying_an_unselected_device_is_not_streamed_to`, `an_esp32_upgrade_never_reaches_an_mk4_port`; over-limit keygen → `the_keygen_ceiling_comes_from_the_participating_firmware` tests `keygen_ceiling()`, the function `generate_new_key` consults *before* `BeginKeygen::new`. ~~**The `generate_new_key` refusal itself is not unit-tested** — it needs a `FfiCoordinator` with a sqlite DB and a populated device list, which is an integration fixture this task has no harness for.~~ **CLOSED IN THE REPAIR ROUND**: the refusal was extracted verbatim into `api::device_list::check_keygen_group`, which `generate_new_key` now calls and which two tests drive directly. No fixture needed. |

### The two deliberate behaviour changes under criterion 2

1. `ConnectedDevice::ready()` no longer requires `firmware_is_up_to_date()`. With
   **no** bundled firmware (which the user's `justfile` `run` recipe opts into), a
   *known-release* ESP32 previously reported `CannotUpgrade{"No firmware available
   in app"}` and so was never ready; it is now compatible and ready. This is the
   separation criterion 2 of the prompt's Work items asks for. `ready()` has zero
   Dart callers today, so nothing in the shipped UI changes because of it.
2. ~~An **unrecognized** device in the upgrade set now selects the *legacy*
   `PrepareUpgrade` message where it previously selected `PrepareUpgrade2`, because
   an unrecognized profile claims no feature. For an unsigned development bundle
   `digest_with_signature == digest`, so the bytes carried are identical and only
   the variant differs; both are handled by every device that handles either.~~
   **WITHDRAWN AND FIXED IN THE REPAIR ROUND.** This scoped itself to an unsigned
   bundle, where the two digests coincide. The default `just run` path bundles a
   **signed** image (`justfile:187-197` → `build-firmware-signed`;
   `frostsnapp/rust/build.rs:26-28` asserts it), and there
   `digest_with_signature != digest` — pinned by `firmware_digest_test.rs:17-20`.
   `device/src/ota.rs:61-68` accepts **only** the body digest, so on the default
   path this was not a variant rename but every device refusing the image. Fixed:
   message selection is now opt-in by positive identification
   (`DeviceProfile::needs_legacy_upgrade_message`). See "Repair round".

## Audit against each forbidden shortcut, by name

Global:
- *Never claim a command ran that did not run; paste real exit codes.* Every exit
  code above is a `$status` read after the process, not from a pipeline. The one
  failure (101) is reported as a failure.
- *Exit 0 with SKIP is not a pass.* No check here emits SKIP. `tools/pixel-check.py`
  was not run or cited.
- *Capture the process's status, never a filtering pipeline's.* Redone deliberately:
  an early `time cargo test … | grep | tail` reported `exit=0` for a run that in
  fact exited 101, so every exit code in this file was re-measured with output to a
  file and `echo "EXIT=$status"`.
- *Historical figures are reproduction clues, never current evidence.* The only
  historical number used as a constant is the golden vector `33b54101…`, which is a
  *pinned test vector in a file both consumers read*, cited as such. 397,312 B and
  the `58f1b3fe…` digest were **measured** from the artifact this session. `12` is a
  declared capability with its source cited, not a measured result; I make no claim
  to have measured a 12-device keygen. No 379,876/379,880, no 508 tests, no 60,512.
- *Never delete or relax a failing assertion.* Nothing deleted. `FirmwareVersion::features()`
  was removed because it *was* the fail-open the prompt forbids inheriting; the
  assertion count went up. The pre-existing incompatible-device abort in
  `FirmwareUpgradeProtocol::new` was kept and is now covered by a test.
- *No "hardware verified" / "safe for funds".* Claim made: **software/pre-bench
  checks passed, unit-level, no device involved**.
- *Unit tests are never reported as an integration run.* Stated in
  `mock_port_upgrade_routing.rs`'s own module docs and again here: no device, no
  port, no USB. Task 04 supplies the virtual-device integration run.

Task-specific:
- *No `FirmwareFeatures::all()` fallback for an unknown digest.* Met by deletion:
  `FirmwareVersion::features()` no longer exists, and `DeviceProfile::features()`
  answers `FirmwareFeatures::default()` (all false) for `Unrecognized`. Pinned by
  `an_unknown_digest_claims_no_feature_and_no_capability`, which asserts both
  `== default()` and `!= all()`. `all()` survives in exactly one arm — the app's
  **own byte-identical bundled image** — which is a decision about our build, not a
  fallback for an unknown digest.
- *No ESP32 release identity assigned to a Mk4 to satisfy a version comparison.*
  `ColdsnapMk4` carries a `revision: String` and no `VersionNumber`; there is no
  code path that constructs `Esp32Frostsnap` for a registered Mk4 digest
  (`registered_digests_identify_as_mk4` pins this over the whole registry). The one
  place that *did* declare an ESP32 version for a cold-snap device —
  `hostcheck`'s `Phase::Quiz` — was changed to declare the Mk4 profile.
- *No fake attestation success.* `FactoryAttestation` has no success variant in
  Rust or in the generated Dart (`enum FactoryAttestation { unsupported, notChecked }`).
  Mk4 is `Unsupported`; ESP32 is `NotChecked`, which is explicitly not a pass.
- *Capability refusals enforced in the Rust API, not the UI alone.* `erase_device`,
  `erase_all_devices`, `generate_new_key`, `begin_upgrade_firmware`,
  `enter_firmware_upgrade_mode` and `run_firmware_upgrade` each refuse on their own;
  `run_firmware_upgrade` is the last gate before the raw bytes, and it refuses there
  too. No Dart was changed, so no refusal in this task exists only in the UI.
- *Do not hand-edit generated bindings.* `just gen` + `just build-runner` only, run
  three times; the output is byte-identical across runs. `frb_generated.rs` and
  `lib/src/rust/*` were never opened for editing.
- *Do not link cold-snap's vendored Frostsnap crates into the coordinator graph.*
  No `Cargo.toml` was touched in either repo. `hostcheck` still depends on the
  upstream path (`hostcheck/Cargo.toml:59`) and nothing from
  `cold-snap/vendor/` or `coldsnap_hal` entered the frostsnap graph.

Prompt "do not" sentences:
- *"This registry describes compatibility, not permission to install an image."*
  The registry is read in exactly three places — `DeviceProfile::identify`,
  `check_upgrade_eligibility`'s Mk4 refusal, and tests. It is never consulted before
  installing anything (nothing in this diff installs anything), it gates no
  signature check, and both the file header and the tool's docstring say so.
  `ValidatedFirmwareBin::new`'s `UnknownSignedFirmware` gate was not touched.
- *"Keep registration outside the image whose digest is being registered."* The
  registry lives in `frostsnap_coordinator/src/`; the Mk4 image contains nothing
  about it.
- *"Unknown digests must not become compatible automatically."*
  `Unrecognized.is_compatible() == false`.
- *"Avoid assigning cold-snap an ESP32 release identity just to satisfy a version
  comparison."* See above.
- *"A self-reported digest identifies compatibility, not authenticated hardware."*
  Stated in the module docs, the registry header and the tool docstring; enforced by
  `FactoryAttestation` having no pass.

## Residual questions, bench-only, in the prompt's own terms

1. **Criterion 1's app-side half.** The naming flow has never been driven by the
   released app — only by `firmware/src/lib.rs` unit tests, and
   `firmware/src/lib.rs:1895-1903` says so in the device's own comment. This task
   makes it *expressible* in Rust; whether the row renders and the name commits is
   task 04's virtual-device run against the real app, after sub-step 2 rewires
   `wallet_create.dart`. A test that has never run is not evidence.
2. **"A connected Mk4 must neither receive ESP32 bytes nor be awaited."** Proven
   against a fake `Serial` whose ports are `Vec<u8>`. Not proven is that a real
   `UsbSerialManager` over a real pty/USB behaves the same under timing: a real port
   that never answers is *evicted* after the 5 s read timeout
   (`usb_serial_manager.rs:302-311`), which the fake does not model. Bench only.
3. **The 13-device refusal.** 13-of-13 `CertifyPlease` ≈ 3,091 B **fits** the 4,096-byte
   frame, so no wire or transport error will ever produce the rejection — it is a
   coordinator-side policy check against a declared capability, and the device's own
   half is a refusal that is "an ack that does not arrive". A real coordinator's
   reaction to a device's `Refusal::GroupTooLarge` at n=13 remains unmeasured; so
   does an end-to-end run at n=12.
4. **`update_mode` for an unregistered Mk4.** An Mk4 whose digest is *not* in the
   registry is wire-indistinguishable from an ESP32 development build (the only
   magic-bytes-time discriminator is `DeviceSupportedFeatures { conch_enabled }`), so
   on a development app it still lands in the `(None, None) => CanUpgrade` arm and
   `run_firmware_upgrade` will not refuse it. Registering it is the remedy and the
   documented one; the alternative — refusing every unknown digest — would break the
   native development upgrade path, which criterion 2 protects. Recorded as an
   accepted limit of digest-only identification, not as a closed hole.
5. **Mk4 `upgrade_digest_no_sig: true`.** Unreachable for that profile
   (`update_mode: false` means the flag is never consulted), set so a stray Mk4
   cannot drag ESP32 peers onto the legacy message. If a Mk4 updater ever arrives,
   this value needs measuring rather than inheriting.
6. **`erase_all_devices` with mixed hardware.** Now addressed to the erase-capable
   subset. Whether a daisy-chained Mk4 downstream of an addressed ESP32 forwards the
   `DataErase` cleanly and drops it is device behaviour, unexercised here.
7. **The evil-maid hole is not closed.** Nothing in this diff touches it. Key 0's
   private key is published, so a key-0 signature is a format check and not an
   authorisation check; the registry does not change that in either direction.

## Claim

**Software/pre-bench checks passed**, scoped to: the Rust compatibility/capability
model, its frb surface, and port-scoped upgrade routing, verified by 24 new unit
tests (10 + 6 in `frostsnap_coordinator`, 8 in `rust_lib_frostsnapp`), a pinned
bridge regeneration, `flutter analyze` and the existing Dart test. No device was
involved. The Dart/UI slice and the real-app integration run are not done.

---

# Sub-step 2 of 2 — the bridge and app (Flutter/Dart) slice

Appended by the sub-step-2 implementer. Sub-step 1 (above) landed the Rust
compatibility/capability model, its frb mirrors and port-scoped routing, and closed
its own report with "The Dart/UI slice and the real-app integration run are not
done." This section is that Dart/UI slice. The integration run remains task 04's.

No Rust file was touched in this sub-step. The bridge was regenerated with the
repository's own recipes only; no generated file was hand-edited.

## Pinned SDK confirmation (before any Flutter/Dart command)

```sh
export PATH="$HOME/repos/frostsnap/frostsnapp/.fvm/flutter_sdk/bin:$PATH"
which flutter dart
flutter --version
```
cwd `~/repos/frostsnap`, exit **0**, ~3 s. Observed:

```
/Users/garykrause/repos/frostsnap/frostsnapp/.fvm/flutter_sdk/bin/flutter
/Users/garykrause/repos/frostsnap/frostsnapp/.fvm/flutter_sdk/bin/dart
Flutter 3.38.5 • channel stable • revision f6ff1529fd
Tools • Dart 3.10.4 • DevTools 2.51.1
```
3.38.5 / Dart 3.10.4, matching `frostsnapp/.fvmrc`. The system 3.35.1 was never
used and no result below comes from it. This export prefixed every Flutter/Dart
command in this section.

## Checks block, verbatim, with real exit codes

Exit codes are the process's own `$?`, captured with output redirected to a file —
never a pipeline's status. The two runs whose output was piped to `tail` are marked,
and their real status was re-captured by re-running unpiped.

| # | command | cwd | exit | elapsed |
|---|---|---|---|---|
| 1 | `flutter --version` | `~/repos/frostsnap` | **0** | ~3 s |
| 2 | `just gen` | `~/repos/frostsnap` | **0** | 44.3 s |
| 3 | `just build-runner` | `~/repos/frostsnap` | **0** | 18.8 s |
| 4 | `cargo test --target aarch64-apple-darwin -p frostsnap_coordinator` | `~/repos/frostsnap` | **101 — BLOCKED, pre-existing** | 2.6 s (compile abort) |
| 5 | `cargo test --target aarch64-apple-darwin -p frostsnap_coordinator --lib --test device_profile_test --test mock_port_upgrade_routing --test firmware_digest_test --test real_psbts --test tofu_tests` | `~/repos/frostsnap` | **0** | 3.0 s |
| 6 | `cargo test --target aarch64-apple-darwin -p rust_lib_frostsnapp` | `~/repos/frostsnap` | **0** | 5.3 s |
| 7 | `flutter analyze` (1st, pre-fix) | `~/repos/frostsnap/frostsnapp` | **1** | 22.4 s |
| 8 | `flutter analyze` (after adding the missing import) | `~/repos/frostsnap/frostsnapp` | **0** | 8.8 s |
| 9 | `flutter test` | `~/repos/frostsnap/frostsnapp` | **0** | 2.9 s |
| 10 | `dart format --set-exit-if-changed --output=none $(find ./lib ./test -type f -name "*.dart" -not -path "./lib/src/rust/*" -not -name "*.freezed.dart")` (1st) | `~/repos/frostsnap/frostsnapp` | **1** | 0.3 s |
| 11 | `dart format --output=write ./lib/wallet_create.dart ./lib/device.dart` then re-check | `~/repos/frostsnap/frostsnapp` | **0** | 0.3 s |
| 12 | `just gen` (reproducibility re-run) | `~/repos/frostsnap` | **0** | ~40 s |
| 13 | `just build-runner` (reproducibility re-run) | `~/repos/frostsnap` | **0** | ~13 s |
| 14 | `diff` of 32 generated-Dart-file sha256s, before vs after 12+13 | `~/repos/frostsnap/frostsnapp` | **0 — identical** | <1 s |
| 15 | `flutter analyze` (final, post-format, post-hoist) | `~/repos/frostsnap/frostsnapp` | **0** | 4.5 s |
| 16 | `flutter test` (final) | `~/repos/frostsnap/frostsnapp` | **0** | ~3 s |

Counts from the runs above:

- #5: `58 passed; 0 failed; 2 ignored` (lib) + `10` (`device_profile_test`) + `1`
  (`firmware_digest_test`) + `6` (`mock_port_upgrade_routing`) + `5` (`real_psbts`)
  + `3` (`tofu_tests`). All `test result: ok`.
- #6: `18 passed; 0 failed`.
- #9/#16: `+8: All tests passed!` — the 5 pre-existing
  `wallet_create_duplicate_name_test.dart` cases plus my 3 new ones.
- #14: `rust/src/frb_generated.rs` sha256 after the re-run:
  `2e7b60b3c481a04018129ccac9b9c78400d62d281717643aa7a9018b8445629c`.

### #7 — the analyzer failure I caused and fixed

```
error • Undefined name 'FactoryAttestation' • lib/device.dart:220:11 • undefined_identifier
error • Undefined name 'FactoryAttestation' • lib/device.dart:222:11 • undefined_identifier
```
Cause: `FactoryAttestation` is generated into `lib/src/rust/api/firmware.dart`, which
`device.dart` did not import. Fixed by adding the import at `device.dart:12`. No
assertion was relaxed and no `switch` default was added to hide it — the `switch`
over `FactoryAttestation` is still exhaustive, which is what makes a future variant
(including a hypothetical success one) a compile error here.

### #4 — BLOCKED, exact cause, unchanged from sub-step 1

```
error[E0308]: mismatched types
   --> frostsnap_coordinator/tests/coldcard_msg_len.rs:97:56
97  |  bip32_path: BitcoinBip32Path::external(i as u32),
    |              -------------------------- ^^^^^^^^ expected `NormalIndex`, found `u32`
note: associated function defined here
   --> /Users/garykrause/repos/frostsnap/frostsnap_core/src/tweak.rs:148:12
error: could not compile `frostsnap_coordinator` (test "coldcard_msg_len") due to 1 previous error
```
Real exit **101** (captured unpiped). Provenance re-verified this sub-step:
`git status --short frostsnap_coordinator/tests/coldcard_msg_len.rs` → `??`
(untracked pre-existing user work, on this run's protected list), and
`git diff --quiet HEAD -- frostsnap_core/src/tweak.rs` → exit 0 (clean at HEAD).
Neither file is in any sub-step's diff, so the target cannot compile at HEAD either.
Not touched, not formatted, not deleted, not relaxed. #5 is the same target with
that one test file excluded by name, so nothing of mine is hidden by the exclusion.

## Files changed in this sub-step (all under `~/repos/frostsnap/frostsnapp/`)

Diffstat: `lib/device.dart` +64/-9, `lib/device_list.dart` +14/-4,
`lib/restoration/device_discovery.dart` +19/-0, `lib/settings.dart` +13/-1,
`lib/wallet_create.dart` +82/-38, plus one new test file. No Rust, no generated
file, no protected user-work file.

**`lib/wallet_create.dart`** — the acceptance-criterion-1 blocker
- `:83-97` (signature at `:92`) new pure top-level `declaredKeygenCeiling(Iterable<int?>)` — smallest
  declared ceiling, `null` when none is declared. Testable without `RustLib`, same
  shape as the existing `duplicateNamedDeviceIdsAmong`. Its doc comment says in
  terms that the refusal is in Rust and this is not the enforcement.
- `devicesCanUpgrade` **deleted** (was at `:308-316`) — it was a literal duplicate of
  `devicesNeedUpgrade` (both mean `eligibility == CanUpgrade`). Its one caller now
  reads `devicesNeedUpgrade`.
- `:325-330` `devicesIncompatible` now `any((dev) => !dev.isCompatible())`, i.e.
  asked of the PROFILE. It previously meant `any(eligibility == CannotUpgrade)`,
  which is also what "this app holds no image for you" returns — the false negative.
- `:332-339` new `exceededKeygenCeiling` getter (body at `:335-339`).
- `:368` `canGoNext` for `WalletCreateStep.devices` gains `exceededKeygenCeiling == null`.
- `:681-743` the per-device row (comment at `:682`). Was a 3-arm `when` on eligibility with the name
  field on the `upToDate` arm ALONE. Now ordered: `needsFirmwareUpgrade()` → "Old
  firmware / Tap to upgrade" (unchanged, preserves the dev affordance);
  `!isCompatible()` → "Incompatible firmware" + `firmwareName()`, row disabled;
  everything else → the inline name field and its edit button. A recognized Mk4
  lands in the third arm and is nameable.
- `:760` banner condition `devicesCanUpgrade` → `devicesNeedUpgrade`.
- `:789-807` new ceiling banner, keyed off a hoisted local (`:655`) so the getter
  is not re-read three times per build.

**`lib/device.dart`**
- `:12` the import that fixed #7.
- `:124` `final capabilities = device.capabilities();`
- `:190-216` the erase row is gated on `capabilities.erase`: disabled, trailing
  "Unsupported", and a subtitle saying where the erase does live. Comment states
  the button's absence is not the enforcement.
- `:217-229` new **Factory attestation** row, an exhaustive `switch` over
  `FactoryAttestation` → "Unsupported by this firmware — nothing to check" /
  "Not checked by this app". There is no "passed"/"genuine" string anywhere.
- `:276-280` the firmware chip renders `device.firmwareName()` (profile-aware)
  instead of `device.firmware.versionName()` (which printed `dev-xxxxxx` for an Mk4
  and an ESP32 dev build alike).
- `:308-337` the `cannotUpgrade` trailing splits on `device.isCompatible()`:
  "No update" + info icon when compatible, "Incompatible" + warning when not.
  Tooltip still carries the Rust reason string verbatim.
- `:506-515` new `catch` around the `eraseDevice` stream. `erase_device` became
  `Result` in sub-step 1, so a refusal now arrives as a Dart exception into a
  `try`/`finally` that had no `catch` — it would have been an unhandled async
  error. Surfaced as a snackbar.

**`lib/device_list.dart` `:91-103`** — the list badge's `cannotUpgrade` arm shows
nothing when `isCompatible()`, and the warning triangle only for genuinely
unrecognized firmware (tooltip now prefixed with `firmwareName()`).

**`lib/settings.dart` `:1191-1215`** — erase-all now filters to
`capabilities().erase`. This is a **real defect introduced by sub-step 1**, not
cosmetics: `coord.eraseAllDevices()` was changed there to address only the
erase-capable subset, while this same list also seeds
`FullscreenActionDialogController(devices:)`'s action-needed set. A Mk4 in the list
would never confirm an erase it was never sent, so the dialog would have waited on
it forever. The empty case now distinguishes "no devices" from "no erasable device".

**`lib/restoration/device_discovery.dart` `:125-138`** — new `_refuseIncompatible`,
called from both `_handleBlankDevice` and `_handleDeviceWithShare` (the two places a
`TargetDevice` is constructed). Refuses only a positively-identified incompatible
device, reusing the existing `_errorMessage` surface. `recovery_flow.dart:437`'s
`needsFirmwareUpgrade()` routing is left alone: it is still correct, and it cannot
answer the compatibility question because an app with no bundled image says "no
upgrade" about every device.

**`test/wallet_create_keygen_ceiling_test.dart`** — NEW, 3 cases: an all-native
group declares no ceiling (and the empty list is `null`); the smallest declared
ceiling wins in a mixed group; 12 is inside the bound and 13 is over. Header states
in terms that the refusal is in Rust and this covers the pure predicate only.

## Mutation check on the new Dart logic

`(lowest == null || ceiling < lowest)` → `... ceiling > lowest` in
`declaredKeygenCeiling`:

```
MUTATED_EXIT=1
  Expected: <4>
    Actual: <12>
00:01 +2 -1: Some tests failed.
```
File restored from backup; `flutter test test/wallet_create_keygen_ceiling_test.dart`
→ exit **0**. The test bites on the min/max inversion, i.e. on the case that
matters (a mixed group must be held to the smallest ceiling present).

## Acceptance criteria after this sub-step

| # | criterion | verdict |
|---|---|---|
| 1 | Known Mk4 named and included in wallet creation without an ESP32 digest match or a bundled Mk4 image; unrecognized stays explicit | **met at unit/analyzer level.** Rust met in sub-step 1. App side now met in code: the name field no longer lives on the `upToDate` arm (`wallet_create.dart:681-743`), `devicesIncompatible` is profile-based (`:330`), and `canGoNext` (`:368`) no longer blocks. `firmwareName()` renders `mk4 <rev>`; unrecognized renders "Incompatible firmware" + `unrecognized-xxxxxx`. **Not driven end to end** — see the honesty note below. |
| 2 | Native readiness and updates retain existing supported behavior | **met, with one deliberate behaviour change reported below.** `needsFirmwareUpgrade()` semantics are untouched, the upgrade row/banner/bubble/`device_action_upgrade` filters are untouched, and `upToDate` still renders "Latest". |
| 3 | Mock-port tests prove ESP32 traffic never reaches Mk4/unselected ports and no wait for their acks | **met at unit level, in sub-step 1** (`mock_port_upgrade_routing.rs`, 6 tests, re-run here at exit 0). Nothing in this sub-step weakens it; nothing in this sub-step is that test. Explicitly NOT an integration run. |
| 4 | Unsupported erase/attestation/update actions have clear API/UI outcomes | **met.** API was met in sub-step 1; UI now renders all three — erase (`device.dart:190-216`, `settings.dart:1191`), attestation (`device.dart:217-229`), update-unavailable as "No update" rather than "Incompatible" (`device.dart:308-337`, `device_list.dart:91-103`). Refusals remain enforced in Rust; every UI gate here has a Rust refusal behind it, and the `eraseDevice` catch exists precisely because the Rust refusal is the real one. **Repair round:** this was false for the restoration gate, which had no Rust refusal behind it; that gate was removed, so the claim now holds for what remains — erase (`coordinator.rs:1081`), erase-all (`:1101`), keygen (`api/device_list.rs check_keygen_group`), upgrade streaming (`usb_serial_manager.rs:704`), check-backup (`check_backup.rs:49`). |
| 5 | Tests cover no bundled firmware, unsupported firmware, capability differences, mixed ports, over-limit keygen rejected before starting | **5 of 5 met after the repair round.** First four: sub-step 1's tests, re-run at exit 0. Over-limit keygen: the refusal `generate_new_key` applies before `BeginKeygen::new` is now the function `api::device_list::check_keygen_group`, driven directly by `an_over_limit_keygen_is_refused_before_it_starts` (12 in / 13 out / no-ceiling group) and `unrecognized_firmware_is_refused_from_a_keygen`. No `FfiCoordinator` fixture was needed: `generate_new_key` calls nothing else between building `selected` and `BeginKeygen::new`. |

## Audit against every forbidden shortcut, by name

Global:
- **"Never claim a command ran that did not run. Paste real exit codes."** Every row
  above was run in this session; exit codes are the process's `$?`.
- **"Capture the process's status, never a filtering pipeline's."** The only piped
  runs were two `| tail` inspections of #4; its real status (101) was re-captured
  unpiped. Every other command redirected to a file and reported `$?`.
- **"Exit 0 with SKIP output is not a pass."** Nothing here skips. `tools/pixel-check.py`
  was not run or cited.
- **"Historical figures are reproduction clues."** No figure in this section is
  copied from a document: the 12 in the ceiling test comes from
  `DeviceCapabilities.max_keygen_devices`, itself declared by the Mk4 profile; the
  test asserts the 12/13 boundary against the declared value, not against a literal.
  Test counts, digests and timings above are from this session's runs.
- **"Never delete or relax a failing assertion."** #7 was fixed by adding the
  missing import. The `FactoryAttestation` switch stays exhaustive with no default,
  so a new variant breaks the build here on purpose. No test was deleted; #4's
  blocked test file was left exactly as found.
- **"No 'hardware verified' or 'safe for funds'."** Neither phrase appears. The
  claim is scoped below.
- **"Unit tests are never reported as an integration run."** Stated at criteria 1,
  3 and 5, and in the claim. Task 04 owns the integration run.

Task-specific:
- **No `FirmwareFeatures::all()` fallback for an unknown digest.** Nothing in this
  sub-step touches `features()`. Sub-step 1 deleted the fail-open; an unrecognized
  profile still returns `FirmwareFeatures::default()`. Verified by re-running
  `device_profile_test` (10 passed) and the `rust_lib_frostsnapp` suite (18 passed),
  which includes `unrecognized_firmware_is_not_compatible`.
- **No ESP32 release identity assigned to a Mk4 to satisfy a version comparison.**
  No Dart edit synthesises a version. The chip in `device.dart` moved AWAY from
  `FirmwareVersion.versionName()` to the profile's own label, which is the opposite
  of borrowing an ESP32 identity.
- **No fake attestation success.** `FactoryAttestation` has two variants and my
  `switch` renders them as "Unsupported…" and "Not checked by this app". There is no
  "passed", "genuine" or "verified" string. `grep -rni "genuine\|attest"` over
  `lib/` excluding `lib/src/rust` hits my row and two unrelated pre-existing prose
  comments (`secure_key_provider.dart:41`, `wallet_key_mismatch.dart:44`, both about a
  "genuine platform failure") — no other attestation surface exists.
- **Capability refusals enforced in the Rust API, not the UI alone.** Every gate I
  added is in front of a Rust refusal that already existed after sub-step 1: erase →
  `coordinator.rs:1071`; keygen ceiling → `coordinator.rs:414`; update-mode →
  `usb_serial_manager.rs:686`. The `eraseDevice` `catch` is the proof I treated the
  Rust refusal as the real one rather than assuming the hidden button sufficed.
- **Do not hand-edit generated bindings.** `just gen` and `just build-runner` only,
  four times total. No file under `lib/src/rust/` or `rust/src/frb_generated.rs` was
  edited; #14 shows a re-run reproduces all 32 generated Dart files byte-identically.
- **Do not link cold-snap's vendored Frostsnap crates into the coordinator graph.**
  No `Cargo.toml` was touched in either repo this sub-step.

Run rules:
- No device, serial port, flashing, provisioning, OTP write, callgate or network
  broadcast. No Bitcoin node was started (this task needs none).
- `~/repos/coldcard-firmware` not read from or written to this sub-step.
- `~/repos/cold-snap` write confined to this evidence file under ignored `target/`.
- Protected user work re-verified untouched after all work:
  `frostsnapp/.gitignore` +3/-0, `frostsnapp/macos/Podfile.lock` +1/-1, `justfile`
  +12/-2 — the pre-existing diffs only; `frostsnap_coordinator/tests/coldcard_msg_len.rs`
  still `??` and unmodified; cold-snap `?? prompts/` intact.
- Nothing committed, nothing pushed, no PR.

## Deliberate behaviour change, reported rather than buried

**A released ESP32 device newer than the app is now usable in wallet creation.**
`check_upgrade_eligibility` returns `CannotUpgrade{"This is a development app.
Cannot upgrade proper device."}` / `{"Device firmware version newer app…"}` for it
(`frostsnap_coordinator/src/firmware.rs:73-86`), and the old
`devicesIncompatible`/row logic read any `CannotUpgrade` as incompatible — so that
device was disabled and blocked Continue. Its profile is
`Esp32Frostsnap{release: Some(_)}`, which `is_compatible()` answers true, so it now
gets a name field and passes `canGoNext`. I believe this is the correction the task
asks for (compatibility and update availability are different questions, and a
released device is certainly usable for a keygen), but it IS a change to native
behaviour under criterion 2 and a verifier should judge it rather than discover it.

## Left for the verifier to judge

1. **Criterion 1 is not driven end to end.** `flutter analyze` cannot execute a
   widget tree, and a widget test of the device row needs `RustLib` — which
   `flutter test` has no native library for (see
   `integration_test/testnet4_chooser_test.dart`'s own header). So the claim "a
   recognized Mk4 can be named in the app" is a code-and-analyzer claim plus the
   Rust unit tests behind it, not an executed app path. `PLAN.md` §9 item 21's note
   applies to me too: a test that has never run is not evidence. Task 04 is the run.
2. **No Dart test covers the row-ordering change, the erase gate, the attestation
   row, the settings filter or the restoration gate.** All five are widget/UI paths
   that need `RustLib`. Only `declaredKeygenCeiling` is unit-tested.
3. ~~**`_refuseIncompatible` fails open on a null device** … The Rust APIs refuse
   regardless; judge whether that ordering is the one wanted.~~ **WITHDRAWN: the
   whole gate was removed in the repair round.** "The Rust APIs refuse regardless"
   was false — none of the entry points in `frostsnapp/rust/src/api/recovery.rs`
   carries a compatibility or capability check, so the gate was UI-only, which this
   task's shortcut list forbids. It also refused every native dev ESP32. See
   "Repair round".
4. **The erase-all filter silently narrows the set.** A user with one ESP32 and one
   Mk4 who taps "Erase all devices" now erases the ESP32 only, and the dialog says
   nothing about the skipped Mk4. That matches what `erase_all_devices` actually
   does, but a per-device notice would be better and I did not add one.
5. **Sub-step 1's residuals are unchanged and still open**: an *unregistered* Mk4
   still lands in the `(None,None) => CanUpgrade` dev arm and is offered an ESP32
   upgrade in the row (it is `Unrecognized`, so the ordering shows it the upgrade
   arm first — registering is the documented remedy); the `generate_new_key` /
   `begin_upgrade_firmware` / `enter_firmware_upgrade_mode` / `erase_device`
   refusals are typed and reasoned but only `run_firmware_upgrade`'s and
   `generate_new_key`'s are tested (the latter closed in the repair round;
   `begin_upgrade_firmware` / `enter_firmware_upgrade_mode` / `erase_device` remain
   untested and are the known-open residual);
   `Destination::Particular` reaching a daisy-chained ESP32 is argued, not measured;
   a real port that never answers is evicted after 5 s where a fake one is not.
6. **`just lint-app` was not run** because it depends on `maybe-gen` and is not
   read-only. Bare `flutter analyze` (exit 0) and `dart format --set-exit-if-changed`
   (exit 0) were run instead. `just lint-ordinary` remains red on pre-existing
   clippy findings in `macros/` and `frost_backup/`, none in any file I touched —
   and I touched no Rust.

## Claim for this sub-step

**Software/pre-bench checks passed**, scoped to: the Flutter/Dart callers of the new
compatibility/capability API, and a bridge regenerated with the repository's own
recipes under the pinned 3.38.5 SDK — evidenced by `just gen` + `just build-runner`
at exit 0 and reproducible across a re-run, `flutter analyze` with no issues,
`flutter test` 8/8 including 3 new mutation-checked cases, and the sub-step-1 Rust
suites re-run green (58+10+1+6+5+3 and 18). No device, port or network was involved.
The real-app virtual-device integration run is task 04's and has not been done.

---

# Repair round — 2026-09-22

Agent: repair (write lock). Scope: the nine CONFIRMED verifier findings, nothing
else. No commit. Every Flutter/Dart command ran with
`export PATH="$HOME/repos/frostsnap/frostsnapp/.fvm/flutter_sdk/bin:$PATH"` first;
`flutter --version` confirmed **Flutter 3.38.5 / Dart 3.10.4**, revision
`f6ff1529fd`, before anything else. The system 3.35.1 was never used.

## The root cause four findings shared

Findings 2, 5, 6 and 7 are all one mistake in two places. `DeviceProfile::features()`
answers `FirmwareFeatures::default()` for `Unrecognized` — correct, and the
fail-open this task exists to close — but two call sites were reading that flag as
though "unknown" meant "old":

- `firmware_upgrade.rs`: `!features().upgrade_digest_no_sig` → legacy
  `PrepareUpgrade`, which announces `digest_with_signature()`. `device/src/ota.rs`
  accepts only the body digest, so on the default (signed) bundle every device
  refuses the image.
- `check_backup.rs`: `!features().check_backup` → the legacy flow, which asks the
  **human** to retype all 25 words instead of letting the device sit the 3-option
  quiz.

`Unrecognized` is what every native ESP32 flashed from a different tree state than
the app's bundle identifies as, and every device at all when the app bundles none.
Both flags are **protocol-dialect selectors, not permissions**, and the wrong answer
is fatal rather than cosmetic.

Fix: the legacy dialect is now **opt-in by positive identification**. Two new
predicates on `DeviceProfile`, each matching only an ESP32 release we recognize as
predating the feature:

- `frostsnap_coordinator/src/device_profile.rs:114` `needs_legacy_upgrade_message()`
- `frostsnap_coordinator/src/device_profile.rs:134` `needs_legacy_check_backup()`

This is **not** a `FirmwareFeatures::all()` fallback for an unknown digest — the
forbidden shortcut is untouched. `features()` and `capabilities()` still claim
*nothing at all* for `Unrecognized` (`device_profile_test.rs`
`an_unknown_digest_claims_no_feature_and_no_capability` still green, unmodified),
and `is_compatible()` is still false for it. What changed is which of two wire
dialects a device we cannot identify is spoken to in.

## Per finding

| # | finding | verdict | where |
|---|---|---|---|
| 1 | hostcheck TRAP-2 relaxed to a tautology; `CHECK_BACKUP_SINCE` dead behind a new `#[allow(dead_code)]`; documented failure case no longer reproduces | **FIXED** | `hostcheck/src/main.rs:1061` (`#[allow(dead_code)]` removed, doc rewritten), `:2061` + `:2069` (guard in two halves), `:2675-2694` (new test module), `:286-292` (header) |
| 2 | dev ESP32 hard-refused from restoration and loses the wallet-create upgrade banner | **FIXED (both consequences)** | `frostsnapp/lib/restoration/device_discovery.dart:125` (gate removed), `frostsnapp/lib/wallet_create.dart:341` (`devicesIncompatible`) |
| 3 | criterion 5: no test covers the over-limit keygen rejection itself | **FIXED** | `frostsnapp/rust/src/api/device_list.rs:187` `check_keygen_group`, called at `frostsnapp/rust/src/coordinator.rs:401`; tests at `api/device_list.rs:396` and `:425` |
| 4 | evidence clippy row records a judgement instead of an exit code, overstated at file granularity | **FIXED** | this file, the clippy row above; real exit **101** recorded |
| 5 | dev-app ESP32 upgrade announces the wrong digest and every device refuses it | **FIXED** | `frostsnap_coordinator/src/firmware_upgrade.rs:133-144` |
| 6 | check-backup silently drops to the legacy full-seed re-entry path for dev devices | **FIXED** | `frostsnap_coordinator/src/check_backup.rs:50-56` |
| 7 | restoration newly refused for native dev ESP32s | **FIXED** | `frostsnapp/lib/restoration/device_discovery.dart:125` |
| 8 | "The Rust APIs refuse regardless" false — the restoration gate was UI-only | **FIXED by deletion** | gate removed, so there is no UI-only refusal left to justify; claim corrected in criterion 4 and residual 3 above |
| 9 | no test asserts `PrepareUpgrade2` is selected | **FIXED** | `frostsnap_coordinator/tests/device_profile_test.rs:321`, `:358`, `:385` (3 new tests) |

### Finding 1, in detail

The guard is now two halves and neither is a tautology:

1. `CHECK_BACKUP_SINCE.features().check_backup` — the constant run through
   upstream's own `VersionNumber::features()`. Fires if upstream raises its
   threshold past 0.3.0 **and** if the constant is lowered below it, which is
   exactly the reproduction the module header documents. The constant is live
   again; `#[allow(dead_code)]` is gone and `cargo check` is still 0 warnings.
2. `!profile.needs_legacy_check_backup()` — the *same predicate*
   `CheckBackupProtocol::new` branches on, so harness and driver cannot drift.

The runtime bail in `Phase::Quiz` needs a stub run to reach, so the same two facts
are also a unit test (`check_backup_threshold::the_recorded_threshold_is_the_one_upstream_uses`),
which makes the documented failure case checkable by `cargo test` alone.

**Mutation-verified.** `CHECK_BACKUP_SINCE` lowered to `VersionNumber::new(0, 2, 0)`,
`cargo test --target aarch64-apple-darwin` in `~/repos/cold-snap/hostcheck`:

```
test check_backup_threshold::the_recorded_threshold_is_the_one_upstream_uses ... FAILED
thread '...' panicked at src/main.rs:2679:9:
upstream no longer grants check_backup at v0.2.0, so M7c's guard would bail and the quiz would not run
test result: FAILED. 1 passed; 1 failed
```
exit **101**. File restored from `/tmp/hc.bak`; re-run exit **0**, 2 passed. The
`v0.2.0` rendering confirms the header's quoted bail string still matches verbatim.
(The `:2679:9` in that captured output is the line as it stood during the mutation
run; the module-header edit that followed shifted the file down by 3 lines, so the
assert now sits at `:2682`. Captured output is quoted as measured, not renumbered.)

### Finding 9, in detail — mutation-verified

`needs_legacy_upgrade_message` temporarily given the old semantics
(`_ => !self.features().upgrade_digest_no_sig`), then
`cargo test --target aarch64-apple-darwin -p frostsnap_coordinator --test device_profile_test`:

```
test only_a_release_that_predates_the_modern_message_takes_the_legacy_dialect ... FAILED
test result: FAILED. 12 passed; 1 failed
```
File restored from `/tmp/dp.bak`; re-run exit **0**, 13 passed. The new test is the
regression test, not a test that passes by construction.

`the_modern_message_announces_the_body_digest` additionally asserts the bytes the
modern arm carries equal `bundle.digest()` and that `digest() != digest_with_signature()`
for the signed fixture, which is the byte-level half of the same defect.

### Findings 2 and 7, in detail

`_refuseIncompatible` and both its call sites are removed;
`frostsnapp/lib/restoration/device_discovery.dart` is now identical to HEAD apart
from a comment recording why there is no gate there. `!isCompatible()` answers "is
this the exact image I ship", which for native dev hardware is a different question
from "can I talk to this device", and the gate refused exactly the population
`RecoveryFlowStage.firmwareUpgrade()` (`recovery_flow.dart:437-438`, reachable from
nowhere else) exists to serve.

`devicesIncompatible` (`wallet_create.dart`) is now
`!dev.isCompatible() && !dev.needsFirmwareUpgrade()` — the same order
`buildDevicesBody` already renders the rows in, so the getter means exactly "a
device shown as *Incompatible firmware*". That restores the
`devicesNeedUpgrade && !devicesIncompatible` banner for an upgradeable dev device
without weakening `canGoNext`, which independently requires `!devicesNeedUpgrade`.

## Commands re-run — cwd and real exit codes

Exit codes are the process's status (`${pipestatus[1]}` where a `| tail` was used
for display), never a pipeline's.

| command | cwd | exit | result |
|---|---|---|---|
| `flutter --version` | `~/repos/frostsnap` | **0** | Flutter 3.38.5 • Dart 3.10.4, rev `f6ff1529fd` |
| `just gen` | `~/repos/frostsnap` | **0** | frb 2.11.1, `Done!`, rewrote `binding-rerun.sha256` |
| `just build-runner` | `~/repos/frostsnap` | **0** | 24 outputs, 142 actions, 9.1 s |
| `just gen` (second run) + `diff` of `lib/src/rust/api/device_list.dart` | `~/repos/frostsnap` | **0** | byte-identical — codegen reproducible. `frb_generated.rs` md5 `c32eb598…` unchanged by this round: the new Rust surface is `pub(crate)`/`#[frb(ignore)]` and the two new `DeviceProfile` methods are not in the `api/firmware.rs` mirror. No generated file was hand-edited. |
| `cargo test --target aarch64-apple-darwin -p frostsnap_coordinator` | `~/repos/frostsnap` | **101** | unchanged pre-existing blocker: `tests/coldcard_msg_len.rs:97` E0308, protected user work, untouched |
| `cargo test … -p frostsnap_coordinator --lib --test device_profile_test --test firmware_digest_test --test mock_port_upgrade_routing` | `~/repos/frostsnap` | **0** | lib 58 passed / 2 ignored; `device_profile_test` **13 passed** (10 + 3 new); `firmware_digest_test` 1; `mock_port_upgrade_routing` 6 |
| `cargo test --target aarch64-apple-darwin -p rust_lib_frostsnapp` | `~/repos/frostsnap` | **0** | **20 passed** (18 + 2 new) |
| `cargo clippy --target aarch64-apple-darwin -p frostsnap_coordinator -p rust_lib_frostsnapp --all-features --lib --tests` | `~/repos/frostsnap` | **101** | same pre-existing E0308. 58 `uninlined_format_args` warnings workspace-wide; **0 in any file or region this round touched** (`device_profile.rs`, `check_backup.rs`, `firmware_upgrade.rs`, `api/device_list.rs`, `device_profile_test.rs` appear nowhere in the warning list). The 7 in task-edited files sit on pre-existing lines outside every `git diff -U0` hunk. |
| `rustfmt --edition 2021 --check` on the 6 Rust files changed this round | `~/repos/frostsnap` | **0** | after one `rustfmt --edition 2021` pass on `device_profile_test.rs` and `api/device_list.rs` |
| `dart format --set-exit-if-changed lib/wallet_create.dart lib/restoration/device_discovery.dart` | `~/repos/frostsnap/frostsnapp` | **0** | "Formatted 2 files (0 changed)" |
| `flutter analyze` | `~/repos/frostsnap/frostsnapp` | **0** | "No issues found!" (20.2 s) |
| `flutter test` | `~/repos/frostsnap/frostsnapp` | **0** | **8 passed** (3 keygen-ceiling + 5 duplicate-name) |
| `cargo check --target aarch64-apple-darwin` | `~/repos/cold-snap/hostcheck` | **0** | no warnings — with `#[allow(dead_code)]` removed, so the constant is genuinely used |
| `cargo test --target aarch64-apple-darwin` | `~/repos/cold-snap/hostcheck` | **0** | 2 passed (`golden_vector_agrees_with_m13s_own_digest`, `the_recorded_threshold_is_the_one_upstream_uses`) |

Not re-run: a hostcheck stub/qemu pass. This round changed no hostcheck seam, only
its TRAP-2 guard, and that guard is now covered by a unit test. No device, port,
flash, OTP write, callgate or network was involved in anything above.

## What this round deliberately did NOT do

- **No Rust compatibility check was added to `api/recovery.rs`.** Finding 8 is
  resolved by removing the UI-only gate, not by adding 20 guards. Restoration
  compatibility is not named by any acceptance criterion (criterion 4 names
  erase/attestation/update, all three of which do have Rust refusals), and adding a
  refusal there would re-break the dev-device flow findings 2 and 7 are about.
- **The `(None, None) => CanUpgrade` dev arm in `firmware.rs:68` was left alone.**
  It is a sub-step-1 residual already recorded as known-open, and it is what keeps
  the dev upgrade affordance working.
- **No pre-existing `uninlined_format_args` warning was fixed.** Out of scope, and
  they are not this task's.

## Claim, scoped

**Software/pre-bench checks passed** for this repair round, scoped to: the nine
CONFIRMED findings, the Rust unit suites and Flutter analyzer/unit tests listed
above, and a bridge regenerated reproducibly with the repository's own recipes
under the pinned 3.38.5 SDK. Two fixes are mutation-verified. Not hardware
verified; not safe for funds; the real-app virtual-device integration run is task
04's and has not been done.

---

# Close-out — 2026-09-22

Agent: close-out. Write scope: this file and
`target/software-only/evidence/run.json` only. **No source file in either repo was
edited by this agent** — verified by `git diff --numstat` before and after, and by
the file list in the commit below. The only commands run that write anything are
`just gen` / `just build-runner`, whose entire output is gitignored and untracked
(`frostsnapp/.gitignore:52` `lib/src/rust/*`, `:54` `rust/src/frb_generated.rs`,
`:63` `binding-rerun.sha256`; `git ls-files --error-unmatch
frostsnapp/binding-rerun.sha256` → *did not match any file known to git*), so no
generated byte enters the commit.

## A. The re-runner's independent re-run, labelled as such

Three verification agents re-ran this task's Checks block independently of the
implementers. Their measurements are reproduced here as *theirs*, not as the
implementers' and not as close-out's.

### A1 — re-runner 1 (pre-repair)

All commands with an explicit cwd; every Flutter/Dart command with the pinned SDK
first on PATH and the version confirmed by that agent before proceeding; exit codes
the process's own `$?` on the unpiped command, never a pipeline's.

| command | cwd | exit |
|---|---|---|
| `flutter --version` (pinned; `which flutter dart` both under `.fvm/flutter_sdk/bin`) | `~/repos/frostsnap` | **0** — Flutter **3.38.5**, Dart **3.10.4**, DevTools 2.51.1, rev `f6ff1529fd`. Not 3.35.1. |
| `just gen` | `~/repos/frostsnap` | **0** |
| `just build-runner` | `~/repos/frostsnap` | **0** |
| `cargo test --target aarch64-apple-darwin -p frostsnap_coordinator` | `~/repos/frostsnap` | **101** — reproduced; sole error `error[E0308]` at `tests/coldcard_msg_len.rs:97` vs `frostsnap_core/src/tweak.rs:148`. Verified pre-existing: file untracked, `git diff --quiet HEAD -- frostsnap_core/src/tweak.rs` → 0. No other error behind it. |
| same `+ --lib --test device_profile_test --test mock_port_upgrade_routing --test firmware_digest_test --test real_psbts --test tofu_tests` | `~/repos/frostsnap` | **0** — 58+10+1+6+5+3 = **83 passed**, 0 failed. The 2 `ignored` are pre-existing `#[ignore] // requires network` at `src/bitcoin/tofu/connection.rs:305,332`. |
| `cargo test --target aarch64-apple-darwin -p rust_lib_frostsnapp` | `~/repos/frostsnap` | **0** — 18 passed |
| `flutter analyze` | `~/repos/frostsnap/frostsnapp` | **0** — "No issues found!" |
| `flutter test` | `~/repos/frostsnap/frostsnapp` | **0** — 8 passed |
| `dart format --set-exit-if-changed --output=none $(find ./lib …)` | `~/repos/frostsnap/frostsnapp` | **0** — 79 files, 0 changed |
| `just check-safe-area-surfaces` (the read-only part of `lint-app`) | `~/repos/frostsnap` | **0** |
| reproducibility: 35 generated-file sha256s → `just gen` → `just build-runner` → re-checksum → `diff` | `~/repos/frostsnap` | **0 / 0 / 0 — byte-identical** |
| `cargo fmt -- --check` | `~/repos/frostsnap` | **1** — exactly one hunk, `tests/coldcard_msg_len.rs:182` (protected untracked user work). No implementer file unformatted. |
| `cargo clippy --target aarch64-apple-darwin -p frostsnap_coordinator -p rust_lib_frostsnapp --all-features --lib --tests` | `~/repos/frostsnap` | **101** (same pre-existing E0308) |
| `cargo check` (after `touch src/main.rs`, so warnings re-emit) | `~/repos/cold-snap/hostcheck` | **0**, **0 warnings** |
| `cargo test` | `~/repos/cold-snap/hostcheck` | **0** — 1 passed |
| `python3 frostsnap_coordinator/tools/register-mk4-firmware.py --self-check` | `~/repos/frostsnap` | **0** — `33b54101…9489`, equals the `announced` column of `cold-snap/golden/mk4-staging-vectors.txt` |
| `… --print target/software-only/package/firmware-signed.bin` (task 01's real signed artifact) | `~/repos/frostsnap` | **0** — `58f1b3fe…9f441`, **identical to the sole registry entry**. Convention verified against the source of truth `firmware/src/lib.rs:3003-3052` — not the ELF hash, not the ESP32 contiguous prefix, not a stub constant. |

Deliberate-failure cases that agent re-ran, fixtures built fresh under ignored
`~/repos/cold-snap/target/software-only/rerun02/fixtures/`, nothing in either repo
mutated:

| negative case | exit | failed for the named reason? |
|---|---|---|
| `--print short.bin` (header `firmware_length` = 261,632) | **1** | yes — `header firmware_length 261632 < FW_MIN_BODY_LEN 262144` |
| `--print misaligned.bin` (262,145) | **1** | yes — `header firmware_length 262145 is not a multiple of 512` |
| `--print toolong.bin` (397,824 > 397,312-byte file) | **1** | yes — `header firmware_length 397824 exceeds the 397312-byte file` |
| `--print flipped.bin` (one body byte flipped) | **0**, digest `959ca4f3…` ≠ registry `58f1b3fe…` | yes — a tampered image is not recognized |
| every capability anchor cited in `device_profile.rs`, checked against the real cold-snap firmware | — | all present: `MAX_PARTIES: usize = 12` at `firmware/src/lib.rs:291`; `Upgrade(_) => Refusal::FirmwareUpgrade` `:1070`; `DataErase => Refusal::DataErase` `:1071`; `Challenge(_) => Refusal::GenuineChallenge` `:1072`; `CheckBackup` ADMITTED `:1239`; `DisplayBackup` `:1136`; restore flow `:1184` |

Stated by that agent rather than glossed: it could **not** reproduce either of the
implementers' two mutation checks, because both require editing source and its brief
was read-only. It read the 6 routing tests and the 4 protocol tests instead and
confirmed they are not vacuous — `an_esp32_upgrade_never_reaches_an_mk4_port`
asserts `written(&esp32_port) > bin.size()` in the same test as the two `== 0`
assertions, so the fake ports demonstrably record writes. It also did not re-run the
registry *write* path (which modifies a source file); that result is verified
instead by the registry's current content matching `--print`.

### A2 — re-runner 2 (pre-repair)

| command | cwd | exit | note |
|---|---|---|---|
| `cargo test … -p frostsnap_coordinator --lib --test device_profile_test --test mock_port_upgrade_routing --test firmware_digest_test --test real_psbts --test tofu_tests` | `~/repos/frostsnap` | **0** | 58 (2 ignored) + 10 + 1 + 6 + 5 + 3 — matches the claim exactly |
| `cargo test --target aarch64-apple-darwin -p frostsnap_coordinator` | `~/repos/frostsnap` | **101** | same E0308; cause verified pre-existing by both tests (untracked file, `tweak.rs` clean at HEAD) |
| `cargo test --target aarch64-apple-darwin -p rust_lib_frostsnapp` | `~/repos/frostsnap` | **0** | 18 passed |
| `flutter --version` (pinned SDK first on PATH) | `~/repos/frostsnap/frostsnapp` | **0** | 3.38.5 / Dart 3.10.4, not the system 3.35.1 |
| `flutter analyze` | `~/repos/frostsnap/frostsnapp` | **0** | "No issues found!" |
| `flutter test` | `~/repos/frostsnap/frostsnapp` | **0** | 8 passed |
| `cargo check` | `~/repos/cold-snap/hostcheck` | **0** | 0 warning lines |
| `cargo test` | `~/repos/cold-snap/hostcheck` | **0** | 1 passed |
| `tools/register-mk4-firmware.py --self-check` | `~/repos/frostsnap` | **0** | reproduces golden `33b54101…` from `cold-snap/golden/mk4-staging-vectors.txt:49` |
| `… --print target/software-only/package/firmware-signed.bin` | `~/repos/frostsnap` | **0** | `58f1b3fe…` — identical to the registry entry and to `verify/runA/firmware-signed.bin`. Digest provenance measured from the wave-1 artifact. |
| `git diff HEAD --numstat -- justfile frostsnapp/.gitignore frostsnapp/macos/Podfile.lock` | `~/repos/frostsnap` | **0** | 12/2, 3/0, 1/1 — protected user work exactly as declared; `coldcard_msg_len.rs` still `??`; cold-snap `?? prompts/` intact |
| generated-binding inspection (`ls -la` + `grep` on `lib/src/rust/api/{firmware,device_list}.dart`, `rust/src/frb_generated.rs`) | `~/repos/frostsnap` | — | regenerated 11:05-11:06 with the new mirrors present; all of `lib/src/rust/*` gitignored, so a hand-edit could not appear in the diff either way |
| cited-source spot checks (`firmware/src/lib.rs:184-187,291,1070-1072,1136,1184,1239`; `frostsnap_comms/src/lib.rs:259-292`; `device/src/ota.rs:51-86`; `device/src/esp32_run.rs:378-392,544-566`) | both repos | — | every line citation in `device_profile.rs`, the registry header and the registration tool checks out |

### A3 — re-runner 3 (**post-repair**; the round that produced the findings still on the ledger)

| command | cwd | exit |
|---|---|---|
| `flutter --version` (pinned SDK first on PATH) | `~/repos/frostsnap` | **0** — Flutter 3.38.5, Dart 3.10.4, rev `f6ff1529fd` |
| `just gen` | `~/repos/frostsnap` | **0** — frb 2.11.1, `Done!` |
| `just build-runner` | `~/repos/frostsnap` | **0** — "Succeeded after 9.0s with 24 outputs (142 actions)" |
| `just gen` + `just build-runner` (2nd run) | `~/repos/frostsnap` | **0 / 0** — all 33 generated hashes identical to its own run 1; `frb_generated.rs` md5 `c32eb5989d4ec9fc98d049a78b7999a7` |
| 33-file sha256 diff of *the state the repair agent left* vs after its own run 1 | `~/repos/frostsnap` | **1 — 6 of 33 `.freezed.dart` files differed** → its finding 1, now closed; see §D |
| `cargo test --target aarch64-apple-darwin -p frostsnap_coordinator` | `~/repos/frostsnap` | **101** — same pre-existing E0308; `git diff --quiet HEAD -- frostsnap_core/src/tweak.rs` → **0** |
| `cargo test … -p frostsnap_coordinator --lib --test device_profile_test --test mock_port_upgrade_routing --test firmware_digest_test` | `~/repos/frostsnap` | **0** — 58 passed/2 ignored, **13**, 6, 1 |
| `cargo test --target aarch64-apple-darwin -p rust_lib_frostsnapp` | `~/repos/frostsnap` | **0** — **20 passed** |
| `cargo clippy --target aarch64-apple-darwin -p frostsnap_coordinator -p rust_lib_frostsnapp --all-features --lib --tests` | `~/repos/frostsnap` | **101** — same E0308; 58 `uninlined_format_args`, the 7 in edited files at `firmware.rs:28,31,180,183,190` + `rust/src/coordinator.rs:1022,1499`, all verified pre-existing lines outside every `git diff -U0` hunk |
| `rustfmt --edition 2021 --check` on all 12 changed Rust files | `~/repos/frostsnap` | **0** |
| `flutter analyze` | `~/repos/frostsnap/frostsnapp` | **0** — "No issues found!" |
| `flutter test` | `~/repos/frostsnap/frostsnapp` | **0** — 8 passed |
| `dart format --set-exit-if-changed --output=none` (lib + test, freezed/rust excluded) | `~/repos/frostsnap/frostsnapp` | **0** — 81 files, 0 changed |
| `just dart-format-check-app` | `~/repos/frostsnap` | **0** |
| `just check-safe-area-surfaces` | `~/repos/frostsnap` | **0** |
| `cargo check --target aarch64-apple-darwin` | `~/repos/cold-snap/hostcheck` | **0** — 0 warnings |
| `cargo test --target aarch64-apple-darwin` | `~/repos/cold-snap/hostcheck` | **0** — 2 passed |
| `rustfmt --edition 2021 --check hostcheck/src/main.rs` | `~/repos/cold-snap` | **1** — 28 hunks |
| same, on `git show HEAD:hostcheck/src/main.rs` | `/tmp` copy | **1** — 28 hunks, every line number the working-tree set minus the insertion offset (1346→1364, 2652→2721, 4904→4973). **The 28 rustfmt hunks are provably the same 28 as at HEAD, line-shifted.** |
| `tools/register-mk4-firmware.py --self-check` | `~/repos/frostsnap` | **0** — `33b54101…`, equals `cold-snap/golden/mk4-staging-vectors.txt` |
| `tools/register-mk4-firmware.py --print target/software-only/package/firmware-signed.bin` | `~/repos/frostsnap` | **0** — `58f1b3fe…9f441`, byte-equal to the registry's only entry |
| NEGATIVE: `--print /nonexistent.bin` | `~/repos/frostsnap` | **1** — `FileNotFoundError` |
| NEGATIVE: `--print` a 100-byte file | `~/repos/frostsnap` | **1** — `header firmware_length 0 < FW_MIN_BODY_LEN 262144` |
| NEGATIVE: `--print` a body-tampered copy (byte 20000 flipped) | `~/repos/frostsnap` | **0** — `a05f9d9fc154…`, **not** in the registry → `Unrecognized`, fail-closed |
| NEGATIVE: `--print` a signature-range tamper (byte 16350 flipped) | `~/repos/frostsnap` | **0** — digest unchanged, which is the documented punched-out `[16320,16384)` convention, not a defect |
| `--print` left the registry byte-identical | `~/repos/frostsnap` | sha256 `8bff12c1df0c…`, still `??` |
| `git status --short` before vs after all its runs | both repos | **identical** — its runs modified no source |

## B. Close-out's own re-run — cwd, real exit code, elapsed

Run by this agent at close-out against the exact tree being committed. Elapsed is
wall clock from `date +%s` either side; exit is the process's own `$?` with output
redirected to a file, never a pipeline's. Cargo caches were warm, so these are
incremental, not cold-build, costs.

| # | command | cwd | exit | elapsed |
|---|---|---|---|---|
| 1 | `export PATH="$HOME/repos/frostsnap/frostsnapp/.fvm/flutter_sdk/bin:$PATH"; which flutter dart; flutter --version` | `~/repos/frostsnap` | **0** | 1 s |
| 2 | `cargo test --target aarch64-apple-darwin -p frostsnap_coordinator` | `~/repos/frostsnap` | **101** | 5 s |
| 3 | `cargo test --target aarch64-apple-darwin -p frostsnap_coordinator --lib --test device_profile_test --test mock_port_upgrade_routing --test firmware_digest_test --test real_psbts --test tofu_tests` | `~/repos/frostsnap` | **0** | 3 s |
| 4 | `cargo test --target aarch64-apple-darwin -p rust_lib_frostsnapp` | `~/repos/frostsnap` | **0** | 4 s |
| 5 | `flutter analyze` | `~/repos/frostsnap/frostsnapp` | **0** | 33 s |
| 6 | `flutter test` | `~/repos/frostsnap/frostsnapp` | **0** | 3 s |
| 7 | `find frostsnapp/lib/src/rust -type f \| sort \| xargs shasum -a 256` + `shasum frb_generated.rs` → `/tmp/cl-g0.txt` (34 files) | `~/repos/frostsnap` | **0** | <1 s |
| 8 | `just gen` | `~/repos/frostsnap` | **0** | 37 s |
| 9 | `just build-runner` | `~/repos/frostsnap` | **0** | 18 s |
| 10 | re-checksum → `diff /tmp/cl-g0.txt /tmp/cl-g1.txt` | `~/repos/frostsnap` | **0 — identical** | <1 s |
| 11 | `just gen` (second pair) | `~/repos/frostsnap` | **0** | 25 s |
| 12 | `just build-runner` (second pair) | `~/repos/frostsnap` | **0** | 18 s |
| 13 | re-checksum → `diff /tmp/cl-g1.txt /tmp/cl-g2.txt` | `~/repos/frostsnap` | **0 — identical** | <1 s |
| 14 | `python3 frostsnap_coordinator/tools/register-mk4-firmware.py --self-check` | `~/repos/frostsnap` | **0** | <1 s |
| 15 | `python3 frostsnap_coordinator/tools/register-mk4-firmware.py --print /Users/garykrause/repos/cold-snap/target/software-only/package/firmware-signed.bin` | `~/repos/frostsnap` | **0** | <1 s |
| 16 | `cargo check --target aarch64-apple-darwin` (first, warm) | `~/repos/cold-snap/hostcheck` | **0** | 2 s |
| 17 | `cargo test --target aarch64-apple-darwin` | `~/repos/cold-snap/hostcheck` | **0** | <1 s |
| 18 | `touch src/main.rs` then `cargo check --target aarch64-apple-darwin` (so warnings re-emit) | `~/repos/cold-snap/hostcheck` | **0** | 2 s |
| 19 | `git show HEAD:frostsnap_coordinator/src/device_profile.rs` | `~/repos/frostsnap` | **128** | <1 s |
| 20 | `git diff HEAD --numstat -- justfile frostsnapp/.gitignore frostsnapp/macos/Podfile.lock` | `~/repos/frostsnap` | **0** | <1 s |
| 21 | `git status --porcelain` | `~/repos/coldcard-firmware` | **0** | <1 s |

Results measured at #1-#21, in full:

- **#1** `/Users/garykrause/repos/frostsnap/frostsnapp/.fvm/flutter_sdk/bin/flutter`
  and `/…/dart`; `Flutter 3.38.5 • channel stable • revision f6ff1529fd`,
  `Tools • Dart 3.10.4 • DevTools 2.51.1`. The system 3.35.1 was not used.
- **#2** unchanged pre-existing blocker, reproduced a fourth time:
  `148 | pub fn external(index: NormalIndex) -> Self` /
  `error: could not compile frostsnap_coordinator (test "coldcard_msg_len") due to 1
  previous error`. `frostsnap_coordinator/tests/coldcard_msg_len.rs` is still `??`
  untracked protected user work and is not in this task's commit.
- **#3** `lib` 58 passed / 0 failed / 2 ignored; `device_profile_test` **13 passed**;
  `firmware_digest_test` 1; `mock_port_upgrade_routing` **6 passed**; `real_psbts` 5;
  `tofu_tests` 3. Total **86 passed, 0 failed**.
- **#4** **20 passed**, 0 failed.
- **#5** `No issues found! (ran in 29.5s)`.
- **#6** `+8: All tests passed!` — the 3 `wallet_create_keygen_ceiling_test.dart`
  cases plus the 5 pre-existing `wallet_create_duplicate_name_test.dart` cases.
- **#7/#10/#13** **34** generated files (33 under `frostsnapp/lib/src/rust/` plus
  `frostsnapp/rust/src/frb_generated.rs`). The state this agent *inherited* was
  already at codegen's fixed point, and two further full `just gen` +
  `just build-runner` pairs reproduce all 34 sha256s byte-identically. Codegen is
  reproducible **and** the committed tree is at its fixed point.
- **#14** `self-check ok: m13-synth-262656 announced =
  33b54101f5ab06c1db9f6a968b4687114926ccac1a5054821e8bbf6e1ab19489`.
- **#15** `58f1b3fe4cd2df9e38b93dda2a1224c8d7652ef89e0c10d38d5a46f04e39f441`,
  byte-identical to the sole registry line in
  `frostsnap_coordinator/src/coldsnap-mk4-registry.txt`. Digest provenance is
  measured from task 01's real signed artifact, not a constant.
- **#16/#17** exit 0, **0 warning lines**; `test result: ok. 2 passed`.
- **#18** exit 0 with the file's mtime bumped so rustc re-emits — still **0 warning
  lines**, which is what makes "0 warnings" a measurement rather than a cache
  artifact. `grep -n 'CHECK_BACKUP_SINCE\|allow(dead_code)'` confirms the repair:
  no `#[allow(dead_code)]` anywhere near it, the const live at `:1061`, consumed at
  `:2061` and `:2676`.
- **#19** exit **128** — `frostsnap_coordinator/src/device_profile.rs` does not exist
  at frostsnap's HEAD. This is the open CONFIRMED finding in the status block.
- **#20** `frostsnapp/.gitignore` 3/0, `frostsnapp/macos/Podfile.lock` 1/1,
  `justfile` 12/2 — the pre-existing protected diffs, unchanged.
  `frostsnap_coordinator/tests/coldcard_msg_len.rs` still `??`. cold-snap
  `?? prompts/` intact.
- **#21** 10 pre-existing entries in `~/repos/coldcard-firmware`, unchanged. That
  repo was never written by any agent in any round.

## C. Files changed — consolidated, and exactly what this close-out stages

### `~/repos/frostsnap` (primary, writable) — 12 Rust + 5 Dart edited, 6 new

New:
- `frostsnap_coordinator/src/device_profile.rs`
- `frostsnap_coordinator/src/coldsnap-mk4-registry.txt`
- `frostsnap_coordinator/tools/register-mk4-firmware.py`
- `frostsnap_coordinator/tests/device_profile_test.rs`
- `frostsnap_coordinator/tests/mock_port_upgrade_routing.rs`
- `frostsnapp/test/wallet_create_keygen_ceiling_test.dart`

Edited:
- `frostsnap_coordinator/src/lib.rs`
- `frostsnap_coordinator/src/firmware.rs`
- `frostsnap_coordinator/src/firmware_upgrade.rs`
- `frostsnap_coordinator/src/check_backup.rs`
- `frostsnap_coordinator/src/usb_serial_manager.rs`
- `frostsnapp/rust/src/api/device_list.rs`
- `frostsnapp/rust/src/api/firmware.rs`
- `frostsnapp/rust/src/api/coordinator.rs`
- `frostsnapp/rust/src/coordinator.rs`
- `frostsnapp/lib/wallet_create.dart`
- `frostsnapp/lib/device.dart`
- `frostsnapp/lib/device_list.dart`
- `frostsnapp/lib/settings.dart`
- `frostsnapp/lib/restoration/device_discovery.dart` (repair round reverted the gate;
  the file is now identical to HEAD apart from one comment recording why there is
  none)

Regenerated, **not staged because gitignored and untracked**: 33 files under
`frostsnapp/lib/src/rust/`, `frostsnapp/rust/src/frb_generated.rs`,
`frostsnapp/binding-rerun.sha256`.

NOT staged — pre-existing protected user work, left exactly as inherited:
` M frostsnapp/.gitignore`, ` M frostsnapp/macos/Podfile.lock`, ` M justfile`,
`?? frostsnap_coordinator/tests/coldcard_msg_len.rs`.

### `~/repos/cold-snap` (reference, writable)

- `hostcheck/src/main.rs` (+101/-32) — the TRAP-2 guard and its new test module.
  Touched only because `hostcheck/Cargo.toml:59` depends on the writable sibling
  `frostsnap_coordinator`, so deleting `FirmwareVersion::features()` broke it.
- `target/software-only/evidence/02-recognize-coldsnap-in-app.md` — this file,
  force-added (`target/` is ignored by `.gitignore:5`).
- `target/software-only/evidence/run.json` — force-added. **Disclosure:** this file
  arrived at close-out already dirty with a one-line change made by *task 05's*
  close-out — its own `"commit"` field backfilled from `null` to
  `1c9f5c2a98a3782ad11d046850b3dc22d398281e`, which a commit cannot contain about
  itself. Verified correct (`git -C ~/repos/cold-snap log -1 --format=%H 1c9f5c2` ==
  that value) and carried in this task's commit rather than reverted, exactly as
  task 03's backfill rode in task 05's. Task 02's own `"commit"` field will be
  `null` for the same reason.

NOT staged: `?? prompts/` (pre-existing user work).

`~/repos/coldcard-firmware`: never written, verified at #21.

## D. Consolidated finding ledger — every CONFIRMED finding, and whether repair fixed it

Round 1 (pre-repair) produced 5 + 6 findings across two re-runners, of which nine
were CONFIRMED. Round 2 (post-repair) produced 2 CONFIRMED + 2 PLAUSIBLE.

| # | round | verdict | finding | fixed by repair? |
|---|---|---|---|---|
| 1 | 1 | CONFIRMED | hostcheck TRAP-2 guard relaxed to a tautology; `CHECK_BACKUP_SINCE` dead behind a new undisclosed `#[allow(dead_code)]` that was what kept "0 warnings"; module header still documented a deliberate-failure reproduction that no longer reproduced | **YES** — guard split in two halves at `hostcheck/src/main.rs:2061`+`:2069`, `#[allow(dead_code)]` removed, header rewritten `:286-292`, new unit test `:2675-2694`. **Mutation-verified**: `CHECK_BACKUP_SINCE` lowered to 0.2.0 → `cargo test` exit **101** with the header's documented message. Re-confirmed at close-out #18: 0 warnings with warnings re-emitted, const live. |
| 2 | 1 | CONFIRMED | undisclosed native-development regression: a non-exact ESP32 dev build was hard-refused from restoration (making `recovery_flow.dart:438`'s firmware-upgrade branch unreachable for the only population it serves) and lost the wallet-create upgrade banner | **YES** — restoration gate removed entirely; `devicesIncompatible` (`wallet_create.dart:341`) narrowed to `!isCompatible() && !needsFirmwareUpgrade()`, restoring the banner |
| 3 | 1 | CONFIRMED | criterion 5 not met: no test covered the over-limit keygen *rejection*, only the ceiling arithmetic | **YES** — refusal extracted verbatim into `api/device_list.rs:187 check_keygen_group`, the single call `generate_new_key` makes at `coordinator.rs:401`; driven by `an_over_limit_keygen_is_refused_before_it_starts` and `unrecognized_firmware_is_refused_from_a_keygen`. No `FfiCoordinator` fixture needed. Re-runner 3 independently confirmed "criterion 5 is now genuinely closed". |
| 4 | 1 | CONFIRMED | evidence clippy row held a judgement in place of an exit code, and the judgement was false at the file granularity it claimed | **YES** — row corrected in place above; real exit **101** recorded, with the 7 warning sites named and the claim restated at region granularity |
| 5 | 1 | CONFIRMED | dev-app ESP32 upgrade announced `digest_with_signature()` on the legacy arm while `device/src/ota.rs:61-68` accepts only the body digest, so on the default *signed* bundle every device refused the image | **YES** — legacy dialect is now opt-in by positive identification (`device_profile.rs:114 needs_legacy_upgrade_message`), consumed at `firmware_upgrade.rs:133-144`. **Mutation-verified** (old semantics restored → `only_a_release_that_predates_the_modern_message_takes_the_legacy_dialect` FAILED). |
| 6 | 1 | CONFIRMED | check-backup silently dropped to the legacy full-25-word-re-entry path for every native dev device | **YES** — `device_profile.rs:134 needs_legacy_check_backup`, consumed at `check_backup.rs:50-56`; and `hostcheck` asserts the *same* predicate so harness and driver cannot drift |
| 7 | 1 | CONFIRMED | restoration newly refused for native dev ESP32s | **YES** — same fix as #2; the gate is gone |
| 8 | 1 | CONFIRMED | "The Rust APIs refuse regardless" was false — the restoration gate was UI-only, which this task's own shortcut list forbids | **YES, by deleting the gate** rather than by adding 20 guards to `api/recovery.rs`. No UI-only refusal remains. The five Rust enforcement points are `coordinator.rs:1081` (erase), `:1101` (erase-all filter), `api/device_list.rs check_keygen_group` (keygen), `usb_serial_manager.rs:704` (upgrade streaming), `check_backup.rs:49` (dialect). |
| 9 | 1 | CONFIRMED | no test asserted `PrepareUpgrade2` is selected, so the #5 regression was invisible to a green 16-test suite | **YES** — 3 new tests at `device_profile_test.rs:321`, `:358`, `:385`. Partially re-opened as #13 below. |
| 10 | 1 | PLAUSIBLE | the 12-device keygen ceiling is a fourth unbound copy of cold-snap's `MAX_PARTIES`, where cold-snap's own convention (`golden/mk4-staging-vectors.txt`) is a golden file both consumers read | **NO, deliberately.** `frostsnap_coordinator` cannot link `coldsnap_hal` (lockfile package collision, recorded in `hostcheck/Cargo.toml`), so the two sides cannot be bound by compilation. Drift hazard only: nothing fails today, the 12 is cited to `firmware/src/lib.rs:291` in code, and it is framed as a *declared envelope*, never as a measured result. Recorded, open. |
| 11 | 1 | PLAUSIBLE | an *unregistered* Mk4 in a dev app is `Unrecognized`, so the capability gate at `usb_serial_manager.rs:694-710` never fires for it and it can still be streamed the ESP32 image | **NO, deliberately.** Inherent to digest-only identification; refusing every unknown digest is what findings 2/5/6/7 prove breaks the native dev path that criterion 2 protects. Registering the image is the documented remedy. Disclosed by the implementers as an accepted limit, not a closed hole. Open. |
| 12 | 2 | CONFIRMED | the repair round's codegen-reproducibility row shrank to a diff of ONE file and ended on `just gen` with no following `just build-runner`, leaving 6 of 33 generated `.freezed.dart` files off codegen's fixed point | **CLOSED AT CLOSE-OUT BY MEASUREMENT, not by a source edit.** Close-out #7/#10/#13: the inherited tree is already at the fixed point across all **34** generated files, and two further full `just gen` + `just build-runner` pairs reproduce every sha256 byte-identically. Impact was low throughout (every one of those files is gitignored and untracked, so none entered any commit) and `flutter analyze` / `flutter test` were 0 before and after. Closed. |
| 13 | 2 | CONFIRMED | **the open one.** `hostcheck/Cargo.toml:59` is an unpinned path dependency on the writable sibling checkout, so cold-snap's committed `hostcheck/src/main.rs` cannot compile against frostsnap's HEAD — `device_profile.rs` does not exist there | **NOT FIXED; mitigated.** Verified at close-out #19, exit **128**. This close-out lands both repos in the same step so the pair is consistent, but a path dependency records no revision and nothing prevents a future mismatched checkout. Close-out may not edit source. **This is why the task is DEGRADED.** Breaks no acceptance criterion. |
| 14 | 2 | PLAUSIBLE | `esp32_upgrade_devices()` dropping every `CannotUpgrade` device composes with `upgrade_ports()`'s all-or-nothing rule so that an **all-native** chain carrying one `CannotUpgrade` ESP32 is refused wholesale, where HEAD broadcast to every ready port and did upgrade the devices behind it | **NO.** Confirmed by close-out source reading (`coordinator.rs:586-591` filter; `usb_serial_manager.rs:675` `on_port.iter().all(...)`) but **not executed** — the mixed-eligibility all-native fixture does not exist. It is the necessary cost of the isolation criterion 3 demands and is correct for a chained Mk4, but it is a narrowing of native behaviour that no implementer residual named. Recorded, open. |
| 15 | 2 | PLAUSIBLE | the test added for #9, `the_modern_message_announces_the_body_digest` (`device_profile_test.rs:358`), builds its protocol as `upgrade_protocol(&[])` — an **empty** device set, a configuration `run_firmware_upgrade` explicitly refuses — so no populated fixture lands on the modern arm | **NO.** Verified verbatim at close-out. Low severity: the byte-level assertion is real (`digest() != digest_with_signature()` for the signed fixture, body digest chosen), and the empty set is the degenerate "all predicates false" case that `only_a_release_that_predates_the_modern_message_takes_the_legacy_dialect` establishes for four *populated* device shapes. What is missing is one populated fixture at a release ≥ 0.0.2. Recorded, open. |

Nine of nine round-1 CONFIRMED findings fixed, two of those mutation-verified. One
round-2 CONFIRMED finding closed at close-out by measurement. **One CONFIRMED
finding open (#13), plus four PLAUSIBLE (#10, #11, #14, #15).**

## E. Acceptance criteria — consolidated, in the prompt's own wording

| # | criterion, verbatim from the prompt | verdict | basis |
|---|---|---|---|
| 1 | "Known Mk4 firmware can be named and included in wallet creation without an ESP32 digest match or a bundled Mk4 image; unrecognized firmware remains explicit" | **MET** (unit + analyzer level; the executed-app confirmation is assigned to task 04 by the prompt itself, not withheld here) | Rust: `a_recognized_mk4_is_ready_with_no_bundled_firmware`, `a_registered_mk4_is_compatible_without_any_bundled_image`, `unrecognized_firmware_is_not_compatible`; `is_compatible()`/`ready()` true and `firmware_name()` = `mk4 <rev>` for a registered Mk4 with `latest_firmware: None`. App: the name field no longer lives on the `upToDate` arm (`wallet_create.dart:681-743`), `devicesIncompatible` is profile-based (`:341`), `canGoNext` (`:368`) no longer blocks. Unrecognized renders "Incompatible firmware" + `unrecognized-xxxxxx`. Re-run green at close-out #3/#4/#5/#6. |
| 2 | "Native Frostsnap readiness and updates retain their existing supported behavior" | **MET**, with one disclosed behaviour change and one open PLAUSIBLE narrowing (#14) | The four regressions round 1 found here (#2, #5, #6, #7) are all fixed and the fixes are mutation-verified where mutable. Disclosed change: a released ESP32 *newer than the app* is now usable in wallet creation, because `is_compatible()` asks the profile and not update availability — reported in "Deliberate behaviour change" above rather than discovered. Open PLAUSIBLE: #14, the all-native mixed-eligibility chain. |
| 3 | "Mock-port tests prove ESP32 upgrade traffic never reaches Mk4/unselected ports, and the protocol does not wait for their acknowledgements" | **MET, unit-level. Explicitly NOT an integration run.** | `mock_port_upgrade_routing.rs`, **6 passed** at close-out #3, over the real `UsbSerialManager` and an in-memory fake `Serial`; unselected/Mk4 port byte counts asserted `== 0` in the same test that asserts `written(&esp32_port) > bin.size()`, so the fakes demonstrably record writes. Ack half: `the_protocol_waits_for_an_ack_from_every_device_in_its_set`, `an_mk4_left_in_the_upgrade_set_aborts_instead_of_hanging`. Mutation-verified: both gates removed → exactly the 3 routing tests redden, the other 3 stay green. |
| 4 | "Unsupported erase/attestation/update actions have clear API/UI outcomes" | **MET** | API: `erase_device` → `Err("mk4 … does not support erasing device data from the app")`; `erase_all_devices` addresses only the erase-capable subset; `run_firmware_upgrade` refuses a recognized profile without `update_mode` as the last gate before raw bytes; `capabilities().factory_attestation == Unsupported` and `FactoryAttestation` **has no success variant** in Rust or in the generated Dart. UI: erase row gated (`device.dart:190-216`, `settings.dart:1191`), attestation row an exhaustive `switch` with no default and no "passed"/"genuine" string (`:217-229`), update-unavailable renders "No update" vs "Incompatible" (`:308-337`, `device_list.dart:91-103`). Round-1 #8 corrected the one place this claim was false. |
| 5 | "Tests cover no bundled firmware, unsupported firmware, capability differences, mixed ports, and rejection of an over-limit keygen before starting it" | **MET, 5 of 5** | no bundled firmware → `a_recognized_mk4_is_ready_with_no_bundled_firmware`, `a_known_esp32_release_is_compatible_with_no_bundled_firmware`; unsupported → `unrecognized_firmware_is_not_compatible`, `an_unknown_digest_claims_no_feature_and_no_capability`; capability differences → `mk4_and_esp32_capabilities_differ`, `capability_differences_are_on_the_api`, plus the 3 dialect tests added for #9; mixed ports → `a_chain_carrying_an_unselected_device_is_not_streamed_to`, `an_esp32_upgrade_never_reaches_an_mk4_port`; over-limit keygen → **the refusal itself**, `api/device_list.rs check_keygen_group`, driven by `an_over_limit_keygen_is_refused_before_it_starts` and `unrecognized_firmware_is_refused_from_a_keygen`. The fifth was the round-1 #3 gap and is closed; re-runner 3 confirmed it independently. Caveat #15 (the modern-arm fixture is the empty set) is recorded open. |

**5 met / 0 not met / 0 unverifiable-without-hardware.** Nothing here is claimed as
hardware-verified; §F lists what only a bench can answer, but no *criterion* is
blocked on it.

## F. Forbidden-shortcut audit — result, by name

### Global list

| shortcut | result |
|---|---|
| "Never claim a command ran that did not run. Paste real exit codes." | **PASS.** Every exit code in this file is a process `$?` with output redirected to a file. The one place this was violated — a clippy row carrying a judgement instead of a status — was round-1 finding #4 and is fixed; the real **101** is recorded. Close-out re-ran 21 commands itself and pasted every code, including the two nonzero ones (#2 = 101, #19 = 128). |
| "Exit 0 with `SKIP` output is not a pass. `tools/pixel-check.py` does exactly this." | **PASS.** No check in this task emits SKIP. `tools/pixel-check.py` was not run, not cited, and is not part of this task's Checks block. No reference checkout is missing. |
| "Capture the process's status, never a filtering pipeline's. Never equate a warning-count pipeline with a successful compiler invocation." | **PASS, after a caught violation.** Sub-step 1 recorded that an early `cargo test … \| grep \| tail` reported `exit=0` for a run that in fact exited 101, and re-measured everything unpiped as a result. Close-out ran nothing through a pipe before reading `$?`. The hostcheck "0 warnings" claim is a warning-*line count* over a `cargo check` whose own exit was 0, taken twice, the second time after `touch src/main.rs` so warnings had to be re-emitted rather than replayed from cache (#18) — the count is corroboration, not the status. |
| "Historical figures are reproduction clues, never current evidence and never hardcoded constants: the 379,876 vs 379,880 byte gap, 508 passing tests, 60,512 bytes in a 65,536-byte arena, the 12-device keygen ceiling as a measured result." | **PASS.** None of 379,876/379,880, 508 or 60,512 appears anywhere in this task. The **12** appears as `max_keygen_devices: Some(12)` and is stated everywhere as a *declared envelope* cited to `firmware/src/lib.rs:291`, never as a measured result; no agent claims to have run a 12-device keygen. The one pinned constant is the golden vector `33b54101…`, which is a test vector in a file both consumers read, reproduced by `--self-check` this session. `58f1b3fe…` and 397,312 B were **measured** from task 01's artifact at close-out #15. Open PLAUSIBLE #10 is the *drift hazard* around the 12, disclosed rather than hidden. |
| "Never delete or relax a failing assertion to make a build pass. Fix the underlying cause." | **PASS, after a caught violation.** Round-1 #1 was exactly this — a guard relaxed into a tautology and its constant silenced with `#[allow(dead_code)]` — and it is fixed at the cause: the suppression is gone, the constant is live, the guard is two independent halves, and a mutation run reproduces the documented failure. The analyzer error at sub-step 2 was fixed by adding the missing import, not by a `switch` default; the `FactoryAttestation` switch is still exhaustive on purpose. `FirmwareVersion::features()` was *removed* because it **was** the `None => all()` fail-open the prompt forbids inheriting — the assertion count went up, from 16 to 86 passing tests in the scoped run. The pre-existing blocked test file was left byte-identical. |
| "No label of 'hardware verified' or 'safe for funds'." | **PASS.** Neither phrase appears. Every claim block in this file says "software/pre-bench checks passed", scoped, and says explicitly that it is not hardware verified and not safe for funds. |
| "Unit tests are never reported as an integration run. A mocked effect is never reported as a real one." | **PASS.** Stated at criteria 1, 3 and 5, in `mock_port_upgrade_routing.rs`'s own module docs, and in every claim block: no device, no port, no USB, fake `Serial` over `Vec<u8>`. Task 04 owns the virtual-device run. The one place a mock could be mistaken for the real thing — a real port that never answers is *evicted* after 5 s where the fake is not — is named as bench-only in §G. |

### Task-specific list

| shortcut | result |
|---|---|
| No `FirmwareFeatures::all()` inherited merely because a digest is unknown (Work item 3) | **PASS by deletion.** `FirmwareVersion::features()` no longer exists. `DeviceProfile::features()` answers `FirmwareFeatures::default()` — every flag false — for `Unrecognized`, pinned by `an_unknown_digest_claims_no_feature_and_no_capability`, which asserts both `== default()` **and** `!= all()` and was left unmodified through the repair round. `all()` survives in exactly one arm, the app's own byte-identical bundled image, which is a decision about our build and not a fallback for an unknown digest. |
| No ESP32 release identity assigned to a Mk4 to satisfy a version comparison (Work item 2) | **PASS.** `ColdsnapMk4 { revision: String }` carries no `VersionNumber`; `registered_digests_identify_as_mk4` pins this over the whole registry. The one site that *did* declare an ESP32 version for a cold-snap device, `hostcheck`'s `Phase::Quiz`, now declares `DeviceProfile::ColdsnapMk4` (`hostcheck/src/main.rs:2055`). No Dart edit synthesises a version; the firmware chip moved *away* from `FirmwareVersion.versionName()` to the profile's own label. |
| No fake factory-attestation success; report it as unsupported for Mk4 (Work item 4) | **PASS.** `FactoryAttestation` has two variants, `Unsupported` and `NotChecked`, and **no success variant** in Rust or in the generated `lib/src/rust/api/firmware.dart`. Nothing in the tree can produce a pass (`DO_GENUINE_CHECK = false`, `usb_serial_manager.rs:10`). The Dart row renders "Unsupported by this firmware — nothing to check" / "Not checked by this app"; no "passed", "genuine" or "verified" string exists on that surface. |
| Capability refusals enforced in the Rust APIs as well as the UI, so direct calls cannot bypass them (Work item 6) | **PASS, after a caught violation.** Round-1 #8 found the restoration gate was UI-only while the evidence claimed otherwise; the gate was removed, so no UI-only refusal remains. The five Rust enforcement points are `coordinator.rs:1081`, `:1101`, `api/device_list.rs check_keygen_group`, `usb_serial_manager.rs:704`, `check_backup.rs:49`. `run_firmware_upgrade` is the last gate before the raw bytes and refuses there too. The `eraseDevice` `catch` exists precisely because the Rust refusal is treated as the real one. |
| Do not hand-edit generated bindings; regenerate with the repo's recipes under the pinned SDK (Work item 7) | **PASS.** `just gen` + `just build-runner` only — at least eight full pairs across the session, two of them at close-out — always with the pinned 3.38.5 SDK first on PATH. All 34 generated files are byte-identical across runs (#10, #13) and the committed tree is at codegen's fixed point. Every one of them is gitignored and untracked, so no generated byte is in the commit and a hand-edit could not be smuggled in through the diff either way. |
| Do not link cold-snap's vendored Frostsnap crates into the upstream coordinator graph (Workspace rules) | **PASS.** No `Cargo.toml` was touched in either repo, in any round. `hostcheck/Cargo.toml:59` still points at the upstream path and nothing from `cold-snap/vendor/` or `coldsnap_hal` entered the frostsnap graph — which is also *why* open finding #13 exists: the two workspaces cannot be bound by compilation, only by landing together. |
| "This registry describes compatibility, not permission to install an image." / "Keep registration outside the image whose digest is being registered." / "Unknown digests must not become compatible automatically." / "A self-reported digest identifies compatibility, not authenticated hardware." | **PASS on all four.** The registry is read in exactly three places (`DeviceProfile::identify`, the Mk4 refusal in `check_upgrade_eligibility`, tests); it gates no signature check, is never consulted before installing anything, and both the file header and the tool docstring say so. It lives in `frostsnap_coordinator/src/`, outside any image. `Unrecognized.is_compatible() == false`, pinned by test. `ValidatedFirmwareBin::new`'s `UnknownSignedFirmware` gate was not touched. No new signing authority, authenticated manifest, release allowlist, factory certificate or coordinator share-proof gate was introduced; dev key 0 only. |

### Run-wide prohibitions

No physical device, serial port, USB enumeration, flashing, provisioning, OTP write,
real callgate invocation or public-network broadcast, in any round. No Bitcoin node
was started — this task needs none. `~/repos/coldcard-firmware` was never written
(verified at close-out #21: 10 pre-existing entries, unchanged) and was read only for
line-citation checks. All generated output lives under ignored paths. Nothing was
pushed; no PR was opened.

## G. Residual and bench-only questions, in the prompt's own terms

In the prompt's wording, with what remains unanswerable at the desk.

1. **"Known Mk4 firmware can be named and included in wallet creation"** — made
   *expressible* and asserted by Rust unit tests plus `flutter analyze`, but **never
   executed as an app path**. A widget test of the device row needs `RustLib`, for
   which `flutter test` has no native library. The prompt assigns that run to task
   04: "Task 04 supplies the real-app virtual-device integration test; unit tests
   here must not be reported as that run." A test that has never run is not evidence.
2. **"A connected Mk4 must neither receive ESP32 bytes nor be awaited for an ESP32
   upgrade acknowledgement."** Proven against a fake `Serial` whose ports are
   `Vec<u8>`. Not proven: that a real `UsbSerialManager` over a real pty/USB behaves
   the same under timing — a real port that never answers is **evicted** after the
   5 s read timeout (`usb_serial_manager.rs:302-311`), which the fake does not model.
   Bench only.
3. **"Preserve legitimate native-chain forwarding."** That
   `Destination::Particular` reaches a daisy-chained ESP32 is *argued* from
   `frostsnap_comms/src/lib.rs:143-155` and `device/src/esp32_run.rs:378-392`, not
   measured. Open PLAUSIBLE #14 is the other half of this sentence: an all-native
   chain carrying one `CannotUpgrade` device is now refused wholesale, derived from
   two code paths and not executed.
4. **"rejection of an over-limit keygen before starting it"** at the wire. 13-of-13
   `CertifyPlease` ≈ 3,091 B **fits** the 4,096-byte frame, so no transport error
   will ever produce the rejection — it is a coordinator-side policy check against a
   declared capability, and the device's own half is a refusal that is "an ack that
   does not arrive". A real coordinator's reaction to `Refusal::GroupTooLarge` at
   n = 13 is unmeasured, and so is any end-to-end run at n = 12.
5. **"expose its update operation as unavailable while preserving signing
   compatibility"** — Mk4 `features.upgrade_digest_no_sig: true` is **unreachable**
   for that profile (`update_mode: false` means the flag is never consulted) and is
   set defensively so a stray Mk4 cannot drag ESP32 peers onto the legacy message. If
   a Mk4 updater ever arrives, that value needs *measuring* rather than inheriting.
6. **"A self-reported digest identifies compatibility, not authenticated
   hardware."** An Mk4 whose digest is *not* in the registry is wire-indistinguishable
   from an ESP32 development build (the only magic-bytes-time discriminator is
   `DeviceSupportedFeatures { conch_enabled }`), so on a dev app it still lands in the
   `(None, None) => CanUpgrade` arm. Registering it is the documented remedy; refusing
   every unknown digest is what round-1 findings #2/#5/#6/#7 prove breaks the native
   dev path criterion 2 protects. Accepted limit of digest-only identification
   (finding #11), not a closed hole. Whether real hardware can be told apart at all
   without a factory certificate is a bench-and-provisioning question this task does
   not touch.
7. **"Unsupported erase … actions"** with mixed hardware: `erase_all_devices` is now
   addressed to the erase-capable subset, and the dialog says nothing about the
   skipped Mk4. Whether a daisy-chained Mk4 downstream of an addressed ESP32 forwards
   the `DataErase` cleanly and drops it is device behaviour, unexercised here.
8. **The evil-maid hole is untouched and stays open.** Key 0's private key is
   published, so a key-0 signature is a *format* check, not an authorisation check.
   The registry changes that in neither direction, and no agent in any round claimed
   otherwise.
9. **Not bench-only and must not be cited later as measured:** `begin_upgrade_firmware`,
   `enter_firmware_upgrade_mode` and `erase_device` each carry a typed, reasoned
   refusal that **no test drives** — only `run_firmware_upgrade`'s and
   `generate_new_key`'s are tested. That is a missing desk-level test, not a hardware
   limit, and it is recorded as known-open rather than deferred to a bench.

## H. Close-out claim

**Software/pre-bench checks passed**, scoped to: the Rust compatibility / capability /
profile model and its port-scoped upgrade routing, its frb surface regenerated
reproducibly with the repository's own recipes under the pinned Flutter 3.38.5 /
Dart 3.10.4 SDK, the Flutter/Dart callers of that API at analyzer and unit level, and
cold-snap's `hostcheck` TRAP-2 guard. Evidenced by 86 passing Rust tests in the
scoped coordinator run plus 20 in `rust_lib_frostsnapp`, `flutter analyze` with no
issues, `flutter test` 8/8, 34 generated files byte-identical across three
independent codegen runs, a digest reproduced from task 01's real signed artifact,
and `hostcheck` at 0 warnings / 2 tests with warnings forced to re-emit. Status
**DEGRADED** for one open CONFIRMED finding — `hostcheck`'s unpinned cross-repo path
dependency, mitigated by landing both repos in this one close-out — with four
PLAUSIBLE findings recorded open. One command in the prompt's Checks block exits 101
for a cause outside this task's diff: `frostsnap_coordinator/tests/coldcard_msg_len.rs`
is untracked protected user work that cannot compile at HEAD either, and it was not
touched, formatted, relaxed or deleted. Not hardware verified. Not safe for funds.
The real-app virtual-device integration run is task 04's and has not been done.

# Vendored dependencies

## frostsnap

Source: <https://github.com/frostsnap/frostsnap>
Commit: `0bbc18be3f9fb0a408b0c47a021816ece97f4661` (2026-08-11)
Upstream `master` has since moved to `0cdf09ec698ffedc51652997918c721a66bb6856`;
it touches none of the files modified below.
License: MIT — Nick Farrow, Adam Mashrique, Lloyd Fournier (`frostsnap/LICENSE`)

### Vendored crates

Only the hardware-independent crates are here. Everything ESP32-specific
(`device`, `cst816s`), display-specific (`frostsnap_widgets`,
`frostsnap_fonts`) and host-only (`frostsnap_coordinator`, `frostsnapp`) is
excluded — see `../PLAN.md` §3–4.

| Crate | LOC | Purpose |
|---|---|---|
| `frostsnap_core` | 13,998 | FROST state machine, nonce management, tweaks |
| `frost_backup` | 2,671 | share backup encoding |
| `frostsnap_comms` | 1,679 | wire protocol, bincode framing |
| `frostsnap_embedded` | 881 | flash storage (`NorFlash`-generic) |
| `macros` | 511 | `frostsnap_macros` proc macros |
| **Total** | **19,740** | |

### Verified build

```
cargo build --release          # target defaults to thumbv7em-none-eabihf
→ Finished `release` profile [optimized] target(s) in 9.11s
```

Output objects confirmed `ELF32 machine=0x28 (EM_ARM)`.

### Local modifications

Kept minimal and mechanical so upstream can be rebased.

| File | Change | Why |
|---|---|---|
| `frostsnap_core/Cargo.toml` | `default = []` (was `["coordinator", "serde_json"]`) | upstream default pulls `std`/`rusqlite`; unbuildable for the device |
| `frostsnap_core/Cargo.toml` | added `hex-conservative` dep | `bitcoin` 0.32.8 has no `alloc` feature, so its hex dep compiled with neither `std` nor `alloc` (144 errors). Not referenced by source. |
| `frostsnap_core/Cargo.toml` | dropped `schnorr_fun`'s `libsecp_compat_0_29` feature | decision 3 — see below |
| `frostsnap_comms/src/lib.rs` | added `impl EncapsBody { pub fn as_bytes(&self) -> &[u8] }` (one method, ~4 lines incl. docs) | **Additive only: no wire change, no behaviour change, nothing upstream reads it.** It exists so the *nested* decode can be bounded by the device. `WireCoordinatorSendBody::decode` re-enters `bincode` over these bytes under the crate-wide `BINCODE_CONFIG` (32 KiB) — measured: a **20-byte** inner blob provokes a **32,640 B** allocation there, remotely reachable. `coldsnap_hal::comms::decode_body` decodes them under `ENCAPS_DECODE_LIMIT = 20,480` instead. The field is private with no accessor, so there is no way to do this without the one-line addition. **RE-APPLY ON EVERY RE-VENDOR** — without it `hal/src/comms.rs` will not compile, so the failure is loud, not silent. |
| `frostsnap_comms/src/lib.rs` | `MAX_MESSAGE_ALLOC_SIZE` **`1 << 15` → `20_480`** (one literal, `:54`) | **RE-APPLY ON EVERY RE-VENDOR — and unlike `as_bytes()` this one fails SILENTLY if you forget: the build stays green and the bound simply reverts to 32 KiB.** `the_vendored_budget_admits_every_legitimate_claim_and_refuses_the_historical_one` (`hal/src/comms.rs`) is the pin that catches it. 20,480 = `coldsnap_hal::comms::ENCAPS_DECODE_LIMIT`, so one number bounds both encapsulated legs. Cleared by measuring the direction that had never been measured: device→coordinator peaks at **17,664 B** debug / 15,360 release for the largest frame `FRAME_LIMIT` admits (61 nonces in one segment, frame 4,086 B), and effective budget is 20,472 (bincode's `Limit<L>` charges the 8-byte length claim), so nothing legitimate is refused in either direction in either profile. Decode-side only — bincode's encoder never reads the limit, so **zero wire bytes change** and no coordinator agreement is needed. **Scope: nothing device-side decodes that direction today**, so this is a pre-emptive bound, not the repair of a live exposure; it changes neither flash nor heap. Do not lower further: 16,384 misses 17,664, and 8,192 refuses a real 30-nonce `NonceResponse` in debug while admitting it in release. Derivation: `tools/research-scratch/device_send_alloc_measure.rs`; PLAN.md §9 item 7(d). |
| `frostsnap_core/Cargo.toml` | added `frostsnap_comms = { workspace = true, features = ["coordinator"] }` to **`[dev-dependencies]`** | so `tools/research-scratch/wire_size_measure.rs` can be copied into `tests/` and run (it needs `mod common`, which lives there). `frostsnap_comms` depends on `frostsnap_core`, so this is a **cycle** — legal for a dev-dep, and Cargo resolves it. Dev-only: it cannot reach the device graph. Kept rather than reverted because the measurement is the source of `../PLAN.md` §7's table and has already been wrong once. |
| `frostsnap_core/src/tweak.rs` | added `bip341_taptweak_key_only()`; `AppTweak::derive_xonly_key` uses it instead of `bitcoin::taproot::TapTweakHash` | decision 3 — see below |
| `frostsnap_core/src/tweak.rs` | `to_libsecp_key` default body: `PublicKey::from_slice(&self.to_key().to_bytes())` (was `self.to_key().into()`) | the `From` impl came from `libsecp_compat_0_29`; identical bytes |
| `frostsnap_core/src/bitcoin_transaction.rs` | `LocalSpk::spk`: `XOnlyPublicKey::from_slice(&x.to_xonly_bytes())` (was `x.into()`) | same; this is the taproot address path |
| `frostsnap_core/src/tweak.rs`, `bitcoin_transaction.rs` | added tests `bip341_taptweak_vectors`, `local_spk_regression`; 2 conversions in `bip32_derivation_matches_rust_bitcoin` | validate the above |
| `frostsnap_comms/Cargo.toml` | `default = []` (was `["coordinator"]`) | same — pulls `std` + `rsa` |
| `frostsnap_embedded/Cargo.toml` | `default = []` (was `["std"]`) | runs on-device |
| `frost_backup/Cargo.toml` | `default = ["bincode"]` (was `["cli"]`) | upstream default pulls `clap`/`std`/`miniscript` |
| `frost_backup/Cargo.toml` | dropped `frostsnap_coordinator`, `miniscript`, `bitcoin` dev-deps | not vendored; not buildable for the target |

#### Panic-site fixes (`../DECISIONS.md` decision 6, `../PLAN.md` §6.3)

Under `panic = "abort"` plus a reset-based panic handler, a *deterministic* panic
is a reset loop — a brick. Every row below is a panic that a coordinator (or a
real flash error) could reach. Upstream has fixed **none** of these: `git diff
0bbc18be origin/master` over `device.rs`, `message.rs`, `sign_task.rs`,
`device_nonces.rs` and all of `frostsnap_embedded/src` is empty as of
`0cdf09ec698ffedc51652997918c721a66bb6856`, so there is no upstream fix to adopt
verbatim.

| File | Change | Why |
|---|---|---|
| `frostsnap_core/src/message.rs` | `GroupSignReq::check` rejects `agg_nonces.len() != sign_task.n_sign_items()` (`:112-118`) | **priority 1.** `device.rs:491` indexes `agg_nonces[i]` per sign_item. A coordinator sending fewer nonces than sign_items panicked the device post-consent. Fixed at the validation seam so the invariant holds by construction for every `GroupSignReq<CheckedSignTask>` holder. |
| `frostsnap_core/src/sign_task.rs` | added `CheckedSignTask::n_sign_items()` (`:123`) and `SignTaskError::WrongNumberOfNonces { got, expected }` (`:198`, Display `:227`) | supports the above; additive variant, no existing match arm changes |
| `frostsnap_core/src/device_nonces.rs` | new `pub const MAX_NONCE_SKIP_BATCHES: u32 = 64` (`:28`) | bounds how far ahead of us a coordinator may claim to be. 64 × `NONCE_BATCH_SIZE` (30, `device.rs:32`) = 1,920 derivations; unbounded it is ~4.29e9. |
| `frostsnap_core/src/device_nonces.rs` | `reconcile_coord_nonce_stream_state` clamps the job to one `nonce_batch_size` and uses `try_nonce_task` (`:272`) | **pre-consent**, and the worst site found: a single `OpenNonceStreams` with `index = u32::MAX` panicked in `nonce_task` with no user prompt at all. Also stopped a `Vec::with_capacity(length)` × 288 B/nonce ≈ 1.2 TB request. |
| `frostsnap_core/src/device_nonces.rs` | `SecretNonceSlot::try_nonce_task` added (`:598`); the 3 panics it replaced became `NoncesUnavailable`; `nonce_task` retained as a panicking wrapper (`:639`) | keeps upstream's callers compiling; the wrapper's only in-tree caller is a test |
| `frostsnap_core/src/device_nonces.rs` | slot read (`:293`), nonce-iterator exhaustion, and PRG-state exhaustion return `NoncesUnavailable` instead of `.expect(…)` | `.expect("tried to sign with nonces out of range")` was reachable post-consent with a claimed index at the end of the stream |
| `frostsnap_core/src/device_nonces.rs` | skip bound at `:336-341` → `NoncesUnavailable::SkipTooLarge { skip, max }` | without it a large claimed index makes the device grind one ChaCha20+EC derivation per skipped index. No panic, so no reset and no reboot counter — only the watchdog escapes. Negative control: removing the bound takes the regression test from ms to **>60 s**. |
| `frostsnap_core/src/device_nonces.rs` | write read-back verification (`:412-420`) returns `NoncesUnavailable::WriteVerifyFailed` | class (b): reachable on a real flash error. Safe to `Err` here — `device.rs:507` maps it to `ActionError::StateInconsistent` and aborts **without emitting a signature share**, and the cached-signature branch keys on `session_id`, so a retry re-writes rather than re-deriving and cannot advance the index twice. |
| `frostsnap_core/src/device_nonces.rs` | `NoncesUnavailable` gained `SlotUnreadable`, `WriteVerifyFailed`, `SkipTooLarge` (`:671-685`) + Display arms | additive |
| `frostsnap_core/src/device_nonces.rs` | `NonceJob::n_nonces_to_generate` / `n_derivations_remaining` use `saturating_sub` | were subtraction, i.e. a debug-build overflow panic |
| `frostsnap_core/src/device_nonces.rs` | stream-id `assert_eq!` at `:301` **left in place**, comment added | class (a): unreachable, the slot is reached through an `AbSlots` lookup keyed by that same id. Priority 3 — comment, no code churn. |
| `frostsnap_embedded/src/ab_write.rs` | `AbSlot::try_write` returning new `pub enum AbWriteOutcome { Committed, CommittedSingleCopy(NorFlashErrorKind), NotCommitted(NorFlashErrorKind) }` (`:56`, `:214`) | **highest-value class (b) site.** `AbSlot::write` erases+writes **twice**; a flash error between the copies leaves a value that *is* committed and readable. A bare `Result` cannot say that, and collapsing it to `Err` would make callers discard good nonce state — nonce loss/reuse is the one failure that leaks the secret share. Writes the **older** slot first so `NotCommitted` is truthful. |
| `frostsnap_embedded/src/ab_write.rs` | index exhaustion → `NotCommitted(OutOfBounds)` via `checked_add` (`:68`) | was an unchecked increment past the `u32::MAX` empty-slot sentinel |
| `frostsnap_embedded/src/ab_write.rs` | `AbSlot::write` kept as a thin panicking wrapper over `try_write` (`:100`) | upstream's 4 callers all live in the non-vendored `device` crate and compile untouched |
| `frostsnap_embedded/src/ab_write.rs` | `Slot::try_write -> Result<(), NorFlashErrorKind>` (`:158`); `Slot::write` now `#[cfg(test)]` (`:182`) | `BincodeFlashWriter`'s `Drop` asserts `buf_index == 0` (`partition.rs:318-325`), so an early return holding buffered bytes panics in the destructor. `flush()` takes self by value and zeroes `buf_index` before it can fail, so it is called before the encode result is inspected. |
| `frostsnap_embedded/src/ab_write.rs` | `read_index` `.expect("should always be able to read an int")` → `.ok()?` (`:186`) | an unreadable slot is a normal outcome, not an invariant violation |
| `frostsnap_embedded/src/ab_write.rs` | `AbSlot::new` given a `# Panics` doc (`:17`) | class (a), priority 3: comment only |
| `frostsnap_embedded/src/test.rs` | added `FaultyNorFlash` / `FaultyError` (`:64-172`) | `TestNorFlash::Error = Infallible`, so **no** flash-error path in this crate was reachable from a host test. Schedules refusals by operation count, so a test can target "the second erase of this write" without knowing the layout. |
| `frostsnap_core/tests/agg_nonce_count.rs` | new, 4 tests | priority-1 regression suite |
| `frostsnap_core/tests/nonce_index_bounds.rs` | new, 7 tests | `device_nonces.rs` regressions, split pre-consent (`OpenNonceStreams`) vs post-consent (`sign_ack`). Calls `sign_ack` directly: the shared harness `unwrap()`s it (`tests/env/test_env.rs:220-223`), which would turn the `ActionError` under test into a harness panic indistinguishable from the device panic being ruled out. Includes positive controls so the bounds cannot be "fixed" by refusing everything. |
| `frostsnap_embedded/src/ab_write.rs` | 5 new tests (of 8 in `ab_write::test`) | fault-injected: erase refused on the first slot, fault between the two copies, write refused after a successful erase, index exhaustion, torn-write index reuse |
| `frostsnap_embedded/src/nonce_slots.rs` | `NonceAbSlot` is now a struct with a `last_write: Option<AbWriteOutcome>` field (`:9-20`); `write_slot_versioned` calls `AbSlot::try_write` and records the outcome (`:70-72`) instead of `AbSlot::write` (`:158` old); new `last_write_outcome()` accessor (`:44`) | **found at integration, not by any single-module agent.** `ab_write.rs` was made non-panicking, but its one in-tree caller — the nonce path — still went through the panicking wrapper, so the whole `try_write` refactor was bypassed on the exact path it was written for. `AbSlot::write` panics on **both** `CommittedSingleCopy` and `NotCommitted` (`ab_write.rs:100-110`), and under `panic = "abort"` a `PROGERR`/`WRPERR` mid-nonce-update became a reset loop. Worse, `CommittedSingleCopy` means the advance **did** reach flash, so halting there loses the fact that the nonce was consumed. Read semantics are unchanged, so `device_nonces.rs:412-420`'s read-back check still catches a `NotCommitted` and aborts without emitting a share. |
| `frostsnap_embedded/src/nonce_slots.rs` | 3 new tests in a new `nonce_slots::test` module (`:75-210`) | round trip, refused write reports rather than panics, single-copy write reported as committed. Uses a local `CountingRng` (SplitMix64) rather than `rand_chacha`: this crate has no such dependency and a dev-dep added to a vendored manifest is a divergence to re-apply on every rebase. |
| `frostsnap_core/src/bitcoin_transaction.rs` | `fee()` sums with `try_fold`/`checked_add` instead of `.sum::<u64>()` (`:252`) | **a validation *bypass*, not just a panic — and the only one of these the device executes today.** `fee()` is the device's sole arithmetic check on a sign request: `WireSignTask::check` rejects `fee().is_none()` (`sign_task.rs:88-90`) pre-consent, reached from `device.rs:331-333` → `message.rs:112` on a wire message with no user interaction. `overflow-checks = false` in the shipped profile (`../Cargo.toml:82`) made the overflow **silent**, so inputs summing past `u64::MAX` returned `Some(<wrapped>)` and the check passed a transaction it exists to reject. `[profile.dev]` omits the key, so it defaults to `true`: the same message *panicked* under `cargo test` and *wrapped* in firmware — the two profiles disagreed about what the bug was. PLAN.md §4.2 already flagged the weaker form ("the displayed fee is coordinator-controlled"); the wrap makes it forgeable rather than merely unverified. |
| `frostsnap_core/src/bitcoin_transaction.rs` | `net_value() -> Option<BTreeMap<RootOwner, i64>>` (`:275`); both `i64::try_from(..).expect("input ridiciously large")` → `.ok()?`, and `-=`/`+=` → `checked_sub`/`checked_add` | two panics on wire-supplied `u64`. **The `fee()` guard does not protect these, and the distinction matters:** `fee()` bounds only the *difference* between the sums, never the magnitudes. One input of `2^63` and one output of `2^63` gives `fee() == Some(0)`, so `check` accepts it, and `i64::try_from(2^63)` still fails. Fixing `fee()` alone would have left this reachable. `Option` rather than saturating because this feeds the amounts shown for approval, and a saturated total is a plausible-looking wrong number on a consent screen. |
| `frostsnap_core/src/bitcoin_transaction.rs` | `user_prompt() -> Option<PromptSignBitcoinTx>` (`:300`); both `expect`s → `?` | `Address::from_script` returns `Err(UnrecognizedScript)` for anything not p2pkh/p2sh/witness-program — OP_RETURN, bare/P2PK, bare multisig, the empty script (bitcoin 0.32.8 `address/mod.rs:567-590`) — and **nothing** validates a foreign output's spk. `WireSignTask::check` looks at owner keys, that something is ours to sign, and `fee()`; its own test asserts a `ScriptBuf::new()` output is *accepted* (`sign_task.rs:343-350`). Unreachable today only because `user_prompt` has zero callers (upstream's are the non-vendored display crates); the device hands the UI the raw `TransactionTemplate` (`device.rs:377-381`), so PLAN.md phase 5's sign-approval screen would have reset-looped on a legal transaction. Deliberately **not** fixed by rejecting such outputs in `check`: OP_RETURN is legitimate Bitcoin and refusing to sign it is a policy call, not a safety fix, and it would contradict `sign_task.rs:332-352`. One unrenderable recipient fails the whole prompt rather than being dropped from the list — a consent screen that omits a recipient is worse than one that refuses to appear. |
| `frostsnap_core/src/bitcoin_transaction.rs` | 12 new tests in a new `wire_value_bounds` module (`:600`) | Builds templates from **raw wire values**, bypassing the builder API: the builder derives `value` from a real `TxOut` and so cannot express these, but the wire format can, and the wire format is what an attacker controls. Includes the `2^63`/`2^63` case proving `fee()`'s guard does not cover `net_value`, positive controls so the bounds cannot be "fixed" by refusing everything, and `check_rejects_a_template_whose_fee_overflows` at the seam that actually protects signing today. |

**Flash cost.** Re-measured the same way as the decision-3 table below
(`CARGO_PROFILE_RELEASE_LTO=false` into a clean target dir, then
`tools/measure-flash.py`): `ALL, as built` went 844,229 (59.2%) → 849,330
(59.6%), i.e. **+5,101 bytes**. That is an upper bound — the shipped profile is `lto =
"fat"` and these are new `Display` arms and error enums, exactly the kind of
thing LTO collapses.

The `nonce_slots.rs` change above costs **0 bytes**, measured: reverting
`write_slot_versioned` to `self.slot.write(&value)` and rebuilding into a clean
target dir gives the same `ALL, as built` of 856,872 to the byte. `try_write` was
already in the binary — `write` is a wrapper around it — so this only stops
calling the panicking wrapper.

That 849,330 predates the `coldsnap_hal` crate being implemented. The **whole
integrated workspace** measured **860,592 (60.4%)** at the end of phase 3, i.e.
**+16,363 over the 844,229 phase-0 baseline**. (This ledger is the phase-3-era
record and is **not** maintained as the current figure: as of 2026-08-19 a clean
re-measure of the whole tree is **860,898**. PLAN.md §10 is the authority.) Split, all measured into separate clean target dirs:

| build | `ALL, as built` |
|---|---|
| vendored crates only (`-p frostsnap_core -p frostsnap_comms -p frostsnap_embedded -p frost_backup`) | 844,848 |
| whole workspace (adds `-p coldsnap_hal`) | 856,872 |
| the same, after the three `bitcoin_transaction.rs` fixes | 857,125 |
| the same, after phase 3 (`comms.rs` + `usb.rs`) | **860,592** |
| the same, clean re-measure 2026-08-19 (adds `decode_body`, the lowered `MAX_MESSAGE_ALLOC_SIZE`) | **860,898** |

**Every row above is an rlib sum with LTO off, and as of 2026-08-24 the linked
image says those rows overestimate by 8.6×.** `firmware/` links at **99,684 B =
6.99%** of `FLASH_TEXT`, because LTO plus `--gc-sections` keeps only what is
reachable. Read the table for what it is good for — the *marginal* cost of a change,
which is why the +253 figure below is still the meaningful one — and not as a
prediction of image size. The linked figure is itself a floor, not the budget: no
`FrostSigner` is constructed yet, so keygen and signing are unreferenced and
`llvm-nm` finds exactly **1** `rust-bitcoin` symbol against that crate's 327,408-byte
rlib row. Neither number is the answer; the one measured after signing is reachable
will be.

**The three `Option` returns cost +253 bytes** — 0.02 pt of `FLASH_TEXT`. Worth
recording, because "it will bloat the image" is the usual argument for leaving an
`expect()` in embedded code, and at this budget the argument does not survive
contact with a measurement.

`libcoldsnap_hal.rlib` is **15,565 bytes** (14,612 `.text` + 953 `.rodata`) — it was
12,098 (11,420 + 678) before phase 3, so `comms.rs` + `usb.rs` together are
**+3,467 bytes**, and that rlib accounts for the whole workspace delta to within 0
bytes both times. Do **not** read 15,565 as the on-device cost of the HAL: LTO is
off for this measurement, so each rlib carries its own copy of the
`sha2`/`rand_chacha`/`bincode` generic instantiations it uses, and `lto = "fat"`
collapses them. It is an upper bound.

Negative controls, all measured: collapsing `CommittedSingleCopy` into
`NotCommitted` fails exactly 1 of 14 embedded tests; removing the skip bound
makes `huge_skip_is_refused_rather_than_ground_through` run >60 s; reverting the
reconcile clamp re-panics in `nonce_task` and fails
`large_claimed_index_does_not_request_unbounded_work`; reverting
`write_slot_versioned` to `AbSlot::write` fails exactly 1 of the 17 embedded
tests, panicking at `ab_write.rs:109:48` with `ab-write committed nothing: Other`
— i.e. the halt the change removes is reachable, not theoretical.

Host-side tooling must request `coordinator` explicitly.

`frostsnap_core`'s full test suite builds and passes — **63 tests across 13
binaries** (51 before the `bitcoin_transaction.rs` work; 44 before the panic-site
work; 40 before `agg_nonce_count.rs`) with `--features coordinator` (that feature
is required; the vendored `default = []` leaves the integration tests unable to
resolve `frostsnap_core::coordinator`). `frostsnap_embedded --features std` is
**17 tests** (14 after the `ab_write.rs` work, 9 before it; the last 3 are
`nonce_slots::test`) — and **15 without `std`**, up from 7, which is the number
that matters, because no-std is the configuration the firmware ships.

**Verified by compiling, 2026-08-14.** These changes were written in a session
where the shell never responded (every command, including a bare `echo`, timed out
with empty output) and both rust-analyzer and the LSP were unavailable, so for two
sessions they were verified by reading the crate sources at the pinned versions
only. The shell came back: **63 tests pass, all 12 in `wire_value_bounds`**, and
`cargo clippy --all-targets` and `cargo doc` are clean on the crate. Both of the
specifics that reading could not settle came out clean — `ScriptBuf::new_op_return([])`
does infer `[u8; 0]` with no explicit type (the length-0 `from_array!` arm at
`push_bytes.rs:184-189` is the only `AsRef<PushBytes>` impl that can unify with
`[?T; 0]`), and `schnorr_fun::fun::prelude::*` does **not** collide with
`bitcoin::hashes::Hash` in the new module, as the sibling `local_spk_regression`
(`:556`) suggested but could not prove.

Files **moved out** of the vendored tree to `tools/research-scratch/`:
`wire_size_measure.rs`, `zz_claim3_crossover.rs`, `inner_alloc_measure.rs` (the
coordinator->device inner decode leg; carries its own copy-in/delete commands and a
per-row provenance caveat -- read that header before quoting its 5,120 B figure) and
`device_send_alloc_measure.rs` (the device->coordinator leg; the measurement that
cleared the `MAX_MESSAGE_ALLOC_SIZE` change above). They were added by an
earlier cold-snap research session, are **untracked** in the upstream checkout,
and wanted a `frostsnap_comms` dev-dependency `frostsnap_core` did not declare —
26× `E0432`, which broke `cargo test -p frostsnap_core` wholesale rather than
just skipping. Not upstream code, so moving them is not a divergence.

That dev-dependency **is** now declared (row above), so `wire_size_measure.rs`
compiles when copied back — which is the only way to run it, because it needs
`mod common` from the vendored `tests/` directory. Copy it in, run it, delete it;
the exact commands are in the file's own header. It must not be left there: the
reason it was moved out has not changed, only its dependency has.

**Phase 3 re-ran it, and its results were wrong in a way worth recording.** Every
line it labelled "FULL WIRE" was the message **body** — a `WireCoordinatorSendBody`
or `WireDeviceSendBody` — with no `ReceiveSerial<D>` envelope, and nothing puts a
bare body on the wire. The real envelope is **+36 B upstream** (`Message` tag 1 +
`Destination::Particular` tag 1 + set length 1 + `DeviceId` 33) and **+34 B
downstream** (tag 1 + `DeviceId` 33). Not the "+128 B upstream" this file claimed
until 2026-08-16: that 128 is the whole distance from a bare `GroupSignReq` to the
full frame on the `RequestSign` row — envelope *plus* `DeviceSignReq`, two message
tags, the `Core` tag and the `EncapsV0` wrap — so it is per-row, not the envelope.
`../PLAN.md` §7's transport table was built from those figures and
therefore understated every message; the correction flips two rows from "fits" to
"over", including `RequestSign` at 10 inputs, which had been recorded as fitting
with 44 bytes to spare and is in fact 84 over.

`frost_backup/tests/descriptor_match.rs` still does not build (wants
`frostsnap_coordinator` + `miniscript`, neither vendored) and remains excluded.

### Decision 3: pure-Rust BIP-341 tweak (applied)

`AppTweak::derive_xonly_key` previously computed the taproot tweak with
`bitcoin::taproot::TapTweakHash::from_key_and_tweak(k.to_libsecp_xonly(), None)`,
round-tripping the key through the C libsecp256k1 `XOnlyPublicKey` type to reach
a hash that does no EC math at all. It now calls `bip341_taptweak_key_only`,
which uses `secp256kfun`'s `Tag` — the same BIP-340 midstate construction
`schnorr_fun` already uses for `BIP0340/challenge`.

Dropping the `libsecp_compat_0_29` feature broke exactly **four** sites (two in
the lib, two test-only), all pure byte round-trips, all fixed above. Note this is
fewer and different from the six `PLAN.md` §2.2 predicted: `tweak.rs:187` — named
there as "the load-bearing one" — did not break, while `bitcoin_transaction.rs`
(`LocalSpk::spk`, the address path) was not listed at all.

Validation, all on `thumbv7em-none-eabihf` + `aarch64-apple-darwin`:

- `tagged_hash_matches_published_tweaks` / `output_keys_match_published_vectors`
  pin internal key → tweak → output key against 4 published key-path-only
  vectors: BIP-341 `scriptPubKey[0]` (the only official vector with
  `scriptTree: null`) plus BIP-86 `m/86'/0'/0'/{0/0, 0/1, 1/0}`. Hardcoded, so
  they survive `bitcoin`'s eventual removal.
- `local_spk_regression` pins two full `LocalSpk::spk()` scriptPubKeys, computed
  independently with a from-scratch Python secp256k1/BIP-32/BIP-341
  implementation.
- `matches_rust_bitcoin_over_many_keys` cross-checks 256 curve points against
  `TapTweakHash` while `bitcoin` is still present; delete it with that dep.
- Negative control: flipping one bit of the `"TapTweak"` tag fails **all four**
  new tests (3 in `tweak.rs` + `local_spk_regression`) and neither of the two
  pre-existing ones — 4 passed, 4 failed. The lib-test count went **4 → 8**.

**Known gap in the surviving coverage.** All four hardcoded vectors are fed in
already even-Y, so `tweak.rs:342`'s `into_point_with_even_y()` is a no-op for
them: deleting BIP-341's `lift_x` leaves `output_keys_match_published_vectors`
**passing**. Only `matches_rust_bitcoin_over_many_keys` and
`local_spk_regression` catch it, and both depend on `bitcoin`. Both production
`LocalSpk` vectors have odd-y internal keys, so this is the common path. Add an
odd-y assertion before that dep is ever dropped. Also: `bitcoin_transaction.rs:524`
now raises `clippy::uninlined_format_args` (test-only).

**Corrections to `PLAN.md` §2.2, which overstated the benefit.** Measured with
`CARGO_PROFILE_RELEASE_LTO=false` into clean target dirs:

| | before | after |
|---|---|---|
| `ALL, as built` | 845,414 (59.3%) | 844,229 (59.2%) |

That is **−1,185 bytes, not −97KB**, and the C toolchain requirement is *not*
removed. `bitcoin` 0.32.8 declares `secp256k1` non-optionally, so
`secp256k1-sys` 0.10.1 + `cc` stay in the graph and `libsecp256k1.a` is
byte-identical before and after (sha256 `0358790a…`); verified by pointing `CC`
at a nonexistent path, which still fails inside cc-rs. `cargo tree -i
secp256k1@0.29.1` now shows `bitcoin` as the sole parent — `secp256kfun` is
gone, which was the actual point of decision 3. A C-free build needs `bitcoin`
dropped (blocked by decision 4, and by `TapSighash` in
`bitcoin_transaction.rs`).

### Rebasing onto a newer upstream

```sh
git -C /path/to/frostsnap fetch && git -C /path/to/frostsnap checkout <new-rev>
for c in frostsnap_core frostsnap_comms frostsnap_embedded frost_backup macros; do
  rsync -a --exclude target /path/to/frostsnap/$c/ vendor/frostsnap/$c/
done
# then re-apply the manifest changes in the table above
```

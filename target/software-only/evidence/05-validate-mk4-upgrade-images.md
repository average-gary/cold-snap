# 05 — Validate Mk4 upgrade images and the transfer contract

## Status: DEGRADED

**Reason.** All 5 acceptance criteria are met and every check passes for the right reason
(13 commands re-run at close-out, exit codes below, logs on disk). DEGRADED because **two
CONFIRMED findings are open** and close-out may not edit source:

1. `hal/src/psram.rs:89`, `hal/src/psram.rs:520` and `firmware/src/upgrade.rs:5` still
   assert that `psram::check_burn_len` "has no caller outside this file's own tests" /
   "no caller in any build that can reach hardware". This task's own new code falsifies
   that: `hal/src/image.rs:164` calls it in ordinary non-`cfg(test)` code, reached on the
   device by `upgrade::Stager::installable` and on the host by `checkfw` R14. Three stale
   comments, stale in the *unsafe* direction (they under-report the reachable surface).
   Nothing burns — 18/7 is still unbound and `installable` takes `&self` — so this is a
   documentation-accuracy defect, not a behavioural one. Breaks no acceptance criterion.
2. The two host-side negative fixtures
   (`target/software-only/fixtures/05/misaligned-397824.bin`,
   `.../wrong-family-mk5-only.bin`) have **no recorded minting recipe**: a repo-wide grep
   outside `target/` for either filename returns nothing, and both files live under
   ignored `target/`, so a `cargo clean` or fresh checkout makes those two exit-1
   demonstrations unrepeatable. Bounded impact: the re-runner recovered the recipe by
   byte-diffing against the real artifact (misaligned = one byte at offset 16281 plus 512
   bytes of `0xff` pad; wrong-family = one byte at offset 16288, `hw_compat 0x28 -> 0x20`),
   and the equivalent negative coverage is in tracked source that the prompt's own Checks
   block runs (`hal/src/image.rs:235`, `firmware/src/upgrade.rs:1459`, `:1484`). Breaks no
   acceptance criterion.

The only claim available from this work is **software/pre-bench checks passed** for
cold-snap's Mk4 image/transfer contract. Not "hardware verified". Not "safe for funds".
Nothing ran on silicon; no device, port, flash, provisioning, OTP write or real callgate
was involved.

**Provenance.** Task 05 had *no implementation at all* when the repair round started (no
evidence file, no ledger entry, no commit, no working-tree change): nine CONFIRMED findings
were "unmet by absence". All nine were fixed in the repair round of 2026-09-22. The two
findings above are what the post-repair re-run found in the finished tree.

**Tamper baseline at close-out.** cold-snap on branch `software-only/run-2026-09-21`,
parent commit `89a102195993987359f531518e1c28c95923a05b`.
`~/repos/coldcard-firmware` at `0431fd2b00095a9ac0e5df4a023acd6eaf6a15a6` with
`status --porcelain | wc -l` = **10**, the same 00-preflight baseline — **not written**.
`~/repos/frostsnap` at its run-start HEAD `9d7f55bf52e3fad47582a9ce39e1823a5d9c5052` with
exactly its four pre-existing user-work paths dirty — **no frostsnap file was touched**
(that is a decision; see F8). `prompts/` left untouched as pre-existing user work.

---

## The contract this task landed, in one paragraph

**Two boundaries where the tree had one.** *Staging* (unchanged) judges a transfer:
512-byte alignment (`signit.py:295`, every product's rule), the
`[BURN_LEN_MIN, BURN_LEN_MAX]` window, exact `received == size ==
header.firmware_length`, and the announced SHA-256 recomputed from PSRAM read-back.
*Installability* (new) judges whether the staged bytes could ever boot: header magic,
`hw_compat` admitting Mk4, header/announced length agreement, the burn window, and
**4,096-byte installation alignment**. The new code is one pure `no_std` function,
`coldsnap_hal::image::check_installable(image, announced)`, called on the device by
`upgrade::Stager::installable` and on the host by `checkfw` R14 — one implementation,
two consumers, no second image format. The cross-workspace consumer that *cannot* call
it (`hostcheck`, because cargo refuses the combined dependency graph) is bound to it by
a fixed golden vector instead. Digests remain integrity checks on the transfer and the
read-back; the key-0 wrapper remains a format check whose private half is published.
Nothing burns anything: `pin_firmware_upgrade` (18/7) is still unbound, and the
validator takes `&self`.

---

## Findings ledger — 11 CONFIRMED, 9 fixed, 2 open

| # | finding | repair outcome |
|---|---------|----------------|
| F1 | Task 05 was never implemented: no evidence file, no run.json entry, no commit, no working-tree change | **FIXED** (implemented in the repair round) |
| F2 | `UPGRADE-PLAN.md` / `DECISIONS.md` still carried the superseded coordinator-contribution gate as the live, blocking requirement | **FIXED** |
| F3 | Criterion 4 had no implementation: no installation validator existed and a non-4-KiB-aligned image passed every validator in the crates | **FIXED** |
| F4 | Criterion 1 was false for the alignment bound: host 4,096 vs device 512 on the same header field | **FIXED** |
| F5 | Criterion 3's "wrong image family" had no validation boundary anywhere: `hw_compat` decoded, printed, never checked | **FIXED** |
| F6 | No golden vector existed, and the one cross-workspace consumer pair had no shared code to agree through | **FIXED** |
| F7 | The Checks block never ran the tests covering criterion 3's "readback corruption" clause | **FIXED** |
| F8 | Nothing was written, committed or staged in either repo (cheat-hunter pass) | **FIXED** (with three deliberate non-actions, named below) |
| F9 | The evidence file to audit did not exist and the ledger had no task-05 entry | **FIXED** (this file; ledger appended at close-out) |
| F10 | Three doc sites still assert `psram::check_burn_len` has no non-test caller, which this task's own new code falsifies | **OPEN** — close-out may not edit source. Fix is three comment edits at `hal/src/psram.rs:89`, `:520`, `firmware/src/upgrade.rs:5` |
| F11 | The two host-side negative fixtures have no recorded minting recipe, so that leg of the evidence is not reproducible from the tree | **OPEN** — close-out may not edit source. Fix is one script or a recorded recipe under `tools/` |

Nothing was fixed by deleting, relaxing or hard-coding anything. No assertion was
weakened: the alignment tripwire at `firmware/src/lib.rs:3676` is still
`assert!(firmware_digest(&image).is_some(), ...)`; `hostcheck/src/main.rs` is +65/-0; the
only deletions across the whole diff are comment/doc prose, the `MK4_ALIGN` literal that
moved into `memmap`, two `checkfw` legend `println!` lines that were replaced, one
assertion *message* string, and one path line replaced by a list that still contains
`unix/simulator.py` and now also `cli/signit.py`.

### F1 + F8 + F9 — detail

Implemented in the repair round; this file is the artifact F9 named as missing. Three
parts are deliberately **not** done, recorded as decisions rather than omissions:

* **No commit before close-out.** The repair round is forbidden to commit; close-out makes
  the single commit.
* **No `run.json` entry before close-out.** The ledger records a status and a commit SHA,
  both of which are close-out's verdict, so the repair round left `run.json` byte-identical
  to how it found it.
* **No frostsnap change.** Work item 5 says to add protocol fields "only if a concrete
  transport limitation demands them", and none does: `PrepareUpgrade2` / `EnterUpgradeMode`
  / raw 4,096-byte chunks / the `0x11` ack are sufficient and already exercised. The two
  coordinator-side incompatibilities stay **recorded, not patched**:
  `firmware_upgrade.rs:105` gates on an `AckUpgradeMode` this identity-independent listener
  structurally cannot send, and `ValidatedFirmwareBin::new` computes a contiguous-prefix
  digest that cannot match ours. The second is now a *pinned number* (see F6) rather than a
  paragraph.

### F2 — the dev-key-only policy is now recorded in both governing documents

Correction trails preserved (old text quoted or struck, never silently deleted):

* `UPGRADE-PLAN.md:42` — §1.2 is now "SUPERSEDED 2026-09-21 — there is NO
  coordinator-contribution gate", listing what replaces it (published dev key 0 as a
  FORMAT check; no manifest/authority/threshold proof/factory certificate; a
  recognized-release digest list is compatibility metadata, not an allowlist; digests are
  integrity, never trust; physical consent + format/bounds checks + the bootloader's
  existing PIN and downgrade rules are all that remain). The superseded requirement is
  quoted verbatim below the new text.
* `UPGRADE-PLAN.md:96` — §1.3's "That is the evil-maid hole, and §1.2 is what closes it"
  now records the hole as **ACCEPTED**, with physical possession plus a consent screen as
  the only barrier. The analysis is unchanged; only the claim that it is closed is
  withdrawn. That is the cost of the user's decision, stated rather than buried.
* `UPGRADE-PLAN.md:102` — §1.4's matrix no longer lists "coord-contrib gate" in any row.
* `UPGRADE-PLAN.md:307` — phase 4 is "WITHDRAWN 2026-09-21, not deferred".
* `UPGRADE-PLAN.md:335` — §5 item 3 is closed **by withdrawal, not by measurement**, in
  those words: no wire size for a `SharedKey`-carrying message has been measured and
  nothing may later cite the item as evidence that one fits.
* `UPGRADE-PLAN.md:771` — the §7 "What phase 4 still needs" paragraph marked superseded in
  place.
* `UPGRADE-PLAN.md:809` — new §7e records this task's work and what still needs hardware.
* `DECISIONS.md:786,790,793` — decision 8's "Not decided here, and deliberately" clause
  about the gate is struck (kept, struck) and a dated amendment **(e)** records the
  decision AGAINST the gate, the accepted evil-maid cost, the integrity-not-trust reading
  of the digest, and the new staged/installable split with its named gap.

### F3 — the installation validator

`hal/src/image.rs:149` `check_installable` refuses a non-4-K-aligned image;
`firmware/src/upgrade.rs:599` `Stager::installable` is the device-side boundary that
applies it to the staged window. Proven both directions in one test,
`firmware/src/upgrade.rs:1459 a_short_tail_image_stages_and_verifies_but_cannot_be_installed`:
the 266,240-byte (65 x 4,096) image stages **and** installs `Ok(266_240)`; the
262,656-byte short-tail fixture stages, verifies its digest from PSRAM read-back, reaches
`State::Staged`, and is then refused `Err(NotInstallable::Alignment(262_656))`. That is
criterion 4's "may exercise supported staging mechanics but cannot pass the installation
validator" as two legs of one assertion. `check_installable` is also the **first non-test
caller of `psram::check_burn_len`** — the decoupling guard (`verify_firmware_in_ram` signs
`hdr->firmware_length` while `psram_do_upgrade` erases a caller-supplied `len`) that had no
caller at all. (That reachability change is exactly what F10 records as undocumented.)
Also measured through the host boundary on a real-shaped artifact: the
512-but-not-4,096-aligned fixture is refused by `checkfw` at R8 **and** R14, exit 1. R12
also fails on that fixture because editing a signed header invalidates the key-0
signature; no re-sign was done, so that leg is stated, not claimed as isolated.

### F4 — one home per rule, rather than picking a winner

* `hal/src/lib.rs:345` — new `memmap::FW_INSTALL_ALIGN: u32 = 4096`, documented as the
  INSTALL rule (`signit.py:305`, tied by `verify.c:106` to `psram_do_upgrade`'s page-erase
  stride) and distinct from `FW_BODY_ALIGN`'s 512 (`signit.py:295`, the TRANSFER rule for
  every product).
* `firmware/examples/checkfw.rs:55` — the local `const MK4_ALIGN: u32 = 4096` literal is
  deleted; `MK4_ALIGN` is now `memmap::FW_INSTALL_ALIGN`. That literal was the second home
  of the number and the reason two consumers could disagree.
* `firmware/src/lib.rs:3025` — the "8x too loose" comment that recorded the gap now records
  the resolution, and `firmware/src/lib.rs:3035` **fixes a wrong number found in the same
  block**: `FW_MAX_LENGTH_MK4` was cited as 2,031,616, which is not `0x200000 - 0x20000`;
  it is 1,966,080, as `hal/src/psram.rs:126` and `checkfw.rs:43` both already had it.
* **`FW_BODY_ALIGN` was deliberately NOT tightened to 4,096.** That would make one constant
  answer two questions and would delete the short-tail coverage the 262,656-byte fixture
  (65 chunks, a genuinely short final chunk, `hostcheck` M13) exists for. Both tripwires on
  it stay green and their docs now say *why*: `firmware/src/lib.rs:3663` and
  `firmware/src/upgrade.rs`'s `prepare_refuses_a_size_the_burn_cannot_align` doc.
* Both packer alignments are now **read from the reference** rather than asserted:
  `tools/check-reference-contracts.py:858,860` parse `align_to(len(body), 512)` and
  `align_to(body_len, 4096)` out of `cli/signit.py` and compare them to the two constants;
  `:871` checks the 16,384-byte header+vector prefix is itself 4 K-aligned, which is what
  makes judging a whole-image length by a BODY rule legitimate. Both report COVERED.

### F5 — `hw_compat` is now checked

* Device/installer boundary: `hal/src/image.rs:129 family_ok` + `:149 check_installable`,
  with `MK_4_OK` at `:91` and the field offset at `:88`.
* Host boundary: `firmware/examples/checkfw.rs:406` rule **R13**, calling the same
  `image::family_ok` rather than re-deriving the bit.
* The reference's own reading is followed exactly, including the part that is *not*
  stricter: `hw_compat == 0` means "no constraint" (`shared/utils.py:401` only consults the
  bits `if hw_compat != 0`), so `0` is accepted. Being stricter would refuse images
  Coldcard's own updater installs.
* Stated in the code where it matters: `hw_compat` is tested by **no line of
  `mk4-bootloader/`** (0 hits in `verify.c`), so the installer is the only applicable
  boundary — which is why the rule lives here rather than being deferred to the bootloader.
* Tests: `firmware/src/upgrade.rs:1484
  a_wrong_family_or_magic_stages_and_is_refused_only_at_the_install_boundary` (Mk5-only
  `0x20` and Mk1-3-only `0x07` both stage and both refuse; `0` installs; a wrong magic
  refuses) and `hal/src/image.rs:235`. Through the host boundary too: the `0x28 -> 0x20`
  fixture is refused by `checkfw` R13 + R14, exit 1.
* The constants are pinned against the reference, not retyped:
  `tools/check-reference-contracts.py:727,729,732` check `FW_HEADER_MAGIC`,
  `HW_COMPAT_FIELD_OFFSET` against `offsetof(coldcardFirmwareHeader_t, hw_compat)`, and
  `MK_4_OK` against `sigheader.h:71`, using the compiled-reference ABI probe.

### F6 — the golden vector, and the three digests it distinguishes

`golden/mk4-staging-vectors.txt` (new) pins M13's synthetic image with **all three digests
it can be confused with**, so Work item 3's distinction is checked numbers, not prose:

| digest | what it is | value (m13-synth-262656) |
|---|---|---|
| announced | ours: single SHA-256 over `[0,16320)` ++ `[16384,length)` | `33b54101…1ab19489` |
| fw_check | the Mk4 bootloader's DOUBLE hash over the same ranges (`verify.c:226`) | `cd00f217…452ee629` |
| prefix | a stock ESP32 coordinator's contiguous prefix (`frostsnap_coordinator/src/firmware.rs:206-212`) | `f0660a40…e726cff9` |

Read by two independent consumers, both via `include_str!` so a deleted vector is a
compile error and never a skipped test:

* `firmware/src/upgrade.rs:1550` — checks the vector against the **production**
  `firmware_digest` and against the test fixture's own literal-derived copy, so neither can
  drift alone.
* `hostcheck/src/main.rs:2587,2616` — checks it against M13's own `signed_digest`.
  `hostcheck` cannot depend on `coldsnap_hal` (cargo refuses the graph), so these were two
  independent implementations of one range with **nothing comparing them**: a matching pair
  of wrong literals was green on both sides.

The re-runner independently recomputed all three digests in Python from the recipe in the
vector file's own header and got the three pinned values bit-for-bit, so the binding is
real and not a pair of matching literals. `STAGE_SIZE = 262_656` was left as it is on
purpose: it is the point of that leg (short final chunk, 65 acks), and F3's separation is
what makes its non-installability explicit instead of implied.

### F7 — readback corruption, moved to where the Checks block can see it

The prompt file is pre-existing untracked user work and was not edited, so the fix is on
the code side: `firmware/src/upgrade.rs:1515
psram_reading_back_a_byte_it_was_never_given_is_a_digest_refusal` drives
`FakePsram::corrupt_writes_at` **through `Stager`**, armed after admission (at admission
`readback_selftest` would catch it earlier as `Refuse::Selftest(Mismatch)`), and asserts
the wire-clean / storage-corrupt case ends in `Refuse::Digest`, that the fake really did
store a byte nobody sent, and that the result is not installable. It runs under `cargo test
-p coldsnap_firmware` — row 4 of the prompt's own block. `cargo test -p coldsnap_hal` was
**also** run (E1 below) and is reported as an extra, never as one of the five.

---

## Files changed

`git diff --stat` at close-out (plus two untracked additions):

```
 DECISIONS.md                           |  44 +++++-
 UPGRADE-PLAN.md                        | 178 ++++++++++++++++++++----
 firmware/examples/checkfw.rs           |  66 ++++++++-
 firmware/src/lib.rs                    |  61 ++++++---
 firmware/src/upgrade.rs                | 239 ++++++++++++++++++++++++++++++++-
 hal/src/lib.rs                         |  22 +++
 hostcheck/src/main.rs                  |  65 +++++++++
 target/software-only/evidence/run.json |   2 +-
 tools/check-reference-contracts.py     |  42 +++++-
 9 files changed, 665 insertions(+), 54 deletions(-)
```

| file:line | what |
|---|---|
| `hal/src/image.rs` (new, 292 lines) | the checked Mk4 image contract: `FW_HEADER_MAGIC:78`, `HW_COMPAT_FIELD_OFFSET:88`, `MK_4_OK:91`, `NotInstallable:96`, `family_ok:129`, `check_installable:149`, a `const _` invariant block, and one test `:235` |
| `hal/src/lib.rs:132` | `pub mod image;` |
| `hal/src/lib.rs:345` | `memmap::FW_INSTALL_ALIGN = 4096`, the single home of the Mk4 install alignment |
| `firmware/src/upgrade.rs:599` | `Stager::installable(&self) -> Result<u32, NotInstallable>` — the install boundary; `&self`, burns nothing |
| `firmware/src/upgrade.rs:1413-1600` | `INSTALL_SIZE`, `installable_image`, `staged`, four new tests (`:1459`, `:1484`, `:1515`, `:1550`) and the golden-vector reader `:1576` |
| `firmware/src/upgrade.rs` (`prepare_refuses_a_size_the_burn_cannot_align` doc) | records that `FW_BODY_ALIGN` must NOT be tightened, and where 4,096 now lives |
| `firmware/src/lib.rs:3016-3040` | alignment comment block rewritten (transfer rule vs install rule); `FW_MAX_LENGTH_MK4` corrected 2,031,616 -> 1,966,080 |
| `firmware/src/lib.rs:3652-3690` | the tripwire test's doc and assertion message now state why the digest keeps the looser bound; the assertion itself is unchanged (`is_some()`) |
| `firmware/examples/checkfw.rs:44-55` | `MK4_ALIGN` is `memmap::FW_INSTALL_ALIGN`; local literal deleted |
| `firmware/examples/checkfw.rs:406,427` | new rules **R13** (`hw_compat` admits Mk4) and **R14** (the device's own install boundary, called not copied); `:130,151` verdict legend updated |
| `golden/mk4-staging-vectors.txt` (new) | one vector, three digests, reproduction recipe in the header |
| `hostcheck/src/main.rs:2587` | `mod golden_vector` + `golden_vector_agrees_with_m13s_own_digest`; no change to any interop leg (+65/-0) |
| `tools/check-reference-contracts.py:84,300,320,727-734,855-876` | parses `hal/src/image.rs`; new `off_hw_compat` ABI probe word; six new pins (magic, `hw_compat` offset, `MK_4_OK`, both signit alignments, header-prefix divisibility); `cli/signit.py` added to the sha256-pinned consumed set |
| `UPGRADE-PLAN.md:42,96,102,307,335,771,809` | the policy correction and new §7e (F2) |
| `DECISIONS.md:786,790,793` | decision 8 amendment (e) (F2) |
| `target/software-only/evidence/05-validate-mk4-upgrade-images.md` (new) | this file |
| `target/software-only/evidence/run.json` | the task-05 ledger entry, appended at close-out. **Also carries task 03's pre-existing one-line commit-SHA backfill** (`"commit": null -> "89a1021…"` on the task-03 entry), left dirty by task 03's close-out because a commit cannot contain its own SHA; it is disclosed in task 03's own notes and rides in this commit rather than being reverted |

No file under `~/repos/coldcard-firmware` was written. No file in `~/repos/frostsnap` was
written. `prompts/` was left exactly as the run found it.

---

## Commands

Three independent runs of the same command set are recorded. **Elapsed time was not
recorded by the repair round or by the re-runner**; close-out re-ran the identical set with
wall-clock timing rather than inventing theirs. Close-out's elapsed figures are
**warm-cargo-cache** numbers (the tree was already built), not cold-build costs. Exit codes
in all three runs are the **process's own status**, never a pipeline's: close-out's runner
executes each command in a subshell with full-file redirection and reads `$?`.

Close-out run: 2026-09-22, logs at `target/software-only/closeout/05/<id>.log`, timings at
`target/software-only/closeout/05/timings.tsv`, runner script
`target/software-only/closeout/05/rerun.sh`.

### The prompt's five Checks commands — cwd `/Users/garykrause/repos/cold-snap`

| id | command (verbatim) | exit: repair / re-runner / close-out | close-out elapsed | result reproduced at close-out |
|---|---|---|---|---|
| C1 | `cargo build --release` | 0 / 0 / **0** | 1.20 s | ARM image builds |
| C2 | `cargo clippy --release --target thumbv7em-none-eabihf -p coldsnap_hal -p coldsnap_firmware` | 0 / 0 / **0** | 0.45 s | 0 warnings attributed to either crate; all 15 are vendored (`frostsnap_comms` 11, `frost_backup` 3, `frostsnap_macros` 1) |
| C3 | `cargo clippy --target thumbv7em-none-eabihf -p coldsnap_hal -p coldsnap_firmware` | 0 / 0 / **0** | 0.53 s | same 15 vendored warnings; **0** warning locations under `hal/src` or `firmware/src` |
| C4 | `cargo test --target aarch64-apple-darwin -p coldsnap_firmware` | 0 / 0 / **0** | 1.47 s | `139 passed; 0 failed; 0 ignored` (lib) + `57 passed` (bin) = **196 passed**, doc-tests 0. Was 192 before this task: +4, the four new tests named in F3/F5/F6/F7. Not the historical 508 |
| C5 | `cargo run --release --target aarch64-apple-darwin -p coldsnap_firmware --example heap_session --features coldsnap_hal/test-seam,frostsnap_core/coordinator` | 0 / 0 / **0** | 1.08 s | arena FOOTPRINT high-water **60,512 B of 65,536 B (5,024 B spare)**, PEAK requested 54,496 B in ≤30 blocks, LIVE between frames 17,844 B, `NULLS: 0`, 0 allocator refusals |

**C5 is reported as a re-run baseline, NOT as evidence of new cost.** The validation this
task adds allocates nothing and retains nothing: `check_installable` is a pure function
over a borrowed slice, `Stager::installable` takes `&self` and added no field, and no new
buffer or frame path exists (chunks still bypass `Link`). The prompt's warning that "an
unchanged old example alone does not establish new cost" applies precisely to this
unchanged figure, so the claim is only: the workload was extended by nothing because there
is nothing to extend it with, and the number is measured this run rather than cited.
`heap_session.rs` still has no `Stager` in its workload — that gap is pre-existing,
recorded at `UPGRADE-PLAN.md:335`, and untouched here. The 4,096-byte `FRAME_LIMIT` is
unchanged; no message type was added.

### Extra checks this task's changes obligate

| id | command (verbatim) | cwd | exit: repair / re-runner / close-out | close-out elapsed | result reproduced at close-out |
|---|---|---|---|---|---|
| E1 | `cargo test --target aarch64-apple-darwin -p coldsnap_hal` | `/Users/garykrause/repos/cold-snap` | 0 / 0 / **0** | 3.67 s | `293 + 5 + 19 passed, 0 failed`, 1 ignored (the pre-existing `hal/src/usb.rs:8` doctest, not a disabled test). 292 before: +1, `image::tests::every_rule_refuses_on_its_own_and_the_real_shape_passes`. Includes the `readback_selftest`/`PsramError::Mismatch` suite, reported as an extra because the prompt's block cannot see it |
| E2 | `cargo test golden_vector` | `/Users/garykrause/repos/cold-snap/hostcheck` | 0 / 0 / **0** | 0.65 s | `running 1 test` … `1 passed` — the cross-workspace golden-vector agreement. Must run from `hostcheck/`: its own `.cargo/config.toml` is what overrides `build.target`; from the root the graph builds for thumbv7em and fails in `bech32`. The re-runner confirmed with `cargo test -- --list` that this is `hostcheck`'s only `#[test]`, so the filter excluded nothing |
| E3 | `cargo run --release --target aarch64-apple-darwin -p coldsnap_firmware --example checkfw -- target/software-only/package/firmware-signed.bin` | `/Users/garykrause/repos/cold-snap` | 0 / 0 / **0** | 0.48 s | `RESULT: ACCEPT — 14/14 locally checkable rules pass.` incl. `[PASS] R13 … actual 0x28` and `[PASS] R14 … actual Ok(397312)`. `pubkey_num 0`; no registration, manifest or coordinator proof consulted |
| E4 | `cargo run --release --target aarch64-apple-darwin -p coldsnap_firmware --example checkfw -- target/software-only/fixtures/05/misaligned-397824.bin` | `/Users/garykrause/repos/cold-snap` | 1 / 1 / **1** | 0.35 s | `RESULT: REFUSE — 3 of 14`: `[FAIL] R8 … 397824 % 4096 = 512`, `[FAIL] R14 … actual Alignment(397824)`, `[FAIL] R12 …` (header edit invalidates the key-0 signature; no re-sign). **Nonzero for the named reason** |
| E5 | `cargo run --release --target aarch64-apple-darwin -p coldsnap_firmware --example checkfw -- target/software-only/fixtures/05/wrong-family-mk5-only.bin` | `/Users/garykrause/repos/cold-snap` | 1 / 1 / **1** | 0.34 s | `RESULT: REFUSE — 3 of 14`: `[FAIL] R13 … actual 0x20`, `[FAIL] R14 … actual WrongFamily(32)`, `[FAIL] R12 …` (same reason). **Nonzero for the named reason** |
| E6 | `python3 tools/check-reference-contracts.py --json target/software-only/closeout/05/refcheck.json` | `/Users/garykrause/repos/cold-snap` | 0 / 0 / **0** | 11.06 s | `PASS: 120 checks agree with the reference.` (114 before: +6). **0** lines matching `/skip/i`. All six new pins COVERED: `abi/fw-header-magic` 0xcc001234, `abi/hw-compat-field-offset` 32, `abi/mk-4-ok` 8, `memory/signit-body-align` 512, `memory/signit-install-align` 4096, `memory/install-align-divides-header-prefix` |
| E7 | `python3 tools/test-pack-signed.py` | `/Users/garykrause/repos/cold-snap` | 0 / 0 / **0** | 1.39 s | `OK: 18 cases` — "part A: 16 pure geometry cases, all as required"; "part B: 2 end-to-end refusals, both nonzero for the intended reason" (pack-signed exit 1 on `bad-layout.elf`; checkfw exit 1 on `bad-signature.bin`, criterion 3's broken key-0 wrapper). The existing malformed-input harness still passes with R13/R14 in place |
| E8 | `python3 tools/pack-signed.py --out target/software-only/closeout/05/pack --no-dfu` | `/Users/garykrause/repos/cold-snap` | 0 / 0 / **0** | 0.21 s | flash cost measured, not assumed: body **379,880 B**, `firmware_length = 397,312 (0x61000) = 97 x 4096`, `hw_compat 0x28 => Mk4+Mk5`, 397,248 B hashed. Byte-identical to the pre-task artifact, because the new validator has no ARM caller yet and does not reach the image. The historical 379,876-vs-379,880 gap is a reproduction clue only; 379,880 is what this run measured |

The repair round's own logs are under `target/software-only/fixtures/05/`
(`checkfw-real.log`, `checkfw-misaligned.log`, `checkfw-wrong-family.log`, `refcheck.log`,
`test-pack-signed.log`, `pack.log`) alongside the two negative fixtures; close-out's are
under `target/software-only/closeout/05/`.

### Not run, and not claimed

* `hostcheck`'s **M13 staging interop was not driven end to end**. Its interop code is
  unchanged (the only edit is an added `#[cfg(test)]` module); `cargo test` in that
  directory compiled the whole crate and ran the new test. No M13 result is reported.
  A unit test is not reported as an integration run.
* No frostsnap-side test was run, because no frostsnap file was changed.
* `tools/qemu-boot.sh` and `tools/pixel-check.py` are diagnostics, not gates, and are
  claimed in neither direction. `pixel-check.py` in particular exits 0 with `SKIP`, which
  would not be a pass.

---

## Acceptance criteria

| # | criterion (prompt's wording) | verdict | evidence |
|---|---|---|---|
| 1 | "Host and device consumers agree on header lengths, digest ranges, and bounds." | **met** | Agreement is through *code*, not matching constants: `checkfw` derives header geometry from `memmap`, calls `firmware_digest` for the range, and calls `image::family_ok` + `image::check_installable` for family and bounds (R13, R14 — E3). The 4,096-vs-512 divergence is resolved by two named constants for two boundaries (`FW_INSTALL_ALIGN`, `FW_BODY_ALIGN`), both pinned against `cli/signit.py` by E6. The one consumer that cannot share code (`hostcheck`) is bound by `golden/mk4-staging-vectors.txt` (E2) |
| 2 | "A valid local key-0-signed artifact is accepted without a release registration, manifest, coordinator share proof, or new signing credential." | **met** | E3: ACCEPT 14/14 on the real artifact, `pubkey_num 0`, dev key 0 only, no registry/manifest/new key anywhere in the tree; the coordinator gate is recorded as *withdrawn* in both governing documents (F2) |
| 3 | "Malformed headers, wrong image family, truncation, size disagreement, overrun, and readback corruption reject at the applicable validation boundary. A broken key-0 wrapper fails host signature verification." | **met** | magic `upgrade.rs:1484` / `image.rs:235`; family `upgrade.rs:1484` + E5 (R13/R14, exit 1); truncation `lib.rs:3561` + `image.rs:235` (`StageError::Truncated`); size disagreement `upgrade.rs:1176` + `StageError::LengthMismatch`; overrun `upgrade.rs:1138`; readback corruption `upgrade.rs:1515`, now inside the prompt's own C4; broken key-0 wrapper `checkfw` R12 via E7 part B, exit 1 |
| 4 | "A non-4-K-aligned fixture may exercise supported staging mechanics but cannot pass the installation validator." | **met** | Both legs of `upgrade.rs:1459`: 266,240 B stages *and* installs `Ok`; 262,656 B stages, verifies from PSRAM read-back, reaches `State::Staged`, then `Err(NotInstallable::Alignment(262_656))`. Host-side too: E4, exit 1 |
| 5 | "Task 06 has a concrete artifact/transfer contract and task 07 a checked-image boundary. Transport and ARM checks run; no actual installation is attempted." | **met** | Task 06 inherits `golden/mk4-staging-vectors.txt` (three digests, one reproduction recipe) and `hal/src/image.rs`'s rule table with a citation per rule; task 07 inherits `Stager::installable` as the checked-image predicate, with no gate bindings and nothing burned. ARM checks ran (C1 release build, C2/C3 thumbv7em clippy); transport contract exercised by C4's stager tests and unchanged on the wire. No installation was attempted; 18/7 stays unbound and classified `Destructive` |

**5 of 5 met. 0 not met. 0 unverifiable-without-hardware** — no criterion required silicon
to decide. What silicon would decide is a *different* question, listed below: these
criteria are about validators refusing and agreeing, not about a validated image booting.

---

## Forbidden-shortcut audit

### Global list, by name

| shortcut | result |
|---|---|
| "Never claim a command ran that did not run. Paste real exit codes." | Clean. All 13 commands re-run at close-out; exit codes read from `$?` and recorded in `target/software-only/closeout/05/timings.tsv`, full output in `<id>.log` |
| "Exit 0 with `SKIP` output is not a pass. `tools/pixel-check.py` does exactly this." | Clean. `pixel-check.py` not invoked and not claimed. E6's log has **0** lines matching `/skip/i`; a missing reference checkout would have surfaced as a nonzero UNAVAILABLE, not a skip |
| "Capture the process's status, never a filtering pipeline's." | Clean. Each command runs in a subshell with `> log 2>&1` and no pipe; `$?` is the process's. (Relevant here: the login shell is fish, where `${PIPESTATUS[0]}` expands to empty — the runner is `bash` and pipes nothing) |
| "Historical figures are reproduction clues, never current evidence and never hardcoded constants" | Clean on all four named figures. 379,876-vs-379,880: E8 **measured** body 379,880 B this run. 508 passing tests: not used anywhere; the current figures are 196 (C4) and 317 (E1), both measured. 60,512 of 65,536: measured at C5 this run and explicitly demoted to a baseline, not new-cost evidence. 12-device keygen ceiling: not touched by this task |
| "Never delete or relax a failing assertion to make a build pass." | Clean. The alignment tripwire still asserts `firmware_digest(&image).is_some()`; `hostcheck` is +65/-0; every deletion in the diff is comment/doc prose, a relocated constant literal, two replaced `println!` legend lines, one assertion *message* string, or a path line replaced by a superset list |
| "No label of 'hardware verified' or 'safe for funds'." | Clean. The only claim made, here and in E6's own footer, is "software/pre-bench checks passed", scoped to cold-snap's image/transfer contract |
| "Unit tests are never reported as an integration run. A mocked effect is never reported as a real one." | Clean. M13 interop explicitly not driven end to end and not claimed; `FakePsram::corrupt_writes_at` is named as a fake in the test name and docs; no callgate transit occurred and 18/7 remains unbound |
| No physical device, port, flashing, provisioning, OTP write, real callgate, network broadcast | Clean. None occurred. `checkfw` and the packer are host programs reading files |
| `~/repos/coldcard-firmware` read-only | Clean. HEAD `0431fd2b…`, `status --porcelain | wc -l` = 10, the unchanged 00-preflight baseline. Negative fixtures live under `target/`, never in the reference tree |
| Dev key 0 only; no new signing authority, manifest, allowlist, factory certificate, or coordinator share-proof gate | Clean, and this task *withdrew* the last standing gate requirement from the two governing documents (F2). The digest-list reading is stated as compatibility metadata, never installation permission |
| Generated output under ignored `target/`; preserve unrelated user work | Clean except by design: `golden/mk4-staging-vectors.txt` is a tracked source input read by `include_str!`, not generated output. `prompts/` and frostsnap's four dirty paths untouched |
| Absolute paths, explicit cwd, no inherited cwd | Clean. The runner sets `cd "$cwd"` per command; every path in this file is absolute or explicitly repo-relative with its cwd named |
| NEVER push, NEVER open a PR | Clean. One commit on `software-only/run-2026-09-21`; no push, no PR |

### Task 05's own "do not" list, by name

| prompt clause | result |
|---|---|
| Work 1: "add only missing checks rather than building a second parallel image format" | Honoured. One new pure function that *reuses* `psram::check_burn_len` and the existing header parse; no second format, no duplicated digest |
| Work 2: "Separate transfer-stage validity from installability: existing synthetic short-tail staging tests do not establish a bootable image" | Honoured, and this is the task's central change (F3). The 262,656-byte short-tail fixture is now explicitly *staged but not installable* |
| Work 3: "Distinguish it from the bootloader's double SHA-256 and ESP32's contiguous-prefix digest" | Honoured as three distinct pinned numbers in `golden/mk4-staging-vectors.txt`, independently recomputed by the re-runner |
| Work 3: "These are integrity checks, not proof that the sender or firmware is trusted" | Honoured in the code docs and in the `UPGRADE-PLAN.md` §1.2 / `DECISIONS.md` (e) amendments |
| Work 4: "Keep host verification of the dev-key wrapper and the bootloader's eventual verification separate from device-side size/digest checks" | Honoured. R12 is host-only and named as such; R14 calls the device validator; the bootloader's own U1-U4 are printed on every `checkfw` run as unresolvable off-bench |
| Work 4: "Introduce no new release allowlist, rollback ratchet, or OTP writes" | Honoured. None added; no OTP write path exists in the diff |
| Work 5: "Only add protocol fields if a concrete transport limitation demands them, preserving existing discriminants" | Honoured by adding none: no frostsnap file changed, no discriminant touched (F8) |
| Work 6: "keep it in a leaf module/crate that cannot pull both Frostsnap dependency graphs together" | Honoured. `hal::image` is a leaf module with no Frostsnap dependency; `hostcheck` is bound by a fixed vector, not a path dep, so its manifest prohibition stands |
| Work 7: "Keep the 4,096-byte frame and 64 KiB heap bounds" | Honoured. `FRAME_LIMIT` untouched; C5 measures 60,512 B of 65,536 |
| Workspace rules: "No additional signing keys or provisioning are required" | Honoured. `stm32/keys/00.pem` only |
| Workspace rules: "No commits, pushes, physical-device access, real callgate calls, or provisioning" | Partially superseded, disclosed: the orchestrated run designates exactly one commit per task at close-out, which is this commit. No push, no PR, no device, no callgate, no provisioning |

---

## Residual bench-only questions — in the prompt's own terms

The prompt's Return asks for "checks still requiring hardware", and Work item 4 asks to
"Make explicit which checks depend on physical state, including the existing OTP minimum
timestamp". Unchanged by this task:

* **The OTP minimum timestamp** (Work 4, named in the prompt). `checkfw` U2,
  `verify.c:143,181`: install path only, and it ratchets with every install already done on
  that unit. No file can satisfy it and no OTP write was made.
* **`checkfw` U1** — SE1 world checksum / CHECKMAC of `KEYNUM_firmware`
  (`verify.c:305,326,336`): covers flash outside the image, so no artifact can satisfy it.
* **`checkfw` U3** — the RDP level (`verify.c:340`): decides Factory boot vs red light and
  whether a failed verify can still reach `enter_dfu`.
* **`checkfw` U4** — whether an install path exists at all: only `pins.c:1276-1340` from a
  logged-in MicroPython installs new firmware; `sdcard_recovery` cannot.
* **Every ARM leg of staging**: `MappedPsram::from_raw_parts`, `Cdc`'s `Wire` impl,
  `readback_selftest` against real OCTOSPI, the step-6d key-hold read. Nothing in this
  project has run on silicon; the corruption test uses `FakePsram`.
* **"no actual installation is attempted"** (criterion 5) is the standing limit, not a gap:
  the burn itself (callgate 18/7) stays unbound and stays classified `Destructive`, and
  task 07 models installation without real gate bindings. That a 14/14-ACCEPT image
  actually boots is unproven and unprovable here.
* **`hw_compat` is enforced by the installer only.** The Mk4 bootloader tests it in no
  line of `verify.c`, so whether a real unit refuses a wrong-family image depends entirely
  on the installer that runs — a bench question about the unit's software, not about this
  validator.
* **The wire size of a `SharedKey`-carrying upgrade message** is *not* on this list and
  must not be cited later as measured: `UPGRADE-PLAN.md:335` now records that item as
  closed **by withdrawal, not by measurement**.

---

## Commit

One commit on `software-only/run-2026-09-21`, staged by explicit path. The SHA is reported
in close-out's return value and backfilled into `run.json`'s task-05 entry after the commit
— a commit cannot contain its own SHA. That backfill is left uncommitted, exactly as task
01's was, and task 03's equivalent backfill rides inside this commit (disclosed above in
Files changed).

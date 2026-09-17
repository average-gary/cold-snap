# cold-snap — a Frostsnap device on Coldcard Mk4 hardware

**Status:** **decisions made 2026-08-12** — the six architectural choices are
settled and recorded in **[DECISIONS.md](DECISIONS.md)** — seven now, 7 being the
`FRAME_LIMIT` reversal of 2026-08-18. Phases 0-4 are complete **on the host**:
phase 3's transport is written and host-verified, and phase 4's interop gate is met
by `hostcheck/` but **not signed off** (§8, §9 item 12). **Phase 5's mono UI is also
written and host-verified** — seven of the eight §4.2 screens have callers, the
eighth being the one the dispatch refuses (§9 item 16) — along with the keypad, the
share store, 25-word entry, the backup quiz, a bin target, a linker script, a reset
entry that sets `VTOR`, and a registered `#[global_allocator]`. **No code has run on
hardware.** (This block said "nothing will [run on hardware] before phase 5" and
described phases 0-4 only; phase 5 was written ahead of it, which is why so much of
this document's status prose describes a tree that no longer exists — see §9 item 22
and the correction trails throughout.) This document is the implementation plan of
record, not a proposal.

**Reading this document.** Its figures are supposed to be measured, never estimated,
and where one has been re-derived the old value is recorded beside it with a date.
That convention is load-bearing: it is how a reader knows which numbers have been
checked. It is **not** decoration and must not be tidied away. A full reconciliation
against the tree was run on 2026-09-10 — 1,447 falsifiable claims across this file,
DECISIONS.md, README.md and vendor/README.md — and the corrections it produced are
dated inline.
**Date:** 2026-08-12
**Target:** COLDCARD Mk4 (STM32L4S5, `thumbv7em-none-eabihf`) — decision 1
**Upstream:** `frostsnap/frostsnap` @ `0bbc18be` (2026-08-11), MIT
**Reference:** `coldcard/firmware` @ `0431fd2b`, MIT (firmware), proprietary (`hardware/`)

---

## 1. What this is

A **bare-metal Rust firmware** that makes a Coldcard Mk4 behave as a Frostsnap
signing device — reusing Frostsnap's own crates rather than reimplementing FROST
against Coldcard's existing libraries.

The framing that makes this tractable: *we are building a Frostsnap device that
happens to run on Coldcard silicon.* Not *porting FROST into Coldcard's
MicroPython firmware*. The two differ in almost every consequence.

### Why this framing, and not the MicroPython route

The alternative — keep Coldcard's MicroPython firmware and add FROST as a Rust
`USER_C_MODULES` static library — was investigated first and is viable. It was
rejected on a **trust constraint**, not an efficiency one:

The 2021–2026 entropy advisory's fixes land entirely in Coldcard's own TRNG
driver, never in libngu:

| Commit | Date | Author | Files |
|---|---|---|---|
| `43b21392` | 2026-08-04 | scgbckbone | `COLDCARD_MK4/rng.c`, `mk4-bootloader/rng.c` |
| `82ced47a` | 2026-08-01 | scgbckbone | `COLDCARD_MK4/rng.c`, `mk4-bootloader/rng.c`, keyboard/mempad |
| `b987de50` | 2026-07-31 | scgbckbone | *"Use hardware RNG for Mk and Q **libngu**"* |
| `ca724637` | 2026-07-30 | Peter D. Gray | both board families, `shared.mk` |

Read `b987de50`'s title: libngu **was not using the hardware RNG**.
`external/libngu/ngu/random.c:16-46` shows how that was possible — an `#ifdef`
ladder that **fails open**:

```c
#ifdef MICROPY_PY_STM
extern uint32_t rng_get(void);
# define CHIP_TRNG_32()   rng_get()
#endif
#ifdef __linux__
# define CHIP_TRNG_32()   random()      /* glibc non-crypto PRNG */
#endif
```

If the STM32 branch is not selected, the build silently falls through to
`arc4random()` or glibc `random()` rather than refusing to compile. The defect
lived at the libngu↔Coldcard seam, and libngu's structure is what let a
build-configuration mistake become a silent entropy failure.

Under this plan there is no MicroPython and no `ngu` module — the 147 `ngu.*`
call sites across 34 Coldcard modules cease to exist rather than needing
replacement.

**Stated honestly:** libngu and the Coldcard firmware share authors
(scgbckbone, Peter D. Gray). This plan still retains their bootloader and
secure-element code (§6). That is a deliberate trade — see §6 for why
discarding it costs more than it saves.

---

## 2. Verified findings

All measured this session, not estimated.

### 2.1 The portable crates cross-compile for Coldcard's exact target

```
cargo build -p frostsnap_core --no-default-features \
      --target thumbv7em-none-eabihf        →  Finished in 8.51s
```

| Crate | LOC as vendored | LOC now | `no_std` | Cross-compiles unpatched |
|---|---|---|---|---|
| `frostsnap_core` | 13,516 | **14,753** | ✅ | ✅ |
| `frost_backup` | 2,671 | 2,671 | ✅ | ✅ |
| `frostsnap_comms` | 1,679 | **1,713** | ✅ | ✅ |
| `frostsnap_embedded` | 881 | **1,454** | ✅ | ✅ |
| `frostsnap_macros` | 511 | 511 | — | ✅ |
| **Total** | **19,258** | **21,102** | | |

LOC is every `.rs` file in the crate, tests included. "As vendored" is **upstream at
`0bbc18be`**, read out of the sibling checkout — not this tree at any commit, because
`vendor/frostsnap/` arrived already patched in the initial commit, so the baseline is
not recoverable from our own history.

**This table read `frostsnap_core` 13,998 → 14,260 and Total 19,740 → 20,002 until
2026-09-10, and the "as vendored" column was wrong as well as the "now" column.**
13,998 matches no upstream commit (13,516 at the vendored `0bbc18be`), and the `comms`
and `embedded` "now" cells had never been re-measured after the panic-site pass at all.

The **+1,237** lines in `frostsnap_core` are decision 3 and its vector tests
(`tweak.rs` +235, `bitcoin_transaction.rs` +371) plus the panic-site work
(`device_nonces.rs` +176, `sign_task.rs` +24, `message.rs` +12) and two new test files
(`tests/nonce_index_bounds.rs` 285, `tests/agg_nonce_count.rs` 134).

**Two other crates are not byte-identical either, and this paragraph claimed
"Everything else is byte-identical to upstream" until 2026-09-10.**
`frostsnap_comms` is **+34** (`EncapsBody::as_bytes` plus the `MAX_MESSAGE_ALLOC_SIZE`
literal — both RE-APPLY ON EVERY RE-VENDOR, and the second fails *silently* if
forgotten) and `frostsnap_embedded` is **+573** (`ab_write.rs` +272, `nonce_slots.rs`
+181, `test.rs` +120 — the panic-site fixes and the `FaultyNorFlash` harness they need).
Both are already in `vendor/README.md`'s local-modifications tables, so this sentence
contradicted a table two files away as well as the one directly above it. Only
`frost_backup` (Cargo.toml aside) and `frostsnap_macros` are untouched.

**Correction to earlier analysis.** I previously stated `frostsnap_core` could
not cross-compile without patching `tweak.rs:186` to drop `libsecp_compat_0_29`.
That was wrong. It compiles unpatched. The real blocker was a missing C
cross-compiler; `secp256k1-sys` runs `cc-rs`, and no `arm-none-eabi-gcc` was
installed. Substituting clang resolves it:

```sh
export CC_thumbv7em_none_eabihf=/opt/homebrew/opt/llvm/bin/clang
export AR_thumbv7em_none_eabihf=/opt/homebrew/opt/llvm/bin/llvm-ar
export CFLAGS_thumbv7em_none_eabihf="--target=thumbv7em-none-eabihf \
  -mcpu=cortex-m4 -mfpu=fpv4-sp-d16 -mfloat-abi=hard -ffreestanding -Os"
```

### 2.2 Flash: one feature flag decides whether it fits

Measured by parsing allocatable `SHT_PROGBITS` sections across every `ar`
member of each release `.rlib`, LTO disabled so code is materialized. Budget is
`FLASH_TEXT` = 1,425,408 bytes (`stm32/COLDCARD_MK4/layout.ld:17`).

Measure into a **clean, dedicated** target dir. The live `./target` accumulates
stale duplicate rlibs (e.g. two `libbitcoin-*.rlib`) which the tool's glob
double-counts.

| Component | Default tables | With `secp-lowmemory` | Now, post-decision-3 |
|---|---|---|---|
| C `secp256k1-sys` + wrapper | 1,177,733 (82.6%) | 96,947 (6.8%) | **96,947 (6.8%)** |
| `rust-bitcoin` + bech32/base58/hex | 326,180 (22.9%) | 327,408 (23.0%) | **327,408 (23.0%)** |
| Frostsnap + pure-Rust crypto | 416,607 (29.2%) | 421,059 (29.5%) | **419,874 (29.5%)** |
| **Total** | **1,920,520 (134.7%) — does not fit** | 845,414 (59.3%) | **844,229 (59.2%) — fits** |
| Without `secp256k1-sys` at all | 742,787 (52.1%) | 748,467 (52.5%) | 747,282 (52.4%) |
| Without `secp256k1-sys` and `rust-bitcoin` | 416,607 (29.2%) | 421,059 (29.5%) | 419,874 (29.5%) |

**Resolved.** `bitcoin`'s `secp-lowmemory` feature sets `ECMULT_WINDOW_SIZE=4`
and `ECMULT_GEN_PREC_BITS=2` (`secp256k1-sys-0.10.1/build.rs:34-36`), shrinking
the C library by 92% — 1,177,733 → 96,947 bytes — with **no source changes**.
This is enabled in `Cargo.toml`. The whole table above is the **phase-1** image —
it predates `coldsnap_hal`, and is kept in that form because its point is the
comparison across feature flags, not the current size. Current: **899,400 B = 63.1%** as an rlib sum with LTO off, re-measured
2026-09-10 (**this read 860,898 B = 60.4%, "with phases 2 and 3 in", until then**);
the linked image is **379,648 B = 26.6343%** from `cargo build --release`
(§10, and README "Flash budget" for both splits and why they differ by ~2.4×; **this
read 377,192 B = 26.46% until 2026-09-12** and **376,752 B = 26.43% until 2026-09-11**
— the 376,752 was the figure before the keygen check's randomised digit added 440 B,
and it is the figure a review found copied into SIX places while two carried the new
one, which is why every image figure in this document now names its invocation). **This paragraph ended "The
cost is slower EC operations (smaller precomputation window); signing latency
on-device remains unmeasured — see §9 'Genuinely open' item 1, now the highest-value
open question" until 2026-09-13.** There is **no such cost on this port**: the smaller
window shrinks code that decision 3 then removed from the device graph entirely, and
MEASURED 2026-09-13 the feature changes the linked image by **exactly 0 bytes** —
`379,648 B` with and without it, section for section, and both `precomputed_ecmult*.c`
survive only as zero-size `df` file symbols either way. The 92% above is a real
**rlib-sum** saving and it stays; what does not follow from it is a latency cost. See
§9 "Genuinely open" item 1 for both measurements and for the unknown that IS real,
which is `secp256kfun`'s own `field_10x26`/`scalar_8x32` on a 120 MHz M4F.

The 1.18MB, at default window sizes, is **C libsecp256k1's precomputed ECMULT
tables**:

```
524,288  .rodata.rustsecp256k1_v0_10_0_pre_g
524,288  .rodata.rustsecp256k1_v0_10_0_pre_g_128
 65,536  .rodata.rustsecp256k1_v0_10_0_ecmult_gen_prec_table
```

`secp256kfun` — Frostsnap's own pure-Rust curve library — has **no such
tables**; its largest section is 3,724 bytes (`Scalar::mul`). So there are two
independent ways to solve this, and `secp-lowmemory` (above) already does it
without touching code.

#### `libsecp_compat_0_29` — dropped (decision 3), and the benefit was overstated

**This paragraph previously claimed dropping the feature "removes the C
dependency entirely, eliminating cc-rs, the C toolchain requirement, and ~97KB"
at a "cost of 6 call sites". All four of those figures were wrong.** Corrected
against measurement:

| Claim as written | Measured reality |
|---|---|
| −97 KB | **−1,185 bytes**: 845,414 → 844,229 |
| removes `cc-rs` / C toolchain | **retained.** `bitcoin` 0.32.8 declares `secp256k1` non-optionally |
| C `secp256k1-sys` shrinks | **unchanged at 96,947.** `libsecp256k1.a` byte-identical, sha256 `0358790a…` |
| 6 call sites, all in `tweak.rs` | **4 sites**, one of them in `bitcoin_transaction.rs` |

What it *did* achieve, and the actual point of decision 3: `cargo tree --target
thumbv7em-none-eabihf -p frostsnap_core -i secp256k1@0.29.1` now shows exactly
one parent, `bitcoin v0.32.8`. `secp256kfun` — Frostsnap's own crypto path — is
no longer a consumer of C libsecp256k1.

The load-bearing site was the BIP-341 taproot tweak, now computed by
`bip341_taptweak_key_only` (`frostsnap_core/src/tweak.rs:35`, called at
`:222`) on `secp256kfun`'s `Tag` instead of
`bitcoin::taproot::TapTweakHash::from_key_and_tweak`. The four sites that
actually broke were `tweak.rs:259`, `bitcoin_transaction.rs:415` (the *address*
path, not listed in the original prediction) and two in tests. `PLAN.md` named
`tweak.rs:187` "the load-bearing one"; it did not break.

Validation and its residual gaps — including a confirmed parity blind spot in
the one test designated to outlive the `bitcoin` dep — are in
[DECISIONS.md](DECISIONS.md) decision 3 and its residual-gaps section.

`rust-bitcoin` itself (327,408 bytes) is **kept — decision 4**. It fits, and it
supplies consensus-critical taproot sighash. Its non-optional `secp256k1` dep is
why the C library and clang remain; full C elimination requires revisiting that
decision.

### 2.3 Hardware coupling is narrow and trait-mediated

Storage is generic over a trait, not welded to ESP32:

```rust
// frostsnap_embedded/src/nor_flash_log.rs:2
use embedded_storage::nor_flash::NorFlash;
impl<'a, S: NorFlash> NorFlashLog<'a, S> { ... }
```

Randomness likewise — `frostsnap_core` takes `&mut impl RngCore` at 20+ sites
(`device.rs:106`, `device_nonces.rs:145`, `nonce_stream.rs:162`,
`symmetric_encryption.rs:35`, …). Adapting to STM32 means implementing two
traits, not editing crypto.

---

## 3. What must be rewritten

19 of 32 files in `device/src` touch `esp_hal` — **4,674 of 6,025 LOC (78%)**.

| Group | Files | LOC | Disposition |
|---|---|---|---|
| Event loop | `esp32_run.rs` | 801 | logic ports; pin wiring does not |
| Peripherals / transport | `peripherals.rs`, `io.rs`, `uart_interrupt.rs` | 888 | rewrite for STM32 USB CDC |
| Firmware lifecycle | `secure_boot.rs`, `ota.rs`, `partitions.rs`, `firmware_size.rs` | 1,334 | **discard** (§3.1) |
| Root of trust | `efuse.rs`, `ds.rs`, `flash/genuine_certificate.rs` | 708 | rewrite against callgate (§5) |
| Panic / stack | `panic.rs`, `stack_guard.rs` | 117 | rewrite (§6.2) |
| UI | `frosty_ui.rs`, `screen_test.rs`, binaries | ~600 | rewrite (§4) |

Cross-reference note: `device/src/frosty_ui.rs:72` calls
`set_constraints(Size::new(240, 280))`. Every layout constant in that tree is
sized for a panel 3.7× larger in area than Mk4's.

### 3.1 Discarded: OTA and secure boot

Coldcard's bootloader is PCROP-protected, runs first, and is **never
field-upgradable**. Frostsnap's `secure_boot.rs` and `ota.rs` have no role.
Installation uses Coldcard's existing key-zero DFU path, inheriting a permanent
warning screen and forced delay on every boot. That is unavoidable and
by design (`docs/dev-access.md`).

---

## 4. Wall #1 — the display (Phase 5 scope)

Frostsnap's UI cannot run on Mk4. Decision 1 accepts this cost knowingly.

| | Frostsnap | Coldcard Mk4 |
|---|---|---|
| Panel | 240×280 ST7789 SPI | 128×64 SSD1306 **SPI1 @ 40 MHz**, CS `PA4` / RESET `PA6` / DC `PA8` (`shared/display.py:19-20,32-35,44` for the geometry and pin setup; the **40 MHz is not at any of those lines** — `:32` is a bare `machine.SPI(1)` with no baud rate — it is `shared/ssd1306.py:214`, `rate = 40_000_000 if not self.is_mk5 else 10_000_000`, so Mk4 takes the 40 MHz branch and Mk5 10 MHz. Corrected 2026-09-12) |
| Pixels | 67,200 | 8,192 |
| Buffer | — | 1,024 B `MONO_VLSB` `framebuf.FrameBuffer` (`shared/ssd1306.py:33,40,43`) |
| Flush | partial | **full 1,024 B every `show()`** (`ssd1306.py:123-132`) |
| Color | `Rgb565` (`frostsnap_widgets/src/lib.rs:241`) | 1-bit |
| Fonts | Gray4 anti-aliased, min 15 px (`frostsnap_fonts/src/noto_sans_14_light.rs:6`) | 1-bit bitmap 14/21/6 px (`shared/zevvpeep.py:33,132,329`) |
| Input | CST816S touch, swipe + 2–3 s hold-to-confirm (`frostsnap_widgets/src/lib.rs:142`, `sign_prompt.rs:31`) | 4×3 membrane keypad, 12 keys `0123456789xy`, **randomised scan order** as a Tempest defence (`shared/mempad.py:12-13,36-38`; `shared/numpad.py:10`) |

### 4.1 How much of `frostsnap_widgets` survives — measured

| | LOC | |
|---|---|---|
| `frostsnap_widgets`, total | 19,799 | measured |
| …in files naming `Rgb565` | **13,459 (68%)** | unusable |
| `frostsnap_fonts` | 14,032 | **fully discarded** — Gray4, and its smallest face (15 px) is taller than Mk4's `FontSmall` (14 px) |
| **genuinely reusable, colour-free** | **~850** | see below |

The reusable ~850 LOC, as assessed at phase 0: `backup_model.rs` (398 —
backup-entry state machine, cursor/row/completed-rows), `string_ext.rs` (241 —
no-alloc `StringFixed` with wrapping), `widget_list.rs` (86 — pagination trait),
`distractor.rs` (59 — levenshtein BIP39 decoys for the backup quiz),
`animation_speed.rs` (39).

**None of it was reused in the end, and `distractor.rs` is a REJECTION rather than a
candidate — this list contradicted §7 until 2026-09-10.** §7's cap notes say "Do NOT
port `frostsnap_widgets/src/backup/distractor.rs`", and the reason is a measurement:
`find_closest_distractors` is a pure function of the TRUE word
(`levenshtein*3 − shared_suffix*2`, no RNG), so the displayed triple **identifies its
own answer** — over the vendored 2,048 words, 1,288 are recovered from the triple with
no human input, leaving ~0.467 of `log2(3)` bits per word, i.e. 11.7 bits over 25
words, which `ShareBackup::from_words`' checksums reduce to one candidate. A photograph
of upstream's quiz is a full share disclosure. `firmware/src/quiz.rs` draws uniformly
inside a predicate *symmetric* over the triple instead. The other four were superseded
too: `hal/src/ui.rs` and `firmware/src/wordentry.rs` were written against `ui::Frame`
directly. Treat this row as the phase-0 estimate it was, not as a plan of record.

**Not obvious, and worth exploiting:** the `Widget` *contract* is not
colour-bound. `Widget::Color` is an associated type (`Widget::Color` in `frostsnap_widgets/src/lib.rs`, cited by symbol — **this said `lib.rs:230-232` until 2026-09-12 and was NEVER right**: `type Color: WidgetColor;` is at `:227` inside `pub trait Widget` at `:225`, while `:230-232` is `fn draw`'s doc and signature. Not sibling drift — that file is byte-identical between `0bbc18be` and the sibling's HEAD),
`VecFramebuffer` already bit-packs `BinaryColor` (`vec_framebuffer.rs:230-237,366`)
and `ColorInterpolate` has a `BinaryColor` impl thresholding at 50%
(`widget_color.rs:42-50`). Build a mono `DrawTarget` and reuse the
`Widget`/`DynWidget` traits; reuse none of the concrete widgets.

### 4.2 Text budget and the eight required screens

Usable capacity, computed from the font heights above against 128×64:
**18 cols × 4 rows** (`FontSmall` 7×14), 12×3 (`FontLarge`), 32×10
(`FontTiny` 4×6). Coldcard's own story renderer advances `y` by 13 px and sizes
its scroll bar at `per_page=4` (`shared/display.py:287,289`), confirming 4 lines
is the practical budget.

`PLAN.md` previously listed 4 screens. The `Workflow`/`Prompt` enums
(`device/src/ui.rs:66-99,109-122`; 13 `WidgetTree` variants at
`device/src/widget_tree.rs:25-95`) require **8**:

| # | Screen | Fits in 18×4? | Security-load-bearing |
|---|---|---|---|
| 1 | Standby — device name + held share | yes | no |
| 2 | **Keygen check** — t-of-n + 4-byte code | yes (8 hex chars in `FontLarge`) | **yes** |
| 3 | **Sign approval** — amount / address / fee | **no, paginate** | **yes** |
| 4 | Test-message sign confirm | yes | yes |
| 5 | **Backup display** — 25 words | no: 7 screens at 4 rows, 3 at `FontTiny` | yes |
| 6 | **Backup entry** — 25 words + share index | no, paginate | yes |
| 7 | **Backup check quiz** — 8 of 25 words, three candidates each | yes | **yes** |
| 8 | Address verification — 62-char bech32m | no: 4 lines `FontSmall`, 2 at `FontTiny` | **yes** |

**Five** security requirements that the renderer must not quietly drop (this said
"Four" over a list of five until 2026-09-10):

- **The check quiz is reveal-class and is treated as such.** One candidate in three
  is the true word at the position being asked and a second is a real word from
  elsewhere in the same share, so a clean 8-question pass puts up to **16 of the 25
  words** on the glass (measured worst case over 300 passes; ceiling
  `2 × QUIZ_POSITIONS`, enforced by `const _: () = assert!(quiz::QUIZ_POSITIONS <
  ui::BACKUP_WORDS)`). It therefore has the same consent screen, the same `SECRET on
  glass` warning, the same randomised `ConfirmDigit`, and `mark_sensitive` on every
  candidate row as `DisplayBackup`. This row read "not security-load-bearing" until
  2026-09-10; that was wrong. It is still *less* exposing than a reveal — 8 renders
  against 7, but ≤16 words against 25, no positional certainty, and 17 positions
  never drawn — which is the whole reason it is a subset quiz and not upstream's
  26-screen shape.
- **Sign approval must show, per foreign recipient, both amount and the full
  destination address, plus the network fee** — otherwise the device is a blind
  signer. Frostsnap's own decomposition is
  `2·recipients + fee + optional high-fee warning + confirm`
  (`frostsnap_widgets/src/sign_prompt.rs:337,341-360`; thresholds 100,000 sats /
  5% at `:227-229`), and it deliberately shows only *foreign* recipients, change
  filtered out (`bitcoin_transaction.rs:291-298,300-324`). **The page
  decomposition ports as logic; the rendering does not.**
- **Keygen check must show the 4-byte session-hash code and instruct the user to
  compare it on every device** — this is the anti-MITM check
  (`device/src/widget_tree.rs:102-105`; `frostsnap_widgets/src/keygen_check.rs:30-36,64-71`).
- **The displayed fee is coordinator-controlled.** `TransactionTemplate::fee()`
  is `sum(inputs) − sum(outputs)` over caller-supplied input values, with no
  prevout check (`bitcoin_transaction.rs:252-258`; `push_foreign_input` takes
  `value` on trust at `:112-120`, only `push_owned_input` at `:122-144` validates
  the spk). Taproot sighash *does* bind prevout amounts via `Prevouts::All`
  (`:203-217`), so a forged value yields an invalid signature rather than a
  stolen fee — but the number shown at prompt time is still the coordinator's.
  Do not present it as device-verified.

  This was **worse than stated** until §8.1 defect 10: both sums were
  `.sum::<u64>()`, and with `overflow-checks = false` in the shipped profile the
  overflow was silent, so the fee was not merely unverified but *forgeable in
  both directions* — and because `check` gates on `fee().is_none()`, the wrap also
  let an arithmetically invalid transaction through the device's only validation
  of it. Now `checked_add`, so an overflowing template is refused pre-consent.
- **`user_prompt()` returns an `Option`, and `None` means refuse to sign** — it is
  not a rendering hint. §8.1 defect 12: a foreign output with no address
  representation (OP_RETURN, bare, empty) used to panic here, which under
  `panic = "abort"` is a reset loop reachable from a legal transaction. A caller
  must treat `None` as "reject this request", and must **not** fall back to
  rendering the recipients it *can* display: a consent screen that silently omits
  a recipient is worse than one that refuses to appear.

Address chunking: Coldcard already has a 4-char grouping helper
(`shared/utils.py:728-730`) and a fixed-indent renderer (`display.py:276-279`).
Frostsnap's 6×3 = 18-chunk grid (`address_display.rs:29-40`) does not fit;
the chunking concept transfers, the layout does not.

Input: **hold-to-confirm must be rebuilt on key-down duration** — there is no
touch surface. **Paging is `9` = next and `7` = back, NOT the `5`/`8` this paragraph
specified until 2026-09-10**, and that correction is load-bearing rather than
cosmetic: `firmware/src/main.rs`'s `answer` routes `5` and `8` to `Answer::No`, so a
human following the old instruction part-way through transcribing 25 words would have
**abandoned their own backup** — on the one screen whose entire purpose is to be
copied down carefully. `ui::NEXT_KEY` = `b'9'` and `ui::BACK_KEY` = `b'7'`
(both in `hal/src/ui.rs`); the printed legends were fixed on 2026-09-08 and are now
covered by a `const` assert that compares legend text against the key constants, so
the class is closed rather than the instance. The Coldcard `5`/`8` mapping
(`shared/lcd_display.py:23-26`) was the source of the error and is *not* this
device's mapping.

PIN entry was to wrap Coldcard's existing `ux_show_pin` / `ux_show_phish_words`
(`shared/ux_mk4.py:361-445,351-359`) rather than being redesigned, since decision 2
keeps the gate semantics behind them. **PIN is PUNTED (§5, decided 2026-09-10)**, so
this is a design note for a flow nobody is building: `ui::pin_entry` exists and is
gc-sectioned out for want of a caller.

Note also `shared/display.py:284-285` — `mark_sensitive` is a side-channel
defence triggered specifically by the seed-words layout. The mono backup screen
must preserve it.

---

## 5. Wall #2 — root of trust

| | Frostsnap | Coldcard Mk4 |
|---|---|---|
| Identity | read-protected eFuse key | SE1 + SE2 + MCU key slots |
| Access | direct register reads | bootloader callgate |
| PIN | none | mandatory, SE1-enforced |
| Rate limiting | none | SE1 counter, 13-attempt brick |
| Anti-coercion | none | trick PINs, duress wallets, fast wipe |

These are not interchangeable. **Keep Coldcard's.** The callgate is a
fixed-address PCROP entry point callable from Rust via `extern "C"`, preserving
PIN validation, rate limiting, the brick counter, trick PINs and fast wipe
(`shared/callgate.py` wraps ~25 methods). Discarding it forfeits the entire
dual-secure-element rationale for choosing this hardware — which is presumably
why the hardware was chosen.

**PIN is PUNTED — decided 2026-09-10, and it has one hard consequence.** The
callgate bindings and the entry screens exist but are gc-sectioned out for want of
a caller, and the SE1 sequencing they need cannot be written without a bench
session (slot 11 is writable **once per PIN** because the AES-CTR keystream repeats
from offset 0, a stale slot decrypts to silent garbage with `rv = 0` so the 72
bytes must be self-tagging, and selector 18/2 is deliberately left unbound because
it can brick the unit). Punting is a schedule choice, not a reversal of decision 3
— the callgate stays, and nothing here forecloses adding a PIN later.

What it does foreclose is **recovery**. Installing cold-snap on a unit is
ONE-WAY: `sdcard_recovery` restores only the image already installed, because
`sdcard_try_file` needs an SE1 CHECKMAC against `KEYNUM_firmware` that only a
PIN-authorised upgrade writes, and `enter_dfu` is skipped outright at RDP=2
(`main.c:174-182`). **A PIN is the thing that would make a unit re-flashable**, so
until one exists, any unit that receives this firmware is committed to it. That is
the argument for keeping the dev unit on the bench and not flashing a second.

This is where the trust position in §1 is knowingly compromised: the retained
bootloader and SE code are Coinkite-authored. The alternative is a device with
no PIN, no rate limiting and no coercion resistance, which is strictly worse.

### 5.1 The TRNG — a genuine improvement, but **two** sources, not three

**You write this driver.** This section previously said Mk4 exposes *three
independent* entropy sources — the STM32 TRNG plus SE1 and SE2 RNGs via
`callgate.read_rng(source=…)` — and told you to hash all three. **Reading the
Coldcard sources refutes both halves of that claim**, and the correction is
recorded here rather than quietly dropped, because the §1 rejection of the
MicroPython route rests on entropy integrity:

| Source | Claimed | Measured |
|---|---|---|
| STM32 TRNG | independent | **independent.** Real hardware entropy. |
| SE1 (ATECC608) | independent | **not independent.** `ae_gendig_slot` feeds 20 bytes of *our own STM32 TRNG* into `ae_pick_nonce` (`ae.c:1332`), so its output is a function of the source it is supposed to corroborate. |
| SE2 (DS28C36) | independent | **not an entropy source at all.** `se2_read_rng` reads static `PROT_APH` page 28 (`se2.c:1341-1343`, `:586`) — a fixed value, constant across boots. |

So the honest count is **2**, and SE2 is reclassified as a **fixed
personalisation input**: it still belongs in the transcript (it binds the seed to
this specific unit's secure element) but it contributes no entropy and must never
be counted toward the fail-closed threshold.
`coldsnap_hal::rng::ENTROPY_SOURCE_COUNT` is `2`, and a test fails if the count
is raised without a bench measurement to justify it.

Note also what `check_source` can and cannot do: it is **stateless**, comparing
words *within a single draw* (as `random.c:74-80` does). It therefore cannot
detect a source that is constant *across boots* — exactly SE2's failure mode —
which is why the reclassification had to be structural rather than a health check.

The STM32 TRNG is still better than Frostsnap's ESP32 (single source), and it
still lets us implement RM0432 §32.3.7 SEIS conditioning — the fix Coinkite
shipped only in August 2026 — from the start. Requirements:

- **Fail closed.** No `#ifdef` fallback, ever. Compile error if any source is
  unavailable. This is the specific failure mode of §1.
- **The `cfg` rule is directional.** A `cfg` on a *refusal* fails open and is
  forbidden — that is libngu's defect. A `cfg` on a *bypass* fails closed and is
  mandatory. Stating it as "the module has no conditional compilation at all" got
  this backwards and left an unconditionally public constructor
  (`Entropy::from_proven_seed`) that minted a full `CryptoRng` from hardcoded
  bytes with zero hardware reads — and it compiled for the device target. It is
  now behind the non-default `test-seam` feature.
- Reject on repeated words per source (as `random.c:74-80` does), understanding
  the stateless limit above.
- Health-check each source independently before mixing.

---

## 6. Wall #3 — brick risk, and the panic handler (Phase 2 requirement)

| | MicroPython route | This plan |
|---|---|---|
| Panic behavior | exception, caught | `panic = "abort"` → `b .` |
| Recovery | REPL survives | must be engineered — see below |

Coldcard's own docs: a crash before the login path completes **bricks the
device**. And `frostsnap_core/src/device_nonces.rs` uses `assert_eq!` for flash
read-back verification (`:235` stream id, `:300` read-back; the function spans
`:223`–`:311`) — under `panic = "abort"` each is a permanent halt with no
recovery path. Decision 6 makes fixing this mandatory.

### 6.1 "panic → DFU" does not work on production hardware

This section previously said: *display the panic, then enter DFU via
`callgate.enter_dfu()`*. Reading the bootloader **refutes that**, and not for the
reason assumed:

| Assumed | Actual, verified in source |
|---|---|
| `enter_dfu` is PIN-gated | It is **RDP-gated**. `dispatch.c` case 2 contains no PIN check and no `pinAttempt_t` reference at all. |
| Only a pre-login panic is unrecoverable | Selector 2 / `arg2=0` checks `flash_is_security_level2()` and returns `EPERM`, bailing to `fail` **without entering DFU and without a screen** — pre- *and* post-login (`stm32/mk4-bootloader/dispatch.c:150-165`; `storage.h:39-42`). |
| Production units can DFU | Production units are RDP=2 (`dispatch.c:417-418`, `:404-407`; `shared/version.py:127`), so `EPERM` is the branch that always runs. |
| DFU is reachable somehow | The bootloader's own `enter_dfu()` refuses at RDP=2: `if(flash_is_security_level2()) { LOCKUP_FOREVER(); }` (`main.c:256-258`). Hardware-impossible, not policy-blocked. |

`fail:` re-arms the firewall and **returns to the caller** (`dispatch.c:697-699`),
so the call is a silent no-op rather than a trap.

The only recovery on a locked unit is the bootloader's microSD path
(`main.c:161-182`), and it restores **only the exact image already installed**:
it requires an SE1 checkmac against `KEYNUM_firmware` (`sdcard.c:248-251`;
`verify.c:300-305`), written only by a PIN-authenticated upgrade (`pins.c:1327`,
gated on `PA_SUCCESSFUL` at `:1283-1286`).

### 6.2 The Phase 2 requirement, as amended

**`NVIC_SystemReset`, not DFU.** A reset returns control to the bootloader, whose
verify path still holds a valid signed image, so a transient panic self-heals.
The callgate is a late fallback only — real DFU on RDP≠2 dev units, a harmless
no-op elsewhere.

1. `cpsid i` — stop reentrancy from interrupts.
2. Bump a reboot-survivable panic counter.
3. Under threshold → `NVIC_SystemReset` (AIRCR `0xE000ED0C`, `VECTKEY|SYSRESETREQ`).
4. Past threshold → callgate selector 2, **`arg2 = 0` only**.
5. Unconditional reset as final fallback, so it can never halt.

**Step 4 read "`arg2` 0 then 2" until 2026-09-10, and the code has never done that.**
`hal/src/panic.rs:877-878` calls `callgate::try_enter_dfu()` once, and its comment says
`arg2 = 0` "is baked into `try_enter_dfu` and is not a parameter". That is deliberate and
must not be "fixed" back: `arg2 = 2` on the DFU selector is one of the sub-calls this
project leaves unbound because it can brick the unit (§5). DECISIONS.md decision 6
carried the same wrong ordering.

No display and no allocation in the handler: the OLED driver can itself panic,
and the bootloader repaints on reset. The handler must also **not touch flash** —
the bootloader's verification is what makes the reset recoverable.

A handler in this shape **compiles clean under 1.88.0 for
`thumbv7em-none-eabihf`** and its disassembly was checked (`cpsid i`, RTC WPR
`0xCA`/`0x53` unlock, `cmp #0x3`, AIRCR store, `blx` guarded by the
`(dest & 0xff) == 0x05` check). Two `asm!` constraints, found empirically:
`clobber_abi("C")` warns about reserved FP registers D16–D31 on this hard-float
target and must be avoided; `r6`/`r7` are LLVM-reserved and cannot be clobbered
even though the C caller says the gate trashes `r0-r4`/`r9`/`r10`. Legal set:
`r4, r5, r8, r9, r10, r11, r12, lr`.

The counter needs reboot-survivable storage and **SRAM is unusable** — the
bootloader wipes SRAM1/2/3 on every boot (`main.c:44-49`), which is exactly why
it reads its own DFU flag at `0x20008000` *before* wiping (`main.c:115-122,129`).
RTC backup registers are the right home: the bootloader enables the RTC clock
(`clocks.c:161,171,186`) but never touches `BKPxR`. Two assumptions there need
bench confirmation — see §9.

### 6.3 Reset-loop risk moves the work upstream: panic sites to remove

With reset as the recovery, a *deterministic* panic becomes a reset loop. So
eliminating panic sites, not perfecting recovery, is the priority.

| Priority | Site | Why |
|---|---|---|
| **1** | `device.rs:491` indexes `agg_nonces[signature_index]` | **Remotely triggerable by the coordinator, pre-flash-write.** `signature_index` enumerates `sign_items` (`device.rs:480-491`), whose length is the count of locally-owned input sighashes (`sign_task.rs:120-144`), but `GroupSignReq::check` never validates `agg_nonces.len()` against it (`message.rs:101-113` copies `agg_nonces` through unchecked; `sign_task.rs:42-102` checks purpose and ownership only). A coordinator sending fewer `agg_nonces` than sighashes panics the device. Must return `ActionError`. It is **post-consent**: `device.rs:491` is inside `sign_ack`, invoked only on `UiEvent::SigningConfirm` (`device/src/esp32_run.rs:736-741`), and is the only site indexing `agg_nonces`. |
| 2 | `device_nonces.rs` write/sign path, in `sign_guaranteeing_nonces_destroyed`, BY SYMBOL: the `read_slot` before the stream-id check, the `assert_eq!(.., "wrong stream id")`, the nonce-iterator `next()`, the empty-`sessions` and `next_prg_state` pair, the read-back `read_slot`, the read-back `assert_eq!`, and the `signing_state` unwrap | 8 of that file's 16 panic sites; each a reset-loop trigger. **ALL CONVERTED.** **The line numbers that stood here until 2026-09-12 (`:234, :235, :269, :278, :281, :298, :300, :307`) were UPSTREAM's, not this repo's** — they resolve exactly in `/Users/garykrause/repos/frostsnap` but in `vendor/` `:234-235` are doc-comment prose, `:298-300` are a justification comment and `:278` is blank. Cited by symbol per a5922e4's rule. Four of the eight now have named tests reaching them — see §9 item 4. |
| 3 | `frostsnap_embedded/src/ab_write.rs`, BY SYMBOL: `AbSlot::try_write`'s index `checked_add`, and in `Slot::try_write` the `erase_all`, the encode, the `flush` and `read_index`'s int decode (**the `:44, :106, :109, :110, :118` that stood here until 2026-09-12 were UPSTREAM lines** — in `vendor/` `:44` is `///`, `:106` is a match arm and `:110` is a bare `}`) | The panics that actually fire on real flash I/O errors, previously out of scope. `AbSlot::write` erases+writes **twice** (`:56-57`), so any STM32 flash error panics mid-A/B-update — the worst moment for nonce state. |

Boot sequencing: clear the panic counter only *after* the event loop is proven
healthy, or it never trips.

Related safety findings that must be preserved regardless of route:

- `shared/pwsave.py:277-292` — `enforce_policy()` calls
  `callgate.fast_wipe(silent=False)` when the microSD 2FA file fails to
  decrypt, and is invoked unconditionally at login
  (`actions.py:874-875`). **A partial cipher migration destroys the seed.**
- `shared/nvstore.py:356-373` — settings slots are found by trial-decrypting
  for a literal `{"`, and garbage is explicitly *not* an error. A cipher change
  **silently resets all settings**.
- FROST nonce reuse is affine: two challenges over one nonce solve for the
  secret share `x_i`. Nonce storage requires read-back-verified writes.

---

## 7. What is lost: the simulator — and the harness that replaces it

| | MicroPython route | This plan |
|---|---|---|
| Coldcard simulator | **works** (`unix/variant/mpconfigvariant.mk:47`) | **does not — no MicroPython** |
| Coldcard Python test suite | usable | unusable |

This is the most material loss. Decision 5 accepts it and names the substitutes:
host unit tests plus interop against a real `frostsnap_coordinator`. Three tiers,
in increasing cost:

### Tier 1 — host unit tests (working; counts re-measured 2026-08-17, all passing)

**A plain `cargo test --workspace` does not compile.** The exact per-crate
invocations must be pinned in a script; the vendored manifests have `default = []`
(see `vendor/README.md`) so features are never implicit.

| Crate | Invocation | Tests |
|---|---|---|
| `frostsnap_core` | `--features coordinator` (all 13 targets) | 51 → **63** |
| `frostsnap_comms` | `--features coordinator` | 10 |
| `frostsnap_embedded` | `--features std` | 17 (**15** without `std`, was 7) |
| `frost_backup` | `--lib` + 5 of 6 test targets | 19 |
| `frostsnap_macros` | *(none needed)* | 7 |
| `coldsnap_hal` | **`--features fake-flash,test-seam`** — 267 lib + 5 smoke + 16 integration | 88 → **288** |
| `coldsnap_firmware` | *(none needed)* — 120 lib + 52 bin | **172** |
| **Total** | | 204 → **576** |

**The `coldsnap_hal` row read "135 lib + 5 smoke + 11 integration \| 88 → 151" and the
total "204 → 268" until 2026-09-10, and the table had no `coldsnap_firmware` row at
all** — the crate that holds the dispatch, the consent gate, the event loop and 172 of
the 576 tests. Every figure above was re-verified 2026-09-10 by running each gate and
taking the exit status off the command rather than off a pipe; all fourteen exit 0.

`coldsnap_hal` needs those two features for its `tests/` directory (`cfg(test)`
does not reach `tests/`, which links the lib as an ordinary dependency). Both are
off by default so neither a fake flash nor an entropy bypass can be linked into
firmware — the `test-seam` gate is itself one of the §8.1 fixes.

`coldsnap_hal`'s `tests/integration_frostsnap_over_hal.rs` is the only place the
real `frostsnap_embedded::AbSlot` / `frostsnap_core::device_nonces` stack runs
against the HAL's actual geometry (`WRITE_SIZE = 8`, `ERASE_SIZE = 4096`) and the
real `Entropy` as the `&mut impl RngCore`. It is what catches a const or
trait-bound mismatch between the two halves; a per-module test cannot see one.

The phase-3 delta is `coldsnap_hal` 88 → 137: **+18** in `comms.rs` (**+20** after
decision 7's `FRAME_LIMIT` reversal added two, §7) and **+31** in
`usb.rs`. Both modules were mutation-tested before being called done — 23
deliberate defects in `usb.rs`, each caught by a named test, 0 survivors (§8.2).

**Read this table as a lower bound on effort, not as evidence of correctness.**
A count of passing tests says nothing about what they reach. All 60 of
`coldsnap_hal`'s passed while `flash.rs` had **zero** tests and six independent
safety checks in it were deletable without any test noticing (§8.1). The number
went up because the gaps were found by adversarial review, not by the suite.

All with `--target aarch64-apple-darwin`, which is required to override
`build.target`.

Two traps, both measured:

- **`frostsnap_embedded` without `--features std` loses all `NorFlashLog`
  coverage** — the append-only log used for nonce durability. Gated on
  `cfg(test)` **and** `feature = "std"`
  (`frostsnap_embedded/src/nor_flash_log.rs:77-78`); the vendored manifest moved
  `std` out of `default`. Silent, not an error. (The count is now 17 with `std`;
  it was 9 when this trap was first measured.)
- **`frostsnap_core` requires `--features coordinator` to test at all.** Without
  it the integration binaries fail to resolve `frostsnap_core::coordinator`
  (`E0432`), a consequence of the vendored `default = []`. With it: **63 tests
  across 12 binaries, all passing** — the 11 `.rs` files in
  `vendor/frostsnap/frostsnap_core/tests/` plus the `--lib` target, 21 lib + 42
  integration — including both wire-format backward-compat guards. `cargo test -p
  frostsnap_core --features coordinator` is the real invocation; `--lib` alone
  runs 21 of the 63. The trajectory (40 → 44 → 51 → 63) lives in
  `vendor/README.md`, which is the authority for it; all 11 test files predate this
  repo's first commit, so the earlier pairings cannot be re-derived here.
  **This read "51 tests across 13 binaries, all passing (40 across 11 before the
  panic-site work)" and "`--lib` alone runs only 9 of the 51" until 2026-09-13**, and
  the "13" was wrong even at 51. **The mechanism accounts for BOTH readings, so
  neither is a typo:** `grep -c '^test result:'` over the gate log is **13**, because
  `cargo test` gives `Doc-tests frostsnap_core` its own line — log lines 137-139,
  `Doc-tests frostsnap_core` / `running 0 tests`. It carries **zero** tests; the
  crate's only doc fence is a non-Rust `text` fence at `tweak.rs:13`. So 13 is a LINE
  count of harnesses and 12 is the count of binaries that hold tests.
  `tests/common/` and `tests/env/` are `mod` helper dirs with no `main.rs`, so cargo
  builds no target from them.
- `frostsnap_core/tests/{wire_size_measure,zz_claim3_crossover}.rs` were **moved
  to `tools/research-scratch/`** — earlier-session scratch, untracked upstream,
  and their 26 `E0432`s broke `cargo test` for the whole package rather than
  being skipped. `frost_backup/tests/descriptor_match.rs` still needs
  `frostsnap_coordinator` + `miniscript` and remains excluded.

`TestNorFlash` (`frostsnap_embedded/src/test.rs:4,15,37-38,46-47`) is a 16 KB
in-RAM array, `WRITE_SIZE=4` / `ERASE_SIZE=4096`, asserting word alignment. It
covers `AbSlot` A/B writes including torn-write recovery, `FlashPartition`
splitting, and `NorFlashLog` append/replay. **It does not model power-loss
mid-erase, bit-rot, or write-disturb** — so it is not a substitute for Phase 7.

Note its `WRITE_SIZE = 4` is **not** the device's. `coldsnap_hal::flash::fake::FakeFlash`
is the same idea at the shipped geometry (`WRITE_SIZE = 8`, `ERASE_SIZE = 4096`)
with the NOR program-once rule enforced and schedulable `PROGERR`/`WRPERR`
refusals; it is behind the `fake-flash` feature so a test double can never be
linked into firmware. Everything in the previous paragraph's "does not model" list
applies to it too.

### Tier 2 — the in-process protocol simulator (cheapest real coverage)

`frostsnap_core` already ships one, and it needs no transport and no flash:
`tests/common/mod.rs` (456 LOC) has a `Run` driver, a `Send` enum routing all
four message directions (`:26-40`), and `TestDeviceKeyGen` implementing
`DeviceSecretDerivation` with HMAC (`:78-103`). `tests/endtoend.rs:20-33,57`
already drives multi-device keygen plus repeated signing with rotating signer
subsets — 11 tests passing.

No flash is needed because `FrostSigner` is generic with an in-RAM default:
`FrostSigner<S = MemoryNonceSlot>` (`device.rs:35`; `device_nonces.rs:501-514`).
Only `frostsnap_embedded`'s `NonceAbSlot<'a, S: NorFlash>`
(`nonce_slots.rs:9-21`) needs a `NorFlash` at all. **This is where Phase 4
starts.**

### Tier 3 — coordinator interop over a stub transport

The seam is two methods. `frostsnap_coordinator::Serial`
(`serial_port.rs:15-22`) returns `Box<dyn serialport::SerialPort>` (`:10`), taken
by trait object at `usb_serial_manager.rs:83`. Of `SerialPort`'s 25 methods,
`FramedSerialPort` calls only `bytes_to_read()` (`serial_port.rs:70`) plus
`io::Read`/`io::Write` (`:133-135,139,177-178`). Upstream already proves the rest
is stubbable: `cdc_acm_usb.rs:192` implements the trait over a `nusb` transport
with **22 `unimplemented!()`** (measured); `frostsnapp/rust/src/api/port.rs:57`
implements `Serial` over a raw fd. **No ESP32 and no hardware.**

**An in-memory duplex pipe was the plan here and it is impossible**; this is now
two processes over a pty pair, measured 2026-08-16. A single cargo graph cannot
hold both `coldsnap_hal` (which pulls the vendored frostsnap crates) and upstream
`frostsnap_coordinator` (which pulls its own): `cargo generate-lockfile` fails
with `package collision in the lockfile: packages frost_backup v0.1.0
(cold-snap/vendor/…) and frost_backup v0.1.0 (frostsnap/…) are different`. So the
split is enforced by cargo, not by discipline, and the transport must cross a
process boundary. **The separated graph does resolve** — measured 2026-08-17:
`hostcheck/` (own `[workspace]`, `frostsnap_coordinator` by path + `anyhow`) locks
185 packages / 133 normal crates with **no `links` conflict on `secp256k1-sys`**,
builds, and runs. That was genuinely open until now: the collision probe above dies
on the `frost_backup` name clash *before* resolution ever reaches a `links` key, so
it proved nothing either way about duplicate native libraries.
Use `serialport::TTYPort::pair()` — both ends implement
`serialport::SerialPort`, so no 25-method impl is needed at all — and give the
**coordinator the slave end**: FIONREAD on a darwin pty *master* always returns 0
(measured), and `FramedSerialPort::anything_to_read()` is exactly that ioctl
(`serial_port.rs:69-75`), so a coordinator holding the master reads nothing
forever with no error or log. Two further measured traps: an undrained pty blocks
writes past ~1 KB, and `TTYPort::pair()` sets a 100 ms timeout while a read
timeout is turned into a port *disconnect* (`usb_serial_manager.rs:302-311`) — set
5 s to match `DesktopSerial` (`serial_port.rs:257-260`).

That write trap matters more than it looks: `raw_send` → `flush()` → `tcdrain(fd)`
is **not** subject to `PORT_TIMEOUT`, and every signing frame is over 1 KB, so a
device that stops reading parks the harness on its first frame (measured 8.176 s,
released by the stub's watchdog rather than by any deadline). Fixed with a writer
thread on a `dup`ed fd plus `WRITE_STALL_LIMIT`, which bounds **the run** — the
parked `tcdrain` itself remains uninterruptible, so "the write path is bounded" is
true of the harness and not of the syscall. Say it that way.

**A third measured trap, and it made a test that could not fail.** At the default
`STUB_CHUNK=64` the stub's writes **coalesce** in the pty and the coordinator still
decodes a whole frame from one buffer, so `decode_from_reader`'s reassembly is never
exercised. The real mechanism is the **1 ms inter-chunk gap**, not the chunk size —
without the gap, chunked writes coalesce at *any* size. Only `STUB_CHUNK=1` plus the
gap forces a genuine partial frame (magic→announce delta 2.5 ms → 85 ms). For one
run `STUB_CHUNK` was an env var nothing set. `main` now runs both sizes on every
invocation.

**`hostcheck/src/main.rs`'s module header is the harness's measurement and mutation
record** — the pty polarity above, the chunk trap, the write-path bound, the
nonce-stream arithmetic, and ~15 mutations each with its run timing and failure
string. Read it before changing the harness; it is not duplicated here.

Construct `FramedSerialPort::new` directly (it is `pub`, `serial_port.rs:57-67`)
to bypass discovery, which filters on `VID=12346`/`PID=4097`
(`usb_serial_manager.rs:2-3,165-167`). Upstream's own `frostsnap_factory` is the
Flutter-free precedent for exactly this: `genuine_check.rs:40-120` is a ~60-line
poll loop doing magic bytes → `Announce` → `AnnounceAck` over a directly
constructed `FramedSerialPort::<Downstream>`.

The stub must speak the framing itself, since `device/src/io.rs` is `esp_hal`-bound —
but only 3 `esp_hal` references in 350 lines, and the framing lives in the
portable crate: bincode with a 32 KB limit, a 7-byte magic-byte handshake resent
every 100 ms, and a type-level `Upstream`/`Downstream` split with a "conch" token
for daisy-chain turn-taking (`frostsnap_comms/src/lib.rs:30,36,54-60,68,335-366`).
The device side is `Upstream`.

### Tier 4 — Renode, and what it still cannot reach

Renode is the only listed path to executing real firmware images without
hardware, and it covers the STM32 core, flash controller, SPI, and the TRNG
register interface. It **cannot** cover the two highest-risk items: the callgate
is PCROP bootloader code outside the firmware image being emulated (§5), and SE1
/ SE2 are external I2C parts with no Renode model. *(Assessed, not attempted.)*

### Not testable without hardware, at any tier

SSD1306 init/timing and physical legibility; keypad scan/debounce and its
randomised timing; the callgate in any form; the TRNG (§5.1 — **two** sources, not
three) and its health
checks; panic→reset recovery; real STM32 program/erase semantics and power-loss
durability; FROST signing latency in `secp256kfun` on a 120 MHz M4F (**this read
"`secp-lowmemory` signing latency" until 2026-09-13**; that feature is provably inert
here — §9 item 1 — and the latency belongs to pure-Rust code, not to the C library);
and — new in phase 3 — the OTG_FS
register sequences (core reset, FIFO flush, endpoint enable/NAK, VBUS override)
plus the host-driven enumeration that exercises them. Budget for this.

### Transport sizing — re-measured 2026-08-14, and the bound RAISED to 4,096 on 2026-08-18

> **Read this first.** `FRAME_LIMIT` is now **4,096 B**, not 2,060 — see
> **DECISIONS.md 7** for the reversal, the declared support envelope (*n* ≤ 12
> devices, any *t* ≤ *n*) and what is out of scope. Every measurement below stands
> exactly as taken; the "vs 2,060" columns are kept as the evidence that produced
> the raise, and each table says what changes at 4,096. The SRAM cost is
> **2 × `FRAME_LIMIT` = 8,192 B**, not one buffer's worth.

**Where 2,060 comes from, corrected.** It is `MAX_MSG_LEN` from Coldcard's **HID**
reassembly buffer — 4+4+4+2048, `shared/public_constants.py:26-31`, consumed by
the 64-byte-report framing in `shared/usb.py:140-172`. That is not this
transport: phase 3 is CDC, and `frostsnap_comms` has never heard of the number.
`frostsnap_coordinator/tests/coldcard_msg_len.rs:26`, cited by earlier drafts of
this section as the pinning assertion, has now been read, and it is **not an
upstream file at all** — it is an untracked scratch test *this project* wrote in
the sibling frostsnap checkout. Line 26 is `const COLDCARD_MAX_MSG_LEN: usize =
2060; // shared/public_constants.py: 4+4+4+2048`: our own constant, pinning
nothing upstream. It also asserts the *opposite* of what those drafts implied —
`assert!(!overs.is_empty(), "expected at least one real message to exceed
MAX_MSG_LEN")` (`:243-246`) — so it is evidence that 2,060 is too small, not that
it is adequate. Its printed figures are further **body-only despite being labelled
"FULL WIRE"**, so they understate by the envelope; prefer this table.
So 2,060 was a bound this project chose, not one the wire imposes — but *some*
hard bound must exist, because the vendored decoder's own limit is
`MAX_MESSAGE_ALLOC_SIZE = 1 << 15` (`frostsnap_comms/src/lib.rs:54,57`) and
32 KiB is 5% of SRAM. It is enforced structurally in
`coldsnap_hal::comms::FRAME_LIMIT`: the accumulator *is* `[u8; FRAME_LIMIT]`, so
the bound cannot be forgotten, only deleted. **The number chosen is 4,096**
(DECISIONS.md 7): the census below refused four real messages at 2,060, one of
them device-emitted.

**Every figure in this table used to be the message BODY only.** Nothing puts a
bare `WireCoordinatorSendBody`/`WireDeviceSendBody` on the wire; the frame is
`ReceiveSerial<D>`, which adds a variant tag plus the direction's envelope —
`Destination` upstream, `DeviceId` downstream. The **envelope proper** is **+36 B
upstream** (`Message` tag 1 + `Destination::Particular` tag 1 + set length 1 +
`DeviceId` 33; only +2 B for `Destination::All`) and **+34 B downstream** (tag 1 +
`DeviceId` 33).

Earlier drafts called the envelope "+128 B upstream". That is wrong, and the error
is worth naming because it is easy to repeat: 128 is the *whole* distance from the
bare `GroupSignReq` to the full frame on the `RequestSign` row (2,016 → 2,144),
which is the 36-byte envelope **plus** `DeviceSignReq`, the `Signing`/`RequestSign`
tags, the `Core` tag and the `EncapsV0` wrap. The Body column below is a different
inner struct on each row, so the Body→Full-wire distance is per-row, not a
constant: it is 128 B for the `RequestSign` rows and 39 B for the `NonceResponse`
rows (2,001 → 2,040). **No number in the table changes** — the measurement always
encoded the real frame (`wire_size_measure.rs:70-83` wraps every body in
`ReceiveSerial`) — only this explanation of it does. Re-measured with
`tools/research-scratch/wire_size_measure.rs` (see its header for the invocation).
Four rows are pinned as `coldsnap_hal::comms` tests, which print the same figures
and now assert them **exactly**:
`a_single_stream_nonce_response_fits_with_the_margin_plan_records` (2,040),
`real_signature_share_batch_now_fits_within_the_raised_bound` (2,105 and 2,713 —
this test was `real_signature_share_batch_is_refused` before the raise),
`the_four_frames_the_old_bound_refused_now_fit` (2,105 / 2,238 / 2,179 / 2,215,
plus the two-segment 4,038) and
`three_nonce_segments_are_refused_by_the_new_bound` (6,036).

| Frame, as it reaches the wire | Body | Full wire | vs 2,060 (the old bound) |
|---|---|---|---|
| `NonceResponse` 1×30 (one full batch) | 2,001 | **2,040** | fits, **20 spare** — the old row claimed 2,006 B / 54 spare |
| `SignatureShare`, 1 share + 30 replenish nonces | — | **2,105** | **over by 45** |
| `SignatureShare`, 20 shares + 30 replenish nonces | — | **2,713** | **over by 653** |
| `SignatureShare`, 20 shares, `replenish = None` | — | 715 | fits |
| `RequestSign` 5 in / 2 out | 1,089 | 1,217 | fits, 843 spare |
| `RequestSign` 10 in / 3 out | 2,016 | **2,144** | **over by 84** — body-only said "fits, 44 spare" |
| `RequestSign` 20 in / 3 out | 3,816 | 3,944 | over by 1,884 |
| `NonceResponse` 2×30 | 3,999 | 4,038 | over by 1,978 |
| `OpenNonceStreams` ×64, max varints | — | 1,708 | fits, 352 spare |
| `OpenNonceStreams` ×85, max varints | — | 2,254 | over by 194 |

**At 4,096 every row above fits** — the largest is the 20-in/3-out `RequestSign`
at 3,944 (152 spare) and the two-segment `NonceResponse` at 4,038 (58 spare).
That 58 B is exactly why the number is 4,096 and not 3,072. Three segments
(6,036 B) does not fit and is out of scope; see the caps below.

**Keygen, measured 2026-08-18 — it fits, but only just, and it scales with device
count.** Every figure above is signing or nonces; this section previously said
nothing about keygen, so a keygen frame could have exceeded the bound at phase-4
milestone 4 instead of milestone 6. It does not, for realistic device counts. These
are **real** messages captured from real keygens driven through the vendored Tier-2
`Run` harness (`start_after_keygen` at each *n*, walking `run.transcript`) — not
hand-built, because `AggKeygenInput` and `KeyGenResponse` are crypto objects whose
size is the whole point.

| Devices | `Begin` | `CertifyPlease` (worst) | `Check` | vs 2,060 (the old bound) |
|---|---|---|---|---|
| 2 | 205 | 583 | 483 | fits |
| 3 | 271 | 778 | 646 | fits |
| 5 | 403 | 1,201 | 972 | fits |
| 7 | 537 | 1,624 | 1,298 | fits, 436 spare |
| 9 (t=5) | 669 | 2,047 | 1,624 | fits by 13 B |
| **9 (t=9)** | — | **2,179** | 1,624 | **over by 119** |
| 10 | — | **2,242** | 1,787 | **over by 182** |
| 11 | 801 | 2,470 | 1,950 | over by 410 |
| 13 | 933 | 2,893 | **2,276** | `Check` crosses too |

**At 4,096, keygen fits to 17 devices and is declared to 12** (12-of-12
`CertifyPlease` = 2,863 B, 1,233 B spare). The gap between "fits" and "declared"
is deliberate: the 13-byte margin at 9-of-5 below is the whole argument — a margin
inside a varint boundary is not a margin, and one added upstream field moves the
edge. DECISIONS.md 7.

`CertifyPlease` is the binding frame and its size is **exactly `195·n + 33·t + 127`**
— measured 2026-08-18 over n∈{5,7,9} × t=2..n, 18 real keygens, slope 195.0 B/device
at every t and exactly +33 per threshold step. The earlier "~211 B per device" was an
artefact of moving t with n. **The worst cell is always t = n**, i.e. `228·n + 127`.
`Check` is **t-independent** at `163·n + 157` and crosses at **n = 12 (2,113 B)** — its
map carries **n+1** entries because the coordinator inserts its own key
(`coordinator.rs:677-680`, shipped at `:740-743`). Device→coordinator keygen traffic is never the problem —
`Response` is `32·n + 33·t + 156` — **741 B at 9-of-9**, not the 611 B an earlier
draft recorded (that was the grid's low-*t* cell at n=7); it crosses 2,060 only at
n = t = 30. `Certify` 152 B, `Ack` 87 B.

Two things worth naming. **The table's *t* moves with *n*, so read it as a lower
bound, not the worst case.** At t = n the crossover is earlier: 8-of-8 = 1,951 fits,
**9-of-9 = 2,179 does not**. The largest all-*t* configuration that fits 2,060 is
**8-of-8**. And the 13-byte margin at 9-of-5 is not a margin at all — it is inside a
varint boundary.
And a third of the size at that point is the **envelope**: the coordinator
broadcasts keygen to every participant, so `Destination::Particular` carries 33·*n*
+ 4 bytes — 299 B at *n* = 9. Unicasting would cost 36 B and move the crossover well
out, but that is not available: `Destination::All` is produced **only for
payload-free bodies** (`usb_serial_manager.rs:674/755/800`,
`firmware_upgrade.rs:143`), so **33·n is a floor on every C2D frame that carries
anything**, not an avoidable case.

**Three crossovers, all exact.** Inbound `RequestSign` with 1 output exceeds 2,060
at **11 owned inputs (2,238 B)**; 10 inputs is 2,058, i.e. two bytes under, so the
margin at the last fitting size is noise. A single-segment `NonceResponse` exceeds
it at **31 nonces (2,106 B)** — and `NONCE_BATCH_SIZE` is 30, so a full batch
fits *alone* and overflows the moment it rides along with anything else. The third
is keygen `CertifyPlease` at **10 devices (2,242 B)**, above.

**What this meant for the `FRAME_LIMIT` decision — and the decision, taken
2026-08-18.** A raise has to clear the worst frame the device must accept, and the
candidates are `SignatureShare` + a full replenish at **2,713 B** (20 shares) and
keygen `CertifyPlease`, which is unbounded in *n* at 195 B/device + 33 B/threshold
step. So a raise cannot be justified as "big enough for everything" — only against
a stated maximum device count. **3,072 B is not enough, and the reason was missed
until the full census.** It fails **`RequestSign` at 20 owned inputs / 3 outputs,
3,944 B**, which is inside the declared envelope. (Earlier drafts justified 4,096
with a 2-segment `NonceResponse` at 4,038 B "which the coordinator can force,
because its producer never calls `OpenNonceStreams::split()`". **That was false** —
see the correction under the caps below. The 4,038 B frame still fits 4,096 and is
still in the envelope; it is simply not the frame that rules 3,072 out. 3,944 is.)
**So the number is 4,096 and the declared envelope is
*n* ≤ 12 devices at any *t* ≤ *n*** — both recorded, because a number without a
stated *n* is decoration again. **DECISIONS.md 7** is the authority: rationale,
consequences, the out-of-scope list, and the 2 × `FRAME_LIMIT` SRAM cost.

**What enforcing 2,060 cost, and what the raise did about it.** Signing could not
complete over this transport, in both directions:

- **Outbound.** `device.rs:509-523` builds `SignatureShare { signature_shares,
  replenish_nonces }` as one indivisible message, and a replenish of a full batch
  puts it at 2,105 B for even a single share. `NONCE_BATCH_SIZE` (30,
  `device.rs:32`) moves in lockstep with the coordinator's
  `MIN_NONCES_BEFORE_REQUEST` (`coordinator.rs:43`), so it cannot be shrunk on the
  device side alone. **Fixed by the raise** — it fits with 1,991 B spare, pinned by
  `real_signature_share_batch_now_fits_within_the_raised_bound`.
- **Inbound.** `Link::poll` reports `Desync` on any frame it cannot buffer, so a
  transaction with **11 or more owned inputs was unsignable**. **Fixed by the
  raise** to 20 inputs (3,944 B); 21+ is out of scope.

The raise was the fix available *because* segmentation was not. The claim earlier
drafts made here — that the wire format "already has one,
`SigningReqSubSegment`" — is **false, and its replacement figures were false the
same way**. `SigningReqSubSegment` occurs in exactly two places in the vendored
tree: its definition (`nonce_stream.rs:11`) and a coordinator-internal
`BTreeMap<DeviceId, SigningReqSubSegment>` (`coord_nonces.rs:47-48`). It is a field
of **no message enum** and appears nowhere in `frostsnap_comms`, so it never
travels as a frame. Its 1,999 B at 30-of-30 is a `bincode` measurement of a struct
that is never framed: it therefore neither fits nor overflows, and the "+128 puts
it 67 B over" arithmetic and the later "≈2,042 B, fits with 18 B spare" both
invented a wire size for something with no wire representation. Neither figure
should be cited.

The consequence is worse than the old text implied: there is **no existing
segmentation on either failing path**. `RequestSign`'s size comes from
`GroupSignReq`'s inputs, and outbound `SignatureShare` has no segment type at all.
Segmenting either direction is a *new* wire format needing upstream agreement — so
the raise was the only option that did not require the coordinator, and it is
recorded as a deliberate reversal (DECISIONS.md 7) with both pinning tests updated
to the new number rather than deleted.

#### Three device-side caps: ALL THREE IMPLEMENTED (`Outbox::push`)

**This heading read "REQUIRED and UNIMPLEMENTED (phase 4)" until 2026-09-10, and
the paragraph under it read:** *"Three caps are required, and none is implemented,
because all three live in message-construction code that does not exist in this
tree: there is no event loop, no bin target, and nothing calls `encode_frame`
outside tests. No helper was written for them either — a cap with no caller cannot
be tested against the code that will need it."* **Every clause of that was false.**
There is an event loop (`firmware/src/main.rs` step 10), there is a bin target
(`firmware/`, which links at 379,648 B under `cargo build --release`), `encode_frame` has a production caller
(`Outbox::encode`, `firmware/src/lib.rs`'s `Outbox::encode`), and all three caps are implemented in
`Outbox::push` (`firmware/src/lib.rs`). This was the single most misleading
paragraph in the file: it read as a standing reason to go and build something that
already existed.

**4,096 is necessary and now sufficient for what the device constructs.**
`FRAME_LIMIT` bounds what the device will *buffer* and what its encoder will
*emit*; `Outbox::push` is what bounds what the device **constructs**, and it is the
one funnel every device-bound body goes through. Each cap below records what is
implemented and the named test that fails if it is removed — verified by mutation
2026-09-10, four mutations, four caught, 0 survivors.

1. **One nonce segment per frame — IMPLEMENTED.** `NonceResponse` is unbounded in
   segment count (1 → 2,040 B, 2 → 4,038, 3 → 6,036), and the count is **not the
   device's own choice**: `device.rs:273-296` emits one segment per stream in the
   received `OpenNonceStreams`, so the coordinator picks it. `Outbox::push` splits a
   multi-segment `NonceResponse` into one frame per segment, recursing at depth 2 at
   most because each recursive call carries exactly one segment. Splitting is legal:
   the coordinator's handler is a per-segment loop with no cross-segment state.
   Pinned by `nonce_response_is_split_one_segment_per_frame`, which opens all four
   nonce slots with `remaining: 0` so the reply genuinely exceeds `FRAME_LIMIT` —
   and asserts that it does, so the test cannot pass vacuously. **Mutation:**
   widening the split guard to `segments.len() > 9_999` fails it with
   `dispatch: Comms(FrameTooLong)`. The old refusal boundary
   `three_nonce_segments_are_refused_by_the_new_bound` still stands as the
   encoder-side backstop.

   **Correction, 2026-08-19.** Earlier drafts of this item and of §7 said "the
   coordinator's producer never calls `OpenNonceStreams::split()`". **It does**, and
   unconditionally: `NonceReplenishProtocol::new` calls
   `open_nonce_stream.split()` (`frostsnap_coordinator/src/nonce_replenish.rs:31`,
   the *only* `OpenNonceStreams` sender), and `split()` yields one message per stream
   (`frostsnap_core/src/message/signing.rs:17-24`). The corrected facts make this cap
   **more** necessary, not less: the flutter app asks for **four** streams
   (`frostsnapp/rust/src/coordinator.rs:50`, `N_NONCE_STREAMS = 4`), so the split is
   the only reason four streams is not already an upstream bug — an unsplit
   four-segment reply is **~8 KB**, which no `FRAME_LIMIT` in scope covers and which
   the device would build and then have its own encoder refuse. So the cap is
   belt-and-braces against a coordinator that stops splitting, not a fix for one that
   never did. Do not "correct" this back by deleting the cap.
2. **A `HeldShares2` cap — IMPLEMENTED as a whole-message REFUSAL, deliberately
   not as a truncation.** 188 B + ~150 B per extra stored share, so ~26 stored
   shares overruns 4,096. **Device-emitted**, no coordinator involved. `Outbox::push`
   gives it no special case on purpose: it falls through to `encode`, and an
   over-large reply comes back `CommsError::FrameTooLong` with no frame written and
   no partial write. Truncating a restoration reply would tell the coordinator a
   share does not exist — a data-loss-shaped lie, and the one failure mode worse
   than a dropped message. Refusing is recoverable and visible. Pinned by
   `held_shares2_over_frame_limit_is_refused_whole`, which also pushes a
   single-share `HeldShares2` as a positive control so the bound cannot be "fixed"
   by refusing everything. **Mutation:** making `encode` swallow the encoder's
   refusal (`encode_frame(..).unwrap_or(0)`) fails it.
3. **`Debug` truncation — IMPLEMENTED.** `WireDeviceSendBody::Debug`'s `String` is
   unbounded and is the one field whose length the device picks freely.
   `Outbox::push` cuts it to `DEBUG_MESSAGE_LIMIT` = 256 B **on a UTF-8 boundary**;
   `truncate_debug` walks back to the nearest boundary because `String::truncate`
   panics off one and a panic here is a brick. Pinned by
   `debug_message_is_truncated_on_a_char_boundary` and by
   `nothing_but_the_outbox_truncating_arm_may_construct_a_debug_send`, which asserts
   against the module's own source text so a second construction site cannot bypass
   the arm. **Two mutations:** removing the `truncate_debug` call from the arm fails
   the first; replacing the boundary walk with a bare
   `message.truncate(DEBUG_MESSAGE_LIMIT)` fails it too, inside `String::truncate`
   itself — i.e. the mutation reproduces the brick the walk exists to prevent.

All three exist, so the device no longer builds a frame over a bound and then has
its own encoder refuse it. What remains true is the shape of the residual risk: cap
(b) is a refusal rather than a fix, so a device holding ~26 or more shares still
cannot answer `RequestHeldShares` at all, and nonce batch size is still a live
protocol design constraint rather than a theoretical one.

---

## 8. Phasing

Each phase ends at a testable artifact. No hardware until Phase 5.

| # | Phase | Deliverable | Gate | Status |
|---|---|---|---|---|
| 0 | Vendor + prove build | crates compile for `thumbv7em`; fits flash | build green, **844,229 B = 59.2%** | ✅ **done** |
| 1 | Drop `libsecp_compat_0_29` (decision 3) | `secp256kfun` no longer a consumer of C libsecp256k1 | BIP-341/BIP-86 vectors + `cargo tree -i` shows one parent | ✅ **done** — but **−1,185 B, not −97 KB**, and the C toolchain is **not** removed (§2.2) |
| 1b | Close the residual test gaps | odd-y/`lift_x` assertion; device-path vector; clippy at `bitcoin_transaction.rs:524` | tests fail on mutating `tweak.rs:342` | 🟡 **two of three closed; this row read "⬜ pending" until 2026-09-10.** The odd-y assertion shipped as `odd_y_internal_keys_tweak_to_the_same_output` (`frostsnap_core/src/tweak.rs:583`), which pins the *property* — `P` and `-P` must tweak to the same output key — touches no `bitcoin` type, and so survives decision 4 being revisited (DECISIONS.md residual gap 1, marked FIXED there). The clippy finding is fixed too (residual gap 4); `bitcoin_transaction.rs:524` is now `pub fn spk`, so that citation no longer locates anything. **Still open: the device-path vector** — every shipped test exercises `TweakableKey for Point`, while production signs through `SharedKey` and `PairedSecretShare` (residual gap 2). |
| 2 | STM32 HAL substrate | `NorFlash` for STM32 flash, **2-source** `RngCore` (§5.1 — not three), **panic → `NVIC_SystemReset`** (§6.2), plus removal of the §6.3 panic sites | host tests; handler disassembly; **§8.1 defect register empty** | 🟡 **written, all 12 review defects fixed, host-verified; hardware claims unverified** — see **§8.1**. Device build links; clippy and rustdoc clean; **204 tests** and **857,125 B = 60.1%** at the gate (now 268 / 860,898 with phase 3 and 4 on top). What remains is §8.1 items 3–5 — the real `DBANK`, `.ramfunc`, ECC/NMI — all bench work. Every on-silicon claim is still an assumption (§9); nothing has run on hardware. |
| 3 | Transport | USB CDC carrying `frostsnap_comms` framing, within the **4,096 B** ceiling (§7, raised from 2,060 — DECISIONS.md 7) | coordinator handshake | 🟡 **written and host-verified; no enumeration has been attempted.** `hal/src/comms.rs` (framing, +18 tests) and `hal/src/usb.rs` (OTG_FS device mode + CDC-ACM, +31 tests, **23/23 mutations caught**) — see **§8.2**. The bound is structural, not a comparison: the accumulator *is* `[u8; FRAME_LIMIT]`, and it costs 2 × that in SRAM. The gate is **not** met **on silicon**, which is what it means here — a real unmodified coordinator *has* handshaked with this framing on the host over a pty (§9 item 6, phase 4's row below); what has never happened is enumeration on the device. §7's census is what raised the bound: at 2,060 the transport refused a real `SignatureShare`, a real 11-input `RequestSign`, 9-of-9 keygen and a 14-share `HeldShares2`; at 4,096 it refuses none of them, and the **three device-side construction caps are now implemented** in `Outbox::push` (§7; this cell said they "remain UNIMPLEMENTED" until 2026-09-10). |
| 4 | Protocol on host | keygen + sign, Tier 2 simulator first, then Tier 3 stub `Serial` against real `frostsnap_coordinator` | end-to-end on host | 🟡 **gate MET on host 2026-08-18; not signed off.** `hostcheck/` + `firmware/examples/stub.rs` complete a **9-of-9 keygen, nonce replenishment and a signature that VERIFIES** (`Schnorr::verify_only()` against the coordinator's own derived x-only key) over a pty in two processes, against an **unmodified** sibling `frostsnap_coordinator`, at both `STUB_CHUNK=64` and `=1`, plus a third **DECLINE** pass. The two §7 size crossovers are **closed** by decision 7 (`FRAME_LIMIT` 2,060 → 4,096), validated on the wire: largest coordinator→device frame actually written is **2,179 B**, above the old bound, so this keygen was previously refused. Tier 1 **576** tests green. **This cell listed five uncovered items until 2026-09-10 and FOUR of them had already closed** — it read: *"the stub auto-acks `SignatureRequest`, so the approval policy — the actual security property — is untested; … but only CORE-to-CORE — nothing yet asserts the four bytes the screen renders are the coordinator's; restoration, backup consolidation, physical-backup entry and naming flows have never been driven at all; the three device-side caps (§7) are unimplemented; the allocator is sized and chosen but not registered (§9 item 7)."* Corrected: `SignatureRequest` **is** gated, on the randomised digit read back off the rendered frame (`stub.rs`'s `approved`, whose `SignatureRequest` arm is `digit.accepts(key)`), and a DECLINE pass fails the run if a refused prompt yields a share (`hostcheck/src/main.rs`'s `ASSERTION 2: A DECLINED PROMPT YIELDS NO SIGNATURE` block); the four rendered bytes **are** compared against the coordinator's session-hash prefix (its `ASSERTION 1: THE GLASS SHOWS THE COORDINATOR'S CODE` block, closed 2026-08-31, §9 item 12); the three caps **are** implemented (`Outbox::push` in `firmware/src/lib.rs`, §7); and the allocator **is** registered (`ALLOCATOR` in `firmware/src/alloc.rs`, §9 item 7). **Cited by SYMBOL and by banner comment rather than by line since 2026-09-12**: every one of those five was a line number, all five had rotted, and `hostcheck/src/main.rs:776` had moved by ~1,900 lines. **THE RESTORATION FLOWS ARE NOW COORDINATOR-DRIVEN — this cell said they were "driven by unit tests but not by a real coordinator" until 2026-09-11, and that was the largest remaining phase-4 gap.** `hostcheck` gained the five-call `UiProtocol` lifecycle and drives **four of the five** flows from UPSTREAM's own drivers, unmodified and by path — `DisplayBackupProtocol`, `CheckBackupProtocol`, `EnterPhysicalBackup`, plus consolidation through the same `queue` the keygen frames use (upstream has no driver for it). One boxed protocol at a time; no `UiStack`. Ordered AFTER the verified signature, because at t = n = 9 every device is needed to sign and `Consolidate` REPLACES the one share record the store keeps. What each asserts: the **25 words read back off the device's own framebuffer** with `ui::Frame::cell` re-encode through upstream's `ShareBackup::from_words` to this coordinator's own `expected_share_image`; the check quiz passes in **exactly 8 answers** taken only from what that reveal drew (the stub's picker is handed no `quiz::Quiz` and no option list); those same words go back in through the letter picker — whose candidate letters are a function of the secret prefix, so the typing is off the pixels too — and `check_physical_backup` accepts the result; and after the destructive consolidation the device's re-reported share **image** matches. MEASURED cost: **+1.4 s at chunk 64, +2.4 s at chunk 1**. Seventeen mutations RUN, each file restored and `diff`ed byte-identical, including three that remove one lifecycle leg each and all die on the new `DEADLINE (95s)` in the right state; plus `COLDSNAP_GLASS_KEYS=yy9`, which shows with NO source change that a hardcoded key cannot authorise a reveal, an ingest or a consolidation. See §9 item 12 for the three upstream facts this turned up, and for what did NOT get demonstrated. **NAMING AND `erase_device` CLOSED THE SAME DAY.** A coordinator-previewed name — 14 chars and 56 bytes at once, i.e. simultaneously the `FixedString<14>` wire bound and `DEVICE_NAME_MAX_BYTES` — reaches FLASH on all nine devices and comes back byte-exact as `SetName`, with a `NeedName` required first so an announce-time echo cannot be mistaken for a commit. It needed no device change: the preview must ride with the `AnnounceAck` because `commit_name` fires during keygen, and a mutation sending it post-keygen yields zero `SetName` lines. And upstream's own `EraseDevice` driver is now proven NEVER to complete against this device: `is_complete()` stays `None` for the whole grace window AND the device reports `refused=DataErase` — both halves, because silence alone is what a dead device looks like. **AND `CheckKeyGen` NOW ASKS FOR THE RANDOMISED DIGIT.** This cell said until 2026-09-11 that it was "gated on the fixed `1=match` key the screen advertises … so a hardcoded script can answer it". `ui::keygen_check` now prints `press_legend(confirm)` like the signing screens, `KEYGEN_MATCH_KEY` is deleted, and `answer` has one rule for every prompt. **No literal answers any consent screen on this device now**, shown with no source mutation: `COLDSNAP_GLASS_KEYS=1yy` exits 1 with 8 of 9 devices declining (the ninth drew `1`, which is the 1-in-5 made visible) and `=9yy` exits 1 with 9/9. Cost +440 B of flash, and the 2x code rows deliberately did not move because `glass_code` reads them back from those exact cells. **`Cancel` AND THE LEGACY `SavePhysicalBackup` v1 ARE NOW DRIVEN TOO, 2026-09-12 (M10, M11), and this cell said until then that `Cancel` was "the cheapest real gap in phase 4" — which was wrong twice over.** It is not the cheapest (five of its six clearings already had named, mutation-verified Tier-1 tests asserting the downstream refusal), and the prescription that went with it — "send it mid-reveal" — was a re-proof of those tests over a transport. The one clearing with no assertion anywhere was `pending_name`, and M10 closes it as a DIFFERENTIAL: two devices get the same two frames in OPPOSITE ORDERS, so `Cancel`-then-preview must commit the byte-exact name while preview-then-`Cancel` must commit none, and a lost preview silences both rather than passing vacuously. M11 drives the v1 body, whose naive assertion CANNOT FAIL — v1 recurses into v2, so `PhysicalSaved` is byte-identical — and asserts the one field that distinguishes them, the `threshold` v1 forces `Some(..)` and today's v2 leaves `None`, read back off the wire with `V1_THRESHOLD = 7` so the value exists nowhere else in the run. Both variants are driven by ONE `cargo run` (v2 at chunk 64, v1 at chunk 1), so nothing was traded away. SIX mutations run across the two, each file restored and `diff`ed byte-identical; two SEPARATE defects fell out of them and are fixed — a refusal of a frame the coordinator was waiting on was a log line that then burned the whole 95 s budget to die naming the state instead of the cause, and every FAILING run leaked its stub child (the PASS block's 15 `bail!`s are `return`s that fire before the reaping — the first draft of that accounting said 31 and said they were inside the loop, and review corrected both), which after three failures made the next run die at `TTYPort::pair: No such device or address`. **INGEST ONTO A DEVICE HOLDING NOTHING IS NOW CLOSED TOO, 2026-09-12 (M12, commit 7ba6ea4), and this cell said "DEFER stands" until then.** `hostcheck` announces `ALL_DEVICES = 10` and cuts a nine-device keygen roster out of `announced[..N_DEVICES]`, so `announced[N_DEVICES]` is blank **BY CONSTRUCTION** — identification is ASSIGNMENT, from one expression on one lap at the `BeginKeygen` site it already owns, so no back-channel is needed and nothing is trusted to a device about the thing under test. That device is then handed the FIRST device's sheet, types the 25 words in through the letter picker (198 keypresses) and CONSOLIDATES them onto a flash that held nothing. **What it buys is ONE new falsifiable assertion, not the two §9 item 12 commissioned it for:** the `Some`/`None` discrimination on the re-report. The share-image half of M7e and the `index != r.share_index` bound both stay OVER-DETERMINED — see the M12 block in `hostcheck/src/main.rs` for the mechanism that shadows each, and §9 item 12 for the three claims this turned out to have got wrong. Zero device code, zero flash, zero test-count movement; harness 10.11 s -> 12.38 s. **What the gate STILL does not cover: nothing has run on silicon.** |
| 5 | Mono UI | **8 screens** (§4.2), mono `DrawTarget`, ~850 LOC ported from `frostsnap_widgets` | manual, on hardware | 🟡 **written and host-verified; the manual-on-hardware gate is untouched.** **This row read "⬜ pending — largest single item" until 2026-09-10**, by which time `hal/src/ui.rs` was 5,541 lines rendering all eight screens with real callers (§9 item 16 — which was itself PARTLY closed that day and only fully closed on 2026-09-12, when address verification got its caller; the parenthetical here read "closed the same day" until then) and `tools/pixel-check.py` was checking them against an independent framebuffer decoder. Nothing was ported from `frostsnap_widgets` in the end — the ~850 LOC estimate was never drawn on; the screens are written against `ui::Frame` directly, and the one upstream artefact reused is the idea of a distractor quiz, deliberately **not** its implementation (§7 cap notes). What the gate still means here is the part a host cannot do: whether 16 px is legible on a physical OLED, and whether the keypad's hold-to-confirm feels right (§9 item 15). It inherits §8.1 defect 12: `user_prompt()`'s `None` is a **refusal**, not a rendering fallback — now enforced, since `SignPages`/`prompt_screen` funnel through one renderability gate. |
| 6 | Callgate integration | SE1/SE2 identity, PIN, rate limiting; ABI already determined (§5, DECISIONS.md decision 2) | hardware | ⬜ pending |
| 7 | Nonce durability | read-back-verified writes as `Result` not `assert!`, power-loss testing | fault injection | 🟡 **first half DONE and PINNED BY NAME; the helper and the defect pin both LANDED 2026-09-13 (hal 288 → 290); ONE NAMED GAP left open on purpose and the rest needs silicon.** (**This read "second half narrowed to a 3-line helper — and one REAL DEFECT found, with zero coverage" until 2026-09-13**, which was true when written; see (b) and (c) for what landed and (c)'s tail for the gap that is deliberately still open.) **This row read "⬜ pending — `TestNorFlash` does not model power loss (§7)" until 2026-09-12**, which understated what had landed and mis-stated what remained. (a) The read-back-verified writes are `Result` and are no longer only asserted: `a_refused_nonce_advance_reports_write_verify_failed_and_leaves_the_index_unadvanced` reaches the comparison NON-VACUOUSLY (§9 item 4), and deleting the comparison returns `Ok` carrying another session's shares for an advance that never reached flash. (b) POWER LOSS / TORN WRITES is what remains, and its entire increment is a 3-line `FakeFlash::refuse_programs_after(k: u32)` mirroring `FaultyNorFlash::fail_write_after` — plus the chunk-boundary measurement, now MEASURED: a `SecretNonceSlot` with 6 signature shares is **297 B** against `BUFFER_SIZE = 256`, so the boundary falls 256 B in and the two A/B copies program **76** doublewords (2 × 38 = one full 32-doubleword chunk plus a 41 B tail padded to 48 = 6), so `BincodeFlashWriter::write`'s multi-chunk branch is crossed. **The 41 B is RIGHT and must not be "corrected" to 45:** the 297 B is the whole `SlotValue`, whose ledger's FIRST term is `SlotValue.index` (`hal/tests/integration_frostsnap_over_hal.rs`'s `a_full_secret_nonce_slot_survives_the_hal_flash_round_trip` doc: `4 + 4 + 4 + 16 + 32 + 4 + 1 + 32 + 8 + 32n` = 105 + 32n, n=6 → 297), so 297 − 256 = 41 already counts the index. A "45 B" correction was proposed on 2026-09-13 on the theory that 297 measured `SecretNonceSlot` alone, and **WITHDRAWN** the same day; 41 and 45 pad to the same 48 either way, so the 38/76 doubleword figures were never in doubt. **This row claimed the new fixture entered that multi-chunk branch "for the first time by any test in this file" until 2026-09-13. It did not.** The branch was ALREADY crossed before this increment, by `a_full_secret_nonce_slot_survives_the_hal_flash_round_trip`, which already ships the 6-share fixture and already MEASURES the crossing as `assert!(programmed > 2 * (256 / 8), ..)` — 76 doublewords for two copies. That test's own doc states the "no test in this file had ever entered the multi-chunk branch" fact in the PAST TENSE, describing the state before its `signing_state` went from `None` to `Some`; **this row copied a past-tense observation as a present-tense promise about work not yet done.** What is new is not ENTERING the branch, it is **TEARING** it: `a_torn_multi_chunk_write_makes_the_slot_unreadable_and_refuses_to_sign` schedules a refusal BETWEEN the 256 B chunk and the 41 B tail flush. With `signing_state: None` the value is 65 B, pads to 72, and programs 18. (c) **AND A REAL DEFECT, which is the load-bearing part of this row now:** in `frostsnap_embedded/src/ab_write.rs`'s `AbSlot::try_write`, swapping the two `try_write` calls so the **LIVE** copy is erased first passed EVERY test in the tree. **This row said "hal's 16 integration tests and `frostsnap_embedded`'s 17" until 2026-09-13; it is BROADER than that, re-measured against the swap itself:** hal **288**, `frostsnap_embedded` **17** and `coldsnap_firmware` **172** were all exit 0 under it — **477 tests, in the three crates that LINK this function, and not one could see the erase order.** **THE "540 of the 576 sweep tests" FIGURE THIS ROW CARRIED UNTIL 2026-09-13 IS WITHDRAWN, and it is the orchestrator's own error.** `frostsnap_core` (63) was exit 0 under the swap too and it proves nothing: `frostsnap_core/Cargo.toml` declares NO `frostsnap_embedded` dependency (`grep -n embedded` exits 1) — the arrow points the OTHER way, `frostsnap_embedded/Cargo.toml:10` is `frostsnap_core.workspace = true` — so that gate never compiled `AbSlot::try_write`, and neither did `frostsnap_macros` (7), `frostsnap_comms` (10) or `frost_backup` (19). Running those four gates under the swap was uninformative BY CONSTRUCTION, not evidence of a coverage gap. **A gate with no view of a function is not a coverage measurement.** What links it: `frostsnap_embedded` 17 + `coldsnap_hal` 288 + `coldsnap_firmware` 172 = 477 at the base commit. From a `CommittedSingleCopy` state the two copies hold DIFFERENT values, so erasing the live one and then failing rolls the nonce index **BACK** to the older copy's — the device re-derives a nonce for which a signature share has already been emitted, which is the affine break that solves for the share. The comment at `try_write` asserts the correct ordering ("Write the *older* slot first") and **nothing enforces it**. `ab_write::test::fault_between_the_two_copies_reports_committed_and_the_new_value_is_live` does NOT own this claim, contrary to what a design report assumed: after a `Committed` write both copies hold the same value, so the erase order is unobservable. It only becomes observable from `CommittedSingleCopy`, which no test then follows with a further refused write — which is exactly what `refuse_programs_after(k)` buys.<br><br>**(c) LANDED 2026-09-13. hal 288 → 290.** `FakeFlash::refuse_programs_after(k)` (`hal/src/flash.rs`, `fake` module) schedules a refusal by DOUBLEWORD count, so it can land part way THROUGH one logical write; `programs` accumulates `bytes.len() / WRITE_SIZE`, i.e. 32 for a 256 B chunk and 6 for a 48 B tail, and refusal stays all-or-nothing per program. Two tests in `hal/tests/integration_frostsnap_over_hal.rs`: `a_refused_write_after_a_single_copy_write_erases_the_older_copy_not_the_live_one` (the only test in the tree that reaches `try_write` from ASYMMETRIC copies — one live, one blank — and the only thing that fails on the swap: exit 101, one named test) and `a_torn_multi_chunk_write_makes_the_slot_unreadable_and_refuses_to_sign`. The `fake` module doc's "does not model power loss" sentence was amended in the same increment, because landing the helper made that half of it false; bit rot, write disturb and ECC stay unmodelled. **ZERO ARM flash delta, and structurally so rather than luckily:** the whole `fake` module is `#[cfg(any(test, feature = "fake-flash"))]`, `fake-flash = []` is off by default, and `firmware` enables it only under `[dev-dependencies]` — image unmoved at 379,648 B, section for section.<br><br>**THREE PARTIAL SURVIVALS FROM THAT ROUND, recorded because they say which legs are load-bearing and a later reader will otherwise delete the wrong one.** (i) On a 5-share fixture the torn tail still DECODES, and there `assert!(matches!(err, NoncesUnavailable::WriteVerifyFailed))` **survived green** — only the separate non-destructive `AbSlot` probe's `is_none()` went red. So the variant assertion alone is a THREE-WAY ambiguity, the equality leg silently substitutes for the read-back's `ok_or`, and **anyone who deletes the probe leg as decorative removes the only thing naming the site.** (ii) Making `FakeFlash` count a REFUSED program left 267 lib + 5 smoke + all 16 pre-existing integration tests green: the fake could have started lying about `programs` and the whole 288-test baseline would not have noticed, which is why the counter legs stay in the asymmetric test despite adding nothing against the ordering mutation. (iii) Inverting `AbSlot::current_slot_and_index`'s `b_index > a_index` left all 16 pre-existing hal integration tests green — the vendored `unreadable_or_blank_slot_ranks_below_a_written_one` does catch it, so it is not unguarded, but the hal integration layer had no view of it before this round.<br><br>**SEVERITY IS HIGHER THAN THIS ROW ORIGINALLY STATED, because `AbSlot` HAS THREE CONSUMERS and one of them asserts the unenforced property in its PRODUCTION docs, in so many words.** `ShareStore::open` builds the share store's `AbSlot` and `ShareStore::persist_staged` calls `try_write`, both in `firmware/src/store.rs` — cited by SYMBOL, because the same commit that wrote the old `:355`/`:429`/`:64-66`/`:89-92` citations also inserted 10 lines at `:69` and 12 at `:101` and rotted them all. That module's torn-write paragraph in its module docs states "`AbSlot` writes the *older* copy first and picks the highest index, so an interrupted save leaves the previous value live in the other copy" as a load-bearing premise of the record format, and the `ponytail:` note in the same module docs closes the escape hatch: "`AbSlot` exposes no route to the intact older copy, so the previous share becomes unreachable too". Under the swap a torn share save leaves NEITHER copy holding the previous share, on a device that holds ONE share, has no recovery install (`mk4-bootloader/sdcard.c:248`) and no route to the intact older copy — **unspendable unless the holder had already taken the 25-word backup, which `Session::recv_core` does admit** (`DisplayBackup` plus the four restore-flow messages), **a different mechanism from the affine nonce break.** **THE THIRD CONSUMER, added 2026-09-13:** `NameStore::save` in `firmware/src/lib.rs` is a plain `frostsnap_embedded::AbSlot` over the name region — cheapest of the three, since a lost name reads back `None`, the device announces `NeedName` and a human retypes it. One pin on the shared function covers all three; no second test was written, and that is the point.<br><br>**THE ROLLBACK SYMPTOM IS NOW PINNED TOO, 2026-09-14, hal 290 → 291.** This paragraph read "**NOT PINNED, deliberately**" until then, and the decision it recorded was REVERSED on the security question while its arithmetic was accepted: one source mutation does fail both tests, but the two failure MESSAGES say different things and only one of them is the affine break. `FakeFlash::refuse_erases_after(erases: u32)` schedules by PAGE count (`erases` accumulates `len / ERASE_SIZE`, where `programs` counts DOUBLEWORDS), and both `refuse_erases_now` and `refuse_programs_now` now delegate to their `_after` form so the pair cannot drift — which earned itself immediately, since neutering the `_after` form now reddens the `_now` form's tests. `a_further_refused_write_after_an_erase_refused_single_copy_does_not_roll_the_index_back` asserts the VALUE and the INDEX, not the variant, and its step-(b) precondition — both copies readable AT DIFFERENT INDEXES — is asserted explicitly, because `CommittedSingleCopy` alone is reached by the program-scheduled route too and asserting only the variant would have made the discrimination vacuous. **THE SCHEDULE THAT LOOKS RIGHT IS WRONG, and it is the measurement worth keeping: a further write with the erase refusal STILL ARMED leaves the swap GREEN**, because the further write's FIRST erase is then refused and nothing is touched. It has to `heal()` and then `refuse_programs_now()`, so the further write's erase SUCCEEDS and its program fails. Two more notes for the next reader: an `AbSlot` probe CANNOT do the per-copy read (`AbSlot::new` asserts `n_sectors() >= 2`, so a probe only ever sees a PAIR, which is exactly what hides which copy holds which index — hence the `ab_copy` helper), and step (c)'s `read == Some(33)` is DOMINATED, tripped by no mutation alone; it stays as an anti-vacuity leg and the site says so. **This row still stays 🟡 and not 🟢**, but for ONE reason now instead of two: `FakeFlash` models refusal at program and page-erase granularity and NOT bit rot, write disturb, ECC or partially programmed rows, which is the residue "power-loss testing" named, and closing it needs silicon.<br><br>The paragraph that follows is kept as the argument for why the earlier increment could not reach this symptom, which is still the useful part: `refuse_programs_after(k)` can only reach a `CommittedSingleCopy` whose loser copy is **BLANK**, because `Slot::try_write` runs `self.flash.erase_all()?` as its FIRST statement — so under the swap BOTH copies are lost and `AbSlot::read` returns `None`, which is what the new asymmetric test asserts. On hardware a `CommittedSingleCopy` arising from a refused **ERASE** instead leaves the loser holding the OLD value, and there the same one-line ordering error rolls the nonce index **BACK** to a spent index rather than losing it — the affine break stated in (c)'s own words above. Pinning that needs a `refuse_erases_after(k)` companion plus ~25 lines, and it falsifies the SAME source mutation, so it was skipped as duplicate coverage. **The security property — a refused erase leaves the loser holding a spent nonce index — is asserted nowhere in the tree.** **That "asserted nowhere in the tree" clause was TRUE until 2026-09-14 and is now closed — see the paragraph above this one, which supersedes this one's conclusion.** |

Phases 1–4 carry no brick risk. Phase 5 is the largest single item.

**Phase 2 is now gated on more than the handler.** The §6.3 panic-site removals
belong to it, and item 1 there — `device.rs:491`, an unvalidated index panic a
coordinator can trigger remotely — should land first regardless of phase, since
it is a protocol-level defect independent of the port.

### 8.1 Phase-2 defect register

Phase 2 was marked "done on host" on the strength of 164 passing tests. An
adversarial review of the substrate then found **9 defects**, which is the useful
datum here: *the tests passing did not mean the code was right*, and in the flash
driver's case they could not have, because it had **zero** tests. Six simultaneous
mutations to `flash.rs` — deleting the containment bound, `checked_add` →
`wrapping_add`, deleting the alignment check, deleting the erase-floor guard,
inverting the bank-select bit, and making `dbank_ok` return unconditional `true` —
left the whole suite green. The tests exercised `FakeFlash`, never the driver.

| # | Defect | Class | Status |
|---|---|---|---|
| 1 | `Entropy::from_proven_seed` / `mix_sources` / `ProvenSeed::expose` were unconditionally public — a full `CryptoRng` from hardcoded bytes, zero hardware reads, compiling for the device. libngu's fail-open defect in a new shape. | fail-open | ✅ fixed — behind non-default `test-seam` |
| 2 | The SE1/SE2 refusal legs had no test asserting they refuse, or that they leave the output buffer untouched. | untested refusal | ✅ fixed — `0xA5` sentinel test |
| 3 | RNG seed-error recovery cleared `SEIS` without the disable/re-enable `RNGEN` toggle ST's own driver requires (`stm32l4xx_hal_rng.c:773-778`); the **latched** `SEIS`/`CEIS` were cleared but never *read*. | silent wrong behaviour | ✅ fixed |
| 4 | **"Three independent entropy sources" was false on both halves** (§5.1). SE1 is fed our own TRNG; SE2 is a static page. | false premise | ✅ fixed — `ENTROPY_SOURCE_COUNT = 2` |
| 5 | `FakeFlash` accepted re-programming a doubleword, which is `PROGERR` on silicon — so the fake was *more permissive* than the hardware it stood in for. | invalid test double | ✅ fixed |
| 6 | **`FLASH_SR` wedge.** `wait_done` reports latched errors without clearing them, and `write` waited *before* its own clear, so the clear was unreachable and one transient `PROGERR` made every later write fail forever on healthy flash. `erase` never wrote `SR` at all. | permanent brick after one fault | ✅ fixed — `sr_prologue` clears then waits; reproduced and pinned on `SimPort` |
| 7 | **The DBANK check never ran.** `StmFlash::take()` already returned a usable `NorFlash`, and `StmFlash::new()` — which held the `OPTR` read — had **zero callers**. At `DBANK == 0` pages are 8 K, so an `ERASE_SIZE = 4096` erase destroys the adjacent sector; `NonceAbSlot` puts the A and B copies in two *consecutive* sectors, so both die at once while reporting `Committed`. Silent nonce loss, and nonce reuse is what leaks the share. | unreachable safety check | ✅ fixed — `StmFlashToken` type-state; `open()` is the only way to mint an `StmFlash` |
| 8 | `flash.rs` had **zero tests**, and the six mutations above all passed. | untested | ✅ fixed — `SimPort` + pure-function tests |
| 9 | **`flash.rs`'s own docs described repairs that did not exist in the file** — `operation_prologue`, `FlashPort`/`Mmio`/`SimPort`, `StmFlashToken`, the bank-arithmetic functions, `RAM_EXECUTION_IS_UNRESOLVED`. Worse than the underlying bugs, because a reviewer is *told* the defect is closed. | false documentation | ✅ fixed — every claim either implemented or deleted |
| 10 | **`fee()` overflowed, and that is a validation *bypass*.** `sum::<u64>()` over wire-supplied `input.value`. This is the device's only arithmetic check on a sign request — `check` rejects `fee().is_none()` **pre-consent** (`device.rs:331-333` → `message.rs:112` → `sign_task.rs:88`) — and `overflow-checks = false` in the shipped profile (`Cargo.toml:82`) made the wrap **silent**, so inputs summing past `u64::MAX` returned `Some(<wrapped>)` and the check passed a transaction it exists to reject. `[profile.dev]` omits the key, so it defaults to `true`: the same message *panicked* under `cargo test` and *wrapped* in firmware. | validation bypass, pre-consent | ✅ fixed — `try_fold`/`checked_add` |
| 11 | `net_value()` held two `i64::try_from(..).expect("input ridiciously large")` plus bare `-=`/`+=` on wire-supplied `u64`. **The `fee()` guard does not cover this**: `fee()` bounds only the *difference* between the sums, never the magnitudes, so one input of `2^63` and one output of `2^63` gives `fee() == Some(0)`, is accepted by `check`, and still overflows an `i64`. | panic on wire data | ✅ fixed — returns `Option` |
| 12 | **The first sign-approval screen would have reset-looped on a legal transaction.** `user_prompt()` did `Address::from_script(spk, ..).expect("has address representation")` on **foreign** output scripts. `from_script` errs on OP_RETURN, bare/P2PK, bare multisig and the empty script (bitcoin 0.32.8 `address/mod.rs:567-590`), and nothing validates foreign spks — `sign_task.rs:343-350` asserts an unaddressable output is *accepted*. **This cell said "Unreachable only because `user_prompt` has no caller yet … so phase 5 inherits this" until 2026-09-10; it has a caller and phase 5 has already inherited it correctly:** `coldsnap_firmware::sign_consent` calls it at `firmware/src/lib.rs:1926` and maps `None` to `Refusal::Undisplayable`, on the live `SignatureRequest` path. So the `Option` is load-bearing today, not latent. | latent panic → live refusal | ✅ fixed — returns `Option`; see §4.2 |

Defects 10–12 are in the **vendored** tree, not the HAL, and were found while
re-verifying the phase-2 panic-site work rather than by the review that produced
1–9 — so the register is a record of what has been looked at, not a bound on what
is there. All three are recorded with their reasoning in `vendor/README.md`.

**Not closed, and blocking the phase-2 gate:**

1. ~~**None of the flash fixes have been compiled.**~~ **Done, 2026-08-14.** The
   shell came back. Everything in #1–#12 compiles; `coldsnap_hal` is **88 tests**
   passing (72 lib + 5 + 11), `frostsnap_core` **63**, the tree **204** — those are
   the figures *at the phase-2 gate*; phase 3 adds 49, see §8.2 — and
   `cargo clippy --all-targets` plus `cargo doc` are clean on both crates. The
   release build for `thumbv7em-none-eabihf` links. Three real nits surfaced only
   under the tools, none of them behavioural: an `implicit_saturating_sub` in
   `flash_text_bytes_in_bank2`, a duplicated comment paragraph in
   `text_and_fs_really_do_share_bank_two`, and eight intra-doc links from **public**
   docs in `rng.rs` into private items (`Sources::draw`, `recover_seed_error`,
   `mix_checked_draws`), which rustdoc renders as dead references. The `assert!` on
   two constants in that same test is now a `const {}` block, so the geometry
   invariant is a **build** failure on every target rather than a host-test failure
   an embedded-only change could walk past.
2. ~~**The test counts predate all of this.**~~ **Re-measured**; 60/164 is gone from
   this document and README. The number worth noting is `frostsnap_embedded`'s
   **no-std** count, 7 → 15: those are the A/B-write and nonce-slot tests, and
   no-std is the configuration the firmware actually ships.
3. **The real `DBANK` value on silicon is still unknown.** The driver now refuses
   rather than guessing, which converts a silent-corruption bug into a boot-time
   refusal — but if `DBANK == 0`, `ERASE_SIZE` must become 8192 *and*
   `nonce_slots.rs:27`'s `split_off_front(2)` must change. Bench work.
4. **Whether the flash driver must execute from RAM is unresolved**, and the old
   justification for saying it need not was arithmetically false: 512 K of
   `FLASH_FS` is now partitioned, and the map lives in `hal/src/lib.rs`'s `memmap`
   with `const` asserts rather than here, so it cannot drift from the code that
   obeys it: identity at offset 0 (8 KiB), nonce slots at 8 KiB (32 KiB), the SHARE
   record at 40 KiB (16 KiB, `FS_SHARE_OFFSET`), the device NAME record at 56 KiB
   (16 KiB, `FS_NAME_OFFSET`, carved out and reserved but not yet written), and the
   remaining 440 K unclaimed from `FS_FREE_OFFSET` at 72 KiB.
   **This sentence read "the rest `FS_FREE_OFFSET` and reserved" straight after the nonce
   region until 2026-09-12, i.e. it said no region for shares existed** — false since
   `store::ShareStore` landed, and doubly ironic in a sentence whose own premise is that
   the map "cannot drift from the code that obeys it". `AUDIT-2026-09-10.md` had already
   recorded the corrected layout. The knock-on this stale claim had elsewhere is worth
   recording, because it cost a whole assertion pair: `firmware/examples/stub.rs` carried
   the same belief ("firmware's job is to write these to flash, and NOTHING DOES YET --
   there is no `FLASH_FS` region for shares"), and on the strength of it drained
   `session.signer.staged_mutations()` looking for `KeyMutation::SaveShare` — which
   **NEVER MATCHED ONCE**, because `store::ShareStore::persist_staged` had already consumed
   and cleared them as `Session::run`'s FIRST statement (`firmware/src/lib.rs:1898-1900`,
   `firmware/src/store.rs:421`). Probed at **308 drain calls per harness run, every one
   `staged=0`**. So the `saved` map stayed empty and BOTH conditions on it were vacuous —
   the latch advancing the stub's `STATE` to `SharesSaved` and the "every share belongs to
   ONE access structure" check never fired — until commit 7ba6ea4 switched the source to
   `signer.held_shares()`, at which point `saved` reaches 9 on all three passes for the
   first time. A stale layout claim in this document is what a harness reasoned from. Every offset and length is a multiple of the
   **8 KiB `DBANK0_PAGE`**, not of the 4 KiB `ERASE_SIZE`, and that is the whole
   point: it is what makes an identity-region erase unable to reach the nonce region
   even if the real `DBANK` turns out to be 0 (item 3 above, still open).

   `FLASH_TEXT` shares bank 2 with `FLASH_FS`. **This said "only ~44 K of margin at the
   current image size" and "settling it needs a linker script (`.ramfunc`), which this
   tree does not yet have" until 2026-09-10.** Both are wrong now: `firmware/link.x`
   exists (10 link-time `ASSERT`s, two of which pin the `FLASH_TEXT`/`FLASH_FS`
   boundary at `0x0818_0000`), so adding a `.ramfunc` output section is an edit to an
   existing file rather than new work; and the margin is not 44 K but **1,045,760 B** —
   the linked image is 379,648 B of a 1,425,408-byte `FLASH_TEXT` (`cargo build
   --release`), and the margin is that subtraction so the two cannot drift apart again.
   The 44 K figure came from the *rlib sum*, which overestimates the image by ~2.4×.
   **This sentence read "the margin is not 44 K but **1,048,656 B** — the linked image is
   377,192 B" until 2026-09-12, and the two halves did not agree with each other:**
   1,425,408 − 377,192 is 1,048,216, while 1,048,656 is 1,425,408 − 376,752, i.e. the
   margin was left behind when the image beside it was updated one image earlier. What is still unresolved
   is the actual question — whether the flash driver must execute from RAM — and that is
   bench work. Pinned as `flash::RAM_EXECUTION_IS_UNRESOLVED`.
5. **ECC is unhandled.** An uncorrectable double-bit error on a nonce read raises
   an NMI, not a `Result::Err`, so no error path in the driver can observe it.
6. ~~**The vendored panic-site fixes have not been independently re-verified.**~~
   **Done.** All three hold. `AbWriteOutcome` writes the *older* slot first, so
   `NotCommitted` is truthful, and the load-bearing claim in `Slot::try_write`'s
   comment checks out: `flush` takes `self` **by value** and zeroes `buf_index`
   (`partition.rs:270-276`) *before* the write that can fail, so the `?` cannot
   reintroduce the `Drop` panic at `:320-324`. `MAX_NONCE_SKIP_BATCHES = 64` is
   real and used at `device_nonces.rs:336`. `GroupSignReq::check`'s length guard
   is real, and the seam its docs did **not** cover also holds: `check` counts via
   `iter_locally_owned_inputs` while `device.rs:491` indexes over
   `iter_sighashes_of_locally_owned_inputs` — two different iterators, but both
   are a single `filter_map` whose only `None` path is the same shared
   `local_owner()?`, and `iter_sighash` yields exactly `(0..inputs.len())`, so the
   `zip` truncates nothing and the counts are equal element-for-element.
7. ~~**The three new vendored fixes (defects 10–12) have not been compiled.**~~
   **Done.** All 12 `wire_value_bounds` tests pass. Both specifics that reading
   could not settle came out clean: `ScriptBuf::new_op_return([])` does infer
   `[u8; 0]` with no explicit type, and `schnorr_fun::fun::prelude::*` does **not**
   collide with `bitcoin::hashes::Hash` in the new module.
8. ~~**The flash cost of defects 10–12 is unmeasured.**~~ **Measured: +253 bytes**,
   taking the image 856,872 → **857,125**, which is still 60.1% of `FLASH_TEXT`.
   That figure is worth keeping because "it will bloat the image" is the standard
   argument for leaving an `expect()` in embedded code; closing three
   wire-reachable defects cost 0.02 pt.

**What is left is bench work — items 3, 4 and 5.** No part of the phase-2 gate is
now blocked on the toolchain; it is blocked on silicon. Nothing in this tree has
run on a device.

### 8.2 Phase-3 register — mutations, and the ST defects deliberately not copied

§8.1's lesson was that a green suite proves nothing, so phase 3 was mutation-tested
before being called written. **23 deliberate defects in `usb.rs`, 23 caught by the
named test that was supposed to catch them, 0 survivors, 0 hangs.** The list is in
`/tmp` only, so the ones worth keeping as a record of what the tests reach:

| Mutation | Caught by |
|---|---|
| `fifo_read` writes the trailing whole word past `len` (ST's `USB_ReadPacket` bug) | `fifo_read_does_not_write_past_len` |
| `fifo_read` refuses an oversize packet *before* draining the FIFO | `fifo_read_drains_the_whole_packet_even_when_it_refuses` |
| `fifo_read` drops the oversize refusal entirely | the same pair |
| `fifo_write` returns `Ok` when its spin countdown expires | `fifo_write_gives_up_instead_of_spinning_when_the_fifo_never_drains` (`hal/src/usb.rs:2640`; asserts `Err(UsbError::FifoTimeout)` on a `SimPort::wedged()` AND `port.written().len() == 0`). **This cell named `fifo_write_reports_a_timeout_rather_than_dropping_bytes` until 2026-09-12; NO SUCH TEST EXISTS**, and `AUDIT-2026-09-10.md` had already said so |
| `fifo_write` writes without re-checking `DTXFSTS` for space | `SimPort`'s own assert — the "test double no more permissive than the hardware" rule paying for itself |
| `Setup::recipient` masks 2 bits, as ST's `USB_REQ_RECIPIENT_MASK` does | `reserved_recipients_are_not_aliased` |
| SET_ADDRESS masks to `0x7f` instead of refusing | `set_address_is_range_checked_rather_than_masked` |
| SET_LINE_CODING accepts `wLength >= 7` | `set_line_coding_with_a_wrong_length_is_refused` |
| SET_CONFIGURATION accepts any `wValue`; SET_FEATURE acknowledges; DEVICE_QUALIFIER answered | three separate control-dispatch tests |
| `ep0_xfer_size` uses the wide `XFRSIZ` field width; PKTCNT bound dropped | `ep0_xfer_size_is_narrower_than_every_other_endpoint` |
| `rx_status` truncates BCNT to 8 bits; PKTSTS mask lets DPID leak | two `rx_status` tests |
| `fifo_words` truncates instead of rounding up | **THREE** named tests, and this is the one cell in this table whose pairing was RE-RUN rather than re-read. MEASURED 2026-09-13: `len / 4 + (len % 4 != 0) as usize` → `len / 4` in `hal/src/usb.rs`'s `fifo_words`, then `cargo test --target aarch64-apple-darwin -p coldsnap_hal --features fake-flash,test-seam` → **exit 101, 264 passed / 3 failed**. (1) `fifo_read_does_not_write_past_len` fails at `assert_eq!(n, len)`, `left: 0, right: 1` — `n` is `fifo_read`'s per-byte `copied` counter and `len` the test's loop variable, so neither side derives from `fifo_words`. (2) `fifo_write_pads_the_final_partial_word` fails and **not by an assertion**: `&written[..len]` panics, `range end index 1 out of range for slice of length 0`. Real coverage, delivered by a panic rather than by an assert — weaker evidence of intent, but not zero. (3) `cdc_packets_reassemble_a_frostsnap_frame` fails at `assert_eq!(n, packet.len())`, `left: 8, right: 9`, on the stream's trailing 9-byte packet. `hal/src/usb.rs` restored byte-identical, sha256 `b34a95891b8bdba4b0b7eb206bd90c687793f98ec49612dd2ba3d3463bf25492` before = after. **No direct `fifo_words` test was added, deliberately:** three tests already fail by name, so the defect here was a wrong CLAIM in this table and not missing coverage. Add one only if this cell rots a third time. What survives from the old cell, because it is right: both `fifo_read_does_not_write_past_len` and `fifo_write_pads_the_final_partial_word` compute their word-count expectation *from* `fifo_words`, so **their word-count assertions cannot see this mutation at all**. **This cell named `fifo_words_rounds_up` until 2026-09-12; NO SUCH TEST EXISTS.** **And until 2026-09-13 it said the coverage was `fifo_read_does_not_write_past_len`'s `&dest[..len] == payload` assert ALONE, that `fifo_write_pads_the_final_partial_word` "cannot see this mutation at all", and that "the mutation has not been re-run since" — wrong THREE ways.** The payload comparison is never even evaluated: `assert_eq!(n, len)` sits one line above it and fires first, so the cell named the wrong assertion inside the right test; the second test dies anyway; and a third test was never mentioned. **The lesson is worth more than the repair.** That cell stated its own provenance as *"Pairing re-derived by READING on 2026-09-12 (and independently by `AUDIT-2026-09-10.md`)"* — **two independent readings agreed on an answer that is wrong three ways. Reading is not measuring**, and this is the strongest in-tree evidence for §8.2's own rule that a pairing is established only by running the mutation. It is also the standing argument against any proposed mechanical gate that verifies a claim by reading — see "CITATION HYGIENE — the 2026-09-13 sweep, its yield, and BOTH rejected gates" in §9's claim-hygiene item, where both proposed gates were rejected with their measurements |
| `DIEPTXF2` overlaps `DIEPTXF0` | `the_fifo_partition_fits_and_does_not_overlap` (the `const _` block cannot see this one) |
| `wTotalLength` off by one; `line_coding` byte order swapped; strings Latin-1 not UTF-16LE | three descriptor tests |
| `UsbToken::take()` hands out the peripheral every time | `the_peripheral_is_handed_out_once` |

**One path could not be mutated cleanly, and that is stated rather than hidden.**
Deleting `fifo_write`'s spin countdown outright makes the test **hang** instead of
fail, because with a wedged FIFO the countdown is the only proof of termination —
exactly the situation `flash::FLASH_SPIN_LIMIT` is in. So the two mutations chosen
for that path were "timeout returns `Ok`" and "skip the space check", both of which
fail cleanly. The countdown itself is guarded only by the fact that removing it
breaks the build's runtime, not by an assertion.

**Four ST HAL defects were read and deliberately not copied.** They are enumerated
in `usb.rs`'s module docs with citations: `USB_ReadPacket`'s whole-word tail write
overrunning the caller's buffer; `USB_REQ_RECIPIENT_MASK` being `0x03` when the
field is 5 bits; `USB_SetDevSpeed` not clearing `DSPD` before setting it; and
`PCD_WriteEmptyTxFifo` reading `DTXFSTS` once and then trusting it for the whole
packet (MicroPython patches this one; ST has not). Three of the four appear as
mutations in the table above. The fourth, `DSPD`, is in the ARM-only `bring_up`
path — there is no host test that could fail on it, so it is **read-verified
only**, like every other register write in that function.

**Four things are genuinely open in `usb.rs`**, all listed in its module docs and
in §9: polling vs interrupts, `MODE_SETTLE_SPINS` as a bench-tunable, the `PWREN`
state at bootloader handoff, and the 48 MHz clock the USB core needs.

### Effort

The UI (§4) and root-of-trust rewrite (§5) dominate. This is a rewrite of
Frostsnap's ~6,000-line device crate plus a new mono UI — not a port in the
light sense. Prior estimate for the far smaller MicroPython route was 9–12
months; this is larger in scope but avoids re-auditing 147 call sites.

Decision 1 sizes the UI item concretely: **13,459 of 19,799 LOC** of
`frostsnap_widgets` is `Rgb565`-bound and all 14,032 LOC of `frostsnap_fonts` is
discarded, against **~850 LOC** reusable.

---

## 9. Open questions

### Closed by the 2026-08-12 decisions

| Was | Closed by |
|---|---|
| Q1 instead of Mk4? | **Decision 1 — Mk4.** Cost accepted: from-scratch mono UI, §4. |
| Keep `rust-bitcoin`? | **Decision 4 — keep.** And it is why the C library stays, §2.2. |
| Does the retained Coinkite bootloader satisfy the trust requirement? | **Decision 2 — yes, keep it.** The trade is recorded explicitly in DECISIONS.md. |
| `arm-none-eabi-gcc` vs clang / is a C-free build reachable? | **Answered: no, not while decision 4 stands.** `bitcoin` 0.32.8 declares `secp256k1` non-optionally; verified by pointing `CC` at a nonexistent path after dropping `libsecp_compat_0_29` — still fails inside cc-rs. clang 21 remains required. |

### Genuinely open

1. **`secp-lowmemory` is PROVABLY INERT for this image, so its latency cost is not an
   unknown — it is ZERO. The unknown that IS real is a DIFFERENT question.**
   **This item read *"Signing latency under `secp-lowmemory` is UNMEASURED. This is now
   the highest-value unknown. `ECMULT_WINDOW_SIZE=4` / `ECMULT_GEN_PREC_BITS=2` bought
   92% of the flash budget (§2.2) by shrinking the precomputation window; the cost is
   slower EC math, on a 120 MHz Cortex-M4, and nothing measures it. No host benchmark
   substitutes — the window size interacts with the actual core. A bad answer partly
   reopens decision 4."* until 2026-09-13.** Its COST PREMISE IS FALSE, measured twice:

   - **The code is not in the image.** `/usr/bin/objdump --syms
     target/thumbv7em-none-eabihf/release/coldsnap_firmware | grep -ci secp256k1` = **23**,
     and every one is field arithmetic (`fe_impl_mul`, `fe_impl_sqr`, `fe_sqrt`,
     `fe_impl_normalize{,_var}`, `fe_impl_set_b32_{mod,limit}`, `fe_impl_get_b32`,
     `fe_impl_to_storage`, `fe_impl_normalizes_to_zero`), point decompression
     (`ge_set_xo_var`, `ge_from_storage`) or parse/serialize (`pubkey_{load,save}`,
     `xonly_pubkey_{parse,serialize}`), plus `context_static_` (180 B),
     `context_no_precomp` (4 B), two callbacks and `strlen`. The same output under
     `grep -iE 'ecmult|pre_g|prec_table'` yields exactly two entries and **neither is
     code**: `precomputed_ecmult.c` and `precomputed_ecmult_gen.c` as **zero-size `df`
     FILE symbols**. Those translation units linked and were entirely gc'd. No ecmult
     instructions, no table bytes.
   - **The falsification, RUN and not argued.** Remove `secp-lowmemory` from
     `Cargo.toml:52` and `cargo build --release` into a private target dir. Result:
     **379,648 B on BOTH sides**, section for section (`.vector_table 0x40`,
     `.text 0x4e7e0`, `.rodata 0xe2bc`, `.data 0x24`, `.bss 0x10024`), an identical
     symbol COUNT, and no `pre_g`/`prec_table` either way. The residual symbol-name
     differences are `-C metadata` hash churn and `.Lanon` label renaming — the effect
     §10 already documents for the 4 B padding difference between `cargo build --release`
     and `-p coldsnap_firmware`. `Cargo.toml` restored, sha256
     `89cb3d3cf408adb4f3bce3afec6a75f7ec565032e6e305090b6872c280e87852`, tree clean.
     (Symbol-count caveat, recorded rather than smoothed: the identity is what carries
     the argument, and the absolute figure depends on the counting filter —
     `grep -c '^[0-9a-f]\{8\} '` over `--syms` gives 2,519 on the image today against
     the 2,523 recorded when the two builds were compared. Same image, different filter.)

   **So the feature changes this image by exactly 0 bytes.** `ECMULT_WINDOW_SIZE` and
   `ECMULT_GEN_PREC_BITS` govern code that is not linked, so there is nothing to ratio
   against and no latency for them to cost. **ROOT CAUSE: decision 3.** Moving every EC
   operation to `secp256kfun` (`Xpub::derive_bip32_in_place` → `TweakableKey::tweak` →
   `g!(self + tweak * G)`) left exactly TWO C libsecp calls in the device graph and
   **both are PARSES** — `TweakableKey::to_libsecp_key` is
   `PublicKey::from_slice(33 B)` (`frostsnap_core/src/tweak.rs:255-260`) and
   `LocalSpk::spk` is `XOnlyPublicKey::from_slice(32 B)`
   (`frostsnap_core/src/bitcoin_transaction.rs:476-480`). §2.2's table stays exactly as
   it is: the 92% it records is real, and it is real for the **rlib sum**, which is a
   different quantity from the linked image (README "Flash budget" for why they differ
   by ~2.4×). **KEEP THE FEATURE**: the tables are gc'd either way so it is free, and it
   is the standing guard for the day some future code does reach an ecmult. Dropping it
   saves zero bytes and costs a `Cargo.toml` change, a build and a re-measure.

   **THE UNKNOWN THAT IS REAL, and it is a different question:** how long ONE FROST
   signature share takes in `secp256kfun`'s `field_10x26` / `scalar_8x32` on a 120 MHz
   Cortex-M4F **with no precomputed generator table at all** — the image's largest
   `.rodata` symbol is `frost_backup::BIP39_WORDS` at 16,384 B and `secp256kfun` ships
   no table either. That is still UNMEASURED, still needs the board, and it is what the
   watchdog-period decision in §9's watchdog item actually waits on.
   **A HOST BENCH CANNOT ANSWER IT, and that is measured too:** the device links
   `secp256kfun`'s vendored k256 at 32-bit limb width (`field_10x26`, `scalar_8x32`, by
   `objdump --syms` on the release ELF) and the host links the 64-bit ones
   (`field_5x52`, `scalar_4x64`, by `/usr/bin/nm` over the host rlibs). Those are
   **different source files at different limb widths**, not the same code on a faster
   clock, so neither an absolute time nor a field-multiply count transfers. Only the
   CURVE-level operation count transfers, and that is READABLE from `secp256kfun`'s
   sign path with no benchmark at all. **And no benchmark exists anywhere in the tree**
   — `rg 'criterion|\[\[bench\]\]|black_box'` finds only prose, and the only
   `Instant::now()` in the tree are `hostcheck`'s wall-clock deadlines. So the correct
   pre-silicon artifact here is a `g!` count, not a bench crate, and **the host signing
   benchmark was KILLED on 2026-09-13** on exactly these grounds. Six sites in this
   document set told a reader to reserve bench time for a measurement that could not
   come back non-zero; they are corrected in the same pass.

   **Decided 2026-08-18: this stays open until phase 5, deliberately.** The cheap
   way to close it early was a generic STM32L4 dev board (same Cortex-M4F at
   120 MHz, recoverable over SWD/DFU), which would also have closed items 3–5 of
   §8.1 — the real `DBANK`, the `.ramfunc` question and ECC/NMI behaviour. That was
   considered and **declined**: no intermediate board, Mk4 only, later. The costs of
   that choice, stated so they are not rediscovered later: the highest-value unknown
   in the project stays open through all of phase 4; §8.1 items 3–5 stay open with
   it; and the **first flash of this firmware will be onto the one board where a
   crash before the login path completes bricks the device**, with DFU unavailable
   at RDP=2 (§6.1). Phase 4 therefore has to carry more host-side proof than it
   otherwise would — which is the argument for the interop harness rather than
   against it. (**This paragraph ended "No linker script or entry point work is
   scheduled before phase 5" until 2026-09-10.** Both were written anyway, ahead of
   schedule: `firmware/link.x` and `firmware/src/entry.rs`, which is what made the
   linked-image measurements in §10 possible at all. Nothing about the signing-latency
   decision changes — that still needs the board.)
2. **Is the panic counter's storage actually writable?** §6.2's handler writes
   `RTC_BKP0R` after the `0xCA`/`0x53` WPR unlock. Two things are **assumed**:
   that `PWR->CR1` `DBP` is already set when firmware runs — if it is not, the
   write is silently dropped, the counter always reads 1, and the handler resets
   forever without ever reaching the callgate fallback — and the exact RTC base
   for STM32L4S5 (used `0x4000_2800`, `BKP0R` at `+0x50`, `WPR` at `+0x24`;
   confirm against RM0432). Fallback if `DBP` is unset: set it in the handler, or
   use the bootloader-reserved 8 K at the top of SRAM3 (`0x2009_e000`,
   `docs/memory-map.md:48`) which `wipe_all_sram` deliberately skips — but that
   region belongs to the bootloader, so confirm it is unused.
3. **Is calling the callgate from a panic context firewall-safe?**
   `dispatch.c:96-101` disables IRQ and calls `__HAL_FIREWALL_PREARM_DISABLE()`
   on entry, re-arming at `:697`; the STM32 firewall resets the CPU if code
   outside the protected segment runs while armed. The handler enters with
   `cpsid i`, matching `modckcc.c:104`, but source alone does not establish that
   an entry from exception/handler mode — possibly on a different stack, and the
   gate switches to its own (`startup.S:137-138`, the `mov r10, sp` / `mov sp, r9` pair — **this said `:139-145` until 2026-09-12**, which is the `push {r10, lr}` / `bl firewall_dispatch` / `pop` window and contains no stack switch; DECISIONS.md's `startup.S:122-158` for the same fact was right) — satisfies the firewall. If it
   does not, the result is a firewall reset: benign here (same outcome as the
   intended reset) but it means the DFU fallback silently never works even on dev
   units. **Confirm on an RDP≠2 dev unit that a deliberate panic lands in DFU.**
4. **Which flash-error paths actually panic? — STILL OPEN, but NARROWED, and its
   PREMISE WAS WRONG.** This item read, until 2026-09-12: *"The §6.3 priority-2 and -3
   sites cannot be shown reachable without a fault-injecting harness. `TestNorFlash`
   models no failures. Build one on the existing doubles — `MemoryNonceSlot`
   (`device_nonces.rs:501-514`) and `TestNorFlash` (`frostsnap_embedded/src/test.rs`) —
   that injects write failures and records which of the 13 enumerated sites fire."*
   **THE HARNESS DOES NOT NEED BUILDING: it exists twice, and both copies are already
   gated.** Two of its three citations were also wrong. `MemoryNonceSlot` is at
   `device_nonces.rs:648`, not `:501-514` (which is `AbSlots::get_or_create`'s tail); and
   `"TestNorFlash models no failures"` is true of `TestNorFlash` itself and FALSE of the
   tree.

   What exists:
   - `FaultyNorFlash`/`FaultyError` in `vendor/frostsnap/frostsnap_embedded/src/test.rs`
     (`fail_erase_after`, `fail_write_after`, `heal`, `erase_count`, `write_count`) drives
     **5** fault tests — 3 in `ab_write::test`, 2 in `nonce_slots::test` — all inside the
     `frostsnap_embedded --features std` gate (17 tests). It is **`#[cfg(test)]`**
     (`frostsnap_embedded/src/lib.rs:9-11`), so it is unreachable from `hal`/`firmware`
     **and it is WEAKER THAN THE HARDWARE**: it delegates to `TestNorFlash::write`, which
     `copy_from_slice`s with no clear-bits-only rule at `WRITE_SIZE = 4` — a double more
     permissive than the silicon, i.e. the §8.1 defect-5 class. **Use `FakeFlash`.**
   - `hal/src/flash.rs`'s `fake::FakeFlash` (`refuse_programs_now`, `refuse_erases_now`,
     `heal`, `scribble`, `programs`, `erases`, and `refuse_programs_after` as of
     2026-09-13) drives **6 of hal's 18 integration tests**, up from 4 of 16 (**this read
     "4 of hal's 16 integration tests", up from 2 at commit 2a055f7, until 2026-09-13**;
     the +2 is `a_refused_write_after_a_single_copy_write_erases_the_older_copy_not_the_live_one`
     and `a_torn_multi_chunk_write_makes_the_slot_unreadable_and_refuses_to_sign`).
     **Say which metric:** that is FAULT-INJECTING tests. "Tests backed by `FakeFlash` at
     all" is **14 of 18**, up from 12 of 16 (`rg -c 'FakeFlash::new'`). The lane that
     landed the first four reported "7 of 16" and its reviewer disproved it with a
     one-line grep; both numbers are written here so the next reader does not re-derive
     either. Two of those four inject NO fault and use the counters as an observable only.
     **AND THE GREP IS NO LONGER SAFE TO QUOTE RAW — this is the trap-15 shape again.**
     `rg -c 'refuse_programs_now|refuse_erases_now|refuse_programs_after|\.scribble\('`
     over that file is **8**, not 6: two of the eight are DOC-COMMENT mentions of the
     helper (`:938` and `:1080`), not calls. Attributing per-test without excluding
     comment lines counts a seventh test that injects nothing —
     `a_retry_of_the_same_signing_session_returns_the_cached_shares_without_advancing`
     was mis-attributed exactly that way while this paragraph was being written. The 6
     is CODE lines only, one per test.

   **Four of the §6.3 priority-2 sites now have named tests reaching them**, all in
   `hal/tests/integration_frostsnap_over_hal.rs`:
   `an_unreadable_nonce_slot_refuses_to_sign_instead_of_halting` (`SlotUnreadable` — and it
   scribbles `0xff`, not `0x00`, deliberately: at `0x00` the slot DECODES under Fixint and
   the live `assert_eq!(.., "wrong stream id")` fires from the test's own SETUP, i.e. the
   fixture would produce the brick), `empty_sign_sessions_are_refused_before_anything_reaches_flash`
   (the `let-else -> Err(Overflow)` backstop that replaced two upstream panics),
   `a_retry_of_the_same_signing_session_returns_the_cached_shares_without_advancing`, and
   `a_refused_nonce_advance_reports_write_verify_failed_and_leaves_the_index_unadvanced`
   (the read-back comparison, reached NON-VACUOUSLY with a stale `SigningState` for a
   DIFFERENT session).

   **BOTH LEGS ARE NOW SETTLED, and they settle DIFFERENTLY. This read "STILL OPEN: the
   read-back's `read_slot()`-returns-`None` leg and `ab_write.rs`'s `EncodeError` leg both
   need a TORN multi-chunk write, whose whole increment is a 3-line
   `FakeFlash::refuse_programs_after(k)` mirroring `FaultyNorFlash::fail_write_after`"
   until 2026-09-13.** The grouping was the error: only ONE of the two legs is about a torn
   write.

   **LEG 1, `read_slot()` returns `None` — CLOSED 2026-09-13 by
   `a_torn_multi_chunk_write_makes_the_slot_unreadable_and_refuses_to_sign`**, and
   mutation-verified: `read_slot().ok_or(WriteVerifyFailed)?` →
   `.unwrap_or_else(|| with_signatures.clone())` is exit 101 with exactly that one named
   failure, and the mutation's own panic payload shows the call returning `Ok` carrying six
   cached shares for an advance that never reached flash. The helper landed as
   `FakeFlash::refuse_programs_after(k)` scheduling by DOUBLEWORD count (§8's phase-7 row).
   **And the division of labour is worth stating, because a production doc comment had it
   backwards until 2026-09-13:** `Session::open`'s `load_slots` does NOT notice a torn nonce
   write — a slot too torn to decode is silently DROPPED from the `last_used` maximum,
   `AbSlots::new` `filter_map`s it out. What DOES notice it is this read-back-and-compare on
   the CONSUMING path, which turns it into `NoncesUnavailable::WriteVerifyFailed` so **no
   signature share is emitted** (`frostsnap_embedded/src/nonce_slots.rs`'s own
   `last_write_outcome` doc). Verified by reading `AbSlots::new` in
   `frostsnap_core/src/device_nonces.rs`.

   **AND A LIVE HAZARD SITTING IN A DOCUMENTED UPGRADE PATH, which is the most valuable
   thing the 2026-09-13 round measured and belongs in this register rather than only in a
   source comment.** `firmware/src/store.rs`'s own `ponytail:` note proposes, as the upgrade
   for a torn second keygen, "`identity.rs`'s paired-record design, read both copies and pick
   the newest that checksums". **Implemented as a fallback inside `AbSlot::read`, that is a
   nonce-reuse hazard.** MEASURED: making `AbSlot::read` fall back to the older copy on a
   decode failure left **267 hal lib tests, 5 smoke tests and all 16 pre-existing integration
   tests GREEN**, while making `sign_guaranteeing_nonces_destroyed` return `Ok` carrying six
   cached `SignatureShare`s for a nonce advance that never reached flash — because the cached
   arm's `with_signatures` **IS** the older copy, so the read-back equality check passes.
   `a_torn_multi_chunk_write_makes_the_slot_unreadable_and_refuses_to_sign` is the only test
   in the tree that catches it. The share record can fall back safely **only** because it has
   its own checksum; the nonce slot has none, and its read-back verification depends on
   `AbSlot::read` NOT falling back. The scoping sentence is now in `store.rs` beside the note
   that proposes it, so the implementer reads it where the work would start.

   **LEG 2, `ab_write.rs`'s `EncodeError` leg — RECLASSIFIED from open to UNREACHABLE BY
   CONSTRUCTION, and deliberately NOT converted to an `expect`.** `BincodeFlashWriter::write`
   (`partition.rs:292-315`) returns its only error from inside `if self.buf_index ==
   BUFFER_SIZE`, **before** `self.buf_index = 0` and **before** `self.word_pos +=`. So it
   returns with `buf_index == BUFFER_SIZE` and `word_pos` unmoved; `flush()` then computes
   `aligned_index == BUFFER_SIZE` (`BUFFER_SIZE % WRITE_SIZE == 0` is asserted at
   construction), fills an EMPTY range, and issues `nor_write(word_pos * WRITE_SIZE,
   &self.buf[..BUFFER_SIZE])` — **the byte-identical program at the identical offset that
   just failed.** `writer.flush()?` therefore returns first and `encode_result` is NEVER
   inspected. Observing that leg needs one identical program to fail and its exact replay to
   succeed: impossible under any monotone count-scheduled refusal (`FakeFlash::programs`
   only increments on SUCCESS, so once `programs >= k` it never rises again), impossible
   under the vendored `FaultyNorFlash::fail_write_after`'s identical permanent-from-n
   semantics, and impossible under `FakeFlash`'s clear-bits rule since the failed attempt
   mutated nothing. **NOT converted to `expect`/`unreachable!`, and the reason is the
   project's whole shape:** that would turn a provably unobservable total error branch into
   a REACHABLE panic on a transient `PROGERR`, under `panic = "abort"` at RDP=2 with DFU
   hardware-impossible and no PIN — strictly worse than the `map_err`. Both legs also
   collapse to `NorFlashErrorKind::Other` (`hal/src/flash.rs` maps `FlashError::Hardware`
   to `Other`), so no assertion could name the site even if it were reached. Reaching it at
   all would need a TRANSIENT knob (`refuse_next_programs(n)`), which is a different helper
   from the one this item scoped.
   **MUST NOT GET A TEST:** `read_back_state.signing_state.ok_or(WriteVerifyFailed)?` is
   unreachable BY CONSTRUCTION — the equality check one line above has just proved
   `read_back_state == with_signatures`, and `with_signatures.signing_state` is `Some` in
   both branches. And `assert_eq!(.., "wrong stream id")` is unreachable through `AbSlots`
   (`AbSlots::get` filters an unreadable slot one call earlier and yields `Overflow`) but is
   a LIVE panic through the trait method — so the vendored comment justifying it names the
   wrong window, which is recorded in the new test's doc rather than by editing `vendor/`.

   **TWO MEASUREMENT LESSONS FROM THAT ROUND, both worth more than the tests:**
   (i) `last_write_outcome()` CANNOT distinguish "no write was attempted" from "a write that
   succeeded" — a self-healing mutation inside the `SlotUnreadable` arm re-writes onto
   already-erased cells, so the recorded outcome is `Some(Committed)`, byte-identical to its
   value before the call, and the mutation is GREEN. The `FakeFlash` program/erase COUNTERS
   are the leg that catches it. (ii) The obvious shape of the headline test — a slot with
   `signing_state: None` — makes the headline mutation GREEN, because the `ok_or` two lines
   below catches the stale `None` and returns the identical variant. "Reach the site" is not
   the same as "be the only site that can fire".
5. ~~**PSRAM capacity is unverified from Coldcard source.**~~ **CLOSED as declined,
   2026-08-20.** It is in the source: **8 MiB at `0x9000_0000`**, configured by the
   bootloader's `psram_setup()` (`mk4-bootloader/psram.h`; called `main.c:150`).
   Recorded as `memmap::PSRAM_BASE`/`PSRAM_LEN`. It does not change the heap decision:
   usable internal SRAM is 647,168 B against a 64 KiB heap, so placement was never
   short of space. Declined rather than deferred — this firmware does not use PSRAM,
   and adopting it would mean inheriting the OSPI/QUADSPI state the bootloader leaves
   configured, for no measured benefit.
6. ~~**Wire-level interop is unproven.**~~ **Run, 2026-08-18.** Decision 5's second
   leg is done for keygen and signing: `hostcheck/` drives a real unmodified
   `frostsnap_coordinator` against real `coldsnap_hal::comms` framing over a pty in
   two processes, completing a **9-of-9** keygen, nonce replenishment and a signature
   that **verifies** with `schnorr_fun`'s `verify_only()` against the coordinator's
   own derived x-only key. See §8.3.

   **Raised to 9-of-9 on 2026-08-18, and that closed two gaps at once.** Frames over
   1 KB now cross **coordinator→device**, which had never happened: measured by
   encoding each outbound frame with the same `BINCODE_CONFIG` `raw_send` uses, the
   harness writes `CertifyPlease` at **2,179 B** and `Check` at **1,624 B**. Both
   match §7's formulas to the byte — `195·9 + 33·9 + 127 = 2,179` and
   `163·9 + 157 = 1,624` — which is independent confirmation from the real
   coordinator's encoder rather than from the scratch measurement harness. And
   2,179 B is **above the old 2,060 bound**, so this keygen was previously *refused*:
   decision 7's raise is now validated on the wire instead of by arithmetic. Timing
   1.16 s at `STUB_CHUNK=64`, 4.65 s at `STUB_CHUNK=1`.

   What remains unproven is interop on *silicon*: this is two host processes.

### 8.3 Phase-4 register — five vendored defects found by mutating the device

**This heading read "two vendored defects" until 2026-09-12**, when implementing screen 8
(address verification) turned up three more, all DEVICE-side, all reproduced or
shadowed-by-a-reproduced-sibling, and all routed around rather than fixed. See the second
table below and the qualification on "COORDINATOR-side" that follows the first.

Nine device-side mutations were run against the M3/M5 harness and all nine failed the
run. **One** of them failed the *wrong way* — by panicking inside the **upstream**
`frostsnap_core` the coordinator process links (not the vendored copy) rather than being
refused. The second was **accepted** where it should have been refused, and only failed
later and from the device side. **This paragraph said "Two of them failed the wrong way
— by panicking inside vendored `frostsnap_core`" until 2026-09-10**, which was wrong
twice over: the defect-14 mutation does not panic at all — `coord_nonces.rs:36` accepts
it and the coordinator builds a signing session on it, exit 1 at 1.21 s — and the crate
that panics is the coordinator's own build, reached by path from `hostcheck/Cargo.toml`,
not the copy in `vendor/`. Both are still findings about the code rather than the
harness.

**Read this first: defect 13 IS fixed in the sibling checkout `hostcheck` actually
links.** `/Users/garykrause/repos/frostsnap` is on branch
`fix/signature-share-unknown-session` at `d8b0525`, "[coord] Don't panic on a signature
share for an unknown session", where `coordinator.rs:874-879` is now
`.get(&session_id).ok_or(Error::coordinator_invalid_message(..))?`. So the coordinator
*process* in a `hostcheck` run no longer carries the panic, and the "exit 101 at 1.33 s"
mutation timing recorded below will not reproduce against that checkout. The **vendored**
copy and upstream `origin/master` still carry the `expect`, which is what the table
below describes. Defect 14 is not fixed anywhere. Per the standing rule nothing is being
filed or proposed upstream; this is recorded because it changes what the harness proves.

**Both are COORDINATOR-side and are NOT in the device image.** `coordinator.rs` is
behind `#[cfg(feature = "coordinator")]` (`frostsnap_core/src/lib.rs:31`) and
cold-snap's vendored manifest sets `default = []` (`Cargo.toml:49`), so neither can
brick a Mk4. They are recorded because cold-snap is the *device* that can trigger
them, we compile this code for host tests, and "our device can crash any coordinator
it is plugged into" is a defect we own the discovery of even when we do not own the
fix. **Do not read this section as a repair of the vendored tree — neither defect is fixed
there.** (This read "Neither is fixed" until 2026-09-10; see the note above for the
sibling checkout, where 13 is.)

| # | Defect | Site | Trigger | Effect |
|---|---|---|---|---|
| 13 | `.expect("inavariant")` on a **device-supplied** field, with no prior guard: `self.active_signing_sessions.get(&session_id).expect(..)` | `vendor/frostsnap/frostsnap_core/src/coordinator.rs:874-877` | a `SignatureShare` naming a `session_id` the coordinator has no session for — reached in the harness by altering the sign task, and independently by flipping one `session_id` byte | coordinator **panics**, exit 101. No named state, no counters, and the harness's `reap` is not on that path, so it also orphans the device process. Any device, or any corruption that survives framing, kills the coordinator |
| 14 | `check_can_extend` returns `Ok(())` for a stream the coordinator never opened *and* for an unknown device — both `None` arms | `vendor/frostsnap/frostsnap_core/src/coord_nonces.rs:33-38` | a device volunteering `NonceResponse` segments for arbitrary `stream_id`s | the device can insert entries into the coordinator's nonce cache unbidden. Fails late and from the wrong side, so the diagnosis points away from the cause |

Both are candidates to report upstream. Defect 13 is the more serious: it is an
unguarded `expect` on attacker-controlled input, which is exactly the class §8.1
catalogued on the device side, sitting on the host side of the same protocol.

#### And three DEVICE-side ones, found 2026-09-12 while implementing screen 8

**"Both are COORDINATOR-side and are NOT in the device image" above is true of defects 13
and 14 and is NOT true of this section.** These three sit in the vendored code the DEVICE
links, on the `ScreenVerify::VerifyAddress` path and the BIP-32 path conversion beside it.
They are not in the shipped image today — `--gc-sections` drops them, because
`Session::recv_core` never calls `FrostSigner::recv_coordinator_message` for that variant
and nothing in the tree formats a `DerivationPath`. **The device is safe because it is
ROUTED AROUND, not because upstream is fixed.** Per the standing PUNT EVERYTHING UPSTREAM
rule (§6.3, decision 6) nothing is being filed; these are recorded because a future edit
that "simplifies" the dispatch arm into a fall-through re-arms defect 15 in one line, and
because `vendor/README.md`'s panic-site table had no row for any of them. Each was
verified symbol by symbol against the vendored tree on 2026-09-12, not taken from a
report. `device.rs` is byte-identical to upstream `d8b0525`; `tweak.rs` differs only by
decision 3, which does not touch the site.

| # | Defect | Site | Trigger | Effect |
|---|---|---|---|---|
| 15 | `.expect("cannot verify address on key that doesn't support bitcoin")` on `wallet_network(..)`, **after** the key-existence check has already passed | `vendor/frostsnap/frostsnap_core/src/device.rs`, `FrostSigner::recv_coordinator_message`'s `ScreenVerify(ScreenVerify::VerifyAddress { .. })` arm (cited by SYMBOL — the arm is ~`:383-414` today and vendored line numbers rot on every re-vendor) | **ONE WIRE FRAME.** `wallet_network` returns `Some` only for `KeyPurpose::Bitcoin(network)` and `None` for `Test` and `Nostr`, and the arm's own `self.keys.get(&key_id)` check has ALREADY returned a clean `Error::signer_invalid_message` for an unknown key — so the only way to reach this `expect` is a key the device DOES hold whose purpose is not Bitcoin | device **panics** = reset loop = **brick**. **REPRODUCED as a panic at `device.rs:411:22`, 2026-09-12**, by replacing our own dispatch arm with a fall-through. Routed around, not fixed: `Session::recv_core`'s `ScreenVerify` arm destructures the payload and RETURNS before the fall-through to `signer.recv_coordinator_message`, and `Session::verify_prompt` does the same lookup as `.ok_or(Refusal::AddressVerify)?`. **That `return` is the whole safety story**, which is why the mutation that deletes it is a named test |
| 16 | `bitcoin::Address::from_script(&spk.spk(), network).expect("has address form")` | same file, same arm, the line immediately after defect 15 (`:414`) | a script with no address form for the chosen network | device panics = brick. Not independently reproduced — defect 15 fires first on the only route in — so it is recorded as LIVE-but-shadowed. Routed around by the same `return`; our `Session::verify_prompt` spells it `.map_err(\|_\| Refusal::Undisplayable)?` |
| 17 | `ChildNumber::from_normal_idx(path_segment).expect("valid normal derivation index")` | `vendor/frostsnap/frostsnap_core/src/tweak.rs`, `<DerivationPath as DerivationPathExt>::from_normal_path_segments` (`:456` in the vendored copy; the line differs upstream because decision 3 inserts `bip341_taptweak_key_only` above it — cite the SYMBOL) | ANY index with bit 31 set. `impl From<BitcoinBip32Path> for DerivationPath` (`:96-106`) chains `bip32_path.index` straight in, and `BitcoinBip32Path.index` is a raw `pub index: u32` (`:75-78`) that is `bincode::Decode`, i.e. wire-constructible with any `u32`. `ChildNumber::from_normal_idx` errs for `>= 2^31`, so **half of all coordinator-sendable indices** reach it | device panics = brick. **REPRODUCED as `valid normal derivation index: InvalidChildNumber(4294967295)`, 2026-09-12.** It has **NO in-tree caller** — `firmware/src/lib.rs` composes a `ui::Buf::<16>` of `"Recv #"` plus the decimal index precisely so it never formats a `DerivationPath` — and the mutation that writes the naive version is a named test that fires only on the `u32::MAX` fixture, not the index-0 one |

The SHAPE these three share, and it is the phase-4 lesson: **a vendored `expect` we route
around is one `=> {}` away from being a vendored `expect` we execute.** Defect 15's
reachability is not hypothetical and does not need a corrupt frame — an ordinary
`KeyPurpose::Test` keygen, which is what `hostcheck` itself does, plus one
`VerifyAddress` frame, is the whole recipe.

#### Opened by phase 3

7. **Does this firmware need a global allocator? YES — settled by measurement
   2026-08-18.** The seam is `comms::Link::poll`, generic over the frame type and
   allocating nothing itself; decoding a real `ReceiveSerial<Upstream>` allocates,
   because `EncapsBody(Vec<u8>)` and `Destination::Particular(BTreeSet<DeviceId>)`
   are in the type. Forcing that monomorphisation and then forcing a link step:

   ```text
   cargo rustc --release -p coldsnap_hal --crate-type staticlib
   error: no global memory allocator found but one is required
   ```

   **The earlier "links for the device without one" claim was an artefact of the
   build shape, not a finding.** An rlib defers the allocator check to link time, so
   every clean device build *of the library* was silent on the question rather than
   evidence for it. **That is now settled the other way round: `firmware/` is a bin
   target, it links, and it registers one.** `firmware/src/alloc.rs`'s `ALLOCATOR` is
   `#[cfg_attr(target_os = "none", global_allocator)]` over `linked_list_allocator`
   0.10.6 on a 64 KiB static arena; `firmware/src/main.rs`'s `entry_point` calls `alloc::init()`
   as boot step 5, after `.bss` and `.data`. Verified by mutation 2026-09-10: delete
   the attribute and `cargo build --release` fails at exit 101 with *"no global memory
   allocator found but one is required"*, so the registration is load-bearing and a
   gate catches its removal. **This paragraph ended "the only thing deferring it is
   that no caller instantiates the concrete type yet. Phase 4 must therefore choose a
   heap, not decide whether to have one" until 2026-09-10.** The choice was made and
   the heap shipped; (a)-(d) below are the record of how it was sized.

   **SUMMARY — both decode legs are now bounded, 2026-08-18.** (The detail is in
   (c) and the block after it; this is not a fourth item in the (a)/(b)/(c) list
   below.) The outer leg has been
   `comms::DECODE_ALLOC_LIMIT = 2 x FRAME_LIMIT = 8,192` since the OOM reset loop was
   found (a **10-byte** frame provoked a 32,748 B allocation on the one error path
   `drain` keeps buffered, so it re-allocated on *every* subsequent poll). The nested
   `EncapsBody` leg is now `comms::ENCAPS_DECODE_LIMIT = 5 x FRAME_LIMIT = 20,480`
   via `comms::decode_body`, which replaces the vendored
   `WireCoordinatorSendBody::decode` at the device call site. Measured before: a
   **20-byte** inner blob provoked a **32,640 B** single allocation there.

   Per-frame worst case **~65,516 B -> 28,672 B**, a 56% reduction. `heap.rs`'s
   binding assert went from 6,540 B spare to 18,828 B at the time
   (18,036 + 8,192 + 20,480 = 46,708 <= 65,536). **Both figures are superseded: the
   relation is now 17,844 + 8,192 + 20,480 + `OUTBOX_CEILING` 8,160 = 54,676, leaving
   10,860 B**, and the constraint on `HEAP_BYTES` is
   `MEASURED_ARENA_FOOTPRINT_BYTES` = 60,512 (5,024 B spare) — a real
   `linked_list_allocator` high-water figure — rather than either the hostile ceiling
   or `MEASURED_PEAK_BYTES`, which is **54,496**, not the 48,166 this paragraph
   carried until 2026-09-10. `hal/src/heap.rs` is the authority for all of them.

   Two properties of the number worth keeping: it is **sized off the DEBUG column**
   (amplification is 3.64x release but 4.36x debug, because `size_of::<Point>()` is
   120 B against 144 B, so a 16 KiB limit would refuse a legitimate frame in debug
   while admitting it in release -- the profile-divergence class of §8.1); and
   bincode's `Limit<L>` charges the 8-byte length claim against the same budget, so
   the effective budget is 20,472 B, found by bisection and pinned by
   `the_inner_limit_boundary_is_exact`.

   **And the shared vendored constant came down with it, 2026-08-19:**
   `MAX_MESSAGE_ALLOC_SIZE` **32,768 → 20,480**. It also governs the *other*
   direction (device→coordinator bodies), which is why it was left alone until that
   direction was measured — lowering a shared bound with a direction unmeasured is
   how 2,060 happened. It is measured now: **17,664 B** debug / 15,360 B release for
   the largest frame the transport admits at all, so 20,480 (effective 20,472)
   refuses nothing either direction can legitimately carry. See (d) below for the
   scope of that change, which is narrower than it looks. `comms::decode_body`
   stays regardless: it is what stops the bound reverting on the next re-vendor.
   **Is it hardware-specific?** The allocator *implementation* is not — any of the
   portable ones is ordinary Rust. What is hardware-specific is the region it hands
   out, and on this board that is not a free choice: SRAM is not zeroed but *filled*
   with `0xdeadbeef` by the bootloader (`main.c:42,47,130`), the top 8 K at
   `BL_SRAM_BASE = 0x2009_e000` belongs to the bootloader and is **wiped on every
   callgate entry and exit** (`startup.S:124-134,148-157` — **the exit range read `148-156` until 2026-09-12**, one line short of the loop's own `bne wipe_loop2` at `:157`), and item 5 below — PSRAM —
   would change the size available by an order of magnitude if it were characterised.
   A heap whose extent is picked before those three are settled is picked wrong.

   **Sized, bounded, and LANDED. Read the four parts separately — (a) and (b) are
   findings, (c) is a repair, (d) is a measurement plus a pre-emptive bound. This
   heading ended "The allocator itself is still not registered" until 2026-09-10;
   it is registered, in the bin crate, and `hal/src/heap.rs` remains
   constants-only so no library dictates the choice to its consumers.**

   **(a) SIZE — measured, landed as constants.** `hal/examples/heap_profile.rs`
   (host, release, `--features heap-profile`) drives a real `FrostCoordinator`
   against real vendored `FrostSigner`s through keygen → nonce replenishment → a
   signature asserted to verify, with a tracking allocator, attributing heap **per
   device** rather than per process: transient in windows around single device
   calls, live destructively by dropping one `FrostSigner` and watching the
   net-bytes counter fall. One Mk4 in a 9-of-9 group needed **48,166 B peak**
   = 18,036 B live across frames + 30,130 B worst transient frame on this harness.
   **Both constants have since been re-measured, and this paragraph quoted the old
   pair until 2026-09-10:** `heap::MEASURED_PEAK_BYTES` is **54,496** and
   `MEASURED_LIVE_BYTES` is **17,844**. The peak went *up*, and the reason is recorded
   in `heap.rs`: the claim that "the hostile decode legs do not stack on top of the
   live peak — the device processes one frame at a time" was wrong. `heap_session`
   holds `Link::poll`, `comms::decode_body`, `Session::recv`, `Session::confirm` and
   the `staged_mutations` drain in one span **with the `Outbox` undrained**, and they
   do stack. `heap.rs` also records a *simultaneous* live peak of 35,413 B in at most
   26 blocks (largest single block 7,200 B), which is what a reusing allocator
   actually has to serve; `MEASURED_PEAK_BYTES` is a high-water figure including
   churn a non-reusing allocator never gives back. The live half is
   a **constant** — identical at group size 1/2/3/5/9, identical after 1/2/4
   signing sessions, +112 B per nonce slot — which is what makes a static budget
   provable. `coldsnap_hal::heap` now records `HEAP_BYTES = 64 KiB` with those
   measurements and the compile-time relations that derive it. Host 64-bit figures —
   and **the "32-bit direction is lower (certain), magnitude (~10–40%) unmeasured"
   claim this sentence carried until 2026-09-10 is wrong in its load-bearing half.**
   The direction is right; the magnitude is not, and it is nearer zero than 10%.
   `secp256kfun` reaches the curve through `k256`, whose `FieldElement10x26` (32-bit)
   and `FieldElement5x52` (64-bit) are **both exactly 40 B**, so `Point` is 120 B on
   both widths and the dominant consumers do not shrink at all (`hal/src/heap.rs`).
   Do not budget on a 32-bit discount.
   Also actionable: 12,456 B of the 18,036 B (69%) is empty-but-allocated keygen
   `BTreeMap` leaf nodes and is reclaimable after `keygen_finalize`. Call the
   narrower **`clear_unfinished_keygens()`** (`device.rs:249`), **not**
   `clear_tmp_data()` — they free the same 12,456 B, but `clear_tmp_data` also clears
   the restoration leg and so can discard a typed-in physical backup. The saving is
   n-independent (identical at *n* = 1, 9, 11, 12, 13) precisely because it is nodes
   and not data. **Still not called by firmware — but "no event loop exists" was the
   stated reason until 2026-09-10, and one does.** `clear_unfinished_keygens()` has no
   caller outside `firmware/examples/heap_session.rs`. What firmware *does* call is
   the wider `clear_tmp_data()`, once, in the `Cancel` arm (`firmware/src/lib.rs:955`)
   — where discarding the restoration leg is the intent rather than the hazard, since
   `Cancel` also drops the reveal grant, the previewed name and any half-typed share.
   So the 12,456 B is still on the table, and `MEASURED_LIVE_BYTES` still records the
   figure for firmware that does not reclaim it, which is the conservative direction. Durable live residual after the call is
   **5,580 B**. See `heap::MEASURED_LIVE_BYTES` for the scope of the green run.

   **(b) A bump-reset arena is DISQUALIFIED, and that is a finding, not a
   preference.** Decode is perfectly LIFO (`held == 0` for every inbound frame,
   including the largest that fits `FRAME_LIMIT`), but `FrostSigner` keeps two
   `BTreeMap`s, a `String` and a `BTreeMap` of encrypted shares alive across frames
   (`frostsnap_core/src/device.rs:37,48,50,88`), and the long-lived set *grows*
   after transient allocations, so no high-watermark scheme rescues it: a reset
   point frees live key material. A general allocator is therefore required.
   Candidates were measured as thumbv7em staticlibs and **flash is a non-criterion**
   — the whole spread between cheapest and dearest is 1,513 B = 0.11% of
   `FLASH_TEXT`. This survey named `buddy_system_allocator` 0.13 the
   leading candidate and said "**Neither is in the manifest**, and nothing here
   registers a `#[global_allocator]`". **Both clauses are superseded, 2026-09-10.**
   Buddy was *disqualified* on a later measurement recorded in `hal/src/heap.rs`: it
   rounds every request up to the next power of two, so the 20,480 B
   `ENCAPS_DECODE_LIMIT` leg is charged **32,768 B**, which gives back the entire
   headroom the encaps fix bought and hands a hostile coordinator a free ~2×
   amplifier — claim 16,385 bytes, be charged 32,768. What shipped is
   **`linked_list_allocator` 0.10.6**, in `firmware/Cargo.toml`, wrapped by hand in
   `firmware/src/alloc.rs` — deliberately *not* its `LockedHeap`, because that and its
   `GlobalAlloc` impl are both behind `use_spin`, and a spinlock an ISR could contend
   on would hang forever on a unit with no DFU. The rule that a *library* must not
   register one still holds, and is why `hal/src/heap.rs` is constants-only
   (measured: 575 harness allocations through it, and a `SIGABRT` before any test runs
   with an un-`init`ed arena). §1's line-by-line `unsafe` review was paid rather than
   waived: it is what found the two guards `alloc.rs` documents — `dealloc`
   bounds-checks the pointer, because `check_merge_bottom` (`hole.rs:246-252`) tests
   only an *upper* bound and underflows into a ~4 GiB free-list hole on a pointer
   below the arena, while `hole.rs:501` tests the other end and so cannot catch it;
   and the init sentinel is `b"HLL1"` rather than any of `0xdeadbeef` / `0` /
   `0xffff_ffff`, each of which a cold Mk4 boot, the `.bss` loop or a faulted read
   would otherwise present as "initialised".

   **(c) The remote OOM reset loop — REPAIRED.** `FRAME_LIMIT` never bounded
   per-frame allocation: `bincode`'s
   `Limit<1<<15>` from `frostsnap_comms` did, at **8 × `FRAME_LIMIT`**. A
   **ten-byte** frame (three variant tags + a three-byte length varint + four bytes
   of payload) made the decoder allocate **32,748 B**, because `Vec<u8>`'s decode
   runs `vec![0u8; len]` *before* reading — and it landed on
   `DecodeError::UnexpectedEnd`, the one error `comms::drain` treats as "more bytes
   coming" and keeps buffered, so the allocation repeated on **every** subsequent
   `poll`, forever, with no further attacker bytes. Since OOM = `handle_alloc_error`
   → `#[panic_handler]` → `NVIC_SystemReset` with no way to refuse
   (`handle_alloc_error` is infallible on stable), that is a remote coordinator
   holding the device in a reset loop, and the RTC counter bounds it in neither
   direction (§6.3: either it never clears and saturates into `try_enter_dfu`, or it
   was cleared and never trips). Fixed by `comms::DECODE_ALLOC_LIMIT =
   2 × FRAME_LIMIT`, a decode-side-only config change: `LIMIT` is never read by
   `bincode`'s encoder, so **zero wire bytes change** and no coordinator agreement
   is needed, and an over-claim now returns `LimitExceeded` *before* allocating,
   into the existing tested `unlink()` + `Desync` refusal. 2 × is safe because
   every container in `ReceiveSerial<Upstream>` charges `len * size_of::<T>()`
   with `size_of == wire size` (`DeviceId(pub [u8; 33])` is a byte array, not a
   `Point`; `EncapsBody(Vec<u8>)` is 1:1), so a frame that fits `FRAME_LIMIT`
   cannot legitimately claim much more. Verified in both directions and
   mutation-tested: `an_over_claiming_frame_is_refused_before_it_allocates`,
   `the_over_claim_would_otherwise_repeat_on_every_poll`,
   `a_limit_sized_frame_of_device_ids_still_decodes_under_the_new_limit`, plus the
   real 9-of-9 `hostcheck` run against an **unmodified** coordinator.

   **Also repaired, and the shared constant is now down too (2026-08-19).** The
   nested `EncapsBody` decode is bounded in our code by `comms::decode_body`
   (see (c) above), and the vendored `MAX_MESSAGE_ALLOC_SIZE`
   (`frostsnap_comms/src/lib.rs:54`) has come **32,768 → 20,480**, the same figure,
   so one number now bounds both encapsulated legs. What cleared it was the
   device→coordinator measurement this section previously recorded as never taken:
   see (d) below. `heap::ENCAPS_ALLOC_CEILING` tracks
   `comms::ENCAPS_DECODE_LIMIT` by reference, and `HEAP_BYTES` is asserted large
   enough to absorb both legs at once alongside the measured live set
   (`MEASURED_LIVE_BYTES` 17,844 + 8,192 + 20,480 + `OUTBOX_CEILING` 8,160 = 54,676
   ≤ 65,536, leaving 10,860 B), so the build fails rather than the
   device if either limit is ever widened. (**This relation read
   "18,036 + 8,192 + 20,480 = 46,708" here until 2026-09-10**; the live figure was
   re-measured to 17,844 and the outbox term was added, both already recorded in
   `hal/src/heap.rs`.) **Placement is SETTLED, and this sentence read "Placement is
   untouched — the four blockers above (no linker script, …) all still stand" until
   2026-09-10.** `firmware/link.x` is what settles it, and its two load-bearing bounds
   are both link-time `ASSERT`s: `RAM` starts at `0x2000_8010`, *above* the
   bootloader's 12-byte `dfu_flag` at `0x2000_8000` — which `main.c:115` memcmps
   against `REBOOT_TO_DFU` *before* `wipe_all_sram()`, so a surviving byte of ours
   there is a **remote permanent brick** at RDP=2 — and ends exactly at
   `BL_SRAM_BASE = 0x2009_e000`, below the 8 K the callgate wipes on entry and exit.
   The arena is measured into `.bss`: `llvm-nm` puts `ALLOCATOR` at `0x2000_8038`,
   65,564 B, all but 8 bytes of `.bss`'s 65,572 — zero flash, and its ready sentinel
   gets zeroed by the entry's step-3 loop for free. `.uninit` is emitted and **empty**;
   moving the arena there to skip 64 KiB of boot-time zeroing is one `#[link_section]`
   away and deliberately not done, because nothing has measured that zeroing as a cost.
   `0xdeadbeef` is handled by `alloc.rs`'s GUARD 2 rather than avoided, and PSRAM was
   declined outright (item 5). What remains true: 64 KiB is a reservation derived from
   the workload — though `MEASURED_ARENA_FOOTPRINT_BYTES` = 60,512 is now a real
   high-water figure for `linked_list_allocator` specifically, leaving 5,024 B, so the
   allocator's own overhead is no longer entirely unmeasured. The reset entry zeroing
   `.bss` is a *correctness precondition* for the allocator, not a nicety: its
   control block is a `static`, so an unzeroed one comes up as `0xdeadbeef` — the
   same defect `singleton::TakeOnce` exists to fix, and the reason GUARD 2's sentinel
   may not be any of `0xdeadbeef`, `0` or `0xffff_ffff`. Restoration/backup flows were
   never driven by the profiler and share the same phase enum, so re-run it before
   treating the size as final.

   **(d) The device→coordinator leg — MEASURED 2026-08-19, and the shared constant
   lowered. Read the scope before crediting it.** This was the gate on
   `MAX_MESSAGE_ALLOC_SIZE`, and it is closed. Measured with a tracking allocator
   over both profiles (`tools/research-scratch/device_send_alloc_measure.rs`, 5
   tests, copied into `frostsnap_core/tests/` to run and deleted after — same
   constraint as its siblings, §7):

   | claim | release | debug |
   |---|---|---|
   | worst *transcript-real* (`NonceResponse`, 1 segment × 30 nonces at `NONCE_BATCH_SIZE`; blob 2,002 B, frame 2,040 B) | 7,424 | **8,704** |
   | worst any `FRAME_LIMIT`-bounded frame can make (61 nonces in one segment; blob 4,048 B, frame 4,086 B — 62 nonces is 4,152 B and `encode_frame` refuses it) | 15,360 | **17,664** |

   So **20,480 is the number, and 16,384 and 8,192 are both wrong.** 8,192 is not
   merely tight, it is the §8.1 defect in miniature: it *refuses* the real
   production 30-nonce `NonceResponse` under `debug_assertions` (8,704) while
   *admitting* it in release (7,424), so the refusal boundary would move with the
   profile. `inner_alloc_measure.rs`'s "the inner limit could come down to 8,192" was
   a coordinator→device-only finding and must not be generalised. The two legs
   converge on the same ceiling for the same reason — both are dominated by `Point`,
   33 wire bytes against 120/144 in memory, so both amplify 3.64x release / 4.36x
   debug (C2D worst ~17,702 computed, D2C 17,664 measured).

   **What the change is worth, stated plainly because it is less than it looks.**
   **Nothing device-side decodes this direction.** `hal/src/comms.rs` decodes
   `ReceiveSerial<Upstream>` and inner *coordinator* bodies only; every mention of
   `WireDeviceSendBody` in `hal/` sits below `#[cfg(test)]`, `frostsnap_comms/src/lib.rs`
   is the only non-test file in the vendored tree that names the type, and
   `hostcheck`'s coordinator decodes with the *sibling* checkout, which this change
   does not touch. So this is a correct **pre-emptive** bound for the day a device
   relays a downstream device's body — not the repair of a live exposure. It also
   **changes neither flash nor heap**: `heap::ENCAPS_ALLOC_CEILING` was already
   20,480, and no new call site is created. What it does buy is the hostile ceiling,
   which tracks the limit 1:1: a **21-byte** blob provoked 32,544 B in one allocation
   under the vendored 32,768, and 20,448 under 20,480 — a 37% cut.

   Two things this did *not* settle, kept here so nobody reads the row as broader
   than it is. The decode limit does **not** bound multi-segment heap use: a
   2-segment `NonceResponse` holds 17,436 B (debug) live at once while still decoding
   under an 8,960 B limit, and 4 segments 34,828 B — it is `FRAME_LIMIT` that refuses
   3+ segments (6,036 B), not the limit. And `HeldShares2` is device-emitted and
   uncapped in this tree (`device/restoration.rs:362` iterates every stored access
   structure); measured with a real element at synthetic counts, it overruns
   `FRAME_LIMIT` at ~27 shares — long before any decode limit binds — which confirms
   cap 2 below is the right place to fix it. Nothing ran on ARM; all figures are host.
8. **Polling vs interrupts for OTG_FS.** `usb.rs` polls `GINTSTS` and never enables
   the NVIC line, which is the only shape that works in a tree with no vector table
   and no `cortex-m-rt`. Whether polling keeps up with a 64-byte-packet CDC stream
   at 120 MHz is a bench measurement, and it interacts with item 1 (signing latency):
   a slow `secp` operation with no ISR means no `poll` call for its duration.
9. **`MODE_SETTLE_SPINS` is a placeholder, not a figure.** It stands in for ST's
   `HAL_Delay(50)` after the mode write (`stm32l4xx_ll_usb.c:236`), as a spin count
   because this crate has no timer. It is deliberately the knob to turn first at the
   bench. Same class as `RESET_SPIN_LIMIT` and `EP_IDLE_SPIN_LIMIT`.
10. **Two register-state assumptions at bootloader handoff.** Whether
    `RCC_APB1ENR1.PWREN` is already on (`bring_up` enables it only if off, and
    restores it) and whether the 48 MHz clock is live — the code assumes the
    bootloader leaves PLLSAI1-Q running with `RCC_CCIPR.CLK48SEL = 0b01` and
    programs neither. If the clock assumption is wrong, enumeration fails at
    `ENUMDNE` and the fix is one register; if `PWREN` is wrong, `PWR_CR2.USV` never
    takes and VBUS detection never reports.
11. **Coexisting with the bootloader's own USB is unexamined.** The Mk4 bootloader
    uses USB for DFU and for upgrade mode. Nothing here establishes what state it
    leaves the OTG_FS core in, or whether re-initialising it from firmware while the
    host still has the bootloader's device enumerated works or needs a bus reset.
    `bring_up` does a full core reset, which is the right default, but that is an
    argument from first principles and not a measurement.

12. **The consent gap. HALF OF THIS ITEM IS CLOSED and the text below was stale
    until 2026-08-27** — it claimed the session hash is never compared
    device↔coordinator, and that has not been true since the gap-closing pass:
    `hostcheck/src/main.rs`'s `THE SESSION HASH, COMPARED ACROSS THE PROCESSES` block compares **every** device's computed session
    hash against the coordinator's, requires all `N_DEVICES` to have reported, and
    bails with `SESSION HASH MISMATCH: {id} computed {got}, the coordinator computed
    {want}`. It is a genuine cross-check — two OS processes and two *different builds*
    of `frostsnap_core` (upstream via `frostsnap_coordinator` on one side, vendored in
    the stub on the other) — and it is ours by name rather than relying on upstream's
    internal `recv_device_message` refusal, which a re-vendor could silently drop.

    **What remains open is narrower and worth stating precisely: the hash is compared
    CORE-to-CORE, not SCREEN-to-coordinator.** Nothing asserts that the 4-byte code
    `ui::keygen_check` actually *renders* is the code the coordinator computed. A
    device that verified the right transcript and then drew the wrong four bytes would
    pass everything above, and the human comparison is the whole anti-MITM defence.
    **CLOSED 2026-08-31.** `firmware/examples/stub.rs::glass_code()` reads the four
    rendered bytes back off the *same* `ui::Frame` the consent answered, using the
    promoted `ui::Frame::cell_2x` (not a second implementation of the mapping), and
    reports them on the existing wire as a `Debug` line. `hostcheck/src/main.rs`'s `ASSERTION 1` block
    compares them against its own session-hash prefix, requires all 9 devices to have
    reported, and bails `GLASS CODE MISMATCH: <id> RENDERED <x> on the screen a human
    reads aloud, but this coordinator's session hash starts <y>`. Measured:
    `THE GLASS shows d25f9b9b on 9/9 devices`, the same value from two OS processes and
    two different builds of `frostsnap_core`.

    The assertion is **structural, not additional**, and that is the part worth
    understanding: the confirm digit is randomised, so a script cannot answer a signing
    prompt without first reading the digit out of the framebuffer. Verified with no
    source change — `COLDSNAP_GLASS_KEYS=y9` (a hardcoded key) and `=11` both exit 1,
    while the pixel-reading path exits 0. A device that renders the wrong prompt fails
    automatically because the script presses the wrong key and is refused.

    **ALSO CLOSED, and this paragraph denied it until 2026-09-10.** It read: *"Still
    open, unchanged: `firmware/examples/stub.rs` **auto-acks `SignatureRequest`**, so
    the approval policy — the only thing between a coordinator and a signature — has
    never been exercised on the gate path."* It does not auto-ack it.
    `stub.rs`'s `approved` answers `DeviceToUserMessage::SignatureRequest { .. } => digit.accepts(key)`,
    where `digit` is a fresh `ui::ConfirmDigit::draw(rng)` printed on the very frame
    the consent answered (the frame `stub.rs`'s `approved` drew) and `key` comes back from the `Consent`
    closure, which reads the legend out of the rendered pixels
    (`stub.rs`'s `advertised_key`). `hostcheck` runs a **third DECLINE pass** on
    every invocation (`hostcheck/src/main.rs`'s `Expect::Decline`) in which every device presses `x`,
    and fails the run if a declined prompt yields a share (`:1520`; also
    `A DECLINED PROMPT PRODUCED A SIGNATURE` at `:1331`). Measured this session:
    `all 9/9 device(s) pressed \`x\` at the signing screen and NOT ONE signature share
    reached the coordinator`. The stub's own log line still says "auto-ack" for both
    consent arms, which is where this claim came from — the log is wrong, not the gate.

    **CLOSED 2026-09-11 — `CheckKeyGen` now asks for the randomised digit like every
    other consent screen, and the paragraph this replaces is the withdrawn reasoning.**
    It read: *"`CheckKeyGen` is gated on the key the screen advertises rather than on a
    randomised digit: `ui::keygen_check` prints `1=match` and `stub.rs:495` accepts
    `key == b'1'`. That is deliberate — accepting the signing digit there would accept a
    key the screen never showed — and `advertised_key` does read the legend off the
    glass, but the byte it finds is a **constant**, so a hardcoded `1` answers it too."*

    The last clause was the whole problem, and the justification was wrong in a way
    worth naming: it ranked the screens by how much money moves on the press, so the
    signing screens got the strong gesture and the anti-MITM screen got a fixed key.
    But the measure that picks a confirm key is **how much a script can fake**, not how
    much a press is worth — and by that measure the keygen check was the weakest screen
    on the device while being the one whose whole purpose is defeating a lying
    coordinator.

    `ui::keygen_check` now takes a `ConfirmDigit` and prints `press_legend(confirm)` +
    `" x=no"`, the same legend the signing screens use; `KEYGEN_MATCH_KEY` is deleted
    and `answer`'s per-prompt arm went with it, so `Consent::Prompt` has exactly one
    rule for every prompt. **The 2x code rows did NOT move** — `((COLS-8)/2, 2)` and
    `(.., 4)` — because `stub.rs::glass_code` reads them back from those cells and that
    read is the anti-MITM gate; a mutation moving the low half to row 3 fails three hal
    tests AND `hostcheck` with `GLASS CODE MISMATCH: … RENDERED UNREADABLE`.

    Proven with NO source mutation, which is the point: `COLDSNAP_GLASS_KEYS=1yy` —
    a hardcoded `1` at the keygen screen — now exits 1 with **8 of 9 devices declining**
    (one happened to draw `1`, which is the 1-in-5 made visible and is deterministic
    under the stub's fixed seed), and `=9yy` exits 1 with 9/9 declining because `9` is
    not in `CONFIRM_CHARSET` at all. Before the change `1yy` completed both signature
    passes in full. Cost: **+440 B of flash** (376,752 → 377,192 B, 26.43% → 26.46%).

    So no literal answers any consent screen on this device now.

    And note a constraint found while designing the fix: **the vendored protocol has no
    "decline" message**, so a refusal is expressible only as *not confirming* plus a
    `Debug` back-channel line. This is why phase 4's gate is recorded as *met but not
    signed off* in §8, and it is the reason that row should not be read as "signing is
    verified".

    **The restoration flows are IMPLEMENTED but not coordinator-driven, and this
    paragraph said they had "never been driven by any harness" until 2026-09-10.**
    `Session::recv` admits `DisplayBackup`, `CheckBackup`, `EnterPhysicalBackup`,
    `SavePhysicalBackup`, `SavePhysicalBackup2` and `Consolidate`
    (`firmware/src/lib.rs:1059,1106-1110,1162`), each behind its own consent digit, and
    all of them are driven by unit tests in `firmware/src/lib.rs`. What no harness does
    is drive them from a **real coordinator**: `hostcheck` drives keygen,
    `RequestHeldShares`/`HeldShares2`, a forged `DataErase` that all nine devices must
    refuse, nonce replenishment, signing and the decline pass — and nothing else. The
    coordinator-side entry points exist and are public
    (`request_device_display_backup`, `request_device_check_backup`,
    `start_restoring_key`, `consolidate_pending_physical_backups`,
    `update_name_preview`), so this is host-side work with no hardware dependency; it is
    the largest genuinely-implementable gap left in phase 4.

    **CLOSED 2026-09-11, except for naming — the paragraph above is now history and is
    kept only because it is what the correction is against.** `hostcheck` gained the
    five-call `UiProtocol` lifecycle (`connected` / `poll` /
    `process_to_user_message` / `process_comms_message` / `is_complete`), one boxed
    protocol at a time and deliberately no `UiStack`, and now drives **four** of the
    five flows from their REAL upstream drivers, inside both signature passes and
    strictly after the signature exists:

    | flow | upstream driver | how the pass is decided |
    |---|---|---|
    | `DisplayBackup` | `display_backup::DisplayBackupProtocol` | its **sink**, because `is_complete()` never returns `Success` (see below) |
    | `CheckBackup` | `check_backup::CheckBackupProtocol` | `is_complete() == Success` on `CommsMisc::BackupChecked` |
    | `EnterPhysicalBackup` + `SavePhysicalBackup2` | `enter_physical_backup::EnterPhysicalBackup` | `is_complete() == Success` on `PhysicalBackupSaved` |
    | `Consolidate` | **none exists upstream** — driven through the same `queue` the keygen frames use | `ToUserRestoration::FinishedConsolidation`, then `HeldShares2` again |

    The four assertions, and the reason they are not merely "the flow ran":
    1. the device walks its own reveal, reads all **25 words back out of the
       framebuffer** with the shipped `ui::Frame::cell`, and reports them; `hostcheck`
       re-encodes them with UPSTREAM's `ShareBackup::from_words` and compares the
       resulting share image against its own `expected_share_image`. Two OS processes,
       two builds of `frost_backup`;
    2. the check quiz is answered **only from what that reveal drew** — the stub's
       `quiz_answer` is handed no `quiz::Quiz`, no `quiz::Screen` and no option list,
       and reads the position off row 0 and the three candidates off rows 2/4/6. A
       wrong answer re-asks the same position, so the pass is asserted at **exactly
       `QUIZ_POSITIONS` = 8** answers;
    3. those same 25 words go back in through the letter picker, whose candidate
       letters are **a function of the secret prefix** — so the typing is driven off
       the pixels too — and the coordinator's own `check_physical_backup` accepts the
       share image the device derives from them (MEASURED: 189 keypresses);
    4. after the **destructive** consolidation the device is asked what it holds
       again, and the reported share **image** is compared, not just the
       access-structure ref.

    THREE UPSTREAM FACTS FOUND DOING THIS, all worth writing down:
    * **`DisplayBackupProtocol::is_complete()` can never report success.** It is
      `Some` only on `abort` (`display_backup.rs:60-68`); `CommsMisc::BackupRecorded`
      only pushes `DisplayBackupState { confirmed: true, .. }` into its sink, and every
      field of the driver is private with no accessor. So that one driver's completion
      is observable **only** through a sink, which is why `hostcheck` uses upstream's
      own `Sink::inspect` combinator over the `()` blanket impl rather than passing
      `()` as the other two do.
    * **`CheckBackupProtocol` branches on `firmware.features().check_backup`, which is
      `>= 0.3.0`.** This device announces a DIGEST and never a `FirmwareVersion`, so
      upstream's `FirmwareVersion::new(digest)` leaves `version: None` and `features()`
      FAILS OPEN to `FirmwareFeatures::all()` — the modern path by accident of an
      unknown digest rather than by anyone's decision. `hostcheck` states the version
      (`CHECK_BACKUP_SINCE`) and **asserts the feature** before building the driver, so
      a future upstream that moved the threshold fails by name instead of silently
      driving the legacy physical-backup path with the quiz never running.
    * **`EnterPhysicalBackup::new` calls `EnterPhysicalId::new(&mut rand::thread_rng())`
      inside the constructor** (`enter_physical_backup.rs:23`), so those 16 bytes are
      not reproducible and the M7d frame differs byte-for-byte between runs. Nothing
      downstream derives from them, so no assertion, signature or share image moves.
      Accepted rather than forked: forking the constructor would mean this harness
      stopped driving upstream's own code, which is the only thing it is for.

    Also unavoidable: `PhysicalBackupSaved` — and therefore `EnterPhysicalBackup`'s
    only route to `Completion::Success` — needs a `RestorationId`, which only
    `start_restoring_key` makes usable. A coordinator that already HOLDS the key still
    has to open a restoration to save a physical backup. That is upstream's shape
    (`frostsnapp/rust/src/coordinator.rs`), not a workaround.

    **THE TENTH-DEVICE DECISION, made 2026-09-11: NO tenth device.** `EnterPhysicalBackup`
    is meant for a device holding no share, and all nine hold one, so M7d re-ingests the
    device's OWN backup. The decision rests on a fact worth recording, because it is the
    only thing that makes it safe: **ingest writes nothing durable on this device.**
    `SavePhysicalBackup2` stages `Mutation::Restoration(Save2)`, and
    `store::ShareStore::persist_staged` drops every `Restoration(_)` at the top of
    `Session::run` (`firmware/src/store.rs:424`), so the typed share reaches only the
    signer's RAM-only `saved_backups`. `Consolidate` is the destructive one, and it is
    content-preserving here because it consolidates the same share back.

    The cost of the alternative, named: a tenth blank session would split `N_DEVICES`
    into two constants across **eight** existing assertions — `announced`, `held`,
    `refused_erase`, `device_hashes`, `device_glass`, `replenished`, `device_names` and
    the stub's `saved` — i.e. it would touch every M1–M6 assertion, the highest-value
    evidence in the tree, to add one flow's fidelity. (**This said "seven" until a
    review caught it**: M8's naming assertion, added the same day a few paragraphs up,
    is itself an eighth, and the paragraph naming the cost was edited without
    re-counting. The count is also a floor rather than a total — `declined`,
    `kg.got_shares`, the post-loop `devices.len()` and the stub's `acked` all key off
    `N_DEVICES` too and would all have to be triaged.) And typing the device's own words back is the
    STRONGER assertion: it closes reveal → glass → letter picker →
    `ShareBackup::from_words` → share image → the coordinator's own polynomial in one
    loop, where a blank tenth device could only be handed some other device's backup,
    which is the same assertion with an extra hop.

    **What that leaves genuinely uncovered, and it is a configuration gap rather than a
    code one:** `EnterPhysicalBackup` onto a device whose `Session::open` found nothing
    on flash. The device path does not branch on held shares —
    `tell_coordinator_about_backup_load_result` parks in `tmp_loaded_backups` regardless
    — so nothing untested is *reached* by the blank case. Two second-order consequences,
    stated rather than hidden: M7e's share-image check on the re-reported record cannot
    FAIL in this configuration, and neither can the `index != share_index` guard in
    `Phase::Ingest`.

    **RE-DERIVED 2026-09-12, INDEPENDENTLY, AND THE DEFER STANDS — with three corrections
    to the reasoning above, one of which was a false claim about what M7e checks.**

    FIRST, THE SAFETY FACT HOLDS and the citation is exact: `firmware/src/store.rs:424` is
    `staged.retain(|mutation| !matches!(mutation, Mutation::Restoration(_)));`, above the
    emptiness check, so a queue holding only restoration mutations returns `Ok(())` with
    nothing written. The whole decision rests on that and it is true.

    SECOND, THE COUNT IS RIGHT AND THE SHAPE IS WRONG. The eight named plus the four floor
    items are exactly the twelve counted conditions a fresh enumeration finds — so the
    arithmetic above needs no correction, having already been corrected once from seven.
    But "split `N_DEVICES` into two constants" understates it: `announced` is the keygen
    ROSTER at five sites, not a counter, and the split additionally needs (a) a way for
    `hostcheck` to **ASSIGN** the blank device. **(a) READ "IDENTIFY" AND CONCLUDED THE
    PROTOCOL COULD NOT SUPPLY IT, until 2026-09-12: the premise was true and the conclusion
    was FALSE**, and it was the largest error in this cost estimate. It read: *"a way for
    `hostcheck` to IDENTIFY the blank device, which the protocol cannot supply because all
    ten flashes are blank before keygen."* `hostcheck` OWNS `BeginKeygen`, so it does not
    identify the blank device, it DECIDES which one it is: `roster = announced[..N_DEVICES]`
    and `blank = announced[N_DEVICES]` come out of ONE expression on ONE lap at the
    `BeginKeygen` site, so they cannot disagree, and the choice is then re-checked against
    the coordinator's own `contains_device`. No back-channel, and nothing trusted to a
    device — a harness that asked the devices which one was blank would be trusting them
    about the thing under test. (b) a loosening of the fail-closed per-device
    `None =>` arm in the `HeldShares2` handler, which is the only place a tenth device
    makes an EXISTING assertion weaker; and (c) a second, shorter phase sequence, because
    M7b and M7c cannot run on a share-less device at all — upstream refuses `DisplayBackup`
    and `CheckBackup` for a share it does not hold. **THE CONCLUSION IS RIGHT AND THE
    MECHANISM WAS WRONG: this read "which surfaces as `Fault::Signer` and the stub's
    `die(2)`" until 2026-09-12.** It never gets that far. The refusal is COORDINATOR-side,
    in `request_device_display_backup` and `request_device_check_backup`'s
    `device_to_share_index.get(&device_id).ok_or(ActionError::StateInconsistent("device does
    not have share in key"))` (`frostsnap_core/src/coordinator/restoration.rs`, cited by
    symbol), which runs BEFORE any `CoordinatorSend::ToDevice` is built — **no frame is ever
    written and the stub never sees a `DisplayBackup`.** MEASURED by starting the blank leg
    at `Phase::Reveal`: `DisplayBackupProtocol::new / state inconsistent: device does not
    have share in key`, exit 1. The device-side refusals do exist and are unreachable from
    this harness, so an implementer looking for `Fault::Signer` would be reading the wrong
    process. `Restore`'s `share_index` is not an `Option`, so the struct cannot
    even be constructed for a device that has none.

    THIRD, AND IT IS A SUPERSET RATHER THAN AN ALTERNATIVE: the cross-device ingest that
    looked like a cheaper way to make the two assertions falsifiable was checked and is
    NOT better evidence. A blank device has no reveal of its own to type back, so the
    sheet plumbing (`paper.entry(id).or_default()`, and the `die(2, "no share index was
    ever read off a reveal page")` behind it) is unavoidable in BOTH designs while the
    roster split is needed by only one. And the device does not refuse a foreign share —
    there is no such check, and there should not be, because accepting a share you do not
    hold is the entire purpose of the restore flow. The only thing that would stop a
    cross-device ingest is `hostcheck`'s OWN `index != r.share_index` guard, which makes
    it evidence about the harness rather than about the device.

    **THE FALSE CLAIM, withdrawn: "the write is content-preserving, so a record that
    survived is indistinguishable from one that was never replaced."** That is not why
    M7e cannot fail, and it implies a read that does not happen. `RequestHeldShares` is
    answered from `held_shares()`, which iterates the signer's in-RAM `keys`; our arm for
    it is a pass-through; and the stub's only restart is PRE-KEYGEN. So no flash read
    occurs between the consolidation and the re-report at all, and the true reason is
    stronger than the withdrawn one: **a record that was never written would also
    re-report correctly.** `hostcheck`'s own doc and its M7e failure message both said
    "the record it wrote is one it can read back"; both are corrected, and the flash half
    is covered at Tier 1 by `consolidation_persists_the_share_before_it_acks`, which
    reopens the store after a real reset.

    **BUILT, 2026-09-12, commit 7ba6ea4 — M12.** ~+130 lines across two HARNESS files
    (`hostcheck/src/main.rs` and `firmware/examples/stub.rs`), zero device code, **zero
    flash, zero test-count movement**, harness wall clock 10.11 s -> 12.38 s. TEN devices
    announce and NINE do the keygen; the tenth reaches the verified signature holding
    nothing at all, is handed the 25 words the FIRST device's glass drew, types them back
    through the letter picker (198 keypresses), saves them, and CONSOLIDATES them onto a
    flash that held nothing — then describes the record to a coordinator that had never
    given it one.

    **WHAT IT ACTUALLY BUYS IS ONE ASSERTION, NOT TWO, and this item commissioned it for
    two.** `blank_reported_empty` — the `Some`/`None` discrimination on the re-report —
    becomes falsifiable, because on leg 1 the device consolidates its OWN share back onto
    itself, so a consolidation that acked without reaching the signer is GREEN there.
    **The SHARE-IMAGE half of M7e does NOT become falsifiable and this item claimed it
    would:** the vendored device's own `Consolidate` handler refuses a wrong image before
    any prompt exists (`expected_image != actual_image || secret_share.index !=
    consolidate.share_index`, `frostsnap_core/src/device/restoration.rs`), so on BOTH legs
    the coordinator's comparison is a second opinion. Nor does `index != r.share_index`
    become falsifiable: `check_physical_backup` takes the index FROM the device's own claim
    (`phase.backup.share_image.index`) and then requires it on the polynomial, so every
    one-line corruption is `ShareImageIsWrong` first, with a better message. Only handing
    over the WRONG SHEET reaches that bail, and that needs a SECOND reveal in the room —
    which the stub's `sheet_read` now REFUSES, deliberately, so the rule cannot be added by
    accident. So of the two assertions commissioned here, ONE arrived, by a different
    mechanism than the one recorded.

    **THE COUNTED-CONDITION ESTIMATE OF TWELVE IS A FLOOR — THERE ARE FIFTEEN.** The three
    unnamed are the stub's `blank_flashes()` `(0..N_DEVICES)`, the stub's wire-EOF
    `saved.len() == N_DEVICES` (a SEPARATE site from the `announced_save` latch), and
    `hostcheck`'s `Destination::All => N_DEVICES`. The estimate also omitted the one place
    an EXISTING assertion loses its teeth in a way a constant cannot fix: leg 2's
    `FinishedConsolidation` makes the coordinator record the blank device as a TENTH
    shareholder, so the PASS-block roster-size check had to MOVE into the loop (one-shot on
    the lap `kg.finished` becomes `Some`, as `devices().count() == N_DEVICES` AND
    `!contains_device(blank)`) rather than have its constant changed. Writing `ALL_DEVICES`
    at PASS and calling it the roster check would have DELETED the only check that the
    keygen finalized with the right roster.

    **WITHDRAWN 2026-09-12. This paragraph read:** *"RECOMMENDATION: BUILD NOTHING HERE."*
    The payoff it pointed at is real and still stands as Tier-1 coverage on a
    blank flash with a foreign share — `a_device_ready_to_consolidate`,
    `consolidation_persists_the_share_before_it_acks` and
    `a_consolidate_under_a_different_polynomial_is_refused`. What it said deferring would
    lose was: *"no COORDINATOR-DRIVEN evidence exists for an ingest onto a device
    holding no share, so the two named assertions stay unfalsifiable in this
    configuration and the gap stays a fidelity gap rather than a correctness one."* Half of
    that is now closed — the coordinator-driven evidence exists — and the OTHER HALF WAS
    ALREADY TRUE OF THE BUILT VERSION TOO, which is the finding: building it did not make
    both named assertions falsifiable, only one. Its sequencing advice was right and was
    followed: the SHEET PLUMBING went first. `N_DEVICES` was deliberately NOT renamed to
    `KEYGEN_DEVICES` (40-plus occurrences, most inside format strings; a mechanical rename
    would have flipped the seven conditions that must stay at 9 and weakened all seven at
    once), so `N_DEVICES` now names something narrower than it reads and its own doc says
    so on line one. `EnterPhysicalBackup` at the blank device was NOT driven either: it
    would add a tenth `refused=DataErase` and fail the exact `refused_erase.len() !=
    N_DEVICES` — MEASURED, by starting leg 2 at `Phase::Erase`, and the claim given up ("a
    device holding nothing also refuses an erase") is strictly weaker than the one the nine
    already make.

    **BOTH REMAINING ADMITTED BODIES ARE NOW DRIVEN, 2026-09-12 (M10 and M11).** The
    paragraph this replaces is kept below because it is what the correction is against,
    and because one of its sentences was FALSE.

    **M10 — `CoordinatorSendBody::Cancel`, and the scope of the old claim was wrong.**
    The withdrawn text said "NONE of them is exercised by any harness: `Cancel` appears
    zero times in a green run". The qualifier saves the first clause and nothing saves
    the second: `Cancel` is constructed SIX times in the Tier-1 run, and the clearings
    already had named host tests asserting the DOWNSTREAM REFUSAL. So "send it mid-reveal
    and assert the grant is gone" was NOT the cheapest real gap; it was a re-proof, over a
    transport, of a fact already mutation-verified by name.

    **BUT THE COVERAGE IS 4 + 1 + 1, NOT FIVE OF SIX. This paragraph read "FIVE of the six
    clearings already had named host tests asserting the DOWNSTREAM REFUSAL, each with its
    own MUTATION-VERIFY note", and listed `cancel_is_handled_and_silent` as one of the five,
    until 2026-09-13.** The six clearings are `firmware/src/lib.rs`'s `Cancel` arm, in
    order: `signer.clear_tmp_data()`, `pending_name = None`, `reveal = None`,
    `record_pending = false`, `entry = None`, `check = None`.
      - **FOUR** carry a doc-comment MUTATION-VERIFY naming that exact clearing:
        `a_reveal_grant_ends_with_its_pages_and_is_revoked_by_cancel` (cancels mid-reveal
        and requires `show_backup` to answer `Err(Refused(DisplayBackup))` afterwards),
        `a_cancelled_ceremony_cannot_be_acked_as_recorded`,
        `cancel_drops_a_live_quiz_and_a_pass_acks_once`, `cancel_drops_a_half_typed_backup`.
      - **THE FIFTH, `pending_name`, had the coverage but not the RECORD — CLOSED
        2026-09-14.** `a_previewed_name_is_neither_written_nor_announced` ends with a live
        falsifiable `assert_eq!(session.pending_name(), None)` after a `Cancel`, and that
        test's MUTATION-VERIFY note named a DIFFERENT mutation ("Save or announce the name
        from the `Naming` arm") — a false record of a true fact, which is the class 9d199df
        spent 64 corrections on. **This read "STILL OPEN as of 2026-09-13" until
        2026-09-14**, because the one-sentence edit lives in `firmware/src/lib.rs`, which
        was not in the doc lane's write set that round. The note now records BOTH facts, and
        the second one is MEASURED rather than asserted: deleting `self.pending_name = None;`
        from the `Cancel` arm gives `cargo test --target aarch64-apple-darwin -p
        coldsnap_firmware` **exit 101, EXACTLY ONE named failure**,
        `a_previewed_name_is_neither_written_nor_announced`, `left: Some("cold-1") right:
        None`. One failure and not two is the load-bearing part: it confirms this test is
        the ONLY witness, so the ordinal in this list is now a fact about the tree rather
        than an inference from reading.
      - **THE SIXTH, `signer.clear_tmp_data()`, HAD no assertion anywhere on the `Cancel`
        path — CLOSED 2026-09-14, and what it guards is worse than the code said.**
        `cancel_is_handled_and_silent` — the test the withdrawn count listed as the fifth
        witness — opens a FRESH session with no half-finished state and asserts only
        `prompts.is_empty()` and `out.frames() == 0`, so **all six clearings can be deleted
        and it stays green.** It was never a witness for any of them, and its own doc claimed
        otherwise until 2026-09-14.
      - **THE PRODUCTION COMMENT THAT SAID WHY THE SIXTH MATTERS WAS MEASURABLY FALSE, and
        disproving it is what found the real property.** The `Cancel` arm read *"Dropping the
        half-finished keygen/backup state matters: keeping it makes the next legitimate
        message fail on a stale state."* Driving exactly that — `KeyGen::Begin` → `Cancel` →
        `Begin` with a fresh id → `Begin` with the SAME id, through `Session::recv`, with
        `clear_tmp_data()` DELETED — is **exit 0, all tests GREEN**. It is false
        STRUCTURALLY, not by accident: there is no read of the signer's tmp state anywhere
        that a stale entry can make FAIL. All five accesses are `insert`/`remove`/`get`, and
        in every one a HIT is the SUCCESS path — `tmp_loaded_backups.remove(&share_image)` on
        `SavePhysicalBackup2` and `.get(&share_image)` on `Consolidate` both make a stale
        entry make the message **succeed**.
      - **SO THE CLEARING FAILS OPEN.** Without it, a `SavePhysicalBackup2` that MUST be
        refused instead PERSISTS the abandoned ceremony's plaintext `ShareBackup` under
        whatever `key_name`, `purpose` and `threshold` the NEXT coordinator chooses —
        measured, the mutation's panic payload is
        `BackupSaved { key_name: Some("restored"), threshold: Some(1) }`. Attacker-chosen
        metadata over a share a human typed for a ceremony they cancelled. That is a
        confidentiality property on FLASH, not the "RAM retention" this item claimed until
        2026-09-14, and it is why the sixth was NOT the acceptable one to leave.
      - **NO VENDOR MODIFICATION WAS NEEDED, contrary to what this item said.** It read that
        asserting the effect "needs a vendor modification with a new `vendor/README.md` row",
        because `FrostSigner` exposes no read accessor for `restoration`'s or `keygen`'s tmp
        data — the accessor half is TRUE and still is. The conclusion was wrong: the
        discriminator is on the RESTORATION half and visible through `Session::recv`'s
        ordinary `Result`. `cancel_drops_a_typed_in_share_before_it_can_be_saved` drives a
        real 25-word share in through the public API, sends `Cancel`, then requires the save
        of that share image to be REFUSED. firmware 172 → **173**. Deleting the clearing gives
        exit 101, **EXACTLY ONE named failure**.
      - **AND THE ACCOUNTING IS NOW A PARTITION, which is stronger than "all six are
        covered".** Each of the other five clearings was deleted SINGLY: each fails exactly
        ONE test, and in every case the new test stayed green. So the six clearings partition
        over six witnesses with NO overlap — each names its own clearing and nothing else.

    What had no assertion anywhere in the tree was the WIRE half of the `pending_name`
    clearing (**this said "the SIXTH clearing" until 2026-09-13, on the withdrawn
    five-of-six count above; `pending_name` is the fifth, and the ordinal is the only thing
    that changes here**): its test
    (`a_previewed_name_is_neither_written_nor_announced`) stops at `pending_name() == None`
    and never runs the keygen that would have committed it, so "a cancelled preview is never
    acked as a `SetName`" was unasserted. **That distinction is exactly why the field
    clearing and the wire claim are separate rows**: the field clearing IS asserted there,
    the announcement is not. M10 closes the wire half, and it needed no stub change and no
    device change.

    THE ASSERTION IS A DIFFERENTIAL, because an absent `SetName` proves nothing on its
    own — this item already records that a LATE preview is indistinguishable from no
    preview, so silence is equally consistent with a preview that never arrived. Two
    devices get the SAME TWO FRAMES IN OPPOSITE ORDERS: `name_cancelled` gets
    preview-then-`Cancel` and must report NO name, `name_recovered` gets
    `Cancel`-then-preview and must report the byte-exact one. A delivery failure silences
    both, so the pair cannot pass vacuously. `device_names` is `N_DEVICES - 1`, checked as
    an EXACT count AFTER the two named bails so a second unexplained absence still fails.

    The send site is FORCED and it is the only safe window in the run: the `Cancel` arm's
    first statement is `signer.clear_tmp_data()`, so sent any later it breaks the ceremony
    every other assertion rests on, and the stub turns a non-`Refused` fault into
    `die(2, ..)`. Beside the `AnnounceAck`, before `begin_keygen`, the signer has nothing
    in flight and `clear_tmp_data` is a provable no-op. It is also the app's own sequence:
    `frostsnapp/lib/device_setup.dart` calls `updateNamePreview` from the name field's
    `onChanged` and `sendCancel(id)` when the sheet is popped. Upstream's own drivers
    DECIDE to send this body — `DisplayBackupProtocol::cancel()` sets `abort` and
    `is_complete()` then reports `Completion::Abort { send_cancel_to_all_devices: true }` —
    but the FRAME is emitted by `UsbSender::send_cancel{,_all}` in
    `usb_serial_manager.rs`, which needs real serial ports, so the body is built in
    `hostcheck` in the shape that function builds it and the claim is about the DEVICE's
    handling of it.

    THREE MUTATIONS RUN, each file restored and `diff`ed byte-identical: deleting
    `self.pending_name = None` gives `A CANCELLED PREVIEW WAS COMMITTED`; sending both
    devices the frames in the SAME order gives `THE M10 DIFFERENTIAL IS VACUOUS`; deleting
    the `commit_name` call gives the same VACUOUS bail, which is the right diagnosis
    because with nothing committing the control device is silent too. **Stated plainly: the
    first of those is ALSO caught by Tier-1** -- `a_previewed_name_is_neither_written_nor_announced`
    fails, 113 passed / 1 failed of the 114 lib tests that existed when the mutation was
    run (115 now; the figure is dated, not stale). M10 adds the WIRE
    consequence, not the field's mutation coverage — and the SECOND mutation is a class
    Tier-1 cannot catch at all, because it is an error in the harness.

    **M11 — the legacy `SavePhysicalBackup` (v1), and the naive assertion CANNOT FAIL.**
    `DeviceRestoration::PhysicalSaved` carries only a `ShareImage`, and
    `EnterPhysicalBackup::process_to_user_message` sets `saved = true` on any
    `PhysicalBackupSaved` for its device without checking a field — so "v1 produced
    PhysicalSaved" and "the driver completed" are byte-identical to what v2 produces. The
    v1 arm reaches v2 by RECURSING into it, so there is nothing else on the
    device-to-coordinator wire to tell them apart.

    THE ONE FIELD THAT DOES is the threshold. v1's is a non-optional `u16`, so the rebuild
    forces `threshold: Some(..)`; the v2 a real coordinator sends carries `None`, because
    `prepare_save_physical_backup` fills it only on a successful trial recovery and
    `find_valid_subset` refuses one share image against a threshold of 9. And it is
    wire-observable: `held_shares()`' saved-backup iterator reports
    `threshold: saved_backup.threshold` verbatim. `V1_THRESHOLD` is **7** so the value
    exists nowhere else in the run — at 9 a lookup that picked the real access structure's
    entry would pass. It is safe to choose because it is INERT on the device: `Consolidate`
    derives `threshold` from the coordinator's own `root_shared_key.threshold()` and never
    reads `saved_backup.threshold`, which is itself a property worth pinning and is now
    pinned by this.

    BOTH VARIANTS ARE DRIVEN BY ONE `cargo run`: v2 on the chunk-64 pass and v1 on the
    chunk-1 pass, so v2 stays coordinator-driven rather than being replaced. A new
    `Phase::SavedV1` reads the threshold back with `request_held_shares` BETWEEN the
    ingest and the consolidation, because consolidating DELETES the record it reads —
    `Phase::Reheld`'s existing read is far too late. Upstream's own
    `tell_device_to_save_physical_backup` still RUNS and its send is REWRITTEN rather than
    dropped, because that call is what inserts into `tmp_waiting_save` and without the
    entry the device's `PhysicalSaved` is refused by `recv_device_message`.

    THREE MUTATIONS RUN: skipping the downgrade so the v1 pass sends v2 gives
    `threshold=None`; dropping the `needs_consolidation` filter from the `HeldShare2`
    lookup gives `threshold=Some(9)`, which is why the constant is 7; and making the
    DEVICE refuse the v1 body gives `<id> REFUSED PhysicalBackup while this coordinator
    was in Ingest WAITING for it` in seconds.

    **THAT THIRD MUTATION FOUND A SEPARATE DEFECT AND IT IS FIXED.** A `refused=` from
    the restore device was a LOG LINE only — the run printed `REFUSED PhysicalBackup (a
    frame our own coordinator never asked for)`, which was itself wrong because the
    coordinator HAD asked for it, and then sat out the whole 95 s `BackupIngest` budget to
    die with `DEADLINE ... in state BackupIngest`. A refusal of a frame this coordinator
    is waiting on now fails immediately, scoped to the restore device and to the two
    phases that wait on a save for `Restore::erase_refusals`' reason.

    **AND `hostcheck` LEAKED ITS STUB ON EVERY FAILING RUN**, found the same way. The
    accounting here was WRONG in its first form and review caught it, so it is counted:
    `one_pass`'s `let outcome = loop` contains **ZERO** `bail!`s — it ends a failing lap
    with `break Err(..)`, 29 of them, which is exactly why those laps DID reach the
    reaping. The leak is the **15** `bail!`s of the PASS block, which sits inside
    `match outcome`'s `Ok(())` arm and therefore BEFORE that arm's own `reap`; `bail!`
    expands to `return`, so each of the 15 left the function with the child alive. (31 is
    the FILE-wide count across five functions; the withdrawn sentence said "the 31 `bail!`s
    in the PASS block sit inside `let outcome = loop`", which was two errors in one
    clause.) MEASURED: three failing runs left three stubs at PPID 1, each holding a pty
    master until its own 240 s watchdog fired, and the next run died at
    `TTYPort::pair: No such device or address` — a message pointing at the OS rather than
    at the leak. Fixed by a `Reaped(Child)` newtype with a `Drop` impl, which covers every
    present and future early return; verified by FOUR consecutive failing runs leaving
    zero orphans.

    The withdrawn paragraph, kept because the correction is against it:

    > **NOT QUITE COMPLETE, and a review caught the overclaim.** Two admitted bodies are
    > still undriven and both belong here rather than in a footnote:
    >
    >  * **`CoordinatorSendBody::Cancel`** (`firmware/src/lib.rs:954-987`). Not a stub: it
    >    calls `clear_tmp_data` and drops `pending_name`, `reveal`, `record_pending`,
    >    `entry` and `check` — six pieces of state whose entire purpose is that a
    >    ceremony the coordinator abandoned acks nothing and leaves no share-shaped screen
    >    lit. Every one of those lines carries its own justification comment, and NONE of
    >    them is exercised by any harness: `Cancel` appears zero times in a green run, and
    >    the only non-`Core` bodies `hostcheck` sends are `AnnounceAck`, `Naming(Preview)`
    >    and `DataErase`. This is now the cheapest real gap left in phase 4 — send it
    >    mid-reveal and assert the grant is gone and the ack never comes.
    >  * **`CoordinatorRestoration::SavePhysicalBackup`**, the v1 variant
    >    (`firmware/src/lib.rs:1108`). Admitted, and upstream's own alias — it rebuilds
    >    itself as a `SavePhysicalBackup2` and recurses — but only v2 is ever sent, so the
    >    recursion is untested over a real transport.

    **NAMING CLOSED 2026-09-11 too.**
    The paragraph this replaces said `SetName` is sent by the device but no harness
    ever sends `NameCommand::Preview`, so `Session::recv`'s naming arm and
    `commit_name`'s persist-before-ack ordering were unit-tested and never
    coordinator-driven. `hostcheck` now sends the preview and asserts the round trip.

    It needed NO device change — the flow was already whole. `Session::recv` handles
    `Naming(NameCommand::Preview)` by setting `pending_name` (no flash write, no
    prompt: the app previews once per typed *character*), and `Session::run`'s
    `FinalizeKeyGen` arm calls `commit_name`, which persists through `NameStore::save`
    and only THEN pushes `SetName`. The whole gap was that `hostcheck` printed
    `ignoring NeedName` 27 times a run and never answered. It is 0 now.

    **The preview must ride with the `AnnounceAck`, and that is forced rather than
    chosen:** `commit_name` fires from the `FinalizeKeyGen` prompt, i.e. DURING keygen,
    so a preview sent after the signature — where the M7 phases above live — arrives
    too late to be committed. A mutation that sends the identical frame post-keygen
    produces ZERO `SetName` lines: a late preview is indistinguishable from no preview.

    The name is **14 chars and 56 bytes at once**, which is the widest input the wire
    admits and is the point of choosing it: `DeviceName` is `FixedString<14>` counted
    in CHARS (`fixed_string.rs:31-40`), so 14 chars can be 56 UTF-8 bytes, and 56 is
    exactly `DEVICE_NAME_MAX_BYTES` (`4 * DEVICE_NAME_MAX_LENGTH`) — the byte bound
    re-applied at the flash boundary precisely because `FixedString`'s own `Decode`
    truncates on chars and would otherwise let a 56-byte name through a 14-byte
    expectation. Constructed with `DeviceName::new`, never `truncate`, so an over-long
    name is a harness failure rather than a silently cut one.

    Asserted: all nine devices report it, the round trip is byte-exact, and a `SetName`
    must have been preceded by a `NeedName` — otherwise it is an announce-time echo of
    a name already on flash and not evidence that this run committed one.

    **HONEST LIMIT: this proves persist-before-ack, NOT durability.** The stub restarts
    immediately after *announcing* and before keygen, so there is no restart after the
    name is persisted; nothing here shows the name survives a power cycle. And the
    limit already recorded at `commit_name` still stands: the shipped Flutter app will
    not offer to name this device whatever the device side does, because cold-snap's
    digest can never be `UpToDate`.

    **ALSO CLOSED 2026-09-11 — `erase_device` is now proven never to complete.**
    Upstream's `erase_device::EraseDevice` reaches `Completion::Success` only on
    `CommsMisc::EraseConfirmed`, which this device deliberately never sends
    (`Session::recv` returns `Err(Fault::Refused(Refusal::DataErase))`). Nothing
    asserted that. It is now driven through the same seam and BOTH halves are required
    over a 1 s grace window: `is_complete()` stays `None`, AND the device reports
    `refused=DataErase` on the wire. Either alone is ambiguous — silence is also what a
    dead device looks like.

    Distinct from the forged raw `DataErase` this harness has sent since M6: that one is
    a hand-rolled frame, this drives upstream's own driver, and the claim is that its
    completion path is unreachable here. The refusals are counted PER PHASE rather than
    read off the existing `refused_erase` set, which is already full from the forged
    frame and so could not have failed.

    THREE mutations SURVIVED GREEN here and are recorded rather than buried (**this
    paragraph said "two" until a review caught it** — the third is the one most worth
    surfacing, because it says an assertion's own guard is currently redundant):

     1. a 15-char name pushed through `DeviceName::truncate` instead of `new` — upstream
        cuts it, the device round-trips the cut value exactly, and only the INPUT bound
        catches it, which is why the construction uses `new`;
     2. omitting `connected()` on `EraseDevice` — which unlike `EnterPhysicalBackup`'s
        trap 4 does not override the empty default and whose `poll` sends
        unconditionally, so the call is decoration there and the comment says so;
     3. dropping the `phase == Phase::Erase` half of the refusal guard — green, because
        `Restore` does not exist until a signature does, which is already past the
        forged `DataErase`. Kept as belt and labelled as such at the field.

13. **The identity record's false-refusal rate on a *converted* Mk4, and it is the
    one item here that a single bench read retires for free.** `identity.rs` refuses
    rather than erases when it finds a record whose commit word carries
    `MAGIC_DOMAIN` but an unrecognised version, so that a downgraded firmware cannot
    destroy a newer format's key. The cost is that residual bytes already in
    `FLASH_FS` — a converted unit's `FLASH_FS` held MicroPython LFS2, not erased
    flash — can collide with the 4-byte domain and make a *virgin* device refuse to
    generate, which is unrecoverable. The collision probability is **2⁻³²**, about
    2.3e-6 across 10,000 units, against 2⁻⁶⁴ if the arm were dropped. That trade is
    deliberate and is the right way round: a one-in-400,000-fleet dead unit beats a
    downgrade that destroys wallets, and the arm had to ship in the *first* firmware
    or never. **Read one real converted unit's `FLASH_FS[0x2c..0x30]` on the bench**
    and the estimate becomes a fact. (**This said `[0x28..0x2c]` until 2026-09-10, and
    that is the wrong four bytes** — a bench instruction that would have measured the
    wrong thing. The commit *doubleword* is at offset `0x28`, 8 bytes, and
    `identity.rs:220` compares `(commit_word >> 32) as u32` against `MAGIC_DOMAIN`, so
    the domain lives in its **high** half: `0x2c..0x30` little-endian.) Nothing else in §9 is this cheap to close.

14. **CLOSED 2026-08-25 — the identity hold now says why.** `ui::identity_fault`
    draws the fault discriminator and the word *refusing* (never *failed*, which
    would invite a retry that cannot help), and `boot()` draws it on the way into the
    hold — one frame, never inside the loop, so a wedged panel cannot turn a hold
    into a hang. The panel open and the `show` are both best-effort: neither can
    change the outcome, and a `?` there would convert a display fault into a reset
    loop. The hold stays **above** USB bring-up, so the security property is
    unchanged. Pinned by `identity_fault_names_the_state_and_refuses_rather_than_inviting_a_retry`.
    The original text follows, for the record. A damaged
    or ambiguous record holds *dark* — `firmware/src/main.rs` step 8b spins above USB
    bring-up, so the device never enumerates and there is no channel on which to say
    why. That is the correct fail-closed direction (a device that cannot prove which
    device it is must not talk to a coordinator) but it is indistinguishable from dead
    silicon at a bench. It is only resolvable by phase-5 UI, and the fix is **not** to
    bring USB up early to obtain a channel — that trades the security property for a
    diagnostic. First screen phase 5 should draw.

24. **CLOSED 2026-09-03 — the three absent features, and one of them was a blind
    signer I had called fail-closed.**

    *Durable share storage.* `firmware/src/store.rs` persists the keygen triple as one
    512-byte fixed-shape record in a **vendored `AbSlot`** at `memmap::FS_SHARE_OFFSET` —
    no new store and no `NorFlashLog` patch, because the vendored A/B slot works on
    8-byte-programmed flash where the log does not. The checksum occupies the final
    doubleword, so a tear anywhere leaves the tail at `0xff` and `load` answers `Damaged`
    rather than a half-share — the same commit-word-last property `identity.rs` uses.
    Verified by mutation: tampering one body byte is caught by the checksum, so reload
    genuinely reads flash rather than replaying a constant (the stability-vs-durability
    trap that bit the identity test).

    *Persist-before-ack, enforced not merely ordered.* `persist_staged` sits at the TOP of
    `Session::run`, above the loop that pushes to the outbox, so no coordinator-bound
    message can precede it. I ran both mutations myself — deleting the call, and moving it
    below the drain — and each fails
    `a_share_that_cannot_be_written_is_never_acked`. The property being defended: an ack
    this device cannot back leaves a threshold silently short, discovered only when
    someone tries to spend.

    *The page cursor — and my error.* I reported page 0 of a bitcoin transaction as
    "unapprovable, correctly fail-closed" because no confirm digit is rendered on it.
    **That was wrong.** `confirming(confirm)` attached the digit to the whole page SET
    while `render(0, ...)` drew a page that never printed it, and `answer` still compared
    a keypress against that drawn digit — so a **1-in-5 blind guess signed a transaction
    whose fee and recipients had never been displayed.** Unapprovable by an honest user
    reading the screen; approvable by luck. The cursor is now an *argument* rather than
    state (so `confirm` re-renders the exact page the human read), the digit lives in the
    same `is_last` branch the consent check tests, and the footer reads `pg 4/67 (9)next`.
    Pinned by `only_the_last_page_of_a_transaction_advertises_the_key_that_signs`,
    `the_consent_gate_uses_the_page_it_was_given_and_demands_the_last_one` and
    `the_page_0_funnel_reports_a_paged_transaction_as_unanswerable`.

    *`SetName`.* Sent, and committed at `FinalizeKeyGen`; consent belongs at the commit,
    not the per-keystroke preview. The name is NOT a core `Mutation`, so it gets its own
    record in the share store. The false comment claiming `NeedName` registers a device is
    gone. **Still blocked upstream:** the shipped Flutter row renders the name field only
    when the device digest equals the app's bundled digest
    (`wallet_create.dart:662-704`), which cold-snap's never will. **This sentence ended
    "so this is exercised by `hostcheck`, not by the released app" until 2026-09-10, and
    that was wrong in the one place it mattered:** `hostcheck` never sends a
    `NameCommand`, and `SetName`/`key_name` appear nowhere in `hostcheck/src/main.rs`.
    The device side is exercised by unit tests in `firmware/src/lib.rs` only. So the
    naming flow is driven by *neither* the released app nor the harness — it is the
    smallest of the coordinator-driven gaps and `update_name_preview`
    (`frostsnap_coordinator/src/usb_serial_manager.rs:770`) is the entry point that
    would close it.

    A process note worth keeping: a temporary probe an agent left behind
    (`/// TEMPORARY VERIFICATION PROBE — remove.`) had never executed because the file did
    not compile, and it failed on first run against a record it was over-reaching past by
    8 bytes. The correctly-scoped test beside it passes. **A test that has never run is
    not evidence**, and a green report from an agent whose gates never compiled the file
    is worth nothing — check the counts, not the claim.

22. **184 `cfg(target_arch = "arm")` blocks were invisible to every LINT in this project.
    Now they are linted; they are still never executed.** Re-measured 2026-09-12:
    usb 88, flash 22, `firmware/src/main.rs` 18, panic 13, callgate 11, keypad 8,
    display 8, rng 6, `firmware/src/lib.rs` 4, `firmware/src/entry.rs` 4,
    `hal/src/lib.rs` 1, `ui.rs` 1 = **184**, from
    `rg -c 'cfg\(target_arch = "arm"\)' hal/src/*.rs firmware/src/*.rs`. Every test,
    clippy and rustdoc command here runs `--target aarch64-apple-darwin`, so none of that
    code was ever compiled under a lint.

    **This heading and its breakdown disagreed with each other twice, which is the
    defect this whole audit exists to catch.** It read 152 until 2026-09-08, **169
    until 2026-09-10** and **181 until 2026-09-12**, while the body carried a *2026-09-02*
    per-file breakdown (keypad 8, display 8, usb 85, flash 20, panic 13, rng 6, callgate 5,
    `main.rs` 7 = 152) that summed to neither. The trail further down the item recorded
    the 181 re-count on 2026-09-10 and the heading was not brought with it. Both the
    heading and the breakdown above are now the same measurement, taken together, and
    the sum is written out so the next reader can check it in one line. **What moved
    between 181 and 184 was `firmware/src/main.rs` alone, 15 → 18** (the 15 was already
    stale at 181 — it was 17 on 2026-09-10 and every OTHER per-file figure in that
    breakdown reproduced exactly, which is what made a wrong total read as freshly
    measured; the further +1 is a comment added by a63eaa7). This is the same shape as
    README's `268 total` headline that this document records as its canonical failure:
    a breakdown that checks, under a total that does not.

    **The original wording of this item overstated the hole, and correcting it is worth
    more than repeating it.** `cargo build --release` does compile those blocks, and it
    is not silent: it enforces every *rustc*-level lint in them, including the
    deny-by-default ones. A probe planting `let _ = [0u8; 4][9];` inside `keypad.rs`
    `scan_once`'s `cfg`-arm block failed that gate outright — exit 101,
    `error: this operation will panic at runtime`, `#[deny(unconditional_panic)] on by
    default` — while host tests stayed at 261 and host clippy at 0. So rustc was already
    looking. The hole was **clippy and rustdoc only**, and that is the whole of what the
    two new gate lines close.

    This was found the expensive way. `hal/src/keypad.rs` shuffles its row scan order per
    scan from `Entropy` — the Tempest defence, so EM emissions cannot reveal which key
    was pressed. `shuffle_rows` is thoroughly host-tested as a function, but its only
    call site is inside a `cfg`-arm block, and replacing `let order = shuffle_rows(rng)`
    with a fixed `[0, 1, 2, 3]` left **all 237 hal tests green and the ARM release build
    clean**. A security property was preserved by review alone.

    Closed for the keypad by `the_scan_order_is_actually_shuffled_at_the_only_call_site`,
    which reads its own source with `include_str!` and asserts the call site textually
    (both the removal AND a hardcoded order alongside a still-present call are caught —
    verified by mutation). A fake GPIO was rejected as the alternative: a test double
    more permissive than the hardware is worse than no test, which is the same reason
    `fake-flash` is off by default.

    **WHAT IS NOW ENFORCED for all of them**, added 2026-09-08 and listed in README's
    "Test" section: `cargo clippy --release --target thumbv7em-none-eabihf -p coldsnap_hal
    -p coldsnap_firmware` (0 hits in `hal/src`/`firmware/src`) and the same
    `--target thumbv7em-none-eabihf` for `cargo doc`. It works with no tricks — no
    `--lib`, no feature juggling, no allocator problem, because clippy stops at
    `--emit=metadata` and nothing reaches the linker. **`--all-targets` must NOT be in
    the gate**: dev-dependencies (proptest → getrandom) have no `thumbv7em` support and
    it fails with 298 errors. Cost, measured not estimated: 8 s cold, 2.4 s incremental,
    0.22 s warm — the cheapest gate here.

    **QUALIFICATION on "0 warnings", added 2026-09-12 because four lanes reported it
    differently.** The claim that holds is **0 hits in `hal/src` and `firmware/src`** — which
    is why both device clippy lines above are written with `grep -cE "hal/src|firmware/src"`
    rather than a bare exit code. Clippy ALSO reports warnings inside
    `vendor/frostsnap`, and they are pre-existing: **MEASURED 2026-09-12 on
    `cargo clippy --target aarch64-apple-darwin -p coldsnap_hal --features
    fake-flash,test-seam --all-targets`, exactly 15** — `frostsnap_comms` 11,
    `frost_backup` 3, `frostsnap_macros` 1, every one of them
    `uninlined_format_args`, and `grep -cE 'hal/src|firmware/src'` over that log is **0**.
    (Beware counting the log: a bare `grep -c '^warning'` gives 18, because each crate's
    "generated N warnings" SUMMARY line also starts with `warning`. Three of the 18 are
    summaries.) Lanes reporting 18 on the device profiles were counting the same way. They
    are vendored, and per PUNT
    EVERYTHING UPSTREAM they stay. "0 warnings everywhere" is true of `cargo build
    --release` and is NOT true of clippy over vendored code; say which.

    **AND THERE IS NO `-D warnings` ANYWHERE.** `.cargo/config.toml` sets only
    `-C target-cpu=cortex-m4` and `-C link-arg=-Tfirmware/link.x`, and the only crate-level
    denies are `#![deny(unsafe_op_in_unsafe_fn)]`. So `cargo build --release` exits **0**
    with an `unused_mut` or `unused_imports` warning. Two mutations in this round were
    described in comments as "already a build failure" on that basis; **they are not** —
    exit 0 with a warning is a 0-warnings-gate failure read by a HUMAN. Any pin whose sole
    claimed defence is a warning is undefended against a CI that checks exit codes. (Both of
    those two mutations turned out to be caught by an exact-text pin anyway, which is the
    other half of the correction: the lane understated its own coverage.)

    **SEVEN WAYS A SOURCE PIN GOES SOFT — two found 2026-09-12, five more on 2026-09-13,
    every one of the five with a mutation that was GREEN on the tree that already carried
    the "fix". Read them before writing another pin.**
      - **`contains` on a pattern FRAGMENT tests that a pattern is PRESENT, never that it is
        ALONE.** `the_consent_gate_uses_the_page_it_was_given_and_demands_the_last_one`
        pinned `confirm_at`'s accepting arm with a bare
        `arms.contains("Ok(Shown::Page { last: true }) => {}")`. Widening the arm by
        ALTERNATION — `Ok(Shown::Info) | Ok(Shown::Page { last: true }) => {}` — leaves the
        needle intact, and that mutation ran **GREEN on all 120 lib tests** while the pin
        that exists to forbid exactly this did not fire. It was writable before the
        address-verification work and would have passed then too, so this is a PRE-EXISTING
        fail-open in the pin, not a regression. Fixed on 2026-09-12 by anchoring the needle
        to the WHOLE LINE (leading newline + indent), so a `| `-prefixed form no longer
        matches; re-verified in BOTH directions, including that the pin's own originally
        documented mutation still fails.

        **THAT FIX WAS ITSELF INCOMPLETE, and this is the SECOND time a repair for this
        class has shipped containing a fresh instance of it.** Anchoring the needle closes
        widening-by-ALTERNATION and leaves **widening-by-ADDED-ARM wide open.** MEASURED
        2026-09-13 against the SHIPPED fix, not argued from reading: inserting a whole new
        line `Ok(Shown::Page { last: false }) => {}` **above** the pinned arm left **all 172
        firmware tests GREEN, exit 0, with no `unreachable_patterns` warning**. A non-last
        page then authorises while the assertion's own message says "only the last page may
        authorise". **So the rule to record is not "anchor the needle". It is: AN
        EXCLUSIVITY CLAIM NEEDS A BOUND ON BOTH SIDES OF THE REGION IT IS ABOUT.** Closed
        2026-09-13 by holding the arm block BY VALUE —
        `assert_eq!(arms.lines().collect::<Vec<_>>(), [the three exact arm lines])`, bounded
        LEFT by a `split_once` on the `) {` that opens the block and RIGHT by a `split_once`
        on the `}` that closes it. **The "right-bounding also kills a self-match hazard"
        clause that stood here until 2026-09-13 was FALSE and is withdrawn:** `arms` came
        from `call`, which came from `body`, and BOTH of those were `split(..).nth(1)` — a
        MIDDLE segment, bounded on the right by the next delimiter — so at the base commit
        `body` spanned lines 1277-4616 and `call` spanned 1313-2570, nowhere near the test
        module at 4644. A vanished `match prompt {` could only have widened `arms` to the
        rest of `call`, never to EOF, and the needle literal in this module was never inside
        it (measured: 1 occurrence in `call`, and it is the production one). What IS true and
        is the reason the code uses `split_once`: `split(..).next()` is INFALLIBLE, so a
        vanished delimiter widens the region SILENTLY instead of failing.

        `hal/src/keypad.rs`'s `the_scan_order_is_actually_shuffled_at_the_only_call_site`
        **was called "the same shape" here until 2026-09-13, and is not.** That dismissal
        compared it to a `contains` on a pattern fragment; the consent-gate pin is now a
        right-bounded value comparison, so the analogy no longer says anything. The keypad
        pin stands on its own recorded grounds: its needles are span-scoped to the `pub fn
        scan_once` body (the next `\n    pub fn ` is `read_key`), its "only call site" is
        true, and its residual hole is an ENUMERATION ceiling — three literal spellings, so
        `let _ = shuffle_rows(rng); let order = [1u8, 0, 3, 2];` survives it, because a
        fixed order is fixed whether or not it is sorted. That ceiling was already recorded
        at `AUDIT-2026-09-10.md:264` over a block inside `cfg(target_arch = "arm")` that no
        gate compiles, and as of 2026-09-13 it is recorded IN THE SOURCE too, beside the
        enumeration it limits. The test was NOT renamed and its needles were NOT changed:
        the name is cited eight times across this file and that audit, which is 5c1232b's
        orphan trap eight times over.
      - **`production_source()` splits `include_str!("main.rs")` on the FIRST `#[cfg(test)]`,
        so DOC COMMENTS above that point are production source as far as every counted pin
        is concerned.** Writing `glass.take()` longhand in a doc comment fails
        `a_parked_prompt_is_serviced_once_per_iteration_and_never_in_a_loop` with
        `left: 2, right: 1` on an otherwise-green tree. The code says so in place now.
      - **THE SUPERSTRING CLASS, found 2026-09-13. A `contains` needle whose FIRST or LAST
        character is a RENDERED NUMBER is satisfied by a SUPERSTRING**, so the value the
        screen exists to display can be wrong with the pin green. EIGHT sites in
        `hal/src/ui.rs`, all closed 2026-09-13: one `push_str("1")` before the threshold in
        `keygen_check` defeated the quorum pin AND the hostile-threshold `contains` at once
        (`"165535-of-65535"` contains both at offset 1), and one `push_u64(n * 10)` defeated
        both fail-counter pins. **The two QUIZ-count pins were a DIFFERENT mutation and this
        bullet conflated them into that one until 2026-09-13:** `backup_quiz_passed` builds
        its own `Buf` and never calls `keygen_check`, so they needed their own
        `push_str("1")` (`"18 of 25 words"` contains `"8 of 25 words"` at offset 1;
        `"125 of 25 words"` contains `"25 of 25 words"` at offset 1) plus a gated variant for
        the all-25 half. The remedy is
        that file's own dominant idiom, `assert_eq!(row_text(&f, ROW), ..)`, because the
        drawing row is a literal in the production function. **THE CLASS IS NARROW and the
        contrast is what proves it, so do not read this as a ban on `contains`:**
        `format!("pg {}/{}", ..)` is anchored on BOTH sides and `"pg 12/67"` does not contain
        `"pg 2/67"`; same for `"word 3 of 25"`, `"03: abo_"` and every
        `Press (N)` needle, where the digit sits inside its own parentheses. **But the
        discriminator is NOT "anchored on both sides", and this bullet listed `"share #3"` as
        safe on that reading until 2026-09-13. It is not safe:** its LAST character is a
        rendered number, so `"share #30"` contains it — MEASURED, appending a digit to
        `standby`'s rendered index left all 267 hal lib tests GREEN while the screen named a
        share the device does not hold. That is the EIGHTH site, closed the same day with
        `assert_eq!(row_text(&f, 4), "share #3", ..)`. The test to apply is the heading's
        own: neither the FIRST nor the LAST character of the needle may be a rendered
        number. **And one
        prescribed fix for this class did NOT close it, measured:** widening
        `contains("65535-of-6")` to `contains("65535-of-65535")` closes TRUNCATION and not
        the superstring, because `"165535-of-65535"` still contains it at offset 1. That
        needle's claim is held by NAME in a different test, and the source comment says so.
      - **A HEADER PINNED WHERE A BEHAVIOUR WAS CLAIMED.** `hal/src/callgate.rs`'s
        `no_counted_or_destructive_selector_is_reachable_from_this_module` pinned
        `contains("impl Drop for PinAttempt")` — an impl HEADER — while the comment above it
        claimed the BEHAVIOUR, "the PIN buffer must still be wiped on the way out". MEASURED
        2026-09-13: with that `Drop` body emptied to `fn drop(&mut self) {}` — the
        `write_volatile` deleted, a 280-byte buffer holding a PIN, its HMAC and 72 bytes of
        pairing secret left in SRAM — the hal gate was **exit 0, 290 passed**. There is no
        runtime witness and there cannot be one: observing a dropped local's bytes is UB.
        The needle now BOUNDS the destructor on BOTH sides — `split_once` on the header,
        `split_once` on the impl's closing brace — and requires the `write_volatile`
        statement to be INSIDE it, and it carries a message, which it did not before (it was
        the only assertion in that test with none). **The statement alone is not enough, and
        neither is the statement CONJOINED with the header, MEASURED 2026-09-13:**
        `&mut self.raw` compiles in ANY `&mut self` method of `PinAttempt` and
        `PinAttempt::as_mut_ptr` takes the identical expression, so moving the wipe there
        left an empty destructor, BOTH needles satisfied and the hal gate at **exit 0, 290
        passed** — while the same mutation is exit 101 by name against the bounded form.
        Residual, recorded rather than closed: a NEW `&mut self` method declared below that
        impl could hold the statement instead. **SEVERITY,
        stated so nobody writes this up as closing a live leak:** nothing outside
        `callgate.rs` constructs a `PinAttempt` today (PIN is PUNTED), so this is an
        unpinned FORWARD guard, not a live leak. The same shape held the anti-phishing
        screen's LEARN-vs-CHECK discrimination as two PRESENCE checks on two frames:
        `assert_ne!(PIN_WORDS_LEARN, PIN_WORDS_CHECK)` proves the consts differ and nothing
        proved the screen PICKS, so drawing BOTH unconditionally on rows 0 and 1 — a screen
        saying "Write these down" AND "Recognize these?" at once — left both needles green.
        Now two row-0 equalities, each with its own gated mutation. The `assert_ne!` was
        KEPT and is not redundant: were the consts equal, both equalities would still pass.
      - **AN ASSERTION THAT FAILS OPEN IS WORSE THAN NONE, and this one named the exact
        overrun it could not see.** `hal/src/ui.rs`'s `text_never_panics_on_hostile_input`
        carried `assert!(Buf::<16>::new().push_str(s).as_str().len() <= 16, "Buf overran on
        {s:?}")`. `Buf::push` writes through a checked `get_mut` on a `[u8; N]`, so `len` can
        never exceed N, and `as_str()` is `buf.get(..len).and_then(from_utf8).unwrap_or("")`
        — so the exact overrun the message named produced an EMPTY string, length 0, and the
        assertion read that as SUCCESS. MEASURED 2026-09-13: with `push_str` silently
        DROPPING every non-ASCII-printable character, the hal gate was **exit 0, 290
        passed**. Replaced by the char-count identity `push_str`'s own doc states; the same
        mutation is now exit 101 with one named failure, and that test is the only one of the
        290 that sees it.
      - **`str::split(..).next()` IS INFALLIBLE, so `.expect(..)` on it is VACUOUS** — and
        worse, the message names a condition the expect cannot detect. Three such messages
        in `firmware/src/lib.rs`, all replaced 2026-09-13 with `split_once`, whose `None` IS
        reachable and whose messages now claim only that. `hal/src/callgate.rs`'s
        `.expect("split always yields at least one part")` is the MODEL and is deliberately
        left: its message is honest about what it can see, and a real guard follows on the
        next lines. Note what the change does NOT buy, stated in the source rather than
        dressed up: re-spelling the `#[cfg(test)]` cut literal is red on BOTH forms (8 named
        tests on the new one, 5 on the old), so `split_once` buys message honesty, not
        detection. What actually detects a broken cut is the named tests either side of it.
      - **A UNIVERSALLY QUANTIFIED CLAIM NEEDS A QUANTIFIED MUTATION, or the pin is credited
        to the wrong assertion.** A whole-row `assert_eq!` on the ONE digit a test happens to
        render does not hold a claim about EVERY digit. MEASURED 2026-09-13 in
        `hal/src/ui.rs`'s `keygen_check_renders_the_code_and_the_compare_instruction`: a
        uniform `frame.text(1, FOOTER_ROW, ..)` fires that single-digit equality, but
        shifting the legend **only for the four `CONFIRM_CHARSET` digits that case never
        renders** left all 290 hal tests GREEN under the loop's old
        `contains(press_legend) + ends_with("x=no")` pair. The anti-MITM consent legend is
        off-position on 4 of 5 possible digits with the suite green. The loop now carries the
        same equality. **And the uniform mutation is caught by the WRONG assertion**, so
        recording it as the loop's evidence would have been the wrong-reason pairing 7f168fa
        exists to prevent.

    **THE SOURCE-PIN POPULATION, RECONCILED 2026-09-13 — and the reconciliation IS the
    finding, because the figure that has been quoted is not a count of source pins.**
    Measured at `5c1232b`: contains-based SOURCE pins are `firmware/src/main.rs` **57** +
    `hal/src/ui.rs` **0** + `firmware/src/lib.rs` **2** + `hal/src/callgate.rs` **4** +
    `hal/src/keypad.rs` **2** = **65**, NOT 106. The **182** that has been quoted is
    `rg -c 'contains('` over those five files — a LINE count, not a pin count; the
    OCCURRENCE count is **199**. **`hal/src/ui.rs` holds ZERO source pins**: it contains no
    `include_str!` and no `production_source()`, so it is not one of the five self-reading
    harnesses (`hal/src/callgate.rs`, `hal/src/keypad.rs`, `firmware/src/lib.rs` **twice**,
    `firmware/src/main.rs`). **37 of the quoted 106 therefore never existed** — the premise
    was wrong IN KIND, not off by a little — and all 94 `contains` calls over 82 lines in
    that file are framebuffer readbacks, `Range`/`RangeInclusive` bounds or `[u8]`/`Vec`
    membership. The analogous defect IS real there, in the framebuffer medium rather than the
    source medium: that is the superstring class above, closed as six edit patterns.
    (Snapshot, per this section's own rule: the 2026-09-13 edits moved the raw greps to
    **180** lines / **196** occurrences over the same five files, and `main.rs`'s
    `.matches(` from 29 to 33, because eleven `contains` pins became `assert_eq!` forms.)

    **AND THE LOAD-BEARING CONSEQUENCE, which is worth more than the tidying.** Commit
    9d199df's *"all 30 counted source-pin substrings over `production_source()` are IDENTICAL
    to HEAD"* refers to the **29** `.matches(..).count()` needles at that commit — 2
    `production_source().matches(` + 27 `src.matches(` — plus, most likely, the harness's own
    `split("#[cfg(test)]")` literal. **That is a plausible reconstruction and not a verified
    identity; it is marked as such here rather than repaired, because the 30 cannot be
    recovered from the commit.**
    **THE MARKER STAYS, AND 2026-09-16 GAVE IT A HARDER REASON THAN "not recovered": the 30
    is DEGENERATE — TWO different readings produce it, so counting cannot pick, and the
    reconstruction above is not the unique candidate it reads as.** The enumeration nobody
    had done is the enumeration across ALL FIVE source-pin harnesses at that commit, not just
    `main.rs`. Measured with `git show 9d199df:<file> | grep -c '\.matches('`: `main.rs`
    **29**, `firmware/src/lib.rs` **1**, `hal/src/callgate.rs` **3**, `hal/src/keypad.rs`
    **0** — **33** in total, so the all-harness reading is not 30 either. And
    `production_source()` is defined ONLY in `main.rs` (`git show 9d199df:<file> | grep -c
    production_source` returns 0 for the other four), so the STRICT reading of "over
    `production_source()`" is **29** and cannot be made 30 without adding something. The two
    readings that do reach 30 are: **(A)** `main.rs`'s 29 plus `production_source()`'s own
    `split("#[cfg(test)]")` delimiter — the reconstruction above, which has to count a
    string that is *split on* rather than counted; and **(B)** `main.rs`'s 29 plus
    `firmware/src/lib.rs`'s single `production.matches("DeviceSendBody::Debug {").count()`,
    i.e. every genuinely counted needle in the `coldsnap_firmware` crate — and that harness
    builds its `production` with the byte-identical `src.split("#[cfg(test)]").next()` idiom,
    so it IS a `production_source` over `lib.rs` in everything but the function name.
    **(B) needs no reclassification and (A) does, but the commit says neither, so neither is
    adopted** — that is the whole point of leaving the marker.
    **WHAT IS NOW VERIFIED IS THE SUBSTANCE, WHICH MATTERS MORE THAN THE CARDINAL: the claim
    is TRUE under every one of those readings.** Every `.matches(..)` needle AND its expected
    count is byte-identical between `9d199df` and its PARENT `d5628df` across all five
    harnesses (29 / 1 / 3 / 0 both sides, needle-and-count lists diffed empty), and `#[test]`
    in `main.rs` is **38** at both — which is the second figure that sentence asserts, and it
    checks. **"HEAD" in that message means the PRE-COMMIT tree, not today's:** against today's
    `2956a39` the same comparison DIFFERS (`main.rs` is 36 `.matches(` and `keypad.rs` is 1),
    because seven needles were added after that commit — which is a trajectory, not a
    falsification, and reading "HEAD" as today's tip is the error that would make a true
    sentence look false.
    What IS verified is that the counted population and the 57
    `contains` pins are **DISJOINT**. So that verification pass covered exactly the half that
    already expresses exclusivity CORRECTLY, and **not one** of the 57 that does not.
    **25 of the 57 are now closed, with 24 measured green mutations** — twelve on 2026-09-13
    and thirteen more on 2026-09-14; this sentence read "Twelve … with eleven mutations" until
    the second pass. The 2026-09-13 twelve came with **eleven mutations that were GREEN on the
    tree before them** — including moving `let _ = clear_counter(Counter::Panic);` below its
    guard's closing brace, which leaves the header needle, the count of 1 and all 172
    firmware tests green while turning a BOUNDED reset loop into an unbounded one: at RDP=2
    with DFU hardware-impossible and no PIN, a permanent brick.

    **THE TWELFTH PIN AND THE ELEVENTH GREEN MUTATION WERE FOUND BY THE REVIEW ROUND ITSELF,
    AFTER the pass above had already anchored its sibling — which is the finding.**
    `every_exit_from_the_entry_takes_the_words_off_the_glass` anchored the entry's
    `Err(_fault) => refuse(..)` arm and the reveal's `RevealStep::Park` arm, and left
    `EntryStep::Park => glass = Some(Flow::Entry),` on a BARE `contains` beside a
    `matches("glass = Some(Flow::Entry)").count() == 2`. MEASURED 2026-09-13: commenting the
    live arm out and putting `EntryStep::Park => {}` under it is **exit 0, all 172 firmware
    tests GREEN** — the needle matches from inside the `// ` and the count stays at 2 because
    the commented copy is still text. A `Wait` mid-entry would then re-park NOTHING: the flow
    cursor is dropped while the typed prefix stays lit, i.e. the reveal's own leak in the
    entry's clothing, in the very test whose name is about taking words off the glass. Both
    needles are now anchored with their leading `\n` and their MEASURED indents (24 and 28),
    and the same mutation is **exit 101, one named failure**. THE LESSON, and it is why the
    green count moved after the lane closed: a pass that anchors N of N+1 sibling needles
    leaves the unanchored one looking reviewed. The three-siblings-in-one-test shape is what
    hid it. In the same pass the
    `production_source()` harness doc's "Three tests read this" was corrected to **13 call
    sites across 12 tests** — and **do NOT quote a raw `rg -c 'production_source()'` total
    for it**: the grep also matches the definition and every comment that names the helper,
    so the figure moves whenever anyone writes prose about it. Two drafts of that very
    sentence falsified themselves by adding a matching line.

    **THIRTEEN MORE CLOSED 2026-09-14, AND THE HIT RATE HELD AT 100%: every mutation aimed at
    a bare needle inside `boot` was GREEN before its anchor.** `boot` is
    `#[cfg(target_arch = "arm")]`, so no host gate compiles a line of it and a source pin is
    the only witness its consent, leak and brick properties have. Running total: **25 of the 57
    closed, with 24 measured green mutations.** The worst is a TOTAL CONSENT-GATE BYPASS:
    comment out `match ask(keypad.as_mut(), &mut entropy, consent, last) {`, add
    `let _ = (consent, last);` and `match Answer::Yes {` under it, and every parked prompt
    auto-confirms with no key pressed — **exit 0, 172/172, and `cargo build --release` exit 0
    with ZERO warnings**, the neighbouring `ask(`==2 count unmoved. Beside it, all green with
    zero ARM warnings: `page.saturating_sub(1)` in the `confirm_at` call (a signature on a page
    the human never reached), `let verdict = Answer::Next;` (every backup flow advances
    untouched), `EntryStep::Key(_key) => match Ok(Typed::Unchanged)` (requirement 5's leak on
    keypress one), `grants(&prompt).and(None)`, and `(Consent::Quiz, flow_consent(flow).1)`.
    One further run defeated SIX pins at once.

    **A NEW MUTATION SHAPE, and it is why anchoring the call line is not enough:** insert
    `let page = page.saturating_add(1);` and DELETE NOTHING. The pinned line is untouched, the
    cursor is rebound above it, `show_backup_page(`==2 / `glass =`==13 /
    `session.show_backup(`==1 all hold, and no `unused_variables` fires. A statement pinned
    outside its own block says nothing about what runs between the arm header that binds `page`
    and the call that consumes it, so the remedy is to pin the WHOLE arm at measured indents.

    **AND THE CORRECTION THAT INVALIDATED EIGHT WRITTEN "SAFE" VERDICTS: A
    `matches(..).count()` BESIDE A BARE `contains` DOES NOT PROTECT IT.** A `// `-commented
    copy of the line is STILL TEXT, so it supplies the occurrence the count demands. A count of
    1 is satisfied by a dead copy; a count of 2 reads 2 with the live call gone. **Counts stop
    an EXTRA LIVE site; they say nothing about the pinned one having been commented out.**
    Proven at four sites. Nine of that pass's thirteen anchors were found only after that
    reasoning collapsed — and it is the same shape as this register's own withdrawn belief that
    a count and a needle are independent legs.

    **THE `/* */` CEILING IS CLOSED — once, for all 86 pins in the file — and THIS REGISTER
    NEVER RECORDED IT.** A block comment that preserves indentation leaves a depth anchor's
    bytes (leading `\n`, indent, line, trailing `\n`) verbatim, so it defeats every depth
    anchor in the tree; MEASURED against the already-anchored `EntryStep::Park` arm at
    172/172 GREEN. A source comment shipped on 2026-09-14 asserted that this ceiling "is
    recorded once, in PLAN.md" — **it was not.**
    `grep -rn 'block comment\|/\* \*/\|comment-out' PLAN.md README.md DECISIONS.md
    AUDIT-2026-09-10.md` returned NOTHING: a pointer to a record that did not exist, written
    into the commit that closed three citations pointing at things that do not exist. It is
    recorded here now, and it is closed in code: `assert_eq!(prod.matches("/*").count(), 0, ..)`
    inside `production_source()` itself, so all 13 call sites across 12 tests inherit it and no
    future pin can skip it. `/*` measured **0** in the production half of all four source-pin
    files, so it is not a retroactive style change; it fails CLOSED, and a deliberate future
    block comment or a `/*` in a production string literal is a FALSE RED — one line to fix,
    and it makes a human look.

    **FIVE CLASSES DELIBERATELY LEFT BARE, each measured rather than argued**, because an
    assertion whose mutation already fails a gate is a second thing that cannot fail alone:
    23 are multi-line block needles at interior indents, which a `// ` on any line but the
    first already destroys; 4 live in HOST-COMPILED module functions where a value test is the
    witness (`answer` driven over all 256 bytes, `reveal_draw`, `reveal_consent`,
    `flow_consent`); 2 are held by the **0-warnings release gate** (`Consent::Pages` gives
    ``variant `Prompt` is never constructed``, `match None {` gives ``unused variable: grant``);
    1 is held by the COMPILER (any `while let` there is
    ``error: `while...else` loops are not supported`` on BOTH targets); and `entry_step(verdict)`
    is DOMINATED by the entry test's cancel-guard needle, measured by name. Two further
    negative results worth keeping: "measurably ambiguous needle" is NOT a pattern in this file
    — all 46 needles' occurrences were counted programmatically and every one is exactly 1 —
    and rewriting `production_source()` to strip `//` lines, which would immunise all 86 pins
    in one edit, was REJECTED because it needs a `OnceLock<String>` to keep the `&'static str`
    signature, silently changes what 86 pins see, and a count it accidentally shifted would
    most likely be "fixed" by adjusting the count.

    **THE RUNNING TALLY OF VACUOUS ASSERTIONS WRITTEN AND DELETED IN THIS REPO IS NOW 22.**
    The arithmetic in full, because a wrong total sitting over a checking breakdown is this
    tree's canonical failure and this is the worst paragraph in the document to commit it in:
    **14** across three prior sessions (one of them inside a fix for exactly this class),
    **+2** on 2026-09-13 in `hal/src/ui.rs` — the fails-open `Buf` assertion above, and the
    dominated digit check `!screen_text(&a).contains('1')`, which was DELETED rather than
    replaced because the `assert_eq!(a.as_bytes(), b.as_bytes())` three lines above already
    held the fact (it could only have fired on an input-INDEPENDENT '1', which is not a
    leak). **That deletion's stated GROUND was too broad and was narrowed the same day:** a
    byte equality over ONE pair of PINs holds only the digit-derived functions that DIFFER
    on that pair, and '9876' shares '1234''s odd/even pattern, so a rendering that leaked
    per-digit PARITY was invisible to it — MEASURED green. The second PIN is now '9875'
    (parity 1011 against 1234's 1010, digit sets still disjoint) and the same leak is
    MEASURED red. **+3** on 2026-09-13, the three infallible
    `split(..).next().expect(..)` messages in `firmware/src/lib.rs`. **+3** on 2026-09-13,
    `assert_ne!(Grant::Reveal, Grant::Entry)`, `(Reveal, Check)` and `(Entry, Check)` at the
    tail of `firmware/src/main.rs`'s `only_a_display_backup_prompt_grants_a_reveal` —
    **WRITTEN AND DELETED INSIDE ONE SESSION**, which is the shortest round trip this class
    has managed here. `Grant` is three FIELDLESS variants under a derived `PartialEq`, so
    the comparison is a discriminant compare and a duplicate discriminant is
    `error[E0081]`: they could not fail. Worse, the two-line comment above them claimed a
    property about the MATCH ARMS ("no arm can accidentally hand a reveal's screen to an
    entry or to a quiz") that they did not test at all — the same header-vs-behaviour class
    this session fixed elsewhere. What holds that fact now is the by-value `assert_eq!` over
    `grants`'s four arm lines plus the three `matches("Some(Grant::X)").count() == 2` in the
    same test. **14 + 2 + 3 + 3 = 22.** Two further sites are deliberately NOT in
    that total, for the same reason in both: `hal/src/callgate.rs`'s and
    `firmware/src/main.rs`'s `.expect("split always yields …")` messages were HONEST about
    what they could see, so changing the second and keeping the first were form calls, not
    vacuity repairs. (The commit that landed the +2 calls the `Buf` assertion "the
    sixteenth", which is its running index at that moment: 14 + the digit check = 15, + the
    `Buf` assertion = 16. Same series, different vantage — not a disagreement.)

    **THE TALLY STAYS 22 AFTER 2026-09-14, AND THE NEAR-MISSES ARE COUNTED SEPARATELY ON
    PURPOSE.** Four candidates were written and killed that day WITHOUT EVER BEING COMMITTED,
    which is a different category from the 22 and must not be folded into them or the number
    stops meaning anything: (i) an `assert_eq!(out.frames(), answered, ..)` at the tail of
    `cancel_drops_a_typed_in_share_before_it_can_be_saved`, DOMINATED by the `expect_err` two
    lines above — under the only mutation that test exists for, the save returns `Ok` and the
    line is never reached; and (ii-iv) three draft COMMENTS in
    `hal/tests/integration_frostsnap_over_hal.rs` rejected before shipping, one of which was an
    intra-doc link to `AbWriteOutcome::CommittedSingleCopy` caught by reading `hal/Cargo.toml`
    (`frostsnap_embedded` is a `[dev-dependencies]` entry, so `cargo doc -p coldsnap_hal` never
    builds it and the link would have been a rustdoc warning against a 0-warnings gate).
    **The distinction worth keeping: the 22 were all committed and later deleted; these four
    were caught by their own author before the commit.** A tally that merges the two cannot
    show whether the practice is improving, which is the only reason to keep it.

    **ONE 5c1232b-CLASS ORPHAN CLOSED 2026-09-13.** `hal/src/ui.rs`'s prose named
    `every_pin_string_fits_the_panel`; the function is
    `every_pin_string_this_module_owns_fits_the_panel`. The PROSE was fixed and the function
    name left alone. Commit d5628df's message carries the same wrong short name and is
    correctly unfixable: a commit message is the record.

    **CITATION HYGIENE — the 2026-09-13 sweep, its yield, and BOTH rejected gates.**

    **THE CORPUS, at `5c1232b`, and SAY WHICH METRIC because two of these numbers depend on
    the pattern.** `rg -o -N --no-filename '[A-Za-z0-9_./-]+\.(py|S|c|h|rs|x|ld|md|toml|json):[0-9]+'`
    over PLAN.md, DECISIONS.md, README.md, vendor/README.md, `hal/src`, `firmware/src`,
    `firmware/examples`, `hostcheck/src`, `tools/*.py` and `firmware/link.x` = **1,449**
    `path:line` occurrences and **257** distinct paths, of which **1,158** are on the SOURCE
    side. Re-measured 2026-09-13 against a clean checkout of `5c1232b`; all three reproduce
    exactly. **Distinct CITATIONS is 881 under that pattern and 922 under the sweep's own,
    which also captures the `-<end>` and `:<col>` suffixes** — `startup.S:148-156` and
    `startup.S:148` collapse together under the shorter one. Neither is wrong; quoting either
    without its pattern is.
    **AND THE CORPUS IS SELF-REFERENTIAL, which is a trap unique to this material:** prose
    ABOUT citations contains citations. The same commands over the tree carrying this
    paragraph give **1,492** occurrences and **1,163** source-side. Any figure here is a
    dated snapshot at a named commit, never a running total. ~155 hand-verified,
    including a blind random sample of 25 coldcard citations: **24 correct, 1 off by one.**
    Measured rot ~**3.4%**. **DO NOT RE-RUN THE 922-CITATION SWEEP** — the yield does not pay
    for the resolver, both previously known rots (`ssd1306.py:214`, `startup.S:137-138`) are
    already fixed and still hold, and a range check over all **564** resolved coldcard
    citations finds **0** pointing past EOF. 20 defect sites shipped 2026-09-13.

    **THE CADENCE FINDING, and it is worth more than the 20 sites.** `AUDIT-2026-09-10.md`
    spent 26 agents on the FOUR DOCUMENTS — PLAN.md 249, README.md 101, DECISIONS.md 61,
    vendor/README.md 48 findings, and only **6** of its 465 findings were source files —
    while **1,158 of the 1,449** `path:line` citations live on the SOURCE side (both counts
    re-measured 2026-09-13 at `5c1232b`; the AUDIT split is
    `rg -o '^### [A-Za-z0-9_/.-]+' AUDIT-2026-09-10.md | sed 's/^### //;s/:.*//' | sort |
    uniq -c`, which also shows `hostcheck/src/main.rs` 3 and `firmware/examples/stub.rs` 3 —
    the 6 source-file findings). **The
    instance:** commit 9d199df fixed `startup.S:148-156` → `:148-157` in PLAN.md and
    `firmware/link.x` and recorded it DONE, and **five live `hal/src` sites still said
    `148-156`** — `callgate.rs:1219`, `lib.rs:256`, `heap.rs:10`, `heap.rs:304`,
    `panic.rs:87`. Ground truth: `bne wipe_loop2` is `startup.S:157`, so `:156` stops one
    line inside the loop. All five fixed 2026-09-13. None of the five carries a "this read
    `148-156` until 2026-09-13" clause, and that OMISSION is right — the correction trail for
    this citation already lives here and in `firmware/link.x:65-66`, so the source comments
    carry none. **The REASON given for it in that fix's own commit message — "that is the doc
    register's convention, not a source comment's" — is a generalisation this document
    contradicts, and it is scoped to this one citation as of 2026-09-13:** the same commit
    wrote "this read X until" clauses into source comments nine times. A commit message is
    the record and is not edited; the scoping lives here. **A doc-lane fix that never reaches
    the source comments is this project's real rot mechanism, and it is the highest-value
    unopened surface in the tree.** NEXT SESSION'S PRIORITY 1, with its mechanical check:
    `rg` each 9d199df-corrected citation across `hal/src` and `firmware/src`. (One
    quotation is deliberately left at `148-156`: `AUDIT-2026-09-10.md:164` quotes
    `hal/src/panic.rs:84-87` VERBATIM as prescribed replacement text, and `:163` and `:2879`
    are correction record — `:2879` says in as many words "with `bne` at `:157` — one line
    past". Renumbering inside a quotation of what the source USED to say destroys the
    evidence, which is 9d199df's own DELIBERATELY-LEFT-ALONE rule.)

    **THE OBLIGATORY EXCLUSION, measured.** **132 of the 1,449 citations are PROTECTED** —
    dated trajectory rows, "this read X until <date>" clauses, and citations inside quoted
    withdrawn text — including **20 of the 24 in `vendor/README.md`**, whose citations are
    almost entirely correction record and were left wholesale. Per file: `firmware/link.x`
    15 of 27, PLAN.md 63 of 182, DECISIONS.md 16 of 70. And the counting rule that produces
    132 rather than 236 is worth keeping: **a `///`-only line IS a paragraph break.** Treating
    a whole Rust doc block as one paragraph over-protects, and it wrongly shielded a real
    finding (`hal/src/heap.rs`'s dead `hal/examples/stub.rs` path) behind a `SUPERSEDES
    18,036 B` note fourteen lines above it. The struck-through `bitcoin_transaction.rs:524`
    in DECISIONS.md gets a parenthetical, **never a renumber**; it already has one.

    **THE TRAP THAT WOULD HAVE MANUFACTURED FALSE ROT.** `/Users/garykrause/repos/frostsnap`
    is **1,269 commits AHEAD** of the vendored `0bbc18be` with **17 differing files**, so
    every vendored-crate citation must be verified against `vendor/frostsnap/` IN-TREE, never
    against the sibling; resolving `device.rs:491` or `tweak.rs:573` there would report rot
    that does not exist, over ~171 distinct citations. Conversely
    `/Users/garykrause/repos/coldcard-firmware` is at `0431fd2b` (2026-08-09), BEFORE this
    project's first citation, with local changes only under `docs/` — so **coldcard rot is
    never DRIFT, only WRONG-AS-WRITTEN**, which makes the check a content read rather than a
    diff. Two further resolution traps: `stm32l4s5xx.h` exists in **FIVE** copies in that
    sibling and they disagree inside `SPI_TypeDef`, and `oled.c` / `storage.c` each exist in
    both `stm32/bootloader/` (Mk3) and `stm32/mk4-bootloader/` (Mk4). `main.c:42` is cited at
    **29** sites and `dispatch.c:570-574` at 7; both are verified correct and are **not** to
    be re-derived — if either ever moves it moves 36 times.

    **GATE (a) — pair every line citation with a companion MARKER: REJECTED, with numbers.**
    Implemented and run over all **924** coldcard citation occurrences: **125 pass, 671
    (72.6%) carry NO MARKER AT ALL, 128 no-match.** Of 6 no-matches hand-verified, **5 were
    false positives** — `ssd1306.py:61` for `0xf0` is `SET_DISP_CLK_DIV, 0xF0` (hex case),
    and `oled.c:71`, `oled.c:498`, `clocks.h:6`, `clocks.c:147-149` are all exact. So it is
    silent on nearly three quarters of the corpus and ~83% wrong on the rest. Worse, **it
    cannot RESOLVE a third of its own input**: 284 of the 922 distinct citations are bare
    basenames with no directory, and nothing in the tree declares a citation base path. The
    range check it would subsume finds **nothing** (0 of 564). And it gates a **DEPRECATED
    idiom** — this repo has been moving citations from LINES to SYMBOLS precisely because
    lines rot. **The suggested alternative, a lint FORBIDDING new line citations, is also
    REJECTED:** it would have caught NONE of the nine findings (one is a wrong PATH, one a
    test NAME, three pre-existing), and `main.c:42` is correct at 29 sites.

    **GATE (b) — every named test in prose exists: REJECTED.** 175 backticked snake_case
    candidates, 16 not any `fn` in the tree. Triaged all 16: 7 external symbols, 1 local
    variable, 1 struct field, **6 deliberately-preserved rename or withdrawal records**, and
    exactly **1 live defect**. 94% false positive — and **6 of the 15 FPs are text this
    project FORBIDS touching. A gate that fires on the correction record has only two
    responses: suppress (forbidden here) or delete the evidence (worse).**

    **THE HONEST CONCLUSION, written as the conclusion: THERE IS NO CHEAP MECHANICAL GATE FOR
    THIS CLASS. KEEP DOING PASSES.** The narrowed form of (b) survives as ONE `rg` line in a
    REVIEW CHECKLIST and not in CI: run the name check only over prose in an ASSERTING
    position (`enforced by|pinned by|caught by|covered by|the pin is`) and only OUTSIDE
    withdrawal-marked paragraphs. At 1 true positive per 175 candidates that is a checklist
    line. **And §8.2's `fifo_words` cell is the standing argument against any gate that
    verifies a claim by READING:** two independent readings agreed on an answer that was
    wrong three ways, and only running the mutation found it.

    **The count is a snapshot, not a bound, and it has moved three times:** 152 → **169**
    on 2026-09-08 (the first recount said 164, missing `entry.rs` and `hal/src/lib.rs`
    entirely) → **181** on 2026-09-10 → **184** on 2026-09-12: usb 88, flash 22,
    main.rs 18, panic 13, callgate 11, keypad 8, display 8, rng 6, `firmware/src/lib.rs` 4,
    `firmware/src/entry.rs` 4, `hal/src/lib.rs` 1, `ui.rs` 1 = 184. (The 181 breakdown
    said `main.rs` 15; it was 17 that day and is 18 now. Nothing else moved.)
    Do not chase the number — the gate is a whole-target
    compile, so it covers however many there are. **`firmware/src/quiz.rs` contributes
    0**, which is not an accident: a pure module is exhaustively host-testable, and a
    `cfg` in one would put a security property where no host test can reach it.

    The gate bites where the four existing ones do not, proven by mutation:
    `ROW_SETTLE_SPINS as u32 + 0` in the same `cfg`-arm block left host tests at 261,
    host clippy at 0, and `cargo build --release` at **0 warnings and 0 errors**, while
    the device clippy flagged it twice (`identity_op`, `unnecessary_cast`).

    **What those blocks actually contained: nothing.** (This read "the 152 blocks"; the
    survey below was taken at the 152-block count and has not been re-run at 181 — say
    so rather than restating the current number over an old survey.) At clippy's default level, from a
    cold target dir, 0 findings in `hal/src` and `firmware/src` and 0 rustdoc warnings.
    A deeper hunt — restriction and pedantic lints as a one-off survey, plus a
    brace-matching grep of all 152 spans for `unwrap`/`expect`/`panic!`/`assert`/
    `copy_from_slice`/variable indexing — found **no reachable panic and no unbounded
    hardware spin**: every register poll is a `checked_sub` countdown returning an error
    (`usb::wait_bits`, `usb::wait_ep_idle`, `display::write_byte`, `display::drain`,
    `rng::read_one_word`, `flash`'s `while off < to`), and `panic::system_reset`'s
    exit-less loop is decision 6 by design. **This read "All 19
    `cfg(not(target_arch = "arm"))` blocks are refusals" until 2026-09-10; the count is
    16 and two of them are not refusals.** Re-measured: 16 blocks, of which **14 are
    refusals** returning a value — `display` 3, `flash` 4, `usb` 3, `keypad` 2, `rng` 2,
    all `…Error::NotOnThisTarget` or a `SourceFault` — and **2 are host shims**:
    `callgate::with_irq_off`'s host arm is `{ f() }` (no `cpsid i` to perform off-target)
    and `firmware/src/main.rs`'s host arm of `entry_point` is a `loop { spin_loop() }` after `boot()`, which
    exists so `entry_point` diverges on the host. Neither shim bypasses a device-side
    check — `callgate::raw` is itself ARM-only and its host arm returns
    `Errno::BAD_GATE`, so nothing reachable through `with_irq_off` on the host can
    touch the gate — but "all of them are refusals" was a stronger claim than the code
    supports, and the forbidden direction (a cfg on a refusal, which fails open) is
    what the sentence exists to rule out. It is still ruled out: on the device arm every
    one of the 16 does the real work, and it is the *host* arm that refuses. The single real defect was a missing `SAFETY` comment on the `SPI1_CR1`/`CR2`
    read in `display::PanelToken::open`, now written. That is a boring result and it is
    the true one.

    **The restriction lints are deliberately NOT in the gate**, and this is the judgement
    call to not re-litigate. `-W clippy::cast_possible_truncation`,
    `arithmetic_side_effects` and `indexing_slicing` produce 281 findings, 40 inside
    `cfg`-arm spans, and **39 of those 40 are false on this target**: 37 are `usize → u32`
    casts the lint itself describes as lossy only "on targets with 64-bit wide pointers"
    (`target_pointer_width = "32"` here, so `usize` *is* `u32`), 8 are `chunks_exact(8)`
    indexing that is total, 2 are a slice already bounded by `.min(4)` with a comment
    saying so, and 16 are `const fn` register-address arithmetic on constants. A gate
    whose only available response is `#[allow]` is a permanent hall pass, which is
    exactly what this project forbids. Run them as a survey; keep them out of the list.

    **PARTLY CLOSED 2026-09-09, and the wording above overstated the hole a second time.**
    "No assertion in any of those blocks has ever evaluated" was false when written. Split
    the claim in two:

      - **COMPILE-TIME ASSERTIONS: CLOSED, and they were already closed by the gate above.**
        Every `const _: ()` block in non-test `hal/src` and `firmware/src` (22 on
        2026-09-09; the count moves with the source, so do not gate on it) is
        const-evaluated *for `thumbv7em-none-eabihf`, with `usize` = 32 bits*, inside and
        outside `cfg`-arm blocks alike, because const-eval is not optional in rustc and
        happens for whatever target is being compiled. Proven by planting
        `const _: () = assert!(size_of::<usize>() == 8, "PLANTED")`: `--target thumbv7em`
        gives `error[E0080]: evaluation panicked: PLANTED`, `--target
        aarch64-apple-darwin` compiles clean. A runner cannot add anything here — a
        `const` item has no runtime. **Do not build one for this.**
      - **RUNTIME ASSERTIONS: STILL OPEN, and still the larger half.** Every non-`const`
        volatile access, every spin-limit countdown, every `Timeout` branch. That needs
        QEMU or hardware, and see the fidelity ceiling below for how little QEMU buys.

    **A REAL HOLE FOUND WHILE CHECKING THAT, AND CLOSED: the device gate ran `--release`,
    where const-eval WRAPS.** `overflow-checks = false` does not merely skip a check in
    const-eval; when the arithmetic sits inside a `const fn` body it silently wraps.
    Measured three ways: `pub const fn scale(n: usize) -> usize { n * 4 }` called as
    `scale(0x4000_0000)` returns **0** under `--release`, so `assert!(scale(..) > 0)`
    fails on its own logic rather than naming the overflow, and
    `const _: [(); 0] = [(); V]` type-checks and **exits 0**. Under the dev profile the
    same expression is `error[E0080]: attempt to compute 1073741824_usize * 4_usize, which
    would overflow`. At 64 bits the product is 4294967296 and no host gate can ever see
    it. So a `usize` overflow that exists *only at 32 bits* was invisible to all six
    gates, which is precisely the class this item exists to hunt.

    **Closed by one more gate line, no `--release`** (README "Test"), 4.4 s warm, passing
    clean today: `cargo clippy --target thumbv7em-none-eabihf -p coldsnap_hal
    -p coldsnap_firmware`. Proven by a planted probe run on a `git archive HEAD` copy so
    the working tree was never touched — `pub const fn planted_probe(n: usize) -> usize
    { n * 100 }` plus `const _: () = assert!(planted_probe(FLASH_SPIN_LIMIT as usize) > 0)`
    inside `flash.rs`'s existing `cfg`-arm block: the two `--release` lines exit **0** with
    **0** `hal/src` hits, the new line exits **101** with **2**, `error[E0080] ... attempt
    to compute 50000000_usize * 100_usize, which would overflow` in `hal/src/flash.rs`. (**The line number is deliberately gone as of 2026-09-12**: it located a PLANTED PROBE on a `git archive HEAD` copy, so citing it sends a reader hunting for a line that has never existed in this tree — today it is `impl SrPort for Mmio`.)
    With the probe removed both go back to 0/0. The probe must be `pub` and documented, or
    it trips `dead_code` and the existing gate catches it for the wrong reason — which is
    how the first attempt at this demonstration was wrong. **No live instance exists in the
    tree today**; the gate is a trap for the next one.

    **AND A RUNNER WAS DELIBERATELY NOT BUILT.** `tools/qemu-boot.sh` boots the unmodified
    release ELF under `-machine b-l475e-iot01a` with `-d guest_errors,unimp` and is
    explicitly a **diagnostic, not a gate** — the image emits no semihosting output, so
    there is no pass criterion. Its failure paths are what is verified, each demonstrated
    with a stub `qemu-system-arm`: absent QEMU → 2, empty `.text` → 3, unknown machine → 4,
    **QEMU exits 0 having printed nothing → 5**, **QEMU itself exits non-zero → 6**, wall
    clock → 124. Exit 6 and the `timeout 15` on both `-machine help` probes were added
    2026-09-09 by adversarial re-verification, which found the first cut treating qemu's
    OWN stderr as a guest trace: a stub printing `Kernel image must be loaded` and exiting
    1 got **exit 0 and the word OK**, guest never executed — and that is the likeliest real
    first outcome, since nothing sets SP. A stub that hung on `-machine help` also hung the
    script past `WALL`, which only ever covered the guest. Two mutations measured in the
    same pass, on a `git archive HEAD` copy: a 32-bit-only `usize` overflow in a `cfg`-arm
    block in `rng.rs` (a different file from the one the gate was demonstrated on) is caught
    by the new dev line and by nothing else — `--release` device clippy exits 0 with 0 hits,
    dev exits 101 with 2, `attempt to compute 1000000_usize * 4300_usize, which would
    overflow` in `hal/src/rng.rs` (line number omitted for `flash.rs`'s reason above: a planted probe, never a live line). In the same tree, `transaction()` in `display.rs`
    rewritten to `bsrr_set(CS_PIN)` where it must `bsrr_clear` — `CS` deasserted for the
    whole transfer, so the panel receives nothing — produced **zero** diagnostics from
    either line, and would produce none under QEMU either: GPIO writes are accepted and
    nothing observes the pin. That mutation is the honest ceiling of every tier here.
    **QEMU IS installed on this machine** — 11.1.1 at `/opt/homebrew/bin/qemu-system-arm`,
    since 2026-09-09, and `tools/qemu-boot.sh` has been **run** in all three modes;
    README's own section records exit 6 bare, exit 6 with `SHIM=1`, and exit 124 with a
    deliberately faked `SP`. (**This sentence read "QEMU is not installed on this
    machine (`brew install qemu`, ~1.5 GB)" until 2026-09-10**, in the same item whose
    README counterpart documents the runs.) The conclusion is unchanged and is the
    point: the script stays a **diagnostic, not a gate**, because the image emits no
    semihosting output so there is no pass criterion, and no available QEMU machine has
    both flash at `0x0802_0000` and RAM at `0x2009_e000`. Three findings settled why a `no_std`
    harness crate was rejected rather than deferred: (a) `cargo test --target thumbv7em`
    cannot build a single test — `error[E0463]: can't find crate for 'test'`, libtest needs
    std — so the 474 host tests can never run on ARM; (b) **zero** of the `cfg`-arm blocks
    in `usb.rs`, `flash.rs`, `keypad.rs`, `display.rs` and `rng.rs` expose a `pub fn`, so a
    separate crate cannot call any register code, and making them `pub` is the seam
    `hal/Cargo.toml` calls "the libngu defect of §1 reproduced"; (c) a `no_std` thumbv7em
    binary whose vector table is neither `#[used]` nor `KEEP`ed links "successfully" to a
    **zero-byte `.text`** with cargo printing `Finished` — the silent-pass trap, which is
    why the script asserts on `.text` bytes and on observed output, never on an exit code.
    Nothing about registers changes at any tier: the callgate, SE1/SE2, the SSD1306, the
    keypad, OTG_FS, the flash controller and RDP stay **unverified-on-silicon**.

    Nor does a
    lint see a *deleted security property*: the keypad shuffle regression above would
    still pass all six gates today if `shuffle_rows` were replaced by a call to some
    other correctly-typed function. Source-level guards like
    `the_scan_order_is_actually_shuffled_at_the_only_call_site` remain the only defence
    for that class, and they exist for exactly one call site.

    **THE TRACTABLE SLICE WAS TAKEN 2026-09-12, and it was taken because a mutation
    inside `boot` PASSED ALL SEVEN GATES.** `show_backup_page` returned
    `Some(Reveal::Page(page))` — the pairing "the cursor names the page that was DRAWN" —
    and changing that to `Some(Reveal::Page(page.saturating_add(1)))` left firmware tests,
    hal tests, BOTH device clippy profiles, `cargo build --release` at 0 warnings,
    `tools/pixel-check.py` at PASS all 7, and the `hostcheck` interop harness at exit 0.
    MEASURED, all seven, before the fix — **and "passed" means two different things across
    them, which is stated rather than rounded off because the weaker half is the more
    damning one.** `show_backup_page` is nested inside `boot`, so only THREE of the seven
    COMPILED the mutated line: the ARM release build and the two device clippy profiles.
    Those three passed because the edit is well-formed code that does the wrong thing —
    exactly the "*plausible-but-wrong*" blind spot recorded further up this item. The other
    four passed TRIVIALLY, having never compiled it: both host test gates are
    `--target aarch64-apple-darwin`, `pixel-check` drives `examples/simulator`, and
    `hostcheck` drives the stub's own reveal walk. Together that IS the argument for
    hoisting: the only gate that can see this class is a host test, and a host test cannot
    reach inside `boot`. What it does: `reveal_step` adds one to a cursor
    that is already one ahead, so a human is shown pages 0, 2, 4, 6 and then asked "Wrote
    down all 25 words?" over **13 words that were never drawn** (12 of the 25 reach the
    glass). **THE TWO HALVES WERE SWAPPED HERE UNTIL 2026-09-12:** this sentence read
    "over **12 words that were never drawn**", and commit 3ccc891's subject says the
    mutation "showed a human 13 of 25 words" — both have it backwards, and the pushed
    commit cannot be edited, so the correction lives here. It re-derives from
    `ui::BackupPages::page` without a build: page 0 is `BackupPage::ShareIndex` and carries
    NO word, so drawn pages 2, 4 and 6 carry words 5-8, 13-16 and 21-24 = **12 shown**,
    while pages 1, 3, 5 and 7 carry 1-4, 9-12, 17-20 and word 25 alone = **13 never
    drawn**. Page 7 holding only word 25 is why the split is 12/13 and not 12/12. The page
    SET was always right; only the counts were wrong. They say yes,
    `CommsMisc::BackupRecorded` reaches the coordinator, and the app records a backup that
    cannot restore the share. This is requirement 5's own class — a share-shaped screen
    that is not what it claims — and no gate could see it because every line of `boot` is
    `cfg(target_arch = "arm")` and the stub's reveal walk calls `Session::show_backup`
    directly rather than through that file.

    THE FIX IS HOISTING, not a host `display::Panel`, and the panel was ruled out rather
    than merely skipped: `display::Panel` is `struct Panel { _private: () }` whose ONLY
    constructor is inside `PanelToken::open`'s `cfg(target_arch = "arm")` arm, and the host
    arm of that same function returns `Err(DisplayError::NotOnThisTarget)`. A host `Panel`
    in ANY form — trait, shim, `test-seam` feature, `Default` — requires turning that
    refusal into a success, which is the FORBIDDEN direction of this project's cfg rule and
    is not a trade worth making for a test double. There is also no thinner seam to hide
    behind: `Panel::show` already takes a bare `[u8; FRAME_BYTES]`.

    What shipped is `reveal_draw(page, shown, record_pending, confirm) -> (RevealScreen,
    Option<Reveal>)`, a module item with a value test, plus `show_backup_page` reduced to
    forwarding what it returns. It carries TWO pairings that were review-only: the cursor
    names the page that was drawn, and the recorded question is drawn with the same
    `ui::ConfirmDigit` the cursor will accept. `the_reveal_cursor_names_the_page_that_was_drawn`
    walks EVERY page and one past the end, because a single sample at page 0 would pass
    under `page * 1`. THREE MUTATIONS RUN: the original `+ 1` now fails the value test AND
    the source pin; rebuilding the cursor at the call site instead of forwarding fails a
    new body-scoped source pin; and decoupling the two digits fails the value test and two
    others. Cost **+64 B** of flash for the whole round (377,192 -> 377,256 B, 26.46% -> 26.47%),
    measured in a clean target dir. It was +104 B before the review pass deleted a vacuous
    legend-length comparison and replaced an early `return` with a value.

    **AND THE FIRST CUT DID NOT CLOSE THE HOLE — IT MOVED IT ONE LINE. TWO REVIEWERS FOUND
    THAT INDEPENDENTLY and it is the most valuable output of the round.** `boot`'s loop has
    a SECOND call, `glass = show_backup_page(&mut session, page, panel, &mut entropy)`, and
    the `page` going IN is arithmetic too. Mutating it to `page.saturating_add(1)` was
    MEASURED green on firmware tests, both device clippy profiles and `cargo build
    --release` at 0 warnings — because `reveal_draw` is then handed page+1 and pairs it
    CONSISTENTLY with the cursor, so the new value test sees nothing wrong, and the body pin
    only says `show_backup_page` does not BUILD a `Reveal`. The drawn pages are
    0, 2, 4, 6 AGAIN — the same 12 of 25 words shown and the same 13 never drawn as the
    original defect, byte for byte the same symptom, because the START call is pinned at
    page 0 and only the STEP is shifted: the cursor begins at `Reveal::Page(0)`,
    `reveal_step` yields 1, the mutated call draws 1 + 1 = 2, then 4, then 6, then 8 =
    `BACKUP_END`, which ends the reveal. Same unrestorable backup.
    **WITHDRAWN 2026-09-12, quoted so the correction is visible:** this read "Drawn pages
    become 1, 3, 5, 7: 16 of 25 words shown, the recorded question asked over the 9 that
    were not, same unrestorable backup." Wrong page set and wrong counts. The code
    comment above the step-call pin in `firmware/src/main.rs` carried the same error in a
    worse form — "16 of 25 words shown ... over the 12 that were never on the glass", which
    is 28 words of 25 and is the cheapest tell that nobody re-derived it. The MUTATION was
    always caught by the pin; only the symptom prose was wrong.
    Only the START call (`, 0,`) was pinned; the count pin
    (`show_backup_page(` == 2) is blind to an argument. Closed by one more exact-text
    assertion on the step call, and RE-MEASURED: the mutation now fails
    `every_exit_from_the_reveal_takes_the_words_off_the_glass` by name.

    HONEST LIMIT: this does not make a wrong cursor impossible, it makes the arithmetic
    reachable by a value test. Both residues — a caller that rebuilds the cursor, and a
    caller that alters the page going in — are source pins, which is the same remedy the
    keypad shuffle uses and is all that is on offer for a line inside a `cfg`-arm function.
    Source pins DO run on the host despite `boot` being ARM-only, because `include_str!`
    reads the file as text, and that is why they are the right remedy rather than a
    consolation. The five other
    panel-taking functions in `boot` (`take_glass`, `show_entry_page`, `show_quiz`,
    `refuse`, `idle`) are NOT hoisted and that is deliberate: none has a page cursor to
    mispair, both entry and quiz already delegate composition to the value-tested
    `entry_frame`/`quiz_frame`, and their surviving pairings are pinned by exact text.
    RE-CONFIRMED 2026-09-12 (a63eaa7) by tracing a mutation for each of the five: the
    reasoning holds and no severity-1 leak survives in them.

    **TWO FURTHER HOISTS PROPOSED AND STILL DECLINED, re-derived 2026-09-13 so the grounds
    are on the record rather than in a lane's head.**
      - **Hoisting `Flow`/`Reveal`/`Check` and the three `*_step` routers — DECLINED,
        because all 16 of those items are ALREADY at module scope** in
        `firmware/src/main.rs`: `Reveal`, `reveal_consent`, `RevealStep`, `RevealScreen`,
        `reveal_draw`, `reveal_step`, `Flow`, `flow_consent`, `EntryStep`, `entry_step`,
        `entry_frame`, `Check`, `CheckStep`, `check_step`, `quiz_frame`, `grants`, with 38
        host tests in that file (`grep -c '#\[test\]' firmware/src/main.rs` = 38,
        re-confirmed 2026-09-13). There is nothing left to hoist. What the proposal actually
        wanted was a CONSUMER, and the 2026-09-13 nonce-durability round does not create one
        by a single line: it landed in `hal/src/flash.rs` and `hal/tests/`, and adds no
        caller in `firmware/examples/stub.rs` or `firmware/src/main.rs`.
      - **Lap-driven restoration walks — DEFERRED, and the corrected `Cancel` count in §8.3's
        M10 makes the case STRONGER rather than weaker.** `reveal`, `check_quiz` and
        `type_backup` in `firmware/examples/stub.rs` are each a blocking `loop` with **no
        wire read**, so making them resumable across laps is a ~250-line state-machine
        rewrite of the stub plus the main loop. The one clearing it might newly exercise is
        the UNCOVERED sixth, `signer.clear_tmp_data()` — and it would not ASSERT it, because
        the stub has no observable for `tmp_loaded_backups`. So the cost buys the STUB's
        guards, not `boot()`'s, exactly as already recorded.

    **BUT THE COUNT WAS WRONG, AND THE MISCOUNT IS WHAT HID THE REAL HOLE.** "The five
    other" — six with `show_backup_page` — undercounts by three. `boot` nests **NINE**
    functions that put pixels on the glass: `hold`, `draw_prompt`, `draw_batch`,
    `take_glass`, `refuse`, `idle`, `show_backup_page`, `show_entry_page`, `show_quiz`.
    (Precisely: nine nested fns, **eight** of which take a panel by argument — `hold(reason:
    &str) -> !` opens its own through `display::PanelToken::take().map(PanelToken::open)`.
    The review round corrected this lane's own first phrasing, which said all nine took a
    panel.) The three never counted were `hold`, `draw_prompt` and `draw_batch` — and
    **BOTH mutations that survived every gate lived in `draw_prompt`**, the one that was
    never on the list, so the omission was not cosmetic. Both are now pinned inside the
    existing `every_exit_from_the_reveal_takes_the_words_off_the_glass`, so no test count
    moved:
      - deleting `draw_prompt`'s `if matches!(shown, Ok(Shown::Nothing)) { return None; }`
        reads as a pure simplification, because the `_ => None` arm four lines below returns
        the same value — and it blanks the panel on every completed keygen
        (`FinalizeKeyGen` maps to `Ok(Shown::Nothing)`) and drops any live reveal, entry or
        quiz with it. The pin also catches the widening to `Ok(Shown::Nothing) | Err(_)`.
      - HOISTING `draw_prompt`'s `take_glass` call above the composition parks a consent
        prompt over a BLANK screen: the frame reaches the glass empty, the composed prompt
        screen never reaches it at all, and `draw_batch` still parks the prompt and its
        confirm digit — a consent question answerable with nothing on the glass. MEASURED
        green before the pin: firmware 168/168 exit 0, `cargo build --release` at 0 warnings
        and a `.text` **24 B SMALLER**, so it reads as a free simplification. Pinned by an
        ordering assert scoped to `draw_prompt`'s own body text, not by a bare `find` over
        the image. **The design report had traced this exact edit and declined to pin it on
        the grounds that it is "instantly visible at a bench". A bench is not a gate** —
        `pixel-check` and `hostcheck` both drive examples rather than `boot`, so nothing in
        this project could see it.

    **BOTH OF THOSE ARE NOW PINNED, 2026-09-08.** Each was an inline expression inside
    a `cfg`-arm block; each is now a pure `const fn` with a host test that checks the
    VALUE rather than the spelling, which is strictly stronger than a source-text pin:
      - `usb::fifo_window(ep)` — `OTG_FS_BASE + FIFO + (ep & 0x0f) * FIFO_STRIDE`, pinned
        by `fifo_window_stays_inside_the_peripheral_for_any_ep`, which walks all 256 `ep`
        values and separately asserts `ep` and `ep | 0x10` land identically (so the mask
        itself is what is tested). Dropping the mask now fails with `ep 63 maps to
        0x50040000, outside the OTG_FS window`. This required hoisting `FIFO` and
        `FIFO_STRIDE` out of the ARM-only `offset` module: keeping register CONSTANTS
        behind a cfg is what made the expression unreachable, and constants are numbers,
        not code.
      - `flash::pnb_bits(page)` — pinned by `pnb_bits_encodes_the_page_number_itself`
        across the whole 8-bit field. `page << 4` now fails with `page 1 encoded as page
        2`. Worth restating why the mask does not save it: the masked result is a VALID
        field value naming the wrong page, so page 5 erases page 10 and the erase
        reports success because it did erase a page.
    The rule of thumb below still holds for everything not yet extracted, and the lesson
    generalises: an expression worth guarding is an expression worth making a function.

    **Two concrete mutations that pass all six gates**, measured 2026-09-08 during
    adversarial verification of this item, recorded because "a lint cannot see a deleted
    security property" is abstract and these are not. (a) Deleting the `& 0x0f` bound the
    mask's own doc calls what "keeps the address inside the peripheral for ANY `ep`, rather
    than relying on every caller" — inline in `usb::Mmio::write_fifo_word` when this was
    measured, **extracted to `hal/src/usb.rs`'s `fifo_window` later the same day** — puts an
    unsafe `write_volatile` outside the OTG_FS window. (b) Changing `page << 3` to
    `page << 4` in `hal/src/flash.rs`'s `pnb_bits`, whose value reaches `FLASH_CR`'s `PNB`
    field in `StmFlash::erase`, erases the **wrong page**. (**Both were cited as
    `usb.rs:1351` and `flash.rs:1169` until 2026-09-13 and neither line holds anything
    relevant now** — `flash.rs:1169` is now a comment inside `StmFlash::erase`'s
    latched-error note (the statement it used to quote, `let (page, bank2) =
    erase_page_of(abs)?;`, sits four lines above it at the time of writing, which is the
    whole reason this citation is a symbol now) and `usb.rs:1351` is an unrelated volatile
    pair. Converted to SYMBOLS rather than to fresh
    numbers, per this document's own remedy: both expressions were HOISTED into pure `const
    fn`s two paragraphs above, which is exactly the movement that rots a line citation. The
    dated counts in this paragraph are the 2026-09-08 measurement and stay as written.) Both left 265 hal + 81 firmware tests green, host clippy 0, `cargo build
    --release` at 0 warnings *and* 0 errors, and both new device gates at 0. What the
    gate does catch, also by mutation: `apb2 & RCC_APB2ENR_SPI1EN == 0` → `== 1` in
    `display::enable_clocks` (a flag test that can never be true, so `SPI1`'s clock is
    never ungated) fails device clippy at exit 101 on deny-by-default
    `clippy::bad_bit_mask`, while every other gate stays green. So the rule of thumb is:
    the gate sees *malformed* register code and is blind to *plausible-but-wrong*
    register code. Only a source pin or silicon closes the second half.

23. **A near-miss worth recording because the cause was a plausible-looking source
    citation.** The Mk4 keypad has TWO decode strings in the Coldcard tree and they are
    exact reverses. `shared/mempad.py:19` is the authoritative electrical matrix map,
    `DECODER = 'y0x987654321'`, indexed `(row * NUM_COLS) + col` (`:120`) and decoded at
    `:152`. `unix/simulator.py:491` uses `'123456789x0y'[(row*3) + col]` — but that
    `row`/`col` come from **screen pixel coordinates** (`(y - KEYPAD_TOP) //
    KEYPAD_PITCH`), i.e. the photo's visual layout, NOT the matrix.

    The pixel string was handed to the keypad agents as "the matrix map". Under it,
    electrical index 2 — physically CANCEL — decodes to `'3'`, and `'3'` is in
    `ui::CONFIRM_CHARSET = *b"12346"`. **Pressing CANCEL would have signed on one prompt
    in five**, with the other four unapprovable. Caught during the build, not after.
    Now guarded by a `const _: ()` assert (`keypad.rs:488`,
    `DECODER[CANCEL_INDEX] == KEY_CANCEL`) so the wrong table is a BUILD FAILURE, plus
    `the_decode_table_is_the_matrix_map_not_the_printed_layout`. Both verified by
    mutation: substituting the pixel string fails `E0080` at compile time.

    The lesson is about citations, not keypads: a file:line that exists and looks
    authoritative can still be the wrong file. The simulator's string was real, cited,
    and about pixels.

21. **The randomised confirm digit is drawn and rendered on the device path but never
    EVALUATED there, because no keypad driver exists.** `firmware/src/main.rs`'s `ask` draws
    a fresh `ui::ConfirmDigit` per prompt and renders it, and `Session::confirm_at`
    (`firmware/src/lib.rs`) documents that the render and the accept share one
    `ConfirmDigit` so they cannot disagree — but `ConfirmDigit::accepts` has **no caller anywhere in `firmware/src`**.
    `boot()` has no button input, so nothing on the device evaluates a keypress. The
    fail-closed rule therefore lives in two places today: the type in `hal`
    (`accepts` compares against a *private* field only `draw` can fill, so no
    cross-crate caller can forge a digit) and the only consumer,
    `firmware/examples/stub.rs::approved`.

    **CLOSED 2026-09-02.** `hal/src/keypad.rs` landed (the Mk4 4x3 membrane matrix, real
    pins from `stm32/COLDCARD_MK4/pins.csv:74-80` — cols PB0-PB2, rows PD8-PD11) and
    `firmware/src/main.rs`'s `answer` calls `confirm.accepts(key)` in BOTH of its digit
    arms -- `Consent::Prompt` and `Consent::Question` -- reachable only from
    `keypad::Event::Down`. (**Cited by ARM rather than by line since 2026-09-12, because
    the line numbers had rotted TWICE: `main.rs:221` until 2026-09-10, then `:543`/`:565`
    until 2026-09-12, by which time the two calls were at `:560`/`:589`. Two rots in one
    citation is the argument for not writing the third.**) `Answer::Yes` is the sole route to
    `session.confirm`. The `keypad::Event` match is exhaustive with no `_` arm, so a new
    driver variant is a compile error rather than a silent default. Proven fail-closed
    over all 256 byte values x all 5 digits (`only_the_rendered_digit_confirms`), plus
    ghosting refused across all 4,096 scan patterns
    (`simultaneous_contacts_are_refused_never_guessed`) and a dead pad refusing
    (`a_missing_keypad_never_confirms`).

    The original text is kept below because its warning still applies to any OTHER
    mechanism of this shape. So do not read "fail-closed confirm digit" as "the device
    enforces it" — **before this landed, on silicon the digit was a legend with no
    enforcement.** It becomes real when a keypad
    driver lands, which is phase-5 work alongside `display.rs`. Both call sites say this
    in comments. Pinned meanwhile by `ui::tests::anything_but_the_confirm_digit_is_a_refusal`
    (every non-digit key refuses, including all four *other* charset digits — the near
    miss a sloppy implementation gets wrong) and
    `ui::tests::the_signing_screens_print_the_digit_that_accepts`.

20. **CLOSED 2026-08-25, and it was a permanent-brick path: the declared envelope
    n <= 12 existed only in prose.** No code anywhere refused a larger group —
    `grep -n 'MAX_PARTIES|MAX_DEVICES|MAX_SIGNERS' firmware/src hal/src` returned
    nothing. An n=16 `CertifyPlease` is 3,775 B by §7's own measured formula
    (`195n + 33t + 127`), comfortably inside `comms::FRAME_LIMIT` 4,096, so it was
    **wire-legal**; and `firmware/examples/heap_session.rs` measured the allocator
    refusing at n=16 with the FIRST refusal in keygen requesting 4,256 B — before any
    consent screen. On device that is `handle_alloc_error` -> panic -> reset, and with
    `panic = "abort"`, RDP=2, no PIN UI and `sdcard_try_file` demanding an SE1 CHECKMAC
    (item 19), the reset loop is permanent. **One coordinator message would have ended
    the device.** Now bounded by `coldsnap_firmware::MAX_PARTIES = 12` at the
    `Keygen::Begin` arm, before the signer, together with `1 <= t <= n` — both
    coordinator-chosen. Pinned by
    `a_group_over_max_parties_or_a_bad_threshold_is_refused_before_the_signer`, which
    asserts **zero frames emitted** on refusal so the check must precede the work, and
    which catches removal of the bound, an off-by-one that would refuse a legal 12-of-12,
    and removal of the threshold check. `Begin` is the right and sufficient place: the
    other three keygen steps carry only a `keygen_id`, so a keygen refused at Begin
    cannot be advanced.

19. **Installing cold-snap on a unit at RDP=2 is ONE-WAY, and the SD-card path is
    not the general escape hatch it looks like.** Established from primary source
    2026-08-25, and it corrects a reassurance given earlier in this project's
    conversation. On a failed verify, `main.c:174-182` does: `psram_recover_firmware()`
    (helps only with reset pulses, not power-downs), then `if(!flash_is_security_level2())
    enter_dfu()`, then `while(1) sdcard_recovery()`. So **at RDP<2 DFU rescues you and
    the unit is fully recoverable**; at RDP=2 only the SD loop remains.
    And that loop will not install an arbitrary image: `sdcard_try_file`
    (`sdcard.c:248`) requires `verify_world_checksum`, which is
    `ae_checkmac_hard(KEYNUM_firmware, world_check)` (`verify.c:300-306`) — a CHECKMAC
    against a value held in **SE1**. The only thing that writes it is
    `pins.c`'s `ae_encrypted_write(KEYNUM_firmware, KEYNUM_main_pin, …)`, i.e. an
    upgrade **authorised by the main PIN** from logged-in MicroPython. So the SD path
    recovers a damaged copy of the firmware SE1 already blesses; it cannot bless a
    different one. Consequence for the bench: cold-snap has no PIN UI, no MicroPython
    and no upgrade path, so **once it is installed at RDP=2 there is no supported way
    to install anything else** — the unit becomes a permanent cold-snap unit. Read RDP
    FIRST (step 0 of the flash procedure: the bootloader's USART1 console on the RGT
    header at 115200 8N1 — an instant boot means RDP<2, a ~25 s "Danger!" bar means
    RDP=2). This does not change any code; it changes which unit you are willing to use.

17. **PARTLY CLOSED. The heap figures HAVE been re-measured against the shipping
    construction; what is still absent is any measurement on ARM.** **This item read
    "`heap::MEASURED_PEAK_BYTES` (48,166) and `MEASURED_LIVE_BYTES` (18,036)" until
    2026-09-10** — both constants had already moved. They are **54,496** and **17,844**,
    re-measured by `firmware/examples/heap_session.rs`, which drives the shipping
    `Session` over flash-backed `NonceAbSlot`s, i.e. the construction this item said had
    never been profiled. The peak went **up**, not down as the reasoning below predicted,
    and the reason is a corrected finding rather than a bigger workload: the hostile
    decode legs *do* stack on the live set. `heap_session` holds `Link::poll`,
    `comms::decode_body`, `Session::recv`, `Session::confirm` and the `staged_mutations`
    drain in one span with the `Outbox` undrained. Two further figures now exist that did
    not: a *simultaneous* live peak of **35,413 B** in at most 26 blocks (largest single
    block 7,200 B), and `MEASURED_ARENA_FOOTPRINT_BYTES` = **60,512** — a real
    `linked_list_allocator` high-water figure, 5,024 B under `HEAP_BYTES`, which is what
    actually constrains the budget now. The original 48,166/18,036 pair was measured on a
    64-bit host driving `FrostSigner::new_random` + `MemoryNonceSlot`, neither of which is
    on the device path any more. The shipping `Session` uses flash-backed `NonceAbSlot`s, whose state
    lives on flash rather than the heap, so live bytes plausibly FALL. **That reasoning
    was right in direction and small in size** — 18,036 → 17,844, i.e. 192 B, not the
    material fall it implied — and it is now a measurement rather than an argument:
    `firmware/examples/heap_session.rs` is the firmware-side harness this item asked for
    and it exists. `hal/examples/heap_profile.rs` / `heap_lifo.rs` still drive the old
    construction and are kept for the *shape* of the figures (n-independent live,
    +112 B per nonce slot), not as the current numbers. What HAS been measured is the
    dispatch's own addition:
    `heap::OUTBOX_CEILING` = 4 × 2,040 = **8,160 B**, the encoded frames a 4-stream
    nonce replenishment parks until drained, and it is now IN the binding assert —
    which had omitted the largest single new heap consumer. Slack fell 18,828 →
    **10,860 B** (17,844 + 8,192 + 20,480 + 8,160 = 54,676 ≤ 65,536; this figure read
    10,668 until 2026-09-10, against the pre-re-measurement live set).

    **What is STILL OPEN, and it is now the only part:** every figure above is a
    **64-bit host** measurement. Nothing has run on ARM, and nothing can —
    `cargo test --target thumbv7em-none-eabihf` cannot build a single test
    (`E0463: can't find crate for 'test'`; libtest needs std), so the 565 host tests can
    never execute on the target. **And the "32-bit should make the host figures
    conservative" direction is weaker than it looks:** `secp256kfun` reaches the curve
    through `k256`, whose `FieldElement10x26` (32-bit) and `FieldElement5x52` (64-bit)
    are both exactly 40 B, so `Point` is 120 B on **both** widths and the dominant
    consumers do not shrink at all. Expect the 32-bit figures to be close to these, not
    comfortably below them. Closing this needs the bench, not another host harness.

18. **Nonce durability across a power cycle is unit-tested only.** Nonce state is
    written through the real flash-backed `NonceAbSlot` at `FS_NONCE_OFFSET` during
    the harness run, and the verified signature could not exist otherwise. The
    harness's restart still happens BEFORE keygen — but **the stated reason, "because
    nothing persists a completed share yet", stopped being true and this item carried
    it until 2026-09-10.** `firmware/src/store.rs` persists the keygen triple to
    `FS_SHARE` and `Session::open` (`firmware/src/lib.rs`) replays it through
    `FrostSigner::apply_mutation`; §10's own trajectory lists "362,288 B once …the
    persistent share store landed". So the restart placement is now an inherited
    default rather than a limitation, moving it after keygen is possible, and that is
    the obvious next step for this item — along with the matching stale rationale in
    `firmware/examples/stub.rs`. Reload of a nonce
    stream after a reset is covered by
    `signer_reconstructed_from_flash_keeps_device_id_and_nonce_stream` and nowhere
    else — untested across a process boundary and untested on silicon.

15. **The UI ships ONE glyph table at TWO sizes where §4.2 specifies three faces;
    exactly one face — `FontTiny` — is genuinely absent.** `hal/src/ui.rs` carries a
    single 768-byte table (MicroPython `petme128` 8×8, MIT) rendered two ways: 8×8 →
    16 cols × 8 rows, and `Frame::text_2x` integer-doubled to 16×16 → 8 × 4, via a
    16-byte nibble lookup and **no second glyph table**. Against §4.2's measured
    `FontSmall` 7×14 → 18×4, `FontLarge` → 12×3 and `FontTiny` 4×6 → 32×10, that
    means `FontLarge`'s *purpose* is served (see the 2026-08-25 resolution below) and
    `FontTiny` is the only face with nothing standing in for it. **The heading of this
    item said "three … and the missing one is the security-relevant one" until
    2026-09-10** — self-contradictory once its own body records `FontLarge` as
    resolved, since the security-relevant face is the one that *shipped*.
    Two consequences matter. **Columns went 18 → 16**, so a
    screen §4.2 called "fits" may now hit the refusal path — no truncation, but a
    capacity regression against the plan. And **there is no `FontLarge`**, which
    §4.2 asked for on screen 2 by name ("8 hex chars in `FontLarge`") because the
    keygen check code is read *aloud* and compared across every device — that
    comparison is the whole anti-MITM defence. **Resolved 2026-08-25 for screen 2:**
    `Frame::text_2x` gives `FontLarge`'s 16 px line by integer-doubling the existing
    glyphs, for a 16-byte lookup table and no new glyph data, and `keygen_check` now
    uses it. Because a 2× glyph is 16 px wide, 8 characters is exactly the 128 px
    panel, so the code is drawn as two 4-character groups on separate lines — which
    also reads aloud better. **What remains open is only the human half:** whether
    16 px is legible *enough* on a physical OLED cannot be settled by a host test. It
    needs an eye on screen 005 of `cargo run -p coldsnap_hal --example ui_render`,
    then a bench confirmation. The 16-vs-18 column point above stands unchanged.

    **`FontTiny` is still absent and is NOT scheduled — a recommendation, not a
    decision, recorded 2026-09-10 so it stops reading as an outstanding chore.** It is
    the only §4.2 face with no substitute, and adding it is not free the way `text_2x`
    was: 4×6 needs a genuinely *second* glyph table (~96 new glyphs of `.rodata`) and a
    second blitter path, because nothing about the 8×8 table can be scaled *down*. The
    two screens §4.2 wanted it for no longer want it: screen 5 (backup display) is
    paginated and its rows carry `mark_sensitive` noise that a 4-px glyph would compete
    with, and screen 8 (address verification) is now IMPLEMENTED and
    draws a 62-or-64-char bech32m address across four rows, so it is the ONE screen with
    a real argument for a narrower face (item 16). **This clause read "is **refused** by
    the dispatch, so it has nothing to draw" until 2026-09-12.** It still does not change
    the decision: the legibility question is the bench's, not a host test's. And the only question that would justify it — whether a
    4-px-wide glyph is legible at all on this OLED — cannot be answered by any host
    test, which makes it the wrong thing to build before the bench. The 8×8 cell already
    gives 128 characters per screen against `FontSmall`'s 72, so capacity is not the
    argument either. Decide it with an eye on the panel, not from here.

16. **CLOSED 2026-09-12 — ALL EIGHT §4.2 screens have real callers, and screen 8 was
    the last one.** `Session::verify_prompt` and `prompt_screen_at`'s
    `DeviceToUserMessage::VerifyAddress` arm now draw `ui::address_verify` (ce62444), so
    `coldsnap_hal::ui::address_block` is a standalone OUTLINED symbol at 248 B in the
    linked image where it previously had none. `pin_entry` is still gc-sectioned out and
    that is still correct — there is no PIN.

    **WITHDRAWN 2026-09-12. This item read, until then:** *"PARTLY CLOSED 2026-09-10 —
    SEVEN of the eight §4.2 screens have callers. … Screen 8, **address verification**,
    has no caller: `ui::address_verify` is referenced only by
    `hal/examples/ui_render.rs`, `firmware/examples/simulator.rs` and the test
    `address_verify_is_refused` (`firmware/src/lib.rs`'s tests) — and `llvm-nm
    --defined-only` finds **zero** `address_verify` or `pin_entry` symbols in the linked
    image, so both are still gc-sectioned out. That is consistent, not a bug: the
    dispatch **refuses** `ScreenVerify` with `Refusal::AddressVerify`
    (`firmware/src/lib.rs:1165`), so the screen has nothing to draw for."* Every clause
    of that is now false: the dispatch ADMITS `ScreenVerify::VerifyAddress`, the
    `llvm-nm` zero-symbol evidence no longer reproduces for `address_verify`, and the
    test it cites was RENAMED to
    `verify_address_for_a_key_this_device_does_not_hold_is_refused`.
    `Refusal::AddressVerify` now means one thing only: `FrostSigner::wallet_network` for
    that `master_appkey`'s `KeyId` returned `None`, i.e. the device does not hold the key
    or the key's purpose is not `KeyPurpose::Bitcoin(..)`. The new screen returns
    `Shown::Info` — drawn, authorises nothing, prints no confirm digit — and
    `Session::confirm_at` refuses it through an untouched arm.
    Until 2026-08-25 `boot()` referenced neither `ui` nor `display`, so
    `--gc-sections` dropped both entirely: **0** symbols, and the image was
    byte-identical at 99,684 B before and after ~3,000 lines of UI — the same trap
    that made it read 11,604 B before `comms` was wired in. Wiring the identity-hold
    screen (§9 item 14) fixed that for the parts it reaches: **101,416 B = 7.11%**,
    `+1,732 B`, of which `.rodata` `+924 B` is the **measured** font-table cost
    against the 768 B source count. What is still dropped is everything nothing
    calls yet — sign approval, backup display and entry, address verification (which
    stayed dropped until 2026-09-12), the quiz. **Substantially closed 2026-08-25:** a real `FrostSigner` in `boot()` took
    the image to **282,080 B = 19.79%**, a 2.78× jump, with `rust-bitcoin` going 1 → 14
    symbols. Proof it is `boot()` that pulls it in: deleting the single `session.recv`
    call drops `.text` by 142,916 B and `bitcoin` back to 1. **Fully closed
    2026-09-10 at 376,752 B = 26.43%:** every §4.2 screen now has an honest caller,
    the quiz included, so nothing in `ui` is gc-sectioned out any more. `quiz.rs` is
    the cleanest illustration of the trap in this file — its author measured it at
    **+0 B** while it compiled and tested but nothing called it, then it cost
    **+2,304 B** the moment a dispatch arm referenced it, without one line changing.
    Measure after wiring, never before.

25. **Four features are code-verified ABSENT as of 2026-09-10, and this item exists so
    that absence is a recorded state rather than an oversight. NOTHING BELOW IS
    DECIDED — these are recommendations awaiting a call.** Measured by grep over
    non-comment `hal/src` and `firmware/src`: zero references to IWDG/WWDG, zero to
    wipe or decommission, no time source, no MPU or stack guard.

    **(a) IWDG watchdog — RECOMMEND: land the reset-cause plumbing first, do not
    enable the peripheral yet.** Facts established: the Mk4 bootloader does **not**
    enable IWDG (`HAL_IWDG_MODULE_ENABLED` is commented out in
    `mk4-bootloader/stm32l4xx_hal_conf.h:60`, and there is no `IWDG` register write
    anywhere in that tree), and Coldcard's own MicroPython firmware does not either —
    zero hits across `stm32/COLDCARD_MK4/` and `shared/`. So nothing forces a kick on
    us and nothing stops us adding one. Starting it needs no clock setup (writing
    `0xCCCC` to `IWDG_KR` force-enables LSI) and cannot be undone except by reset. Max
    period is **32.77 s** (`PR` = /256, `RLR` = 4095, LSI ≈ 32 kHz).

    **The blocking interaction is with the panic counter, and it is the reason not to
    just switch it on.** `hal/src/panic.rs` never reads `RCC_CSR`, so the device cannot
    today distinguish a power-on from a software reset from a watchdog reset. An IWDG
    reset therefore would **not** bump the RTC counter, would never reach
    `past_threshold`, and would never reach `try_enter_dfu` — converting a *hang* into
    an **invisible, unbounded reset loop**. That is the exact failure class decision 6
    exists to prevent, and it would be harder to diagnose than the hang it replaces.
    So the first change is the one that is host-testable on its own merits: read
    `RCC_CSR`, decode `IWDGRSTF`/`SFTRSTF`/`PINRSTF`/`BORRSTF`/`PORRSTF`, write `RMVF`
    to clear, and fold a watchdog-caused reset into the counter. The decode is a pure
    function, so it pins exactly like `decode_counter` and `past_threshold` already do.

    **Only then choose a period, and choose it against a measured signing latency.**
    Every spin limit in the tree is comfortably inside 32.77 s — `FLASH_SPIN_LIMIT`
    50,000,000 volatile reads is ≈ 1.3-2 s at 120 MHz, and `MODE_SETTLE_SPINS` 6 M,
    `SAMPLE_GAP_SPINS` 2 M, `DISPLAY_SPIN_LIMIT`/`USB_SPIN_LIMIT`/`DRDY_SPIN_LIMIT`
    1 M each are far below it — but **FROST signing latency is UNMEASURED (item 1)** and
    is the one operation that could plausibly approach tens of seconds on a 120 MHz M4.
    (**This read "`secp-lowmemory` signing latency is UNMEASURED" until 2026-09-13.** The
    concern is unchanged and the attribution is: `secp-lowmemory` is provably inert for
    this image — 0 bytes, measured — so the cost, if any, is in `secp256kfun`'s
    `field_10x26`/`scalar_8x32`, which no feature flag reaches.) A watchdog whose window a legitimate signature can exceed kills
    the device mid-signature, and if that turns out to be the case the fix is not a
    longer period (32.77 s is the ceiling) but a kick *inside* the signing loop —
    i.e. threading one through vendored `frostsnap_core`, a far larger change than
    enabling a peripheral. Note the **NO TIMEOUT** rule on the backup reveal, the quiz
    and word entry is *not* in tension with this: the event loop keeps polling while a
    human reads, so it can kick freely, provided the kick is unconditional in the loop
    and never gated on protocol progress. What an IWDG genuinely buys is the one
    failure decision 6 cannot reach — a hang rather than a panic, including the window
    before `VTOR` is set. What it costs is one-way-per-boot behaviour that no tier
    below silicon can test at all.

    **(b) Wipe / decommission — RECOMMEND: do not build.** `hal/src/callgate.rs` binds
    six calls (`read_rng`, `try_enter_dfu`, `check_pin_subcall`, `pin_setup_attempt`,
    `read_counter0`, `read_mcu_key_usage`) and deliberately not `fast_wipe`. It is
    hardware-blocked in the strong sense — decision 2 records that the callgate is
    PCROP code testable at no tier — it is destructive and one-way, and its natural
    trigger is a PIN/duress policy, which is **PUNTED** (§5). Worth recording rather
    than leaving implied: the device is not merely missing a wipe, it **refuses to be
    told to erase** — `CoordinatorSendBody::DataErase` returns `Refusal::DataErase`
    (`firmware/src/lib.rs:994`) and `hostcheck` forges one at all nine devices and
    fails unless every one refuses it and can still sign.

    **(c) A time source — RECOMMEND: do not add one, and write down why SysTick is not
    available.** SysTick **is running** — the bootloader programs it at 1 ms with
    `TICKINT` clear (`mk4-bootloader/clocks.c:66-72`) — but it is **owned by the
    callgate**, which polls `COUNTFLAG` for SE1 timeouts (`ae.c:96-100`,
    `delay.c:16-22`) and writes `SysTick->VAL = 0`. Reading `SysTick->CTRL` *clears*
    `COUNTFLAG`, so a firmware clock built on it would silently steal the callgate's
    timing. That trap is **already documented where an implementer will meet it** —
    `firmware/src/entry.rs`'s "Deliberately NOT here" list says SysTick is untouched,
    that COUNTFLAG clears on read, and that touching it "silently breaks every SE
    operation" — so nothing needs adding there; it is recorded here only because this
    item is where someone will come looking for a clock.
    Nothing in the current design needs a clock, and the two places that
    might were deliberately decided against one: the reveal/quiz/entry have **no
    timeout by choice**, and every spin limit is a *count* rather than a duration
    precisely because there is no clock (`MODE_SETTLE_SPINS` is documented as the first
    bench knob). Adding a clock would invite converting those counts to durations,
    which is a behaviour change on unverified silicon. If one is ever needed it should
    be DWT `CYCCNT` (free-running, 32-bit, wraps at 35.8 s at 120 MHz, needs
    `DEMCR.TRCENA`, collides with nothing) — and the first thing to establish at the
    bench is whether `CYCCNT` increments at all at RDP=2, since it is debug
    infrastructure.

    **(d) An MPU stack guard — RECOMMEND: do not add an MPU region; a canary is the
    right shape if anything is wanted, and even that is probably premature.** Armv7E-M
    has no `MSPLIM` (that is Armv8-M), which `firmware/src/main.rs` already says. The
    reason an MPU region is the *wrong* mechanism on this core is specific: a no-access
    guard faults on the offending access, but exception entry then stacks 32 B (104 with
    FP state) *below* the faulting SP — inside the guard — so the stacking itself
    faults, escalates to HardFault, whose entry stacks again and also faults, and the
    core **locks up**. Lockup is no reset at all, i.e. strictly worse than today under
    decision 6. The shape that composes with decision 6 instead of defeating it is a
    **canary**: a small `[u32; 8]` at the bottom of the stack's travel, written at boot
    and checked once per event-loop iteration, with a mismatch as `panic!()` → the
    existing counted reset. Its check is a pure function, so it is host-testable, and it
    has no lockup mode. But the measured margin argues for deferring even that: the
    runway is **548,776 B** (`ESTACK_TOP 0x2009_e000` − `_end 0x2001_8058`), the largest
    single stack object is the 4 KiB `comms::Link`, then `ui::Frame` at 1,024 B and the
    signer at 272 B, and the only recursion in the tree is `Outbox::push` at depth 2 by
    construction. That is a ~100× margin with no unbounded recursion. Build the canary
    when a stack-depth measurement says the margin is not 100×, not before.

---

## 10. Provenance

| Item | Value |
|---|---|
| Frostsnap commit | `0bbc18be3f9fb0a408b0c47a021816ece97f4661` (2026-08-11) |
| Frostsnap license | MIT — Nick Farrow, Adam Mashrique, Lloyd Fournier |
| Coldcard commit | `0431fd2b` |
| Coldcard license | MIT (firmware); `hardware/` proprietary, non-commercial |
| Rust toolchain | 1.88.0 (upstream pin) + `thumbv7em-none-eabihf` |
| C cross-compiler | clang 21 (`/opt/homebrew/opt/llvm/bin/clang`) — still required, decision 4 |
| Decisions record | [DECISIONS.md](DECISIONS.md), dated 2026-08-12 |
| Flash, as built | **899,400 B = 63.1%** of `FLASH_TEXT` as an rlib sum, re-measured in a clean target dir **2026-09-10** (**this row read 860,898 B = 60.4% until then**, which was the 2026-08-19 figure, taken before the UI, the keypad, the share store, 25-word entry, the quiz and the `coldsnap_firmware` crate existed; the two C-secp and rust-bitcoin components are byte-identical, and the whole +38,502 is `libcoldsnap_hal.rlib` 15,873 → **30,627** plus `libcoldsnap_firmware.rlib` **21,000**, a crate absent from every earlier row — **plus `liblinked_list_allocator` 2,748 B. SETTLED 2026-09-13, residual ZERO. This read *"the two deltas sum to 35,754 (14,754 + 21,000), so 2,748 B of that +38,502 is UNATTRIBUTED. Flagged 2026-09-12 rather than reconciled by invention: … so either the hal delta is understated or a third rlib moved. Re-run `tools/measure-flash.py` into a CLEAN target dir before quoting the split"* until then.** It is a THIRD rlib, and it is the global allocator: `liblinked_list_allocator-385fcb8155824808.rlib` = 1,762 `.text` + 986 `.rodata` = **2,748 B**, so 14,754 + 21,000 + 2,748 = **38,502** against a recorded delta of 899,400 − 860,898 = **38,502**, residual **0**. Each component's own internal split still checks (27,636 + 2,991 = 30,627; 18,912 + 2,088 = 21,000). Command, in a PRIVATE target dir so the shared `target/` was untouched: `CARGO_TARGET_DIR=/tmp/cs-rlib-clean CARGO_PROFILE_RELEASE_LTO=false cargo build --release` (exit 0, 50 rlibs) then `python3 tools/measure-flash.py '/tmp/cs-rlib-clean/thumbv7em-none-eabihf/release/deps/*.rlib'` (exit 0). **The exact match is an inference and not a coincidence, because the CAUSE is airtight:** `linked_list_allocator` reaches the RELEASE rlib set by exactly ONE normal dependency edge, `firmware/Cargo.toml`'s `[dependencies]` section; `hal/Cargo.toml` declares it under **`[dev-dependencies]`**, which `cargo build --release` never builds. So it entered the graph precisely WITH `coldsnap_firmware` — the crate this very sentence calls "absent from every earlier row". **The sentence named the new crate and missed the transitive dependency that new crate brought with it**, which is why the residual was exactly one third-party rlib and not a diffuse rounding error. The version is pinned `=0.10.6`, so its 2,748 B today IS its 2,748 B on 2026-09-10 — that pinning is what makes the reconciliation exact rather than approximate — and the old instruction to re-run `measure-flash.py` "before quoting the split" is DELETED because it is DONE, not pending. **AND A TRAJECTORY ROW, NOT a correction of the figure above: today's clean re-measure is 899,707 B = 63.1%**, with `libcoldsnap_hal` 30,644 (27,662 + 2,982), `libcoldsnap_firmware` 21,290 (19,196 + 2,094) and **50** rlibs, against the recorded 30,627 (27,636 + 2,991) / 21,000 (18,912 + 2,088) / "a clean 48"; group rows C secp256k1-sys **96,947 = 6.8%**, rust-bitcoin + encodings **327,408 = 23.0%**, frostsnap + pure-Rust crypto **475,352 = 33.3%**. The +307 B and the +2 rlibs are the tree MOVING since 2026-09-10 (address verification, ce62444), not a defect in the old row, and the 63.1% headline is unchanged. **Do NOT overwrite 899,400 with 899,707 as if the old figure were wrong** — this repo's convention for a later tree is a trajectory row, not a correction.). Headroom on that sum is **526,008 B**. Earlier: 860,898 on 2026-08-19 (844,229 at phase 0; +5,101 panic sites, +253 for §8.1 defects 10–12, **+15,873 `coldsnap_hal` rlib** — of which **+3,467** is phase 3's `comms.rs` + `usb.rs` — less −4,482 instantiations that moved between rlibs; all with LTO off, so upper bounds). **THAT BREAKDOWN DOES NOT CLOSE, and it is stated rather than adjusted: 5,101 + 253 + 15,873 − 4,482 = 16,745 against 860,898 − 844,229 = 16,669, a residual of −76 B.** Confirmed by addition 2026-09-13. `AUDIT-2026-09-10.md:713-714` found the same 76 B and prescribed correcting the −4,482 term to −4,558; that prescription was applied nowhere, and it is NOT applied here either, because the per-rlib table that would justify moving that particular term was never recorded and any named term would be fabricated. **The residual is the artifact.** Same treatment as README's larger hole in the same family — see README "Flash budget". **SETTLED AS TO LOCATION 2026-09-16 by REBUILDING THE ROOT COMMIT, and the 860,898 row is now CORROBORATED rather than merely recorded.** `73695f1` (2026-08-26) is the repo's only root commit (`git rev-list --max-parents=0 --all`), it builds clean on the same `1.88.0` pin, and it measures **880,024 B = 61.7%** with `libcoldsnap_hal` **25,667** (23,286 `.text` + 2,381 `.rodata`), `libcoldsnap_firmware` **6,584** (5,934 + 650) and `liblinked_list_allocator` **2,748**. Commands: `git worktree add --detach /private/tmp/cs-hist-aaaaaaaaaaaa 73695f1` (exit 0) — a path of **33 characters, the same length as the main checkout's**, because panic `Location` strings embed it — then `CARGO_TARGET_DIR=/private/tmp/cs-t-init CARGO_PROFILE_RELEASE_LTO=false cargo build --release` (exit 0) then `python3 tools/measure-flash.py '/private/tmp/cs-t-init/thumbv7em-none-eabihf/release/deps/*.rlib'` (exit 0; 50 rlibs on disk, 43 with allocatable sections). **The calibration that makes the comparison legitimate:** HEAD built and measured the same way at the same path reproduces **899,707** and every single component of the trajectory row above — 30,644 (27,662 + 2,982), 21,290 (19,196 + 2,094), 2,748, and the group rows 96,947 / 327,408 / 475,352 — to the byte. `tools/measure-flash.py` is byte-identical at `73695f1` and HEAD (`git show 73695f1:tools/measure-flash.py | diff - tools/measure-flash.py`, exit 0), and `vendor/frostsnap/` is byte-identical across the ENTIRE history — not merely at the endpoints: `git log --oneline -- vendor/frostsnap/` returns exactly ONE commit, `73695f1` itself, so no commit has touched a vendored source since the tree was first committed (`git diff --stat 73695f1 2956a39 -- vendor/frostsnap/` is empty as well) — so **of the 43 size-bearing rlibs exactly TWO move between the root commit and HEAD** — `coldsnap_hal` +4,977 and `coldsnap_firmware` +14,706, summing to 19,683 against a measured 899,707 − 880,024 = **19,683**. **THE KEY QUANTITY: the third-party rlib sum is an INVARIANT 845,025 B, measured two independent ways** — by subtraction at both trees, and directly by `cargo build --release -p frostsnap_core -p frostsnap_comms -p frostsnap_embedded -p frost_backup` at the root commit into `/private/tmp/cs-t-vend` (exit 0), which measures `ALL, as built` = **845,025** on the nose. All four totals in this row then decompose over it with residual **ZERO**: 845,025 + 15,873 + 0 + 0 = **860,898**; 845,025 + 25,667 + 6,584 + 2,748 = **880,024** (measured); 845,025 + 30,627 + 21,000 + 2,748 = **899,400**; 845,025 + 30,644 + 21,290 + 2,748 = **899,707** (measured). **CONSEQUENCE 1 — "taken before … the `coldsnap_firmware` crate existed" and "a crate absent from every earlier row" are CONFIRMED, not refuted.** Had `coldsnap_firmware` or `linked_list_allocator` carried one byte at the 860,898 measurement, that first decomposition could not land on zero; and the same identity re-derives the 2,748 settlement above independently of the dependency-edge argument. The root commit is NOT the 860,898 tree (880,024 ≠ 860,898, a gap of 19,126 = 9,794 hal + 6,584 firmware + 2,748 allocator, residual zero), so the 2026-08-19 tree is **not in git and never was** — a review hypothesis that `73695f1` might BE it, on the strength of that tree's README presenting 860,898 and 15,873 as current, is **disproved by measurement**: those docs were ALREADY STALE at the first commit, by 19,126 B on the total and 9,794 B on the hal rlib. **CONSEQUENCE 2 — the −76 B is confined to ONE term, and it is NOT the −4,482.** The third-party leg of this row's chain reads 844,229 + 5,101 + 253 − 4,482 = **845,101** against the measured invariant **845,025**, so the whole 76 B sits in the third-party terms and NOT in the +15,873 or the 860,898, both of which the identity confirms exactly. Within those terms: 844,229 + 5,101 = **849,330**, which `vendor/README.md` records independently in its own words, and 849,330 − 4,482 = **844,848**, which is `vendor/README.md`'s independently-recorded "vendored crates only" ledger row **to the byte** — so `844,229`, `+5,101` and `−4,482` all close on a figure this row never cites, residual zero. `AUDIT-2026-09-10.md:713-714`'s prescription to correct `−4,482` to `−4,558` is therefore **REFUTED, not merely unapplied**: moving it would break a three-figure identity that currently closes exactly. What is left is the interval the `+253` term covers, where the measured vendored movement is **844,848 → 845,025 = +177** and the chain supplies **+253**; **253 − 177 = 76**, exactly the residual. **The 76 B is the `+253` term's, and the term is NOT adjusted here, because the 76 cannot be split between the two readings that both fit:** either 76 B of the 253 is `coldsnap_hal` and double-counted — README describes the term as "the three `Option`-returning fixes in `bitcoin_transaction.rs` plus one `saturating_sub` in `flash.rs`", `flash.rs` IS `coldsnap_hal`, its bytes are already inside the +15,873, and `vendor/README.md` measures the 253 as a whole-workspace delta 856,872 → 857,125 in a build that includes `-p coldsnap_hal` — or the 253 is wholly vendored and a separate −76 B of vendored movement occurred in the same interval. Both close. The tree behind `844,848` predates the root commit and is not in git, so **nothing in this repository can pick, and the residual stays stated.** (**The sub-term read +3,461 until 2026-09-13**; `vendor/README.md` carries the per-change split with a table row behind it — `libcoldsnap_hal.rlib` 15,565 = 14,612 `.text` + 953 `.rodata`, up from 12,098 = 11,420 + 678, so +3,467 = its own 860,592 − 857,125 — and README.md's "Flash budget" already names that file as the authority for exactly this split. The competing set closes internally too (14,606 + 953 = 15,559 → +3,461 → 860,586), so ARITHMETIC CANNOT PICK; the phase-3 tree can no longer be rebuilt, so the 6 B is **unresolvable** and the choice is made on designated authority, not on evidence. Recorded rather than picked silently. **CLOSED PERMANENTLY 2026-09-16, and now on PROOF rather than on a hedge.** `73695f1` is the repo's ROOT COMMIT and it already carries BOTH competing sets: `15,559`, `14,606` and `860,586` in `README.md`, `15,565`, `14,612` and `860,592` in `vendor/README.md`, all present in that one tree (`git grep -c -F '15,559' 73695f1` → `README.md:1`; `git grep -c -F '15,565' 73695f1` → `README.md:1`, `vendor/README.md:2`; likewise `14,606`/`14,612` and `860,586`/`860,592`). So the disagreement PREDATES the first commit: there is no earlier tree, no earlier diff and no earlier message in this repository, and therefore no artefact anywhere in it that could adjudicate which `.text` figure was typed from a measurement and which was typed from the other document. The root commit measures **880,024 B** (above), so it is not the 857,125 tree either. **The provenance question is not open, it is unrecoverable** — which is a better recorded outcome than "unresolvable, adopted on authority", and the authority-based choice stands unchanged because it is now the only choice available.) **This row read 893,099 B = 62.7% until 2026-08-19**, on the strength of a +32,513 B growth attributed to `comms::decode_body`; that does not reproduce clean and is retracted — see README "Flash budget". The live `./target` glob measures 1,311,110 B = 92.0% from 131 rlibs against a clean 48, which is the artefact to suspect first.  **The linked image is measured, and the rlib sum above overestimates it by ~2.4×:** `firmware/` links at **379,648 B = 26.6343%** of `FLASH_TEXT` (`/usr/bin/objdump -h` after `cargo build --release` — `.vector_table` `0x40` + `.text` `0x4e7e0` + `.rodata` `0xe2bc` + `.data` `0x24`; re-measured 2026-09-12 in the MAIN checkout after the four-lane merge; margin **1,045,760 B**), because LTO plus `--gc-sections` keeps only what is reachable. **The ratio in this sentence read `~2.9×` until 2026-09-12 and was simply wrong arithmetic** — 899,400 / 377,256 = 2.384, and README's "Flash budget" said `2.39×` in the same document set; against today's image it is 899,400 / 379,648 = 2.369. **The image read 377,256 B = 26.47% until 2026-09-12** (and 377,192 B = 26.46% at 2026-09-11, 376,752 B = 26.43% at 2026-09-10). **Do NOT take an absolute image figure from a report written in a worktree under `.claude/worktrees/`:** the longer absolute path is embedded ~11 times in panic `Location` strings and inflates `.rodata` by ~424 B while leaving `.text` and `.bss` exact — see the traps note in §9 item 22's neighbourhood. Three of this round's four lanes reported 377,680 B for an unchanged image for exactly that reason, and one of them concluded the 377,256 record was stale. It was not. `llvm-nm` finds **190** frostsnap/secp/schnorr/bitcoin symbols (frostsnap 118, bitcoin 34, schnorr 28, secp256k1 22) and **22** `coldsnap_hal::ui` symbols, re-measured 2026-09-10 — **this pair read 267 and 17 until then** and neither reproduced; README carried the same pair, so both were copied rather than re-derived. The trajectory, each step a real caller appearing rather than a code addition: 11,604 B when `boot()` polled USB but touched no `comms` · 94,304 B with `Link::poll` + `decode_body` · 99,684 B with `identity` · 101,416 B once the identity-hold screen gave `ui`/`display` a caller · 282,080 B once a real `FrostSigner` was constructed and dispatched to · 297,064 B once the remaining §4.2 consent screens got honest callers · 331,116 B with the keypad driver and real consent · 362,288 B once `DisplayBackup`, `mark_sensitive` and the persistent share store landed · 372,688 B once 25-word entry made restore possible · 376,752 B once `CheckBackup` became a real 8-question quiz behind its own consent digit (+4,064 B: +32 B of `ui.rs` screens, +2,232 B when `firmware/src/quiz.rs` first acquired a caller and its generics were instantiated, +1,800 B for the `main.rs` event-loop arm) · **377,192 B** once the keygen check stopped printing a fixed `1=match` and started printing the randomised `press_legend(confirm)` (+440 B: a `Buf<16>` legend build and a call replacing a 12-byte literal). · **377,256 B** once `reveal_draw` hoisted the reveal's screen/cursor pairing out of `boot` into a value-tested module item (§9 item 22) and the three restoration consent screens started REFUSING a row that does not fit instead of drawing a clipped one (+64 B net: +104 B for those two, less 40 B when the review round deleted a vacuous legend-length comparison and turned an early `return` into a value). · **379,648 B** once address verification stopped being refused and got a real caller (`Session::verify_prompt` + `prompt_screen_at`'s `VerifyAddress` arm, ce62444): **+2,392 B**, `.text` +2,352 and `.rodata` +40, attributed symbol by symbol with `llvm-nm --print-size` over both images rather than predicted — +1,366 B `coldsnap_hal::comms::Link::drain` (the new `verify_prompt` and dispatch arm, inlined: THIS is the feature), +1,298 B `<bitcoin::Address as Display>::fmt` and +248 B `coldsnap_hal::ui::address_block` becoming OUTLINED shared symbols, less 668 B as `coldsnap_firmware::prompt_screen_at` gave up its inline copies of both. So ~878 B of it is outlining rather than new functionality. NOT a new dependency edge: `bitcoin::address::Address::from_script` is byte-identical at 342 B in BOTH images, so it was already linked, and no BIP-32 HMAC-SHA512 chain appears — `derive_xonly_key` and `bip341_taptweak_key_only` were already reachable through `sign_ack`. Zero new crates; `bitcoin =0.32.8` was already a non-optional dependency of `frostsnap_core`. That +440 was DISPUTED on review as +444, and **the dispute is SETTLED as of 2026-09-12: BOTH readings were correct and neither party named the cargo invocation.** `cargo build --release` gives `.text 0x4de70` (377,192 B); `cargo build --release -p coldsnap_firmware` gives `.text 0x4de74` (377,196 B). Reproduced in a CLEAN private target dir, both figures, both stable, and the two artifacts' `-C metadata` hashes are the same there as in the live tree — the 0x4de74 binary was still on disk at `target/thumbv7em-none-eabihf/release/deps/`. CAUSE, measured rather than hypothesised: `frostsnap_comms` is a WORKSPACE MEMBER, so the all-members build compiles it with its own `default` feature while `-p coldsnap_firmware` compiles it only as a dependency, where the workspace dep says `default-features = false`. `default = []` has NO CODE BEHIND IT, so the two units compile IDENTICAL source and differ only in the metadata hash cargo derives from the feature list — which changes every generic instantiation's symbol hash, hence function ordering under `lto = "fat"`, hence inter-function ALIGNMENT PADDING. Both binaries hold exactly **807 `.text` symbols totalling 318,780 B of code**; the difference is 312 B of padding against 308 B, and ZERO bytes of code. `.rodata`, `.data` and `.vector_table` are byte-identical. `firmware/link.x`'s `.text : ALIGN(4)` quantises the section, so the smallest observable difference is exactly 4 B. **CONSEQUENCE FOR THE RECIPE, and it is the actionable part: a flash figure is only meaningful with its invocation named.** Every figure in this document is the `cargo build --release` side, which is what README's "Test" section runs. **RE-MEASURED 2026-09-17 and the gap has GROWN with the tree, which is the part that makes this trap expensive: at `311a41b` the all-members build is `.text 0x4e7e0` + `.rodata 0xe2bc` = 379,648 B and `-p coldsnap_firmware` is `.text 0x4e7e4` + `.rodata 0xe2c4` = 379,660 B, a difference of 12 B (`.text` +4, `.rodata` +8) against the 4 B recorded above for the 377,192 tree.** So the two invocations no longer differ by one alignment quantum alone, and `-p coldsnap_firmware` now reads **12 B over** every figure in this document. This was paid for rather than reasoned: a verification pass measured 379,660 with `-p coldsnap_firmware`, concluded the recorded 379,648 was stale, and bisected all thirteen commits from `9d199df` to `311a41b` in a length-matched worktree — every one of which measured 379,660 — before noticing that the sentence it was about to correct is the sentence that predicts the error. **A bisect that returns the same figure at every commit including the one that recorded a DIFFERENT figure is not evidence of drift; it is evidence the recipe differs**, and that is the shape to recognise before spending the builds. Also settled by the same experiment: "incremental readings have disagreed by 4 B" does NOT reproduce — two clean builds in separate private target dirs and the in-tree incremental build produced a BYTE-IDENTICAL ELF (sha256 `938d317f56…`), so under `codegen-units = 1`, `lto = "fat"`, `incremental = false` this build is bit-for-bit reproducible. `.bss` is byte-identical across all of it at `0x2000_8034..0x2001_8058`, and nothing on the quiz path allocates, so the ~5,024 B arena margin is unchanged. **This cell said "`EnterPhysicalBackup`, `SavePhysicalBackup`, `SavePhysicalBackup2`, `Consolidate` and the naming flows are refused rather than implemented (§9), so their code is absent" until 2026-09-10. All five are IMPLEMENTED and ADMITTED**, which is part of why the image is 376,752 B: `Session::recv` passes each of them through to the signer (`firmware/src/lib.rs:1106-1110` for the four restoration variants, `:935` for `Naming(NameCommand::Preview)`), each behind its own consent digit, with `ToUserRestoration::EnterBackup` and `ConsolidateBackup` handlers at `:1334` and `:1358`. What IS refused, and where the absent code actually is: `Upgrade` (`Refusal::FirmwareUpgrade`), `DataErase` and `Challenge` (the genuine check) — cited by SYMBOL, in **`Session::recv`**'s refusal arms in `firmware/src/lib.rs`. **That read `Session::recv_core` until 2026-09-17 and was measurably wrong:** the three arms are consecutive in `recv`'s own `CoordinatorSendBody` match, and `fn recv_core` begins BELOW the last of them (`grep -n` puts the `Upgrade` arm at :1039 and `fn recv_core` at :1047 today — the SYMBOL is the citation, the numbers are only how it was checked). `recv_core` does hold refusals, which is what made the mis-citation plausible, but they are two `Refusal::GroupTooLarge` returns and not these three. **`ScreenVerify` (address verification) was on this list until 2026-09-12 and is not refused any more** (ce62444, §9 item 16): the dispatch admits it, `Session::verify_prompt` draws the address, and the +2,392 B in the trajectory above is what it cost. So a PIN's SE1 paths are what remains bound-but-gc-sectioned, and address verification is no longer the ceiling. Read the rlib rows for the MARGINAL cost of a change, never as a prediction of image size. |
| Host tests passing | **576** = hal 288 (267 lib + 5 smoke + 16 integration) + firmware 172 (120 lib + 52 bin) + vendored 116 (`frostsnap_core` 63 + `comms` 10 + `embedded` 17 with `--features std`, 15 without + `frost_backup` 19 + `macros` 7), re-verified 2026-09-12 against every gate, all exit 0; **568** earlier the same day, before hal's integration file went 12 → 16 (`device_nonces`' post-write half: `SlotUnreadable`, the empty-`sessions` `Overflow` backstop, the cached-retry branch and the read-back `WriteVerifyFailed` comparison — 2a055f7) and `firmware/src/lib.rs` went 116 → 120 lib (address verification — ce62444; a fifth name in that commit is a RENAME of `address_verify_is_refused`, not an addition, which is why it is +4 and not +5, and hal stayed at 284 there because its scraper test was renamed and extended in place); **565** before the round before that's THREE new host tests (the consent-row fit refusal, its propagation through `prompt_screen_at`, and the reveal cursor's pairing); **530** before the `CheckBackup` quiz (+6 hal, +29 firmware); 357 before the gap-closing pass; 355 before the signing pipeline; 344 on 2026-08-25 before `FrostSigner`; the firmware gate is now a SUM of two `test result` lines, 11 lib + 14 bin; 341 on 2026-08-24, +40 for `ui.rs`; 268 until 2026-08-24, which never counted `coldsnap_firmware`'s 14; +19 for `identity`; 204 at the phase-2 gate, 253 at the end of phase 3, 261 before §9 item 7(c)'s three outer-leg tests, 264 before the three inner-leg `decode_body` tests, 267 before the pin on the vendored `MAX_MESSAGE_ALLOC_SIZE`; `frostsnap_core` no longer needs an allowlist, `frost_backup` still does — §7) |

Vendored crates live in `vendor/frostsnap/` with upstream commit recorded in
`vendor/README.md`, which also carries the local-modifications table. Changes are
kept mechanical so upstream can be rebased.

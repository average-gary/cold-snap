# cold-snap — a Frostsnap device on Coldcard Mk4 hardware

**Status:** **decisions made 2026-08-12** — the six architectural choices are
settled and recorded in **[DECISIONS.md](DECISIONS.md)** — seven now, 7 being the
`FRAME_LIMIT` reversal of 2026-08-18. Phases 0-4 are complete **on the host**:
phase 3's transport is written and host-verified, and phase 4's interop gate is met
by `hostcheck/` but **not signed off** (§8, §9 item 12). **No code has run on
hardware**, and nothing will before phase 5. This document is now the implementation plan of
record, not a proposal.
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
| `frostsnap_core` | 13,998 | **14,260** | ✅ | ✅ |
| `frost_backup` | 2,671 | 2,671 | ✅ | ✅ |
| `frostsnap_comms` | 1,679 | 1,679 | ✅ | ✅ |
| `frostsnap_embedded` | 881 | 881 | ✅ | ✅ |
| `frostsnap_macros` | 511 | 511 | — | ✅ |
| **Total** | **19,740** | **20,002** | | |

The +262 lines in `frostsnap_core` are the decision-3 change and its vector tests
(`vendor/README.md` local-modifications table). Everything else is byte-identical
to upstream.

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
comparison across feature flags, not the current size. Current, with phases 2 and
3 in: **860,898 B = 60.4%** (§10, and README "Flash budget" for the split). The
cost is slower EC operations (smaller precomputation window);
**signing latency on-device remains unmeasured** — see §9 "Genuinely open" item
1, now the highest-value open question.

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
| Panel | 240×280 ST7789 SPI | 128×64 SSD1306 **SPI1 @ 40 MHz**, CS `PA4` / RESET `PA6` / DC `PA8` (`shared/display.py:19-20,32-35,44`) |
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

The reusable ~850 LOC: `backup_model.rs` (398 — backup-entry state machine,
cursor/row/completed-rows), `string_ext.rs` (241 — no-alloc `StringFixed` with
wrapping), `widget_list.rs` (86 — pagination trait), `distractor.rs` (59 —
levenshtein BIP39 decoys for the backup quiz), `animation_speed.rs` (39).

**Not obvious, and worth exploiting:** the `Widget` *contract* is not
colour-bound. `Widget::Color` is an associated type (`lib.rs:230-232`),
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

Four security requirements that the renderer must not quietly drop:

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
touch surface — and page swipes become the `5`/`8` keys, matching Coldcard's own
mapping (`shared/lcd_display.py:23-26`). PIN entry wraps Coldcard's existing
`ux_show_pin` / `ux_show_phish_words` (`shared/ux_mk4.py:361-445,351-359`)
rather than being redesigned, since decision 2 keeps the gate semantics behind
them.

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
4. Past threshold → callgate selector 2, `arg2` 0 then 2.
5. Unconditional reset as final fallback, so it can never halt.

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
| 2 | `device_nonces.rs` write/sign path `:234, :235, :269, :278, :281, :298, :300, :307` | 8 of that file's 16 panic sites; each a reset-loop trigger. Convert to `Result`. |
| 3 | `frostsnap_embedded/src/ab_write.rs:44, :106, :109, :110, :118` | The panics that actually fire on real flash I/O errors, previously out of scope. `AbSlot::write` erases+writes **twice** (`:56-57`), so any STM32 flash error panics mid-A/B-update — the worst moment for nonce state. |

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
| `coldsnap_hal` | **`--features fake-flash,test-seam`** — 135 lib + 5 smoke + 11 integration | 88 → **151** |
| **Total** | | 204 → **268** |

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
  (`E0432`), a consequence of the vendored `default = []`. With it: **51 tests
  across 13 binaries, all passing** (40 across 11 before the panic-site work),
  including both wire-format backward-compat guards. `cargo test -p
  frostsnap_core --features coordinator` is the real invocation; `--lib` alone
  runs only 9 of the 51.
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
durability; `secp-lowmemory` signing latency; and — new in phase 3 — the OTG_FS
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

#### Three device-side caps: REQUIRED and UNIMPLEMENTED (phase 4)

**4,096 is necessary but not sufficient**, and this is the honest limit of what
phase 3 achieved. `FRAME_LIMIT` bounds what the device will *buffer* and what its
encoder will *emit* — nothing bounds what the device **constructs**. Three caps are
required, and **none is implemented**, because all three live in
message-construction code that does not exist in this tree: there is no event loop,
no bin target, and nothing calls `encode_frame` outside tests. No helper was
written for them either — a cap with no caller cannot be tested against the code
that will need it.

1. **One nonce segment per frame.** `NonceResponse` is unbounded in segment count
   (1 → 2,040 B, 2 → 4,038, 3 → 6,036), and the count is **not the device's own
   choice**: `device.rs:273-296` emits one segment per stream in the received
   `OpenNonceStreams`, so the coordinator picks it. The reply builder must emit one
   segment per frame. Pinned as a refusal today by
   `three_nonce_segments_are_refused_by_the_new_bound`.

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
2. **A `HeldShares2` cap.** 188 B + ~150 B per extra stored share, so ~26 stored
   shares overruns 4,096. **Device-emitted**, no coordinator involved.
3. **`Debug` truncation.** `WireDeviceSendBody::Debug`'s `String` is unbounded and
   is the one field whose length the device picks freely.

Until all three exist the device can build a frame over *any* bound and then have
its own encoder refuse it — a dropped message rather than a corrupt one, but a
functional failure the device caused itself. Nonce batch size therefore remains a
live protocol design constraint, not a theoretical one.

---

## 8. Phasing

Each phase ends at a testable artifact. No hardware until Phase 5.

| # | Phase | Deliverable | Gate | Status |
|---|---|---|---|---|
| 0 | Vendor + prove build | crates compile for `thumbv7em`; fits flash | build green, **844,229 B = 59.2%** | ✅ **done** |
| 1 | Drop `libsecp_compat_0_29` (decision 3) | `secp256kfun` no longer a consumer of C libsecp256k1 | BIP-341/BIP-86 vectors + `cargo tree -i` shows one parent | ✅ **done** — but **−1,185 B, not −97 KB**, and the C toolchain is **not** removed (§2.2) |
| 1b | Close the residual test gaps | odd-y/`lift_x` assertion; device-path vector; clippy at `bitcoin_transaction.rs:524` | tests fail on mutating `tweak.rs:342` | ⬜ pending — see DECISIONS.md residual gaps |
| 2 | STM32 HAL substrate | `NorFlash` for STM32 flash, **2-source** `RngCore` (§5.1 — not three), **panic → `NVIC_SystemReset`** (§6.2), plus removal of the §6.3 panic sites | host tests; handler disassembly; **§8.1 defect register empty** | 🟡 **written, all 12 review defects fixed, host-verified; hardware claims unverified** — see **§8.1**. Device build links; clippy and rustdoc clean; **204 tests** and **857,125 B = 60.1%** at the gate (now 268 / 860,898 with phase 3 and 4 on top). What remains is §8.1 items 3–5 — the real `DBANK`, `.ramfunc`, ECC/NMI — all bench work. Every on-silicon claim is still an assumption (§9); nothing has run on hardware. |
| 3 | Transport | USB CDC carrying `frostsnap_comms` framing, within the **4,096 B** ceiling (§7, raised from 2,060 — DECISIONS.md 7) | coordinator handshake | 🟡 **written and host-verified; no enumeration has been attempted.** `hal/src/comms.rs` (framing, +18 tests) and `hal/src/usb.rs` (OTG_FS device mode + CDC-ACM, +31 tests, **23/23 mutations caught**) — see **§8.2**. The bound is structural, not a comparison: the accumulator *is* `[u8; FRAME_LIMIT]`, and it costs 2 × that in SRAM. The gate is **not** met **on silicon**, which is what it means here — a real unmodified coordinator *has* handshaked with this framing on the host over a pty (§9 item 6, phase 4's row below); what has never happened is enumeration on the device. §7's census is what raised the bound: at 2,060 the transport refused a real `SignatureShare`, a real 11-input `RequestSign`, 9-of-9 keygen and a 14-share `HeldShares2`; at 4,096 it refuses none of them, and the **three device-side construction caps remain UNIMPLEMENTED** phase-4 work. |
| 4 | Protocol on host | keygen + sign, Tier 2 simulator first, then Tier 3 stub `Serial` against real `frostsnap_coordinator` | end-to-end on host | 🟡 **gate MET on host 2026-08-18; not signed off.** `hostcheck/` + `firmware/examples/stub.rs` complete a **9-of-9 keygen, nonce replenishment and a signature that VERIFIES** (`Schnorr::verify_only()` against the coordinator's own derived x-only key) over a pty in two processes, against an **unmodified** sibling `frostsnap_coordinator`, at both `STUB_CHUNK=64` and `=1`. The two §7 size crossovers are **closed** by decision 7 (`FRAME_LIMIT` 2,060 → 4,096), validated on the wire: largest coordinator→device frame actually written is **2,179 B**, above the old bound, so this keygen was previously refused. Tier 1 268 tests green. **What the gate does NOT cover, and why phase 4 is not signed off:** the stub auto-acks `SignatureRequest`, so the *approval policy* — the actual security property — is untested; the keygen session hash **is** now compared device↔coordinator across two processes and two builds of `frostsnap_core` (`hostcheck/src/main.rs:1188-1217`, added after this row was written), but only CORE-to-CORE — nothing yet asserts the four bytes the *screen* renders are the coordinator's, which is the half a human actually compares; restoration, backup consolidation, physical-backup entry and naming flows have never been driven at all; the three device-side caps (§7) are unimplemented; the allocator is sized and chosen but not registered (§9 item 7); and nothing has run on silicon.
| 5 | Mono UI | **8 screens** (§4.2), mono `DrawTarget`, ~850 LOC ported from `frostsnap_widgets` | manual, on hardware | ⬜ pending — largest single item. Note it inherits §8.1 defect 12: the sign-approval screen is the first caller of `user_prompt()`, whose `None` must be a **refusal**, not a rendering fallback. |
| 6 | Callgate integration | SE1/SE2 identity, PIN, rate limiting; ABI already determined (§5, DECISIONS.md decision 2) | hardware | ⬜ pending |
| 7 | Nonce durability | read-back-verified writes as `Result` not `assert!`, power-loss testing | fault injection | ⬜ pending — `TestNorFlash` does **not** model power loss (§7) |

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
| 12 | **The first sign-approval screen would have reset-looped on a legal transaction.** `user_prompt()` did `Address::from_script(spk, ..).expect("has address representation")` on **foreign** output scripts. `from_script` errs on OP_RETURN, bare/P2PK, bare multisig and the empty script (bitcoin 0.32.8 `address/mod.rs:567-590`), and nothing validates foreign spks — `sign_task.rs:343-350` asserts an unaddressable output is *accepted*. Unreachable only because `user_prompt` has no caller yet; the device hands the UI the raw template (`device.rs:377-381`), so **phase 5 inherits this**. | latent panic, blocks phase 5 | ✅ fixed — returns `Option`; see §4.2 |

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
   obeys it: identity at offset 0 (8 KiB), nonce slots at 8 KiB (32 KiB), the rest
   `FS_FREE_OFFSET` and reserved. Every offset and length is a multiple of the
   **8 KiB `DBANK0_PAGE`**, not of the 4 KiB `ERASE_SIZE`, and that is the whole
   point: it is what makes an identity-region erase unable to reach the nonce region
   even if the real `DBANK` turns out to be 0 (item 3 above, still open).

   `FLASH_TEXT` shares bank 2 with `FLASH_FS`, with only ~44 K of margin at the
   current image size. Settling it needs a linker script (`.ramfunc`), which this
   tree does not yet have. Pinned as `flash::RAM_EXECUTION_IS_UNRESOLVED`.
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
| `fifo_write` returns `Ok` when its spin countdown expires | `fifo_write_reports_a_timeout_rather_than_dropping_bytes` |
| `fifo_write` writes without re-checking `DTXFSTS` for space | `SimPort`'s own assert — the "test double no more permissive than the hardware" rule paying for itself |
| `Setup::recipient` masks 2 bits, as ST's `USB_REQ_RECIPIENT_MASK` does | `reserved_recipients_are_not_aliased` |
| SET_ADDRESS masks to `0x7f` instead of refusing | `set_address_is_range_checked_rather_than_masked` |
| SET_LINE_CODING accepts `wLength >= 7` | `set_line_coding_with_a_wrong_length_is_refused` |
| SET_CONFIGURATION accepts any `wValue`; SET_FEATURE acknowledges; DEVICE_QUALIFIER answered | three separate control-dispatch tests |
| `ep0_xfer_size` uses the wide `XFRSIZ` field width; PKTCNT bound dropped | `ep0_xfer_size_is_narrower_than_every_other_endpoint` |
| `rx_status` truncates BCNT to 8 bits; PKTSTS mask lets DPID leak | two `rx_status` tests |
| `fifo_words` truncates instead of rounding up | `fifo_words_rounds_up` |
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

1. **Signing latency under `secp-lowmemory` is UNMEASURED.** This is now the
   highest-value unknown. `ECMULT_WINDOW_SIZE=4` / `ECMULT_GEN_PREC_BITS=2`
   bought 92% of the flash budget (§2.2) by shrinking the precomputation window;
   the cost is slower EC math, on a 120 MHz Cortex-M4, and nothing measures it.
   No host benchmark substitutes — the window size interacts with the actual
   core. A bad answer partly reopens decision 4.

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
   against it. No linker script or entry point work is scheduled before phase 5.
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
   gate switches to its own (`startup.S:139-145`) — satisfies the firewall. If it
   does not, the result is a firewall reset: benign here (same outcome as the
   intended reset) but it means the DFU fallback silently never works even on dev
   units. **Confirm on an RDP≠2 dev unit that a deliberate panic lands in DFU.**
4. **Which flash-error paths actually panic?** The §6.3 priority-2 and -3 sites
   cannot be shown reachable without a fault-injecting harness. `TestNorFlash`
   models no failures. Build one on the existing doubles —
   `MemoryNonceSlot` (`device_nonces.rs:501-514`) and `TestNorFlash`
   (`frostsnap_embedded/src/test.rs`) — that injects write failures and records
   which of the 13 enumerated sites fire.
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

### 8.3 Phase-4 register — two vendored defects found by mutating the device

Nine device-side mutations were run against the M3/M5 harness and all nine failed the
run. Two of them failed the *wrong way* — by panicking inside vendored
`frostsnap_core` rather than being refused — and that is a finding about the code, not
about the harness.

**Both are COORDINATOR-side and are NOT in the device image.** `coordinator.rs` is
behind `#[cfg(feature = "coordinator")]` (`frostsnap_core/src/lib.rs:31`) and
cold-snap's vendored manifest sets `default = []` (`Cargo.toml:49`), so neither can
brick a Mk4. They are recorded because cold-snap is the *device* that can trigger
them, we compile this code for host tests, and "our device can crash any coordinator
it is plugged into" is a defect we own the discovery of even when we do not own the
fix. **Neither is fixed. Do not read this section as a repair.**

| # | Defect | Site | Trigger | Effect |
|---|---|---|---|---|
| 13 | `.expect("inavariant")` on a **device-supplied** field, with no prior guard: `self.active_signing_sessions.get(&session_id).expect(..)` | `vendor/frostsnap/frostsnap_core/src/coordinator.rs:874-877` | a `SignatureShare` naming a `session_id` the coordinator has no session for — reached in the harness by altering the sign task, and independently by flipping one `session_id` byte | coordinator **panics**, exit 101. No named state, no counters, and the harness's `reap` is not on that path, so it also orphans the device process. Any device, or any corruption that survives framing, kills the coordinator |
| 14 | `check_can_extend` returns `Ok(())` for a stream the coordinator never opened *and* for an unknown device — both `None` arms | `vendor/frostsnap/frostsnap_core/src/coord_nonces.rs:33-38` | a device volunteering `NonceResponse` segments for arbitrary `stream_id`s | the device can insert entries into the coordinator's nonce cache unbidden. Fails late and from the wrong side, so the diagnosis points away from the cause |

Both are candidates to report upstream. Defect 13 is the more serious: it is an
unguarded `expect` on attacker-controlled input, which is exactly the class §8.1
catalogued on the device side, sitting on the host side of the same protocol.

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
   build shape, not a finding.** This workspace builds rlibs, and an rlib defers the
   allocator check to link time — `cargo build --release` reports nothing either
   way, so every previous clean device build was silent on the question rather than
   evidence for it. The requirement is real and arrives with the first real inbound
   frame; the only thing deferring it is that no caller instantiates the concrete
   type yet. Phase 4 must therefore choose a heap, not decide whether to have one.

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
   binding assert goes from 6,540 B spare to **18,828 B** (18,036 + 8,192 + 20,480 =
   46,708 <= 65,536), so `MEASURED_PEAK_BYTES = 48,166` is now the constraint on
   `HEAP_BYTES` rather than the hostile ceiling.

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
   callgate entry and exit** (`startup.S:124-134,148-156`), and item 5 below — PSRAM —
   would change the size available by an order of magnitude if it were characterised.
   A heap whose extent is picked before those three are settled is picked wrong.

   **Sized, bounded and partly landed 2026-08-18/19. Read the four parts
   separately — (a) and (b) are findings, (c) is a repair, (d) is a measurement
   plus a pre-emptive bound. The allocator itself is still not registered.**

   **(a) SIZE — measured, landed as constants.** `hal/examples/heap_profile.rs`
   (host, release, `--features heap-profile`) drives a real `FrostCoordinator`
   against real vendored `FrostSigner`s through keygen → nonce replenishment → a
   signature asserted to verify, with a tracking allocator, attributing heap **per
   device** rather than per process: transient in windows around single device
   calls, live destructively by dropping one `FrostSigner` and watching the
   net-bytes counter fall. One Mk4 in a 9-of-9 group needs **48,166 B peak**
   = 18,036 B live across frames + 30,130 B worst transient frame. The live half is
   a **constant** — identical at group size 1/2/3/5/9, identical after 1/2/4
   signing sessions, +112 B per nonce slot — which is what makes a static budget
   provable. `coldsnap_hal::heap` now records `HEAP_BYTES = 64 KiB` with those
   measurements and the compile-time relations that derive it. Host 64-bit figures;
   the 32-bit direction is **lower** (certain), magnitude (~10–40%) unmeasured.
   Also actionable: 12,456 B of the 18,036 B (69%) is empty-but-allocated keygen
   `BTreeMap` leaf nodes and is reclaimable after `keygen_finalize`. Call the
   narrower **`clear_unfinished_keygens()`** (`device.rs:249`), **not**
   `clear_tmp_data()` — they free the same 12,456 B, but `clear_tmp_data` also clears
   the restoration leg and so can discard a typed-in physical backup. The saving is
   n-independent (identical at *n* = 1, 9, 11, 12, 13) precisely because it is nodes
   and not data. Not written, no event loop exists; `MEASURED_LIVE_BYTES` records the
   figure for firmware that does not call it. Durable live residual after the call is
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
   `FLASH_TEXT`. `buddy_system_allocator` 0.13 (`default-features = false`) is the
   leading candidate on trust surface and bounded coalescing;
   `embedded-alloc`/`tlsf` wins if PSRAM lands. **Neither is in the manifest**, and
   nothing here registers a `#[global_allocator]`: a library that does silently
   overrides std's (measured: 575 harness allocations through it, and a
   `SIGABRT` before any test runs with an un-`init`ed arena) and permanently
   forbids the future `main` its own choice. A line-by-line review of the winner's
   `unsafe` code is still owed before it ships (§1's rule).

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
   (18,036 + 8,192 + 20,480 = 46,708 ≤ 65,536), so the build fails rather than the
   device if either limit is ever widened. **Placement is untouched**
   — the four blockers above (no linker script, `0xdeadbeef` fill, the
   callgate-wiped 8 K, uncharacterised PSRAM) all still stand, and 64 KiB is a
   reservation derived from the workload, not a figure any allocator's own
   fragmentation overhead has met. The reset entry zeroing `.bss` is now a
   *correctness precondition* for any allocator, not a nicety: every candidate's
   control block is a `static`, so an unzeroed one comes up as `0xdeadbeef` — the
   same defect `singleton::TakeOnce` exists to fix. Restoration/backup flows were
   never driven by the profiler and share the same phase enum, so re-run it before
   freezing the size.

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
    `hostcheck/src/main.rs:1188-1217` compares **every** device's computed session
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
    reports them on the existing wire as a `Debug` line. `hostcheck/src/main.rs:1477`
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

    Still open, unchanged: `firmware/examples/stub.rs` **auto-acks
    `SignatureRequest`**, so the approval policy — the only thing between a
    coordinator and a signature — has never been exercised on the gate path. And note
    a constraint found while designing the fix: **the vendored protocol has no
    "decline" message**, so a refusal is expressible only as *not confirming* plus a
    `Debug` back-channel line. This is why phase 4's gate is recorded as *met but not
    signed off* in §8, and it is the reason that row should not be read as "signing is
    verified".
    Restoration, backup, consolidation and naming flows have never been driven by any
    harness in this tree either.

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
    or never. **Read one real converted unit's `FLASH_FS[0x28..0x2c]` on the bench**
    and the estimate becomes a fact. Nothing else in §9 is this cheap to close.

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
    (`wallet_create.dart:662-704`), which cold-snap's never will — so this is exercised by
    `hostcheck`, not by the released app.

    A process note worth keeping: a temporary probe an agent left behind
    (`/// TEMPORARY VERIFICATION PROBE — remove.`) had never executed because the file did
    not compile, and it failed on first run against a record it was over-reaching past by
    8 bytes. The correctly-scoped test beside it passes. **A test that has never run is
    not evidence**, and a green report from an agent whose gates never compiled the file
    is worth nothing — check the counts, not the claim.

22. **169 `cfg(target_arch = "arm")` blocks were invisible to every LINT in this project.
    (This heading read 152 until 2026-09-08; the re-count is in the body below, and the
    miss was `entry.rs`, which no earlier pass had listed and therefore no earlier pass
    had read.)
    Now they are linted; they are still never executed.** Measured 2026-09-02:
    keypad 8, display 8, usb 85, flash 20, panic 13, rng 6, callgate 5,
    firmware/src/main.rs 7. Every test, clippy and rustdoc command here runs
    `--target aarch64-apple-darwin`, so none of that code was ever compiled under a lint.

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

    **The count is a snapshot, not a bound, and it has moved twice:** 152 → **169** on
    2026-09-08 (the first recount said 164, missing `entry.rs` and `hal/src/lib.rs`
    entirely) → **181** on 2026-09-10: usb 88, flash 22, main.rs 15, panic 13, callgate
    11, keypad 8, display 8, rng 6, `firmware/src/lib.rs` 4, `firmware/src/entry.rs` 4,
    `hal/src/lib.rs` 1, `ui.rs` 1. Do not chase the number — the gate is a whole-target
    compile, so it covers however many there are. **`firmware/src/quiz.rs` contributes
    0**, which is not an accident: a pure module is exhaustively host-testable, and a
    `cfg` in one would put a security property where no host test can reach it.

    The gate bites where the four existing ones do not, proven by mutation:
    `ROW_SETTLE_SPINS as u32 + 0` in the same `cfg`-arm block left host tests at 261,
    host clippy at 0, and `cargo build --release` at **0 warnings and 0 errors**, while
    the device clippy flagged it twice (`identity_op`, `unnecessary_cast`).

    **What the 152 blocks actually contained: nothing.** At clippy's default level, from a
    cold target dir, 0 findings in `hal/src` and `firmware/src` and 0 rustdoc warnings.
    A deeper hunt — restriction and pedantic lints as a one-off survey, plus a
    brace-matching grep of all 152 spans for `unwrap`/`expect`/`panic!`/`assert`/
    `copy_from_slice`/variable indexing — found **no reachable panic and no unbounded
    hardware spin**: every register poll is a `checked_sub` countdown returning an error
    (`usb::wait_bits`, `usb::wait_ep_idle`, `display::write_byte`, `display::drain`,
    `rng::read_one_word`, `flash`'s `while off < to`), and `panic::system_reset`'s
    exit-less loop is decision 6 by design. All 19 `cfg(not(target_arch = "arm"))` blocks
    are refusals, so the forbidden fail-open direction — a cfg on a refusal — does not
    occur. The single real defect was a missing `SAFETY` comment on the `SPI1_CR1`/`CR2`
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
    to compute 50000000_usize * 100_usize, which would overflow` at `hal/src/flash.rs:876`.
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
    overflow` at `hal/src/rng.rs:593`. In the same tree, `transaction()` in `display.rs`
    rewritten to `bsrr_set(CS_PIN)` where it must `bsrr_clear` — `CS` deasserted for the
    whole transfer, so the panel receives nothing — produced **zero** diagnostics from
    either line, and would produce none under QEMU either: GPIO writes are accepted and
    nothing observes the pin. That mutation is the honest ceiling of every tier here.
    **QEMU is not installed on this machine** (`brew install qemu`, ~1.5 GB). Three findings settled why a `no_std`
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
    security property" is abstract and these are not. (a) Deleting the `& 0x0f` bound in
    `usb::Mmio::write_fifo_word` (`usb.rs:1351`) — the mask the comment there calls "a
    property of the code rather than of every caller" — puts an unsafe
    `write_volatile` outside the OTG_FS window. (b) Changing `page << 3` to `page << 4`
    in `StmFlash::erase`'s `FLASH_CR` `PNB` field (`flash.rs:1169`) erases the **wrong
    page**. Both left 265 hal + 81 firmware tests green, host clippy 0, `cargo build
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
    EVALUATED there, because no keypad driver exists.** `firmware/src/main.rs:581` draws
    a fresh `ui::ConfirmDigit` per prompt and renders it, and `firmware/src/lib.rs:780-789`
    documents that the render and the accept share one `ConfirmDigit` so they cannot
    disagree — but `ConfirmDigit::accepts` has **no caller anywhere in `firmware/src`**.
    `boot()` has no button input, so nothing on the device evaluates a keypress. The
    fail-closed rule therefore lives in two places today: the type in `hal`
    (`accepts` compares against a *private* field only `draw` can fill, so no
    cross-crate caller can forge a digit) and the only consumer,
    `firmware/examples/stub.rs::approved`.

    **CLOSED 2026-09-02.** `hal/src/keypad.rs` landed (the Mk4 4x3 membrane matrix, real
    pins from `stm32/COLDCARD_MK4/pins.csv:74-80` — cols PB0-PB2, rows PD8-PD11) and
    `firmware/src/main.rs:221` now calls `confirm.accepts(key)` inside `fn answer`,
    reachable only from `keypad::Event::Down`. `Answer::Yes` is the sole route to
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

17. **The heap figures predate the construction the device now uses, and the binding
    assert was incomplete until 2026-08-25.** `heap::MEASURED_PEAK_BYTES` (48,166) and
    `MEASURED_LIVE_BYTES` (18,036) were measured on a 64-bit host driving
    `FrostSigner::new_random` + `MemoryNonceSlot` — neither of which is on the device
    path any more. The shipping `Session` uses flash-backed `NonceAbSlot`s, whose state
    lives on flash rather than the heap, so live bytes plausibly FALL; but that is
    reasoning, not a measurement, and `hal/examples/heap_profile.rs` /
    `heap_lifo.rs` still drive the old construction, so re-measuring needs a new
    firmware-side harness. What HAS been measured is the dispatch's own addition:
    `heap::OUTBOX_CEILING` = 4 × 2,040 = **8,160 B**, the encoded frames a 4-stream
    nonce replenishment parks until drained, and it is now IN the binding assert —
    which had omitted the largest single new heap consumer. Slack fell 18,828 →
    **10,668 B**. Closing this properly means a firmware-side heap harness, and the
    32-bit target should make the 64-bit host figures conservative rather than
    optimistic — but that direction is argued, not measured.

18. **Nonce durability across a power cycle is unit-tested only.** Nonce state is
    written through the real flash-backed `NonceAbSlot` at `FS_NONCE_OFFSET` during
    the harness run, and the verified signature could not exist otherwise. But the
    harness's restart happens BEFORE keygen, because nothing persists a completed
    share yet, so at restart the flash holds only the identity. Reload of a nonce
    stream after a reset is covered by
    `signer_reconstructed_from_flash_keeps_device_id_and_nonce_stream` and nowhere
    else — untested across a process boundary and untested on silicon.

15. **The UI ships one 8×8 font where §4.2 specifies three, and the missing one is
    the security-relevant one.** `hal/src/ui.rs` renders at a single 8×8 cell →
    16×8, against §4.2's measured `FontSmall` 7×14 → 18×4, `FontLarge` → 12×3 and
    `FontTiny` 4×6 → 32×10. Two consequences matter. **Columns went 18 → 16**, so a
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

16. **CLOSED 2026-09-10 — the UI is fully linked; all eight screens have callers.**
    Until 2026-08-25 `boot()` referenced neither `ui` nor `display`, so
    `--gc-sections` dropped both entirely: **0** symbols, and the image was
    byte-identical at 99,684 B before and after ~3,000 lines of UI — the same trap
    that made it read 11,604 B before `comms` was wired in. Wiring the identity-hold
    screen (§9 item 14) fixed that for the parts it reaches: **101,416 B = 7.11%**,
    `+1,732 B`, of which `.rodata` `+924 B` is the **measured** font-table cost
    against the 768 B source count. What is still dropped is everything nothing
    calls yet — sign approval, backup display and entry, address verification, the
    quiz. **Substantially closed 2026-08-25:** a real `FrostSigner` in `boot()` took
    the image to **282,080 B = 19.79%**, a 2.78× jump, with `rust-bitcoin` going 1 → 14
    symbols. Proof it is `boot()` that pulls it in: deleting the single `session.recv`
    call drops `.text` by 142,916 B and `bitcoin` back to 1. **Fully closed
    2026-09-10 at 376,752 B = 26.43%:** every §4.2 screen now has an honest caller,
    the quiz included, so nothing in `ui` is gc-sectioned out any more. `quiz.rs` is
    the cleanest illustration of the trap in this file — its author measured it at
    **+0 B** while it compiled and tested but nothing called it, then it cost
    **+2,304 B** the moment a dispatch arm referenced it, without one line changing.
    Measure after wiring, never before.

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
| Flash, as built | 860,898 B = **60.4%** of `FLASH_TEXT`, re-measured in a clean target dir 2026-08-19 (844,229 at phase 0; +5,101 panic sites, +253 for §8.1 defects 10–12, **+15,873 `coldsnap_hal` rlib** — of which +3,461 is phase 3's `comms.rs` + `usb.rs` — less −4,482 instantiations that moved between rlibs; all with LTO off, so upper bounds). **This row read 893,099 B = 62.7% until 2026-08-19**, on the strength of a +32,513 B growth attributed to `comms::decode_body`; that does not reproduce clean and is retracted — see README "Flash budget". The live `./target` glob measures 1,311,110 B = 92.0% from 131 rlibs against a clean 48, which is the artefact to suspect first.  **The linked image is measured, and the rlib sum above overestimates it by ~2.9×:** `firmware/` links at **376,752 B = 26.43%** of `FLASH_TEXT` (`llvm-objdump -h`, 2026-09-10), because LTO plus `--gc-sections` keeps only what is reachable. `llvm-nm` finds **267** frostsnap/secp/schnorr/bitcoin symbols and **17** `coldsnap_hal::ui` symbols. The trajectory, each step a real caller appearing rather than a code addition: 11,604 B when `boot()` polled USB but touched no `comms` · 94,304 B with `Link::poll` + `decode_body` · 99,684 B with `identity` · 101,416 B once the identity-hold screen gave `ui`/`display` a caller · 282,080 B once a real `FrostSigner` was constructed and dispatched to · 297,064 B once the remaining §4.2 consent screens got honest callers · 331,116 B with the keypad driver and real consent · 362,288 B once `DisplayBackup`, `mark_sensitive` and the persistent share store landed · 372,688 B once 25-word entry made restore possible · **376,752 B** once `CheckBackup` became a real 8-question quiz behind its own consent digit (+4,064 B: +32 B of `ui.rs` screens, +2,232 B when `firmware/src/quiz.rs` first acquired a caller and its generics were instantiated, +1,800 B for the `main.rs` event-loop arm). `.bss` is byte-identical across all of it at `0x2000_8034..0x2001_8058`, and nothing on the quiz path allocates, so the ~5,024 B arena margin is unchanged. Still not the ceiling: `EnterPhysicalBackup`, `SavePhysicalBackup`, `SavePhysicalBackup2`, `Consolidate` and the naming flows are refused rather than implemented (§9), so their code is absent — and a PIN would add the SE1 paths that are currently bound but gc-sectioned out. Read the rlib rows for the MARGINAL cost of a change, never as a prediction of image size. |
| Host tests passing | **565** = hal 284 + firmware 165 + vendored 116 (`frostsnap_core` 63 + `comms` 10 + `embedded` 17 + `frost_backup` 19 + `macros` 7), re-measured 2026-09-10; **530** before the `CheckBackup` quiz (+6 hal, +29 firmware); 357 before the gap-closing pass; 355 before the signing pipeline; 344 on 2026-08-25 before `FrostSigner`; the firmware gate is now a SUM of two `test result` lines, 11 lib + 14 bin; 341 on 2026-08-24, +40 for `ui.rs`; 268 until 2026-08-24, which never counted `coldsnap_firmware`'s 14; +19 for `identity`; 204 at the phase-2 gate, 253 at the end of phase 3, 261 before §9 item 7(c)'s three outer-leg tests, 264 before the three inner-leg `decode_body` tests, 267 before the pin on the vendored `MAX_MESSAGE_ALLOC_SIZE`; `frostsnap_core` no longer needs an allowlist, `frost_backup` still does — §7) |

Vendored crates live in `vendor/frostsnap/` with upstream commit recorded in
`vendor/README.md`, which also carries the local-modifications table. Changes are
kept mechanical so upstream can be rebased.

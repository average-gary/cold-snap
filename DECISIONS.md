# cold-snap — architecture decision record

**Status:** decided. These **seven** choices are settled and are not re-litigated
below. (1-6 were decided 2026-08-12; **7**, the `FRAME_LIMIT` reversal, 2026-08-18.)
**Date decided:** 2026-08-12
**Supersedes:** `PLAN.md` §9 open questions 1, 2, 5 (now closed by decisions 1, 4, 2)

Each entry states the decision, the rationale, the consequences, and what it
forecloses. Where a decision's *premise* turned out to be wrong on inspection of
the source, that is recorded under the decision rather than quietly fixed —
see decision 6, whose stated mechanism does not work on production hardware.

Confidence markers used throughout:

| Marker | Meaning |
|---|---|
| **measured** | a number or behaviour reproduced by running a command this session |
| **read** | asserted by named source at `file:line`, not executed |
| **assumed** | not verified; needs bench confirmation |

---

## 1. Target board: Coldcard Mk4, not Q1

**Decision.** Build for the Mk4 (STM32L4S5, 128×64 1-bit OLED). Q1 is out of
scope.

**Rationale.** The Mk4 is the board in hand and the one whose bootloader and
secure-element behaviour was audited for decisions 2 and 6.

**Consequences.** The display is the single largest work item in the project.
Frostsnap's UI stack is not portable to it:

| | Frostsnap (ESP32 device) | Coldcard Mk4 |
|---|---|---|
| Panel | 240×280 ST7789 SPI | 128×64 SSD1306 SPI, 40 MHz (`shared/display.py:19-20,32-35,44`) |
| Pixels | 67,200 | 8,192 |
| Colour | `Rgb565` (`frostsnap_widgets/src/lib.rs:241`) | 1-bit `MONO_VLSB`, 1,024-byte buffer (`shared/ssd1306.py:33,40,43`) |
| Fonts | Gray4 anti-aliased, min 15 px line height (`frostsnap_fonts/src/noto_sans_14_light.rs:6`) | 1-bit bitmap, 14/21/6 px (`shared/zevvpeep.py:33,132,329`) |
| Input | CST816S capacitive touch, swipe + hold-to-confirm | 4×3 membrane keypad, 12 keys, randomised scan order (`shared/mempad.py:12-13,36-38`; `shared/numpad.py:10`) |

`frostsnap_widgets` is **19,799 LOC measured**, of which **13,459 (68%) sit in
files that name `Rgb565`**; `frostsnap_fonts` adds **14,032 LOC measured** of
Gray4 glyph data whose smallest face is taller than Mk4's `FontSmall`. Only
about **850 LOC is genuinely colour-free and reusable** — `backup_model.rs`
(398), `string_ext.rs` (241), `widget_list.rs` (86), `distractor.rs` (59),
`animation_speed.rs` (39).

**What this forecloses.** On a Q1 (320×240 colour) most of `frostsnap_widgets`
and all of `frostsnap_fonts` would have ported, and this work item would largely
have disappeared. Choosing Mk4 buys that cost deliberately: a from-scratch mono
UI, plus rebuilding hold-to-confirm on key-down duration because there is no
touch surface. It also forecloses reusing Frostsnap's 6×3 chunked-address grid
(`frostsnap_widgets/src/address_display.rs:29-40`) — 18 chunks do not fit in
18×4 characters.

**Not foreclosed.** The `Widget`/`DynWidget` *contract* is not intrinsically
colour-bound: `Widget::Color` is an associated type (`lib.rs:230-232`),
`VecFramebuffer` already bit-packs `BinaryColor`
(`vec_framebuffer.rs:230-237,366`) and `ColorInterpolate` already has a
`BinaryColor` impl that thresholds at 50% (`widget_color.rs:42-50`). The trait
scaffolding can be reused even though every concrete widget cannot.

---

## 2. Keep Coldcard's root of trust, via the bootloader callgate

**Decision.** Retain the PCROP bootloader and both secure elements. PIN
validation, rate limiting, the brick counter, trick PINs and fast wipe stay
Coinkite's code, reached from Rust through the callgate.

**Rationale.** The alternative is a device with no PIN, no rate limiting and no
coercion resistance, which forfeits the entire dual-secure-element rationale for
choosing this hardware.

| | Frostsnap | Coldcard Mk4 |
|---|---|---|
| Identity | read-protected eFuse key | SE1 + SE2 + MCU key slots |
| Access | direct register reads | bootloader callgate |
| PIN | none | mandatory, SE1-enforced |
| Rate limiting | none | SE1 counter, 13-attempt brick |
| Anti-coercion | none | trick PINs, duress wallets, fast wipe |

**Consequences — the ABI is now fully determined (read).** The entry pointer is
the first word of a fixed table at `0x0800_0040`
(`stm32/COLDCARD_MK4/modckcc.c:41-47,51-57`; bootloader side
`stm32/mk4-bootloader/startup.S:62-67`). Convention: `r0`=method, `r1`=buffer or
NULL, `r2`=len, `r3`=arg2; return in `r0`; reached by `BLX`, so the address has
its LSB set and `(dest & 0xff) == 0x05` is asserted by Coldcard's own caller.
The gate switches to its own stack and clobbers `r9`/`r10` beyond the normal
call-clobbered set (`modckcc.c:64-65`; `startup.S:122-158`). Callers must
disable interrupts (`modckcc.c:104`; `dispatch.c:96-101`).

Two `asm!` constraints found **measured** while compiling a handler for this
target: `clobber_abi("C")` warns about reserved FP registers D16–D31 on
`thumbv7em-none-eabihf` and must be avoided; `r6` and `r7` are LLVM-reserved and
cannot appear in a clobber list at all. The legal explicit clobber set is
`r4, r5, r8, r9, r10, r11, r12, lr`.

**What this forecloses.** §1 of `PLAN.md` argues the MicroPython route was
rejected on a trust constraint — that libngu's `#ifdef` ladder failed open to
glibc `random()`. This decision knowingly does not fully honour that position:
the retained bootloader and SE code are by the same authors. The trade is
explicit. It also forecloses ever testing the highest-risk paths off-hardware —
the callgate is PCROP-protected code outside any firmware image, so neither host
tests nor Renode can execute it.

**Corollary adopted.** PIN entry should wrap Coldcard's existing Mk4 renderers
(`shared/ux_mk4.py:361-445` `ux_show_pin` including the shoulder-surfing keypad
remap at `:371-388`, and `:351-359` `ux_show_phish_words`) rather than being
redesigned, since the gate semantics behind them are unchanged.

---

## 3. Go pure Rust: drop `schnorr_fun`'s `libsecp_compat_0_29`

**Decision.** Frostsnap's own crypto path must not route through C
libsecp256k1. Applied.

**How far it was actually carried — stated plainly.**

The feature was **fully removed**, not merely bypassed
(`vendor/frostsnap/frostsnap_core/Cargo.toml:10`). The load-bearing change is
`AppTweak::derive_xonly_key`, which computed the BIP-341 taproot tweak by
round-tripping the key through the C `XOnlyPublicKey` type to reach a hash that
does no EC math at all. It now calls a local
`bip341_taptweak_key_only()` built on `secp256kfun`'s `Tag`
(`frostsnap_core/src/tweak.rs:35`, called at `tweak.rs:222`). No `bitcoin::`
reference remains in the tweak computation.

**The goal was met, and it is narrower than "no C".** `cargo tree --target
thumbv7em-none-eabihf -p frostsnap_core -i secp256k1@0.29.1` now shows exactly
one parent, `bitcoin v0.32.8` (**measured**). `secp256kfun` is no longer a parent
of C libsecp256k1. That — and only that — was decision 3's achievable goal.

**Removing the feature broke four sites, not the six `PLAN.md` §2.2 predicted**,
all pure byte round-trips: `tweak.rs:259` (`to_libsecp_key` default body),
`bitcoin_transaction.rs:415` (`LocalSpk::spk`, the address path), and two in
tests. `PLAN.md` §2.2 named `tweak.rs:187` "the load-bearing one" and did not
list `bitcoin_transaction.rs` at all; the reverse was true.

**Consequences — the benefit is much smaller than `PLAN.md` claimed.**
Measured with `CARGO_PROFILE_RELEASE_LTO=false` into two separate clean target
dirs, then `tools/measure-flash.py`:

| | before | after | delta |
|---|---|---|---|
| C `secp256k1-sys` | 96,947 (6.8%) | 96,947 (6.8%) | **0** |
| `rust-bitcoin` + encodings | 327,408 (23.0%) | 327,408 (23.0%) | 0 |
| Frostsnap + pure-Rust crypto | 421,059 (29.5%) | 419,874 (29.5%) | −1,185 |
| **ALL, as built** | **845,414 (59.3%)** | **844,229 (59.2%)** | **−1,185** |

**−1,185 bytes, not the −97 KB `PLAN.md` §2.2 and §8 asserted.** `libsecp256k1.a`
is byte-identical before and after (sha256 `0358790a…`), and the C
cross-compiler is still required: pointing `CC_thumbv7em_none_eabihf` at a
nonexistent path still fails inside cc-rs with `secp256k1-sys@0.10.1: Compiler
family detection failed … ToolNotFound` (**measured**).

**What this forecloses — nothing, but it does not deliver what was hoped.** The
C dependency, `cc-rs`, and the clang requirement all remain. See the next
section for why.

**One deliberate behaviour change, accepted.** rust-bitcoin's `to_scalar()`
panics if the tweak hash is ≥ the curve order
(`bitcoin-0.32.8/src/taproot/mod.rs:78-80`). The replacement uses
`Scalar::from_bytes_mod_order`, which reduces. Identical for every hash below
`n`; above `n` the old code panicked — a halt, under `panic = "abort"` — and the
new code produces a valid reduced scalar. Strictly better under decision 6.
Probability ≈ 2⁻¹²⁸. Note this *deviates* from BIP-341's reference
`taproot_tweak_pubkey`, which raises rather than reducing; it is not
"conformance", it is a safer unreachable branch.

---

## 3↔4. The tension, stated without hedging

Decision 3 says "pure Rust". Decision 4 says "keep rust-bitcoin". These are
partly incompatible and decision 4 wins:

> **`bitcoin` 0.32.8 declares its `secp256k1` dependency NON-optionally.** C
> libsecp256k1, `secp256k1-sys` 0.10.1 and `cc-rs` therefore remain in the
> dependency graph, and a C cross-compiler remains a build requirement, for as
> long as rust-bitcoin is retained. Decision 3 removed `secp256kfun` as a
> *consumer* of the C library; it did not and cannot remove the library.
>
> **Full C elimination requires revisiting decision 4.**

The remaining in-tree blockers to dropping `bitcoin`, if that is ever revisited:

| Blocker | Site | Difficulty |
|---|---|---|
| Taproot sighash | `bitcoin_transaction.rs:203` `iter_sighash`, `:210` `taproot_key_spend_signature_hash` | real work — consensus-critical, needs its own vector suite |
| `Xpub` construction + `fingerprint()` | `tweak.rs:408-427` `to_bitcoin_xpub_with_lies` | small — `fingerprint()` is the only in-tree caller and reduces to `hash160(33-byte pubkey)[0..4]` |
| Address/SPK encoding | `bitcoin_transaction.rs:415` `LocalSpk::spk` → `ScriptBuf::new_p2tr_tweaked` | small |

`to_libsecp_xonly` (`tweak.rs:267` default, `:351` override) is now dead code.
It is a `pub trait` method so it raises no `dead_code` warning; kept to limit
rebase conflict surface, and to be deleted together with the `bitcoin` dep.

---

## 4. Keep rust-bitcoin

**Decision.** Retain `bitcoin = "=0.32.8"`, features `["serde",
"secp-lowmemory"]`.

**Rationale.** 327,408 bytes **measured**, 23.0% of `FLASH_TEXT`, and it fits at
59.2% total. It provides consensus-critical taproot sighash, which is the last
thing worth reimplementing. `secp-lowmemory` already solved the flash problem
that mattered — `ECMULT_WINDOW_SIZE=4`, `ECMULT_GEN_PREC_BITS=2`
(`secp256k1-sys-0.10.1/build.rs:34-36`), shrinking the C library 92% from
1,177,733 to 96,947 bytes with no source changes.

**Consequences.**

1. The 3↔4 tension above: C stays, clang stays.
2. `bitcoin` 0.32.8 has **no `alloc` feature**, only `std`. Its
   `hex-conservative` dep therefore compiles with neither and fails with 144
   errors; `alloc` is forced on via an explicit dep line in
   `frostsnap_core/Cargo.toml`. This is a workspace-shaped fix, not upstream's.
3. `secp-lowmemory` trades flash for EC speed. **Signing latency on a 120 MHz
   Cortex-M4 is UNMEASURED** and is now the highest-value open question.

**What this forecloses.** A `cc`-free, C-free build; and the possibility of
reporting "pure Rust" without qualification. Also foreclosed: deleting the
rust-bitcoin differential tests (`matches_rust_bitcoin_over_many_keys`), which
are the strongest guard on the decision-3 tweak — they live only as long as this
decision does. See the residual-gaps section: that guard's departure is a
scheduled loss of coverage, not a neutral cleanup.

---

## 5. Validation: host unit tests + interop against a real coordinator

**Decision.** Validate with host-target unit tests plus interop against a real
`frostsnap_coordinator`. The Coldcard MicroPython simulator is not available —
there is no MicroPython in this design.

**Rationale.** Losing Coldcard's Python test suite and simulator is the most
material cost of the framing in `PLAN.md` §1. These are the substitutes that
actually exist.

**Consequences — what passes today (measured, this session).** 84 tests, but
only with per-crate feature flags and a test allowlist. A plain
`cargo test --workspace` does **not** compile.

| Crate | Invocation | Tests |
|---|---|---|
| `frostsnap_core` | `--features coordinator`, 9 of 11 test targets + `--lib` | 39 |
| `frostsnap_comms` | `--features coordinator` | 10 |
| `frostsnap_embedded` | `--features std` | 9 |
| `frost_backup` | `--lib` + 5 of 6 test targets | 19 |
| `frostsnap_macros` | *(none)* | 7 |
| **Total** | | **84** |

Two invocation traps, both **measured**, both worth pinning in a script:

- `frostsnap_embedded` without `--features std` silently yields **7** tests
  instead of 9 and loses *all* `NorFlashLog` coverage — the append-only log used
  for nonce durability. The tests are gated on `cfg(test)` **and**
  `feature = "std"` (`frostsnap_embedded/src/nor_flash_log.rs:77-78`), and the
  vendored manifest moved `std` out of `default`.
- `frostsnap_core`'s `tests/wire_size_measure.rs` and `tests/zz_claim3_crossover.rs`
  fail to compile (`E0432 unresolved import frostsnap_comms`). These were added
  by an earlier session, are **untracked** in the reference checkout, and fail
  identically there. A 2-line `[dev-dependencies]` addition
  (`frostsnap_comms` + `bitcoin`, a legal dev-only cycle) fixes them; verified
  working then reverted, as this is a planning artifact.
  `frost_backup`'s `tests/descriptor_match.rs` fails for the same class of
  reason — it wants `frostsnap_coordinator` and `miniscript`, neither vendored.

**The interop seam is small.** `frostsnap_coordinator::Serial` is a two-method
trait returning `Box<dyn serialport::SerialPort>`
(`frostsnap_coordinator/src/serial_port.rs:10,15-22`), taken by trait object at
`usb_serial_manager.rs:83`. Of `SerialPort`'s 25 methods, `FramedSerialPort`
only ever calls `bytes_to_read()` plus `io::Read`/`io::Write`; upstream already
ships a non-`serialport` impl with **22 `unimplemented!()`** (**measured**, in
`cdc_acm_usb.rs`). **A host stub device needs no ESP32 and no hardware.**

**What this forecloses.** Everything below the trait boundary. Not testable
without hardware: SSD1306 init/timing and physical legibility; keypad
scan/debounce and its randomised timing; the callgate in any form (decision 2);
the TRNG and its health checks (PLAN.md §5.1 — **two** sources, not three:
SE1 is fed our own TRNG and SE2 returns a static page); panic→recovery; real STM32
program/erase semantics and power-loss durability; and `secp-lowmemory` signing
latency. Renode would cover the core, flash controller, SPI and TRNG register
interface only — not the PCROP callgate, not the external SE parts.

**Carried into Phase 3 as a hard constraint, and re-measured there.** The 2,060
bytes is `MAX_MSG_LEN` from Coldcard's **HID** reassembly buffer (4+4+4+2048,
`shared/public_constants.py:26-31`) — not a CDC or `frostsnap_comms` constraint,
so it is a bound this project chose. It is enforced anyway, structurally
(`coldsnap_hal::comms::FRAME_LIMIT`), because the vendored decoder's own limit is
32 KiB. **The figures this section carried were the message body only**, missing
the `ReceiveSerial` envelope (+36 B upstream, +34 B downstream — *not* the +128 this
paragraph said until 2026-08-16; 128 is the bare-`GroupSignReq`-to-full-frame
distance on the `RequestSign` row, envelope included): `NonceResponse`
1×30 is **2,040 B** on the wire (20 spare, not 54); `SignatureShare` with a
30-nonce replenish is **2,105 B** for one share and 2,713 B for twenty; and
inbound `RequestSign` crosses the bound at **11 owned inputs (2,238 B)**, which the
body-only figures put comfortably inside it. So enforcing the ceiling refuses real
signing traffic in both directions. Nonce batch size is a live protocol design
constraint, not a theoretical one — see PLAN.md §7 for the full table and §8's
phase-4 row for who owns it. **The measurements above stand; the conclusion —
enforce 2,060 — is reversed by decision 7 below.**

---

## 6. Panic policy: never halt, always reach a re-flashable state

**Decision.** A panic must never leave the device spinning. Under
`panic = "abort"` with no unwinder, every `assert_eq!` in
`frostsnap_core/src/device_nonces.rs` is otherwise a permanent halt.

### The stated mechanism does not work on production hardware

`PLAN.md` §6 and the decision as originally phrased say "enter DFU via
`callgate.enter_dfu()`". Reading the bootloader **refutes the premise**, and the
reason is not the one assumed:

| Assumed | Actual (**read**) |
|---|---|
| `enter_dfu` is PIN-gated | It is **RDP-gated**. `dispatch.c` case 2 contains no PIN check and no reference to `pinAttempt_t` at all. |
| A pre-login panic can't reach DFU | Selector 2 / `arg2=0` checks `flash_is_security_level2()` and returns `EPERM`, bailing to `fail` **without entering DFU and without a screen** (`stm32/mk4-bootloader/dispatch.c:150-165`). This is true pre- *and* post-login. |
| Production units can DFU | Production units are RDP=2 (`dispatch.c:417-418`, `:404-407`; `shared/version.py:127`), so the `EPERM` branch is the branch that always executes. |
| DFU is reachable somehow | The bootloader's own `enter_dfu()` refuses to run at RDP=2 — `if(flash_is_security_level2()) { LOCKUP_FOREVER(); }` (`stm32/mk4-bootloader/main.c:256-258`). It is hardware-impossible, not merely policy-blocked. |

`fail:` re-arms the firewall and **returns to the caller** (`dispatch.c:697-699`),
so the call is a no-op rather than a trap.

The only recovery on a locked unit is the bootloader's microSD path
(`main.c:161-182`), and it restores **only the exact image already installed**:
it requires an SE1 checkmac against `KEYNUM_firmware` (`sdcard.c:248-251`;
`verify.c:300-305`), which is written only by a PIN-authenticated upgrade
(`pins.c:1327`, gated on `PA_SUCCESSFUL` at `:1283-1286`). Installing a *new*
build is PIN-gated; restoring the *same* build is not.

### A HOLE, found 2026-08-20: this covers `panic!()` but NOT hardware faults

`hal/src/panic.rs` implements `#[panic_handler]`, so it catches `panic!()`,
`assert!`, `unwrap` and arithmetic overflow traps. **It does not catch a HardFault,
NMI, MemManage, BusFault or UsageFault**, because those are *exceptions*, not panics —
and on this board, today, they do not reach any of our code at all.

The bootloader **never sets `SCB->VTOR`**. It is left at the reset value
`0x0000_0000`, which aliases to the **bootloader's own** vector table, and every fault
handler there is a bare `bkpt` followed by `b .`
(`mk4-bootloader/startup.S:43-59`). With no debugger attached a `bkpt` escalates to
HardFault and then to Lockup. So **a fault today is an infinite hang — no reset, no
counted reset, no recovery** — which is precisely the state this decision exists to
prevent. MicroPython did not inherit this because it sets `VTOR` itself
(`micropython/ports/stm32/main.c:308-311`, `MICROPY_HW_VTOR = 0x0802_0000`).

The fix is one store, and it belongs in the firmware entry:

    SCB->VTOR = memmap::FLASH_ISR_BASE;   // 0x0802_0000, then dsb + isb

with a full 16-entry vector table `KEEP`-ed at that address whose fault entries
trampoline into `panic!()` — which then reaches the existing handler and the existing
counted reset. It must be the **first** thing the entry does, before `.bss` zeroing and
before the allocator, because NMI is unmaskable and is reachable from a flash
double-bit ECC error (PLAN.md §8.1 item 5), so the window before `VTOR` is set is a
window in which any fault is unrecoverable.

**Status: not yet implemented** — there is no entry point and no vector table in this
tree. Recorded here because the decision as written above overstates its own coverage:
"a panic must never leave the device spinning" is currently true of panics and false of
faults. Do not treat decision 6 as satisfied until `VTOR` is set.

### Amended mechanism (the decision's intent is unchanged)

**`NVIC_SystemReset`, not DFU.** A plain system reset returns control to the
bootloader, whose verify path still holds a valid signed image, so a transient
panic self-heals. The callgate is attempted only as a late fallback, where it is
effective on RDP≠2 dev units and a harmless no-op elsewhere. Ordering:

1. `cpsid i` — stop reentrancy from interrupts.
2. Bump a reboot-survivable panic counter.
3. Under threshold → `NVIC_SystemReset`.
4. Past threshold → attempt callgate `enter_dfu` (selector 2, `arg2` 0 then 2).
5. Unconditional reset as the final fallback, so it can never halt.

No display and no allocation in the handler: the OLED driver can itself panic,
and the bootloader repaints on reset anyway. A handler in this shape **compiles
clean under 1.88.0 for `thumbv7em-none-eabihf`** and its disassembly was checked
(`cpsid i`, RTC WPR `0xCA`/`0x53` unlock, `cmp #0x3`, store to AIRCR `0xE000ED0C`,
and the `blx` guarded by the `(dest & 0xff) == 0x05` check) — **measured**.

The panic must additionally **not corrupt flash**, since the bootloader's own
verification is what makes the reset recoverable.

### Consequences: reset-loop risk moves the work upstream

A reset loop on a *deterministic* panic is now the real brick risk, so the
priority is eliminating panic sites rather than perfecting recovery.

| Priority | Site | Why |
|---|---|---|
| **1** | `device.rs:491` indexes `agg_nonces[signature_index]` | **Remotely triggerable by the coordinator.** `signature_index` enumerates `sign_items` (`device.rs:480-491`), whose length is the count of locally-owned input sighashes (`sign_task.rs:120-144`), but `GroupSignReq::check` never validates `agg_nonces.len()` against it (`message.rs:101-113` copies `agg_nonces` through unchecked; `sign_task.rs:42-102` checks purpose and ownership only). A coordinator sending fewer `agg_nonces` than sighashes panics the device. Must return `ActionError`. **Correction to an earlier draft of this table:** this is *post*-consent, not pre-consent — `device.rs:491` sits inside `sign_ack`, which upstream invokes only on `UiEvent::SigningConfirm` (`device/src/esp32_run.rs:736-741`), and `device.rs:491` is the *only* site that indexes `agg_nonces` (verified by grep across `frostsnap_core/src`). It is still a remote DoS/reset-loop reachable by a malicious or buggy coordinator once a user approves, and it still fires before any flash write. |
| 2 | `device_nonces.rs` write/sign path: `:234, :235, :269, :278, :281, :298, :300, :307` | 8 of the 16 panic sites in that file; each is a reset-loop trigger under `panic = "abort"`. `PLAN.md` §6 cited "223-310" — the function does span `:223`–`:311`, but the two `assert_eq!` are specifically at `:235` (stream id) and `:300` (read-back). |
| 3 | `frostsnap_embedded/src/ab_write.rs:44, :106, :109, :110, :118` | The panics that actually fire on real flash I/O errors, and not previously in scope. `AbSlot::write` erases+writes **twice** (`:56-57`), so any STM32 flash error panics mid-A/B-update — the worst possible moment for nonce state. |

Boot sequencing requirement: clear the panic counter only *after* the event loop
is proven healthy, or the counter never trips.

**What this forecloses.** Any design that treats DFU as the recovery path, and
any expectation that a field unit can be rescued into a *new* firmware build
without a working PIN. It also forecloses leaving `assert!`-based flash
verification in place: correctness asserts must become `Result` before hardware.

**Assumed, needs bench confirmation** — see `PLAN.md` §9.

---

## Residual gaps in the decision-3 change

Recorded because they are real, verified, and easy to lose track of. Three
independent adversarial reviews attempted to refute the tweak change; **none
refuted it** — the new hash was shown byte-identical to BIP-341 across 200,000
random messages and 5,000 curve points including 2,496 odd-y keys, and every
hardcoded vector was re-derived from primary sources with from-scratch
implementations. The following survived as confirmed defects anyway:

1. ~~**A parity blind spot in the test designated to outlive `bitcoin`.**~~
   **FIXED.** `output_keys_match_published_vectors` (`tweak.rs:548`) fed each
   vector in as `Point::<EvenY,..>::from_xonly_bytes(..).normalize()`, i.e.
   already even-Y, so `let (even_y, _) = self.into_point_with_even_y();`
   (`tweak.rs:342`) was a no-op for all four vectors. Replacing that line with
   `let even_y = self;` — deleting BIP-341's `lift_x` — left this test
   **passing**; only `matches_rust_bitcoin_over_many_keys` and
   `local_spk_regression` caught it, and **both die with the `bitcoin` dep**.
   Both production `LocalSpk` vectors have odd-y internal keys, so this was the
   common case, not an edge case.

   `odd_y_internal_keys_tweak_to_the_same_output` (`tweak.rs:573`) closes it by
   asserting the *property* rather than a fixture: `P` and `-P` share an x
   coordinate, so BIP-341 must tweak both to the same output key. Verified
   load-bearing — with the `lift_x` deletion applied it FAILS (3 failed vs the
   2 that failed before), and it does not depend on `bitcoin`, so the coverage
   survives decision 4 being revisited.
2. **Coverage asymmetry across impls.** All shipped tests exercise
   `TweakableKey for Point`. Production signs through `SharedKey`
   (`coordinator.rs:1591`, `:1614`) and `PairedSecretShare` (`device.rs:486`).
   Not a live bug — both funnel through `to_key()` — and `SharedKey` was
   confirmed to agree over 50 trials, but no pinned vector covers the device
   signing path.
3. **Doc claims that were wrong and are now corrected.** The change was
   reported as 6→8 tests; the true baseline is **4** (measured against the
   pristine backup), so it is 4→9 with the parity test added. The negative
   control was reported as "4 passed; 3 failed"; the true result is
   **4 passed; 4 failed** — `local_spk_regression` also fails and was omitted.
   And `wire_size_measure.rs` / `zz_claim3_crossover.rs` were described as
   matching "upstream's own fmt state"; they are **untracked** files in the
   reference checkout, i.e. this project's own earlier research scratch. They
   did not compile (26× `E0433` on `frostsnap_comms`), which broke
   `cargo test -p frostsnap_core` wholesale, so they were moved to
   `tools/research-scratch/`. The full suite is now **40 passing across 11
   binaries** with `--features coordinator`, including both wire-format
   backward-compat guards.
4. ~~**One new clippy warning, contradicting a "clippy clean" claim.**~~
   **FIXED.** `bitcoin_transaction.rs:524` raised `clippy::uninlined_format_args`
   from `alloc::format!("{:x}", spk)`; now `alloc::format!("{spk:x}")`. Neither
   changed file raises a clippy finding on the device or host+tests target.
5. **Interop was not run.** Decision 5's second leg — a real
   `frostsnap_coordinator` — has not been exercised against this change. The
   vector tests and the rust-bitcoin differential are strong evidence of
   consensus correctness; they are not evidence of wire-level interop.

---

## 7. `FRAME_LIMIT` is 4,096, not 2,060 — a reversal of decision 5's carried constraint

**Decision.** `coldsnap_hal::comms::FRAME_LIMIT` is **4,096 bytes**, raised from
2,060 on 2026-08-18. The bound stays structural and stays enforced in both
directions; only the number changes. This reverses the "carried into Phase 3 as a
hard constraint" paragraph in decision 5 and the phase-3 status text that called
2,060 a ceiling.

**Rationale — 2,060 was the wrong number, not merely a tight one.** It is
`MAX_MSG_LEN` from Coldcard's **HID** reassembly buffer (4+4+4+2048,
`shared/public_constants.py:26-31`, consumed by the 64-byte-report framing in
`shared/usb.py:140-172`). Phase 3 is **CDC**, and `frostsnap_comms` has never
heard of the number. A bound whose provenance is a different transport's framing
is not a security property, and this one refused **four real messages**, all
measured on the full `ReceiveSerial` frame rather than the body:

| Frame | Size | Who emits it |
|---|---|---|
| `SignatureShare` + a full 30-nonce replenish, **1** share | **2,105 B** | device |
| Inbound `RequestSign`, **11** owned inputs | **2,238 B** | coordinator |
| Keygen `CertifyPlease`, **9-of-9** | **2,179 B** | coordinator |
| `HeldShares2`, **14** stored shares | **2,215 B** | **device** |

The last row is the one that settles it: the device refusing to send a message the
device itself constructed is not a defence against anything. And no cheaper fix
was available — `SignatureShare` is one indivisible message
(`frostsnap_core/src/device.rs:509-523`), `NONCE_BATCH_SIZE` moves in lockstep
with the coordinator's `MIN_NONCES_BEFORE_REQUEST` (`coordinator.rs:43`), and
neither failing path has any existing segmentation to lean on (see PLAN.md §7 on
`SigningReqSubSegment`, which is not a wire type).

**Why 4,096 and not 3,072.** 3,072 covers every frame in the table and still
fails: **`RequestSign` at 20 owned inputs / 3 outputs is 3,944 B**, inside the
declared envelope. (This sentence used to read "a two-segment `NonceResponse` is
4,038 B, and the coordinator can force it, because its producer never calls
`OpenNonceStreams::split()`" — the split claim was **false**, corrected
2026-08-19; the coordinator does split, see PLAN.md §7's cap 1. 4,038 still fits
4,096; it is just not what rules 3,072 out.) 4,096 clears 3,944 with 152 B to
spare, clears every other measured frame in scope, and is a
round number — so the next raise is a decision about a power of two rather than an
argument about a Python constant.

**Consequences.**

- **SRAM: 8,192 B, not 4,096.** The cost is **2 × `FRAME_LIMIT`** — the
  accumulator is `[u8; FRAME_LIMIT]` inline in `Link` *and* `encode_frame` takes
  a `&mut [u8; FRAME_LIMIT]`. The raise costs 4,120 → 8,192 B, **1.25% of
  640 KiB**. Still SRAM nothing in this tree allocates yet, since nothing places
  a `Link`.
- **Signing and keygen are no longer refused by the transport**, in either
  direction, anywhere inside the declared envelope below.
- **Two pinning tests changed meaning rather than being deleted.**
  `real_signature_share_batch_is_refused` became
  `real_signature_share_batch_now_fits_within_the_raised_bound` — same fixture,
  same printed figures, opposite assertion — and
  `a_single_stream_nonce_response_fits_with_the_margin_plan_records` now records a
  2,056 B margin instead of 20 B. Both now assert **exact** sizes, so a wire-format
  change fails them instead of being absorbed by the bigger bound. Two tests were
  added: `the_four_frames_the_old_bound_refused_now_fit` (the reversal's
  justification, executable) and
  `three_nonce_segments_are_refused_by_the_new_bound` (the new refusal boundary,
  pinned with a real message so a future raise has to be deliberate too).
- **`usb.rs` arithmetic moved with it**: 4,096 is 64 × 64 exactly, so the
  short-final-packet case that 2,060 supplied for free is now exercised
  explicitly (`a_full_size_frame_survives_its_packets`), and the simulated FIFO
  grew to hold a whole frame.

**Declared support envelope: *n* ≤ 12 devices, any *t* ≤ *n*.** The binding frame
is keygen `CertifyPlease` at `195·n + 33·t + 127`, worst at *t* = *n*; 12-of-12 is
**2,863 B**, leaving **1,233 B spare**. `Check` (`163·n + 157`, *t*-independent)
is 2,113 B at *n* = 12. Also inside: up to 20 owned inputs, a full nonce batch
riding along with a `SignatureShare`, two nonce segments.

**Why 12 and not 17,** which is where `CertifyPlease` actually crosses 4,096: the
9-of-5 cell fits 2,060 by **13 bytes**, and that taught the lesson this envelope is
sized by — a margin that sits inside a varint boundary is not a margin, and one
added field on an upstream message moves the edge by more than it. 12 keeps
~1.2 KB of headroom, i.e. room for the wire format to grow without re-opening the
decision. It is also a number a support statement can survive: nobody runs a
17-device Frostsnap key today, and if they do, that is a phase-4 conversation with
a measurement attached.

**What this forecloses / what is explicitly out of scope.** All of these are
refusals — `CommsError::Desync` inbound, `CommsError::FrameTooLong` outbound, i.e.
a dropped message, never a truncated one — and none of them is fixed by this
decision:

- *n* ≥ 13 devices (13-of-13 `CertifyPlease` ≈ 3,091 B *fits*, but is outside the
  declared envelope on purpose, per the margin argument above).
- More than 20 owned inputs in one `RequestSign`.
- **Three or more nonce segments** in one `NonceResponse` (≈ 6,036 B at three, and
  unbounded in count).
- Hostile field content: an oversized `key_name`, `ScriptBuf`, `Test`, or `Nostr`
  body. None is bounded by anything today.
- OTA / firmware upgrade frames, the genuine check (`DO_GENUINE_CHECK = false`,
  and no coordinator-side refusal site exists), and the conch (off: `Downstream`
  signals VERSION_SIGNAL 2, conch needs 1).

**Three device-side caps are REQUIRED and UNIMPLEMENTED, so 4,096 is necessary
but not sufficient.** Nothing bounds what the device *constructs*: one nonce
segment per frame, a `HeldShares2` cap, and `Debug` string truncation. All three
live in message-construction code that does not exist in this tree — no event
loop, no bin target, no caller of `encode_frame` outside tests — so none was
written, and no helper was added that nothing calls. Recorded in `comms.rs`'s
module docs and PLAN.md §7 as phase-4 work. Without them the device can still
build a frame over any bound and then have its own encoder refuse it.

---

## Provenance

| Item | Value |
|---|---|
| Frostsnap commit | `0bbc18be3f9fb0a408b0c47a021816ece97f4661` (2026-08-11), MIT |
| Coldcard commit | `0431fd2b`, MIT (firmware); `hardware/` proprietary |
| Rust toolchain | 1.88.0 (`rust-toolchain.toml`) + `thumbv7em-none-eabihf` |
| C cross-compiler | clang 21, `/opt/homebrew/opt/llvm/bin/clang` (still required — decision 4) |
| Flash, as built | **860,898 bytes = 60.4%** of `FLASH_TEXT` 1,425,408 (`stm32/COLDCARD_MK4/layout.ld:17`); 844,229 at phase 0, 857,125 at the phase-2 gate. Re-measured 2026-08-19. The 893,099 figure was NOT a bad measurement: it is correct for a tree where the vendored `MAX_MESSAGE_ALLOC_SIZE` (32,768) differed from `comms::ENCAPS_DECODE_LIMIT` (20,480), which made `BINCODE_CONFIG` and `ENCAPS_CONFIG` distinct types and monomorphised the whole `CoordinatorSendBody` decode tree twice. Aligning the two constants collapsed the duplicate, worth 32,201 B; net cost of bounding both decode legs is +312 B. Confirmed by reverting the constant and reproducing 893,099 exactly — PLAN.md §10 is the authority. |
| Host tests passing | **268** (164 when this file was written; 204 at the phase-2 gate; 253 at the end of phase 3; 259 before decision 7 added two `comms` tests; 261 before PLAN.md §9 item 7(c) added three outer-leg decode-limit `comms` tests; 264 before the three inner-leg `decode_body` tests; 267 before the pin on the vendored `MAX_MESSAGE_ALLOC_SIZE`, 2026-08-19); only `frost_backup/tests/descriptor_match.rs` is excluded (decision 5) |

//! The Mk4 4×3 membrane keypad — cols `PB0`-`PB2` in, rows `PD8`-`PD11`
//! open-drain out.
//!
//! This is the **missing half of consent**. [`crate::ui::ConfirmDigit::accepts`]
//! has existed since phase 4 with no caller anywhere on the device path
//! (PLAN.md §9 item 21): `boot()` draws a randomised confirm digit and has no way
//! to receive the answer. Everything else in the stack is present-and-unverified,
//! which is what a bench is for; this was *absent*, which no bench can fix. This
//! module is the byte source, and nothing more — it decides which key closed and
//! refuses when it cannot tell. Whether that byte authorises a signature is
//! [`crate::ui`]'s question, exactly as [`crate::display`] moves pixels without
//! knowing what they say.
//!
//! # NOTHING HERE HAS RUN ON SILICON
//!
//! Every address, bit and mask below is transcribed from source, cited per item,
//! and **not one has been observed on a real Mk4**. Every `write_volatile` in
//! this file is **unverified-on-silicon**. See [the bench
//! list](#the-bench-list-phase-5).
//!
//! # THE DECODE TABLE IS NOT THE PRINTED LAYOUT — read this before touching it
//!
//! The matrix is wired **180° from the legend on the case**. The authoritative
//! electrical map is `shared/mempad.py:19`:
//!
//! ```text
//! DECODER = 'y0x987654321'          # indexed (row * NUM_COLS) + col
//! ```
//!
//! confirmed by its two use sites: `mempad.py:120` builds the index as
//! `(row * NUM_COLS) + col`, and `:152` decodes it as `DECODER[event]`. So
//! electrical `(0, 0)` is `y` (**OK**), and electrical index 2 is `x`
//! (**CANCEL**).
//!
//! **The orientation is settled from source, not transcribed on faith.** Their
//! git history has the table longhand: at commit `3bcd6512` ("Membrane keypad
//! support") `shared/numpad.py:14-30` is `DECODER = { (3,2):'1', (3,1):'2',
//! (3,0):'3', … (0,2):'x', (0,1):'0', (0,0):'y' }` under the comment
//! `# (row, col) => keycode`, grouped in the legend's reading order — the author
//! stating that the visually *top* row is electrical `M2_ROW3` and the visually
//! *left* column is electrical `M2_COL2`. Enumerated at `row * NUM_COLS + col`
//! that dict is byte-for-byte the string above, which `f999707f` merely
//! flattened it into. So electrical row 0 is the **bottom** physical row,
//! electrical col 0 the **rightmost** column, electrical index 0 the
//! bottom-right OK key: the pad is the legend rotated 180°, which is why the two
//! strings are exact reverses (all 12 bytes distinct, so `i → 11 - i` forces
//! `11 - (3r + c) = 3(3 - r) + (2 - c)`, and that decomposition is unique). It
//! agrees with what this module ships.
//!
//! Second source, per unit: `shared/selftest.py:35-49`'s `test_numpad()` walks
//! `'123456789x0y'`, prompts for each printed key and asserts the byte this
//! exact pipeline decodes; `shared/main.py:101-110` blocks the factory `tested`
//! flag on it. So which corner of the PCB `M2_ROW0` reaches is unknown *and
//! inconsequential* — we drive the same nets in the same roles, index with the
//! same arithmetic and decode with the same string, so we inherit the composite
//! that every shipped Mk4 was tested against. The only link that inheritance can
//! lose is the pin *order*, which the `const _: ()` block asserts against the
//! literal `pins.csv` values.
//!
//! There is a second, *wrong* string in the Coldcard tree and it is the one that
//! looks right: `'123456789x0y'[(row*3) + col]` at `unix/simulator.py:491`. That
//! is `click_to_key`, whose `row`/`col` come from **screen-pixel arithmetic on a
//! mouse click** (`(y - KEYPAD_TOP) // KEYPAD_PITCH`) and never from a matrix
//! scan. It is the printed layout, and the two strings are exact reverses.
//!
//! Shipping the simulator string here would be a **consent bypass, not a
//! cosmetic bug**, and it is worth spelling out because a reviewer skims a
//! keypad driver:
//!
//! * Electrical index 2 is physically CANCEL. Under the simulator string it
//!   decodes to `'3'`, which is in [`crate::ui::CONFIRM_CHARSET`] (`*b"12346"`).
//!   On the one prompt in five that draws `(3)`, **pressing CANCEL signs.**
//! * The other four digits become unpressable: a user pressing `1` (electrical
//!   index 11) would report `'y'`, which [`crate::ui::ConfirmDigit::accepts`]
//!   correctly refuses.
//!
//! 80% dead, 20% accidental approval, after an installation that is one-way
//! (RDP=2; `mk4-bootloader/dispatch.c:407`). [`DECODER`] therefore carries a
//! named regression test that asserts the byte at [`CANCEL_INDEX`] and asserts
//! the simulator string is *not* it — see
//! [`the_decode_table_is_the_matrix_map_not_the_printed_layout`](self).
//!
//! # The randomised row order is a security property
//!
//! `mempad.py:84` calls `shuffle(self.scan_order)` and `:35` says why: "We scan
//! in random order, because Tempest." Driving rows in a fixed sequence makes the
//! EM signature of a scan a function of *which* row was driven when a contact
//! closed, so an emissions capture leaks the key — on a device whose keypad
//! enters a PIN on shipping firmware and a signing approval here.
//!
//! **Do not delete [`shuffle_rows`] as a quirk.** It is six lines, it costs one
//! [`rand_core::RngCore::next_u32`] per scan, and this crate already carries an
//! RNG that everything else takes by `&mut`. It is deliberately **not** behind a
//! `cfg`: a `cfg` on a defence is a defence that fails open (lib.rs's directional
//! rule).
//!
//! The RNG arrives as a parameter rather than from a global, for the same reason
//! [`crate::ui::ConfirmDigit::draw`] takes one: it keeps the shuffle a pure
//! function of a seed and therefore host-testable, and it keeps this module free
//! of singleton state beyond the one pad token.
//!
//! # Simultaneous keys are a REFUSAL, because a diodeless matrix ghosts
//!
//! There are no diodes in the NUMPAD block — row rail → metal dome → column
//! rail, with a 1 kΩ series resistor per line and no external pull-up. So three
//! closed contacts synthesise a fourth: with `(r1,c1)`, `(r1,c2)` and `(r2,c1)`
//! held, scanning `r2` reads `c2` low as well and reports a key **nobody
//! pressed**. On a signing screen that is an accidental-approval path.
//!
//! The fail-closed answer is one `if`, and it is exact rather than heuristic: a
//! ghost requires two closed contacts sharing a row *and* two sharing a column,
//! so **a ghost can never be the only bit set in a full scan**. [`Debounce`]
//! therefore reports [`Event::MultiKey`] the moment any single full scan observes
//! more than one closed contact, and [`Event::Down`] is reachable only from a
//! scan that saw exactly one — which is provably ghost-free.
//!
//! `mempad.py` does not do this. Its `_finish_scan` comment is "not trying to
//! support multiple presses, just one" (`:141`) and it then pushes *every*
//! confirmed key into the queue (`:127-130`), leaving the layer above to take
//! whichever arrives first. That is acceptable for a PIN entry that gets
//! retried; it is not acceptable for a one-shot signing consent, so this is a
//! deliberate divergence and the stricter direction.
//!
//! # No waiting for a human happens here
//!
//! [`Keypad::read_key`] performs exactly [`DEBOUNCE_SAMPLES`] scans and returns,
//! reporting [`Event::AllUp`] if nothing was pressed. It never loops until a key
//! arrives. That is not an oversight: "wait for a human" is unbounded by nature,
//! and DECISIONS.md decision 6 forbids this crate from being where an unbounded
//! wait lives. The caller — `boot()` — owns the decision to keep asking and owns
//! its own bound on doing so, and it is also the only layer that knows whether a
//! timeout means "refuse" or "redraw".
//!
//! # The pins, double-sourced
//!
//! `shared/mempad.py:29-32` names the pins `'M2_COL0'`…`'M2_ROW3'`; those names
//! resolve in `stm32/COLDCARD_MK4/pins.csv:74-80`, **read directly for this
//! module**:
//!
//! | Signal | Pin | | Signal | Pin |
//! |---|---|---|---|---|
//! | `M2_COL0` | `PB0` | | `M2_ROW0` | `PD8` |
//! | `M2_COL1` | `PB1` | | `M2_ROW1` | `PD9` |
//! | `M2_COL2` | `PB2` | | `M2_ROW2` | `PD10` |
//! | | | | `M2_ROW3` | `PD11` |
//!
//! The `hardware/schematic-mark4d.png` U1A block agrees, package pin numbers
//! included (35/36/37 and 55/56/57/58) — second-sourced by the pin
//! investigation, not read here. So the map is **not a guess** and needs no
//! bench correction; it lives in one block ([`COL_PINS`]/[`ROW_PINS`]) and every
//! register mask below is *derived* from it rather than hand-computed twice.
//! Derived, but order-blind — the masks are OR-reductions, so the block's *order*
//! is separately asserted against these literal `pins.csv` numbers.
//!
//! Do **not** use `stm32/COLDCARD/pins.csv:96-102`. That is the Mk3 pad (rows
//! `PB12`/`PB13`/`PB14`/`PC6`, cols `PA1`/`PA3`/`PA2`, with col1/col2
//! transposed) and `PB13`/`PB14` on Mk4 are the DS28C36B's I²C
//! (`mk4-bootloader/se2.c:1022-1034`) — writing them would break SE2.
//!
//! # Who else owns these ports
//!
//! No cold-snap module touches `GPIOB` or `GPIOD`: [`crate::display`] is
//! `GPIOA` `BSRR` only and [`crate::usb`] is `GPIOA` `PA11`/`PA12`. The Mk4
//! bootloader configures exactly two pins across both ports and neither is
//! ours — `PB13`/`PB14` (I²C2, `se2.c:1022-1034`) and `PD2` (`SDMMC1_CMD`,
//! `sdcard.c:74-83`). `sdcard.c:47`'s `GPIO_PIN_8|9|10|11|12` reads like our
//! rows but the port at `:53` is `GPIOC`.
//!
//! **The collision that matters is in `RCC_AHB2ENR`, not in the ports.** Bit 0
//! `GPIOAEN` belongs to the panel (`display.rs`) and USB, bit 12 to `OTGFSEN`,
//! bit 18 to `RNGEN`. A blind `write_volatile(RCC_AHB2ENR, GPIOBEN | GPIODEN)`
//! would switch off the screen, the USB port and the entropy source in one
//! instruction. `enable_clocks` is a guarded read-modify-write, the shape
//! `rng`'s `enable_rng_clock` and `display::enable_clocks` already use.
//!
//! # `MODER` is not optional, and this is the failure it prevents
//!
//! The bootloader never reads the pad — there is no `mempad`/`numpad`/keypad
//! reference anywhere under `stm32/mk4-bootloader/` (grepped) — so unlike the
//! panel we inherit nothing and our seven pins arrive at reset defaults, i.e.
//! **analog mode**. An analog-mode pin reads 0 from `IDR` forever. A driver that
//! sets `PUPDR` and forgets `MODER` therefore sees all three columns low on
//! every scan: every key "pressed", every scan [`Event::MultiKey`], and a pad
//! that can never confirm anything. That is why `init_pins` writes both, and
//! why [`KeypadToken::open`] then *checks* it — see [`check_idle_columns`].
//!
//! No `ASCR` write is needed leaving analog mode on this part: that block of
//! `HAL_GPIO_Init` is `#if defined(STM32L471xx) || … || STM32L486xx`
//! (`stm32l4xx_hal_gpio.c:252-263`) and STM32L4S5 is not in the list.
//!
//! # Rows are OPEN-DRAIN. Push-pull would be a short
//!
//! `mempad.py:31` is `Pin(i, Pin.OUT_OD, value=0)`. With push-pull rows, any two
//! simultaneously closed domes in one column tie a driven-high row to a
//! driven-low row through 2 kΩ. Open-drain makes "not selected" mean Hi-Z, so
//! the worst case is a column that nobody pulls down. [`ROW_OTYPER_OD`] is the
//! security-relevant bit in this file's init.
//!
//! Row select is one atomic [`GPIOD_BSRR`] write, never a read-modify-write of
//! `ODR` — the argument `display.rs` gives for `GPIOA_BSRR`, and it applies
//! harder here because the bootloader also drives `PD2` on this port.
//!
//! # EXTI is deliberately skipped
//!
//! `mempad.py:56-57` arms falling+rising interrupts on the three columns
//! (EXTI0/1/2) purely so scanning starts on a press. cold-snap has no vector
//! table and no ISR by design (`usb.rs:56-62`). The idle state this module
//! leaves behind — all four rows driven low ([`ROWS_ALL_LOW`]) — makes any
//! closed dome pull its column low, so the same any-press detect is a poll of
//! [`GPIOB_IDR`] with zero interrupt machinery. It is also the Tempest-friendlier
//! idle: the row drivers are static.
//!
//! # What is host-testable here, and it is most of the file
//!
//! Everything except the seven `volatile` accesses: [`DECODER`] and [`key_at`],
//! [`pressed_cols`], [`row_select`], [`row_bits`], [`shuffle_rows`],
//! [`check_idle_columns`], all of [`Debounce`], and every derived register mask
//! against its hand-computed literal.
//!
//! There is deliberately **no fake GPIO**. A `GpioPort` double would be built
//! from the same header reading as the driver, so agreement would prove only
//! self-consistency — and a double more permissive than the hardware is worse
//! than no test (`display.rs` makes the same call about SPI). What replaces it
//! is that the register path is a thin shell over pure functions that *are*
//! tested: the scan loop is three lines of `volatile` around [`row_select`],
//! [`pressed_cols`] and [`row_bits`].
//!
//! # The bench list, phase 5
//!
//! 1. **Confirm the pad reads at all** — *not* the orientation, which is settled
//!    from source above and is no longer a gate. What no host test can reach is
//!    the ARM scan path. One press does it: print the raw electrical index from a
//!    single-bit [`Keypad::scan_once`] result and press the key marked `1`.
//!    Expect **11** (`DECODER[11] == b'1'`); a different single-bit index means
//!    the pad is wired unlike `pins.csv` and nothing downstream is trustworthy.
//!    Free prior, no build: boot stock Coldcard firmware and press `1` at the PIN
//!    prompt — if that echoes a digit, the wiring matches the firmware whose
//!    table this module copies verbatim.
//! 2. **[`ROW_SETTLE_SPINS`]** — a calculated floor times a safety factor, not a
//!    scope trace. Lower it until keys ghost, then take 4×. Belongs on the same
//!    list as [`crate::usb::MODE_SETTLE_SPINS`].
//! 3. **[`SAMPLE_GAP_SPINS`]** — stands in for `mempad.py`'s 60 Hz timer, which
//!    is what makes three "consecutive" samples a *debounce* rather than three
//!    reads of the same contact bounce. Wrong by 10× either way is still a
//!    working pad, so it is a comfort knob, not a correctness one.
//! 4. **[`KeypadError::ColumnsStuckLow`] should never be seen.** If it is, the
//!    `MODER` write did not take (see above) or a column line is shorted; either
//!    way the number in the error is the diagnostic.

use crate::display::{bsrr_clear, bsrr_set};
use crate::singleton::TakeOnce;
use rand_core::RngCore;

// ---------------------------------------------------------------------------
// Geometry
// ---------------------------------------------------------------------------

/// Rows in the matrix (`shared/mempad.py:12`, `NUM_ROWS = const(4)`).
pub const NUM_ROWS: usize = 4;

/// Columns in the matrix (`shared/mempad.py:13`, `NUM_COLS = const(3)`).
pub const NUM_COLS: usize = 3;

/// Keys on the pad: 12 metal domes, `B1`-`B12` on the schematic.
pub const KEY_COUNT: usize = NUM_ROWS * NUM_COLS;

// ---------------------------------------------------------------------------
// THE PIN MAP. One block, and every register mask below is derived from it.
// ---------------------------------------------------------------------------

/// Column pins on **`GPIOB`**: `PB0`, `PB1`, `PB2` — inputs with pull-ups.
///
/// `M2_COL0`/`M2_COL1`/`M2_COL2` at `stm32/COLDCARD_MK4/pins.csv:74-76` (read),
/// second-sourced from the `hardware/schematic-mark4d.png` U1A block (LQFP100
/// pins 35/36/37).
pub const COL_PINS: [u32; NUM_COLS] = [0, 1, 2];

/// Row pins on **`GPIOD`**: `PD8`…`PD11` — open-drain outputs.
///
/// `M2_ROW0`…`M2_ROW3` at `stm32/COLDCARD_MK4/pins.csv:77-80` (read),
/// second-sourced from the schematic U1A block (LQFP100 pins 55/56/57/58).
pub const ROW_PINS: [u32; NUM_ROWS] = [8, 9, 10, 11];

// ---------------------------------------------------------------------------
// The decode table. See the module docs -- this is the one that signs.
// ---------------------------------------------------------------------------

/// Electrical `(row, col)` → key byte, indexed `row * `[`NUM_COLS`]` + col`.
///
/// **Verbatim from `shared/mempad.py:19`**, whose index is built at `:120` as
/// `(row * NUM_COLS) + col` and decoded at `:152` as `DECODER[event]`.
///
/// This is the matrix map and **not** the printed layout. The reversed string
/// `"123456789x0y"` in `unix/simulator.py:491` is a mouse-click-to-pixel map;
/// substituting it turns CANCEL into a confirm digit. The module docs give the
/// full consequence, and
/// [`the_decode_table_is_the_matrix_map_not_the_printed_layout`](self) fails if
/// anyone swaps them.
pub const DECODER: [u8; KEY_COUNT] = *b"y0x987654321";

/// The decline key, as the pad reports it (`x`, bottom-left on the case).
///
/// [`crate::ui::ConfirmDigit::accepts`] refuses this like any other non-digit —
/// the refusal is "not the digit", never "is `x`". Named here only so the
/// electrical index of CANCEL can be asserted.
pub const KEY_CANCEL: u8 = b'x';

/// The OK key, as the pad reports it (`y`, bottom-right on the case).
///
/// Note it authorises **nothing** on a signing screen: consent is the randomised
/// digit, and `y` is in neither [`crate::ui::CONFIRM_CHARSET`] nor any accept
/// path.
pub const KEY_OK: u8 = b'y';

/// Electrical index of CANCEL in [`DECODER`], i.e. row 0, col 2.
///
/// The single number the printed-layout confusion turns on: under the simulator
/// string this index holds `'3'`, a live confirm digit.
pub const CANCEL_INDEX: usize = 2;

// ---------------------------------------------------------------------------
// Registers. Offsets from the CMSIS header in this tree, not from memory.
//
// `external/micropython/lib/stm32lib/CMSIS/STM32L4xx/Include/stm32l4s5xx.h`,
// referred to below as `stm32l4s5xx.h`. Same file `display.rs` and `usb.rs` cite.
// ---------------------------------------------------------------------------

/// `GPIOB` base: `AHB2PERIPH_BASE + 0x0400` = `0x4800_0400`
/// (`stm32l4s5xx.h:1449`, `AHB2PERIPH_BASE` at `:1320`).
pub const GPIOB_BASE: u32 = 0x4800_0400;

/// `GPIOD` base: `AHB2PERIPH_BASE + 0x0C00` = `0x4800_0C00`
/// (`stm32l4s5xx.h:1451`).
pub const GPIOD_BASE: u32 = 0x4800_0C00;

/// `GPIOB->MODER`, offset `0x00` (`GPIO_TypeDef`, `stm32l4s5xx.h:618`).
///
/// Read-modify-written once, for the three column pins only. `PB13`/`PB14` on
/// this port are SE2's I²C (`se2.c:1022-1034`), which is exactly why this is
/// never a whole-register store.
pub const GPIOB_MODER: *mut u32 = GPIOB_BASE as *mut u32;
/// `GPIOB->PUPDR`, offset `0x0C` (`stm32l4s5xx.h:621`).
pub const GPIOB_PUPDR: *mut u32 = (GPIOB_BASE + 0x0C) as *mut u32;
/// `GPIOB->IDR`, offset `0x10` (`stm32l4s5xx.h:622`). The only register this
/// module reads to sample a key. A column bit **low** means a dome is closed
/// against the currently driven row.
pub const GPIOB_IDR: *mut u32 = (GPIOB_BASE + 0x10) as *mut u32;

/// `GPIOD->MODER`, offset `0x00` (`stm32l4s5xx.h:618`).
pub const GPIOD_MODER: *mut u32 = GPIOD_BASE as *mut u32;
/// `GPIOD->OTYPER`, offset `0x04` (`stm32l4s5xx.h:619`) — the open-drain bit.
pub const GPIOD_OTYPER: *mut u32 = (GPIOD_BASE + 0x04) as *mut u32;
/// `GPIOD->PUPDR`, offset `0x0C` (`stm32l4s5xx.h:621`).
pub const GPIOD_PUPDR: *mut u32 = (GPIOD_BASE + 0x0C) as *mut u32;
/// `GPIOD->BSRR`, offset `0x18` (`stm32l4s5xx.h:624`).
///
/// Row select is one write here and never a read-modify-write of `ODR`:
/// `display.rs:409-412`'s argument, and the bootloader drives `PD2` on this same
/// port (`sdcard.c:74-83`).
pub const GPIOD_BSRR: *mut u32 = (GPIOD_BASE + 0x18) as *mut u32;

/// `RCC->AHB2ENR`, `0x4002_104C`. The **same register** [`crate::display`] and
/// [`crate::rng`] use; see the module docs for what a blind store here costs.
pub const RCC_AHB2ENR: *mut u32 = (0x4002_1000 + 0x4C) as *mut u32;
/// `RCC_AHB2ENR_GPIOBEN`, bit 1 (`stm32l4s5xx.h:12713`).
pub const RCC_AHB2ENR_GPIOBEN: u32 = 1 << 1;
/// `RCC_AHB2ENR_GPIODEN`, bit 3 (`stm32l4s5xx.h:12719`).
pub const RCC_AHB2ENR_GPIODEN: u32 = 1 << 3;

// ---------------------------------------------------------------------------
// Masks, DERIVED from the pin map. One definition of the pin map, so a pin
// change cannot leave a stale mask behind -- `display.rs`'s `window_prologue`
// lesson. The literals are pinned by `masks_match_the_hand_computed_literals`.
// ---------------------------------------------------------------------------

/// Two-bit-per-pin field mask (`MODER`, `PUPDR`, `OSPEEDR`) for `pins`.
const fn field2_mask(pins: &[u32]) -> u32 {
    let mut m = 0;
    let mut i = 0;
    while i < pins.len() {
        m |= 0x3 << (pins[i] * 2);
        i += 1;
    }
    m
}

/// Two-bit-per-pin field set to `value` for every pin in `pins`.
const fn field2_value(pins: &[u32], value: u32) -> u32 {
    let mut m = 0;
    let mut i = 0;
    while i < pins.len() {
        m |= (value & 0x3) << (pins[i] * 2);
        i += 1;
    }
    m
}

/// One-bit-per-pin mask (`OTYPER`, `IDR`, `ODR`, either `BSRR` half) for `pins`.
const fn field1_mask(pins: &[u32]) -> u32 {
    let mut m = 0;
    let mut i = 0;
    while i < pins.len() {
        m |= 1 << pins[i];
        i += 1;
    }
    m
}

/// `MODER` bits belonging to the columns: `0x0000_003F`.
pub const COL_MODER_MASK: u32 = field2_mask(&COL_PINS);
/// `PUPDR` bits belonging to the columns: `0x0000_003F`.
pub const COL_PUPDR_MASK: u32 = COL_MODER_MASK;
/// `PUPDR` value for the columns: pull-up on each, `0x0000_0015`.
///
/// `GPIO_PULLUP = 1` (`stm32l4xx_hal_gpio.h:151`), written as
/// `PUPDR |= Pull << (position * 2)` (`stm32l4xx_hal_gpio.c:266-269`). Matches
/// `mempad.py:30`'s `pull=Pin.PULL_UP`.
///
/// There is **no external pull-up** anywhere in the schematic's NUMPAD block
/// (`R13`-`R15` are 1 kΩ *series* to the MCU), so this internal one is the only
/// thing that makes an unpressed column read high. Omitting it is a pad that
/// reads noise.
pub const COL_PUPDR_PULLUP: u32 = field2_value(&COL_PINS, 1);
/// `IDR`/`BSRR` bit mask of the three column pins: `0x0000_0007`.
pub const COL_MASK: u32 = field1_mask(&COL_PINS);

/// `MODER` bits belonging to the rows: `0x00FF_0000`.
pub const ROW_MODER_MASK: u32 = field2_mask(&ROW_PINS);
/// `MODER` value for the rows: output on each, `0x0055_0000`.
///
/// `GPIO_MODE_OUTPUT_OD = 0x11` and `MODER` takes `Mode & GPIO_MODE` where
/// `GPIO_MODE = 0x3` (`stm32l4xx_hal_gpio.h:119`, `hal_gpio.c:130,227-230`), so
/// the two-bit field is `0b01`.
pub const ROW_MODER_OUTPUT: u32 = field2_value(&ROW_PINS, 1);
/// `PUPDR` bits belonging to the rows, cleared to `GPIO_NOPULL`
/// (`stm32l4xx_hal_gpio.h:150`; `mempad.py:31` passes no `pull`).
pub const ROW_PUPDR_MASK: u32 = ROW_MODER_MASK;
/// `OTYPER` bits for the rows — **open drain**: `0x0000_0F00`.
///
/// From `GPIO_MODE_OUTPUT_OD = 0x11`: `(0x11 & GPIO_OUTPUT_TYPE) >> 4 = 1`
/// (`stm32l4xx_hal_gpio.c:137,205-209`). The security-relevant bit in this
/// file — push-pull rows short row-to-row through two closed domes.
pub const ROW_OTYPER_OD: u32 = field1_mask(&ROW_PINS);
/// `BSRR`/`ODR` bit mask of the four row pins: `0x0000_0F00`.
pub const ROW_MASK: u32 = ROW_OTYPER_OD;

/// `BSRR` word driving **every** row low: the idle any-press probe.
///
/// `mempad.py:76`'s `_wait_any` does exactly this (`r.off()` on all four rows)
/// so that any closed dome pulls its column low and can be noticed without a
/// scan. This is the state [`KeypadToken::open`] and every
/// [`Keypad::scan_once`] leave the port in.
pub const ROWS_ALL_LOW: u32 = bsrr_clear(ROW_MASK);

/// `BSRR` word releasing every row to Hi-Z (open-drain, `ODR = 1`).
///
/// With all rows released nothing can pull a column down, which is what makes
/// [`check_idle_columns`] a real test of the column configuration.
pub const ROWS_ALL_RELEASED: u32 = bsrr_set(ROW_MASK);

// ---------------------------------------------------------------------------
// Timing. Counts, not times -- this crate has no timer.
// ---------------------------------------------------------------------------

/// Spin count standing in for the row→column settling the membrane needs.
///
/// `shared/mempad.py` has **no explicit delay at all**: between its last row
/// write (`:106-109`) and its first column read (`:112`) there are four
/// MicroPython attribute lookups, order of 10 µs at 120 MHz. Coldcard gets its
/// settle for free by being slow. Compiled Rust reads within ~10 ns of the
/// [`GPIOD_BSRR`] write and would sample the *previous* row.
///
/// The physics of the floor: columns have no external pull-up (schematic NUMPAD
/// block, `R13`-`R15` are 1 kΩ series), rows are open-drain so de-select is
/// Hi-Z, and the rise is the internal ~30-50 kΩ pull-up against dome and trace
/// capacitance — τ ≈ 2 µs, 3τ ≈ 6 µs. The pressed direction is fast and hard
/// (2 kΩ to a driven row).
///
/// Taking [`crate::usb::MODE_SETTLE_SPINS`]'s implied calibration (6e6 spins for
/// ST's `HAL_Delay(50)`, so ~120 iterations/µs) this is ~33 µs, 5× the floor,
/// and it costs 4 × 4,000 ≈ 133 µs against a 16.67 ms sample period — 0.8% duty.
/// Generous on purpose: too short fails **silently** into misread keys.
///
/// A count and not a figure. Bench item 2.
pub const ROW_SETTLE_SPINS: u32 = 4_000;

/// Spin count standing in for `mempad.py`'s 60 Hz sample timer
/// (`SAMPLE_FREQ = const(60)`, `:14` → 16.67 ms per full sample).
///
/// **This is what makes the debounce a debounce.** Three samples taken 100 µs
/// apart all observe the same contact bounce and confirm it; three samples 16 ms
/// apart do not. At the same ~120 iterations/µs this is ~16.7 ms, so a full
/// [`Keypad::read_key`] is ~50 ms — which is exactly `mempad.py`'s
/// `NUM_SAMPLES = 3` at 60 Hz (`:15`, `:123-136`).
///
/// A count and not a figure. Bench item 3, and the least critical of the three:
/// wrong by 10× in either direction still yields a working pad.
pub const SAMPLE_GAP_SPINS: u32 = 2_000_000;

/// Agreeing samples required to call a key down or up
/// (`shared/mempad.py:15`, `NUM_SAMPLES = const(3)`).
///
/// Halving this to 1 removes the debounce entirely and is caught by
/// [`one_sample_is_never_enough`](self).
pub const DEBOUNCE_SAMPLES: u8 = 3;

// ---------------------------------------------------------------------------
// Compile-time consistency. Cheap, and they hold on ARM too.
// ---------------------------------------------------------------------------

const _: () = {
    // 4 × 3 = 12 keys, and the decode table covers all of them.
    assert!(KEY_COUNT == 12);
    assert!(DECODER.len() == KEY_COUNT);
    // One `u16` must hold the whole pad, or `row_bits` shifts off the end.
    assert!(KEY_COUNT <= 16);
    // CANCEL really is where `CANCEL_INDEX` says, and it is not a digit.
    assert!(DECODER[CANCEL_INDEX] == KEY_CANCEL);
    assert!(DECODER[0] == KEY_OK);
    // The pin map must be the LITERAL `pins.csv:74-80` order, not merely
    // self-consistent, because that order is the whole inheritance argument:
    // `pressed_cols` reports raw `GPIOB` bit positions, so bit `j` is
    // `M2_COL{j}` only while `COL_PINS[j] == j`, and `row_select` drives
    // `ROW_PINS[k]` for the `k` that `row_bits` shifts by `k * NUM_COLS`
    // straight into a `DECODER` index. Every derived mask is an OR-reduction and
    // therefore order-insensitive, so a permuted array mirrors an axis of the
    // pad with every test in this file still green — CANCEL landing where a
    // confirm digit is drawn. Not hypothetical: the Mk3 pad really is wired
    // `PA1`/`PA3`/`PA2` (`stm32/COLDCARD/pins.csv:100-102`), which is exactly
    // this permutation.
    assert!(COL_PINS[0] == 0 && COL_PINS[1] == 1 && COL_PINS[2] == 2);
    assert!(ROW_PINS[0] == 8 && ROW_PINS[1] == 9);
    assert!(ROW_PINS[2] == 10 && ROW_PINS[3] == 11);
    // The two ports are distinct, so a column mask can never collide with a row
    // mask even though both are bit masks in the same numeric space.
    assert!(GPIOB_BASE != GPIOD_BASE);
    // Derived masks must be non-empty and must not overlap the bits the
    // bootloader owns on either port: `PB13`/`PB14` (SE2 I2C) and `PD2` (SDMMC).
    assert!(COL_MODER_MASK != 0 && ROW_MODER_MASK != 0);
    assert!(COL_MASK & ((1 << 13) | (1 << 14)) == 0);
    assert!(ROW_MASK & (1 << 2) == 0);
    assert!(field2_mask(&COL_PINS) & field2_value(&[13, 14], 0x3) == 0);
    assert!(field2_mask(&ROW_PINS) & field2_value(&[2], 0x3) == 0);
    // The pull-up value must sit inside the mask it is OR'd into, or the init
    // writes a bit belonging to another pin.
    assert!(COL_PUPDR_PULLUP & !COL_PUPDR_MASK == 0);
    assert!(ROW_MODER_OUTPUT & !ROW_MODER_MASK == 0);
    // The bounds that replace unbounded waits must actually be bounds.
    assert!(ROW_SETTLE_SPINS > 0 && ROW_SETTLE_SPINS < u32::MAX);
    assert!(SAMPLE_GAP_SPINS > 0 && SAMPLE_GAP_SPINS < u32::MAX);
    // A zero threshold confirms every key on zero evidence; 1 is no debounce.
    assert!(DEBOUNCE_SAMPLES >= 2);
    // Both `BSRR` halves must be the halves `display.rs` says they are.
    assert!(ROWS_ALL_LOW == 0x0F00_0000);
    assert!(ROWS_ALL_RELEASED == 0x0000_0F00);
};

// ---------------------------------------------------------------------------
// Pure logic. Most of this module, and all of what a test can reach.
// ---------------------------------------------------------------------------

/// The key byte at electrical `(row, col)`, or `None` out of range.
///
/// Total by construction: no indexing panic, no arithmetic that can overflow
/// (`row < 4`, `col < 3`, so the index is at most 11). That matters because
/// `overflow-checks = false` in release makes a wrapped index a *wrong key*
/// rather than a trap.
#[must_use]
pub fn key_at(row: usize, col: usize) -> Option<u8> {
    if row >= NUM_ROWS || col >= NUM_COLS {
        return None;
    }
    DECODER.get(row * NUM_COLS + col).copied()
}

/// Which columns read closed, from a raw [`GPIOB_IDR`] word: a 3-bit mask.
///
/// **Active low.** `mempad.py:112-119` tests `self.cols[n].value() == 0`, because
/// the only pull-up is internal and a closed dome ties the column to the driven
/// (low) row. Getting this inversion backwards is a pad that reports 11 keys
/// down at rest, which [`check_idle_columns`] would catch at open — but it is
/// cheaper to have a test.
///
/// Bits outside [`COL_MASK`] are ignored, so the other 13 pins on `GPIOB`
/// (`PB13`/`PB14` are SE2's I²C) cannot influence a keypress.
#[must_use]
pub const fn pressed_cols(idr: u32) -> u8 {
    ((!idr) & COL_MASK) as u8
}

/// [`GPIOD_BSRR`] word selecting `row`: that row's pin driven low, the other
/// three released to Hi-Z.
///
/// One atomic write, so no read-modify-write of an `ODR` the bootloader also
/// drives (`PD2`). Mirrors `mempad.py:106-109`'s `rows[i].value(row != i)` — the
/// selected row gets 0 (driven), the rest get 1 (Hi-Z under open drain).
///
/// An out-of-range `row` releases **every** row, i.e. drives nothing and reads
/// as no key. Fail-closed, and it is why this is not an indexing expression.
#[must_use]
pub fn row_select(row: usize) -> u32 {
    match ROW_PINS.get(row) {
        Some(&pin) => bsrr_clear(1 << pin) | (bsrr_set(ROW_MASK) & !bsrr_set(1 << pin)),
        None => ROWS_ALL_RELEASED,
    }
}

/// One row's sampled column mask, placed into the 12-bit pad bitmap.
///
/// Bit `row * `[`NUM_COLS`]` + col`, i.e. the same index [`DECODER`] takes. An
/// out-of-range `row` contributes nothing — total, and no shift overflow.
#[must_use]
pub const fn row_bits(row: usize, cols: u8) -> u16 {
    if row >= NUM_ROWS {
        return 0;
    }
    (((cols as u32) & COL_MASK) as u16) << (row * NUM_COLS)
}

/// Whether an idle [`GPIOB_IDR`] read is consistent with a configured pad.
///
/// With every row released to Hi-Z ([`ROWS_ALL_RELEASED`]) nothing in the matrix
/// can pull a column down, so all three must read high. A column reading low
/// means either the [`GPIOB_MODER`] write did not take — an analog-mode pin
/// reads 0 from `IDR` **forever**, which is the permanent all-keys-pressed
/// brick the module docs describe — or that line is shorted.
///
/// Cheap ( two writes and a read) and it converts a pad that would confirm every
/// prompt into a named error.
///
/// # Errors
///
/// [`KeypadError::ColumnsStuckLow`] carrying the raw word, because this is a
/// bench diagnostic first.
pub const fn check_idle_columns(idr: u32) -> Result<(), KeypadError> {
    if idr & COL_MASK != COL_MASK {
        return Err(KeypadError::ColumnsStuckLow { idr });
    }
    Ok(())
}

/// A fresh random row order — the Tempest defence, one `next_u32` per scan.
///
/// Fisher-Yates over `[0, 1, 2, 3]`, shuffled per scan rather than per press
/// burst. `mempad.py:84` shuffles once per `_start_scan`; per-scan is strictly
/// better for the property being bought and costs one more draw.
///
/// `%` rather than rejection sampling, for [`crate::ui::ConfirmDigit::draw`]'s
/// reason: the worst bias is the `% 3` case at 1 part in 1.4 billion, this is a
/// scan-order scramble and not a key, and a fixed-cost expression is what a
/// firmware path wants over a loop that can in principle spin.
///
/// The invariant that matters is that the result is a **permutation**: an order
/// that drops a row leaves three keys permanently unreadable, which on a confirm
/// screen is an unapprovable prompt.
#[must_use]
pub fn shuffle_rows<R: RngCore>(rng: &mut R) -> [u8; NUM_ROWS] {
    let mut order = [0u8; NUM_ROWS];
    let mut i = 0;
    while i < NUM_ROWS {
        order[i] = i as u8;
        i += 1;
    }
    // Downward Fisher-Yates. `i > 1` keeps `i - 1 >= 1`, so the decrement can
    // never wrap -- and under `overflow-checks = false` a wrap here would index
    // past the array.
    let mut i = NUM_ROWS;
    while i > 1 {
        i -= 1;
        let j = (rng.next_u32() % (i as u32 + 1)) as usize;
        order.swap(i, j);
    }
    order
}

/// What a completed debounce window says happened.
///
/// Four outcomes and not two, because "I could not tell" and "nothing was
/// pressed" are different answers on a consent screen and only one of them is a
/// refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// Every key open in every sample of the window. Not a refusal — the caller
    /// may simply ask again.
    AllUp,

    /// Exactly one key, the same one in every sample: the byte from
    /// [`DECODER`]. Provably ghost-free, because a matrix ghost needs two closed
    /// contacts sharing a row and two sharing a column and therefore can never
    /// be the only bit in a scan.
    Down(u8),

    /// More than one contact closed in a single scan, or more than one key
    /// confirmed across the window.
    ///
    /// **A REFUSAL, not a guess.** This is the ghost rejection: it is the only
    /// state from which a diodeless matrix can invent a key, so the driver
    /// declines to name one. It also covers two genuinely-held keys, which on a
    /// signing screen is equally not a consent.
    MultiKey,

    /// The samples disagreed — a contact bounced mid-window, or a key was
    /// pressed or released across it. Not an event and not a refusal; poll
    /// again. This is the state `mempad.py:123-136` handles by appending nothing
    /// to its queue.
    Unsettled,
}

/// The debounce state machine: [`DEBOUNCE_SAMPLES`] agreeing scans in, one
/// [`Event`] out.
///
/// Pure, so **host-testable in full**, which is the point: this and [`DECODER`]
/// are where a consent bug would live, and neither needs silicon to exercise.
///
/// Transcribed from `mempad.py:114-136` with two deliberate changes. (1) The
/// per-key counters are [`u8`] with `saturating_add`, not `+= 1`: with
/// `overflow-checks = false` in release a wrapped counter is a key that never
/// confirms, or worse confirms on the wrong sample, and it would pass every host
/// test because dev builds trap instead. (2) Multiple simultaneous keys are
/// [`Event::MultiKey`] rather than several queued keydowns — see the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Debounce {
    /// Per-key count of samples in which that key read closed.
    history: [u8; KEY_COUNT],
    /// Samples fed so far this window.
    samples: u8,
    /// Sticky: some single scan saw more than one contact closed.
    multi: bool,
}

impl Debounce {
    /// An empty window.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            history: [0; KEY_COUNT],
            samples: 0,
            multi: false,
        }
    }

    /// Feed one full-scan bitmap (bit `row * `[`NUM_COLS`]` + col`).
    ///
    /// `None` until [`DEBOUNCE_SAMPLES`] scans have been fed; then the verdict,
    /// and the window resets so the same [`Debounce`] can be reused.
    ///
    /// # Panics
    ///
    /// Must not, ever. All arithmetic is `saturating_add` and every index comes
    /// from iterating a fixed-size array.
    pub fn push(&mut self, bitmap: u16) -> Option<Event> {
        // Ghost rejection, on the RAW scan and not just on the verdict: a scan
        // that observed two contacts is ghost-capable whether or not either
        // contact survives the window.
        if bitmap.count_ones() > 1 {
            self.multi = true;
        }
        for (i, count) in self.history.iter_mut().enumerate() {
            if bitmap & (1 << i) != 0 {
                *count = count.saturating_add(1);
            }
        }
        self.samples = self.samples.saturating_add(1);
        if self.samples < DEBOUNCE_SAMPLES {
            return None;
        }
        let event = self.verdict();
        *self = Self::new();
        Some(event)
    }

    /// The verdict for a full window. Separate from [`Debounce::push`] only so
    /// the reset cannot be forgotten on one path.
    fn verdict(&self) -> Event {
        if self.multi {
            return Event::MultiKey;
        }
        let mut down: Option<u8> = None;
        let mut any_contact = false;
        for (i, count) in self.history.iter().enumerate() {
            if *count == 0 {
                continue;
            }
            any_contact = true;
            if *count >= DEBOUNCE_SAMPLES {
                if down.is_some() {
                    return Event::MultiKey;
                }
                // `history` and `DECODER` are both `[_; KEY_COUNT]`, so this is
                // in range; `get` rather than `[]` because a bounds-check panic
                // on a consent path is permanent on this device, and a `None`
                // here degrades to `Unsettled` rather than to a wrong key.
                down = DECODER.get(i).copied();
            }
        }
        match (down, any_contact) {
            (Some(key), _) => Event::Down(key),
            (None, true) => Event::Unsettled,
            (None, false) => Event::AllUp,
        }
    }
}

impl Default for Debounce {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Failures
// ---------------------------------------------------------------------------

/// Everything that can go wrong between a finger and a byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeypadError {
    /// Not `thumbv7em-none-eabihf`. There is no `GPIOB` on the host and no
    /// fallback: a host build that reached the register accesses would
    /// dereference `0x4800_0400` and `SIGSEGV`.
    NotOnThisTarget,

    /// A column read low with every row released to Hi-Z, which is
    /// electrically impossible on a working pad — see [`check_idle_columns`].
    /// The raw word travels with the error because this is a bench diagnostic
    /// first: `0` here means the [`GPIOB_MODER`] write did not take.
    ColumnsStuckLow {
        /// `GPIOB->IDR` as read.
        idr: u32,
    },
}

// ---------------------------------------------------------------------------
// The capability
// ---------------------------------------------------------------------------

/// The take-once ticket for the pad.
///
/// Same split as [`crate::display::PanelToken`] and [`crate::usb::UsbToken`]:
/// [`KeypadToken::take`] is pure and callable anywhere, [`KeypadToken::open`] is
/// the only thing that configures a pin, and the token implements nothing — so
/// an unconfigured pad is unrepresentable and no caller can sample a column
/// whose `MODER` was never written.
pub struct KeypadToken {
    _private: (),
}

impl KeypadToken {
    /// Take the singleton token. `None` on the second and later calls.
    ///
    /// Touches no hardware.
    #[must_use]
    pub fn take() -> Option<Self> {
        // NOT an `AtomicBool`: `.bss` on this board arrives full of `0xdeadbeef`
        // (`mk4-bootloader/main.c:42,47`), so `AtomicBool::new(false)` reads
        // `true` and this would return `None` on the FIRST call. See
        // `crate::singleton`.
        static TAKEN: TakeOnce = TakeOnce::new();
        if TAKEN.take() {
            Some(Self { _private: () })
        } else {
            None
        }
    }

    /// Configure the seven pins, prove the columns are readable, and hand back
    /// the pad.
    ///
    /// Consumes the token by value, so a failed open cannot be retried with the
    /// same token and a successful one cannot be duplicated.
    ///
    /// Order of operations, and each step is load-bearing:
    ///
    /// 1. `enable_clocks` — guarded read-modify-write of [`RCC_AHB2ENR`].
    /// 2. `init_pins` — rows to open-drain-Hi-Z, columns to input-pull-up.
    /// 3. Read [`GPIOB_IDR`] with all rows still released and refuse via
    ///    [`check_idle_columns`].
    /// 4. Drive all rows low ([`ROWS_ALL_LOW`]), the idle any-press state.
    ///
    /// **Unverified-on-silicon**, all of it.
    ///
    /// # Errors
    ///
    /// [`KeypadError::NotOnThisTarget`] off ARM;
    /// [`KeypadError::ColumnsStuckLow`] if the columns do not read high at rest.
    ///
    /// # Panics
    ///
    /// Must not, ever. A panic here is a boot-time reset loop (DECISIONS.md
    /// decision 6).
    pub fn open(self) -> Result<Keypad, KeypadError> {
        // `return` is load-bearing exactly as in `display::PanelToken::open`: on
        // ARM the block below is deleted and a bare `Err(..)` tail in statement
        // position is a discarded `#[must_use]`, not a return value.
        #[cfg(not(target_arch = "arm"))]
        #[allow(clippy::needless_return)]
        {
            let _ = &self;
            return Err(KeypadError::NotOnThisTarget);
        }

        #[cfg(target_arch = "arm")]
        {
            let _ = &self;
            enable_clocks();
            init_pins();
            // Rows are still released from `init_pins`, so nothing in the matrix
            // can pull a column down. Settle first: this is the same weak
            // pull-up rise the scan depends on.
            spin(ROW_SETTLE_SPINS);
            // SAFETY: `GPIOB_IDR` (`0x4800_0410`) is a 4-byte-aligned
            // memory-mapped register and this is a read with no side effects.
            let idr = unsafe { core::ptr::read_volatile(GPIOB_IDR) };
            check_idle_columns(idr)?;
            // Leave the port in the idle any-press state (`mempad.py:76`).
            bsrr_write(ROWS_ALL_LOW);
            Ok(Keypad { _private: () })
        }
    }
}

/// A configured pad: scans in, key bytes out.
///
/// Obtainable only from [`KeypadToken::open`], which is what makes "the columns
/// are actually readable" a property of the type rather than of a comment.
pub struct Keypad {
    _private: (),
}

impl Keypad {
    /// One full scan of all four rows in a fresh random order — the 12-bit pad
    /// bitmap, bit `row * `[`NUM_COLS`]` + col`.
    ///
    /// A **complete** scan before anything is decided, matching
    /// `mempad.py:36-37`'s "complete scan is done before acting on what was
    /// measured": a partial scan cannot see the second contact that makes a
    /// reading a ghost.
    ///
    /// Public because it is the bench door — item 1 of the bench list is
    /// printing raw indices from this and diffing against [`DECODER`] — and
    /// because [`Debounce`] is public, so a caller with different timing needs
    /// can drive the pair directly. Reachable only through a [`Keypad`].
    ///
    /// Leaves the rows driven low ([`ROWS_ALL_LOW`]) on every path.
    ///
    /// **Unverified-on-silicon.**
    ///
    /// # Errors
    ///
    /// [`KeypadError::NotOnThisTarget`] off ARM.
    ///
    /// # Panics
    ///
    /// Must not, ever. The loop is over a fixed-size array; [`row_select`] and
    /// [`row_bits`] are total.
    pub fn scan_once<R: RngCore>(&mut self, rng: &mut R) -> Result<u16, KeypadError> {
        #[cfg(not(target_arch = "arm"))]
        #[allow(clippy::needless_return)]
        {
            let _ = (&self, rng);
            return Err(KeypadError::NotOnThisTarget);
        }

        #[cfg(target_arch = "arm")]
        {
            let order = shuffle_rows(rng);
            let mut bitmap = 0u16;
            for &row in order.iter() {
                let row = row as usize;
                bsrr_write(row_select(row));
                spin(ROW_SETTLE_SPINS);
                // SAFETY: as `KeypadToken::open` -- a side-effect-free read of
                // `GPIOB->IDR`.
                let idr = unsafe { core::ptr::read_volatile(GPIOB_IDR) };
                bitmap |= row_bits(row, pressed_cols(idr));
            }
            // Back to the idle any-press state on every path.
            bsrr_write(ROWS_ALL_LOW);
            Ok(bitmap)
        }
    }

    /// One debounce window: [`DEBOUNCE_SAMPLES`] scans, [`SAMPLE_GAP_SPINS`]
    /// apart, and the [`Event`] they agree on.
    ///
    /// **Returns rather than waiting.** [`Event::AllUp`] is the answer when
    /// nothing was pressed; there is no loop here that ends only when a human
    /// acts. The caller owns that loop and its bound — see the module docs.
    ///
    /// Bounded by construction: [`DEBOUNCE_SAMPLES`] × ([`NUM_ROWS`] ×
    /// [`ROW_SETTLE_SPINS`] + [`SAMPLE_GAP_SPINS`]) iterations, ~50 ms, no
    /// condition anywhere.
    ///
    /// **Unverified-on-silicon.**
    ///
    /// # Errors
    ///
    /// [`KeypadError::NotOnThisTarget`] off ARM.
    ///
    /// # Panics
    ///
    /// Must not, ever.
    pub fn read_key<R: RngCore>(&mut self, rng: &mut R) -> Result<Event, KeypadError> {
        let mut debounce = Debounce::new();
        // `DEBOUNCE_SAMPLES` is the exact number `push` needs to reach a
        // verdict, so this loop cannot fall through -- but if the constant and
        // the machine ever disagreed, `Unsettled` is the fail-closed answer
        // rather than a fabricated key.
        for _ in 0..DEBOUNCE_SAMPLES {
            let bitmap = self.scan_once(rng)?;
            if let Some(event) = debounce.push(bitmap) {
                return Ok(event);
            }
            #[cfg(target_arch = "arm")]
            spin(SAMPLE_GAP_SPINS);
        }
        Ok(Event::Unsettled)
    }
}

// ---------------------------------------------------------------------------
// The register pokes. ARM only, and every one of them unverified-on-silicon.
// ---------------------------------------------------------------------------

/// One [`GPIOD_BSRR`] write. **Unverified-on-silicon.**
#[cfg(target_arch = "arm")]
fn bsrr_write(word: u32) {
    // SAFETY: `GPIOD_BSRR` (`0x4800_0c18`) is a 4-byte-aligned memory-mapped
    // register. `BSRR` is write-only and atomic by construction -- set bits in
    // the low half, reset bits in the high half -- so this cannot
    // read-modify-write a pin another owner holds and cannot be torn by an
    // interrupt. The only pins named are `PD8`-`PD11`; the bootloader's `PD2`
    // (`sdcard.c:74-83`) is untouched because its bit appears in neither half.
    unsafe { core::ptr::write_volatile(GPIOD_BSRR, word) };
}

/// Burn `count` iterations. Bounded by construction, no condition.
#[cfg(target_arch = "arm")]
fn spin(count: u32) {
    for _ in 0..count {
        // SAFETY: `nop` touches no memory and no special register.
        unsafe { core::arch::asm!("nop", options(nomem, nostack, preserves_flags)) }
    }
}

/// Enable the `GPIOB` and `GPIOD` peripheral clocks, idempotently.
///
/// The bootloader has already enabled all of A-E unconditionally
/// (`mk4-bootloader/gpio.c:26-30`) and handoff is a jump rather than a reset, so
/// in practice this is a no-op. Doing it anyway removes a dependency on
/// bootloader behaviour we do not control, exactly as `rng`'s
/// `enable_rng_clock` and `display::enable_clocks` do.
///
/// **Read-modify-write, and that is the whole point.** A blind store of
/// `GPIOBEN | GPIODEN` to this register clears `GPIOAEN` (the panel and USB),
/// `OTGFSEN` and `RNGEN` — the screen, the USB port and the entropy source, in
/// one instruction.
///
/// **Unverified-on-silicon.**
#[cfg(target_arch = "arm")]
fn enable_clocks() {
    const WANT: u32 = RCC_AHB2ENR_GPIOBEN | RCC_AHB2ENR_GPIODEN;
    // SAFETY: `RCC_AHB2ENR` (`0x4002_104c`) is a 4-byte-aligned memory-mapped
    // register. This is a read-modify-write setting two enable bits, guarded so
    // already-set bits are never rewritten; it cannot disable a peripheral
    // another module owns and it starts no transfer. The read-back is what ST's
    // own clock-enable macros do so the peripheral is reachable before the next
    // access (`stm32l4xx_hal_rcc.h:1134-1140`).
    unsafe {
        let en = core::ptr::read_volatile(RCC_AHB2ENR);
        if en & WANT != WANT {
            core::ptr::write_volatile(RCC_AHB2ENR, en | WANT);
            let _ = core::ptr::read_volatile(RCC_AHB2ENR);
        }
        core::arch::asm!("dsb sy", options(nostack, preserves_flags));
    }
}

/// Configure the seven pins: rows open-drain output released to Hi-Z, columns
/// input with pull-up.
///
/// Every write is a **read-modify-write of the pins in the mask only**. Both
/// ports carry a bootloader-owned pin — `PB13`/`PB14` for SE2's I²C
/// (`se2.c:1022-1034`) and `PD2` for `SDMMC1_CMD` (`sdcard.c:74-83`) — so a
/// whole-register store here would break SE2 or the SD card.
///
/// Order matters, and this is the only ordering that never drives a row
/// push-pull:
///
/// 1. `GPIOD_OTYPER |= `[`ROW_OTYPER_OD`] — open drain **before** the pin is an
///    output at all.
/// 2. `GPIOD_PUPDR &= !`[`ROW_PUPDR_MASK`] — `GPIO_NOPULL`.
/// 3. [`ROWS_ALL_RELEASED`] into `BSRR` — presets `ODR = 1`, which `BSRR`
///    accepts regardless of `MODER`, so the pin is Hi-Z the instant it becomes
///    an output.
/// 4. `GPIOD_MODER` → [`ROW_MODER_OUTPUT`].
/// 5. `GPIOB_PUPDR` → [`COL_PUPDR_PULLUP`] **before** `GPIOB_MODER` leaves
///    analog, so a column is never a floating input.
/// 6. `GPIOB_MODER &= !`[`COL_MODER_MASK`] — `GPIO_MODE_INPUT = 0`
///    (`stm32l4xx_hal_gpio.h:117`).
///
/// `OSPEEDR` is left at its reset value on both ports: `HAL_GPIO_Init` skips it
/// for inputs (`hal_gpio.c:200-204`) and this is a 60 Hz scan, so the slowest
/// setting is correct for the rows too. Fewer registers touched is fewer ways to
/// disturb a neighbour.
///
/// **Unverified-on-silicon.**
#[cfg(target_arch = "arm")]
fn init_pins() {
    // SAFETY: all six are 4-byte-aligned memory-mapped GPIO configuration
    // registers. Every one is a read-modify-write confined to the bits of the
    // seven pins in the module's pin map, which the module docs establish are
    // owned by nobody else in this firmware and by nobody in the bootloader.
    // None of these writes can start a transfer or clear another peripheral's
    // enable.
    unsafe {
        // --- rows: PD8..PD11, open-drain output, no pull, released -----------
        let otyper = core::ptr::read_volatile(GPIOD_OTYPER);
        core::ptr::write_volatile(GPIOD_OTYPER, otyper | ROW_OTYPER_OD);

        let pupdr = core::ptr::read_volatile(GPIOD_PUPDR);
        core::ptr::write_volatile(GPIOD_PUPDR, pupdr & !ROW_PUPDR_MASK);

        core::ptr::write_volatile(GPIOD_BSRR, ROWS_ALL_RELEASED);

        let moder = core::ptr::read_volatile(GPIOD_MODER);
        core::ptr::write_volatile(GPIOD_MODER, (moder & !ROW_MODER_MASK) | ROW_MODER_OUTPUT);

        // --- columns: PB0..PB2, input with pull-up --------------------------
        let pupdr = core::ptr::read_volatile(GPIOB_PUPDR);
        core::ptr::write_volatile(GPIOB_PUPDR, (pupdr & !COL_PUPDR_MASK) | COL_PUPDR_PULLUP);

        let moder = core::ptr::read_volatile(GPIOB_MODER);
        // `GPIO_MODE_INPUT = 0`, so clearing the field IS the write.
        core::ptr::write_volatile(GPIOB_MODER, moder & !COL_MODER_MASK);

        core::arch::asm!("dsb sy", options(nostack, preserves_flags));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic `RngCore`, same shape as `ui`'s test counter. A real
    /// entropy source is not the thing under test here — the permutation
    /// property is.
    struct Counter(u32);

    impl RngCore for Counter {
        fn next_u32(&mut self) -> u32 {
            let v = self.0;
            self.0 = self.0.wrapping_add(1);
            v
        }
        fn next_u64(&mut self) -> u64 {
            self.next_u32() as u64
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for b in dest {
                *b = self.next_u32() as u8;
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    /// A splitmix-ish scrambler, so the shuffle is not only ever fed a counter.
    struct Scramble(u64);

    impl RngCore for Scramble {
        fn next_u32(&mut self) -> u32 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            ((z ^ (z >> 31)) >> 32) as u32
        }
        fn next_u64(&mut self) -> u64 {
            ((self.next_u32() as u64) << 32) | self.next_u32() as u64
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for b in dest {
                *b = self.next_u32() as u8;
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    /// Build a scan bitmap from a list of physical key bytes. Uses the decode
    /// table backwards, so a transposed table shows up as a *different* bitmap
    /// and the debounce tests notice too.
    fn scan_of(keys: &[u8]) -> u16 {
        let mut bitmap = 0u16;
        for k in keys {
            let i = DECODER
                .iter()
                .position(|d| d == k)
                .unwrap_or_else(|| panic!("{:?} is not a key on this pad", *k as char));
            bitmap |= 1 << i;
        }
        bitmap
    }

    /// Run a whole window through a fresh `Debounce`.
    fn window(samples: &[u16]) -> Option<Event> {
        let mut d = Debounce::new();
        let mut out = None;
        for s in samples {
            if let Some(e) = d.push(*s) {
                out = Some(e);
            }
        }
        out
    }

    // -----------------------------------------------------------------------
    // The decode table. This is the test that stops a signing bypass.
    // -----------------------------------------------------------------------

    /// **THE CONSENT-BYPASS REGRESSION.** `shared/mempad.py:19`'s `DECODER` is
    /// the electrical map; `unix/simulator.py:491`'s `'123456789x0y'` is a
    /// mouse-click map for a *picture* of the keypad and the two are exact
    /// reverses.
    ///
    /// Substituting the simulator string puts `'3'` — a live member of
    /// `ui::CONFIRM_CHARSET` — at the electrical index of the CANCEL key, so on
    /// the one prompt in five that draws `(3)`, pressing CANCEL signs. The other
    /// four digits become unpressable. This asserts both halves so neither can
    /// be reintroduced.
    #[test]
    fn the_decode_table_is_the_matrix_map_not_the_printed_layout() {
        assert_eq!(
            DECODER, *b"y0x987654321",
            "DECODER must be verbatim shared/mempad.py:19"
        );

        // The two anchors: CANCEL at electrical index 2, `1` at index 11.
        assert_eq!(DECODER[CANCEL_INDEX], KEY_CANCEL, "electrical 2 must be x");
        assert_eq!(DECODER[KEY_COUNT - 1], b'1', "electrical 11 must be 1");
        assert_eq!(DECODER[0], KEY_OK, "electrical 0 must be y");

        // The wrong string, named so nobody re-derives it from the case legend.
        const SIMULATOR_MOUSE_MAP: [u8; KEY_COUNT] = *b"123456789x0y";
        assert_ne!(
            DECODER, SIMULATOR_MOUSE_MAP,
            "that is unix/simulator.py:491's click_to_key, a PIXEL map"
        );
        // They are exact reverses -- which is why the mistake is so easy.
        let mut reversed = SIMULATOR_MOUSE_MAP;
        reversed.reverse();
        assert_eq!(DECODER, reversed);

        // And here is precisely what the wrong one costs. If this assertion ever
        // fails, the hazard changed shape and the test above needs rewriting;
        // it does not mean the wrong map became safe.
        assert!(
            crate::ui::CONFIRM_CHARSET.contains(&SIMULATOR_MOUSE_MAP[CANCEL_INDEX]),
            "the pixel map puts a CONFIRM DIGIT on the cancel key -- that is the bug"
        );
        assert!(
            !crate::ui::CONFIRM_CHARSET.contains(&DECODER[CANCEL_INDEX]),
            "cancel must never decode to a confirm digit"
        );
    }

    /// Every `(row, col)` maps to the right key, exhaustively, and out-of-range
    /// maps to nothing rather than panicking or wrapping.
    #[test]
    fn every_row_col_pair_maps_to_its_key() {
        // The full table, written out from `mempad.py:19` independently of the
        // constant so an off-by-one in the index arithmetic is visible.
        let expect: [[u8; NUM_COLS]; NUM_ROWS] = [
            [b'y', b'0', b'x'],
            [b'9', b'8', b'7'],
            [b'6', b'5', b'4'],
            [b'3', b'2', b'1'],
        ];
        for (r, row) in expect.iter().enumerate() {
            for (c, want) in row.iter().enumerate() {
                assert_eq!(
                    key_at(r, c),
                    Some(*want),
                    "({r},{c}) must be {}",
                    *want as char
                );
            }
        }
        // All twelve keys distinct, or two contacts report the same byte.
        for (i, a) in DECODER.iter().enumerate() {
            for (j, b) in DECODER.iter().enumerate().skip(i + 1) {
                assert_ne!(a, b, "duplicate key at {i} and {j}");
            }
        }
        // Out of range is `None`, on every axis, including the values that would
        // wrap or alias if the bound were arithmetic instead of a comparison.
        for (r, c) in [
            (NUM_ROWS, 0),
            (0, NUM_COLS),
            (NUM_ROWS, NUM_COLS),
            (usize::MAX, 0),
            (0, usize::MAX),
            (usize::MAX, usize::MAX),
        ] {
            assert_eq!(key_at(r, c), None, "({r},{c}) must not decode");
        }
    }

    /// Every digit a confirm prompt can draw must be producible by this pad, or
    /// that prompt is unapprovable — a device that draws `(4)` and has no `4`.
    #[test]
    fn every_confirm_digit_is_a_key_on_this_pad() {
        for d in crate::ui::CONFIRM_CHARSET {
            assert!(
                DECODER.contains(&d),
                "confirm digit {} is not on the pad",
                d as char
            );
        }
        // And the two non-digit keys exist, exactly once each.
        assert_eq!(DECODER.iter().filter(|k| **k == KEY_CANCEL).count(), 1);
        assert_eq!(DECODER.iter().filter(|k| **k == KEY_OK).count(), 1);
        // `y` must not be a confirm digit: OK-means-yes is the bypass
        // `ui::ConfirmDigit` exists to remove.
        assert!(!crate::ui::CONFIRM_CHARSET.contains(&KEY_OK));
        assert!(!crate::ui::CONFIRM_CHARSET.contains(&KEY_CANCEL));
    }

    // -----------------------------------------------------------------------
    // Column sampling and row select
    // -----------------------------------------------------------------------

    /// Columns are ACTIVE LOW (`mempad.py:112-119` tests `== 0`), and no other
    /// pin on `GPIOB` may influence a keypress — `PB13`/`PB14` are SE2's I²C.
    #[test]
    fn columns_are_active_low_and_ignore_the_rest_of_the_port() {
        // Nothing pressed: all three high.
        assert_eq!(pressed_cols(0xFFFF_FFFF), 0);
        // Each column alone.
        assert_eq!(pressed_cols(!0b001), 0b001);
        assert_eq!(pressed_cols(!0b010), 0b010);
        assert_eq!(pressed_cols(!0b100), 0b100);
        // All three -- the analog-mode / stuck-line failure.
        assert_eq!(pressed_cols(0), 0b111);
        // SE2's I2C pins low must not read as a keypress.
        assert_eq!(pressed_cols(!((1 << 13) | (1 << 14))), 0);
        // Nor any other pin on the port.
        for bit in 3..32 {
            assert_eq!(
                pressed_cols(!(1u32 << bit)),
                0,
                "PB{bit} low must not be a key"
            );
        }
    }

    /// One row driven low, the other three released, in one atomic `BSRR` word —
    /// and `PD2` (the bootloader's `SDMMC1_CMD`) never named in either half.
    #[test]
    fn row_select_drives_exactly_one_row_and_releases_the_rest() {
        for (row, &pin) in ROW_PINS.iter().enumerate() {
            let w = row_select(row);
            let driven = w >> 16;
            let released = w & 0xFFFF;
            assert_eq!(driven, 1 << pin, "row {row} must drive only PD{pin} low");
            assert_eq!(
                released,
                ROW_MASK & !(1 << pin),
                "row {row} must release the other three"
            );
            // Every row pin accounted for, exactly once, in exactly one half.
            assert_eq!(driven | released, ROW_MASK);
            assert_eq!(driven & released, 0);
            // The bootloader's PD2 is in neither half.
            assert_eq!(w & ((1 << 2) | (1 << 18)), 0, "PD2 must never be touched");
        }
        // Out of range releases everything rather than panicking or aliasing
        // onto a real row -- fail closed.
        for row in [NUM_ROWS, NUM_ROWS + 1, usize::MAX] {
            assert_eq!(row_select(row), ROWS_ALL_RELEASED);
        }
        // The two idle words, and the halves they live in.
        assert_eq!(ROWS_ALL_LOW, 0x0F00_0000);
        assert_eq!(ROWS_ALL_RELEASED, 0x0000_0F00);
        assert_ne!(ROWS_ALL_LOW, ROWS_ALL_RELEASED);
    }

    /// `row_bits` must place a row's columns at the same index `DECODER` reads,
    /// or the whole pad is transposed. Cross-checked against `key_at` rather
    /// than against itself.
    #[test]
    fn row_bits_agrees_with_the_decode_index() {
        for r in 0..NUM_ROWS {
            for c in 0..NUM_COLS {
                let bits = row_bits(r, 1 << c);
                assert_eq!(bits.count_ones(), 1, "({r},{c}) must set exactly one bit");
                let i = bits.trailing_zeros() as usize;
                assert_eq!(
                    DECODER.get(i).copied(),
                    key_at(r, c),
                    "bit {i} must decode to the key at ({r},{c})"
                );
            }
            // A whole row at once.
            assert_eq!(row_bits(r, 0b111).count_ones(), 3);
        }
        // Nothing pressed contributes nothing; out-of-range row contributes
        // nothing (and cannot overflow the shift).
        assert_eq!(row_bits(0, 0), 0);
        for r in [NUM_ROWS, usize::MAX] {
            assert_eq!(row_bits(r, 0b111), 0);
        }
        // Bits above the three columns are masked off, so a bad `pressed_cols`
        // cannot smear into the next row's keys.
        assert_eq!(row_bits(0, 0xFF), 0b111);
        assert_eq!(row_bits(1, 0xFF), 0b111 << NUM_COLS);
    }

    // -----------------------------------------------------------------------
    // The Tempest shuffle
    // -----------------------------------------------------------------------

    /// The shuffle must always be a PERMUTATION. An order that drops a row
    /// leaves three keys permanently unreadable, which on a confirm screen is a
    /// prompt nobody can approve — and it would look exactly like a dead pad.
    #[test]
    fn shuffle_is_always_a_permutation_of_every_row() {
        for seed in 0..512u32 {
            let order = shuffle_rows(&mut Counter(seed));
            let mut seen = [false; NUM_ROWS];
            for &r in order.iter() {
                let r = r as usize;
                assert!(r < NUM_ROWS, "row {r} out of range from seed {seed}");
                assert!(!seen[r], "row {r} scanned twice from seed {seed}");
                seen[r] = true;
            }
            assert!(seen.iter().all(|s| *s), "a row was never scanned: {order:?}");
        }
    }

    /// THE TEMPEST DEFENCE. `mempad.py:35` — "We scan in random order, because
    /// Tempest." A fixed order makes the EM signature of a scan reveal which key
    /// closed. Deleting the shuffle (or ignoring the RNG) fails here.
    ///
    /// Requires every one of the 4! = 24 orders to appear, which no
    /// constant-returning or partially-shuffling implementation can satisfy.
    #[test]
    fn shuffle_reaches_every_row_order() {
        let mut rng = Scramble(1);
        let mut seen: [bool; 24] = [false; 24];
        // Lehmer-code index in the factorial number system, so "which
        // permutation" is a number: c0*3! + c1*2! + c2*1! + c3*0!.
        const FACT: [usize; NUM_ROWS] = [6, 2, 1, 1];
        let index = |o: [u8; NUM_ROWS]| -> usize {
            let mut idx = 0usize;
            for i in 0..NUM_ROWS {
                let smaller = o[i + 1..].iter().filter(|x| **x < o[i]).count();
                idx += smaller * FACT[i];
            }
            idx
        };
        for _ in 0..20_000 {
            seen[index(shuffle_rows(&mut rng))] = true;
        }
        let missing = seen.iter().filter(|s| !**s).count();
        assert_eq!(
            missing, 0,
            "{missing} of 24 row orders never produced -- is the shuffle real?"
        );
        // And it must not be the identity every time, which is the specific
        // shape a deleted shuffle takes.
        let mut rng = Scramble(7);
        let identity = [0u8, 1, 2, 3];
        assert!(
            (0..64).any(|_| shuffle_rows(&mut rng) != identity),
            "shuffle returned the fixed order every time"
        );
    }

    // -----------------------------------------------------------------------
    // Debounce and ghost rejection
    // -----------------------------------------------------------------------

    /// THREE agreeing scans, and not one fewer. Halving the threshold, or
    /// emitting a verdict early, fails here.
    ///
    /// The literal `3` is asserted rather than only the loop being written
    /// against [`DEBOUNCE_SAMPLES`]: a test whose expectations are all derived
    /// from the constant it is meant to pin passes at *any* value of it,
    /// including 1, which is no debounce at all.
    #[test]
    fn one_sample_is_never_enough() {
        assert_eq!(
            DEBOUNCE_SAMPLES, 3,
            "mempad.py:15 NUM_SAMPLES -- lowering this removes the debounce"
        );
        let one = scan_of(b"4");
        // Written out at the literal count, so a halved threshold shows up here
        // as a verdict arriving on the second push.
        let mut d = Debounce::new();
        assert_eq!(d.push(one), None, "a verdict after 1 of 3 samples");
        assert_eq!(d.push(one), None, "a verdict after 2 of 3 samples");
        assert_eq!(d.push(one), Some(Event::Down(b'4')));

        let mut d = Debounce::new();
        for n in 1..DEBOUNCE_SAMPLES {
            assert_eq!(
                d.push(one),
                None,
                "a verdict after only {n} of {DEBOUNCE_SAMPLES} samples"
            );
        }
        assert_eq!(d.push(one), Some(Event::Down(b'4')));
        // The window reset itself, so the next press needs the full count again.
        assert_eq!(d.push(one), None);
    }

    /// A steady press on each of the twelve keys reports that key, and nothing
    /// pressed reports `AllUp` — not `Down`, and not `Unsettled`.
    #[test]
    fn a_steady_press_reports_its_own_key() {
        for &key in DECODER.iter() {
            let s = scan_of(&[key]);
            assert_eq!(
                window(&[s; DEBOUNCE_SAMPLES as usize]),
                Some(Event::Down(key)),
                "steady press of {} misreported",
                key as char
            );
        }
        assert_eq!(
            window(&[0; DEBOUNCE_SAMPLES as usize]),
            Some(Event::AllUp),
            "an idle pad must report AllUp"
        );
    }

    /// THE GHOST REJECTION. A diodeless matrix with three closed contacts
    /// reports a fourth key nobody pressed; on a signing screen that is an
    /// accidental approval. Every multi-contact pattern must be `MultiKey`, and
    /// accepting any of them fails here.
    /// The Tempest defence is CALLED, not merely present.
    ///
    /// This reads its own source, and that needs justifying because it is the only
    /// test in the crate that does. `scan_once`'s body is inside
    /// `#[cfg(target_arch = "arm")]`, and every gate in this project runs
    /// `--target aarch64-apple-darwin`, so **no host gate ever compiles that block**.
    /// `shuffle_rows` is thoroughly tested as a function, but nothing tied it to its
    /// only caller: replacing `let order = shuffle_rows(rng)` with a fixed `[0,1,2,3]`
    /// left all 237 hal tests green and the ARM release build clean — MEASURED, which
    /// is why this exists.
    ///
    /// A fake GPIO would be the other way to reach that block, and it is the wrong
    /// way: a test double more permissive than the hardware is worse than no test, and
    /// this crate says so about `fake-flash` already. Reading the source proves the
    /// call site textually, which is exactly the property that was unguarded. The
    /// precedent is `tools/pixel-check.py`, which lifts Coldcard's own decoder out of
    /// their file rather than reimplementing it.
    ///
    /// If `scan_once` is ever renamed or restructured, this test fails loudly rather
    /// than silently passing — the `expect` below is the guard against that.
    #[test]
    fn the_scan_order_is_actually_shuffled_at_the_only_call_site() {
        const SRC: &str = include_str!("keypad.rs");

        let at = SRC
            .find("pub fn scan_once")
            .expect("scan_once was renamed or removed; this guard must be re-pointed");
        // The body ends at the next item at the same indentation.
        let rest = &SRC[at..];
        let end = rest[1..].find("\n    pub fn ").map_or(rest.len(), |i| i + 1);
        let body = &rest[..end];

        assert!(
            body.contains("shuffle_rows("),
            "scan_once no longer shuffles its row order. That is the Tempest defence \
             (EM side-channel: a fixed order lets emissions reveal which key was \
             pressed). See the module docs; do not delete it as a quirk."
        );
        // And not a hardcoded order alongside it, which is how the measured mutation
        // defeated every other test.
        for fixed in ["[0u8, 1, 2, 3]", "[0, 1, 2, 3]", "[0u8, 1u8, 2u8, 3u8]"] {
            assert!(
                !body.contains(fixed),
                "scan_once contains a hardcoded row order {fixed}, which defeats the \
                 shuffle even if `shuffle_rows` is still called"
            );
        }
    }

    #[test]
    fn simultaneous_contacts_are_refused_never_guessed() {
        // The classic ghost: two keys sharing a row, two sharing a column. The
        // scan reports a fourth key -- `x` here is pressed by nobody.
        //   (0,0)=y (0,1)=0 (1,0)=9  =>  ghost at (1,1)=8
        let ghost = scan_of(b"y09");
        assert_eq!(window(&[ghost; 3]), Some(Event::MultiKey));
        // And with the ghost bit actually set, as the hardware would report it.
        let ghost_seen = scan_of(b"y098");
        assert_eq!(window(&[ghost_seen; 3]), Some(Event::MultiKey));

        // Two keys, every way they can share nothing / a row / a column.
        for (a, b) in [
            (b'y', b'0'), // same row
            (b'y', b'9'), // same column
            (b'x', b'1'), // opposite corners
            (b'1', b'2'), // adjacent digits
            (b'x', b'y'), // cancel and OK together
        ] {
            let s = scan_of(&[a, b]);
            assert_eq!(
                window(&[s; 3]),
                Some(Event::MultiKey),
                "{} + {} must refuse",
                a as char,
                b as char
            );
        }

        // A second contact in ONLY ONE sample still refuses: the scan that saw
        // it was ghost-capable whether or not the contact survived. This is the
        // sticky flag, and it is the fail-closed direction.
        let one = scan_of(b"4");
        let two = scan_of(b"46");
        for at in 0..DEBOUNCE_SAMPLES as usize {
            let mut samples = [one; DEBOUNCE_SAMPLES as usize];
            samples[at] = two;
            assert_eq!(
                window(&samples),
                Some(Event::MultiKey),
                "a second contact in sample {at} must refuse"
            );
        }

        // Exhaustive: every 12-bit scan with more than one bit set refuses when
        // held steady. 4,096 patterns, so there is no "pattern we did not think
        // of" left.
        for bits in 0u16..(1 << KEY_COUNT) {
            let want = match bits.count_ones() {
                0 => Event::AllUp,
                1 => Event::Down(DECODER[bits.trailing_zeros() as usize]),
                _ => Event::MultiKey,
            };
            assert_eq!(
                window(&[bits; DEBOUNCE_SAMPLES as usize]),
                Some(want),
                "scan {bits:#014b} misjudged"
            );
        }
    }

    /// A contact that bounces mid-window is `Unsettled` — not a keypress, and
    /// not a refusal either, so the caller can simply ask again. `mempad.py`
    /// handles this by appending nothing to its queue (`:123-136`).
    #[test]
    fn a_bit_flip_mid_press_does_not_register() {
        let one = scan_of(b"2");
        // Press, gap, press: two of three samples.
        assert_eq!(window(&[one, 0, one]), Some(Event::Unsettled));
        // Rising edge caught mid-window.
        assert_eq!(window(&[0, one, one]), Some(Event::Unsettled));
        // Falling edge caught mid-window.
        assert_eq!(window(&[one, one, 0]), Some(Event::Unsettled));
        // A window that sees two DIFFERENT keys in different samples is
        // `Unsettled`, not `MultiKey`, and the distinction is deliberate: no
        // single scan ever observed two closed contacts, so no ghost was
        // possible and nothing was fabricated. It is a roll-off between presses
        // at 16 ms granularity. Either verdict is fail-closed (neither confirms
        // a key); `Unsettled` is the one that lets the caller poll again instead
        // of turning a fumbled press into a hard refusal on a signing screen.
        let other = scan_of(b"3");
        assert_eq!(window(&[one, other, one]), Some(Event::Unsettled));
        assert_eq!(window(&[one, one, other]), Some(Event::Unsettled));
        // Whereas the two keys in the SAME scan is the refusal.
        assert_eq!(
            window(&[scan_of(b"23"); DEBOUNCE_SAMPLES as usize]),
            Some(Event::MultiKey)
        );
        // And an `Unsettled` window leaves no residue: the next clean window
        // reports correctly.
        let mut d = Debounce::new();
        assert_eq!(d.push(one), None);
        assert_eq!(d.push(0), None);
        assert_eq!(d.push(one), Some(Event::Unsettled));
        for _ in 0..(DEBOUNCE_SAMPLES - 1) {
            assert_eq!(d.push(one), None);
        }
        assert_eq!(d.push(one), Some(Event::Down(b'2')));
    }

    /// The per-key counters must SATURATE. `mempad.py:120` is `+= 1`; with
    /// `overflow-checks = false` in release a `u8` counter fed 256 scans wraps
    /// to 0, and a debounce counter that wraps is a key that never confirms.
    /// Dev builds trap instead, so this class of bug is invisible to a passing
    /// test suite unless the saturation is asserted directly.
    #[test]
    fn debounce_counters_saturate_rather_than_wrap() {
        let one = scan_of(b"6");
        let mut d = Debounce::new();
        // Far more pushes than `u8::MAX`, without ever going through a reset:
        // push a partial window repeatedly and check the verdict is still right.
        for _ in 0..400 {
            let mut inner = d;
            // Fill out a window from a deep-counted state.
            for _ in 0..DEBOUNCE_SAMPLES {
                if let Some(e) = inner.push(one) {
                    assert_eq!(e, Event::Down(b'6'));
                }
            }
            let _ = d.push(one).map(|e| assert_eq!(e, Event::Down(b'6')));
        }
        // Direct: a single key held through 300 windows always confirms.
        let mut d = Debounce::new();
        let mut confirmed = 0usize;
        for _ in 0..(300 * DEBOUNCE_SAMPLES as usize) {
            if let Some(e) = d.push(one) {
                assert_eq!(e, Event::Down(b'6'));
                confirmed += 1;
            }
        }
        assert_eq!(confirmed, 300, "a held key stopped confirming");
    }

    // -----------------------------------------------------------------------
    // Registers, as arithmetic rather than as trust
    // -----------------------------------------------------------------------

    /// Every derived mask against the value hand-computed from the reference
    /// manual field layout. The `const fn`s exist so the pin map has one
    /// definition; these literals exist so the `const fn`s cannot be wrong
    /// quietly.
    #[test]
    fn masks_match_the_hand_computed_literals() {
        // Columns PB0/PB1/PB2: two-bit fields at 1:0, 3:2, 5:4.
        assert_eq!(COL_MODER_MASK, 0x0000_003F);
        assert_eq!(COL_PUPDR_MASK, 0x0000_003F);
        assert_eq!(COL_PUPDR_PULLUP, 0x0000_0015, "0b01_01_01, GPIO_PULLUP = 1");
        assert_eq!(COL_MASK, 0x0000_0007);
        // Rows PD8..PD11: two-bit fields at 17:16 .. 23:22.
        assert_eq!(ROW_MODER_MASK, 0x00FF_0000);
        assert_eq!(ROW_MODER_OUTPUT, 0x0055_0000, "0b01 each, GPIO_MODE & 0x3");
        assert_eq!(ROW_PUPDR_MASK, 0x00FF_0000);
        assert_eq!(ROW_OTYPER_OD, 0x0000_0F00, "the open-drain bits");
        assert_eq!(ROW_MASK, 0x0000_0F00);
        // The pull-up and output values sit strictly inside their masks, or the
        // init writes a bit belonging to a neighbouring pin.
        assert_eq!(COL_PUPDR_PULLUP & !COL_PUPDR_MASK, 0);
        assert_eq!(ROW_MODER_OUTPUT & !ROW_MODER_MASK, 0);
        // Neither port's masks may touch the pins the bootloader configured:
        // PB13/PB14 (SE2 I2C, se2.c:1022-1034) and PD2 (SDMMC1_CMD,
        // sdcard.c:74-83).
        for bit in [13u32, 14] {
            assert_eq!(COL_MASK & (1 << bit), 0);
            assert_eq!(COL_MODER_MASK & (0x3 << (bit * 2)), 0);
            assert_eq!(COL_PUPDR_MASK & (0x3 << (bit * 2)), 0);
        }
        assert_eq!(ROW_MASK & (1 << 2), 0);
        assert_eq!(ROW_MODER_MASK & (0x3 << 4), 0, "PD2's MODER field");
        assert_eq!(ROW_OTYPER_OD & (1 << 2), 0, "PD2's OTYPER bit");
    }

    /// The register offsets, as a layout rather than as seven independent
    /// numbers, and pinned against the one other module that uses the same RCC
    /// register.
    #[test]
    fn register_offsets_follow_gpio_typedef() {
        // `GPIO_TypeDef`, stm32l4s5xx.h:618-625.
        assert_eq!(GPIOB_BASE, 0x4800_0400);
        assert_eq!(GPIOD_BASE, 0x4800_0C00);
        assert_eq!(GPIOB_MODER as usize, GPIOB_BASE as usize);
        assert_eq!(GPIOB_PUPDR as usize, GPIOB_BASE as usize + 0x0C);
        assert_eq!(GPIOB_IDR as usize, GPIOB_BASE as usize + 0x10);
        assert_eq!(GPIOD_MODER as usize, GPIOD_BASE as usize);
        assert_eq!(GPIOD_OTYPER as usize, GPIOD_BASE as usize + 0x04);
        assert_eq!(GPIOD_PUPDR as usize, GPIOD_BASE as usize + 0x0C);
        assert_eq!(GPIOD_BSRR as usize, GPIOD_BASE as usize + 0x18);
        // Both ports are `GPIOA_BASE + n * 0x400`, which is what makes the two
        // bases checkable against `display.rs`'s.
        assert_eq!(GPIOB_BASE, 0x4800_0000 + 0x400);
        assert_eq!(GPIOD_BASE, 0x4800_0000 + 3 * 0x400);
        assert_eq!(GPIOD_BSRR as usize - GPIOD_BASE as usize, 0x18);
        // THE SHARED REGISTER. `display` and `rng` both use it; a divergence
        // here means one of the three is wrong, and a blind store to it would
        // switch off the panel, USB and the RNG.
        assert_eq!(RCC_AHB2ENR as usize, 0x4002_104C);
        assert_eq!(RCC_AHB2ENR as usize, crate::display::RCC_AHB2ENR as usize);
        assert_eq!(RCC_AHB2ENR as usize, crate::rng::RCC_AHB2ENR as usize);
        // And our two enable bits must not be anyone else's.
        assert_eq!(RCC_AHB2ENR_GPIOBEN, 1 << 1);
        assert_eq!(RCC_AHB2ENR_GPIODEN, 1 << 3);
        let ours = RCC_AHB2ENR_GPIOBEN | RCC_AHB2ENR_GPIODEN;
        assert_eq!(
            ours & crate::display::RCC_AHB2ENR_GPIOAEN,
            0,
            "GPIOAEN is the panel's and USB's"
        );
        assert_eq!(ours & (1 << 18), 0, "bit 18 is RNGEN");
        assert_eq!(ours & (1 << 12), 0, "bit 12 is OTGFSEN");
    }

    /// The idle-column check is the guard against the permanent
    /// all-keys-pressed brick: an analog-mode pin reads 0 from `IDR` forever, so
    /// a forgotten `MODER` write makes every prompt approve itself.
    #[test]
    fn idle_columns_must_all_read_high() {
        assert_eq!(check_idle_columns(0xFFFF_FFFF), Ok(()));
        // Only the three column bits matter; the rest of the port is somebody
        // else's and must not cause a refusal.
        assert_eq!(check_idle_columns(COL_MASK), Ok(()));
        for other in [0u32, 1 << 13, 1 << 14, 0xFFFF_FFF8] {
            assert_eq!(check_idle_columns(COL_MASK | other), Ok(()));
        }
        // A single column stuck low is a refusal, named and numbered.
        for &pin in COL_PINS.iter() {
            let idr = COL_MASK & !(1 << pin);
            assert_eq!(
                check_idle_columns(idr),
                Err(KeypadError::ColumnsStuckLow { idr }),
                "PB{pin} stuck low must refuse"
            );
        }
        // The analog-mode case: IDR reads 0.
        assert_eq!(
            check_idle_columns(0),
            Err(KeypadError::ColumnsStuckLow { idr: 0 })
        );
    }

    /// The two spin counts are bench knobs, but they must be bounds: zero
    /// settling samples the previous row, and a debounce with no gap between
    /// samples is not a debounce.
    #[test]
    fn the_spin_counts_are_bounds_and_are_named_for_the_bench() {
        // That neither is 0 or `u32::MAX` is asserted in the `const _: ()` block
        // above, which is strictly stronger: it holds at compile time and on ARM
        // too, where this test does not run.
        //
        // The gap between samples must dominate the settling, or three
        // "consecutive" samples are three reads of one contact bounce.
        let one_scan = ROW_SETTLE_SPINS * NUM_ROWS as u32;
        assert!(
            SAMPLE_GAP_SPINS > one_scan,
            "the debounce gap ({SAMPLE_GAP_SPINS}) is shorter than one scan ({one_scan})"
        );
        assert_eq!(DEBOUNCE_SAMPLES, 3, "mempad.py:15, NUM_SAMPLES");
        assert_eq!(NUM_ROWS, 4, "mempad.py:12");
        assert_eq!(NUM_COLS, 3, "mempad.py:13");
    }

    #[test]
    fn token_is_a_singleton_and_cannot_open_off_arm() {
        let token = KeypadToken::take().expect("first take must succeed");
        for _ in 0..4 {
            assert!(
                KeypadToken::take().is_none(),
                "handed the keypad out more than once"
            );
        }
        // `Keypad` is deliberately not `Debug`/`PartialEq` -- it is a
        // capability, not a value -- so compare the error side.
        assert_eq!(token.open().err(), Some(KeypadError::NotOnThisTarget));
    }
}

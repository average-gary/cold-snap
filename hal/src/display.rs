//! The 128×64 SSD1306 OLED on SPI1 — `CS PA4` / `RESET PA6` / `DC PA8`.
//!
//! This module moves 1,024 bytes to a panel and does nothing else. It knows
//! nothing about glyphs, pages or consent screens; that is `ui`'s job, and the
//! split is the same one [`crate::usb`]/[`crate::comms`] draw — the module that
//! touches registers must not also be the module that decides what a user is
//! being asked to approve.
//!
//! # NOTHING HERE HAS RUN ON SILICON
//!
//! Every register address, bit position and byte sequence below is transcribed
//! from source (cited per item) and **not one of them has been observed on a
//! real Mk4**. No hardware and no display exist in the environment this was
//! written in. Every `write_volatile` in this file is **unverified-on-silicon**;
//! see [the bench list](#the-bench-list-phase-5) for the four reads that retire
//! most of the doubt.
//!
//! # The design: no initialisation at all
//!
//! The laziest possible driver is also the most robust one here, and that is not
//! a coincidence — it falls out of two facts about the handoff.
//!
//! **Fact 1 — the panel is already live.** `oled_setup()` runs unconditionally on
//! every boot (`mk4-bootloader/main.c:110`) and, before it hands control to us,
//! has: enabled the `GPIOA` and `SPI1` clocks (`oled.c:183-184`), muxed `PA5`/`PA7`
//! to `AF5_SPI1` and `PA4`/`PA6`/`PA8` to push-pull output (`oled.c:187-206`),
//! pulsed `RESET` (1 ms high, `RESET` low, 10 ms, release — `oled.c:209-213`),
//! configured `SPI1` as an 8-bit mode-0 master with software NSS
//! (`oled.c:144-160`), sent the full Mk4 init sequence including `0x20 0x00`
//! horizontal addressing (`oled.c:18-35`), and left the display **on** and
//! showing the verify screen.
//!
//! **Fact 2 — and this is the hazard, absent from PLAN.md and DECISIONS.md — the
//! bootloader has permanently LOCKED the pin configuration.** `oled.c:205-207`
//! calls `HAL_GPIO_LockPin(GPIOA, RESET_PIN | CS_PIN | DC_PIN)` with the motive
//! "lock the RESET pin so that St's DFU code doesn't clear screen". Per
//! `stm32l4xx_hal_gpio.c:467-505`, that freezes `MODER`, `OTYPER`, `OSPEEDR`,
//! `PUPDR`, `AFRL` and `AFRH` for `PA4`/`PA6`/`PA8` "until the next reset". A
//! driver that tries to configure those pins has its writes **silently
//! dropped** — no error, no fault, no diagnostic. `ODR`/`BSRR` are *not* locked,
//! so driving the pins still works.
//!
//! So: we cannot reconfigure the control pins, and we do not need to. The
//! inherited configuration is exactly what an SSD1306 driver would ask for. A
//! driver that never writes a pin's *configuration* cannot lose a fight it never
//! picks. Precisely, the whole register footprint of this module is: **writes**
//! to [`GPIOA_BSRR`], [`SPI1_DR`] and two enable bits in
//! [`RCC_AHB2ENR`]/[`RCC_APB2ENR`]; **reads** of [`SPI1_CR1`], [`SPI1_CR2`] and
//! [`SPI1_SR`]. No `MODER`, no `AFR`, no `SPI1->CR1` write, ever.
//!
//! Two further consequences of initialising nothing, both worth having:
//!
//! * **Mk4/Mk5 orientation solves itself.** The two boards need different init
//!   sequences and the difference is *geometric*, not cosmetic: Mk4 sends
//!   `0xa1`/`0xc8` where Mk5 sends `0xa0`/`0xc0` (`oled.c:22,26` vs `:45,46`).
//!   Sending the Mk4 sequence to a Mk5 panel renders every screen **rotated
//!   180°** — a
//!   consent screen that is upside down, not one that is blank. Board revision
//!   is a runtime strapping-pin read, not a `cfg` (`gpio.c:145-152`,
//!   `is_mk5()` = `!ReadPin(GPIOE, PIN_0)`). By sending no orientation command we
//!   inherit whichever one the bootloader already picked for the board it is
//!   actually running on, and the whole class of bug is unreachable.
//! * **`SPI1` is not reprogrammed.** The bootloader leaves `SPE` set, and writing
//!   `CR1` while `SPE == 1` is not a supported operation on this part. Raising the
//!   baud rate therefore means clear `SPE` → wait for `BSY` to drop → reprogram,
//!   never a bare `CR1` write. [`PanelToken::open`] instead *validates* `CR1`/`CR2`
//!   ([`check_spi`]) and refuses if the inherited configuration cannot carry
//!   pixels. Refusing with the raw register words in the error beats streaming
//!   into a peripheral that is switched off, which produces a dark panel and no
//!   diagnostic at all — `TXE` reads 1 forever when `SPE` is clear, so there is
//!   not even a timeout.
//!
//! [`RESET_COMMANDS_MK4`] is therefore carried as **data with no caller**. It
//! costs nothing in the image (an unreferenced `const` emits no bytes) and it is
//! what the bench needs if the zero-init assumption turns out to be wrong:
//! [`Panel::write_cmds`]`(&RESET_COMMANDS_MK4)` is the whole re-init, and a
//! `RESET` pulse is
//! three [`GPIOA_BSRR`] writes because that pin's *output* is not locked.
//!
//! # The one command we do send at open: `0x2E`
//!
//! [`DEACTIVATE_SCROLL`], once, in [`PanelToken::open`]. The bootloader's
//! `oled_factory_busy()` starts a **hardware scroll animation** (`0x26`…`0x2f`,
//! `oled.c:466-473`) and the only code that stops it is inside an `#if 0`
//! (`oled.c:~440`). If a unit can reach our entry with that animation running,
//! every frame we draw slides sideways. `0x2E` is the bootloader's own way to
//! stop it (`oled.c:474`), it is a no-op when nothing is scrolling, and the
//! datasheet's caveat — RAM must be rewritten after `0x2E` — is satisfied
//! unconditionally because [`Panel::show`] rewrites all of it every time.
//! One byte to close a bench mystery.
//!
//! For the same reason the 6-byte window prologue ([`window_prologue`]) is sent
//! before **every** frame rather than once at open: `oled_factory_busy` narrows
//! the page window to `7,7` (`oled.c:465`) and any bootloader draw could have
//! left it narrowed. The bootloader re-sends the window on every draw too
//! (`oled.c:308`), so this is its behaviour, not an addition.
//!
//! # `MONO_VLSB` is the wire format, byte for byte
//!
//! No transposition, no bit reversal, no repacking: pixel `(x, y)` is bit
//! `1 << (y & 7)` of byte `(y >> 3) * WIDTH + x`, which is exactly SSD1306
//! GDDRAM under horizontal addressing mode. MicroPython's framebuffer computes
//! `index = (y >> 3) * stride + x; offset = y & 7`
//! (`micropython/extmod/modframebuf.c:97-105`) and `MONO_VLSB`'s stride is not
//! rounded, so `stride == WIDTH == 128` (`modframebuf.c:286-289`). Confirmed from
//! the C side too: "each byte here is a vertical column, 8 pixels tall, MSB at
//! bottom" (`oled.c:498`). A [`Frame`] is therefore streamed raw.
//!
//! # What is host-testable here, and it is not much
//!
//! Honestly: the data, and none of the driver. Tested below are
//! [`window_prologue`] against the bootloader's verbatim bytes,
//! [`RESET_COMMANDS_MK4`] against `oled.c:18-35`, the [`Frame`] geometry
//! invariant, the [`bsrr_set`]/[`bsrr_clear`] half-word encoding (a swapped shift
//! there is a `CS` that never asserts — a dark panel and a long afternoon), and
//! [`check_spi`] against all three `CR1` values recorded in the tree.
//!
//! There is deliberately **no fake SPI**. A hand-written `SpiPort` double would
//! be built from the same header reading as the driver, so agreement would prove
//! only self-consistency — and a double that accepts a byte the real peripheral
//! would refuse is worse than no test (`crate::flash::SrPort` and
//! [`crate::usb::OtgPort`] exist because a *destination overrun* and an
//! *unbounded wait* are reproducible without silicon; "did a photon come out"
//! is not).
//!
//! # The bench list, phase 5
//!
//! This is a **new instance of PLAN.md §9 item 10** — register state assumed at
//! bootloader handoff — and it is strictly worse than item 10's two cases, which
//! §9 should say when it gains this entry. Item 10's assumptions are each "one
//! register" to fix if wrong. The GPIO configuration lock is **not fixable in
//! firmware at all**: if the bootloader's pin setup were wrong for us there would
//! be no remedy short of a reset. It happens to be exactly right. That is luck,
//! and luck is worth writing down rather than relying on silently. (It is *not*
//! an instance of item 11: no external host holds display state.)
//!
//! 1. **Read `SPI1->CR1` and log the `BR` field.** The two records in the tree
//!    disagree by 16×: `oled.c:155` programs `SPI_BAUDRATEPRESCALER_16` (`BR` =
//!    `0b011`, /16, 7.5 MHz from `PCLK2` = 120 MHz per `clocks.h:6` +
//!    `clocks.c:147-149`, `CR1` = `0x35C`), while the comment at `oled.c:217-221`
//!    records the measured `CR1` as `0x37C`, whose `BR` is `0b111` = /256 =
//!    ~469 kHz. Full-frame flush is 1.1 ms or 17.5 ms accordingly — "free" versus
//!    "visibly slow while paging 25 backup words". PLAN.md §4's "SPI1 @ 40 MHz" is
//!    a *requested* rate from `ssd1306.py:214` that this part cannot produce
//!    (prescalers are powers of two; 120 MHz gives 60 or 30), so it is a ceiling
//!    for "the panel tolerates fast SPI" and must not be used as a frame budget.
//! 2. **Confirm a zero-init blit lands.** Everything above says it must: the
//!    panel is on, in horizontal addressing mode, with a live SPI. That is an
//!    argument from source, not a measurement.
//! 3. **Confirm no scroll is running at handoff**, i.e. that
//!    [`DEACTIVATE_SCROLL`] was insurance rather than load-bearing. If it is
//!    load-bearing, note it here; it is one byte either way.
//! 4. **Confirm `PE0`.** We never send an orientation command, so a Mk5 is
//!    expected to work unchanged. If it does not, the fix is a runtime
//!    `is_mk5()` read (`gpio.c:145-152`) plus the Mk5 sequence from
//!    `oled.c:38-58` — never a compile-time `cfg`, because the wrong branch is a
//!    180°-rotated consent screen and not a failure to draw.
//!
//! Not on the list, because it cannot be closed by reading: whether the window
//! narrows or `MODF` sets between frames. Both are handled by construction —
//! the window is re-sent every frame, and `MODF` clearing `SPE` would show as a
//! dark panel that [`check_spi`] catches on the *next* [`PanelToken::open`], of
//! which there is only one per boot. A per-frame `SPE` check is one register read
//! and is the first thing to add if frames ever stop landing mid-session.

use crate::singleton::TakeOnce;

// ---------------------------------------------------------------------------
// Geometry. The panel's, and therefore the framebuffer's.
// ---------------------------------------------------------------------------

/// Panel width in pixels (`shared/display.py:19`, `WIDTH = 128`).
pub const WIDTH: usize = 128;

/// Panel height in pixels (`shared/display.py:20`, `HEIGHT = 64`).
pub const HEIGHT: usize = 64;

/// GDDRAM pages: 8 rows of pixels per byte, so `HEIGHT / 8`. The `0x22 0x00
/// 0x07` page window at `oled.c:63` is this minus one.
pub const PAGES: usize = HEIGHT / 8;

/// Framebuffer length: 1,024 bytes (`shared/ssd1306.py:40`,
/// `bytearray(1024)`), and the full amount pushed by every `show()`
/// (`ssd1306.py:123-132`).
pub const FRAME_BYTES: usize = WIDTH * PAGES;

/// One full frame in `MONO_VLSB` order — the exact bytes the controller wants.
///
/// A bare array rather than a newtype **on purpose**: `ui` owns screen
/// composition and may well want its own wrapper with a cursor and a dirty flag
/// in it. Making the transport take `&[u8; FRAME_BYTES]` means the two modules
/// never have to agree on a struct, and `ui` can pass `&self.pixels` from
/// whatever it builds. This alias exists so the signature still reads
/// `show(&Frame)`.
///
/// It already lines up: [`crate::ui::Frame::as_bytes`] returns
/// `&[u8; ui::FRAME_BYTES]`, so `panel.show(frame.as_bytes())` type-checks with
/// no `try_into` and therefore no `unwrap` — and if the two geometries ever
/// diverged, that call site would be a **compile error** rather than a truncated
/// frame. That is the whole reason [`Panel::show`] takes an array reference and
/// not a `&[u8]`.
/// The bytes this panel streams, in GDDRAM order.
///
/// Note there are **two** `Frame`s in this crate and they are not the same thing:
/// this is a bare byte array, while [`crate::ui::Frame`] is the framebuffer that
/// composes into one. Convert with [`crate::ui::Frame::as_bytes`]. The types are
/// distinct so the compiler catches the confusion rather than a bench operator.
pub type Frame = [u8; FRAME_BYTES];

const _: () = {
    // 128 × 64 monochrome is 1,024 bytes or the format is not what we think.
    assert!(FRAME_BYTES == 1024);
    assert!(WIDTH * HEIGHT / 8 == FRAME_BYTES);
    assert!(PAGES == 8);
    // A page index and a column index must both fit the single command byte the
    // window prologue puts them in.
    assert!(WIDTH <= 256 && PAGES <= 256);
    // The bound that replaces an unbounded spin must actually be a bound: a zero
    // limit refuses every frame, and `u32::MAX` is not a bound.
    assert!(DISPLAY_SPIN_LIMIT > 0 && DISPLAY_SPIN_LIMIT < u32::MAX);
};

// ---------------------------------------------------------------------------
// Failures
// ---------------------------------------------------------------------------

/// Everything that can go wrong between a [`Frame`] and the glass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayError {
    /// Not `thumbv7em-none-eabihf`. There is no `SPI1` on the host and no
    /// fallback: a host build that reached the register writes would dereference
    /// `0x4001_3000` and `SIGSEGV`.
    NotOnThisTarget,

    /// The inherited `SPI1` configuration cannot carry pixels — see
    /// [`check_spi`]. Both raw words travel with the error because this is a
    /// bench diagnostic first: the whole point is to turn "the screen is dark"
    /// into a number.
    SpiMisconfigured {
        /// `SPI1->CR1` as read.
        cr1: u32,
        /// `SPI1->CR2` as read.
        cr2: u32,
    },

    /// A `TXE` or drain poll exhausted [`DISPLAY_SPIN_LIMIT`]. The panel is a
    /// display, not a signing dependency: the caller should carry on rather than
    /// treat this as fatal — but it must never be a hang, which is the whole
    /// reason the bound exists (DECISIONS.md decision 6).
    Timeout,
}

/// Iteration bound for both busy-waits, named to match
/// [`crate::flash::FLASH_SPIN_LIMIT`] and [`crate::usb::USB_SPIN_LIMIT`] so the
/// phase-5 bench list can grep one pattern.
///
/// A count, not a time — this crate has no timer. At the *slowest* baud the tree
/// records (/256, ~469 kHz) one byte shifts out in ~17 µs, i.e. ~2,000 core
/// cycles at 120 MHz, so this is ~500× the worst plausible wait for a single
/// byte. Deliberately not `u32::MAX`: the property being bought is termination.
pub const DISPLAY_SPIN_LIMIT: u32 = 1_000_000;

// ---------------------------------------------------------------------------
// Command bytes, transcribed
// ---------------------------------------------------------------------------

/// `0x2E` — deactivate scroll. The bootloader's own way to stop the animation
/// its `oled_factory_busy()` starts (`oled.c:474`, `:486`, both the first byte of
/// the `animate_*` sequences). Sent once by [`PanelToken::open`]; see the module
/// docs for why.
pub const DEACTIVATE_SCROLL: u8 = 0x2e;

/// The Mk4 reset/init sequence, **verbatim** from
/// `mk4-bootloader/oled.c:18-35`, whose own comment is "As measured! No attempt
/// to understand them here."
///
/// **Carried as data with no caller.** The bootloader has already sent this
/// before we run, and re-sending it is not free: `0xa1`/`0xc8` here are the
/// *Mk4* orientation and would rotate a Mk5 panel 180° (`oled.c:45-46`). If the
/// bench shows a re-init is needed, this plus [`Panel::write_cmds`] is the whole
/// operation — and a board-revision read (`gpio.c:145-152`) becomes mandatory at
/// the same moment.
///
/// Per byte, from the source comments:
///
/// | Bytes | Meaning |
/// |---|---|
/// | `0xae` | display off |
/// | `0x20 0x00` | **horizontal addressing mode** — the one [`Panel::show`] depends on |
/// | `0x40` | RAM display start line 0 |
/// | `0xa1` | column 127 mapped to `SEG0` (Mk4; Mk5 uses `0xa0`) |
/// | `0xa8 0x3f` | multiplex ratio 64 |
/// | `0xc8` | scan `COMn` → `COM0` (Mk4; Mk5 uses `0xc0`) |
/// | `0xd3 0x00` | display offset 0 |
/// | `0xda 0x12` | alternate COM pin config |
/// | `0xd5 0x80` | display clock divide (MicroPython sends `0xf0`, `ssd1306.py:61`) |
/// | `0xd9 0xf1` | pre-charge period |
/// | `0xdb 0x30` | `VCOMH` deselect level |
/// | `0x81 0xff` | contrast, max |
/// | `0xa4` | display RAM contents, not all-on |
/// | `0xa6` | normal, not inverted |
/// | `0x8d 0x14` | enable charge pump |
/// | `0xaf` | display on |
///
/// One ordering note if this is ever used: MicroPython defers `0xaf` until
/// *after* the first frame is written (`ssd1306.py:95-100`), so the panel never
/// flashes undefined GDDRAM. The bootloader turns it on last with RAM still
/// garbage (`oled.c:34`). Copy MicroPython's ordering, not this one.
pub const RESET_COMMANDS_MK4: [u8; 25] = [
    0xae, 0x20, 0x00, 0x40, 0xa1, 0xa8, 0x3f, 0xc8, 0xd3, 0x00, 0xda, 0x12, 0xd5, 0x80, 0xd9, 0xf1,
    0xdb, 0x30, 0x81, 0xff, 0xa4, 0xa6, 0x8d, 0x14, 0xaf,
];

/// The 6 command bytes that precede the 1,024 data bytes: full column range,
/// full page range.
///
/// Derived from [`WIDTH`]/[`PAGES`] rather than hardcoded, so the geometry has
/// exactly one definition — and the test below pins the derivation against the
/// bootloader's literal `{ 0x21, 0x00, 0x7f, 0x22, 0x00, 0x07 }`
/// (`oled.c:61-64`).
///
/// `0x21` = set column address (start, end); `0x22` = set page address
/// (start, end).
#[must_use]
pub const fn window_prologue() -> [u8; 6] {
    [
        0x21,
        0,
        (WIDTH - 1) as u8,
        0x22,
        0,
        (PAGES - 1) as u8,
    ]
}

// ---------------------------------------------------------------------------
// Registers. Offsets from the CMSIS header in this tree, not from memory.
//
// `external/micropython/lib/stm32lib/CMSIS/STM32L4xx/Include/stm32l4s5xx.h`,
// referred to below as `stm32l4s5xx.h`.
// ---------------------------------------------------------------------------

/// `SPI1` base: `APB2PERIPH_BASE + 0x3000` = `0x4001_3000`
/// (`stm32l4s5xx.h:1370`, with `APB2PERIPH_BASE` at `:1318` and `PERIPH_BASE` at
/// `:1292`).
pub const SPI1_BASE: u32 = 0x4001_3000;

/// `SPI1->CR1`, offset `0x00` (`SPI_TypeDef`, `stm32l4s5xx.h:962`).
pub const SPI1_CR1: *mut u32 = SPI1_BASE as *mut u32;
/// `SPI1->CR2`, offset `0x04` (`stm32l4s5xx.h:963`).
pub const SPI1_CR2: *mut u32 = (SPI1_BASE + 0x04) as *mut u32;
/// `SPI1->SR`, offset `0x08` (`stm32l4s5xx.h:964`).
pub const SPI1_SR: *mut u32 = (SPI1_BASE + 0x08) as *mut u32;

/// `SPI1->DR`, offset `0x0C` (`stm32l4s5xx.h:965`), typed `*mut u8`
/// **deliberately**.
///
/// With `DS` = 8-bit, ST's own driver writes this register a byte at a time —
/// `*((__IO uint8_t *)&hspi->Instance->DR) = *pData++`
/// (`stm32l4xx_hal_spi.c:524,542`). A 32-bit store to a `DS`=8 `DR` pushes two
/// frames' worth of data into the TX FIFO at once, which is a different protocol
/// than the one the panel is expecting. Typing the pointer is the cheapest way to
/// make the wrong access impossible to write.
pub const SPI1_DR: *mut u8 = (SPI1_BASE + 0x0C) as *mut u8;

/// `SPI_CR1_CPHA`, bit 0 (`stm32l4s5xx.h:14939`). Must be **clear** — mode 0.
pub const SPI_CR1_CPHA: u32 = 1 << 0;
/// `SPI_CR1_CPOL`, bit 1 (`:14942`). Must be **clear** — mode 0.
pub const SPI_CR1_CPOL: u32 = 1 << 1;
/// `SPI_CR1_MSTR`, bit 2 (`:14945`). Must be **set**.
pub const SPI_CR1_MSTR: u32 = 1 << 2;
/// `SPI_CR1_BR`, bits 3-5 (`:14949-14950`). Read for diagnostics only; this
/// module never writes it. See bench item 1.
pub const SPI_CR1_BR_MASK: u32 = 0x7 << 3;
/// `SPI_CR1_SPE`, bit 6 (`:14956`). Must be **set** or nothing shifts out and
/// `TXE` still reads 1 forever.
pub const SPI_CR1_SPE: u32 = 1 << 6;
/// `SPI_CR1_LSBFIRST`, bit 7 (`:14959`). Must be **clear** — SSD1306 wants MSB
/// first.
pub const SPI_CR1_LSBFIRST: u32 = 1 << 7;
/// `SPI_CR1_RXONLY`, bit 10 (`:14968`). Must be **clear**.
pub const SPI_CR1_RXONLY: u32 = 1 << 10;
/// `SPI_CR1_CRCEN`, bit 13 (`:14977`). Must be **clear** — a CRC appended to a
/// pixel stream is 2 bytes of noise on the glass.
pub const SPI_CR1_CRCEN: u32 = 1 << 13;
/// `SPI_CR1_BIDIMODE`, bit 15 (`:14983`). Must be **clear** — 2-line
/// unidirectional, as `oled.c:148` sets.
pub const SPI_CR1_BIDIMODE: u32 = 1 << 15;

/// `SPI_CR2_DS`, bits 8-11 (`stm32l4s5xx.h:15012-15013`).
pub const SPI_CR2_DS_MASK: u32 = 0xF << 8;
/// `SPI_DATASIZE_8BIT` = `0x0000_0700`, i.e. `DS` = `0b0111`
/// (`stm32l4xx_hal_spi.h:243`; `oled.c:147` selects it).
pub const SPI_CR2_DS_8BIT: u32 = 0x700;

/// `SPI_SR_TXE`, bit 1 (`stm32l4s5xx.h:15033`) — TX FIFO has room.
pub const SPI_SR_TXE: u32 = 1 << 1;
/// `SPI_SR_BSY`, bit 7 (`:15051`).
pub const SPI_SR_BSY: u32 = 1 << 7;
/// `SPI_SR_FTLVL`, bits 11-12 (`:15062-15063`) — TX FIFO occupancy.
pub const SPI_SR_FTLVL: u32 = 0x3 << 11;

/// `GPIOA` base: `AHB2PERIPH_BASE + 0` = `0x4800_0000` (`stm32l4s5xx.h:1448`,
/// `AHB2PERIPH_BASE` at `:1320`).
pub const GPIOA_BASE: u32 = 0x4800_0000;

/// `GPIOA->BSRR`, offset `0x18` (`GPIO_TypeDef`, `stm32l4s5xx.h:624`).
///
/// The **only** `GPIOA` register this module writes, and the reason the pin lock
/// (module docs) is harmless: `HAL_GPIO_LockPin` freezes `MODER`/`OTYPER`/
/// `OSPEEDR`/`PUPDR`/`AFRL`/`AFRH` and *not* `BSRR`.
pub const GPIOA_BSRR: *mut u32 = (GPIOA_BASE + 0x18) as *mut u32;

/// `CS`, `PA4` (`oled.c:71`, `CS_PIN = GPIO_PIN_4`). Active low.
pub const CS_PIN: u32 = 1 << 4;
/// `RESET`, `PA6` (`oled.c:69`, `RESET_PIN = GPIO_PIN_6`). Active low, pulsed by
/// the bootloader (`oled.c:209-213`) and **never by us** — the pin's *output* is
/// writable despite the config lock, so a bench re-init can pulse it, but a
/// working panel does not need to be reset again.
pub const RESET_PIN: u32 = 1 << 6;
/// `DC`, `PA8` (`oled.c:70`, `DC_PIN = GPIO_PIN_8`). Low = command, high = data.
pub const DC_PIN: u32 = 1 << 8;

/// `RCC->AHB2ENR`, `0x4002_104C` (`RCC_TypeDef` offset `0x4C`,
/// `stm32l4s5xx.h:816`; `RCC_BASE` at `:1400`). Same register
/// [`crate::rng`] uses for `RNGEN`.
pub const RCC_AHB2ENR: *mut u32 = (0x4002_1000 + 0x4C) as *mut u32;
/// `RCC_AHB2ENR_GPIOAEN`, bit 0 (`stm32l4s5xx.h:12710`).
pub const RCC_AHB2ENR_GPIOAEN: u32 = 1 << 0;
/// `RCC->APB2ENR`, `0x4002_1060` (`RCC_TypeDef` offset `0x60`,
/// `stm32l4s5xx.h:821`).
pub const RCC_APB2ENR: *mut u32 = (0x4002_1000 + 0x60) as *mut u32;
/// `RCC_APB2ENR_SPI1EN`, bit 12 (`stm32l4s5xx.h:12865`).
pub const RCC_APB2ENR_SPI1EN: u32 = 1 << 12;

// ---------------------------------------------------------------------------
// Pure helpers — the whole host-testable surface
// ---------------------------------------------------------------------------

/// `BSRR` word that drives `mask` **high**: the set half is bits 0-15
/// (`GPIO_BSRR_BS0_Pos` = 0, `stm32l4s5xx.h:10032`).
#[must_use]
pub const fn bsrr_set(mask: u32) -> u32 {
    mask
}

/// `BSRR` word that drives `mask` **low**: the reset half is bits 16-31
/// (`GPIO_BSRR_BR0_Pos` = 16, `stm32l4s5xx.h:10080`).
///
/// Getting this shift backwards is a `CS` that never asserts and a panel that
/// never updates, with no error anywhere — which is why it is a named function
/// with a test rather than an inline `<< 16`.
#[must_use]
pub const fn bsrr_clear(mask: u32) -> u32 {
    mask << 16
}

/// Whether the `SPI1` configuration inherited from the bootloader can carry
/// pixels to this panel.
///
/// Pure, so **host-testable in full**, and it is the only validation in this
/// module. Required set: [`SPI_CR1_MSTR`], [`SPI_CR1_SPE`]. Required clear:
/// [`SPI_CR1_CPHA`], [`SPI_CR1_CPOL`], [`SPI_CR1_LSBFIRST`],
/// [`SPI_CR1_RXONLY`], [`SPI_CR1_CRCEN`], [`SPI_CR1_BIDIMODE`]. Required in
/// `CR2`: `DS` = 8-bit.
///
/// Deliberately **not** checked: `BR` (any baud works, only speed differs — bench
/// item 1) and `SSM`/`SSI`. Software NSS is what `oled.c:149` selects and both
/// bits are set in every `CR1` recorded in the tree, but neither corrupts the
/// byte stream, and every additional required bit is one more way to refuse a
/// panel that would in fact have worked. The bits above are the ones whose wrong
/// value means "dark" or "garbage".
///
/// # Errors
///
/// [`DisplayError::SpiMisconfigured`] carrying both raw words.
pub const fn check_spi(cr1: u32, cr2: u32) -> Result<(), DisplayError> {
    const REQUIRED_SET: u32 = SPI_CR1_MSTR | SPI_CR1_SPE;
    const REQUIRED_CLEAR: u32 = SPI_CR1_CPHA
        | SPI_CR1_CPOL
        | SPI_CR1_LSBFIRST
        | SPI_CR1_RXONLY
        | SPI_CR1_CRCEN
        | SPI_CR1_BIDIMODE;

    if cr1 & REQUIRED_SET != REQUIRED_SET
        || cr1 & REQUIRED_CLEAR != 0
        || cr2 & SPI_CR2_DS_MASK != SPI_CR2_DS_8BIT
    {
        return Err(DisplayError::SpiMisconfigured { cr1, cr2 });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The capability
// ---------------------------------------------------------------------------

/// The take-once ticket for the panel.
///
/// Same split as [`crate::usb::UsbToken`] and [`crate::flash::StmFlashToken`]:
/// [`PanelToken::take`] is pure and callable anywhere, [`PanelToken::open`] is the
/// only thing that reads a register, and the token implements nothing — so a
/// caller cannot push pixels without the `SPI1` validation having passed.
pub struct PanelToken {
    _private: (),
}

impl PanelToken {
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

    /// Validate the inherited `SPI1` configuration and hand back the panel.
    ///
    /// Does **not** reset or re-initialise anything — see the module docs. What
    /// it does: idempotently enables the `GPIOA`/`SPI1` clocks, reads
    /// `CR1`/`CR2`, refuses via [`check_spi`], and sends
    /// [`DEACTIVATE_SCROLL`].
    ///
    /// Consumes the token by value, so a failed open cannot be retried with the
    /// same token and a successful one cannot be duplicated.
    ///
    /// **Unverified-on-silicon**, all of it.
    ///
    /// # Errors
    ///
    /// [`DisplayError::NotOnThisTarget`] off ARM;
    /// [`DisplayError::SpiMisconfigured`] if the bootloader did not leave `SPI1`
    /// able to carry bytes; [`DisplayError::Timeout`] if the one command byte
    /// could not be pushed.
    ///
    /// # Panics
    ///
    /// Must not, ever. A panic here is a boot-time reset loop (DECISIONS.md
    /// decision 6).
    pub fn open(self) -> Result<Panel, DisplayError> {
        // `return` is load-bearing exactly as in `usb::UsbToken::open`: on ARM
        // the block below is deleted and a bare `Err(..)` tail in statement
        // position is a discarded `#[must_use]`, not a return value.
        #[cfg(not(target_arch = "arm"))]
        #[allow(clippy::needless_return)]
        {
            let _ = &self;
            return Err(DisplayError::NotOnThisTarget);
        }

        #[cfg(target_arch = "arm")]
        {
            let _ = &self;
            enable_clocks();
            let (cr1, cr2) =
                unsafe { (core::ptr::read_volatile(SPI1_CR1), core::ptr::read_volatile(SPI1_CR2)) };
            check_spi(cr1, cr2)?;
            let mut panel = Panel { _private: () };
            panel.write_cmds(&[DEACTIVATE_SCROLL])?;
            Ok(panel)
        }
    }
}

/// A panel whose `SPI1` configuration has been checked: 1,024 bytes in, pixels
/// out.
///
/// Obtainable only from [`PanelToken::open`], which is what makes "the peripheral
/// can actually transmit" a property of the type rather than of a comment.
pub struct Panel {
    _private: (),
}

impl Panel {
    /// Push a whole frame: the 6-byte window prologue, then all
    /// [`FRAME_BYTES`] bytes.
    ///
    /// Full-frame every time, matching `ssd1306.py:123-132` — there is no partial
    /// update here and none is wanted: at 1 KiB the composition cost of tracking
    /// dirty pages exceeds the transfer it would save.
    ///
    /// The window prologue is re-sent per frame on purpose: any bootloader draw
    /// could have narrowed the window (`oled_factory_busy` sets pages `7,7`,
    /// `oled.c:465`), and the bootloader itself re-sends it every draw
    /// (`oled.c:308`).
    ///
    /// **Unverified-on-silicon.** Every write below is transcribed, never
    /// observed.
    ///
    /// # Errors
    ///
    /// [`DisplayError::NotOnThisTarget`] off ARM; [`DisplayError::Timeout`] if a
    /// `TXE` or drain poll exhausted [`DISPLAY_SPIN_LIMIT`]. On timeout `CS` is
    /// still deasserted, so the controller is not left mid-transaction and the
    /// next frame can be attempted.
    ///
    /// # Panics
    ///
    /// Must not, ever. No indexing, no arithmetic that can overflow: the frame
    /// is a fixed-size array and the spin counters use `checked_sub`. Note
    /// `overflow-checks = false` in release would make a `-= 1` past zero *wrap*
    /// rather than trap, i.e. an effectively unbounded spin, which is why the
    /// counters are `checked_sub` and not `-=`.
    pub fn show(&mut self, frame: &Frame) -> Result<(), DisplayError> {
        #[cfg(not(target_arch = "arm"))]
        #[allow(clippy::needless_return)]
        {
            let _ = (&self, frame);
            return Err(DisplayError::NotOnThisTarget);
        }

        #[cfg(target_arch = "arm")]
        {
            self.write_cmds(&window_prologue())?;
            transaction(true, frame)
        }
    }

    /// Send raw command bytes: one `CS`-toggled, `DC`-low transaction **per
    /// byte**.
    ///
    /// Per byte, not per slice, because that is what the bootloader does —
    /// `oled_write_cmd_sequence` loops over `oled_write_cmd` (`oled.c:108-117`,
    /// `:96-106`) — and a command framing that has shipped on every Mk4 is not
    /// worth improving on blind. Six toggles for a window prologue costs six
    /// extra [`GPIOA_BSRR`] writes.
    ///
    /// Public because it is the **bench door**: it is how
    /// [`RESET_COMMANDS_MK4`] gets sent if item 2 of the bench list comes back
    /// negative, and how [`DEACTIVATE_SCROLL`] gets re-sent if item 3 does. It is
    /// reachable only through a [`Panel`], so an unvalidated `SPI1` still cannot
    /// be poked.
    ///
    /// **Unverified-on-silicon.**
    ///
    /// # Errors
    ///
    /// [`DisplayError::NotOnThisTarget`] off ARM; [`DisplayError::Timeout`].
    pub fn write_cmds(&mut self, cmds: &[u8]) -> Result<(), DisplayError> {
        #[cfg(not(target_arch = "arm"))]
        #[allow(clippy::needless_return)]
        {
            let _ = (&self, cmds);
            return Err(DisplayError::NotOnThisTarget);
        }

        #[cfg(target_arch = "arm")]
        {
            for byte in cmds {
                transaction(false, core::slice::from_ref(byte))?;
            }
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// The register pokes. ARM only, and every one of them unverified-on-silicon.
// ---------------------------------------------------------------------------

/// One `CS`-framed transaction: `CS` high → set `DC` → `CS` low → bytes → drain →
/// `CS` high.
///
/// The lead `CS` high is the bootloader's own ordering (`oled.c:99-101`,
/// `:120-122`) and is kept rather than reasoned about.
///
/// **The drain and the final `CS` high happen on every path, including the
/// timeout.** Same property as [`crate::usb::fifo_read`]'s unconditional FIFO
/// drain: a refusal that skips the cleanup leaves `CS` asserted and the
/// controller mid-transaction, so the *next* frame is corrupt too — a refusal
/// that poisons the following operation is worse than no refusal. Deasserting
/// `CS` before `BSY` clears would also truncate the byte still in the shift
/// register, which is why the drain mirrors `HAL_SPI_Transmit`'s end-of-transfer
/// wait (`stm32l4xx_hal_spi.c:599-605`: `FTLVL` empty, then `BSY` clear).
#[cfg(target_arch = "arm")]
fn transaction(dc_high: bool, bytes: &[u8]) -> Result<(), DisplayError> {
    bsrr_write(bsrr_set(CS_PIN));
    bsrr_write(if dc_high {
        bsrr_set(DC_PIN)
    } else {
        bsrr_clear(DC_PIN)
    });
    bsrr_write(bsrr_clear(CS_PIN));

    let mut sent = Ok(());
    for byte in bytes {
        if let Err(e) = write_byte(*byte) {
            sent = Err(e);
            break;
        }
    }

    let drained = drain();
    bsrr_write(bsrr_set(CS_PIN));
    sent.and(drained)
}

/// One `GPIOA->BSRR` write. **Unverified-on-silicon.**
#[cfg(target_arch = "arm")]
fn bsrr_write(word: u32) {
    // SAFETY: `GPIOA_BSRR` (`0x4800_0018`) is a 4-byte-aligned memory-mapped
    // register. `BSRR` is write-only and atomic by construction — set bits in
    // the low half, reset bits in the high half — so this cannot read-modify-write
    // a pin another module owns, and it cannot be torn by an interrupt. The only
    // pins named are `PA4`/`PA8`, which the bootloader configured for this panel
    // and nothing else uses.
    unsafe { core::ptr::write_volatile(GPIOA_BSRR, word) };
}

/// Wait for `TXE`, then push one byte. **Unverified-on-silicon.**
///
/// # Errors
///
/// [`DisplayError::Timeout`] if `TXE` never asserts within
/// [`DISPLAY_SPIN_LIMIT`].
#[cfg(target_arch = "arm")]
fn write_byte(byte: u8) -> Result<(), DisplayError> {
    let mut spins = DISPLAY_SPIN_LIMIT;
    // SAFETY: `SPI1_SR` (`0x4001_3008`) is a 4-byte-aligned memory-mapped
    // register and this is a read with no side effects.
    while unsafe { core::ptr::read_volatile(SPI1_SR) } & SPI_SR_TXE == 0 {
        spins = match spins.checked_sub(1) {
            Some(n) => n,
            None => return Err(DisplayError::Timeout),
        };
    }
    // SAFETY: an 8-bit store to `SPI1->DR` with `DS` = 8-bit, which
    // `PanelToken::open` verified via `check_spi`. This is the access width ST's
    // own driver uses (`stm32l4xx_hal_spi.c:524`); a 32-bit store here would
    // enqueue two frames.
    unsafe { core::ptr::write_volatile(SPI1_DR, byte) };
    Ok(())
}

/// Wait until the TX FIFO is empty **and** the peripheral is idle, so `CS` can be
/// deasserted without truncating the byte in the shift register.
///
/// Mirrors `HAL_SPI_Transmit`'s end-of-transfer wait
/// (`stm32l4xx_hal_spi.c:599-605`). `FRLVL` is deliberately not waited on: this
/// is a transmit-only link with `MISO` unconnected, so the RX FIFO fills with
/// garbage and stays full — the tree's own measured `SR` of `0x603`
/// (`oled.c:219-221`) has `FRLVL` = `0b11`, i.e. full, on a working panel.
/// Waiting for it to empty would hang forever.
///
/// **Unverified-on-silicon.**
///
/// # Errors
///
/// [`DisplayError::Timeout`].
#[cfg(target_arch = "arm")]
fn drain() -> Result<(), DisplayError> {
    let mut spins = DISPLAY_SPIN_LIMIT;
    loop {
        // SAFETY: as `write_byte` — a side-effect-free read of `SPI1->SR`.
        let sr = unsafe { core::ptr::read_volatile(SPI1_SR) };
        if sr & (SPI_SR_FTLVL | SPI_SR_BSY) == 0 {
            return Ok(());
        }
        spins = match spins.checked_sub(1) {
            Some(n) => n,
            None => return Err(DisplayError::Timeout),
        };
    }
}

/// Enable the `GPIOA` and `SPI1` peripheral clocks, idempotently.
///
/// The bootloader has already done this (`oled.c:183-184`) and calls
/// `oled_setup()` on every boot (`main.c:110`), so in practice both bits are
/// set. Doing it anyway removes a dependency on bootloader behaviour we do not
/// control — exactly as [`crate::rng`]'s `enable_rng_clock` and
/// [`crate::panic`]'s `enable_backup_access` do.
///
/// Note what this deliberately does *not* do: touch `CR1`. Enabling an
/// already-enabled clock is harmless; writing `CR1` with `SPE` set is not.
///
/// **Unverified-on-silicon.**
#[cfg(target_arch = "arm")]
fn enable_clocks() {
    // SAFETY: `RCC_AHB2ENR` (`0x4002_104c`) and `RCC_APB2ENR` (`0x4002_1060`)
    // are 4-byte-aligned memory-mapped registers. Both writes are
    // read-modify-write settings of a single enable bit, guarded so a set bit is
    // never rewritten; neither can disable a peripheral another module owns and
    // neither starts a transfer. The read-back is what ST's own clock-enable
    // macros do so the peripheral is reachable before the next access
    // (`stm32l4xx_hal_rcc.h:1134-1140`).
    unsafe {
        let ahb2 = core::ptr::read_volatile(RCC_AHB2ENR);
        if ahb2 & RCC_AHB2ENR_GPIOAEN == 0 {
            core::ptr::write_volatile(RCC_AHB2ENR, ahb2 | RCC_AHB2ENR_GPIOAEN);
            let _ = core::ptr::read_volatile(RCC_AHB2ENR);
        }
        let apb2 = core::ptr::read_volatile(RCC_APB2ENR);
        if apb2 & RCC_APB2ENR_SPI1EN == 0 {
            core::ptr::write_volatile(RCC_APB2ENR, apb2 | RCC_APB2ENR_SPI1EN);
            let _ = core::ptr::read_volatile(RCC_APB2ENR);
        }
        core::arch::asm!("dsb sy", options(nostack, preserves_flags));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `Frame` must be exactly the panel, and exactly what `show()` pushes. If
    /// this drifts, `show()` sends a partial frame or over-runs the window.
    #[test]
    fn frame_is_the_panel() {
        assert_eq!(FRAME_BYTES, 1024, "ssd1306.py:40 says bytearray(1024)");
        assert_eq!(core::mem::size_of::<Frame>(), FRAME_BYTES);
        assert_eq!(WIDTH * HEIGHT / 8, FRAME_BYTES);
        assert_eq!(PAGES, 8);
        // The `ui` seam: its framebuffer must be exactly what `show()` pushes,
        // or `panel.show(frame.as_bytes())` stops compiling.
        assert_eq!(crate::ui::FRAME_BYTES, FRAME_BYTES);
        assert_eq!(crate::ui::WIDTH, WIDTH);
        assert_eq!(crate::ui::HEIGHT, HEIGHT);
    }

    /// THE PROLOGUE PIN. `window_prologue()` is derived from `WIDTH`/`PAGES`;
    /// this is the only place the bootloader's literal bytes appear, so a change
    /// to the geometry constants that does not belong fails here rather than on
    /// the glass.
    #[test]
    fn window_prologue_matches_the_bootloader() {
        // `mk4-bootloader/oled.c:61-64`, verbatim.
        assert_eq!(
            window_prologue(),
            [0x21, 0x00, 0x7f, 0x22, 0x00, 0x07],
            "must equal before_show[] at oled.c:61-64"
        );
    }

    /// The init sequence is data, and its value is that it is *verbatim*. A typo
    /// here would only ever show up at a bench, months from now, as a panel that
    /// does not come back after a re-init attempt.
    #[test]
    fn init_sequence_is_the_bootloaders_mk4_sequence() {
        // `mk4-bootloader/oled.c:18-35`, flattened in order.
        let verbatim: [u8; 25] = [
            0xae, // display off
            0x20, 0x00, // horizontal addressing
            0x40, // start line 0
            0xa1, // col 127 -> SEG0 (Mk4)
            0xa8, 0x3f, // multiplex 64
            0xc8, // scan COMn -> COM0 (Mk4)
            0xd3, 0x00, // offset 0
            0xda, 0x12, // alt COM pins
            0xd5, 0x80, // clock divide
            0xd9, 0xf1, // pre-charge
            0xdb, 0x30, // VCOMH
            0x81, 0xff, // contrast max
            0xa4,       // RAM contents
            0xa6,       // not inverted
            0x8d, 0x14, // charge pump
            0xaf, // display on
        ];
        assert_eq!(RESET_COMMANDS_MK4, verbatim);

        // The one byte pair `show()` actually depends on: horizontal addressing
        // mode, which is what makes a MONO_VLSB buffer streamable raw.
        assert_eq!(
            RESET_COMMANDS_MK4[1..3],
            [0x20, 0x00],
            "0x20 0x00 = horizontal addressing; without it MONO_VLSB does not map"
        );
        // Mk4 orientation, not Mk5's 0xa0/0xc0 (oled.c:45-46). Recorded so the
        // constant cannot be quietly retargeted without this failing.
        assert!(RESET_COMMANDS_MK4.contains(&0xa1));
        assert!(RESET_COMMANDS_MK4.contains(&0xc8));
    }

    /// `BSRR`'s two halves. A swapped shift means `CS` is driven high when it
    /// should go low: the panel never sees a transaction, nothing errors, and the
    /// screen is simply dark.
    #[test]
    fn bsrr_puts_reset_in_the_high_half() {
        assert_eq!(bsrr_set(CS_PIN), 0x0000_0010);
        assert_eq!(bsrr_clear(CS_PIN), 0x0010_0000);
        assert_eq!(bsrr_set(DC_PIN), 0x0000_0100);
        assert_eq!(bsrr_clear(DC_PIN), 0x0100_0000);
        assert_eq!(bsrr_set(RESET_PIN), 0x0000_0040);

        for pin in [CS_PIN, DC_PIN, RESET_PIN] {
            assert_eq!(bsrr_set(pin) & 0xFFFF_0000, 0, "set half must be bits 0-15");
            assert_eq!(
                bsrr_clear(pin) & 0x0000_FFFF,
                0,
                "reset half must be bits 16-31"
            );
            assert_ne!(bsrr_set(pin), bsrr_clear(pin));
        }
        // Three distinct pins, all on port A, all within the 16 a BSRR half has.
        assert_eq!((CS_PIN | RESET_PIN | DC_PIN).count_ones(), 3);
        assert_eq!(CS_PIN | RESET_PIN | DC_PIN, 0x0150);
    }

    /// Every `SPI1->CR1` value recorded anywhere in the Coldcard tree must pass,
    /// or `open()` refuses a panel that works in shipping firmware.
    ///
    /// Three exist, and they disagree about the baud rate — which is exactly why
    /// `check_spi` ignores `BR` (bench item 1).
    #[test]
    fn check_spi_accepts_every_cr1_the_tree_records() {
        // `oled.c:217-221` comment: mpy `0x354`, "this code" `0x37c`; and
        // `0x35c` is what `oled.c:155`'s SPI_BAUDRATEPRESCALER_16 actually
        // programs. CR2 = 0x1700 (DS=8bit | FRXTH) from the same comment.
        for cr1 in [0x354_u32, 0x35c, 0x37c] {
            assert_eq!(
                check_spi(cr1, 0x1700),
                Ok(()),
                "{cr1:#x} is a measured working CR1 and must not be refused"
            );
        }
        // And they genuinely disagree about the baud rate: /8, /16 and /256.
        // `check_spi` must therefore ignore `BR`, which is what makes bench item
        // 1 a measurement and not a blocker.
        assert_eq!(0x354_u32 & SPI_CR1_BR_MASK, 0b010 << 3);
        assert_eq!(0x35c_u32 & SPI_CR1_BR_MASK, 0b011 << 3);
        assert_eq!(0x37c_u32 & SPI_CR1_BR_MASK, 0b111 << 3);
    }

    /// And every configuration that means "dark" or "garbage" must be refused.
    /// Mutating `check_spi` to drop any one of these bits fails a named case
    /// here.
    #[test]
    fn check_spi_refuses_what_cannot_carry_pixels() {
        const GOOD_CR1: u32 = 0x37c;
        const GOOD_CR2: u32 = 0x1700;
        assert_eq!(check_spi(GOOD_CR1, GOOD_CR2), Ok(()));

        // Bits that must be SET.
        for (name, cr1) in [
            ("SPE clear: nothing shifts out, TXE reads 1 forever", GOOD_CR1 & !SPI_CR1_SPE),
            ("MSTR clear: slave mode, no clock generated", GOOD_CR1 & !SPI_CR1_MSTR),
        ] {
            assert_eq!(
                check_spi(cr1, GOOD_CR2),
                Err(DisplayError::SpiMisconfigured { cr1, cr2: GOOD_CR2 }),
                "must refuse -- {name}"
            );
        }

        // Bits that must be CLEAR.
        for (name, bit) in [
            ("CPHA set: wrong SPI mode", SPI_CR1_CPHA),
            ("CPOL set: wrong SPI mode", SPI_CR1_CPOL),
            ("LSBFIRST set: every byte mirrored", SPI_CR1_LSBFIRST),
            ("RXONLY set: transmit disabled", SPI_CR1_RXONLY),
            ("CRCEN set: 2 bytes of CRC land in GDDRAM", SPI_CR1_CRCEN),
            ("BIDIMODE set: 1-line mode", SPI_CR1_BIDIMODE),
        ] {
            let cr1 = GOOD_CR1 | bit;
            assert_eq!(
                check_spi(cr1, GOOD_CR2),
                Err(DisplayError::SpiMisconfigured { cr1, cr2: GOOD_CR2 }),
                "must refuse -- {name}"
            );
        }

        // Data size: anything but 8-bit reframes the whole stream.
        for cr2 in [0x0000_u32, 0x1000, 0x1F00, 0x1300] {
            assert_eq!(
                check_spi(GOOD_CR1, cr2),
                Err(DisplayError::SpiMisconfigured { cr1: GOOD_CR1, cr2 }),
                "DS != 8-bit ({cr2:#x}) must be refused"
            );
        }
        // A reset-value SPI (never touched by anyone) is refused, which is the
        // case that matters: it is indistinguishable from a working one by
        // watching the screen.
        assert!(check_spi(0, 0).is_err());
    }

    /// The register offsets, as a layout rather than as four independent numbers.
    #[test]
    fn register_offsets_follow_spi_typedef() {
        assert_eq!(SPI1_BASE, 0x4001_3000);
        assert_eq!(SPI1_CR1 as usize, SPI1_BASE as usize);
        assert_eq!(SPI1_CR2 as usize, SPI1_BASE as usize + 0x04);
        assert_eq!(SPI1_SR as usize, SPI1_BASE as usize + 0x08);
        assert_eq!(SPI1_DR as usize, SPI1_BASE as usize + 0x0C);
        assert_eq!(GPIOA_BSRR as usize, 0x4800_0018);
        assert_eq!(RCC_AHB2ENR as usize, 0x4002_104C);
        assert_eq!(RCC_APB2ENR as usize, 0x4002_1060);
        // `crate::rng` reads the same RCC register; a divergence here means one
        // of the two is wrong.
        assert_eq!(RCC_AHB2ENR as usize, crate::rng::RCC_AHB2ENR as usize);
    }

    #[test]
    fn token_is_a_singleton_and_cannot_open_off_arm() {
        let token = PanelToken::take().expect("first take must succeed");
        for _ in 0..4 {
            assert!(
                PanelToken::take().is_none(),
                "handed the panel out more than once"
            );
        }
        // `Panel` is deliberately not `Debug`/`PartialEq` -- it is a capability,
        // not a value -- so compare the error side.
        assert_eq!(token.open().err(), Some(DisplayError::NotOnThisTarget));
    }
}

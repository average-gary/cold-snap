//! `ui` — the 1,024-byte `MONO_VLSB` framebuffer and the eight required screens
//! (PLAN.md §4.2), composed from **plain data** and touching **no hardware**.
//!
//! # Why this module has no registers in it
//!
//! This module is to [`crate::comms`] what `comms` is to [`crate::usb`]: it knows
//! what the bytes *mean* and touches nothing. A 128×64 monochrome framebuffer is
//! 1,024 bytes of ordinary data, so every screen in PLAN.md §4.2 can be composed,
//! asserted on, and *looked at* on the host with no panel, no SoC simulator and
//! nothing flashed. `display.rs` owns the SPI1 pokes that push
//! [`Frame::as_bytes`] at the panel; if a register write ever appears in this
//! file, that property is gone and so is every test below.
//!
//! Corollary, and the reason the signatures look the way they do: this module
//! takes `u64` sats, `&str` addresses and `&[&str]` word lists, **never**
//! `frostsnap_core` types. `frostsnap_core` is a dev-dependency of this crate and
//! must stay one (`hal/Cargo.toml`). `firmware/` adapts. That seam is what lets a
//! host test hand a screen a hostile input directly.
//!
//! # The pixel mapping (get this wrong and everything else here is noise)
//!
//! `MONO_VLSB`, byte-for-byte identical to SSD1306 page-mode GDDRAM under
//! horizontal addressing, so the buffer streams out raw with no transposition:
//!
//! ```text
//! pixel (x, y)  ->  byte (y / 8) * 128 + x,  bit 1 << (y % 8)
//! ```
//!
//! bit 0 is the **top** row of the 8-pixel page. Derived from MicroPython
//! `extmod/modframebuf.c:97-105` (`index = (y >> 3) * stride + x; offset = y & 7`)
//! with `stride == width == 128` (`:286-289` — `FRAMEBUF_MVLSB` takes no stride
//! rounding), and corroborated by `mk4-bootloader/oled.c:414-415` ("each byte
//! here is a vertical column, 8 pixels tall") and `shared/ssd1306.py:33,40,43`.
//! [`mono_vlsb_corner_pixels_map_to_exact_bytes`](self) pins it.
//!
//! # The font: MicroPython `petme128` 8×8, MIT, 768 B
//!
//! Investigation C recommended regenerating Coldcard's zevv-peep 7×14 tables
//! (1,877 B subset). This module ships C's own named fallback instead, for three
//! reasons that all point the same way:
//!
//! 1. **Licence.** zevv-peep's BDF carries `COPYRIGHT "Zevv"` and *no grant*; C
//!    flagged it "BLOCKING BEFORE SHIP". `petme128` is MIT (MicroPython, Damien
//!    George — licence header in `font_petme128_8x8.h:1-21`), which is this
//!    crate's own licence. Shipping the licensed one is not a compromise, it is
//!    the rung below "resolve a licence by email".
//! 2. **It is already in `MONO_VLSB` layout.** `petme128` is column-major, one
//!    byte per column, bit 0 top — *bit-identical* to a page-aligned framebuffer
//!    cell. A glyph blit is [`slice::copy_from_slice`] of 8 bytes. No row
//!    trimming, no bit shifting, no per-glyph width table, and therefore no
//!    instance of C's measured defect (zevv `FontSmall` is **not** monospace: `-`
//!    is 8 px, so three hyphens on an 18-char line is 129 px on a 128 px panel).
//! 3. **768 B, one table, one code path.** One text path means one truncation
//!    rule and one UTF-8 rule to audit, not two.
//!
//! Cost: an 8 px cell against the 14 px PLAN.md §4.2 measured. The grid becomes
//! **16 cols × 8 rows** (`COLS`×`ROWS`) rather than 18×4, and screens spend blank
//! rows to buy back legibility, so effective density is the 4–6 lines §4.2 asks
//! for. 16 cols is *better* for the one place §4.2's budget was tight: a 62-char
//! bech32m address is 4 rows of 16 with 2 cells spare, and this module allows 5
//! ([`ADDRESS_ROWS`] = 80 cells) because a v2-v16 witness program reaches ~76
//! chars. Swapping in C's zevv table later is a table swap plus a width array;
//! nothing above [`Frame::text`] changes.
//!
//! Regenerate the table with:
//!
//! ```text
//! python3 -c 'import re,sys; h=open(sys.argv[1]).read(); \
//!   print(re.findall(r"0x[0-9a-f]{2}", h[h.index("{"):h.rindex("}")]))' \
//!   .../ports/stm32/font_petme128_8x8.h
//! ```
//!
//! Glyph 95 (`chr(127)`) is a checkerboard, which this module uses as the
//! **missing-glyph** cell. Per `shared/display.py:98-102`, an unmappable
//! codepoint must draw a box, never be dropped: a coordinator-supplied device
//! name that renders *shorter* than it is, is a spoofing primitive.
//!
//! # No panics, and no wrapping either
//!
//! `overflow-checks = false` in the release profile, so arithmetic that panics in
//! a test wraps silently in firmware. Every index here goes through
//! [`slice::get`]/[`slice::get_mut`], every accumulation is `saturating_*`, and
//! the fee-percentage comparison is done in `u128` so it cannot wrap at any input
//! (the vendored `sign_prompt` original multiplies `u64`s — see
//! [`SignPages::high_fee`]). Text is walked with `chars()`, never sliced at a byte
//! index, because a coordinator picks the bytes and a non-boundary slice panics.
//!
//! # The three security requirements of PLAN.md §4.2, and where they live
//!
//! - **Sign approval shows every foreign recipient, amount *and* full address,
//!   plus the fee — or it refuses.** [`SignPages`] holds a `&[Recipient]` and
//!   derives its page count from that slice's length; there is no count field and
//!   no mutator, so a page set that omits a recipient is unrepresentable rather
//!   than merely untested. [`SignPages::new`] validates *every* address up front
//!   and returns `Err` if any one of them cannot be rendered in full — which is
//!   the same posture PLAN.md §4.2 requires of `user_prompt() == None`: refuse the
//!   request, never fall back to rendering the recipients you *can* draw.
//! - **Keygen check shows the 4-byte code *and* the compare-on-every-device
//!   instruction.** [`keygen_check`] draws [`KEYGEN_COMPARE_1`] /
//!   [`KEYGEN_COMPARE_2`] unconditionally alongside the code; a code with no
//!   instruction is not the anti-MITM check.
//! - **The fee is coordinator-supplied.** [`fee_page`] draws
//!   [`FEE_UNVERIFIED_1`] / [`FEE_UNVERIFIED_2`] on the same page as the number.
//!
//! # What is deliberately not here
//!
//! No `DrawTarget`, no `Widget` trait, no animation, no partial redraw (the flush
//! is all 1,024 B every time, so a dirty rect buys nothing), no allocation, no
//! `core::fmt` (its formatting machinery is real flash; [`Buf`] does the three
//! conversions actually needed). No BIP39 distractor selection — that needs the
//! wordlist, which this crate does not have, so it belongs above this seam.

use core::str;

/// Panel width in pixels.
pub const WIDTH: usize = 128;
/// Panel height in pixels.
pub const HEIGHT: usize = 64;
/// Framebuffer size: `WIDTH * HEIGHT / 8`, and the exact number of bytes
/// `ssd1306.py:123-132` flushes on every `show()`.
pub const FRAME_BYTES: usize = WIDTH * HEIGHT / 8;
/// Glyph cell edge, in pixels. Square, so it is also the bytes-per-glyph.
///
/// # This is ONE font where PLAN.md §4.2 specifies THREE, and the difference is
/// not merely cosmetic
///
/// §4.2's measured budget is `FontSmall` 7×14 → **18×4**, `FontLarge` → 12×3, and
/// `FontTiny` 4×6 → 32×10. This module ships a single 8×8 cell → **16×8**. The
/// deviation is recorded here rather than left for a reader to discover, because
/// two of its three consequences are load-bearing:
///
/// 1. **16 columns, not 18.** Every "fits 18×4" entry in §4.2's table was computed
///    against a wider line than this module provides. Nothing here silently
///    truncates to absorb that — over-long text is refused (see [`Unrenderable`])
///    — but a screen §4.2 called "fits" may now refuse, which is a capacity
///    regression against the plan and not a rendering detail.
/// 2. **`FontLarge` is provided by [`Frame::text_2x`], not by a second table.**
///    §4.2 asks for it by name on screen 2 ("8 hex chars in `FontLarge`") because
///    the keygen check code is read *aloud* and compared across every device, and
///    that comparison is the entire defence against a coordinator substituting its
///    own key. An integer 2× blit of these same glyphs gives a 16 px line at 12
///    columns available — `FontLarge`'s budget — for 16 bytes of lookup table and
///    no new glyph data. [`keygen_check`] uses it.
///
///    One geometric consequence, since it changed the screen: a 2× glyph is 16 px
///    wide, so **8 characters is exactly the 128 px panel** and there is no room for
///    the separator `keygen_code` places between the halves. The code is therefore
///    drawn as two 4-character groups on separate 2× lines, which also reads aloud
///    better than eight undifferentiated hex digits. Whether 16 px is legible
///    *enough* on a physical OLED remains a human judgement no host test can make.
/// 3. `FontTiny`'s absence costs only density, and §4.2 wanted it for the backup
///    and address screens. Those fit at 16×8 without it, so this one is genuinely
///    cosmetic.
///
/// The single font is otherwise the right rung: 96 glyphs × 8 B = 768 B of
/// `.rodata` for the whole printable ASCII range, against a general font crate.
pub const CELL: usize = 8;
/// Text columns: `WIDTH / CELL`. **16**, where PLAN.md §4.2 assumes 18 — see
/// [`CELL`].
pub const COLS: usize = WIDTH / CELL;
/// Text rows: `HEIGHT / CELL`. 8, where §4.2's `FontSmall` budget assumes 4.
pub const ROWS: usize = HEIGHT / CELL;

/// Rows an address block may occupy, and therefore the address length ceiling:
/// `ADDRESS_ROWS * COLS` = 80 characters, all visible at once.
///
/// 62 chars is the P2TR/P2WSH case, **not** the maximum: `Address::from_script`
/// accepts any witness version with a 2..=40 byte program, which is
/// `hrp(4) + "1" + version(1) + 64 + checksum(6)` ≈ 76 chars on regtest. Sized
/// to cover that with slack; above it, refuse.
pub const ADDRESS_ROWS: usize = 5;

/// Characters per address chunk, matching Coldcard's own 4-char grouping
/// (`shared/utils.py:728-730`). `COLS` is a multiple of this, so chunks never
/// straddle a row.
pub const CHUNK: usize = 4;

/// Recipient ceiling for [`SignPages`]. Over-bound is a **refusal**, not a
/// truncation — a truncated page list is exactly the silent-omission failure
/// PLAN.md §4.2 forbids.
///
/// `frostsnap_core`'s `foreign_recipients` is a `Vec` bounded only by
/// `comms::FRAME_LIMIT`, and nobody has computed how many outputs a 4,096-byte
/// frame permits. 32 recipients is 66 pages, which a human cannot meaningfully
/// check anyway; raising it is this one const.
pub const MAX_RECIPIENTS: usize = 32;

/// Words in a `frost_backup` share backup.
pub const BACKUP_WORDS: usize = 25;
/// Backup words shown per page: 4 labelled rows plus a header row.
pub const WORDS_PER_PAGE: usize = 4;

/// Absolute high-fee threshold in sats, from `sign_prompt.rs:30`. Strictly
/// greater, and it short-circuits the relative test.
pub const HIGH_FEE_SATS: u64 = 100_000;
/// Relative high-fee threshold, percent of the sum of **foreign** recipient
/// amounts (not the total, not the inputs), from `sign_prompt.rs:31`.
pub const HIGH_FEE_PERCENT: u64 = 5;

/// First codepoint in [`FONT`].
const FONT_FIRST: u32 = 32;
/// One past the last codepoint in [`FONT`].
const FONT_LAST: u32 = 127;
/// Glyph index drawn for any codepoint outside the table: `chr(127)`, a
/// checkerboard. Visible, one cell wide, and unmistakably not a character.
const MISSING_GLYPH: usize = 95;

/// Bit-doubling table for [`Frame::text_2x`]: index by a 4-bit nibble, get the byte
/// with each bit duplicated (`0b1010` -> `0b11001100`).
///
/// A table rather than a loop because it is 16 bytes of `.rodata` against a
/// per-pixel shift loop, and because `text_2x` already runs 8 iterations per glyph.
const DOUBLE_NIBBLE: [u8; 16] = [
    0b0000_0000, 0b0000_0011, 0b0000_1100, 0b0000_1111,
    0b0011_0000, 0b0011_0011, 0b0011_1100, 0b0011_1111,
    0b1100_0000, 0b1100_0011, 0b1100_1100, 0b1100_1111,
    0b1111_0000, 0b1111_0011, 0b1111_1100, 0b1111_1111,
];

/// MicroPython `font_petme128_8x8.h`, MIT. Column-major, one byte per column,
/// bit 0 = top pixel — i.e. already in `MONO_VLSB` cell order.
static FONT: [u8; 96 * CELL] = [
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //  
    0x00, 0x00, 0x00, 0x4f, 0x4f, 0x00, 0x00, 0x00, // !
    0x00, 0x07, 0x07, 0x00, 0x00, 0x07, 0x07, 0x00, // "
    0x14, 0x7f, 0x7f, 0x14, 0x14, 0x7f, 0x7f, 0x14, // #
    0x00, 0x24, 0x2e, 0x6b, 0x6b, 0x3a, 0x12, 0x00, // $
    0x00, 0x63, 0x33, 0x18, 0x0c, 0x66, 0x63, 0x00, // %
    0x00, 0x32, 0x7f, 0x4d, 0x4d, 0x77, 0x72, 0x50, // &
    0x00, 0x00, 0x00, 0x04, 0x06, 0x03, 0x01, 0x00, // apostrophe
    0x00, 0x00, 0x1c, 0x3e, 0x63, 0x41, 0x00, 0x00, // (
    0x00, 0x00, 0x41, 0x63, 0x3e, 0x1c, 0x00, 0x00, // )
    0x08, 0x2a, 0x3e, 0x1c, 0x1c, 0x3e, 0x2a, 0x08, // *
    0x00, 0x08, 0x08, 0x3e, 0x3e, 0x08, 0x08, 0x00, // +
    0x00, 0x00, 0x80, 0xe0, 0x60, 0x00, 0x00, 0x00, // ,
    0x00, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x00, // -
    0x00, 0x00, 0x00, 0x60, 0x60, 0x00, 0x00, 0x00, // .
    0x00, 0x40, 0x60, 0x30, 0x18, 0x0c, 0x06, 0x02, // /
    0x00, 0x3e, 0x7f, 0x49, 0x45, 0x7f, 0x3e, 0x00, // 0
    0x00, 0x40, 0x44, 0x7f, 0x7f, 0x40, 0x40, 0x00, // 1
    0x00, 0x62, 0x73, 0x51, 0x49, 0x4f, 0x46, 0x00, // 2
    0x00, 0x22, 0x63, 0x49, 0x49, 0x7f, 0x36, 0x00, // 3
    0x00, 0x18, 0x18, 0x14, 0x16, 0x7f, 0x7f, 0x10, // 4
    0x00, 0x27, 0x67, 0x45, 0x45, 0x7d, 0x39, 0x00, // 5
    0x00, 0x3e, 0x7f, 0x49, 0x49, 0x7b, 0x32, 0x00, // 6
    0x00, 0x03, 0x03, 0x79, 0x7d, 0x07, 0x03, 0x00, // 7
    0x00, 0x36, 0x7f, 0x49, 0x49, 0x7f, 0x36, 0x00, // 8
    0x00, 0x26, 0x6f, 0x49, 0x49, 0x7f, 0x3e, 0x00, // 9
    0x00, 0x00, 0x00, 0x24, 0x24, 0x00, 0x00, 0x00, // :
    0x00, 0x00, 0x80, 0xe4, 0x64, 0x00, 0x00, 0x00, // ;
    0x00, 0x08, 0x1c, 0x36, 0x63, 0x41, 0x41, 0x00, // <
    0x00, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x00, // =
    0x00, 0x41, 0x41, 0x63, 0x36, 0x1c, 0x08, 0x00, // >
    0x00, 0x02, 0x03, 0x51, 0x59, 0x0f, 0x06, 0x00, // ?
    0x00, 0x3e, 0x7f, 0x41, 0x4d, 0x4f, 0x2e, 0x00, // @
    0x00, 0x7c, 0x7e, 0x0b, 0x0b, 0x7e, 0x7c, 0x00, // A
    0x00, 0x7f, 0x7f, 0x49, 0x49, 0x7f, 0x36, 0x00, // B
    0x00, 0x3e, 0x7f, 0x41, 0x41, 0x63, 0x22, 0x00, // C
    0x00, 0x7f, 0x7f, 0x41, 0x63, 0x3e, 0x1c, 0x00, // D
    0x00, 0x7f, 0x7f, 0x49, 0x49, 0x41, 0x41, 0x00, // E
    0x00, 0x7f, 0x7f, 0x09, 0x09, 0x01, 0x01, 0x00, // F
    0x00, 0x3e, 0x7f, 0x41, 0x49, 0x7b, 0x3a, 0x00, // G
    0x00, 0x7f, 0x7f, 0x08, 0x08, 0x7f, 0x7f, 0x00, // H
    0x00, 0x00, 0x41, 0x7f, 0x7f, 0x41, 0x00, 0x00, // I
    0x00, 0x20, 0x60, 0x41, 0x7f, 0x3f, 0x01, 0x00, // J
    0x00, 0x7f, 0x7f, 0x1c, 0x36, 0x63, 0x41, 0x00, // K
    0x00, 0x7f, 0x7f, 0x40, 0x40, 0x40, 0x40, 0x00, // L
    0x00, 0x7f, 0x7f, 0x06, 0x0c, 0x06, 0x7f, 0x7f, // M
    0x00, 0x7f, 0x7f, 0x0e, 0x1c, 0x7f, 0x7f, 0x00, // N
    0x00, 0x3e, 0x7f, 0x41, 0x41, 0x7f, 0x3e, 0x00, // O
    0x00, 0x7f, 0x7f, 0x09, 0x09, 0x0f, 0x06, 0x00, // P
    0x00, 0x1e, 0x3f, 0x21, 0x61, 0x7f, 0x5e, 0x00, // Q
    0x00, 0x7f, 0x7f, 0x19, 0x39, 0x6f, 0x46, 0x00, // R
    0x00, 0x26, 0x6f, 0x49, 0x49, 0x7b, 0x32, 0x00, // S
    0x00, 0x01, 0x01, 0x7f, 0x7f, 0x01, 0x01, 0x00, // T
    0x00, 0x3f, 0x7f, 0x40, 0x40, 0x7f, 0x3f, 0x00, // U
    0x00, 0x1f, 0x3f, 0x60, 0x60, 0x3f, 0x1f, 0x00, // V
    0x00, 0x7f, 0x7f, 0x30, 0x18, 0x30, 0x7f, 0x7f, // W
    0x00, 0x63, 0x77, 0x1c, 0x1c, 0x77, 0x63, 0x00, // X
    0x00, 0x07, 0x0f, 0x78, 0x78, 0x0f, 0x07, 0x00, // Y
    0x00, 0x61, 0x71, 0x59, 0x4d, 0x47, 0x43, 0x00, // Z
    0x00, 0x00, 0x7f, 0x7f, 0x41, 0x41, 0x00, 0x00, // [
    0x00, 0x02, 0x06, 0x0c, 0x18, 0x30, 0x60, 0x40, // backslash
    0x00, 0x00, 0x41, 0x41, 0x7f, 0x7f, 0x00, 0x00, // ]
    0x00, 0x08, 0x0c, 0x06, 0x06, 0x0c, 0x08, 0x00, // ^
    0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, // _
    0x00, 0x00, 0x01, 0x03, 0x06, 0x04, 0x00, 0x00, // `
    0x00, 0x20, 0x74, 0x54, 0x54, 0x7c, 0x78, 0x00, // a
    0x00, 0x7f, 0x7f, 0x44, 0x44, 0x7c, 0x38, 0x00, // b
    0x00, 0x38, 0x7c, 0x44, 0x44, 0x6c, 0x28, 0x00, // c
    0x00, 0x38, 0x7c, 0x44, 0x44, 0x7f, 0x7f, 0x00, // d
    0x00, 0x38, 0x7c, 0x54, 0x54, 0x5c, 0x58, 0x00, // e
    0x00, 0x08, 0x7e, 0x7f, 0x09, 0x03, 0x02, 0x00, // f
    0x00, 0x98, 0xbc, 0xa4, 0xa4, 0xfc, 0x7c, 0x00, // g
    0x00, 0x7f, 0x7f, 0x04, 0x04, 0x7c, 0x78, 0x00, // h
    0x00, 0x00, 0x00, 0x7d, 0x7d, 0x00, 0x00, 0x00, // i
    0x00, 0x40, 0xc0, 0x80, 0x80, 0xfd, 0x7d, 0x00, // j
    0x00, 0x7f, 0x7f, 0x30, 0x38, 0x6c, 0x44, 0x00, // k
    0x00, 0x00, 0x41, 0x7f, 0x7f, 0x40, 0x00, 0x00, // l
    0x00, 0x7c, 0x7c, 0x18, 0x30, 0x18, 0x7c, 0x7c, // m
    0x00, 0x7c, 0x7c, 0x04, 0x04, 0x7c, 0x78, 0x00, // n
    0x00, 0x38, 0x7c, 0x44, 0x44, 0x7c, 0x38, 0x00, // o
    0x00, 0xfc, 0xfc, 0x24, 0x24, 0x3c, 0x18, 0x00, // p
    0x00, 0x18, 0x3c, 0x24, 0x24, 0xfc, 0xfc, 0x00, // q
    0x00, 0x7c, 0x7c, 0x04, 0x04, 0x0c, 0x08, 0x00, // r
    0x00, 0x48, 0x5c, 0x54, 0x54, 0x74, 0x20, 0x00, // s
    0x04, 0x04, 0x3f, 0x7f, 0x44, 0x64, 0x20, 0x00, // t
    0x00, 0x3c, 0x7c, 0x40, 0x40, 0x7c, 0x3c, 0x00, // u
    0x00, 0x1c, 0x3c, 0x60, 0x60, 0x3c, 0x1c, 0x00, // v
    0x00, 0x1c, 0x7c, 0x30, 0x18, 0x30, 0x7c, 0x1c, // w
    0x00, 0x44, 0x6c, 0x38, 0x38, 0x6c, 0x44, 0x00, // x
    0x00, 0x9c, 0xbc, 0xa0, 0xa0, 0xfc, 0x7c, 0x00, // y
    0x00, 0x44, 0x64, 0x74, 0x5c, 0x4c, 0x44, 0x00, // z
    0x00, 0x08, 0x08, 0x3e, 0x77, 0x41, 0x41, 0x00, // {
    0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, // |
    0x00, 0x41, 0x41, 0x77, 0x3e, 0x08, 0x08, 0x00, // }
    0x00, 0x02, 0x03, 0x01, 0x03, 0x02, 0x03, 0x01, // ~
    0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, // 
];

/// Glyph index for a codepoint, [`MISSING_GLYPH`] if unmapped.
///
/// Every non-ASCII-printable char — a zero-width joiner, a combining mark, a
/// U+202E right-to-left override — lands here as one visible cell. Layout is
/// strictly left-to-right by codepoint into a fixed cell, so no input can
/// reorder a rendered address.
const fn glyph(c: char) -> usize {
    let b = c as u32;
    if b >= FONT_FIRST && b < FONT_LAST {
        (b - FONT_FIRST) as usize
    } else {
        MISSING_GLYPH
    }
}

/// A 128×64 1-bit framebuffer in `MONO_VLSB` order. Push [`Frame::as_bytes`] at
/// the panel; nothing in this type knows the panel exists.
///
/// 1,024 B, so it belongs in `.bss` as a single `static`, not threaded through
/// every screen signature on the stack (~0.17% of the 599 KiB RAM region).
#[derive(Clone, PartialEq, Eq)]
pub struct Frame([u8; FRAME_BYTES]);

impl Default for Frame {
    fn default() -> Self {
        Self::new()
    }
}

impl Frame {
    /// An all-pixels-off frame.
    pub const fn new() -> Self {
        Frame([0u8; FRAME_BYTES])
    }

    /// Turn every pixel off.
    pub fn clear(&mut self) {
        self.0 = [0u8; FRAME_BYTES];
    }

    /// The bytes to flush, in the panel's own order. `display.rs` streams these
    /// after the 6-byte `21 00 7f 22 00 07` window; no transposition.
    pub fn as_bytes(&self) -> &[u8; FRAME_BYTES] {
        &self.0
    }

    /// Set or clear one pixel. Out-of-range coordinates are a no-op, never a
    /// panic and never a wrap into another row.
    pub fn set_pixel(&mut self, x: usize, y: usize, on: bool) {
        if x >= WIDTH || y >= HEIGHT {
            return;
        }
        let Some(byte) = self.0.get_mut((y / CELL) * WIDTH + x) else {
            return;
        };
        let mask = 1u8 << (y % CELL);
        if on {
            *byte |= mask;
        } else {
            *byte &= !mask;
        }
    }

    /// Read one pixel. Out of range reads `false`.
    pub fn pixel(&self, x: usize, y: usize) -> bool {
        if x >= WIDTH || y >= HEIGHT {
            return false;
        }
        self.0
            .get((y / CELL) * WIDTH + x)
            .is_some_and(|b| b & (1u8 << (y % CELL)) != 0)
    }

    /// Draw `s` at cell (`col`, `row`), returning how many characters were drawn.
    ///
    /// Truncates at [`COLS`]; the return value is how a caller detects that. Any
    /// codepoint the font does not have draws the missing-glyph cell rather than
    /// vanishing. Safe for arbitrary attacker text of arbitrary length: the input
    /// is walked with `chars()` and never sliced.
    pub fn text(&mut self, col: usize, row: usize, s: &str) -> usize {
        self.text_styled(col, row, s, false)
    }

    /// [`Frame::text`] with every glyph's pixels complemented (inverse video —
    /// the mono stand-in for upstream's highlight colour, and what
    /// `shared/display.py:74` calls `invert=1`).
    pub fn text_inverted(&mut self, col: usize, row: usize, s: &str) -> usize {
        self.text_styled(col, row, s, true)
    }

    /// Draw `s` at **2× scale** from cell (`col`, `row`), returning characters drawn.
    ///
    /// This is PLAN.md §4.2's `FontLarge` budget reached without a second font: each
    /// glyph becomes 16×16 px, so it spans **2 columns and 2 rows**, giving a
    /// 12-column 16 px line — which is what §4.2 specifies for screen 2's keygen
    /// code. 96 glyphs of new data avoided; see [`CELL`].
    ///
    /// Truncates at [`COLS`] like [`Frame::text`], and returns 0 rather than
    /// clipping if the second row would fall off the panel. Same attacker-text
    /// guarantees: walked with `chars()`, never sliced.
    pub fn text_2x(&mut self, col: usize, row: usize, s: &str) -> usize {
        // Needs two byte-rows. `row + 1` cannot wrap: `row < ROWS` is checked first.
        if row >= ROWS || row + 1 >= ROWS {
            return 0;
        }
        let mut drawn = 0usize;
        for c in s.chars() {
            let x = col.saturating_add(drawn.saturating_mul(2));
            // A 2x glyph needs two whole cells; a partial one would be a half-drawn
            // character, which on a consent screen is worse than a missing one.
            if x.saturating_add(2) > COLS {
                break;
            }
            let g = glyph(c).saturating_mul(CELL);
            let Some(src) = FONT.get(g..g.saturating_add(CELL)) else {
                break;
            };
            for (i, sb) in src.iter().enumerate() {
                // One source byte is 8 rows of one column. Doubling vertically
                // splits it across two byte-rows: low nibble -> this row, high
                // nibble -> the next. Doubling horizontally writes it twice.
                let lo = DOUBLE_NIBBLE[(*sb & 0x0f) as usize];
                let hi = DOUBLE_NIBBLE[(*sb >> 4) as usize];
                let dx = x.saturating_mul(CELL).saturating_add(i.saturating_mul(2));
                for k in 0..2 {
                    if let Some(d) = self.0.get_mut(row.saturating_mul(WIDTH) + dx + k) {
                        *d = lo;
                    }
                    if let Some(d) = self.0.get_mut((row + 1).saturating_mul(WIDTH) + dx + k) {
                        *d = hi;
                    }
                }
            }
            drawn = drawn.saturating_add(1);
        }
        drawn
    }

    fn text_styled(&mut self, col: usize, row: usize, s: &str, invert: bool) -> usize {
        if row >= ROWS {
            return 0;
        }
        let mut drawn = 0usize;
        for c in s.chars() {
            let x = col.saturating_add(drawn);
            if x >= COLS {
                break;
            }
            let g = glyph(c) * CELL;
            let base = row * WIDTH + x * CELL;
            let Some(src) = FONT.get(g..g.saturating_add(CELL)) else {
                break;
            };
            let Some(dst) = self.0.get_mut(base..base.saturating_add(CELL)) else {
                break;
            };
            if invert {
                for (d, s) in dst.iter_mut().zip(src) {
                    *d = !*s;
                }
            } else {
                dst.copy_from_slice(src);
            }
            drawn = drawn.saturating_add(1);
        }
        drawn
    }

    /// Draw `s` across `rows` consecutive rows of [`COLS`] cells each, starting
    /// at row `row`, column 0. Returns characters drawn.
    ///
    /// Hard-wraps at the column boundary — no word breaking, because the strings
    /// that matter here are addresses and digit runs where a reflow would be a
    /// lie. Callers that must not truncate compare the result against
    /// `s.chars().count()`.
    pub fn wrap(&mut self, row: usize, rows: usize, s: &str) -> usize {
        let mut drawn = 0usize;
        let mut chars = s.chars();
        for r in 0..rows {
            let y = row.saturating_add(r);
            if y >= ROWS {
                break;
            }
            let mut col = 0usize;
            while col < COLS {
                let Some(c) = chars.next() else {
                    return drawn;
                };
                let mut one = [0u8; 4];
                let n = self.text(col, y, c.encode_utf8(&mut one));
                if n == 0 {
                    return drawn;
                }
                col += 1;
                drawn = drawn.saturating_add(1);
            }
        }
        drawn
    }

    /// Complement `n` cells starting at (`col`, `row`) — inverse video over a
    /// region already drawn. Clipped, never a panic.
    pub fn invert_cells(&mut self, col: usize, row: usize, n: usize) {
        if row >= ROWS {
            return;
        }
        for i in 0..n {
            let x = col.saturating_add(i);
            if x >= COLS {
                return;
            }
            let base = row * WIDTH + x * CELL;
            if let Some(dst) = self.0.get_mut(base..base.saturating_add(CELL)) {
                for d in dst.iter_mut() {
                    *d = !*d;
                }
            }
        }
    }

    /// Read back the character at cell (`col`, `row`) by reverse glyph lookup,
    /// and whether that cell is in inverse video.
    ///
    /// This is what makes the screens *assertable* rather than merely renderable:
    /// a test reads the composed text out of the pixels, so a layout mutation
    /// (an address short by one character, a missing instruction line) fails a
    /// named test instead of passing a byte-count check. Firmware never calls it,
    /// so `--gc-sections` drops it.
    pub fn cell(&self, col: usize, row: usize) -> Option<(u8, bool)> {
        if col >= COLS || row >= ROWS {
            return None;
        }
        let base = row * WIDTH + col * CELL;
        let got = self.0.get(base..base.saturating_add(CELL))?;
        for i in 0..96 {
            let src = FONT.get(i * CELL..i * CELL + CELL)?;
            if got == src {
                return Some((FONT_FIRST as u8 + i as u8, false));
            }
            if got.iter().zip(src).all(|(g, s)| *g == !*s) {
                return Some((FONT_FIRST as u8 + i as u8, true));
            }
        }
        None
    }
}

/// A fixed-capacity ASCII scratch string: the "bounded text into a fixed-size
/// sink" helper this tree did not have.
///
/// ASCII-only by construction (a non-ASCII push becomes the missing-glyph
/// codepoint), so [`Buf::as_str`] cannot fail. Overflow **truncates and records
/// it** — [`Buf::truncated`] — rather than returning an `Err` nobody checks or
/// panicking. No `core::fmt`: three conversions, no formatting machinery.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Buf<const N: usize> {
    buf: [u8; N],
    len: usize,
    truncated: bool,
}

impl<const N: usize> Default for Buf<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Buf<N> {
    /// An empty buffer.
    pub const fn new() -> Self {
        Buf {
            buf: [0u8; N],
            len: 0,
            truncated: false,
        }
    }

    /// Characters held.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether nothing has been pushed.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Whether any push was dropped for lack of room.
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    /// The contents. Always valid UTF-8 because only ASCII is ever stored.
    pub fn as_str(&self) -> &str {
        self.buf
            .get(..self.len)
            .and_then(|b| str::from_utf8(b).ok())
            .unwrap_or("")
    }

    fn push(&mut self, b: u8) -> &mut Self {
        match self.buf.get_mut(self.len) {
            Some(slot) => {
                *slot = b;
                self.len += 1;
            }
            None => self.truncated = true,
        }
        self
    }

    /// Append `s`, mapping every non-ASCII-printable char to the missing-glyph
    /// codepoint so the count of cells matches the count of input characters.
    pub fn push_str(&mut self, s: &str) -> &mut Self {
        for c in s.chars() {
            let b = c as u32;
            self.push(if (FONT_FIRST..FONT_LAST).contains(&b) {
                b as u8
            } else {
                FONT_LAST as u8
            });
        }
        self
    }

    /// Append `v` in decimal. `u64::MAX` is 20 digits.
    pub fn push_u64(&mut self, v: u64) -> &mut Self {
        let mut digits = [0u8; 20];
        let mut i = digits.len();
        let mut v = v;
        loop {
            i -= 1;
            if let Some(d) = digits.get_mut(i) {
                *d = b'0' + (v % 10) as u8;
            }
            v /= 10;
            if v == 0 || i == 0 {
                break;
            }
        }
        for d in digits.iter().skip(i) {
            self.push(*d);
        }
        self
    }

    /// Append `v` in decimal, zero-padded to two digits — the `NN:` shape
    /// `shared/display.py:284-285` triggers `mark_sensitive` on, which PLAN.md
    /// §4.2 requires the mono backup screen preserve.
    pub fn push_u8_pad2(&mut self, v: u8) -> &mut Self {
        self.push(b'0' + (v / 10) % 10);
        self.push(b'0' + v % 10);
        self
    }

    /// Append `b` as two lowercase hex digits.
    pub fn push_hex(&mut self, b: u8) -> &mut Self {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        self.push(*HEX.get((b >> 4) as usize).unwrap_or(&b'?'));
        self.push(*HEX.get((b & 0xf) as usize).unwrap_or(&b'?'))
    }
}

/// Why a screen refused to render. Every variant means **reject the request** —
/// same posture as `user_prompt() == None` (PLAN.md §4.2). None of them is a
/// rendering hint, and none may be answered by drawing a partial screen.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Unrenderable {
    /// The text does not fit its budget in full. Truncating it here would mean
    /// consenting to bytes the user never saw.
    TooLong,
    /// An "address" containing something other than printable ASCII. A base58 or
    /// bech32 address is ASCII by construction, so this is not an address.
    NotAscii,
    /// More foreign recipients than [`MAX_RECIPIENTS`].
    TooManyRecipients,
    /// A word list that is not [`BACKUP_WORDS`] long, or holds a non-BIP39-shaped
    /// word.
    BadWordList,
}

// ---------------------------------------------------------------------------
// Screen 1 — standby
// ---------------------------------------------------------------------------

/// Screen 1: device name, key name and held share index. Not
/// security-load-bearing, and the only screen that truncates hostile text
/// silently — `device_name` is a `FixedString<14>` upstream, which bounds
/// *chars*, not columns, and whose `Decode` truncates rather than erroring
/// (`fixed_string.rs:133-140`), so the column bound has to happen here.
pub fn standby(frame: &mut Frame, device_name: &str, key_name: &str, held_share: Option<u32>) {
    frame.clear();
    frame.text(0, 0, device_name);
    frame.text(0, 2, key_name);
    if let Some(index) = held_share {
        let mut b = Buf::<16>::new();
        b.push_str("share #").push_u64(index as u64);
        frame.text(0, 4, b.as_str());
    } else {
        frame.text(0, 4, "no share held");
    }
}

// ---------------------------------------------------------------------------
// Screen 2 — keygen check (anti-MITM)
// ---------------------------------------------------------------------------

/// First line of the compare instruction. Rendering the code without this is not
/// the anti-MITM check (`device/src/widget_tree.rs:102-105`,
/// `keygen_check.rs:64-71`).
pub const KEYGEN_COMPARE_1: &str = "Compare code on";
/// Second line of the compare instruction.
pub const KEYGEN_COMPARE_2: &str = "EVERY device:";

/// The 4-byte session-hash security code, formatted exactly as upstream:
/// lowercase hex, `2 bytes, space, 2 bytes` (`keygen_check.rs:29-35`).
///
/// This format is a **wire-compatibility constant, not a style choice** — two
/// devices formatting `4+4` against `2+space+2`, or upper against lower case,
/// cannot complete the comparison the check exists for.
pub fn keygen_code(code: [u8; 4]) -> Buf<9> {
    let mut b = Buf::<9>::new();
    b.push_hex(code[0])
        .push_hex(code[1])
        .push_str(" ")
        .push_hex(code[2])
        .push_hex(code[3]);
    b
}

/// Screen 2: the first 4 bytes of the 32-byte VRF session hash, plus the
/// instruction to compare it on every device, plus the threshold being agreed.
///
/// The instruction is drawn unconditionally and from a const, so removing it is
/// a source edit that a named test catches rather than a configuration.
pub fn keygen_check(frame: &mut Frame, threshold: u16, parties: u16, code: [u8; 4], key_name: &str) {
    frame.clear();
    frame.text(0, 0, KEYGEN_COMPARE_1);
    frame.text(0, 1, KEYGEN_COMPARE_2);

    // The code at 2x, per PLAN.md §4.2's `FontLarge` requirement for THIS screen:
    // it is read aloud and compared across every device, and that comparison is the
    // whole anti-MITM defence. Two groups of 4 rather than one line of 8 because a
    // 2x glyph is 16 px wide, so 8 characters is exactly the full 128 px panel and
    // there is no room left for the separator `keygen_code` puts between the halves.
    // Splitting keeps the grouping that makes the value readable aloud.
    let code = keygen_code(code);
    let s = code.as_str();
    // Byte indices are safe here and only here: `keygen_code` builds this string
    // itself out of hex digits and one ASCII space, so it is always 9 ASCII bytes.
    // Nothing a coordinator controls reaches these slices.
    let (hi, lo) = match (s.get(..4), s.get(5..9)) {
        (Some(h), Some(l)) => (h, l),
        // Unreachable while `keygen_code` is 9 ASCII bytes; a refusal rather than a
        // panic if it ever is not, because this screen must not be a reset loop.
        _ => (s, ""),
    };
    frame.text_2x((COLS - 8) / 2, 2, hi);
    frame.text_2x((COLS - 8) / 2, 4, lo);

    // Threshold and key name share the last content row: the 2x code costs four
    // rows, and of the two the threshold is the one being agreed to.
    let mut b = Buf::<16>::new();
    b.push_u64(threshold as u64)
        .push_str("-of-")
        .push_u64(parties as u64)
        .push_str(" ");
    frame.text(0, 6, b.as_str());
    frame.text(b.as_str().chars().count().min(COLS), 6, key_name);
    frame.text(0, 7, "1=match x=no");
}

// ---------------------------------------------------------------------------
// Screen 3 — sign approval
// ---------------------------------------------------------------------------

/// First line of the fee provenance label.
pub const FEE_UNVERIFIED_1: &str = "NOT VERIFIED BY";
/// Second line of the fee provenance label.
pub const FEE_UNVERIFIED_2: &str = "THIS DEVICE";

/// One foreign recipient: amount and the full destination address.
///
/// Change outputs never appear here — upstream filters them
/// (`bitcoin_transaction.rs` `foreign_recipients`), and unlike the fee that
/// filter is trustworthy, because an output tagged as ours has a *derived*
/// script rather than a supplied one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Recipient<'a> {
    /// Destination address, exactly as it will be signed over.
    pub address: &'a str,
    /// Amount in satoshis.
    pub sats: u64,
}

/// One page of the sign-approval sequence. Pagination is **logic**: this enum and
/// [`SignPages::page`] are testable with no framebuffer in sight.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SignPage<'a> {
    /// No foreign recipients at all — every output is change. Legal (a
    /// consolidation), but it must not be silent: consenting to a bare fee with
    /// no visible destination is the blind-signer failure in miniature.
    SelfSend,
    /// Amount going to recipient `index` (0-based; displayed 1-based) of `of`.
    Amount {
        /// 0-based recipient index.
        index: usize,
        /// Total recipients.
        of: usize,
        /// Amount in satoshis.
        sats: u64,
    },
    /// Full destination address of recipient `index` of `of`.
    Address {
        /// 0-based recipient index.
        index: usize,
        /// Total recipients.
        of: usize,
        /// The address, in full.
        address: &'a str,
    },
    /// High-fee warning. Emitted **before** the fee page, matching
    /// `sign_prompt.rs:362,373` — the warning exists to frame the number the user
    /// is about to read.
    HighFeeWarning {
        /// The fee, in satoshis.
        fee_sats: u64,
        /// Sum of foreign recipient amounts, for comparison.
        sent_sats: u64,
    },
    /// The network fee, labelled as coordinator-supplied.
    Fee {
        /// The fee, in satoshis.
        sats: u64,
    },
    /// The final hold-to-confirm page. Always last, so reaching it requires
    /// stepping through every prior page.
    Confirm,
}

/// The sign-approval page set: `2·recipients + optional warning + fee + confirm`
/// (`sign_prompt.rs:296`).
///
/// **A page set that drops a recipient is unrepresentable.** The only recipient
/// state is the borrowed slice; the page count is computed from its length on
/// every call and there is no count field, no push, and no mutator. Construction
/// validates every address, so partial rendering is not reachable either:
/// [`SignPages::new`] either accepts the whole transaction or refuses it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SignPages<'a> {
    recipients: &'a [Recipient<'a>],
    fee_sats: u64,
}

impl<'a> SignPages<'a> {
    /// Validate a whole transaction for display, or refuse it.
    ///
    /// Refuses when: there are more than [`MAX_RECIPIENTS`]; any address is not
    /// printable ASCII; any address is longer than `ADDRESS_ROWS * COLS`. All
    /// three are "this device cannot show you what you would be signing", which
    /// per PLAN.md §4.2 means reject the request.
    pub fn new(recipients: &'a [Recipient<'a>], fee_sats: u64) -> Result<Self, Unrenderable> {
        if recipients.len() > MAX_RECIPIENTS {
            return Err(Unrenderable::TooManyRecipients);
        }
        for r in recipients {
            check_address(r.address)?;
        }
        Ok(SignPages {
            recipients,
            fee_sats,
        })
    }

    /// The recipients, in order. Same slice the pages are derived from.
    pub fn recipients(&self) -> &'a [Recipient<'a>] {
        self.recipients
    }

    /// The fee this set will display. Coordinator-supplied.
    pub fn fee_sats(&self) -> u64 {
        self.fee_sats
    }

    /// Sum of foreign recipient amounts, exact. `u128` because the vendored
    /// `total_sent()` is a bare `u64` `.sum()` that wraps under
    /// `overflow-checks = false`, and "a saturated total is a plausible-looking
    /// wrong number on a consent screen".
    pub fn sent_sats(&self) -> u128 {
        self.recipients.iter().map(|r| r.sats as u128).sum()
    }

    /// Whether the high-fee warning page is present.
    ///
    /// Absolute first and short-circuiting (`fee > HIGH_FEE_SATS`), then relative
    /// against the sum of foreign amounts only. Both comparisons in `u128`:
    /// upstream's `fee_sats > total_sent * 5 / 100` multiplies `u64`s
    /// (`sign_prompt.rs:317`), which panics under `overflow-checks = true` and
    /// wraps under `false`.
    pub fn high_fee(&self) -> bool {
        if self.fee_sats > HIGH_FEE_SATS {
            return true;
        }
        let sent = self.sent_sats();
        sent > 0 && (self.fee_sats as u128) * 100 > sent * (HIGH_FEE_PERCENT as u128)
    }

    /// Pages devoted to recipients: two each, or one [`SignPage::SelfSend`] when
    /// there are none.
    fn recipient_pages(&self) -> usize {
        if self.recipients.is_empty() {
            1
        } else {
            self.recipients.len() * 2
        }
    }

    /// Total pages. Never zero.
    pub fn len(&self) -> usize {
        self.recipient_pages() + usize::from(self.high_fee()) + 2
    }

    /// Always `false`; there is always a fee page and a confirm page.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// The page at `index`, or `None` past the end.
    pub fn page(&self, index: usize) -> Option<SignPage<'a>> {
        let n = self.recipients.len();
        let rp = self.recipient_pages();
        if index < rp {
            if n == 0 {
                return Some(SignPage::SelfSend);
            }
            let recipient = index / 2;
            let r = self.recipients.get(recipient)?;
            return Some(if index % 2 == 0 {
                SignPage::Amount {
                    index: recipient,
                    of: n,
                    sats: r.sats,
                }
            } else {
                SignPage::Address {
                    index: recipient,
                    of: n,
                    address: r.address,
                }
            });
        }
        let mut i = index - rp;
        if self.high_fee() {
            if i == 0 {
                return Some(SignPage::HighFeeWarning {
                    fee_sats: self.fee_sats,
                    sent_sats: self.sent_sats().min(u64::MAX as u128) as u64,
                });
            }
            i -= 1;
        }
        match i {
            0 => Some(SignPage::Fee {
                sats: self.fee_sats,
            }),
            1 => Some(SignPage::Confirm),
            _ => None,
        }
    }

    /// Compose page `index` into `frame`.
    ///
    /// Returns `false` for "there is nothing consentable on this index" — either
    /// `index` is past the end (frame untouched) or the page could not be drawn in
    /// full (frame holds [`refusal`]). A caller must only advance or accept
    /// consent when this returns `true`.
    pub fn render(&self, index: usize, frame: &mut Frame) -> bool {
        let Some(page) = self.page(index) else {
            return false;
        };
        frame.clear();
        match page {
            SignPage::SelfSend => {
                frame.text(0, 0, "No recipients:");
                frame.text(0, 2, "all outputs go");
                frame.text(0, 3, "back to this");
                frame.text(0, 4, "wallet.");
            }
            SignPage::Amount { index, of, sats } => {
                frame.text(0, 0, "Send amount");
                frame.text(0, 1, counter(index, of).as_str());
                let mut b = Buf::<20>::new();
                b.push_u64(sats);
                frame.wrap(3, 2, b.as_str());
                frame.text(0, 6, "sats");
            }
            SignPage::Address { index, of, address } => {
                frame.text(0, 0, "To address");
                frame.text(0, 1, counter(index, of).as_str());
                // `new` validated every address, so this branch is unreachable
                // through the public API. It is still handled rather than
                // discarded, because the failure mode of discarding it is a
                // consent screen showing a partial address — and a `let _ =` on
                // a refusal is how this project has been bitten before.
                if address_block(frame, 2, address, index as u32).is_err() {
                    refusal(frame);
                    return false;
                }
            }
            SignPage::HighFeeWarning {
                fee_sats,
                sent_sats,
            } => {
                frame.text(0, 0, "!! HIGH FEE !!");
                frame.text(0, 2, "fee sats:");
                let mut b = Buf::<20>::new();
                b.push_u64(fee_sats);
                frame.text(0, 3, b.as_str());
                frame.text(0, 5, "sent sats:");
                let mut b = Buf::<20>::new();
                b.push_u64(sent_sats);
                frame.text(0, 6, b.as_str());
            }
            SignPage::Fee { sats } => fee_page(frame, sats),
            SignPage::Confirm => {
                frame.text(0, 0, "Approve and");
                frame.text(0, 1, "sign?");
                frame.text(0, 4, "hold 1 to sign");
                frame.text(0, 6, "x to cancel");
            }
        }
        true
    }
}

/// The screen for "this device cannot show you what you would be signing".
///
/// The only correct answer to an [`Unrenderable`] at draw time. It is not a
/// fallback layout: nothing about it can be confirmed, and the caller is expected
/// to reject the coordinator's request outright.
pub fn refusal(frame: &mut Frame) {
    frame.clear();
    frame.text(0, 0, "CANNOT DISPLAY");
    frame.text(0, 2, "this request in");
    frame.text(0, 3, "full. Refusing");
    frame.text(0, 4, "to sign it.");
    frame.text(0, 7, "x to dismiss");
}

/// The screen for "this device cannot prove which device it is".
///
/// PLAN.md §9 item 14: an identity fault holds *dark* — the firmware spins above USB
/// bring-up so a device that cannot prove its identity never enumerates — and that
/// hold was undiagnosable, indistinguishable from dead silicon at a bench. This is
/// the screen that fixes it, and it is why §9 item 14 called the identity hold the
/// first thing phase 5 should draw.
///
/// `reason` is a short discriminator, not a message: the caller maps its own fault
/// type to one, because this module deliberately does not depend on
/// `crate::identity`. Truncated at [`COLS`] like any other text, so a caller cannot
/// make this screen overrun.
///
/// It says *refusing*, never *failed*. A user who reads "failed" reasonably tries
/// again; the whole point of this state is that retrying cannot help, because the
/// bytes on flash are the same every boot.
pub fn identity_fault(frame: &mut Frame, reason: &str) {
    frame.clear();
    frame.text(0, 0, "IDENTITY FAULT");
    frame.text(0, 1, reason);
    frame.text(0, 3, "Cannot prove");
    frame.text(0, 4, "which device");
    frame.text(0, 5, "this is.");
    frame.text(0, 7, "Will not start");
}

/// The fee page: the number, and the fact that this device did not verify it.
///
/// `TransactionTemplate::fee()` is `sum(inputs) - sum(outputs)` over
/// caller-supplied values with no prevout check, and `push_foreign_input` takes
/// `value` on trust. The taproot sighash does bind prevout amounts via
/// `Prevouts::All`, so a forged value yields an invalid signature rather than a
/// stolen fee — but the number on screen at consent time is still the
/// coordinator's, and PLAN.md §4.2 forbids presenting it as device-verified.
pub fn fee_page(frame: &mut Frame, sats: u64) {
    frame.text(0, 0, "Network fee:");
    let mut b = Buf::<20>::new();
    b.push_u64(sats);
    frame.wrap(1, 2, b.as_str());
    frame.text(0, 3, "sats");
    frame.text(0, 5, FEE_UNVERIFIED_1);
    frame.text(0, 6, FEE_UNVERIFIED_2);
}

/// `"#3 of 12"` — the only thing tying an amount page to its address page on a
/// 16-column screen, so it is load-bearing rather than decoration.
fn counter(index: usize, of: usize) -> Buf<16> {
    let mut b = Buf::<16>::new();
    b.push_str("#")
        .push_u64(index.saturating_add(1) as u64)
        .push_str(" of ")
        .push_u64(of as u64);
    b
}

/// Reject anything that is not a renderable address before it reaches a screen.
fn check_address(address: &str) -> Result<(), Unrenderable> {
    if !address.bytes().all(|b| b.is_ascii_graphic()) || address.is_empty() {
        return Err(Unrenderable::NotAscii);
    }
    if address.len() > ADDRESS_ROWS * COLS {
        return Err(Unrenderable::TooLong);
    }
    Ok(())
}

/// Draw an address in full across [`ADDRESS_ROWS`] rows from `row`, with two
/// interior 4-char chunks in inverse video.
///
/// The highlighting is not decoration: it is upstream's anti-skimming defence
/// (`address_display.rs:145-166`, "exclude first and last"). It forces attention
/// into the middle of the string, which is the region a user who checks only the
/// first and last few characters never reads.
fn address_block(frame: &mut Frame, row: usize, address: &str, seed: u32) -> Result<(), Unrenderable> {
    check_address(address)?;
    let n = address.chars().count();
    if frame.wrap(row, ADDRESS_ROWS, address) != n {
        return Err(Unrenderable::TooLong);
    }
    let chunks = n / CHUNK;
    if let Some((a, b)) = pick_highlights(seed, chunks) {
        for c in [a, b] {
            let start = c * CHUNK;
            frame.invert_cells(start % COLS, row + start / COLS, CHUNK);
        }
    }
    Ok(())
}

/// Two distinct interior chunk indices to highlight, or `None` when there is no
/// interior. Ported from `address_display.rs:145-166`; the `chunks <= 2` early
/// return is what bounds the retry loop.
fn pick_highlights(seed: u32, chunks: usize) -> Option<(usize, usize)> {
    if chunks <= 2 {
        return None;
    }
    let interior = chunks - 2;
    let a = 1 + (seed as usize) % interior;
    if interior == 1 {
        return None;
    }
    let mut b = 1 + (seed.wrapping_mul(0x9e37_79b9) as usize) % interior;
    if b == a {
        b = 1 + (a % interior);
    }
    Some((a, b))
}

// ---------------------------------------------------------------------------
// Screen 4 — test-message sign confirm
// ---------------------------------------------------------------------------

/// Rows available to the test message body.
const MESSAGE_ROWS: usize = 4;

/// Screen 4: consent to signing an arbitrary message.
///
/// Refuses any message that does not fit **entirely** on screen.
/// `SignTask::Test { message }` is an unbounded `String` on the wire (bounded only
/// by `comms::FRAME_LIMIT`), and showing 64 characters of 4,000 while signing all
/// 4,000 is a blind signer. Truncation here would be a security bug, so it is a
/// refusal.
pub fn sign_test_message(frame: &mut Frame, message: &str) -> Result<(), Unrenderable> {
    if !message.bytes().all(|b| b.is_ascii_graphic() || b == b' ') {
        return Err(Unrenderable::NotAscii);
    }
    let n = message.chars().count();
    if n > MESSAGE_ROWS * COLS {
        return Err(Unrenderable::TooLong);
    }
    frame.clear();
    frame.text(0, 0, "Sign message?");
    if frame.wrap(2, MESSAGE_ROWS, message) != n {
        return Err(Unrenderable::TooLong);
    }
    frame.text(0, 7, "hold 1  x=no");
    Ok(())
}

// ---------------------------------------------------------------------------
// Screen 5 — backup display
// ---------------------------------------------------------------------------

/// One page of the backup display.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BackupPage<'a> {
    /// The share index. First page and not optional: a backup written down
    /// without its share index is unrestorable.
    ShareIndex(u32),
    /// Up to [`WORDS_PER_PAGE`] words, `first` being the 1-based number of the
    /// first of them.
    Words {
        /// 1-based number of the first word on this page.
        first: usize,
        /// The words on this page.
        words: &'a [&'a str],
    },
}

/// The 25-word backup display: one share-index page plus
/// `ceil(25 / WORDS_PER_PAGE)` word pages = 8.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BackupPages<'a> {
    share_index: u32,
    words: &'a [&'a str],
}

impl<'a> BackupPages<'a> {
    /// Validate a backup for display, or refuse it. Requires exactly
    /// [`BACKUP_WORDS`] words, each 1..=8 lowercase ASCII letters (BIP39 shape).
    pub fn new(share_index: u32, words: &'a [&'a str]) -> Result<Self, Unrenderable> {
        if words.len() != BACKUP_WORDS {
            return Err(Unrenderable::BadWordList);
        }
        for w in words {
            if w.is_empty() || w.len() > 8 || !w.bytes().all(|b| b.is_ascii_lowercase()) {
                return Err(Unrenderable::BadWordList);
            }
        }
        Ok(BackupPages { share_index, words })
    }

    /// Total pages: 1 + word pages.
    pub fn len(&self) -> usize {
        1 + self.words.len().div_ceil(WORDS_PER_PAGE)
    }

    /// Always `false`; the share-index page always exists.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// The page at `index`, or `None` past the end.
    pub fn page(&self, index: usize) -> Option<BackupPage<'a>> {
        if index == 0 {
            return Some(BackupPage::ShareIndex(self.share_index));
        }
        let start = (index - 1) * WORDS_PER_PAGE;
        let end = start.saturating_add(WORDS_PER_PAGE).min(self.words.len());
        let words = self.words.get(start..end)?;
        if words.is_empty() {
            return None;
        }
        Some(BackupPage::Words {
            first: start + 1,
            words,
        })
    }

    /// Compose page `index`. `false` past the end.
    ///
    /// Word rows keep the two-digit-colon `NN:` shape, because
    /// `shared/display.py:284-285` triggers Coldcard's `mark_sensitive`
    /// side-channel defence on exactly that shape and PLAN.md §4.2 requires it be
    /// preserved.
    pub fn render(&self, index: usize, frame: &mut Frame) -> bool {
        let Some(page) = self.page(index) else {
            return false;
        };
        frame.clear();
        match page {
            BackupPage::ShareIndex(i) => {
                frame.text(0, 0, "Write this down");
                frame.text(0, 2, "Share index:");
                let mut b = Buf::<16>::new();
                b.push_str("#").push_u64(i as u64);
                frame.text(0, 4, b.as_str());
                frame.text(0, 7, "5=next");
            }
            BackupPage::Words { first, words } => {
                let mut head = Buf::<16>::new();
                head.push_str("words ")
                    .push_u64(first as u64)
                    .push_str("-")
                    .push_u64((first + words.len() - 1) as u64);
                frame.text(0, 0, head.as_str());
                for (i, w) in words.iter().enumerate() {
                    let mut b = Buf::<16>::new();
                    b.push_u8_pad2((first + i) as u8)
                        .push_str(": ")
                        .push_str(w);
                    frame.text(0, 2 + i, b.as_str());
                }
                frame.text(0, 7, "5=next 8=back");
            }
        }
        true
    }
}

// ---------------------------------------------------------------------------
// Screen 6 — backup entry
// ---------------------------------------------------------------------------

/// One page of backup entry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EntryPage<'a> {
    /// Entering the share index. Page 0, and word entry is gated behind it
    /// (upstream's `share_index_confirmed`, `backup_model.rs:100-101,167-171`).
    ShareIndex {
        /// Digits typed so far.
        partial: &'a str,
    },
    /// Entering word `number` (1-based) of [`BACKUP_WORDS`].
    Word {
        /// 1-based word number.
        number: usize,
        /// Letters typed so far.
        partial: &'a str,
        /// The previously entered word, for context.
        previous: Option<&'a str>,
    },
}

/// Backup-entry paging: one share-index page then [`BACKUP_WORDS`] word pages.
///
/// This is the state machine reduced to what a 12-key membrane pad needs: no
/// keyboard model, no candidate list, no rendering of either. `firmware/` owns
/// key handling and hands the accumulated state here as plain data.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EntryPages<'a> {
    /// The share index, once confirmed. `None` while it is still being entered.
    pub share_index: Option<u32>,
    /// Words confirmed so far, in order.
    pub words: &'a [&'a str],
    /// Digits or letters typed for the current field but not yet confirmed.
    pub partial: &'a str,
}

impl<'a> EntryPages<'a> {
    /// Total pages: share index plus one per word.
    pub fn len(&self) -> usize {
        1 + BACKUP_WORDS
    }

    /// Always `false`.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// The page the user is on. Stays at 0 until the share index is confirmed —
    /// that gate is the whole state machine, and it is why this is a function
    /// rather than a field.
    pub fn cursor(&self) -> usize {
        if self.share_index.is_none() {
            0
        } else {
            1 + self.words.len().min(BACKUP_WORDS - 1)
        }
    }

    /// The page at `index`, or `None` past the end.
    pub fn page(&self, index: usize) -> Option<EntryPage<'a>> {
        if index == 0 {
            return Some(EntryPage::ShareIndex {
                partial: self.partial,
            });
        }
        if index > BACKUP_WORDS {
            return None;
        }
        Some(EntryPage::Word {
            number: index,
            partial: if index - 1 == self.words.len() {
                self.partial
            } else {
                ""
            },
            previous: if index >= 2 {
                self.words.get(index - 2).copied()
            } else {
                None
            },
        })
    }

    /// Compose page `index`. `false` past the end.
    pub fn render(&self, index: usize, frame: &mut Frame) -> bool {
        let Some(page) = self.page(index) else {
            return false;
        };
        frame.clear();
        match page {
            EntryPage::ShareIndex { partial } => {
                frame.text(0, 0, "Restore backup");
                frame.text(0, 2, "share index:");
                let mut b = Buf::<16>::new();
                b.push_str(partial).push_str("_");
                frame.text(0, 4, b.as_str());
                frame.text(0, 7, "1=ok x=del");
            }
            EntryPage::Word {
                number,
                partial,
                previous,
            } => {
                let mut head = Buf::<16>::new();
                head.push_str("word ")
                    .push_u64(number as u64)
                    .push_str(" of ")
                    .push_u64(BACKUP_WORDS as u64);
                frame.text(0, 0, head.as_str());
                if let Some(p) = previous {
                    let mut b = Buf::<16>::new();
                    b.push_u8_pad2((number - 1) as u8).push_str(": ").push_str(p);
                    frame.text(0, 2, b.as_str());
                }
                let mut b = Buf::<16>::new();
                b.push_u8_pad2(number as u8)
                    .push_str(": ")
                    .push_str(partial)
                    .push_str("_");
                frame.text(0, 4, b.as_str());
                frame.text(0, 7, "1=ok x=del");
            }
        }
        true
    }
}

// ---------------------------------------------------------------------------
// Screen 7 — backup check quiz
// ---------------------------------------------------------------------------

/// Screen 7: a multiple-choice quiz question, three options on the `1`/`2`/`3`
/// keys.
///
/// The distractors are chosen above this seam (upstream `distractor.rs` picks the
/// two most-confusable BIP39 words by edit distance) because that needs the
/// wordlist, which this crate does not carry. `question` and the options are
/// device-generated, not coordinator text, but they still go through the same
/// bounded text path.
pub fn backup_quiz(frame: &mut Frame, question: &str, options: [&str; 3], selected: Option<usize>) {
    frame.clear();
    frame.text(0, 0, question);
    for (i, opt) in options.iter().enumerate() {
        let mut b = Buf::<16>::new();
        b.push_u64(i as u64 + 1).push_str(") ").push_str(opt);
        let row = 2 + i * 2;
        if selected == Some(i) {
            frame.text_inverted(0, row, b.as_str());
        } else {
            frame.text(0, row, b.as_str());
        }
    }
}

// ---------------------------------------------------------------------------
// Screen 8 — address verification
// ---------------------------------------------------------------------------

/// Screen 8: show a receive address in full for comparison against the
/// coordinator's, with its derivation path.
///
/// All of the address is on screen simultaneously — the property upstream's 6×3
/// grid had and that scrolling would destroy. If it does not fit in full, refuse:
/// a truncated address that looks complete is upstream's `chunk_address` bug
/// (`address_display.rs:88-96` silently drops the tail past 72 chars).
///
/// `path` is coordinator-supplied and unbounded (`derivation_index` is a raw
/// `u32`), so it is truncated at 16 columns; the address is the security payload
/// and is never truncated.
pub fn address_verify(
    frame: &mut Frame,
    address: &str,
    path: &str,
    seed: u32,
) -> Result<(), Unrenderable> {
    check_address(address)?;
    frame.clear();
    frame.text(0, 0, path);
    address_block(frame, 2, address, seed)?;
    frame.text(0, 7, "1=ok x=no");
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    extern crate std;

    use super::*;
    use alloc::format;
    use alloc::string::String;
    use alloc::vec::Vec;

    /// Read a whole row back out of the pixels as text.
    /// Decode a [`Frame::text_2x`] region back to characters, by INVERTING the
    /// doubling and matching the reconstructed cell against `FONT`.
    ///
    /// Deliberately an exact inverse rather than a fuzzy check: it reconstructs the
    /// source byte from the even destination columns of both byte-rows and then
    /// requires a byte-for-byte font match, so it fails if the blit is wrong in any
    /// bit — including a horizontal-only or vertical-only double, which a
    /// "some pixels are set" assertion would pass.
    fn text_2x_at(f: &Frame, col: usize, row: usize, len: usize) -> String {
        let mut out = String::new();
        for i in 0..len {
            let x = col + i * 2;
            let mut src = [0u8; CELL];
            for (j, s) in src.iter_mut().enumerate() {
                let dx = x * CELL + j * 2;
                let lo = f.as_bytes()[row * WIDTH + dx];
                let hi = f.as_bytes()[(row + 1) * WIDTH + dx];
                let mut b = 0u8;
                for k in 0..4 {
                    b |= ((lo >> (2 * k)) & 1) << k;
                    b |= ((hi >> (2 * k)) & 1) << (k + 4);
                }
                *s = b;
            }
            // Find which glyph this is. FONT_FIRST + index is the codepoint.
            let found = (0..96).find(|g| FONT[g * CELL..(g + 1) * CELL] == src);
            out.push(match found {
                Some(g) => char::from_u32(FONT_FIRST + g as u32).unwrap_or('?'),
                None => '?',
            });
        }
        out
    }

    fn row_text(f: &Frame, row: usize) -> String {
        let mut s = String::new();
        for col in 0..COLS {
            match f.cell(col, row) {
                Some((b, _)) => s.push(b as char),
                None => s.push('\u{0}'),
            }
        }
        s.trim_end().into()
    }

    fn screen_text(f: &Frame) -> String {
        (0..ROWS)
            .map(|r| row_text(f, r))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn art(f: &Frame) -> String {
        let mut s = String::new();
        for y in 0..HEIGHT {
            for x in 0..WIDTH {
                s.push(if f.pixel(x, y) { '#' } else { '.' });
            }
            s.push('\n');
        }
        s
    }

    // -- 1. the pixel mapping. Everything else in this file is worthless if this
    //       is wrong, so it is pinned against the spec, not against itself.

    #[test]
    fn mono_vlsb_corner_pixels_map_to_exact_bytes() {
        // (x, y) -> byte (y/8)*128 + x, bit 1 << (y%8); bit 0 is the TOP row.
        for (x, y, byte, bit) in [
            (0usize, 0usize, 0usize, 0u8),
            (127, 0, 127, 0),
            (0, 7, 0, 7),
            (0, 8, 128, 0),
            (0, 63, 896, 7),
            (127, 63, 1023, 7),
            (5, 20, 2 * 128 + 5, 4),
        ] {
            let mut f = Frame::new();
            f.set_pixel(x, y, true);
            let bytes = f.as_bytes();
            assert_eq!(
                bytes[byte], 1u8 << bit,
                "pixel ({x},{y}) must be byte {byte} bit {bit}"
            );
            assert_eq!(
                bytes.iter().filter(|b| **b != 0).count(),
                1,
                "pixel ({x},{y}) lit more than one byte"
            );
            assert!(f.pixel(x, y));
        }
    }

    #[test]
    fn out_of_range_pixels_are_noops_not_wraps() {
        let mut f = Frame::new();
        f.set_pixel(WIDTH, 0, true);
        f.set_pixel(0, HEIGHT, true);
        f.set_pixel(usize::MAX, usize::MAX, true);
        assert!(f.as_bytes().iter().all(|b| *b == 0));
        assert!(!f.pixel(WIDTH, 0));
    }

    #[test]
    fn glyph_cell_is_a_byte_for_byte_copy_of_the_font_table() {
        // petme128 is column-major bit0-top, so a page-aligned cell IS the glyph.
        let mut f = Frame::new();
        f.text(3, 5, "A");
        let g = (b'A' - 32) as usize * CELL;
        let base = 5 * WIDTH + 3 * CELL;
        assert_eq!(&f.as_bytes()[base..base + CELL], &FONT[g..g + CELL]);
    }

    #[test]
    fn known_glyph_pixels_match_reference_bitmap() {
        // 'A' from petme128, transcribed from the table independently of the
        // renderer. If the mapping is transposed this is unrecognisable.
        const A: [&str; 8] = [
            "...##...",
            "..####..",
            ".##..##.",
            ".######.",
            ".##..##.",
            ".##..##.",
            ".##..##.",
            "........",
        ];
        let mut f = Frame::new();
        f.text(0, 0, "A");
        for (y, want) in A.iter().enumerate() {
            let got: String = (0..8)
                .map(|x| if f.pixel(x, y) { '#' } else { '.' })
                .collect();
            assert_eq!(&got, want, "row {y} of 'A'");
        }
    }

    // -- 2. text: attacker-controlled, arbitrary length, arbitrary bytes.

    #[test]
    fn text_reports_chars_drawn_and_truncates_at_the_column_budget() {
        let mut f = Frame::new();
        assert_eq!(f.text(0, 0, "0123456789abcdef"), 16);
        assert_eq!(f.text(0, 1, "0123456789abcdefg"), 16);
        assert_eq!(f.text(14, 2, "abcdef"), 2);
        assert_eq!(f.text(COLS, 0, "x"), 0);
        assert_eq!(f.text(0, ROWS, "x"), 0);
    }

    #[test]
    fn text_never_panics_on_hostile_input() {
        let mut f = Frame::new();
        let four_k: String = "\u{1F600}".repeat(1024);
        for s in [
            "",
            "\u{202e}drainmywallet",   // RTL override
            "a\u{200d}b",              // ZWJ
            "e\u{301}",                // combining acute
            "\u{0}\u{7f}\u{ffff}",
            "日本語テキスト",
            four_k.as_str(),
        ] {
            let n = f.text(0, 0, s);
            assert!(n <= COLS);
            assert!(f.wrap(0, ROWS, s) <= COLS * ROWS);
            assert!(
                Buf::<16>::new().push_str(s).as_str().len() <= 16,
                "Buf overran on {s:?}"
            );
        }
    }

    #[test]
    fn rtl_override_and_zero_width_render_as_visible_cells_and_do_not_reorder() {
        let mut f = Frame::new();
        // U+202E would reverse the visual order in a shaping engine. Here it is
        // one missing-glyph cell and the rest is unchanged, left to right.
        f.text(0, 0, "\u{202e}abc");
        assert_eq!(&row_text(&f, 0)[..4], "\u{7f}abc");
        f.clear();
        f.text(0, 0, "a\u{200d}b");
        assert_eq!(&row_text(&f, 0)[..3], "a\u{7f}b");
    }

    #[test]
    fn unmapped_codepoints_draw_a_box_and_are_never_dropped() {
        // A name that renders shorter than it is, is a spoofing primitive.
        let mut f = Frame::new();
        assert_eq!(f.text(0, 0, "a\u{4e00}\u{4e01}b"), 4);
    }

    #[test]
    fn buf_push_u64_handles_zero_and_max() {
        assert_eq!(Buf::<20>::new().push_u64(0).as_str(), "0");
        assert_eq!(
            Buf::<20>::new().push_u64(u64::MAX).as_str(),
            "18446744073709551615"
        );
        let mut small = Buf::<4>::new();
        small.push_u64(u64::MAX);
        assert!(small.truncated());
        assert_eq!(small.as_str(), "1844");
    }

    // -- 3. sign approval: the security screen.

    fn recips<'a>(v: &'a [(&'a str, u64)]) -> Vec<Recipient<'a>> {
        v.iter()
            .map(|(a, s)| Recipient {
                address: a,
                sats: *s,
            })
            .collect()
    }

    const ADDR: &str = "bc1p5cyxnuxmeuwuvkwfem96l7c9uhrsltzslxk4v6rncpwjhg6c6nzsxcykmp";

    #[test]
    fn sign_page_count_is_two_per_recipient_plus_fee_and_confirm() {
        for n in 1..=8usize {
            let v: Vec<(&str, u64)> = (0..n).map(|_| (ADDR, 1_000u64)).collect();
            let r = recips(&v);
            let p = SignPages::new(&r, 10).unwrap();
            assert!(!p.high_fee(), "fee 10 of {} sent must not warn", n * 1000);
            assert_eq!(p.len(), n * 2 + 2, "{n} recipients");
            assert_eq!(p.page(p.len() - 1), Some(SignPage::Confirm));
            assert_eq!(p.page(p.len()), None);
        }
    }

    #[test]
    fn every_recipient_appears_with_its_amount_and_full_address() {
        // The property PLAN.md 4.2 demands: no page set can omit a recipient.
        let v: Vec<(&str, u64)> = (0..7)
            .map(|i| (["1A", "3B", "bc1q", ADDR][i % 4], 1_000 + i as u64))
            .collect();
        let r = recips(&v);
        let p = SignPages::new(&r, 100).unwrap();

        let pages: Vec<SignPage> = (0..p.len()).filter_map(|i| p.page(i)).collect();
        for (i, want) in r.iter().enumerate() {
            assert!(
                pages.contains(&SignPage::Amount {
                    index: i,
                    of: r.len(),
                    sats: want.sats
                }),
                "recipient {i} has no amount page"
            );
            assert!(
                pages.contains(&SignPage::Address {
                    index: i,
                    of: r.len(),
                    address: want.address
                }),
                "recipient {i} has no address page"
            );
        }
        assert!(pages.iter().any(|pg| matches!(pg, SignPage::Fee { .. })));
        assert_eq!(pages.last(), Some(&SignPage::Confirm));
        // and every address is rendered in full, character for character
        let mut f = Frame::new();
        for i in 0..p.len() {
            if let Some(SignPage::Address { address, .. }) = p.page(i) {
                assert!(p.render(i, &mut f));
                let shown: String = screen_text(&f).chars().filter(|c| !c.is_whitespace()).collect();
                assert!(
                    shown.contains(address),
                    "address {address} not fully on screen: {shown}"
                );
            }
        }
    }

    #[test]
    fn too_many_recipients_is_refused_not_truncated() {
        let v: Vec<(&str, u64)> = (0..=MAX_RECIPIENTS).map(|_| (ADDR, 1u64)).collect();
        let r = recips(&v);
        assert_eq!(
            SignPages::new(&r, 1),
            Err(Unrenderable::TooManyRecipients)
        );
        let ok: Vec<(&str, u64)> = (0..MAX_RECIPIENTS).map(|_| (ADDR, 1u64)).collect();
        assert!(SignPages::new(&recips(&ok), 1).is_ok());
    }

    #[test]
    fn unrenderable_address_refuses_the_whole_transaction() {
        // Not "render the ones we can" -- the whole request is rejected.
        let long = "b".repeat(ADDRESS_ROWS * COLS + 1);
        for (addr, want) in [
            (long.as_str(), Unrenderable::TooLong),
            ("", Unrenderable::NotAscii),
            ("bc1q\u{202e}spoof", Unrenderable::NotAscii),
            ("bc1 q with space", Unrenderable::NotAscii),
        ] {
            let v = [(ADDR, 1u64), (addr, 2u64), (ADDR, 3u64)];
            assert_eq!(SignPages::new(&recips(&v), 1), Err(want), "addr {addr:?}");
        }
    }

    #[test]
    fn address_is_rendered_to_the_last_character() {
        let mut f = Frame::new();
        let addr = "b".repeat(ADDRESS_ROWS * COLS);
        address_block(&mut f, 2, &addr, 0).unwrap();
        let shown: String = (2..2 + ADDRESS_ROWS)
            .map(|r| row_text(&f, r))
            .collect::<Vec<_>>()
            .join("");
        assert_eq!(shown.len(), addr.len(), "every cell of the address is drawn");
        // and one character more than the budget refuses rather than clipping
        let over = "b".repeat(ADDRESS_ROWS * COLS + 1);
        assert_eq!(
            address_block(&mut f, 2, &over, 0),
            Err(Unrenderable::TooLong)
        );
    }

    #[test]
    fn address_highlight_inverts_two_interior_chunks() {
        let mut f = Frame::new();
        address_block(&mut f, 2, ADDR, 7).unwrap();
        let inverted: Vec<usize> = (0..ADDRESS_ROWS)
            .flat_map(|r| (0..COLS).map(move |c| (r, c)))
            .filter(|(r, c)| f.cell(*c, 2 + r).map(|(_, i)| i).unwrap_or(false))
            .map(|(r, c)| r * COLS + c)
            .collect();
        assert_eq!(inverted.len(), 2 * CHUNK, "two 4-char chunks inverted");
        // never the first or last chunk: skimming the ends must not suffice
        let n = ADDR.chars().count();
        assert!(inverted.iter().all(|i| *i >= CHUNK && *i < n - CHUNK));
    }

    #[test]
    fn high_fee_absolute_threshold_fires_above_100k_sats() {
        let v = [(ADDR, 100_000_000_000u64)];
        let r = recips(&v);
        assert!(!SignPages::new(&r, HIGH_FEE_SATS).unwrap().high_fee());
        assert!(SignPages::new(&r, HIGH_FEE_SATS + 1).unwrap().high_fee());
        // and the warning page exists, before the fee page
        let p = SignPages::new(&r, HIGH_FEE_SATS + 1).unwrap();
        assert_eq!(p.len(), 2 + 1 + 2);
        assert_eq!(
            p.page(2),
            Some(SignPage::HighFeeWarning {
                fee_sats: HIGH_FEE_SATS + 1,
                sent_sats: 100_000_000_000
            })
        );
        assert_eq!(
            p.page(3),
            Some(SignPage::Fee {
                sats: HIGH_FEE_SATS + 1
            })
        );
    }

    #[test]
    fn high_fee_relative_threshold_fires_above_five_percent_of_sent() {
        let v = [(ADDR, 10_000u64)];
        let r = recips(&v);
        assert!(!SignPages::new(&r, 500).unwrap().high_fee(), "exactly 5%");
        assert!(SignPages::new(&r, 501).unwrap().high_fee(), "just over 5%");
        assert_eq!(SignPages::new(&r, 501).unwrap().len(), 5);
    }

    #[test]
    fn high_fee_does_not_overflow_at_extreme_amounts() {
        // upstream's `total_sent * 5 / 100` in u64 wraps here under
        // overflow-checks = false, and panics under = true.
        let v = [(ADDR, u64::MAX), (ADDR, u64::MAX)];
        let r = recips(&v);
        let p = SignPages::new(&r, u64::MAX).unwrap();
        assert!(p.high_fee());
        assert_eq!(p.sent_sats(), u64::MAX as u128 * 2);
        let small = [(ADDR, u64::MAX)];
        assert!(!SignPages::new(&recips(&small), 1).unwrap().high_fee());
    }

    #[test]
    fn zero_recipients_shows_an_explicit_self_send_page() {
        let p = SignPages::new(&[], 42).unwrap();
        assert_eq!(p.page(0), Some(SignPage::SelfSend));
        assert_eq!(p.len(), 3);
        assert!(!p.high_fee(), "no relative warning with nothing sent");
        let mut f = Frame::new();
        assert!(p.render(0, &mut f));
        assert!(screen_text(&f).contains("No recipients"));
    }

    #[test]
    fn fee_page_is_labelled_not_device_verified() {
        let r = recips(&[(ADDR, 1_000u64)]);
        let p = SignPages::new(&r, 7).unwrap();
        let mut f = Frame::new();
        let fee_index = (0..p.len())
            .find(|i| matches!(p.page(*i), Some(SignPage::Fee { .. })))
            .expect("a fee page always exists");
        assert!(p.render(fee_index, &mut f));
        let t = screen_text(&f);
        assert!(t.contains(FEE_UNVERIFIED_1), "missing provenance line 1: {t}");
        assert!(t.contains(FEE_UNVERIFIED_2), "missing provenance line 2: {t}");
        assert!(t.contains('7'));
    }

    #[test]
    fn confirm_is_always_the_last_page_so_no_page_can_be_skipped() {
        for n in 0..=4usize {
            for fee in [1u64, HIGH_FEE_SATS + 1] {
                let v: Vec<(&str, u64)> = (0..n).map(|_| (ADDR, 1_000_000u64)).collect();
                let r = recips(&v);
                let p = SignPages::new(&r, fee).unwrap();
                assert_eq!(p.page(p.len() - 1), Some(SignPage::Confirm));
                for i in 0..p.len() - 1 {
                    assert_ne!(p.page(i), Some(SignPage::Confirm));
                }
            }
        }
    }

    // -- 4. keygen check: the anti-MITM screen.

    #[test]
    fn keygen_code_format_is_two_bytes_space_two_bytes_lowercase() {
        assert_eq!(keygen_code([0xab, 0xcd, 0xef, 0x01]).as_str(), "abcd ef01");
        assert_eq!(keygen_code([0, 0, 0, 0]).as_str(), "0000 0000");
        assert_eq!(keygen_code([0xff; 4]).as_str(), "ffff ffff");
    }

    #[test]
    fn text_2x_doubles_in_both_axes_and_round_trips_through_the_font() {
        // Every printable char must survive draw-then-decode. This is what makes
        // `text_2x_at` trustworthy as an oracle for the keygen tests.
        let mut enc = [0u8; 4];
        for c in ' '..='~' {
            let s: &str = c.encode_utf8(&mut enc);
            let mut f = Frame::new();
            assert_eq!(f.text_2x(0, 0, s), 1, "{c:?} not drawn");
            assert_eq!(
                text_2x_at(&f, 0, 0, 1).chars().next(),
                Some(c),
                "{c:?} did not round trip"
            );
        }
        // Doubling is in BOTH axes: a 2x glyph occupies 16 px across and 16 down,
        // i.e. 2 cells and 2 byte-rows. Compare a pixel-by-pixel expectation
        // against the 1x glyph rather than trusting the decoder alone.
        let mut one = Frame::new();
        one.text(0, 0, "M");
        let mut two = Frame::new();
        two.text_2x(0, 0, "M");
        for y in 0..8 {
            for x in 0..8 {
                let src = one.pixel(x, y);
                for (dy, dx) in [(0, 0), (0, 1), (1, 0), (1, 1)] {
                    assert_eq!(
                        two.pixel(x * 2 + dx, y * 2 + dy),
                        src,
                        "2x pixel ({},{}) from 1x ({x},{y})",
                        x * 2 + dx,
                        y * 2 + dy
                    );
                }
            }
        }
    }

    #[test]
    fn text_2x_refuses_rather_than_half_drawing_at_the_edges() {
        let mut f = Frame::new();
        // Last row cannot host a 2x glyph: it needs the row below it.
        assert_eq!(f.text_2x(0, ROWS - 1, "8"), 0, "drew off the bottom");
        assert_eq!(f.text_2x(0, ROWS, "8"), 0, "drew past the bottom");
        // 8 chars is exactly the panel width at 2x; the 9th must not half-draw.
        let mut g = Frame::new();
        assert_eq!(g.text_2x(0, 0, "123456789"), 8, "should stop at COLS/2");
        // And the odd last column cannot host one either.
        let mut h = Frame::new();
        assert_eq!(h.text_2x(COLS - 1, 0, "8"), 0, "drew off the right edge");
    }

    #[test]
    fn keygen_check_renders_the_code_and_the_compare_instruction() {
        let mut f = Frame::new();
        keygen_check(&mut f, 2, 3, [0xab, 0xcd, 0xef, 0x01], "wallet");
        let t = screen_text(&f);
        // The code is drawn at 2x per PLAN.md §4.2's FontLarge requirement, so it is
        // NOT in the 8x8 cell grid and `screen_text` cannot see it. Decode the 2x
        // region exactly instead -- and assert both halves, because the whole value
        // is what gets compared between devices.
        assert_eq!(text_2x_at(&f, (COLS - 8) / 2, 2, 4), "abcd", "code high half");
        assert_eq!(text_2x_at(&f, (COLS - 8) / 2, 4, 4), "ef01", "code low half");
        assert!(t.contains(KEYGEN_COMPARE_1), "no compare instruction: {t}");
        assert!(t.contains(KEYGEN_COMPARE_2), "no compare instruction: {t}");
        assert!(t.contains("2-of-3"), "no threshold: {t}");
    }

    #[test]
    fn keygen_check_survives_a_hostile_key_name_and_extreme_threshold() {
        let mut f = Frame::new();
        let name: String = "\u{202e}".repeat(4096);
        keygen_check(&mut f, u16::MAX, u16::MAX, [1, 2, 3, 4], &name);
        let t = screen_text(&f);
        assert_eq!(text_2x_at(&f, (COLS - 8) / 2, 2, 4), "0102", "code high half");
        assert_eq!(text_2x_at(&f, (COLS - 8) / 2, 4, 4), "0304", "code low half");
        assert!(t.contains(KEYGEN_COMPARE_1), "hostile name pushed out the check");
        assert!(t.contains("65535-of-6"), "threshold row: {t}");
    }

    // -- 5. the remaining screens.

    #[test]
    fn identity_fault_names_the_state_and_refuses_rather_than_inviting_a_retry() {
        let mut f = Frame::new();
        identity_fault(&mut f, "damaged record");
        let t = screen_text(&f);
        assert!(t.contains("IDENTITY FAULT"), "no title: {t}");
        assert!(t.contains("damaged record"), "no reason: {t}");
        assert!(t.contains("Will not start"), "no refusal: {t}");
        // "failed" invites a retry, and retrying cannot help: the flash bytes are
        // identical every boot. This is the whole reason the wording is "refusing".
        assert!(!t.to_lowercase().contains("failed"), "invites a retry: {t}");
        assert!(!t.to_lowercase().contains("retry"), "invites a retry: {t}");

        // A hostile-length reason must not push the refusal off the screen.
        let mut g = Frame::new();
        identity_fault(&mut g, "x".repeat(4096).as_str());
        let u = screen_text(&g);
        assert!(u.contains("IDENTITY FAULT"), "long reason ate the title");
        assert!(u.contains("Will not start"), "long reason ate the refusal");
    }

    #[test]
    fn standby_shows_the_name_and_the_held_share() {
        let mut f = Frame::new();
        standby(&mut f, "coldsnap-01", "family", Some(3));
        let t = screen_text(&f);
        assert!(t.contains("coldsnap-01") && t.contains("family") && t.contains("share #3"));
        standby(&mut f, "x", "y", None);
        assert!(screen_text(&f).contains("no share held"));
    }

    #[test]
    fn test_message_longer_than_the_screen_is_refused_not_truncated() {
        let mut f = Frame::new();
        assert!(sign_test_message(&mut f, "hello frostsnap").is_ok());
        assert!(screen_text(&f).contains("hello frostsnap"));
        let fits = "a".repeat(MESSAGE_ROWS * COLS);
        assert!(sign_test_message(&mut f, &fits).is_ok());
        let over = "a".repeat(MESSAGE_ROWS * COLS + 1);
        assert_eq!(
            sign_test_message(&mut f, &over),
            Err(Unrenderable::TooLong),
            "signing more than is shown is a blind signer"
        );
        assert_eq!(
            sign_test_message(&mut f, &"x".repeat(4096)),
            Err(Unrenderable::TooLong)
        );
        assert_eq!(
            sign_test_message(&mut f, "drain\u{202e}me"),
            Err(Unrenderable::NotAscii)
        );
    }

    const WORDS: [&str; BACKUP_WORDS] = [
        "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd",
        "abuse", "access", "accident", "account", "accuse", "achieve", "acid", "acoustic",
        "acquire", "across", "act", "action", "actor", "actress", "actual", "adapt",
    ];

    #[test]
    fn backup_pages_cover_all_25_words_with_the_two_digit_colon_shape() {
        let p = BackupPages::new(9, &WORDS).unwrap();
        assert_eq!(p.len(), 1 + BACKUP_WORDS.div_ceil(WORDS_PER_PAGE));
        assert_eq!(p.page(0), Some(BackupPage::ShareIndex(9)));
        let mut seen: Vec<&str> = Vec::new();
        let mut f = Frame::new();
        for i in 1..p.len() {
            assert!(p.render(i, &mut f));
            let t = screen_text(&f);
            match p.page(i) {
                Some(BackupPage::Words { first, words }) => {
                    for (k, w) in words.iter().enumerate() {
                        // mark_sensitive (display.py:284-285) triggers on "NN:"
                        let label = format!("{:02}: {}", first + k, w);
                        assert!(t.contains(&label), "page {i} missing {label:?}: {t}");
                        seen.push(w);
                    }
                }
                other => panic!("page {i} was {other:?}"),
            }
        }
        assert_eq!(seen, WORDS.to_vec(), "not every word was shown, in order");
        assert_eq!(p.page(p.len()), None);
    }

    #[test]
    fn backup_display_refuses_a_malformed_word_list() {
        assert_eq!(
            BackupPages::new(1, &WORDS[..24]),
            Err(Unrenderable::BadWordList)
        );
        let mut bad = WORDS;
        bad[7] = "\u{202e}drain";
        assert_eq!(BackupPages::new(1, &bad), Err(Unrenderable::BadWordList));
        bad[7] = "";
        assert_eq!(BackupPages::new(1, &bad), Err(Unrenderable::BadWordList));
    }

    #[test]
    fn backup_entry_gates_word_entry_behind_the_share_index() {
        let words = ["abandon", "ability"];
        let mut e = EntryPages {
            share_index: None,
            words: &words[..0],
            partial: "12",
        };
        assert_eq!(e.cursor(), 0, "no word entry until the share index is in");
        assert_eq!(e.len(), 1 + BACKUP_WORDS);
        assert_eq!(e.page(0), Some(EntryPage::ShareIndex { partial: "12" }));
        e.share_index = Some(12);
        e.words = &words;
        e.partial = "abo";
        assert_eq!(e.cursor(), 3);
        assert_eq!(
            e.page(3),
            Some(EntryPage::Word {
                number: 3,
                partial: "abo",
                previous: Some("ability")
            })
        );
        assert_eq!(e.page(BACKUP_WORDS + 1), None);
        let mut f = Frame::new();
        assert!(e.render(3, &mut f));
        let t = screen_text(&f);
        assert!(t.contains("word 3 of 25") && t.contains("03: abo_"), "{t}");
    }

    #[test]
    fn quiz_shows_three_numbered_options_and_marks_the_selection() {
        let mut f = Frame::new();
        backup_quiz(&mut f, "word 7 was:", ["absorb", "absurd", "abstract"], Some(1));
        let t = screen_text(&f);
        for want in ["word 7 was:", "1) absorb", "2) absurd", "3) abstract"] {
            assert!(t.contains(want), "missing {want:?}: {t}");
        }
        assert_eq!(f.cell(0, 4).map(|(_, inv)| inv), Some(true), "row 4 inverted");
        assert_eq!(f.cell(0, 2).map(|(_, inv)| inv), Some(false));
    }

    #[test]
    fn address_verify_shows_the_whole_address_and_refuses_what_it_cannot() {
        let mut f = Frame::new();
        address_verify(&mut f, ADDR, "m/0/17", 3).unwrap();
        let t = screen_text(&f);
        let shown: String = t.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(shown.contains(ADDR), "address not shown in full: {t}");
        assert!(t.contains("m/0/17"));
        assert_eq!(
            address_verify(&mut f, &"b".repeat(81), "m", 0),
            Err(Unrenderable::TooLong)
        );
        assert_eq!(
            address_verify(&mut f, "bc1\u{202e}", "m", 0),
            Err(Unrenderable::NotAscii)
        );
        // a 76-char v16 witness program still fits on one page
        assert!(address_verify(&mut f, &"q".repeat(76), "m/0/4294967295", 0).is_ok());
    }

    /// The artefact: every page of every screen, as ASCII art. Not a snapshot —
    /// it is how a human judges the layouts with nothing flashed.
    ///
    /// `cargo test --target aarch64-apple-darwin -p coldsnap_hal ui::tests::render -- --nocapture`
    #[test]
    fn render_every_screen_for_review() {
        use std::println;
        let mut f = Frame::new();
        let show = |name: &str, f: &Frame| {
            println!("=== {name} ===\n{}\n", screen_text(f));
            println!("{}", art(f));
        };

        standby(&mut f, "coldsnap-01", "family fund", Some(2));
        show("1 standby", &f);

        keygen_check(&mut f, 2, 3, [0xab, 0xcd, 0xef, 0x01], "family fund");
        show("2 keygen check", &f);

        let v = [(ADDR, 1_234_567u64), ("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", 250_000u64)];
        let r = recips(&v);
        let p = SignPages::new(&r, 150_000).unwrap();
        for i in 0..p.len() {
            assert!(p.render(i, &mut f));
            show(&format!("3 sign approval page {}/{}", i + 1, p.len()), &f);
        }

        sign_test_message(&mut f, "frostsnap test 1").unwrap();
        show("4 test message", &f);

        let b = BackupPages::new(2, &WORDS).unwrap();
        for i in 0..b.len() {
            assert!(b.render(i, &mut f));
            show(&format!("5 backup display page {}/{}", i + 1, b.len()), &f);
        }

        let words = ["abandon", "ability"];
        let e = EntryPages {
            share_index: Some(2),
            words: &words,
            partial: "abo",
        };
        assert!(e.render(0, &mut f));
        show("6 backup entry (share index)", &f);
        assert!(e.render(e.cursor(), &mut f));
        show("6 backup entry (word 3)", &f);

        backup_quiz(&mut f, "word 7 was:", ["absorb", "absurd", "abstract"], Some(0));
        show("7 backup quiz", &f);

        address_verify(&mut f, ADDR, "m/0/17", 3).unwrap();
        show("8 address verify", &f);
    }
}

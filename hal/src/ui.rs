//! `ui` — the 1,024-byte `MONO_VLSB` framebuffer, the eight required screens
//! (PLAN.md §4.2) and the PIN prompt (PLAN.md §8 phase 6), composed from **plain
//! data** and touching **no hardware**.
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
//! - **A row with a seed word on it is noised.** §4.2's note on
//!   `shared/display.py:284-285` is [`Frame::mark_sensitive`], a fresh
//!   random-length run per scanline; [`BackupPages::render`] and
//!   [`EntryPages::render`] take the RNG for it as a **required** argument, so
//!   there is no un-noised way to put a share on the glass. Its one unclosed
//!   edge — averaging over redraws — is documented on `mark_sensitive` itself
//!   rather than left for a reader to discover.
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

/// Shortest noise run `Frame::mark_sensitive` draws, in pixels: upstream's
/// `max(2, ...)` floor (`shared/display.py:203`). Never zero, so a secret row is
/// never distinguishable from a noised one by having no ink at all.
const SENSITIVE_MIN: usize = 2;
/// Longest noise run, in pixels. Upstream draws `max(2, ckcc.rng() % 32)`, whose
/// inclusive maximum is 31; `mark_sensitive` derives its modulus from this.
const SENSITIVE_MAX: usize = 31;
/// Cells the `NN: ` label on a noised row occupies: two digits from
/// [`Buf::push_u8_pad2`] plus `": "`. Not the string that gets drawn — the rows
/// are built from those two pushes — so
/// `the_sensitive_row_budget_matches_the_label_actually_drawn` ties this number to
/// them.
const SENSITIVE_LABEL_CELLS: usize = "NN: ".len();
/// Cells a noised row may spend on TEXT, and the width every such row is built
/// at: the `NN: ` label plus one [`MAX_WORD_LEN`] word.
const SENSITIVE_TEXT_CELLS: usize = SENSITIVE_LABEL_CELLS + MAX_WORD_LEN;

/// The noise must not reach the word it is standing next to.
///
/// This is host-compiled on purpose. The property is geometric, so it would
/// otherwise be the kind of security invariant that lives only in a
/// `cfg(target_arch = "arm")` block and is checked by no gate (PLAN.md §9 item
/// 22). `mark_sensitive` anchors each run at the last column, so the leftmost
/// pixel it can touch is `WIDTH - SENSITIVE_MAX`; the text ends at
/// `SENSITIVE_TEXT_CELLS * CELL`. 12 * 8 + 31 = 127 < 128 — one column of slack,
/// which is why widening the label, [`MAX_WORD_LEN`] or the run length is a BUILD
/// FAILURE and not a legibility bug reported from a bench.
const _: () = assert!(
    SENSITIVE_TEXT_CELLS * CELL + SENSITIVE_MAX < WIDTH,
    "the sensitive-row noise would overlap the word it is drawn beside"
);

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

    /// Fill the right margin of text row `row` with a **fresh random-length run
    /// per scanline** — `shared/display.py:201-205`, and the side-channel defence
    /// PLAN.md §4.2 requires the mono backup screen preserve.
    ///
    /// Upstream, for every scanline `y` of a secret row:
    ///
    /// ```text
    /// wx = WIDTH - 4                      # avoid the scroll bar
    /// ln = max(2, ckcc.rng() % 32)
    /// dis.line(wx - ln, y, wx, y, 1)
    /// ```
    ///
    /// One length per *pixel* row, 13 per 13 px text row — not one per text row.
    /// This is the same thing at this module's geometry: [`CELL`] scanlines per
    /// row, each a run of 2..=31 px ending at the last column. The 4 px upstream
    /// reserves is for a scroll bar these screens do not draw, so the run ends at
    /// `WIDTH - 1`.
    ///
    /// `shared/display.py:284-285` (`is_sensitive and len(ln) > 3 and ln[2] ==
    /// ':'`) is only upstream's TRIGGER — it sniffs the text to pick which rows to
    /// noise. It is not the defence, and preserving the `NN:` shape is not
    /// implementing it. Here the choice of rows is structural instead: the callers
    /// noise the rows they drew words on, so a row cannot lose its noise by having
    /// its label reformatted.
    ///
    /// # What this defends, measured
    ///
    /// The channel is remote observation of the panel — power draw and EM emission
    /// both scale with lit pixels per row, so the *ink* on a row is observable even
    /// when the glyphs are not. A BIP39 word is 3..=8 letters, and over the in-tree
    /// list (`frost_backup::bip39_words::BIP39_WORDS`, counted from the array
    /// itself) the length histogram is `3:103 4:442 5:555 6:508 7:352 8:88` —
    /// 2,048 — giving H(word) = 11.0000 bits and H(word | length) = 8.6645 bits:
    /// **word length alone is 2.3355 bits**. `frost_backup`'s `to_word_indices`
    /// packs the 256-bit scalar plus an 8-bit checksum into words 1..24
    /// (24 × 11 = 264 bits), so reading every length leaks 24 × 2.3355 =
    /// **56.1 bits — 264 down to 207.9**. 208 bits is infeasible on its own, but it
    /// composes with any second partial leak, and an unlucky all-8-letter
    /// transcript (the rarest bucket, 88 words) leaks 109 bits and leaves 155.
    ///
    /// # What it does NOT defend — unresolved, not papered over
    ///
    /// The run lengths are redrawn from `rng` on every render, and **a page turn is
    /// a redraw**. An observer who watches a user page back and forth, or read the
    /// backup twice, averages N independent noise draws away: the true per-row ink
    /// re-emerges at roughly `sqrt(N)` fewer observations than a single-shot
    /// estimate would need. Upstream has exactly the same property. This raises the
    /// cost of the measurement; it does not close the channel, and nothing in this
    /// module makes a claim stronger than that.
    ///
    /// Also out of scope, and deliberately: [`pin_words`] draws its two
    /// anti-phishing words with [`Frame::text_2x`], where 8 characters is exactly
    /// the panel — there is no margin left to noise. That screen is unprotected.
    ///
    /// A row past [`ROWS`] draws nothing, via [`Frame::set_pixel`]: never a panic
    /// and never a wrap into another row, which is why `row * CELL` is
    /// `saturating_mul` (release builds run `overflow-checks = false`).
    pub fn mark_sensitive(&mut self, row: usize, rng: &mut impl rand_core::RngCore) {
        let top = row.saturating_mul(CELL);
        for y in top..top.saturating_add(CELL) {
            // `max(2, rng() % 32)`, verbatim, as 2..=SENSITIVE_MAX.
            let run = ((rng.next_u32() % (SENSITIVE_MAX as u32 + 1)) as usize).max(SENSITIVE_MIN);
            for x in WIDTH.saturating_sub(run)..WIDTH {
                self.set_pixel(x, y, true);
            }
        }
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

    /// Read back the character of the **2× glyph** whose top-left cell is
    /// (`col`, `row`) — the exact inverse of [`Frame::text_2x`]. One glyph per
    /// call, so a caller reading a run of them steps `col` by 2.
    ///
    /// Reconstructs the source byte from the even destination columns of both
    /// byte-rows and then requires a byte-for-byte font-table match, so it is
    /// `None` unless those pixels are exactly some glyph doubled — a
    /// vertical-only double, an off-by-one row and a wrong glyph all fail,
    /// where a "some pixels are set" check would pass. It samples the even
    /// columns only; the horizontal duplication in the odd columns is asserted
    /// separately, against the 1× glyph, by
    /// `text_2x_doubles_in_both_axes_and_round_trips_through_the_font`.
    ///
    /// Public because the 2× keygen code is the whole anti-MITM defence and the
    /// only thing that reads it is a human eye: a gate outside this crate has to
    /// be able to assert that the four bytes on the *glass* are the
    /// coordinator's, and re-deriving the doubling to do that would be a second
    /// implementation of the same mapping to keep in sync. Like [`Frame::cell`],
    /// firmware never calls it, so `--gc-sections` drops it from the ARM image;
    /// it costs flash only once something on the device path reads a screen back.
    pub fn cell_2x(&self, col: usize, row: usize) -> Option<u8> {
        // A 2x glyph is two cells wide and two byte-rows tall. Anything smaller
        // than that window cannot hold one, so there is nothing to read.
        if col.saturating_add(2) > COLS || row.saturating_add(2) > ROWS {
            return None;
        }
        let mut src = [0u8; CELL];
        for (j, s) in src.iter_mut().enumerate() {
            let dx = col * CELL + j * 2;
            let lo = *self.0.get(row * WIDTH + dx)?;
            let hi = *self.0.get((row + 1) * WIDTH + dx)?;
            let mut b = 0u8;
            for k in 0..4 {
                b |= ((lo >> (2 * k)) & 1) << k;
                b |= ((hi >> (2 * k)) & 1) << (k + 4);
            }
            *s = b;
        }
        // FONT_FIRST + index is the codepoint, as in `cell`.
        let g = (0..96).find(|g| FONT.get(g * CELL..g * CELL + CELL) == Some(&src[..]))?;
        Some(FONT_FIRST as u8 + g as u8)
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

    /// Append `v` in decimal, zero-padded to two digits — the `NN:` row label the
    /// backup screens number their words with, so that `07` and `17` are the same
    /// width and a column of them is scannable by eye.
    ///
    /// It is also the shape `shared/display.py:284-285` sniffs (`ln[2] == ':'`) to
    /// decide which rows to noise, but that is upstream's TRIGGER and **not** the
    /// side-channel defence PLAN.md §4.2 asks for: the defence is the random-length
    /// scanline noise, [`Frame::mark_sensitive`], and this module's callers select
    /// the rows structurally rather than by re-sniffing the text. Padding here buys
    /// alignment, and nothing else.
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

/// The five keys a confirm digit may be drawn from — `0`, `5`, `7`, `8` and `9`
/// are deliberately absent.
///
/// Copied verbatim from Coldcard's own highest-stakes approval
/// (`shared/hsm_ux.py:58`, `confirm_char = '12346'[ngu.random.uniform(5)]`)
/// rather than chosen here: it is their considered set for THIS keypad, and a
/// substitution would be a worse-informed guess dressed as a decision.
pub const CONFIRM_CHARSET: [u8; 5] = *b"12346";

/// The key that advances one page of a multi-page approval, and the key that goes
/// back one.
///
/// Not invented here: this is Coldcard's own story-screen map, `9` page-down and
/// `7` page-up (`shared/ux.py:237-247`), and it is *why* [`CONFIRM_CHARSET`]
/// omits `0`, `5`, `7`, `8` and `9` — those five are the scroll keys, so the key
/// that turns a page can never be the key that signs. `hsm_ux.py:65` runs the
/// randomised-digit approval with `strict_escape=True` for the same reason: the
/// only exits are the digit and `x`, while the scroll keys keep scrolling.
///
/// They live here rather than in the firmware because [`SignPages::render`] draws
/// their legend: a caller that compares against a different byte than the glass
/// advertises is the desync this const exists to prevent. Both are on the Mk4 pad
/// (`shared/mempad.py:19` `DECODER = 'y0x987654321'`) — the pad half of that
/// claim is asserted in `hal::keypad`, which owns the decode table; this module
/// is pure and cannot see it.
pub const NEXT_KEY: u8 = b'9';
/// Back one page. See [`NEXT_KEY`].
pub const BACK_KEY: u8 = b'7';

/// The advance legend, deliberately with **no `=`**: `firmware/examples/stub.rs`
/// reads a screen's yes key off the last row and treats `<k>=<what>` as a
/// plain-press consent legend, so `9=next` would make a page that cannot consent
/// advertise a yes key. `(9)next` leaves that scraper at `None`, which is the
/// truth about every page but the last.
const NEXT_LEGEND: &str = " (9)next";

/// The paging legend for the backup screens, in the same no-`=` form and for the
/// same reason as [`NEXT_LEGEND`].
///
/// # These printed `5=next 8=back` until 2026-09-08, and 5 and 8 both mean NO
///
/// [`NEXT_KEY`] is `9` and [`BACK_KEY`] is `7`; `firmware/src/main.rs`'s `answer`
/// routes `5` and `8` to `Answer::No`. So **a human following the printed
/// instruction part-way through transcribing 25 words abandoned their own backup** —
/// on the one screen whose entire purpose is to be copied down carefully.
///
/// It survived because the `const` assert below only checked [`NEXT_LEGEND`], which
/// the sign-approval pages use; these two were bare string literals that nothing
/// compared against [`NEXT_KEY`]. The assert now covers both, so the class is closed
/// rather than the instance.
const BACKUP_NEXT_LEGEND: &str = "(9)next";
/// Paging back on the backup screens. See [`BACKUP_NEXT_LEGEND`].
const BACKUP_BACK_LEGEND: &str = "(9)next (7)back";

const _: () = {
    // The legend must print the key the firmware compares against.
    assert!(
        NEXT_LEGEND.as_bytes()[2] == NEXT_KEY,
        "the advance legend must name NEXT_KEY"
    );
    // The backup legends too. Omitting them is how `5=next 8=back` shipped on the
    // screen a user transcribes, naming two keys that both mean No.
    assert!(
        BACKUP_NEXT_LEGEND.as_bytes()[1] == NEXT_KEY,
        "the backup advance legend must name NEXT_KEY"
    );
    assert!(
        BACKUP_BACK_LEGEND.as_bytes()[1] == NEXT_KEY,
        "the backup paging legend must name NEXT_KEY"
    );
    assert!(
        BACKUP_BACK_LEGEND.as_bytes()[9] == BACK_KEY,
        "the backup paging legend must name BACK_KEY"
    );
    // And neither paging key may be drawable as a confirm digit: turning a page
    // would then be indistinguishable from signing on one prompt in five. This is
    // a build failure rather than a test because both sides are consts — the same
    // rung `hal::keypad`'s CANCEL/decode-table assert already stands on.
    let mut i = 0;
    while i < CONFIRM_CHARSET.len() {
        assert!(
            CONFIRM_CHARSET[i] != NEXT_KEY,
            "the advance key must not be able to confirm"
        );
        assert!(
            CONFIRM_CHARSET[i] != BACK_KEY,
            "the back key must not be able to confirm"
        );
        i += 1;
    }
};

/// One randomised confirm digit: what a screen that authorises a signature
/// prints, and the **only** key that may authorise it.
///
/// # Why the screens take this as data rather than taking an RNG
///
/// The digit is drawn by the caller and passed in, exactly as every other screen
/// here takes `u64` sats and `&str` addresses. That keeps the screens
/// deterministic under test — a rendered legend is a pure function of its
/// arguments — and keeps this module free of RNG state, which is the property
/// the module docs above rest on. [`ConfirmDigit::draw`] is the one function
/// here that touches an RNG and it touches the *caller's*, through a
/// `rand_core::RngCore` bound that is already a dependency of this crate
/// (`crate::rng`): no hardware, no singleton, no register. Giving three screens
/// an RNG parameter instead would make all three non-deterministic to test and
/// buy nothing.
///
/// [`BackupPages::render`] and [`EntryPages::render`] *do* take an RNG, and that
/// is not a contradiction: their randomness is not a value to be shown and then
/// compared against a keypress, it is the [`Frame::mark_sensitive`] noise, which
/// is only a defence if it is fresh on every scanline of every render. There is
/// no "data" form of it to pass in. Nothing on those two screens is authorised by
/// a key, so nothing there needs to stay comparable.
///
/// # Why a digit at all, and why it replaced a hold
///
/// The two signing screens used to print `hold 1`, a gesture **this hardware
/// cannot produce**: the Mk4 numpad emits keydown and "all up" only
/// (`shared/numpad.py`), and nothing in Coldcard's UX layer interprets a hold.
/// A randomised digit is their own answer to the same problem, and it has a
/// second property a fixed key does not: a script cannot hardcode it, so it can
/// only be answered by reading the screen.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ConfirmDigit(u8);

impl ConfirmDigit {
    /// Draw one from `rng`.
    ///
    /// On the device `rng` is [`crate::rng::Entropy`] — 2-source and fail-closed
    /// — and **never** libngu, which PLAN.md §1 forbids outright. What is copied
    /// from `hsm_ux.py` is the pattern, not the RNG.
    ///
    /// `% 5` rather than rejection sampling: `2^32 % 5 == 1`, so one digit is
    /// favoured by 1 part in 858,993,459, which is undetectable in a one-in-five
    /// press gate — and it keeps the draw a fixed-cost expression with no loop,
    /// which is what a firmware path wants.
    pub fn draw<R: rand_core::RngCore>(rng: &mut R) -> Self {
        ConfirmDigit(CONFIRM_CHARSET[(rng.next_u32() % CONFIRM_CHARSET.len() as u32) as usize])
    }

    /// The digit as text for a legend. Always exactly one ASCII character.
    pub fn as_str(&self) -> &str {
        // Every byte of `CONFIRM_CHARSET` is ASCII and the field is private, so
        // the fallback is unreachable by construction. It exists because a
        // `unwrap` on a screen path would be a reachable panic, and on this
        // device a reachable panic is permanent (README.md: installation at
        // RDP=2 is one-way).
        core::str::from_utf8(core::slice::from_ref(&self.0)).unwrap_or("?")
    }

    /// **FAIL CLOSED**: `true` for the exact digit and for nothing else.
    ///
    /// This is `hsm_ux.py:58`'s `self.refused = (ch != confirm_char)` read the
    /// other way round, and the inversion is the whole mechanism: a wrong digit,
    /// `x`, an unrelated key and a key that is not even on the pad are all
    /// **refusals**, not ignored presses and not retries. Treating only `x` as
    /// refusal is the way this gets subtly wrong, and it fails *open* — hence
    /// [`anything_but_the_confirm_digit_is_a_refusal`](self).
    pub fn accepts(&self, key: u8) -> bool {
        key == self.0
    }
}

/// `"Press (4)"` — the one place the confirm instruction is spelled, so the two
/// signing screens cannot word it differently or print different digits.
fn press_legend(confirm: ConfirmDigit) -> Buf<16> {
    let mut b = Buf::<16>::new();
    b.push_str("Press (")
        .push_str(confirm.as_str())
        .push_str(")");
    b
}

/// The row every page of a paged approval puts its footer on — the last one.
///
/// Free on all six [`SignPage`] kinds, and the row a harness reads a screen's yes
/// key off (`firmware/examples/stub.rs` `advertised_key`), so the confirm legend
/// has to be here or the only executed end-to-end harness in the tree can never
/// approve a signature.
const FOOTER_ROW: usize = ROWS - 1;

/// `"pg 4/67"` — which page of how many.
///
/// Load-bearing, not decoration: 32 recipients is 67 pages, and a screen that
/// says nothing about position invites consenting on page 1 of 67 in the belief
/// it is the whole transaction. Distinct from [`counter`]'s `#3 of 12`, which
/// counts *recipients*; the two appear on the same screen and must not be
/// confusable.
fn page_of(index: usize, len: usize) -> Buf<16> {
    let mut b = Buf::<16>::new();
    b.push_str("pg ")
        .push_u64(index.saturating_add(1) as u64)
        .push_str("/")
        .push_u64(len as u64);
    b
}

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
    /// The final confirm page. Always last, so reaching it requires stepping
    /// through every prior page.
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
    /// The digit [`SignPage::Confirm`] advertises, or `None` for "this page set
    /// advertises no way to say yes". See [`SignPages::confirming`].
    confirm: Option<ConfirmDigit>,
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
            confirm: None,
        })
    }

    /// Attach the randomised digit [`SignPage::Confirm`] will print.
    ///
    /// A builder rather than a fourth argument to [`SignPages::new`] because the
    /// page *set* is what a caller validates and the digit is what a caller
    /// draws, and the two have different lifetimes: `new` refuses transactions,
    /// this only decorates one it accepted.
    ///
    /// Without it the confirm page advertises no confirm key at all, and that is
    /// the deliberate direction: a page set built by a fixture with no RNG
    /// (`hal/examples/ui_render`, `firmware/examples/simulator`) must not print a
    /// key that nothing is checking. The device path
    /// (`coldsnap_firmware::prompt_screen`) always calls this.
    pub fn confirming(self, confirm: ConfirmDigit) -> Self {
        SignPages {
            confirm: Some(confirm),
            ..self
        }
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

    /// Whether `index` is the last page — **the only page a signature may be
    /// authorised on**, and the only page [`SignPages::render`] prints a confirm
    /// digit on.
    ///
    /// Public because the caller that decides whether to accept a keypress and
    /// the render that drew the glass must agree on this bit, and the way they
    /// stay agreed is by asking the same function rather than each recomputing it.
    ///
    /// `index == len() - 1`, never `index + 1 == len()`: `overflow-checks = false`
    /// in release, so `index + 1` wraps to 0 for `usize::MAX` and would call page
    /// 0 the last page of a 1-page set. [`SignPages::len`] is provably at least 3,
    /// so the subtraction cannot underflow.
    pub fn is_last(&self, index: usize) -> bool {
        index == self.len() - 1
    }

    /// Draw page `index`'s footer: where you are, and the one key that leaves.
    ///
    /// **The confirm digit is drawn here and nowhere else in a page set**, and
    /// only when `index` is the last page. Before this, the digit rode on
    /// [`SignPage::Confirm`] and was therefore only correct by the coincidence
    /// that `Confirm` sorts last; now the page that prints it is the page the
    /// consent check asks about ([`SignPages::is_last`]), so a caller cannot draw
    /// a signable-looking screen for page 1 of 67.
    ///
    /// A page that is not last advertises the *advance* key, not a yes key. A last
    /// page with no digit attached advertises nothing: fail-closed, per
    /// [`SignPages::confirming`].
    fn footer(&self, frame: &mut Frame, index: usize) {
        match (self.is_last(index), self.confirm) {
            (false, _) => {
                let mut b = page_of(index, self.len());
                b.push_str(NEXT_LEGEND);
                frame.text(0, FOOTER_ROW, b.as_str());
            }
            // Byte-for-byte `sign_test_message_confirm`'s legend: the same words
            // in the same place for the same gesture, and the form
            // `advertised_key` can read.
            (true, Some(confirm)) => {
                let mut b = press_legend(confirm);
                b.push_str(" x=no");
                frame.text(0, FOOTER_ROW, b.as_str());
            }
            (true, None) => {}
        }
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
    ///
    /// Every page it draws ends with a footer on the last row: `pg 4/67 (9)next`
    /// while pages remain, the `Press (n) x=no` legend on the last page only.
    /// `true` therefore means "drawn in full" and **not** "consentable" — that
    /// second question is [`SignPages::is_last`], and the caller has to ask it.
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
                // "You have read all of it" belongs on the page that authorises
                // more than anywhere else, and the footer row is spent on the
                // digit here, so it goes in the body. `index` is deliberately the
                // outer one — the `Amount`/`Address` arms shadow that name with a
                // *recipient* index, which is why the footer is drawn after the
                // match and not inside it.
                frame.text(0, 3, page_of(index, self.len()).as_str());
                frame.text(0, 6, "x to cancel");
            }
        }
        // The digit, or the advance key, or nothing — see `footer`.
        self.footer(frame, index);
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
/// This form advertises **no confirm key**, so nothing drawn by it can be
/// consented to. It is for callers with no RNG and nothing to authorise — the
/// screen catalogues (`hal/examples/ui_render`, `firmware/examples/simulator`).
/// The device path is [`sign_test_message_confirm`], reached through
/// `coldsnap_firmware::prompt_screen`.
pub fn sign_test_message(frame: &mut Frame, message: &str) -> Result<(), Unrenderable> {
    test_message(frame, message, None)
}

/// Screen 4 with the randomised digit that will authorise the signature.
///
/// The digit printed here is the same value the caller must hand to
/// [`ConfirmDigit::accepts`]: one drawn value, rendered and checked, so the
/// legend and the acceptance cannot drift.
pub fn sign_test_message_confirm(
    frame: &mut Frame,
    message: &str,
    confirm: ConfirmDigit,
) -> Result<(), Unrenderable> {
    test_message(frame, message, Some(confirm))
}

fn test_message(
    frame: &mut Frame,
    message: &str,
    confirm: Option<ConfirmDigit>,
) -> Result<(), Unrenderable> {
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
    match confirm {
        Some(confirm) => {
            let mut b = press_legend(confirm);
            b.push_str(" x=no");
            frame.text(0, 7, b.as_str());
        }
        // No digit, no yes key. `x` still cancels; that direction is always safe.
        None => {
            frame.text(0, 7, "x=no");
        }
    }
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
            check_word(w)?;
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
    /// # Why `rng` is a parameter and not a second `render_noised` method
    ///
    /// Every word row drawn here is covered by [`Frame::mark_sensitive`], which
    /// needs fresh randomness per scanline, so the RNG is threaded in. It is
    /// **mandatory** rather than an opt-in variant because an opt-in fails OPEN:
    /// the day some caller reaches for the plain method, the defence silently
    /// vanishes and no test anywhere notices a missing decoration. A caller that
    /// cannot produce an RNG cannot draw a share — which is the correct answer, not
    /// an inconvenience. On the device this is [`crate::rng::Entropy`], 2-source
    /// and fail-closed; the `rand_core::RngCore` bound keeps this module free of
    /// hardware and of any global, exactly as [`ConfirmDigit::draw`] does.
    ///
    /// Consequence a test must expect: the frame is **not** a pure function of its
    /// arguments any more. Two renders of the same page differ in the noise
    /// columns, and only in those — see
    /// `backup_word_rows_are_noised_and_the_words_stay_clear`.
    ///
    /// The share-index page carries no noise: an index in 1..=n is not the secret,
    /// it is what makes the secret restorable, and upstream does not noise it
    /// either (its trigger only fires on `NN:` word rows).
    ///
    /// Word rows are built at `SENSITIVE_TEXT_CELLS` (12), the width the geometry
    /// assert reserves, so the noise and the words cannot overlap for any input
    /// [`BackupPages::new`] accepts.
    pub fn render(
        &self,
        index: usize,
        frame: &mut Frame,
        rng: &mut impl rand_core::RngCore,
    ) -> bool {
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
                frame.text(0, 7, BACKUP_NEXT_LEGEND);
            }
            BackupPage::Words { first, words } => {
                let mut head = Buf::<16>::new();
                head.push_str("words ")
                    .push_u64(first as u64)
                    .push_str("-")
                    .push_u64((first + words.len() - 1) as u64);
                frame.text(0, 0, head.as_str());
                for (i, w) in words.iter().enumerate() {
                    let mut b = Buf::<SENSITIVE_TEXT_CELLS>::new();
                    b.push_u8_pad2((first + i) as u8)
                        .push_str(": ")
                        .push_str(w);
                    // Draw, then noise the same row. Structural, not text-sniffed:
                    // this is a row we just put a word on, so it gets covered.
                    let row = 2 + i;
                    frame.text(0, row, b.as_str());
                    frame.mark_sensitive(row, rng);
                }
                frame.text(0, 7, BACKUP_BACK_LEGEND);
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
    ///
    /// `rng` is mandatory for the same reason it is on [`BackupPages::render`], and
    /// the threat is the same one: a share being typed back in is on the glass
    /// exactly as much as a share being read out, so both word rows here — the
    /// previous word and the one being typed — go through
    /// [`Frame::mark_sensitive`]. The share-index page is not noised.
    ///
    /// Both word rows are built at `SENSITIVE_TEXT_CELLS` (12) so they cannot reach
    /// the noise. That budget is `NN: ` plus [`MAX_WORD_LEN`], which means the
    /// trailing `_` cursor is what gives way on a full 8-letter field — never a
    /// letter. A field that has stopped accepting letters showing no cursor is
    /// honest; a letter silently dropped from the word a user is transcribing would
    /// not be.
    pub fn render(
        &self,
        index: usize,
        frame: &mut Frame,
        rng: &mut impl rand_core::RngCore,
    ) -> bool {
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
                    let mut b = Buf::<SENSITIVE_TEXT_CELLS>::new();
                    b.push_u8_pad2((number - 1) as u8).push_str(": ").push_str(p);
                    frame.text(0, 2, b.as_str());
                    frame.mark_sensitive(2, rng);
                }
                let mut b = Buf::<SENSITIVE_TEXT_CELLS>::new();
                b.push_u8_pad2(number as u8)
                    .push_str(": ")
                    .push_str(partial)
                    .push_str("_");
                frame.text(0, 4, b.as_str());
                frame.mark_sensitive(4, rng);
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

// ---------------------------------------------------------------------------
// Screen 9 — PIN (PLAN.md §8 phase 6)
// ---------------------------------------------------------------------------

/// Longest PIN half this panel draws, and Coldcard's own maximum
/// (`shared/login.py:14`).
///
/// `[` + six `*` + `]` is 8 characters, which at [`Frame::text_2x`] is *exactly*
/// the 128 px panel — so the masked field can never truncate. A longer one is
/// refused ([`Unrenderable::TooLong`]) rather than silently shortened, because a
/// star count that stops growing is a feedback lie about what was typed.
pub const MAX_PIN_PART_LEN: usize = 6;

/// The longest word [`pin_words`] or [`BackupPages`] will draw.
///
/// 8 is both the longest BIP39 English word and exactly [`COLS`] at 2× — the
/// const block below ties those two facts together so a wider word bound cannot
/// be raised without noticing that it no longer fits the glass.
pub const MAX_WORD_LEN: usize = 8;

const _: () = {
    assert!(
        MAX_WORD_LEN * 2 == COLS,
        "an 8-char word at 2x is exactly the panel"
    );
    // `[` + digits + `]`, at 2x, must fit too — this is what makes the masked
    // field untruncatable rather than merely usually short enough.
    assert!(
        (MAX_PIN_PART_LEN + 2) * 2 <= COLS,
        "the masked PIN field must fit the panel at 2x"
    );
};

/// Cells the masked field occupies: the digits plus its two brackets.
const FIELD_CELLS: usize = MAX_PIN_PART_LEN + 2;

/// Shown the first time a PIN is set, when the words must be *recorded*.
pub const PIN_WORDS_LEARN: &str = "Write these down";
/// Shown at every login, when the words must be *recognised*.
pub const PIN_WORDS_CHECK: &str = "Recognize these?";

/// First line of the consequence label: what the attempts figure counts.
pub const PIN_TRIES_1: &str = "wrong tries";
/// Second line of the consequence label: what happens when it reaches zero.
pub const PIN_TRIES_2: &str = "before erase";

/// The one PIN footer. **No `=`**: `firmware/examples/stub.rs`'s `advertised_key`
/// reads `<k>=<what>` on the last row as a plain-press consent legend, and a PIN
/// screen authorises no transaction. Same dodge as [`NEXT_LEGEND`].
const PIN_FOOTER: &str = "(y)ok (x)del";

/// Which PIN is being asked for.
///
/// The titles live here rather than being passed as text because the
/// set-versus-login distinction is load-bearing: a user who is *setting* a PIN
/// must be told so, and `shared/login.py:54-55` makes the same split for the same
/// reason. A `&str` title would let a caller word it wrongly; four variants
/// cannot.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PinPrompt {
    /// The first half, the one the anti-phishing words are derived from.
    Prefix,
    /// The second half. Spending an attempt happens after this one.
    Suffix,
    /// First-time set, first pass.
    Set,
    /// First-time set, confirmation pass.
    Repeat,
}

impl PinPrompt {
    /// The title row for this prompt. Always ≤ [`COLS`] characters.
    pub fn title(&self) -> &'static str {
        match self {
            PinPrompt::Prefix => "Enter PIN prefix",
            PinPrompt::Suffix => "Rest of your PIN",
            PinPrompt::Set => "Set a new PIN",
            PinPrompt::Repeat => "Repeat new PIN",
        }
    }
}

/// Which screen [`pin_entry`] actually drew.
///
/// Returned rather than documented because the accepted key differs on all three
/// and the key handler lives above this seam: on [`PinScreen::Entry`] a digit
/// extends the PIN, on [`PinScreen::LastTry`] only the drawn [`ConfirmDigit`] may
/// submit, and on [`PinScreen::Bricked`] nothing may submit anything. A caller
/// that matches this cannot forget the last-attempt case.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PinScreen {
    /// Ordinary masked entry, two or more attempts left.
    Entry,
    /// One attempt left. The next wrong PIN destroys the key.
    LastTry,
    /// No attempts left: SE1 has already erased the secret.
    Bricked,
}

/// The entry field: `[`, one character per digit typed, `]`.
///
/// `mask` false is the deliberate exception — see [`pin_entry`]'s last-attempt
/// branch, the only caller that passes it.
fn pin_field(typed: &str, mask: bool) -> Buf<FIELD_CELLS> {
    let mut b = Buf::<FIELD_CELLS>::new();
    b.push_str("[");
    if mask {
        for _ in typed.chars() {
            b.push_str("*");
        }
    } else {
        b.push_str(typed);
    }
    b.push_str("]");
    b
}

/// Draw `s` at 2× if it fits the panel at 2×, else at 1× on the same row.
///
/// For the attempts figure, which comes straight out of SE1's attempt struct and
/// is never recomputed here: `attempts_left` is 13 on healthy silicon and
/// `num_fails` has a sentinel of 99 (`pins.c:478`), but a struct that reports
/// nonsense must *look* like nonsense rather than being shortened into a
/// plausible small number. 2× truncates at 8 characters, so anything longer drops
/// to the ordinary [`Frame::text`] path every other screen already uses.
fn big_number(frame: &mut Frame, row: usize, s: &str) {
    if s.chars().count() * 2 <= COLS {
        frame.text_2x(0, row, s);
    } else {
        frame.text(0, row, s);
    }
}

/// Screen 9: PIN entry — masked field, and the attempts remaining at 2× beside
/// it.
///
/// # Why the attempts figure is not optional
///
/// SE1 destroys the key at the limit and there is no reset and no recovery
/// (`shared/login.py:181-189`). So this is not a status line: it is the only
/// warning a user gets before an irreversible act, and it is drawn from
/// `attempts_left` **as SE1 reported it**. Never subtract locally — release
/// builds run `overflow-checks = false`, so a local `13 - fails` wraps to 255 and
/// would print *255 tries left* on a unit one guess from death.
///
/// # Why the last attempt cannot be drawn as an ordinary screen
///
/// This function diverts on `attempts_left` itself rather than trusting the
/// caller to notice. One attempt left draws a distinct screen that names the
/// consequence, un-masks the typed PIN so a typo is catchable before the attempt
/// is spent (`shared/login.py:200-208` does exactly this, and near the brick
/// counter correctness beats secrecy), and gates the submit on `confirm` so
/// neither a stuck key nor a script can spend it. Zero attempts is not a prompt
/// at all — it draws [`pin_bricked`]. Both branches are structural: there is no
/// argument a caller can pass to get an ordinary entry screen at one attempt.
///
/// `confirm` is used only by the last-attempt branch and ignored otherwise; it is
/// taken unconditionally so that reaching that branch cannot require a caller to
/// have prepared for it.
///
/// Refuses (`Unrenderable::TooLong`) a `typed` longer than [`MAX_PIN_PART_LEN`].
pub fn pin_entry(
    frame: &mut Frame,
    prompt: PinPrompt,
    typed: &str,
    attempts_left: u64,
    confirm: ConfirmDigit,
) -> Result<PinScreen, Unrenderable> {
    if typed.chars().count() > MAX_PIN_PART_LEN {
        return Err(Unrenderable::TooLong);
    }
    if attempts_left == 0 {
        pin_bricked(frame);
        return Ok(PinScreen::Bricked);
    }
    if attempts_left == 1 {
        pin_last_try(frame, typed, confirm);
        return Ok(PinScreen::LastTry);
    }
    frame.clear();
    frame.text(0, 0, prompt.title());
    let field = pin_field(typed, true);
    frame.text_2x(centred(field.len()), 1, field.as_str());
    let mut left = Buf::<20>::new();
    left.push_u64(attempts_left);
    big_number(frame, 3, left.as_str());
    frame.text(0, 5, PIN_TRIES_1);
    frame.text(0, 6, PIN_TRIES_2);
    frame.text(0, FOOTER_ROW, PIN_FOOTER);
    Ok(PinScreen::Entry)
}

/// Column that centres `cells` 2× characters, saturating rather than wrapping.
fn centred(cells: usize) -> usize {
    COLS.saturating_sub(cells.saturating_mul(2)) / 2
}

/// The last-attempt screen. Private: reachable only through [`pin_entry`], which
/// is what makes it unskippable.
fn pin_last_try(frame: &mut Frame, typed: &str, confirm: ConfirmDigit) {
    frame.clear();
    frame.text_2x(0, 0, "LAST TRY");
    frame.text(0, 2, "Wrong = the key");
    frame.text(0, 3, "is erased. Check");
    frame.text(0, 4, "your PIN below:");
    let field = pin_field(typed, false);
    frame.text_2x(centred(field.len()), 5, field.as_str());
    frame.text(0, FOOTER_ROW, press_legend(confirm).as_str());
}

/// The screen after a rejected PIN: how many tries are left, at 2×, and what
/// running out costs.
///
/// Both figures come from SE1's attempt struct verbatim — `num_fails` too, whose
/// 99 is a sentinel rather than a count (`pins.c:478`), which is why neither is
/// formatted as two digits.
pub fn pin_wrong(frame: &mut Frame, attempts_left: u64, num_fails: u64) {
    frame.clear();
    frame.text(0, 0, "WRONG PIN");
    let mut left = Buf::<20>::new();
    left.push_u64(attempts_left);
    big_number(frame, 1, left.as_str());
    frame.text(0, 3, PIN_TRIES_1);
    frame.text(0, 4, PIN_TRIES_2);
    let mut fails = Buf::<24>::new();
    fails.push_str("fails: ").push_u64(num_fails);
    frame.text(0, 6, fails.as_str());
    frame.text(0, FOOTER_ROW, "(x)retry");
}

/// The terminal screen for a unit SE1 has already killed.
///
/// Not [`refusal`] and not [`identity_fault`]: both of those describe a request
/// this device declined, and this one describes a device that no longer holds a
/// key. It advertises no key, because there is nothing left to answer.
pub fn pin_bricked(frame: &mut Frame) {
    frame.clear();
    frame.text(0, 0, "PIN ATTEMPTS");
    frame.text(0, 1, "EXHAUSTED");
    frame.text(0, 3, "The secure chip");
    frame.text(0, 4, "erased the key.");
    frame.text(0, 5, "No reset and no");
    frame.text(0, 6, "recovery.");
    frame.text(0, FOOTER_ROW, "Will not start");
}

/// First-time set, the two entries differed. Says plainly that nothing was
/// stored, because a user who believes a PIN was set is a user locked out of a
/// unit that has no PIN.
pub fn pin_mismatch(frame: &mut Frame) {
    frame.clear();
    frame.text(0, 0, "PINS DIFFER");
    frame.text(0, 2, "The two entries");
    frame.text(0, 3, "did not match.");
    frame.text(0, 5, "No PIN was set.");
    frame.text(0, FOOTER_ROW, "(x)again");
}

/// The screen that stands in for a countdown this silicon does not have.
///
/// `calc_delay_required` returns a hard 0 on the 608 (`pins.c:518-522`) — the
/// rate limit *is* the KDF, ~1.4 s measured for the words alone (`pins.c:22`).
/// The callgate blocks the core while it runs, so this cannot animate; a static
/// screen that says so is the difference between a slow check and an apparent
/// hang. It also tells the user not to cut power mid-KDF.
pub fn pin_checking(frame: &mut Frame) {
    frame.clear();
    frame.text(0, 0, "Checking...");
    frame.text(0, 2, "This takes a");
    frame.text(0, 3, "few seconds.");
    frame.text(0, 5, "Do not remove");
    frame.text(0, 6, "power.");
}

/// The anti-phishing words: two words at 2×, derived above this seam.
///
/// The words are `&str`, never derived here — this module is pure (see the module
/// header), it carries no wordlist, and `BackupPages` already takes its words the
/// same way. `first_time` picks between recording them and recognising them; that
/// distinction is the whole check (`shared/login.py:54-55`), so it is a `bool`
/// rather than caller-supplied text.
///
/// Refuses (`Unrenderable::BadWordList`) anything that is not 1..=[`MAX_WORD_LEN`]
/// lowercase ASCII, because a 2× word wider than that would be *truncated* by
/// [`Frame::text_2x`] — and a silently shortened anti-phishing word is one a user
/// cannot tell from the right one.
pub fn pin_words(
    frame: &mut Frame,
    first_time: bool,
    words: [&str; 2],
) -> Result<(), Unrenderable> {
    for w in words {
        check_word(w)?;
    }
    frame.clear();
    frame.text(
        0,
        0,
        if first_time {
            PIN_WORDS_LEARN
        } else {
            PIN_WORDS_CHECK
        },
    );
    frame.text_2x(0, 2, words[0]);
    frame.text_2x(0, 4, words[1]);
    frame.text(0, FOOTER_ROW, "(y)ok (x)stop");
    Ok(())
}

/// One BIP39-shaped word, or a refusal: 1..=[`MAX_WORD_LEN`] ASCII letters of a
/// SINGLE case, either all-upper or all-lower.
///
/// One rule, two callers ([`BackupPages::new`] and [`pin_words`]), because two
/// word-shape rules is one of them being wrong.
///
/// # This demanded lowercase until 2026-09-08, and that rejected every real word
///
/// The vendored list is UPPERCASE — `frost_backup::bip39_words::BIP39_WORDS` is
/// `[&str; 2048]` beginning `"ABANDON", "ABILITY", "ABLE", ...` — so an
/// `is_ascii_lowercase` gate made `BackupPages::new` return
/// `Err(Unrenderable::BadWordList)` for **every share a keygen can produce**. The
/// backup-display screen could not draw a real backup at all, and nothing caught it
/// because `hal` has no `frost_backup` dependency: `ui` takes `&[&str]` and every
/// test here supplied its own lowercase fixture, so the gate and the only real
/// caller were never compared. That comparison now lives in `coldsnap_firmware`,
/// which has both — see its `every_vendored_bip39_word_is_renderable`.
///
/// Mixed case is still refused, and deliberately: a backup a human transcribes must
/// not vary in case between words, because a user copying "ABANDON" then "ability"
/// will reasonably wonder which is significant. BIP39 recovery is case-insensitive,
/// so the refusal costs nothing real and buys a consistent page.
fn check_word(w: &str) -> Result<(), Unrenderable> {
    if w.is_empty() || w.len() > MAX_WORD_LEN {
        return Err(Unrenderable::BadWordList);
    }
    let all_upper = w.bytes().all(|b| b.is_ascii_uppercase());
    let all_lower = w.bytes().all(|b| b.is_ascii_lowercase());
    if !(all_upper || all_lower) {
        return Err(Unrenderable::BadWordList);
    }
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

    /// Decode a run of `len` [`Frame::text_2x`] glyphs back to characters.
    ///
    /// The inverse itself is [`Frame::cell_2x`], now public — this is only the
    /// string loop over it, so the round-trip proof below covers the shipping
    /// function rather than a test-only copy of the mapping.
    fn text_2x_at(f: &Frame, col: usize, row: usize, len: usize) -> String {
        (0..len)
            .map(|i| f.cell_2x(col + i * 2, row).map_or('?', char::from))
            .collect()
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

    /// The TEXT half of a row `Frame::mark_sensitive` has covered: the cells the
    /// geometry assert reserves for glyphs, decoded and right-trimmed.
    ///
    /// It stops short of the noise columns deliberately. Those bytes are random, so
    /// they may reverse-look-up to a glyph, to nothing, or to something different
    /// on the next seed — asserting on them would be asserting on the RNG. A text
    /// cell that failed to decode still shows up, as a NUL that `trim_end` does not
    /// remove.
    fn noised_row_text(f: &Frame, row: usize) -> String {
        let mut s = String::new();
        for col in 0..SENSITIVE_TEXT_CELLS {
            s.push(f.cell(col, row).map_or('\u{0}', |(b, _)| b as char));
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

    /// **THE PAGED-CONSENT INVARIANT, read off the pixels.** A confirm digit on a
    /// page that cannot authorise is the same lie `hold 1` was: it invites a press
    /// that signs while the glass shows "recipient 1 of 32" and no fee. This walks
    /// every page of five page sets and requires the legend to appear on exactly
    /// the page [`SignPages::is_last`] names.
    #[test]
    fn only_the_last_page_prints_a_confirm_digit() {
        let d = ConfirmDigit::draw(&mut Counter(0));
        let legend = format!("Press ({})", d.as_str());
        for n in [0usize, 1, 2, 3, MAX_RECIPIENTS] {
            for fee in [1u64, HIGH_FEE_SATS + 1] {
                let v: Vec<(&str, u64)> = (0..n).map(|_| (ADDR, 1_000_000u64)).collect();
                let r = recips(&v);
                let p = SignPages::new(&r, fee).unwrap().confirming(d);
                for i in 0..p.len() {
                    let mut f = Frame::new();
                    assert!(p.render(i, &mut f), "page {i} of {} must draw", p.len());
                    let shown = screen_text(&f);
                    // The LEGEND, not the digit byte: an amount page legitimately
                    // renders the character '4' when the amount contains a 4, so a
                    // byte-level assertion would fail for an honest reason.
                    assert_eq!(
                        shown.contains(&legend),
                        p.is_last(i),
                        "page {}/{} (n={n} fee={fee}) advertises the wrong thing:\n{shown}",
                        i + 1,
                        p.len()
                    );
                    assert!(!shown.contains("hold"), "unproducible gesture: {shown}");
                }
            }
        }
    }

    /// 32 recipients is 67 pages. A page set that never says which page you are on
    /// invites consenting on page 1 in the belief it is the whole transaction, so
    /// the position is on every page — including the last, where it is the only
    /// evidence that there is nothing further to read.
    #[test]
    fn every_page_says_where_it_is_in_the_set() {
        let v: Vec<(&str, u64)> = (0..MAX_RECIPIENTS).map(|_| (ADDR, 1_000_000u64)).collect();
        let r = recips(&v);
        let p = SignPages::new(&r, HIGH_FEE_SATS + 1)
            .unwrap()
            .confirming(ConfirmDigit::draw(&mut Counter(0)));
        assert_eq!(
            p.len(),
            2 * MAX_RECIPIENTS + 3,
            "amount+address each, plus warning, fee, confirm"
        );
        for i in 0..p.len() {
            let mut f = Frame::new();
            assert!(p.render(i, &mut f));
            let shown = screen_text(&f);
            assert!(
                shown.contains(&format!("pg {}/{}", i + 1, p.len())),
                "page {} does not say where it is:\n{shown}",
                i + 1
            );
        }
    }

    /// [`Frame::text`] truncates at [`COLS`] **silently**, and the widest footer
    /// this device can produce is exactly `COLS` wide: `pg 66/67 (9)next`. One more
    /// page and the advance legend would be cut off with nothing failing — so this
    /// is the thing that fails. Raising [`MAX_RECIPIENTS`] means shortening the
    /// footer, not deleting this test.
    #[test]
    fn the_widest_page_footer_still_fits_the_screen() {
        let v: Vec<(&str, u64)> = (0..MAX_RECIPIENTS).map(|_| (ADDR, 1_000_000u64)).collect();
        let r = recips(&v);
        let p = SignPages::new(&r, HIGH_FEE_SATS + 1).unwrap();
        let widest = p.len() - 2; // last page that still advertises "next"
        assert!(
            page_of(widest, p.len()).as_str().len() + NEXT_LEGEND.len() <= COLS,
            "the footer would be truncated"
        );
        let mut f = Frame::new();
        assert!(p.render(widest, &mut f));
        let row = row_text(&f, ROWS - 1);
        assert_eq!(row, format!("pg {}/{}{NEXT_LEGEND}", widest + 1, p.len()));
        // No `=` on a page that cannot consent: `stub.rs` `advertised_key` reads
        // `<k>=<what>` on this row as a yes key, so `9=next` would hand a harness a
        // way to approve a transaction it has only seen one page of.
        assert!(!row.contains('='), "non-consenting page advertises a yes key: {row}");
    }

    /// Every byte of a device name is coordinator-controlled: upstream's
    /// `DeviceName` bounds 14 **chars** (up to 56 bytes) and its `Decode`
    /// truncates rather than erroring (`fixed_string.rs:131-140`), so the column
    /// bound has to hold here. Screen 1 is also the screen a human uses to tell
    /// two cold-snaps apart at the moment one of them asks for a signature, which
    /// is what makes a reorderable name a security property and not cosmetics.
    #[test]
    fn a_hostile_device_name_cannot_overrun_or_reorder_screen_one() {
        let mut f = Frame::new();
        // RTL override, zero-width joiner, combining acute — then 4 KiB of text.
        let name = format!("a\u{202e}b\u{200d}c\u{301}{}", "Z".repeat(4096));
        standby(&mut f, &name, "family", Some(3));
        let row = row_text(&f, 0);
        assert_eq!(
            row.chars().count(),
            COLS,
            "the name filled its row and stopped: {row:?}"
        );
        let shown = screen_text(&f);
        assert!(
            shown.contains("family") && shown.contains("share #3"),
            "a long name pushed the rest of screen 1 off:\n{shown}"
        );
        // ONE ROW, not "the rows the other fields happen to redraw afterwards": a
        // name that wraps would spill over every row screen 1 leaves blank, and
        // the two fields drawn after it would hide only two of them.
        for r in [1usize, 3, 5, 6, 7] {
            assert!(
                row_text(&f, r).is_empty(),
                "the name spilled onto row {r}:\n{shown}"
            );
        }
        // Strictly left-to-right by codepoint into fixed cells: the first char
        // drawn is the first char given, and each unmappable one is ONE visible
        // missing-glyph cell (`chr(127)`) rather than a reordering directive.
        assert!(
            row.starts_with("a\u{7f}b\u{7f}c\u{7f}"),
            "name was reordered or a control char vanished: {row:?}"
        );
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
    fn cell_2x_reads_a_known_code_off_the_glass_and_is_none_where_no_glyph_is() {
        // The public path an out-of-crate gate uses: read the 2x keygen code back
        // out of the pixels one glyph at a time, no test helper involved.
        let mut f = Frame::new();
        keygen_check(&mut f, 2, 3, [0xab, 0xcd, 0xef, 0x01], "wallet");
        let base = (COLS - 8) / 2;
        let read: Vec<u8> = [2usize, 4]
            .iter()
            .flat_map(|row| (0..4).filter_map(|i| f.cell_2x(base + i * 2, *row)))
            .collect();
        assert_eq!(read, b"abcdef01", "code not readable off the glass");

        // Blank pixels are not a glyph at 2x (the blank cell doubles to a blank
        // cell, so ' ' is the one exception and it reads as ' ').
        assert_eq!(f.cell_2x(0, 0), None, "1x text decoded as a 2x glyph");
        let blank = Frame::new();
        assert_eq!(blank.cell_2x(0, 0), Some(b' '), "blank is a doubled space");
        // Out of bounds, and the two windows that are too small for a 2x glyph.
        assert_eq!(f.cell_2x(COLS, 0), None, "read past the right edge");
        assert_eq!(f.cell_2x(0, ROWS), None, "read past the bottom");
        assert_eq!(f.cell_2x(COLS - 1, 0), None, "read a half-width glyph");
        assert_eq!(f.cell_2x(0, ROWS - 1), None, "read a half-height glyph");
        assert_eq!(f.cell_2x(usize::MAX, usize::MAX), None, "no overflow panic");
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

    // -- the randomised confirm digit (Coldcard `shared/hsm_ux.py:58`). The
    //    hardware cannot produce a hold, so the two signing screens ask for a
    //    digit instead; these are the tests that make it worth having.

    /// A counter, not an RNG: `draw` must be a pure function of the bytes it is
    /// handed, so a test can drive every branch of it. Being *worse* than the
    /// hardware RNG is the point — a double that only ever returned one value
    /// would hide a `draw` that ignores its argument.
    struct Counter(u32);

    impl rand_core::RngCore for Counter {
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

    #[test]
    fn the_confirm_digit_is_drawn_from_coldcards_five_and_reaches_all_of_them() {
        assert_eq!(&CONFIRM_CHARSET, b"12346", "charset is hsm_ux.py:58's, verbatim");
        let mut rng = Counter(0);
        let mut seen = Vec::new();
        for _ in 0..50 {
            let d = ConfirmDigit::draw(&mut rng);
            let key = d.as_str().as_bytes()[0];
            assert!(
                CONFIRM_CHARSET.contains(&key),
                "drew {:?}, which is not one of 12346",
                d.as_str()
            );
            if !seen.contains(&key) {
                seen.push(key);
            }
        }
        // Every digit must be reachable: a `draw` that returns a constant (or
        // ignores its RNG) is a fixed key a script could hardcode, which is the
        // whole thing this replaces.
        assert_eq!(seen.len(), CONFIRM_CHARSET.len(), "digits reached: {seen:?}");
    }

    /// FAIL CLOSED. `hsm_ux.py:58`'s `refused = (ch != confirm_char)`: anything
    /// that is not the exact digit is a REFUSAL, never an ignored press and never
    /// a retry. Treating only `x` as refusal is how this gets subtly wrong, and it
    /// fails *open*, so that direction is asserted explicitly.
    #[test]
    fn anything_but_the_confirm_digit_is_a_refusal() {
        for expect in CONFIRM_CHARSET {
            let d = ConfirmDigit::draw(&mut Counter(
                CONFIRM_CHARSET.iter().position(|c| *c == expect).unwrap() as u32,
            ));
            assert!(d.accepts(expect), "the drawn digit must confirm");
            // A WRONG digit from the same charset — the near miss.
            for other in CONFIRM_CHARSET.iter().filter(|c| **c != expect) {
                assert!(
                    !d.accepts(*other),
                    "{} must refuse the wrong charset digit {}",
                    expect as char,
                    *other as char
                );
            }
            // `x`, the advertised decline.
            assert!(!d.accepts(b'x'), "x must refuse");
            // Keys that are not in the charset at all, including the ones
            // Coldcard deliberately left out, `y` (which two designs would have
            // confirmed on), and the all-up byte.
            for stray in [b'0', b'5', b'7', b'8', b'9', b'y', b'*', b'#', 0u8, 0xff] {
                assert!(
                    !d.accepts(stray),
                    "{} must refuse stray key {stray:#04x}",
                    expect as char
                );
            }
        }
    }

    /// The screen shows the digit that will be accepted — the property the whole
    /// mechanism rests on, because a script can only answer by reading the glass.
    #[test]
    fn the_signing_screens_print_the_digit_that_accepts() {
        let rs = [Recipient {
            address: "bc1qexampleaddress0000",
            sats: 1_000,
        }];
        for seed in 0..CONFIRM_CHARSET.len() as u32 {
            let d = ConfirmDigit::draw(&mut Counter(seed));

            let pages = SignPages::new(&rs, 500).unwrap().confirming(d);
            let mut f = Frame::new();
            let last = pages.len() - 1;
            assert_eq!(pages.page(last), Some(SignPage::Confirm));
            assert!(pages.render(last, &mut f));
            let shown = screen_text(&f);
            assert!(
                shown.contains(&format!("Press ({})", d.as_str())),
                "confirm page must print the drawn digit, got:\n{shown}"
            );

            let mut f = Frame::new();
            sign_test_message_confirm(&mut f, "frostsnap test", d).unwrap();
            let shown = screen_text(&f);
            assert!(
                shown.contains(&format!("Press ({})", d.as_str())),
                "test-message screen must print the drawn digit, got:\n{shown}"
            );

            // Read the digit back OUT OF THE PIXELS and require the code to
            // accept exactly that. A screen that printed one digit while the
            // logic accepted another would pass every other assertion here.
            let row = row_text(&f, 7);
            let printed = row
                .as_bytes()
                .iter()
                .copied()
                .find(|b| CONFIRM_CHARSET.contains(b))
                .unwrap_or(0);
            assert!(
                d.accepts(printed),
                "the digit on the glass ({}) is not the digit accepted ({})",
                printed as char,
                d.as_str()
            );
            // And no hold is asked for anywhere, on either screen: the numpad
            // emits keydown and all-up only, so a hold legend is unhonourable.
            assert!(!shown.contains("hold"), "hold gesture is unproducible: {shown}");
        }
    }

    /// A caller that draws no digit gets a screen with NO way to say yes, rather
    /// than one advertising a fixed key nothing checks. Fail-closed by default,
    /// which is what lets the fixture catalogues keep their two-argument calls.
    #[test]
    fn a_signing_screen_with_no_digit_advertises_no_confirm_key() {
        let rs = [Recipient {
            address: "bc1qexampleaddress0000",
            sats: 1_000,
        }];
        let pages = SignPages::new(&rs, 500).unwrap();
        let mut f = Frame::new();
        assert!(pages.render(pages.len() - 1, &mut f));
        let shown = screen_text(&f);
        assert!(shown.contains("x to cancel"), "cancel is always offered: {shown}");
        assert!(!shown.contains("Press"), "no digit was drawn: {shown}");
        assert!(!shown.contains("hold"), "and no hold either: {shown}");

        let mut f = Frame::new();
        sign_test_message(&mut f, "frostsnap test").unwrap();
        let shown = screen_text(&f);
        assert!(shown.contains("x=no"), "cancel is always offered: {shown}");
        assert!(!shown.contains("Press") && !shown.contains("hold"), "{shown}");
    }

    const WORDS: [&str; BACKUP_WORDS] = [
        "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd",
        "abuse", "access", "accident", "account", "accuse", "achieve", "acid", "acoustic",
        "acquire", "across", "act", "action", "actor", "actress", "actual", "adapt",
    ];

    /// Every word, exactly once, in order, across the pages — the property that
    /// makes the screen a *backup* rather than a partial one.
    ///
    /// This test used to be called `..._with_the_two_digit_colon_shape`, which named
    /// the wrong thing as the point: the `NN:` shape is upstream's trigger predicate
    /// (`display.py:284-285`), not the side-channel defence. That defence is
    /// `Frame::mark_sensitive`, and it is pinned by
    /// `backup_word_rows_are_noised_and_the_words_stay_clear` below. What is
    /// load-bearing here is coverage: 25 words, in order, none dropped.
    #[test]
    fn backup_pages_cover_every_word_exactly_once_in_order() {
        let p = BackupPages::new(9, &WORDS).unwrap();
        assert_eq!(p.len(), 1 + BACKUP_WORDS.div_ceil(WORDS_PER_PAGE));
        assert_eq!(p.page(0), Some(BackupPage::ShareIndex(9)));
        let mut seen: Vec<&str> = Vec::new();
        let mut f = Frame::new();
        for i in 1..p.len() {
            assert!(p.render(i, &mut f, &mut Counter(i as u32)));
            let t = screen_text(&f);
            match p.page(i) {
                Some(BackupPage::Words { first, words }) => {
                    for (k, w) in words.iter().enumerate() {
                        // The label is alignment, nothing more; see push_u8_pad2.
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
        assert!(e.render(3, &mut f, &mut Counter(0)));
        let t = screen_text(&f);
        assert!(t.contains("word 3 of 25") && t.contains("03: abo_"), "{t}");
    }

    // -- the seed-word side-channel defence: `Frame::mark_sensitive`, ported from
    //    `shared/display.py:201-205`. The `NN:` label is NOT this; see
    //    `push_u8_pad2`.

    /// Every scanline of a noised row gets its own run, and the runs are not all
    /// the same length. Both halves matter: one run per *text* row instead of one
    /// per *pixel* row, or a fixed length, is a pattern that subtracts out.
    #[test]
    fn mark_sensitive_draws_a_fresh_run_on_every_scanline_of_the_row() {
        let row = 3;
        let mut f = Frame::new();
        f.mark_sensitive(row, &mut Counter(0));

        let mut lengths = Vec::new();
        for y in 0..HEIGHT {
            let lit: Vec<usize> = (0..WIDTH).filter(|x| f.pixel(*x, y)).collect();
            if !(row * CELL..row * CELL + CELL).contains(&y) {
                assert!(lit.is_empty(), "row {row} noise leaked onto scanline {y}");
                continue;
            }
            let run = lit.len();
            assert!(
                (SENSITIVE_MIN..=SENSITIVE_MAX).contains(&run),
                "scanline {y} run of {run} px is outside max(2, rng % 32)"
            );
            // Contiguous and right-anchored, exactly like `dis.line(wx-ln, y, wx, y)`.
            assert_eq!(lit.last(), Some(&(WIDTH - 1)), "run must end at the last column");
            assert_eq!(
                lit,
                (WIDTH - run..WIDTH).collect::<Vec<_>>(),
                "scanline {y} run is not one contiguous line"
            );
            lengths.push(run);
        }
        assert_eq!(lengths.len(), CELL, "one run per scanline of the row");
        assert!(
            lengths.iter().any(|l| Some(l) != lengths.first()),
            "every scanline drew {lengths:?} — a constant-length margin is not noise"
        );
        // A row off the panel draws nothing rather than wrapping or panicking.
        let mut g = Frame::new();
        g.mark_sensitive(ROWS, &mut Counter(0));
        g.mark_sensitive(usize::MAX, &mut Counter(0));
        assert!(g.as_bytes().iter().all(|b| *b == 0));
    }

    /// The whole point, end to end: every word row of a rendered backup page is
    /// noised, the words themselves are still readable, the rows that are not
    /// secret are untouched, and the noise actually comes from the RNG.
    #[test]
    fn backup_word_rows_are_noised_and_the_words_stay_clear() {
        // The widest legal row: MAX_WORD_LEN letters, so the text ends exactly at
        // the column the geometry assert reserves.
        let widest = ["abstract"; BACKUP_WORDS];
        let p = BackupPages::new(4, &widest).unwrap();
        let mut f = Frame::new();
        assert!(p.render(1, &mut f, &mut Counter(0)));

        for row in 2..2 + WORDS_PER_PAGE {
            // Readable: every text cell still reverse-looks-up to its glyph, which
            // it cannot if a single noise pixel reached the word.
            assert_eq!(
                noised_row_text(&f, row),
                format!("{:02}: abstract", row - 1),
                "row {row}: the word must survive the noise beside it"
            );
            for y in row * CELL..row * CELL + CELL {
                assert!(
                    f.pixel(WIDTH - 1, y),
                    "scanline {y} of word row {row} is not noised at all"
                );
                // The gutter: the const assert leaves exactly one column between
                // the widest text and the longest run, so THIS column is blank on
                // a noised row whichever side would have encroached.
                assert!(
                    !f.pixel(SENSITIVE_TEXT_CELLS * CELL, y),
                    "row {row} scanline {y}: text and noise met at the gutter column"
                );
            }
        }
        // Not secret, and therefore not noised: the header and the paging legend
        // both read back cleanly, which they could not if the noise were sprayed
        // over the whole page.
        assert_eq!(row_text(&f, 0), "words 1-4");
        assert_eq!(row_text(&f, 7), BACKUP_BACK_LEGEND);
        // Nor is the share-index page: an index is what makes a share restorable,
        // it is not the share.
        let mut g = Frame::new();
        assert!(p.render(0, &mut g, &mut Counter(0)));
        assert_eq!(row_text(&g, 2), "Share index:");
        assert_eq!(row_text(&g, 4), "#4");

        // The RNG is consumed, not ignored: a different stream is a different
        // frame, and it differs ONLY right of the text.
        let mut h = Frame::new();
        assert!(p.render(1, &mut h, &mut Counter(0x5eed_1234)));
        assert!(f != h, "render ignored its rng");
        for y in 0..HEIGHT {
            for x in 0..SENSITIVE_TEXT_CELLS * CELL {
                assert_eq!(
                    f.pixel(x, y),
                    h.pixel(x, y),
                    "the noise changed a text pixel at ({x},{y})"
                );
            }
        }
    }

    /// The entry screen is the same secret on the same glass, so it is noised too —
    /// including the row being typed, where the cursor is what gives way at a full
    /// field rather than a letter.
    #[test]
    fn backup_entry_noises_both_word_rows_and_keeps_a_full_field_readable() {
        let entered = ["abstract"; 4];
        let e = EntryPages {
            share_index: Some(7),
            words: &entered,
            partial: "abstract",
        };
        let mut f = Frame::new();
        assert!(e.render(5, &mut f, &mut Counter(0)));
        assert_eq!(row_text(&f, 0), "word 5 of 25");
        assert_eq!(noised_row_text(&f, 2), "04: abstract", "previous word");
        assert_eq!(
            noised_row_text(&f, 4),
            "05: abstract",
            "a full field keeps all 8 letters; the cursor is what is dropped"
        );
        for row in [2, 4] {
            for y in row * CELL..row * CELL + CELL {
                assert!(f.pixel(WIDTH - 1, y), "entry row {row} scanline {y} not noised");
                // `_` is 0xc0 in all eight of its columns, so a cursor drawn one
                // cell too far right lights this gutter column and is caught here.
                assert!(
                    !f.pixel(SENSITIVE_TEXT_CELLS * CELL, y),
                    "entry row {row} scanline {y}: text and noise met at the gutter"
                );
            }
        }
        assert_eq!(row_text(&f, 7), "1=ok x=del");
        // A shorter field keeps its cursor.
        let e = EntryPages { partial: "abs", ..e };
        let mut g = Frame::new();
        assert!(e.render(5, &mut g, &mut Counter(0)));
        assert_eq!(noised_row_text(&g, 4), "05: abs_");
        // The share-index page is not a word row.
        let mut h = Frame::new();
        assert!(e.render(0, &mut h, &mut Counter(0)));
        assert_eq!(row_text(&h, 2), "share index:");
    }

    /// `SENSITIVE_LABEL_CELLS` is a hand-written 4 standing in for two pushes. Tie
    /// it to the pushes, or the geometry assert is guarding a width nothing draws.
    #[test]
    fn the_sensitive_row_budget_matches_the_label_actually_drawn() {
        let mut b = Buf::<SENSITIVE_TEXT_CELLS>::new();
        b.push_u8_pad2(25).push_str(": ");
        assert_eq!(b.len(), SENSITIVE_LABEL_CELLS, "the NN: label is 4 cells");
        assert!(!b.truncated());
        b.push_str("abstract");
        assert_eq!(b.as_str(), "25: abstract");
        assert!(
            !b.truncated(),
            "a MAX_WORD_LEN word must fit the noised-row budget in full"
        );
        assert_eq!(b.len() * CELL + SENSITIVE_MAX, WIDTH - 1, "one column of slack");
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

    // -- 9. the PIN prompt. SE1 destroys the key at the limit, so unlike every
    //       other screen here these stand between a user and an *irreversible*
    //       act. Each of the four below fails if its guard is deleted.

    /// The lowest-entropy confirm digit there is — `Counter(0)` always yields
    /// `CONFIRM_CHARSET[0]`, which keeps the last-attempt footer assertable.
    fn confirm() -> ConfirmDigit {
        ConfirmDigit::draw(&mut Counter(0))
    }

    const PROMPTS: [PinPrompt; 4] = [
        PinPrompt::Prefix,
        PinPrompt::Suffix,
        PinPrompt::Set,
        PinPrompt::Repeat,
    ];

    #[test]
    fn a_typed_pin_is_never_rendered_in_cleartext_on_the_entry_screen() {
        // Stated as the property rather than as a layout detail: two different
        // PINs of the same length must produce a byte-identical panel. That
        // covers the whole frame, 2x band included, and no assertion about where
        // the field sits can be weakened to let a digit through somewhere else.
        for prompt in PROMPTS {
            let (mut a, mut b) = (Frame::new(), Frame::new());
            assert_eq!(
                pin_entry(&mut a, prompt, "1234", 13, confirm()),
                Ok(PinScreen::Entry)
            );
            pin_entry(&mut b, prompt, "9876", 13, confirm()).unwrap();
            assert_eq!(
                a.as_bytes(),
                b.as_bytes(),
                "{prompt:?}: the panel leaks which digits were typed"
            );
            assert!(
                !screen_text(&a).contains('1'),
                "{prompt:?}: a typed digit reached the 1x rows"
            );
        }
        // Longer than the field can hold is a refusal, not a shortened star run:
        // a count that stops growing is a lie about what was typed.
        let mut f = Frame::new();
        assert_eq!(
            pin_entry(&mut f, PinPrompt::Prefix, "1234567", 13, confirm()),
            Err(Unrenderable::TooLong)
        );
    }

    #[test]
    fn the_masked_field_shows_one_star_per_digit_so_a_press_is_visible() {
        for n in 0..=MAX_PIN_PART_LEN {
            let typed = "7".repeat(n);
            let mut f = Frame::new();
            pin_entry(&mut f, PinPrompt::Set, &typed, 13, confirm()).unwrap();
            let want = format!("[{}]", "*".repeat(n));
            let cells = want.chars().count();
            assert_eq!(
                text_2x_at(&f, centred(cells), 1, cells),
                want,
                "{n} digits typed"
            );
        }
    }

    #[test]
    fn the_entry_screen_always_shows_the_attempts_remaining() {
        for n in [2u64, 3, 12, 13, 99] {
            let mut f = Frame::new();
            assert_eq!(
                pin_entry(&mut f, PinPrompt::Suffix, "12", n, confirm()),
                Ok(PinScreen::Entry)
            );
            let mut want = Buf::<20>::new();
            want.push_u64(n);
            assert_eq!(
                text_2x_at(&f, 0, 3, want.len()),
                want.as_str(),
                "{n} attempts left must be on the panel at 2x"
            );
            let s = screen_text(&f);
            assert!(
                s.contains(PIN_TRIES_1) && s.contains(PIN_TRIES_2),
                "the figure needs its consequence: {s}"
            );
        }
        // Same figure, same 2x treatment, on the screen a user actually reads it
        // on — the one right after a rejected PIN.
        let mut f = Frame::new();
        pin_wrong(&mut f, 4, 9);
        assert_eq!(text_2x_at(&f, 0, 1, 1), "4");
        let s = screen_text(&f);
        assert!(s.contains("WRONG PIN") && s.contains(PIN_TRIES_2), "{s}");
        assert!(s.contains("fails: 9"), "{s}");
        // 99 is `pins.c:478`'s sentinel, not a count: it must print in full.
        pin_wrong(&mut f, 13, 99);
        assert!(screen_text(&f).contains("fails: 99"));
    }

    #[test]
    fn the_final_attempt_screen_is_not_an_ordinary_entry_screen() {
        let c = confirm();
        let mut f = Frame::new();
        assert_eq!(
            pin_entry(&mut f, PinPrompt::Suffix, "1234", 1, c),
            Ok(PinScreen::LastTry)
        );
        assert_eq!(text_2x_at(&f, 0, 0, 8), "LAST TRY");
        let s = screen_text(&f);
        assert!(s.contains("erased"), "must name the consequence: {s}");
        // Submit is the drawn confirm digit, not the ordinary key.
        assert!(s.contains(press_legend(c).as_str()), "{s}");
        assert!(!s.contains(PIN_FOOTER), "{s}");
        // And here, deliberately, the PIN is in the clear so a typo is catchable
        // before the attempt is spent (`shared/login.py:200-208`).
        assert_eq!(text_2x_at(&f, centred(6), 5, 6), "[1234]");
        // No argument produces an ordinary entry screen with one attempt left.
        for prompt in PROMPTS {
            for typed in ["", "1", "123456"] {
                assert_eq!(
                    pin_entry(&mut f, prompt, typed, 1, c),
                    Ok(PinScreen::LastTry),
                    "{prompt:?} {typed:?}"
                );
            }
        }
    }

    #[test]
    fn a_unit_with_no_attempts_left_is_never_offered_an_entry_screen() {
        let mut f = Frame::new();
        assert_eq!(
            pin_entry(&mut f, PinPrompt::Suffix, "1234", 0, confirm()),
            Ok(PinScreen::Bricked)
        );
        let mut want = Frame::new();
        pin_bricked(&mut want);
        assert_eq!(f.as_bytes(), want.as_bytes(), "0 attempts is not a prompt");
        let s = screen_text(&f);
        assert!(s.contains("EXHAUSTED") && s.contains("No reset"), "{s}");
        // Nothing to press: a dead unit must not advertise a key.
        assert!(!s.contains("(y)") && !s.contains("(x)"), "{s}");
    }

    #[test]
    fn an_over_long_anti_phishing_word_is_refused_not_truncated() {
        let mut f = Frame::new();
        // Exactly MAX_WORD_LEN is fine, and lands as exactly the full panel.
        pin_words(&mut f, true, ["aaaaaaaa", "bbbbbbbb"]).unwrap();
        assert_eq!(text_2x_at(&f, 0, 2, MAX_WORD_LEN), "aaaaaaaa");
        assert_eq!(text_2x_at(&f, 0, 4, MAX_WORD_LEN), "bbbbbbbb");
        // One over, empty, uppercase, spaced, digits: all refusals. A silently
        // shortened word is one a user cannot tell from the right one.
        for bad in ["abilities", "", "Ability", "abil ty", "ability9"] {
            assert_eq!(
                pin_words(&mut f, false, ["abandon", bad]),
                Err(Unrenderable::BadWordList),
                "{bad:?} in second position"
            );
            assert_eq!(
                pin_words(&mut f, false, [bad, "abandon"]),
                Err(Unrenderable::BadWordList),
                "{bad:?} in first position"
            );
        }
        // Same rule, same refusal, on the other caller of `check_word`.
        let mut words = WORDS;
        words[7] = "abilities";
        assert_eq!(
            BackupPages::new(1, &words).err(),
            Some(Unrenderable::BadWordList)
        );
    }

    #[test]
    fn the_words_screen_says_record_them_the_first_time_and_recognise_them_after() {
        assert_ne!(PIN_WORDS_LEARN, PIN_WORDS_CHECK);
        let mut f = Frame::new();
        pin_words(&mut f, true, ["abandon", "ability"]).unwrap();
        assert!(screen_text(&f).contains(PIN_WORDS_LEARN));
        pin_words(&mut f, false, ["abandon", "ability"]).unwrap();
        assert!(screen_text(&f).contains(PIN_WORDS_CHECK));
    }

    #[test]
    fn no_pin_screen_advertises_a_consent_key_to_the_stub_scraper() {
        // `firmware/examples/stub.rs`'s `advertised_key` reads `<k>=<what>` on the
        // last row as a plain-press yes key. No PIN screen authorises a
        // signature, so none of them may match that shape — the same trap
        // `NEXT_LEGEND` documents.
        let c = confirm();
        let mut f = Frame::new();
        let mut footers = Vec::new();
        pin_entry(&mut f, PinPrompt::Prefix, "12", 13, c).unwrap();
        footers.push(("entry", row_text(&f, FOOTER_ROW)));
        pin_entry(&mut f, PinPrompt::Suffix, "12", 1, c).unwrap();
        footers.push(("last try", row_text(&f, FOOTER_ROW)));
        pin_wrong(&mut f, 5, 8);
        footers.push(("wrong", row_text(&f, FOOTER_ROW)));
        pin_bricked(&mut f);
        footers.push(("bricked", row_text(&f, FOOTER_ROW)));
        pin_mismatch(&mut f);
        footers.push(("mismatch", row_text(&f, FOOTER_ROW)));
        pin_checking(&mut f);
        footers.push(("checking", row_text(&f, FOOTER_ROW)));
        pin_words(&mut f, true, ["abandon", "ability"]).unwrap();
        footers.push(("words", row_text(&f, FOOTER_ROW)));
        for (name, row) in footers {
            assert_ne!(
                row.as_bytes().get(1),
                Some(&b'='),
                "{name}: footer {row:?} reads to the scraper as a consent legend"
            );
        }
    }

    #[test]
    fn every_pin_string_this_module_owns_fits_the_panel() {
        let mut all = Vec::new();
        for p in PROMPTS {
            all.push(p.title());
        }
        all.extend([
            PIN_WORDS_LEARN,
            PIN_WORDS_CHECK,
            PIN_TRIES_1,
            PIN_TRIES_2,
            PIN_FOOTER,
        ]);
        for s in all {
            assert!(
                s.chars().count() <= COLS,
                "{s:?} is {} cols, panel is {COLS}",
                s.chars().count()
            );
        }
        // And the prose rows: nothing a PIN screen draws may be clipped, which on
        // a 16-col grid means every rendered row is at most COLS and the
        // right-hand column is the last thing on it.
        let mut f = Frame::new();
        pin_mismatch(&mut f);
        assert!(screen_text(&f).lines().all(|l| l.chars().count() <= COLS));
        pin_checking(&mut f);
        assert!(screen_text(&f).lines().all(|l| l.chars().count() <= COLS));
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
        // A counter, not the hardware RNG: the artefact stays diffable, and the
        // run lengths still vary per scanline the way the device's will.
        let mut noise = Counter(0);
        for i in 0..b.len() {
            assert!(b.render(i, &mut f, &mut noise));
            show(&format!("5 backup display page {}/{}", i + 1, b.len()), &f);
        }

        let words = ["abandon", "ability"];
        let e = EntryPages {
            share_index: Some(2),
            words: &words,
            partial: "abo",
        };
        assert!(e.render(0, &mut f, &mut noise));
        show("6 backup entry (share index)", &f);
        assert!(e.render(e.cursor(), &mut f, &mut noise));
        show("6 backup entry (word 3)", &f);

        backup_quiz(&mut f, "word 7 was:", ["absorb", "absurd", "abstract"], Some(0));
        show("7 backup quiz", &f);

        address_verify(&mut f, ADDR, "m/0/17", 3).unwrap();
        show("8 address verify", &f);

        let c = confirm();
        pin_words(&mut f, true, ["abandon", "absurd"]).unwrap();
        show("9 PIN anti-phishing words (first time)", &f);
        pin_entry(&mut f, PinPrompt::Prefix, "12", 13, c).unwrap();
        show("9 PIN entry (prefix, 13 left)", &f);
        pin_entry(&mut f, PinPrompt::Suffix, "1234", 3, c).unwrap();
        show("9 PIN entry (suffix, 3 left)", &f);
        pin_checking(&mut f);
        show("9 PIN checking", &f);
        pin_wrong(&mut f, 2, 11);
        show("9 PIN wrong (2 left)", &f);
        pin_entry(&mut f, PinPrompt::Suffix, "1234", 1, c).unwrap();
        show("9 PIN LAST TRY (1 left, PIN shown, confirm-digit gate)", &f);
        pin_entry(&mut f, PinPrompt::Suffix, "1234", 0, c).unwrap();
        show("9 PIN bricked (0 left)", &f);
        pin_mismatch(&mut f);
        show("9 PIN mismatch (first-time set)", &f);
    }
}

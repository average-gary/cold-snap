//! Render every `coldsnap_hal::ui` screen on the HOST, so the layouts can be
//! judged before anything is flashed.
//!
//! No SoC simulator is involved and none is needed. A 128x64 monochrome
//! framebuffer is 1,024 bytes of ordinary data (`shared/lcd.py:33,40,43`), and
//! `ui.rs` composes into it with no register access and no `frostsnap_core`
//! type. So the *entire* display layer is exercisable here: this binary is the
//! same composition code the device runs, pointed at stdout and at a directory
//! of BMPs instead of at SPI1.
//!
//! WHAT IT IS NOT EVIDENCE FOR. Nothing here says a glyph is *legible* on the
//! real SSD1306, or that the 8 px cap height survives a hand-copied seed word.
//! It answers "what is on the screen, in full, at every page" — pixel-exact and
//! byte-identical to what the panel would be handed. Legibility is silicon's
//! call. Every claim from this binary is unverified-on-silicon.
//!
//! TWO OUTPUTS FROM THE SAME FRAMEBUFFERS, because they answer different
//! questions:
//!
//!   * ASCII art to stdout, one char per pixel inside a 128-wide border. The
//!     border is the panel edge, so anything `ui.rs` clipped is visible as
//!     missing ink at the right margin rather than as a silent truncation. This
//!     output is a diff: `cargo run ... > before.txt`, edit a layout, diff.
//!   * 1-bit uncompressed BMPs, integer-upscaled 4x to 512x256, because 128x64
//!     is postage-stamp sized in an image viewer. ~40 lines of `core` and zero
//!     new dependencies (PLAN.md §1's bar); verified readable by macOS ImageIO.
//!
//! REALISTIC *AND* HOSTILE INPUT. Every string a coordinator can supply is
//! attacker-controlled, so the catalogue below carries the ordinary case AND the
//! ones that break layouts: the longest legal segwit address, an address exactly
//! at and exactly one over `ui::ADDRESS_ROWS * ui::COLS`, 0 sats, 21e14 sats, a
//! fee over BOTH high-fee thresholds, 17 recipients, a maximum-length device
//! name and a name of multi-byte UTF-8. Each block is labelled with the input it
//! came from, so a wrong-looking screen is diagnosable without reading this file.
//!
//! REFUSALS ARE RENDERED TOO, and labelled `REFUSED`. `SignPages::new` returning
//! `Err` is the `user_prompt() == None` posture of PLAN.md §8.1 defect 12: it
//! means *reject the coordinator's request*, not "render fewer recipients". A
//! refusal that shows up here as a missing screen is how someone later "fixes"
//! it into a fail-open, so it shows up as a block that says what was refused and
//! why.
//!
//! DETERMINISTIC, but no longer RNG-free. No clock and no `HashMap`; the address
//! highlight seed is still an explicit argument. What changed: the backup display
//! and entry screens take a **required** `RngCore`, because every row with a seed
//! word on it is covered by `Frame::mark_sensitive` — a fresh random-length run
//! per scanline (`shared/display.py:201-205`), which is only a defence if it is
//! actually random. Those screens are therefore NOT a pure function of their
//! arguments on the device.
//!
//! Here they are fed `Counter`, a fixed-seed counter re-created per page, so the
//! artefacts stay byte-stable and a layout regression is still a diff. The cost of
//! that choice, stated so nobody reads the BMPs as evidence: the ragged margin
//! looks the SAME on every page here and it will not on the device. What these
//! files show is the geometry — that the noise starts clear of the words — not the
//! distribution.
//!
//! Run:
//! ```text
//! cargo run --target aarch64-apple-darwin -p coldsnap_hal --example ui_render
//! ```

use coldsnap_hal::ui::{
    self, BackupPages, ConfirmDigit, EntryPages, Frame, PinPrompt, Recipient, SignPage, SignPages,
    ADDRESS_ROWS, BACKUP_WORDS, COLS, HEIGHT, MAX_PIN_PART_LEN, WIDTH,
};
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

/// Integer upscale for the BMPs. 128x64 -> 512x256, whose 1bpp stride (64 B) is
/// already 4-byte aligned, so no row padding is needed.
const SCALE: usize = 4;

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

struct Out {
    dir: PathBuf,
    n: usize,
}

impl Out {
    fn new() -> Self {
        // Compile-time manifest dir, not the CWD: `cargo run --example` and a
        // bare `./ui_render` must write to the same place.
        let dir = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../target/ui_render"));
        // Wipe first: a stale BMP from a previous catalogue is exactly the kind
        // of thing someone reviews by accident.
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create output dir");
        Out { dir, n: 0 }
    }

    /// One block: numbered title, the input that produced it, the BMP path, then
    /// the framebuffer as ASCII art inside the panel border.
    fn emit(&mut self, title: &str, input: &str, slug: &str, frame: &Frame) {
        self.n += 1;
        let name = format!("{:03}-{}.bmp", self.n, slug);
        fs::write(self.dir.join(&name), bmp(frame)).expect("write bmp");

        println!("{}", "=".repeat(WIDTH + 2));
        println!("SCREEN {:03}  {}", self.n, title);
        println!("input:  {input}");
        println!("file:   {name}");
        print!("{}", art(frame));
        println!();
    }

    /// A refusal block. The screen is real — it is what the device draws — and
    /// the title carries the typed reason `ui.rs` gave.
    fn refused(&mut self, title: &str, input: &str, slug: &str, reason: &str) {
        let mut frame = Frame::new();
        ui::refusal(&mut frame);
        self.emit(
            &format!("REFUSED  {title}  -> {reason}"),
            input,
            &format!("{slug}-refused"),
            &frame,
        );
    }

    fn finish(self) {
        let dir = fs::canonicalize(&self.dir).unwrap_or(self.dir);
        println!("{}", "=".repeat(WIDTH + 2));
        println!(
            "{} screens emitted as {}x{} 1-bit BMPs ({}x upscale of {WIDTH}x{HEIGHT}).",
            self.n,
            WIDTH * SCALE,
            HEIGHT * SCALE,
            SCALE
        );
        println!("open {}", dir.display());
    }
}

/// The framebuffer as one char per pixel, inside a border the exact width of the
/// panel. `#` is a lit pixel.
fn art(frame: &Frame) -> String {
    let edge = format!("+{}+\n", "-".repeat(WIDTH));
    let mut s = String::with_capacity((WIDTH + 3) * (HEIGHT + 2));
    s.push_str(&edge);
    for y in 0..HEIGHT {
        s.push('|');
        for x in 0..WIDTH {
            s.push(if frame.pixel(x, y) { '#' } else { '.' });
        }
        s.push_str("|\n");
    }
    s.push_str(&edge);
    s
}

/// 1-bit uncompressed BMP, bottom-up, `SCALE`x nearest-neighbour upscale.
///
/// 14 B file header + 40 B BITMAPINFOHEADER + 8 B two-entry palette + pixels.
/// Palette entry 0 is black and 1 is white, matching an OLED's lit-pixel-is-ink.
fn bmp(frame: &Frame) -> Vec<u8> {
    let (w, h) = (WIDTH * SCALE, HEIGHT * SCALE);
    let stride = w.div_ceil(32) * 4;
    let pixels = stride * h;
    let mut v = Vec::with_capacity(62 + pixels);

    v.extend_from_slice(b"BM");
    v.extend_from_slice(&(62 + pixels as u32).to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes()); // reserved
    v.extend_from_slice(&62u32.to_le_bytes()); // pixel data offset
    v.extend_from_slice(&40u32.to_le_bytes()); // DIB header size
    v.extend_from_slice(&(w as i32).to_le_bytes());
    v.extend_from_slice(&(h as i32).to_le_bytes()); // positive => bottom-up
    v.extend_from_slice(&1u16.to_le_bytes()); // planes
    v.extend_from_slice(&1u16.to_le_bytes()); // bits per pixel
    v.extend_from_slice(&0u32.to_le_bytes()); // BI_RGB, uncompressed
    v.extend_from_slice(&(pixels as u32).to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes()); // x pixels per metre
    v.extend_from_slice(&0u32.to_le_bytes()); // y pixels per metre
    v.extend_from_slice(&2u32.to_le_bytes()); // palette entries used
    v.extend_from_slice(&0u32.to_le_bytes()); // important colours
    v.extend_from_slice(&[0, 0, 0, 0, 0xff, 0xff, 0xff, 0]); // BGRA: off, on

    for row in 0..h {
        let y = (h - 1 - row) / SCALE; // bottom-up
        let mut line = vec![0u8; stride];
        for x in 0..w {
            if frame.pixel(x / SCALE, y) {
                line[x / 8] |= 0x80 >> (x % 8);
            }
        }
        v.extend_from_slice(&line);
    }
    debug_assert_eq!(v.len(), 62 + pixels);
    v
}

// ---------------------------------------------------------------------------
// Input catalogue
// ---------------------------------------------------------------------------

/// BIP-350 test vector, 62 chars — the ordinary P2TR case PLAN.md §4.2 sizes
/// screen 8 against.
const P2TR: &str = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0";
/// BIP-173 test vector, 42 chars.
const P2WPKH: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
/// Base58 P2PKH, 34 chars — the shortest thing screen 8 has to lay out.
const P2PKH: &str = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";

/// A synthetic bech32-charset string of exactly `len` chars.
///
/// SYNTHETIC AND NOT CHECKSUM-VALID, deliberately: `ui.rs` validates printable
/// ASCII and column budget, not bech32, so what matters for a layout is the
/// length and the character set. Generating a real 40-byte-witness address would
/// add a bech32 encoder to prove nothing about pixels.
fn synth(len: usize) -> String {
    const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let mut s = String::from("bc1");
    while s.len() < len {
        s.push(CHARSET[s.len() % CHARSET.len()] as char);
    }
    s
}

/// 25 real BIP39 words, all within the 1..=8 lowercase shape `BackupPages::new`
/// requires and within 16 columns as `NN: word`.
const WORDS: [&str; BACKUP_WORDS] = [
    "absorb", "abstract", "absurd", "abuse", "access", "accident", "account", "accuse", "achieve",
    "acid", "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
    "adapt", "add", "addict", "address", "adjust", "admit", "adult",
];

fn main() {
    let mut out = Out::new();

    // --- screen 1: standby -------------------------------------------------
    let mut f = Frame::new();
    ui::standby(&mut f, "coldsnap-01", "family fund", Some(2));
    out.emit(
        "1 standby — ordinary",
        "name \"coldsnap-01\" (11c), key \"family fund\", share #2",
        "standby-ordinary",
        &f,
    );

    // Upstream's device name is a `FixedString<14>`, so 14 chars is the wire
    // maximum and it must fit the 16-col grid with room for nothing else.
    ui::standby(&mut f, "MMMMMMMMMMMMMM", "wwwwwwwwwwwwwwww", None);
    out.emit(
        "1 standby — max-length name, no share",
        "name 14x'M' (upstream FixedString<14> maximum), key 16x'w', held_share None",
        "standby-maxname",
        &f,
    );

    // Longer than the grid: this is the ONE screen ui.rs truncates silently, so
    // look at where the truncation lands.
    ui::standby(&mut f, "coldsnap-device-number-seventeen", "a-very-long-key-name", Some(4_294_967_295));
    out.emit(
        "1 standby — over-long name (silent column clip) + u32::MAX share",
        "name 32c, key 20c, share #4294967295",
        "standby-overlong",
        &f,
    );

    ui::standby(&mut f, "\u{65e5}\u{672c}\u{8a9e}\u{306e}dev", "\u{202e}gnitset", Some(1));
    out.emit(
        "1 standby — multi-byte UTF-8 and an RTL override",
        "name \"<CJK x4>dev\", key \"U+202E RIGHT-TO-LEFT OVERRIDE + gnitset\" \
         (each non-ASCII codepoint = one checkerboard cell, never dropped, never reordered)",
        "standby-utf8",
        &f,
    );

    // --- screen 2: keygen check (anti-MITM) --------------------------------
    ui::keygen_check(&mut f, 2, 3, [0xab, 0xcd, 0xef, 0x01], "family fund");
    out.emit(
        "2 keygen check — ordinary (SECURITY: anti-MITM)",
        "2-of-3, code abcd ef01, key \"family fund\"",
        "keygen-ordinary",
        &f,
    );

    ui::keygen_check(&mut f, u16::MAX, u16::MAX, [0x00, 0x00, 0x00, 0x00], "\u{65e5}\u{672c}\u{8a9e}");
    out.emit(
        "2 keygen check — u16::MAX threshold, all-zero code, UTF-8 key name",
        "65535-of-65535 (14 of 16 cols), code 0000 0000, key \"<CJK x3>\"",
        "keygen-extreme",
        &f,
    );

    // --- screen 3: sign approval (SECURITY) --------------------------------
    let long = synth(74);
    assert_eq!(long.len(), 74, "longest legal segwit address is 74 chars");
    let at_limit = synth(ADDRESS_ROWS * COLS);
    assert_eq!(at_limit.len(), 80);
    let over_limit = synth(ADDRESS_ROWS * COLS + 1);
    assert_eq!(over_limit.len(), 81);

    sign_case(
        &mut out,
        "ordinary 2-recipient payment",
        "sign-ordinary",
        &[
            Recipient {
                address: P2TR,
                sats: 150_000,
            },
            Recipient {
                address: P2PKH,
                sats: 25_000,
            },
        ],
        2_000,
    );

    sign_case(
        &mut out,
        "0 sats and 21e14 sats, fee over BOTH high-fee thresholds",
        "sign-extremes",
        &[
            Recipient {
                address: P2WPKH,
                sats: 0,
            },
            Recipient {
                address: P2TR,
                sats: 2_100_000_000_000_000,
            },
        ],
        // 200,000 > HIGH_FEE_SATS (100,000) AND > 5% of sent. Both legs fire.
        200_000,
    );

    // Two recipients at u64::MAX: the sum overflows u64, which is upstream's
    // `PromptSignBitcoinTx::total_sent` wrap. `SignPages::sent_sats` is u128, so
    // the high-fee comparison here is done on the true total; the WARNING page
    // still has to print a u64, so watch what it says. 20 digits also exercises
    // the amount page's 2-row digit wrap at its true maximum.
    sign_case(
        &mut out,
        "2x u64::MAX sats (sum overflows u64 — upstream total_sent wrap)",
        "sign-u64max",
        &[
            Recipient {
                address: P2TR,
                sats: u64::MAX,
            },
            Recipient {
                address: P2WPKH,
                sats: u64::MAX,
            },
        ],
        u64::MAX,
    );

    sign_case(
        &mut out,
        "longest legal segwit address (40-byte witness program)",
        "sign-longest",
        &[Recipient {
            address: &long,
            sats: 1,
        }],
        60_000,
    );

    sign_case(
        &mut out,
        "address exactly at the ADDRESS_ROWS*COLS budget",
        "sign-atlimit",
        &[Recipient {
            address: &at_limit,
            sats: 21_000_000 * 100_000_000,
        }],
        1,
    );

    let many: Vec<Recipient> = (0..17)
        .map(|i| Recipient {
            address: if i % 2 == 0 { P2TR } else { P2WPKH },
            sats: 1_000 * (i as u64 + 1),
        })
        .collect();
    sign_case(
        &mut out,
        "17 recipients (2 pages each + fee + confirm)",
        "sign-17",
        &many,
        150_000,
    );

    sign_case(
        &mut out,
        "zero foreign recipients (consolidation — all outputs are change)",
        "sign-selfsend",
        &[],
        900,
    );

    // Refusals. Every one of these is a LEGAL transaction that this device
    // cannot display, which per PLAN.md §8.1 defect 12 means refuse to sign —
    // NOT render the recipients that did resolve.
    for (label, slug, address) in [
        (
            "OP_RETURN / bare P2PK — no address representation at all",
            "sign-noaddr",
            "",
        ),
        (
            "address one char over the budget (81 > ADDRESS_ROWS*COLS)",
            "sign-over",
            over_limit.as_str(),
        ),
        (
            "address containing U+202E RIGHT-TO-LEFT OVERRIDE",
            "sign-rtl",
            "bc1q\u{202e}508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        ),
    ] {
        // The unaddressable output is the MIDDLE recipient, so a fail-open that
        // rendered "the ones it can" would still show two real payments.
        let rs = [
            Recipient {
                address: P2TR,
                sats: 10_000,
            },
            Recipient { address, sats: 500 },
            Recipient {
                address: P2WPKH,
                sats: 20_000,
            },
        ];
        match SignPages::new(&rs, 1_000) {
            Ok(_) => panic!("{label}: SignPages::new accepted an undisplayable address"),
            Err(e) => out.refused(
                &format!("3 sign approval — {label}"),
                &format!(
                    "3 recipients, #2 address = {:?} ({} chars); whole transaction rejected, \
                     not partially rendered",
                    address,
                    address.chars().count()
                ),
                slug,
                &format!("SignPages::new -> Err(Unrenderable::{e:?})"),
            ),
        }
    }

    match SignPages::new(&many.repeat(2), 1_000) {
        Ok(_) => panic!("34 recipients accepted over MAX_RECIPIENTS"),
        Err(e) => out.refused(
            "3 sign approval — 34 recipients over MAX_RECIPIENTS",
            "34 recipients (MAX_RECIPIENTS = 32), fee 1000 sats",
            "sign-toomany",
            &format!("SignPages::new -> Err(Unrenderable::{e:?})"),
        ),
    }

    // --- screen 4: test-message sign confirm ------------------------------
    for (label, slug, msg) in [
        ("ordinary", "msg-ordinary", "frostsnap device 2 attestation".to_string()),
        ("exactly 4 rows x 16 cols = 64 chars, the last that fits", "msg-full", "A".repeat(64)),
        ("65 chars — one over", "msg-over", "A".repeat(65)),
        ("4096 chars — a whole frame's worth", "msg-huge", "A".repeat(4096)),
    ] {
        match ui::sign_test_message(&mut f, &msg) {
            Ok(()) => out.emit(
                &format!("4 test-message sign confirm — {label}"),
                &format!("message {} chars", msg.chars().count()),
                slug,
                &f,
            ),
            Err(e) => out.refused(
                &format!("4 test-message sign confirm — {label}"),
                &format!(
                    "message {} chars; refused rather than head-truncated, because showing 64 \
                     of {} characters while signing all of them is a blind signer",
                    msg.chars().count(),
                    msg.chars().count()
                ),
                slug,
                &format!("sign_test_message -> Err(Unrenderable::{e:?})"),
            ),
        }
    }

    // --- screen 5: backup display -----------------------------------------
    let backup = BackupPages::new(2, &WORDS).expect("25 lowercase BIP39-shaped words");
    for i in 0..backup.len() {
        // Fresh counter per page, so adding a screen above does not re-noise every
        // page below it and turn the diff into confetti. The device draws a fresh
        // pattern per render; here the pattern is per page and repeats.
        assert!(
            backup.render(i, &mut f, &mut Counter(0)),
            "backup page {i} must render"
        );
        out.emit(
            &format!("5 backup display — page {}/{}", i + 1, backup.len()),
            &format!(
                "share #2, {BACKUP_WORDS} words \"{}..{}\" — the ragged right margin on each \
                 word row is Frame::mark_sensitive (shared/display.py:201-205), one fresh run \
                 per scanline; here from a counter, on the device from rng::Entropy",
                WORDS[0],
                WORDS[BACKUP_WORDS - 1]
            ),
            &format!("backup-p{:02}", i + 1),
            &f,
        );
    }

    let short: Vec<&str> = WORDS[..24].to_vec();
    match BackupPages::new(2, &short) {
        Ok(_) => panic!("24 words accepted"),
        Err(e) => out.refused(
            "5 backup display — 24-word list",
            "share #2, 24 words (BACKUP_WORDS = 25): a backup shown short is unrestorable",
            "backup-short",
            &format!("BackupPages::new -> Err(Unrenderable::{e:?})"),
        ),
    }

    // --- screen 5b: did the human actually write it down? -------------------
    ui::backup_recorded(&mut f, ConfirmDigit::draw(&mut Counter(0)));
    out.emit(
        "5b backup recorded? — the question that CLOSES a reveal",
        "no word, no phase and no Secrets reach this screen: the answer is a claim \
         to the coordinator that a backup exists ON PAPER, so the yes is a fresh \
         randomised digit and never a paging key",
        "backup-recorded",
        &f,
    );

    // --- screen 6: backup entry -------------------------------------------
    let entered: Vec<&str> = WORDS[..7].to_vec();
    let entry = EntryPages {
        share_index: Some(2),
        words: &entered,
        partial: "abso",
    };
    for i in 0..entry.len() {
        assert!(
            entry.render(i, &mut f, &mut Counter(0)),
            "entry page {i} must render"
        );
        out.emit(
            &format!(
                "6 backup entry — page {}/{}{}",
                i + 1,
                entry.len(),
                if i == entry.cursor() { "  <- cursor" } else { "" }
            ),
            "share #2 confirmed, 7 words entered, partial \"abso\"",
            &format!("entry-p{:02}", i + 1),
            &f,
        );
    }

    let pre = EntryPages {
        share_index: None,
        words: &[],
        partial: "1",
    };
    assert_eq!(pre.cursor(), 0, "word entry is gated behind the share index");
    assert!(pre.render(0, &mut f, &mut Counter(0)));
    out.emit(
        "6 backup entry — share index not yet confirmed (word entry gated)",
        "share_index None, 0 words, partial \"1\"",
        "entry-gate",
        &f,
    );

    // --- screen 6, the DEVICE form: the candidate letters ------------------
    //
    // `EntryPages` above has no candidate list, so its word page offers no letter
    // key — a screen a human cannot type on. `WordEntry` is the one that can. The
    // candidates come from `frost_backup::bip39_words::get_valid_next_letters`
    // above this seam, UPPERCASE, and are fixtures here.
    for (label, slug, w) in [
        (
            "fresh word, 25 valid first letters (3 pages)",
            "wordentry-fresh",
            ui::WordEntry {
                number: 3,
                partial: "",
                previous: Some("ABILITY"),
                candidates: "ABCDEFGHIJKLMNOPQRSTUVWYZ",
                page: 0,
                complete: false,
            },
        ),
        (
            "same word, page 3 of the letters (S..Z)",
            "wordentry-page3",
            ui::WordEntry {
                number: 3,
                partial: "",
                previous: Some("ABILITY"),
                candidates: "ABCDEFGHIJKLMNOPQRSTUVWYZ",
                page: 2,
                complete: false,
            },
        ),
        (
            "one letter in: 10 candidates, so 2 pages (page 2, the short one)",
            "wordentry-page2of2",
            ui::WordEntry {
                number: 4,
                partial: "A",
                previous: Some("ABANDON"),
                candidates: "BCDGILMNRT",
                page: 1,
                complete: false,
            },
        ),
        (
            "ACT: a word that is ALSO a prefix — (y) live AND letters left",
            "wordentry-act",
            ui::WordEntry {
                number: 3,
                partial: "ACT",
                previous: Some("ABILITY"),
                candidates: "IOR",
                page: 0,
                complete: true,
            },
        ),
        (
            "narrowed to one word: no letters left, (y) is the only way on",
            "wordentry-done",
            ui::WordEntry {
                number: 25,
                partial: "ABSTRACT",
                previous: Some("ABSURD"),
                candidates: "",
                page: 0,
                complete: true,
            },
        ),
    ] {
        w.render(&mut f, &mut Counter(0)).expect("renderable");
        out.emit(
            &format!("6 word entry (device form) — {label}"),
            // Described, not `{w:?}`: `WordEntry` derives Debug and holds the
            // partial word, so a formatted one is share material in a log line.
            &format!(
                "word {} of {BACKUP_WORDS}, {} candidate letters, page {} of {}, \
                 complete={}. Row 1 is the letter-page indicator (blank when there \
                 is only one page) and rows 5 and 6 are the ruler and the letters — \
                 all three noised: the letters are a function of the secret prefix, \
                 their COUNT is too, and the page total IS that count over nine",
                w.number,
                w.candidates.len(),
                w.page % w.pages() + 1,
                w.pages(),
                w.complete
            ),
            slug,
            &f,
        );
    }

    match (ui::WordEntry {
        number: 3,
        partial: "ACT",
        previous: Some("ABILITY"),
        candidates: "ABCDEFGHIJKLMNOPQRSTUVWXYZA",
        page: 0,
        complete: true,
    })
    .render(&mut f, &mut Counter(0))
    {
        Ok(()) => panic!("27 candidate letters accepted"),
        Err(e) => out.refused(
            "6 word entry — 27 candidate letters",
            "MAX_CANDIDATE_LETTERS is the alphabet: a longer list would page to a \
             page this screen cannot show, i.e. letters with no key",
            "wordentry-over",
            &format!("WordEntry::render -> Err(Unrenderable::{e:?})"),
        ),
    }

    // --- screen 7: backup check quiz --------------------------------------
    //
    // The WORD form takes the RNG on the same mandatory terms as the backup
    // display, because CheckBackup draws all 25 words and the share index — the
    // same decrypted phase DisplayBackup uses, over 26 screens instead of 8.
    ui::backup_quiz_word(&mut f, 7, ["account", "accuse", "acid"], &mut Counter(0))
        .expect("renderable");
    out.emit(
        "7 backup check quiz — the WORD question (all three rows noised)",
        "word 7, options [account, accuse, acid]. The distractors must be drawn \
         UNIFORMLY from rng::Entropy: upstream's nearest-neighbour rule is a pure \
         function of the answer and identifies it for 1,288 of 2,048 words",
        "quiz-word",
        &f,
    );
    ui::backup_quiz(&mut f, "index was?", ["1", "2", "3"], None);
    out.emit(
        "7 backup check quiz — the SHARE-INDEX question, nothing selected",
        "options [1, 2, 3], selected None. No noise and no RNG: an index is not the \
         secret, it is what makes the secret restorable. Draw the three uniformly \
         from 1..=n — upstream's correct-1/correct/correct+1 leaves the true index \
         the median of three consecutive integers, every time",
        "quiz-none",
        &f,
    );
    ui::backup_quiz(&mut f, "index was?", ["1", "2", "3"], Some(1));
    out.emit(
        "7 backup check quiz — option 2 selected (inverse video)",
        "same, selected Some(1)",
        "quiz-selected",
        &f,
    );
    ui::backup_quiz(&mut f, "word 7 was?", ["account", "accuse", "acid"], None);
    out.emit(
        "7 backup check quiz — a WORD handed to the RNG-free form is MASKED",
        "same options as the word screen above. This form cannot noise a row \
         because it has no RNG, so it redacts rather than drawing an unprotected \
         word; the mask is fixed width, so it does not leak the length either",
        "quiz-masked",
        &f,
    );

    // --- screen 8: address verification (SECURITY) ------------------------
    for (label, slug, address, path, seed) in [
        ("ordinary P2TR (62 chars)", "addr-p2tr", P2TR, "m/84h/0h/0h/0/0", 0u32),
        ("P2WPKH (42 chars)", "addr-p2wpkh", P2WPKH, "m/84h/0h/0h/0/7", 1),
        ("base58 P2PKH (34 chars)", "addr-p2pkh", P2PKH, "m/44h/0h/0h/0/0", 2),
        (
            "longest legal segwit (74 chars)",
            "addr-longest",
            long.as_str(),
            "m/86h/0h/0h/0/4294967295",
            3,
        ),
        (
            "exactly at the 80-char budget",
            "addr-atlimit",
            at_limit.as_str(),
            "m/86h/0h/0h/1/12345678901234",
            4,
        ),
    ] {
        match ui::address_verify(&mut f, address, path, seed) {
            Ok(()) => out.emit(
                &format!("8 address verification — {label}"),
                &format!(
                    "address {address} ({} chars), path {path:?} (coordinator-supplied, clipped \
                     at 16 cols), highlight seed {seed}",
                    address.chars().count()
                ),
                slug,
                &f,
            ),
            Err(e) => panic!("{label}: address_verify refused a displayable address: {e:?}"),
        }
    }

    match ui::address_verify(&mut f, &over_limit, "m/86h/0h/0h/0/0", 5) {
        Ok(()) => panic!("81-char address accepted"),
        Err(e) => out.refused(
            "8 address verification — 81 chars, one over the budget",
            "a truncated address that looks complete is upstream's chunk_address bug \
             (address_display.rs:88-96 drops the tail past 72 chars)",
            "addr-over",
            &format!("address_verify -> Err(Unrenderable::{e:?})"),
        ),
    }

    // --- screen 9: PIN (SECURITY: the attempts figure is the only warning
    //     before an irreversible act) ---------------------------------------
    //
    // One drawn confirm digit for the whole block, from `Counter` below.
    let confirm = ConfirmDigit::draw(&mut Counter(0));
    //
    // `attempts_left` here is what SE1's attempt struct would have reported; 13
    // is `MAX_TARGET_ATTEMPTS` (`stm32/mk4-bootloader/pins.c:28`). Note that 1
    // and 0 do NOT produce an entry screen at all — `pin_entry` diverts on the
    // figure itself, so look at what it drew, not at what was asked for.
    for (words, label, first) in [
        (["abandon", "absurd"], "first time (record them)", true),
        (["abandon", "absurd"], "login (recognise them)", false),
        (["acoustic", "abstract"], "8-char words = exactly the panel at 2x", false),
    ] {
        match ui::pin_words(&mut f, first, words) {
            Ok(()) => out.emit(
                &format!("9 PIN anti-phishing words — {label}"),
                &format!("words {words:?}, first_time {first} (derived ABOVE this seam: ui carries no wordlist)"),
                &format!("pin-words-{}", if first { "learn" } else { "check" }),
                &f,
            ),
            Err(e) => panic!("{label}: pin_words refused a legal word pair: {e:?}"),
        }
    }
    match ui::pin_words(&mut f, false, ["abandon", "abilities"]) {
        Ok(()) => panic!("a 9-char anti-phishing word was accepted"),
        Err(e) => out.refused(
            "9 PIN anti-phishing words — 9-char word",
            "a word wider than 8 chars would be TRUNCATED at 2x, and a shortened \
             anti-phishing word is one the user cannot tell from the right one",
            "pin-words-over",
            &format!("pin_words -> Err(Unrenderable::{e:?})"),
        ),
    }

    for (prompt, typed, left, label, slug) in [
        (PinPrompt::Prefix, "", 13u64, "prefix, nothing typed yet, 13 left", "pin-prefix-empty"),
        (PinPrompt::Prefix, "12", 13, "prefix, 2 digits", "pin-prefix-2"),
        (PinPrompt::Suffix, "123456", 13, "suffix, field full (6 digits)", "pin-suffix-full"),
        (PinPrompt::Suffix, "1234", 3, "suffix, 3 left", "pin-suffix-3"),
        (PinPrompt::Suffix, "1234", 2, "suffix, 2 left (last ordinary screen)", "pin-suffix-2"),
        (PinPrompt::Suffix, "1234", 1, "asked with 1 left -> LAST TRY, PIN un-masked, confirm-digit gate", "pin-lasttry"),
        (PinPrompt::Suffix, "1234", 0, "asked with 0 left -> terminal screen, no key offered", "pin-bricked"),
        (PinPrompt::Set, "12", 13, "first-time set", "pin-set"),
        (PinPrompt::Repeat, "1234", 13, "first-time set, confirm pass", "pin-repeat"),
    ] {
        match ui::pin_entry(&mut f, prompt, typed, left, confirm) {
            Ok(drew) => out.emit(
                &format!("9 PIN entry — {label}  [drew {drew:?}]"),
                &format!(
                    "{prompt:?}, {} digit(s) typed, attempts_left {left} (from SE1, never \
                     computed here), confirm digit {}",
                    typed.chars().count(),
                    confirm.as_str()
                ),
                slug,
                &f,
            ),
            Err(e) => panic!("{label}: pin_entry refused: {e:?}"),
        }
    }
    match ui::pin_entry(&mut f, PinPrompt::Prefix, "1234567", 13, confirm) {
        Ok(s) => panic!("a {}-digit PIN was accepted and drawn as {s:?}", 7),
        Err(e) => out.refused(
            &format!("9 PIN entry — 7 digits, one over MAX_PIN_PART_LEN ({MAX_PIN_PART_LEN})"),
            "a star run that stops growing is a lie about what was typed",
            "pin-over",
            &format!("pin_entry -> Err(Unrenderable::{e:?})"),
        ),
    }

    for (left, fails, label, slug) in [
        (12u64, 1u64, "12 left", "pin-wrong-12"),
        (2, 11, "2 left", "pin-wrong-2"),
        (1, 12, "1 left — the next one ends the device", "pin-wrong-1"),
        (13, 99, "num_fails 99, which is pins.c:478's SENTINEL not a count", "pin-wrong-sentinel"),
        (u64::MAX, u64::MAX, "nonsense from the attempt struct: too wide for 2x, so it drops to 1x rather than being shortened into a plausible small number", "pin-wrong-absurd"),
    ] {
        ui::pin_wrong(&mut f, left, fails);
        out.emit(
            &format!("9 PIN wrong — {label}"),
            &format!("attempts_left {left}, num_fails {fails} (both verbatim from SE1)"),
            slug,
            &f,
        );
    }

    ui::pin_checking(&mut f);
    out.emit(
        "9 PIN checking — the screen that replaces a countdown this silicon has no delay for",
        "no input: calc_delay_required returns a hard 0 on the 608 (pins.c:518-522); the \
         rate limit IS the ~1.4 s KDF, and the callgate blocks the core so this cannot animate",
        "pin-checking",
        &f,
    );

    ui::pin_mismatch(&mut f);
    out.emit(
        "9 PIN mismatch — first-time set, the two entries differed",
        "no input; says NO PIN WAS SET, because a user who thinks one was is locked out of a \
         unit that has none",
        "pin-mismatch",
        &f,
    );

    ui::pin_bricked(&mut f);
    out.emit(
        "9 PIN bricked — the terminal screen, drawn directly",
        "no input; identical to what pin_entry draws at 0 attempts",
        "pin-bricked-direct",
        &f,
    );

    out.finish();
}

/// A fixed-seed LCG masquerading as an RNG, so the catalogue's BMPs stay
/// byte-stable (see the module header's DETERMINISTIC note).
///
/// Deliberately worse than the hardware RNG and deliberately NOT a shortcut in
/// `ui.rs`: a public const `ConfirmDigit` would be one a script could hardcode,
/// which is the exact property the randomised digit exists to deny. The bad
/// double lives here, in a host-only example, where it cannot reach firmware.
///
/// Not a constant and not a counter, and both rejections are about what the
/// artefacts then SHOW. `Frame::mark_sensitive` draws one run length per scanline,
/// so a constant draws a straight edge and a counter draws a monotonic wedge —
/// either would put a picture of a *pattern* in front of a reviewer whose job is
/// to see that the margin is ragged and clear of the words. The first value out is
/// still 0, so `ConfirmDigit::draw` picks the same digit it always did.
struct Counter(u32);

impl rand_core::RngCore for Counter {
    fn next_u32(&mut self) -> u32 {
        let v = self.0;
        // Numerical Recipes' constants; any full-period LCG would do.
        self.0 = self.0.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
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

/// Emit every page of one sign-approval transaction, or the refusal it produced.
fn sign_case(out: &mut Out, label: &str, slug: &str, rs: &[Recipient<'_>], fee: u64) {
    let input = describe(rs, fee);
    let pages = match SignPages::new(rs, fee) {
        Ok(p) => p,
        Err(e) => {
            return out.refused(
                &format!("3 sign approval — {label}"),
                &input,
                slug,
                &format!("SignPages::new -> Err(Unrenderable::{e:?})"),
            );
        }
    };
    let n = pages.len();
    let mut frame = Frame::new();
    for i in 0..n {
        let kind = page_name(pages.page(i));
        // `false` here is not "past the end" — `page(i)` is Some for i < len, so
        // it means the page could not be drawn IN FULL and the frame now holds
        // `ui::refusal`. Label it as such; never present it as a normal page.
        let drawn = pages.render(i, &mut frame);
        let mark = if drawn { "" } else { "  REFUSED (render returned false)" };
        out.emit(
            &format!("3 sign approval — {label} — page {p}/{n} {kind}{mark}", p = i + 1),
            &input,
            &format!("{slug}-p{:02}", i + 1),
            &frame,
        );
    }
    assert!(
        pages.page(n).is_none(),
        "{label}: page({n}) must be None past the end"
    );
    assert!(
        matches!(pages.page(n - 1), Some(SignPage::Confirm)),
        "{label}: Confirm must be structurally last, so no page can be skipped"
    );
}

fn page_name(page: Option<SignPage<'_>>) -> &'static str {
    match page {
        Some(SignPage::SelfSend) => "[SelfSend]",
        Some(SignPage::Amount { .. }) => "[Amount]",
        Some(SignPage::Address { .. }) => "[Address]",
        Some(SignPage::HighFeeWarning { .. }) => "[HighFeeWarning]",
        Some(SignPage::Fee { .. }) => "[Fee: coordinator-supplied]",
        Some(SignPage::Confirm) => "[Confirm]",
        None => "[none]",
    }
}

/// The transaction, in one label. Capped at 4 recipients so a 17-recipient run
/// stays readable; the amounts and addresses are on the screens themselves.
fn describe(rs: &[Recipient<'_>], fee: u64) -> String {
    let sent: u128 = rs.iter().map(|r| r.sats as u128).sum();
    let mut s = format!(
        "{} recipient(s), fee {fee} sats, sent {sent} sats{}",
        rs.len(),
        if fee as u128 > ui::HIGH_FEE_SATS as u128
            || (sent > 0 && fee as u128 * 100 > sent * ui::HIGH_FEE_PERCENT as u128)
        {
            "  [high fee]"
        } else {
            ""
        }
    );
    for (i, r) in rs.iter().take(4).enumerate() {
        let _ = write!(
            s,
            "\n        #{}: {} sats -> {} ({} chars)",
            i + 1,
            r.sats,
            r.address,
            r.address.chars().count()
        );
    }
    if rs.len() > 4 {
        let _ = write!(s, "\n        ... and {} more", rs.len() - 4);
    }
    s
}

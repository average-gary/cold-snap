//! A terminal simulator for the §4.2 screens: press keys, see the frames the
//! device would push to the SSD1306.
//!
//! WHY IT IS HERE AND WHAT IT IS FOR. Phase 5's screens had exactly two ways to
//! be looked at: `hal/examples/ui_render.rs` (still images, one screen per run,
//! no navigation, no state) and a flashed device (nothing is flashed, and at
//! RDP=2 installation is one-way). Neither lets anyone *walk* a 36-page sign
//! approval and see whether page 19 is legible. This does.
//!
//! WHAT IS REAL, and it is the whole point:
//!
//!  - Every pixel comes from `coldsnap_hal::ui`. Nothing here draws; it calls
//!    `standby` / `keygen_check` / `SignPages::render` / `BackupPages::render` /
//!    `EntryPages::render` / `backup_quiz` / `address_verify` / `refusal` and
//!    prints the resulting 1,024-byte MONO_VLSB frame. A layout bug shows up here
//!    as a layout bug.
//!  - Every sign-approval page set comes from the shipped consent gate,
//!    `coldsnap_firmware::sign_consent`, fed a real `bitcoin`
//!    `TransactionTemplate` through a real `CheckedSignTask`. The page
//!    decomposition, the change filter, the high-fee thresholds and — crucially —
//!    the REFUSALS are computed by the code the device runs. This sim cannot show
//!    you a screen the device would not show, and cannot hide a refusal the device
//!    would make: see the startup assertion.
//!  - Scene "session" opens a real `Session` (flash-backed identity on `FakeFlash`
//!    at the shipped geometry, flash-backed nonce slots) and feeds it real
//!    `CoordinatorSendBody` messages, then renders exactly what `main.rs`'s loop
//!    renders for the result: `ui::refusal` on `Err(Fault::Refused(_))`, and
//!    NOTHING on any other fault (`main.rs:600-607`). The device id on the standby
//!    frame is that session's real `DeviceId`.
//!
//! WHAT IS SYNTHETIC, stated because a sim that blurs this is worse than none:
//! the keygen-check and test-message scenes take their parameters (t-of-n, the
//! 4-byte session-hash code, the message) from fixtures, not from a live
//! `KeyGenPhase3` / `SignatureRequest`. Those phases cannot be constructed without
//! a coordinator, and the harness that does have one is `hostcheck` + the `stub`
//! example. So the *screen* is real and the *prompt that chose it* is not; the two
//! consent screens' `Session::confirm` call is therefore described, not performed.
//! `hostcheck` is what exercises the wire; this is what exercises the glass.
//!
//! THE KEYPAD. Mk4 has a 4x3 membrane pad — `1 2 3 / 4 5 6 / 7 8 9 / x 0 y`, no
//! arrows (`coldcard-firmware/unix/simulator.py:499-511`; keyboard arrows are
//! remapped onto `9`/`7`/`8`/`5` at `:1035-1037`). Paging is `5`/`8` because
//! PLAN.md §4.2 says so, `1`/`y` is OK and `x` is cancel because that is what the
//! `ui` hint rows already say. There is NO keypad driver in this tree
//! (`firmware/src/main.rs:81-85`), so the mapping below is this file's proposal,
//! not a port of shipped code.
//!
//! Run it (TERMINAL front-end — no install, works over ssh):
//!   cargo run --target aarch64-apple-darwin -p coldsnap_firmware \
//!       --features coldsnap_hal/test-seam --example simulator
//! One key per line (the terminal stays line-buffered on purpose, so a scripted
//! run is just `printf '3\n8\n8\n1\nq\n' | cargo run ...`).
//!
//! WINDOW front-end — the SAME scenes and the SAME `Frame`s, in Coldcard's own
//! SDL simulator window, with a clickable Mk4 keypad:
//!   tools/sim-window.sh
//! That script runs `coldcard-firmware/unix/simulator.py` from a scratch
//! directory with this binary standing in for `coldcard-mpy`, so the parent hands
//! us four inherited pipe fds as decimal argv strings after its `-i <sim_boot.py>`
//! (`unix/simulator.py:926`). When those fds are on argv this program pushes
//! `Frame::as_bytes()` down the display pipe and reads keypad bytes back instead
//! of drawing ASCII — see [`sim_fds`], [`push`] and [`gui`]. No SSD1306 is
//! involved either way: the window is a decoder for the same 1,024 bytes the
//! terminal front-end prints, and every "DOES NOT PROVE" line below still holds.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufRead, Read, Write};
use std::os::fd::FromRawFd;

use bitcoin::{Amount, Network, OutPoint, ScriptBuf, TxOut, WitnessProgram, WitnessVersion};
use coldsnap_firmware::{sign_consent, DebugFlash, Fault, Outbox, Session};
use coldsnap_hal::comms::CoordinatorSendBody;
use coldsnap_hal::flash::fake::FakeFlash;
use coldsnap_hal::flash::ERASE_SIZE;
use coldsnap_hal::rng::{mix_sources, Entropy, ProvenSeed, SE1_BYTES, SE2_BYTES, TRNG_BYTES};
use coldsnap_hal::ui::{self, Frame};
use coldsnap_hal::{identity, memmap};
use frostsnap_core::bitcoin_transaction::{PushInput, TransactionTemplate};
use frostsnap_core::message::screen_verify::ScreenVerify;
use frostsnap_core::message::{CoordinatorRestoration, CoordinatorToDeviceMessage};
use frostsnap_core::{CheckedSignTask, EnterPhysicalId, MasterAppkey, SignTask};

/// One thing a user can look at: a title, a note about how it was produced, and
/// the frames, in order.
///
/// `refusal` is `Some(why)` when the fixture was REFUSED by real code. It is a
/// separate field rather than a flavour of note so that the loop can make the
/// refusal impossible to mistake for a missing screen — the failure mode that
/// gets "fixed" into a fail-open later.
struct Scene {
    name: String,
    note: String,
    pages: Vec<Frame>,
    refusal: Option<String>,
}

impl Scene {
    fn shown(name: &str, note: &str, pages: Vec<Frame>) -> Self {
        Scene {
            name: name.into(),
            note: note.into(),
            pages,
            refusal: None,
        }
    }

    /// The device said no. One frame — `ui::refusal`, the same one `main.rs` draws
    /// on `Err(Fault::Refused(_))` — and the reason, from the real error value.
    fn refused(name: &str, note: &str, why: String) -> Self {
        let mut f = Frame::new();
        ui::refusal(&mut f);
        Scene {
            name: name.into(),
            note: note.into(),
            pages: vec![f],
            refusal: Some(why),
        }
    }
}

/// One frame from a `FnOnce(&mut Frame)`. Every screen in `hal::ui` draws into a
/// borrowed frame, so this is the whole adapter.
fn frame(draw: impl FnOnce(&mut Frame)) -> Frame {
    let mut f = Frame::new();
    draw(&mut f);
    f
}

// ---------------------------------------------------------------------------
// rendering: 1,024 MONO_VLSB bytes -> terminal
// ---------------------------------------------------------------------------

/// Two pixel rows per terminal row via half-block glyphs, so a 128x64 frame is 32
/// lines and a keypress can redraw it without scrolling the screen away.
///
/// Deliberately reads back through the public `Frame::pixel` — the same accessor
/// `hal/examples/ui_render.rs:129` uses — rather than decoding glyphs out of the
/// text layer. Decoding would agree with the font table even if the blit were
/// wrong; this shows what the panel would be handed.
fn art(f: &Frame) -> String {
    let edge = format!("+{}+\n", "-".repeat(ui::WIDTH));
    let mut s = String::with_capacity((ui::HEIGHT / 2 + 2) * (ui::WIDTH + 4));
    s.push_str(&edge);
    for y in (0..ui::HEIGHT).step_by(2) {
        s.push('|');
        for x in 0..ui::WIDTH {
            s.push(match (f.pixel(x, y), f.pixel(x, y + 1)) {
                (true, true) => '\u{2588}',
                (true, false) => '\u{2580}',
                (false, true) => '\u{2584}',
                (false, false) => ' ',
            });
        }
        s.push_str("|\n");
    }
    s.push_str(&edge);
    s
}

// ---------------------------------------------------------------------------
// rendering: 1,024 MONO_VLSB bytes -> Coldcard's simulator window
// ---------------------------------------------------------------------------

/// THE ONLY code that may touch the display fd.
///
/// One frame is ONE `write_all` of exactly [`ui::FRAME_BYTES`], no header and no
/// concatenation, because the parent does `buf = read(...); buf = buf[-1024:];
/// assert len(buf) == 1024` (`unix/simulator.py:461-467`). Coalescing whole frames
/// is fine and intended; a split frame trips that assert, and a stray byte sails
/// past it and renders a byte-rotated screen. Never wrap this fd in a `BufWriter`
/// — an 8 KiB buffer would swallow eight frames and freeze the window.
fn push(out: &mut impl Write, f: &Frame) -> std::io::Result<()> {
    // A single `write`, NOT `write_all`, so a short write becomes OBSERVABLE instead
    // of being silently papered over.
    //
    // macOS `PIPE_BUF` is 512 and a frame is 1,024, so writing a whole frame to a pipe
    // is NOT atomic: if the parent has fallen behind and the buffer is nearly full, the
    // kernel takes a prefix and returns a short count. `write_all` would then loop and
    // finish the frame in a second write — exactly the split that fires the parent's
    // `assert len(buf) == 1024` and kills the window with a Python traceback that says
    // nothing about us. `tools/pixel-check.py` reproduces that split and confirms their
    // assert is what fires.
    //
    // This is inherent to their protocol and their own `coldcard-mpy` shares the
    // exposure, so there is nothing here to FIX — only something to make legible. The
    // frame still MUST be completed: stopping mid-frame would leave every later frame
    // offset by the remainder and render every screen as garbage. So complete it, then
    // say so loudly, because the alternative is a crash whose cause is invisible.
    //
    // NOT covered by a test, and deliberately so: reverting this to `write_all` changes
    // no observable behaviour on a drained pipe, so no assertion can distinguish them.
    // It is an observability change, not a behavioural one. In practice the parent
    // drains up to 1,024,000 bytes non-blocking on every SDL event-loop pass and we
    // write only on a state change, so the buffer should never approach full. If this
    // warning ever appears, that assumption was wrong.
    let bytes = f.as_bytes();
    let n = out.write(bytes)?;
    if n != bytes.len() {
        eprintln!(
            "simulator: WARNING short frame write ({n} of {} bytes). The display pipe \
             was nearly full, so this frame is being completed in a second write; the \
             parent asserts a 1,024-byte read and may abort. That is their protocol's \
             non-atomicity above PIPE_BUF (512 on macOS), not a corrupt frame.",
            bytes.len()
        );
        out.write_all(&bytes[n..])?;
    }
    Ok(())
}

/// A `Write` that remembers the length of every individual `write`, so the
/// startup self-check can prove the *transport* discipline and not just the
/// pixels. See [`check_display_stream`].
#[derive(Default)]
struct WireLog {
    bytes: Vec<u8>,
    writes: Vec<usize>,
}

impl Write for WireLog {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.writes.push(buf.len());
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The one thing the gated `hal` tests do NOT cover: what actually lands on the
/// display fd.
///
/// `hal/src/ui.rs:1583` (`mono_vlsb_corner_pixels_map_to_exact_bytes`) already
/// pins the MONO_VLSB mapping itself and rejects a transpose, a reversed bit
/// order, row-major, an off-by-one page and inversion, so this does not re-test
/// geometry. It tests the pipe contract:
///
///  1. every frame is exactly one write of exactly `FRAME_BYTES` — a split frame
///     is the parent's `AssertionError`, whose traceback escapes before
///     `xterm.kill()` and orphans us;
///  2. no extra bytes ever enter the stream — one stray newline PASSES the
///     parent's length assert and silently renders a rotated screen;
///  3. the bytes decode, through a verbatim transcription of the parent's own
///     decoder (`unix/simulator.py:470-480`), to the pixels `Frame::pixel` reports
///     — so no transform can sneak in between `ui` and the wire.
fn check_display_stream(scenes: &[Scene]) {
    let menu = menu_frame(scenes, 0);
    let note = note_frame("self-check");
    let all: Vec<&Frame> = scenes
        .iter()
        .flat_map(|s| s.pages.iter())
        .chain([&menu, &note])
        .collect();

    let mut wire = WireLog::default();
    for f in &all {
        push(&mut wire, f).expect("a Vec never fails to write");
    }

    assert_eq!(
        wire.writes,
        vec![ui::FRAME_BYTES; all.len()],
        "every redraw must be ONE write of exactly {} bytes",
        ui::FRAME_BYTES
    );
    assert_eq!(wire.bytes.len(), all.len() * ui::FRAME_BYTES);

    for (i, f) in all.iter().enumerate() {
        let buf = &wire.bytes[i * ui::FRAME_BYTES..(i + 1) * ui::FRAME_BYTES];
        // unix/simulator.py:470-480, transcribed:
        //   for y in range(0, 64, 8):
        //     val = buf[(y * 128 // 8) + x]; mask = 0x01
        //     for i in range(8): pixel[y+i][x] = fg if (val & mask) else bg; mask <<= 1
        for y in (0..ui::HEIGHT).step_by(ui::CELL) {
            for x in 0..ui::WIDTH {
                let val = buf[(y * ui::WIDTH / 8) + x];
                for bit in 0..ui::CELL {
                    assert_eq!(
                        val & (1 << bit) != 0,
                        f.pixel(x, y + bit),
                        "frame {i}: the parent would light ({x},{}) differently",
                        y + bit
                    );
                }
            }
        }
    }
}

/// How many scenes one 128x64 menu screen lists. 16 columns x 8 rows total: a
/// header, five entries, two legend rows.
const MENU_ROWS: usize = 5;

/// The scene list, on the panel. A window has no scrollback, so the menu — and
/// the key legend — has to be a frame like everything else.
fn menu_frame(scenes: &[Scene], mpage: usize) -> Frame {
    let mut f = Frame::new();
    let pages = scenes.len().div_ceil(MENU_ROWS);
    f.text_inverted(
        0,
        0,
        &format!("{:<width$}", format!("SCENES {}/{pages}", mpage + 1), width = ui::COLS),
    );
    for (n, sc) in scenes.iter().skip(mpage * MENU_ROWS).take(MENU_ROWS).enumerate() {
        let mark = if sc.refusal.is_some() { '!' } else { ' ' };
        let name: String = sc.name.chars().take(ui::COLS - 2).collect();
        f.text(0, 1 + n, &format!("{}{mark}{name}", n + 1));
    }
    f.text(0, 6, "1-5 open 8/5 pg");
    f.text(0, 7, "y ok x back !=no");
    f
}

/// A simulator message (`last page`, `CONFIRMED`, `REFUSED ...`) as its own
/// screen. Deliberately NOT an overlay: the whole point of this program is that a
/// scene's frame is byte-for-byte what `hal::ui` drew, so nothing of ours is ever
/// composited onto one. The inverted header says whose screen this is.
fn note_frame(msg: &str) -> Frame {
    let mut f = Frame::new();
    f.text_inverted(0, 0, &format!("{:<width$}", "-- SIM NOTE --", width = ui::COLS));
    f.wrap(1, ui::ROWS - 1, msg);
    f
}

/// The four inherited pipe fds, POSITIONALLY: the four args after `-i
/// <sim_boot.py>` (`unix/simulator.py:926`), in the order
/// `display_w, numpad_r, led_w, data_r` (`:865`). `None` means "not launched by
/// simulator.py" — i.e. the terminal front-end.
///
/// Do NOT scan for numeric args instead: `--metal`/`--scan` append more of them
/// (`:884`, `:896`), user args are spliced in verbatim, the fds are not ascending,
/// and `--headless` passes the literal string `-1` for the numpad (`:859`). A
/// misassignment is silent — frames written to `led_w` are read two bytes at a
/// time as `[mask, state]` and just flicker the LED while the screen stays blank.
fn sim_fds() -> Option<[i32; 4]> {
    let args: Vec<String> = std::env::args().collect();
    // The FIRST `-i` is always the injected one at index 3; a user `-i` can follow.
    let i = args.iter().position(|a| a == "-i")?;
    let four: Vec<i32> = args
        .get(i + 2..i + 6)
        .unwrap_or_default()
        .iter()
        .filter_map(|a| a.parse().ok())
        .collect();
    match four[..] {
        [d, n, l, x] if d >= 0 && n >= 0 => Some([d, n, l, x]),
        _ => {
            eprintln!(
                "simulator: `-i` is on argv but the four fds after it are not two-plus \
                 usable pipe fds: {:?}\n\
                 This program only speaks simulator.py's protocol when launched by \
                 tools/sim-window.sh (which passes --mk4, never --headless: headless \
                 sends the display to /dev/null and the numpad as \"-1\").",
                &args[1..]
            );
            std::process::exit(2);
        }
    }
}

/// The window front-end. Same scenes, same `Frame`s, same [`apply_key`]; the only
/// difference from the terminal loop is where the bytes go and where the keys come
/// from.
fn gui(scenes: &[Scene], [display, numpad, led, _data]: [i32; 4], refused: &str) {
    // stdout is /dev/null under the launcher (`unix/simulator.py:974`), so the
    // header and the self-check result go to stderr or nowhere.
    eprintln!("{BANNER}");
    eprintln!("Refusals confirmed by real code on startup: {refused}");
    eprintln!("Display stream self-check passed: every frame one write of 1024 B.\n");

    // SAFETY: simulator.py created these pipes and cleared CLOEXEC for them via
    // `pass_fds`; nothing else in this process has them.
    let mut disp = unsafe { File::from_raw_fd(display) };
    let mut pad = unsafe { File::from_raw_fd(numpad) };
    if led >= 0 {
        // `[mask, state]` (`unix/variant/machine.py:39`), the one write their child
        // also does (`unix/variant/ckcc.py:19`). Without it the window's genuine
        // LED stays on the red "unsafe" sprite. Dropping the fd afterwards is fine:
        // the parent holds its own copy of the write end, so it sees no EOF.
        let _ = unsafe { File::from_raw_fd(led) }.write_all(&[0xff, 0x01]);
    }

    let mut here: Option<usize> = None;
    let mut page = 0usize;
    let mut mpage = 0usize;
    let mut msg = String::new();
    let mut keys: VecDeque<char> = VecDeque::new();

    loop {
        let shown = if !msg.is_empty() {
            note_frame(&msg)
        } else if let Some(i) = here {
            scenes[i].pages[page].clone()
        } else {
            menu_frame(scenes, mpage)
        };
        if let Err(e) = push(&mut disp, &shown) {
            // EPIPE: the parent is gone (it dies on its own length assert before it
            // gets to `xterm.kill()`, so this is the other half of the no-orphan
            // rule). Rust ignores SIGPIPE, so we have to notice.
            eprintln!("display pipe closed ({e}) -- parent gone, exiting.");
            return;
        }

        // Blocking read, ALWAYS, even with nothing to do: the parent writes keys
        // from inside its SDL event loop on a blocking unbuffered handle
        // (`:981`,`:1000`), so a child that stops draining eventually freezes the
        // window with no error anywhere.
        while keys.is_empty() {
            let mut buf = [0u8; 64];
            match pad.read(&mut buf) {
                // The parent exited (ctrl-Q / window closed) and its numpad_w copy
                // went with it. This is the normal quit path.
                Ok(0) => {
                    eprintln!("numpad EOF -- window closed. Nothing was signed, nothing was flashed.");
                    return;
                }
                Err(e) => {
                    eprintln!("numpad read failed ({e}) -- exiting.");
                    return;
                }
                // One read can carry several bytes: a mouse click delivers the key
                // and the all-up `b"\0"` back to back, and ctrl-M writes 30x b"y\n"
                // (`:1070`). Anything not on the Mk4 pad -- `\0`, `\n` -- is not a
                // keypress.
                Ok(n) => keys.extend(
                    buf[..n]
                        .iter()
                        .filter(|b| b"0123456789xy".contains(b))
                        .map(|b| *b as char),
                ),
            }
        }
        let k = keys.pop_front().expect("refilled above");
        msg.clear();

        // On the menu, digits 1-5 pick from the group the menu is SHOWING, and
        // 8/5 page the list; `apply_key` only knows absolute scene numbers, so
        // translate here rather than teaching it about the window.
        let owned;
        let key: &str = if here.is_none() {
            match k {
                '8' | '9' if (mpage + 1) * MENU_ROWS < scenes.len() => {
                    mpage += 1;
                    continue;
                }
                '5' | '7' if mpage > 0 => {
                    mpage -= 1;
                    continue;
                }
                '1'..='5' if mpage * MENU_ROWS + (k as usize - '0' as usize) <= scenes.len() => {
                    owned = (mpage * MENU_ROWS + (k as usize - '0' as usize)).to_string();
                    &owned
                }
                _ => {
                    msg = format!("no scene on key {k} of menu page {}", mpage + 1);
                    continue;
                }
            }
        } else {
            owned = k.to_string();
            &owned
        };
        // `q` is not on a Mk4 pad, so this never returns false; closing the window
        // is the way out.
        apply_key(scenes, &mut here, &mut page, &mut msg, key);

        match here {
            Some(i) => eprintln!(
                "[{k}] {} -- page {}/{}{}",
                scenes[i].name,
                page + 1,
                scenes[i].pages.len(),
                scenes[i]
                    .refusal
                    .as_deref()
                    .map(|w| format!("  REFUSED: {w}"))
                    .unwrap_or_default()
            ),
            None => eprintln!("[{k}] menu page {}", mpage + 1),
        }
        if !msg.is_empty() {
            eprintln!("    {msg}");
        }
    }
}

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

/// A segwit output script of the given version. `V1` with 32 bytes is P2TR (62
/// chars); `V2` with 40 bytes is the LONGEST address bech32m admits at all — 74
/// chars — and it is legal, so a device that cannot show it must refuse rather
/// than truncate.
fn witness_spk(version: WitnessVersion, program: &[u8]) -> ScriptBuf {
    ScriptBuf::new_witness_program(&WitnessProgram::new(version, program).expect("legal program"))
}

fn p2tr(seed: u8) -> ScriptBuf {
    witness_spk(WitnessVersion::V1, &[seed; 32])
}

/// A `CheckedSignTask` for a transaction with one foreign input worth
/// `outputs + fee`, so `fee()` computes to exactly `fee`.
///
/// `master_appkey` is a placeholder: `sign_consent` reads only `inner`, and
/// nothing here has an owned input to bind. Change filtering is therefore not
/// exercised by these fixtures — every output below is foreign, which is the
/// hostile direction anyway (more pages, not fewer).
fn bitcoin_task(outputs: Vec<(ScriptBuf, u64)>, fee: u64) -> CheckedSignTask {
    let total: u64 = outputs.iter().map(|(_, v)| *v).sum::<u64>() + fee;
    let mut t = TransactionTemplate::new();
    let prev = TxOut {
        value: Amount::from_sat(total),
        script_pubkey: p2tr(0xaa),
    };
    t.push_foreign_input(PushInput::spend_outpoint(&prev, OutPoint::null()));
    for (script_pubkey, sats) in outputs {
        t.push_foreign_output(TxOut {
            value: Amount::from_sat(sats),
            script_pubkey,
        });
    }
    CheckedSignTask {
        master_appkey: MasterAppkey([0u8; 65]),
        inner: SignTask::BitcoinTransaction {
            tx_template: t,
            network: Network::Bitcoin,
        },
    }
}

/// Build a sign-approval scene THROUGH THE SHIPPED GATE.
///
/// `sign_consent` either hands back a validated `SignPages` — every recipient
/// present, nothing dropped to make it fit — or a `Refusal`. Both outcomes become
/// a scene, so a fixture that stops refusing becomes visible instead of silently
/// looking fine.
fn sign_scene(name: &str, note: &str, task: &CheckedSignTask) -> Scene {
    let render_all = |pages: &ui::SignPages<'_>| {
        (0..pages.len())
            .map(|i| {
                frame(|f| {
                    pages.render(i, f);
                })
            })
            .collect::<Vec<_>>()
    };
    match sign_consent(task, render_all) {
        Ok(Some(pages)) => {
            let note = format!("{note} -- {} pages from sign_consent", pages.len());
            Scene::shown(name, &note, pages)
        }
        // Not a Bitcoin task: `sign_consent` has nothing to say, and inventing
        // consent for it is exactly what its docs forbid.
        Ok(None) => Scene::refused(
            name,
            note,
            "sign_consent returned Ok(None): not a Bitcoin task".into(),
        ),
        Err(r) => Scene::refused(name, note, format!("Refusal::{r:?} from sign_consent")),
    }
}

const WORDS: [&str; 25] = [
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd",
    "abuse", "access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire",
    "across", "act", "action", "actor", "actress", "actual", "adapt",
];

/// A deterministic `Entropy` through the real `mix_sources` seam. Copied from
/// `examples/stub.rs:242` — same 12 lines, same reason: a `ProvenSeed` has no
/// other constructor, so even a fixture passes three `check_source` calls.
fn entropy(salt: u8) -> Entropy {
    let varying = |len: usize, salt: u8| {
        let mut b = [0u8; 32];
        let mut v = salt;
        for slot in b.iter_mut().take(len) {
            v = v.wrapping_mul(7).wrapping_add(11);
            *slot = v;
        }
        b
    };
    let t = varying(TRNG_BYTES, salt);
    let s1 = varying(SE1_BYTES, salt.wrapping_add(1));
    let s2 = varying(SE2_BYTES, salt.wrapping_add(2));
    let seed: ProvenSeed = mix_sources(&t[..TRNG_BYTES], &s1[..SE1_BYTES], &s2[..SE2_BYTES])
        .expect("three good draws must mix");
    Entropy::from_proven_seed(seed)
}

// ---------------------------------------------------------------------------
// scenes
// ---------------------------------------------------------------------------

/// The eight §4.2 screens plus the hostile fixtures, in §4.2's order.
fn ui_scenes() -> Vec<Scene> {
    let long_addr = bitcoin::Address::from_script(&witness_spk(WitnessVersion::V2, &[0x11; 40]), Network::Bitcoin)
        .expect("witness v2 has an address form")
        .to_string();
    let p2tr_addr = bitcoin::Address::from_script(&p2tr(0x33), Network::Bitcoin)
        .expect("p2tr has an address form")
        .to_string();

    let mut scenes = vec![
        // -- screen 1 -------------------------------------------------------
        Scene::shown(
            "1 standby (name: normal / 14-char max / over-long / UTF-8)",
            "the only screen that truncates hostile text silently: device_name is a \
             FixedString<14> upstream, which bounds CHARS not columns",
            vec![
                frame(|f| ui::standby(f, "coldsnap", "family funds", Some(3))),
                frame(|f| ui::standby(f, "abcdefghijklmn", "family funds", Some(7))),
                frame(|f| ui::standby(f, "MMMMMMMMMMMMMMMMMMMMMMMMMMMMMM", "no key yet", None)),
                frame(|f| ui::standby(f, "\u{dc}n\u{ef}c\u{f8}d\u{e9} w\u{e5}llet", "\u{4e2d}\u{6587} key", Some(1))),
            ],
        ),
        // -- screen 2 -------------------------------------------------------
        Scene::shown(
            "2 keygen check, the anti-MITM code (SYNTHETIC t-of-n and code)",
            "real ui::keygen_check; the 4 bytes would be the first 4 of a real \
             KeyGenPhase3 session hash, which needs a coordinator",
            vec![
                frame(|f| ui::keygen_check(f, 2, 3, [0xde, 0xad, 0xbe, 0xef], "family funds")),
                frame(|f| ui::keygen_check(f, 15, 15, [0x00, 0x0f, 0xf0, 0xff], "fifteen of fifteen")),
                frame(|f| ui::keygen_check(f, 1, 2, [0x12, 0x34, 0x56, 0x78], "\u{fc}nicode key name")),
            ],
        ),
    ];

    // -- screen 3, every page of it, all through sign_consent --------------
    scenes.push(sign_scene(
        "3a sign approval: one recipient, ordinary fee",
        "amount, address, fee, confirm",
        &bitcoin_task(vec![(p2tr(0x33), 12_345_678)], 2_000),
    ));
    scenes.push(sign_scene(
        "3b sign approval: 17 recipients (2 pages each + fee + confirm)",
        "the page count is the thing to look at",
        &bitcoin_task(
            (0..17u8).map(|i| (p2tr(i + 1), 100_000 + i as u64)).collect(),
            5_000,
        ),
    ));
    scenes.push(sign_scene(
        "3c sign approval: fee over BOTH thresholds (100k sats and 5%)",
        "a HighFeeWarning page must appear BEFORE the fee page",
        &bitcoin_task(vec![(p2tr(0x44), 1_000_000)], 250_000),
    ));
    scenes.push(sign_scene(
        "3d sign approval: longest legal bech32m address (74 chars, witness v2)",
        "62-char P2TR is the common case; this is the longest an address can be",
        &bitcoin_task(
            vec![(witness_spk(WitnessVersion::V2, &[0x11; 40]), 21_000_000)],
            1_500,
        ),
    ));
    scenes.push(sign_scene(
        "3e sign approval: self-send, no foreign recipient at all",
        "legal (a consolidation) but it must not be silent: consenting to a bare fee",
        &bitcoin_task(vec![], 4_200),
    ));
    scenes.push(sign_scene(
        "3f sign approval: UNADDRESSABLE output (bare empty script) -> REFUSAL",
        "PLAN.md 8.1 defect 12: this used to panic, which under panic=abort is a \
         reset loop reachable from a legal transaction",
        &bitcoin_task(vec![(ScriptBuf::new(), 1_000), (p2tr(0x55), 2_000)], 900),
    ));
    scenes.push(sign_scene(
        "3g sign approval: OP_RETURN output -> REFUSAL",
        "Address::from_script errs on OP_RETURN; sign_consent turns that into a refusal",
        &bitcoin_task(
            vec![(ScriptBuf::from_bytes(vec![0x6a, 0x02, 0x01, 0x02]), 0), (p2tr(0x66), 5_000)],
            1_000,
        ),
    ));
    scenes.push(sign_scene(
        "3h sign approval: 33 recipients, one over MAX_RECIPIENTS -> REFUSAL",
        "SignPages::new refuses the whole transaction rather than paginate 32 of 33",
        &bitcoin_task(
            (0..33u8).map(|i| (p2tr(i + 1), 10_000)).collect(),
            1_000,
        ),
    ));

    scenes.extend([
        // -- screen 4 -------------------------------------------------------
        Scene::shown(
            "4 test-message sign: short / 4,000 chars -> REFUSAL / UTF-8",
            "real ui::sign_test_message; on Err it draws ui::refusal, exactly as \
             main.rs's draw_prompt does -- 64 chars of 4,000 while signing all \
             4,000 is a blind signer",
            vec![
                frame(|f| {
                    if ui::sign_test_message(f, "frostsnap test").is_err() {
                        ui::refusal(f);
                    }
                }),
                frame(|f| {
                    if ui::sign_test_message(f, &"A".repeat(4_000)).is_err() {
                        ui::refusal(f);
                    }
                }),
                frame(|f| {
                    if ui::sign_test_message(f, "\u{3053}\u{3093}\u{306b}\u{3061}\u{306f} \u{20ac}5").is_err() {
                        ui::refusal(f);
                    }
                }),
            ],
        ),
    ]);

    // -- screen 5: 25 words, page by page ---------------------------------
    match ui::BackupPages::new(3, &WORDS) {
        Ok(b) => scenes.push(Scene::shown(
            "5 backup display: share index + 7 word pages",
            "8 pages: the share-index page is not optional, a backup without it is \
             unrestorable",
            (0..b.len()).map(|i| frame(|f| { b.render(i, f); })).collect(),
        )),
        Err(e) => scenes.push(Scene::refused("5 backup display", "25 good words", format!("{e:?}"))),
    }
    let short: Vec<&str> = WORDS[..24].to_vec();
    match ui::BackupPages::new(3, &short) {
        Ok(b) => scenes.push(Scene::shown(
            "5b backup display, 24 words: EXPECTED A REFUSAL",
            "a word list that is not 25 long must be refused",
            (0..b.len()).map(|i| frame(|f| { b.render(i, f); })).collect(),
        )),
        Err(e) => scenes.push(Scene::refused(
            "5b backup display: 24 words -> REFUSAL",
            "BackupPages::new requires exactly BACKUP_WORDS words of BIP39 shape",
            format!("Unrenderable::{e:?}"),
        )),
    }

    // -- screen 6: entry, page by page ------------------------------------
    let entry_pages: Vec<Frame> = (0..1 + WORDS.len())
        .map(|i| {
            let confirmed = i.saturating_sub(1).min(WORDS.len() - 1);
            let e = ui::EntryPages {
                share_index: if i == 0 { None } else { Some(3) },
                words: &WORDS[..confirmed],
                partial: if i == 0 { "1" } else { "ab" },
            };
            frame(|f| {
                e.render(i, f);
            })
        })
        .collect();
    scenes.push(Scene::shown(
        "6 backup entry: share index then 25 word pages",
        "the share-index gate is the whole state machine (EntryPages::cursor). \
         There is no keypad driver in this tree, so the typed 'partial' is a \
         fixture, not a T9 model",
        entry_pages,
    ));

    // -- screen 7 ---------------------------------------------------------
    scenes.push(Scene::shown(
        "7 backup check quiz (page = which option is selected)",
        "not security-load-bearing per 4.2; the distractors come from above this \
         seam because the wordlist is not in hal",
        (0..4usize)
            .map(|i| {
                frame(|f| {
                    ui::backup_quiz(
                        f,
                        "word 7 was?",
                        ["absorb", "absurd", "abstract"],
                        i.checked_sub(1),
                    )
                })
            })
            .collect(),
    ));

    // -- screen 8 ---------------------------------------------------------
    scenes.push(Scene::shown(
        "8 address verify: 62-char P2TR / 74-char bech32m / over-long -> REFUSAL",
        "the address is never truncated: if it does not fit in full, refuse. `path` \
         IS truncated at 16 cols because derivation_index is a raw u32",
        vec![
            frame(|f| {
                if ui::address_verify(f, &p2tr_addr, "m/84'/0'/0'/0/7", 7).is_err() {
                    ui::refusal(f);
                }
            }),
            frame(|f| {
                if ui::address_verify(f, &long_addr, "m/86'/0'/0'/0/4294967295", 4_294_967_295).is_err() {
                    ui::refusal(f);
                }
            }),
            frame(|f| {
                if ui::address_verify(f, &"z".repeat(81), "m/0/0", 0).is_err() {
                    ui::refusal(f);
                }
            }),
        ],
    ));

    scenes
}

/// Scenes driven by a REAL `Session`, rendered exactly the way `main.rs`'s loop
/// renders them: `ui::refusal` for `Err(Fault::Refused(_))`, and no screen change
/// at all for anything else.
fn session_scenes(
    session: &mut Session<'_, DebugFlash<FakeFlash>>,
    rng: &mut Entropy,
) -> Vec<Scene> {
    let id = session.device_id();
    let short: String = format!("{id}").chars().take(12).collect();
    let mut out = Outbox::new(id);
    let announced = session
        .announce(
            frostsnap_comms::Sha256Digest([0x11; 32]),
            &mut out,
        )
        .map(|()| format!("{} frames, {} bytes", out.frames(), out.bytes().len()))
        .unwrap_or_else(|e| format!("announce failed: {e:?}"));

    let hostile: Vec<(&str, &str, CoordinatorSendBody)> = vec![
        (
            "9a session: RequestHeldShares (read-only, ALLOWED)",
            "the one restoration message that is safe with no consent screen. No \
             prompt comes back, so the panel keeps showing standby",
            CoordinatorSendBody::Core(CoordinatorToDeviceMessage::Restoration(
                CoordinatorRestoration::RequestHeldShares,
            )),
        ),
        (
            "9b session: EnterPhysicalBackup -> REFUSAL",
            "no entry UI exists, so there is nothing to consent with",
            CoordinatorSendBody::Core(CoordinatorToDeviceMessage::Restoration(
                CoordinatorRestoration::EnterPhysicalBackup {
                    enter_physical_id: EnterPhysicalId::new(rng),
                },
            )),
        ),
        (
            "9c session: ScreenVerify::VerifyAddress -> REFUSAL",
            "harmless but unimplemented; refusing beats silently dropping it and \
             leaving the app waiting",
            CoordinatorSendBody::Core(CoordinatorToDeviceMessage::ScreenVerify(
                ScreenVerify::VerifyAddress {
                    master_appkey: MasterAppkey([0u8; 65]),
                    derivation_index: 7,
                },
            )),
        ),
    ];

    hostile
        .into_iter()
        .map(|(name, note, body)| match session.recv(body, rng, &mut out) {
            Ok(prompts) if prompts.is_empty() => Scene::shown(
                name,
                &format!("{note} [announce: {announced}]"),
                vec![frame(|f| ui::standby(f, "coldsnap", &short, None))],
            ),
            // Any real prompt would be drawn by main.rs's draw_prompt; none of
            // these messages can produce one.
            Ok(prompts) => Scene::shown(
                name,
                &format!("{note} -- {} prompt(s), UNEXPECTED", prompts.len()),
                vec![frame(|f| ui::standby(f, "coldsnap", &short, None))],
            ),
            Err(Fault::Refused(r)) => {
                Scene::refused(name, note, format!("Fault::Refused(Refusal::{r:?})"))
            }
            // main.rs draws nothing here, and that is the honest thing to show:
            // an empty page list would be a lie, so this is standby unchanged.
            Err(f) => Scene::shown(
                name,
                &format!("{note} -- Fault::{f:?}: main.rs leaves the screen UNCHANGED"),
                vec![frame(|fr| ui::standby(fr, "coldsnap", &short, None))],
            ),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// the loop
// ---------------------------------------------------------------------------

const BANNER: &str = "\
cold-snap screen simulator -- coldsnap_hal::ui on a terminal, no device attached.

WHAT THIS PROVES
  * layout: every frame below is drawn by the shipped `coldsnap_hal::ui` code and
    printed from the same 1,024 MONO_VLSB bytes the panel would be handed.
  * logic: sign-approval pagination, the high-fee thresholds and every refusal are
    computed by `coldsnap_firmware::sign_consent`, the shipped consent gate.
  * flow: page order, and that a request this device cannot render in full reaches
    a REFUSAL screen instead of a partial one.
  * dispatch: scene 9 runs a real `Session` (flash-backed identity + nonce slots
    on FakeFlash) against real coordinator messages.

WHAT THIS DOES NOT PROVE -- nothing here has touched hardware
  * the SSD1306: no init sequence, no register writes, no contrast, no glass. A
    frame that is legible here can be unreadable on a 0.9-inch OLED.
  * SPI1, chip select, DMA, timing, refresh rate: not exercised at all.
  * the bootloader handoff, the callgate, RDP=2, the vector table: not exercised.
  * the keypad: there is NO keypad driver in this tree. The key map below is a
    proposal (PLAN.md 4.2's 5/8 paging), not a port.
  * the release profile: this builds `dev`, where `overflow-checks = true`.
    Arithmetic that panics here WRAPS in the shipped image.
  * the two consent screens' prompts: keygen-check and test-message parameters are
    fixtures. A real `KeyGenPhase3` needs a coordinator -- that is `hostcheck`.
  Every claim from this program is unverified-on-silicon.

KEYS (Mk4 pad: 1 2 3 / 4 5 6 / 7 8 9 / x 0 y -- no arrows). One key, then Enter.
  <number>  open that scene        q  quit
  8 or 9    next page              5 or 7  previous page
  1 or y    OK/confirm             x       cancel
  0 or m    back to the menu       (bare Enter = next page)
In the WINDOW front-end the same keys are the same actions, clicked or typed; the
menu lists five scenes at a time (8/5 page the list) and carries the legend, since
a window has no scrollback. There is no `q`: close the window.
";

fn menu(scenes: &[Scene], msg: &str) -> String {
    let mut s = String::from("\n-- screens ------------------------------------------------------\n");
    for (i, sc) in scenes.iter().enumerate() {
        s.push_str(&format!(
            "{:>3}  {}{}\n",
            i + 1,
            sc.name,
            if sc.refusal.is_some() {
                "   [REFUSED]"
            } else {
                ""
            }
        ));
    }
    s.push_str("  q  quit\n");
    if !msg.is_empty() {
        s.push_str(&format!(">>> {msg}\n"));
    }
    s.push_str("scene> ");
    s
}

/// The one key handler, shared by both front-ends so the terminal and the window
/// cannot drift into two different state machines. `false` means quit.
fn apply_key(
    scenes: &[Scene],
    here: &mut Option<usize>,
    page: &mut usize,
    msg: &mut String,
    key: &str,
) -> bool {
    if key == "q" {
        return false;
    }
    match *here {
        None => {
            if let Some(i) = key
                .parse::<usize>()
                .ok()
                .filter(|n| (1..=scenes.len()).contains(n))
            {
                *here = Some(i - 1);
                *page = 0;
            } else if !key.is_empty() {
                // Stay on the menu, which reprints itself next lap.
                *msg = format!("no scene {key:?}");
            }
        }
        Some(i) => {
            let last = scenes[i].pages.len() - 1;
            match key {
                "" | "8" | "9" => {
                    if *page < last {
                        *page += 1;
                    } else {
                        *msg = "last page".into();
                    }
                }
                "5" | "7" => {
                    if *page > 0 {
                        *page -= 1;
                    } else {
                        *msg = "first page".into();
                    }
                }
                "1" | "y" => {
                    if let Some(why) = &scenes[i].refusal {
                        *msg = format!("REFUSED ({why}) -- there is nothing here to confirm");
                    } else if *page < last {
                        *page += 1;
                        *msg = "OK: next page. Consent is the LAST page, so every page has \
                                to be stepped through"
                            .into();
                    } else {
                        *msg = "CONFIRMED. On the device this is where \
                                Session::confirm(prompt) runs -- which re-checks \
                                sign_consent before signing anything"
                            .into();
                    }
                }
                "x" => {
                    *here = None;
                    *page = 0;
                    *msg = "CANCELLED. Nothing was confirmed.".into();
                }
                "0" | "m" => {
                    *here = None;
                    *page = 0;
                }
                other => *msg = format!("no key {other:?} on this pad"),
            }
        }
    }
    true
}

fn show(scene: &Scene, page: usize, msg: &str) -> String {
    let mut s = format!(
        "\n=== {} ===\n{}\npage {}/{}\n{}",
        scene.name,
        scene.note,
        page + 1,
        scene.pages.len(),
        art(&scene.pages[page]),
    );
    if let Some(why) = &scene.refusal {
        s.push_str(&format!(
            "\n*** REFUSED BY THE DEVICE: {why}\n*** This screen is the refusal. It is not a missing screen, and there is\n*** nothing on it to confirm: `Session::confirm` would reject it too.\n"
        ));
    }
    if !msg.is_empty() {
        s.push_str(&format!("\n>>> {msg}\n"));
    }
    s.push_str("[8/9 next  5/7 prev  1/y ok  x cancel  0 menu  q quit] > ");
    s
}

fn main() {
    // Real flash at the shipped geometry, real identity record, real Session --
    // the same three lines `examples/stub.rs:268-297` uses, for the same reason:
    // a MemoryNonceSlot signer would prove nothing about this firmware.
    let sectors = memmap::FS_FREE_OFFSET as usize / ERASE_SIZE;
    let flash = RefCell::new(DebugFlash(FakeFlash::new(sectors)));
    let mut rng = entropy(0x5a);
    let secret = identity::load_or_create(&mut *flash.borrow_mut(), &mut rng)
        .expect("FakeFlash identity record");
    let mut session = Session::open(&flash, &secret).expect("Session::open");

    let mut scenes = ui_scenes();
    scenes.extend(session_scenes(&mut session, &mut rng));

    // SELF-CHECK, and the only assert in this file: the fail-closed fixtures must
    // actually have been refused by real code. If `sign_consent` or `SignPages`
    // ever stops refusing one of them, this sim would otherwise present the
    // fail-open as a perfectly good screen -- which is the exact failure it exists
    // to catch.
    let refused: Vec<&str> = scenes
        .iter()
        .filter(|s| s.refusal.is_some())
        .map(|s| s.name.as_str())
        .collect();
    for expected in ["3f", "3g", "3h", "5b", "9b", "9c"] {
        assert!(
            refused.iter().any(|n| n.starts_with(expected)),
            "fixture {expected} was NOT refused -- fail-open. refused: {refused:#?}"
        );
    }

    // SELF-CHECK 2: the display stream. Runs in both front-ends -- the terminal one
    // prints the same bytes it would push, so a transport bug found here is real
    // either way. See `check_display_stream` for what it does and does not cover.
    check_display_stream(&scenes);

    // The window front-end, when simulator.py launched us and put its pipe fds on
    // our argv. Everything above this line is identical for both.
    if let Some(fds) = sim_fds() {
        gui(&scenes, fds, &refused.join(", "));
        return;
    }

    print!("{BANNER}");
    println!(
        "Refusals confirmed by real code on startup: {}\n",
        refused.join(", ")
    );

    let stdin = std::io::stdin();
    let mut lines = stdin.lock().lines();
    let mut here: Option<usize> = None;
    let mut page = 0usize;
    let mut msg = String::new();

    loop {
        match here {
            None => print!("{}", menu(&scenes, &msg)),
            Some(i) => print!("{}", show(&scenes[i], page, &msg)),
        }
        msg.clear();
        let _ = std::io::stdout().flush();

        let Some(Ok(line)) = lines.next() else {
            println!("\n(end of input)");
            return;
        };
        if !apply_key(&scenes, &mut here, &mut page, &mut msg, line.trim()) {
            println!("bye. Nothing was signed and nothing was flashed.");
            return;
        }
    }
}

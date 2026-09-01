//! The `hostcheck` harness's device side: the SHIPPING dispatch
//! (`coldsnap_firmware::Session`) and the REAL `coldsnap_hal::comms` framing, on
//! real file descriptors, against a real `frostsnap_coordinator` in another
//! process.
//!
//! WHAT CHANGED, and it is the whole reason this file moved out of
//! `hal/examples/`: it used to build `FrostSigner::new_random(&mut rng, 4)` with
//! the default in-RAM `MemoryNonceSlot`, so a green run proved `frostsnap_core`
//! works and proved nothing about this firmware. It now goes through
//! `Session::open`, which derives the keypair from
//! `coldsnap_hal::identity::load_or_create` and puts the nonce slots on flash at
//! `memmap::FS_NONCE_OFFSET` — byte for byte the code path in the ARM image. The
//! flash is `FakeFlash`, at `StmFlash`'s exact geometry (WRITE_SIZE 8,
//! ERASE_SIZE 4096), so the double is no more permissive than the hardware.
//!
//! Knows nothing about ptys. **fd 0 is the wire in, fd 1 is the wire out.** The
//! harness creates the pty, keeps the SLAVE for the coordinator, and hands us the
//! MASTER as both of our standard streams (MEASURED: `FIONREAD` on a darwin pty
//! master always returns 0, so a coordinator holding the master would see an
//! eternally empty port and hang silently).
//!
//! NEVER `println!` IN THIS FILE. fd 1 *is* the wire: one stray byte
//! desynchronises the coordinator, whose magic-byte scan has no backtracking
//! (any mismatch resets progress to 0). Every diagnostic goes to **stderr**.
//!
//! `N_DEVICES` (currently **9**) sessions in this one process, each with its OWN
//! `FakeFlash`, all multiplexed over the one wire and told apart by
//! `Destination` — which is what the real daisy chain does too, so nothing is
//! faked by co-hosting them. We complete a THRESHOLD-of-N_DEVICES keygen, a nonce
//! replenishment and a signature with the coordinator, and then keep serving so
//! the coordinator can ask each device what it holds.
//!
//! OUR EXIT STATUS IS NOT THE PROOF, and under `hostcheck` it is not even
//! observed: `hostcheck`'s `reap()` SIGKILLs this process once its own
//! verification is done, so the EOF/PASS path below is reached only when this
//! binary is run BY HAND. What the harness passes on is what the COORDINATOR
//! verified for itself — the aggregated signature against its own derived key,
//! and 9/9 `HeldShares2` replies. Every `die` here is still a failure, because a
//! stub that dies mid-run makes `hostcheck`'s `try_wait` fail the pass by name.
//!
//! WHAT IT PROVES, precisely: this binary links cold-snap's VENDORED
//! `frostsnap_core` through `coldsnap_firmware`; `hostcheck` links UPSTREAM's via
//! `frostsnap_coordinator`. Two independent copies of the state machine agree on
//! every message, bincode-encoded through `frostsnap_comms` and framed by
//! `hal/src/comms.rs`. A mock could not fail; these can, and mutation-tested,
//! they do.
//!
//! THE RESTART, and what it is worth. Immediately after writing the announces
//! this process throws away **everything RAM-side** — every `Session`, every
//! `FrostSigner`, every nonce cache — and rebuilds from the same `FakeFlash`
//! bytes, then does the entire keygen/nonce/signing/HeldShares2 run with the
//! rebuilt sessions. The coordinator learned our `DeviceId`s from the PRE-restart
//! announce, so if `identity::load_or_create` had failed to read back what it
//! wrote, the ids would differ and the coordinator would never complete a keygen
//! with them. That is the end-to-end proof that flash-backed identity survives a
//! reset. HONEST LIMIT: it is an in-process restart. `FakeFlash` lives in RAM, so
//! a second OS process would need the flash image persisted to a file, which is
//! harness plumbing, not device code — see the open list.
//!
//! NOT evidence about the shipped device. An `examples/` target here compiles
//! `coldsnap_hal` with `fake-flash` AND `test-seam` on; both are BYPASSES. The
//! RNG is the real `rng::Entropy` but seeded through the `test-seam`
//! `mix_sources` constructor from FIXED bytes, so a failure replays exactly. The
//! digest is computed by the shipped `firmware_digest` over a SYNTHETIC image (a
//! host process has no flashed image to hash) — real function, fake input.
//!
//! WRITE-BLOCKING / DEADLOCK, read this before raising n. Every frame leaves here
//! in 64-byte chunks (`STUB_CHUNK` overrides). MEASURED: an undrained pty blocks
//! writes past ~1 KB. `CertifyPlease` is 2,179 B at 9-of-9 and a single-segment
//! `NonceResponse` is 2,040 B, so the coordinator's own write bound is what carries
//! this, not the frame sizes. It works because the traffic is one-directional at
//! those points. What deadlocks is both sides writing >1 KB AT ONCE. Today no
//! exchange does that.
//!
//! Our half of that hazard is now structurally gone rather than merely unexercised:
//! `spawn_reader` drains fd 0 from its own thread, so the pty keeps emptying while
//! the main loop is inside `write_chunked` (which sleeps 1 ms per chunk for the
//! first 64) or inside a keygen. UNTESTED as a claim — no exchange writes >1 KB
//! both ways, so nothing here demonstrates it; what IS demonstrated is the
//! parked-progress property `spawn_reader` exists for. The coordinator's own write
//! path stays bounded by its `WRITE_STALL_LIMIT`, which is its business, not ours.
//!
//! Run it via the harness, not by hand:
//!   cargo build --target aarch64-apple-darwin -p coldsnap_firmware --example stub
//!   (then `hostcheck` spawns the built artifact)

use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::Duration;

use coldsnap_firmware::{firmware_digest, prompt_screen, DebugFlash, Fault, Outbox, Session};
use coldsnap_hal::comms::{decode_body, CoordinatorSendBody, Link, MAGIC_REPLY};
use coldsnap_hal::flash::fake::FakeFlash;
use coldsnap_hal::flash::ERASE_SIZE;
use coldsnap_hal::rng::{mix_sources, Entropy, ProvenSeed, SE1_BYTES, SE2_BYTES, TRNG_BYTES};
use coldsnap_hal::{identity, memmap, ui};
use frostsnap_comms::{DeviceSendBody, ReceiveSerial, Upstream};
use frostsnap_core::device::keys::KeyMutation;
use frostsnap_core::device::{DeviceToUserMessage, Mutation};
use frostsnap_core::schnorr_fun::frost::Fingerprint;
use frostsnap_core::{AccessStructureRef, DeviceId};

/// Must match `hostcheck`'s N_DEVICES; the coordinator learns the ids from our
/// Announces, so only the count has to agree.
const N_DEVICES: usize = 9;

/// One flash per device, at the shipped geometry. `DebugFlash` is only the
/// `core::fmt::Debug` shim `FrostSigner::new` demands — see its doc in the lib.
type Flash = DebugFlash<FakeFlash>;

/// Named so a stall is a diagnosis rather than a mystery.
///
/// MONOTONIC, and that is load-bearing: every store is a `fetch_max`, because
/// dispatching any `Core` body sets `KeygenInProgress` and would otherwise walk
/// the signing states backwards and report the wrong stall.
///
/// There is no `NonceJobsRun` state any more: running the nonce batch moved into
/// the shipped dispatch (`Session::run`), so this process never sees it as a
/// prompt. `hostcheck` proves the replenishment happened — the signature it
/// verifies cannot exist without it.
const STATES: [&str; 7] = [
    "WaitingForCoordinatorMagic",
    "SentAnnounces",
    "RestartedFromFlash",
    "WaitingForKeygenBegin",
    "KeygenInProgress",
    "SharesSaved",
    "SignatureShareSent",
];
static STATE: AtomicUsize = AtomicUsize::new(0);
static BYTES_READ: AtomicUsize = AtomicUsize::new(0);
/// How many devices have handed back a `SignatureShare`. Global rather than
/// threaded through `drive` because `STATE` already is, and it is read only by
/// `die` and the exit log.
static SIG_ACKS: AtomicUsize = AtomicUsize::new(0);
/// How many prompts the consent closure DECLINED. Global for the same reason
/// `SIG_ACKS` is, and read by the main loop's fail-closed check.
static DECLINES: AtomicUsize = AtomicUsize::new(0);

/// LONGER than the harness's own budget on purpose, and that is load-bearing.
/// `hostcheck` owns the budget and kills us itself; this watchdog only exists so
/// a stub run BY HAND cannot hang forever. If it fires during a `hostcheck` run,
/// the news is that the harness's bound is broken.
///
/// 90 s: a 9-of-9 certpedpop keygen is real elliptic-curve work in a DEBUG build,
/// nine signers deep, and at `STUB_CHUNK=1` every byte of every frame costs a
/// syscall. The harness's own budget is 35 s, so this is ~2.5x its bound —
/// deliberately, so that when both fire it is the harness's message you read.
///
/// SCALED by [`timeout_scale`], and that is why it is not used raw: `hostcheck`
/// scales its budgets by the same variable, so leaving this fixed would invert the
/// ~2.5x relationship above the first time a human took ten seconds per screen —
/// the stub would kill the run and the harness's diagnosis would never print.
const DEADLINE: Duration = Duration::from_secs(90);

/// The tier-2 test fingerprint (`frostsnap_core/tests/common/mod.rs`), NOT the
/// shipped `Fingerprint::FROST_V0`, and `hostcheck` sets the identical value.
///
/// Why: the fingerprint is a coordinator-side grind — `FROST_V0` is 18 bits per
/// coefficient, i.e. ~2^18 trials per coefficient inside
/// `finish_with_fingerprint`, which in a debug build is minutes of CPU and
/// nothing to do with the wire. It selects WHICH coefficients get chosen, never
/// how they are encoded, so the cross-tree bincode agreement this harness exists
/// to prove is unaffected. It must match on both sides because the device
/// verifies it (`device/keygen.rs` `check_fingerprint`) — mismatch is a keygen
/// failure, which is why it is stated in both files rather than defaulted.
const TEST_FINGERPRINT: Fingerprint = Fingerprint {
    bits_per_coeff: 2,
    max_bits_total: 6,
    tag: "test",
};

/// USB packet reality: `frostsnap_comms` moves bytes over OTG_FS in 64-byte
/// packets, so a real device NEVER hands the coordinator a whole frame at once.
/// Override with `STUB_CHUNK=<n>`; `STUB_CHUNK=1` is the adversarial setting.
fn chunk_size() -> usize {
    std::env::var("STUB_CHUNK")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(64)
}

/// Multiplies this process's watchdog AND every budget in `hostcheck`
/// (`COLDSNAP_TIMEOUT_SCALE`, default **1** — the automated gate is unchanged).
///
/// ONE factor, read by both processes, because they are one clock: `hostcheck`
/// spawns us, so we inherit whatever it was given, and [`DEADLINE`]'s whole
/// contract is being ~2.5x the harness's bound. It exists for the window, where a
/// human takes seconds per screen and there are 18 consent prompts back to back;
/// no fixed budget covers both that and two debug builds talking to each other
/// (LIVE-GLASS-PLAN §10).
///
/// `filter(|&n| n > 0)`: a 0 would make the watchdog fire instantly, i.e. a typo
/// would look like a device fault.
fn timeout_scale() -> u32 {
    std::env::var("COLDSNAP_TIMEOUT_SCALE")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(1)
}

/// The SCRIPTED KEY SOURCE: what to press at each of the two consent screens
/// (`COLDSNAP_GLASS_KEYS`, default `yy`, i.e. exactly today's behaviour).
///
/// Two characters, `<CheckKeyGen><SignatureRequest>`:
///  - `y` — press whatever the GLASS advertises, read back out of the rendered
///    pixels by [`advertised_key`]. The ONLY way to answer a signing screen
///    correctly, because step 0 made that digit random.
///  - anything else — press THAT byte, whatever the screen says. `x` declines; `9`
///    is a wrong digit (not in `ui::CONFIRM_CHARSET`, so it is *always* a
///    refusal), which is how a hardcoded-key script is demonstrated to fail.
///
/// A missing character is `y`, so `COLDSNAP_GLASS_KEYS=y` also means "approve
/// both".
///
/// KEYED BY PROMPT KIND, not positional, and that is deliberate: `N_DEVICES`
/// devices produce 2xN interleaved prompts, so a positional list would encode the
/// device count in an env var and start answering the wrong screen the moment n
/// changed. There are exactly two consent screens, so two characters is the whole
/// vocabulary.
///
/// LIVE-GLASS-PLAN §6 wrote this as `COLDSNAP_GLASS_KEYS=11`. That is no longer
/// expressible and the reason is the point of the whole step: with a randomised
/// digit there IS no fixed byte that authorises a signature. `y` is what "press
/// the confirm key" has to mean now, and it can only be answered by reading the
/// screen.
fn glass_keys() -> String {
    std::env::var("COLDSNAP_GLASS_KEYS").unwrap_or_else(|_| "yy".into())
}

/// WHEN the device throws away its keygen scratch state, i.e. where firmware
/// would put `FrostSigner::clear_tmp_data()`. Sized in `hal/src/heap.rs`: it is
/// worth 12,456 B of an 18,036 B per-device live figure, so whether firmware may
/// call it decides `HEAP_BYTES`. Values:
///
///  - `finalize` (DEFAULT): in the `FinalizeKeyGen` arm, i.e. after
///    `keygen_finalize` -> `save_complete_share` has staged NewKey/
///    NewAccessStructure/SaveShare. This is the shipped call site. Default ON so
///    that every `hostcheck` run is evidence for it, not just the run that
///    measured it: keygen -> nonces -> a signature that VERIFIES -> HeldShares2
///    all have to keep working with the scratch state gone.
///  - `off`: the vendored default, for A/B comparison.
///  - `check`: DELIBERATELY WRONG and kept runnable so the failure stays
///    reproducible -- clears in the `CheckKeyGen` arm, i.e. AFTER `keygen_ack`
///    stashed `tmp_keygen_pending_finalize` but BEFORE the coordinator's
///    `Finalize` asks for it back. Expect the stub to die 2 with "device doesn't
///    have keygen for <keygen_id>" (`device/keygen.rs` `keygen_finalize`).
fn clear_tmp_mode() -> String {
    std::env::var("STUB_CLEAR_TMP").unwrap_or_else(|_| "finalize".into())
}

/// Write in `chunk`-sized pieces, flushing each, with a 1 ms gap on the first
/// `GAP_CHUNKS`.
///
/// The gap is what makes the chunking REAL rather than cosmetic: chunked
/// `write`+`flush` syscalls take ~2 us each, so with no gap the pty coalesces
/// them into the coordinator's next poll (it sleeps 2 ms a lap) and it still
/// decodes one complete frame from one buffer -- exactly the case that was
/// already covered. With the gap the coordinator provably sees a partial frame
/// and reassembles inside `decode_from_reader`: MEASURED, its magic->announce
/// delta goes from 2.5 ms at chunk 64 to 85 ms at chunk 1.
///
/// The gap stops after 64 chunks because these frames are hundreds to thousands
/// of bytes, not 67: 1 ms/byte across an 800-byte frame is 0.8 s of sleeping per
/// frame, and while we sleep we do not read — which is exactly the undrained-pty
/// hazard in the header note. Sixty-four one-byte writes are already enough to
/// guarantee the reader sees an incomplete frame; the rest proves nothing new.
fn write_chunked(w: &mut impl Write, bytes: &[u8], chunk: usize) -> std::io::Result<()> {
    const GAP_CHUNKS: usize = 64;
    for (i, piece) in bytes.chunks(chunk).enumerate() {
        w.write_all(piece)?;
        w.flush()?;
        if i < GAP_CHUNKS {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    Ok(())
}

/// One fd-0 read. `Ok(bytes)` non-empty is wire traffic, `Ok(bytes)` EMPTY is EOF
/// (`read` returning 0), `Err` is the read error the old inline `match` reported by
/// name. It is an `io::Result` rather than a bespoke enum because `read` already
/// models all three and `io::Error` is `Send`.
type WireEv = std::io::Result<Vec<u8>>;

/// fd 0 in its own thread, feeding ONE channel. The main loop then consumes it with
/// a `recv_timeout`, which is the whole point.
///
/// WHY, and it is a deadlock rather than a tidiness argument. The old loop blocked
/// in `read(fd 0)`, so the ONLY thing that could ever wake it was a byte from the
/// coordinator. Any work the loop still owes that the coordinator is *waiting for*
/// therefore never happens — the loop is parked on the wrong fd. The comment on the
/// deferred-`hello` hazard further down describes exactly that shape ("the
/// coordinator stops writing magic bytes the moment it reads our reply, so deferring
/// to the next loop iteration would park us in `read()` waiting for a byte it will
/// never send"), and MUTATION-VERIFIED: defer that write by one lap and a blocking
/// consumer hangs the pass while a `recv_timeout` consumer still passes.
///
/// Live glass needs that property for a second reason: a prompt parked on a human
/// keypress arrives on a channel that is not fd 0, and a loop blocked on fd 0 can
/// never observe it. This step lands the threading alone, with no consent change and
/// no key channel, so that a regression here is unambiguous.
///
/// Same shape as `hostcheck`'s own `spawn_writer` — one thread, one unbounded
/// `mpsc` — deliberately, so this process has one concurrency model and not two.
/// Unbounded is not sloppy here: the sender is the coordinator, whose traffic is
/// already bounded by its own budgets, and a bounded queue would have to block the
/// reader, which is the thing being removed.
fn spawn_reader() -> Receiver<WireEv> {
    let (tx, rx) = std::sync::mpsc::channel::<WireEv>();
    std::thread::spawn(move || {
        // 512 B and one allocation per read, exactly the old inline buffer's size.
        // `Link` reassembles across reads, so read granularity was never load-bearing.
        let mut wire_in = std::io::stdin().lock();
        let mut buf = [0u8; 512];
        loop {
            let ev: WireEv = wire_in.read(&mut buf).map(|n| buf[..n].to_vec());
            // Stop after EOF or an error: `read` on a closed fd returns `Ok(0)`
            // forever, and looping on that would spin a core and flood the channel.
            let last = !matches!(&ev, Ok(bytes) if !bytes.is_empty());
            if tx.send(ev).is_err() || last {
                return;
            }
        }
    });
    rx
}

/// How long the main loop waits for wire bytes before doing another lap.
///
/// It adds ZERO latency to the automated path: `recv_timeout` returns the instant a
/// message lands, so this bounds only how long an IDLE loop sleeps. The numbers it
/// has to stay clear of are all `hostcheck`'s, and it is three orders of magnitude
/// under the smallest: `PORT_TIMEOUT` 250 ms, `WRITE_STALL_LIMIT` 5 s,
/// `HANDSHAKE_DEADLINE` 5 s, then cumulative budgets of 35 s (handshake + keygen)
/// and 65 s (+ signing), with a once-per-pass watchdog at 67 s
/// (`65 s + WATCHDOG_SLACK`). 2 ms matches the coordinator's own poll lap, so
/// neither side idles finer than the other. Step 6 scales the harness's budgets for
/// human latency; nothing here needs scaling, because a longer park costs laps, not
/// deadline.
const WIRE_POLL: Duration = Duration::from_millis(2);

/// How many prompts this run EXPECTS the consent closure to decline
/// (`STUB_EXPECT_DECLINES`, default **0**).
///
/// FAIL CLOSED, and that default is the whole point. A refusal has NO protocol
/// message (see [`decline`]), so all a decline can ever look like from outside is
/// a `Debug{declined=...}` line plus silence where a signature share would have
/// been — which is also exactly what a device that declines EVERYTHING looks
/// like. Default 0 therefore makes any unexpected decline a nonzero exit, and a
/// run that WANTS declines has to say how many (LIVE-GLASS-PLAN §10).
fn expect_declines() -> usize {
    std::env::var("STUB_EXPECT_DECLINES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0)
}

/// The consent seam, and the only one: ONE closure threaded through [`drive`],
/// answering with **the key byte** a human would press after looking at `frame`.
///
/// WHY A KEY BYTE, when LIVE-GLASS-PLAN §4 drew this as
/// `&mut dyn FnMut(&DeviceToUserMessage) -> bool`. Step 0 landed after that was
/// written and made the digit that authorises a signature RANDOM
/// (`ui::ConfirmDigit`, charset `12346`, copied from Coldcard's `hsm_ux.py:58`),
/// so "did the user approve" is no longer answerable without the digit — and a
/// closure that is TOLD the digit can approve without ever looking at the screen,
/// which is the one shortcut this whole gate exists to forbid. So the closure is
/// handed the rendered [`ui::Frame`] and nothing else: its only route to the digit
/// is the pixels. That is what makes the glass assertion structural instead of
/// additional.
///
/// The other half of the shape is that [`approved`] — not the closure — calls
/// [`ui::ConfirmDigit::accepts`]. The fail-closed rule then lives at ONE place for
/// all three closures that will exist (this stub's, the window's, the script's)
/// rather than being re-implemented, and got subtly wrong, in each; and the
/// window's closure needs no `ui` knowledge at all, just "write 1,024 bytes, read
/// one back".
type Consent<'a> = &'a mut dyn FnMut(&DeviceToUserMessage, &ui::Frame) -> u8;

/// `"Press ("` — the fixed part of the legend `ui::press_legend` composes, and the
/// anchor [`advertised_key`] finds the digit by.
const PRESS: &[u8] = b"Press (";

/// The key the LAST ROW of `frame` advertises as its yes: the digit inside
/// `Press (n)`, or the `1` of `1=match`. `None` when the screen advertises no yes
/// key at all — which is a screen nothing may consent to.
///
/// This reads the digit **off the pixels**, and it is the cheapest always-approve
/// closure that can exist rather than an early down-payment on step 4: with a
/// randomised digit there IS no fixed byte that authorises a signature, so any
/// approving closure has to read the screen. `ui::Frame::cell` is the reverse
/// glyph lookup that already ships (`hal/src/ui.rs`) and requires a byte-for-byte
/// font match, so nothing here re-implements the font — an independent second
/// copy of that mapping would be a second thing to keep in sync.
///
/// Both consent legends live on the last row and there are only two forms:
/// `keygen_check` prints `1=match x=no`, `sign_test_message_confirm` prints
/// `Press (n) x=no`.
fn advertised_key(frame: &ui::Frame) -> Option<u8> {
    let row: Vec<u8> = (0..ui::COLS)
        .map(|col| frame.cell(col, ui::ROWS - 1).map_or(b' ', |(ch, _)| ch))
        .collect();
    if let Some(i) = row.windows(PRESS.len()).position(|w| w == PRESS) {
        return row.get(i + PRESS.len()).copied();
    }
    // `<key>=<what it does>`, the plain-press legend.
    if row.get(1) == Some(&b'=') {
        return row.first().copied();
    }
    None
}

/// The four bytes the KEYGEN CHECK screen actually **drew**, read back off the
/// glass as 8 lowercase hex characters. `None` if those pixels are not eight
/// doubled font glyphs.
///
/// THE OPEN HALF OF PLAN.md §9 item 12. The session hash is already compared
/// core-to-core across the two processes (`hostcheck` bails `SESSION HASH
/// MISMATCH`); nothing until now asserted that the code on the SCREEN is that
/// value. Those four bytes are the entire anti-MITM defence, because they are what
/// a human reads aloud — a device that verified the right transcript and then drew
/// the wrong code passed every existing check.
///
/// `ui::Frame::cell_2x` is the shipping inverse of `text_2x` (one glyph per call,
/// `col` stepped by 2, byte-for-byte font match), so nothing here re-derives the
/// doubling; `ui::keygen_check` draws the high half at `((COLS - 8) / 2, 2)` and
/// the low half two rows down. `?` rather than `filter_map`, because a short read
/// must be a FAILURE and not a shorter string that might still prefix-match.
fn glass_code(frame: &ui::Frame) -> Option<String> {
    let base = (ui::COLS - 8) / 2;
    let mut code = String::new();
    for row in [2usize, 4] {
        for i in 0..4 {
            code.push(frame.cell_2x(base + i * 2, row)? as char);
        }
    }
    Some(code)
}

/// Render `prompt`, ask `consent` for a keypress, and decide. `true` means
/// confirm it.
///
/// THE ONE PLACE A KEY BECOMES CONSENT. `Session::confirm` renders the screen
/// again for its own renderability gate, with its own throwaway digit (documented
/// at that call in `firmware/src/lib.rs`); THIS frame is the one the closure
/// answers and this digit is the one printed on it, so the legend that is
/// displayed and the value that is accepted are one `ConfirmDigit` and cannot
/// drift.
///
/// It also REPORTS the keygen code off this same frame (`glass=`), which is why it
/// takes the outbox. From THIS frame and not a re-render, deliberately: the four
/// bytes `hostcheck` compares against its own session hash have to be the four
/// bytes on the screen the consent below answered, or the assertion is about a
/// picture nobody approved.
fn approved(
    prompt: &DeviceToUserMessage,
    rng: &mut Entropy,
    consent: Consent,
    out: &mut Outbox,
) -> bool {
    let digit = ui::ConfirmDigit::draw(rng);
    let mut frame = ui::Frame::new();
    // `Ok(false)` (informational, no screen) and `Err` (this device cannot draw
    // the request in full) are both prompts NO key may authorise. They are
    // deliberately not called declines: `Session::confirm` fails closed on exactly
    // these two — `NotConfirmable` and `Refused` — and names the failure itself,
    // so it stays the authority and its diagnostics keep their existing wording.
    if !matches!(prompt_screen(&mut frame, prompt, digit), Ok(true)) {
        return true;
    }
    // ASSERTION 1, on the wire. `UNREADABLE` rather than skipping the report: a
    // screen whose code cannot be read back is a screen whose code is not the
    // coordinator's, and `hostcheck` must fail on it rather than on a missing map
    // entry it could mistake for a device that never got there.
    if matches!(prompt, DeviceToUserMessage::CheckKeyGen { .. }) {
        let code = glass_code(&frame).unwrap_or_else(|| "UNREADABLE".into());
        if let Err(e) = out.push(DeviceSendBody::Debug {
            message: format!("glass={code}"),
        }) {
            die(2, &format!("Debug(glass) refused by framing: {e:?}"));
        }
    }
    let key = consent(prompt, &frame);
    match prompt {
        // `keygen_check` advertises `1=match`, NOT a digit: the stronger gesture
        // belongs on the screens that authorise a signature (`prompt_screen`'s
        // doc). Accepting the digit here would accept a key the screen never
        // showed.
        DeviceToUserMessage::CheckKeyGen { .. } => key == b'1',
        // FAIL CLOSED — `hsm_ux.py:58`'s `refused = (ch != confirm_char)`,
        // inverted. Only the digit that is ON THE SCREEN signs; `x`, another
        // charset digit and a key that is not on the pad are all refusals.
        DeviceToUserMessage::SignatureRequest { .. } => digit.accepts(key),
        // Not a consent prompt. Unreachable from the two call sites in `drive`,
        // and a decline — which fails the run — if that ever stops being true.
        _ => false,
    }
}

/// The consent closure said no: `Session::confirm` is never called, and the only
/// thing that can carry a "no" to the coordinator is the `Debug` back-channel a
/// `Fault::Refused` already uses two dozen lines below.
///
/// The vendored protocol HAS no decline variant — that is a finding, not a detail
/// — so the alternative to `Debug` is silence, and silence is indistinguishable
/// from a dead device. `Outbox` caps `Debug` at 256 B on a UTF-8 boundary and
/// `hostcheck` intercepts it before the `FrostCoordinator` state machine, so it
/// cannot perturb the protocol.
fn decline(id: DeviceId, what: &str, out: &mut Outbox) {
    DECLINES.fetch_add(1, Ordering::Relaxed);
    eprintln!("stub: {id} DECLINED {what} -- the protocol has no message for a no");
    if let Err(e) = out.push(DeviceSendBody::Debug {
        message: format!("declined={what}"),
    }) {
        die(2, &format!("Debug(declined) refused by framing: {e:?}"));
    }
}

/// Lowercase hex, for the two values this stub reports to the coordinator over
/// the wire. Same one-liner `hostcheck` has; a dependency for this would be silly.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn die(code: i32, why: &str) -> ! {
    eprintln!(
        "stub: FAIL in {} after {} bytes read, {} signature share(s) sent: {why}",
        STATES[STATE.load(Ordering::Relaxed)],
        BYTES_READ.load(Ordering::Relaxed),
        SIG_ACKS.load(Ordering::Relaxed),
    );
    std::process::exit(code)
}

/// A `ProvenSeed` through the real mixer from FIXED bytes — the `test-seam`
/// bypass, used on purpose so a failing keygen replays byte for byte. There is
/// deliberately no other way to get a `ProvenSeed`, so even this has to pass
/// three `check_source` calls. Copied from
/// `hal/tests/integration_frostsnap_over_hal.rs`; 12 lines beats a shared
/// test-support crate for two callers.
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

/// `N_DEVICES` blank flashes at the shipped geometry, sized so a write past the
/// nonce region is out of bounds rather than silently landing in `FS_FREE`.
///
/// Separate from `open_sessions` because these must OUTLIVE every session: a
/// `Session` borrows its `RefCell<Flash>`, and the restart works by dropping all
/// the sessions while the flashes stay exactly as they are — which is what a
/// power cycle does.
fn blank_flashes() -> Vec<RefCell<Flash>> {
    let sectors = memmap::FS_FREE_OFFSET as usize / ERASE_SIZE;
    (0..N_DEVICES)
        .map(|_| RefCell::new(DebugFlash(FakeFlash::new(sectors))))
        .collect()
}

/// Build one `Session` per flash, entirely out of what is ON that flash.
///
/// THE POINT OF THIS FILE: `identity::load_or_create` for the keypair (durable,
/// so the `DeviceId` is stable across resets) and `Session::open` for the nonce
/// slots (durable, because FROST nonce reuse after a reset is a key leak).
/// Neither `FrostSigner::new_random` nor `MemoryNonceSlot` appears anywhere.
///
/// Called TWICE: once at start-up, which creates each identity, and once for the
/// restart, which must READ BACK the same 32 bytes. The second call getting a
/// different secret shows up as a changed `DeviceId`.
fn open_sessions<'a>(
    flashes: &'a [RefCell<Flash>],
    rng: &mut Entropy,
) -> BTreeMap<DeviceId, Session<'a, Flash>> {
    let mut sessions = BTreeMap::new();
    for flash in flashes {
        // `load_or_create` wants `&mut Flash` and the session takes a shared
        // borrow of the same `RefCell` for its whole life, so the identity has to
        // be read first. Nothing else may hold a borrow here.
        let secret = match identity::load_or_create(&mut *flash.borrow_mut(), rng) {
            Ok(secret) => secret,
            Err(e) => die(2, &format!("identity::load_or_create: {e:?}")),
        };
        let mut session = match Session::open(flash, &secret) {
            Ok(session) => session,
            Err(e) => die(2, &format!("Session::open: {e:?}")),
        };
        session.signer.keygen_fingerprint = TEST_FINGERPRINT;
        if sessions.insert(session.device_id(), session).is_some() {
            die(2, "two devices derived the SAME DeviceId from different flashes");
        }
    }
    sessions
}

/// The digest the shipped `firmware_digest` computes, over a synthetic image.
///
/// The function is the one the ARM image calls; the INPUT cannot be real, because
/// a host process has no flashed, signed Mk4 image to hash. So: a
/// `FW_MIN_BODY_LEN` buffer with a valid `firmware_length` at header+24, hashed
/// over exactly the range `mk4-bootloader/verify.c:265-273` signs. No
/// coordinator refuses any digest today (`DO_GENUINE_CHECK = false`) and none
/// verifies one, so what this exercises is our own bounds-checking and framing,
/// not attestation.
fn synthetic_digest() -> frostsnap_comms::Sha256Digest {
    let length = memmap::FW_MIN_BODY_LEN;
    let mut image = vec![0xa5u8; length as usize];
    let off = memmap::FW_HEADER_OFFSET as usize + 24;
    image[off..off + 4].copy_from_slice(&length.to_le_bytes());
    firmware_digest(&image).expect("a well-formed synthetic image must hash")
}

/// Feed one decoded coordinator body to one session, answer the prompts a human
/// would answer, and record any share it staged.
///
/// CONSENT, and it is why the two consent prompts are NOT answered by the
/// dispatch: `Session::recv` returns `CheckKeyGen` and `SignatureRequest` and
/// answers neither. `CheckKeyGen` is a human comparing the session hash against
/// the coordinator's display, which is the defence against a coordinator that
/// lies about who is in the access structure; `SignatureRequest` is a human
/// reading the transaction. **A REAL DEVICE MUST NOT ACK EITHER ITSELF.** That
/// the answer lives HERE rather than in `firmware/src/lib.rs` is the load-bearing
/// part, and it is now a `Consent` closure rather than an unconditional ack, so
/// the same two `session.confirm` call sites serve this harness, a human at the
/// simulator window and a scripted gate. By default the closure is the
/// always-approve one — press whatever the glass advertises — so it remains a
/// harness affordance and every existing measurement is unchanged;
/// `COLDSNAP_GLASS_KEYS` scripts it (see [`glass_keys`]), which is how
/// `hostcheck`'s DECLINE pass proves that `x` refuses.
fn drive(
    session: &mut Session<'_, Flash>,
    body: CoordinatorSendBody,
    rng: &mut Entropy,
    consent: Consent,
    wire: &mut Vec<u8>,
    saved: &mut BTreeMap<DeviceId, AccessStructureRef>,
) {
    let id = session.device_id();
    // The shipped outbox: it applies the three framing caps (one nonce segment
    // per frame, `Debug` truncation, refuse an over-long `HeldShares2` whole) at
    // the single point where a body becomes bytes. This file no longer encodes
    // anything itself.
    let mut out = Outbox::new(id);
    let mut prompts: VecDeque<DeviceToUserMessage> = match session.recv(body, rng, &mut out) {
        Ok(prompts) => prompts.into(),
        // A refusal is policy, not failure: the device cannot do the thing at
        // all. It answers nothing and the link stays up.
        Err(Fault::Refused(r)) => {
            eprintln!("stub: {id} REFUSED {r:?} (policy, not an error)");
            // ON THE WIRE, not just on stderr. A refusal the coordinator cannot
            // observe is a refusal no harness can assert, and "the device answered
            // nothing" is also what a dead device looks like. `Debug` is the only
            // free-form device body; `Outbox` caps it at 256 B on a UTF-8
            // boundary, and `hostcheck` intercepts it before the
            // `FrostCoordinator` state machine, so it cannot perturb the protocol.
            if let Err(e) = out.push(DeviceSendBody::Debug {
                message: format!("refused={r:?}"),
            }) {
                die(2, &format!("Debug(refused) refused by framing: {e:?}"));
            }
            VecDeque::new()
        }
        Err(e) => die(2, &format!("Session::recv({id}): {e:?}")),
    };

    while let Some(prompt) = prompts.pop_front() {
        match prompt {
            DeviceToUserMessage::CheckKeyGen { phase } => {
                // THE ANTI-MITM VALUE, PUT ON THE WIRE. The device computes this
                // itself, over the transcript it VERIFIED (`KeyGenPhase3`); the
                // coordinator computes its own from its own state. A real device
                // shows it to a human who compares it against the coordinator's
                // screen -- that human is unautomatable, but the EQUALITY is not,
                // and reporting it here is what turns it into a host gate
                // (`hostcheck` compares, by name, at PASS).
                let session_hash = phase.session_hash();
                if let Err(e) = out.push(DeviceSendBody::Debug {
                    message: format!("session_hash={}", hex(&session_hash.0)),
                }) {
                    die(2, &format!("Debug(session_hash) refused by framing: {e:?}"));
                }
                let p = DeviceToUserMessage::CheckKeyGen { phase };
                if !approved(&p, rng, &mut *consent, &mut out) {
                    decline(id, "CheckKeyGen", &mut out);
                } else {
                    eprintln!("stub: {id} CheckKeyGen -> auto-ack (a real device asks a human)");
                    match session.confirm(p, rng, &mut out) {
                        Ok(more) => prompts.extend(more),
                        Err(e) => die(2, &format!("confirm(CheckKeyGen, {id}): {e:?}")),
                    }
                    if clear_tmp_mode() == "check" {
                        eprintln!("stub: {id} clear_tmp_data() at CheckKeyGen -- WRONG ON PURPOSE");
                        session.signer.clear_tmp_data();
                    }
                }
            }
            p @ DeviceToUserMessage::SignatureRequest { .. } => {
                if !approved(&p, rng, &mut *consent, &mut out) {
                    decline(id, "SignatureRequest", &mut out);
                } else {
                    eprintln!(
                        "stub: {id} SignatureRequest -> auto-ack (a real device asks a human)"
                    );
                    match session.confirm(p, rng, &mut out) {
                        Ok(more) => {
                            SIG_ACKS.fetch_add(1, Ordering::Relaxed);
                            STATE.fetch_max(6, Ordering::Relaxed);
                            prompts.extend(more);
                        }
                        Err(e) => die(2, &format!("confirm(SignatureRequest, {id}): {e:?}")),
                    }
                }
            }
            DeviceToUserMessage::FinalizeKeyGen { key_name } => {
                let clear = clear_tmp_mode() == "finalize";
                eprintln!("stub: {id} FinalizeKeyGen(key_name={key_name:?}) clear_tmp_data={clear}");
                // THE SHIPPED CALL SITE. Safe here because every tmp map has
                // already been `remove`d from by this point -- phase1 by
                // `CertifyPlease`, phase2 by `Check`, pending_finalize by the
                // `Finalize` that produced this very message -- and because it
                // does not touch `self.mutations`, which is the share drained
                // below. If either were false this run fails.
                //
                // FIRMWARE SHOULD PREFER `clear_unfinished_keygens()` (the keygen
                // leg alone, `device.rs:249`). It frees the SAME 12,456 B -- the
                // restoration leg only clears `tmp_loaded_backups`, whose
                // `BTreeMap` never allocates in a flow that enters no physical
                // backup -- while not being able to throw away a backup a human
                // has typed in but not yet saved. This calls the WIDER one on
                // purpose: passing the superset is the stronger evidence.
                if clear {
                    session.signer.clear_tmp_data();
                }
            }
            // Debug is not derived on every inner phase type, so no {other:?}.
            _other => eprintln!("stub: {id} ignoring an unrelated ToUser message"),
        }
    }

    // The device's persistence record. `keygen_finalize` -> `save_complete_share`
    // stages NewKey/NewAccessStructure/SaveShare; firmware's job is to write
    // these to flash, and NOTHING DOES YET -- there is no FLASH_FS region for
    // shares (`FS_FREE_OFFSET` is unclaimed), which is why the restart below
    // happens before keygen rather than after it. Draining them here is what "the
    // device saved its share" means for this harness, and the coordinator checks
    // it independently over the wire with `RequestHeldShares`.
    for mutation in session.signer.staged_mutations().drain(..) {
        if let Mutation::Keygen(KeyMutation::SaveShare(save)) = mutation {
            eprintln!(
                "stub: {id} SAVED share for {:?} (index {})",
                save.access_structure_ref, save.encrypted_secret_share.share_image.index
            );
            saved.insert(id, save.access_structure_ref);
        }
    }

    wire.extend_from_slice(&out.take());
}

fn main() {
    std::thread::spawn(|| {
        std::thread::sleep(DEADLINE * timeout_scale());
        die(3, "watchdog fired: no progress within the deadline");
    });

    let mut rng = entropy(0x5a);
    let flashes = blank_flashes();
    let mut sessions = open_sessions(&flashes, &mut rng);
    let ids: Vec<DeviceId> = sessions.keys().copied().collect();
    eprintln!("stub: {N_DEVICES} flash-backed sessions: {ids:?}");

    let digest = synthetic_digest();
    let mut saved: BTreeMap<DeviceId, AccessStructureRef> = BTreeMap::new();
    let mut announced_save = false;

    // THE SCRIPTED GATE'S CONSENT, and the default is the automated gate's: press
    // whatever the SCREEN advertises.
    //
    // Not `|_| true`, because with a randomised digit there is no fixed byte that
    // authorises a signature — `advertised_key` reads it back out of the rendered
    // pixels, which is the only channel a closure has. `y` is still an
    // unconditional yes and still a harness affordance: it never says no, it just
    // cannot say yes without having read the screen correctly. A device that
    // rendered the wrong legend would make this press the wrong key and get a
    // refusal, which fails the run — so the glass assertion is a PRECONDITION of
    // passing, not an extra check bolted on.
    //
    // The digit is never derived from the RNG, the seed, or the `ConfirmDigit` the
    // caller holds. `COLDSNAP_GLASS_KEYS` can only ask for a LITERAL key, which is
    // exactly the hardcoded-script case, and a literal cannot match a randomised
    // digit reliably (`9` never can).
    let keys = glass_keys();
    eprintln!(
        "stub: consent keys = {keys:?} (y = press what the glass advertises; anything else is \
         that literal key, whatever the screen says)"
    );
    let mut consent = |prompt: &DeviceToUserMessage, frame: &ui::Frame| -> u8 {
        let scripted = match prompt {
            DeviceToUserMessage::CheckKeyGen { .. } => keys.as_bytes().first(),
            _ => keys.as_bytes().get(1),
        };
        match scripted.copied().unwrap_or(b'y') {
            b'y' => match advertised_key(frame) {
                Some(key) => key,
                // FAIL CLOSED: a screen advertising no yes key gets `x`, which is a
                // decline, which fails the run unless it was declared.
                None => {
                    eprintln!("stub: the glass advertises NO confirm key -- declining");
                    b'x'
                }
            },
            key => key,
        }
    };

    let mut link = Link::new();
    let wire_rx = spawn_reader();
    let mut wire_out = std::io::stdout().lock();
    let chunk = chunk_size();

    loop {
        // fd 0 is drained by `spawn_reader`, never by this loop: an undrained pty
        // blocks writes past ~1 KB, while unlinked `Link::poll` is silent so wire
        // bytes are still the only thing that advances the protocol, and a loop
        // that BLOCKS for them cannot service anything else (see `spawn_reader`).
        let bytes = match wire_rx.recv_timeout(WIRE_POLL) {
            // EOF is the ending for a HAND run: `hostcheck` kills us instead
            // (`reap()`), so in a harness run neither of these arms is reached and
            // our exit status is not what the pass hinges on. Kept, and kept
            // asymmetric, because it is the only contract a hand run has: EOF
            // after a successful save is success, EOF before one is a failure, and
            // it must stay that way or a stub killed early would look clean.
            Ok(Ok(bytes)) if bytes.is_empty() => {
                if saved.len() == N_DEVICES {
                    eprintln!(
                        "stub: PASS -- coordinator closed the wire after verifying \
                         {N_DEVICES}/{N_DEVICES} held shares and {} signature share(s), all from \
                         sessions REBUILT FROM FLASH after the restart",
                        SIG_ACKS.load(Ordering::Relaxed)
                    );
                    return;
                }
                die(
                    2,
                    &format!(
                        "wire EOF with only {}/{N_DEVICES} share(s) saved -- the coordinator gave \
                         up first",
                        saved.len()
                    ),
                )
            }
            Ok(Ok(bytes)) => bytes,
            Ok(Err(e)) => die(2, &format!("read(fd 0): {e}")),
            // No wire bytes this lap. Nothing else can have changed either --
            // `saved`, `coordinator_acked` and `wire` are all downstream of a
            // decoded body -- so skipping the rest is EXACTLY what the old blocking
            // read did, minus the block. Once a prompt can park (step 2) this arm is
            // where it gets serviced.
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => {
                die(2, "the fd-0 reader thread vanished without an EOF or an error")
            }
        };
        BYTES_READ.fetch_add(bytes.len(), Ordering::Relaxed);

        // The "just linked" edge is observed HERE, from outside, on purpose:
        // `Link` exposes `is_linked()` but no edge, and this file is specified to
        // need zero `hal/src/` changes.
        let was_linked = link.is_linked();
        let mut wire: Vec<u8> = Vec::new();
        let poll = link.poll::<ReceiveSerial<Upstream>, _>(&bytes, |frame| match frame {
            ReceiveSerial::Message(msg) => {
                let mut dest = msg.target_destinations;
                let targets: Vec<DeviceId> =
                    ids.iter().copied().filter(|id| dest.is_destined_to(*id)).collect();
                // `decode_body`, NOT the vendored `message_body.decode()`: the
                // vendored one re-enters bincode with a 32 KiB budget, where a
                // 20-byte inner blob provokes a 32,640 B allocation (measured).
                // This bounds it at `ENCAPS_DECODE_LIMIT` and names the failure.
                match decode_body(msg.message_body) {
                    Ok(body) => {
                        if matches!(body, CoordinatorSendBody::Core(_)) {
                            STATE.fetch_max(4, Ordering::Relaxed);
                            eprintln!("stub: rx Core -> {} device(s)", targets.len());
                        } else {
                            eprintln!("stub: rx {body:?} -> {} device(s)", targets.len());
                        }
                        // EVERY body goes to the shipped dispatch, including
                        // `AnnounceAck` (which latches `coordinator_acked`) and
                        // anything it refuses. This file no longer has an opinion
                        // about which bodies matter.
                        for id in targets {
                            let session =
                                sessions.get_mut(&id).expect("id came from `sessions`");
                            drive(
                                session,
                                body.clone(),
                                &mut rng,
                                &mut consent,
                                &mut wire,
                                &mut saved,
                            );
                        }
                    }
                    // Over the inner limit, not valid bincode, or one of the two
                    // dead compat variants. NOT a desync: the framing is intact
                    // and the link stays up, so a single bad body cannot drop it.
                    Err(e) => eprintln!("stub: rx undecodable body ({e:?})"),
                }
            }
            // The coordinator keeps re-sending magic every 100 ms until it reads
            // our reply; those arrive as ordinary frames once linked.
            ReceiveSerial::MagicBytes(_) => eprintln!("stub: rx MagicBytes"),
            ReceiveSerial::Conch => eprintln!("stub: rx Conch"),
            ReceiveSerial::Reset => eprintln!("stub: rx Reset"),
            _ => eprintln!("stub: rx unused variant"),
        });
        if let Err(e) = poll {
            die(
                2,
                &format!("Link::poll: {e:?} (pending {} bytes)", link.pending()),
            );
        }

        if !was_linked && link.is_linked() {
            eprintln!(
                "stub: LINKED after {} bytes",
                BYTES_READ.load(Ordering::Relaxed)
            );
            // MAGIC_REPLY then `Session::announce` per device -- `Announce` AND
            // `NeedName`, because announce alone never registers a device with the
            // real coordinator: its gate is a NAME. All in this iteration
            // deliberately: the coordinator stops writing magic bytes the moment
            // it reads our reply, so deferring to the next loop iteration would
            // park us in `read()` waiting for a byte it will never send.
            let mut hello = Vec::from(MAGIC_REPLY);
            for session in sessions.values() {
                let mut out = Outbox::new(session.device_id());
                if let Err(e) = session.announce(digest, &mut out) {
                    die(2, &format!("announce({}): {e:?}", session.device_id()));
                }
                hello.extend_from_slice(&out.take());
            }
            if let Err(e) = write_chunked(&mut wire_out, &hello, chunk) {
                die(2, &format!("write(fd 1): {e}"));
            }
            STATE.fetch_max(1, Ordering::Relaxed);
            eprintln!(
                "stub: sent MAGIC_REPLY + {N_DEVICES} Announce+NeedName = {} bytes in {} chunk(s) \
                 of {chunk}",
                hello.len(),
                hello.len().div_ceil(chunk),
            );

            // ===================== THE RESTART =====================
            // Everything RAM-side goes away and is rebuilt from the same flash
            // bytes -- which is exactly what a power cycle does, since `FakeFlash`
            // IS the flash array and the sessions are all the state that is not
            // on it. This happens HERE, immediately after the announce write and
            // before any reply can be read, for two reasons:
            //
            //  - the coordinator learned our ids from the PRE-restart announce, so
            //    everything after this point -- keygen, nonce replenishment, the
            //    signature it verifies, HeldShares2 -- is done by sessions that
            //    read their keypair back out of flash. A non-durable identity
            //    yields different ids and the coordinator never completes a keygen
            //    with them. The coordinator is the judge, not us;
            //  - nothing persists a completed share yet (see `drive`), so a
            //    restart after keygen would lose it. Before keygen there is
            //    nothing on flash but the identity, which is the point.
            //
            // The assert below is belt: it fails fast and by name, whereas the
            // coordinator's failure would be a keygen timeout.
            sessions = open_sessions(&flashes, &mut rng);
            let after: Vec<DeviceId> = sessions.keys().copied().collect();
            if after != ids {
                die(
                    2,
                    &format!(
                        "IDENTITY DID NOT SURVIVE THE RESTART: announced {ids:?} but flash \
                         rebuilt as {after:?}"
                    ),
                );
            }
            STATE.fetch_max(2, Ordering::Relaxed);
            eprintln!(
                "stub: RESTARTED -- dropped all {N_DEVICES} signers and rebuilt them from flash; \
                 every DeviceId unchanged, so the coordinator is still talking to the same devices"
            );
        }

        let acked = sessions.values().filter(|s| s.coordinator_acked).count();
        if acked == N_DEVICES && STATE.load(Ordering::Relaxed) == 2 {
            STATE.fetch_max(3, Ordering::Relaxed);
            eprintln!(
                "stub: all {N_DEVICES} devices acked (post-restart sessions), waiting for keygen"
            );
        }

        if !wire.is_empty() {
            let bytes = wire.len();
            if let Err(e) = write_chunked(&mut wire_out, &wire, chunk) {
                die(2, &format!("write(fd 1): {e}"));
            }
            eprintln!("stub: sent {bytes} B");
        }

        // FAIL CLOSED on a decline, and checked AFTER the write so the
        // `declined=` line is on the wire before we go. A decline is a pass only
        // if the run asked for one: otherwise a bug that declined every prompt
        // would look like a quiet, clean — and completely signature-free — run,
        // which is the failure mode LIVE-GLASS-PLAN §10 names.
        let declined = DECLINES.load(Ordering::Relaxed);
        if declined > expect_declines() {
            die(
                2,
                &format!(
                    "{declined} prompt(s) DECLINED but STUB_EXPECT_DECLINES={} -- a declined \
                     prompt is a FAILURE unless the run declares it",
                    expect_declines()
                ),
            );
        }

        if saved.len() == N_DEVICES && !announced_save {
            announced_save = true;
            STATE.fetch_max(5, Ordering::Relaxed);
            let refs: std::collections::BTreeSet<_> = saved.values().collect();
            // Every share belongs to ONE access structure, or the keygen did not
            // agree with itself.
            if refs.len() != 1 {
                die(
                    2,
                    &format!("{} distinct access structures saved: {refs:?}", refs.len()),
                );
            }
            eprintln!(
                "stub: {N_DEVICES}/{N_DEVICES} devices saved a share for {:?}",
                saved.values().next().expect("just checked len"),
            );
            // DO NOT exit here. Exiting on our own say-so made the device half of
            // the proof a single bit -- our exit status -- decided by the process
            // the claim is about; a stub that persisted nothing and returned 0
            // passed. Now we keep serving so the coordinator can send
            // `RequestHeldShares` and check for itself, and the run ends when IT
            // closes the pty (read -> EOF above).
        }
    }
}

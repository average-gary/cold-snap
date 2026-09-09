//! cold-snap firmware image for the Coldcard Mk4 (STM32L4S5, Cortex-M4F).
//!
//! **This is the most dangerous file in the project.** A crash before the login
//! path completes bricks the unit, and there is no recovery: DFU is RDP-gated
//! (`mk4-bootloader/dispatch.c:150-165` returns `EPERM`) and the bootloader's own
//! `enter_dfu()` calls `LOCKUP_FOREVER()` rather than trying
//! (`mk4-bootloader/main.c:256-258`).
//!
//! # The handoff, as read from the bootloader
//!
//! The bootloader reads **exactly two words** from
//! [`memmap::FLASH_ISR_BASE`](coldsnap_hal::memmap::FLASH_ISR_BASE)
//! (`mk4-bootloader/startup.S:102-112`): word 0 into `SP`, word 1 into `PC` via
//! `bx lr`. Word 1's LSB **must be set** for Thumb — here that comes free from
//! taking a function pointer on a Thumb target, and it is verified in the linked
//! ELF rather than assumed. `r0` arrives as `1` (`reset_mode`, ignorable) and `LR`
//! holds the entry address itself, so **the entry must never return**: hence
//! `-> !`.
//!
//! State on arrival, all read from bootloader source:
//!
//! * PRIMASK = 1, interrupts globally masked (`dispatch.c:98`, never re-enabled).
//! * `SCB->VTOR` **not set** — still 0, aliasing the bootloader's vector table
//!   whose fault handlers are `bkpt; b .` (`startup.S:43-59`). So a HardFault
//!   today is an infinite hang, not a reset. Setting VTOR is the highest-value
//!   instruction in the entry, and it is step 1 of [`entry::init_hardware`].
//! * FPU already enabled (`clocks.c:87-89`), but behind a compile-time `#if`, so
//!   the entry re-asserts CPACR anyway.
//! * SYSCLK 120 MHz. SysTick **running** at 1 kHz with TICKINT clear. The callgate
//!   polls its COUNTFLAG for SE1 timeouts and COUNTFLAG clears on read, so nothing
//!   here may reprogram or disable SysTick, and nothing may `cpsie i`.
//! * All SRAM below [`memmap::BL_SRAM_BASE`](coldsnap_hal::memmap::BL_SRAM_BASE)
//!   arrives filled with `0xdeadbeef`, **not zeroed**
//!   (`mk4-bootloader/main.c:42,47-49`). That is why
//!   [`singleton::TakeOnce`](coldsnap_hal::singleton::TakeOnce) is tagged, and why
//!   `.bss` zeroing is mandatory rather than a nicety.
//!
//! # The boot sequence, in order
//!
//! [`entry_point`] runs PLAN.md's amended step list and nothing else:
//!
//! | Step | What | Where |
//! |---|---|---|
//! | 0 | vector table: SP, reset, 14 fault trampolines | [`VECTOR_TABLE`], `link.x` |
//! | 1-4a | VTOR, CPACR, `.bss`, `.data`, `compiler_fence` | [`entry::init_hardware`] |
//! | 5 | `#[global_allocator]` init | [`alloc::init`] |
//! | 6 | `BootHealth::read()` — **before any clear** | [`boot`] |
//! | 7 | `Entropy::boot(Sources)` — fail-closed | [`boot`] |
//! | 8 | `StmFlashToken::take().open()` — DBANK geometry | [`boot`] |
//! | 8b | `identity::load_or_create` — the durable secret, or a hold | [`boot`] |
//! | 8c | `Session::open` — the flash-backed `FrostSigner`, share reloaded | [`boot`] |
//! | 8d | `KeypadToken::take().open()` — consent input, best-effort | [`boot`] |
//! | 9 | `UsbToken::take().open()` — OTG_FS + CDC-ACM | [`boot`] |
//! | 10 | bounded event loop, then the panic-counter clear | [`boot`] |
//! | 11 | never returns | `-> !` everywhere |
//!
//! Steps 6-10 are ARM-only because `BootHealth::read`, `bump_counter` and
//! `clear_counter` are all `#[cfg(target_arch = "arm")]` in the HAL — there are no
//! backup registers to read on a host. On a host build [`entry_point`] therefore
//! falls through to a spin loop, which is what keeps `entry.rs`'s host tests
//! buildable.
//!
//! Length rules, both now satisfied: `cli/signit.py:293` requires the *body* —
//! everything at or after `FLASH_TEXT_BASE`, i.e. `.text + .rodata + .data`, and
//! *not* the 16 K vector+header region — to be `>= FW_MIN_LENGTH`
//! (`stm32/sigheader.py:30`, `256*1024`), and
//! `signit.py:295,305` pads it to 512 and then, on the Mk4/Mk5 branch, to **4096**
//! (`verify.c:106`: the installer erases 4 K pages). The measured body is
//! **362,316 B**, 100,172 B over the floor, and signit pads it by 2,228 B
//! (`align_to(362_316, 512) = 362_496`, then `align_to(.., 4096) = 364_544`).
//! Padding is signit's job; never hand it a pre-padded body.
//!
//! Those three numbers were 282,016 / 19,872 / 608 before the dispatch and
//! 331,052 / 68,908 / 724 before the backup reveal was reachable; they are
//! re-measured off the linked ELF, not carried. A stale MEASURED number reads
//! exactly like a checked one, which is why they are corrected here rather than
//! left for the next reader to trust. MEASURED split of the last step (+1,940 B):
//! `.text` +1,884, `.rodata` +56. The BIP39 word table was already linked before it
//! — `Session::confirm_at` calls `backup_pages` for its pre-grant renderability
//! check — so what wiring the reveal into the loop bought back from
//! `--gc-sections` is the CODE that draws a word: `BackupPages::render`,
//! `Frame::mark_sensitive`, `Session::show_backup` and `boot`'s two helpers.
//!
//! Neither rule bounds `firmware_length` in the header, which is the whole image
//! including the 16 K: `verify.c:215` floors *that* at 256 K and `verify.c:212-217`
//! enforces no alignment at all.
//!
//! # What is deliberately NOT brought up
//!
//! * **No clock, PWR or RCC work here.** `usb::bring_up` enables `OTGFSEN`,
//!   `PWREN` and `PWR_CR2.USV` itself (`hal/src/usb.rs:1755-1790`); the 48 MHz
//!   CLK48 source is assumed live from the bootloader's PLLSAI1-Q and is
//!   programmed by nobody in this tree. That is a documented gap in [`usb`], not
//!   one this file papers over.
//! * **No back key on a prompt.** `ui::SignPages`' footer advertises `(9)next`
//!   and nothing else (`hal/src/ui.rs:879`), so on a *prompt* `7` — even though
//!   `ui::BACK_KEY` names it — is a key the glass never offers, and an
//!   unadvertised key must not be a hidden command: [`answer`] refuses it like
//!   any other wrong key. The backup pages are the one screen whose footer does
//!   print it (`BACKUP_BACK_LEGEND`, `(9)next (7)back`), so that is the one
//!   screen [`answer`] returns [`Answer::Back`] for — keyed off the absence of a
//!   consent digit, which is exactly what distinguishes those pages. The rule did
//!   not change: the pad obeys the footer that is actually on the glass.
//! * **No screen for a dead keypad.** A pad that fails to open leaves the
//!   standby screen alone and shows itself only as a refusal the first time
//!   consent is needed. `ui::standby`'s second field is the *key name*, and
//!   putting a device status in it would be a lie on the one screen a user
//!   reads at rest.
//! * **No preview screen for a name being typed.** `Session::pending_name()`
//!   exists and nothing here draws it. Naming is not consent-gated on this port
//!   — the name is committed by `Session::run`'s `FinalizeKeyGen` arm, behind
//!   the keygen screen a human already answered — and the shipped app will not
//!   even offer the field for this device's digest
//!   (`wallet_create.dart:662-704`). A screen for it would be decoration inside
//!   a `cfg(arm)` block that no gate executes. Draw it when a coordinator that
//!   can reach the naming flow exists.
//! * **No store failure counter.** A `Fault::Store` draws a refusal and the loop
//!   carries on; nothing counts how often flash refused. See the `Fault::Store`
//!   arm for why that is not a hold and not a reset.
//! * **No UI task.** The panel is drawn on the way into a state and never in a
//!   loop, here as in the identity hold: one `show` per event, so a wedged panel
//!   can never turn the event loop into a hang.

#![no_std]
// `no_main` only when we are NOT the host test harness. `cargo test` generates its
// own `main`, and `#![no_main]` suppresses it — the link then fails with
// `Undefined symbols: "_main"`. MEASURED: that is the only thing that stood between
// `entry.rs` and having host tests at all. `#![no_std]` needs no such gate; rustc's
// test harness pulls `std` in for itself.
#![cfg_attr(not(test), no_main)]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

mod alloc;
mod entry;

use coldsnap_hal::{keypad, memmap, ui};
use frostsnap_core::device::DeviceToUserMessage;

// ---------------------------------------------------------------------------
// Consent. NOT inside `boot`, and that is the whole reason it is testable.
//
// `boot` is `#[cfg(target_arch = "arm")]`, so anything living in it is invisible
// to every host test — which for a *consent gate* is the one place that is not
// affordable. [`answer`] and [`ask`] are therefore plain module items, compiled
// on both targets, and the tests at the bottom of this file drive every arm of
// them. The only thing left ARM-only is reading a register.
// ---------------------------------------------------------------------------

/// The key [`ui::keygen_check`](coldsnap_hal::ui::keygen_check)'s legend asks
/// for.
///
/// That screen prints a literal `"1=match x=no"` (`hal/src/ui.rs:833`) and **not**
/// a [`ui::ConfirmDigit`]: the randomised digit belongs to the two screens that
/// authorise a *signature*, which was the pre-existing split in
/// [`prompt_screen`](coldsnap_firmware::prompt_screen) and is deliberate.
///
/// So this is the one fact about a screen that is spelled twice in this tree, and
/// the duplicate is the lesser evil. Demanding the digit here instead would
/// refuse four honest keygens in five while the glass says `1` — a legend that
/// lies, which is the failure mode the randomised digit exists to remove. The day
/// `keygen_check` prints a `ConfirmDigit`, delete this constant and the arm of
/// [`answer`] that reads it; nothing else changes.
///
/// Not a guess, and not only mine: `firmware/examples/stub.rs:493-499` reached the
/// same two arms independently (`CheckKeyGen => key == b'1'`,
/// `SignatureRequest => digit.accepts(key)`), and `hostcheck` drives them over a
/// pty against a real coordinator through a 9-of-9 keygen and a signature that
/// verifies. That is the closest thing this tree has to a bench for the arm below.
/// It also means the fact is now spelled in three places (`ui::keygen_check` draws
/// it, the stub checks it, this checks it), which is two too many: the right home
/// is one function beside `prompt_screen` in `firmware/src/lib.rs` that all three
/// call. That file is not mine to edit today.
const KEYGEN_MATCH_KEY: u8 = b'1';

/// The pad half of the paging-key claim, as a **build failure** rather than a test.
///
/// `hal::ui` already asserts that neither paging key is in `CONFIRM_CHARSET`
/// (`hal/src/ui.rs:881-903`) but it is a pure module and cannot see the decode
/// table, and it does not know about [`KEYGEN_MATCH_KEY`] — which is the *other*
/// key [`answer`] accepts. Both halves belong wherever the two are visible
/// together, which is here.
///
/// If [`ui::NEXT_KEY`] were not on the pad, the advance arm would be dead code and
/// a multi-page transaction would be unreachable past page 0. If it collided with
/// [`KEYGEN_MATCH_KEY`], turning a page and matching a keygen code would be the
/// same press. Both inputs are `const`, so neither has to be a test.
const _: () = {
    let mut on_the_pad = false;
    let mut i = 0;
    while i < keypad::DECODER.len() {
        if keypad::DECODER[i] == ui::NEXT_KEY {
            on_the_pad = true;
        }
        i += 1;
    }
    assert!(on_the_pad, "the advance key is not a key this pad can send");
    assert!(
        ui::NEXT_KEY != KEYGEN_MATCH_KEY,
        "the advance key must not also match a keygen code"
    );
};

/// What the pad said about the prompt currently on the glass.
///
/// Four states and not two, because neither "the human has not answered yet" nor
/// "the human wants the next page" is a refusal and neither may be turned into one
/// — see [`answer`]. Naming [`Answer::Wait`] is also what keeps the event loop
/// non-blocking: it is returned, the prompt is re-parked, and the next iteration
/// starts with `cdc.poll` again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answer {
    /// Nothing down, or the debounce samples disagreed. Keep the prompt parked
    /// and go service USB.
    Wait,
    /// [`ui::NEXT_KEY`] on a page that is **not** the last of its set. Draw the
    /// next page and re-park. Never produced for a last page, so it cannot walk
    /// off the end of a page set, and never for any other key.
    Next,
    /// [`ui::BACK_KEY`] on a screen that printed a back legend — which is the
    /// backup pages and nothing else. Produced **only** for a screen carrying no
    /// consent digit (see [`answer`]), so it can never appear on a prompt, where
    /// no footer offers it and a hidden command is the failure mode.
    Back,
    /// The exact key the rendered screen asked for, on the page that printed it.
    /// The **only** path to
    /// [`Session::confirm_at`](coldsnap_firmware::Session::confirm_at) in this
    /// image.
    Yes,
    /// Refuse. The wrong digit, the right digit on a page that did not print it,
    /// `x`, `ui::BACK_KEY` (which no footer advertises), a key that is not on the
    /// pad, two contacts, a pad that could not be read, or no pad at all — all one
    /// answer.
    No,
}

/// One pad [`keypad::Event`] plus the prompt it is answering, into a verdict.
///
/// **FAIL CLOSED.** Exactly one key confirms — the one the screen printed — and
/// everything else is [`Answer::No`], which is a refusal and not a retry. That is
/// [`ui::ConfirmDigit::accepts`]'s own contract (`hal/src/ui.rs:914`,
/// `key == self.0`) and Coldcard's rule at its highest-stakes approval
/// (`shared/hsm_ux.py:58`, `self.refused = (ch != confirm_char)`). A loop that
/// waited for a *valid* key instead of refusing an invalid one would let a human
/// fumble a signing screen until they got it right, which is the fail-open
/// reading of the same code.
///
/// The [`keypad::Event`] match is exhaustive with no `_` arm on purpose: a new
/// variant in the driver must be a compile error here, never a silent fall into
/// a default — and whichever default it fell into would be wrong for half of the
/// possible variants.
///
/// [`keypad::Event::MultiKey`] is a refusal rather than a wait because it is the
/// only state a diodeless matrix can invent a key from, and two keys genuinely
/// held on a signing screen is equally not a consent. `Err` is a refusal for
/// requirement 3's reason: a device that cannot read consent must not sign.
///
/// # `last`, and why the digit is worthless without it
///
/// `last` is [`Shown::Page::last`](coldsnap_firmware::Shown) as returned by the
/// render that put the current frame on the glass — never recomputed here, and
/// never derived from the prompt. A page that is not last prints **no digit**
/// (`hal/src/ui.rs`'s footer prints `(9)next` there instead), so accepting the
/// digit on one would be accepting a key nothing displayed: a blind signature on a
/// screen reading "Send amount #1 of 2", at one guess in five. Hence the rule:
/// with `last` false the only keys that do anything at all are
/// [`ui::NEXT_KEY`] and — on a screen with no `consent` — [`ui::BACK_KEY`], and
/// every other byte, including the digit, is [`Answer::No`].
///
/// # `consent`, and why it is an `Option`
///
/// `Some((prompt, digit))` is a screen that printed a digit and can therefore be
/// answered; `None` is a screen that printed none and can only be paged. Today the
/// second case is exactly the backup reveal, whose consent was given once, on a
/// screen that showed no word, before the first word was drawn.
///
/// This is a **type-level** statement of "the reveal authorises nothing": with
/// `None` there is no [`ui::ConfirmDigit`] in scope to accept and no prompt to hand
/// to [`Session::confirm_at`](coldsnap_firmware::Session::confirm_at), so no key
/// pressed while a share is on the glass can return [`Answer::Yes`]. A `bool` flag
/// would have left a digit lying beside a screen that never drew one, which is the
/// desync the randomised digit exists to prevent. It is also what selects the back
/// arm: the pages that print `(7)back` are precisely the pages that print no digit.
///
/// [`ui::NEXT_KEY`] on the last page **clamps** to [`Answer::Wait`] rather than
/// refusing, which is Coldcard's own story behaviour (`shared/ux.py:237-247`
/// clamps page-down with `min()`), so an over-press at the end of a 67-page
/// transaction costs nothing instead of killing a ceremony the coordinator would
/// have to re-issue. It cannot fail open: `Wait` authorises nothing, and
/// `NEXT_KEY` is const-asserted out of `CONFIRM_CHARSET` (`hal/src/ui.rs:891-902`)
/// and off [`KEYGEN_MATCH_KEY`] (above), so it is not a key any screen can ask
/// for.
fn answer(
    event: Result<keypad::Event, keypad::KeypadError>,
    consent: Option<(&DeviceToUserMessage, ui::ConfirmDigit)>,
    last: bool,
) -> Answer {
    match event {
        // Not a refusal: `read_key` returns after three scans whether or not a
        // human has done anything, so "all up" is the ordinary answer while
        // someone reads the screen.
        Ok(keypad::Event::AllUp | keypad::Event::Unsettled) => Answer::Wait,
        // Turn the page, or clamp. Checked before anything else because it is the
        // one key that is about the *set* rather than the request, and it can
        // never be a confirm key (see the docs above).
        Ok(keypad::Event::Down(key)) if key == ui::NEXT_KEY => {
            if last {
                Answer::Wait
            } else {
                Answer::Next
            }
        }
        // Page back — only on a screen that printed a back legend, which is the
        // backup pages and nothing else. `consent.is_none()` is that test and not a
        // proxy for it: `hal/src/ui.rs`'s `BACKUP_BACK_LEGEND` is drawn by exactly
        // the pages that draw no `ConfirmDigit`, and a screen with a digit is a
        // screen whose footer offers `x` and the digit instead. On a prompt this
        // falls through to the arms below and is refused like any other
        // unadvertised key — `the_back_key_is_not_a_hidden_command`.
        Ok(keypad::Event::Down(key)) if key == ui::BACK_KEY && consent.is_none() => Answer::Back,
        // The page on the glass has more to read after it, so it printed no key to
        // press. Nothing here may authorise, and that includes the digit.
        Ok(keypad::Event::Down(_)) if !last => Answer::No,
        Ok(keypad::Event::Down(key)) => match consent {
            // A screen with no digit and no prompt cannot be answered — there is
            // nothing to accept and nothing to confirm. Unreachable in this image
            // (the only `None` caller is the reveal, which passes `last` false and
            // is caught by the arm above), and a refusal if it ever is reached.
            None => Answer::No,
            Some((prompt, confirm)) => {
                let asked_for = match prompt {
                    // The screen for this one prints `1=match x=no`. See
                    // [`KEYGEN_MATCH_KEY`].
                    DeviceToUserMessage::CheckKeyGen { .. } => key == KEYGEN_MATCH_KEY,
                    // Every other prompt that got as far as being parked printed the
                    // randomised digit, so the digit is the only key that authorises
                    // it. `accepts`, not a comparison spelled here: the value that
                    // was RENDERED and the value that is ACCEPTED are the same
                    // `ConfirmDigit`, so they cannot disagree.
                    //
                    // A non-consent prompt cannot reach this line — `draw_batch`
                    // parks only what `prompt_screen_at` drew a `Shown::Page` for, and
                    // `last` being true narrows that to the page that printed the digit
                    // — and if one somehow did, `Session::confirm_at` refuses it with
                    // `Fault::NotConfirmable`. Two gates, both fail-closed.
                    _ => confirm.accepts(key),
                };
                if asked_for {
                    Answer::Yes
                } else {
                    Answer::No
                }
            }
        },
        Ok(keypad::Event::MultiKey) | Err(_) => Answer::No,
    }
}

/// Ask the pad about whatever is on the glass: **at most one bounded read**, then
/// return.
///
/// `None` for the pad is [`Answer::No`], and that is requirement 3's decision
/// argued in one place. A keypad that failed to open must not brick the device —
/// so this is not a hold, the unit still enumerates, still announces, still
/// answers the read-only messages `Session::recv` admits, and is still
/// diagnosable at a bench. But it must not let a signature through unapproved
/// either, so a device that cannot read consent **refuses** every prompt that
/// needs it. Fail-closed beats available: the failure mode of refusing is a user
/// who cannot sign today, and the failure mode of approving is a coordinator that
/// signs without a human, forever, on a unit whose flash is one-way.
///
/// The refusal is per-prompt rather than a dark hold at open time on purpose. A
/// hold would take a unit with one bad solder joint on `PB0` and make it
/// indistinguishable from dead silicon, on a device that cannot be re-flashed;
/// a refusal says no on the glass and leaves the USB link up to say why.
///
/// [`keypad::Keypad::read_key`] does exactly [`keypad::DEBOUNCE_SAMPLES`] scans
/// (~50 ms) and never waits for a human, so this cannot starve the event loop —
/// which is the other half of the same requirement. Generic over the RNG rather
/// than taking `rng::Entropy`, so the tests below need no entropy seam.
///
/// A dead pad on a backup page (`consent` `None`) is [`Answer::No`] for the same
/// reason and with a bonus: the reveal ends and the words come off the glass on the
/// very next iteration. Fail-closed in both directions.
fn ask<R: rand_core::RngCore>(
    pad: Option<&mut keypad::Keypad>,
    rng: &mut R,
    consent: Option<(&DeviceToUserMessage, ui::ConfirmDigit)>,
    last: bool,
) -> Answer {
    let Some(pad) = pad else {
        return Answer::No;
    };
    answer(pad.read_key(rng), consent, last)
}

/// The vector table: `SP`, the entry, then 14 fault trampolines.
#[repr(C)]
struct VectorTable {
    /// Word 0 -> `SP`. Our free choice; the bootloader takes whatever is here.
    stack_top: u32,
    /// Word 1 -> `PC`, LSB set by the Thumb function-pointer relocation.
    reset: unsafe extern "C" fn() -> !,
    /// Vectors 2..15 — NMI, HardFault, MemManage, BusFault, UsageFault, the four
    /// reserved slots, SVCall, DebugMon, reserved, PendSV, SysTick.
    ///
    /// All 14, including the reserved slots, not just the five real faults. A
    /// reserved slot cannot be taken by hardware, but "cannot" here rests on
    /// reading the core right, and a wrong non-zero pointer costs one reset while a
    /// wrong zero costs the unit. Filling them is free.
    ///
    /// **These are why step 1 is worth anything.** Without them `VTOR` points at a
    /// two-word table and a fault fetches whatever follows it in `FLASH_ISR` —
    /// zero, since nothing else is emitted there. A zero vector escalates to
    /// HardFault, and a HardFault with a zero vector is lockup: the exact
    /// permanent hang that moving `VTOR` off the bootloader's `bkpt; b .` table
    /// was supposed to remove.
    exceptions: [extern "C" fn() -> !; 14],
}

/// Placed at `0x0802_0000` by `firmware/link.x`.
///
/// `#[used]` plus `KEEP()` in the linker script: without both, LTO or `--gc-sections`
/// drops the only thing the bootloader ever reads and the unit jumps to `0xdeadbeef`.
#[used]
// Section name gated for the same reason as `no_main` above: a bare
// `.vector_table` is not a legal mach-o section specifier ("requires a segment and
// section separated by a comma"), so under a host test build LLVM aborts before any
// test can run. `not(test)` and not `target_os = "none"` so that the ARM build —
// which is what the linker script and every ASSERT act on — is affected by nothing
// at all.
#[cfg_attr(not(test), link_section = ".vector_table")]
static VECTOR_TABLE: VectorTable = VectorTable {
    // Top of usable SRAM. A full-descending stack never writes *at* `SP`, so
    // being equal to `BL_SRAM_BASE` does not touch the bootloader's 8 K — which
    // the callgate wipes on every entry AND exit.
    stack_top: memmap::ESTACK_TOP,
    reset: entry_point,
    exceptions: [fault_trampoline; 14],
};

/// Vectors 2..15: one bare `panic!()`, which `hal::panic` turns into a counted
/// reset (DECISIONS.md decision 6).
///
/// One handler for all fourteen on purpose. `IPSR` already says which exception
/// was taken and the counter already says how often, so per-vector handlers would
/// add flash and a maintenance surface to report something the core reports for
/// free. `-> !` matches the table's field type and is honest: a fault handler here
/// never returns to the faulting instruction, because the faulting state is exactly
/// what must not be resumed.
///
/// Safe `extern "C" fn`, not `unsafe`: it takes no arguments and touches nothing,
/// so there is no contract for a caller to break, and it coerces to the table's
/// pointer type either way. The hardware pushes the exception frame; nothing here
/// reads it.
extern "C" fn fault_trampoline() -> ! {
    // A `&'static str`, no formatting arguments: `core::fmt` machinery on this path
    // would be flash spent on a message nothing can display.
    panic!("fault");
}

/// Reset entry. `LR` holds this address, so returning would jump back here with a
/// dirtied machine state: the signature is `-> !` and that is not negotiable.
///
/// # Safety
///
/// Only ever called by the bootloader's `bx lr` handoff, once, on a machine with
/// masked interrupts, `VTOR` = 0 and `0xdeadbeef`-filled SRAM.
#[no_mangle]
pub unsafe extern "C" fn entry_point() -> ! {
    // Steps 1-4a: VTOR, CPACR, `.bss`, `.data`, `compiler_fence`. Nothing may be
    // moved above this call — every instruction before the VTOR store inside it
    // runs with faults still vectoring into the bootloader's `bkpt; b .`.
    //
    // SAFETY: this is the reset entry, reached once, from the bootloader's `bx lr`.
    // No `static` has been read and nothing has allocated.
    unsafe { entry::init_hardware() };

    // Step 5: the heap. AFTER step 3, not merely after step 4 — the allocator's
    // `READY` sentinel lives in `.bss` (measured: `.bss._ZN..ALLOCATOR..`), so an
    // init before the zeroing loop would be overwritten by it and every later
    // allocation would be refused. Before step 6 because everything from here on
    // is allowed to allocate.
    //
    // SAFETY: `.bss` and `.data` are initialised by the call above, and this is the
    // first and only call.
    unsafe { alloc::init() };

    #[cfg(target_arch = "arm")]
    boot();

    // Host builds only: steps 6-10 need backup registers, an SE and an OTG core.
    // `spin_loop()` rather than a bare `loop {}` so there is an instruction in the
    // body to find in a disassembly.
    #[cfg(not(target_arch = "arm"))]
    loop {
        core::hint::spin_loop();
    }
}

/// Steps 6-11: boot health, entropy, flash, USB, then the event loop.
///
/// Split out of [`entry_point`] only because every counter function it calls is
/// `#[cfg(target_arch = "arm")]` in the HAL. Diverges, so [`entry_point`] can call
/// it as a statement and still be `-> !`.
///
/// # Failure policy
///
/// Bring-up failures `panic!()`, which is a *counted* reset, not a halt
/// (DECISIONS.md decision 6): a transient fault self-heals because the bootloader
/// still holds a verified signed image, and a deterministic one is bounded by
/// [`PANIC_RESET_THRESHOLD`](coldsnap_hal::panic::PANIC_RESET_THRESHOLD) rather than
/// looping forever. There is no DFU fallback to reach: DECISIONS.md decision 6
/// records DFU as hardware-impossible at RDP=2 (dispatch.c:150-165).
///
/// Durable-state failures are the third case and neither of the other two: a
/// damaged identity record, or a stored secret that is not a scalar, is
/// bit-for-bit identical on the next boot, so they *hold* — see `hold`, which
/// draws one frame and then spins, above USB bring-up so the device never
/// enumerates.
///
/// A keypad that will not open is the fourth case and none of the other three:
/// it neither panics nor holds. See [`ask`] for the argument — the short version
/// is that a pad is what makes the device *usable*, while the identity is what
/// makes it *itself*, so a missing pad refuses consent rather than refusing to
/// boot. Nothing about it can approve anything: [`Answer::No`] is the only value
/// [`ask`] can return without a pad.
///
/// A flash write that refuses a *share* is the fifth case and is none of the four:
/// it draws a refusal and the loop carries on. It cannot be a hold (a hold above
/// USB is unreachable from inside the loop, and the link is the only way to
/// diagnose a refusing flash) and it must not be a panic (the input is
/// coordinator-controlled). What makes that safe is not this file: `Session::run`
/// persists **before** it fills the outbox, so a `Fault::Store` means nothing was
/// acknowledged. See the `Fault::Store` arm in the dispatch for the full argument.
///
/// Runtime failures inside the loop **must not** panic, and that asymmetry is
/// deliberate. `Cdc::poll` can fail on a coordinator-supplied oversize packet
/// (`UsbError::OversizePacket`), so panicking there would hand a hostile
/// coordinator a remote reset loop. The FIFO is drained on that error anyway, so the link resynchronises
/// on the next packet; dropping the error is the fail-safe direction here.
#[cfg(target_arch = "arm")]
fn boot() -> ! {
    use coldsnap_hal::panic::{bump_counter, clear_counter, BootHealth, Counter};
    use coldsnap_hal::{comms, display, flash, identity, rng, usb};
    use coldsnap_firmware::{
        firmware_digest, prompt_screen_at, DebugFlash, Fault, Outbox, Session, Shown,
    };
    use core::cell::RefCell;
    // `Session` is generic over its flash (`Session<'a, F: NorFlash + Debug>`), so
    // the two nested helpers that take one have to name the bound. Nothing else here
    // touches `embedded_storage`.
    use embedded_storage::nor_flash::NorFlash;
    use frostsnap_comms::Sha256Digest;

    /// Say why, then hold forever. The two durable-state faults — a damaged
    /// identity record and a stored secret that is not a scalar — share this
    /// because they are the same situation: bytes on flash that will be
    /// bit-for-bit identical on the next boot, so a counted reset cannot help and
    /// would only spend the `Counter::Panic` budget on the way to
    /// `LOCKUP_FOREVER`.
    ///
    /// Drawing happens on the way *in* and never inside the hold: one frame, no
    /// loop, so a wedged panel cannot turn a hold into a hang. Every step is
    /// best-effort — a `?` or an `unwrap` here would turn a display fault into a
    /// reset loop, which is the opposite of the point. The panel is opened here
    /// rather than at step 8 so the happy path pays nothing for it.
    fn hold(reason: &str) -> ! {
        let mut frame = ui::Frame::new();
        ui::identity_fault(&mut frame, reason);
        if let Some(Ok(mut panel)) = display::PanelToken::take().map(display::PanelToken::open) {
            let _ = panel.show(frame.as_bytes());
        }
        loop {
            core::hint::spin_loop();
        }
    }

    /// The prompt on the glass, the digit it was drawn with, the page it was drawn
    /// at, and whether that page printed a key.
    ///
    /// One tuple and not four variables because all four are facts about **one
    /// render**: they are produced together by [`draw_prompt`] and consumed
    /// together by [`answer`], so nothing can update three of them and leave the
    /// fourth describing the previous screen. A cursor kept anywhere else — on
    /// `Session`, or in a variable beside this one — would be a second copy free to
    /// drift from the glass, which is precisely the desync a randomised digit
    /// exists to make impossible.
    type Parked = (DeviceToUserMessage, ui::ConfirmDigit, usize, bool);

    /// Draw one prompt, if this device can draw it at all.
    ///
    /// The map itself is
    /// [`prompt_screen`](coldsnap_firmware::prompt_screen), in the pure library
    /// and NOT here, because `boot` is `#[cfg(target_arch = "arm")]`: a map in
    /// this file is invisible to every host test and to the pty harness, and —
    /// the part that matters — `Session::confirm` could not share it. It does
    /// share it, so a request whose screen refused can never be signed. All this
    /// function adds is the panel, which is the only ARM-only thing about
    /// drawing.
    ///
    /// `Shown::Nothing` is an informational prompt with no screen: leave whatever
    /// is already on the panel rather than blanking it. An `Err` frame holds
    /// [`ui::refusal`](coldsnap_hal::ui::refusal) and is worth showing — the
    /// device saying no is something a user is entitled to see.
    ///
    /// `Some(last)` means **page `page` of this request is now on the glass**, and
    /// `last` is that render's own [`ui::SignPages::is_last`], not a recomputation:
    /// it is the fact that the frame printed a key to press. That pair is the park
    /// predicate for [`Answer`], and reading it off the same funnel
    /// `Session::confirm_at` gates on is what stops this file from growing a second
    /// prompt-to-screen map that could disagree with the library's.
    ///
    /// `None` is also what an over-advanced cursor gets: `page` past the end of a
    /// set is `Err(Refusal::Undisplayable)` in the library, so the glass shows a
    /// refusal and the caller drops the prompt. Fail-closed with no arithmetic
    /// here to get wrong.
    ///
    /// **Takes the panel by `&mut`, not `Option<&mut>`, and that is a security
    /// property rather than tidiness.** The confirm digit is randomised precisely
    /// so it can only be answered by *reading* it, so a device that cannot draw is
    /// a device on which nothing can have been read and therefore nothing can have
    /// been consented to. Making the panel mandatory here means the "no panel, no
    /// consent" rule is a type and not a one-line `else` branch someone could flip
    /// — there is no branch to flip, because [`draw_batch`] is unreachable without
    /// a panel and it is the only thing that produces a parked prompt.
    fn draw_prompt(
        panel: &mut display::Panel,
        prompt: &DeviceToUserMessage,
        confirm: ui::ConfirmDigit,
        page: usize,
    ) -> Option<bool> {
        let mut frame = ui::Frame::new();
        match prompt_screen_at(&mut frame, prompt, confirm, page) {
            // No screen for this prompt. Nothing drawn, nothing parked.
            Ok(Shown::Nothing) => None,
            Ok(Shown::Page { last }) => {
                let _ = panel.show(frame.as_bytes());
                Some(last)
            }
            // The frame holds `ui::refusal`; show it and park nothing.
            Err(_refusal) => {
                let _ = panel.show(frame.as_bytes());
                None
            }
        }
    }

    /// Draw a batch of prompts and hand back the one a human can answer, with the
    /// digit it was drawn with, the page it was drawn at, and whether that page
    /// printed a key.
    ///
    /// A fresh [`ui::ConfirmDigit`] per prompt, from the same proven entropy the
    /// signer uses, and the whole tuple travels together: the value that was
    /// RENDERED is the value [`answer`] will check, at the page it was rendered
    /// for, so neither the digit nor the page is ever re-derived between showing
    /// and accepting.
    ///
    /// Always page 0 — a request arrives at its first page, and the cursor only
    /// ever moves by an [`Answer::Next`] in the event loop.
    ///
    /// The **last** consent screen wins, because it is the one on the glass — a
    /// human answers what they can see. Earlier ones are dropped rather than
    /// queued, which is the fail-closed direction: a dropped prompt is never
    /// confirmed. Nothing is returned for a batch with no consent screen in it,
    /// so an informational message arriving while a signing prompt is parked
    /// cannot silently discard it (see the call sites, which only overwrite on
    /// `Some`).
    ///
    /// `&mut display::Panel` and not `&mut Option<..>`: this is the **only**
    /// producer of a parked prompt in the image, so requiring a panel to call it is
    /// what makes "a device that cannot draw cannot consent" structural. Both call
    /// sites are inside an `if let Some(panel)`, and a batch that is never drawn is
    /// a batch that parks nothing — which is the fail-closed direction, since a
    /// prompt that is never parked is never confirmed.
    fn draw_batch(
        panel: &mut display::Panel,
        rng: &mut rng::Entropy,
        prompts: impl IntoIterator<Item = DeviceToUserMessage>,
    ) -> Option<Parked> {
        let mut parked = None;
        for prompt in prompts {
            let confirm = ui::ConfirmDigit::draw(rng);
            if let Some(last) = draw_prompt(panel, &prompt, confirm, 0) {
                parked = Some((prompt, confirm, 0, last));
            }
        }
        parked
    }

    /// The device saying no, which a user is entitled to see. Best-effort: a
    /// display fault must never turn a refusal into a reset.
    fn refuse(panel: Option<&mut display::Panel>) {
        let Some(panel) = panel else { return };
        let mut frame = ui::Frame::new();
        ui::refusal(&mut frame);
        let _ = panel.show(frame.as_bytes());
    }

    /// The screen the device shows at rest — and **the screen that takes a backup
    /// off the glass**.
    ///
    /// One definition for both, because they are one frame: "nothing is happening
    /// here now" is exactly what the panel must say the moment a reveal ends, and a
    /// second variant of it would be a second thing to keep in step with the first.
    ///
    /// The name is read back off flash, so a device named in a previous session is
    /// named on this screen after an unplug. `"no name"` is the *unnamed* case only.
    ///
    /// ponytail: the share row still says "no share held" even when step 8c reloaded
    /// one. `ui::standby`'s third field is a share INDEX and `frostsnap_core`'s
    /// `ShareIndex` is a scalar with no honest `u32` form
    /// (`schnorr_fun::frost::ShareIndex`), so the only way to fill it here is to
    /// invent a number. Fixing it means `ui::standby` taking a `ShareImage`, which is
    /// `hal/src/ui.rs`'s call; until then a held share is visible over
    /// `RequestHeldShares`, which does answer from flash.
    fn idle<F: NorFlash + core::fmt::Debug>(session: &Session<'_, F>, panel: &mut display::Panel) {
        let mut frame = ui::Frame::new();
        let name = session.stored_name();
        ui::standby(&mut frame, name.as_deref().unwrap_or("no name"), "", None);
        let _ = panel.show(frame.as_bytes());
    }

    /// Draw page `page` of a granted backup reveal, or take the words off the glass.
    ///
    /// **The only caller of [`Session::show_backup`] and the only producer of the
    /// reveal cursor**, which is what makes requirement 5 control flow instead of a
    /// rule someone has to remember: every leg that returns `None` redraws the panel
    /// first, so there is no way to end this flow with a share still lit, and no way
    /// to keep a cursor alive without a frame behind it.
    ///
    /// `Ok(false)` is `page` past the end of the set, which is how a reveal ENDS —
    /// [`Session::show_backup`] drops the grant on that leg, so a human cannot page
    /// back afterwards to re-read word 20 without consenting again, and the
    /// coordinator cannot ask twice on one press. The library leaves `frame`
    /// untouched there (drawing is deliberately the caller's), so the words stay on
    /// the panel until [`idle`] overwrites them — which is this function's job and
    /// the reason it, and not the event loop, owns the ending.
    ///
    /// `Err` is the device saying no: no grant at all, a share that no longer
    /// decrypts, or a word `ui::BackupPages::new` refuses. Never a panic — this runs
    /// inside the event loop where a `Fault` is coordinator-influenced and a panic
    /// is a counted reset with no DFU beyond it (decision 6).
    ///
    /// `&mut display::Panel` rather than `Option<&mut ..>`, for
    /// [`draw_batch`]'s reason: a device that cannot draw must not be able to start
    /// paging a secret it is not showing anyone.
    fn show_backup_page<F: NorFlash + core::fmt::Debug>(
        session: &mut Session<'_, F>,
        page: usize,
        panel: &mut display::Panel,
        rng: &mut rng::Entropy,
    ) -> Option<usize> {
        let mut frame = ui::Frame::new();
        match session.show_backup(page, &mut frame, rng) {
            Ok(true) => {
                let _ = panel.show(frame.as_bytes());
                Some(page)
            }
            Ok(false) => {
                idle(session, panel);
                None
            }
            Err(_fault) => {
                ui::refusal(&mut frame);
                let _ = panel.show(frame.as_bytes());
                None
            }
        }
    }

    /// One past the last page of a backup, i.e. the index that ENDS a reveal.
    ///
    /// Derived from `hal::ui`'s own two constants rather than written as `8`, so the
    /// day a page holds five words this still names the first invalid index.
    /// `BackupPages::len()` is the same arithmetic, but reaching it needs a
    /// `BackupPages`, and building one needs the words — which is precisely what
    /// this file must never hold.
    const BACKUP_END: usize = 1 + ui::BACKUP_WORDS.div_ceil(ui::WORDS_PER_PAGE);

    // --- Step 6: read the counters BEFORE anything clears one. --------------
    // Not merely diagnostics-ordering hygiene: `read_counter` is what calls
    // `enable_backup_access`, so this is also where the backup domain becomes
    // writable for the clear at the bottom of the loop.
    let health = BootHealth::read();

    // --- Step 7: entropy, fail-closed. -------------------------------------
    // `take_all()` is the whole `Sources` proof; `Entropy::boot` is the only
    // unconditional constructor, so a stub source cannot reach this line.
    let Some(sources) = rng::Sources::take_all() else {
        // Unreachable by construction — this is the first and only `take_all` in
        // the image — so if it fires, a `TakeOnce` tag decoded wrong and every
        // singleton in the tree is suspect. Reset, do not continue without entropy.
        panic!("entropy singletons already taken");
    };
    let mut entropy = match rng::Entropy::boot(sources) {
        Ok(entropy) => {
            // Rule 4 of `panic::boot_sequencing`: clear `RngFault` only once
            // entropy is *proven*, which is precisely what an `Ok` here is. Its
            // budget is separate from `Panic`'s, so it clears here and not with the
            // other one.
            let _ = clear_counter(Counter::RngFault);
            entropy
        }
        Err(_fault) => {
            // The one counter nothing else bumps: `Counter::RngFault` documents
            // itself as "consecutive `RngFault`s at boot", and this is the only
            // place a boot-time entropy failure is observable. Bump BEFORE the
            // panic — the panic handler only ever touches `Counter::Panic`, so
            // without this the entropy budget would never accumulate.
            //
            // No retry loop. A stuck source stays stuck (`Entropy::boot`'s own
            // docs) and retrying at boot is a brick, so this resets instead.
            let _ = bump_counter(Counter::RngFault);
            panic!("entropy fail-closed");
        }
    };

    // --- Step 8: flash. ----------------------------------------------------
    // `open()` and not a bare `take()`: opening is what reads `FLASH->OPTR` and
    // applies the DBANK check, and it clears the stale `FLASH->SR` error bits the
    // bootloader leaves behind (including `PEMPTY`). Both are once-per-boot work,
    // and doing them here means a wrong page geometry is a reset at boot instead of
    // a surprise on the first nonce write.
    let Some(Ok(flash)) = flash::StmFlashToken::take().map(flash::StmFlashToken::open) else {
        panic!("flash geometry");
    };
    // Into a `RefCell` immediately, because the signer's nonce slots hold a
    // SHARED borrow of the flash for as long as `boot`'s frame lives, while
    // `identity::load_or_create` wants `&mut`. `borrow_mut()` below is a
    // statement-scoped temporary, so the `RefMut` is dead before the slots exist.
    // `DebugFlash` supplies the `core::fmt::Debug` that `FrostSigner::new`'s bound
    // demands and nothing else — delete it the day the HAL grows its own impl.
    //
    // From here on `flash` has the same rule `link` has: nothing may hold a borrow
    // across a call that might take another, because a `RefCell` double-borrow
    // panics and every reachable panic on this unit is a brick.
    let flash = RefCell::new(DebugFlash(flash));

    // --- Step 8b: identity. ------------------------------------------------
    // Generated once, on the first boot that finds no committed record, and read
    // back off flash on every boot after that. `DeviceId` derives from this
    // secret, so a second one is a second device and every share the user holds
    // would be orphaned — which is why `load_or_create` refuses rather than
    // regenerates when a committed record does not verify.
    //
    // NOT a panic on `Err`, unlike steps 7-9 above, and the failure policy at the
    // top of this function says why: a damaged flash record is stable across
    // resets, so panicking on it spends a bounded counter on an unclearable fault
    // and ends in `LOCKUP_FOREVER`. The refusal is a hold, and the hold is DARK —
    // it sits below step 9, so USB never comes up and no coordinator can reach a
    // device that cannot prove its identity. See the `Err` arm.
    //
    // Placed after step 8 deliberately: flash is already proven open here, so
    // "generated a key but could not persist it" is unreachable rather than
    // handled.
    let secret = match identity::load_or_create(&mut *flash.borrow_mut(), &mut entropy) {
        Ok(secret) => secret,
        // HOLD, and deliberately not a `panic!()` like every bring-up step above.
        // The asymmetry is the point: those faults are plausibly transient, so a
        // counted reset can self-heal. An identity fault is a property of bytes
        // sitting in flash, so it is bit-for-bit identical on the next boot —
        // panicking would spend the `Counter::Panic` budget on a fault that cannot
        // clear and end in `LOCKUP_FOREVER`, which is indistinguishable from dead
        // silicon at a bench.
        //
        // Held BEFORE USB, so a device that cannot prove which device it is never
        // enumerates and a coordinator can never talk to it. `Damaged` in
        // particular means this device may ALREADY have announced and be holding
        // the user's shares, so continuing under a fresh identity is the one
        // outcome that destroys a wallet rather than merely failing.
        //
        // The hold stays above USB bring-up: a device that cannot prove which
        // device it is must never enumerate. Do NOT resolve a future diagnostic
        // need by moving USB earlier — that trades the security property for a
        // channel. The panel is the diagnostic, and it needs no host.
        // PLAN.md §9 item 14: the hold used to be DARK, which is correct
        // fail-closed behaviour but indistinguishable from dead silicon at a
        // bench. Say why, then hold — see `hold`, which diverges, so this arm
        // still cannot fall through to a device without an identity.
        Err(fault) => hold(match fault {
            // Wording matters: this is the one that means "this device may
            // already hold the user's shares", i.e. do not re-key it.
            identity::IdentityFault::Damaged => "damaged record",
            identity::IdentityFault::Flash(_) => "flash refused",
            identity::IdentityFault::VerifyFailed => "write unverified",
            identity::IdentityFault::NoScalar => "no valid scalar",
        }),
    };

    // --- Step 8c: the signer. ----------------------------------------------
    // The real `FrostSigner`, keyed by the durable identity secret and backed by
    // the nonce slots in `FLASH_FS` — not `new_random`, not `MemoryNonceSlot`. A
    // signer whose nonces do not survive a power cycle re-issues nonces after a
    // reset, and FROST nonce reuse leaks the share.
    //
    // FAILURE POLICY, and it is the third of three in this function on purpose.
    // `Session::open`'s only failure is `Fault::IdentityScalar`: the stored secret
    // is not a usable scalar. That is a property of bytes in flash, identical on
    // the next boot, so it belongs with the identity hold and NOT with the
    // `panic!()`s of steps 7-9 — a counted reset cannot clear it and would end in
    // `LOCKUP_FOREVER`. Same hold, same screen, and the same reason string
    // `IdentityFault::NoScalar` gets, because to a user at a bench it is the same
    // fault: this device cannot prove which device it is.
    //
    // Unreachable in practice — `load_or_create` only ever returns bytes it has
    // checked are `0 < s < n` — but it is an `Option`, so it is an arm and never an
    // `expect`.
    //
    // THE SHARE AND NAME STORES COME UP HERE TOO, and they take the same
    // `&RefCell<DebugFlash<StmFlash>>` this line already passes — no second flash
    // handle, no second geometry check, and no `StmFlashToken::take()` that could
    // fail: `Session::open` opens `ShareStore` and `NameStore` over the very cells
    // the nonce slots and the identity record share, at `memmap::FS_SHARE_OFFSET`
    // and `FS_NAME_OFFSET`. That is why this file gained no store plumbing at all
    // for gap 1: the ownership pattern step 8 already established is the one the
    // stores wanted.
    //
    // `open` is also where a saved share comes BACK: it replays the keygen triple
    // through `apply_mutation`, so `RequestHeldShares` answers from flash on the
    // boot after a keygen rather than from a keygen that is still in RAM. A
    // record that fails its own checksum is "no share this boot" and not a hold —
    // it was never acked, so no coordinator believes it exists.
    let mut session = match Session::open(&flash, &secret) {
        Ok(session) => session,
        Err(_fault) => hold("no valid scalar"),
    };

    // The digest a coordinator sees. Computed once, before USB, over the range the
    // bootloader signs; `firmware_digest` bounds the header's length field three
    // ways before using it.
    //
    // An all-zero digest when the header is unreadable, never a panic and never a
    // skipped announce: zeros can match no released firmware, so upgrade
    // eligibility fails closed, and the device still announces and is still
    // usable. On real hardware `None` is unreachable — the bootloader will not
    // start an image whose header it could not verify.
    //
    // Nothing in this tree emits the header and nothing should: `link.x` reserves
    // the 128 bytes by shrinking `FLASH_ISR`, and `cli/signit.py` writes the slot
    // itself at pack time from its own CLI arguments (`signit.py:315-325`),
    // *discarding* whatever the input had there (`signit.py:275-276` splits the
    // `-r` input around the slot and keeps neither end of it). So `Some` is the
    // path taken for any signed artifact, and `None` only for an unsigned flat
    // binary on a bench, where the slot is still erased `0xff`.
    //
    // SAFETY: `FLASH_ISR_BASE .. + FLASH_ISR_LEN + FLASH_TEXT_LEN` is this image's
    // own memory-mapped, read-only flash, const-asserted contiguous and to end at
    // `FLASH_FS_BASE` in `hal/src/lib.rs`. Nothing writes it, so a shared slice
    // over it aliases nothing mutably. Erased cells read as `0xff`; no read past
    // the header's length field happens unless that field passed its bounds.
    let image = unsafe {
        core::slice::from_raw_parts(
            memmap::FLASH_ISR_BASE as *const u8,
            (memmap::FLASH_ISR_LEN + memmap::FLASH_TEXT_LEN) as usize,
        )
    };
    let digest = firmware_digest(image).unwrap_or(Sha256Digest([0u8; 32]));

    // The panel, for the rest of the boot. Best-effort and `Option`: a device that
    // cannot draw is still a device that can sign, so a display fault must not be a
    // reset. Taken AFTER both holds above, each of which diverges, so the
    // take-once can never be contended.
    let mut panel = display::PanelToken::take()
        .map(display::PanelToken::open)
        .and_then(Result::ok);

    // --- Step 8d: the pad. -------------------------------------------------
    // Alongside the panel and with the same shape, because the two are one
    // instrument: the screen asks and the pad answers, and neither alone is
    // consent. Before USB so `open`'s `ColumnsStuckLow` check — the one that
    // catches a `GPIOB_MODER` write that did not take, which would otherwise be
    // a pad reading all twelve keys down forever — runs before any coordinator
    // can reach us.
    //
    // `Option` and best-effort, NOT a `panic!()` like steps 7-9 and NOT a hold
    // like 8b/8c. The full argument is on `ask`; here is the one line of it that
    // matters: `None` reaches exactly one place, and that place returns
    // `Answer::No`.
    let mut keypad = keypad::KeypadToken::take()
        .map(keypad::KeypadToken::open)
        .and_then(Result::ok);

    // One standby frame, before USB, so a bench sees a live device rather than a
    // dark one while it waits for a coordinator. See [`idle`], which is also what
    // ends a backup reveal — the same screen, drawn from one place.
    if let Some(panel) = panel.as_mut() {
        idle(&session, panel);
    }

    // --- Step 9: USB. ------------------------------------------------------
    // `open()` runs `bring_up`, which enables `OTGFSEN`/`PWREN`/`USV` itself. The
    // 48 MHz CLK48 source is NOT programmed by anything in this tree — see the
    // module docs. Nothing here fakes it.
    let Some(Ok(mut cdc)) = usb::UsbToken::take().map(usb::UsbToken::open) else {
        panic!("usb bring-up");
    };

    // --- Step 10: the event loop. ------------------------------------------
    let mut packet = [0u8; usb::MAX_PACKET_SIZE];
    // Latched so the clear is attempted once, not on every iteration of a hot loop
    // that would otherwise write a backup register forever.
    let mut cleared = false;

    // The device end of the wire. `Link::new` is `const`, and this lives in `boot`'s
    // frame rather than in a `static` on purpose: `boot` never returns, so the frame
    // is effectively permanent, and a `static` would put `FRAME_LIMIT` bytes in `.bss`
    // for the entry to zero on every boot for no benefit. The stack descends from
    // `ESTACK_TOP` with 548,268 B of runway (MEASURED: `ESTACK_TOP - _end` in the
    // linked ELF), so a 4 KiB inline buffer is affordable — but it IS the largest
    // single thing on this stack, ahead of `ui::Frame` at 1,024 B and the signer at
    // 272 B, so it is the first place to look if the runway ever gets tight. There
    // is no stack-depth tool in this tree to say when that is, and no guard page
    // either: Armv7E-M has no MSPLIM, so the runway is the only thing between a
    // descending SP and the bootloader's `dfu_flag`.
    let mut link = comms::Link::new();

    // Set inside `poll`'s callback and acted on after it returns. `poll` borrows
    // `link` mutably for the duration of the callback, so nothing that touches
    // `link` — or that could panic into a path that inspects it — may run in there.
    // Deferring the write also keeps the USB write off the callback's stack depth.
    let mut send_magic_reply = false;

    // Replies, already encoded and already capped (one nonce segment per frame, a
    // truncated `Debug`, an over-long `HeldShares2` refused whole). Filled inside
    // `poll`'s callback and drained to `cdc` after it returns, for the same reason
    // `send_magic_reply` is: the callback holds `link` and must not also reach the
    // USB write path.
    let mut outbox = Outbox::new(session.device_id());

    // The prompt currently on the glass waiting for a human — see `Parked`.
    // `Option` and not a queue: there is one screen, so there is one answerable
    // question, and a second consent prompt replaces the first rather than stacking
    // behind it — an unanswered prompt is an unsigned one, and its page cursor goes
    // with it rather than surviving to describe a screen nobody is looking at.
    //
    // Parked here rather than answered inside `poll`'s callback for the reason
    // requirement 4 gives: the callback holds `link` mutably, and a human takes
    // seconds. Answering in there would stop `cdc.poll` for as long as someone
    // stared at the screen — and a 67-page transaction is 67 human presses, so the
    // paging cursor makes that worse, not better, if it is ever moved in there.
    let mut parked: Option<Parked> = None;

    // The page of a granted backup reveal that is on the glass, if one is. A
    // CURSOR AND NOTHING ELSE: the grant itself lives in `Session`, set only by
    // `confirm_at` and taken by `show_backup`, so this cannot authorise a reveal
    // any more than `Parked`'s page cursor can authorise a signature. It can only
    // page one a human already consented to.
    //
    // Separate from `parked` because the two screens answer different keys — a
    // backup page prints no digit, so nothing on it can confirm anything, and it is
    // the only screen whose footer advertises `ui::BACK_KEY`. They are mutually
    // exclusive by construction: the `else if` below means at most one of them is
    // serviced per iteration (so at most ONE bounded pad read), and the cursor drop
    // beside the only other place a prompt reaches the glass clears this one when a
    // prompt is drawn over the words.
    let mut revealing: Option<usize> = None;

    loop {
        // `unwrap_or(0)` and never `?`/`unwrap`: see the failure policy above. A
        // coordinator chooses the packet length.
        // `.min(packet.len())` is defence in depth, not a fix for a known bug:
        // `usb::CdcPort::poll` is bounded by `hal::usb::fifo_read` today, but that
        // bound lives two crates away from the slice below, and nothing here would
        // notice if it moved. At RDP=2 an out-of-range slice is a `panic!` with
        // `panic = "abort"` and no way to reinstall — permanently dead silicon from a
        // refactor in another crate. The clamp costs one instruction and makes the
        // bound local to the code that depends on it.
        //
        // NOT `unwrap`/`expect`: a coordinator chooses the packet length, so a
        // failure here must never be a remote reset. See the failure policy above.
        let n = cdc.poll(&mut packet).unwrap_or(0).min(packet.len());

        // Every byte from here to `decode_body` is coordinator-controlled. The bound
        // is structural — `Link`'s accumulator IS `[u8; FRAME_LIMIT]` — and both
        // decode legs are limited (`DECODE_ALLOC_LIMIT`, `ENCAPS_DECODE_LIMIT`), so
        // this is the first place in the image where those refusals actually run.
        let mut handled_frame = false;
        // Read off the link itself rather than latched across iterations, so the
        // `continue` on a desync cannot leave a stale flag behind: `Link::poll`
        // unlinks on desync, so the next successful handshake is an edge again and
        // re-announces, which is exactly what a restarted coordinator needs.
        let was_linked = link.is_linked();
        let polled = link.poll::<comms::FromCoordinator, _>(&packet[..n], |frame| {
            match frame {
                // The coordinator re-sends its pattern every `MAGIC_BYTES_PERIOD`
                // until it reads our reply, so seeing this once we are already
                // linked is ordinary, not an error.
                comms::ReceiveSerial::MagicBytes(_) => send_magic_reply = true,
                comms::ReceiveSerial::Message(msg) => {
                    // `decode_body`, NOT the vendored `.decode()`: the vendored one
                    // re-enters bincode with a 32 KiB budget where a 20-byte inner
                    // blob provokes a 32,640 B allocation. See `comms::decode_body`.
                    match comms::decode_body(msg.message_body) {
                        Ok(body) => {
                            // Unchanged from before the dispatch landed, and
                            // deliberately: a decoded frame is what proves the
                            // core reset, the FIFOs, enumeration, every control
                            // transfer, the RX path and both decode legs worked.
                            // What the device then chooses to DO with the body —
                            // answer it, refuse it, or find it out of order — is
                            // policy, and a refusal is a healthy image, not an
                            // unhealthy one.
                            handled_frame = true;
                            // The dispatch. NOTHING here may panic: every byte in
                            // `body` is coordinator-controlled, so a panic is a
                            // remote reset loop, and `session` reports with a
                            // `Fault` rather than unwinding.
                            match session.recv(body, &mut entropy, &mut outbox) {
                                // Drawn inside the callback because the panel is
                                // not `link` and is not `flash`: no borrow of
                                // either is held across it. Replies still leave via
                                // the outbox after `poll` returns.
                                //
                                // ANSWERED outside it, though — `parked` is set
                                // here and serviced below, after `poll` has
                                // returned and released `link`. Overwritten only
                                // on `Some`, so a batch with no consent screen
                                // in it cannot discard a prompt already waiting.
                                Ok(prompts) => {
                                    if let Some(panel) = panel.as_mut() {
                                        if let Some(next) =
                                            draw_batch(panel, &mut entropy, prompts)
                                        {
                                            // The prompt is on the glass now, so a
                                            // backup no longer is: drop the cursor
                                            // with the frame it described. The grant
                                            // left behind in `Session` is
                                            // unreachable — `show_backup_page` is
                                            // its only caller and it runs only from
                                            // this cursor — and the next
                                            // `confirm_at` overwrites it.
                                            revealing = None;
                                            parked = Some(next);
                                        }
                                    }
                                }
                                // A policy refusal is worth a screen — it is the
                                // device saying no, which a user is entitled to
                                // see. A state error (`Cancel` mid-keygen, a
                                // replayed phase) is the coordinator's bookkeeping
                                // and there is nothing to show; either way this
                                // returns, never resets.
                                //
                                // `Fault::Store` — flash would not take the share —
                                // gets the same screen, and the choice of policy is
                                // requirement 4:
                                //
                                // * It is NOT an ack. `Session::run` persists at the
                                //   top and returns before its outbox loop, so
                                //   nothing was pushed and the coordinator hears
                                //   silence. A ceremony that fails is recoverable;
                                //   a coordinator that believes in a share this
                                //   device does not hold is a threshold that is
                                //   silently one short, which is the failure the
                                //   persist-before-ack ordering exists to prevent.
                                // * It is NOT a panic. Every byte that got here is
                                //   coordinator-controlled, and a panic is a counted
                                //   reset with no DFU beyond it (decision 6).
                                // * It is NOT a hold. A hold above USB is
                                //   unreachable from inside the loop, and a hold
                                //   here would be worse than the fault: the staged
                                //   mutations survive in RAM, the identity and the
                                //   nonce slots are intact, and the link is the only
                                //   way to diagnose a flash that refused. An erase
                                //   or program failure is also not necessarily
                                //   stable across a retry, unlike the identity
                                //   faults at step 8b, which is what earns those a
                                //   hold and this one a screen.
                                //
                                // ponytail: `ui::refusal` says "CANNOT DISPLAY",
                                // which is imprecise for "flash refused" — a
                                // one-screen lie about the reason, not about the
                                // outcome. The eight §4.2 screens live in
                                // `hal/src/ui.rs` and a ninth is not this file's to
                                // add; add `ui::store_fault` there and swap this
                                // arm.
                                Err(Fault::Refused(_) | Fault::Store(_)) => refuse(panel.as_mut()),
                                Err(_fault) => {}
                            }
                        }
                        // Not a desync: the framing is intact and the link stays up,
                        // so one unreadable body must not drop a working link.
                        Err(_e) => {}
                    }
                }
                // Conch is off on this firmware (`Downstream::VERSION_SIGNAL` is 2 and
                // the conch protocol needs 1), and `Reset` is the coordinator telling
                // us to drop state we do not hold yet.
                _ => {}
            }
        });

        if polled.is_err() {
            // `Link::poll` has already unlinked itself, so recovery is to wait for
            // the coordinator's next magic bytes. Nothing to do but keep polling —
            // and specifically NOT to reset: a desync is a coordinator that mis-spoke,
            // not a fault in this device, and resetting on it would let a hostile
            // coordinator reset-loop us.
            continue;
        }

        if send_magic_reply {
            send_magic_reply = false;
            // A const, not an `encode_frame` call: the ARM send path should not need
            // a `FRAME_LIMIT` staging buffer and a monomorphised encoder to say hello.
            let _ = cdc.write(&comms::MAGIC_REPLY);
        }

        // Announce on the LINK EDGE, after the magic reply, exactly where upstream
        // does it (`device/src/esp32_run.rs:349-367`: the `PowerOn` ->
        // `Established` transition). Not once per boot — a coordinator that
        // restarts re-sends magic and expects a fresh announce — and not on every
        // magic frame, which arrives every `MAGIC_BYTES_PERIOD` for as long as we
        // are linked.
        //
        // `let _`, not `?`: `announce` can only fail by refusing to frame a 32-byte
        // digest and one short name message, which cannot happen, and if it somehow
        // did, an unannounced device that keeps polling is recoverable while a reset
        // loop is not.
        //
        // `announce` sends `Announce` and then either `SetName` (a name is on
        // flash) or `NeedName` (there is none) — `SetName` is the only message that
        // ever creates the coordinator's `device_names` entry
        // (`usb_serial_manager.rs:366-375,462-478`), so a device with a stored name
        // re-registers itself on every link edge without a human touching it. Both
        // legs are the library's; nothing about naming is decided in this file.
        if !was_linked && link.is_linked() {
            let _ = session.announce(digest, &mut outbox);
        }

        // --- Consent. ----------------------------------------------------------
        // ONE bounded pad read per loop iteration, and only while a prompt is
        // actually on the glass: with nothing parked the pad is never touched and
        // this loop runs exactly as fast as it did before. `read_key` does
        // `DEBOUNCE_SAMPLES` scans (~50 ms) and returns whatever it saw, so the
        // worst case is that `cdc.poll` is 50 ms late while a human is being
        // waited on — and the coordinator is waiting on that human too. There is
        // no loop here and no condition; `Answer::Wait` re-parks and control
        // returns to the top, which is what keeps a parked prompt from starving
        // USB. Do NOT wrap this in a `while` — see `ask`.
        //
        // That rule is what makes the page cursor safe to put here: paging a
        // 67-page transaction is 67 trips round this loop, each one a `cdc.poll`
        // followed by one bounded read, so `cdc.poll` is serviced between every
        // press a human makes. A `while` that waited for the last page would stop
        // USB for as long as it took someone to read a transaction.
        //
        // Placed AFTER the announce and BEFORE the outbox drain so a `keygen_ack`
        // or `sign_ack` reaches the wire in the same iteration that authorised it.
        // Below the desync `continue`, so a mis-speaking coordinator leaves the
        // prompt parked rather than answering it.
        if let Some((prompt, confirm, page, last)) = parked.take() {
            // Does a yes to THIS prompt grant a backup reveal? Read here because
            // `confirm_at` takes the prompt by value, and read as the variant rather
            // than copied out of the library: `Restoration` is the only family
            // `confirm_at` answers with a grant instead of a message, and every
            // variant of it other than `DisplayBackup` is `Fault::NotConfirmable`,
            // so an `Ok` from a `Restoration` prompt IS a live grant. If that ever
            // stops being true the direction of the mistake is a refusal on the
            // glass (`show_backup_page`'s `Err` leg), not a word drawn without one.
            let grants_reveal = matches!(prompt, DeviceToUserMessage::Restoration(_));
            // The prompt and the digit that were RENDERED, travelling together — see
            // `answer`. Bound rather than written inline so the call below stays on one
            // line and `cargo fmt` cannot reflow the shape the source pin matches.
            let consent = Some((&prompt, confirm));
            match ask(keypad.as_mut(), &mut entropy, consent, last) {
                // Nobody has answered yet. Put it back exactly as it was — same
                // prompt, same digit, same page, same `last`, so the glass and the
                // gate stay in step. Nothing is redrawn: the frame is still up.
                Answer::Wait => parked = Some((prompt, confirm, page, last)),
                // Turn one page. `Answer::Next` is only ever returned for a page
                // that was NOT the last of its set, so this is a single forward
                // step through a set the library already validated whole.
                //
                // `saturating_add` rather than `+ 1` even though the wrap is
                // unreachable — `Next` implies `page < len() - 1` and `len()` is at
                // most 67 — because `overflow-checks = false` in release means a
                // wrap here would be silent, and page 0 of a transaction is exactly
                // the screen that must never be mistaken for the last one.
                //
                // The re-park takes the NEW render's `last`, so the fact that
                // authorises a keypress is always the fact the current frame
                // printed. A page that will not draw (past the end, or an address
                // that stopped being renderable) returns `None` and the prompt is
                // dropped with `ui::refusal` on the glass — fail-closed, and the
                // coordinator must re-issue.
                Answer::Next => {
                    let next = page.saturating_add(1);
                    if let Some(panel) = panel.as_mut() {
                        if let Some(last) = draw_prompt(panel, &prompt, confirm, next) {
                            parked = Some((prompt, confirm, next, last));
                        }
                    }
                }
                // The one path to `Session::confirm_at` in this image, and it is
                // reachable only from `keypad::Event::Down` carrying the exact key
                // the screen printed, on the page that printed it. `confirm_at`
                // re-gates on `prompt_screen_at` at THIS page, so a request whose
                // screen refused — or a page that advertises no key — cannot be
                // signed even from here.
                //
                // `page` and not `0`: handing it `0` would ask the library "is page
                // 0 the last page?", which for a real transaction is false, so it
                // would refuse every honest multi-page signature; and handing it a
                // page the human never reached would be a signature on a screen
                // nobody read. The value passed is the one the frame on the glass
                // was drawn with.
                //
                // NOT a panic on `Err` — this runs inside the event loop, and a
                // `Fault` here is either a phase the coordinator has already moved
                // past, a prompt that was never confirmable, or flash refusing the
                // share (`Fault::Store`, raised before anything is acked). All are
                // "no signature", which is what the refusal screen says.
                Answer::Yes => match session.confirm_at(prompt, page, &mut entropy, &mut outbox) {
                    Ok(prompts) => {
                        if let Some(panel) = panel.as_mut() {
                            if grants_reveal {
                                // THE REVEAL STARTS HERE, and only here. `prompts`
                                // is empty on this leg by the library's design —
                                // `confirm_at` acks nothing, because upstream's
                                // `BackupRecorded` means "a human wrote it down" and
                                // no screen in this tree asks that yet — so there is
                                // nothing to draw except page 0, and page 0 is the
                                // share index rather than a word.
                                revealing = show_backup_page(&mut session, 0, panel, &mut entropy);
                            } else if let Some(next) = draw_batch(panel, &mut entropy, prompts) {
                                parked = Some(next);
                            }
                        }
                    }
                    Err(_fault) => refuse(panel.as_mut()),
                },
                // Dropped, not retried. The prompt is gone and only a coordinator
                // can raise it again — which is the point of a consent gate.
                //
                // `Answer::Back` is here because no prompt footer advertises
                // `ui::BACK_KEY`, so on a prompt it is a key the glass did not offer
                // — the same refusal as any other. It is also unreachable with a
                // `Some(consent)`: `answer` produces `Back` only for a screen with no
                // digit. Grouped rather than given an `unreachable!()`, because a
                // panic in this loop is a counted reset a coordinator could provoke.
                Answer::Back | Answer::No => refuse(panel.as_mut()),
            }
        // --- The reveal. -------------------------------------------------------
        // `else if`, so an iteration does at most ONE bounded pad read whatever is on
        // the glass. That is requirement 4 for a flow that is 8 pages of human
        // transcription: `cdc.poll` runs once per page turn, and there is no loop
        // here and no wait for a human, exactly as for a parked prompt. Do NOT make
        // this a `while` — see `ask`.
        //
        // `None` is passed where the prompt and its digit go, and that is the gate
        // rather than a convenience: with no `ConfirmDigit` in scope `answer` cannot
        // return `Answer::Yes`, so no key pressed while a share is on the glass can
        // reach `Session::confirm_at`. The consent for these pages was given once, on
        // a screen that showed no word, before the first word was drawn.
        //
        // `last` is `false` because every backup page has somewhere to go: `9` past
        // the last one is what ENDS the flow (`show_backup` returns `Ok(false)` and
        // drops the grant), which is a deliberate difference from a signing page set,
        // where the last page clamps because the last page is the one that
        // authorises.
        } else if let Some(page) = revealing.take() {
            match ask(keypad.as_mut(), &mut entropy, None, false) {
                // Still reading. Nothing is redrawn, and that is not just economy: a
                // redraw re-randomises `ui::Frame::mark_sensitive`'s noise, and
                // averaging that noise over N observations is the one open edge that
                // defence documents. Paging costs a redraw because it must; sitting
                // still must not.
                Answer::Wait => revealing = Some(page),
                // The two keys this footer actually advertises (`(9)next (7)back`).
                // `saturating_*` and not `+ 1` / `- 1`: `overflow-checks = false` in
                // release, so a wrap here would silently alias onto another page of
                // the same share instead of ending the flow. `saturating_sub` also
                // clamps page 0's back-press to a redraw of page 0.
                Answer::Next => {
                    if let Some(panel) = panel.as_mut() {
                        revealing = show_backup_page(
                            &mut session,
                            page.saturating_add(1),
                            panel,
                            &mut entropy,
                        );
                    }
                }
                Answer::Back => {
                    if let Some(panel) = panel.as_mut() {
                        revealing = show_backup_page(
                            &mut session,
                            page.saturating_sub(1),
                            panel,
                            &mut entropy,
                        );
                    }
                }
                // ANY other key ends the flow, and ending it is drawn: `BACKUP_END`
                // is past the last page, so `show_backup` drops the grant and
                // `show_backup_page` puts `idle` over the words. One ending, shared
                // with the natural one, so there is no second path to get wrong.
                //
                // Harsh on purpose. An over-press costs a re-ask and a second
                // consent and loses no word; the alternative — ignoring keys this
                // screen did not offer — leaves a share lit on the panel after
                // whoever pressed `x` has walked away, which is the leak this whole
                // feature exists to avoid.
                //
                // `Answer::Yes` cannot occur (no digit was passed) and is grouped
                // here rather than given an `unreachable!()`: a panic in the event
                // loop is a counted reset, and "stop showing the secret" is the right
                // answer to an unadvertised key either way.
                Answer::Yes | Answer::No => {
                    if let Some(panel) = panel.as_mut() {
                        revealing = show_backup_page(&mut session, BACKUP_END, panel, &mut entropy);
                    }
                }
            }
        }

        // The only place a reply reaches the wire. `write` chunks to
        // `MAX_PACKET_SIZE` itself and the framing is self-delimiting, so one call
        // per drain is enough however many frames are buffered — and draining
        // every iteration is what keeps the outbox's ~8 KiB worst case (a 4-stream
        // nonce replenishment) from being resident.
        if outbox.frames() > 0 {
            let bytes = outbox.take();
            let _ = cdc.write(&bytes);
        }

        // One received data packet means the core reset, the FIFOs, enumeration,
        // every control transfer and the RX path all worked: "at least one full
        // iteration that did real work", not merely "reached the loop" (rule 2). An
        // empty poll does not count, which is why this is `n > 0` and not
        // `is_configured()`.
        //
        // `!health.in_reset_loop()` is the second condition and it is load-bearing:
        // on a unit already past the threshold, clearing here would reset the
        // budget to 0 on every boot, so a fault that fires just after this point
        // would loop forever instead of the counter reaching
        // `PANIC_RESET_THRESHOLD` and the reset loop terminating. Refusing to clear
        // lets the counter finish climbing. (There is no DFU fallback beyond it —
        // decision 6, RDP=2.) 
        //
        // `let _ =` on the result, per rule 3: a dead backup domain must not be a
        // dead device.
        if handled_frame && !cleared && !health.in_reset_loop() {
            cleared = true;
            let _ = clear_counter(Counter::Panic);
        }
    }
}

// ---------------------------------------------------------------------------
// Host tests for the consent gate.
//
// `boot` cannot be tested — it is `#[cfg(target_arch = "arm")]` and it pokes
// registers — but the DECISION inside it can be, and is, which is why [`answer`]
// and [`ask`] are module items rather than nested functions. Between them these
// tests reach every arm of both: all four `keypad::Event`s, a scan error, and a
// pad that never opened.
//
// Four properties are NOT covered by a behavioural test here, and saying so is
// worth more than a test that pretends otherwise:
//
// 1. That `boot` calls `ask` **at most once per loop iteration** — the
//    requirement that a parked prompt must not stop `cdc.poll`. No behavioural
//    test can see that and no type enforces it: MEASURED, turning the `if let`
//    around `ask` into a `while let` compiles clean and, until this note was
//    written, passed every gate. It is now pinned as a source shape by
//    `a_parked_prompt_is_serviced_once_per_iteration_and_never_in_a_loop`, the
//    same remedy item 3 leans on. A source pin is not a behavioural test and does
//    not pretend to be one: it fails when the shape changes, which is all that is
//    on offer for a line inside a `cfg(target_arch = "arm")` function. The backup
//    reveal is the second screen with a cursor and it obeys the same rule for the
//    same reason: it is serviced by an `else if` on the SAME `if`, so the two are
//    mutually exclusive and an iteration reads the pad at most once whatever is on
//    the glass. Same test.
// 2. That a prompt is never parked on a device with no panel. Not a test but a
//    TYPE: `draw_batch` takes `&mut display::Panel`, so the natural weakening
//    (hand it the `Option` back) is `error[E0308]` — MEASURED. What that does not
//    stop is a rewrite that parks a prompt without calling `draw_batch` at all;
//    `Session::confirm_at`'s own `prompt_screen_at` re-gate is the backstop there,
//    and it is why the funnel is worth having twice.
// 3. That the cursor moves by **single forward steps** and that a re-park always
//    carries the new render's `last`. Both live in the `Answer::Next` arm inside
//    `boot`, which no gate compiles (PLAN.md §9 item 22). What stands in for a
//    test: `the_only_consent_call_passes_the_page_that_was_drawn` pins the call
//    shapes textually, `draw_prompt` returns `None` for a page past the end so an
//    over-advance draws `ui::refusal` instead of consenting, and `saturating_add`
//    means the increment cannot wrap under `overflow-checks = false`.
// 4. That an `Err` arm diverges. `hold` returns `!`, so the identity arms cannot
//    fall through to a device without an identity — a TYPE, not a test, and the
//    same for `boot`'s own `-> !`.
// 5. That **the words leave the glass when a reveal ends**. Control flow, then a
//    source pin: `show_backup_page` is the only caller of `Session::show_backup`
//    and the only producer of the reveal cursor, and both of its `None` legs draw
//    before returning — `idle` past the last page, `ui::refusal` on a fault. So
//    there is no ending that does not redraw, and
//    `every_exit_from_the_reveal_takes_the_words_off_the_glass` pins that the loop
//    has not grown one. The fourth ending is a coordinator's next prompt, which
//    `draw_batch` draws over the words and which drops the cursor beside it.
//
// The `keypad::Event` match in `answer` is exhaustive with no `_` arm, so a new
// driver variant is `error[E0004]` here rather than a silent default. The guarded
// arms do not weaken that: `Ok(keypad::Event::Down(key))` still appears unguarded,
// and a new variant is covered by nothing.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use coldsnap_hal::keypad::{Event, KeypadError, DECODER, KEY_CANCEL, KEY_OK};
    use coldsnap_hal::ui::{ConfirmDigit, BACK_KEY, CONFIRM_CHARSET, NEXT_KEY};
    use std::string::String;
    use std::vec::Vec;

    /// "The frame on the glass is the last page of its set, so it printed a key."
    ///
    /// Spelled once, so the tests that are about the *key* read as they did before
    /// the page cursor landed, and so the tests that are about the *page* stand out
    /// by passing something else. Every test below that uses this is asserting a
    /// property of the last page — which is the only page where a key can be
    /// accepted at all.
    const LAST: bool = true;

    /// A counter, not an RNG, and the same double `hal/src/ui.rs`'s own
    /// `ConfirmDigit` tests use: `draw` must be a pure function of the words it
    /// is handed, so every one of the five digits is reachable from a test.
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

    /// A prompt that is NOT `CheckKeyGen`, so [`answer`] takes its digit arm —
    /// the one the two signing screens use and the one that must be exact.
    ///
    /// It has to be this variant: `CheckKeyGen` and `SignatureRequest` both wrap
    /// a phase whose only constructor is a real coordinator, and
    /// `frostsnap_core/coordinator` is deliberately not in this test gate's
    /// feature set (it drags a C SQLite build — see `firmware/Cargo.toml`). The
    /// arm that cannot be exercised from a test is therefore the *keygen* one,
    /// and that arm is a comparison against a constant; the arm that carries the
    /// randomised digit is the one covered here.
    fn signing_shaped() -> DeviceToUserMessage {
        DeviceToUserMessage::FinalizeKeyGen {
            key_name: String::from("k"),
        }
    }

    /// The `ConfirmDigit` whose legend prints `digit`.
    ///
    /// Drawn through the real `ConfirmDigit::draw` rather than constructed, because
    /// the field is private *and* because that is the only way the test's notion
    /// of "the rendered digit" is the same object the screen would have printed.
    fn digit(digit: u8) -> ConfirmDigit {
        let index = CONFIRM_CHARSET
            .iter()
            .position(|c| *c == digit)
            .expect("must be one of the five");
        let mut rng = Counter(index as u32);
        let drawn = ConfirmDigit::draw(&mut rng);
        assert_eq!(drawn.as_str().as_bytes(), &[digit], "draw is not a bijection");
        drawn
    }

    /// FAIL CLOSED, the whole point of this file's change: the rendered digit
    /// confirms and **every other byte refuses**.
    ///
    /// Every byte, not just the pad's twelve: `Event::Down` carries a `u8`, and a
    /// gate that only checked the keys it expected would be a gate with a hole
    /// the width of a driver bug.
    #[test]
    fn only_the_rendered_digit_confirms() {
        let prompt = signing_shaped();
        for rendered in CONFIRM_CHARSET {
            let confirm = digit(rendered);
            let accepted: Vec<u8> = (0..=u8::MAX)
                .filter(|key| {
                    answer(Ok(Event::Down(*key)), Some((&prompt, confirm)), LAST) == Answer::Yes
                })
                .collect();
            assert_eq!(
                accepted,
                std::vec![rendered],
                "screen printed {:?}; these keys were accepted",
                rendered as char
            );
        }
    }

    /// The two non-digit keys are refusals, and `x` is not special-cased.
    ///
    /// `hsm_ux.py:58` is `refused = (ch != confirm_char)`, so CANCEL and OK are
    /// refusals for exactly the same reason a wrong digit is. Treating only `x` as
    /// refusal is how this gets subtly wrong, and it fails OPEN.
    #[test]
    fn cancel_and_ok_are_both_refusals() {
        let prompt = signing_shaped();
        for rendered in CONFIRM_CHARSET {
            let confirm = digit(rendered);
            for key in [KEY_CANCEL, KEY_OK] {
                assert_eq!(
                    answer(Ok(Event::Down(key)), Some((&prompt, confirm)), LAST),
                    Answer::No,
                    "{:?} answered a prompt showing {:?}",
                    key as char,
                    rendered as char
                );
            }
        }
        // And neither is a digit that could ever be rendered, so the case above is
        // not vacuous.
        assert!(!CONFIRM_CHARSET.contains(&KEY_CANCEL));
        assert!(!CONFIRM_CHARSET.contains(&KEY_OK));
    }

    /// Of the pad's twelve physical keys, exactly one confirms. This is the same
    /// property as `only_the_rendered_digit_confirms` restricted to keys a finger
    /// can actually produce, and it is what makes "1 in 12" the honest number.
    #[test]
    fn exactly_one_of_the_twelve_keys_confirms() {
        let prompt = signing_shaped();
        for rendered in CONFIRM_CHARSET {
            let confirm = digit(rendered);
            let yes = DECODER
                .iter()
                .filter(|key| {
                    answer(Ok(Event::Down(**key)), Some((&prompt, confirm)), LAST) == Answer::Yes
                })
                .count();
            assert_eq!(yes, 1, "prompt showing {:?}", rendered as char);
        }
    }

    /// Two contacts closed in one scan is a REFUSAL and never a guess: it is the
    /// only state a diodeless matrix can invent a key from.
    #[test]
    fn two_contacts_never_confirm() {
        let prompt = signing_shaped();
        assert_eq!(
            answer(Ok(Event::MultiKey), Some((&prompt, digit(b'4'))), LAST),
            Answer::No
        );
    }

    /// A pad that could not be read refuses. Requirement 3's runtime half: a
    /// device that cannot read consent must not sign.
    #[test]
    fn a_pad_that_cannot_be_read_never_confirms() {
        let prompt = signing_shaped();
        for error in [
            KeypadError::NotOnThisTarget,
            KeypadError::ColumnsStuckLow { idr: 0 },
        ] {
            assert_eq!(
                answer(Err(error), Some((&prompt, digit(b'4'))), LAST),
                Answer::No,
                "{error:?}"
            );
        }
    }

    /// A keypad that never opened refuses every prompt — and refuses it *without*
    /// a keypad, which is the arm no `Keypad` can be constructed to reach on a
    /// host.
    ///
    /// This is the mutation that matters most: making this `Answer::Yes` is a
    /// device that signs on its own the moment a pad connector is loose.
    #[test]
    fn a_missing_keypad_never_confirms() {
        let prompt = signing_shaped();
        let mut rng = Counter(0);
        assert_eq!(
            ask(None, &mut rng, Some((&prompt, digit(b'4'))), LAST),
            Answer::No,
            "no pad must be a refusal, never an approval and never a wait"
        );
    }

    /// Nothing pressed is NOT a refusal — the loop must be able to come back.
    ///
    /// The fail-closed instinct gets this one backwards: `read_key` returns after
    /// ~50 ms whether or not a human has moved, so treating `AllUp` as a refusal
    /// would refuse every prompt roughly 50 ms after drawing it and no human would
    /// ever get to answer one.
    #[test]
    fn nothing_pressed_is_neither_a_refusal_nor_an_approval() {
        let prompt = signing_shaped();
        for event in [Event::AllUp, Event::Unsettled] {
            assert_eq!(
                answer(Ok(event), Some((&prompt, digit(b'4'))), LAST),
                Answer::Wait,
                "{event:?}"
            );
        }
    }

    /// The digit is drawn per prompt, so a *stale* digit must not confirm. Pins
    /// the pairing: `draw_batch` returns the prompt and the digit it rendered
    /// together precisely so this cannot drift.
    #[test]
    fn a_digit_from_a_previous_prompt_does_not_confirm() {
        let prompt = signing_shaped();
        for rendered in CONFIRM_CHARSET {
            for stale in CONFIRM_CHARSET.iter().filter(|c| **c != rendered) {
                assert_eq!(
                    answer(
                        Ok(Event::Down(*stale)),
                        Some((&prompt, digit(rendered))),
                        LAST
                    ),
                    Answer::No,
                    "screen showed {:?}, key was last prompt's {:?}",
                    rendered as char,
                    *stale as char
                );
            }
        }
    }

    /// `KEYGEN_MATCH_KEY` is the byte `ui::keygen_check`'s legend actually prints,
    /// and it is a key this pad has.
    ///
    /// The keygen arm of `answer` cannot be reached from a test (no coordinator,
    /// so no `KeyGenPhase3`), so this pins the constant instead — including the
    /// part that would silently break it: `1` must be on the pad at all.
    #[test]
    fn the_keygen_match_key_is_the_legend_and_is_on_the_pad() {
        assert_eq!(KEYGEN_MATCH_KEY, b'1', "hal/src/ui.rs:833, \"1=match x=no\"");
        assert!(
            DECODER.contains(&KEYGEN_MATCH_KEY),
            "the keygen screen asks for a key the pad cannot send"
        );
        assert_ne!(KEYGEN_MATCH_KEY, KEY_CANCEL, "match must not be cancel");
        assert_ne!(KEYGEN_MATCH_KEY, KEY_OK);
    }

    /// **The page rule.** On a page that is not the last of its set, NOTHING
    /// confirms — and that includes the digit, which such a page never printed.
    ///
    /// This is the hole this change closes. Before it, `main.rs` parked page 0 of a
    /// bitcoin transaction (which renders fine: "Send amount #1 of 2") with a digit
    /// the screen had not drawn, and one press of the right key in five signed it.
    /// Every byte is checked, not just the pad's twelve, for the same reason
    /// `only_the_rendered_digit_confirms` checks all 256.
    #[test]
    fn the_digit_confirms_only_on_the_last_page() {
        let prompt = signing_shaped();
        for rendered in CONFIRM_CHARSET {
            let confirm = digit(rendered);
            let approved: Vec<u8> = (0..=u8::MAX)
                .filter(|key| {
                    answer(Ok(Event::Down(*key)), Some((&prompt, confirm)), false) == Answer::Yes
                })
                .collect();
            assert!(
                approved.is_empty(),
                "a page with more to read after it printed {:?} and accepted {:?}",
                rendered as char,
                approved
            );
            // And the same digit on the last page DOES confirm, so the assertion
            // above is a statement about the page and not about the digit.
            assert_eq!(
                answer(Ok(Event::Down(rendered)), Some((&prompt, confirm)), LAST),
                Answer::Yes
            );
        }
    }

    /// The advance key pages forward while there is more to read, and **clamps**
    /// on the last page rather than refusing.
    ///
    /// Clamping is `shared/ux.py:237-247`'s own behaviour (page-down is a `min()`),
    /// and it cannot fail open: `Answer::Wait` authorises nothing, re-parks the same
    /// frame, and `ui::NEXT_KEY` is const-asserted out of `CONFIRM_CHARSET`
    /// (`hal/src/ui.rs:891-902`) so it is not a key any screen can ask for. The cost
    /// of the alternative is real: one over-press at the end of a 67-page
    /// transaction would drop the prompt and the coordinator would have to re-issue
    /// the whole request.
    #[test]
    fn the_advance_key_pages_forward_and_clamps_on_the_last_page() {
        let prompt = signing_shaped();
        let confirm = digit(b'4');
        assert_eq!(
            answer(Ok(Event::Down(NEXT_KEY)), Some((&prompt, confirm)), false),
            Answer::Next,
            "a page with more to read must be advanceable"
        );
        assert_eq!(
            answer(Ok(Event::Down(NEXT_KEY)), Some((&prompt, confirm)), LAST),
            Answer::Wait,
            "the last page has nowhere to advance to"
        );
        // Never a confirmation, on either page. The const assert above this
        // module's `answer` is the build-time half of the same claim.
        assert!(!CONFIRM_CHARSET.contains(&NEXT_KEY));
        assert_ne!(NEXT_KEY, KEYGEN_MATCH_KEY);
    }

    /// `ui::BACK_KEY` is **not** a hidden command on a prompt. No prompt footer
    /// advertises it (`hal/src/ui.rs:879` prints `(9)next` and nothing else), so on
    /// a prompt it is refused like any other key the glass did not offer — on
    /// either page of a set, and whatever digit was drawn.
    ///
    /// The one screen that DOES print `(7)back` is the backup reveal
    /// (`BACKUP_BACK_LEGEND`), and the second half of this test is what keeps the
    /// two halves together: the pad obeys `7` exactly where the footer offers it and
    /// nowhere else. `consent` is what tells them apart, because a reveal page draws
    /// no `ConfirmDigit` — see `answer`.
    #[test]
    fn the_back_key_is_not_a_hidden_command() {
        let prompt = signing_shaped();
        for last in [false, LAST] {
            assert_eq!(
                answer(
                    Ok(Event::Down(BACK_KEY)),
                    Some((&prompt, digit(b'4'))),
                    last
                ),
                Answer::No,
                "no prompt advertises {:?} (last page: {last})",
                BACK_KEY as char
            );
        }
        // And the screen that does print it pages back rather than refusing, which
        // is the whole reason the arm exists. A human mid-transcription who follows
        // the printed legend must not lose the backup they are copying down.
        assert_eq!(
            answer(Ok(Event::Down(BACK_KEY)), None, false),
            Answer::Back,
            "the backup footer prints {:?}, so it must mean what it says",
            BACK_KEY as char
        );
    }

    /// **A share on the glass authorises nothing.** Every byte, on a screen with no
    /// consent: `9` pages forward, `7` pages back, and everything else — including
    /// all five bytes of `CONFIRM_CHARSET` — ends the flow. `Answer::Yes` is
    /// impossible, and not by policy: there is no `ConfirmDigit` to accept and no
    /// prompt to hand `Session::confirm_at`, so `answer` has nothing to say yes with.
    ///
    /// That matters because these are the pages that hold the secret. The consent
    /// for them was given once, on a screen that printed a digit and showed no word;
    /// a key pressed while word 13 is up must never be able to authorise anything
    /// else the coordinator has queued.
    #[test]
    fn a_backup_page_answers_only_its_two_paging_keys() {
        for key in 0..=u8::MAX {
            let got = answer(Ok(Event::Down(key)), None, false);
            let want = if key == NEXT_KEY {
                Answer::Next
            } else if key == BACK_KEY {
                Answer::Back
            } else {
                Answer::No
            };
            assert_eq!(got, want, "key {:?} on a backup page", key as char);
            assert_ne!(
                got,
                Answer::Yes,
                "key {:?} confirmed something while a share was on the glass",
                key as char
            );
        }
        // The non-`Down` events answer as they do everywhere else: nothing pressed
        // keeps the page up, and anything the driver could not read ends the flow.
        for event in [Event::AllUp, Event::Unsettled] {
            assert_eq!(answer(Ok(event), None, false), Answer::Wait, "{event:?}");
        }
        assert_eq!(answer(Ok(Event::MultiKey), None, false), Answer::No);
        for error in [
            KeypadError::NotOnThisTarget,
            KeypadError::ColumnsStuckLow { idr: 0 },
        ] {
            assert_eq!(answer(Err(error), None, false), Answer::No, "{error:?}");
        }
        // Not vacuous: the digit a consent screen WOULD have accepted is dead here.
        assert!(CONFIRM_CHARSET
            .iter()
            .all(|d| answer(Ok(Event::Down(*d)), None, false) == Answer::No));
        // And with `last` TRUE — a combination `boot` never produces, since the
        // reveal always passes `false` — nothing confirms either. This is the only
        // exercise the `consent: None` arm of the digit match gets, and without it a
        // mutation making that arm `Answer::Yes` would leave the suite green.
        assert_eq!(
            answer(Ok(Event::Down(NEXT_KEY)), None, true),
            Answer::Wait,
            "the advance key clamps on a last page, as everywhere else"
        );
        for key in 0..=u8::MAX {
            if key == NEXT_KEY || key == BACK_KEY {
                continue;
            }
            assert_eq!(
                answer(Ok(Event::Down(key)), None, true),
                Answer::No,
                "key {:?} confirmed a screen that printed no digit",
                key as char
            );
        }
    }

    /// The reveal's arithmetic: `BACKUP_END` — the index `boot` uses to END a reveal
    /// — really is past the last page and is derived from `hal::ui`'s constants
    /// rather than written as `8`, and the cursor moves by single **saturating**
    /// steps.
    ///
    /// Both live inside `boot`, which no gate compiles (PLAN.md §9 item 22), so this
    /// is the arithmetic checked against the real `ui::BackupPages` plus source pins
    /// that `boot` uses it. Getting it wrong is not cosmetic: an end index that still
    /// renders would leave a word on the glass on the path that is supposed to clear
    /// it, and `overflow-checks = false` in release means a `+ 1` that wrapped would
    /// silently alias onto another page of the same share instead of ending the flow.
    #[test]
    fn the_reveal_cursor_saturates_and_ends_one_past_the_last_page() {
        let end = 1 + ui::BACKUP_WORDS.div_ceil(ui::WORDS_PER_PAGE);
        // A real BIP39 word, repeated: the page COUNT is what is under test, and
        // `BackupPages::new` only cares that each word has the shape it can draw.
        let words = ["abandon"; ui::BACKUP_WORDS];
        let pages = ui::BackupPages::new(1, &words).expect("a 25-word list must render");
        assert_eq!(pages.len(), end, "the page count is not what boot assumes");
        assert!(
            pages.page(end).is_none(),
            "boot's end index still draws a page"
        );
        assert!(
            pages.page(end - 1).is_some(),
            "boot's end index is one page too early, so a word is never shown"
        );
        let src = production_source();
        assert!(
            src.contains(
                "const BACKUP_END: usize = 1 + ui::BACKUP_WORDS.div_ceil(ui::WORDS_PER_PAGE);"
            ),
            "boot must derive its end index from ui's constants, not hardcode it"
        );
        // One step at a time, in each direction, and neither can wrap. A `+ 1` here
        // is the mutation `overflow-checks = false` would hide.
        assert!(
            src.contains("page.saturating_add(1)"),
            "the reveal must advance by one saturating step"
        );
        assert!(
            src.contains("page.saturating_sub(1)"),
            "the reveal must page back by one saturating step, clamping at page 0"
        );
    }

    /// **Every exit from the reveal takes the words off the glass** — the leak this
    /// feature exists to avoid, pinned as the shape that prevents it.
    ///
    /// It is control flow first: `show_backup_page` is the only caller of
    /// `Session::show_backup` and the only producer of the reveal cursor, and both
    /// of its `None` legs draw before returning (`idle` past the last page,
    /// `ui::refusal` on a fault). So a `None` cursor and a share still lit cannot
    /// coexist. This pins that the loop has not grown a second way out, because
    /// `boot` is `#[cfg(target_arch = "arm")]` and nothing else here can see it.
    #[test]
    fn every_exit_from_the_reveal_takes_the_words_off_the_glass() {
        let src = production_source();
        assert_eq!(
            src.matches("session.show_backup(").count(),
            1,
            "only `show_backup_page` may call the reveal, so only it can end one"
        );
        // Four calls to the drawing function — start, forward, back, and stop — and
        // six assignments to the cursor: those four, the `Wait` re-park, and the one
        // drop a prompt draws over. So every assignment either came from a function
        // that redrew or is one of the two accounted for by name; there is no third
        // shape. (The definition is generic, so `show_backup_page<F..>(` is not one
        // of the four.)
        assert_eq!(
            src.matches("show_backup_page(").count(),
            4,
            "four call sites: start, forward, back, and stop"
        );
        assert_eq!(
            src.matches("revealing =").count(),
            6,
            "four `show_backup_page` results, one re-park, one drop"
        );
        assert_eq!(
            src.matches("revealing = None").count(),
            1,
            "the only cursor drop that does not redraw is the one a prompt draws over"
        );
        assert!(
            src.contains("revealing = Some(page)"),
            "`Answer::Wait` must re-park the same page without redrawing it"
        );
        // The third leg, for completeness: a page that DID render reaches the panel.
        // MEASURED — deleting this `show` leaves every other test in this file green,
        // because it lives in `boot`: the device would consent to a reveal and then
        // draw nothing, which is the exact bug this change repaired. The direction is
        // safe (fewer pixels, never more), so it is pinned here rather than argued
        // about.
        assert!(
            src.contains("Ok(true) => {\n                let _ = panel.show(frame.as_bytes());"),
            "a rendered backup page must reach the panel"
        );
        // And the ending is `idle`, drawn from one place, shared with standby.
        assert_eq!(
            src.matches("idle(session, panel)").count(),
            1,
            "one screen ends a reveal, and `show_backup_page` draws it"
        );
        assert_eq!(
            src.matches("idle(&session, panel)").count(),
            1,
            "step 8c draws the same screen; a second variant would drift"
        );
    }

    /// The consent call in `boot` passes **the page that was drawn**, and it is the
    /// only route to the signer's confirm in this image.
    ///
    /// A SOURCE-LEVEL PIN, not a behavioural test, and the same remedy
    /// `hal::keypad`'s `the_scan_order_is_actually_shuffled_at_the_only_call_site`
    /// uses: `boot` is `#[cfg(target_arch = "arm")]`, so the call site is compiled
    /// by no gate in this tree (PLAN.md §9 item 22). Passing `0` there instead of
    /// `page` would make every honest multi-page signature refuse *and* would be
    /// invisible to every other test in this file; passing a page the human never
    /// reached would be a signature on a screen nobody read.
    ///
    /// Cheap, and it fails loudly if the shape changes for a good reason — which is
    /// the point: a change to how consent reaches `Session` should have to say so
    /// here.
    #[test]
    fn the_only_consent_call_passes_the_page_that_was_drawn() {
        // Everything ABOVE this test module, so the assertions below do not count
        // their own string literals. MEASURED: without the split, the first count is
        // 3 — the call site plus these two literals.
        let src = production_source();
        assert_eq!(
            src.matches("session.confirm_at(prompt, page,").count(),
            1,
            "the consent call must pass the drawn page, exactly once"
        );
        assert!(
            src.contains("Answer::Yes => match session.confirm_at(prompt, page,"),
            "Answer::Yes must be the only thing in front of it"
        );
        // The page-0 wrapper is fail-closed for a paged request, but using it here
        // would silently refuse every real transaction.
        assert_eq!(
            src.matches("session.confirm(").count(),
            0,
            "boot must not use the page-0 wrapper"
        );
        // And the pad read must be handed the *rendered* `last`, not a literal,
        // together with the prompt and the digit that frame was drawn with.
        assert!(
            src.contains("ask(keypad.as_mut(), &mut entropy, consent, last)")
                && src.contains("let consent = Some((&prompt, confirm));"),
            "the gate must be told which page the frame showed, and with which digit"
        );
        // The reveal's read passes NO consent, which is what makes `Answer::Yes`
        // unreachable while a share is on the glass. `Some((..))` here would hand a
        // digit to a screen that printed none.
        assert!(
            src.contains("ask(keypad.as_mut(), &mut entropy, None, false)"),
            "the reveal must be paged with no prompt and no digit"
        );
        // And the reveal starts from that same `Ok` and from nowhere else — behind
        // the one prompt family whose consent grants one. Both halves are pinned
        // because losing either is silent: without the `matches!` the flag is a
        // constant, and a constant `false` is a device that consents to a reveal and
        // then draws nothing, which is exactly the state this change repaired.
        assert!(
            src.contains(
                "let grants_reveal = matches!(prompt, DeviceToUserMessage::Restoration(_));"
            ),
            "the grant must be read off the prompt that was answered"
        );
        assert!(
            src.contains("if grants_reveal {"),
            "the reveal must start behind that flag"
        );
        // And it starts at page 0, which is the SHARE INDEX page. Starting at 1 would
        // show every word and never the index, and a backup written down without its
        // index is unrestorable — a silent way to hand out 25 useless words.
        assert!(
            src.contains("show_backup_page(&mut session, 0, panel, &mut entropy)"),
            "a reveal must begin on the share-index page"
        );
    }

    /// Everything in this file ABOVE the test module: the source `boot` is really
    /// compiled from, minus the assertions below, so a pin can never match its own
    /// string literal.
    ///
    /// MEASURED: without the split, the first count in
    /// `the_only_consent_call_passes_the_page_that_was_drawn` is 3 — the call site
    /// plus that test's own two literals.
    ///
    /// Three tests read this and all three exist for one reason: `boot` is
    /// `#[cfg(target_arch = "arm")]`, so PLAN.md §9 item 22 applies and no gate in
    /// this tree compiles a line of it. A source pin is the weakest useful thing
    /// that can fail when one of the shapes inside it changes.
    fn production_source() -> &'static str {
        include_str!("main.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("split always yields one")
    }

    /// **The parked prompt is serviced once per iteration and never in a loop** —
    /// the property that stops a human reading pages from stopping `cdc.poll`.
    ///
    /// Item 1 of the four "NOT covered by a behavioural test" notes above this
    /// module said exactly this, and said why: turning the `if let` around `ask`
    /// into a `while let` "compiles clean and passes every gate". This is now that
    /// gate. `Answer::Wait` re-parks the prompt, so under a `while let` the loop
    /// spins on the pad until a human finally answers and `cdc.poll` is not reached
    /// for as long as that takes — the coordinator's ceremony times out while the
    /// device looks alive.
    ///
    /// A 25-word backup display is 7 pages (PLAN.md §4.2), so it is 7 presses of
    /// reading time rather than one, on the one screen where making the coordinator
    /// re-issue means asking the device for the secret a second time. That is why
    /// this guard is worth writing before any such flow exists rather than after.
    #[test]
    fn a_parked_prompt_is_serviced_once_per_iteration_and_never_in_a_loop() {
        let src = production_source();
        assert!(
            src.contains("if let Some((prompt, confirm, page, last)) = parked.take() {"),
            "the parked prompt must be serviced by ONE `if let`; a `while let` here \
             starves `cdc.poll` for as long as a human takes to read"
        );
        // One service site, so a second cannot appear beside it, and one `ask` per
        // state, so no arm of either `match` can take a second bite in the same
        // iteration.
        assert_eq!(
            src.matches("parked.take()").count(),
            1,
            "exactly one place services the parked prompt"
        );
        // The reveal is the second cursor and it hangs off the SAME `if` — so the
        // two are mutually exclusive and an iteration still reads the pad at most
        // once. `if` instead of `else if` here would be two reads (100 ms) whenever
        // a coordinator parked a prompt while a backup was up.
        assert!(
            src.contains("} else if let Some(page) = revealing.take() {"),
            "the reveal must be the `else` of the parked prompt, not a second `if`"
        );
        assert_eq!(
            src.matches("revealing.take()").count(),
            1,
            "exactly one place services the reveal"
        );
        assert_eq!(
            src.matches("ask(").count(),
            2,
            "exactly one bounded pad read per loop iteration, per exclusive state"
        );
        // And one poll, so the pad read cannot be moved above it or duplicated
        // below it — the ordering the comment at the call site relies on.
        assert_eq!(
            src.matches("cdc.poll(").count(),
            1,
            "exactly one USB poll per loop iteration"
        );
    }

    /// The `Counter::Panic` clear must stay behind **both** of its conditions, and
    /// `!health.in_reset_loop()` is the brick-shaped half.
    ///
    /// Dropping it compiles clean and passes every gate, because the clear lives in
    /// `boot` which no gate compiles — and it converts a *bounded* reset loop into
    /// an unbounded one: the budget would be zeroed on every boot, so the counter
    /// could never climb to
    /// [`PANIC_RESET_THRESHOLD`](coldsnap_hal::panic::PANIC_RESET_THRESHOLD) and
    /// terminate the loop. There is nothing beyond it to reach — DFU is
    /// hardware-impossible at RDP=2 (DECISIONS.md decision 6) — so a unit in that
    /// state is finished.
    ///
    /// `handled_frame` is pinned in the same breath: clearing on `is_configured()`
    /// or on an empty poll would spend the budget on a unit that never decoded
    /// anything, which is rule 2 of `panic::boot_sequencing` read backwards.
    #[test]
    fn the_panic_counter_clear_stays_behind_both_of_its_conditions() {
        let src = production_source();
        assert_eq!(
            src.matches("clear_counter(Counter::Panic)").count(),
            1,
            "one clear site, at the bottom of the loop"
        );
        assert!(
            src.contains("if handled_frame && !cleared && !health.in_reset_loop() {"),
            "the clear must require a decoded FRAME and a unit that is not already \
             in a bounded reset loop"
        );
    }

    /// The five `Answer`s are distinct, so `Wait` cannot be `No` by accident.
    /// Cheap, and it is what `assert_eq!` above is worth anything against.
    #[test]
    fn the_five_answers_are_distinct() {
        let all = [
            Answer::Wait,
            Answer::Next,
            Answer::Back,
            Answer::Yes,
            Answer::No,
        ];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                assert_eq!(i == j, a == b, "{a:?} vs {b:?}");
            }
        }
    }
}

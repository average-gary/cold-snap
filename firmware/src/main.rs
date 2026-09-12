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
//! **377,192 B**, 115,048 B over the floor, and signit pads it by **3,736 B**
//! (`align_to(377_192, 512) = 377_344`, then `align_to(377_344, 4096) = 380_928` — the 4 K
//! branch is the one Mk4/Mk5 take, and it is **no longer a no-op**). **This read 376,760 /
//! 114,616 / 72 B and "`align_to(.., 4096)` is the same number" until 2026-09-12**, when
//! `reveal_draw` and the consent-row refusals took the image past a 4 K boundary; README's
//! "Packaging" section carried the same chain and was corrected in the same pass. The old
//! text's agreement between the two branches was a coincidence of one image, and it ended
//! — which is exactly what its README counterpart had hedged about and nobody re-checked.
//! Padding is signit's job; never hand it a pre-padded body.
//!
//! Those three numbers were 282,016 / 19,872 / 608 before the dispatch,
//! 331,052 / 68,908 / 724 before the backup reveal was reachable,
//! 362,316 / 100,172 / 2,228 before the recorded question,
//! 364,588 / 102,444 / 4,052 before the restore flow was reachable from the pad, and
//! 374,960 / 112,816 / 336 before the check quiz was; they
//! are re-measured off the linked ELF, not carried. A stale MEASURED number reads
//! exactly like a checked one, which is why they are corrected here rather than left
//! for the next reader to trust — two consecutive steps' were, each of them a change
//! that landed the library side without a caller in this file.
//!
//! MEASURED cost of the last step, which is the check QUIZ becoming REACHABLE:
//! **+1,800 B** of image (+1,712 `.text`, +88 `.rodata`, `.bss` unchanged at
//! `0x2000_8034..0x2001_8058`), taking the image to **376,824 B**, 26.44% of
//! `FLASH_TEXT`. Measured by building the tree with this file reverted and again with
//! it, not inferred from a diff. Little of it is this file's ~250 lines: before them,
//! nothing in `boot` called `Session::quiz_key` or either quiz renderer, so LTO dropped
//! `ui::backup_quiz_word` and `backup_quiz_passed` monomorphised for `rng::Entropy`,
//! and `coldsnap_firmware::quiz`'s generics were never instantiated at all — which is
//! why that module's author measured it at 0 B. The step before this one was the same
//! story for the entry (+8,036 B, +7,708 `.text`, +328 `.rodata`). A `cfg(arm)` event
//! loop is what decides which of `coldsnap_firmware` exists on the device, and that is
//! worth knowing before reading a flash delta as the size of a diff.
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
//! * **No "show me the words again" key on the quiz.** Coldcard's quiz answers `y` by
//!   re-showing the whole seed (`shared/seed.py:877-879`, `show_words(words)`). Not
//!   here: that would be a full reveal reachable from a screen whose consent was taken
//!   for a *quiz*, i.e. a reveal with weaker consent than a reveal, and
//!   [`Grant::Reveal`] is issued only by a `DisplayBackup` digit. So `keypad::KEY_OK`
//!   is dead on this path — it is delivered like every other byte and
//!   `Session::quiz_key` ignores it — and [`ui::backup_quiz_word`] prints no legend for
//!   it either. A human who needs to re-read the share asks the coordinator for
//!   `DisplayBackup`, which has its own consent screen and its own `BackupRecorded`
//!   claim at the end of it. Fail-closed costs one round trip.
//!
//!   The quiz ITSELF is live: `Session::recv` admits `CheckBackup`, the state machine is
//!   `coldsnap_firmware::quiz` (pure, Coldcard's `word_quiz` construction, 8 of the 25
//!   positions), and this file owns four things and nothing else — the fifth
//!   [`Consent`] variant, the [`CheckStep`] routing, [`quiz_frame`], and the
//!   [`Grant::Check`] arm of [`grants`]. It hangs off the same `else if` chain as the
//!   reveal and the entry, so an iteration still does at most ONE bounded pad read and
//!   `cdc.poll` is never starved, and it holds no word: the 25 words, the position order
//!   and the three candidates live in `Session`, which is what makes
//!   `Session::confirm_at` the only thing that can start a quiz.
//!
//!   Word ENTRY is live the same way: `Session::recv` admits
//!   `EnterPhysicalBackup`/`SavePhysicalBackup`/`SavePhysicalBackup2`/`Consolidate`,
//!   the state machine is `coldsnap_firmware::wordentry` (pure, 2,048 words pinned),
//!   and this file owns three things and nothing else — the fourth [`Consent`]
//!   variant, the [`EntryStep`] routing, and [`entry_frame`]. It hangs off the same
//!   `else if` chain as the reveal, so an iteration still does at most ONE bounded
//!   pad read and `cdc.poll` is never starved, and it holds no word: the 25 slots,
//!   the prefix and the candidate letters live in `Session`, which is what makes
//!   `Session::confirm_at` the only thing that can start an ingest.
//! * **No `Consent` variant for the entry's or the quiz's own keys that can confirm
//!   anything.** The entry keys are `ui::ENTRY_LETTER_KEYS` plus
//!   `ui::ENTRY_PAGE_KEY`/`ENTRY_OK_KEY`/`ENTRY_DELETE_KEY` — `1`-`9`, `0`, `y`, `x`
//!   — and five of those bytes are ALSO in [`ui::CONFIRM_CHARSET`] (`1`, `2`, `3`,
//!   `4`, `6`). The quiz's are [`ui::QUIZ_KEYS`], `1`/`2`/`3`, and **all three** are in
//!   the charset. There is no byte-level separation to lean on in either case, unlike
//!   [`ui::NEXT_KEY`]/[`ui::BACK_KEY`] which are const-asserted off the charset
//!   (`hal/src/ui.rs:1069-1076`). [`Consent::Entry`] and [`Consent::Quiz`] are the whole
//!   separation, and both are UNIT variants: no digit to accept and no prompt to hand
//!   `Session::confirm_at`, so [`Answer::Yes`] is unreachable while a share is being
//!   typed or a candidate is being picked — the same type-level argument
//!   [`Consent::Pages`] makes for the reveal.
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
use frostsnap_core::device::{restoration::ToUserRestoration, DeviceToUserMessage};

// ---------------------------------------------------------------------------
// Consent. NOT inside `boot`, and that is the whole reason it is testable.
//
// `boot` is `#[cfg(target_arch = "arm")]`, so anything living in it is invisible
// to every host test — which for a *consent gate* is the one place that is not
// affordable. [`answer`] and [`ask`] are therefore plain module items, compiled
// on both targets, and the tests at the bottom of this file drive every arm of
// them. The only thing left ARM-only is reading a register.
// ---------------------------------------------------------------------------

/// The pad half of the paging-key claim, as a **build failure** rather than a test.
///
/// `hal::ui` already asserts that neither paging key is in `CONFIRM_CHARSET`
/// (`hal/src/ui.rs:1113-1123`) but it is a pure module and cannot see the decode
/// table, so the pad half belongs wherever the two are visible together, which is
/// here.
///
/// If [`ui::NEXT_KEY`] were not on the pad, the advance arm would be dead code and
/// a multi-page transaction would be unreachable past page 0. The input is `const`,
/// so this does not have to be a test.
///
/// # This block asserted a second thing until 2026-09-11
///
/// `ui::NEXT_KEY != KEYGEN_MATCH_KEY` — because [`answer`] used to accept a FIXED
/// `b'1'` on the keygen check screen, a byte `hal::ui` knew nothing about, so the
/// charset assert over there could not cover it. `ui::keygen_check` now prints a
/// [`ui::ConfirmDigit`] like every other consent screen, the constant is gone, and
/// the claim is subsumed by `hal`'s own `CONFIRM_CHARSET[i] != NEXT_KEY`: there is
/// no longer any key a screen can ask for that is not in that charset.
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
};

/// What the pad said about the prompt currently on the glass.
///
/// Four states and not two, because neither "the human has not answered yet" nor
/// "the human wants the next page" is a refusal and neither may be turned into one
/// — see [`answer`]. Naming [`Answer::Wait`] is also what keeps the event loop
/// non-blocking: it is returned, the prompt is re-parked, and the next iteration
/// starts with `cdc.poll` again.
///
/// `Debug` is hand-written below rather than derived — see there.
#[derive(Clone, Copy, PartialEq, Eq)]
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
    /// A KEYSTROKE, produced only under [`Consent::Entry`]: the byte goes to
    /// `Session::entry_key` and means a letter, a page turn, a delete or an accept
    /// *within the share a human already consented to type in*.
    ///
    /// It authorises nothing. [`Consent::Entry`] carries no [`ui::ConfirmDigit`] and
    /// no prompt, so there is nothing for `Session::confirm_at` to be handed, and the
    /// parked-prompt arm groups this with the refusal — see [`answer`] and
    /// [`entry_step`]. That matters more here than for any other variant, because
    /// `1`, `2`, `3`, `4` and `6` are live entry keys AND members of
    /// [`ui::CONFIRM_CHARSET`]: the variant is the only thing that separates "the
    /// digit that authorises a signature" from "the key that picks letter 3".
    Key(u8),
}

/// The variant NAME, and for [`Answer::Key`] the name ALONE.
///
/// Manual, and it is the same defence `coldsnap_firmware::wordentry::Step`'s
/// hand-written `Debug` is, for the same material. The byte in `Key` is one press of a
/// letter key, and a whole press SEQUENCE determines the word it typed — that is what a
/// measured 5.7-presses-per-word encoding means, and 25 of those sequences are the
/// share. So a `Debug` that printed the byte would be a share-shaped log line waiting
/// for a logger, and a `derive` would make adding one a zero-line change.
///
/// Nothing in this image formats an `Answer`: there is no `defmt`, no semihosting and
/// no formatted panic (`fault_trampoline` passes a `&'static str` deliberately). This
/// is what keeps that true the day one of those arrives. It exists at all so
/// `assert_eq!` in the tests below can name a verdict; those tests carry the pressed
/// key in their own message instead.
impl core::fmt::Debug for Answer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Answer::Wait => "Wait",
            Answer::Next => "Next",
            Answer::Back => "Back",
            Answer::Yes => "Yes",
            Answer::No => "No",
            Answer::Key(_) => "Key(<press>)",
        })
    }
}

/// What the screen currently on the glass will accept as "yes".
///
/// Three cases and not an `Option<(&DeviceToUserMessage, ConfirmDigit)>`, which is
/// what this was until the reveal grew an ending. That shape could say "a
/// coordinator prompt with a digit" and "a page with no digit at all", and had no
/// way to say the third thing a device needs to say: *this device is asking a
/// question of its own*. The only ways to bolt that onto an `Option` were to hand
/// the recorded question a paging key — an over-press claiming a backup exists on
/// paper — or to keep a cloned `BackupDisplayPhase` alive purely as a key-selection
/// token, i.e. an encrypted share resident for as long as a human takes to answer.
/// Both are worse than a named enum.
///
/// The variant is what selects [`Answer::Yes`] and [`Answer::Back`], so a screen
/// cannot be answered with a gesture it did not draw.
#[derive(Debug, Clone, Copy)]
enum Consent<'a> {
    /// A coordinator prompt and the digit its screen printed. [`Answer::Yes`] here
    /// is the one route to
    /// [`Session::confirm_at`](coldsnap_firmware::Session::confirm_at).
    ///
    /// The prompt is a **construction-site obligation, not a value [`answer`]
    /// reads** — and since 2026-09-11 nothing reads it, because that was the day the
    /// keygen check stopped having a key of its own and `answer` stopped matching on
    /// the prompt kind at all. It stays for a reason worth stating precisely, because
    /// the first version of this comment gave a weaker one and conceded its own
    /// counter-example: it argued that dropping the field would let a `Prompt` be built
    /// with no prompt in hand, then admitted the converse confusion is unprevented
    /// either way.
    ///
    /// **The real reason is that this field is the only `&'a` in [`Consent`].** Drop it
    /// and the enum becomes lifetime-free, at which point nothing ties a parked
    /// `Consent` to the liveness of the prompt it was made for — a digit could outlive
    /// the `DeviceToUserMessage` that has already been moved into
    /// [`Session::confirm_at`](coldsnap_firmware::Session::confirm_at). Today the borrow
    /// checker forbids that pairing; without the field it would compile.
    ///
    /// `#[expect]` and not `#[allow]`, on the FIELD and not the variant: on the variant
    /// it would also silence *"variant is never constructed"*, so deleting the sole
    /// construction site — which would make it impossible to consent to any coordinator
    /// prompt at all — would build with zero warnings. Narrower is louder.
    /// MEASURED: reading the field warns `this lint expectation is unfulfilled` on the
    /// release ARM build, and 0 warnings is a gate, so the marker cannot rot into an
    /// `#[allow]`.
    Prompt(
        #[expect(
            dead_code,
            reason = "the only &'a in Consent: it is what borrow-checks a parked digit \
                      against the liveness of the prompt it was drawn for"
        )]
        &'a DeviceToUserMessage,
        ui::ConfirmDigit,
    ),
    /// A question this DEVICE is asking, and the digit its screen printed. There is
    /// no prompt, so [`Answer::Yes`] cannot reach `confirm_at` at all — it can only
    /// mean "the human answered the device's own question", and the caller decides
    /// what that is worth. Today it is exactly one screen:
    /// [`ui::backup_recorded`](coldsnap_hal::ui::backup_recorded).
    Question(ui::ConfirmDigit),
    /// A page-only screen: no digit, so [`Answer::Yes`] is unreachable, and
    /// [`ui::BACK_KEY`] pages back because these are the pages that print its
    /// legend. Today exactly the backup reveal, whose consent was given once, on a
    /// screen that showed no word, before the first word was drawn.
    Pages,
    /// A share is being TYPED IN: every byte is a keystroke for
    /// `Session::entry_key`, and none of them authorises anything.
    ///
    /// A unit variant, exactly like [`Consent::Pages`] and for the same type-level
    /// reason: with no [`ui::ConfirmDigit`] in scope there is nothing to accept, and
    /// with no prompt there is nothing to hand `Session::confirm_at`. So no key
    /// pressed while a prefix is on the glass can return [`Answer::Yes`], however
    /// much the entry keys overlap [`ui::CONFIRM_CHARSET`] — and they overlap on five
    /// of twelve.
    ///
    /// It is also the reason [`answer`]'s [`Answer::Key`] arm has to come FIRST:
    /// `ui::NEXT_KEY` (`9`) and `ui::BACK_KEY` (`7`) are `ENTRY_LETTER_KEYS[8]` and
    /// `[6]`, so a paging arm ahead of it would eat two of the nine letter keys.
    Entry,
    /// A backup CHECK QUIZ is on the glass: every byte is a keystroke for
    /// `Session::quiz_key`, and none of them authorises anything.
    ///
    /// A unit variant for [`Consent::Entry`]'s reason, and the overlap it separates is
    /// worse rather than better: the quiz's answer keys are [`ui::QUIZ_KEYS`] (`1`,
    /// `2`, `3`) and **all three are members of [`ui::CONFIRM_CHARSET`]** (`12346`), so
    /// a keypress alone cannot say whether a human meant "candidate 2" or "confirm".
    /// There is no const-assert to fall back on either — `hal/src/ui.rs:1069-1076`
    /// asserts only that `NEXT_KEY` and `BACK_KEY` stay *out* of the charset, and
    /// `hal/src/ui.rs:2503-2515` asserts only that a quiz key is not also a paging,
    /// cancel or OK key. This variant is the whole separation: with no
    /// [`ui::ConfirmDigit`] in scope there is nothing to accept, and with no prompt
    /// there is nothing to hand `Session::confirm_at`, so [`Answer::Yes`] is
    /// unreachable while three candidates are on the glass.
    ///
    /// The quiz's own decline (`x`) is *not* special-cased here. It arrives as
    /// [`Answer::Key`] like every other byte and `coldsnap_firmware::quiz::Quiz::key`
    /// — which is pure and total over all 256 — is what turns it into an abort. One
    /// decision, in the module that already tests it over every byte at every state.
    Quiz,
}

/// One pad [`keypad::Event`] plus the prompt it is answering, into a verdict.
///
/// **FAIL CLOSED.** Exactly one key confirms — the one the screen printed — and
/// everything else is [`Answer::No`], which is a refusal and not a retry. That is
/// [`ui::ConfirmDigit::accepts`]'s own contract (`hal/src/ui.rs:914`,
/// `key == self.0`) and Coldcard's rule at its highest-stakes approval
/// (`shared/hsm_ux.py:66`, `self.refused = (ch != confirm_char)`). A loop that
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
/// # `consent`, and why it is an enum
///
/// See [`Consent`]. [`Consent::Pages`] is a **type-level** statement of "the reveal
/// authorises nothing": there is no [`ui::ConfirmDigit`] in scope to accept and no
/// prompt to hand to
/// [`Session::confirm_at`](coldsnap_firmware::Session::confirm_at), so no key
/// pressed while a share is on the glass can return [`Answer::Yes`]. A `bool` flag
/// would have left a digit lying beside a screen that never drew one, which is the
/// desync the randomised digit exists to prevent. It is also what selects the back
/// arm: the pages that print `(7)back` are precisely the pages that print no digit.
///
/// [`Consent::Question`] carries a digit but no prompt, so its `Answer::Yes` is
/// **not** a route to `confirm_at` — there is nothing to pass it. That is the
/// type-level half of "the recorded question authorises no signature and no
/// reveal": all it can buy is the one call its own caller makes.
///
/// [`Consent::Entry`] and [`Consent::Quiz`] carry neither, and they are the two
/// screens whose keys OVERLAP the ones a signing screen asks for: `1`, `2`, `3`, `4`
/// and `6` are members of [`ui::CONFIRM_CHARSET`] *and* live letter keys, and all
/// three of [`ui::QUIZ_KEYS`] (`1`, `2`, `3`) are members of it too. So the variant
/// does the whole separation, and it does it in the direction that cannot fail open —
/// under either one the function returns [`Answer::Key`], which is not
/// [`Answer::Yes`] and which the parked-prompt arm refuses. The converse is the
/// property worth naming twice: under [`Consent::Prompt`] this function never returns
/// [`Answer::Key`], so a keystroke cannot reach a prompt either.
/// `an_entry_key_cannot_answer_a_signing_or_revealing_screen` and
/// `a_quiz_answer_key_cannot_answer_a_signing_or_revealing_screen` check both
/// directions over all 256 bytes.
///
/// [`ui::NEXT_KEY`] on the last page **clamps** to [`Answer::Wait`] rather than
/// refusing, which is Coldcard's own story behaviour (`shared/ux.py:237-247`
/// clamps page-down with `min()`), so an over-press at the end of a 67-page
/// transaction costs nothing instead of killing a ceremony the coordinator would
/// have to re-issue. It cannot fail open: `Wait` authorises nothing, and
/// `NEXT_KEY` is const-asserted out of `CONFIRM_CHARSET`
/// (`hal/src/ui.rs:1113-1123`), and since 2026-09-11 that charset is the WHOLE set
/// of keys a screen can ask for — the keygen check's fixed `b'1'` was the one
/// exception and it is gone — so `NEXT_KEY` is not a key any screen can ask for.
/// This used to add "and off `KEYGEN_MATCH_KEY` (above)" because of that exception.
fn answer(
    event: Result<keypad::Event, keypad::KeypadError>,
    consent: Consent<'_>,
    last: bool,
) -> Answer {
    match event {
        // Not a refusal: `read_key` returns after three scans whether or not a
        // human has done anything, so "all up" is the ordinary answer while
        // someone reads the screen.
        Ok(keypad::Event::AllUp | keypad::Event::Unsettled) => Answer::Wait,
        // A SHARE IS BEING TYPED IN, OR A QUIZ IS BEING ANSWERED: every byte is a
        // keystroke, and this arm comes FIRST because the two arms below it would
        // otherwise eat two of the nine letter keys — `ui::NEXT_KEY` is `9`, which is
        // `ENTRY_LETTER_KEYS[8]`, and `ui::BACK_KEY` is `7`, which is `[6]`. It is also
        // ahead of the `!last` refusal, so no value of `last` can turn typing or
        // answering into a refusal: neither screen is a page of a set and neither has a
        // last page to be on.
        //
        // ONE arm for both, not two, because the verdict is the same value and the
        // routing is `Flow`'s job: `flow_consent` already decided which screen is on
        // the glass, so a second arm here would be a second place for the two to
        // disagree.
        //
        // It authorises NOTHING. Both variants are unit variants, so there is no digit
        // here to accept and no prompt to hand `Session::confirm_at`; the strongest
        // statement about the overlap between these keys and `ui::CONFIRM_CHARSET` —
        // five of twelve for the entry, and all THREE of the quiz's answer keys — is
        // that `Answer::Key` is not `Answer::Yes` and cannot become one without a type
        // changing.
        Ok(keypad::Event::Down(key)) if matches!(consent, Consent::Entry | Consent::Quiz) => {
            Answer::Key(key)
        }
        // Turn the page, or clamp. Checked before anything else that is about the
        // request because it is the one key that is about the *set*, and it can
        // never be a confirm key (see the docs above).
        Ok(keypad::Event::Down(key)) if key == ui::NEXT_KEY => {
            if last {
                Answer::Wait
            } else {
                Answer::Next
            }
        }
        // Page back — only on a screen that printed a back legend, which is the
        // backup pages and nothing else. `Consent::Pages` is that test and not a
        // proxy for it: `hal/src/ui.rs`'s `BACKUP_BACK_LEGEND` is drawn by exactly
        // the pages that draw no `ConfirmDigit`, and a screen with a digit is a
        // screen whose footer offers `x` and the digit instead. On a prompt or on the
        // recorded question this falls through to the arms below and is refused like
        // any other unadvertised key — `the_back_key_is_not_a_hidden_command`.
        Ok(keypad::Event::Down(key))
            if key == ui::BACK_KEY && matches!(consent, Consent::Pages) =>
        {
            Answer::Back
        }
        // The page on the glass has more to read after it, so it printed no key to
        // press. Nothing here may authorise, and that includes the digit.
        Ok(keypad::Event::Down(_)) if !last => Answer::No,
        Ok(keypad::Event::Down(key)) => match consent {
            // Unreachable: the guarded arm at the top of this `match` takes every
            // `Down` under `Consent::Entry` and `Consent::Quiz` alike. Spelled with the
            // SAME value rather than a different one, so that removing the guard changes
            // behaviour nowhere — an "unreachable" arm that disagreed with the reachable
            // one is how the next refactor introduces a bug.
            Consent::Entry | Consent::Quiz => Answer::Key(key),
            // A screen with no digit and no prompt cannot be answered — there is
            // nothing to accept and nothing to confirm. Unreachable in this image
            // (the only `Pages` caller is the reveal, which passes `last` false and
            // is caught by the arm above), and a refusal if it ever is reached.
            Consent::Pages => Answer::No,
            // The device's own question. One digit, drawn by whoever drew the
            // screen, and `accepts` rather than a comparison spelled here for the
            // same reason as below: the value RENDERED and the value ACCEPTED are one
            // `ConfirmDigit`.
            Consent::Question(confirm) => {
                if confirm.accepts(key) {
                    Answer::Yes
                } else {
                    Answer::No
                }
            }
            // EVERY prompt that got as far as being parked printed the randomised
            // digit, so the digit is the only key that authorises it. `accepts`, not a
            // comparison spelled here: the value that was RENDERED and the value that
            // is ACCEPTED are the same `ConfirmDigit`, so they cannot disagree.
            //
            // A non-consent prompt cannot reach this line — `draw_batch` parks only
            // what `prompt_screen_at` drew a `Shown::Page` for, and `last` being true
            // narrows that to the page that printed the digit — and if one somehow
            // did, `Session::confirm_at` refuses it with `Fault::NotConfirmable`. Two
            // gates, both fail-closed.
            //
            // THE PROMPT IS NOT LOOKED AT, and that is the change of 2026-09-11. This
            // was a `match prompt` whose `CheckKeyGen` arm read `key ==
            // KEYGEN_MATCH_KEY`, a fixed `b'1'`, because `ui::keygen_check` printed a
            // fixed `1=match` legend. That made the ANTI-MITM screen — the one screen
            // whose whole purpose is that a human read four bytes off it — the one a
            // hardcoded script could answer blind. `keygen_check` now prints the same
            // `ConfirmDigit` this arm already held, so there is nothing left to
            // special-case and no per-prompt rule to drift: one screen kind, one key.
            // `the_keygen_prompt_is_answered_by_the_same_rule_as_every_other_prompt`
            // pins the absence, because the arm itself is unreachable from a test (a
            // `CheckKeyGen` needs a `KeyGenPhase3`, which needs a coordinator).
            Consent::Prompt(_, confirm) => {
                if confirm.accepts(key) {
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
/// A dead pad on a backup page ([`Consent::Pages`]) is [`Answer::No`] for the same
/// reason and with a bonus: the reveal ends and the words come off the glass on the
/// very next iteration. Fail-closed in both directions. On the recorded question
/// ([`Consent::Question`]) it is also [`Answer::No`], so a device that cannot read a
/// keypress never claims a backup exists on paper. During an entry
/// ([`Consent::Entry`]) it is [`Answer::No`] once more, which [`entry_step`] routes
/// to the ending — so a pad that stops mid-word takes the prefix and the previous
/// word off the glass instead of leaving them lit for whoever walks past next. During
/// a quiz ([`Consent::Quiz`]) the same, through [`check_step`]: one of the three
/// candidates on that screen is a true word of the share, so a pad that stops
/// mid-quiz must take them off the glass rather than leave them lit.
fn ask<R: rand_core::RngCore>(
    pad: Option<&mut keypad::Keypad>,
    rng: &mut R,
    consent: Consent<'_>,
    last: bool,
) -> Answer {
    let Some(pad) = pad else {
        return Answer::No;
    };
    answer(pad.read_key(rng), consent, last)
}

// ---------------------------------------------------------------------------
// The backup flow's routing. MODULE ITEMS for the same reason [`answer`] is one:
// `boot` is `#[cfg(target_arch = "arm")]`, so every line inside it is linted and
// none of it is ever executed (PLAN.md §9 item 22) — and a line that decides which
// key ends a reveal, which screen accepts a digit, or which prompt buys permission
// to draw 25 plain words is not a line to leave uncompiled by every gate. The only
// thing left in `boot` is the panel and the session, which no host has.
// ---------------------------------------------------------------------------

/// What a granted backup flow has on the glass, and therefore what the next
/// keypress means.
///
/// Two states rather than a bare page cursor, because the flow has two screens with
/// different footers and a `usize` cannot tell them apart. `Reveal::Done` does not
/// exist: "nothing is on the glass" is `None`, which is what the event loop's
/// `if let` already tests, so there is no dead variant to route by mistake.
///
/// **A CURSOR AND NOTHING ELSE.** The grant lives in
/// [`Session`](coldsnap_firmware::Session), set only by `confirm_at` and taken by
/// `show_backup`, so this cannot authorise a reveal any more than a page number can
/// authorise a signature. It can only page one a human already consented to — and,
/// on its second state, remember which digit the "did you write it down?" screen
/// printed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reveal {
    /// Page `n` of the words is on the glass. Paged with `9`/`7`; **no digit**, so
    /// nothing pressed here can authorise anything.
    Page(usize),
    /// The words are off the glass and [`ui::backup_recorded`] is up, drawn with
    /// this digit. That digit — and nothing else — is the yes.
    Recorded(ui::ConfirmDigit),
}

/// One past the last page of a backup, i.e. the index that ENDS a reveal.
///
/// Derived from `hal::ui`'s own two constants rather than written as `8`, so the day
/// a page holds five words this still names the first invalid index.
/// `BackupPages::len()` is the same arithmetic, but reaching it needs a
/// `BackupPages`, and building one needs the words — which is precisely what this
/// file must never hold. `the_reveal_cursor_saturates_and_ends_one_past_the_last_page`
/// checks the value against a real `ui::BackupPages`.
const BACKUP_END: usize = 1 + ui::BACKUP_WORDS.div_ceil(ui::WORDS_PER_PAGE);

/// What the backup screen on the glass will accept, and whether it is the last page
/// of its set.
///
/// The whole reason [`Answer::Yes`] is unreachable while a share is lit is that
/// [`Consent::Pages`] carries no digit, and this is the one place that pairing is
/// made — so it is checked by value rather than by a source pin.
///
/// `last` goes with it: every backup page has somewhere to go, because
/// [`ui::NEXT_KEY`] past the last one is what ENDS the flow, while the whole
/// recorded question fits one page and must therefore be answerable on it.
fn reveal_consent(state: Reveal) -> (Consent<'static>, bool) {
    match state {
        Reveal::Page(_) => (Consent::Pages, false),
        Reveal::Recorded(confirm) => (Consent::Question(confirm), true),
    }
}

/// What the event loop does next with the backup flow on the glass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RevealStep {
    /// Nothing pressed. Keep the same screen, and on the recorded question the same
    /// digit. **Nothing is redrawn**, which is not economy: a redraw re-randomises
    /// [`ui::Frame::mark_sensitive`]'s noise and averaging that over N observations
    /// is the one open edge that defence documents, and a fresh digit would leave
    /// the glass naming a key that no longer answers it.
    Park,
    /// Draw page `n` of the reveal. `n == `[`BACKUP_END`] is how a reveal ENDS:
    /// `Session::show_backup` drops the grant there and the caller puts standby over
    /// the words.
    Show(usize),
    /// The digit the recorded question printed: send `CommsMisc::BackupRecorded`,
    /// then standby.
    Ack,
    /// The recorded question answered with anything but its digit. Send NOTHING and
    /// draw standby — a backup that was not recorded was not recorded, and the app
    /// has its own cancel. Fail-closed here is silence, not a reassuring ack.
    Idle,
}

/// Which screen a granted reveal puts on the glass for one answer from
/// [`Session::show_backup`]. See [`reveal_draw`].
///
/// [`RevealScreen::Page`] carries nothing because the words are already in the frame:
/// `show_backup` composed them there, and this file may never hold a word (it has no
/// `Secrets`). The other three are composed by the caller from `hal::ui`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RevealScreen {
    /// The words `show_backup` just drew. Push the frame as it stands.
    Page,
    /// The pages ran out and the recorded question is armed. Draw
    /// [`ui::backup_recorded`] with this digit, over the words, into the same frame.
    Recorded(ui::ConfirmDigit),
    /// The reveal ended with nothing to ack. Standby, which is what takes the words off.
    Idle,
    /// A fault. [`ui::refusal`], which is also what takes the words off.
    Refuse,
}

/// The PAIRING at the heart of a reveal: which screen goes up, and which cursor the
/// event loop parks — decided together, by value, in a module item a host test can run.
///
/// **This function exists because of a mutation that passed every gate in the project.**
/// The pairing used to be two expressions inside `boot`'s `show_backup_page`, and
/// `Some(Reveal::Page(page))` there could be changed to
/// `Some(Reveal::Page(page.saturating_add(1)))` with NOTHING failing: MEASURED
/// 2026-09-12 against firmware tests, hal tests, both device clippy profiles,
/// `cargo build --release` at 0 warnings, `tools/pixel-check.py` PASS all 7, and the
/// `hostcheck` interop harness at exit 0.
///
/// **"Passed" means two different things across those seven and the difference matters,
/// so it is spelled out rather than rounded off.** `show_backup_page` is a nested `fn`
/// inside `boot`, which is `#[cfg(target_arch = "arm")]`, so THREE of the seven compiled
/// the mutated line at all — the ARM release build and the two device clippy profiles —
/// and they passed because the edit is well-formed code that does the wrong thing, which
/// is precisely the blind spot PLAN.md §9 item 22 records ("the gate sees *malformed*
/// register code and is blind to *plausible-but-wrong*"). The other four passed
/// TRIVIALLY: the two host test gates never compiled it, `pixel-check` drives
/// `examples/simulator`, and `hostcheck` drives the stub's own reveal walk. Neither half
/// is reassuring, and together they are the whole argument for hoisting: the only gate
/// that can see this class is a host test, and a host test cannot reach inside `boot`.
///
/// What the mutation does is skip every other page —
/// [`reveal_step`] adds one to a cursor that is already one ahead — so a human is shown
/// pages 0, 2, 4, 6 and then asked "Wrote down all 25 words?" over **12 words that were
/// never drawn**. They say yes, `CommsMisc::BackupRecorded` goes to the coordinator, and
/// the app records a backup that cannot restore the share. No gate could see it because
/// every line of `boot` is `cfg(target_arch = "arm")` (PLAN.md §9 item 22) and the stub's
/// own reveal walk (`firmware/examples/stub.rs`) calls `Session::show_backup` directly
/// rather than through this file.
///
/// Hoisting is what makes it visible, and it is the same remedy the eight routers above
/// already use: `the_reveal_cursor_names_the_page_that_was_drawn` checks the pairing by
/// VALUE, so the `+ 1` is now a failing host test instead of a comment nobody re-derives.
/// It does not make a wrong cursor impossible — the caller still forwards what this
/// returns, and `every_exit_from_the_reveal_takes_the_words_off_the_glass` is the source
/// pin over that residue — but it moves the arithmetic to where a value test reaches it,
/// which is the whole of what §9 item 22's "tractable slice" means. The pin works on the
/// host despite `boot` being ARM-only because `include_str!` reads this file as TEXT, and
/// that is the property that makes source pins the right remedy for whatever cannot be
/// hoisted: MEASURED, a mutation that rebuilds the cursor at the call site instead of
/// forwarding it fails that pin on the host.
///
/// The SECOND pairing here is the digit: the screen is drawn with the same
/// [`ui::ConfirmDigit`] the cursor will accept, and both come out of ONE match arm, so
/// there is no longer a place to draw one digit and park another.
///
/// `Result<bool, ()>` and not `Result<bool, Fault>`: nothing here reads the fault, and
/// taking the library type would make the test construct one.
fn reveal_draw(
    page: usize,
    shown: Result<bool, ()>,
    record_pending: bool,
    confirm: ui::ConfirmDigit,
) -> (RevealScreen, Option<Reveal>) {
    match shown {
        // THE PAIRING. `page`, and never an expression over it: the cursor names the
        // page that was DRAWN, because that is the page whose footer the human is
        // reading and whose `NEXT_KEY` press `reveal_step` will advance from.
        Ok(true) => (RevealScreen::Page, Some(Reveal::Page(page))),
        // The pages ran out with the question armed. `confirm` twice, from one arm.
        Ok(false) if record_pending => (
            RevealScreen::Recorded(confirm),
            Some(Reveal::Recorded(confirm)),
        ),
        // Ended with nothing to ack, or faulted. Both end the flow, and both hand back
        // `None` so the event loop stops delivering keypresses in the same statement the
        // caller redraws the glass in.
        Ok(false) => (RevealScreen::Idle, None),
        Err(()) => (RevealScreen::Refuse, None),
    }
}

/// One pad verdict against the backup screen on the glass, into the next step.
///
/// Exhaustive over both enums with no `_` on [`Answer`], so a new pad verdict is a
/// compile error here as well as in [`answer`].
///
/// Every unadvertised key on a backup page ends the flow, through `end` — the same
/// index the natural ending uses, so there is one ending and not two. Harsh on
/// purpose: an over-press costs a re-ask and a second consent and loses no word,
/// while ignoring keys the footer did not offer leaves a share lit on the panel
/// after whoever pressed `x` has walked away, which is the leak this whole feature
/// exists to avoid. [`Answer::Yes`] cannot occur on a page — [`reveal_consent`]
/// hands those pages no digit — and is grouped with the refusal rather than given an
/// `unreachable!()`, because a panic in the event loop is a counted reset a
/// coordinator could provoke.
///
/// `saturating_*` and not `+ 1` / `- 1`: `overflow-checks = false` in release, so a
/// wrap here would silently alias onto another page of the same share instead of
/// ending the flow. `saturating_sub` also clamps page 0's back-press to a redraw of
/// page 0.
///
/// NO TIMEOUT, on either screen, and that is CHOSEN. There is no clock in this
/// signature and nowhere to put one: transcribing 25 words is slow, and a screen
/// that blanked mid-copy would cost a second full disclosure of the same secret to
/// finish the job. [`Answer::Wait`] is what a human reading produces, and it parks.
fn reveal_step(state: Reveal, answer: Answer, end: usize) -> RevealStep {
    match (state, answer) {
        (_, Answer::Wait) => RevealStep::Park,
        (Reveal::Page(page), Answer::Next) => RevealStep::Show(page.saturating_add(1)),
        (Reveal::Page(page), Answer::Back) => RevealStep::Show(page.saturating_sub(1)),
        // `Answer::Key` is unreachable here — [`flow_consent`] hands the reveal
        // `Consent::Pages`, never `Consent::Entry` — and it is grouped with the
        // refusal because that is the direction that takes the words off the glass.
        // An `unreachable!()` would be a panic in the event loop instead.
        (Reveal::Page(_), Answer::Yes | Answer::No | Answer::Key(_)) => RevealStep::Show(end),
        (Reveal::Recorded(_), Answer::Yes) => RevealStep::Ack,
        // `Answer::Next` cannot occur — `reveal_consent` passes `last: true`, so
        // `answer` clamps `ui::NEXT_KEY` to `Wait` — so an over-press of the key that
        // walked the human onto this screen leaves the question up rather than
        // dismissing it. `Back` is the key the page before advertised, and it is not
        // an answer to this one.
        (Reveal::Recorded(_), Answer::Next | Answer::Back | Answer::No | Answer::Key(_)) => {
            RevealStep::Idle
        }
    }
}

/// Which device-driven flow the glass is answering for, if any.
///
/// **ONE cursor and not two `Option`s.** Both flows put a secret on the panel and
/// both are ended by anything that takes the glass, so `take_glass` (inside `boot`)
/// must be able to end *both* in the one line that already ends the reveal — with two
/// variables that line becomes two lines and the second one is the one a future edit
/// forgets. It is an enum rather than a struct because there is one panel: a reveal and
/// an entry cannot both be on it, and every producer of either runs on a frame
/// `take_glass` has just cleared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flow {
    /// A granted backup reveal, at the page (or the question) it is on — see
    /// [`Reveal`].
    Reveal(Reveal),
    /// A granted backup ENTRY: the entry screen is on the glass and the pad is
    /// typing into it.
    ///
    /// **A unit variant, and that is the whole design.** The 25 slots, the prefix,
    /// the candidate letters and the page cursor all live in the
    /// `coldsnap_firmware::wordentry::Entry` inside `Session`, which only
    /// `Session::confirm_at` can create — so this file cannot start an ingest, cannot
    /// hold a typed word, and cannot put a share-shaped screen on the glass without a
    /// digit having been pressed first. What it can do is stop delivering keystrokes,
    /// which is what dropping this variant means.
    Entry,
    /// A granted backup CHECK QUIZ, at the screen it is on — see [`Check`].
    ///
    /// Carries a state and not a cursor: the position order, the question counter and
    /// the three candidates all live in the `coldsnap_firmware::quiz::Quiz` inside
    /// `Session`, which only `Session::confirm_at` can create. So this file cannot
    /// start a quiz, cannot pick a distractor and cannot put a share word on the glass
    /// without a digit having been pressed first.
    Check(Check),
}

/// What the flow currently on the glass will accept, and whether it is the last page
/// of its set.
///
/// One funnel for both flows so the event loop performs ONE bounded pad read whatever
/// is on the panel — the `cdc.poll` requirement — and so the pairing "which screen,
/// which gesture" is checked by value in one place. [`reveal_consent`] is delegated to
/// rather than inlined, so the reveal's own tests still exercise the function the
/// device runs.
///
/// `last` is `true` for [`Flow::Entry`] and it is IRRELEVANT there, by construction:
/// [`answer`]'s [`Consent::Entry`] arm sits above every arm that reads `last`. Passed
/// as `true` rather than `false` so that the value is the honest one if the ordering
/// ever changes — an entry screen is a whole screen, not page 1 of 8 —
/// and `the_entry_screen_answers_every_byte_as_a_keystroke` checks both values anyway.
fn flow_consent(flow: Flow) -> (Consent<'static>, bool) {
    match flow {
        Flow::Reveal(state) => reveal_consent(state),
        Flow::Entry => (Consent::Entry, true),
        // Both quiz screens, and `last` is irrelevant to both for the entry's reason.
        // ONE pairing for the question and for the passed screen, because the
        // difference between them is what a keystroke MEANS ([`check_step`]) and not
        // which keys reach it: the passed screen's own legend is `(x)done`, so it wants
        // a byte delivered too.
        Flow::Check(_) => (Consent::Quiz, true),
    }
}

/// What the event loop does next with a backup ENTRY on the glass.
///
/// The counterpart of [`RevealStep`], and deliberately not the same enum: the reveal's
/// steps are page arithmetic and this one carries a keystroke. There is no `Ack` here
/// because nothing this file can press acks an entry — `Session::entry_key` sends
/// `PhysicalEntered` itself, and only when 25 words pass their checksum.
///
/// `Debug` is hand-written below, redacting the press, for [`Answer`]'s reason: it is
/// the same byte.
#[derive(Clone, Copy, PartialEq, Eq)]
enum EntryStep {
    /// Nothing pressed. Keep the same screen and **do not redraw it**: a redraw
    /// re-samples [`ui::Frame::mark_sensitive`]'s noise over the prefix and the
    /// previous word, and averaging that over N observations is the one open edge that
    /// defence documents. Five rows of this screen are noised, against two on a reveal
    /// page (`hal/src/ui.rs`'s `WordEntry::render`), so it matters more here.
    Park,
    /// A live key: hand this byte to `Session::entry_key`.
    Key(u8),
    /// End the flow: standby over the words. Reached by two contacts, an unreadable
    /// scan, or a pad that never opened — never by a timer, see below.
    End,
}

/// The variant name, with the press redacted. See [`Answer`]'s impl for the argument;
/// this is the same byte one function later, so a `derive` here would undo it.
impl core::fmt::Debug for EntryStep {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            EntryStep::Park => "Park",
            EntryStep::Key(_) => "Key(<press>)",
            EntryStep::End => "End",
        })
    }
}

/// One pad verdict against an entry on the glass, into the next step.
///
/// Exhaustive over [`Answer`] with no `_` arm, so a new pad verdict is a compile error
/// here as it is in [`answer`] and [`reveal_step`].
///
/// **[`Answer::Yes`] ends the entry, it does not confirm anything.** It is unreachable
/// — [`flow_consent`] hands an entry [`Consent::Entry`], which carries no digit and no
/// prompt — and this is the value-level half of that claim: even if it arrived, the
/// only thing it could buy is the ending. There is no `Session::confirm_at` reachable
/// from this function, and no prompt in scope to pass one.
///
/// NO TIMEOUT, and that is CHOSEN. There is no clock in this signature and nowhere to
/// put one: 25 words at ~5.7 presses each is minutes of typing, and a screen that
/// blanked mid-word would cost the human the words they had entered *and* the second
/// full disclosure needed to get them back. [`Answer::Wait`] is what a human thinking
/// produces, and it parks.
fn entry_step(answer: Answer) -> EntryStep {
    match answer {
        Answer::Wait => EntryStep::Park,
        Answer::Key(key) => EntryStep::Key(key),
        // Two contacts, an unreadable scan, or no pad at all. Fail-closed in the
        // direction that clears the glass — the same choice the reveal makes, and for
        // the same reason: a prefix left lit after a human walks away is the leak.
        Answer::No => EntryStep::End,
        // All three are unreachable: `Consent::Entry`'s arm in `answer` takes every
        // `Down` before the paging arms can produce `Next`/`Back`, and neither of the
        // two arms that can produce `Yes` is reachable without a digit. Grouped with
        // the ending rather than given an `unreachable!()`, because a panic in the
        // event loop is a counted reset a coordinator could provoke.
        Answer::Next | Answer::Back | Answer::Yes => EntryStep::End,
    }
}

/// Compose the entry screen `coldsnap_firmware` says is current. `false` means
/// **nothing was drawn** and the caller must put something else on the glass.
///
/// A module item rather than a closure inside `boot`, for [`answer`]'s reason: `boot`
/// is `#[cfg(target_arch = "arm")]`, so a frame built in there is composed by no test
/// in this tree. Every row that carries share material comes from `hal::ui`'s own
/// renderers — `ui::EntryPages` for the public share index and [`ui::WordEntry`] for a
/// word — so the `mark_sensitive` noise, the 12-cell sensitive budget and the footer
/// legends are the ones `hal`'s pixel gate covers, and this function only chooses
/// between them.
///
/// `rng` is mandatory in both, which is why it is mandatory here. An opt-in would fail
/// OPEN.
fn entry_frame(
    screen: coldsnap_firmware::wordentry::Screen<'_>,
    frame: &mut ui::Frame,
    rng: &mut impl rand_core::RngCore,
) -> bool {
    use coldsnap_firmware::wordentry::Screen;
    match screen {
        // The share index is PUBLIC — it is on the coordinator's screen too — so it is
        // the one entry row that is not noised, and `ui::EntryPages`' page 0 is the
        // screen `hal` already draws for it. `share_index: None` and no words: page 0
        // reads neither, and handing it anything else would be inventing state this
        // file does not have.
        Screen::ShareIndex { typed } => {
            let mut digits = ui::Buf::<16>::new();
            if let Some(index) = typed {
                digits.push_u64(u64::from(index));
            }
            ui::EntryPages {
                share_index: None,
                words: &[],
                partial: digits.as_str(),
            }
            .render(0, frame, rng)
        }
        // The word page, with the candidate letters. `wordentry` built the whole
        // `ui::WordEntry` — the ruler the human reads and the key the machine decodes
        // come from one value — so there is no arithmetic here to get wrong. `Err` is
        // `ui::Unrenderable`, which draws NOTHING (every check runs before the
        // `clear`), so the caller's refusal goes onto a clean frame.
        Screen::Word(word) => word.render(frame, rng).is_ok(),
        // The 25 words did not checksum. The device does NOT know which word is wrong
        // — the checksum is one SHA-256 over the whole share, so there is no per-word
        // syndrome — and it must not pretend to, so this names no position. All 25 are
        // still held: any key returns to word 25 with nothing discarded, which is what
        // the footer says.
        //
        // ponytail: composed here rather than in `hal::ui`, so `tools/pixel-check.py`
        // and the simulator do not cover its layout — the ceiling is that a row could
        // overrun `ui::COLS` unnoticed (`Frame::text` truncates, so the failure is a
        // clipped word and never a panic). Upgrade path: `ui::entry_checksum_failed`
        // beside `ui::backup_recorded`, which is `hal/src/ui.rs`'s call, not this
        // file's. Nothing sensitive is on it: no word, no prefix, no index.
        Screen::Failed => {
            frame.clear();
            frame.text(0, 0, "CHECKSUM FAILED");
            frame.text(0, 2, "All 25 words");
            frame.text(0, 3, "are still held.");
            frame.text(0, 5, "Check them");
            frame.text(0, 6, "against paper.");
            frame.text(0, ui::ROWS - 1, "any key=word 25");
            true
        }
    }
}

/// What a granted check quiz has on the glass, and therefore what the next keypress
/// means.
///
/// Two states rather than a unit variant, and the second one is not decoration:
/// `ui::backup_quiz_passed`'s footer prints `(x)done` (`hal/src/ui.rs:2457`), so a key
/// has to be able to dismiss that screen. `Session::quiz_key` cannot serve it — the
/// pass DROPPED the quiz, so every later call refuses — and a refusal drawn over
/// "Quiz passed" would be a screen saying CANNOT DISPLAY for a quiz that displayed
/// fine. The state is what makes the legend honest.
///
/// **A CURSOR AND NOTHING ELSE**, exactly as [`Reveal`] is. The grant lives in
/// [`Session`](coldsnap_firmware::Session), set only by `confirm_at` and read only by
/// `quiz_screen`/`quiz_key`, so this cannot authorise a quiz any more than a page
/// number can authorise a signature — and it holds no word, no candidate and no
/// position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Check {
    /// A question is on the glass: three candidates on [`ui::QUIZ_KEYS`], one of which
    /// is a true word of the share. **No digit**, so nothing pressed here can
    /// authorise anything.
    Asking,
    /// The quiz passed and `ui::backup_quiz_passed` is up. The words are already off
    /// the glass — that screen takes a count and cannot be handed a `&str` — and
    /// `CommsMisc::BackupChecked` is already in the outbox, so this screen answers
    /// NOTHING: any key dismisses it and the ack cannot be sent twice.
    Passed,
}

/// What the event loop does next with a check quiz on the glass.
///
/// The counterpart of [`RevealStep`] and [`EntryStep`], and deliberately **not**
/// [`EntryStep`] even though the three states line up: `EntryStep::Key` is documented
/// as "hand this byte to `Session::entry_key`", which INGESTS a share, and the two
/// routers would then differ by one identifier in a `match` arm that reads the same.
/// A quiz keystroke reaching `entry_key` is not a compile error and never would be, so
/// the separation that is on offer is a distinct pattern in a distinct arm — which is
/// what the source pins on both flows can then hold.
///
/// There is no `Ack` here, unlike [`RevealStep`]: `Session::quiz_key` sends
/// `CommsMisc::BackupChecked` itself, and only when every question has been answered
/// correctly. Nothing this file can press acks a quiz.
///
/// `Debug` is hand-written below, redacting the press, for [`Answer`]'s reason.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CheckStep {
    /// Nothing pressed. Keep the same screen and **do not redraw it**: a redraw
    /// re-samples [`ui::Frame::mark_sensitive`]'s noise over three option rows, one of
    /// which holds a true word of the share, and averaging that over N observations is
    /// the one open edge that defence documents.
    Park,
    /// A live key: hand this byte to `Session::quiz_key`. Reached only from
    /// [`Check::Asking`].
    Key(u8),
    /// End the flow: standby over the candidates. Reached by two contacts, an
    /// unreadable scan, a pad that never opened, or any key on the passed screen —
    /// never by a timer, see below.
    Done,
}

/// The variant name, with the press redacted. See [`Answer`]'s impl for the argument.
///
/// The byte here is `1`, `2` or `3` — which candidate slot a human tapped — and on its
/// own that is not the secret, because the slot means nothing without the three words
/// it indexed (and no `Debug` in this tree prints those: `quiz::Screen`'s manual impl
/// drops the options and `ui::QuizWord` never holds one). Redacted anyway, because the
/// pairing is one log line away and because a `Key(u8)` that prints its byte is the
/// habit this file already refused twice.
impl core::fmt::Debug for CheckStep {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            CheckStep::Park => "Park",
            CheckStep::Key(_) => "Key(<press>)",
            CheckStep::Done => "Done",
        })
    }
}

/// One pad verdict against a check quiz on the glass, into the next step.
///
/// Exhaustive over both enums with no `_` on [`Answer`], so a new pad verdict is a
/// compile error here as it is in [`answer`], [`reveal_step`] and [`entry_step`].
///
/// **[`Answer::Yes`] ends the quiz, it does not confirm anything.** It is unreachable
/// — [`flow_consent`] hands a quiz [`Consent::Quiz`], which carries no digit and no
/// prompt — and this is the value-level half of that claim: even if it arrived, the
/// only thing it could buy is standby. There is no `Session::confirm_at` reachable
/// from this function and no prompt in scope to pass one, which matters more here than
/// anywhere else in this file because all three answer keys are also confirm digits.
///
/// The decline (`x`) is **not** a step of its own. It arrives as [`Answer::Key`] and
/// `coldsnap_firmware::quiz::Quiz::key` turns it into an abort, so "which key gives
/// up" is decided in one pure module that already drives all 256 bytes at every state
/// — rather than twice, in two places free to disagree about `x`.
///
/// NO TIMEOUT, and that is CHOSEN. There is no clock in this signature and nowhere to
/// put one: eight questions is minutes of comparing words against paper, and a screen
/// that blanked mid-quiz would cost the human the whole quiz *and* a second consent to
/// re-take it — at which point the coordinator draws three more real words. Which is
/// strictly worse than three that stay lit until a key or a coordinator prompt.
/// [`Answer::Wait`] is what a human reading produces, and it parks.
fn check_step(state: Check, answer: Answer) -> CheckStep {
    match (state, answer) {
        (_, Answer::Wait) => CheckStep::Park,
        (Check::Asking, Answer::Key(key)) => CheckStep::Key(key),
        // ANY key dismisses the passed screen, not only the `(x)done` its footer
        // prints. There is nothing on it a further press could change, and nothing to
        // send twice, so being generous here costs nothing — while refusing every byte
        // but one would leave a screen up that says it can be dismissed.
        (Check::Passed, Answer::Key(_)) => CheckStep::Done,
        // Two contacts, an unreadable scan, or no pad at all. Fail-closed in the
        // direction that clears the glass — the same choice the reveal and the entry
        // make, and for a sharper version of the same reason: one of the three rows on
        // this screen is a true word of the share.
        (_, Answer::No) => CheckStep::Done,
        // All three are unreachable: `Consent::Quiz`'s arm in `answer` takes every
        // `Down` before the paging arms can produce `Next`/`Back`, and neither of the
        // two arms that can produce `Yes` is reachable without a digit. Grouped with
        // the ending rather than given an `unreachable!()`, because a panic in the
        // event loop is a counted reset a coordinator could provoke.
        (_, Answer::Next | Answer::Back | Answer::Yes) => CheckStep::Done,
    }
}

/// Compose the quiz screen `coldsnap_firmware` says is current. `false` means
/// **nothing was drawn** and the caller must put something else on the glass.
///
/// A module item rather than a closure inside `boot`, for [`entry_frame`]'s reason:
/// `boot` is `#[cfg(target_arch = "arm")]`, so a frame built in there is composed by no
/// test in this tree — and this is the frame that carries a real share word.
///
/// Every row of it comes from `hal::ui`'s own renderers, so the `mark_sensitive` noise
/// over the three option rows, the 12-cell sensitive budget and the footer legends are
/// the ones `hal`'s pixel gate covers, and this function only chooses between them.
/// `rng` is mandatory in [`ui::backup_quiz_word`], which is why it is mandatory here;
/// an opt-in would fail OPEN over a row holding a true word.
///
/// `Err` from either renderer is `ui::Unrenderable`, which draws NOTHING (every check
/// runs before the `clear`), so the caller's refusal goes onto a clean frame.
fn quiz_frame(
    screen: coldsnap_firmware::quiz::Screen,
    frame: &mut ui::Frame,
    rng: &mut impl rand_core::RngCore,
) -> bool {
    use coldsnap_firmware::quiz::Screen;
    match screen {
        // The question. `quiz::Quiz` built the whole `ui::QuizWord` — the progress the
        // human reads and the position the machine scores come from one value — and the
        // options travel beside it rather than inside it, so the type that derives
        // `Debug` holds no word. There is no arithmetic here to get wrong.
        Screen::Word { question, options } => {
            ui::backup_quiz_word(frame, question, options, rng).is_ok()
        }
        // The ending. Takes a COUNT and no `&str`, so this frame cannot carry a word
        // even by mistake, and it says "n of 25 words matched / the rest were not
        // checked" rather than "backup verified" — which is the honest claim, because
        // `quiz::QUIZ_POSITIONS` is 8.
        Screen::Passed { checked } => ui::backup_quiz_passed(frame, checked).is_ok(),
    }
}

/// Which device-driven flow a `yes` to this prompt GRANTS, if any — permission for
/// `Session::show_backup` to draw the whole share in plain, for
/// `Session::entry_key` to take a keystroke, or for `Session::quiz_key` to score one.
///
/// Exactly three prompts in the protocol grant anything, they grant DIFFERENT things,
/// and the match is exhaustive with no `_` arm so a new upstream variant is a compile
/// error rather than a silent grant. That is worth more than it looks: `show_backup`
/// draws all 25 words, so a variant wrongly routed to [`Grant::Reveal`] answers a
/// request for something *else* with a full disclosure. `CheckBackup` is the live
/// example and it is now on the `Some` side of this match — but on
/// [`Grant::Check`]'s side of it, which draws one question of three candidates through
/// [`ui::backup_quiz_word`] and acks `BackupChecked`. Routing it to [`Grant::Reveal`]
/// is the catastrophic mutation this arm exists to make loud, and it is what
/// `only_a_display_backup_prompt_grants_a_reveal` fails on.
///
/// **One function and not three predicates**, which is the whole reason the reveal's
/// `bool` became an `Option`: three booleans over the same five variants can all be
/// true, and "grant a reveal" plus "grant an entry" at once is 25 plain words drawn
/// over a screen that asked to type them in. An `Option<Grant>` cannot say that.
///
/// Read off the prompt rather than out of the library because `confirm_at` takes the
/// prompt by value — and, for the entry, because reading it out of the library would
/// be WRONG: `Session`'s entry grant can outlive the screen (a pad fault ends the flow
/// here while the library still holds the words, exactly as it does for the reveal), so
/// `entry_screen().is_some()` would resurrect an abandoned entry on the next unrelated
/// consent. The prompt that was answered is the fact; the grant is its consequence.
///
/// Two gates already stand in front of this one — `prompt_screen_at` draws no screen
/// for `BackupSaved`, and `confirm_at` refuses it — so this is the third, and it is the
/// one that stays correct when a *future* change opens the first two for a different
/// variant. It was the fourth until `Session::recv` admitted `CheckBackup`; the
/// dispatch's refusal is gone and this arm is now load-bearing rather than redundant.
fn grants(prompt: &DeviceToUserMessage) -> Option<Grant> {
    let DeviceToUserMessage::Restoration(restoration) = prompt else {
        return None;
    };
    match **restoration {
        ToUserRestoration::DisplayBackup { .. } => Some(Grant::Reveal),
        ToUserRestoration::EnterBackup { .. } => Some(Grant::Entry),
        ToUserRestoration::CheckBackup { .. } => Some(Grant::Check),
        ToUserRestoration::BackupSaved { .. } | ToUserRestoration::ConsolidateBackup(_) => None,
    }
}

/// What a `yes` buys, when it buys a flow of its own. See [`grants`].
///
/// `ConsolidateBackup` is deliberately absent: its consent buys a flash WRITE, which
/// `Session::confirm_at` performs itself and which puts nothing on the glass, so there
/// is no cursor for this file to hold. Its digit is no weaker for that — it is the same
/// [`Consent::Prompt`] path the signing digit uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Grant {
    /// Permission for `Session::show_backup` to draw the whole share in plain.
    Reveal,
    /// Permission for `Session::entry_key` to accept a keystroke — the one flow on
    /// this device that INGESTS a secret.
    Entry,
    /// Permission for `Session::quiz_key` to score a keypress against the check quiz.
    ///
    /// **Reveal-class, not the cheap one.** One of every three candidates on every
    /// question is the true word at that position and a second is a real word from
    /// elsewhere in the same share, so this grant is taken behind the same randomised
    /// digit, over the same warning, as [`Grant::Reveal`]. What it is NOT is a reveal:
    /// `Session` keeps two separate grant fields with no assignment between them, so
    /// this buys eight questions and never `Session::show_backup`.
    Check,
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
    use coldsnap_firmware::{
        firmware_digest, prompt_screen_at, quiz, Checked, DebugFlash, Fault, Outbox, Session,
        Shown, Typed,
    };
    use coldsnap_hal::panic::{bump_counter, clear_counter, BootHealth, Counter};
    use coldsnap_hal::{comms, display, flash, identity, rng, usb};
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
        glass: &mut Option<Flow>,
    ) -> Option<bool> {
        let mut frame = ui::Frame::new();
        let shown = prompt_screen_at(&mut frame, prompt, confirm, page);
        // No screen for this prompt. Nothing drawn, nothing parked — and, because
        // the glass is left exactly as it was, whatever backup flow was on it is
        // still on it and still answerable. That is the one leg that must NOT reach
        // `take_glass`.
        //
        // It is also the leg the restore flow leans on: `SavePhysicalBackup2` answers
        // with a `BackupSaved`, for which `prompt_screen_at` draws no screen, so the
        // coordinator's own bookkeeping arriving mid-ceremony does not blank a word the
        // human is halfway through typing.
        if matches!(shown, Ok(Shown::Nothing)) {
            return None;
        }
        // Either the prompt's own screen or `ui::refusal`, and both belong to this
        // prompt now.
        take_glass(panel, &frame, glass);
        match shown {
            Ok(Shown::Page { last }) => Some(last),
            // The frame held `ui::refusal`; it is shown and nothing is parked.
            _ => None,
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
        glass: &mut Option<Flow>,
    ) -> Option<Parked> {
        let mut parked = None;
        for prompt in prompts {
            let confirm = ui::ConfirmDigit::draw(rng);
            if let Some(last) = draw_prompt(panel, &prompt, confirm, 0, glass) {
                parked = Some((prompt, confirm, 0, last));
            }
        }
        parked
    }

    /// Put a frame on the glass, **ending whatever backup flow was on it** — a reveal
    /// or an entry, in the same line, because [`Flow`] is one value.
    ///
    /// The pixels and the cursor move together, in one function, so a caller cannot
    /// take the glass and leave the gate still answering for a screen that is gone.
    /// That was a live fail-open, and it was reachable without a hostile
    /// coordinator: any message `Session::recv` refuses drew `ui::refusal` over the
    /// "wrote down all 25 words?" question, and the digit that question printed
    /// stayed live behind it — so one lucky press on a screen nobody could read told
    /// the app a wallet was backed up. An undisplayable prompt did the same through
    /// [`draw_prompt`]'s `Err` leg.
    ///
    /// It is also what makes `ui::BACK_KEY` stop being a hidden command on a backup
    /// page: with a refusal on the glass the `(9)next (7)back` footer is not on it,
    /// so neither key may still page.
    ///
    /// The cursor is dropped rather than the words redrawn, which is the fail-closed
    /// direction — a reveal that ends costs a second consent, and a reveal that
    /// resurrects itself under a screen that says something else costs the secret.
    /// `Session`'s grant is left behind and is unreachable: [`show_backup_page`] is
    /// its only reader and it runs only from this cursor.
    ///
    /// The same for an entry, and it is the coordinator-prompt half of requirement 5:
    /// the prefix and the previous word leave the glass the moment anything else is
    /// drawn, and the pad stops delivering keystrokes in the same statement. `Session`
    /// keeps its `wordentry::Entry` and it is equally unreachable — the entry branch
    /// of the event loop is gated on this cursor, and only [`grants`] plus a fresh
    /// digit can produce a new one.
    fn take_glass(panel: &mut display::Panel, frame: &ui::Frame, glass: &mut Option<Flow>) {
        *glass = None;
        let _ = panel.show(frame.as_bytes());
    }

    /// The device saying no, which a user is entitled to see. Best-effort: a
    /// display fault must never turn a refusal into a reset.
    ///
    /// Ends a backup flow, through [`take_glass`] — see there. With no panel there is
    /// nothing to overwrite and nothing to end: every producer of a [`Flow`] needs a
    /// panel ([`show_backup_page`] and [`show_entry_page`] both take one by `&mut`), so
    /// the cursor is already `None` on that leg.
    fn refuse(panel: Option<&mut display::Panel>, glass: &mut Option<Flow>) {
        let Some(panel) = panel else { return };
        let mut frame = ui::Frame::new();
        ui::refusal(&mut frame);
        take_glass(panel, &frame, glass);
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
    ) -> Option<Reveal> {
        let mut frame = ui::Frame::new();
        // Drawn BEFORE the match and on every leg, so the digit handed to [`reveal_draw`]
        // exists whichever arm it takes. Unused on three of the four, which costs one
        // `Entropy` byte per page and buys a pure router: the alternative is to draw it
        // inside the `Recorded` arm, which is exactly the arm-local arithmetic this
        // change exists to get out of `boot`.
        let confirm = ui::ConfirmDigit::draw(rng);
        let shown = session.show_backup(page, &mut frame, rng).map_err(|_| ());
        // The pages running out is how a reveal ENDS. `Session::show_backup` has already
        // dropped the grant and re-derived nothing, so the only thing left to decide is
        // what goes over the words — and `record_pending` is the library's answer to
        // whether it ended or faulted; it is armed on the ending leg only.
        //
        // The screen and the cursor are decided TOGETHER, by [`reveal_draw`], and this
        // function only forwards what it says. That is the whole point: the cursor
        // arithmetic used to live here, where no gate in the project could execute it.
        let (screen, next) = reveal_draw(page, shown, session.record_pending(), confirm);
        match screen {
            // The words are already in `frame` — `show_backup` composed them there.
            RevealScreen::Page => {
                let _ = panel.show(frame.as_bytes());
            }
            // Drawn into the SAME `frame` the words were in, which is both cheaper than a
            // second 1,024-byte frame and the reason requirement 5 still holds: every leg
            // here overwrites the glass, so there is no exit from a reveal with a share
            // still lit.
            RevealScreen::Recorded(digit) => {
                ui::backup_recorded(&mut frame, digit);
                let _ = panel.show(frame.as_bytes());
            }
            RevealScreen::Idle => idle(session, panel),
            RevealScreen::Refuse => {
                ui::refusal(&mut frame);
                let _ = panel.show(frame.as_bytes());
            }
        }
        next
    }

    /// Draw the current screen of a granted backup ENTRY. `false` means the entry is
    /// over and something else is already on the glass.
    ///
    /// **The only producer of [`Flow::Entry`]**, which is what makes requirement 5
    /// control flow rather than a rule to remember: both legs that return `false` have
    /// redrawn the panel first, so there is no way to keep typing into a screen that is
    /// gone and no way to end this flow with a prefix still lit.
    ///
    /// `&Session` and not `&mut`: this function cannot advance the machine, only draw
    /// what it says is current. The composing is [`entry_frame`], a module item with
    /// host tests, so what is ARM-only here is the panel and nothing else.
    ///
    /// `None` from `entry_screen` is the entry having ended underneath us — a
    /// coordinator `Cancel` drops the grant and draws nothing (`Session::recv`'s
    /// `Cancel` arm) — and it draws standby, so the words come off the glass on that
    /// iteration rather than on the next keypress.
    ///
    /// `entry_frame` returning `false` is `ui::Unrenderable` from `ui::WordEntry`, which
    /// is unreachable (`wordentry` keeps its cursor in `0..25` and its prefix
    /// BIP39-shaped by construction) and draws nothing, so the refusal goes onto a clean
    /// frame and the flow ends. Never a panic: this runs inside the event loop.
    fn show_entry_page<F: NorFlash + core::fmt::Debug>(
        session: &Session<'_, F>,
        panel: &mut display::Panel,
        rng: &mut rng::Entropy,
    ) -> bool {
        let Some(screen) = session.entry_screen() else {
            idle(session, panel);
            return false;
        };
        let mut frame = ui::Frame::new();
        if !entry_frame(screen, &mut frame, rng) {
            ui::refusal(&mut frame);
            let _ = panel.show(frame.as_bytes());
            return false;
        }
        let _ = panel.show(frame.as_bytes());
        true
    }

    /// Draw one screen of a granted check quiz. `None` means nothing quiz-shaped is on
    /// the glass any more and something else has already been drawn over it.
    ///
    /// **The only producer of [`Flow::Check`]**, which is what makes requirement 6
    /// control flow rather than a rule to remember: every leg that returns `None` has
    /// redrawn the panel first, so there is no way to end this flow with three
    /// candidates still lit and no way to keep a cursor alive without a frame behind it.
    ///
    /// The screen is an ARGUMENT rather than read from the session, because the two
    /// screens come from different places and only one of them is the library's:
    /// `session.quiz_screen()` is the question, and the passed screen is drawn AFTER
    /// `Session::quiz_key` has dropped the quiz (so `quiz_screen()` is already `None` by
    /// then — the pass is what dropped it). One producer for both is worth an argument;
    /// two producers would be two places to forget to redraw.
    ///
    /// `&Session` and not `&mut`: this cannot advance the quiz, only draw what it says
    /// is current. The composing is [`quiz_frame`], a module item with host tests, so
    /// what is ARM-only here is the panel and nothing else.
    ///
    /// `None` from `quiz_screen` is the quiz having ended underneath us — a coordinator
    /// `Cancel` drops the grant and draws nothing (`Session::recv`'s `Cancel` arm) — and
    /// it draws standby, so the candidates come off the glass on that iteration rather
    /// than on the next keypress.
    ///
    /// `quiz_frame` returning `false` is `ui::Unrenderable`, which is unreachable
    /// (`quiz::Quiz` refuses at construction anything its own screens could not render)
    /// and draws nothing, so the refusal goes onto a clean frame and the flow ends.
    /// Never a panic: this runs inside the event loop.
    fn show_quiz<F: NorFlash + core::fmt::Debug>(
        session: &Session<'_, F>,
        screen: Option<quiz::Screen>,
        panel: &mut display::Panel,
        rng: &mut rng::Entropy,
    ) -> Option<Check> {
        let Some(screen) = screen else {
            idle(session, panel);
            return None;
        };
        let mut frame = ui::Frame::new();
        if !quiz_frame(screen, &mut frame, rng) {
            ui::refusal(&mut frame);
            let _ = panel.show(frame.as_bytes());
            return None;
        }
        let _ = panel.show(frame.as_bytes());
        // Read off the screen that was just drawn rather than passed in beside it, so
        // the cursor and the pixels cannot describe different things — `Check` decides
        // what the next keypress MEANS, and a `Passed` screen routed as `Asking` would
        // hand its dismissal to `Session::quiz_key`, which refuses a quiz that is over.
        Some(match screen {
            quiz::Screen::Word { .. } => Check::Asking,
            quiz::Screen::Passed { .. } => Check::Passed,
        })
    }

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
    // `ESTACK_TOP` with 548,776 B of runway (MEASURED 2026-09-10: `ESTACK_TOP`
    // 0x2009_e000 - `_end` 0x2001_8058 in the linked ELF; this comment read 548,268,
    // which was measured against a smaller `.bss`), so a 4 KiB inline buffer is
    // affordable — but it IS the largest
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

    // Which device-driven flow is on the glass, if any — see [`Flow`]. A reveal at the
    // page it is on, or an entry.
    //
    // Separate from `parked` because the screens answer different keys — a backup page
    // prints no digit, so nothing on it can confirm anything, and it is the only screen
    // whose footer advertises `ui::BACK_KEY`; an entry answers every byte as a
    // keystroke and confirms nothing either. They are mutually exclusive by
    // construction: the `else if` below means at most one of them is serviced per
    // iteration (so at most ONE bounded pad read), and `Flow` being one enum means a
    // reveal and an entry cannot be live at once.
    //
    // IT IS ONLY EVER SOME WHILE ITS OWN SCREEN IS ON THE GLASS. Every producer draws
    // first (`show_backup_page`, `show_entry_page`) and everything that overwrites the
    // glass drops it (`take_glass`), so the gate cannot answer for a frame that is gone.
    // That was a live fail-open before `take_glass` existed.
    let mut glass: Option<Flow> = None;

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
                                // `&mut glass`: whatever this batch puts on the
                                // glass ends the backup flow that was on it — a
                                // reveal or an entry — inside `take_glass`, so the
                                // cursor cannot outlive the frame it described.
                                // Passed even though nothing here reads it back —
                                // that is the point, the drop is not this call
                                // site's to remember.
                                Ok(prompts) => {
                                    if let Some(panel) = panel.as_mut() {
                                        if let Some(next) =
                                            draw_batch(panel, &mut entropy, prompts, &mut glass)
                                        {
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
                                //
                                // `&mut glass` for `draw_batch`'s reason and one
                                // more: THIS is the arm that was the fail-open. A
                                // refusal drawn over the "wrote it down?" question
                                // used to leave that question's digit live behind
                                // it, so a press on a screen reading "CANNOT
                                // DISPLAY" could tell the coordinator a backup was
                                // on paper. See `take_glass`. The entry inherits the
                                // fix: a refused message draws over a prefix and
                                // stops the keystrokes in the same statement.
                                Err(Fault::Refused(_) | Fault::Store(_)) => {
                                    refuse(panel.as_mut(), &mut glass)
                                }
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
            // Does a yes to THIS prompt grant a flow of its own — a reveal, or an
            // entry? Read before the consent because `confirm_at` takes the prompt by
            // value, and read by `grants` — a host-compiled exhaustive match — rather
            // than by a `matches!` on the family, because the family is where the trap
            // is: three of the five `ToUserRestoration` variants grant nothing and one
            // of those (`CheckBackup`) is a QUIZ, so a family-wide reveal would answer
            // a request for one word of three with all 25 in plain.
            let grant = grants(&prompt);
            // The prompt and the digit that were RENDERED, travelling together — see
            // `answer`. Bound rather than written inline so the call below stays on one
            // line and `cargo fmt` cannot reflow the shape the source pin matches.
            let consent = Consent::Prompt(&prompt, confirm);
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
                        if let Some(last) = draw_prompt(panel, &prompt, confirm, next, &mut glass) {
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
                            match grant {
                                // THE REVEAL STARTS HERE, and only here. `prompts`
                                // is empty on this leg by the library's design —
                                // `confirm_at` acks nothing, because upstream's
                                // `BackupRecorded` means "a human wrote it down" and
                                // that is the question `Reveal::Recorded` asks at the
                                // END — so there is nothing to draw except page 0,
                                // and page 0 is the share index rather than a word.
                                Some(Grant::Reveal) => {
                                    glass = show_backup_page(&mut session, 0, panel, &mut entropy)
                                        .map(Flow::Reveal);
                                }
                                // THE ENTRY STARTS HERE, and only here — the mirror
                                // image of the reveal, and the only place on this
                                // device where a human can begin handing a secret IN.
                                // `prompts` is empty on this leg too: `confirm_at`'s
                                // `EnterBackup` arm sets the grant and sends nothing,
                                // because `PhysicalEntered` belongs to the moment 25
                                // words checksum and not to the moment someone agrees
                                // to start typing.
                                //
                                // `show_entry_page` draws page 0, which is the SHARE
                                // INDEX and not a word — upstream's own gate
                                // (`share_index_confirmed`) — so the first thing on
                                // the glass carries nothing secret at all.
                                Some(Grant::Entry) => {
                                    glass = show_entry_page(&session, panel, &mut entropy)
                                        .then_some(Flow::Entry);
                                }
                                // THE QUIZ STARTS HERE, and only here. `prompts` is
                                // empty on this leg for the same library reason as the
                                // other two: `confirm_at`'s `CheckBackup` arm builds the
                                // `quiz::Quiz` and sends nothing, because
                                // `CommsMisc::BackupChecked` belongs to the moment the
                                // last question is answered and not to the moment
                                // someone agrees to be asked.
                                //
                                // Unlike the reveal, the FIRST screen already carries a
                                // real word — one of the three candidates is the true
                                // word at the position being asked — so there is no
                                // index page in front of it to soften the start. That is
                                // why this grant is issued on the same digit, over the
                                // same "SECRET on glass" warning, as `Grant::Reveal`.
                                Some(Grant::Check) => {
                                    glass = show_quiz(
                                        &session,
                                        session.quiz_screen(),
                                        panel,
                                        &mut entropy,
                                    )
                                    .map(Flow::Check);
                                }
                                None => {
                                    if let Some(next) =
                                        draw_batch(panel, &mut entropy, prompts, &mut glass)
                                    {
                                        parked = Some(next);
                                    }
                                }
                            }
                        }
                    }
                    Err(_fault) => refuse(panel.as_mut(), &mut glass),
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
                //
                // **`Answer::Key` IS HERE AND MUST STAY HERE.** It is unreachable —
                // `answer` produces it only under `Consent::Entry`, and this arm is
                // under `Consent::Prompt` — but this is the arm a "just make the entry
                // keys work" patch would reach for, and routing it to `confirm_at`
                // would make `3` sign a transaction whose screen printed `4`. A
                // keystroke is not a consent, on any screen; the entry has its own
                // branch below and it never sees a prompt.
                Answer::Back | Answer::Key(_) | Answer::No => refuse(panel.as_mut(), &mut glass),
            }
        // --- The backup flows: reveal and entry. --------------------------------
        // `else if`, so an iteration does at most ONE bounded pad read whatever is on
        // the glass — and ONE `ask` for both flows, because `flow_consent` picks what
        // that read is asking about. That is requirement 3 for flows that are 8 pages
        // of transcription and 25 words of typing respectively: `cdc.poll` runs once
        // per keypress, and there is no loop here and no wait for a human, exactly as
        // for a parked prompt. Do NOT make this a `while` — see `ask`. An entry is
        // ~142 presses, so it is 142 trips round this loop and 142 polls.
        //
        // Every DECISION in here is `flow_consent`, `reveal_step` and `entry_step`,
        // which are module items with host tests, so what remains at this indentation
        // is the panel and the session — the two things no host has. That split is
        // deliberate: `boot` is `#[cfg(target_arch = "arm")]`, so every line below is
        // linted by the device gate and executed by nothing (PLAN.md §9 item 22),
        // while the routing they carry out is checked by value.
        //
        // NO TIMEOUT, on any of the three screens, and that is CHOSEN — there is no
        // clock in any of these signatures and nowhere here to put one. Transcribing 25
        // words is slow and typing them back in is slower; a screen that blanked
        // mid-word would cost a second full disclosure of the same secret to finish the
        // job, which is strictly worse than words that stay lit until a key or a
        // coordinator prompt arrives.
        } else if let Some(flow) = glass.take() {
            let (consent, last) = flow_consent(flow);
            // Bound rather than written inline, for the reason `consent` is above: the
            // call then stays on one line and `cargo fmt` cannot reflow the shape the
            // source pin matches.
            let verdict = ask(keypad.as_mut(), &mut entropy, consent, last);
            match flow {
                Flow::Reveal(state) => match reveal_step(state, verdict, BACKUP_END) {
                    // Nobody has answered yet. Put the same screen back, undrawn: a
                    // redraw re-randomises `ui::Frame::mark_sensitive`'s noise (averaging
                    // that over N observations is the one open edge that defence
                    // documents) and a fresh digit would leave the recorded question
                    // naming a key that no longer answers it.
                    RevealStep::Park => glass = Some(Flow::Reveal(state)),
                    // Forward, back, or the ending — one call, so the ending cannot
                    // acquire a second path. `show_backup_page` is what redraws, and
                    // every `None` it returns has drawn something else first, which is
                    // requirement 5 as control flow.
                    RevealStep::Show(page) => {
                        if let Some(panel) = panel.as_mut() {
                            glass = show_backup_page(&mut session, page, panel, &mut entropy)
                                .map(Flow::Reveal);
                        }
                    }
                    // The ack, and the only place in this image that sends it. `let _` on
                    // the result for the loop's usual reason: `backup_recorded` fails only
                    // by refusing (no reveal ran to its end) or by refusing to frame a
                    // unit variant, and neither is worth a reset.
                    RevealStep::Ack => {
                        let _ = session.backup_recorded(&mut outbox);
                        if let Some(panel) = panel.as_mut() {
                            idle(&session, panel);
                        }
                    }
                    // Answered "not written down", which sends NOTHING and leaves the
                    // coordinator's dialog open — the honest state. Standby over the
                    // question is tidiness rather than the leak guard: the words went off
                    // the glass when `show_backup_page` drew the question over them.
                    RevealStep::Idle => {
                        if let Some(panel) = panel.as_mut() {
                            idle(&session, panel);
                        }
                    }
                },
                // THE ENTRY. `session.entry_screen()` is checked first because the
                // coordinator can take the grant away without drawing anything: `recv`'s
                // `Cancel` arm drops the `wordentry::Entry` and returns no prompt, so
                // without this the prefix would sit lit on the panel until the next
                // keypress. Requirement 5 says a flow ends on a keypress or a coordinator
                // message, and a `Cancel` is the second kind.
                Flow::Entry => {
                    let step = if session.entry_screen().is_some() {
                        entry_step(verdict)
                    } else {
                        EntryStep::End
                    };
                    match step {
                        // Nothing pressed. Same frame, NOT redrawn — five rows of this
                        // screen go through `mark_sensitive` (the prefix, the previous word,
                        // both candidate rows and the page indicator), so a redraw here
                        // re-samples more noise over the same pixels than a reveal page does.
                        EntryStep::Park => glass = Some(Flow::Entry),
                        // The whole point of the branch: a live key reaches the pure state
                        // machine, and the only impure halves — the grant and the wire — are
                        // `Session::entry_key`'s.
                        EntryStep::Key(key) => match session.entry_key(key, &mut outbox) {
                            // The key did nothing (an unadvertised byte, a page turn on a
                            // single page). DO NOT REDRAW: same reason as `Park`, and this is
                            // the leg that makes `Typed` a three-state enum rather than a
                            // `bool`.
                            Ok(Typed::Unchanged) => glass = Some(Flow::Entry),
                            // The state moved. One redraw per accepted keypress, and
                            // `show_entry_page` is the only thing that draws it.
                            Ok(Typed::Redraw) => {
                                if let Some(panel) = panel.as_mut() {
                                    glass = show_entry_page(&session, panel, &mut entropy)
                                        .then_some(Flow::Entry);
                                }
                            }
                            // Over: either 25 words checksummed and `entry_key` has already
                            // told the coordinator (the reply is in `outbox` and reaches the
                            // wire at the bottom of this iteration), or the human backed out
                            // of the share index. `idle` FIRST, so the prefix leaves the glass
                            // before anything else is decided — requirement 5 — and then any
                            // prompt the completion produced is parked over it. `prompts` is
                            // empty today; carrying it means a vendored bump that adds one
                            // cannot lose it silently.
                            Ok(Typed::Ended(prompts)) => {
                                if let Some(panel) = panel.as_mut() {
                                    idle(&session, panel);
                                    if let Some(next) =
                                        draw_batch(panel, &mut entropy, prompts, &mut glass)
                                    {
                                        parked = Some(next);
                                    }
                                }
                            }
                            // `Fault::Comms` on the completion frame, or `Fault::Store` from
                            // `run`'s persist. NOT a panic, for the loop's usual reason, and
                            // the refusal takes the words off the glass through `take_glass`.
                            // The typed share is not lost by this: `entry_key` has already
                            // parked it in the signer's RAM-only `tmp_loaded_backups`, so a
                            // `Consolidate` can still reach it.
                            Err(_fault) => refuse(panel.as_mut(), &mut glass),
                        },
                        // Two contacts, an unreadable scan, a pad that never opened, or the
                        // coordinator having cancelled underneath us. The words come off the
                        // glass and the cursor is already gone, so no further keystroke is
                        // delivered — `Session` keeps its `wordentry::Entry` and it is
                        // unreachable, exactly as an abandoned reveal's grant is.
                        EntryStep::End => {
                            if let Some(panel) = panel.as_mut() {
                                idle(&session, panel);
                            }
                        }
                    }
                }
                // THE CHECK QUIZ. Same shape as the entry and for the same reasons, with
                // one difference: the cancel guard applies to the QUESTION only. The
                // passed screen has no quiz behind it — the pass is what dropped it — so
                // gating it on `quiz_screen()` would blank "Quiz passed" on the very next
                // iteration, before a human could read it.
                Flow::Check(state) => {
                    let step = match state {
                        // The coordinator can take the grant away without drawing
                        // anything: `recv`'s `Cancel` arm drops the `quiz::Quiz` and
                        // returns no prompt, so without this the three candidates would
                        // sit lit on the panel until the next keypress. Requirement 6
                        // says a flow ends on a keypress or a coordinator message, and a
                        // `Cancel` is the second kind.
                        Check::Asking if session.quiz_screen().is_none() => CheckStep::Done,
                        _ => check_step(state, verdict),
                    };
                    match step {
                        // Nothing pressed. Same frame, NOT redrawn — three rows of this
                        // screen go through `mark_sensitive` and one of them holds a true
                        // word of the share, so a redraw re-samples the noise over the
                        // pixels that matter most.
                        CheckStep::Park => glass = Some(Flow::Check(state)),
                        // The whole point of the branch: a live key reaches the pure
                        // state machine, and the only impure halves — the grant and the
                        // wire — are `Session::quiz_key`'s. `1`/`2`/`3` are answers and
                        // `x` is the give-up; every other byte is `Checked::Unchanged`.
                        CheckStep::Key(key) => {
                            match session.quiz_key(key, &mut entropy, &mut outbox) {
                                // The key did nothing: a byte the footer does not
                                // advertise, which is nine of the pad's twelve. DO NOT
                                // REDRAW, same reason as `Park`. (A key on a quiz that is
                                // already over cannot reach here — `check_step` produces
                                // `Key` only from `Check::Asking`, and `quiz_key` answers
                                // a dropped quiz with `Err` rather than this.)
                                Ok(Checked::Unchanged) => glass = Some(Flow::Check(state)),
                                // The state moved — a correct answer advanced to the next
                                // question, or a WRONG one re-asked this one with three
                                // freshly drawn candidates and the "No - try again"
                                // banner. Both are one redraw and neither sends anything:
                                // there is no failure message in the protocol, no attempt
                                // counter and no lockout.
                                Ok(Checked::Redraw) => {
                                    if let Some(panel) = panel.as_mut() {
                                        glass = show_quiz(
                                            &session,
                                            session.quiz_screen(),
                                            panel,
                                            &mut entropy,
                                        )
                                        .map(Flow::Check);
                                    }
                                }
                                // Over. A PASS draws "n of 25 words matched" — the ack is
                                // already in `outbox` and reaches the wire at the bottom
                                // of this iteration — and holds the glass until a key or a
                                // coordinator prompt, because that screen's footer says
                                // `(x)done` and because it carries no word to leave lit.
                                // Giving up draws standby and sends NOTHING. Both legs
                                // redraw, so the candidates are off the glass either way,
                                // which is requirement 6.
                                Ok(Checked::Ended { checked }) => {
                                    if let Some(panel) = panel.as_mut() {
                                        match checked {
                                            Some(checked) => {
                                                glass = show_quiz(
                                                    &session,
                                                    Some(quiz::Screen::Passed { checked }),
                                                    panel,
                                                    &mut entropy,
                                                )
                                                .map(Flow::Check);
                                            }
                                            None => idle(&session, panel),
                                        }
                                    }
                                }
                                // No grant (the quiz ended underneath us), or the ack
                                // would not frame. NOT a panic, for the loop's usual
                                // reason, and the refusal takes the candidates off the
                                // glass through `take_glass`.
                                Err(_fault) => refuse(panel.as_mut(), &mut glass),
                            }
                        }
                        // Two contacts, an unreadable scan, a pad that never opened, the
                        // coordinator having cancelled underneath us, or any key on the
                        // passed screen. The candidates come off the glass and the cursor
                        // is already gone, so no further keystroke is delivered.
                        CheckStep::Done => {
                            if let Some(panel) = panel.as_mut() {
                                idle(&session, panel);
                            }
                        }
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
// 3. That the PROMPT cursor moves by **single forward steps** and that a re-park
//    always carries the new render's `last`. Both live in the `Answer::Next` arm
//    inside `boot`, which no gate compiles (PLAN.md §9 item 22). What stands in for a
//    test: `the_only_consent_call_passes_the_page_that_was_drawn` pins the call
//    shapes textually, `draw_prompt` returns `None` for a page past the end so an
//    over-advance draws `ui::refusal` instead of consenting, and `saturating_add`
//    means the increment cannot wrap under `overflow-checks = false`. The BACKUP
//    cursor used to be in the same position and is not any more: [`reveal_step`] is
//    a module item, so every step it takes is checked by VALUE below.
// 4. That an `Err` arm diverges. `hold` returns `!`, so the identity arms cannot
//    fall through to a device without an identity — a TYPE, not a test, and the
//    same for `boot`'s own `-> !`.
// 5. That **the words leave the glass when a reveal ends**. Control flow, then a
//    source pin: `show_backup_page` is the only caller of `Session::show_backup`
//    and the only producer of the reveal cursor, and both of its `None` legs draw
//    before returning — `idle` past the last page, `ui::refusal` on a fault. So
//    there is no ending that does not redraw, and
//    `every_exit_from_the_reveal_takes_the_words_off_the_glass` pins that the loop
//    has not grown one. The fourth ending is anything else that takes the glass —
//    a coordinator's next prompt, a refusal, an undisplayable prompt — and that is
//    `take_glass`, which drops the cursor in the same breath as the `panel.show`
//    that replaced the frame. The CONVERSE is the property that was broken: a live
//    cursor whose screen is gone. Both directions are now the same one function.
// 6. That **the prefix leaves the glass when an ENTRY ends**, which is item 5 for the
//    flow that ingests rather than reveals. Same two remedies and one bonus: control
//    flow (`show_entry_page` is the only producer of `Flow::Entry` and both of its
//    `false` legs draw first), a source pin
//    (`every_exit_from_the_entry_takes_the_words_off_the_glass`), and the fact that
//    `Flow` is ONE enum — so `take_glass`'s single drop statement ends a reveal and an
//    entry together and there is no second field to forget. What is NOT covered either
//    way: that `entry_frame`'s output is the frame that reaches the panel. The
//    delegation is checked pixel-for-pixel by
//    `the_entry_screens_are_the_ones_hal_draws`, and the `panel.show` beside it is a
//    counted source pin.
// 7. That a KEYSTROKE cannot buy a signature. This one is a TYPE and not a test:
//    `Consent::Entry` is a unit variant, so under it there is no `ui::ConfirmDigit` to
//    accept and no `DeviceToUserMessage` to hand `Session::confirm_at`, and `answer`
//    returns `Answer::Key` where the two consent variants return `Answer::Yes`. The
//    value-level halves — every byte is a keystroke under `Consent::Entry`, and no byte
//    is a keystroke under `Consent::Prompt` — are
//    `the_entry_screen_answers_every_byte_as_a_keystroke` and
//    `an_entry_key_cannot_answer_a_signing_or_revealing_screen`. It needs saying because
//    five of the twelve pad keys are in BOTH alphabets and no const-assert can separate
//    them, unlike the two paging keys.
//
// The `keypad::Event` match in `answer` is exhaustive with no `_` arm, so a new
// driver variant is `error[E0004]` here rather than a silent default. The guarded
// arms do not weaken that: `Ok(keypad::Event::Down(key))` still appears unguarded,
// and a new variant is covered by nothing. Same for the `Consent` match inside it and
// for `Answer` in `reveal_step` and `entry_step`: adding a screen or a verdict is a
// compile error in every router, which is how the fourth consent variant was added
// without any of them acquiring a silent default.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use coldsnap_firmware::quiz;
    use coldsnap_firmware::wordentry::Screen;
    use coldsnap_hal::keypad::{Event, KeypadError, DECODER, KEY_CANCEL, KEY_OK};
    use coldsnap_hal::ui::{
        ConfirmDigit, BACK_KEY, CONFIRM_CHARSET, ENTRY_DELETE_KEY, ENTRY_LETTER_KEYS, ENTRY_OK_KEY,
        ENTRY_PAGE_KEY, NEXT_KEY, QUIZ_KEYS,
    };
    use frostsnap_core::schnorr_fun::frost::{ShareImage, ShareIndex};
    use frostsnap_core::schnorr_fun::fun::Point;
    use std::boxed::Box;
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

    /// A prompt that reaches [`answer`]'s digit arm — since 2026-09-11 the ONLY arm
    /// [`Consent::Prompt`] has, and the one that must be exact.
    ///
    /// It has to be a variant like this one: `CheckKeyGen` and `SignatureRequest`
    /// both wrap a phase whose only constructor is a real coordinator, and
    /// `frostsnap_core/coordinator` is deliberately not in this test gate's
    /// feature set (it drags a C SQLite build — see `firmware/Cargo.toml`). That
    /// used to matter, because the keygen prompt had an arm of its own comparing a
    /// fixed constant, and it was the arm no test could reach. It has none now:
    /// `answer` does not bind the prompt under `Consent::Prompt` at all, so whatever
    /// variant this returns exercises the same three lines every prompt gets —
    /// which is what `the_keygen_prompt_is_answered_by_the_same_rule_as_every_other_prompt`
    /// pins as source.
    fn signing_shaped() -> DeviceToUserMessage {
        DeviceToUserMessage::FinalizeKeyGen {
            key_name: String::from("k"),
        }
    }

    /// The whole pipeline `boot` runs for one pad event on a backup screen: the
    /// screen's consent kind, the pad's verdict against it, and the step that
    /// follows.
    ///
    /// Spelled once so the tests below read as key-by-key claims rather than as three
    /// nested calls, and so they compose the SAME three functions in the same order
    /// `boot` does — which is the point of moving them out of it.
    fn step(state: Reveal, event: Result<Event, KeypadError>) -> RevealStep {
        let (consent, last) = reveal_consent(state);
        reveal_step(state, answer(event, consent, last), BACKUP_END)
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
        assert_eq!(
            drawn.as_str().as_bytes(),
            &[digit],
            "draw is not a bijection"
        );
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
                    answer(
                        Ok(Event::Down(*key)),
                        Consent::Prompt(&prompt, confirm),
                        LAST,
                    ) == Answer::Yes
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
    /// `hsm_ux.py:66` is `refused = (ch != confirm_char)`, so CANCEL and OK are
    /// refusals for exactly the same reason a wrong digit is. Treating only `x` as
    /// refusal is how this gets subtly wrong, and it fails OPEN.
    #[test]
    fn cancel_and_ok_are_both_refusals() {
        let prompt = signing_shaped();
        for rendered in CONFIRM_CHARSET {
            let confirm = digit(rendered);
            for key in [KEY_CANCEL, KEY_OK] {
                assert_eq!(
                    answer(
                        Ok(Event::Down(key)),
                        Consent::Prompt(&prompt, confirm),
                        LAST
                    ),
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
                    answer(
                        Ok(Event::Down(**key)),
                        Consent::Prompt(&prompt, confirm),
                        LAST,
                    ) == Answer::Yes
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
            answer(
                Ok(Event::MultiKey),
                Consent::Prompt(&prompt, digit(b'4')),
                LAST
            ),
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
                answer(Err(error), Consent::Prompt(&prompt, digit(b'4')), LAST),
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
            ask(None, &mut rng, Consent::Prompt(&prompt, digit(b'4')), LAST),
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
                answer(Ok(event), Consent::Prompt(&prompt, digit(b'4')), LAST),
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
                        Consent::Prompt(&prompt, digit(rendered)),
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

    /// **THE ANTI-MITM SCREEN HAS NO SPECIAL KEY.** `answer` under
    /// `Consent::Prompt` does not look at the prompt at all.
    ///
    /// This test replaces `the_keygen_match_key_is_the_legend_and_is_on_the_pad`,
    /// which asserted `KEYGEN_MATCH_KEY == b'1'` and that `1` was on the pad. That
    /// constant is gone: `ui::keygen_check` printed a fixed `1=match x=no` until
    /// 2026-09-11, so a hardcoded script could clear the ONE screen whose entire
    /// purpose is that a human read four bytes off it and compared them aloud.
    ///
    /// Source-pinned rather than driven, and for the same reason the old test was:
    /// the keygen arm cannot be reached from a test (a `CheckKeyGen` carries a
    /// `KeyGenPhase3` whose only constructor is a real coordinator, and
    /// `frostsnap_core/coordinator` is deliberately out of this gate's feature set).
    /// The same device is driven end to end by `hostcheck` over a pty, where
    /// `COLDSNAP_GLASS_KEYS=1yy` — a script pressing a literal `1` at the keygen
    /// check — fails with no source mutation at all. What a test CAN do is refuse to
    /// let the special case come back, which is what this is.
    #[test]
    fn the_keygen_prompt_is_answered_by_the_same_rule_as_every_other_prompt() {
        let src = production_source();
        // `_`, not a binding, is the whole assertion: a per-screen key needs the
        // prompt, and this arm does not have it. Behaviour is covered by
        // `only_the_rendered_digit_confirms`, which drives this very arm over all 256
        // bytes; what a behavioural test cannot see is a `CheckKeyGen` special case
        // added back for a variant no test can construct.
        assert!(
            src.contains("Consent::Prompt(_, confirm) => {"),
            "the prompt arm must not bind the prompt: a `match prompt` here is how a \
             per-screen key gets back in, and the keygen check is the screen it got in on"
        );
        // The constant itself, by definition site. One that nothing reads would be
        // harmless; one that something reads is this defect returning.
        assert!(
            !src.contains("const KEYGEN_MATCH_KEY"),
            "the fixed keygen key is back; ui::keygen_check prints a ConfirmDigit"
        );
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
                    answer(
                        Ok(Event::Down(*key)),
                        Consent::Prompt(&prompt, confirm),
                        false,
                    ) == Answer::Yes
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
                answer(
                    Ok(Event::Down(rendered)),
                    Consent::Prompt(&prompt, confirm),
                    LAST
                ),
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
            answer(
                Ok(Event::Down(NEXT_KEY)),
                Consent::Prompt(&prompt, confirm),
                false
            ),
            Answer::Next,
            "a page with more to read must be advanceable"
        );
        assert_eq!(
            answer(
                Ok(Event::Down(NEXT_KEY)),
                Consent::Prompt(&prompt, confirm),
                LAST
            ),
            Answer::Wait,
            "the last page has nowhere to advance to"
        );
        // Never a confirmation, on either page. `hal`'s own const assert beside
        // `CONFIRM_CHARSET` is the build-time half of the same claim, and since
        // 2026-09-11 it is the WHOLE claim: this line was followed by
        // `assert_ne!(NEXT_KEY, KEYGEN_MATCH_KEY)` while the keygen check accepted a
        // fixed `b'1'` outside the charset. There is no such key any more.
        assert!(!CONFIRM_CHARSET.contains(&NEXT_KEY));
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
                    Consent::Prompt(&prompt, digit(b'4')),
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
            answer(Ok(Event::Down(BACK_KEY)), Consent::Pages, false),
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
            let got = answer(Ok(Event::Down(key)), Consent::Pages, false);
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
            assert_eq!(
                answer(Ok(event), Consent::Pages, false),
                Answer::Wait,
                "{event:?}"
            );
        }
        assert_eq!(
            answer(Ok(Event::MultiKey), Consent::Pages, false),
            Answer::No
        );
        for error in [
            KeypadError::NotOnThisTarget,
            KeypadError::ColumnsStuckLow { idr: 0 },
        ] {
            assert_eq!(
                answer(Err(error), Consent::Pages, false),
                Answer::No,
                "{error:?}"
            );
        }
        // Not vacuous: the digit a consent screen WOULD have accepted is dead here.
        assert!(CONFIRM_CHARSET
            .iter()
            .all(|d| answer(Ok(Event::Down(*d)), Consent::Pages, false) == Answer::No));
        // And with `last` TRUE — a combination `boot` never produces, since the
        // reveal always passes `false` — nothing confirms either. This is the only
        // exercise the `consent: None` arm of the digit match gets, and without it a
        // mutation making that arm `Answer::Yes` would leave the suite green.
        assert_eq!(
            answer(Ok(Event::Down(NEXT_KEY)), Consent::Pages, true),
            Answer::Wait,
            "the advance key clamps on a last page, as everywhere else"
        );
        for key in 0..=u8::MAX {
            if key == NEXT_KEY || key == BACK_KEY {
                continue;
            }
            assert_eq!(
                answer(Ok(Event::Down(key)), Consent::Pages, true),
                Answer::No,
                "key {:?} confirmed a screen that printed no digit",
                key as char
            );
        }
    }

    /// **The recorded question answers its own digit and nothing else** — in
    /// particular not either paging key, which are the two bytes a human has been
    /// pressing for eight pages to reach it.
    ///
    /// The stakes are not a secret on the glass (the words are gone by then) but a
    /// CLAIM: `Answer::Yes` here sends `CommsMisc::BackupRecorded`, on which the app
    /// closes its dialog and shows the wallet as backed up. A yes a user did not mean
    /// is a wallet they believe is recoverable and is not.
    ///
    /// MUTATION-VERIFY. Make `Consent::Question`'s arm `Answer::Yes` unconditionally
    /// and the first loop fails on 255 keys. Route `ui::BACK_KEY` to `Answer::Back`
    /// for every consent kind — drop the `matches!(consent, Consent::Pages)` guard on
    /// that arm — and the `BACK_KEY` assertion below fails, because dismissing the
    /// question and claiming a backup would be the same press away.
    #[test]
    fn the_recorded_question_answers_only_the_digit_it_printed() {
        for rendered in CONFIRM_CHARSET {
            let confirm = digit(rendered);
            for key in 0..=u8::MAX {
                let got = answer(Ok(Event::Down(key)), Consent::Question(confirm), LAST);
                let want = if key == rendered {
                    Answer::Yes
                } else if key == NEXT_KEY {
                    // Clamped, like every other last page: an over-press of the key
                    // that walked the human here leaves the question up.
                    Answer::Wait
                } else {
                    Answer::No
                };
                assert_eq!(
                    got, want,
                    "key {:?} on a recorded question printing {:?}",
                    key as char, rendered as char
                );
            }
            // Named, because these two are the near misses: `7` is the key the page
            // before this one advertised, and `x` is the refusal.
            assert_eq!(
                answer(Ok(Event::Down(BACK_KEY)), Consent::Question(confirm), LAST),
                Answer::No,
                "the back key dismissed the recorded question as an answer to it"
            );
            assert_eq!(
                answer(Ok(Event::Down(b'x')), Consent::Question(confirm), LAST),
                Answer::No
            );
            // Nothing pressed keeps the question up — there is NO TIMEOUT on it, by
            // choice: a question that expired would leave a human who wrote 25 words
            // down unable to say so, and the only way to say so again is a second full
            // disclosure of the same share.
            for event in [Event::AllUp, Event::Unsettled] {
                assert_eq!(
                    answer(Ok(event), Consent::Question(confirm), LAST),
                    Answer::Wait,
                    "{event:?}"
                );
            }
            // And a pad that cannot be read never claims a backup exists.
            assert_eq!(
                answer(Ok(Event::MultiKey), Consent::Question(confirm), LAST),
                Answer::No
            );
            assert_eq!(
                answer(
                    Err(KeypadError::ColumnsStuckLow { idr: 0 }),
                    Consent::Question(confirm),
                    LAST
                ),
                Answer::No
            );
            assert_eq!(
                ask(None, &mut Counter(0), Consent::Question(confirm), LAST),
                Answer::No,
                "a missing pad claimed a backup was written down"
            );
            // A page that is not the last of its set prints no digit, so nothing on it
            // may answer — the same rule as every other screen. Unreachable for this
            // one (`boot` passes `last: true`, the whole question fits one page) and a
            // refusal if it ever is reached.
            assert_eq!(
                answer(Ok(Event::Down(rendered)), Consent::Question(confirm), false),
                Answer::No,
                "a non-last page confirmed the digit"
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
        // A real BIP39 word, repeated: the page COUNT is what is under test, and
        // `BackupPages::new` only cares that each word has the shape it can draw.
        let words = ["abandon"; ui::BACKUP_WORDS];
        let pages = ui::BackupPages::new(1, &words).expect("a 25-word list must render");
        assert_eq!(
            pages.len(),
            BACKUP_END,
            "the page count is not what the reveal assumes"
        );
        assert!(
            pages.page(BACKUP_END).is_none(),
            "the end index still draws a page"
        );
        assert!(
            pages.page(BACKUP_END - 1).is_some(),
            "the end index is one page too early, so a word is never shown"
        );
        // One step at a time, in each direction, and neither can wrap — checked at
        // the extreme a release build would hide, since `overflow-checks = false`
        // makes `usize::MAX + 1` equal 0, i.e. page 0 of the same share.
        assert_eq!(
            reveal_step(Reveal::Page(usize::MAX), Answer::Next, BACKUP_END),
            RevealStep::Show(usize::MAX),
            "the reveal's advance wrapped instead of saturating"
        );
        assert_eq!(
            reveal_step(Reveal::Page(0), Answer::Back, BACKUP_END),
            RevealStep::Show(0),
            "page 0's back-press must clamp to a redraw of page 0, not wrap to the end"
        );
    }

    /// **The cursor names the page that was DRAWN**, and the recorded question is drawn
    /// with the digit the cursor will accept.
    ///
    /// This is the pairing that lived inside `boot` until 2026-09-11, where no gate in
    /// this project could execute it. The mutation it exists for was RUN and passed
    /// EVERYTHING: `Some(Reveal::Page(page))` → `Some(Reveal::Page(page.saturating_add(1)))`
    /// left firmware tests, hal tests, both device clippy profiles, `cargo build --release`
    /// at 0 warnings, `tools/pixel-check.py` PASS all 7 and the `hostcheck` harness at
    /// exit 0 — while showing a human pages 0, 2, 4, 6 and then asking "Wrote down all 25
    /// words?" over **12 words never drawn**. See [`reveal_draw`].
    ///
    /// Walked over EVERY page rather than one, and one past the end, because the defect is
    /// an off-by-one and a single sample at page 0 would pass under `page * 1` or
    /// `page.saturating_sub(0)`.
    ///
    /// MUTATION-VERIFY: any arithmetic on `page` in [`reveal_draw`]'s `Ok(true)` arm fails
    /// the first half. Handing `Reveal::Recorded` a second digit — the shape that lets a
    /// screen show one key and accept another — fails the second.
    #[test]
    fn the_reveal_cursor_names_the_page_that_was_drawn() {
        // Two DIFFERENT digits, through the real `draw`, so "the same digit" below is a
        // comparison and not a tautology over one value.
        let a = digit(CONFIRM_CHARSET[0]);
        let b = digit(CONFIRM_CHARSET[1]);
        assert_ne!(a.as_str(), b.as_str(), "the two fixtures must differ");

        for page in 0..=BACKUP_END {
            assert_eq!(
                reveal_draw(page, Ok(true), false, a),
                (RevealScreen::Page, Some(Reveal::Page(page))),
                "page {page}: the cursor must name the page that was drawn"
            );
            // `record_pending` is irrelevant while pages remain: the question is armed
            // by the library on the ENDING leg only, so a `true` here must not divert a
            // page that rendered.
            assert_eq!(
                reveal_draw(page, Ok(true), true, a),
                (RevealScreen::Page, Some(Reveal::Page(page))),
                "page {page}: a rendered page must not be diverted by record_pending"
            );
        }

        // The ending, with the question armed: ONE digit, on the screen and in the gate.
        assert_eq!(
            reveal_draw(BACKUP_END, Ok(false), true, a),
            (RevealScreen::Recorded(a), Some(Reveal::Recorded(a))),
            "the recorded screen and the recorded cursor must carry the SAME digit"
        );
        assert_eq!(
            reveal_draw(BACKUP_END, Ok(false), true, b),
            (RevealScreen::Recorded(b), Some(Reveal::Recorded(b))),
            "the digit must come from the argument, not from a second draw"
        );

        // The two endings that park NOTHING. Both must hand back `None`, because the
        // caller stops delivering keypresses on exactly that value — a `Some` here is a
        // live gate behind a screen that is gone.
        assert_eq!(
            reveal_draw(BACKUP_END, Ok(false), false, a),
            (RevealScreen::Idle, None),
            "an ending with nothing to ack must not park a cursor"
        );
        for page in [0usize, 3, BACKUP_END, usize::MAX] {
            assert_eq!(
                reveal_draw(page, Err(()), true, a),
                (RevealScreen::Refuse, None),
                "page {page}: a fault must refuse and park nothing, whatever record_pending says"
            );
        }
    }

    /// **A share on the glass is paged with no digit**, and the recorded question is
    /// the only backup screen that carries one.
    ///
    /// This used to be a source pin on a literal inside `boot`. It is the pairing that
    /// makes [`Answer::Yes`] unreachable while a word is lit — `answer` has nothing to
    /// say yes *with* under [`Consent::Pages`] — so it is worth a checked value.
    #[test]
    fn a_share_on_the_glass_is_paged_with_no_digit() {
        for page in [0usize, 3, BACKUP_END] {
            let (consent, last) = reveal_consent(Reveal::Page(page));
            assert!(
                matches!(consent, Consent::Pages),
                "page {page} of a share was offered a digit"
            );
            assert!(
                !last,
                "a backup page always has somewhere to go: `9` past the last one is \
                 what ENDS the flow"
            );
        }
        let (consent, last) = reveal_consent(Reveal::Recorded(digit(b'4')));
        assert!(
            matches!(consent, Consent::Question(_)),
            "the recorded question must be answerable, or a human who wrote 25 words \
             down can never say so"
        );
        assert!(
            last,
            "the whole question is on one page, so that page must be able to accept \
             the digit it printed"
        );
        // And the funnel `boot` actually calls delegates to this function unchanged, so
        // the pairing checked above is the pairing the device uses. Checked by value
        // rather than by the source pin in
        // `the_only_consent_call_passes_the_page_that_was_drawn`, because a `Consent`
        // handed to the wrong screen is what makes `Answer::Yes` reachable over a share.
        for state in [
            Reveal::Page(0),
            Reveal::Page(3),
            Reveal::Recorded(digit(b'2')),
        ] {
            let (mine, my_last) = flow_consent(Flow::Reveal(state));
            let (theirs, their_last) = reveal_consent(state);
            assert_eq!(my_last, their_last, "{state:?}");
            assert_eq!(
                core::mem::discriminant(&mine),
                core::mem::discriminant(&theirs),
                "`flow_consent` gave {state:?} a different screen's consent"
            );
        }
    }

    /// **Every key on a backup page pages or ends the flow, and none of them acks.**
    ///
    /// The full pipeline `boot` runs — [`reveal_consent`], [`answer`], [`reveal_step`]
    /// — over every byte the pad's `Down` can carry, at four page numbers including
    /// the one `overflow-checks = false` would wrap. Before [`reveal_step`] existed,
    /// all of this lived in `boot` and was checked by matching strings in this file.
    ///
    /// The `Ack` assertion is the one with teeth: a key pressed while word 13 is on
    /// the glass must not be able to tell the coordinator the backup is on paper,
    /// because nothing has asked yet.
    #[test]
    fn every_key_on_a_backup_page_pages_or_ends_and_never_acks() {
        for page in [0usize, 1, BACKUP_END - 1, usize::MAX] {
            let state = Reveal::Page(page);
            let (consent, last) = reveal_consent(state);
            for key in 0..=u8::MAX {
                let step = step(state, Ok(Event::Down(key)));
                let want = if key == NEXT_KEY {
                    RevealStep::Show(page.saturating_add(1))
                } else if key == BACK_KEY {
                    RevealStep::Show(page.saturating_sub(1))
                } else {
                    // Harsh on purpose: an unadvertised key ends the flow rather than
                    // leaving a share lit after whoever pressed it walked away.
                    RevealStep::Show(BACKUP_END)
                };
                assert_eq!(step, want, "key {:?} on page {page}", key as char);
                assert_ne!(
                    step,
                    RevealStep::Ack,
                    "key {:?} claimed a backup was written down while word rows were \
                     still on the glass",
                    key as char
                );
            }
            // Nothing pressed keeps the page up, undrawn. NO TIMEOUT: this is the only
            // thing that happens for as long as a human takes to copy 25 words.
            for event in [Event::AllUp, Event::Unsettled] {
                assert_eq!(step(state, Ok(event)), RevealStep::Park, "{event:?}");
            }
            // Two contacts, an unreadable scan and a pad that never opened all end the
            // flow — fail-closed in the direction that takes the words off the glass.
            for verdict in [
                step(state, Ok(Event::MultiKey)),
                step(state, Err(KeypadError::ColumnsStuckLow { idr: 0 })),
                reveal_step(state, ask(None, &mut Counter(0), consent, last), BACKUP_END),
            ] {
                assert_eq!(
                    verdict,
                    RevealStep::Show(BACKUP_END),
                    "a pad that cannot be read left a share on the glass"
                );
            }
        }
    }

    /// **The recorded question acks on the digit it printed and on nothing else** —
    /// in particular not on either paging key, which are the two bytes a human has
    /// been pressing for eight pages to reach it.
    ///
    /// `CommsMisc::BackupRecorded` is a claim that 25 words exist on paper; the app
    /// closes its dialog and presents the wallet as backed up on it
    /// (`display_backup.rs:87-93`), so a yes a user did not mean is a wallet they
    /// believe is recoverable and is not.
    #[test]
    fn the_recorded_question_acks_only_on_the_digit_it_printed() {
        for rendered in CONFIRM_CHARSET {
            let state = Reveal::Recorded(digit(rendered));
            let (consent, last) = reveal_consent(state);
            let acked: Vec<u8> = (0..=u8::MAX)
                .filter(|key| step(state, Ok(Event::Down(*key))) == RevealStep::Ack)
                .collect();
            assert_eq!(
                acked,
                std::vec![rendered],
                "the question printed {:?}; these keys acked it",
                rendered as char
            );
            // The near misses. `9` is the key that walked the human here, so an
            // over-press must leave the question up rather than dismissing it; `7` is
            // the key the page before advertised and is not an answer to this one.
            assert_eq!(
                step(state, Ok(Event::Down(NEXT_KEY))),
                RevealStep::Park,
                "an over-press of the advance key dismissed the question"
            );
            assert_eq!(
                step(state, Ok(Event::Down(BACK_KEY))),
                RevealStep::Idle,
                "the back key answered a question that never offered it"
            );
            // Nothing pressed keeps the question up. NO TIMEOUT here either, by
            // choice: a question that expired would leave a human who wrote 25 words
            // down unable to say so, and the only way to say so again is a second full
            // disclosure of the same share.
            for event in [Event::AllUp, Event::Unsettled] {
                assert_eq!(step(state, Ok(event)), RevealStep::Park, "{event:?}");
            }
            // And a pad that cannot be read never claims a backup exists on paper.
            for verdict in [
                step(state, Ok(Event::MultiKey)),
                step(state, Err(KeypadError::NotOnThisTarget)),
                reveal_step(state, ask(None, &mut Counter(0), consent, last), BACKUP_END),
            ] {
                assert_eq!(
                    verdict,
                    RevealStep::Idle,
                    "a pad that could not be read acked a backup"
                );
            }
        }
    }

    /// **Only a `DisplayBackup` prompt buys permission to draw 25 plain words, only an
    /// `EnterBackup` prompt buys permission to type one in, and a `CheckBackup` prompt
    /// buys a QUIZ and never either of the other two.**
    ///
    /// The flag used to be `matches!(prompt, Restoration(_))`, i.e. the whole family —
    /// four variants of which are not reveals, and one of which (`CheckBackup`) is a
    /// QUIZ that shows one true word among three. A family-wide `true` answers a quiz
    /// request with a full disclosure. That is no longer a hypothetical: `CheckBackup` is
    /// admitted by `Session::recv` now and is on the `Some` side of this match, so
    /// [`grants`] is the arm standing between "a quiz was requested" and "all 25 words
    /// were drawn". It is the mutation to try first.
    ///
    /// The `Option<Grant>` is what makes the three grants EXCLUSIVE: three booleans over
    /// the same five variants can all be true, and "reveal" plus "enter" at once is 25
    /// plain words drawn over a screen that asked to type them in.
    #[test]
    fn only_a_display_backup_prompt_grants_a_reveal() {
        assert!(
            grants(&signing_shaped()).is_none(),
            "a keygen prompt granted a backup flow"
        );
        // A real `Restoration` prompt that grants NOTHING. `BackupSaved` is the one of
        // the three this test can build — the other two carry phases whose only
        // constructor is a coordinator — and it is enough to show the FAMILY is not the
        // gate, because the old `matches!` said yes to exactly this value.
        let saved = DeviceToUserMessage::Restoration(Box::new(ToUserRestoration::BackupSaved {
            share_image: ShareImage {
                index: ShareIndex::one(),
                image: Point::zero(),
            },
            key_name: None,
            purpose: None,
            threshold: None,
        }));
        assert!(
            grants(&saved).is_none(),
            "a restoration reply granted a reveal of the whole share"
        );
        // Both `Some` cases need a phase, which needs a `SharedKey` or an
        // `EnterPhysicalId` off a coordinator — so they are pinned as source. Losing
        // either fails in the other direction and is just as silent: a device that
        // consents to a reveal and then draws nothing, or one that consents to an
        // ingest and then refuses every key.
        let src = production_source();
        assert!(
            src.contains("ToUserRestoration::DisplayBackup { .. } => Some(Grant::Reveal),"),
            "the one variant that grants a reveal must be named, and be the only one"
        );
        assert!(
            src.contains("ToUserRestoration::EnterBackup { .. } => Some(Grant::Entry),"),
            "the one variant that grants an ingest must be named, and be the only one"
        );
        // THE ARM THAT MATTERS MOST. `CheckBackup` grants a QUIZ, and the value it
        // grants is spelled here so that the copy-paste — `Some(Grant::Reveal)`, one
        // token away — cannot pass. That mutation answers a request for one word of
        // three with all 25 in plain, on a consent screen that said "check".
        assert!(
            src.contains("ToUserRestoration::CheckBackup { .. } => Some(Grant::Check),"),
            "the quiz must grant a quiz, and must be named so it cannot grant a reveal"
        );
        assert!(
            src.contains(
                "ToUserRestoration::BackupSaved { .. } | ToUserRestoration::ConsolidateBackup(_) => None,"
            ),
            "the reply and the consolidation must grant no flow at all"
        );
        // The three grants are different values, so no arm can accidentally hand a
        // reveal's screen to an entry or to a quiz.
        assert_ne!(Grant::Reveal, Grant::Entry);
        assert_ne!(Grant::Reveal, Grant::Check);
        assert_ne!(Grant::Entry, Grant::Check);
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
        // TWO calls to the drawing function — the start and every step, because
        // `reveal_step` folded forward, back and stop into one `RevealStep::Show` —
        // and four assignments to the cursor: those two, the `Park` re-park, and the
        // one drop inside `take_glass`. So every assignment either came from a
        // function that redrew, or is the re-park of a frame that is still up, or is
        // the drop that sits beside a `panel.show`. There is no fourth shape. (The
        // definition is generic, so `show_backup_page<F..>(` is not one of the two.)
        assert_eq!(
            src.matches("show_backup_page(").count(),
            2,
            "two call sites: the start, and every step of the flow"
        );
        // THIRTEEN assignments to the one cursor, and every one of them is either the
        // result of a function that redrew, the re-park of a frame that is still up, or
        // the drop that sits beside a `panel.show`. There is no fourth shape: two
        // `show_backup_page` results, two `show_entry_page` results, three `show_quiz`
        // results (the grant, a redraw, the passed screen), five re-parks (a reveal page,
        // an entry that saw nothing pressed, an entry whose key did nothing, a quiz that
        // saw nothing pressed, a quiz whose key did nothing) and the `take_glass` drop.
        assert_eq!(
            src.matches("glass =").count(),
            13,
            "seven redraw results, five re-parks, one `take_glass` drop"
        );
        // THE FAIL-OPEN THIS CLOSED. The cursor is dropped in exactly one place, and
        // that place is `take_glass`, one line above the `panel.show` that replaces
        // the frame it described. A drop anywhere else is a gate with no screen; a
        // `panel.show` anywhere else is a screen with a live gate behind it, which is
        // how a refusal drawn over the "wrote it down?" question left its digit
        // answerable.
        //
        // `Flow` being ONE enum is what extends that to the entry for free: this single
        // statement ends a reveal and an entry alike, so there is no second field for a
        // future edit to forget.
        assert_eq!(
            src.matches("*glass = None").count(),
            1,
            "one cursor drop in the image, and it is inside `take_glass`"
        );
        assert!(
            src.contains("fn take_glass(panel: &mut display::Panel, frame: &ui::Frame, glass: &mut Option<Flow>) {\n        *glass = None;\n        let _ = panel.show(frame.as_bytes());"),
            "the drop and the redraw must be the same two lines, in that order"
        );
        assert_eq!(
            src.matches("panel.show(").count(),
            10,
            "ten places put pixels on the glass: `hold`, `take_glass`, `idle`, \
             `show_backup_page`'s three legs, `show_entry_page`'s two and `show_quiz`'s \
             two. An eleventh must say what it does to the flow cursor"
        );
        // Both callers of `take_glass` are the ones that used to draw for themselves:
        // a prompt's own screen (or `ui::refusal` for one it cannot draw) and the
        // refusal a policy `Fault` earns.
        assert_eq!(
            src.matches("take_glass(panel, &frame, glass)").count(),
            2,
            "`draw_prompt` and `refuse` are the two things that take the glass"
        );
        assert!(
            src.contains("glass = Some(Flow::Reveal(state))"),
            "`RevealStep::Park` must re-park the SAME state — the same page, and on \
             the recorded question the same digit — without redrawing it"
        );
        // The third leg, for completeness: a page that DID render reaches the panel.
        // MEASURED — deleting this `show` leaves every other test in this file green,
        // because it lives in `boot`: the device would consent to a reveal and then
        // draw nothing, which is the exact bug this change repaired. The direction is
        // safe (fewer pixels, never more), so it is pinned here rather than argued
        // about.
        assert!(
            src.contains(
                "RevealScreen::Page => {\n                let _ = panel.show(frame.as_bytes());"
            ),
            "a rendered backup page must reach the panel"
        );
        // AND THE CURSOR IS NOT REBUILT AT THE CALL SITE. `show_backup_page` forwards
        // [`reveal_draw`]'s `next` verbatim; the moment it constructs a `Reveal` of its
        // own, the page arithmetic is back inside `boot` where no gate executes it and
        // `the_reveal_cursor_names_the_page_that_was_drawn` stops covering it.
        //
        // Scoped to that function's TEXT rather than counted over the image, because the
        // value test below writes the same constructors and a count would be inflated by
        // the test that exists to make the count unnecessary. `RevealScreen::` does not
        // match `Reveal::` — the next character after `Reveal` is `S` — so the body may
        // still name the screen it draws.
        let show_backup_page_body = src
            .split_once("fn show_backup_page")
            .expect("`show_backup_page` is in the image")
            .1
            .split_once("\n    /// ")
            .expect("a doc comment follows it")
            .0;
        assert!(
            !show_backup_page_body.contains("Reveal::"),
            "`show_backup_page` must FORWARD `reveal_draw`'s cursor and never build one; \
             its body is:\n{show_backup_page_body}"
        );
        // And the two pairings themselves, spelled out, so a reordering that put the
        // arithmetic back is a failing test and not a review question. `Ok(true) =>` and
        // `Ok(false) if record_pending =>` are unique to `reveal_draw`.
        assert!(
            src.contains("Ok(true) => (RevealScreen::Page, Some(Reveal::Page(page))),"),
            "the drawn page and the parked cursor must be the SAME `page`"
        );
        assert!(
            src.contains(
                "Ok(false) if record_pending => (\n            RevealScreen::Recorded(confirm),\n            Some(Reveal::Recorded(confirm)),\n        ),"
            ),
            "the recorded screen and the recorded cursor must carry the SAME digit"
        );
        // And the ending is `idle`, drawn from one place, shared with standby.
        assert_eq!(
            src.matches("idle(session, panel)").count(),
            3,
            "one screen ends a reveal and the same one ends an entry or a quiz whose \
             grant went away; `show_backup_page`, `show_entry_page` and `show_quiz` draw \
             it"
        );
        assert_eq!(
            src.matches("idle(&session, panel)").count(),
            7,
            "step 8c, both answers to the recorded question, both endings of an entry \
             and both endings of a quiz that is not a pass draw the same screen; a \
             second definition of it would drift"
        );
    }

    /// **The recorded ack is sent from exactly one place, behind the digit that
    /// screen printed** — and never from the reveal, the consent, or a page turn.
    ///
    /// `CommsMisc::BackupRecorded` is a claim that 25 words exist on paper; the app
    /// closes its dialog and presents the wallet as backed up on it
    /// (`display_backup.rs:87-93`), so a user who gets a false one has no backup in
    /// precisely the situation the backup existed for. `Session::backup_recorded`
    /// carries the library-side gate (`record_pending`, host-tested in
    /// `firmware/src/lib.rs`); this carries the half that lives in `boot`, where no
    /// gate in this tree compiles a line.
    #[test]
    fn the_recorded_ack_is_sent_from_one_place_and_only_on_the_digit() {
        let src = production_source();
        assert_eq!(
            src.matches("session.backup_recorded(").count(),
            1,
            "one ack site, or the claim can be made from a screen that did not ask"
        );
        assert!(
            src.contains(
                "RevealStep::Ack => {\n                        let _ = session.backup_recorded("
            ),
            "the ack must sit directly behind `RevealStep::Ack` and nothing else"
        );
        // And `RevealStep::Ack` can only have come from the digit — which is
        // `the_recorded_question_acks_only_on_the_digit_it_printed`, by value, over
        // every byte the pad can carry. `Consent::Question` carries no prompt, so
        // there is nothing for `confirm_at` to be handed even by mistake.
        assert!(
            src.contains("Reveal::Recorded(confirm) => (Consent::Question(confirm), true),"),
            "the recorded question must be answered as a device question, with a digit"
        );
        assert_eq!(
            src.matches("Consent::Question(").count(),
            2,
            "two mentions and no more: `reveal_consent` builds it and `answer` reads \
             it. A third is a second screen asking a question of its own, and it has \
             to say what a yes to it buys"
        );
        // The screen and the gate must be the SAME digit. `show_backup_page` draws it
        // and hands it back in `Reveal::Recorded`; a second `draw` anywhere in the
        // recorded path would mean the glass and the gate disagreed.
        assert_eq!(
            src.matches("ui::ConfirmDigit::draw(").count(),
            2,
            "one draw per screen that prints a digit: `draw_batch` and the recorded \
             question"
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
                && src.contains("let consent = Consent::Prompt(&prompt, confirm);"),
            "the gate must be told which page the frame showed, and with which digit"
        );
        // The two device-driven flows read the pad with NO digit and NO prompt, which
        // is what makes `Answer::Yes` unreachable while a share is on the glass — being
        // read out or being typed in. Both pairings are checked by value in
        // `a_share_on_the_glass_is_paged_with_no_digit` and
        // `the_entry_screen_answers_every_byte_as_a_keystroke`; what is pinned here is
        // that `boot` gets the pair from `flow_consent` rather than writing its own, so
        // the tested function is the one on the device.
        assert!(
            src.contains("let (consent, last) = flow_consent(flow);"),
            "the backup screens must take their consent kind from `flow_consent`"
        );
        assert!(
            src.contains("Flow::Reveal(state) => reveal_consent(state),"),
            "`flow_consent` must delegate the reveal to the function its own tests drive"
        );
        assert_eq!(
            src.matches("Consent::Pages,").count(),
            1,
            "one screen in this image is paged with no digit at all"
        );
        assert_eq!(
            src.matches("(Consent::Entry, true)").count(),
            1,
            "one screen in this image answers keystrokes, and it carries no digit either"
        );
        // And the quiz's two screens are the second pairing that answers keystrokes with
        // no digit — the one where the overlap is total, because all three of
        // `ui::QUIZ_KEYS` are `ui::CONFIRM_CHARSET` members.
        assert_eq!(
            src.matches("Flow::Check(_) => (Consent::Quiz, true),")
                .count(),
            1,
            "the quiz screens must be answered as a quiz, with no digit and no prompt"
        );
        // And the two flows start from that same `Ok` and from nowhere else — each
        // behind the one prompt VARIANT whose consent grants it. Every half is pinned
        // because losing any of them is silent: without the call the grant is a
        // constant, and a constant `None` is a device that consents to a reveal, or to
        // an ingest, and then draws nothing — which is exactly the state the reveal was
        // repaired from.
        assert!(
            src.contains("let grant = grants(&prompt);"),
            "the grant must be read off the prompt that was answered"
        );
        assert!(
            src.contains("match grant {") && src.contains("Some(Grant::Reveal) => {"),
            "the reveal must start behind that grant"
        );
        assert!(
            src.contains("Some(Grant::Entry) => {"),
            "the entry must start behind that grant, and not behind a library fact: \
             `session.entry_screen().is_some()` here would resurrect an abandoned entry \
             on the next unrelated consent"
        );
        assert!(
            src.contains("Some(Grant::Check) => {"),
            "the quiz must start behind that grant, for the entry's reason: a quiz grant \
             read out of the library would resurrect an abandoned quiz — three candidates \
             of a share the coordinator has stopped asking about — on the next unrelated \
             consent"
        );
        // And the reveal starts at page 0, which is the SHARE INDEX page. Starting at 1
        // would show every word and never the index, and a backup written down without
        // its index is unrestorable — a silent way to hand out 25 useless words. The
        // entry starts on the share-index page too, which is `wordentry`'s own
        // `Stage::Index` and needs no argument here.
        assert!(
            src.contains("show_backup_page(&mut session, 0, panel, &mut entropy)"),
            "a reveal must begin on the share-index page"
        );
        // AND THE STEP CALL PASSES THE CURSOR UNCHANGED. This is the second of the two
        // call sites the count above pins, and it was the ONE PLACE the whole
        // `reveal_draw` hoist did not cover — found by adversarial review, 2026-09-12,
        // and MEASURED before it was closed: `show_backup_page(&mut session,
        // page.saturating_add(1), ..)` left firmware tests, BOTH device clippy profiles
        // and `cargo build --release` at 0 warnings all green, because `reveal_draw` is
        // then handed page+1 and pairs it CONSISTENTLY with the cursor — its value test
        // sees nothing wrong, and neither does the body pin, which only says
        // `show_backup_page` does not BUILD a `Reveal`.
        //
        // The symptom is the original defect exactly: drawn pages become 1, 3, 5, 7, so a
        // human is shown 16 of 25 words and then asked "Wrote down all 25 words?" over
        // the 12 that were never on the glass, and `CommsMisc::BackupRecorded` tells the
        // coordinator the backup was taken.
        //
        // Pinned textually because that is all that is available: this line is inside
        // `boot`, so no host gate compiles it, and the arithmetic is on the ARGUMENT
        // rather than inside the function a value test can call. `reveal_step` is what
        // produces `page`, and it is checked by value.
        assert!(
            src.contains("glass = show_backup_page(&mut session, page, panel, &mut entropy)"),
            "the reveal's step call must pass the cursor `reveal_step` produced, \
             UNCHANGED -- any arithmetic here skips pages and no other gate can see it"
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
    /// re-issue means asking the device for the secret a second time. Typing a share
    /// back IN is the same argument multiplied: 142 presses at the measured mean
    /// (`wordentry`'s own pin), so 142 trips round this loop, and a `while` anywhere in
    /// here would hold `cdc.poll` for the whole ceremony.
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
        // The flow cursor is the second one and it hangs off the SAME `if` — so the
        // two are mutually exclusive and an iteration still reads the pad at most
        // once. `if` instead of `else if` here would be two reads (100 ms) whenever
        // a coordinator parked a prompt while a backup was up.
        assert!(
            src.contains("} else if let Some(flow) = glass.take() {"),
            "the backup flows must be the `else` of the parked prompt, not a second `if`"
        );
        assert_eq!(
            src.matches("glass.take()").count(),
            1,
            "exactly one place services the flow on the glass"
        );
        // TWO reads for two MUTUALLY EXCLUSIVE branches — the parked prompt and the
        // flow on the glass — reached through one `if` / `else if`, so an iteration
        // performs at most one. All THREE flow screens (a reveal page, the recorded
        // question, an entry) share the single read, because `flow_consent` picks what
        // that read is asking about instead of an `ask` per screen. A third would have
        // to justify which branch it belongs to. MEASURED: the entry is where this
        // matters most — 25 words is ~142 presses, so a second read here is 7 seconds of
        // extra latency spread over one ceremony.
        assert_eq!(
            src.matches("ask(").count(),
            2,
            "exactly one bounded pad read per loop iteration, per exclusive branch"
        );
        // The read feeds BOTH step functions and is taken before either, so the verdict
        // that is routed is the verdict the pad just gave, against the state that is on
        // the glass. A second `ask` inside one of the arms would be the starvation this
        // test exists to prevent.
        assert!(
            src.contains("let verdict = ask(keypad.as_mut(), &mut entropy, consent, last);")
                && src.contains(
                    "Flow::Reveal(state) => match reveal_step(state, verdict, BACKUP_END) {"
                )
                && src.contains("entry_step(verdict)"),
            "the flow's one pad read must feed `reveal_step` and `entry_step`, against \
             the state that is on the glass"
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

    /// The `Answer`s are distinct, so `Wait` cannot be `No` by accident — and
    /// `Key(k)` cannot be `Yes`, which is the one pair with a signature behind it.
    /// Cheap, and it is what `assert_eq!` above is worth anything against.
    #[test]
    fn the_five_answers_are_distinct() {
        let all = [
            Answer::Wait,
            Answer::Next,
            Answer::Back,
            Answer::Yes,
            Answer::No,
            // Two keystrokes, so `Key` is distinct from the other four AND from
            // itself-with-another-byte: a gate that compared only the discriminant
            // would let any key stand in for the digit that authorises a signature.
            Answer::Key(b'1'),
            Answer::Key(b'y'),
        ];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                assert_eq!(i == j, a == b, "{a:?} vs {b:?}");
            }
        }
    }

    /// **A keystroke never appears in a `Debug` line**, on either type that carries one.
    ///
    /// The byte is one press of a letter key, and the press SEQUENCE is the word — at
    /// 5.7 presses per word the encoding is close to the entropy, so 25 sequences are
    /// the share. `coldsnap_firmware::wordentry::Step` redacts its `Debug` for exactly
    /// this reason and this is the same material two functions later.
    ///
    /// Asserted as an EQUALITY against a constant string, which is what makes it a
    /// statement about the byte: `#[derive(Debug)]` prints `Key(49)`, so restoring the
    /// derive fails here rather than in review. Nothing in the image formats an `Answer`
    /// today (no `defmt`, no semihosting, no formatted panic), so this guards the day
    /// something does.
    #[test]
    fn a_keystroke_is_redacted_from_every_debug_line() {
        for key in [b'1', b'9', b'0', b'y', b'x', 0u8, u8::MAX] {
            assert_eq!(
                std::format!("{:?}", Answer::Key(key)),
                "Key(<press>)",
                "the pad verdict printed the key {:?} that was pressed",
                key as char
            );
            assert_eq!(
                std::format!("{:?}", EntryStep::Key(key)),
                "Key(<press>)",
                "the entry step printed the key {:?} that was pressed",
                key as char
            );
            assert_eq!(
                std::format!("{:?}", CheckStep::Key(key)),
                "Key(<press>)",
                "the quiz step printed the key {:?} that was pressed",
                key as char
            );
        }
        // Not a blanket string: every other variant still names itself, or the
        // `assert_eq!`s throughout this module would be diagnosing nothing.
        assert_eq!(std::format!("{:?}", Answer::Yes), "Yes");
        assert_eq!(std::format!("{:?}", Answer::No), "No");
        assert_eq!(std::format!("{:?}", Answer::Wait), "Wait");
        assert_eq!(std::format!("{:?}", Answer::Next), "Next");
        assert_eq!(std::format!("{:?}", Answer::Back), "Back");
        assert_eq!(std::format!("{:?}", EntryStep::Park), "Park");
        assert_eq!(std::format!("{:?}", EntryStep::End), "End");
        assert_eq!(std::format!("{:?}", CheckStep::Park), "Park");
        assert_eq!(std::format!("{:?}", CheckStep::Done), "Done");
    }

    // -----------------------------------------------------------------------
    // Backup ENTRY. The flow that INGESTS a secret, so the gate matters in both
    // directions: a keystroke must never authorise anything, and the digit that
    // authorises a signature must never be satisfied by a keystroke. Five of the
    // twelve pad keys are in BOTH alphabets (`1`, `2`, `3`, `4`, `6`), so there is
    // no byte-level separation to fall back on — `Consent::Entry` is the whole of it.
    // -----------------------------------------------------------------------

    /// The twelve keys the entry screens' own legends print.
    ///
    /// Built from `hal::ui`'s constants rather than written out, so a change there is a
    /// change here. It is every key on the pad, which is the point: an entry screen has
    /// no unadvertised key to refuse.
    fn entry_keys() -> Vec<u8> {
        let mut keys = ENTRY_LETTER_KEYS.to_vec();
        keys.extend([ENTRY_PAGE_KEY, ENTRY_OK_KEY, ENTRY_DELETE_KEY]);
        keys
    }

    /// **Every byte is a keystroke while a share is being typed in, and no byte
    /// confirms anything.**
    ///
    /// All 256, at both values of `last`, because `last` must be irrelevant here:
    /// [`answer`]'s [`Consent::Entry`] arm sits above every arm that reads it, and if
    /// it did not, `last: false` would turn every keypress into a refusal and end the
    /// ceremony on letter one. The `Answer::Yes` assertion is the security half —
    /// `Consent::Entry` is a unit variant, so there is nothing to accept and nothing to
    /// hand `Session::confirm_at`.
    ///
    /// The two paging keys are named because they are the trap: `ui::NEXT_KEY` is `9`,
    /// which is `ENTRY_LETTER_KEYS[8]`, and `ui::BACK_KEY` is `7`, which is `[6]`. An
    /// arm ordered ahead of the entry's would silently eat two of the nine letter keys —
    /// and the letters they type are not fixed, so the symptom would be a word that
    /// cannot be entered rather than a key that does nothing.
    #[test]
    fn the_entry_screen_answers_every_byte_as_a_keystroke() {
        for last in [false, LAST] {
            for key in 0..=u8::MAX {
                let got = answer(Ok(Event::Down(key)), Consent::Entry, last);
                assert_eq!(
                    got,
                    Answer::Key(key),
                    "key {:?} on an entry screen (last: {last})",
                    key as char
                );
                assert_ne!(
                    got,
                    Answer::Yes,
                    "key {:?} confirmed something while a share was being typed in",
                    key as char
                );
            }
            // The two keys an earlier arm would have stolen, named.
            assert_eq!(
                answer(Ok(Event::Down(NEXT_KEY)), Consent::Entry, last),
                Answer::Key(NEXT_KEY),
                "the paging arm ate letter key 9"
            );
            assert_eq!(
                answer(Ok(Event::Down(BACK_KEY)), Consent::Entry, last),
                Answer::Key(BACK_KEY),
                "the back arm ate letter key 7"
            );
            // And the five bytes a consent screen would have accepted are keystrokes
            // here, which is the whole overlap stated as a value.
            for d in CONFIRM_CHARSET {
                assert_eq!(
                    answer(Ok(Event::Down(d)), Consent::Entry, last),
                    Answer::Key(d),
                    "a confirm-charset byte was not a keystroke on the entry screen"
                );
            }
        }
        // Nothing pressed parks, undrawn. NO TIMEOUT: this is the only thing that
        // happens for as long as a human takes to find the next word on paper.
        for event in [Event::AllUp, Event::Unsettled] {
            assert_eq!(
                answer(Ok(event), Consent::Entry, LAST),
                Answer::Wait,
                "{event:?}"
            );
        }
        // Two contacts, an unreadable scan and a pad that never opened are refusals,
        // which `entry_step` turns into the ending — fail-closed in the direction that
        // takes the prefix off the glass.
        assert_eq!(
            answer(Ok(Event::MultiKey), Consent::Entry, LAST),
            Answer::No
        );
        for error in [
            KeypadError::NotOnThisTarget,
            KeypadError::ColumnsStuckLow { idr: 0 },
        ] {
            assert_eq!(
                answer(Err(error), Consent::Entry, LAST),
                Answer::No,
                "{error:?}"
            );
        }
        assert_eq!(
            ask(None, &mut Counter(0), Consent::Entry, LAST),
            Answer::No,
            "a missing pad must end the entry, not type into it"
        );
    }

    /// **An entry key cannot answer a signing or revealing screen, and a signing digit
    /// cannot be produced by an entry screen.** Requirement 2, both directions.
    ///
    /// The overlap is real and there is no constant to lean on: `1`, `2`, `3`, `4` and
    /// `6` are live entry keys AND members of [`ui::CONFIRM_CHARSET`], unlike
    /// [`ui::NEXT_KEY`]/[`ui::BACK_KEY`] which `hal/src/ui.rs:1069-1076` const-asserts
    /// out of it. So what is checked here is that the two alphabets are separated by the
    /// [`Consent`] variant and by nothing else:
    ///
    /// * on a PROMPT, an entry key is [`Answer::Yes`] if and only if it is the digit
    ///   that screen rendered — the pre-existing rule, restated over the entry alphabet
    ///   so the overlap cannot creep in as a special case;
    /// * on a prompt, this function never returns [`Answer::Key`], so a keystroke cannot
    ///   reach `Session::confirm_at` even by an arm being added in the wrong place;
    /// * on a reveal page or the recorded question, an entry key answers nothing it did
    ///   not already answer.
    ///
    /// MUTATION-VERIFY: make [`answer`]'s digit arm `confirm.accepts(key) ||
    /// ui::ENTRY_LETTER_KEYS.contains(&key)` — the shape a "let the pad type during a
    /// prompt" patch takes — and the first loop fails on nine keys at once.
    #[test]
    fn an_entry_key_cannot_answer_a_signing_or_revealing_screen() {
        let prompt = signing_shaped();
        for rendered in CONFIRM_CHARSET {
            let confirm = digit(rendered);
            for key in entry_keys() {
                let got = answer(
                    Ok(Event::Down(key)),
                    Consent::Prompt(&prompt, confirm),
                    LAST,
                );
                let want = if key == rendered {
                    // Not a hole: this key IS the digit the screen printed, and a human
                    // reading that screen pressed it. The overlap is a UI fact, not a
                    // gate weakness.
                    Answer::Yes
                } else if key == NEXT_KEY {
                    Answer::Wait
                } else {
                    Answer::No
                };
                assert_eq!(
                    got, want,
                    "entry key {:?} against a prompt printing {:?}",
                    key as char, rendered as char
                );
            }
            // No byte at all — not just the entry alphabet — produces a keystroke on a
            // prompt, at either page position. This is what makes the `Answer::Key` arm
            // of the parked-prompt match unreachable rather than merely refused.
            for last in [false, LAST] {
                for key in 0..=u8::MAX {
                    assert!(
                        !matches!(
                            answer(
                                Ok(Event::Down(key)),
                                Consent::Prompt(&prompt, confirm),
                                last
                            ),
                            Answer::Key(_)
                        ),
                        "a prompt produced a keystroke for {:?} (last: {last})",
                        key as char
                    );
                }
            }
        }
        // The two backup screens are unchanged by the entry landing: an entry key on a
        // reveal page still pages or ends, and on the recorded question it still only
        // acks the digit. Both are covered exhaustively elsewhere; these two lines are
        // the named regression for the ordering change in `answer`.
        for key in entry_keys() {
            assert!(
                !matches!(
                    answer(Ok(Event::Down(key)), Consent::Pages, false),
                    Answer::Yes | Answer::Key(_)
                ),
                "entry key {:?} did something new while a share was on the glass",
                key as char
            );
        }
        let confirm = digit(b'4');
        for key in entry_keys() {
            let got = answer(Ok(Event::Down(key)), Consent::Question(confirm), LAST);
            assert!(
                !matches!(got, Answer::Key(_)),
                "the recorded question produced a keystroke for {:?}",
                key as char
            );
            assert_eq!(
                got == Answer::Yes,
                key == b'4',
                "entry key {:?} on a recorded question printing '4'",
                key as char
            );
        }
        // And the parked-prompt arm keeps refusing it. Unreachable, so it is a source
        // pin: routing `Answer::Key` to `confirm_at` here is the mutation this test
        // exists for, and no behavioural test can see an arm nothing can reach.
        assert!(
            production_source().contains(
                "Answer::Back | Answer::Key(_) | Answer::No => refuse(panel.as_mut(), &mut glass),"
            ),
            "a keystroke arriving at a prompt must be a refusal, never a confirm"
        );
    }

    /// **Every live key reaches the word machine, and nothing else can end the flow by
    /// accident.**
    ///
    /// The whole pipeline `boot` runs for one pad event on an entry screen —
    /// [`flow_consent`], [`answer`], [`entry_step`] — composed in the same order and
    /// from the same functions, which is the point of them being module items. Before
    /// this, a key that never arrived at `wordentry::Entry::key` would have been a dead
    /// keypad with a state machine behind it, and 2,048 words of pinned narrowing
    /// unreachable from the glass.
    #[test]
    fn every_live_entry_key_reaches_the_word_machine() {
        let (consent, last) = flow_consent(Flow::Entry);
        assert!(
            matches!(consent, Consent::Entry),
            "the entry screen must be answered as an entry, with no digit"
        );
        for key in entry_keys() {
            assert_eq!(
                entry_step(answer(Ok(Event::Down(key)), consent, last)),
                EntryStep::Key(key),
                "live key {:?} never reached `Session::entry_key`",
                key as char
            );
        }
        // Every one of the pad's twelve keys, so no physical key is dead — the entry
        // legends print all of them.
        for key in DECODER {
            assert!(
                matches!(
                    entry_step(answer(Ok(Event::Down(key)), consent, last)),
                    EntryStep::Key(_)
                ),
                "pad key {:?} is dead during an entry",
                key as char
            );
        }
        // Nothing pressed parks. NO TIMEOUT, chosen: 25 words at ~5.7 presses each is
        // minutes of typing, and a screen that blanked mid-word would cost the words
        // entered so far AND a second full disclosure to get them back.
        for event in [Event::AllUp, Event::Unsettled] {
            assert_eq!(
                entry_step(answer(Ok(event), consent, last)),
                EntryStep::Park,
                "{event:?}"
            );
        }
        // Two contacts, an unreadable scan and a pad that never opened all END the
        // entry, which is what takes the prefix off the glass.
        for verdict in [
            answer(Ok(Event::MultiKey), consent, last),
            answer(Err(KeypadError::ColumnsStuckLow { idr: 0 }), consent, last),
            ask(None, &mut Counter(0), consent, last),
        ] {
            assert_eq!(
                entry_step(verdict),
                EntryStep::End,
                "a pad that cannot be read left a prefix on the glass"
            );
        }
        // And the three verdicts an entry can never produce end it rather than doing
        // something creative. `Answer::Yes` is the one that matters: it cannot occur
        // (there is no digit in a `Consent::Entry`), and if it did, the only thing it
        // buys is standby.
        for verdict in [Answer::Yes, Answer::Next, Answer::Back] {
            assert_eq!(
                entry_step(verdict),
                EntryStep::End,
                "{verdict:?} must not be able to do anything but end an entry"
            );
        }
    }

    /// **Both entry screens come from `hal::ui`'s own renderers**, so the noise, the
    /// 12-cell sensitive budget and the footer legends are the ones `hal`'s pixel gate
    /// covers — and the checksum-failure screen carries nothing secret.
    ///
    /// Checked by rendering the same screen twice from the same seed and comparing every
    /// pixel: if [`entry_frame`] composed a word row itself instead of delegating to
    /// [`ui::WordEntry::render`], the frames would differ, and the row would have missed
    /// `ui::Frame::mark_sensitive` — the one defence a share on the glass has.
    #[test]
    fn the_entry_screens_are_the_ones_hal_draws() {
        // The word page. Delegation is checked pixel-for-pixel, which also pins that the
        // noise is drawn from the caller's RNG rather than skipped.
        let word = ui::WordEntry {
            number: 3,
            partial: "AB",
            previous: Some("ABANDON"),
            candidates: "ACDEIKLNOSU",
            page: 0,
            complete: false,
        };
        let mut mine = ui::Frame::new();
        assert!(entry_frame(Screen::Word(word), &mut mine, &mut Counter(7)));
        let mut theirs = ui::Frame::new();
        word.render(&mut theirs, &mut Counter(7))
            .expect("a renderable word page");
        assert_eq!(
            mine.as_bytes(),
            theirs.as_bytes(),
            "the word page must be `ui::WordEntry::render` and not a copy of it"
        );

        // The share-index page, likewise — and it is `ui::EntryPages`' page 0, the same
        // screen the simulator draws.
        let mut mine = ui::Frame::new();
        assert!(entry_frame(
            Screen::ShareIndex { typed: Some(12) },
            &mut mine,
            &mut Counter(3)
        ));
        let mut theirs = ui::Frame::new();
        assert!(ui::EntryPages {
            share_index: None,
            words: &[],
            partial: "12",
        }
        .render(0, &mut theirs, &mut Counter(3)));
        assert_eq!(
            mine.as_bytes(),
            theirs.as_bytes(),
            "the share index must reach the glass in decimal, through `ui::EntryPages`"
        );
        // Nothing typed is an empty field and not a `0`: `wordentry` uses `0` to mean
        // "nothing", and a screen reading "share index: 0" would be a lie about a
        // 1-based index.
        let mut empty = ui::Frame::new();
        assert!(entry_frame(
            Screen::ShareIndex { typed: None },
            &mut empty,
            &mut Counter(3)
        ));
        let mut blank = ui::Frame::new();
        assert!(ui::EntryPages {
            share_index: None,
            words: &[],
            partial: "",
        }
        .render(0, &mut blank, &mut Counter(3)));
        assert_eq!(empty.as_bytes(), blank.as_bytes());
        assert_ne!(
            empty.as_bytes(),
            mine.as_bytes(),
            "the typed digits are not on the glass at all"
        );

        // The checksum failure. Composed in this file (see the `ponytail:` note there),
        // so what is checked is the property that matters: it names no word, no letter
        // and no index, it fits the panel, and it says the 25 words are still held —
        // because they are, and a screen that implied otherwise would send a user back
        // to word 1 for nothing.
        let mut failed = ui::Frame::new();
        assert!(entry_frame(Screen::Failed, &mut failed, &mut Counter(0)));
        let rows: Vec<String> = (0..ui::ROWS).map(|r| row_text(&failed, r)).collect();
        let all = rows.join("\n");
        assert!(
            all.contains("CHECKSUM"),
            "the failure must say what failed: {all}"
        );
        assert!(
            all.contains("25"),
            "the failure must say the words are kept: {all}"
        );
        // NO `row.chars().count() <= ui::COLS` here: `row_text` walks `0..ui::COLS`, so
        // every row it returns is at most `ui::COLS` chars however the screen was drawn.
        // The check that used to stand here could not fail for any input, which is worse
        // than none because it read as clip coverage of a screen this file composes
        // itself. What covers the content is the `contains` pair above and the
        // word-material scan below.
        for (r, row) in rows.iter().enumerate() {
            for word in ["ABANDON", "AB", "ABA"] {
                assert!(
                    !row.contains(word),
                    "row {r} of the failure screen carries word material: {row:?}"
                );
            }
        }

        // The `false` leg exists and is reachable, so `show_entry_page`'s refusal is not
        // dead code: `ui::WordEntry::render` refuses a word number outside 1..=25 and
        // draws NOTHING when it does, which is why the caller can put `ui::refusal` on
        // the same frame.
        let mut untouched = ui::Frame::new();
        let bad = ui::WordEntry { number: 0, ..word };
        assert!(
            !entry_frame(Screen::Word(bad), &mut untouched, &mut Counter(0)),
            "an unrenderable word page must be refused, not half-drawn"
        );
        assert_eq!(
            untouched.as_bytes(),
            ui::Frame::new().as_bytes(),
            "a refused screen must leave the frame clean"
        );
    }

    /// One row of a frame, as text. `ui::Frame::cell` is the only reader `hal` exposes,
    /// which is enough: it hands back the byte the glyph came from.
    fn row_text(frame: &ui::Frame, row: usize) -> String {
        (0..ui::COLS)
            .filter_map(|col| frame.cell(col, row).map(|(byte, _)| byte as char))
            .collect::<String>()
            .trim_end()
            .into()
    }

    /// **Every exit from the entry takes the prefix and the previous word off the
    /// glass**, and every re-park leaves a frame that is still up alone.
    ///
    /// Requirement 5, pinned as the shape that keeps it. It is control flow first —
    /// [`show_entry_page`] is the only producer of [`Flow::Entry`] and its only `false`
    /// legs draw `idle` or `ui::refusal` first — but the endings live in `boot`, which no
    /// gate in this tree compiles (PLAN.md §9 item 22), so the loop's own arms are pinned
    /// textually.
    ///
    /// The fourth ending is anything that takes the glass — a coordinator prompt, a
    /// refusal, an undisplayable prompt — and that is `take_glass`, which drops the whole
    /// [`Flow`] in the same statement as the `panel.show`. `Flow` being one enum is why
    /// that needed no second line for the entry.
    #[test]
    fn every_exit_from_the_entry_takes_the_words_off_the_glass() {
        let src = production_source();
        // ONE reader of the machine and ONE writer of a keystroke into it.
        assert_eq!(
            src.matches("session.entry_key(").count(),
            1,
            "one place delivers a keystroke, so only it can end an entry"
        );
        assert!(
            src.contains("EntryStep::Key(key) => match session.entry_key(key, &mut outbox) {"),
            "the keystroke must sit directly behind `EntryStep::Key` and carry that key"
        );
        // Two calls to the drawing function: the start, and every accepted keypress.
        assert_eq!(
            src.matches("show_entry_page(").count(),
            2,
            "two call sites: the start, and every redraw of the flow"
        );
        // The two re-parks, and they are the only two: nothing pressed, and a key that
        // did nothing. Both leave the frame that is already up alone — a redraw would
        // re-sample `mark_sensitive`'s noise over five rows that did not change.
        assert_eq!(
            src.matches("glass = Some(Flow::Entry)").count(),
            2,
            "`EntryStep::Park` and `Typed::Unchanged` re-park without redrawing, and \
             nothing else may"
        );
        assert!(
            src.contains("EntryStep::Park => glass = Some(Flow::Entry),")
                && src.contains("Ok(Typed::Unchanged) => glass = Some(Flow::Entry),"),
            "an unchanged entry screen must not be redrawn"
        );
        // BOTH endings draw. `Typed::Ended` is the 25th word or a back-out, and it draws
        // standby BEFORE parking any prompt the completion produced, so the prefix is off
        // the glass either way. `EntryStep::End` is the pad fault and the cancel.
        assert!(
            src.contains(
                "Ok(Typed::Ended(prompts)) => {\n                                if let Some(panel) = panel.as_mut() {\n                                    idle(&session, panel);"
            ),
            "an entry that ENDS must draw standby first, before anything else is decided"
        );
        assert!(
            src.contains(
                "EntryStep::End => {\n                            if let Some(panel) = panel.as_mut() {\n                                idle(&session, panel);"
            ),
            "a pad fault or a coordinator cancel must take the words off the glass"
        );
        // And a fault on the completing keypress draws the refusal, through `take_glass`,
        // which drops the cursor in the same statement.
        assert!(
            src.contains("Err(_fault) => refuse(panel.as_mut(), &mut glass),"),
            "a fault mid-entry must refuse on the glass and drop the cursor"
        );
        // The cancel guard: the coordinator can drop the grant without drawing anything,
        // so the loop asks the library whether the entry is still live BEFORE routing the
        // verdict. Without this the prefix outlives the ceremony by one keypress.
        assert!(
            src.contains(
                "let step = if session.entry_screen().is_some() {\n                        entry_step(verdict)\n                    } else {\n                        EntryStep::End\n                    };"
            ),
            "a cancelled entry must end on the next iteration, not on the next keypress"
        );
        // `show_entry_page`'s own two `false` legs, which is the control-flow half:
        // there is no way to return "the entry is over" without having drawn something.
        assert!(
            src.contains(
                "let Some(screen) = session.entry_screen() else {\n            idle(session, panel);\n            return false;"
            ),
            "an entry whose grant went away must draw standby before it returns"
        );
        assert!(
            src.contains(
                "if !entry_frame(screen, &mut frame, rng) {\n            ui::refusal(&mut frame);\n            let _ = panel.show(frame.as_bytes());\n            return false;"
            ),
            "an unrenderable entry screen must draw the refusal before it returns"
        );
    }

    // -----------------------------------------------------------------------
    // Backup CHECK QUIZ. The flow where the overlap is TOTAL: `ui::QUIZ_KEYS` is
    // `123` and every one of those three bytes is in `ui::CONFIRM_CHARSET`
    // (`12346`), so a keypress alone cannot say whether a human meant "candidate 2"
    // or "confirm". There is no const-assert to fall back on — `hal::ui` asserts
    // only that a quiz key is not a paging, cancel or OK key — so `Consent::Quiz`
    // is the whole of it, and these tests drive both directions over all 256 bytes.
    // -----------------------------------------------------------------------

    /// A question of a quiz, as [`quiz::Quiz`] would hand it out: a real
    /// `ui::QuizWord` and three BIP39-shaped candidates.
    ///
    /// Built here rather than by running a `quiz::Quiz`, because what these tests are
    /// about is the ROUTING — `quiz.rs` drives the machine itself over all 256 bytes at
    /// every state, and this file must not grow a second copy of that.
    fn quiz_question() -> quiz::Screen {
        quiz::Screen::Word {
            question: ui::QuizWord {
                number: 7,
                asked: 2,
                total: quiz::QUIZ_POSITIONS,
                retry: false,
            },
            options: ["ABANDON", "ZOO", "ACTUAL"],
        }
    }

    /// **Every byte is a keystroke while a quiz is on the glass, and no byte confirms
    /// anything.** Requirement 1, the direction that must not fail open.
    ///
    /// All 256, at both values of `last`, because `last` must be irrelevant here:
    /// [`answer`]'s guarded arm sits above every arm that reads it, and if it did not,
    /// `last: false` would turn every answer into a refusal and end the quiz on question
    /// one. The `Answer::Yes` assertion is the security half — [`Consent::Quiz`] is a
    /// unit variant, so there is nothing to accept and nothing to hand
    /// `Session::confirm_at`.
    ///
    /// The three answer keys are named separately because they are the trap this whole
    /// variant exists for: they are `1`, `2`, `3`, and all three are confirm digits.
    #[test]
    fn the_quiz_screen_answers_every_byte_as_a_keystroke() {
        for last in [false, LAST] {
            for key in 0..=u8::MAX {
                let got = answer(Ok(Event::Down(key)), Consent::Quiz, last);
                assert_eq!(
                    got,
                    Answer::Key(key),
                    "key {:?} on a quiz screen (last: {last})",
                    key as char
                );
                assert_ne!(
                    got,
                    Answer::Yes,
                    "key {:?} confirmed something while three candidates were on the glass",
                    key as char
                );
            }
            // THE OVERLAP, stated as a value: all three answer keys are confirm digits,
            // and on this screen all three are keystrokes.
            for key in QUIZ_KEYS {
                assert!(
                    CONFIRM_CHARSET.contains(&key),
                    "the overlap this variant exists for is gone; simplify it"
                );
                assert_eq!(
                    answer(Ok(Event::Down(key)), Consent::Quiz, last),
                    Answer::Key(key),
                    "a quiz answer key was not delivered as a keystroke"
                );
            }
            // And the two paging keys are not eaten by an arm ordered ahead of this one.
            // They do nothing in the quiz — `quiz::Quiz::key` ignores them — but they
            // must arrive as keystrokes so that the ONE place deciding which keys are
            // live is the pure machine and not this file.
            for key in [NEXT_KEY, BACK_KEY] {
                assert_eq!(
                    answer(Ok(Event::Down(key)), Consent::Quiz, last),
                    Answer::Key(key),
                    "a paging arm ate a byte the quiz machine should have seen"
                );
            }
        }
        // Nothing pressed parks, undrawn. NO TIMEOUT: this is the only thing that
        // happens for as long as a human takes to find word 7 on paper.
        for event in [Event::AllUp, Event::Unsettled] {
            assert_eq!(
                answer(Ok(event), Consent::Quiz, LAST),
                Answer::Wait,
                "{event:?}"
            );
        }
        // Two contacts, an unreadable scan and a pad that never opened are refusals,
        // which `check_step` turns into the ending — fail-closed in the direction that
        // takes the candidates off the glass.
        assert_eq!(answer(Ok(Event::MultiKey), Consent::Quiz, LAST), Answer::No);
        for error in [
            KeypadError::NotOnThisTarget,
            KeypadError::ColumnsStuckLow { idr: 0 },
        ] {
            assert_eq!(
                answer(Err(error), Consent::Quiz, LAST),
                Answer::No,
                "{error:?}"
            );
        }
        assert_eq!(
            ask(None, &mut Counter(0), Consent::Quiz, LAST),
            Answer::No,
            "a missing pad must end the quiz, not answer it"
        );
    }

    /// **A quiz answer key cannot answer a signing or revealing screen, and a signing
    /// digit cannot be produced by a quiz screen.** Requirement 3, both directions.
    ///
    /// This is the sharper twin of
    /// `an_entry_key_cannot_answer_a_signing_or_revealing_screen`: the entry's overlap
    /// with [`ui::CONFIRM_CHARSET`] is five of twelve, and the quiz's is **three of
    /// three** — every key its screen advertises is a key a signing screen might ask
    /// for. So what is checked is that the two alphabets are separated by the
    /// [`Consent`] variant and by nothing else:
    ///
    /// * on a PROMPT, a quiz key is [`Answer::Yes`] if and only if it is the digit that
    ///   screen rendered — the pre-existing rule, restated over the quiz alphabet so the
    ///   overlap cannot creep in as a special case;
    /// * on a prompt, this function never returns [`Answer::Key`], so a keystroke cannot
    ///   reach `Session::confirm_at` even by an arm being added in the wrong place;
    /// * on a reveal page or the recorded question, a quiz key answers nothing it did
    ///   not already answer.
    ///
    /// MUTATION-VERIFY: make [`answer`]'s digit arm `confirm.accepts(key) ||
    /// ui::QUIZ_KEYS.contains(&key)` — the shape a "just make the quiz keys work" patch
    /// takes — and the first loop fails on two keys per rendered digit.
    #[test]
    fn a_quiz_answer_key_cannot_answer_a_signing_or_revealing_screen() {
        let prompt = signing_shaped();
        for rendered in CONFIRM_CHARSET {
            let confirm = digit(rendered);
            for key in QUIZ_KEYS.iter().copied().chain([KEY_CANCEL, KEY_OK]) {
                let got = answer(
                    Ok(Event::Down(key)),
                    Consent::Prompt(&prompt, confirm),
                    LAST,
                );
                // Not a hole when it IS the rendered digit: a human reading that screen
                // pressed the key it printed. The overlap is a UI fact, not a gate
                // weakness — what would be a weakness is the other two answering too.
                let want = if key == rendered {
                    Answer::Yes
                } else {
                    Answer::No
                };
                assert_eq!(
                    got, want,
                    "quiz key {:?} against a prompt printing {:?}",
                    key as char, rendered as char
                );
            }
            // At most ONE of the three answer keys can ever confirm, because at most one
            // of them is the rendered digit. This is the "1 in 3 becomes 1 in 12" claim
            // that makes the separation worth anything.
            let confirming = QUIZ_KEYS
                .iter()
                .filter(|key| {
                    answer(
                        Ok(Event::Down(**key)),
                        Consent::Prompt(&prompt, confirm),
                        LAST,
                    ) == Answer::Yes
                })
                .count();
            assert!(
                confirming <= 1,
                "more than one quiz key confirmed a prompt printing {:?}",
                rendered as char
            );
        }
        // A quiz key on a reveal page still pages or ends, and on the recorded question
        // it still only acks the digit. Both are covered exhaustively elsewhere; these
        // are the named regression for the ordering change in `answer`.
        for key in QUIZ_KEYS {
            assert!(
                !matches!(
                    answer(Ok(Event::Down(key)), Consent::Pages, false),
                    Answer::Yes | Answer::Key(_)
                ),
                "quiz key {:?} did something new while a share was on the glass",
                key as char
            );
        }
        let confirm = digit(b'4');
        for key in QUIZ_KEYS {
            let got = answer(Ok(Event::Down(key)), Consent::Question(confirm), LAST);
            assert!(
                !matches!(got, Answer::Key(_)),
                "the recorded question produced a keystroke for {:?}",
                key as char
            );
            assert_eq!(
                got,
                Answer::No,
                "quiz key {:?} answered a recorded question printing '4'",
                key as char
            );
        }
        // And the parked-prompt arm keeps refusing a keystroke. Unreachable, so it is a
        // source pin — the same one the entry leans on, and it covers both flows because
        // there is one `Answer::Key` and one arm.
        assert!(
            production_source().contains(
                "Answer::Back | Answer::Key(_) | Answer::No => refuse(panel.as_mut(), &mut glass),"
            ),
            "a keystroke arriving at a prompt must be a refusal, never a confirm"
        );
    }

    /// **Every live quiz key reaches the quiz machine, and nothing else can end the flow
    /// by accident.**
    ///
    /// The whole pipeline `boot` runs for one pad event on a question — [`flow_consent`],
    /// [`answer`], [`check_step`] — composed in the same order and from the same
    /// functions, which is the point of them being module items.
    ///
    /// The give-up key is checked here as a *delivery*, not as an abort: `x` must arrive
    /// at `Session::quiz_key` as a byte, because `coldsnap_firmware::quiz::Quiz::key` is
    /// the one place that decides what it means. A `CheckStep::Done` for `x` here would
    /// be a second decision free to disagree with that one.
    #[test]
    fn every_live_quiz_key_reaches_the_quiz_machine() {
        let (consent, last) = flow_consent(Flow::Check(Check::Asking));
        assert!(
            matches!(consent, Consent::Quiz),
            "the quiz screen must be answered as a quiz, with no digit"
        );
        for key in QUIZ_KEYS.iter().copied().chain([KEY_CANCEL]) {
            assert!(
                DECODER.contains(&key),
                "the quiz asks for a key {:?} the pad cannot send",
                key as char
            );
            assert_eq!(
                check_step(Check::Asking, answer(Ok(Event::Down(key)), consent, last)),
                CheckStep::Key(key),
                "live key {:?} never reached `Session::quiz_key`",
                key as char
            );
        }
        // Every one of the pad's twelve keys is delivered, so the decision about which
        // ones are live is entirely the pure machine's.
        for key in DECODER {
            assert_eq!(
                check_step(Check::Asking, answer(Ok(Event::Down(key)), consent, last)),
                CheckStep::Key(key),
                "pad key {:?} never reached the quiz machine",
                key as char
            );
        }
        // Nothing pressed parks. NO TIMEOUT, chosen: eight questions is minutes of
        // comparing words against paper, and a screen that blanked mid-quiz would cost
        // the quiz AND a second consent — at which point three more real words are drawn.
        for event in [Event::AllUp, Event::Unsettled] {
            assert_eq!(
                check_step(Check::Asking, answer(Ok(event), consent, last)),
                CheckStep::Park,
                "{event:?}"
            );
        }
        // Two contacts, an unreadable scan and a pad that never opened all END the quiz,
        // which is what takes the candidates off the glass.
        for verdict in [
            answer(Ok(Event::MultiKey), consent, last),
            answer(Err(KeypadError::ColumnsStuckLow { idr: 0 }), consent, last),
            ask(None, &mut Counter(0), consent, last),
        ] {
            assert_eq!(
                check_step(Check::Asking, verdict),
                CheckStep::Done,
                "a pad that cannot be read left three candidates on the glass"
            );
        }
        // And the three verdicts a quiz can never produce end it rather than doing
        // something creative. `Answer::Yes` is the one that matters: it cannot occur
        // (there is no digit in a `Consent::Quiz`), and if it did, the only thing it buys
        // is standby — never `Session::confirm_at`, which is not reachable from
        // `check_step` at all.
        for verdict in [Answer::Yes, Answer::Next, Answer::Back] {
            assert_eq!(
                check_step(Check::Asking, verdict),
                CheckStep::Done,
                "{verdict:?} must not be able to do anything but end a quiz"
            );
        }
    }

    /// **The passed screen is dismissed by any key, and it acks nothing.**
    ///
    /// Two properties in one, because they are the same shape. The screen exists at all
    /// because `ui::backup_quiz_passed`'s footer prints `(x)done`
    /// (`hal/src/ui.rs:2457`), and a legend naming a key that does nothing is the failure
    /// mode this file's const asserts exist to prevent. It is generous — every byte
    /// dismisses, not just `x` — because there is nothing on it a further press could
    /// change: the words are already off the glass (that screen takes a `usize` and
    /// cannot be handed a `&str`) and `CommsMisc::BackupChecked` is already in the
    /// outbox, sent by `Session::quiz_key` at the moment the last question was answered.
    ///
    /// So the ack cannot be sent twice from here: [`CheckStep`] has no `Ack` variant, and
    /// the source pin below is the half that lives in `boot`.
    #[test]
    fn the_passed_quiz_screen_is_dismissed_by_any_key_and_acks_nothing() {
        let (consent, last) = flow_consent(Flow::Check(Check::Passed));
        assert!(
            matches!(consent, Consent::Quiz),
            "the passed screen must carry no digit either — it authorises nothing"
        );
        for key in 0..=u8::MAX {
            assert_eq!(
                check_step(Check::Passed, answer(Ok(Event::Down(key)), consent, last)),
                CheckStep::Done,
                "key {:?} did not dismiss the passed screen",
                key as char
            );
        }
        // Nothing pressed leaves it up, undrawn. A human is entitled to read it, and
        // there is no timer.
        for event in [Event::AllUp, Event::Unsettled] {
            assert_eq!(
                check_step(Check::Passed, answer(Ok(event), consent, last)),
                CheckStep::Park,
                "{event:?}"
            );
        }
        // A pad fault dismisses it too, which costs nothing: the screen carries no word.
        assert_eq!(
            check_step(Check::Passed, ask(None, &mut Counter(0), consent, last)),
            CheckStep::Done
        );
        // No key on this screen can deliver a keystroke, so `Session::quiz_key` — which
        // refuses a quiz that is over — is never called from it.
        for key in 0..=u8::MAX {
            assert!(
                !matches!(
                    check_step(Check::Passed, answer(Ok(Event::Down(key)), consent, last)),
                    CheckStep::Key(_)
                ),
                "the passed screen sent {:?} to a quiz that no longer exists",
                key as char
            );
        }
        // The two states are distinct, so no arm can route one as the other — which
        // would hand the passed screen's dismissal to `Session::quiz_key`.
        assert_ne!(Check::Asking, Check::Passed);
        // And there is exactly one ack site in the image, and it is the reveal's. The
        // quiz's lives in `Session::quiz_key` where the pass is scored, so nothing this
        // file can press acks a quiz.
        assert_eq!(
            production_source().matches("session.quiz_key(").count(),
            1,
            "one place delivers a quiz keystroke, so only it can ack a quiz"
        );
        assert_eq!(
            production_source().matches("CheckStep::Ack").count(),
            0,
            "the quiz ack belongs to `Session::quiz_key`, not to a pad verdict"
        );
    }

    /// **Both quiz screens come from `hal::ui`'s own renderers**, so the noise over the
    /// three option rows, the 12-cell sensitive budget and the footer legends are the
    /// ones `hal`'s pixel gate covers.
    ///
    /// Checked by rendering the same screen twice from the same seed and comparing every
    /// pixel: if [`quiz_frame`] composed an option row itself instead of delegating to
    /// [`ui::backup_quiz_word`], the frames would differ and that row would have missed
    /// [`ui::Frame::mark_sensitive`] — the one defence a share word on the glass has, and
    /// one of these three rows IS a share word.
    #[test]
    fn the_quiz_screens_are_the_ones_hal_draws() {
        let quiz::Screen::Word { question, options } = quiz_question() else {
            panic!("the fixture is a question");
        };
        let mut mine = ui::Frame::new();
        assert!(quiz_frame(quiz_question(), &mut mine, &mut Counter(11)));
        let mut theirs = ui::Frame::new();
        ui::backup_quiz_word(&mut theirs, question, options, &mut Counter(11))
            .expect("a renderable question");
        assert_eq!(
            mine.as_bytes(),
            theirs.as_bytes(),
            "the question must be `ui::backup_quiz_word` and not a copy of it"
        );
        // The options are on the glass in the order the machine shuffled them, which is
        // what makes the answer's slot uniform. A frame drawn from a permutation must
        // differ, or this file could be reordering them.
        let mut swapped = ui::Frame::new();
        assert!(quiz_frame(
            quiz::Screen::Word {
                question,
                options: [options[2], options[1], options[0]],
            },
            &mut swapped,
            &mut Counter(11)
        ));
        assert_ne!(
            mine.as_bytes(),
            swapped.as_bytes(),
            "the three candidates must reach the glass in the order they were drawn"
        );

        // The passed screen, likewise — and it takes a COUNT, so there is nothing on it
        // to noise and nothing for a word to hide in.
        let mut mine = ui::Frame::new();
        assert!(quiz_frame(
            quiz::Screen::Passed {
                checked: quiz::QUIZ_POSITIONS
            },
            &mut mine,
            &mut Counter(5)
        ));
        let mut theirs = ui::Frame::new();
        ui::backup_quiz_passed(&mut theirs, quiz::QUIZ_POSITIONS).expect("a renderable pass");
        assert_eq!(
            mine.as_bytes(),
            theirs.as_bytes(),
            "the passed screen must be `ui::backup_quiz_passed` and not a copy of it"
        );
        // It says what was CHECKED and not that the backup is good: 8 of 25, with the
        // rest named as unchecked. A screen reading "backup verified" would be a claim
        // about 17 words nobody looked at.
        let rows: Vec<String> = (0..ui::ROWS).map(|r| row_text(&mine, r)).collect();
        let all = rows.join("\n");
        assert!(
            all.contains("8 of 25") && all.contains("not checked"),
            "the passed screen must claim only what was checked: {all}"
        );
        // A BUILD failure and not an assertion, because both inputs are `const`: a quiz
        // over every position would make that screen's caveat ("the rest were not
        // checked") a lie, and would also mean a whole quiz could put the whole share on
        // the glass. That ceiling is asserted at MODULE scope in `quiz.rs` as of
        // 2026-09-10, so it fails the BUILD for `thumbv7em-none-eabihf` -- both copies
        // of it, here and in `lib.rs`, were `#[cfg(test)]`-only and so only ever failed
        // the test build, which is not what their comments claimed.
        // No candidate of the question is anywhere on the passed screen: it is the frame
        // that goes OVER the words.
        for word in options {
            assert!(
                !all.contains(word),
                "the passed screen carries the candidate {word:?}"
            );
        }

        // The `false` leg exists and is reachable, so `show_quiz`'s refusal is not dead
        // code: `ui::backup_quiz_word` refuses a word number outside 1..=25 and draws
        // NOTHING when it does, which is why the caller can put `ui::refusal` on the same
        // frame.
        let mut untouched = ui::Frame::new();
        assert!(
            !quiz_frame(
                quiz::Screen::Word {
                    question: ui::QuizWord {
                        number: 0,
                        ..question
                    },
                    options,
                },
                &mut untouched,
                &mut Counter(0)
            ),
            "an unrenderable question must be refused, not half-drawn"
        );
        assert_eq!(
            untouched.as_bytes(),
            ui::Frame::new().as_bytes(),
            "a refused screen must leave the frame clean"
        );
        // And the same for the pass: `0 of 25 matched` under a passed header is a false
        // assurance, so it is a refusal rather than a frame.
        let mut untouched = ui::Frame::new();
        assert!(!quiz_frame(
            quiz::Screen::Passed { checked: 0 },
            &mut untouched,
            &mut Counter(0)
        ));
        assert_eq!(untouched.as_bytes(), ui::Frame::new().as_bytes());
    }

    /// **Every exit from the quiz takes the three candidates off the glass** —
    /// requirement 6, pinned as the shape that keeps it.
    ///
    /// One of those three rows is the true word at the position being asked and a second
    /// is a real word from elsewhere in the same share, so a panel left showing them
    /// after a human walks away is the leak this flow's consent screen warned about. It
    /// is control flow first — [`show_quiz`] is the only producer of [`Flow::Check`] and
    /// both of its `None` legs draw first — but the endings live in `boot`, which no gate
    /// in this tree compiles (PLAN.md §9 item 22), so the loop's own arms are pinned
    /// textually.
    ///
    /// The fifth ending is anything that takes the glass — a coordinator prompt, a
    /// refusal, an undisplayable prompt — and that is `take_glass`, which drops the whole
    /// [`Flow`] in the same statement as the `panel.show`. [`Flow`] being one enum is why
    /// that needed no third line for the quiz.
    #[test]
    fn every_exit_from_the_quiz_takes_the_candidates_off_the_glass() {
        let src = production_source();
        // ONE writer of a keystroke into the machine, and it sits directly behind the
        // step that carries the byte.
        assert!(
            src.contains(
                "CheckStep::Key(key) => {\n                            match session.quiz_key(key, &mut entropy, &mut outbox) {"
            ),
            "the keystroke must sit directly behind `CheckStep::Key` and carry that key"
        );
        // THE ONE PRODUCER, at its three call sites: the grant, a redraw, and the passed
        // screen. A fourth would have to say what it draws first.
        assert_eq!(
            src.matches("show_quiz(").count(),
            3,
            "three call sites: the start, every redraw, and the ending that passed"
        );
        // The two re-parks, and they are the only two: nothing pressed, and a key that
        // did nothing. Both leave the frame that is already up alone — a redraw would
        // re-sample `mark_sensitive`'s noise over the row holding the true word.
        assert_eq!(
            src.matches("glass = Some(Flow::Check(state))").count(),
            2,
            "`CheckStep::Park` and `Checked::Unchanged` re-park without redrawing, and \
             nothing else may"
        );
        assert!(
            src.contains("CheckStep::Park => glass = Some(Flow::Check(state)),")
                && src.contains("Ok(Checked::Unchanged) => glass = Some(Flow::Check(state)),"),
            "an unchanged quiz screen must not be redrawn"
        );
        // BOTH ENDINGS DRAW. A pass draws the "8 of 25 words matched" screen over the
        // candidates and keeps the glass for it; giving up draws standby. Neither leaves
        // a question up, and the ONLY thing that keeps a `Flow::Check` alive past an
        // ending is the passed screen, which carries no word.
        assert!(
            src.contains(
                "Some(checked) => {\n                                                glass = show_quiz(\n                                                    &session,\n                                                    Some(quiz::Screen::Passed { checked }),"
            ),
            "a passed quiz must draw the passed screen over the candidates"
        );
        assert!(
            src.contains("None => idle(&session, panel),"),
            "a quiz the human gave up on must draw standby, and send nothing"
        );
        assert!(
            src.contains(
                "CheckStep::Done => {\n                            if let Some(panel) = panel.as_mut() {\n                                idle(&session, panel);"
            ),
            "a pad fault, a coordinator cancel or a dismissed pass must take the \
             candidates off the glass"
        );
        // And a fault on the keypress draws the refusal, through `take_glass`, which
        // drops the cursor in the same statement.
        assert_eq!(
            src.matches("Err(_fault) => refuse(panel.as_mut(), &mut glass),")
                .count(),
            3,
            "a fault on a consent, mid-entry and mid-quiz must all three refuse on the \
             glass and drop the cursor in the same statement"
        );
        // The cancel guard: the coordinator can drop the grant without drawing anything,
        // so the loop asks the library whether the quiz is still live BEFORE routing the
        // verdict — and asks it for the QUESTION only, because the passed screen has no
        // quiz behind it and gating that on a grant would blank it on the next iteration.
        assert!(
            src.contains(
                "Check::Asking if session.quiz_screen().is_none() => CheckStep::Done,\n                        _ => check_step(state, verdict),"
            ),
            "a cancelled quiz must end on the next iteration, not on the next keypress — \
             and the passed screen must not be gated on a grant it does not need"
        );
        // `show_quiz`'s own two `None` legs, which is the control-flow half: there is no
        // way to return "nothing quiz-shaped is on the glass" without having drawn
        // something.
        assert!(
            src.contains(
                "let Some(screen) = screen else {\n            idle(session, panel);\n            return None;"
            ),
            "a quiz whose grant went away must draw standby before it returns"
        );
        assert!(
            src.contains(
                "if !quiz_frame(screen, &mut frame, rng) {\n            ui::refusal(&mut frame);\n            let _ = panel.show(frame.as_bytes());\n            return None;"
            ),
            "an unrenderable quiz screen must draw the refusal before it returns"
        );
        // And the cursor is read off the screen that was drawn, so the pixels and the
        // gate cannot describe different screens.
        assert!(
            src.contains(
                "Some(match screen {\n            quiz::Screen::Word { .. } => Check::Asking,\n            quiz::Screen::Passed { .. } => Check::Passed,\n        })"
            ),
            "the cursor must be read off the screen that reached the panel"
        );
    }
}

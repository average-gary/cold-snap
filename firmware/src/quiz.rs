//! The backup CHECK quiz: the pure `(state, key, rng) -> state` machine behind
//! [`ui::backup_quiz_word`].
//!
//! One backup position per screen, three candidate words on [`ui::QUIZ_KEYS`], a
//! wrong tap re-asking the same position with the three drawn again, and
//! [`QUIZ_POSITIONS`] correct answers to finish. No I/O, no registers, no clock, no
//! `cfg(target_arch)`, no allocation — the same shape as its sibling
//! [`crate::wordentry`], and for the same reason: it is exhaustively host-testable
//! only because it is a function of (state, key, rng).
//!
//! # NOTHING WIRES THIS YET
//!
//! `Session::recv` still refuses `CoordinatorRestoration::CheckBackup`
//! ([`crate::Refusal::PhysicalBackup`]) and `main.rs`'s `grants` still returns
//! `None` for the `CheckBackup` prompt. This file is the picker and the keypress
//! map those two were waiting on; **it repairs neither of them**, and until they
//! change, no coordinator message can reach a [`Quiz`]. What is still owed on the
//! other side of the seam:
//!
//! * a consent screen and its rendered `ConfirmDigit` — the quiz shows real share
//!   words, so the digit must be answered BEFORE [`Quiz::new`] is called, exactly
//!   as `show_backup` requires it,
//! * a `Consent` variant that carries **no** `ConfirmDigit`, for the hazard below,
//!   and
//! * `CommsMisc::BackupChecked { access_structure_ref, share_index }` on
//!   [`Step::Passed`] — upstream's success-only ack
//!   (`device/src/esp32_run.rs:748-757`, fired from the widget's `is_verified`).
//!
//! # The hazard: the answer keys are `1`, `2`, `3` and [`ui::CONFIRM_CHARSET`] is `12346`
//!
//! All three answer keys are also confirm digits, so a byte alone cannot say
//! whether the human meant "candidate 2" or "yes, sign it". Nothing here can close
//! that, and nothing here tries to: [`Step`] has **no variant carrying a
//! `ConfirmDigit`** and no payload at all, so no `Answer::Yes` can be constructed
//! from this machine's output and there is nothing to hand `Session::confirm_at`.
//! The separation has to be structural on the other side too — a unit `Consent`
//! variant for the quiz, the way `Consent::Entry` solved it for word entry — and
//! **that is `main.rs`'s and is not done here**. Do not widen `answer`'s prompt arm
//! to accept `1`/`2`/`3`: that digit is what guards signing and revealing.
//!
//! # The design is Coldcard's, and it is pinned by upstream's own device too
//!
//! `shared/seed.py:828-888` `word_quiz(words, limited)`, whose two call sites pass
//! `limited = len(words)//3` (`backups.py:442`, `notes.py:788`):
//!
//! * a shuffled subset of positions, **always including the last one**
//!   (`seed.py:838-847`) — see `draw_order`,
//! * exactly three choices: the right word, a wrong one from the user's OWN set,
//!   and one from the whole 2,048-word list, each behind a dedupe retry, then
//!   shuffled (`seed.py:855-872`) — see `Quiz::draw_options`,
//! * one position per screen, and a wrong answer re-asks that same position
//!   (`seed.py:875-878`).
//!
//! `frostsnap_widgets/src/backup/check_backup.rs` reaches the same place from the
//! other direction: a wrong tap sets `FeedbackKind::Wrong` on the tapped button and
//! the quiz page stays up (`:523`, `:592-600`), and its `rand_seed` comes from
//! `self.rng.next_u32()` (`device/src/esp32_run.rs:695`), so upstream's is
//! randomised too. Both references therefore agree on **no lockout, no attempt
//! counter and no failure outcome** — there is no failure message in the protocol
//! to send (`CheckBackup` carries a `BackupDisplayPhase` and has no counterpart,
//! `frostsnap_core/src/device/restoration.rs:265-323`), and a lockout would be ours
//! alone. This is a "did you write it down correctly" checklist, not access
//! control; it cannot be access control while `DisplayBackup` hands the same holder
//! all 25 words for one confirm digit.
//!
//! # What is deliberately NOT offered: Coldcard's `y`
//!
//! Coldcard's quiz answers `y` by re-showing the whole seed (`seed.py:879-881`).
//! Omitted, and [`keypad::KEY_OK`] is dead here
//! (`the_pad_ok_key_does_not_show_the_words_again`). A reveal reachable from a quiz
//! screen is a reveal whose consent was taken for a *quiz* — weaker consent than
//! [`ui::BackupPages`]' own digit buys — and it is also a screen
//! [`ui::backup_quiz_word`] prints no legend for. A user who needs to re-read the
//! share asks the coordinator for `DisplayBackup`, which has its own gate.
//! Fail-closed costs one round trip.
//!
//! # No timeout, chosen
//!
//! Nothing here expires and there is no clock in this module to expire against, for
//! [`crate::wordentry`]'s reason: a screen that blanks mid-flow costs a second full
//! disclosure of the same secret.
//!
//! # Heap: nothing, and no share material leaves this file
//!
//! Nothing in this module allocates. A [`Quiz`] is one fixed-size struct — 25 word
//! pointers, [`QUIZ_POSITIONS`] position bytes, three option pointers, a counter and
//! a flag, ~240 B on 32-bit — and `draw_order`'s pool is 24 bytes of stack. No
//! `Vec`, no `String`, no `Box`.
//!
//! The words themselves are entries of the vendored `BIP39_WORDS`, and they only
//! ever leave here inside [`Screen::Word`], for [`ui::backup_quiz_word`] to noise
//! onto the glass. There is no `Debug` on anything holding one (see [`Screen`]),
//! nothing here formats, logs or defmts, and no path from this file reaches an
//! outbox: [`Step`] is payload-free by construction.

use coldsnap_hal::{keypad, ui};
use frost_backup::bip39_words::{words_with_prefix, BIP39_WORDS};
use rand_core::RngCore;

/// How many positions the quiz asks: Coldcard's `limited`, `len(words) // 3`
/// (`shared/backups.py:442`), which is 8 of 25.
pub const QUIZ_POSITIONS: usize = ui::BACKUP_WORDS / 3;

/// Candidates per question — one per [`ui::QUIZ_KEYS`] entry, by the assert below.
pub const QUIZ_OPTIONS: usize = ui::QUIZ_KEYS.len();

/// The last backup position, 0-based: the one [`draw_order`] always includes.
const LAST_POSITION: u8 = (ui::BACKUP_WORDS - 1) as u8;

/// How many times a uniform draw is retried before it settles for a worse answer.
///
/// Every retry loop in this file is bounded by it (the others are bounded by an
/// array length). An unbounded retry is a hang, and on
/// this unit a hang is as permanent as a panic — RDP=2 makes DFU
/// hardware-impossible and `sdcard_recovery` cannot install an arbitrary image
/// (`sdcard.c:248` needs an SE1 CHECKMAC, `verify.c:300-306`). 32 is far past the
/// point where the fallbacks are reachable: see [`below`] and [`draw_distinct`].
const DRAW_TRIES: usize = 32;

const _: () = {
    // Every candidate is answered by pressing the digit drawn beside it, so a
    // fourth option or a fourth key would be an option no key selects or a key that
    // selects nothing. `ui::backup_quiz_word` takes exactly three.
    assert!(
        ui::QUIZ_KEYS.len() == QUIZ_OPTIONS,
        "one answer key per candidate"
    );
    // `ui::QuizWord` refuses a `total` outside 1..=BACKUP_WORDS and an `asked` that
    // is not below it, so a quiz asking zero questions or more than there are words
    // would draw nothing but refusals. It is also the bound that makes
    // `QUIZ_POSITIONS - 1` in `draw_order` safe under `overflow-checks = false`.
    assert!(
        QUIZ_POSITIONS >= 1 && QUIZ_POSITIONS <= ui::BACKUP_WORDS,
        "the quiz must ask at least one question and at most one per word"
    );
    // Positions are held as bytes, and `LAST_POSITION` casts one. 25 words fit; a
    // wordlist that did not would truncate silently under `as`.
    assert!(
        ui::BACKUP_WORDS >= 2 && ui::BACKUP_WORDS <= u8::MAX as usize,
        "a backup position must fit a u8, and there must be one to exclude"
    );
};

/// What to put on the glass.
///
/// Every word in it is a `'static` entry of the vendored list, so unlike
/// `wordentry::Screen` this borrows nothing and is `Copy`. It is a SNAPSHOT: draw it
/// and drop it. A kept copy is a stale question, and [`Quiz::key`] scores against
/// the machine's own state rather than against any screen it handed out.
///
/// No `#[derive(Debug)]`: [`Screen::Word`] carries the TRUE word among its options,
/// so a derive would print a share word into whatever formatted it. The manual impl
/// below prints the question and not the options, and exists so that adding the
/// derive back is a conflict rather than a silent leak.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    /// Ask about one position. Hand both fields straight to
    /// [`ui::backup_quiz_word`] — every bound that function refuses is already
    /// established here (`every_screen_the_machine_produces_is_renderable`).
    Word {
        /// Which position, which question of how many, and whether the last answer
        /// at this position was wrong.
        question: ui::QuizWord,
        /// The three candidates, exactly one of which is the true word at
        /// `question.number`. Shuffled: `Quiz::draw_options`.
        options: [&'static str; QUIZ_OPTIONS],
    },
    /// Every question answered correctly. Draw
    /// [`ui::backup_quiz_passed`]`(frame, checked)`; there is no word on it.
    Passed {
        /// How many words were checked — [`QUIZ_POSITIONS`], which is deliberately
        /// not all 25, and which that screen prints so the claim stays honest.
        checked: usize,
    },
}

impl core::fmt::Debug for Screen {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            // The QUESTION and not the options. `ui::QuizWord` holds positions and
            // counts, which are not the secret (it says why); the options hold the
            // answer, which is.
            Screen::Word { question, .. } => write!(f, "Word({question:?})"),
            Screen::Passed { checked } => write!(f, "Passed({checked})"),
        }
    }
}

/// What the caller must do about a keypress.
///
/// Every variant is payload-free, and that is the whole design rather than an
/// accident:
///
/// * there is no `Wrong` outcome, because a miss is reported to nobody — see the
///   module docs. It is a re-ask, i.e. a [`Step::Redraw`],
/// * there is nothing carrying a `ConfirmDigit`, so no `Answer::Yes` can be built
///   out of this machine's output, and
/// * there is no share material anywhere in it, so `derive(Debug)` here is safe and
///   is what a panic message or a future `defmt` line would reach for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[must_use]
pub enum Step {
    /// The key did nothing. **Do not redraw.** Every invalid key lands here, and so
    /// does any key on a passed quiz. Not redrawing is also what keeps
    /// `Frame::mark_sensitive`'s noise from being re-sampled over an unchanged
    /// option row.
    Unchanged,
    /// The state changed. Draw [`Quiz::screen`].
    Redraw,
    /// The human gave up ([`keypad::KEY_CANCEL`]): drop the [`Quiz`] and send
    /// nothing. Silence is the honest wire behaviour — the ack is success-only, so
    /// there is no "quiz failed" to report, and the coordinator's own
    /// `check_backup.rs` ends its dialog on `cancel()`.
    Abort,
    /// Every question answered correctly. Send `CommsMisc::BackupChecked`, draw
    /// [`Screen::Passed`], drop the [`Quiz`].
    Passed,
}

/// The whole state of one check quiz.
///
/// No `Debug` — the module docs say why. `PartialEq` is for the tests that assert a
/// dead key moved nothing.
#[derive(Clone, PartialEq, Eq)]
pub struct Quiz {
    /// The share's 25 words, as [`ui::BACKUP_WORDS`] entries of `BIP39_WORDS`
    /// ([`Quiz::new`] refuses anything else). Read to build questions and to draw
    /// the own-set distractor; never sent, formatted or stored.
    words: [&'static str; ui::BACKUP_WORDS],
    /// The positions to ask about, in the order they will be asked. Distinct, all
    /// below [`ui::BACKUP_WORDS`], and always containing [`LAST_POSITION`]:
    /// [`draw_order`].
    order: [u8; QUIZ_POSITIONS],
    /// How many questions have been answered correctly, `0..=QUIZ_POSITIONS`. Also
    /// the cursor into [`Quiz::order`] and `ui::QuizWord::asked`, so the progress
    /// the human reads and the question the machine scores cannot disagree.
    asked: usize,
    /// The three candidates now on the glass, one of which is the true word at
    /// the position being asked. Written **only** by [`Quiz::draw_options`].
    options: [&'static str; QUIZ_OPTIONS],
    /// The last answer at this position was wrong, so the re-ask carries the banner
    /// (`ui::QuizWord::retry`). Not a counter: nothing counts misses here.
    wrong: bool,
}

impl Quiz {
    /// A fresh quiz over one share's words, usually `ShareBackup::to_words()`.
    ///
    /// The caller must already have taken consent on the rendered `ConfirmDigit`:
    /// one in three candidates on every screen is a real word of this share, and a
    /// second is a real word from elsewhere in it, so this is a reveal-class flow
    /// and the digit is the gate.
    ///
    /// `None` — no quiz at all — when the words are not something this can quiz
    /// honestly:
    ///
    /// * any word is not an entry of the vendored `BIP39_WORDS`, including a
    ///   lowercase one (the list is uppercase). The renderer will NOT catch this for
    ///   us — `ui::check_word` accepts a word of either case, so `1) ABANDON` over
    ///   `2) zoo` draws fine — and a word the vendored list does not hold cannot
    ///   have come out of `ShareBackup::to_words()`, so quizzing it would put a
    ///   candidate the user is asked to trust on a screen with nothing behind it.
    /// * no two words differ, so no own-set distractor exists at any position. Real
    ///   shares are not like this; refusing beats searching forever.
    ///
    /// Both are fail-closed: a refused quiz is a `CheckBackup` the device does not
    /// answer, which is exactly where the feature stands today anyway.
    pub fn new(words: [&'static str; ui::BACKUP_WORDS], rng: &mut impl RngCore) -> Option<Self> {
        if !words.iter().all(|word| is_bip39(word)) {
            return None;
        }
        let mut quiz = Quiz {
            words,
            order: draw_order(rng),
            asked: 0,
            // Not words, so a frame built from these would REFUSE rather than print
            // something (`ui::check_word` rejects empty). Overwritten on the next
            // line, before this constructor hands the quiz out.
            options: [""; QUIZ_OPTIONS],
            wrong: false,
        };
        quiz.draw_options(rng)?;
        Some(quiz)
    }

    /// What to draw.
    pub fn screen(&self) -> Screen {
        match self.position() {
            Some(position) => Screen::Word {
                question: ui::QuizWord {
                    // 1-based for the human, and `saturating_add` because
                    // `overflow-checks = false` in release would wrap rather than
                    // trap. `position` is below `ui::BACKUP_WORDS`, so this is
                    // inside the 1..=25 `ui::backup_quiz_word` demands.
                    number: position.saturating_add(1),
                    asked: self.asked,
                    total: QUIZ_POSITIONS,
                    retry: self.wrong,
                },
                options: self.options,
            },
            None => Screen::Passed {
                checked: QUIZ_POSITIONS,
            },
        }
    }

    /// One keypress, as the byte `keypad::Event::Down` reports, plus the entropy a
    /// re-ask or the next question needs.
    ///
    /// Total: every one of the 256 bytes is handled at every state. Only
    /// [`ui::QUIZ_KEYS`] and [`keypad::KEY_CANCEL`] do anything, everything else is
    /// [`Step::Unchanged`], and a passed quiz is inert.
    pub fn key(&mut self, key: u8, rng: &mut impl RngCore) -> Step {
        let Some(truth) = self.truth() else {
            // Every question is answered: the caller has had `Step::Passed` and owns
            // the screen. Inert, cancel included — there is nothing left to abort
            // and no way to re-enter a finished quiz.
            return Step::Unchanged;
        };
        if key == keypad::KEY_CANCEL {
            return Step::Abort;
        }
        // The key's slot is looked up in the array the screen drew its digits from,
        // and the option is fetched with `get`: an unbounded index would WRAP rather
        // than panic under `overflow-checks = false`, and a wrapped index answers a
        // different question than the one on the glass.
        let Some(slot) = ui::QUIZ_KEYS.iter().position(|&k| k == key) else {
            return Step::Unchanged;
        };
        let Some(chosen) = self.options.get(slot).copied() else {
            return Step::Unchanged;
        };
        if chosen != truth {
            // The SAME position, asked again, with the three drawn again — Coldcard
            // `seed.py:875-878`, Frostsnap `check_backup.rs:592-600`. Nothing is
            // counted, nothing is locked out and nothing is reported.
            self.wrong = true;
            return self.ask(rng);
        }
        self.wrong = false;
        // Bounded: `truth()` was `Some`, so `asked < QUIZ_POSITIONS`.
        // `saturating_add` and not `+ 1` because a wrapped counter under
        // `overflow-checks = false` is a quiz that never ends.
        self.asked = self.asked.saturating_add(1);
        if self.asked >= QUIZ_POSITIONS {
            return Step::Passed;
        }
        self.ask(rng)
    }

    /// Put a question on the glass, or give up.
    fn ask(&mut self, rng: &mut impl RngCore) -> Step {
        match self.draw_options(rng) {
            Some(()) => Step::Redraw,
            // Unreachable after a successful `new` — see `draw_options`. Fail-closed
            // if it ever were reached: three candidates that do not include the
            // answer is a question nobody can pass, and abandoning costs nothing
            // because the ack is success-only.
            None => Step::Abort,
        }
    }

    /// Draw the three candidates for the position being asked, and shuffle them.
    ///
    /// Coldcard's rule exactly (`seed.py:855-872`): the true word, one from the
    /// user's OWN set (`words[randbelow(wl)]`), one from the whole list
    /// (`bip39.wordlist_en[randbelow(0x800)]`), each behind a dedupe retry, then
    /// shuffled. **Not** upstream's `distractor.rs`, whose two words minimise
    /// `levenshtein*3 - shared_suffix*2` against the true one and are therefore a
    /// pure function of the answer — 1,288 of the 2,048 words are recovered from
    /// that triple with no human input. A distractor rule leaks exactly when it is
    /// asymmetric, so all three come out of the same uniform draws and the shuffle
    /// puts the answer in a slot nobody can predict.
    ///
    /// `None` only when the own-set draw has nothing to offer, i.e. when all 25
    /// words equal the word being asked about. That condition does not depend on
    /// *which* position is being asked — it is "all 25 words are identical" — so
    /// [`Quiz::new`]'s call is a complete check for the whole quiz, and the arm in
    /// [`Quiz::ask`] is unreachable. The list draw cannot fail: 2,048 words against
    /// at most two exclusions.
    fn draw_options(&mut self, rng: &mut impl RngCore) -> Option<()> {
        let truth = self.truth()?;
        let own = draw_distinct(&self.words, &[truth], rng)?;
        let any = draw_distinct(&BIP39_WORDS, &[truth, own], rng)?;
        let mut options = [truth, own, any];
        shuffle(&mut options, rng);
        self.options = options;
        Some(())
    }

    /// The 0-based backup position this question is about, or `None` once every
    /// question has been answered.
    ///
    /// The ONLY place `asked` becomes an index, so the bound is checked once instead
    /// of at three call sites — and it is why `screen`, `truth` and `key` cannot
    /// disagree about which position is live.
    fn position(&self) -> Option<usize> {
        self.order.get(self.asked).map(|p| usize::from(*p))
    }

    /// The right answer to the question being asked, or `None` once there is none.
    fn truth(&self) -> Option<&'static str> {
        self.words.get(self.position()?).copied()
    }
}

/// The positions to quiz: Coldcard's `seed.py:838-847`, construction and all.
///
/// Take `0..wl-1`, shuffle, keep `limited - 1` of them, append `wl - 1`, shuffle
/// again. **The last word is always asked**, and it is the one that has to be: word
/// 25 IS the words checksum, 11 bits over the index, the scalar and the polynomial
/// checksum (`frost_backup/src/share_backup.rs:23-33,119-122` — `WORDS_CHECKSUM_BITS
/// = 11` at `WORDS_CHECKSUM_START = SCALAR_BITS + POLY_CHECKSUM_BITS`, i.e. the last
/// 11 of the 275). So an error there is the least self-evident of the 25: it is the
/// only word whose value the other 24 determine, so re-reading word 25 against the
/// paper cannot catch it, and the failure it causes is a whole-share refusal that
/// names no position at all (`wordentry::Stage::Failed`).
///
/// The second shuffle is not decoration: without it the checksum word is always the
/// last question, which tells an observer which screen it is on.
fn draw_order(rng: &mut impl RngCore) -> [u8; QUIZ_POSITIONS] {
    let mut pool = [0u8; ui::BACKUP_WORDS - 1];
    for (slot, position) in pool.iter_mut().zip(0u8..) {
        *slot = position;
    }
    shuffle(&mut pool, rng);
    let mut order = [LAST_POSITION; QUIZ_POSITIONS];
    // `take`, because `pool` is longer than `order`: the final slot must keep
    // `LAST_POSITION`, which is the whole point of the construction.
    for (slot, pick) in order.iter_mut().zip(pool.iter()).take(QUIZ_POSITIONS - 1) {
        *slot = *pick;
    }
    shuffle(&mut order, rng);
    order
}

/// Fisher-Yates over `rng`, which is `random.shuffle`'s algorithm and Coldcard's.
///
/// One function for both shuffles this module needs — positions (bytes) and
/// candidates (words) — because two shuffles is one of them being subtly biased.
/// Every index it produces is below the length by [`below`]'s contract, so
/// `swap` cannot be handed an out-of-range index and panic.
fn shuffle<T>(slice: &mut [T], rng: &mut impl RngCore) {
    let mut i = slice.len();
    while i > 1 {
        i -= 1;
        // `i + 1` is at most `slice.len()`, which every caller here keeps far below
        // `usize::MAX`.
        slice.swap(i, below(i + 1, rng));
    }
}

/// A uniform `0..bound`, by rejection — Coldcard's `random.randbelow`, without
/// libngu (PLAN.md §1: entropy bug, author not trusted).
///
/// Rejection and not a bare `next_u32() % bound`, which over-weights the first
/// `2^32 mod bound` values. At the bounds this module actually uses that bias is
/// negligible and it is stated rather than implied: `2^32 mod 3 = 1`, one value in
/// 1.4 billion, and `2^32 mod 2048 = 0`, none at all. Three lines of rejection buy
/// the property by CONSTRUCTION instead of by that argument, which is worth it
/// because the argument stops holding the moment someone calls this with a
/// different bound — and the thing being placed is which slot holds the answer.
///
/// `0` for a bound of zero or one that does not fit a `u32`. Every caller passes a
/// constant, non-empty length, so that arm is unreachable; it is an arm and not an
/// `expect` because a panic on this unit is permanent.
fn below(bound: usize, rng: &mut impl RngCore) -> usize {
    let span = match u32::try_from(bound) {
        Ok(span) if span > 0 => span,
        _ => return 0,
    };
    // Lemire's multiply-shift: scale the draw into `0..span` by taking the HIGH half
    // of a 64-bit product. Two properties matter more here than the last ulp of
    // uniformity, and both are why this is preferred over `draw % span` behind a
    // rejection zone:
    //
    //   1. It reads the HIGH bits. `%` reads the low ones, so with `span = 2` it is
    //      literally `draw & 1` — and this function is generic over `impl RngCore`,
    //      so a caller with a weak low bit would silently skew slot placement while
    //      every distinctness test still passed. Measured with an LCG mod 2^32
    //      driving the old form: slot counts 5.05 sigma off uniform. `Entropy` is
    //      ChaCha20 and has no weak bit, but correctness here should not rest on a
    //      property of the caller.
    //   2. It cannot loop, so it cannot hang. A hang on this device is permanent.
    //
    // The residual bias is at most `span / 2^32` — one part in ~1.7e8 at the largest
    // bound any caller uses (`span = 25`), which no feasible sample size can see.
    ((u64::from(rng.next_u32()) * u64::from(span)) >> 32) as usize
}

/// A uniform pick from `pool` that is not already in `taken`, or `None` if `pool`
/// holds nothing else.
///
/// Coldcard's `while 1: n = pool[randbelow(len)]; if n in choices: continue` with a
/// bound on the retries, and one function for both distractors so the own-set draw
/// and the wordlist draw cannot dedupe by different rules. Dedupe is by VALUE, not
/// by position: a share that happens to repeat a word must not be able to offer the
/// true word twice.
///
/// The sweep after the retries is what makes it total. It is reachable only when
/// almost every draw collides — 25 words that are nearly all the same, never the
/// 2,048-word list — and a deterministic answer there is strictly better than a
/// loop that might not stop.
fn draw_distinct(
    pool: &[&'static str],
    taken: &[&'static str],
    rng: &mut impl RngCore,
) -> Option<&'static str> {
    for _ in 0..DRAW_TRIES {
        let pick = *pool.get(below(pool.len(), rng))?;
        if !taken.contains(&pick) {
            return Some(pick);
        }
    }
    pool.iter().copied().find(|word| !taken.contains(word))
}

/// Whether `word` is an entry of the vendored `BIP39_WORDS`.
///
/// `words_with_prefix` returns the sorted block starting at the prefix, so a word —
/// being the shortest string with itself as a prefix — is that block's first entry
/// when it is in the list. The same trick `wordentry::Entry::whole_word` uses, and
/// it inherits the list's case: the vendored words are UPPERCASE, so a lowercase
/// one is not a word here.
fn is_bip39(word: &str) -> bool {
    words_with_prefix(word).first().copied() == Some(word)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    /// splitmix64 as an `RngCore`: seeded, so every test below is deterministic, and
    /// with a real finalizer, so the low bits `below` takes `%` of are not an LCG's.
    /// Nothing here reaches a device — the device's is `rng::Entropy`.
    struct Seeded(u64);

    impl Seeded {
        /// The seed is multiplied by something OTHER than the increment below.
        /// `Seeded(seed * INCREMENT)` looks like a fine spread and is not one: the
        /// walk is `state += INCREMENT`, so seed `s` and seed `s + 1` would be the
        /// same stream one draw apart, and the aggregate of 400 of them would be one
        /// stream counted 400 times. Measured as a 4-sigma tilt in
        /// `the_answer_lands_in_every_slot_uniformly` before this line changed.
        fn new(seed: u64) -> Self {
            Seeded(seed.wrapping_mul(0xD1B5_4A32_D192_ED03))
        }
    }

    impl RngCore for Seeded {
        fn next_u32(&mut self) -> u32 {
            (self.next_u64() >> 32) as u32
        }
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for byte in dest.iter_mut() {
                *byte = self.next_u64() as u8;
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    /// 25 distinct words with a share's shape. Not checksum-valid and it does not
    /// need to be: this machine takes words, never a `ShareBackup`. `gcd(37, 2048) =
    /// 1` and `37 * 25 < 2048`, so the 25 are distinct.
    fn share(salt: u64) -> [&'static str; ui::BACKUP_WORDS] {
        let mut words = [""; ui::BACKUP_WORDS];
        for (slot, i) in words.iter_mut().zip(0u64..) {
            let index = (salt.wrapping_mul(101).wrapping_add(i.wrapping_mul(37))) as usize;
            *slot = BIP39_WORDS[index % BIP39_WORDS.len()];
        }
        words
    }

    fn fresh(seed: u64) -> (Quiz, Seeded, [&'static str; ui::BACKUP_WORDS]) {
        let mut rng = Seeded::new(seed);
        let words = share(seed);
        let quiz = Quiz::new(words, &mut rng).expect("a real share can be quizzed");
        (quiz, rng, words)
    }

    /// The question now showing, or a failure. Every test reads state through the
    /// public `screen()`, so none of them can pass on a machine whose renderer would
    /// be handed something else.
    fn question(quiz: &Quiz) -> (ui::QuizWord, [&'static str; QUIZ_OPTIONS]) {
        match quiz.screen() {
            Screen::Word { question, options } => (question, options),
            Screen::Passed { .. } => panic!("expected a question"),
        }
    }

    /// The answer to what is on the glass, derived from the SCREEN's own word number
    /// and the fixture — never from `Quiz::truth`, which is the thing under test. A
    /// machine that scored a different position than it printed would fail here.
    fn answer(words: &[&'static str; ui::BACKUP_WORDS], q: &ui::QuizWord) -> &'static str {
        words
            .get(q.number.wrapping_sub(1))
            .copied()
            .expect("the screen names a word of the share")
    }

    /// Press the key beside the true word.
    fn press_right(
        quiz: &mut Quiz,
        rng: &mut Seeded,
        words: &[&'static str; ui::BACKUP_WORDS],
    ) -> Step {
        let (q, options) = question(quiz);
        let truth = answer(words, &q);
        let slot = options
            .iter()
            .position(|option| *option == truth)
            .expect("the answer is on the screen");
        quiz.key(ui::QUIZ_KEYS[slot], rng)
    }

    /// Press the key beside a distractor.
    fn press_wrong(
        quiz: &mut Quiz,
        rng: &mut Seeded,
        words: &[&'static str; ui::BACKUP_WORDS],
    ) -> Step {
        let (q, options) = question(quiz);
        let truth = answer(words, &q);
        let slot = options
            .iter()
            .position(|option| *option != truth)
            .expect("two of the three are wrong");
        quiz.key(ui::QUIZ_KEYS[slot], rng)
    }

    /// Requirement 1: a third of the words, always including the last, in an order
    /// the second shuffle really randomises.
    #[test]
    fn the_quiz_asks_a_third_of_the_words_and_always_the_last() {
        assert_eq!(QUIZ_POSITIONS, 8, "Coldcard's limited = len(words) // 3");
        assert_eq!(QUIZ_POSITIONS, ui::BACKUP_WORDS / 3);
        let mut slots = [0usize; QUIZ_POSITIONS];
        let mut orders = std::collections::BTreeSet::new();
        for seed in 0..200 {
            let (quiz, ..) = fresh(seed);
            let mut seen = [false; ui::BACKUP_WORDS];
            for position in quiz.order {
                let position = usize::from(position);
                assert!(
                    position < ui::BACKUP_WORDS,
                    "position {position} is not a word"
                );
                assert!(!seen[position], "position {position} is asked twice");
                seen[position] = true;
            }
            let at = quiz
                .order
                .iter()
                .position(|p| usize::from(*p) == ui::BACKUP_WORDS - 1)
                .expect("the checksum word is always quizzed");
            slots[at] += 1;
            orders.insert(quiz.order);
        }
        for (slot, hits) in slots.iter().enumerate() {
            assert!(
                *hits > 0,
                "the last word never landed at question {slot}: the second shuffle is missing"
            );
        }
        assert!(
            orders.len() > 150,
            "the order barely varies: {}",
            orders.len()
        );
    }

    /// Requirement 2, the exact part: three distinct words, the answer among them
    /// exactly once, and the distractors drawn from where Coldcard draws them.
    #[test]
    fn every_triple_is_three_distinct_words_holding_the_answer_once() {
        for seed in 0..40 {
            let (mut quiz, mut rng, words) = fresh(seed);
            let mut triples = 0;
            let mut off_list = 0;
            loop {
                // The question and its two re-asks: every triple the machine draws
                // is checked, not just the first one at each position.
                for attempt in 0..3 {
                    let (q, options) = question(&quiz);
                    let truth = answer(&words, &q);
                    triples += 1;
                    for (i, option) in options.iter().enumerate() {
                        assert!(is_bip39(option), "{option} is not a BIP39 word");
                        for other in options.iter().skip(i + 1) {
                            assert!(option != other, "{option} is offered twice");
                        }
                    }
                    assert_eq!(
                        options.iter().filter(|option| **option == truth).count(),
                        1,
                        "the answer must be on the screen exactly once"
                    );
                    // Coldcard's first distractor comes from the user's OWN words, so
                    // at least one wrong option is always a word of this share.
                    assert!(
                        options
                            .iter()
                            .any(|option| *option != truth && words.contains(option)),
                        "no distractor came from the share's own words"
                    );
                    // ...and the second from the whole 2,048, which lands inside the
                    // share's own 25 only about 1.2% of the time.
                    if options
                        .iter()
                        .any(|option| *option != truth && !words.contains(option))
                    {
                        off_list += 1;
                    }
                    if attempt < 2 {
                        assert_eq!(press_wrong(&mut quiz, &mut rng, &words), Step::Redraw);
                    }
                }
                if press_right(&mut quiz, &mut rng, &words) == Step::Passed {
                    break;
                }
            }
            assert_eq!(triples, QUIZ_POSITIONS * 3, "three triples per position");
            assert!(
                off_list * 10 >= triples * 9,
                "only {off_list} of {triples} triples reached outside the share: the \
                 second distractor is not coming from the whole list"
            );
        }
    }

    /// Requirement 2, the placement half: the answer is uniform over the three
    /// slots. A picker that favours one slot teaches false confidence, and one that
    /// pins slot 0 is worse than no quiz at all.
    #[test]
    fn the_answer_lands_in_every_slot_uniformly() {
        let mut counts = [0usize; QUIZ_OPTIONS];
        let mut total = 0;
        // ONE rng for all 400 quizzes, so the samples come from disjoint stretches of
        // one stream instead of 400 streams that might overlap. Correlated draws
        // inflate the variance and would make this test either flaky or useless.
        let mut rng = Seeded::new(17);
        for salt in 0..400 {
            let words = share(salt);
            let mut quiz = Quiz::new(words, &mut rng).expect("a real share can be quizzed");
            loop {
                let (q, options) = question(&quiz);
                let truth = answer(&words, &q);
                let slot = options.iter().position(|o| *o == truth).expect("on screen");
                counts[slot] += 1;
                total += 1;
                if press_right(&mut quiz, &mut rng, &words) == Step::Passed {
                    break;
                }
            }
        }
        assert_eq!(total, 400 * QUIZ_POSITIONS);
        // 3,200 samples, so ~1,066 per slot with sigma 26.7: a 10% band is 4 sigma.
        // The seed is fixed, so this is measured rather than risked — and it fails
        // instantly for a picker that pins a slot (3200/0/0) or leans on one.
        let expected = total / QUIZ_OPTIONS;
        for (slot, hits) in counts.iter().enumerate() {
            assert!(
                hits * 10 > expected * 9 && hits * 10 < expected * 11,
                "the answer landed in slot {slot} {hits} times, expected ~{expected}"
            );
        }
    }

    /// Requirement 3: wrong -> banner -> the SAME position again, with the three
    /// drawn again. No advance, no lockout.
    #[test]
    fn a_wrong_answer_re_asks_the_same_position_with_fresh_options() {
        for seed in 0..40 {
            let (mut quiz, mut rng, words) = fresh(seed);
            let (before, was) = question(&quiz);
            assert!(!before.retry, "a first question is not a re-ask");
            assert_eq!(press_wrong(&mut quiz, &mut rng, &words), Step::Redraw);
            let (after, now) = question(&quiz);
            assert_eq!(
                after.number, before.number,
                "a miss must re-ask the same word"
            );
            assert_eq!(
                after.asked, before.asked,
                "and must not advance the progress"
            );
            assert!(after.retry, "the re-ask must say the last answer was wrong");
            assert!(
                now != was,
                "the re-ask kept the same three in the same slots: a second guess \
                 would be 1-in-2"
            );
            // The answer is still reachable, and getting it right clears the banner.
            assert_eq!(press_right(&mut quiz, &mut rng, &words), Step::Redraw);
            let (next, _) = question(&quiz);
            assert_eq!(next.asked, before.asked + 1);
            assert!(!next.retry, "a correct answer clears the banner");
        }
    }

    /// A miss costs a re-ask and nothing else: no attempt counter, so no number of
    /// them ends the quiz, advances it, or produces anything to report.
    #[test]
    fn wrong_answers_never_advance_and_never_end_the_quiz() {
        let (mut quiz, mut rng, words) = fresh(11);
        let (first, _) = question(&quiz);
        for _ in 0..100 {
            let step = press_wrong(&mut quiz, &mut rng, &words);
            assert_eq!(
                step,
                Step::Redraw,
                "a miss is a re-ask, never anything else"
            );
            let (q, _) = question(&quiz);
            assert_eq!(q.number, first.number);
            assert_eq!(q.asked, 0);
        }
        // And the quiz is still passable afterwards.
        for _ in 0..QUIZ_POSITIONS - 1 {
            assert_eq!(press_right(&mut quiz, &mut rng, &words), Step::Redraw);
        }
        assert_eq!(press_right(&mut quiz, &mut rng, &words), Step::Passed);
    }

    /// Requirement 7: exactly `QUIZ_POSITIONS` correct answers finish it, each about
    /// a different word, and a finished quiz is inert.
    #[test]
    fn the_quiz_passes_after_exactly_eight_correct_answers() {
        let (mut quiz, mut rng, words) = fresh(5);
        let mut asked_about = std::vec::Vec::new();
        for i in 0..QUIZ_POSITIONS {
            let (q, _) = question(&quiz);
            assert_eq!(q.asked, i, "the progress must be the question index");
            assert_eq!(q.total, QUIZ_POSITIONS);
            assert!((1..=ui::BACKUP_WORDS).contains(&q.number));
            asked_about.push(q.number);
            let step = press_right(&mut quiz, &mut rng, &words);
            if i + 1 == QUIZ_POSITIONS {
                assert_eq!(step, Step::Passed, "the last correct answer passes it");
            } else {
                assert_eq!(step, Step::Redraw, "question {i} must not end the quiz");
            }
        }
        assert_eq!(
            quiz.screen(),
            Screen::Passed {
                checked: QUIZ_POSITIONS
            }
        );
        asked_about.sort_unstable();
        asked_about.dedup();
        assert_eq!(
            asked_about.len(),
            QUIZ_POSITIONS,
            "a position was asked twice"
        );
        assert!(
            asked_about.contains(&ui::BACKUP_WORDS),
            "the checksum word must have been one of them"
        );
        // Inert: every byte, cancel and the answer keys included.
        let before = quiz.clone();
        for key in 0u8..=255 {
            assert_eq!(
                quiz.key(key, &mut rng),
                Step::Unchanged,
                "key {key} after passing"
            );
            assert!(quiz == before, "key {key} moved a passed quiz");
        }
    }

    /// Requirement 5: every key that is not an answer or a cancel changes NOTHING —
    /// not a panic, not a wrong selection — at every state the machine has.
    #[test]
    fn every_invalid_key_is_a_no_op_at_every_state() {
        let (fresh_quiz, mut rng, words) = fresh(3);
        // A first question, a re-ask, and the last question before passing.
        let mut retry = fresh_quiz.clone();
        assert_eq!(press_wrong(&mut retry, &mut rng, &words), Step::Redraw);
        let mut last = fresh_quiz.clone();
        for _ in 0..QUIZ_POSITIONS - 1 {
            assert_eq!(press_right(&mut last, &mut rng, &words), Step::Redraw);
        }
        for state in [fresh_quiz, retry, last] {
            for key in 0u8..=255 {
                if ui::QUIZ_KEYS.contains(&key) || key == keypad::KEY_CANCEL {
                    continue;
                }
                let mut probe = state.clone();
                assert_eq!(probe.key(key, &mut rng), Step::Unchanged, "key {key}");
                assert!(probe == state, "key {key} moved the state");
            }
        }
    }

    /// Cancel gives up from a question and from a re-ask — Coldcard's `x`
    /// (`seed.py:872-874`) — and reports nothing.
    #[test]
    fn cancel_gives_up_from_a_question_and_from_a_re_ask() {
        let (mut quiz, mut rng, words) = fresh(7);
        assert_eq!(quiz.clone().key(keypad::KEY_CANCEL, &mut rng), Step::Abort);
        assert_eq!(press_wrong(&mut quiz, &mut rng, &words), Step::Redraw);
        assert!(question(&quiz).0.retry);
        assert_eq!(quiz.key(keypad::KEY_CANCEL, &mut rng), Step::Abort);
    }

    /// The one thing Coldcard's quiz offers that this one refuses: `y` re-showing
    /// the whole seed (`seed.py:879-881`). That would be a full reveal reachable
    /// from a screen whose consent was taken for a quiz.
    #[test]
    fn the_pad_ok_key_does_not_show_the_words_again() {
        let (mut quiz, mut rng, _) = fresh(2);
        let before = quiz.clone();
        assert_eq!(quiz.key(keypad::KEY_OK, &mut rng), Step::Unchanged);
        assert!(quiz == before);
    }

    /// Every screen this machine produces is one `ui` will actually DRAW.
    ///
    /// `backup_quiz_word` refuses a word number outside 1..=25, a progress pair that
    /// cannot be true, and any option that is not BIP39-shaped; `backup_quiz_passed`
    /// refuses a count outside 1..=25. A refusal on any of them would put
    /// `ui::refusal` on the glass instead of the question, and the quiz would be
    /// unanswerable. This is the two halves of the seam meeting on the state
    /// machine's own output — the cross-crate class this tree has been bitten by
    /// twice.
    #[test]
    fn every_screen_the_machine_produces_is_renderable() {
        let mut frame = ui::Frame::new();
        for seed in 0..12 {
            let (mut quiz, mut rng, words) = fresh(seed);
            loop {
                match quiz.screen() {
                    Screen::Word { question, options } => {
                        assert!(
                            ui::backup_quiz_word(&mut frame, question, options, &mut rng).is_ok(),
                            "unrenderable question {question:?}"
                        );
                    }
                    Screen::Passed { checked } => {
                        assert!(ui::backup_quiz_passed(&mut frame, checked).is_ok());
                        break;
                    }
                }
                // A miss first, so the retry banner's frame is drawn too.
                assert_eq!(press_wrong(&mut quiz, &mut rng, &words), Step::Redraw);
                let (q, options) = question(&quiz);
                assert!(q.retry);
                assert!(ui::backup_quiz_word(&mut frame, q, options, &mut rng).is_ok());
                let _ = press_right(&mut quiz, &mut rng, &words);
            }
        }
    }

    /// Fail-closed at the boundary: words this cannot quiz honestly get no quiz.
    #[test]
    fn a_share_this_cannot_quiz_honestly_gets_no_quiz() {
        let mut rng = Seeded::new(1);
        // 25 of one word: no own-set distractor exists at any position.
        assert!(Quiz::new([BIP39_WORDS[0]; ui::BACKUP_WORDS], &mut rng).is_none());
        // Two distinct words are enough, and the quiz is passable.
        let mut two = [BIP39_WORDS[0]; ui::BACKUP_WORDS];
        two[ui::BACKUP_WORDS - 1] = BIP39_WORDS[1];
        let mut quiz = Quiz::new(two, &mut rng).expect("two distinct words can be quizzed");
        for _ in 0..QUIZ_POSITIONS - 1 {
            assert_eq!(press_right(&mut quiz, &mut rng, &two), Step::Redraw);
        }
        assert_eq!(press_right(&mut quiz, &mut rng, &two), Step::Passed);
        // Not a word at all, and a lowercase one — the vendored list is uppercase,
        // and a word that cannot be rendered cannot be quizzed.
        for bad in ["notaword", "abandon", "", "ABANDONED"] {
            let mut words = share(9);
            words[7] = bad;
            assert!(
                Quiz::new(words, &mut rng).is_none(),
                "{bad:?} must not be quizzable"
            );
        }
        assert!(is_bip39("ABANDON"));
        assert!(!is_bip39("abandon"));
    }

    /// The primitive everything above rests on: in range, unbiased enough for slot
    /// placement, and no bound can make it hang or panic.
    #[test]
    fn the_bounded_draw_stays_in_range() {
        let mut rng = Seeded::new(4);
        assert_eq!(
            below(0, &mut rng),
            0,
            "a zero bound has no member to return"
        );
        assert_eq!(below(1, &mut rng), 0);
        assert_eq!(
            below(usize::MAX, &mut rng),
            0,
            "an over-u32 bound is refused"
        );
        for bound in [2usize, 3, 7, 25, 2048] {
            let mut counts = std::vec![0usize; bound];
            for _ in 0..bound * 200 {
                let draw = below(bound, &mut rng);
                assert!(draw < bound, "{draw} is not below {bound}");
                counts[draw] += 1;
            }
            let low = counts.iter().min().copied().unwrap_or(0);
            let high = counts.iter().max().copied().unwrap_or(0);
            assert!(
                low > 100 && high < 320,
                "bound {bound}: {low}..{high} per value"
            );
        }
    }

    /// A `Debug` line must not be able to print a share word. The screen's impl is
    /// manual for exactly this, and `Step` has no payload to leak.
    #[test]
    fn no_debug_output_holds_a_word() {
        let (mut quiz, mut rng, words) = fresh(6);
        for _ in 0..QUIZ_POSITIONS {
            let printed = std::format!(
                "{:?} {:?} {:?}",
                quiz.screen(),
                Step::Passed,
                Step::Unchanged
            );
            for word in words {
                assert!(
                    !printed.contains(word),
                    "{word} reached a Debug line: {printed}"
                );
            }
            let _ = press_right(&mut quiz, &mut rng, &words);
        }
        // The passed screen too, which is the one a caller is most likely to log.
        assert_eq!(
            std::format!("{:?}", quiz.screen()),
            std::format!("Passed({QUIZ_POSITIONS})")
        );
    }
}

//! Typing a 25-word share back IN: the pure `(state, key) -> state` machine
//! behind [`ui::WordEntry`].
//!
//! cold-snap can emit a backup (`DisplayBackup`) and could not ingest one, and
//! upstream has no host-side restore to fall back on — its only protocol sends
//! `CoordinatorRestoration::EnterPhysicalBackup` and the words are typed **on the
//! device, by design** (`frostsnap_coordinator/src/enter_physical_backup.rs`), so
//! the words never touch the host. This module is the device half of that: the
//! keypress map, and nothing else.
//!
//! # Why it is its own module, and pure
//!
//! No I/O, no RNG, no registers, no `cfg(target_arch)`, no clock, no allocation.
//! Every one of the 2,048 words is driven through the public API by its own
//! letters in this file's tests, which is only possible because the whole thing is
//! a function of (state, key). `Session` owns the two impure touchpoints — the
//! consent that grants an [`Entry`] and the `tell_coordinator_about_backup_load_result`
//! that consumes a [`Step::Entered`] — and `ui` owns the glass.
//!
//! # The keypress map, and why it is not Coldcard's
//!
//! The valid next letters for the typed prefix are numbered and shown;
//! [`ui::ENTRY_LETTER_KEYS`] pick one, [`ui::ENTRY_PAGE_KEY`] pages when there are
//! more than nine, [`ui::ENTRY_DELETE_KEY`] deletes **one letter**, and
//! [`ui::ENTRY_OK_KEY`] accepts once the prefix is unique or is itself a word.
//! Coldcard's own mechanism (`shared/seed.py:56-108`, a prefix-narrowing nest
//! menu) was read and rejected: its `on_cancel` (`seed.py:276-291`) does
//! `words.pop()`, so `x` discards the whole committed word and restarts it — there
//! is no character backspace. Simulated over the real vendored list, that costs a
//! mean 11.64 presses per word (291 per share, 675 worst) against this map's 5.69
//! (142 per share, 225 worst), and a typo there loses a word where here it loses a
//! letter. Both figures are simulations of an optimal typist, not hardware
//! observations; `the_press_count_over_the_whole_wordlist_is_pinned` holds this
//! side's number.
//!
//! # Nothing is discarded, ever
//!
//! `Entry`'s word array is 25 slots and not a stack, so walking back to word 12
//! to fix a typo keeps words 13..25 and re-accepting an unchanged word is one
//! press. A checksum failure keeps all 25 (see `Stage::Failed`). A half-built
//! restore that loses 24 correct words on the 25th is worse than a refusal, and
//! this is the property that avoids it.
//!
//! # No timeout, deliberately
//!
//! Nothing here expires and there is no clock in this module to expire against.
//! Transcribing 25 words is slow, and a screen that blanks mid-flow costs a second
//! full disclosure of the same secret. That is a chosen property, the same one
//! `ui::WordEntry` and the reveal path record.
//!
//! # Heap
//!
//! Nothing in this module allocates. [`Entry`] is one fixed-size struct (~250 B on
//! 32-bit) that lives wherever `Session` puts it; the narrowing primitives return a
//! subslice of the static wordlist and a 27-byte `Copy` value; and
//! `ShareBackup::from_words` allocates only in its `InvalidBip39Word` arm, which
//! this machine cannot reach because every word it submits came out of
//! `BIP39_WORDS`. The one heap cost of the whole restore flow is upstream's
//! `tmp_loaded_backups` insert, on `Session`'s side of the seam.
//!
//! # No `Debug`, anywhere on this path
//!
//! `{:?}` on a `ShareBackup` prints the share scalar in hex (secp256kfun's
//! `impl_debug` has no redaction for the `Secret` marker) and its `Display` prints
//! all 25 words. So neither [`Entry`] nor [`Step`] derives `Debug`, a checksum
//! failure is payload-free — `ShareBackupError::InvalidBip39Word` would carry a
//! word — and nothing here formats anything.

use coldsnap_hal::ui;
use frost_backup::bip39_words::{get_valid_next_letters, words_with_prefix};
use frost_backup::{ShareBackup, NUM_WORDS};
use frostsnap_core::EnterPhysicalId;

const _: () = {
    // The two halves of "25 words" come from different crates: the screens count
    // in `ui::BACKUP_WORDS`, the checksum in `frost_backup::NUM_WORDS`. This module
    // is where they meet, so this is where a divergence has to be a build failure.
    assert!(
        ui::BACKUP_WORDS == NUM_WORDS,
        "the screens and the checksum must agree on the word count"
    );
    // Every letter the machine offers is placed on a key by `slot`, and every key
    // it accepts is one the screen printed a ruler digit for. A candidate list
    // wider than one page is reachable (25 letters at the empty prefix), which is
    // what `ui::ENTRY_PAGE_KEY` is for; a *page* wider than the key row would not
    // be.
    assert!(
        ui::ENTRY_LETTER_KEYS.len() == ui::ENTRY_LETTERS_PER_PAGE,
        "one letter key per candidate slot"
    );
};

/// A fixed-capacity buffer that can hold **uppercase ASCII letters only**.
///
/// This is trap (a), closed by construction rather than by a validator.
/// `BIP39_WORDS` is uppercase and `ValidLetters::letter_to_index` accepts
/// `'A'..='Z'` only, so a lowercase prefix yields an *empty candidate set with no
/// error* — a dead keypad. A near-identical mismatch already shipped once
/// (`ui::check_word` demanded lowercase and refused every real share), and it
/// shipped because both halves compiled. Here the only writers are [`Self::push`],
/// which rejects anything outside `'A'..='Z'`, and [`Self::load`], which is
/// [`Self::push`] in a loop and leaves the buffer EMPTY rather than partly filled
/// if any character is refused. There is no `&str` setter and no lowercase literal
/// in this file.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Uppercase<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> Uppercase<N> {
    const fn new() -> Self {
        Uppercase {
            buf: [0u8; N],
            len: 0,
        }
    }

    /// The contents. Always valid UTF-8, because only `'A'..='Z'` is ever stored —
    /// and `unwrap_or("")` rather than `expect`, because a panic on this unit is a
    /// permanent brick (RDP=2, no DFU) and an empty field is a state the screen
    /// already draws.
    fn as_str(&self) -> &str {
        self.buf
            .get(..self.len)
            .and_then(|b| core::str::from_utf8(b).ok())
            .unwrap_or("")
    }

    fn clear(&mut self) {
        self.len = 0;
    }

    /// Append one letter. `false` if it is not `'A'..='Z'` or there is no room.
    fn push(&mut self, letter: char) -> bool {
        if !letter.is_ascii_uppercase() {
            return false;
        }
        match self.buf.get_mut(self.len) {
            Some(slot) => {
                *slot = letter as u8;
                self.len += 1;
                true
            }
            None => false,
        }
    }

    /// Drop the last letter. `false` if there was none.
    fn pop(&mut self) -> bool {
        match self.len.checked_sub(1) {
            Some(shorter) => {
                self.len = shorter;
                true
            }
            None => false,
        }
    }

    /// Replace the contents with `word`, or leave the buffer EMPTY and return
    /// `false` — which is what a lowercase or over-long word gets. Empty is a state
    /// the screen draws honestly (a fresh field the user retypes); a half-loaded
    /// word would not be.
    fn load(&mut self, word: &str) -> bool {
        self.clear();
        for c in word.chars() {
            if !self.push(c) {
                self.clear();
                return false;
            }
        }
        true
    }
}

/// Which field the machine is on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Stage {
    /// The share index. Public, so its screen is not noised, and word entry is
    /// gated behind it exactly as upstream gates it (`share_index_confirmed`,
    /// `frostsnap_widgets/src/backup/backup_model.rs:100-101,167-171`).
    Index,
    /// A word.
    Word,
    /// All 25 words are in and the checksum refused them.
    ///
    /// **All 25 are still held.** The 11-bit words checksum *is* word 25 and is a
    /// SHA-256 over the index, the whole scalar and the polynomial checksum
    /// (`frost_backup/src/share_backup.rs:25,31,119-122`), so one wrong word
    /// anywhere yields one verdict and there is no per-word syndrome to build. The
    /// device therefore cannot name a position and must not pretend to; any key
    /// returns to word 25 so the user can walk back through all of them against the
    /// paper.
    Failed,
}

/// What the caller must do about a keypress.
///
/// No `Debug`: [`Step::Entered`] carries a share. See the module docs.
#[derive(Clone, PartialEq)]
#[must_use]
pub enum Step {
    /// The key did nothing. **Do not redraw.** Every invalid key lands here, and
    /// so does a valid key with nothing to do (paging a single-page list, deleting
    /// an empty index digit-wise). Not redrawing is also what keeps
    /// `Frame::mark_sensitive`'s noise from being re-sampled over an unchanged
    /// share row.
    Unchanged,
    /// The state changed. Draw [`Entry::screen`].
    Redraw,
    /// The user backed out of the whole flow: drop the [`Entry`] and send nothing.
    ///
    /// Silence is the honest wire behaviour, not a gap — `DeviceRestoration` has no
    /// message for an abandoned entry and upstream's coordinator ends the dialog
    /// on its own `cancel()` (`frostsnap_coordinator/src/enter_physical_backup.rs`).
    Abort,
    /// 25 words that pass the checksum. Hand this to
    /// `tell_coordinator_about_backup_load_result` with
    /// `EnterBackupPhase { enter_physical_id: entry.enter_physical_id() }` and drop
    /// the [`Entry`].
    Entered(ShareBackup),
}

/// The variant NAME and nothing else.
///
/// Manual, and that is the point: `#[derive(Debug)]` on [`Step::Entered`] would
/// print the share scalar in hex, because secp256kfun's `impl_debug` formats "the
/// type as hex and any markers on the type" with no redaction for `Secret`. A
/// manual impl also makes a later `derive` a compile error rather than a silent
/// leak. It exists so `assert_eq!` in the tests can name a step; nothing on the
/// device formats one.
impl core::fmt::Debug for Step {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Step::Unchanged => "Unchanged",
            Step::Redraw => "Redraw",
            Step::Abort => "Abort",
            Step::Entered(_) => "Entered(<share>)",
        })
    }
}

/// What to put on the glass. Borrowed from the [`Entry`], so nothing here is a
/// copy of a share.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Screen<'a> {
    /// The share-index page: `ui::EntryPage::ShareIndex`, whose `partial` is
    /// `typed` in decimal (`ui::Buf::push_u64`) or `""` when nothing is typed. Not
    /// noised — the index is public.
    ShareIndex {
        /// The accumulated index, or `None` when nothing has been typed.
        typed: Option<u32>,
    },
    /// A word page, ready to render. Every field the arithmetic in [`Entry::key`]
    /// used is in here, so the ruler the user reads and the key the machine decodes
    /// come from one value.
    Word(ui::WordEntry<'a>),
    /// The checksum refused the 25 words. Payload-free deliberately: the device
    /// does not know which word is wrong (see `Stage::Failed`) and
    /// `ShareBackupError` would carry a word. Draw "checksum failed / check your
    /// words"; any key returns to word 25.
    Failed,
}

/// The whole state of typing one share back in.
///
/// No `Debug` — see the module docs.
#[derive(Clone, PartialEq)]
pub struct Entry {
    /// The coordinator's id for this entry, carried so the completion can name it.
    /// Public data, 16 bytes.
    id: EnterPhysicalId,
    stage: Stage,
    /// The share index accumulated from digits, `0` meaning "nothing typed".
    /// A `u32` and not a digit buffer, so there is no second field to desync.
    index: u32,
    /// The accepted words. An array and not a stack: that is what lets the cursor
    /// walk back to word 12 without destroying 13..25. Always entries of
    /// `BIP39_WORDS`, since [`Entry::accept`] is the only writer.
    words: [Option<&'static str>; ui::BACKUP_WORDS],
    /// Which word is being edited, `0..ui::BACKUP_WORDS`.
    cursor: usize,
    /// The letters typed for [`Entry::cursor`], uppercase by construction.
    prefix: Uppercase<{ ui::MAX_WORD_LEN }>,
    /// Every letter that may follow [`Entry::prefix`], from
    /// `get_valid_next_letters`. Derived state, written **only** by
    /// [`Entry::refresh`], so it cannot go stale against the prefix.
    letters: Uppercase<{ ui::MAX_CANDIDATE_LETTERS }>,
    /// Which page of [`ui::ENTRY_LETTERS_PER_PAGE`] letters is showing, already
    /// reduced below the page count. Kept normalised (rather than reduced at every
    /// use) so no arithmetic here can wrap under `overflow-checks = false`.
    page: usize,
}

impl Entry {
    /// A fresh entry for the coordinator's `EnterBackupPhase`, on the share-index
    /// page.
    ///
    /// The caller must already have taken consent on the rendered `ConfirmDigit`:
    /// this flow ingests a secret, and the digit is the gate.
    pub fn new(id: EnterPhysicalId) -> Self {
        let mut entry = Entry {
            id,
            stage: Stage::Index,
            index: 0,
            words: [None; ui::BACKUP_WORDS],
            cursor: 0,
            prefix: Uppercase::new(),
            letters: Uppercase::new(),
            page: 0,
        };
        entry.refresh();
        entry
    }

    /// The coordinator's id for this entry, for the completion message.
    pub fn enter_physical_id(&self) -> EnterPhysicalId {
        self.id
    }

    /// What to draw.
    pub fn screen(&self) -> Screen<'_> {
        match self.stage {
            Stage::Index => Screen::ShareIndex {
                typed: (self.index > 0).then_some(self.index),
            },
            Stage::Word => Screen::Word(self.word_entry()),
            Stage::Failed => Screen::Failed,
        }
    }

    /// One keypress, as the byte `keypad::Event::Down` reports.
    ///
    /// Total: every one of the 256 bytes is handled at every state, and anything
    /// that is not a live key is [`Step::Unchanged`]. That is why the letter keys
    /// are looked up in [`ui::ENTRY_LETTER_KEYS`] and the candidate is fetched with
    /// `get` — with four candidates, `7` must do *nothing*, and under
    /// `overflow-checks = false` an unbounded index would wrap rather than panic.
    pub fn key(&mut self, key: u8) -> Step {
        match self.stage {
            Stage::Index => self.index_key(key),
            Stage::Word => self.word_key(key),
            // Payload-free, so there is nothing to acknowledge: any key goes back
            // to the last word with all 25 still held.
            Stage::Failed => {
                self.stage = Stage::Word;
                self.go_to(ui::BACKUP_WORDS - 1)
            }
        }
    }

    // -- the share index ----------------------------------------------------

    /// `ui::ENTRY_PAGE_KEY` is `0`, which on this screen is the DIGIT zero: the
    /// share-index page draws no paging legend because it has no candidate letters,
    /// so the digit arm comes first and there is no page to turn.
    fn index_key(&mut self, key: u8) -> Step {
        match key {
            b'0'..=b'9' => {
                let digit = u32::from(key - b'0');
                // CHECKED, not `* 10 + d`: `overflow-checks = false` in release
                // means the 11th digit would silently wrap ("9999999999" ->
                // 1410065407) and the device would ingest a different share index
                // than the human typed. `from_words` only rejects zero.
                match self
                    .index
                    .checked_mul(10)
                    .and_then(|shifted| shifted.checked_add(digit))
                {
                    // A leading `0` leaves the accumulator at 0, i.e. nothing was
                    // typed and nothing changed.
                    Some(index) if index != self.index => {
                        self.index = index;
                        Step::Redraw
                    }
                    _ => Step::Unchanged,
                }
            }
            ui::ENTRY_OK_KEY if self.index > 0 => {
                self.stage = Stage::Word;
                self.go_to(0)
            }
            ui::ENTRY_DELETE_KEY if self.index > 0 => {
                self.index /= 10;
                Step::Redraw
            }
            // An empty index is the one place with nothing behind it.
            ui::ENTRY_DELETE_KEY => Step::Abort,
            _ => Step::Unchanged,
        }
    }

    // -- a word -------------------------------------------------------------

    fn word_key(&mut self, key: u8) -> Step {
        if let Some(letter) = self.slot(key) {
            return if self.prefix.push(letter) {
                self.refresh();
                Step::Redraw
            } else {
                // No room: unreachable, since no 8-letter BIP39 word has a
                // candidate letter after it. An arm and not an `expect`.
                Step::Unchanged
            };
        }
        match key {
            ui::ENTRY_PAGE_KEY => {
                let pages = self.pages();
                if pages > 1 {
                    // Bounded by construction: `page` is always below `pages`, and
                    // `ui::WordEntry::render` reduces it the same way, so the ruler
                    // the user reads is the page `slot` decodes against.
                    self.page = (self.page + 1) % pages;
                    Step::Redraw
                } else {
                    Step::Unchanged
                }
            }
            ui::ENTRY_DELETE_KEY => {
                if self.prefix.pop() {
                    self.refresh();
                    Step::Redraw
                } else if let Some(previous) = self.cursor.checked_sub(1) {
                    // The accepted word STAYS in its slot; the cursor merely moves
                    // onto it. Nothing is discarded here or anywhere else.
                    self.go_to(previous)
                } else {
                    // Back out of word 1 to the share index, which is the only way
                    // to fix a mistyped index without losing the words already in.
                    // `Abort` is one further press, on an empty index.
                    self.stage = Stage::Index;
                    Step::Redraw
                }
            }
            ui::ENTRY_OK_KEY => match self.accept() {
                Some(word) => {
                    self.words[self.cursor] = Some(word);
                    match self.cursor + 1 {
                        next if next < ui::BACKUP_WORDS => self.go_to(next),
                        _ => self.submit(),
                    }
                }
                None => Step::Unchanged,
            },
            _ => Step::Unchanged,
        }
    }

    /// The letter `key` selects on the page now showing, or `None` if that key is
    /// not a letter key or the page is short (a 25-letter list is 3 pages of 9, 9
    /// and 7, so `8` and `9` on the last page must do nothing rather than select
    /// something).
    ///
    /// The one piece of start-of-page arithmetic on this side of the seam, and it
    /// reads the same `letters` string [`Self::word_entry`] hands the renderer to
    /// draw its ruler from — an expression worth guarding is an expression worth
    /// making a function.
    fn slot(&self, key: u8) -> Option<char> {
        if self.stage != Stage::Word {
            return None;
        }
        let index = ui::ENTRY_LETTER_KEYS.iter().position(|&k| k == key)?;
        let start = self.page * ui::ENTRY_LETTERS_PER_PAGE;
        self.letters
            .as_str()
            .as_bytes()
            .get(start + index)
            .map(|&b| char::from(b))
    }

    /// The word [`ui::ENTRY_OK_KEY`] would commit: the prefix's sole completion, or
    /// the prefix itself when it is a word.
    ///
    /// This is trap (b). **49 BIP39 words are proper prefixes of longer words** —
    /// `ACT`, `ADD`, `AGE`, `AIR`, `ALL`, `ARM`, ... — so a machine that accepts
    /// only at uniqueness cannot enter any of them, and one that accepts only whole
    /// words costs 7.45 presses per word instead of 5.69. Both predicates are
    /// needed, they are genuinely different (`ACT` is a word AND has four
    /// candidates), and together they are unambiguous: an accept is either the
    /// prefix itself or the only word that starts with it.
    fn accept(&self) -> Option<&'static str> {
        self.unique().or_else(|| self.whole_word())
    }

    /// The sole word starting with the prefix, if there is exactly one. This half is
    /// where the press count comes from: `ABA` commits ABANDON.
    fn unique(&self) -> Option<&'static str> {
        match words_with_prefix(self.prefix.as_str()) {
            [only] => Some(only),
            _ => None,
        }
    }

    /// The prefix itself, if it is a word. `words_with_prefix` returns the sorted
    /// block starting at the prefix, so the prefix — being the shortest string with
    /// itself as a prefix — is that block's first entry when it is in the list.
    /// Empty prefixes fall out here too, since `""` is not a word.
    fn whole_word(&self) -> Option<&'static str> {
        let prefix = self.prefix.as_str();
        words_with_prefix(prefix)
            .first()
            .copied()
            .filter(|word| *word == prefix)
    }

    /// The page count, from `ui::WordEntry::pages` itself so the two cannot
    /// disagree about where page 2 starts.
    fn pages(&self) -> usize {
        self.word_entry().pages()
    }

    /// The word page as the renderer will receive it.
    fn word_entry(&self) -> ui::WordEntry<'_> {
        ui::WordEntry {
            number: self.cursor + 1,
            partial: self.prefix.as_str(),
            previous: self
                .cursor
                .checked_sub(1)
                .and_then(|previous| self.words[previous]),
            candidates: self.letters.as_str(),
            page: self.page,
            complete: self.accept().is_some(),
        }
    }

    /// Move onto word `cursor` and load whatever is in its slot.
    fn go_to(&mut self, cursor: usize) -> Step {
        self.cursor = cursor.min(ui::BACKUP_WORDS - 1);
        match self.words[self.cursor] {
            // A word out of `BIP39_WORDS`, so `load` cannot refuse it; if it ever
            // did, the field would be empty and the user retypes it.
            Some(word) => {
                self.prefix.load(word);
            }
            None => self.prefix.clear(),
        }
        self.refresh();
        Step::Redraw
    }

    /// Recompute the candidate letters for the prefix and reset the page.
    ///
    /// The **only** writer of `letters`, and every prefix change goes through it, so
    /// the two cannot desync — and the page reset is here rather than at the call
    /// sites because a shorter list with a stale page would put the renderer on
    /// page 0 while `slot` decoded against page 2.
    fn refresh(&mut self) {
        self.letters.clear();
        for letter in get_valid_next_letters(self.prefix.as_str()).iter_valid() {
            self.letters.push(letter);
        }
        self.page = 0;
    }

    /// All 25 words are in: check them.
    fn submit(&mut self) -> Step {
        if let Some(missing) = self.words.iter().position(|word| word.is_none()) {
            // Unreachable — the cursor only advances past a slot it has just
            // filled — but a total arm, not an `expect`.
            return self.go_to(missing);
        }
        let mut words = [""; ui::BACKUP_WORDS];
        for (slot, word) in words.iter_mut().zip(self.words.iter()) {
            *slot = word.unwrap_or("");
        }
        match ShareBackup::from_words(self.index, words) {
            Ok(backup) => Step::Entered(backup),
            // The error is DROPPED, not carried: `InvalidBip39Word` holds a word,
            // and every `Debug` line is a leak. It also cannot localise the fault
            // (see `Stage::Failed`), so there is nothing to carry.
            Err(_) => {
                self.stage = Stage::Failed;
                Step::Redraw
            }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use frost_backup::bip39_words::BIP39_WORDS;
    use std::vec::Vec;

    fn fresh() -> Entry {
        Entry::new(EnterPhysicalId([7u8; 16]))
    }

    /// The word page now showing, or a failure — every test reads state through
    /// the public `screen()`, so none of them can pass on a machine whose renderer
    /// would be handed something else.
    fn page(entry: &Entry) -> ui::WordEntry<'_> {
        match entry.screen() {
            Screen::Word(word) => word,
            _ => panic!("expected a word page"),
        }
    }

    /// Press the digits of `index` and accept, leaving the machine on word 1.
    fn press_index(entry: &mut Entry, index: u32) {
        let mut digits = Vec::new();
        let mut left = index;
        while left > 0 {
            digits.push(b'0' + (left % 10) as u8);
            left /= 10;
        }
        for digit in digits.iter().rev() {
            assert!(entry.key(*digit) != Step::Unchanged, "a digit must land");
        }
        assert!(entry.key(ui::ENTRY_OK_KEY) != Step::Unchanged);
    }

    /// Type `word` letter by letter through the public API, paging when the letter
    /// is not on the page showing, and accept it. Returns the presses spent.
    ///
    /// This is the honest driver: it can only press keys the screen advertises, so
    /// a letter the ruler does not reach is an unreachable letter and a panic here.
    fn press_letter(entry: &mut Entry, wanted: u8) -> usize {
        let mut presses = 0;
        loop {
            let showing = page(entry);
            let pages = showing.pages();
            let start = showing.page * ui::ENTRY_LETTERS_PER_PAGE;
            let on_page = showing
                .candidates
                .as_bytes()
                .iter()
                .skip(start)
                .take(ui::ENTRY_LETTERS_PER_PAGE)
                .position(|&letter| letter == wanted);
            if let Some(index) = on_page {
                let key = ui::ENTRY_LETTER_KEYS[index];
                assert_eq!(entry.key(key), Step::Redraw, "key {key} was dead");
                return presses + 1;
            }
            assert!(
                presses < pages,
                "{} is on no page of {:?}",
                wanted as char,
                showing.candidates
            );
            assert_eq!(entry.key(ui::ENTRY_PAGE_KEY), Step::Redraw);
            presses += 1;
        }
    }

    fn press_letters(entry: &mut Entry, letters: &str, early: bool) -> usize {
        assert!(
            page(entry).partial.is_empty(),
            "the driver types from an empty field"
        );
        let mut presses = 0;
        for wanted in letters.bytes() {
            // Accepting at uniqueness is where the press count comes from, so the
            // driver stops as soon as the machine could commit this exact word —
            // `complete` alone would be wrong, because BUS is complete on the way
            // to BUSY.
            if early && (page(entry).partial == letters || entry.unique() == Some(letters)) {
                break;
            }
            presses += press_letter(entry, wanted);
        }
        presses
    }

    /// Type `word` the way an optimal user would: letters until the machine could
    /// commit that exact word. Does not accept — the caller does.
    fn press_word(entry: &mut Entry, word: &str) -> usize {
        press_letters(entry, word, true)
    }

    /// Type every letter of `prefix`, past uniqueness. This is how the tests reach
    /// a *particular* prefix rather than the shortest one that names a word.
    fn press_prefix(entry: &mut Entry, prefix: &str) -> usize {
        press_letters(entry, prefix, false)
    }

    /// A checksum-valid 25-word backup, found by SEARCH rather than generated: the
    /// 11-bit words checksum is exactly word 25, so for any first 24 words there is
    /// exactly one word 25 that completes them. No RNG, no polynomial, and the
    /// result is a real `ShareBackup` upstream's own decoder accepts.
    fn valid_backup(salt: usize) -> (u32, [&'static str; ui::BACKUP_WORDS]) {
        let index = 1 + salt as u32;
        let mut words = [""; ui::BACKUP_WORDS];
        for (slot, i) in words.iter_mut().zip(0..) {
            *slot = BIP39_WORDS[(salt * 101 + i * 37) % BIP39_WORDS.len()];
        }
        for candidate in BIP39_WORDS.iter() {
            words[ui::BACKUP_WORDS - 1] = candidate;
            if ShareBackup::from_words(index, words).is_ok() {
                return (index, words);
            }
        }
        panic!("an 11-bit checksum is completed by one of 2048 words");
    }

    /// Drive a whole share in and return what the machine did with it.
    fn press_share(index: u32, words: &[&'static str; ui::BACKUP_WORDS]) -> Step {
        let mut entry = fresh();
        press_index(&mut entry, index);
        let mut step = Step::Unchanged;
        for (number, word) in words.iter().enumerate() {
            press_word(&mut entry, word);
            step = entry.key(ui::ENTRY_OK_KEY);
            assert!(step != Step::Unchanged, "word {number} would not accept");
        }
        step
    }

    /// The words that are proper prefixes of a longer word — trap (b)'s 49.
    fn prefix_words() -> Vec<&'static str> {
        BIP39_WORDS
            .iter()
            .copied()
            .filter(|word| words_with_prefix(word).len() > 1)
            .collect()
    }

    /// EVERY word in the vendored list, typed by its own letters and accepted.
    ///
    /// This is the test the two traps cannot survive: it fails instantly if the
    /// prefix is lowercased anywhere (the candidate set goes empty), if `y` needs
    /// uniqueness (49 words become unenterable), if the page stride or the
    /// candidate index is off by one, or if a letter key is decoded against a
    /// different page than the ruler was drawn from.
    #[test]
    fn every_vendored_bip39_word_is_enterable() {
        for word in BIP39_WORDS.iter() {
            let mut entry = fresh();
            press_index(&mut entry, 3);
            press_word(&mut entry, word);
            assert!(
                page(&entry).complete,
                "{word}: the accept key is dead on its own letters"
            );
            assert_eq!(entry.key(ui::ENTRY_OK_KEY), Step::Redraw);
            assert_eq!(entry.words[0], Some(*word), "{word} was not what committed");
            assert_eq!(page(&entry).number, 2, "{word}: the cursor did not advance");
        }
    }

    /// Trap (b), named: all 49 words that are prefixes of longer words, accepted
    /// while longer candidates are still on the screen.
    #[test]
    fn all_forty_nine_prefix_words_are_enterable() {
        let words = prefix_words();
        assert_eq!(words.len(), 49, "the vendored list's prefix words");
        for word in words {
            let mut entry = fresh();
            press_index(&mut entry, 1);
            press_word(&mut entry, word);
            let showing = page(&entry);
            assert_eq!(showing.partial, word);
            assert!(
                !showing.candidates.is_empty(),
                "{word} is a prefix, so longer words must still be offered"
            );
            assert!(showing.complete, "{word} is a word and must accept");
            assert_eq!(entry.key(ui::ENTRY_OK_KEY), Step::Redraw);
            assert_eq!(entry.words[0], Some(word));
        }
    }

    /// The press count, pinned. 5.69 mean / 9 worst is the number the design was
    /// chosen on (against Coldcard's simulated 11.64 / 27), so it is a number a
    /// regression may not quietly spend: a wrong page stride, a lost
    /// accept-at-unique or an extra page turn all move this total.
    #[test]
    fn the_press_count_over_the_whole_wordlist_is_pinned() {
        let mut total = 0;
        let mut worst = 0;
        for word in BIP39_WORDS.iter() {
            let mut entry = fresh();
            press_index(&mut entry, 1);
            // +1 for the accept, which the driver does not count.
            let presses = press_word(&mut entry, word) + 1;
            assert_eq!(entry.key(ui::ENTRY_OK_KEY), Step::Redraw);
            total += presses;
            worst = worst.max(presses);
        }
        assert_eq!(worst, 9, "the worst word must still be 9 presses");
        assert_eq!(total, 11656, "5.69 presses per word, measured");
    }

    /// Requirement 4, at every candidate count the wordlist produces: with four
    /// candidates, `7` must change NOTHING — not panic, not select candidate 0.
    #[test]
    fn an_invalid_key_is_a_no_op_at_every_candidate_count() {
        // One prefix per distinct candidate count, from 25 (empty) down to 1.
        let mut seen = [false; ui::MAX_CANDIDATE_LETTERS + 1];
        let mut counts = 0;
        for word in BIP39_WORDS.iter() {
            for len in 0..=word.len() {
                let mut entry = fresh();
                press_index(&mut entry, 1);
                press_prefix(&mut entry, &word[..len]);
                let candidates = page(&entry).candidates.len();
                if seen[candidates] {
                    continue;
                }
                seen[candidates] = true;
                counts += 1;
                let pages = page(&entry).pages();
                for turn in 0..pages {
                    if turn > 0 {
                        assert_eq!(entry.key(ui::ENTRY_PAGE_KEY), Step::Redraw);
                    }
                    let showing = page(&entry).page;
                    // The live keys are computed from what the SCREEN prints — the
                    // letters on this page — and never from `slot`, which is the
                    // function under test. Asking `slot` which keys are live is how
                    // a test blesses whatever the implementation does: a `slot` that
                    // wraps a page-3 key onto page 1 would report itself live and be
                    // skipped here.
                    let on_page = page(&entry)
                        .candidates
                        .len()
                        .saturating_sub(showing * ui::ENTRY_LETTERS_PER_PAGE)
                        .min(ui::ENTRY_LETTERS_PER_PAGE);
                    let live: Vec<u8> = ui::ENTRY_LETTER_KEYS[..on_page]
                        .iter()
                        .copied()
                        .chain([ui::ENTRY_OK_KEY, ui::ENTRY_DELETE_KEY, ui::ENTRY_PAGE_KEY])
                        .collect();
                    for key in 0u8..=255 {
                        if live.contains(&key) {
                            continue;
                        }
                        let before = entry.clone();
                        assert_eq!(
                            entry.key(key),
                            Step::Unchanged,
                            "key {key} at {candidates} candidates, page {showing}"
                        );
                        assert!(entry == before, "key {key} moved the state");
                    }
                }
            }
        }
        // 1..=25 candidates plus 0 (a finished 8-letter word).
        assert!(counts >= 20, "only {counts} distinct candidate counts seen");
    }

    /// The whole 256-byte keyspace against every prefix the wordlist can reach:
    /// nothing panics, no state change leaves a dead prefix, and the letters a
    /// screen offers are always exactly the letters that can follow it.
    #[test]
    fn no_key_at_any_reachable_prefix_leads_anywhere_dead() {
        for word in BIP39_WORDS.iter() {
            for len in 0..=word.len() {
                let mut entry = fresh();
                press_index(&mut entry, 1);
                press_prefix(&mut entry, &word[..len]);
                let prefix = page(&entry).partial;
                assert!(
                    !words_with_prefix(prefix).is_empty(),
                    "{prefix} is a dead prefix"
                );
                for key in 0u8..=255 {
                    let mut probe = entry.clone();
                    match probe.key(key) {
                        Step::Unchanged | Step::Abort => continue,
                        Step::Entered(_) => panic!("one word cannot finish a share"),
                        Step::Redraw => {}
                    }
                    if let Screen::Word(showing) = probe.screen() {
                        assert!(
                            !words_with_prefix(showing.partial).is_empty(),
                            "key {key} left the dead prefix {}",
                            showing.partial
                        );
                        assert!(showing.partial.len() <= ui::MAX_WORD_LEN);
                    }
                }
            }
        }
    }

    /// The paging boundary, at exactly 9 and exactly 10 candidates.
    #[test]
    fn the_page_boundary_is_at_nine_candidates() {
        let mut nine = None;
        let mut ten = None;
        for word in BIP39_WORDS.iter() {
            for len in 1..=word.len() {
                let prefix = &word[..len];
                match get_valid_next_letters(prefix).count_enabled() {
                    9 if nine.is_none() => nine = Some(prefix),
                    10 if ten.is_none() => ten = Some(prefix),
                    _ => {}
                }
            }
        }
        let nine = nine.expect("some prefix has exactly nine continuations");
        let ten = ten.expect("some prefix has exactly ten continuations");

        let mut entry = fresh();
        press_index(&mut entry, 1);
        press_prefix(&mut entry, nine);
        assert_eq!(page(&entry).pages(), 1, "nine letters is one page");
        // The 9th letter is on the first page, and paging a single page is dead.
        assert!(entry.slot(ui::ENTRY_LETTER_KEYS[8]).is_some());
        assert_eq!(entry.key(ui::ENTRY_PAGE_KEY), Step::Unchanged);

        let mut entry = fresh();
        press_index(&mut entry, 1);
        press_prefix(&mut entry, ten);
        let showing = page(&entry);
        assert_eq!(showing.pages(), 2, "ten letters is two pages");
        let tenth = showing.candidates.as_bytes()[9];
        assert!(entry.slot(ui::ENTRY_LETTER_KEYS[0]) != Some(char::from(tenth)));
        assert_eq!(entry.key(ui::ENTRY_PAGE_KEY), Step::Redraw);
        assert_eq!(page(&entry).page, 1);
        // Page 2 holds exactly one letter: keys 2..9 must be dead, not wrap.
        assert_eq!(
            entry.slot(ui::ENTRY_LETTER_KEYS[0]),
            Some(char::from(tenth))
        );
        for key in &ui::ENTRY_LETTER_KEYS[1..] {
            assert_eq!(entry.slot(*key), None, "key {key} on a one-letter page");
            assert_eq!(entry.key(*key), Step::Unchanged);
        }
        // And it wraps back rather than running off the end.
        assert_eq!(entry.key(ui::ENTRY_PAGE_KEY), Step::Redraw);
        assert_eq!(page(&entry).page, 0);
    }

    /// Delete from every prefix length of every word: one letter at a time, down to
    /// the empty field, and never more than one.
    #[test]
    fn delete_removes_exactly_one_letter() {
        for word in BIP39_WORDS.iter() {
            let mut entry = fresh();
            press_index(&mut entry, 1);
            press_prefix(&mut entry, word);
            let mut expected = page(&entry).partial.len();
            while expected > 0 {
                assert_eq!(entry.key(ui::ENTRY_DELETE_KEY), Step::Redraw);
                expected -= 1;
                assert_eq!(page(&entry).partial.len(), expected, "{word}: not one");
                assert_eq!(page(&entry).page, 0, "a shorter prefix must reset the page");
            }
        }
    }

    /// Empty the field, then step the cursor one word back.
    ///
    /// Stepping back LOADS the accepted word into the field — so the user can see
    /// what accept-at-unique committed for them, and re-accept it in one press —
    /// which means stepping back *past* a word costs its letters too. The words
    /// themselves are never touched (`words` is written only by an accept), so every
    /// step forward re-loads its word.
    fn walk_back(entry: &mut Entry) {
        while !page(entry).partial.is_empty() {
            assert_eq!(entry.key(ui::ENTRY_DELETE_KEY), Step::Redraw);
        }
        assert_eq!(entry.key(ui::ENTRY_DELETE_KEY), Step::Redraw);
    }

    /// Requirement 5, named: walking back to fix word 1 keeps words 2 and 3, and
    /// re-accepting an unchanged word is one press.
    #[test]
    fn walking_back_to_fix_a_typo_keeps_the_accepted_words() {
        let mut entry = fresh();
        press_index(&mut entry, 4);
        for word in ["ABANDON", "ZOO", "ACT"] {
            press_word(&mut entry, word);
            assert_eq!(entry.key(ui::ENTRY_OK_KEY), Step::Redraw);
        }
        assert_eq!(page(&entry).number, 4);
        // Back to word 1, one word at a time, each arriving with its word loaded.
        for expected in ["ACT", "ZOO", "ABANDON"] {
            walk_back(&mut entry);
            assert_eq!(
                page(&entry).partial,
                expected,
                "the word was not loaded back"
            );
        }
        assert_eq!(page(&entry).number, 1);
        assert_eq!(
            entry.words,
            [
                Some("ABANDON"),
                Some("ZOO"),
                Some("ACT"),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None
            ],
            "nothing may be discarded by walking back"
        );
        // Fix word 1: ABANDON -> ABILITY.
        for _ in 0.."ABANDON".len() {
            assert_eq!(entry.key(ui::ENTRY_DELETE_KEY), Step::Redraw);
        }
        press_word(&mut entry, "ABILITY");
        assert_eq!(entry.key(ui::ENTRY_OK_KEY), Step::Redraw);
        // Words 2 and 3 re-accept in one press each, unchanged.
        assert_eq!(page(&entry).partial, "ZOO");
        assert_eq!(entry.key(ui::ENTRY_OK_KEY), Step::Redraw);
        assert_eq!(page(&entry).partial, "ACT");
        assert_eq!(entry.key(ui::ENTRY_OK_KEY), Step::Redraw);
        assert_eq!(page(&entry).number, 4);
        assert_eq!(
            entry.words[..3],
            [Some("ABILITY"), Some("ZOO"), Some("ACT")]
        );
    }

    /// End to end, against upstream's own decoder: a real checksum-valid share
    /// typed in one word at a time comes out as the same `ShareBackup`.
    #[test]
    fn a_checksum_valid_share_enters_and_round_trips() {
        for salt in 0..3 {
            let (index, words) = valid_backup(salt);
            let expected =
                ShareBackup::from_words(index, words).expect("the search returned a valid share");
            match press_share(index, &words) {
                Step::Entered(backup) => assert!(backup == expected),
                _ => panic!("25 valid words must finish the entry"),
            }
        }
    }

    /// A wrong word costs the checksum, not the other 24: the failure holds all 25,
    /// any key returns to word 25, and walking back to fix the bad one finishes the
    /// entry. This is the property that makes the flow worth trusting.
    #[test]
    fn a_wrong_word_keeps_all_twenty_five_and_can_be_fixed() {
        let (index, words) = valid_backup(1);
        let mut wrong = words;
        wrong[2] = if words[2] == "ZOO" { "ZONE" } else { "ZOO" };
        assert!(
            ShareBackup::from_words(index, wrong).is_err(),
            "the fixture must actually be wrong"
        );

        let mut entry = fresh();
        press_index(&mut entry, index);
        for word in wrong.iter() {
            press_word(&mut entry, word);
            assert!(entry.key(ui::ENTRY_OK_KEY) != Step::Unchanged);
        }
        assert_eq!(entry.screen(), Screen::Failed);
        // All 25 survive the refusal.
        for (slot, word) in entry.words.iter().zip(wrong.iter()) {
            assert_eq!(*slot, Some(*word));
        }
        // Any key returns to the last word, and nothing is cleared.
        assert_eq!(entry.key(b'4'), Step::Redraw);
        assert_eq!(page(&entry).number, ui::BACKUP_WORDS);
        assert_eq!(page(&entry).partial, wrong[ui::BACKUP_WORDS - 1]);

        // Walk back to word 3, retype it, walk forward again.
        while page(&entry).number > 3 {
            walk_back(&mut entry);
        }
        assert_eq!(page(&entry).partial, wrong[2]);
        while !page(&entry).partial.is_empty() {
            assert_eq!(entry.key(ui::ENTRY_DELETE_KEY), Step::Redraw);
        }
        press_word(&mut entry, words[2]);
        // Forward again: every word is still in its slot, so each is ONE press.
        while page(&entry).number < ui::BACKUP_WORDS {
            assert_eq!(
                entry.key(ui::ENTRY_OK_KEY),
                Step::Redraw,
                "an unchanged word must re-accept in one press"
            );
        }
        let step = entry.key(ui::ENTRY_OK_KEY);
        match step {
            Step::Entered(backup) => {
                assert!(backup == ShareBackup::from_words(index, words).expect("valid"))
            }
            _ => panic!("the corrected share must finish"),
        }
    }

    /// Trap (a), named: a lowercase word cannot get into the prefix buffer, and the
    /// vendored list it would be compared against is uppercase.
    #[test]
    fn a_lowercase_word_cannot_enter_the_prefix() {
        assert_eq!(BIP39_WORDS[0], "ABANDON", "the vendored list is uppercase");
        let mut buf = Uppercase::<{ ui::MAX_WORD_LEN }>::new();
        assert!(!buf.load("abandon"), "lowercase must be refused");
        assert_eq!(buf.as_str(), "", "and must not half-load");
        assert!(!buf.push('a'));
        assert!(!buf.push('-'));
        assert_eq!(buf.as_str(), "");
        assert!(buf.load("ABANDON"));
        assert_eq!(buf.as_str(), "ABANDON");
        // Over-long is refused whole, not truncated.
        assert!(!buf.load("ABANDONED"));
        assert_eq!(buf.as_str(), "");
        // And the narrowing really is case-sensitive, which is why the above matters.
        assert_eq!(get_valid_next_letters("a").count_enabled(), 0);
        assert!(words_with_prefix("ac").is_empty());
    }

    /// The share index: digits accumulate, `x` deletes one, an empty index aborts,
    /// zero cannot be accepted, and the eleventh digit cannot wrap.
    #[test]
    fn the_share_index_accumulates_without_wrapping() {
        let mut entry = fresh();
        assert_eq!(entry.screen(), Screen::ShareIndex { typed: None });
        // A leading zero is nothing typed, so it changes nothing and cannot accept.
        assert_eq!(entry.key(b'0'), Step::Unchanged);
        assert_eq!(entry.key(ui::ENTRY_OK_KEY), Step::Unchanged);
        for _ in 0..9 {
            assert_eq!(entry.key(b'9'), Step::Redraw);
        }
        assert_eq!(
            entry.screen(),
            Screen::ShareIndex {
                typed: Some(999_999_999)
            }
        );
        // The tenth digit would be 9,999,999,999 — over u32::MAX, which without the
        // checked arithmetic wraps to 1,410,065,407 in a release build.
        assert_eq!(entry.key(b'9'), Step::Unchanged);
        assert_eq!(
            entry.screen(),
            Screen::ShareIndex {
                typed: Some(999_999_999)
            }
        );
        assert_eq!(entry.key(ui::ENTRY_DELETE_KEY), Step::Redraw);
        assert_eq!(
            entry.screen(),
            Screen::ShareIndex {
                typed: Some(99_999_999)
            }
        );
        // Every non-key does nothing here either.
        for key in 0u8..=255 {
            if key.is_ascii_digit() || key == ui::ENTRY_OK_KEY || key == ui::ENTRY_DELETE_KEY {
                continue;
            }
            assert_eq!(entry.key(key), Step::Unchanged, "key {key} on the index");
        }
        while entry.key(ui::ENTRY_DELETE_KEY) == Step::Redraw {}
        assert_eq!(entry.screen(), Screen::ShareIndex { typed: None });
        assert_eq!(entry.key(ui::ENTRY_DELETE_KEY), Step::Abort);
    }

    /// Backing out of word 1 goes to the share index — the only way to fix a
    /// mistyped index — and keeps the words already typed.
    #[test]
    fn backing_out_of_word_one_returns_to_the_share_index() {
        let mut entry = fresh();
        press_index(&mut entry, 12);
        press_word(&mut entry, "ZOO");
        assert_eq!(entry.key(ui::ENTRY_OK_KEY), Step::Redraw);
        // Word 2 -> word 1 -> the index.
        assert_eq!(entry.key(ui::ENTRY_DELETE_KEY), Step::Redraw);
        assert_eq!(page(&entry).partial, "ZOO");
        for _ in 0.."ZOO".len() {
            assert_eq!(entry.key(ui::ENTRY_DELETE_KEY), Step::Redraw);
        }
        assert_eq!(entry.key(ui::ENTRY_DELETE_KEY), Step::Redraw);
        assert_eq!(entry.screen(), Screen::ShareIndex { typed: Some(12) });
        assert_eq!(
            entry.words[0],
            Some("ZOO"),
            "the word survives the walk back"
        );
        // And back forward again, onto the word that is still there.
        assert_eq!(entry.key(ui::ENTRY_OK_KEY), Step::Redraw);
        assert_eq!(page(&entry).partial, "ZOO");
    }

    /// The accept key is dead on an empty field and on an ambiguous prefix, and the
    /// screen says so through `complete` — a `(y)ok` legend on a screen where `y`
    /// does nothing is the same defect class as a paging key that means no.
    #[test]
    fn the_accept_key_is_dead_until_the_prefix_names_a_word() {
        let mut entry = fresh();
        press_index(&mut entry, 1);
        assert!(!page(&entry).complete);
        assert_eq!(entry.key(ui::ENTRY_OK_KEY), Step::Unchanged);
        // "AB" is ABANDON, ABILITY, ABLE, ABOUT, ... — ambiguous and not a word.
        press_prefix(&mut entry, "AB");
        assert_eq!(page(&entry).partial, "AB");
        assert!(!page(&entry).complete);
        assert_eq!(entry.key(ui::ENTRY_OK_KEY), Step::Unchanged);
        // "ABA" has one completion, so it accepts ABANDON without typing it out.
        press_letter(&mut entry, b'A');
        assert_eq!(page(&entry).partial, "ABA");
        assert!(page(&entry).complete);
        assert_eq!(entry.key(ui::ENTRY_OK_KEY), Step::Redraw);
        assert_eq!(entry.words[0], Some("ABANDON"));
        // The word the user did not type in full appears as the previous word on
        // the next screen, which is where they can check it.
        assert_eq!(page(&entry).previous, Some("ABANDON"));
    }

    /// The two accept predicates are different questions, and both are needed:
    /// `ACT` is a word with four continuations, `ABA` is unique but not a word.
    #[test]
    fn unique_and_whole_word_are_separate_predicates() {
        let mut entry = fresh();
        press_index(&mut entry, 1);
        press_prefix(&mut entry, "ACT");
        assert_eq!(page(&entry).partial, "ACT");
        assert_eq!(entry.whole_word(), Some("ACT"));
        assert_eq!(entry.unique(), None, "ACTION and friends share the prefix");
        assert_eq!(entry.accept(), Some("ACT"));

        let mut entry = fresh();
        press_index(&mut entry, 1);
        for key in [b'1', b'1', b'1'] {
            assert_eq!(entry.key(key), Step::Redraw);
        }
        assert_eq!(page(&entry).partial, "ABA");
        assert_eq!(entry.whole_word(), None, "ABA is not a word");
        assert_eq!(entry.unique(), Some("ABANDON"));
        assert_eq!(entry.accept(), Some("ABANDON"));
    }

    /// A counter as an `RngCore`: `ui`'s noise takes an RNG on mandatory terms and
    /// this test only needs the render to RUN, not to be unpredictable. Nothing here
    /// reaches a device.
    struct Counter(u64);

    impl rand_core::RngCore for Counter {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            self.0
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

    /// Every screen this machine produces is one `ui` will actually DRAW.
    ///
    /// `WordEntry::render` refuses a partial or candidate list that is not
    /// BIP39-shaped (`check_word`, `check_letters`), and a refusal here would put
    /// `ui::refusal` on the glass instead of the word being typed — entry would be
    /// impossible. That is the exact cross-crate class this tree has already been
    /// bitten by twice: `ui::check_word` demanded lowercase while the vendored list
    /// is uppercase, and neither half's tests could see the other. This is the two
    /// halves meeting, on the state machine's own output.
    #[test]
    fn every_screen_the_machine_produces_is_renderable() {
        let mut frame = ui::Frame::new();
        let mut rng = Counter(1);
        for word in BIP39_WORDS.iter().step_by(11) {
            let mut entry = fresh();
            // The share-index page is `EntryPage`'s, and it is drawn from a number.
            assert!(matches!(entry.screen(), Screen::ShareIndex { .. }));
            press_index(&mut entry, 987);
            for letter in word.bytes() {
                for page in 0..3 {
                    let showing = page_at(&entry, page);
                    assert!(
                        showing.render(&mut frame, &mut rng).is_ok(),
                        "{:?} + {:?} is unrenderable",
                        showing.partial,
                        showing.candidates
                    );
                }
                if page(&entry).candidates.is_empty() {
                    break;
                }
                press_letter(&mut entry, letter);
            }
            assert_eq!(entry.key(ui::ENTRY_OK_KEY), Step::Redraw);
            // And the word-2 screen, which carries a `previous` word as well.
            assert!(page(&entry).render(&mut frame, &mut rng).is_ok());
        }
    }

    /// The word page as it would be drawn with the paging cursor at `page` — the
    /// cursor `ui` reduces itself, so an over-large one is a legal input.
    fn page_at(entry: &Entry, page: usize) -> ui::WordEntry<'_> {
        let mut showing = match entry.screen() {
            Screen::Word(word) => word,
            _ => panic!("expected a word page"),
        };
        showing.page = page;
        showing
    }

    /// Every candidate row the machine offers is exactly the letters that can
    /// follow the prefix, in the vendored order — the letters the ruler is drawn
    /// from and the letters `slot` decodes are one string.
    #[test]
    fn the_candidate_row_is_the_vendored_narrowing() {
        let mut entry = fresh();
        press_index(&mut entry, 1);
        assert_eq!(
            page(&entry).candidates.len(),
            25,
            "every letter but X starts a BIP39 word"
        );
        for word in BIP39_WORDS.iter().step_by(37) {
            let mut entry = fresh();
            press_index(&mut entry, 1);
            for (len, letter) in (1..=word.len()).zip(word.bytes()) {
                let expected: std::string::String = get_valid_next_letters(&word[..len - 1])
                    .iter_valid()
                    .collect();
                assert_eq!(
                    page(&entry).candidates,
                    expected,
                    "after {}",
                    &word[..len - 1]
                );
                press_letter(&mut entry, letter);
                assert_eq!(page(&entry).partial, &word[..len]);
            }
        }
    }
}

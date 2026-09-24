//! Firmware INSTALL controller: from an image [`crate::upgrade::Stager`] has
//! staged and read back, to **at most one** install request, through a narrow
//! [`Bootloader`] interface.
//!
//! # Policy here, effects behind a trait
//!
//! Everything in this module is pure workflow policy. The three irreversible or
//! counted effects — selector 18 sub-calls 0 (setup), 2 (login) and 7 (install
//! from PSRAM) — are the three methods of [`Bootloader`], and each takes the ONE
//! [`PinAttempt`] buffer the workflow owns and passes on verbatim: the gate signs
//! bytes `[0, 68)` plus `cached_main_pin` under a per-boot nonce
//! (`pins.c:349-366`), so the struct is never rebuilt between operations. The
//! only thing this module writes into a gate-signed struct is the install request
//! (`change_flags` + `secret[0..8]`), which lies outside that HMAC
//! ([`PinAttempt::set_firmware_request`]).
//!
//! The only `Bootloader` a device build has is [`Unbound`], which answers every
//! operation with [`Errno::NOT_BOUND`] and makes no call. 18/2 and 18/7 are not
//! bound anywhere in this tree (`hal/src/callgate.rs`'s call-site census is
//! unchanged), and 18/0 — bound in `callgate` for the bench procedure — is not
//! wired to this workflow either. Binding any of them is a bench task, not an edit
//! (see "Bench-only" below).
//!
//! # The workflow
//!
//! [`Workflow::begin`] (checked image) → [`Workflow::setup`] (18/0, learn
//! `PA_IS_BLANK`) → [`Workflow::confirm`] (fresh physical consent, bound to this
//! image's digest and length) → [`Workflow::submit_pin`] only if a PIN is set
//! (18/0 with the PIN, then EXACTLY ONE 18/2) → [`Workflow::request_install`]
//! (re-check the image, then EXACTLY ONE 18/7).
//!
//! * Consent is unconditional and per image. The grant lives inside the
//!   [`Workflow`], is consumed by the one request, is cleared by
//!   [`Workflow::cancel`] (and by a declined or keypad-less confirmation), and
//!   cannot outlive the workflow: a replacement image needs `&mut Stager`, which
//!   the borrow checker refuses while a `Workflow` borrows it, and a reboot loses
//!   RAM. There is no API that moves a grant between workflows.
//! * Consent is also bound to ONE workflow. [`Workflow::begin`] claims a serial
//!   from the [`Stager`], and only the newest workflow on it is live: an older one
//!   (even if it holds a grant) answers every step with [`Refusal::Finished`]
//!   and never reaches the gate, so two workflows sharing one `&Stager` cannot
//!   both request. A [`Confirmation::Confirmed`] carries the [`Prompt`] of the
//!   workflow whose screen was shown (digest, length and serial), so a
//!   confirmation captured in one workflow grants nothing in a later one on the
//!   same, unchanged image.
//! * The 18/2 login is conditional on `PA_IS_BLANK` being clear (UPGRADE-PLAN
//!   §1.4). A blank PIN is NOT treated as a gate (§1.3): it is simply the case in
//!   which the bootloader's own `PA_SUCCESSFUL` precondition is already met.
//! * One [`Workflow::submit_pin`] is one physical submission and makes at most one
//!   login call, whatever it returns. `EPIN_AE_FAIL` is NOT retried (Coldcard's
//!   `pincodes.py:102-106` does; `callgate.rs`'s `EPIN_AE_FAIL` doc says we must
//!   not). The attempt floor is `callgate::login_attempt_permitted`, applied to the
//!   `attempts_left` the gate reported in the same submission.
//! * At most one install request per workflow: the workflow is ended BEFORE the
//!   request is made, so no return value — success, refusal or a double that
//!   returns when silicon would not — can reach a second one.
//!
//! # The install boundary, and why lengths are checked here
//!
//! `pin_firmware_upgrade` verifies the image through the HEADER's
//! `firmware_length` and burns the CALLER's `len` (`pins.c:1293-1336`,
//! `verify.c:247-290`); its only ceiling is `2<<20`, past `FLASH_FS`. So this
//! module does not lean on the bootloader's signature check for anything about
//! length. [`CheckedImage::check`], run at [`Workflow::begin`] and again
//! immediately before the request, enforces: the Mk4 header/model contract and
//! 4 KiB install alignment (`image::check_installable`, via
//! `Stager::installable`); received == header == call length
//! (`psram::check_burn_len`, plus the staged-window length); a fresh PSRAM
//! read-back digest equal to the announced one; and [`request_bounds`] on the
//! exact `(start, len)` written into the request — the bootloader's own 32,768
//! floor, `BURN_LEN_MIN`, the `FLASH_FS` ceiling (`BURN_LEN_MAX`, not `2<<20`),
//! lower-half staging and 4 KiB alignment.
//!
//! No signature is verified here and no release list is consulted: key-0
//! signatures, the header rules and the downgrade rule are the BOOTLOADER's, and
//! this module only reports its verdict (`EPIN_AUTH_FAIL` on 18/7 →
//! [`GateFault::ImageRefused`]). No manifest, release authority, factory
//! certificate, coordinator share proof, allowlist or rollback ratchet exists or
//! is consulted (UPGRADE-PLAN §1.2 as corrected by task 05).
//!
//! # Recovery, identity, and the power-on hold
//!
//! Nothing here takes a `Session`, a `DeviceId`, an identity or share record, the
//! flash store or `Entropy`. The listener that stages the image is opened by the
//! boot-time key hold (`main.rs`'s `upgrade_requested`), which sits above identity
//! and entropy at boot, so staging and this workflow are reachable with the
//! identity/share record healthy, damaged or absent, and the same image, consent
//! and PIN rules apply in every case. A healthy or damaged record adds no
//! authorization requirement.
//!
//! The hold is NOT consent to any image: it only opens the listener, before any
//! image exists. The image-specific confirmation is [`Workflow::confirm`], taken
//! after staging, against the digest of the bytes read back. A missing or
//! unreadable keypad is [`Confirmation::NoKeypad`], which cancels — nothing
//! confirms implicitly.
//!
//! **A firmware update does not reconstruct a lost identity secret or recover an
//! encrypted share.** It replaces code in `[FLASH_ISR_BASE, FLASH_FS_BASE)` and
//! nothing else; `FLASH_FS` (where cold-snap's records live) is outside the burn
//! window by construction, and a damaged record is exactly as damaged after a
//! successful install.
//!
//! # Bench-only (not answerable by any test in this tree)
//!
//! * Whether 18/0 moves SE1's `Counter[0]` (`read_counter0` before, between and
//!   after two 18/0 calls; UPGRADE-PLAN §5 item 1). If it moves, this design is
//!   void.
//! * 18/2 on a PIN-set expendable unit (phase 5), including the real
//!   `attempts_left` after a wrong PIN and SE2's `se2_handle_bad_pin` side effects.
//! * 18/7 (phase 6): the real `verify_firmware_in_ram` verdict on a key-0 image,
//!   burn timing, and reset.
//! * Reset/power interruption during the burn and `psram_recover_firmware`
//!   recovery; PSRAM retention across the reset.
//!
//! The test double below models the gate's argument checks, ordering, HMAC
//! freshness across a reboot, attempt counting and at-most-once installation. It
//! does NOT measure SE counters, flash timing or PSRAM retention, and its
//! successful install is a recorded request, never a flashed image.

use coldsnap_hal::callgate::{
    self, Errno, PinAttempt, EPIN_AE_FAIL, EPIN_AUTH_FAIL, EPIN_BAD_MAGIC, EPIN_HMAC_FAIL,
    EPIN_HMAC_REQUIRED, EPIN_I_AM_BRICK, EPIN_MUST_WAIT, EPIN_OLD_ATTEMPT, EPIN_SE2_FAIL,
    PA_IS_BLANK, PA_MAGIC_V2, PA_SUCCESSFUL,
};
use coldsnap_hal::image::NotInstallable;
use coldsnap_hal::memmap;
use coldsnap_hal::psram::{self, Psram, StageError};
use frostsnap_comms::Sha256Digest;

use crate::firmware_digest;
use crate::upgrade::Stager;

/// The bootloader's PIN surface, narrowed to the three operations an install
/// needs. Each is one gate call on `att`, which the caller owns and passes back
/// verbatim.
///
/// An implementation must make exactly one call per method invocation and never
/// retry: the workflow's "one submission, one login" rule is only as good as
/// this.
pub trait Bootloader {
    /// Selector 18 / `arg2` 0, `pin_setup_attempt` (`pins.c:531-592`).
    ///
    /// # Errors
    ///
    /// The gate's code, as an [`Errno`] (EPIN codes are its negative values).
    fn setup(&mut self, att: &mut PinAttempt) -> Result<(), Errno>;

    /// Selector 18 / `arg2` 2, `pin_login_attempt` (`pins.c:695-835`). COUNTED.
    ///
    /// # Errors
    ///
    /// As [`Bootloader::setup`].
    fn login(&mut self, att: &mut PinAttempt) -> Result<(), Errno>;

    /// Selector 18 / `arg2` 7, `pin_firmware_upgrade` (`pins.c:1277-1346`).
    /// DESTRUCTIVE: on silicon a success never returns (it burns and resets).
    ///
    /// # Errors
    ///
    /// As [`Bootloader::setup`].
    fn request_install(&mut self, att: &mut PinAttempt) -> Result<(), Errno>;
}

/// The device build's bootloader: nothing is bound. Every operation is
/// [`Errno::NOT_BOUND`] and no gate call is made.
///
/// Deliberately not a thin wrapper over `callgate::pin_setup_attempt`: wiring
/// 18/0 into a boot path is itself gated on the bench's counter measurement
/// (UPGRADE-PLAN §5 item 1) and on `callgate`'s UART4/I2C2 question, and a
/// half-bound interface would make the unbound half look like a failure mode
/// rather than a decision.
pub struct Unbound;

impl Bootloader for Unbound {
    fn setup(&mut self, _att: &mut PinAttempt) -> Result<(), Errno> {
        Err(Errno::NOT_BOUND)
    }
    fn login(&mut self, _att: &mut PinAttempt) -> Result<(), Errno> {
        Err(Errno::NOT_BOUND)
    }
    fn request_install(&mut self, _att: &mut PinAttempt) -> Result<(), Errno> {
        Err(Errno::NOT_BOUND)
    }
}

/// Which operation a gate code came from — the same code means different things
/// on different sub-calls (`EPIN_AUTH_FAIL` is a wrong PIN on 18/2 and a refused
/// image on 18/7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Setup,
    Login,
    Install,
}

/// A bootloader answer, classified. Every one is an explicit outcome and none is
/// retried by this module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateFault {
    /// [`Errno::NOT_BOUND`]: no binding on this build; no call was made.
    NotBound,
    /// `EPIN_AUTH_FAIL` from a login: the PIN is wrong, and a counter tick was
    /// spent.
    WrongPin,
    /// `EPIN_AUTH_FAIL` from an install request: `verify_firmware_in_ram`
    /// refused the image — header, downgrade (`check_is_downgrade`) or signature.
    ImageRefused,
    /// `EPIN_HMAC_FAIL`, `EPIN_HMAC_REQUIRED`, `EPIN_OLD_ATTEMPT`,
    /// `EPIN_BAD_MAGIC`: the struct is not one this boot's gate signed —
    /// typically a reset between two operations.
    StaleAttempt(i32),
    /// `EPIN_AE_FAIL` or `EPIN_SE2_FAIL`.
    SecureElement(i32),
    /// `EPIN_I_AM_BRICK`. Terminal.
    Bricked,
    /// `EPIN_MUST_WAIT`.
    MustWait,
    /// Any other negative code (`RANGE_ERR`, `BAD_REQUEST`, `WRONG_SUCCESS`, ...):
    /// the gate refused the request's shape.
    Rejected(i32),
    /// A positive `errno.h` code or one of our own `Errno`s.
    Other(Errno),
    /// The gate returned success but the struct does not say what that success
    /// must mean (magic, `PA_SUCCESSFUL`, `PA_IS_BLANK` combinations).
    Malformed,
}

fn classify(e: Errno, op: Op) -> GateFault {
    if e == Errno::NOT_BOUND {
        return GateFault::NotBound;
    }
    match e.signed() {
        EPIN_AUTH_FAIL if op == Op::Login => GateFault::WrongPin,
        EPIN_AUTH_FAIL if op == Op::Install => GateFault::ImageRefused,
        c @ (EPIN_HMAC_FAIL | EPIN_HMAC_REQUIRED | EPIN_OLD_ATTEMPT | EPIN_BAD_MAGIC) => {
            GateFault::StaleAttempt(c)
        }
        c @ (EPIN_AE_FAIL | EPIN_SE2_FAIL) => GateFault::SecureElement(c),
        EPIN_I_AM_BRICK => GateFault::Bricked,
        EPIN_MUST_WAIT => GateFault::MustWait,
        c if c < 0 => GateFault::Rejected(c),
        _ => GateFault::Other(e),
    }
}

/// Why the image failed the install boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageFault {
    /// `Stager::installable`'s verdict: unstaged, unreadable, magic, family,
    /// length (incl. header/call disagreement) or 4 KiB alignment.
    NotInstallable(NotInstallable),
    /// The staged-window length (bytes received) is not the call length.
    Received {
        /// Bytes in the staged window.
        received: u32,
        /// The length the request would carry.
        call: u32,
    },
    /// The PSRAM read-back digest no longer matches the announced digest.
    Digest,
    /// The image re-checked immediately before the request is not the image the
    /// workflow began with and the user confirmed.
    Changed,
    /// `(start, len)` outside [`request_bounds`].
    Bounds {
        /// PSRAM offset.
        start: u32,
        /// Length.
        len: u32,
    },
}

/// The last check on the exact `(start, len)` an install request will carry.
///
/// Redundant with [`CheckedImage::check`] on purpose: it is applied to the two
/// words themselves, immediately before they are written, so no path that
/// produced them can skip it.
///
/// * `start == PSRAM_STAGE_OFFSET` and `start + len <= PSRAM_STAGE_LEN`: lower
///   half only (the recovery header lives in the upper half, `psram.c:32`).
/// * `len >= 32_768` (`pins.c:1297`) and `len >= BURN_LEN_MIN` (`verify.c:215`).
/// * `len <= BURN_LEN_MAX`, i.e. the erase stops below `FLASH_FS_BASE` — NOT the
///   bootloader's `2<<20` (`pins.c:1298`), which is 655,360 B past it.
/// * `len % FW_INSTALL_ALIGN == 0` (4 KiB, `signit.py:305`, `verify.c:106`).
///
/// # Errors
///
/// [`ImageFault::Bounds`].
pub fn request_bounds(start: u32, len: u32) -> Result<(), ImageFault> {
    let in_lower_half = start == psram::PSRAM_STAGE_OFFSET
        && start
            .checked_add(len)
            .is_some_and(|end| end <= psram::PSRAM_STAGE_LEN);
    let ok = in_lower_half
        && len >= BOOTLOADER_MIN_LEN
        && (psram::BURN_LEN_MIN..=psram::BURN_LEN_MAX).contains(&len)
        && len % memmap::FW_INSTALL_ALIGN == 0;
    if ok {
        Ok(())
    } else {
        Err(ImageFault::Bounds { start, len })
    }
}

/// `pin_firmware_upgrade`'s own floor, `len < 32768` → `EPIN_RANGE_ERR`
/// (`pins.c:1297`). Looser than `BURN_LEN_MIN`; kept so the request can never be
/// one the bootloader would refuse on range alone.
const BOOTLOADER_MIN_LEN: u32 = 32_768;

/// A staged image that passed the install boundary: offset, length and digest,
/// none of which a caller can set. Only [`CheckedImage::check`] makes one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckedImage {
    start: u32,
    len: u32,
    digest: Sha256Digest,
}

impl CheckedImage {
    /// Check what `stager` holds NOW. Reads PSRAM back (twice: once through
    /// `Stager::installable`'s header rules, once for the digest).
    ///
    /// # Errors
    ///
    /// Any [`ImageFault`].
    pub fn check<P: Psram>(stager: &Stager<P>) -> Result<Self, ImageFault> {
        let announced = stager
            .staged_digest()
            .ok_or(ImageFault::NotInstallable(NotInstallable::Unstaged))?;
        let len = stager.installable().map_err(ImageFault::NotInstallable)?;
        let view = stager.staged_view().map_err(ImageFault::NotInstallable)?;
        check_view(view, announced, len)
    }

    /// PSRAM offset of the image (always `psram::PSRAM_STAGE_OFFSET`).
    #[must_use]
    pub fn start(&self) -> u32 {
        self.start
    }

    /// Length: header `firmware_length` == bytes received == request length.
    #[must_use]
    pub fn len(&self) -> u32 {
        self.len
    }

    /// Never true: a checked image is at least `BURN_LEN_MIN` long. Present for
    /// clippy's `len_without_is_empty`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The read-back digest, which the consent screen shows.
    #[must_use]
    pub fn digest(&self) -> Sha256Digest {
        self.digest
    }
}

/// The pure half of [`CheckedImage::check`]: `view` is the staged window as read
/// back, `announced` the digest the transfer agreed, `call_len` the length the
/// request will carry.
fn check_view(
    view: &[u8],
    announced: Sha256Digest,
    call_len: u32,
) -> Result<CheckedImage, ImageFault> {
    // Header magic, Mk4 family, header == call length within the burn window,
    // 4 KiB alignment. `check_installable` is the one implementation shared with
    // `Stager::installable` and `checkfw`; called again here on `call_len` so the
    // length that ships is the one it compared.
    let len = coldsnap_hal::image::check_installable(view, call_len)
        .map_err(ImageFault::NotInstallable)?;
    // The decoupling guard, stated on its own so no refactor of
    // `check_installable` can drop it silently: header == call.
    psram::check_burn_len(view, call_len)
        .map_err(|e: StageError| ImageFault::NotInstallable(NotInstallable::Length(e)))?;
    // received == call. The view is exactly the staged window.
    let received = u32::try_from(view.len()).unwrap_or(u32::MAX);
    if received != len {
        return Err(ImageFault::Received {
            received,
            call: len,
        });
    }
    match firmware_digest(view) {
        Some(d) if d == announced => {}
        _ => return Err(ImageFault::Digest),
    }
    let start = psram::PSRAM_STAGE_OFFSET;
    request_bounds(start, len)?;
    Ok(CheckedImage {
        start,
        len,
        digest: announced,
    })
}

/// What the confirmation screen shows: one image, in one workflow.
///
/// Only [`Workflow::prompt`] makes one. Its workflow serial is private, so a
/// prompt from an earlier workflow cannot be relabelled for a later one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prompt {
    digest: Sha256Digest,
    len: u32,
    workflow: u32,
}

impl Prompt {
    /// The read-back digest to display.
    #[must_use]
    pub fn digest(&self) -> Sha256Digest {
        self.digest
    }

    /// The image length to display.
    #[must_use]
    pub fn length(&self) -> u32 {
        self.len
    }
}

/// A physical answer to the image-specific confirmation screen.
///
/// Produced by the keypad/consent UI; this module only decides what each answer
/// permits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confirmation {
    /// The user confirmed the prompt the screen showed.
    Confirmed {
        /// The [`Workflow::prompt`] that was on the screen when the key was
        /// pressed.
        shown: Prompt,
    },
    /// The user declined.
    Declined,
    /// No keypad, or it could not be read. Never a confirmation.
    NoKeypad,
}

/// What 18/0 reported about the PIN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinState {
    /// `PA_IS_BLANK | PA_SUCCESSFUL`: no login needed (and no security from the
    /// PIN either, UPGRADE-PLAN §1.3).
    Blank,
    /// A PIN is set: [`Workflow::submit_pin`] is needed.
    PinSet {
        /// `attempts_left` as the gate reported it.
        attempts_left: u32,
    },
}

/// Why the workflow did not proceed. None of these reached an install request
/// except [`Refusal::Gate`] returned by [`Workflow::request_install`], which is
/// a request the bootloader refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The image failed the install boundary.
    Image(ImageFault),
    /// No current consent grant for this image.
    NoConsent,
    /// Declined, or no keypad: the workflow is over.
    Cancelled,
    /// The step is not valid in the current phase.
    OutOfOrder,
    /// The workflow has ended (an install was requested, it was cancelled, or a
    /// terminal gate fault). Start a new one — which needs new consent.
    Finished,
    /// `attempts_left` is at or below `callgate::ATTEMPTS_LEFT_FLOOR`. No login
    /// was attempted.
    AttemptsFloor {
        /// As the gate reported it.
        attempts_left: u32,
    },
    /// An empty PIN. No gate call was made.
    EmptyPin,
    /// A PIN longer than `callgate::MAX_PIN_LEN`. No gate call was made.
    PinTooLong,
    /// A bootloader answer.
    Gate(GateFault),
}

/// The bootloader accepted a well-formed install request for `len` bytes at
/// PSRAM offset `start`.
///
/// **Not "installed".** On silicon a successful 18/7 does not return: it burns
/// and resets (`pins.c:1336-1339`), so this value can only come from a test
/// double. The only evidence of an installation is a verified reconnect of the
/// new firmware, which is outside this module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstallRequested {
    /// PSRAM offset passed.
    pub start: u32,
    /// Length passed.
    pub len: u32,
}

/// Consent, bound to one checked image. Private: only [`Workflow::confirm`]
/// makes one, and only [`Workflow::request_install`] consumes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Grant {
    digest: Sha256Digest,
    len: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Image checked; 18/0 not yet run.
    Checked,
    /// 18/0 says a PIN is set; a login is needed.
    PinRequired,
    /// The attempt carries `PA_SUCCESSFUL` (blank, or logged in).
    Ready,
    /// Over. Nothing further reaches the gate.
    Ended,
}

/// One install workflow over one staged image. See the module docs.
///
/// Borrows the [`Stager`], so the staged image cannot be replaced while the
/// workflow (and any consent it holds) exists.
pub struct Workflow<'s, P: Psram> {
    stager: &'s Stager<P>,
    image: CheckedImage,
    grant: Option<Grant>,
    attempt: Option<PinAttempt>,
    phase: Phase,
    /// This workflow's serial on `stager`; live only while it is the newest.
    serial: u32,
}

impl<'s, P: Psram> Workflow<'s, P> {
    /// Start a workflow on what `stager` holds. No gate call.
    ///
    /// # Errors
    ///
    /// [`Refusal::Image`] if the image fails the install boundary.
    pub fn begin(stager: &'s Stager<P>) -> Result<Self, Refusal> {
        let image = CheckedImage::check(stager).map_err(Refusal::Image)?;
        Ok(Self {
            stager,
            image,
            grant: None,
            attempt: None,
            phase: Phase::Checked,
            serial: stager.claim_workflow(),
        })
    }

    /// What the confirmation screen must show for this workflow.
    #[must_use]
    pub fn prompt(&self) -> Prompt {
        Prompt {
            digest: self.image.digest,
            len: self.image.len,
            workflow: self.serial,
        }
    }

    /// The phase, after ending this workflow if a newer one has begun on the
    /// same stager.
    fn current(&mut self) -> Phase {
        if self.stager.live_workflow() != self.serial {
            self.cancel();
        }
        self.phase
    }

    /// The image this workflow is for — what the consent screen shows.
    #[must_use]
    pub fn image(&self) -> &CheckedImage {
        &self.image
    }

    /// End the workflow and drop any consent and PIN attempt.
    pub fn cancel(&mut self) {
        self.grant = None;
        self.attempt = None;
        self.phase = Phase::Ended;
    }

    /// End the workflow and report why.
    fn end<T>(&mut self, why: Refusal) -> Result<T, Refusal> {
        self.cancel();
        Err(why)
    }

    /// Run 18/0 with no PIN and learn whether a login is needed. Once per
    /// workflow.
    ///
    /// # Errors
    ///
    /// [`Refusal::OutOfOrder`] / [`Refusal::Finished`]; any gate fault, which
    /// ends the workflow.
    pub fn setup<B: Bootloader>(&mut self, gate: &mut B) -> Result<PinState, Refusal> {
        match self.current() {
            Phase::Checked => {}
            Phase::Ended => return Err(Refusal::Finished),
            _ => return Err(Refusal::OutOfOrder),
        }
        let mut att = match PinAttempt::new(&[]) {
            Ok(a) => a,
            Err(_) => return self.end(Refusal::Gate(GateFault::Malformed)),
        };
        if let Err(e) = gate.setup(&mut att) {
            return self.end(Refusal::Gate(classify(e, Op::Setup)));
        }
        if att.magic() != PA_MAGIC_V2 {
            return self.end(Refusal::Gate(GateFault::Malformed));
        }
        let flags = att.state_flags();
        match (flags & PA_IS_BLANK != 0, flags & PA_SUCCESSFUL != 0) {
            (true, true) => {
                self.attempt = Some(att);
                self.phase = Phase::Ready;
                Ok(PinState::Blank)
            }
            (false, false) => {
                self.phase = Phase::PinRequired;
                Ok(PinState::PinSet {
                    attempts_left: att.attempts_left(),
                })
            }
            _ => self.end(Refusal::Gate(GateFault::Malformed)),
        }
    }

    /// Record the physical answer to the image-specific confirmation.
    ///
    /// Only [`Confirmation::Confirmed`] with THIS workflow's [`Prompt`] (this
    /// image's digest and length, this workflow's serial) grants consent.
    /// Anything else ends the workflow.
    ///
    /// # Errors
    ///
    /// [`Refusal::Cancelled`] for a decline or no keypad; [`Refusal::NoConsent`]
    /// for a confirmation of a different prompt (another image, or an earlier
    /// workflow); [`Refusal::Finished`] after the workflow ended or was superseded
    /// by a newer [`Workflow::begin`] on the same stager.
    pub fn confirm(&mut self, answer: Confirmation) -> Result<(), Refusal> {
        if self.current() == Phase::Ended {
            return Err(Refusal::Finished);
        }
        match answer {
            Confirmation::Confirmed { shown } if shown == self.prompt() => {
                self.grant = Some(Grant {
                    digest: self.image.digest,
                    len: self.image.len,
                });
                Ok(())
            }
            Confirmation::Confirmed { .. } => self.end(Refusal::NoConsent),
            Confirmation::Declined | Confirmation::NoKeypad => self.end(Refusal::Cancelled),
        }
    }

    /// One physical PIN submission: 18/0 with the PIN (free), the attempt floor
    /// on the `attempts_left` it reports, then AT MOST ONE 18/2.
    ///
    /// Requires consent first, so no counter tick is ever spent on an image the
    /// user has not confirmed.
    ///
    /// A wrong PIN leaves the workflow waiting for another submission; every
    /// other gate fault ends it. Nothing here loops.
    ///
    /// # Errors
    ///
    /// Any [`Refusal`]; see above.
    pub fn submit_pin<B: Bootloader>(&mut self, gate: &mut B, pin: &[u8]) -> Result<(), Refusal> {
        match self.current() {
            Phase::PinRequired => {}
            Phase::Ended => return Err(Refusal::Finished),
            _ => return Err(Refusal::OutOfOrder),
        }
        if self.grant.is_none() {
            return Err(Refusal::NoConsent);
        }
        if pin.is_empty() {
            return Err(Refusal::EmptyPin);
        }
        let Ok(mut att) = PinAttempt::new(pin) else {
            return Err(Refusal::PinTooLong);
        };
        if let Err(e) = gate.setup(&mut att) {
            return self.end(Refusal::Gate(classify(e, Op::Setup)));
        }
        if att.magic() != PA_MAGIC_V2 || att.state_flags() & (PA_IS_BLANK | PA_SUCCESSFUL) != 0 {
            return self.end(Refusal::Gate(GateFault::Malformed));
        }
        let attempts_left = att.attempts_left();
        if !callgate::login_attempt_permitted(attempts_left) {
            return self.end(Refusal::AttemptsFloor { attempts_left });
        }
        // The one counted call. Its result is classified and returned; there is no
        // path from here back to a second `login`.
        match gate.login(&mut att) {
            Ok(()) if att.magic() == PA_MAGIC_V2 && att.state_flags() & PA_SUCCESSFUL != 0 => {
                self.attempt = Some(att);
                self.phase = Phase::Ready;
                Ok(())
            }
            Ok(()) => self.end(Refusal::Gate(GateFault::Malformed)),
            Err(e) => match classify(e, Op::Login) {
                GateFault::WrongPin => Err(Refusal::Gate(GateFault::WrongPin)),
                other => self.end(Refusal::Gate(other)),
            },
        }
    }

    /// Re-check the image, then make THE install request — once.
    ///
    /// The consent grant is consumed and the workflow ended before the gate is
    /// called, so no outcome can lead to a second request.
    ///
    /// # Errors
    ///
    /// [`Refusal::NoConsent`], [`Refusal::OutOfOrder`], [`Refusal::Finished`] and
    /// [`Refusal::Image`] never reach the gate. [`Refusal::Gate`] is a request the
    /// bootloader refused — e.g. [`GateFault::ImageRefused`] for a signature or
    /// downgrade refusal — and never an installation.
    pub fn request_install<B: Bootloader>(
        &mut self,
        gate: &mut B,
    ) -> Result<InstallRequested, Refusal> {
        match self.current() {
            Phase::Ready => {}
            Phase::Ended => return Err(Refusal::Finished),
            _ => return Err(Refusal::OutOfOrder),
        }
        let Some(grant) = self.grant.take() else {
            return Err(Refusal::NoConsent);
        };
        let Some(mut att) = self.attempt.take() else {
            return self.end(Refusal::OutOfOrder);
        };
        // From here on the workflow is over, whatever happens.
        self.cancel();

        let now = CheckedImage::check(self.stager).map_err(Refusal::Image)?;
        if now != self.image || grant.digest != now.digest || grant.len != now.len {
            return Err(Refusal::Image(ImageFault::Changed));
        }
        request_bounds(now.start, now.len).map_err(Refusal::Image)?;
        att.set_firmware_request(now.start, now.len);
        match gate.request_install(&mut att) {
            Ok(()) => Ok(InstallRequested {
                start: now.start,
                len: now.len,
            }),
            Err(e) => Err(Refusal::Gate(classify(e, Op::Install))),
        }
    }
}

/// The device instantiation of the whole gate-facing path — `MappedPsram`
/// staging and the [`Unbound`] gate — as one non-generic item, so every ARM
/// build generates code for `setup`, `submit_pin` and `request_install` rather
/// than only type-checking a generic. With [`Unbound`] it stops at `setup` with
/// [`GateFault::NotBound`] and makes no call; that is the point.
///
/// Not a listener driver: it takes no consent (`request_install` without a
/// grant is [`Refusal::NoConsent`]) and nothing in `main.rs` calls it.
///
/// # Errors
///
/// Always, on this tree: [`Refusal::Gate`]`(`[`GateFault::NotBound`]`)`.
pub fn device_path(
    w: &mut Workflow<'_, psram::MappedPsram>,
    pin: &[u8],
) -> Result<InstallRequested, Refusal> {
    let gate = &mut Unbound;
    if let PinState::PinSet { .. } = w.setup(gate)? {
        w.submit_pin(gate, pin)?;
    }
    w.request_install(gate)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::upgrade::State;
    use coldsnap_hal::callgate::{
        EPIN_BAD_REQUEST, EPIN_PRIMARY_ONLY, EPIN_RANGE_ERR, EPIN_WRONG_SUCCESS, MAX_PIN_LEN,
        PIN_ATTEMPT_SIZE,
    };
    use coldsnap_hal::image;
    use coldsnap_hal::psram::fake::FakePsram;
    use frostsnap_comms::CoordinatorUpgradeMessage;
    use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
    use sha2::{Digest, Sha256};
    use std::vec;
    use std::vec::Vec;

    // ---- the strict fake gate ----------------------------------------------

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Call {
        Setup,
        Login,
        Install,
    }

    /// A strict double of `pin_setup_attempt`, `pin_login_attempt` and
    /// `pin_firmware_upgrade`, over the SAME 280 bytes the controller owns.
    ///
    /// Models: `_validate_attempt` (magic, ranges, change-flag mask), an HMAC over
    /// `[0,68) ++ cached_main_pin` keyed by a pairing secret and a per-boot nonce
    /// (so [`FakeGate::reboot`] invalidates every earlier struct), the attempt
    /// counter and brick at 0, `PA_SUCCESSFUL` preconditions, `CHANGE_FIRMWARE`,
    /// the 18/7 range checks, `verify_header`, `check_is_downgrade` against an
    /// OTP minimum timestamp (never against an installed version), and
    /// `uECC_verify` over double-SHA256 of the header-declared range against
    /// `approved[pubkey_num]` — while burning the CALLER's `len`. At most one
    /// accepted install per fake, enforced by panic.
    ///
    /// Does NOT model: SE counter hardware, trick PINs, flash timing, PSRAM
    /// retention across reset. `approved[0]` is a test key standing in for dev
    /// key 0 (whose private half is not embedded in this tree); the fake
    /// models the CHECK, not key 0's identity.
    struct FakeGate<'a> {
        psram: &'a [u8],
        boot: u32,
        pin: Option<Vec<u8>>,
        wrong_since_good: u32,
        approved: Vec<PublicKey>,
        otp_min_timestamp: [u8; 8],
        calls: Vec<Call>,
        fail_next: Option<(Call, i32)>,
        /// Fault injection of a different kind: the named operation returns
        /// success but signs a struct whose flags contradict it.
        lie: Option<Call>,
        burns: Vec<(u32, u32)>,
    }

    const MAX_TARGET_ATTEMPTS: u32 = 13;
    const PAIRING: [u8; 32] = [0x5a; 32];

    impl<'a> FakeGate<'a> {
        fn new(psram: &'a [u8], pin: Option<&[u8]>) -> Self {
            Self {
                psram,
                boot: 1,
                pin: pin.map(<[u8]>::to_vec),
                wrong_since_good: 0,
                approved: vec![PublicKey::from_secret_key(&Secp256k1::new(), &test_key())],
                otp_min_timestamp: [0x24, 0, 0, 0, 0, 0, 0, 0],
                calls: Vec::new(),
                fail_next: None,
                lie: None,
                burns: Vec::new(),
            }
        }

        /// A reset: the per-boot nonce changes. RAM on the controller side is
        /// the caller's to drop.
        fn reboot(&mut self) {
            self.boot += 1;
        }

        fn attempts_left(&self) -> u32 {
            MAX_TARGET_ATTEMPTS.saturating_sub(self.wrong_since_good)
        }

        fn hmac(&self, b: &[u8; PIN_ATTEMPT_SIZE]) -> [u8; 32] {
            let mut h = Sha256::new();
            h.update(PAIRING);
            h.update(self.boot.to_le_bytes());
            h.update(&b[..68]);
            h.update(&b[248..]);
            Sha256::digest(h.finalize()).into()
        }

        fn injected(&mut self, c: Call) -> Result<(), Errno> {
            match self.fail_next {
                Some((at, code)) if at == c => {
                    self.fail_next = None;
                    Err(Errno::from_raw(code).unwrap())
                }
                _ => Ok(()),
            }
        }

        /// `_validate_attempt` (`pins.c:376-411`).
        fn validate(&self, b: &[u8; PIN_ATTEMPT_SIZE], first_time: bool) -> Result<(), Errno> {
            let w = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
            let err = |c| Err(Errno::from_raw(c).unwrap());
            if !first_time && self.hmac(b) != b[68..100] {
                return err(EPIN_HMAC_FAIL);
            }
            if w(0) != PA_MAGIC_V2 {
                return err(EPIN_BAD_MAGIC);
            }
            if w(40) as i32 > MAX_PIN_LEN as i32
                || w(136) as i32 > MAX_PIN_LEN as i32
                || w(172) as i32 > MAX_PIN_LEN as i32
                || w(100) & !0xf7f != 0
            {
                return err(EPIN_RANGE_ERR);
            }
            if w(4) != 0 {
                return err(EPIN_PRIMARY_ONLY);
            }
            Ok(())
        }

        fn sign(&self, b: &mut [u8; PIN_ATTEMPT_SIZE]) {
            let m = self.hmac(b);
            b[68..100].copy_from_slice(&m);
        }

        fn put(b: &mut [u8; PIN_ATTEMPT_SIZE], off: usize, v: u32) {
            b[off..off + 4].copy_from_slice(&v.to_le_bytes());
        }

        /// `verify_firmware_in_ram` (`verify.c:239-291`): `len` is ignored.
        fn verify_in_ram(&self, data: &[u8]) -> bool {
            let h = memmap::FW_HEADER_OFFSET as usize;
            let Some(hdr) = data.get(h..h + 128) else {
                return false;
            };
            let w = |o: usize| u32::from_le_bytes(hdr[o..o + 4].try_into().unwrap());
            let fw_len = w(24);
            // verify_header
            if w(0) != image::FW_HEADER_MAGIC
                || hdr[12] == 0
                || hdr[4] >= 0x40
                || !(256 * 1024..0x1E_0000).contains(&fw_len)
                || w(20) as usize >= self.approved.len()
            {
                return false;
            }
            // check_is_downgrade: major < 3, or timestamp below the OTP minimum.
            let major = if hdr[13] == b'.' {
                hdr[12].wrapping_sub(b'0')
            } else {
                10
            };
            if major < 3 || hdr[4..12] < self.otp_min_timestamp[..] {
                return false;
            }
            let Some(body) = data.get(h + 128..fw_len as usize) else {
                return false;
            };
            let mut s = Sha256::new();
            s.update(&data[..h + 128 - 64]);
            s.update(body);
            let check: [u8; 32] = Sha256::digest(s.finalize()).into();
            let Ok(mut sig) = secp256k1::ecdsa::Signature::from_compact(&hdr[64..128]) else {
                return false;
            };
            // mk4-bootloader/verify.c:232 calls uECC_verify, which (micro-ecc/uECC.c:1411-1420)
            // only range-checks
            // r, s in [1, n) and has no low-S rule, and signit.py:354 never normalizes
            // s, so a high-S key-0 signature is valid there. libsecp256k1 refuses
            // high-S; normalizing first models the bootloader, not a looser gate.
            sig.normalize_s();
            Secp256k1::verification_only()
                .verify_ecdsa(
                    &Message::from_digest(check),
                    &sig,
                    &self.approved[w(20) as usize],
                )
                .is_ok()
        }
    }

    impl Bootloader for FakeGate<'_> {
        fn setup(&mut self, att: &mut PinAttempt) -> Result<(), Errno> {
            self.calls.push(Call::Setup);
            self.injected(Call::Setup)?;
            let (attempts_left, fails) = (self.attempts_left(), self.wrong_since_good);
            let blank = self.pin.is_none();
            let signed = {
                let b = att.raw_mut();
                self.validate(b, true)?;
                let pin_len = u32::from_le_bytes(b[40..44].try_into().unwrap()) as usize;
                let pin: Vec<u8> = b[8..8 + pin_len].to_vec();
                b.fill(0);
                Self::put(b, 0, PA_MAGIC_V2);
                Self::put(b, 40, pin_len as u32);
                b[8..8 + pin_len].copy_from_slice(&pin);
                *b
            };
            if attempts_left == 0 {
                return Err(Errno::from_raw(EPIN_I_AM_BRICK).unwrap());
            }
            let mut b = signed;
            Self::put(&mut b, 52, fails);
            Self::put(&mut b, 56, attempts_left);
            if blank {
                Self::put(&mut b, 60, PA_SUCCESSFUL | PA_IS_BLANK);
            }
            if self.lie == Some(Call::Setup) {
                // Success without blank, on either PIN state.
                Self::put(&mut b, 60, PA_SUCCESSFUL);
            }
            self.sign(&mut b);
            *att.raw_mut() = b;
            Ok(())
        }

        fn login(&mut self, att: &mut PinAttempt) -> Result<(), Errno> {
            self.calls.push(Call::Login);
            self.injected(Call::Login)?;
            let mut b = *att.raw_mut();
            self.validate(&b, false)?;
            let e = |c| Err(Errno::from_raw(c).unwrap());
            if u32::from_le_bytes(b[60..64].try_into().unwrap()) & PA_SUCCESSFUL != 0 {
                return e(EPIN_WRONG_SUCCESS);
            }
            if self.attempts_left() == 0 {
                return e(EPIN_I_AM_BRICK);
            }
            let pin_len = u32::from_le_bytes(b[40..44].try_into().unwrap()) as usize;
            if self.pin.as_deref() != Some(&b[8..8 + pin_len]) {
                self.wrong_since_good += 1;
                return e(EPIN_AUTH_FAIL);
            }
            self.wrong_since_good = 0;
            let flags = if self.lie == Some(Call::Login) {
                0
            } else {
                PA_SUCCESSFUL
            };
            Self::put(&mut b, 60, flags);
            Self::put(&mut b, 52, 0);
            Self::put(&mut b, 56, MAX_TARGET_ATTEMPTS);
            let cache: [u8; 32] = Sha256::digest(&b[8..8 + pin_len]).into();
            b[248..].copy_from_slice(&cache);
            self.sign(&mut b);
            *att.raw_mut() = b;
            Ok(())
        }

        fn request_install(&mut self, att: &mut PinAttempt) -> Result<(), Errno> {
            self.calls.push(Call::Install);
            assert!(
                self.burns.is_empty(),
                "fake gate: a second install request after an accepted one"
            );
            self.injected(Call::Install)?;
            let b = *att.raw_mut();
            self.validate(&b, false)?;
            let e = |c| Err(Errno::from_raw(c).unwrap());
            if u32::from_le_bytes(b[60..64].try_into().unwrap()) & PA_SUCCESSFUL == 0 {
                return e(EPIN_WRONG_SUCCESS);
            }
            if att.change_flags() != 0x040 {
                return e(EPIN_BAD_REQUEST);
            }
            let (start, len) = att.firmware_request();
            if !(32_768..=2 << 20).contains(&len)
                || start as u64 + len as u64 > memmap::PSRAM_LEN as u64
            {
                return e(EPIN_RANGE_ERR);
            }
            let Some(data) = self.psram.get(start as usize..) else {
                return e(EPIN_AUTH_FAIL);
            };
            if !self.verify_in_ram(data) {
                return e(EPIN_AUTH_FAIL);
            }
            // Would burn `len` bytes (not the header's) and NVIC_SystemReset.
            self.burns.push((start, len));
            Ok(())
        }
    }

    // ---- fixtures ------------------------------------------------------------

    fn test_key() -> SecretKey {
        SecretKey::from_slice(&[0x11; 32]).unwrap()
    }

    /// 65 x 4,096: a real artifact's shape at the smallest size over the floor.
    const SIZE: u32 = 266_240;
    const SHORT_TAIL: u32 = 262_656;

    struct Hdr {
        timestamp0: u8,
        version: &'static [u8],
        declared: u32,
        hw_compat: u32,
    }

    fn good() -> Hdr {
        Hdr {
            timestamp0: 0x25,
            version: b"6.3.5X",
            declared: SIZE,
            hw_compat: 0x28,
        }
    }

    /// A signed Mk4-shaped image of `size` bytes.
    fn signed_image(size: u32, hdr: Hdr) -> Vec<u8> {
        let mut v: Vec<u8> = (0..size as usize)
            .map(|i| (i * 13 + i / 509) as u8)
            .collect();
        let h = memmap::FW_HEADER_OFFSET as usize;
        v[h..h + 128].fill(0);
        v[h..h + 4].copy_from_slice(&image::FW_HEADER_MAGIC.to_le_bytes());
        v[h + 4] = hdr.timestamp0;
        v[h + 5] = 0x09;
        v[h + 12..h + 12 + hdr.version.len()].copy_from_slice(hdr.version);
        v[h + 24..h + 28].copy_from_slice(&hdr.declared.to_le_bytes());
        v[h + 32..h + 36].copy_from_slice(&hdr.hw_compat.to_le_bytes());
        let end = (hdr.declared as usize).min(v.len());
        let mut s = Sha256::new();
        s.update(&v[..h + 64]);
        s.update(&v[h + 128..end]);
        let check: [u8; 32] = Sha256::digest(s.finalize()).into();
        let sig = Secp256k1::new().sign_ecdsa(&Message::from_digest(check), &test_key());
        v[h + 64..h + 128].copy_from_slice(&sig.serialize_compact());
        v
    }

    fn stage<P: Psram>(s: &mut Stager<P>, img: &[u8]) {
        s.admit(&CoordinatorUpgradeMessage::PrepareUpgrade2 {
            size: img.len() as u32,
            firmware_digest: firmware_digest(img).unwrap(),
        })
        .unwrap();
        s.admit(&CoordinatorUpgradeMessage::EnterUpgradeMode)
            .unwrap();
        for c in img.chunks(4096) {
            s.feed(c).unwrap();
        }
        assert_eq!(
            s.state(),
            State::Staged {
                size: img.len() as u32
            }
        );
    }

    fn staged(img: &[u8]) -> Stager<FakePsram> {
        let mut s = Stager::new(FakePsram::new(img.len()));
        stage(&mut s, img);
        s
    }

    fn yes<P: Psram>(w: &Workflow<'_, P>) -> Confirmation {
        Confirmation::Confirmed { shown: w.prompt() }
    }

    // ---- acceptance: the two valid fixtures -----------------------------------

    /// Blank PIN: 18/0 then exactly one 18/7, with `CHANGE_FIRMWARE` and the
    /// checked `(0, len)`; the gate verifies the HMAC it made, so the struct was
    /// passed back verbatim. A second request is refused without a gate call.
    #[test]
    fn blank_pin_reaches_exactly_one_well_formed_request() {
        let img = signed_image(SIZE, good());
        let s = staged(&img);
        let mut g = FakeGate::new(s.staged_view().unwrap(), None);
        let mut w = Workflow::begin(&s).unwrap();
        assert_eq!(w.setup(&mut g), Ok(PinState::Blank));
        w.confirm(yes(&w)).unwrap();
        assert_eq!(
            w.request_install(&mut g),
            Ok(InstallRequested {
                start: 0,
                len: SIZE
            })
        );
        assert_eq!(g.calls, [Call::Setup, Call::Install]);
        assert_eq!(g.burns, [(0, SIZE)]);
        assert_eq!(w.request_install(&mut g), Err(Refusal::Finished));
        assert_eq!(w.confirm(yes(&w)), Err(Refusal::Finished));
        assert_eq!(g.calls.len(), 2, "no call after the one request");
    }

    /// python-ecdsa (signit.py:354) does not normalize s, so about half of all
    /// key-0 images carry a high-S signature. uECC_verify accepts it, so the gate
    /// must too; a high-S signature over the wrong digest is still refused.
    #[test]
    fn gate_accepts_high_s_like_uecc_and_still_refuses_a_bad_one() {
        let mut img = signed_image(SIZE, good());
        let h = memmap::FW_HEADER_OFFSET as usize;
        // s' = n - s, big-endian, on the low-S s that libsecp256k1 produced.
        let n = secp256k1::constants::CURVE_ORDER;
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let d = n[i] as i16 - img[h + 96 + i] as i16 - borrow;
            img[h + 96 + i] = d.rem_euclid(256) as u8;
            borrow = (d < 0) as i16;
        }
        let high = secp256k1::ecdsa::Signature::from_compact(&img[h + 64..h + 128]).unwrap();
        let mut low = high;
        low.normalize_s();
        assert_ne!(low, high, "the fixture really is high-S");
        let s = staged(&img);
        let g = FakeGate::new(s.staged_view().unwrap(), None);
        assert!(g.verify_in_ram(&img));
        img[h + 200] ^= 1;
        assert!(!g.verify_in_ram(&img));
    }

    /// PIN set: a wrong submission is one 18/0 + one 18/2 and nothing more; the
    /// right one logs in and reaches exactly one request.
    #[test]
    fn pin_set_logs_in_once_per_submission_then_requests_once() {
        let img = signed_image(SIZE, good());
        let s = staged(&img);
        let mut g = FakeGate::new(s.staged_view().unwrap(), Some(b"12-34"));
        let mut w = Workflow::begin(&s).unwrap();
        assert_eq!(w.setup(&mut g), Ok(PinState::PinSet { attempts_left: 13 }));
        assert_eq!(w.request_install(&mut g), Err(Refusal::OutOfOrder));
        w.confirm(yes(&w)).unwrap();
        assert_eq!(
            w.submit_pin(&mut g, b"99-99"),
            Err(Refusal::Gate(GateFault::WrongPin))
        );
        assert_eq!(g.calls, [Call::Setup, Call::Setup, Call::Login]);
        assert_eq!(g.attempts_left(), 12);
        w.submit_pin(&mut g, b"12-34").unwrap();
        assert_eq!(g.attempts_left(), 13, "a good login re-arms the budget");
        assert_eq!(
            w.request_install(&mut g),
            Ok(InstallRequested {
                start: 0,
                len: SIZE
            })
        );
        assert_eq!(
            g.calls,
            [
                Call::Setup,
                Call::Setup,
                Call::Login,
                Call::Setup,
                Call::Login,
                Call::Install
            ]
        );
        assert_eq!(g.burns, [(0, SIZE)]);
        assert_eq!(w.submit_pin(&mut g, b"12-34"), Err(Refusal::Finished));
    }

    // ---- consent -------------------------------------------------------------

    #[test]
    fn no_consent_declined_or_no_keypad_never_reach_the_gate_install() {
        let img = signed_image(SIZE, good());
        let s = staged(&img);
        for answer in [
            None,
            Some(Confirmation::Declined),
            Some(Confirmation::NoKeypad),
        ] {
            let mut g = FakeGate::new(s.staged_view().unwrap(), None);
            let mut w = Workflow::begin(&s).unwrap();
            w.setup(&mut g).unwrap();
            match answer {
                None => assert_eq!(w.request_install(&mut g), Err(Refusal::NoConsent)),
                Some(a) => {
                    assert_eq!(w.confirm(a), Err(Refusal::Cancelled));
                    // A later "yes" cannot revive a cancelled workflow.
                    assert_eq!(w.confirm(yes(&w)), Err(Refusal::Finished));
                    assert_eq!(w.request_install(&mut g), Err(Refusal::Finished));
                }
            }
            assert!(!g.calls.contains(&Call::Install), "{answer:?}");
        }
    }

    /// A confirmation of a digest other than this image's grants nothing, and a
    /// PIN-set unit spends no counter tick before consent.
    #[test]
    fn consent_is_bound_to_the_shown_digest_and_precedes_any_login() {
        let img = signed_image(SIZE, good());
        let s = staged(&img);
        let mut g = FakeGate::new(s.staged_view().unwrap(), Some(b"12-34"));
        let mut w = Workflow::begin(&s).unwrap();
        w.setup(&mut g).unwrap();
        assert_eq!(w.submit_pin(&mut g, b"12-34"), Err(Refusal::NoConsent));
        assert_eq!(g.calls, [Call::Setup], "no login without consent");
        let mut other = w.prompt();
        other.digest.0[0] ^= 1;
        assert_eq!(
            w.confirm(Confirmation::Confirmed { shown: other }),
            Err(Refusal::NoConsent)
        );
        assert_eq!(w.submit_pin(&mut g, b"12-34"), Err(Refusal::Finished));
        assert!(!g.calls.contains(&Call::Login));
    }

    /// A replacement image needs `&mut Stager`, so the old workflow (and its
    /// grant) must be gone first; the new workflow starts with no consent even
    /// for byte-identical content.
    #[test]
    fn a_replacement_image_starts_without_consent() {
        let a = signed_image(SIZE, good());
        let mut s = staged(&a);
        {
            let mut w = Workflow::begin(&s).unwrap();
            let mut g = FakeGate::new(s.staged_view().unwrap(), None);
            w.setup(&mut g).unwrap();
            w.confirm(yes(&w)).unwrap();
        }
        for replacement in [a.clone(), {
            let mut b = a.clone();
            b[20_000] ^= 0xff;
            b
        }] {
            stage(&mut s, &replacement);
            let mut g = FakeGate::new(s.staged_view().unwrap(), None);
            let mut w = Workflow::begin(&s).unwrap();
            w.setup(&mut g).unwrap();
            assert_eq!(w.request_install(&mut g), Err(Refusal::NoConsent));
            assert!(g.burns.is_empty());
        }
    }

    // ---- reset / re-entry ----------------------------------------------------

    /// A reset between transitions: the gate's nonce moves, so the struct signed
    /// before it is `EPIN_HMAC_FAIL` and the request fails — once. The next boot
    /// is a new workflow that needs new consent.
    #[test]
    fn a_reset_between_setup_and_request_is_a_failed_request_not_a_retry() {
        let img = signed_image(SIZE, good());
        let s = staged(&img);
        let mut g = FakeGate::new(s.staged_view().unwrap(), None);
        let mut w = Workflow::begin(&s).unwrap();
        w.setup(&mut g).unwrap();
        w.confirm(yes(&w)).unwrap();
        g.reboot();
        assert_eq!(
            w.request_install(&mut g),
            Err(Refusal::Gate(GateFault::StaleAttempt(EPIN_HMAC_FAIL)))
        );
        assert_eq!(w.request_install(&mut g), Err(Refusal::Finished));
        drop(w);
        let mut w = Workflow::begin(&s).unwrap();
        w.setup(&mut g).unwrap();
        assert_eq!(w.request_install(&mut g), Err(Refusal::NoConsent));
        assert!(g.burns.is_empty());
        assert_eq!(g.calls, [Call::Setup, Call::Install, Call::Setup]);
    }

    /// Same, on the PIN path: a login struct from before the reset is refused by
    /// the gate on the install request.
    #[test]
    fn a_reset_after_login_invalidates_the_logged_in_struct() {
        let img = signed_image(SIZE, good());
        let s = staged(&img);
        let mut g = FakeGate::new(s.staged_view().unwrap(), Some(b"12-34"));
        let mut w = Workflow::begin(&s).unwrap();
        w.setup(&mut g).unwrap();
        w.confirm(yes(&w)).unwrap();
        w.submit_pin(&mut g, b"12-34").unwrap();
        g.reboot();
        assert_eq!(
            w.request_install(&mut g),
            Err(Refusal::Gate(GateFault::StaleAttempt(EPIN_HMAC_FAIL)))
        );
        assert!(g.burns.is_empty());
    }

    // ---- PIN outcomes ----------------------------------------------------------

    /// The floor: at 2 attempts left no login is made at all.
    #[test]
    fn the_attempt_floor_refuses_before_any_login() {
        let img = signed_image(SIZE, good());
        let s = staged(&img);
        let mut g = FakeGate::new(s.staged_view().unwrap(), Some(b"12-34"));
        g.wrong_since_good = 11;
        let mut w = Workflow::begin(&s).unwrap();
        assert_eq!(w.setup(&mut g), Ok(PinState::PinSet { attempts_left: 2 }));
        w.confirm(yes(&w)).unwrap();
        assert_eq!(
            w.submit_pin(&mut g, b"12-34"),
            Err(Refusal::AttemptsFloor { attempts_left: 2 })
        );
        assert_eq!(g.calls, [Call::Setup, Call::Setup]);
        assert_eq!(g.attempts_left(), 2, "nothing spent");
    }

    /// At 3 left a wrong PIN is permitted once, and then the floor holds.
    #[test]
    fn a_wrong_pin_at_the_edge_leaves_the_floor_intact() {
        let img = signed_image(SIZE, good());
        let s = staged(&img);
        let mut g = FakeGate::new(s.staged_view().unwrap(), Some(b"12-34"));
        g.wrong_since_good = 10;
        let mut w = Workflow::begin(&s).unwrap();
        w.setup(&mut g).unwrap();
        w.confirm(yes(&w)).unwrap();
        assert_eq!(
            w.submit_pin(&mut g, b"00-00"),
            Err(Refusal::Gate(GateFault::WrongPin))
        );
        assert_eq!(
            w.submit_pin(&mut g, b"12-34"),
            Err(Refusal::AttemptsFloor { attempts_left: 2 })
        );
        assert_eq!(
            g.calls.iter().filter(|c| **c == Call::Login).count(),
            1,
            "exactly one counted call across both submissions"
        );
    }

    /// Every non-wrong-PIN login fault is one login call, an explicit outcome,
    /// and the end of the workflow — never an automatic retry (`EPIN_AE_FAIL`
    /// especially, which Coldcard's Python retries).
    #[test]
    fn login_faults_are_explicit_single_shot_outcomes() {
        let img = signed_image(SIZE, good());
        let s = staged(&img);
        for (code, want) in [
            (EPIN_AE_FAIL, GateFault::SecureElement(EPIN_AE_FAIL)),
            (EPIN_SE2_FAIL, GateFault::SecureElement(EPIN_SE2_FAIL)),
            (EPIN_HMAC_FAIL, GateFault::StaleAttempt(EPIN_HMAC_FAIL)),
            (EPIN_MUST_WAIT, GateFault::MustWait),
            (EPIN_I_AM_BRICK, GateFault::Bricked),
        ] {
            let mut g = FakeGate::new(s.staged_view().unwrap(), Some(b"12-34"));
            let mut w = Workflow::begin(&s).unwrap();
            w.setup(&mut g).unwrap();
            w.confirm(yes(&w)).unwrap();
            g.fail_next = Some((Call::Login, code));
            assert_eq!(w.submit_pin(&mut g, b"12-34"), Err(Refusal::Gate(want)));
            assert_eq!(g.calls, [Call::Setup, Call::Setup, Call::Login], "{code}");
            assert_eq!(w.submit_pin(&mut g, b"12-34"), Err(Refusal::Finished));
            assert_eq!(w.request_install(&mut g), Err(Refusal::Finished));
            assert!(g.burns.is_empty());
        }
    }

    #[test]
    fn setup_faults_and_bad_pins_make_no_further_call() {
        let img = signed_image(SIZE, good());
        let s = staged(&img);
        let mut g = FakeGate::new(s.staged_view().unwrap(), None);
        g.fail_next = Some((Call::Setup, EPIN_AE_FAIL));
        let mut w = Workflow::begin(&s).unwrap();
        assert_eq!(
            w.setup(&mut g),
            Err(Refusal::Gate(GateFault::SecureElement(EPIN_AE_FAIL)))
        );
        assert_eq!(g.calls, [Call::Setup]);
        assert_eq!(w.setup(&mut g), Err(Refusal::Finished));

        let mut g = FakeGate::new(s.staged_view().unwrap(), Some(b"12-34"));
        let mut w = Workflow::begin(&s).unwrap();
        w.setup(&mut g).unwrap();
        w.confirm(yes(&w)).unwrap();
        assert_eq!(w.submit_pin(&mut g, b""), Err(Refusal::EmptyPin));
        assert_eq!(w.submit_pin(&mut g, &[b'1'; 33]), Err(Refusal::PinTooLong));
        assert_eq!(g.calls, [Call::Setup], "neither reached the gate");
    }

    // ---- bootloader refusals of the image -----------------------------------

    /// Signature and downgrade refusals are ONE failed request each, never an
    /// installation, and no second request follows.
    #[test]
    fn bootloader_signature_and_downgrade_refusals_are_failed_requests() {
        let tampered = {
            // Flipped AFTER signing: staging and the install boundary both pass
            // (the announced digest is of these bytes), the bootloader refuses.
            let mut v = signed_image(SIZE, good());
            v[100_000] ^= 1;
            v
        };
        let old_timestamp = signed_image(
            SIZE,
            Hdr {
                timestamp0: 0x23,
                ..good()
            },
        );
        let old_major = signed_image(
            SIZE,
            Hdr {
                version: b"2.1.0",
                ..good()
            },
        );
        for img in [tampered, old_timestamp, old_major] {
            let s = staged(&img);
            let mut g = FakeGate::new(s.staged_view().unwrap(), None);
            let mut w = Workflow::begin(&s).expect("passes the install boundary");
            w.setup(&mut g).unwrap();
            w.confirm(yes(&w)).unwrap();
            assert_eq!(
                w.request_install(&mut g),
                Err(Refusal::Gate(GateFault::ImageRefused))
            );
            assert_eq!(w.request_install(&mut g), Err(Refusal::Finished));
            assert_eq!(g.calls, [Call::Setup, Call::Install]);
            assert!(g.burns.is_empty());
        }
    }

    // ---- the install boundary --------------------------------------------------

    /// Staging-valid but not 4 KiB aligned: refused at `begin`, before any gate
    /// call is even possible.
    #[test]
    fn a_short_tail_image_is_refused_at_the_install_boundary() {
        let img = signed_image(
            SHORT_TAIL,
            Hdr {
                declared: SHORT_TAIL,
                ..good()
            },
        );
        let s = staged(&img);
        assert_eq!(
            Workflow::begin(&s).err(),
            Some(Refusal::Image(ImageFault::NotInstallable(
                NotInstallable::Alignment(SHORT_TAIL)
            )))
        );
    }

    /// Header/call length disagreement, oversize, received != call, and a
    /// read-back digest mismatch — on the pure boundary, since staging refuses
    /// every one of these shapes before a `Stager` could hold it.
    #[test]
    fn length_disagreement_oversize_and_digest_mismatch_are_refused() {
        let img = signed_image(SIZE, good());
        let d = firmware_digest(&img).unwrap();
        assert!(check_view(&img, d, SIZE).is_ok());
        // call != header
        assert_eq!(
            check_view(&img, d, SIZE - 4096),
            Err(ImageFault::NotInstallable(NotInstallable::Length(
                StageError::LengthMismatch
            )))
        );
        // header declares past FLASH_FS
        let big = signed_image(
            SIZE,
            Hdr {
                declared: psram::BURN_LEN_MAX + 4096,
                ..good()
            },
        );
        assert_eq!(
            check_view(&big, d, psram::BURN_LEN_MAX + 4096),
            Err(ImageFault::NotInstallable(NotInstallable::Length(
                StageError::TooLarge
            )))
        );
        // received (window) longer than header == call
        let mut long = img.clone();
        long.extend_from_slice(&[0u8; 4096]);
        assert_eq!(
            check_view(&long, d, SIZE),
            Err(ImageFault::Received {
                received: SIZE + 4096,
                call: SIZE
            })
        );
        let mut other = d;
        other.0[31] ^= 1;
        assert_eq!(check_view(&img, other, SIZE), Err(ImageFault::Digest));
    }

    #[test]
    fn request_bounds_are_the_flash_fs_ceiling_not_the_bootloaders() {
        assert!(request_bounds(0, SIZE).is_ok());
        assert!(request_bounds(0, psram::BURN_LEN_MAX).is_ok());
        for (start, len) in [
            (0, psram::BURN_LEN_MAX + 4096),
            (0, 2 << 20),           // the bootloader's own ceiling
            (0, SHORT_TAIL),        // not 4 KiB
            (0, 32_768),            // bootloader floor, below BURN_LEN_MIN
            (4096, SIZE),           // not the staging offset
            (0, u32::MAX & !0xfff), // wrap
        ] {
            assert_eq!(
                request_bounds(start, len),
                Err(ImageFault::Bounds { start, len }),
                "{start} {len}"
            );
        }
    }

    /// Why the controller checks lengths itself: the double, like the
    /// bootloader, verifies the header's length and accepts a caller `len` that
    /// differs from it.
    #[test]
    fn the_bootloader_model_does_not_catch_a_length_disagreement() {
        let mut psram = signed_image(SIZE, good());
        psram.extend_from_slice(&[0u8; 8192]);
        let mut g = FakeGate::new(&psram, None);
        let mut att = PinAttempt::new(&[]).unwrap();
        g.setup(&mut att).unwrap();
        att.set_firmware_request(0, SIZE + 8192);
        assert_eq!(g.request_install(&mut att), Ok(()));
        assert_eq!(g.burns, [(0, SIZE + 8192)], "burned the caller's len");
        assert!(
            request_bounds(0, SIZE + 8192).is_ok(),
            "bounds alone cannot see it"
        );
        let d = firmware_digest(&psram[..SIZE as usize]).unwrap();
        assert!(
            check_view(&psram, d, SIZE + 8192).is_err(),
            "the boundary does"
        );
    }

    /// The fake is strict about ordering and arguments, independent of the
    /// controller: an install struct without `PA_SUCCESSFUL`, without
    /// `CHANGE_FIRMWARE`, or unsigned is refused.
    #[test]
    fn the_fake_gate_enforces_order_and_arguments() {
        let img = signed_image(SIZE, good());
        let mut g = FakeGate::new(&img, Some(b"12-34"));
        let mut att = PinAttempt::new(b"12-34").unwrap();
        g.setup(&mut att).unwrap();
        att.set_firmware_request(0, SIZE);
        assert_eq!(
            g.request_install(&mut att).unwrap_err().signed(),
            EPIN_WRONG_SUCCESS
        );
        let mut att = PinAttempt::new(b"12-34").unwrap();
        g.setup(&mut att).unwrap();
        g.login(&mut att).unwrap();
        assert_eq!(g.login(&mut att).unwrap_err().signed(), EPIN_WRONG_SUCCESS);
        assert_eq!(
            g.request_install(&mut att).unwrap_err().signed(),
            EPIN_BAD_REQUEST
        );
        let mut unsigned = PinAttempt::new(b"12-34").unwrap();
        assert_eq!(g.login(&mut unsigned).unwrap_err().signed(), EPIN_HMAC_FAIL);
        assert!(g.burns.is_empty());
    }

    // ---- fault injection: install, setup, lies, drift -----------------------

    /// Every gate code on 18/7 is ONE failed request: classified, no burn, the
    /// workflow over, and no second request — on both PIN paths.
    #[test]
    fn install_request_faults_are_one_failed_request_each() {
        let img = signed_image(SIZE, good());
        let s = staged(&img);
        for (code, want) in [
            (EPIN_HMAC_FAIL, GateFault::StaleAttempt(EPIN_HMAC_FAIL)),
            (EPIN_OLD_ATTEMPT, GateFault::StaleAttempt(EPIN_OLD_ATTEMPT)),
            (EPIN_AE_FAIL, GateFault::SecureElement(EPIN_AE_FAIL)),
            (EPIN_SE2_FAIL, GateFault::SecureElement(EPIN_SE2_FAIL)),
            (EPIN_I_AM_BRICK, GateFault::Bricked),
            (EPIN_MUST_WAIT, GateFault::MustWait),
            (EPIN_RANGE_ERR, GateFault::Rejected(EPIN_RANGE_ERR)),
            (EPIN_BAD_REQUEST, GateFault::Rejected(EPIN_BAD_REQUEST)),
            (EPIN_WRONG_SUCCESS, GateFault::Rejected(EPIN_WRONG_SUCCESS)),
            (EPIN_AUTH_FAIL, GateFault::ImageRefused),
            (1, GateFault::Other(Errno::from_raw(1).unwrap())),
        ] {
            for pin in [None, Some(&b"12-34"[..])] {
                let mut g = FakeGate::new(s.staged_view().unwrap(), pin);
                let mut w = Workflow::begin(&s).unwrap();
                w.setup(&mut g).unwrap();
                w.confirm(yes(&w)).unwrap();
                if pin.is_some() {
                    w.submit_pin(&mut g, b"12-34").unwrap();
                }
                let before = g.calls.len();
                g.fail_next = Some((Call::Install, code));
                assert_eq!(
                    w.request_install(&mut g),
                    Err(Refusal::Gate(want)),
                    "{code}"
                );
                assert_eq!(w.request_install(&mut g), Err(Refusal::Finished));
                assert_eq!(w.confirm(yes(&w)), Err(Refusal::Finished));
                assert_eq!(g.calls[before..], [Call::Install], "{code} {pin:?}");
                assert!(g.burns.is_empty());
            }
        }
    }

    /// A fault on the 18/0 that opens a PIN submission ends the workflow with no
    /// login and no tick spent; a bricked gate answers 18/0 and nothing follows.
    #[test]
    fn a_setup_fault_inside_a_submission_spends_no_login() {
        let img = signed_image(SIZE, good());
        let s = staged(&img);
        for code in [EPIN_AE_FAIL, EPIN_SE2_FAIL, EPIN_MUST_WAIT] {
            let mut g = FakeGate::new(s.staged_view().unwrap(), Some(b"12-34"));
            let mut w = Workflow::begin(&s).unwrap();
            w.setup(&mut g).unwrap();
            w.confirm(yes(&w)).unwrap();
            g.fail_next = Some((Call::Setup, code));
            assert!(matches!(
                w.submit_pin(&mut g, b"12-34"),
                Err(Refusal::Gate(_))
            ));
            assert_eq!(w.submit_pin(&mut g, b"12-34"), Err(Refusal::Finished));
            assert_eq!(g.calls, [Call::Setup, Call::Setup], "{code}");
            assert_eq!(g.attempts_left(), 13);
        }
        let mut g = FakeGate::new(s.staged_view().unwrap(), Some(b"12-34"));
        g.wrong_since_good = MAX_TARGET_ATTEMPTS;
        let mut w = Workflow::begin(&s).unwrap();
        assert_eq!(w.setup(&mut g), Err(Refusal::Gate(GateFault::Bricked)));
        assert_eq!(w.submit_pin(&mut g, b"12-34"), Err(Refusal::Finished));
        assert_eq!(g.calls, [Call::Setup]);
    }

    /// A gate that returns success but signs contradictory flags is
    /// `Malformed`: the workflow ends and no install request is made.
    #[test]
    fn a_gate_that_lies_about_success_stops_the_workflow() {
        let img = signed_image(SIZE, good());
        let s = staged(&img);
        // 18/0 claims success without blank: on a blank and on a PIN-set unit.
        for pin in [None, Some(&b"12-34"[..])] {
            let mut g = FakeGate::new(s.staged_view().unwrap(), pin);
            g.lie = Some(Call::Setup);
            let mut w = Workflow::begin(&s).unwrap();
            assert_eq!(w.setup(&mut g), Err(Refusal::Gate(GateFault::Malformed)));
            assert_eq!(w.request_install(&mut g), Err(Refusal::Finished));
            assert_eq!(g.calls, [Call::Setup], "{pin:?}");
        }
        // The submission's own 18/0 claims success: no login follows.
        let mut g = FakeGate::new(s.staged_view().unwrap(), Some(b"12-34"));
        let mut w = Workflow::begin(&s).unwrap();
        w.setup(&mut g).unwrap();
        w.confirm(yes(&w)).unwrap();
        g.lie = Some(Call::Setup);
        assert_eq!(
            w.submit_pin(&mut g, b"12-34"),
            Err(Refusal::Gate(GateFault::Malformed))
        );
        assert_eq!(g.calls, [Call::Setup, Call::Setup]);
        // 18/2 returns Ok without PA_SUCCESSFUL.
        let mut g = FakeGate::new(s.staged_view().unwrap(), Some(b"12-34"));
        let mut w = Workflow::begin(&s).unwrap();
        w.setup(&mut g).unwrap();
        w.confirm(yes(&w)).unwrap();
        g.lie = Some(Call::Login);
        assert_eq!(
            w.submit_pin(&mut g, b"12-34"),
            Err(Refusal::Gate(GateFault::Malformed))
        );
        assert_eq!(w.request_install(&mut g), Err(Refusal::Finished));
        assert_eq!(g.calls, [Call::Setup, Call::Setup, Call::Login]);
        assert!(g.burns.is_empty());
    }

    /// A PSRAM whose read-back changes once `drift` is set: models the bytes
    /// changing between consent and the request. Writes follow the silicon's
    /// rule through `psram::check_write`.
    struct DriftPsram {
        cells: Vec<u8>,
        /// `cells` with the byte at `flip_at` XORed with 1.
        drifted: Vec<u8>,
        flip_at: usize,
        drift: std::rc::Rc<core::cell::Cell<bool>>,
    }

    impl Psram for DriftPsram {
        fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), psram::PsramError> {
            psram::check_write(offset, bytes.len())?;
            let (a, b) = (offset as usize, offset as usize + bytes.len());
            self.cells[a..b].copy_from_slice(bytes);
            self.drifted[a..b].copy_from_slice(bytes);
            if (a..b).contains(&self.flip_at) {
                self.drifted[self.flip_at] ^= 1;
            }
            Ok(())
        }
        fn read(&mut self, offset: u32, out: &mut [u8]) -> Result<(), psram::PsramError> {
            let v = self.view(offset + out.len() as u32)?;
            out.copy_from_slice(&v[offset as usize..]);
            Ok(())
        }
        fn view(&self, len: u32) -> Result<&[u8], psram::PsramError> {
            let v = if self.drift.get() {
                &self.drifted
            } else {
                &self.cells
            };
            v.get(..len as usize).ok_or(psram::PsramError::OutOfBounds)
        }
    }

    /// The re-check immediately before the request is live: bytes that change
    /// after `begin` and consent — one body bit, or the header's length field —
    /// are refused at the boundary and never reach 18/7.
    #[test]
    fn readback_drift_after_consent_is_refused_before_the_request() {
        let img = signed_image(SIZE, good());
        let len_field = memmap::FW_HEADER_OFFSET as usize + 24;
        for (at, want) in [
            (100_000, ImageFault::Digest),
            (
                // The header now declares 256 B more than the window holds.
                len_field + 1,
                ImageFault::NotInstallable(NotInstallable::Length(StageError::Truncated)),
            ),
        ] {
            let drift = std::rc::Rc::new(core::cell::Cell::new(false));
            let mut s = Stager::new(DriftPsram {
                cells: vec![0; img.len()],
                drifted: vec![0; img.len()],
                flip_at: at,
                drift: drift.clone(),
            });
            stage(&mut s, &img);
            let mut g = FakeGate::new(&img, None);
            let mut w = Workflow::begin(&s).unwrap();
            w.setup(&mut g).unwrap();
            w.confirm(yes(&w)).unwrap();
            // `Stager` is borrowed by `w`, so the change arrives through the flag.
            drift.set(true);
            assert_eq!(w.request_install(&mut g), Err(Refusal::Image(want)), "{at}");
            assert_eq!(g.calls, [Call::Setup], "no install call");
            assert!(g.burns.is_empty());
        }
    }

    /// Two workflows on one `&Stager`, one physical press: the MUST_WAIT
    /// refusal of the first does not let the second reach a request. `begin`
    /// supersedes w1, and w1's press grants nothing in w2. (Scenario F1 of the
    /// task-07 verify pass.)
    #[test]
    fn a_second_workflow_supersedes_the_first_and_one_press_grants_one_workflow() {
        let img = signed_image(SIZE, good());
        let s = staged(&img);
        let mut g = FakeGate::new(s.staged_view().unwrap(), None);
        let mut w1 = Workflow::begin(&s).unwrap();
        w1.setup(&mut g).unwrap();
        let press = yes(&w1);
        w1.confirm(press).unwrap();
        let mut w2 = Workflow::begin(&s).unwrap();
        g.fail_next = Some((Call::Install, EPIN_MUST_WAIT));
        assert_eq!(w1.request_install(&mut g), Err(Refusal::Finished));
        assert_eq!(w1.confirm(press), Err(Refusal::Finished));
        assert_eq!(g.calls, [Call::Setup], "superseded w1 reached no gate call");
        w2.setup(&mut g).unwrap();
        assert_eq!(w2.confirm(press), Err(Refusal::NoConsent));
        assert_eq!(w2.request_install(&mut g), Err(Refusal::Finished));
        assert!(
            !g.calls.contains(&Call::Install),
            "no install request at all"
        );
        assert!(g.burns.is_empty());
    }

    /// A press captured in a workflow that was refused (AUTH_FAIL) and dropped
    /// grants nothing in a new workflow on the same, unchanged image; only the
    /// new workflow's own prompt does. (Scenario F2 of the task-07 verify pass.)
    #[test]
    fn a_stale_confirmation_is_refused_by_a_new_workflow_on_the_same_image() {
        let img = signed_image(SIZE, good());
        let s = staged(&img);
        let mut g = FakeGate::new(s.staged_view().unwrap(), None);
        let stale = {
            let mut w = Workflow::begin(&s).unwrap();
            w.setup(&mut g).unwrap();
            let press = yes(&w);
            w.confirm(press).unwrap();
            g.fail_next = Some((Call::Install, EPIN_AUTH_FAIL));
            assert_eq!(
                w.request_install(&mut g),
                Err(Refusal::Gate(GateFault::ImageRefused))
            );
            press
        };
        let mut w = Workflow::begin(&s).unwrap();
        assert_eq!(w.image().digest(), {
            let Confirmation::Confirmed { shown } = stale else {
                unreachable!()
            };
            shown.digest()
        });
        w.setup(&mut g).unwrap();
        let before = g.calls.len();
        assert_eq!(w.confirm(stale), Err(Refusal::NoConsent));
        assert_eq!(w.request_install(&mut g), Err(Refusal::Finished));
        assert_eq!(
            g.calls.len(),
            before,
            "the stale press reached no gate call"
        );
        let mut w = Workflow::begin(&s).unwrap();
        w.setup(&mut g).unwrap();
        w.confirm(yes(&w)).unwrap();
        assert_eq!(
            w.request_install(&mut g),
            Ok(InstallRequested {
                start: 0,
                len: SIZE
            })
        );
        assert_eq!(g.burns, [(0, SIZE)], "fresh consent: exactly one burn");
    }

    /// CROSS-PROCESS, with task 06's updater. Driven by `tools/install-xproc.py`,
    /// which makes a pty, hands this process the MASTER as `COLDSNAP_WIRE_FD`, and
    /// runs `coldsnap-mk4-update --port <slave> <key-0 artifact>` in another
    /// process. Here: [`crate::upgrade::serve`] stages what the updater sent into
    /// a `Stager` this test owns, then the workflow runs on THAT stager against the
    /// strict [`FakeGate`], whose `approved[0]` is key 0's PUBLIC half
    /// (`COLDSNAP_KEY0_PUB`, derived from `00.pem` by the driver). Blank-PIN and
    /// PIN-set each reach exactly one request with a fresh fake. A request to a
    /// fake, NOT an installation: nothing is burned and no callgate is reached.
    /// Panics (never skips) when run without the driver.
    #[cfg(unix)]
    #[test]
    #[ignore = "run by tools/install-xproc.py: needs a pty master fd with task 06's CLI on the slave"]
    fn task06_updater_stages_across_processes_then_one_install_request_each_path() {
        use std::io::{Read, Write};
        struct FdWire(std::fs::File);
        impl crate::upgrade::Wire for FdWire {
            fn read(
                &mut self,
                buf: &mut [u8; coldsnap_hal::usb::MAX_PACKET_SIZE],
            ) -> Option<usize> {
                match self.0.read(buf) {
                    Ok(0) | Err(_) => None,
                    Ok(n) => Some(n),
                }
            }
            fn write(&mut self, bytes: &[u8]) {
                self.0.write_all(bytes).unwrap();
                self.0.flush().unwrap();
            }
        }
        let env = |k: &str| {
            std::env::var(k).unwrap_or_else(|_| panic!("{k} unset: run tools/install-xproc.py"))
        };
        let fd: i32 = env("COLDSNAP_WIRE_FD").parse().unwrap();
        let len: u32 = env("COLDSNAP_XPROC_LEN").parse().unwrap();
        let hex = env("COLDSNAP_KEY0_PUB");
        let key0: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let key0 = PublicKey::from_slice(&key0).expect("key-0 public key");

        // `/dev/fd/N` re-opens the inherited master without `unsafe`, which this
        // module's tripwire bans from the test doubles.
        let mut wire = FdWire(
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(std::format!("/dev/fd/{fd}"))
                .expect("open the inherited pty master"),
        );
        let mut s = Stager::new(FakePsram::new(psram::BURN_LEN_MAX as usize));
        assert_eq!(
            crate::upgrade::serve(&mut wire, &mut s),
            crate::upgrade::Outcome::Staged { size: len }
        );
        drop(wire);

        for pin in [None, Some(&b"12-34"[..])] {
            let mut g = FakeGate::new(s.staged_view().unwrap(), pin);
            g.approved = vec![key0];
            let mut w =
                Workflow::begin(&s).expect("the staged artifact passes the install boundary");
            let state = w.setup(&mut g).unwrap();
            w.confirm(yes(&w)).unwrap();
            if pin.is_some() {
                assert_eq!(state, PinState::PinSet { attempts_left: 13 });
                w.submit_pin(&mut g, b"12-34").unwrap();
            } else {
                assert_eq!(state, PinState::Blank);
            }
            assert_eq!(
                w.request_install(&mut g),
                Ok(InstallRequested { start: 0, len })
            );
            assert_eq!(g.calls.iter().filter(|c| **c == Call::Install).count(), 1);
            assert_eq!(g.burns, [(0, len)]);
            assert_eq!(w.request_install(&mut g), Err(Refusal::Finished));
            let d: std::string::String = w
                .image()
                .digest()
                .0
                .iter()
                .map(|b| std::format!("{b:02x}"))
                .collect();
            std::eprintln!(
                "XPROC pin={} requests=1 start=0 len={len} digest={d} calls={:?}",
                pin.is_some(),
                g.calls
            );
        }
    }

    /// The fake's own at-most-once: a second request after an accepted one is a
    /// test failure, whoever makes it.
    #[test]
    #[should_panic(expected = "a second install request after an accepted one")]
    fn the_fake_gate_panics_on_a_second_accepted_install() {
        let img = signed_image(SIZE, good());
        let mut g = FakeGate::new(&img, None);
        let mut att = PinAttempt::new(&[]).unwrap();
        g.setup(&mut att).unwrap();
        att.set_firmware_request(0, SIZE);
        g.request_install(&mut att).unwrap();
        let _ = g.request_install(&mut att);
    }

    // ---- unbound on device ---------------------------------------------------

    #[test]
    fn the_device_bootloader_is_unbound_and_stops_the_workflow() {
        let img = signed_image(SIZE, good());
        let s = staged(&img);
        let mut w = Workflow::begin(&s).unwrap();
        assert_eq!(
            w.setup(&mut Unbound),
            Err(Refusal::Gate(GateFault::NotBound))
        );
        assert_eq!(w.request_install(&mut Unbound), Err(Refusal::Finished));
        let mut att = PinAttempt::new(&[]).unwrap();
        assert_eq!(Unbound.login(&mut att), Err(Errno::NOT_BOUND));
        assert_eq!(Unbound.request_install(&mut att), Err(Errno::NOT_BOUND));
    }

    /// **A TRIPWIRE.** This module's production code reaches no real gate
    /// function and names no selector: the only way to the callgate is through
    /// `hal/src/callgate.rs`, whose census test is unchanged. And it holds
    /// nothing identity- or session-shaped.
    ///
    /// THE MUTATION: in `Unbound::setup`, add
    /// `#[cfg(target_arch = "arm")] return coldsnap_hal::callgate::pin_setup_attempt(_att);`
    /// — the `cfg(arm)` gate is load-bearing. `pin_setup_attempt` exists only on
    /// `target_arch = "arm"`, so an UNGATED call is refused by the host compiler
    /// (E0425) before this test runs; that still blocks the build but does not
    /// exercise this assertion. The gated call compiles on the host and is caught
    /// here by the `pin_setup_attempt` needle.
    #[test]
    fn nothing_here_reaches_a_real_gate_or_an_identity() {
        let prod = include_str!("install.rs")
            .split_once("#[cfg(test)]")
            .expect("the test module marker")
            .0;
        let code: std::string::String = prod
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            code.contains("impl Bootloader for Unbound"),
            "cut kept the code"
        );
        for needle in [
            "pin_setup_attempt",
            "callgate::call",
            "raw(",
            "raw_mut",
            "SELECTOR_",
            "PIN_SUBCALL",
            "asm!",
            "Session",
            "DeviceId",
            "Outbox",
            "Entropy",
            "ShareStore",
            "Vec<",
            "Box<",
            "extern crate alloc",
        ] {
            assert!(
                !code.contains(needle),
                "`{needle}` in install.rs production code"
            );
        }
        // The doubles in this test module never fall back to a real gate: no
        // callgate function, raw pointer or unsafe block above this test.
        let doubles = include_str!("install.rs")
            .split_once("#[cfg(test)]")
            .unwrap()
            .1
            .split_once("fn nothing_here_reaches_a_real_gate_or_an_identity")
            .expect("this test's own name")
            .0;
        let doubles: std::string::String = doubles
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            doubles.contains("impl Bootloader for FakeGate"),
            "cut kept the fake"
        );
        for needle in [
            "pin_setup_attempt(",
            "callgate::call",
            "callgate::raw",
            "as_mut_ptr",
            "unsafe",
            "asm!",
        ] {
            assert!(
                !doubles.contains(needle),
                "`{needle}` in install.rs's test doubles"
            );
        }
        assert_eq!(code.matches("crate::").count(), 2);
        assert!(code.contains("use crate::firmware_digest;"));
        assert!(code.contains("use crate::upgrade::Stager;"));
    }
}

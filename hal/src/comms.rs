//! Frostsnap wire framing over a byte transport: bounded, gated, alloc-free.
//!
//! [`crate::usb`] moves opaque bytes. This module is the only place that knows
//! what those bytes *mean*. It is the device end of frostsnap's **upstream**
//! serial protocol and it reuses the vendored wire format verbatim rather than
//! restating it — [`frostsnap_comms::make_progress_on_magic_bytes`] and
//! [`frostsnap_comms::BINCODE_CONFIG`] are called, not reimplemented, because a
//! second implementation of a handshake is a second thing to keep byte-identical
//! with a coordinator we do not control.
//!
//! # The wire, as read
//!
//! From `vendor/frostsnap/frostsnap_comms/src/lib.rs`. Three facts shape
//! everything below.
//!
//! **There is no length prefix.** A frame is self-delimiting `bincode`
//! (`BINCODE_CONFIG` = little-endian, varint, `lib.rs:60-63`). A frame's length
//! is not knowable until it has been decoded. So a size bound cannot be checked
//! on arrival; it can only be enforced by refusing to *buffer* more than the
//! bound — which is what [`FRAME_LIMIT`] and [`Link`]'s fixed array do. The
//! bound is structural, not a comparison someone can forget to write.
//!
//! **The connection is gated on a magic-byte handshake.** Upstream's device loop
//! (`device/src/esp32_run.rs:346-370`) has exactly two states: before the first
//! detection of the coordinator's 7-byte pattern it *discards* every byte it
//! reads while scanning; after it, it decodes frames. [`Link`] reproduces that,
//! which is also the fail-closed shape — no coordinator-controlled bytes reach a
//! decoder, let alone `frostsnap_core`, until the handshake completes.
//!
//! **Both directions are typed, and the device is the `Upstream` end.** The
//! device *receives* [`frostsnap_comms::ReceiveSerial<Upstream>`] and *sends*
//! `ReceiveSerial<Downstream>`; `MagicBytes<O>`'s `Encode` adds
//! `O::VERSION_SIGNAL` to the last byte (`lib.rs:396-404`), so the pattern we
//! scan for and the pattern we answer with differ in that byte. Getting this
//! backwards produces a device that never links, so [`MAGIC_REPLY`] is pinned
//! byte-for-byte against the vendored encoder by
//! `magic_reply_matches_the_vendored_encoder`.
//!
//! # `FRAME_LIMIT` is 4,096, and that is a reversal
//!
//! It was **2,060** until 2026-08-18. That number is `MAX_MSG_LEN` from
//! Coldcard's **HID** reassembly buffer (`shared/public_constants.py:26-31`,
//! `shared/usb.py:140-172`) — a bound on a 64-byte-report framing this transport
//! does not use and that `frostsnap_comms` has never heard of. Nothing in CDC or
//! in the frostsnap wire format requires it.
//!
//! Enforcing it refused **four real messages**, all measured on the full
//! `ReceiveSerial` frame: a `SignatureShare` carrying a full 30-nonce replenish
//! (**2,105 B** with a single share), an inbound `RequestSign` at 11 owned inputs
//! (**2,238 B**), keygen `CertifyPlease` at 9-of-9 (**2,179 B**), and
//! `HeldShares2` at 14 stored shares (**2,215 B**) — that last one emitted by
//! *this device*, so not even coordinator-provoked. A ceiling borrowed from
//! another transport's framing that refuses the protocol's own traffic is not a
//! security property. It is now 4,096; see DECISIONS.md 7 for the reversal and
//! the declared support envelope.
//!
//! *Some* hard bound must still exist, because the bytes are attacker-controlled
//! and the vendored decoder's own limit is `1 << 15` (`lib.rs:57`) — 32 KiB is 5%
//! of SRAM and not a bound this device can honour. (That limit is no longer what
//! this module decodes under: see [`DECODE_ALLOC_LIMIT`], which is a separate
//! refusal, because `FRAME_LIMIT` bounds *wire bytes* and never bounded what those
//! bytes make the decoder allocate.) **4,096 rather than 3,072** because 3,072
//! fails `RequestSign` at 20 owned inputs / 3 outputs (**3,944 B**), which is inside
//! the declared envelope. (This used to cite a two-segment `NonceResponse` at 4,038 B
//! "which the coordinator can force: its producer never calls
//! `OpenNonceStreams::split()`". That claim was **false** — it does split; corrected
//! 2026-08-19, see [`FRAME_LIMIT`] and PLAN.md §7 cap 1.)
//!
//! The SRAM cost is **2 × `FRAME_LIMIT`, not one**: the accumulator is
//! `[u8; FRAME_LIMIT]` inline in [`Link`] *and* [`encode_frame`] takes a
//! `&mut [u8; FRAME_LIMIT]`. So the raise costs 4,120 → 8,192 B, 1.25% of 640 KiB.
//!
//! # What 4,096 buys, and what it does not
//!
//! **Buys.** Every frame measured inside the declared envelope — *n* ≤ 12
//! devices at any *t* ≤ *n* (12-of-12 `CertifyPlease` = 2,863 B, 1,233 spare), up
//! to 20 owned inputs, a full nonce batch riding along with a `SignatureShare`,
//! and a two-segment `NonceResponse`. Signing and keygen are no longer refused by
//! the transport. Pinned executably by `the_four_frames_the_old_bound_refused_now_fit`
//! and `real_signature_share_batch_now_fits_within_the_raised_bound`.
//!
//! **Does not buy.** *n* ≥ 13 (13-of-13 `CertifyPlease` = 3,091 B fits, but
//! `Check` at 163·*n* + 157 and one added upstream field do not leave a margin
//! worth declaring), more than 20 owned inputs, three or more nonce segments
//! (~6 KB, and unbounded), and a hostile `key_name`/`ScriptBuf`. Those are
//! refusals, not fixes: [`Link::poll`] reports [`CommsError::Desync`] and
//! [`encode_frame`] reports [`CommsError::FrameTooLong`], which is a dropped
//! message rather than a corrupt one. The new refusal boundary is pinned by
//! `one_byte_over_the_limit_is_refused` and
//! `three_nonce_segments_are_refused_by_the_new_bound`.
//!
//! # Three device-side caps: REQUIRED and UNIMPLEMENTED
//!
//! 4,096 is necessary but **not sufficient**, and this is the part a bigger
//! number does not solve. Nothing bounds what the device *constructs*, so the
//! device can still build a frame over any bound and then have its own encoder
//! refuse it. Three caps are required. None can be written yet: they all live in
//! message-construction code that does not exist in this tree — there is no event
//! loop, no bin target and nothing that calls [`encode_frame`] outside tests.
//!
//! 1. **One nonce segment per frame.** `NonceResponse` is unbounded in segment
//!    count (2 segments = 4,038 B, 3 ≈ 6 KB), and the count is the **coordinator's**
//!    choice, not ours: `device.rs:273-296` emits one segment per stream in the
//!    received `OpenNonceStreams`. The real coordinator splits one stream per message
//!    (`nonce_replenish.rs:31`), so live traffic is one segment — but the app asks for
//!    **four** streams, so an unsplit reply is ~8 KB and no `FRAME_LIMIT` in scope
//!    covers it. Whoever builds the reply must emit one segment per frame.
//! 2. **A `HeldShares2` cap.** 188 B + ~150 B per extra stored share, so roughly
//!    26 shares overruns 4,096 — device-emitted, no coordinator involved.
//! 3. **`Debug` truncation.** `WireDeviceSendBody::Debug`'s `String` is unbounded
//!    and is the one field whose length the device picks freely.
//!
//! No helper is added here for any of them, deliberately: a cap with no caller
//! cannot be tested against the code that will need it, and would be wrong by the
//! time it has one. They are recorded in PLAN.md §7 as phase-4 work.
//!
//! # What is host-tested and what cannot be
//!
//! All of it is host-tested. This module has no `cfg`, touches no register and
//! contains no `unsafe`: the transport-dependent half lives in [`crate::usb`].
//! The tests drive real `frostsnap_comms` types through real `bincode`, so they
//! test agreement with the vendored wire format rather than self-consistency.
//!
//! # Allocation
//!
//! [`Link`] itself never allocates: `poll` is generic over the frame type and
//! the accumulator is `[u8; FRAME_LIMIT]` inline. Decoding a real
//! `ReceiveSerial<Upstream>` *does* allocate (`EncapsBody(Vec<u8>)`,
//! `Destination::Particular(BTreeSet<DeviceId>)`), so the choice of `T` is where
//! the global-allocator requirement enters — see PLAN.md §9.
//!
//! **Measured 2026-08-18, and the earlier wording here was misleading.** This used
//! to say "the transport is linkable without an allocator today", which was true
//! only in the sense that nothing in this tree instantiates `poll` at the concrete
//! inbound type for ARM. Force that monomorphisation and the firmware **does**
//! require a `#[global_allocator]`:
//!
//! ```text
//! cargo rustc --release -p coldsnap_hal --crate-type staticlib
//! error: no global memory allocator found but one is required
//! ```
//!
//! Note that `cargo build --release` does **not** report this, because the
//! workspace builds rlibs and an rlib defers the allocator check to link time. So
//! a clean device build is not evidence either way. The requirement is real and
//! arrives the moment the device decodes its first real inbound frame; the only
//! thing deferring it is the absence of a caller.
//!
//! Since the heap is real, how much of it one inbound frame may demand is a
//! refusal this module owns: see [`DECODE_ALLOC_LIMIT`]. The *extent* of the heap
//! is [`crate::heap`]'s, and is deferred.

use bincode::error::{DecodeError, EncodeError};
use frostsnap_comms::{Downstream, Upstream, BINCODE_CONFIG, MAGIC_BYTES_LEN};

/// The frame type this device **receives**, and the only `T` [`Link::poll`] should be
/// instantiated at in firmware.
///
/// Exported because the device is the `Upstream` end and getting that backwards
/// produces a device that never links — see the module docs on [`MAGIC_REPLY`]. Naming
/// it once here means a caller cannot pick the wrong direction by accident, and it keeps
/// `frostsnap_comms` off the firmware crate's dependency list.
pub type FromCoordinator = frostsnap_comms::ReceiveSerial<Upstream>;

/// The frame type this device **sends**. Pair of [`FromCoordinator`].
pub type ToCoordinator = frostsnap_comms::ReceiveSerial<Downstream>;

/// Re-exported so firmware can match on frame variants and bodies without taking a
/// direct dependency on the vendored crate, the way `frostsnap_coordinator` re-exports
/// `serialport`. One version of the wire format in the graph, by construction.
pub use frostsnap_comms::{CoordinatorSendBody, ReceiveSerial};

/// Largest frame this device will send or reassemble, in bytes.
///
/// Raised from 2,060 on 2026-08-18 — see the module docs and DECISIONS.md 7 for
/// why 2,060 was the wrong number and why 4,096 is this one. It bounds both
/// directions: [`encode_frame`] refuses to produce a longer frame, and [`Link`]
/// refuses to buffer one. Costs 2 × this many bytes of SRAM, not one.
pub const FRAME_LIMIT: usize = 4096;

/// A frame must at minimum be able to hold the handshake reply, or the device
/// could not link at all. Cheap, but it is the invariant that would break first
/// if someone "tuned" [`FRAME_LIMIT`] down.
const _: () = {
    assert!(FRAME_LIMIT >= MAGIC_REPLY.len());
    // The bound is only meaningful if it is tighter than bincode's own limit;
    // otherwise it is decoration and the real ceiling is 32 KiB of SRAM.
    assert!(FRAME_LIMIT < 1 << 15);
};

/// Ceiling on what one inbound frame may make `bincode` *claim*, in bytes.
///
/// [`FRAME_LIMIT`] bounds the bytes a coordinator may put on the wire.
/// It does **not** bound what those bytes make the decoder allocate: every
/// `Vec`/`String` in the decoded type is built from a length varint *before* the
/// payload is read (`bincode-2.0.1` `impl_alloc.rs:269` is `alloc::vec![0u8;
/// len]`), and the only ceiling on that length is the config's limit. The
/// vendored [`BINCODE_CONFIG`] sets it to `1 << 15` = **8 × `FRAME_LIMIT`**
/// (`frostsnap_comms/src/lib.rs:54`), so a ten-byte frame buys a 32,748-byte
/// allocation — measured, and pinned by
/// `an_over_claiming_frame_is_refused_before_it_allocates`.
///
/// Worse, that lands on [`DecodeError::UnexpectedEnd`], the one error `drain`
/// treats as "more bytes are coming" and keeps buffered, so the allocation is
/// re-attempted on **every** subsequent [`Link::poll`] — including `poll(&[])`.
/// With `panic = "abort"` and no `#[alloc_error_handler]` on stable, an OOM is
/// `handle_alloc_error` → `#[panic_handler]` → `NVIC_SystemReset`
/// (DECISIONS.md 6), i.e. a remote coordinator holding the device in a reset
/// loop. So this is a refusal, not a tuning knob: no `cfg`, no feature.
///
/// **Why 2 × [`FRAME_LIMIT`] is the right size, and why it costs nothing
/// legitimate.** `bincode` charges a container `len * size_of::<T>()`
/// (`de/mod.rs:182-191`). In the type this device decodes —
/// `ReceiveSerial<Upstream>` — every container's element is as large on the wire
/// as it is in memory: `EncapsBody(Vec<u8>)` is 1:1, and
/// `Destination::Particular(BTreeSet<DeviceId>)` holds `DeviceId(pub [u8; 33])`
/// (`frostsnap_core/src/lib.rs:51`), a byte array, not a `Point`. A frame that
/// fits [`FRAME_LIMIT`] therefore cannot legitimately claim much more than
/// [`FRAME_LIMIT`], which
/// `a_limit_sized_frame_of_device_ids_still_decodes_under_the_new_limit` holds to
/// within the envelope. The factor of 2 is margin for a future vendored field
/// whose in-memory size exceeds its wire size — the case that *would* make an
/// exact-`FRAME_LIMIT` bound refuse real traffic.
///
/// **What this does not cover.** The nested decode inside
/// `WireCoordinatorSendBody::decode` re-enters `bincode` over the `EncapsBody`
/// bytes with the vendored config, and that leg is not changed by *this* constant:
/// its errors are already discarded by the vendored `.ok()` (a silent refusal, not a
/// panic), and it can only ever run on bytes this limit already bounded. It is
/// bounded separately, by [`ENCAPS_DECODE_LIMIT`] via [`decode_body`] — recorded in
/// PLAN.md §9 item 7.
pub const DECODE_ALLOC_LIMIT: usize = 2 * FRAME_LIMIT;

/// [`BINCODE_CONFIG`] with [`DECODE_ALLOC_LIMIT`] in place of the vendored
/// `1 << 15`, and *nothing else* changed: same `LittleEndian`, same `Varint`.
///
/// Decode-side only — `LIMIT` is never read by `bincode`'s encoder, so this
/// changes zero wire bytes and needs no agreement from the coordinator, unlike
/// every other way of bounding a frame. [`encode_frame`] keeps
/// [`BINCODE_CONFIG`] so that the outbound path is visibly byte-identical with
/// the vendored encoder.
const DECODE_CONFIG: bincode::config::Configuration<
    bincode::config::LittleEndian,
    bincode::config::Varint,
    bincode::config::Limit<DECODE_ALLOC_LIMIT>,
> = bincode::config::standard().with_limit::<DECODE_ALLOC_LIMIT>();

/// The bound on the **nested** `EncapsBody` decode, the one the outer limit does
/// not reach.
///
/// # Why this is a second limit and not the same one
///
/// [`Link::poll`] decodes a `ReceiveSerial<Upstream>` under
/// [`DECODE_ALLOC_LIMIT`]. That leg is 1:1 — `EncapsBody(Vec<u8>)` and
/// `DeviceId([u8; 33])` are the same size in memory as on the wire — so a frame
/// that fits [`FRAME_LIMIT`] cannot legitimately claim much more. The **inner**
/// body is not: it carries `secp256kfun` `Point`s, 33 compressed bytes on the wire
/// against `size_of::<Point>()` in memory, so inner claims amplify.
///
/// # The number, derived
///
/// Measured 2026-08-18. Amplification is **3.64x release / 4.36x debug**
/// (`size_of::<Point>()` = 120 B release, 144 B debug). The blob is bounded by the
/// frame, so ≤ ~4,060 B after the envelope. Worst legitimate claim is therefore
/// `4.36 * 4,060 ≈ 17,702 B` — **in debug**, which is the column that governs.
/// `5 * FRAME_LIMIT` clears it by ~2.8 KB and is 37% below the 32,768 it replaced.
/// (The vendored `MAX_MESSAGE_ALLOC_SIZE` was itself lowered to this same 20,480 on
/// 2026-08-19, once the device->coordinator leg was measured at 17,664 B debug. This
/// constant stays the binding one: a re-vendor reverts that literal, not this file.)
///
/// **Sized off the DEBUG column deliberately.** A 16 KiB limit refuses nothing in
/// release but sits below 17,702, so host tests and the device would disagree about
/// where the refusal boundary is. That is the profile-divergence class PLAN.md §8.1
/// already records — `overflow-checks = false` in release and `true` in dev made one
/// coordinator message panic in tests and wrap in firmware. A bound whose position
/// moves with `debug_assertions` is the same trap.
///
/// The largest *legitimate* inner allocation actually measured is 5,120 B release /
/// 6,144 B debug, so the headroom over observed traffic is ~3.3x. The gap between
/// that and 20,480 is deliberate: it covers the in-envelope inner messages nobody
/// has measured yet (`DisplayBackup`, `Consolidate`, restoration, naming,
/// screen-verify), where a refusal would be a permanent interop failure on
/// legitimate traffic — strictly worse than the DoS being prevented.
pub const ENCAPS_DECODE_LIMIT: usize = 5 * FRAME_LIMIT;

/// [`BINCODE_CONFIG`] with [`ENCAPS_DECODE_LIMIT`]. Decode-side only, so zero wire
/// bytes change and the coordinator needs to agree to nothing.
const ENCAPS_CONFIG: bincode::config::Configuration<
    bincode::config::LittleEndian,
    bincode::config::Varint,
    bincode::config::Limit<ENCAPS_DECODE_LIMIT>,
> = bincode::config::standard().with_limit::<ENCAPS_DECODE_LIMIT>();

/// `bincode`'s `Limit<L>` charges the 8-byte length claim against the same budget,
/// so the largest container it admits is `L - 8`, not `L`. Measured by bisection and
/// pinned by `the_inner_limit_boundary_is_exact`; named here because it is the
/// figure the relation below has to clear.
pub const ENCAPS_LIMIT_OVERHEAD: usize = 8;

/// The inner limit must clear the worst legitimate claim in the *debug* profile, or
/// the host tests are measuring a different device from the one that ships.
const _: () = {
    // 4.36x amplification over a blob bounded by the frame, rounded up. Written as
    // integer arithmetic so it is checkable by eye: 436 * 4060 / 100 = 17_701.
    // Checked on the EFFECTIVE budget, not the round constant.
    assert!(ENCAPS_DECODE_LIMIT - ENCAPS_LIMIT_OVERHEAD > 436 * 4060 / 100);
    // And it must actually be an improvement on what it replaces.
    assert!(ENCAPS_DECODE_LIMIT < 1 << 15);
    // The outer leg bounds the blob, so a larger inner limit than the outer one is
    // expected; a SMALLER one would refuse blobs the outer leg admitted.
    assert!(ENCAPS_DECODE_LIMIT > DECODE_ALLOC_LIMIT);
};

/// The exact 8 bytes this device answers a coordinator handshake with:
/// `bincode` variant tag `0` for `ReceiveSerial::MagicBytes` (it is the first of
/// 13 variants, so the varint tag is one byte — `lib.rs:68-85`), then
/// `MAGICBYTES_RECV_DOWNSTREAM` with `Downstream::VERSION_SIGNAL == 2` added to
/// its last byte.
///
/// A const rather than an `encode_frame` call because the ARM send path should
/// not need a [`FRAME_LIMIT`]-byte staging buffer and a monomorphised encoder to
/// say hello.
/// `magic_reply_matches_the_vendored_encoder` proves the two agree.
pub const MAGIC_REPLY: [u8; 1 + MAGIC_BYTES_LEN] =
    [0x00, 0xff, 0xe4, 0x31, 0xb8, 0x02, 0x8b, 0x08];

/// A framing fault, as a value. Never a panic: this module's entire input is
/// coordinator-controlled and `panic = "abort"` makes every reachable panic a
/// brick with no DFU recovery (DECISIONS.md decision 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommsError {
    /// The encoded frame would exceed [`FRAME_LIMIT`]. **Nothing was written.**
    ///
    /// Partial emission is not an option: the wire has no length prefix and no
    /// resynchronisation marker, so a half-written frame desynchronises the
    /// coordinator permanently — every subsequent byte is read at the wrong
    /// offset. Refusing whole is recoverable; truncating is not.
    FrameTooLong,
    /// `bincode` failed to encode for a reason other than running out of room.
    /// Not reachable for the frostsnap types as vendored, but mapping it onto
    /// [`CommsError::FrameTooLong`] would be a lie about which bound tripped.
    EncodeFailed,
    /// The received byte stream cannot be parsed at this offset: either a frame
    /// claimed more than [`FRAME_LIMIT`] bytes, or the bytes are not valid
    /// `bincode` for the expected type, or a frame decoded to zero length.
    ///
    /// [`Link`] has already dropped its buffer and returned to the unlinked
    /// state, so recovery is to wait for the coordinator's next magic bytes (it
    /// re-sends them every `MAGIC_BYTES_PERIOD` = 100 ms, `lib.rs:22`). The
    /// caller must not try to interpret the stream itself.
    Desync,
    /// The body inside the frame claimed more than [`ENCAPS_DECODE_LIMIT`] and was
    /// refused **before** the allocation was made.
    ///
    /// Split out from [`CommsError::BodyUndecodable`] on purpose, and it earns its
    /// keep twice. For a device it is the difference between "the coordinator is
    /// sending something too big for me" and "the coordinator is sending me
    /// nonsense" — different faults with different responses. And in tests it is the
    /// only observable that distinguishes this module's bounded config from the
    /// vendored 32 KiB one: a mid-range over-claim yields *this* under
    /// [`ENCAPS_DECODE_LIMIT`] and a plain decode failure under the vendored limit,
    /// so `an_over_claiming_inner_body_is_refused_before_it_allocates` fails if
    /// anyone swaps the config back. Verified by mutation — without this split, that
    /// swap was silent.
    BodyTooLarge,
    /// The frame decoded, but the **body inside it** did not: it is not valid
    /// `bincode` for a `CoordinatorSendBody`, or it is one of the two dead
    /// compatibility variants (`_Core`/`_Naming`) that a current coordinator never
    /// sends.
    ///
    /// Deliberately *not* [`CommsError::Desync`]. The framing is intact and the
    /// link is still good — one message is unusable. Desyncing on this would drop a
    /// working link over a single bad body, and the vendored
    /// `WireCoordinatorSendBody::decode` loses the distinction entirely by
    /// returning `Option`.
    BodyUndecodable,
}

/// The device end of one upstream serial link: a magic-byte gate in front of a
/// bounded frame reassembler.
///
/// Holds [`FRAME_LIMIT`] bytes inline, so place it in a `static` or a known-deep
/// frame rather than a leaf function's stack.
///
/// Construct with [`Link::new`], hand every received byte to [`Link::poll`], and
/// send with [`encode_frame`] / [`MAGIC_REPLY`]. `Default` forwards to `new` and
/// exists only to satisfy `clippy::new_without_default` — prefer `new`, which is
/// `const` and so usable in a `static`. An unlinked `Link` is the only valid
/// initial state, so the two cannot disagree.
pub struct Link {
    /// Bytes received but not yet decoded into a frame. Only ever the prefix of
    /// a single incomplete frame plus whole frames not yet drained.
    rx: [u8; FRAME_LIMIT],
    rx_len: usize,
    /// How many bytes of the coordinator's magic pattern have matched so far.
    /// Owned by `frostsnap_comms`' state machine, not ours — it is passed in and
    /// taken back out on every call so a pattern split across USB packets still
    /// matches.
    magic_progress: usize,
    linked: bool,
}

impl Link {
    /// A fresh, unlinked link. `const` so it can initialise a `static` without
    /// running code — which matters on a board whose `.bss` is *filled* with
    /// `0xdeadbeef` rather than zeroed (see [`crate::singleton`]); a
    /// `const`-initialised `static` lives in `.data` and is copied from flash by
    /// startup code, whereas a lazily-zeroed one would read `linked == true`
    /// out of garbage and skip the handshake entirely.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            rx: [0u8; FRAME_LIMIT],
            rx_len: 0,
            magic_progress: 0,
            linked: false,
        }
    }

    /// Whether the coordinator's magic bytes have been seen. Until this is true
    /// no received byte is decoded and [`Link::poll`] delivers nothing.
    #[must_use]
    pub const fn is_linked(&self) -> bool {
        self.linked
    }

    /// Bytes currently held in the reassembly buffer. Diagnostic only — it is
    /// the depth of a partial frame, useful at a bench for telling "coordinator
    /// stopped mid-frame" apart from "coordinator sent nothing".
    #[must_use]
    pub const fn pending(&self) -> usize {
        self.rx_len
    }

    /// Drop the link and any partial frame, returning to the pre-handshake
    /// state. Called internally on every [`CommsError::Desync`]; public because
    /// a USB bus reset or a `ReceiveSerial::Reset` frame must have the same
    /// effect and those are the caller's to notice.
    pub fn unlink(&mut self) {
        self.rx_len = 0;
        self.magic_progress = 0;
        self.linked = false;
    }

    /// Feed received bytes and dispatch every complete frame in them.
    ///
    /// This is the whole receive policy in one place: gate, accumulate, decode,
    /// bound, resynchronise. `bytes` is typically one USB packet; passing an
    /// empty slice just drains whatever is already buffered.
    ///
    /// `on_frame` is infallible by construction. It runs *after* the frame's
    /// bytes have been removed from the buffer, so a caller that wants to defer
    /// work can queue and return without risking the same frame twice.
    ///
    /// # Errors
    ///
    /// [`CommsError::Desync`] if the stream cannot be parsed — see that
    /// variant. The link has already been reset when this returns; frames
    /// dispatched before the fault stay dispatched.
    pub fn poll<T, F>(&mut self, bytes: &[u8], mut on_frame: F) -> Result<(), CommsError>
    where
        T: bincode::Decode<()>,
        F: FnMut(T),
    {
        // The gate, once per call. `scan_magic` eats the whole slice unless the
        // pattern completes inside it, in which case the tail is frames — so
        // this cannot need a second pass, and keeping it out of the loop below
        // is what lets that loop's pass budget be exact.
        let mut rest = bytes;
        if !self.linked {
            rest = &rest[self.scan_magic(rest)..];
            if !self.linked {
                return Ok(());
            }
        }

        // One pass per input byte is the worst case; the `..=` supplies the one
        // extra pass that finds the buffer already drained and returns. Bounding
        // the pass count *structurally* is the `flash.rs` `*_SPIN_LIMIT` rule
        // applied to a parser: a fault in the body must be able to produce a
        // wrong answer, never a hung device — and a hang here is a hang in the
        // USB poll loop, where nothing else will ever notice.
        for _ in 0..=rest.len() {
            if rest.is_empty() {
                return self.drain(&mut on_frame);
            }
            let take = (FRAME_LIMIT - self.rx_len).min(rest.len());
            self.rx[self.rx_len..self.rx_len + take].copy_from_slice(&rest[..take]);
            self.rx_len += take;
            rest = &rest[take..];
            self.drain(&mut on_frame)?;
        }

        // Reached only by a pass that consumed nothing, which means the buffer
        // was full and `drain` got no frame out of it: the frame in flight is
        // longer than FRAME_LIMIT. This is the receive-side bound.
        //
        // Note what does *not* depend on this line. `rx` is exactly FRAME_LIMIT
        // bytes, so an over-limit frame can never be decoded no matter what
        // happens here — the safety property is the buffer's size, not this
        // check. What this adds is that the device says so and resynchronises
        // instead of silently dropping the tail of the stream.
        self.unlink();
        Err(CommsError::Desync)
    }

    /// Advance the magic-byte scan, discarding what it consumes. Returns how
    /// many bytes of `bytes` were eaten — everything, unless the pattern
    /// completed, in which case everything up to and including its last byte.
    fn scan_magic(&mut self, bytes: &[u8]) -> usize {
        // A Cell rather than a `&mut usize` capture because
        // `make_progress_on_magic_bytes` takes the iterator by value and returns
        // early on a match; the count has to outlive the iterator.
        let consumed = core::cell::Cell::new(0usize);
        let (progress, found) = frostsnap_comms::make_progress_on_magic_bytes::<Upstream>(
            bytes
                .iter()
                .copied()
                .inspect(|_| consumed.set(consumed.get() + 1)),
            self.magic_progress,
        );
        self.magic_progress = progress;
        if found.is_some() {
            // Discard anything buffered from a previous life: post-handshake
            // offsets have nothing to do with pre-handshake ones.
            self.rx_len = 0;
            self.linked = true;
        }
        consumed.get()
    }

    /// Decode every whole frame currently in `rx`, leaving any partial tail.
    ///
    /// Re-decoding from offset 0 on every pass is O(n²) in the worst case. At
    /// n = [`FRAME_LIMIT`] and 64-byte USB packets that is ~32 re-parses of at
    /// most 2 KB, which is nothing next to one secp256k1 operation.
    // ponytail: O(n²) reassembly. Upgrade path if it ever shows up in a signing
    // latency measurement: have `bincode` tell us the frame length without
    // building the value, which it cannot do today — so the real fix would be a
    // length-prefixed wire format, i.e. an upstream change.
    fn drain<T, F>(&mut self, on_frame: &mut F) -> Result<(), CommsError>
    where
        T: bincode::Decode<()>,
        F: FnMut(T),
    {
        while self.rx_len > 0 {
            match bincode::decode_from_slice::<T, _>(&self.rx[..self.rx_len], DECODE_CONFIG) {
                Ok((frame, n)) => {
                    // `n == 0` is reachable — any `T` that decodes from nothing
                    // does it, and it would spin this loop forever; it is pinned
                    // by `a_zero_length_decode_is_refused_rather_than_looping`.
                    // `n > self.rx_len` is NOT reachable: `decode_from_slice`
                    // cannot read past the slice it was given, so no test here
                    // can provoke it. It is checked anyway, and said to be
                    // unreachable rather than dressed up as covered, because the
                    // alternative is a `copy_within` range panic — and a panic
                    // is a brick.
                    if n == 0 || n > self.rx_len {
                        self.unlink();
                        return Err(CommsError::Desync);
                    }
                    self.rx.copy_within(n..self.rx_len, 0);
                    self.rx_len -= n;
                    on_frame(frame);
                }
                // The only recoverable decode failure: more bytes are coming.
                // Note what this arm implies and why [`DECODE_ALLOC_LIMIT`]
                // exists: a partial frame stays buffered, so anything that
                // allocates *before* reporting `UnexpectedEnd` re-allocates on
                // every poll. `LimitExceeded` deliberately is not here — it is
                // returned before the allocation, and belongs in `Err(_)`.
                Err(DecodeError::UnexpectedEnd { .. }) => return Ok(()),
                Err(_) => {
                    self.unlink();
                    return Err(CommsError::Desync);
                }
            }
        }
        Ok(())
    }
}

impl Default for Link {
    fn default() -> Self {
        Self::new()
    }
}

/// Decode a coordinator body under [`ENCAPS_DECODE_LIMIT`] rather than whatever the
/// vendored `BINCODE_CONFIG` currently says (32 KiB originally; 20,480 since
/// 2026-08-19, but a re-vendor silently restores 32 KiB, which is why this exists).
///
/// Use this and **not** `WireCoordinatorSendBody::decode`. Same result on every
/// legitimate input; the differences are both refusals this device wants:
///
/// - the nested `EncapsV0` decode is bounded (the vendored one is not, and a
///   20-byte inner blob provokes a 32,640 B allocation there — measured);
/// - a failure is a named [`CommsError`] rather than `None`, so "the coordinator
///   sent something I cannot read" is distinguishable from "there was no body".
///
/// The variant mapping is copied from the vendored `decode` so the two cannot
/// disagree about what a body *means*, only about what they will allocate to find
/// out. Pinned by `decode_body_agrees_with_the_vendored_decoder`.
///
/// # Errors
///
/// [`CommsError::BodyUndecodable`] — see that variant. The link stays up.
pub fn decode_body(
    body: frostsnap_comms::WireCoordinatorSendBody,
) -> Result<frostsnap_comms::CoordinatorSendBody, CommsError> {
    use frostsnap_comms::{CoordinatorSendBody as Body, WireCoordinatorSendBody as Wire};
    match body {
        // Dead compatibility variants: a coordinator that still spoke these would
        // be older than any this device supports. The vendored decoder also
        // refuses them (as `None`).
        Wire::_Core | Wire::_Naming => Err(CommsError::BodyUndecodable),
        Wire::AnnounceAck => Ok(Body::AnnounceAck),
        Wire::Cancel => Ok(Body::Cancel),
        Wire::Upgrade(upgrade) => Ok(Body::Upgrade(upgrade)),
        Wire::EncapsV0(encaps) => {
            bincode::decode_from_slice(encaps.as_bytes(), ENCAPS_CONFIG)
                .map(|(inner, _)| inner)
                .map_err(|e| match e {
                    // Refused before allocating. Kept distinct from a plain decode
                    // failure: see `CommsError::BodyTooLarge`.
                    DecodeError::LimitExceeded => CommsError::BodyTooLarge,
                    _ => CommsError::BodyUndecodable,
                })
        }
    }
}

/// Encode one frame into `out`, refusing anything over [`FRAME_LIMIT`].
///
/// The bound is enforced by the buffer's type: `out` is exactly [`FRAME_LIMIT`]
/// bytes, `bincode` stops at its end, and this returns the length actually
/// written. There is no code path that emits a byte before the whole frame has
/// fit, so an over-size frame cannot half-reach the wire.
///
/// `frame` is normally `ReceiveSerial::<Downstream>::Message(..)`; see
/// [`downstream_reset`] and [`downstream_conch`] for the two bodyless frames.
///
/// # Errors
///
/// [`CommsError::FrameTooLong`] if it does not fit, [`CommsError::EncodeFailed`]
/// for any other `bincode` failure.
pub fn encode_frame<T: bincode::Encode>(
    frame: &T,
    out: &mut [u8; FRAME_LIMIT],
) -> Result<usize, CommsError> {
    match bincode::encode_into_slice(frame, out, BINCODE_CONFIG) {
        Ok(n) => Ok(n),
        Err(EncodeError::UnexpectedEnd) => Err(CommsError::FrameTooLong),
        Err(_) => Err(CommsError::EncodeFailed),
    }
}

/// `ReceiveSerial::<Downstream>::Conch` — "you may speak". Returned as a value
/// so the caller does not need to name `Downstream`, and because turn-taking is
/// the one frame whose *identity* matters more than its contents.
#[must_use]
pub fn downstream_conch() -> frostsnap_comms::ReceiveSerial<Downstream> {
    frostsnap_comms::ReceiveSerial::Conch
}

/// `ReceiveSerial::<Downstream>::Reset`.
#[must_use]
pub fn downstream_reset() -> frostsnap_comms::ReceiveSerial<Downstream> {
    frostsnap_comms::ReceiveSerial::Reset
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    extern crate std;

    use super::*;
    // `format!` is not in a no_std crate's prelude, and proptest's assertion
    // macros expand to it.
    use alloc::format;
    use alloc::vec::Vec;
    use frostsnap_comms::{
        CoordinatorSendBody, CoordinatorSendMessage, DeviceSendBody, DeviceSendMessage, Destination,
        MagicBytes, ReceiveSerial, WireCoordinatorSendBody, WireDeviceSendBody,
    };
    use frostsnap_core::DeviceId;

    type FromCoordinator = ReceiveSerial<Upstream>;
    type ToCoordinator = ReceiveSerial<Downstream>;

    fn enc<T: bincode::Encode>(v: &T) -> Vec<u8> {
        bincode::encode_to_vec(v, BINCODE_CONFIG).expect("encodes")
    }

    /// The coordinator's own magic bytes, as it would put them on the wire:
    /// `Upstream::MAGIC_BYTES` with `Upstream::VERSION_SIGNAL == 0` added.
    fn coordinator_magic() -> Vec<u8> {
        enc(&FromCoordinator::MagicBytes(MagicBytes::default()))
    }

    /// A small, real coordinator->device frame.
    fn small_from_coordinator() -> FromCoordinator {
        FromCoordinator::Message(CoordinatorSendMessage {
            target_destinations: Destination::All,
            message_body: WireCoordinatorSendBody::from(CoordinatorSendBody::AnnounceAck),
        })
    }

    /// Collect every frame `poll` delivers for one input slice.
    fn poll_all(link: &mut Link, bytes: &[u8]) -> Result<Vec<FromCoordinator>, CommsError> {
        let mut got = Vec::new();
        link.poll::<FromCoordinator, _>(bytes, |f| got.push(f))?;
        Ok(got)
    }

    // ---- properties: `poll` is the entire attacker-controlled surface ----
    //
    // Every test below this file's property block is a curated input. These are
    // not. A coordinator chooses the bytes; the USB stack chooses where they are
    // split; neither is ours. A hand-written split covers exactly one boundary
    // out of every boundary a 2 KB frame has, so the reassembler's correctness
    // under arbitrary chunking is asserted here rather than sampled above.

    use proptest::prelude::*;

    /// Frames whose encodings differ in length, so a fixed chunk size lands at a
    /// different offset inside each one. Only the envelope is varied: fuzzing the
    /// message space is `frostsnap_core`'s job and its own `proptest.rs` already
    /// does 512 cases of it.
    fn frame_of(kind: u8) -> FromCoordinator {
        let target_destinations = match kind % 3 {
            0 => Destination::All,
            1 => Destination::Particular([DeviceId([7u8; 33])].into()),
            _ => Destination::Particular([DeviceId([7u8; 33]), DeviceId([9u8; 33])].into()),
        };
        FromCoordinator::Message(CoordinatorSendMessage {
            target_destinations,
            message_body: WireCoordinatorSendBody::from(CoordinatorSendBody::AnnounceAck),
        })
    }

    /// Device->coordinator frames spanning the length space: the two bodyless
    /// ones, and a `Debug` body whose `String` is the only field in this
    /// direction whose length can be dialled a byte at a time — so it is what
    /// walks bincode's varint length across its 1-byte boundary at 128.
    fn device_frame_of(kind: u8, pad: usize) -> ToCoordinator {
        match kind % 3 {
            0 => ToCoordinator::Conch,
            1 => ToCoordinator::Reset,
            _ => ToCoordinator::Message(DeviceSendMessage {
                from: DeviceId([7u8; 33]),
                body: WireDeviceSendBody::Debug {
                    message: core::iter::repeat_n('x', pad).collect(),
                },
            }),
        }
    }

    proptest! {
        /// The loop closes through the **vendored** types, in both directions, at
        /// the byte level, for arbitrary frames.
        ///
        /// This is the one property here that is not about `Link`'s behaviour.
        /// Every other test in this file checks our encoder against our decoder
        /// (`encode_frame_writes_the_same_bytes_bincode_would`) or our decoder
        /// against bytes we chose — self-consistency. Neither can fail if our
        /// framing is coherent but disagrees with `frostsnap_comms`, which is the
        /// one class of bug that bricks a link with a real coordinator and that a
        /// hermetic test can still catch before the live harness exists. So:
        /// outbound, the bytes [`encode_frame`] produces are handed to
        /// `bincode::decode_from_slice::<ReceiveSerial<Downstream>>` exactly as a
        /// coordinator would decode them; inbound, bytes `bincode` produced for a
        /// `ReceiveSerial<Upstream>` are handed to [`Link::poll`].
        ///
        /// The lengths are asserted alongside the values, and that is the assert
        /// with teeth. A frame that decodes to the right value at the wrong length
        /// is *worse* than one that fails to decode: the wire has no length prefix
        /// and no resync marker, so a one-byte disagreement about where a frame
        /// ends silently shifts every following frame — the desync this module
        /// exists to prevent. Hence `n == bincode's own length` on the way out and
        /// `pending() == 0` on the way in.
        ///
        /// What it does NOT cover, established by mutating rather than assumed, so
        /// that the paragraph above is not read as a wider guarantee than it is:
        /// its unique catch is a length disagreement on a mid-size frame. Handshake
        /// drift is `magic_reply_matches_the_vendored_encoder`'s job, not this
        /// one's — it uses `coordinator_magic()` to link and never exercises
        /// [`MAGIC_REPLY`]. Trailing-byte over-consumption needs two adjacent
        /// frames to be visible at all, so `chunking_never_changes_what_arrives`
        /// catches it and a single-frame round trip cannot.
        #[test]
        fn a_frame_round_trips_through_the_vendored_wire_format(kind: u8, pad in 0usize..300) {
            // ---- device -> coordinator: our encoder, their decoder ----
            let sent = device_frame_of(kind, pad);
            let expected = enc(&sent);
            let mut out = [0u8; FRAME_LIMIT];
            let n = encode_frame(&sent, &mut out).expect("a padded Debug frame is well under the bound");
            prop_assert_eq!(
                n,
                expected.len(),
                "encode_frame reported {} bytes where bincode wrote {}",
                n,
                expected.len()
            );
            prop_assert_eq!(&out[..n], expected.as_slice());
            let (echoed, read): (ToCoordinator, usize) =
                bincode::decode_from_slice(&out[..n], BINCODE_CONFIG).map_err(|e| {
                    TestCaseError::fail(format!("a coordinator could not decode our frame: {e:?}"))
                })?;
            prop_assert_eq!(read, n, "the coordinator would stop at a different offset");
            // `ReceiveSerial` has no `PartialEq`; re-encoding compares the whole
            // value and is the stronger check anyway.
            prop_assert_eq!(enc(&echoed), expected);

            // ---- coordinator -> device: their encoder, our decoder ----
            let recvd = frame_of(kind);
            let wire = enc(&recvd);
            let mut link = Link::new();
            poll_all(&mut link, &coordinator_magic()).expect("handshake");
            let got = poll_all(&mut link, &wire).expect("bincode's own bytes must decode");
            prop_assert_eq!(got.len(), 1, "one frame in, {} out", got.len());
            prop_assert_eq!(enc(&got[0]), wire);
            prop_assert_eq!(
                link.pending(),
                0,
                "{} bytes left unconsumed by a whole frame",
                link.pending()
            );
        }

        /// No frame escapes an unlinked `Link`. Whatever the coordinator sends, if
        /// it is not preceded by the magic pattern then nothing is decoded and the
        /// link stays down — so a device cannot be driven before it has agreed to
        /// listen. Also pins that an unlinked link cannot report an error at all:
        /// pre-handshake bytes are discarded, never diagnosed.
        #[test]
        fn nothing_is_delivered_before_the_handshake(bytes: Vec<u8>) {
            let magic = coordinator_magic();
            prop_assume!(!bytes.windows(magic.len()).any(|w| w == magic.as_slice()));

            let mut link = Link::new();
            let got = poll_all(&mut link, &bytes).expect("an unlinked link cannot desync");
            prop_assert!(got.is_empty(), "{} frame(s) escaped an unlinked Link", got.len());
            prop_assert!(!link.is_linked());
        }

        /// The frames a coordinator sends arrive exactly once each, in order, no
        /// matter where the stream is split. This is the USB-packet-boundary
        /// property: `a_frame_split_across_usb_packets_reassembles` above proves
        /// one split, this proves every split of every frame length.
        #[test]
        fn chunking_never_changes_what_arrives(
            kinds in prop::collection::vec(any::<u8>(), 1..6),
            chunks in prop::collection::vec(1usize..40, 1..40),
        ) {
            let frames: Vec<FromCoordinator> = kinds.iter().copied().map(frame_of).collect();
            let mut stream = coordinator_magic();
            for f in &frames {
                stream.extend_from_slice(&enc(f));
            }

            let mut link = Link::new();
            let mut got = Vec::new();
            let (mut at, mut i) = (0usize, 0usize);
            while at < stream.len() {
                let n = chunks[i % chunks.len()].min(stream.len() - at);
                link.poll::<FromCoordinator, _>(&stream[at..at + n], |f| got.push(f))
                    .map_err(|e| TestCaseError::fail(format!("desync at byte {at}: {e:?}")))?;
                at += n;
                i += 1;
            }

            prop_assert_eq!(got.len(), frames.len(), "frame count changed with chunking");
            for (a, b) in got.iter().zip(frames.iter()) {
                // Re-encode to compare: `ReceiveSerial` has no `PartialEq`, and
                // comparing bytes is the stronger check anyway.
                prop_assert_eq!(enc(a), enc(b));
            }
        }

        /// An over-limit frame desyncs and unlinks at EVERY size over the bound,
        /// not just the one the curated test picks. This closes the only gap the
        /// mutation sweep found: deleting `unlink()` from `poll`'s over-limit
        /// return path was caught by no property, because reaching that path needs
        /// a stream longer than [`FRAME_LIMIT`] bytes and proptest's default `Vec<u8>` is
        /// nowhere near that. `padded_frame` is valid bincode all the way, so
        /// nothing but the buffer's size stops it.
        #[test]
        fn an_over_limit_frame_desyncs_at_every_size(over in 1usize..400) {
            let mut link = Link::new();
            poll_all(&mut link, &coordinator_magic()).expect("handshake");

            let frame = padded_frame(FRAME_LIMIT + over);
            prop_assert_eq!(
                link.poll::<ToCoordinator, _>(&frame, |_| unreachable!("must not decode")),
                Err(CommsError::Desync)
            );
            prop_assert!(!link.is_linked(), "a desync must drop the link");
            prop_assert_eq!(link.pending(), 0);
        }

        /// A desync ALWAYS drops the link. If it did not, the next bytes would be
        /// decoded from the middle of a stream whose framing we had already lost.
        ///
        /// The desync is forced by construction — a variant tag no `ReceiveSerial`
        /// has — rather than hoped for. That is not fussiness: the
        /// arbitrary-bytes property below was written to catch this and does
        /// **not**. Deleting `unlink()` from `poll`'s desync path leaves it green,
        /// because random short vectors almost always just buffer, so its `Err`
        /// arm is nearly never evaluated. This version fails on that mutation.
        #[test]
        fn a_desync_always_drops_the_link(tail in prop::collection::vec(any::<u8>(), 1..64)) {
            let mut link = Link::new();
            poll_all(&mut link, &coordinator_magic()).expect("handshake");
            prop_assert!(link.is_linked());

            let mut bytes = alloc::vec![0x20u8];
            bytes.extend_from_slice(&tail);
            prop_assert_eq!(
                poll_all(&mut link, &bytes).unwrap_err(),
                CommsError::Desync,
                "an impossible variant tag must not decode"
            );
            prop_assert!(!link.is_linked(), "a desync must drop the link");
        }

        /// After linking, arbitrary bytes never panic, never overrun the
        /// reassembly buffer, and never produce an error other than `Desync`.
        ///
        /// Deliberately weaker than its name once was: it does *not* reliably
        /// exercise the desync path — see `a_desync_always_drops_the_link` for
        /// that, and why.
        #[test]
        fn garbage_after_linking_never_overruns(bytes: Vec<u8>) {
            let mut link = Link::new();
            poll_all(&mut link, &coordinator_magic()).expect("handshake");
            prop_assert!(link.is_linked());

            let result = poll_all(&mut link, &bytes);
            prop_assert!(
                link.pending() <= FRAME_LIMIT,
                "reassembly buffer overran: {} > {FRAME_LIMIT}",
                link.pending()
            );
            if let Err(e) = result {
                prop_assert_eq!(e, CommsError::Desync, "poll must only ever report Desync");
                prop_assert!(!link.is_linked(), "a desync must drop the link");
            }
        }
    }

    // ---- the nested EncapsBody leg ----

    /// [`decode_body`] must mean the same thing as the vendored decoder on every
    /// legitimate input — the whole point is that it differs only in what it will
    /// *allocate*, never in what a body decodes to. Covers both routes through
    /// `From<CoordinatorSendBody>`: the direct variants (`AnnounceAck`, `Cancel`)
    /// and the `EncapsV0`-wrapped ones (`DataErase` — a unit variant, so the
    /// comparison is exact and needs no fixture).
    #[test]
    fn decode_body_agrees_with_the_vendored_decoder() {
        for body in [
            CoordinatorSendBody::AnnounceAck,
            CoordinatorSendBody::Cancel,
            CoordinatorSendBody::DataErase,
        ] {
            let wire = WireCoordinatorSendBody::from(body.clone());
            let ours = decode_body(wire.clone()).expect("legitimate body must decode");
            let theirs = wire.decode().expect("vendored decoder must agree it is valid");
            // `CoordinatorSendBody` has no `PartialEq`; comparing the re-encodings is
            // the stronger check anyway.
            assert_eq!(enc(&ours), enc(&theirs), "disagreed on {body:?}");
            assert_eq!(enc(&ours), enc(&body), "did not round-trip {body:?}");
        }

        // The two dead compatibility variants. A coordinator old enough to send
        // these predates encapsulation, so both must be REFUSED rather than
        // silently mapped onto some other body. Nothing exercised these until a
        // mutation made them return `Ok(Cancel)` and the whole suite stayed green.
        for dead in [WireCoordinatorSendBody::_Core, WireCoordinatorSendBody::_Naming] {
            match decode_body(dead.clone()) {
                Err(e) => assert_eq!(e, CommsError::BodyUndecodable, "wrong error for {dead:?}"),
                Ok(body) => panic!("{dead:?} must not decode, got {body:?}"),
            }
            // And the vendored decoder agrees they are unreadable.
            assert!(dead.clone().decode().is_none(), "vendored decoder took {dead:?}");
        }
    }

    /// The refusal this leg exists for. Five bytes: `Naming` tag, `Preview` tag,
    /// then bincode's 251-marker varint claiming 32,748 bytes of `String`.
    ///
    /// Under the vendored 32 KiB budget that claim is *admitted* — the decoder
    /// allocates and only then discovers the bytes are not there. Under
    /// [`ENCAPS_DECODE_LIMIT`] it is refused before allocating. Both halves are
    /// asserted, because "ours refuses it" is only interesting if theirs does not.
    #[test]
    fn an_over_claiming_inner_body_is_refused_before_it_allocates() {
        // Derived, not magic: tag 1 = `CoordinatorSendBody::Naming`, tag 0 =
        // `NameCommand::Preview`, then the length. Pinned below.
        let poison = [0x01u8, 0x00, 0xfb, 0xec, 0x7f];
        let claimed = u64::from(u16::from_le_bytes([0xec, 0x7f]));
        assert!(
            claimed > ENCAPS_DECODE_LIMIT as u64,
            "the poison must claim more than our limit, else it proves nothing"
        );
        assert!(
            claimed < (1 << 15),
            "and less than the vendored limit, so THEIRS admits it and ours does not"
        );

        let wire = WireCoordinatorSendBody::EncapsV0(
            bincode::decode_from_slice::<frostsnap_comms::EncapsBody, _>(
                &enc(&poison.to_vec()),
                BINCODE_CONFIG,
            )
            .expect("a Vec<u8> encoding is a valid EncapsBody")
            .0,
        );

        // `CoordinatorSendBody` has no `PartialEq`, so compare the error only.
        //
        // `BodyTooLarge`, NOT `BodyUndecodable`, and the distinction is the entire
        // point: the claim is under the vendored 32 KiB, so with the vendored config
        // bincode would ALLOCATE 32,748 B and only then fail on the missing bytes --
        // still an `Err`, just the wrong kind, for the wrong reason, after the damage.
        // Asserting the kind is what makes this test fail if the config is swapped
        // back. Verified by mutation; asserting only `is_err()` did not catch it.
        match decode_body(wire) {
            Err(e) => assert_eq!(
                e,
                CommsError::BodyTooLarge,
                "must be refused BY THE LIMIT, before allocating"
            ),
            Ok(body) => panic!("an over-claiming inner body decoded to {body:?}"),
        }
    }

    /// The boundary is pinned on the config itself, so it cannot drift while the
    /// constant stays put.
    ///
    /// `bincode`'s `Limit<L>` is a budget on the whole decode, and it charges the
    /// **8-byte length claim** against it too — so the largest `Vec<u8>` admitted is
    /// `L - 8`, not `L`. Measured by bisection, not assumed. Worth pinning because it
    /// means the effective inner budget is 20,472 B, and that is the figure that has
    /// to clear the 17,702 B worst legitimate claim, not the round 20,480.
    #[test]
    fn the_inner_limit_boundary_is_exact() {
        // The compile-time relation on the EFFECTIVE budget lives beside the
        // constant (`ENCAPS_LIMIT_OVERHEAD`); asserting it here too would be all
        // constants and optimised out, which clippy correctly refuses.
        const OVERHEAD: usize = ENCAPS_LIMIT_OVERHEAD;

        let at = alloc::vec![0u8; ENCAPS_DECODE_LIMIT - OVERHEAD];
        let (back, _) = bincode::decode_from_slice::<Vec<u8>, _>(&enc(&at), ENCAPS_CONFIG)
            .expect("the largest admissible claim must be admitted");
        assert_eq!(back.len(), ENCAPS_DECODE_LIMIT - OVERHEAD);

        let over = alloc::vec![0u8; ENCAPS_DECODE_LIMIT - OVERHEAD + 1];
        assert!(
            bincode::decode_from_slice::<Vec<u8>, _>(&enc(&over), ENCAPS_CONFIG).is_err(),
            "one byte past the effective budget must be refused"
        );

    }

    // ---- the two facts that decide whether a real coordinator links at all ----

    #[test]
    fn magic_reply_matches_the_vendored_encoder() {
        assert_eq!(
            MAGIC_REPLY.as_slice(),
            enc(&ToCoordinator::MagicBytes(MagicBytes::default())).as_slice(),
            "the hand-written handshake reply has drifted from frostsnap_comms"
        );
    }

    #[test]
    fn we_answer_with_a_different_pattern_than_we_scan_for() {
        // Version byte differs (Downstream signals 2, Upstream 0) and so does
        // the body. Sending the coordinator's own pattern back would be a
        // plausible bug that no other test here would catch.
        assert_ne!(MAGIC_REPLY.as_slice(), coordinator_magic().as_slice());
    }

    // ---- the gate ----

    #[test]
    fn a_frame_before_the_handshake_is_discarded() {
        let mut link = Link::new();
        let early = enc(&small_from_coordinator());
        assert!(poll_all(&mut link, &early).expect("scanning never errors").is_empty());
        assert!(!link.is_linked());

        // ...and the same frame after the handshake is delivered.
        let mut stream = coordinator_magic();
        stream.extend_from_slice(&early);
        let got = poll_all(&mut link, &stream).expect("links then decodes");
        assert!(link.is_linked());
        assert_eq!(got.len(), 1);
    }

    #[test]
    fn magic_bytes_split_across_packets_still_link() {
        let magic = coordinator_magic();
        for split in 1..magic.len() {
            let mut link = Link::new();
            poll_all(&mut link, &magic[..split]).unwrap();
            assert!(!link.is_linked(), "linked early at split {split}");
            poll_all(&mut link, &magic[split..]).unwrap();
            assert!(link.is_linked(), "failed to link at split {split}");
        }
    }

    #[test]
    fn garbage_before_the_handshake_is_skipped() {
        let mut link = Link::new();
        // Deliberately includes a near-miss prefix of the pattern.
        let mut stream: Vec<u8> = alloc::vec![0x00, 0xff, 0x5d, 0xa3, 0x11, 0x00, 0xff];
        stream.extend((0..300u32).map(|i| (i % 251) as u8));
        stream.extend_from_slice(&coordinator_magic());
        poll_all(&mut link, &stream).unwrap();
        assert!(link.is_linked());
        assert_eq!(link.pending(), 0);
    }

    #[test]
    fn magic_bytes_after_the_handshake_are_an_ordinary_frame() {
        // The coordinator re-sends them every 100 ms forever
        // (MAGIC_BYTES_PERIOD, lib.rs:22), so they must decode, not desync.
        let mut link = Link::new();
        let mut stream = coordinator_magic();
        stream.extend_from_slice(&coordinator_magic());
        stream.extend_from_slice(&enc(&small_from_coordinator()));
        let got = poll_all(&mut link, &stream).unwrap();
        assert_eq!(got.len(), 2);
        assert!(matches!(got[0], FromCoordinator::MagicBytes(_)));
    }

    // ---- reassembly ----

    #[test]
    fn a_frame_split_across_usb_packets_reassembles() {
        let mut link = Link::new();
        poll_all(&mut link, &coordinator_magic()).unwrap();

        let frame = enc(&small_from_coordinator());
        let mut got = Vec::new();
        for byte in &frame {
            // One byte at a time is the worst case and the cheapest proof that
            // no packet boundary is assumed.
            link.poll::<FromCoordinator, _>(&[*byte], |f| got.push(f)).unwrap();
        }
        assert_eq!(got.len(), 1);
        assert_eq!(link.pending(), 0);
    }

    #[test]
    fn several_frames_in_one_packet_all_arrive() {
        let mut link = Link::new();
        let mut stream = coordinator_magic();
        for _ in 0..4 {
            stream.extend_from_slice(&enc(&small_from_coordinator()));
        }
        assert_eq!(poll_all(&mut link, &stream).unwrap().len(), 4);
    }

    #[test]
    fn polling_with_no_bytes_drains_what_is_buffered() {
        let mut link = Link::new();
        let mut stream = coordinator_magic();
        stream.extend_from_slice(&enc(&small_from_coordinator()));
        assert_eq!(poll_all(&mut link, &stream).unwrap().len(), 1);
        assert!(poll_all(&mut link, &[]).unwrap().is_empty());
    }

    // ---- the bound, both directions ----

    #[test]
    fn a_received_frame_over_the_limit_desyncs_and_unlinks() {
        let mut link = Link::new();
        poll_all(&mut link, &coordinator_magic()).unwrap();

        // Well-formed for the type being decoded and simply too big, which is
        // the case that must trip the *size* bound rather than the
        // malformed-bytes path. Note the deliberate distinction from
        // `malformed_bytes_desync_rather_than_hang`: an oversize frame is valid
        // bincode all the way to the last byte the buffer can hold, so nothing
        // but the buffer's size stops it.
        let oversize = padded_frame(FRAME_LIMIT + 653);
        let err = link
            .poll::<ToCoordinator, _>(&oversize, |_| unreachable!("must not decode"))
            .expect_err("must refuse");
        assert_eq!(err, CommsError::Desync);
        assert!(!link.is_linked(), "a desync must drop the link, not keep it");
        assert_eq!(link.pending(), 0);
    }

    #[test]
    fn a_frame_exactly_at_the_limit_is_still_accepted() {
        // Guards against an off-by-one that turns the ceiling into 4095 and
        // silently costs a byte of every future budget.
        let mut link = Link::new();
        poll_all(&mut link, &coordinator_magic()).unwrap();
        let frame = padded_frame(FRAME_LIMIT);
        assert_eq!(frame.len(), FRAME_LIMIT);
        let mut n = 0;
        link.poll::<ToCoordinator, _>(&frame, |_| n += 1).unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn one_byte_over_the_limit_is_refused() {
        let mut link = Link::new();
        poll_all(&mut link, &coordinator_magic()).unwrap();
        let frame = padded_frame(FRAME_LIMIT + 1);
        assert_eq!(frame.len(), FRAME_LIMIT + 1);
        assert_eq!(
            link.poll::<ToCoordinator, _>(&frame, |_| unreachable!()),
            Err(CommsError::Desync)
        );
    }

    #[test]
    fn malformed_bytes_desync_rather_than_hang() {
        let mut link = Link::new();
        poll_all(&mut link, &coordinator_magic()).unwrap();
        // Tag 0x20 is past ReceiveSerial's 13 variants.
        assert_eq!(
            link.poll::<FromCoordinator, _>(&[0x20, 0x01, 0x02], |_| unreachable!()),
            Err(CommsError::Desync)
        );
        assert!(!link.is_linked());
    }

    #[test]
    fn a_zero_length_decode_is_refused_rather_than_looping() {
        // `()` decodes from zero bytes, so `drain` would spin forever without
        // its `n == 0` guard. No frostsnap type does this; the guard is there
        // because an infinite loop in firmware is a watchdog reset at best.
        let mut link = Link::new();
        poll_all(&mut link, &coordinator_magic()).unwrap();
        assert_eq!(
            link.poll::<(), _>(&[0x00], |()| unreachable!()),
            Err(CommsError::Desync)
        );
    }

    #[test]
    fn encode_frame_writes_the_same_bytes_bincode_would() {
        let mut out = [0u8; FRAME_LIMIT];
        let frame = ToCoordinator::Conch;
        let n = encode_frame(&frame, &mut out).expect("fits");
        assert_eq!(&out[..n], enc(&frame).as_slice());
        assert_eq!(&out[..n], enc(&downstream_conch()).as_slice());
    }

    #[test]
    fn encode_frame_refuses_an_oversize_frame_whole() {
        let mut out = [0xAAu8; FRAME_LIMIT];
        let err = encode_frame(&nonce_response(3), &mut out).expect_err("must refuse");
        assert_eq!(err, CommsError::FrameTooLong);
        // The caller is told a length only on success, so it can never mistake a
        // partially-filled buffer for a frame. Nothing here asserts the buffer
        // is untouched: bincode may well have written into it, and pretending
        // otherwise would be documenting a repair that does not exist. What is
        // guaranteed is that no length escapes, so no bytes are sent.
        assert!(encode_frame(&ToCoordinator::Reset, &mut out).is_ok());
    }

    /// The bound 2,060 was raised for, from the direction it was raised.
    ///
    /// **This test used to be `real_signature_share_batch_is_refused`, and its
    /// whole point was the refusal.** At 4,096 the batch fits, so the test changes
    /// meaning rather than being quietly deleted: same fixture, same printed
    /// figures, opposite assertion. A `SignatureShare` that *carries* a replenish
    /// batch is 2,105 B for one share and 2,713 B for twenty; it is one
    /// indivisible message (`frostsnap_core/src/device.rs:509-523`) and
    /// `NONCE_BATCH_SIZE` moves in lockstep with the coordinator's
    /// `MIN_NONCES_BEFORE_REQUEST` (`coordinator.rs:43`), so the device could not
    /// have shrunk it unilaterally. That is why the ceiling moved instead — see
    /// DECISIONS.md 7.
    ///
    /// The exact sizes are asserted, not just the comparison. A comparison against
    /// 4,096 would stay green if the wire format grew 1 KB; PLAN.md §7 quotes
    /// these two numbers, so they are pinned.
    #[test]
    fn real_signature_share_batch_now_fits_within_the_raised_bound() {
        for (shares, expect) in [(1usize, 2_105usize), (20, 2_713)] {
            let batch = signature_share_batch(shares);
            let size = enc(&batch).len();
            std::println!(
                "full-wire SignatureShare, {shares} share(s) + 30 replenish nonces: {size} B \
                 ({} spare)",
                FRAME_LIMIT - size
            );
            assert_eq!(size, expect, "the wire format or the fixture changed");
            assert!(size > OLD_FRAME_LIMIT, "this is only interesting if 2,060 refused it");

            let mut out = [0u8; FRAME_LIMIT];
            assert_eq!(
                encode_frame(&batch, &mut out),
                Ok(size),
                "the raised bound must admit it whole"
            );
        }
    }

    /// One full nonce batch, and the margin PLAN.md §7 records for it: 2,040 B,
    /// which fitted 2,060 by 20 bytes and fits 4,096 by 2,056.
    #[test]
    fn a_single_stream_nonce_response_fits_with_the_margin_plan_records() {
        let frame = nonce_response(1);
        let size = enc(&frame).len();
        std::println!("full-wire NonceResponse 1x30: {size} B ({} spare)", FRAME_LIMIT - size);
        assert_eq!(size, 2_040, "the wire format or the fixture changed");
        assert_eq!(FRAME_LIMIT - size, 2_056);
        let mut out = [0u8; FRAME_LIMIT];
        assert_eq!(encode_frame(&frame, &mut out), Ok(size));
    }

    /// **The reversal's justification, executable.** Four real messages that 2,060
    /// refused and 4,096 admits — the four listed in the module docs and
    /// DECISIONS.md 7. Plus the fifth frame that chose 4,096 over 3,072.
    ///
    /// Only the `SignatureShare` is built as a real message here. The other three
    /// cannot be: two are *inbound*, and the coordinator's bodies are all
    /// fixed-size or hidden behind a private `EncapsBody`, while `HeldShares2`
    /// needs a real keygen to produce. Their sizes were measured against real
    /// messages in `tools/research-scratch/wire_size_measure.rs` and are reproduced
    /// here as sizes, through [`padded_frame`] — which is sound for exactly the
    /// reason the bound is structural: [`Link`]'s refusal depends on the byte count
    /// and nothing else, so a frame of the measured length is the whole test. What
    /// this does *not* prove is the measurement; that lives in the scratch file and
    /// in PLAN.md §7.
    #[test]
    fn the_four_frames_the_old_bound_refused_now_fit() {
        // Device-emitted, and buildable for real: `SignatureShare` + a full
        // 30-nonce replenish, one share.
        let mut out = [0u8; FRAME_LIMIT];
        let share = signature_share_batch(1);
        assert_eq!(encode_frame(&share, &mut out), Ok(2_105));

        // Sizes only, for the reason in the doc comment above.
        for (size, what) in [
            (2_238usize, "inbound RequestSign, 11 owned inputs"),
            (2_179, "inbound keygen CertifyPlease, 9-of-9"),
            (2_215, "HeldShares2, 14 stored shares (device-emitted)"),
            (4_038, "NonceResponse, 2 segments — the frame that chose 4,096 over 3,072"),
        ] {
            assert!(size > OLD_FRAME_LIMIT, "{what} was not over the old bound: {size} B");
            assert!(size <= FRAME_LIMIT, "{what} does not fit the new bound: {size} B");

            let mut link = Link::new();
            poll_all(&mut link, &coordinator_magic()).expect("handshake");
            let mut n = 0;
            link.poll::<ToCoordinator, _>(&padded_frame(size), |_| n += 1)
                .unwrap_or_else(|e| panic!("{what} ({size} B) was refused: {e:?}"));
            assert_eq!(n, 1, "{what} did not arrive as one frame");
        }

        // And the two-segment `NonceResponse` as a real message, since that one
        // *is* device-side. (It is not the frame that ruled 3,072 out — that is the
        // 3,944 B 20-input `RequestSign`; see [`FRAME_LIMIT`].)
        assert_eq!(encode_frame(&nonce_response(2), &mut out), Ok(4_038));
    }

    /// The NEW refusal boundary, pinned with a real message rather than padding: a
    /// third nonce segment. `NonceResponse` is unbounded in segment count, and the
    /// count is the *coordinator's* choice, not the device's — `device.rs:273-296`
    /// emits one segment per stream in the received `OpenNonceStreams`. (The real
    /// coordinator does call `OpenNonceStreams::split()`, so real traffic is one
    /// segment per frame; an earlier version of this comment claimed it never does.
    /// Corrected 2026-08-19 — the app asks for 4 streams, so an unsplit reply is
    /// ~8 KB.) So this is the frame a future raise would be argued from — and it
    /// must stay a
    /// deliberate decision, which is what this test costs it. The fix is the
    /// one-segment-per-frame cap the module docs record as REQUIRED and
    /// UNIMPLEMENTED, not another raise.
    #[test]
    fn three_nonce_segments_are_refused_by_the_new_bound() {
        let frame = nonce_response(3);
        let size = enc(&frame).len();
        std::println!("full-wire NonceResponse 3x30: {size} B (over by {})", size - FRAME_LIMIT);
        assert_eq!(size, 6_036, "the wire format or the fixture changed");
        let mut out = [0u8; FRAME_LIMIT];
        assert_eq!(
            encode_frame(&frame, &mut out),
            Err(CommsError::FrameTooLong),
            "the bound must refuse it, not truncate it"
        );
    }

    // ---- fixtures ----

    /// What [`FRAME_LIMIT`] was until 2026-08-18. Kept so the tests that justify
    /// the reversal can say "this was refused" rather than assert it from memory.
    const OLD_FRAME_LIMIT: usize = 2060;

    /// `n` valid `binonce::Nonce`s in a stream identified by `id`. Built from the
    /// generator rather than from the real ratchet: every valid nonce encodes to
    /// the same 66 bytes, and this test is about size, so the nonce generator is
    /// not in the loop.
    fn segment(id: u8, n: usize) -> frostsnap_core::nonce_stream::NonceStreamSegment {
        let g = (*schnorr_fun::fun::G).normalize().to_bytes();
        let mut bytes = [0u8; 66];
        bytes[..33].copy_from_slice(&g);
        bytes[33..].copy_from_slice(&g);
        let nonce = schnorr_fun::binonce::Nonce::from_bytes(bytes).expect("generator is valid");
        frostsnap_core::nonce_stream::NonceStreamSegment {
            stream_id: frostsnap_core::nonce_stream::NonceStreamId([id; 16]),
            nonces: core::iter::repeat_n(nonce, n).collect(),
            index: 0,
        }
    }

    /// `NonceResponse` carrying `segments` full 30-nonce segments. 2,040 B at one
    /// segment, +1,998 for each further one: 4,038 at two (which fits, and is why
    /// [`FRAME_LIMIT`] is 4,096 and not 3,072) and 6,036 at three (which does not,
    /// and is the new boundary). The count is unbounded on the wire.
    fn nonce_response(segments: u8) -> ToCoordinator {
        ToCoordinator::Message(DeviceSendMessage {
            from: DeviceId([7u8; 33]),
            body: WireDeviceSendBody::from(DeviceSendBody::Core(
                frostsnap_core::message::signing::DeviceSigning::NonceResponse {
                    segments: (0..segments).map(|i| segment(0x11 + i, 30)).collect(),
                }
                .into(),
            )),
        })
    }

    /// The largest ordinary device->coordinator frame: a signing response for an
    /// `n`-input transaction that also replenishes a full nonce batch. Wrapped in
    /// the real `ReceiveSerial::Message(DeviceSendMessage { .. })`, so this is
    /// the whole frame as it reaches the wire — tag and `DeviceId` included, the
    /// 34 bytes PLAN.md §7's earlier body-only table omitted.
    fn signature_share_batch(n: usize) -> ToCoordinator {
        use schnorr_fun::fun::prelude::*;
        let shares: Vec<schnorr_fun::frost::SignatureShare> = (1..=n as u8)
            .map(|i| {
                let mut b = [0u8; 32];
                b[31] = i;
                Scalar::<Public, NonZero>::from_bytes(b)
                    .expect("nonzero")
                    .mark_zero()
            })
            .collect();
        ToCoordinator::Message(DeviceSendMessage {
            from: DeviceId([7u8; 33]),
            body: WireDeviceSendBody::from(DeviceSendBody::Core(
                frostsnap_core::message::signing::DeviceSigning::SignatureShare {
                    session_id: frostsnap_core::SignSessionId([3u8; 32]),
                    signature_shares: shares,
                    replenish_nonces: Some(segment(0x11, 30)),
                }
                .into(),
            )),
        })
    }

    /// A well-formed frame of exactly `total` bytes, for probing the boundary.
    ///
    /// This is a `ReceiveSerial<Downstream>` rather than the type the device
    /// actually receives, because `WireDeviceSendBody::Debug`'s `String` is the
    /// only field in either direction whose length can be dialled one byte at a
    /// time — the coordinator's bodies are all fixed-size or encapsulated behind
    /// a private `EncapsBody`. That is sound here: the size bound lives in
    /// [`Link`]'s buffer, not in the decoded type, and `poll` is generic over the
    /// type precisely so it cannot depend on one.
    fn padded_frame(total: usize) -> Vec<u8> {
        for pad in 0..total {
            let frame = ToCoordinator::Message(DeviceSendMessage {
                from: DeviceId([7u8; 33]),
                body: WireDeviceSendBody::Debug {
                    message: core::iter::repeat_n('x', pad).collect(),
                },
            });
            let bytes = enc(&frame);
            if bytes.len() == total {
                return bytes;
            }
            if bytes.len() > total {
                break;
            }
        }
        unreachable!("no padding length yields exactly {total} bytes")
    }

    // ---- the allocation bound (`DECODE_ALLOC_LIMIT`) ----

    /// Bytes that *claim* a `claim`-byte `EncapsBody` and then stop, at the real
    /// inbound type.
    ///
    /// Assembled from raw bytes because `EncapsBody`'s field is private, so no
    /// legitimate constructor can produce a length that disagrees with the
    /// payload — which is exactly what a hostile coordinator does. The three
    /// leading tags come from the *vendored encoder*, not from a table, so the
    /// poison stays well-formed if a variant is ever added ahead of one of them.
    /// The budget the vendored `BINCODE_CONFIG` had when the OOM reset loop was
    /// found: `1 << 15`. Spelled out here rather than reached for through
    /// `BINCODE_CONFIG` because the two tests below assert what the *old, wide*
    /// budget did, and the vendored constant has since come down to 20,480
    /// (PLAN.md §9 item 7(d)). Reading it from the vendored config would silently
    /// re-aim those tests at the new value and stop them documenting the defect.
    const HISTORICAL_32K_CONFIG: bincode::config::Configuration<
        bincode::config::LittleEndian,
        bincode::config::Varint,
        bincode::config::Limit<{ 1 << 15 }>,
    > = bincode::config::standard().with_limit::<{ 1 << 15 }>();

    fn over_claiming_frame(claim: usize) -> Vec<u8> {
        let real = enc(&FromCoordinator::Message(CoordinatorSendMessage {
            target_destinations: Destination::All,
            // `DataErase` has no dedicated wire variant, so `From` encapsulates
            // it: this is a genuine `EncapsV0` frame.
            message_body: WireCoordinatorSendBody::from(CoordinatorSendBody::DataErase),
        }));
        // `ReceiveSerial::Message` (index 1), `Destination::All` (index 0),
        // `WireCoordinatorSendBody::EncapsV0` (index 5). Asserted rather than
        // assumed: if any of the three moves, the rest of this frame is not the
        // thing the test claims to be testing.
        assert_eq!(&real[..3], &[0x01, 0x00, 0x05], "vendored tag layout moved");
        let mut bytes = real[..3].to_vec();
        // The `Vec<u8>` length, as `bincode` writes a varint length.
        bytes.extend_from_slice(&enc(&(claim as u64)));
        // Four of the `claim` bytes actually delivered. Any number below `claim`
        // does; the point is that the frame is short.
        bytes.extend_from_slice(&[0u8; 4]);
        bytes
    }

    #[test]
    fn an_over_claiming_frame_is_refused_before_it_allocates() {
        // 32,748 is the largest claim a `1 << 15` limit still admits at this
        // type, measured by bisecting `over_claiming_frame` — the other 20 bytes
        // of the budget go on the envelope. Deliberately the worst case rather
        // than a round number. That was the vendored budget when this defect was
        // found; see `HISTORICAL_32K_CONFIG`.
        let poison = over_claiming_frame(32_748);
        // Ten bytes on the wire: three variant tags, a three-byte length varint,
        // four bytes of payload. That is the whole attack.
        assert_eq!(poison.len(), 10);

        // Under a 32 KiB budget this is a well-formed *truncated* frame:
        // `bincode` allocates the 32,760 bytes it was told to, then asks for
        // more. Asserting this first is what stops the test passing for the
        // wrong reason — a malformed poison would desync on its tags alone and
        // prove nothing about the limit.
        assert!(
            matches!(
                bincode::decode_from_slice::<FromCoordinator, _>(&poison, HISTORICAL_32K_CONFIG),
                Err(DecodeError::UnexpectedEnd { .. })
            ),
            "poison must be well-formed-but-short under the historical 32 KiB limit"
        );

        // The vendored budget is 20,480 now, so it refuses this too — the defect
        // is closed on both sides of the vendor boundary, not just in our config.
        assert!(matches!(
            bincode::decode_from_slice::<FromCoordinator, _>(&poison, BINCODE_CONFIG),
            Err(DecodeError::LimitExceeded)
        ));

        // Under ours it is refused by the limit, which `bincode` checks before
        // it allocates.
        assert!(matches!(
            bincode::decode_from_slice::<FromCoordinator, _>(&poison, DECODE_CONFIG),
            Err(DecodeError::LimitExceeded)
        ));

        // And that routes into the refusal `Link` already has: not a panic, not
        // a silent retry, and not a link that stays up.
        let mut link = Link::new();
        poll_all(&mut link, &coordinator_magic()).unwrap();
        assert_eq!(
            link.poll::<FromCoordinator, _>(&poison, |_| unreachable!("must not decode")),
            Err(CommsError::Desync)
        );
        assert!(!link.is_linked(), "a desync must drop the link");
        assert_eq!(link.pending(), 0);
    }

    /// Pins the **vendored** `MAX_MESSAGE_ALLOC_SIZE` from both sides, because
    /// nothing else in this tree does.
    ///
    /// It came 32,768 → 20,480 on 2026-08-19 (PLAN.md §9 item 7(d)). Mutation
    /// testing found that lowering it *further* broke no test at all — 8,192 and
    /// 16,384 both left the suite green — which is a direct consequence of nothing
    /// device-side decoding with this config. An unpinned bound is one a future
    /// re-vendor or a well-meant tightening moves silently, so this test is the pin.
    ///
    /// The probe is a `Vec<u8>` claim, which bincode charges 1:1, so it measures the
    /// **budget itself** rather than any one type's amplification — and it is
    /// therefore identical in debug and release. Both numbers are measured, not
    /// chosen: 17,664 B is the largest legitimate claim either encapsulated leg can
    /// make for a frame that fits `FRAME_LIMIT` (device→coordinator, debug, 61 nonces
    /// in one segment), and 32,748 is the hostile claim the historical budget
    /// admitted. `UnexpectedEnd` means *admitted then found short* — i.e. the budget
    /// allowed it; `LimitExceeded` means refused before allocating.
    #[test]
    fn the_vendored_budget_admits_every_legitimate_claim_and_refuses_the_historical_one() {
        // Lower side: a legitimate frame must not be refused. Fails if the vendored
        // const is lowered to 16,384 or 8,192.
        assert!(
            matches!(
                bincode::decode_from_slice::<FromCoordinator, _>(
                    &over_claiming_frame(17_664),
                    BINCODE_CONFIG
                ),
                Err(DecodeError::UnexpectedEnd { .. })
            ),
            "the vendored budget must still admit the 17,664 B worst legitimate claim"
        );

        // Upper side: the historical claim must be refused. Fails if the const is
        // restored to `1 << 15`.
        assert!(
            matches!(
                bincode::decode_from_slice::<FromCoordinator, _>(
                    &over_claiming_frame(32_748),
                    BINCODE_CONFIG
                ),
                Err(DecodeError::LimitExceeded)
            ),
            "the vendored budget must refuse the historical 32,748 B claim"
        );
    }

    #[test]
    fn the_over_claim_would_otherwise_repeat_on_every_poll() {
        // The half of the defect that a one-shot decode does not show: the
        // `UnexpectedEnd` arm keeps a partial frame buffered, so under the 32 KiB
        // budget the 32,748-byte allocation happens again on every poll, forever,
        // with no further bytes from the attacker. Pinned by decoding the
        // *buffered* state twice under the old config and getting the same
        // recoverable answer both times — the loop `DECODE_ALLOC_LIMIT` breaks.
        let poison = over_claiming_frame(32_748);
        for _ in 0..2 {
            assert!(matches!(
                bincode::decode_from_slice::<FromCoordinator, _>(&poison, HISTORICAL_32K_CONFIG),
                Err(DecodeError::UnexpectedEnd { .. })
            ));
        }
        // With the limit in place there is nothing to repeat: the link is gone
        // on the first poll, and an unlinked `Link` buffers nothing.
        let mut link = Link::new();
        poll_all(&mut link, &coordinator_magic()).unwrap();
        assert_eq!(
            link.poll::<FromCoordinator, _>(&poison, |_| unreachable!()),
            Err(CommsError::Desync)
        );
        assert_eq!(link.pending(), 0);
        assert!(poll_all(&mut link, &[]).unwrap().is_empty());
    }

    #[test]
    fn a_limit_sized_frame_of_device_ids_still_decodes_under_the_new_limit() {
        // The other direction of the bound, and the one that would break real
        // traffic if `DECODE_ALLOC_LIMIT` were set too low. `DeviceId` is the
        // densest legitimate container in the inbound type — 33 wire bytes per
        // element, `size_of` 33, so it charges `bincode`'s budget at the highest
        // rate any current field can. This builds the largest such frame that
        // still fits `FRAME_LIMIT`.
        let mut ids = alloc::collections::BTreeSet::new();
        let mut best = None;
        for i in 0..=u16::MAX {
            ids.insert(DeviceId(
                core::array::from_fn(|k| if k == 0 { i as u8 } else { (i >> 8) as u8 ^ k as u8 }),
            ));
            let frame = FromCoordinator::Message(CoordinatorSendMessage {
                target_destinations: Destination::Particular(ids.clone()),
                message_body: WireCoordinatorSendBody::from(CoordinatorSendBody::DataErase),
            });
            let bytes = enc(&frame);
            if bytes.len() > FRAME_LIMIT {
                break;
            }
            best = Some(bytes);
        }
        let bytes = best.expect("some number of device ids fits");
        // Sanity: this really is a frame near the ceiling, not a two-element one.
        assert!(
            bytes.len() > FRAME_LIMIT - 40,
            "expected a near-limit frame, got {}",
            bytes.len()
        );

        let mut link = Link::new();
        poll_all(&mut link, &coordinator_magic()).unwrap();
        let mut n = 0;
        link.poll::<FromCoordinator, _>(&bytes, |_| n += 1)
            .expect("a legitimate limit-sized frame must not be refused");
        assert_eq!(n, 1);
        assert!(link.is_linked());
    }
}

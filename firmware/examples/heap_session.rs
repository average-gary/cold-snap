//! Heap measurement for the **shipped** construction: `identity::load_or_create`
//! -> `Session::open` -> `NonceAbSlot` over `FakeFlash`, driven by a real
//! `FrostCoordinator` through the real `comms` framing and the real `Outbox`.
//!
//! WHY THIS FILE EXISTS. Every number in `coldsnap_hal::heap` was measured with
//! `FrostSigner::new_random` + `MemoryNonceSlot` (`hal/examples/heap_profile.rs`,
//! `hal/examples/heap_lifo.rs`). Neither is on any device path: `boot()` and
//! `examples/stub.rs` both go through `Session::open`, which derives the keypair
//! from flash and puts the nonce slots on flash. With `panic = "abort"` and RDP=2
//! there is no way back from an exhausted allocator, so the budget has to be
//! measured against the construction that ships, not a cousin of it.
//!
//! WHAT IS BEING MEASURED, and it is deliberately two different things:
//!
//!   * **Arena footprint** — the workload run through the same allocator crate and
//!     version the image registers (`linked_list_allocator =0.10.6`, `src/alloc.rs`)
//!     in an arena of exactly `heap::HEAP_BYTES`. This is the fit number, and
//!     `NULLS` is the pass/fail: one null is `handle_alloc_error` -> panic -> reset,
//!     and at RDP=2 with no PIN UI that reset is permanent.
//!   * **Requested bytes** (`live` / `LIVE-BYTES peak`) — the tracking-allocator
//!     figure, `sum(Layout::size())`, which is what `MEASURED_LIVE_BYTES` and
//!     `MEASURED_PEAK_BYTES` are. Allocator-independent, so it is the one that can
//!     be compared with the old numbers and substituted into the binding assert.
//!
//! The wrapper is `heap_lifo.rs`'s `Lll`, not `src/alloc.rs`'s `Arena`: `Arena` is
//! private to the **bin** target (`mod alloc;` at `src/main.rs:104`) and exposes no
//! `used()`/`largest_fit()`, so reaching it would mean editing shipped code for a
//! harness. Its two guards only *reject* (an out-of-arena dealloc, a stale
//! sentinel); they do not change what fits. Same crate, same version, same
//! `Heap::allocate_first_fit`.
//!
//! PER-DEVICE ATTRIBUTION. `alloc` routes to the arena when the `IN_DEV` flag is
//! set; `dealloc`/`realloc` route by **pointer range**, so a block always goes home.
//! The arena therefore holds exactly ONE device's heap — the `Session` — while the
//! coordinator and the other n-1 signers stay on `System`. No division by n, no
//! slope. The other signers are `FrostSigner::new_random` + `MemoryNonceSlot` on
//! purpose: they are harness scaffolding to make the coordinator's protocol
//! complete, and they are not measured.
//!
//! WHAT THE SPAN COVERS, which is the one way to get this wrong: the outer decode
//! leg (`Link::poll`, `comms::DECODE_ALLOC_LIMIT`), the inner leg
//! (`comms::decode_body`, `heap::ENCAPS_ALLOC_CEILING`), `Session::recv`,
//! `Session::confirm` and the `staged_mutations` drain, all while the `Outbox` is
//! **undrained**. That co-residency is precisely what `heap.rs`'s binding assert
//! claims and what nothing in this tree measured before. The span closes before the
//! outbox bytes are handed to the harness — on the device those bytes go to a fixed
//! `[u8; FRAME_LIMIT]` USB buffer, not to the heap.
//!
//! POINTER WIDTH. Host is 64-bit, device is 32-bit thumbv7em, and the direction is
//! conservative: `linked_list_allocator`'s min block and rounding are
//! `2*size_of::<usize>()` / `align_of::<usize>()`, i.e. 16/8 here and 8/4 there;
//! there is no per-allocation header to convert; and 8-byte alignment padding is
//! never smaller than 4-byte. But the *magnitude* is small, not the 10-40% that
//! `heap.rs` used to claim: `secp256kfun` reaches the curve through `k256`, whose
//! `FieldElement10x26` (32-bit) and `FieldElement5x52` (64-bit) are both exactly
//! 40 B, so `Point` is 120 B on both widths and the dominant consumers — nonce
//! vectors, share images, agg nonces, signature shares — do not shrink at all.
//! Treat the printed figures as an upper bound with a low single-digit percent of
//! give, and do not spend it.
//!
//! NOT evidence about silicon. Host allocator, host pointer width, `fake-flash` and
//! `test-seam` both on, RNG seeded from fixed bytes. It bounds the budget; it does
//! not flash anything.
//!
//! Run (release, because `overflow-checks` and `size_of::<Point>()` both differ in
//! debug and release is what ships):
//!   cargo run --release --target aarch64-apple-darwin -p coldsnap_firmware \
//!       --features frostsnap_core/coordinator --example heap_session
//!
//! Knobs: `HEAP_N` = group size (default 12, the declared envelope; t = n, which
//! maximises per-device signing work), `HEAP_ROUNDS` = signing rounds (default 3 —
//! more than one is what makes the per-round series meaningful), `HEAP_ARENA` =
//! arena bytes (default `heap::HEAP_BYTES`; only for finding the cliff).

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::{RefCell, UnsafeCell};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed};

use coldsnap_firmware::{DebugFlash, Fault, Outbox, Session, NONCE_SLOTS};
use coldsnap_hal::comms::{decode_body, encode_frame, Link, DECODE_ALLOC_LIMIT, FRAME_LIMIT};
use coldsnap_hal::flash::fake::FakeFlash;
use coldsnap_hal::flash::ERASE_SIZE;
use coldsnap_hal::heap::{
    ENCAPS_ALLOC_CEILING, HEAP_BYTES, MEASURED_LIVE_BYTES, MEASURED_PEAK_BYTES, OUTBOX_CEILING,
};
use coldsnap_hal::rng::{mix_sources, Entropy, ProvenSeed, SE1_BYTES, SE2_BYTES, TRNG_BYTES};
use coldsnap_hal::{identity, memmap};
use embedded_storage::nor_flash::ReadNorFlash;
use frostsnap_comms::{
    CoordinatorSendBody, CoordinatorSendMessage, Destination, DeviceSendBody, Downstream,
    MagicBytes, ReceiveSerial, Upstream, WireCoordinatorSendBody,
};
use frostsnap_core::coordinator::{
    BeginKeygen, CoordinatorSend, CoordinatorToUserKeyGenMessage, CoordinatorToUserMessage,
    CoordinatorToUserSigningMessage, FrostCoordinator,
};
use frostsnap_core::device::{
    DeviceSecretDerivation, DeviceToUserMessage, FrostSigner, KeyPurpose,
};
use frostsnap_core::message::signing::DeviceSigning;
use frostsnap_core::message::{
    CoordinatorRestoration, CoordinatorToDeviceMessage, DeviceRestoration, DeviceSend,
    DeviceToCoordinatorMessage,
};
use frostsnap_core::schnorr_fun::frost::{Fingerprint, ShareIndex};
use frostsnap_core::schnorr_fun::{Schnorr, Signature};
use frostsnap_core::{
    AccessStructureRef, CoordShareDecryptionContrib, DeviceId, SymmetricKey, WireSignTask,
};
use sha2::{Digest, Sha256};

// ------------------------------------------------------------ the allocator
// Lifted from `hal/examples/heap_lifo.rs`'s `LIFO_MODE=lll` path, minus the bump
// candidate: same wrapper shape, same counters, same routing.

/// Backing store for the arena. `HEAP_BYTES` plus slack so `HEAP_ARENA` can probe
/// past the shipped size without a second static.
const ARENA_CAP: usize = 128 * 1024;

#[repr(align(16))]
struct Backing(UnsafeCell<[u8; ARENA_CAP]>);
// SAFETY: single-threaded harness; every access goes through `base()`/`lll()`,
// reached only from the global allocator and from `snap`.
unsafe impl Sync for Backing {}
static BACK: Backing = Backing(UnsafeCell::new([0u8; ARENA_CAP]));

struct Lll(UnsafeCell<linked_list_allocator::Heap>);
// SAFETY: same argument as `Backing`.
unsafe impl Sync for Lll {}
static LLL: Lll = Lll(UnsafeCell::new(linked_list_allocator::Heap::empty()));

static IN_DEV: AtomicBool = AtomicBool::new(false);
/// Requested bytes currently live in the arena — the `MEASURED_LIVE_BYTES` metric.
static LIVE: AtomicUsize = AtomicUsize::new(0);
/// High-water of the above: the `MEASURED_PEAK_BYTES` metric, and a true
/// simultaneous peak rather than a sum of two maxima.
static LIVE_PEAK: AtomicUsize = AtomicUsize::new(0);
/// High-water of `Heap::used()` — the same live set, rounded to blocks.
static USED_PEAK: AtomicUsize = AtomicUsize::new(0);
/// High-water of the arena FOOTPRINT: the highest byte offset ever handed out.
/// This is the number that has to clear `HEAP_BYTES`.
static HIGH: AtomicUsize = AtomicUsize::new(0);
static BLOCKS: AtomicUsize = AtomicUsize::new(0);
static BLOCKS_PEAK: AtomicUsize = AtomicUsize::new(0);
static MAXONE: AtomicUsize = AtomicUsize::new(0);
static ALLOCS: AtomicUsize = AtomicUsize::new(0);
/// `allocate_first_fit` returning `Err`. On device: `handle_alloc_error` -> panic
/// -> reset -> permanent brick at RDP=2. Nonzero here is the whole finding.
static NULLS: AtomicUsize = AtomicUsize::new(0);
static NULL_PHASE: AtomicUsize = AtomicUsize::new(0);
static NULL_REQ: AtomicUsize = AtomicUsize::new(0);
static PHASE: AtomicUsize = AtomicUsize::new(0);

fn base() -> usize {
    BACK.0.get() as usize
}

fn in_arena(p: *mut u8) -> bool {
    let b = base();
    (p as usize) >= b && (p as usize) < b + ARENA_CAP
}

#[allow(clippy::mut_from_ref)]
fn lll() -> &'static mut linked_list_allocator::Heap {
    // SAFETY: single threaded, and nothing reached from here allocates.
    unsafe { &mut *LLL.0.get() }
}

/// What the allocator really consumes for one request: `size` floored at
/// `HoleList::min_size()` = `2 * size_of::<usize>()`, rounded to
/// `align_of::<Hole>()`. No per-block header — the links live in the free holes.
/// 16-floor/8-round on this 64-bit host, 8-floor/4-round on the 32-bit device.
fn consumed(l: Layout) -> usize {
    let w = size_of::<usize>();
    (l.size().max(2 * w) + w - 1) & !(w - 1)
}

fn arena_alloc(l: Layout) -> *mut u8 {
    let h = lll();
    match h.allocate_first_fit(l) {
        Ok(p) => {
            HIGH.fetch_max(p.as_ptr() as usize - base() + consumed(l), Relaxed);
            USED_PEAK.fetch_max(h.used(), Relaxed);
            LIVE_PEAK.fetch_max(LIVE.fetch_add(l.size(), Relaxed) + l.size(), Relaxed);
            BLOCKS_PEAK.fetch_max(BLOCKS.fetch_add(1, Relaxed) + 1, Relaxed);
            MAXONE.fetch_max(l.size(), Relaxed);
            ALLOCS.fetch_add(1, Relaxed);
            p.as_ptr()
        }
        Err(()) => {
            if NULLS.fetch_add(1, Relaxed) == 0 {
                NULL_PHASE.store(PHASE.load(Relaxed), Relaxed);
                NULL_REQ.store(l.size(), Relaxed);
            }
            // Served off `System` so one run shows the whole trajectory. The arena
            // counters are deliberately untouched, so the later `dealloc` (routed
            // by pointer range, i.e. to `System`) stays balanced.
            unsafe { System.alloc(l) }
        }
    }
}

fn arena_dealloc(p: *mut u8, l: Layout) {
    // SAFETY: routed by pointer range, so `p` came from `arena_alloc` with this layout.
    unsafe { lll().deallocate(NonNull::new_unchecked(p), l) };
    LIVE.fetch_sub(l.size(), Relaxed);
    BLOCKS.fetch_sub(1, Relaxed);
}

/// The largest single block the arena can still serve, by probing. This is the
/// fragmentation number: `free()` is a *sum* of holes, this is the biggest one.
fn largest_fit() -> usize {
    let w = align_of::<usize>();
    let cap = lll().size();
    let mut best = 0usize;
    let mut step = cap.next_power_of_two() / 2;
    while step >= w {
        let want = best + step;
        if want <= cap {
            let l = Layout::from_size_align(want, w).expect("valid layout");
            if let Ok(p) = lll().allocate_first_fit(l) {
                // SAFETY: just returned by `allocate_first_fit` with this layout.
                unsafe { lll().deallocate(p, l) };
                best = want;
            }
        }
        step /= 2;
    }
    best
}

struct Route;

// SAFETY: `alloc` picks a pool by the `IN_DEV` flag; `dealloc`/`realloc` pick by
// pointer range, so a block always goes back to the pool it came from.
unsafe impl GlobalAlloc for Route {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        if IN_DEV.load(Relaxed) {
            arena_alloc(l)
        } else {
            System.alloc(l)
        }
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        if in_arena(p) {
            arena_dealloc(p, l)
        } else {
            System.dealloc(p, l)
        }
    }

    unsafe fn realloc(&self, p: *mut u8, l: Layout, new_size: usize) -> *mut u8 {
        if !in_arena(p) {
            return System.realloc(p, l, new_size);
        }
        // Naive grow, deliberately: the linked list has no top block to extend,
        // and a realloc that has to land in a bigger hole is the case under test.
        let np = arena_alloc(Layout::from_size_align_unchecked(new_size, l.align()));
        if !np.is_null() {
            std::ptr::copy_nonoverlapping(p, np, l.size().min(new_size));
            arena_dealloc(p, l);
        }
        np
    }
}

#[global_allocator]
static ALLOC: Route = Route;

/// Scoped `IN_DEV`. Restores the previous value, so an inner `Dev::on(false)`
/// around harness-only work nests correctly inside a device span.
struct Dev(bool);

impl Dev {
    fn on(yes: bool) -> Dev {
        Dev(IN_DEV.swap(yes, Relaxed))
    }
}

impl Drop for Dev {
    fn drop(&mut self) {
        IN_DEV.store(self.0, Relaxed);
    }
}

const PHASES: &[&str] = &[
    "setup",
    "keygen",
    "nonces",
    "sign",
    "HeldShares2",
    "teardown",
];

fn phase(i: usize) {
    PHASE.store(i.min(PHASES.len() - 1), Relaxed);
}

fn hdr() {
    eprintln!(
        "  {:<34} {:>8} {:>8} {:>8} {:>6} {:>7} {:>8} {:>7}",
        "after", "foot", "used", "live", "pad", "blocks", "maxfree", "allocs"
    );
}

/// `(footprint, used, live, largest free block)`.
fn now() -> (usize, usize, usize, usize) {
    (
        HIGH.load(Relaxed),
        lll().used(),
        LIVE.load(Relaxed),
        largest_fit(),
    )
}

fn snap(tag: &str) {
    let _off = Dev::on(false);
    let (foot, used, live, maxfree) = now();
    eprintln!(
        "  {:<34} {:>8} {:>8} {:>8} {:>6} {:>7} {:>8} {:>7}",
        tag,
        foot,
        used,
        live,
        used.saturating_sub(live),
        BLOCKS.load(Relaxed),
        maxfree,
        ALLOCS.load(Relaxed),
    );
}

// ------------------------------------------ harness-side devices and secrets
// From `heap_profile.rs` / `heap_lifo.rs`, unchanged.

const TEST_FINGERPRINT: Fingerprint = Fingerprint {
    bits_per_coeff: 2,
    max_bits_total: 6,
    tag: "test",
};

const TEST_KEY: SymmetricKey = SymmetricKey([42u8; 32]);

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

/// Secrets for the SCAFFOLDING signers only. The measured device uses
/// `Session`'s own, derived from its flash identity.
struct Secrets;

impl DeviceSecretDerivation for Secrets {
    fn get_share_encryption_key(
        &mut self,
        _a: AccessStructureRef,
        _p: ShareIndex,
        _c: CoordShareDecryptionContrib,
    ) -> SymmetricKey {
        TEST_KEY
    }

    fn derive_nonce_seed(
        &mut self,
        nonce_stream_id: frostsnap_core::nonce_stream::NonceStreamId,
        index: u32,
        seed_material: &[u8; 32],
    ) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(seed_material);
        h.update(nonce_stream_id.to_bytes());
        h.update(index.to_le_bytes());
        h.finalize().into()
    }
}

/// `DebugFlash` is only the `core::fmt::Debug` shim `FrostSigner::new` demands.
type Flash = DebugFlash<FakeFlash>;

// ------------------------------------------------------------ the driver

enum Msg {
    ToDevice {
        dests: BTreeSet<DeviceId>,
        msg: CoordinatorToDeviceMessage,
    },
    ToCoord {
        from: DeviceId,
        msg: DeviceToCoordinatorMessage,
    },
    ToUser(CoordinatorToUserMessage),
}

fn to_msg(s: CoordinatorSend) -> Msg {
    match s {
        CoordinatorSend::ToDevice {
            message,
            destinations,
        } => Msg::ToDevice {
            dests: destinations,
            msg: message,
        },
        CoordinatorSend::ToUser(m) => Msg::ToUser(m),
    }
}

/// A `Link` past the magic-byte handshake. `Link::poll` scans for the UPSTREAM
/// pattern whichever frame type it is later asked to decode, so this is also how
/// the harness-side decoder of the device's own (Downstream) frames is opened.
fn linked_link() -> Link {
    let mut buf = [0u8; FRAME_LIMIT];
    let n = encode_frame(
        &ReceiveSerial::<Upstream>::MagicBytes(MagicBytes::default()),
        &mut buf,
    )
    .expect("magic encodes");
    let mut link = Link::new();
    link.poll::<ReceiveSerial<Upstream>, _>(&buf[..n], |_| {})
        .expect("handshake");
    assert!(link.is_linked(), "magic bytes must link");
    link
}

struct Hep<'a> {
    coord: FrostCoordinator,
    /// The device under measurement: the SHIPPED construction.
    session: Session<'a, Flash>,
    id: DeviceId,
    /// Scaffolding, on `System`, so the coordinator's protocol can complete.
    peers: BTreeMap<DeviceId, FrostSigner>,
    queue: VecDeque<Msg>,
    rng: Entropy,
    sigs: Vec<Signature>,
    /// The device's receive link — in-arena, and long-lived like the real one.
    link: Link,
    /// Harness-side decoder for the frames the device emits.
    back: Link,
    /// Largest number of undrained outbox bytes, and frames, ever parked.
    outbox_peak: usize,
    outbox_frames: usize,
    refusals: usize,
}

impl Hep<'_> {
    fn pump(&mut self) {
        while let Some(m) = self.queue.pop_front() {
            match m {
                Msg::ToDevice { dests, msg } => {
                    if dests.contains(&self.id) {
                        let replies = self.drive_session(&msg);
                        for r in replies {
                            self.queue.push_back(Msg::ToCoord {
                                from: self.id,
                                msg: r,
                            });
                        }
                    }
                    for d in dests {
                        if self.peers.contains_key(&d) {
                            self.drive_peer(d, &msg);
                        }
                    }
                }
                Msg::ToCoord { from, msg } => {
                    let out = self
                        .coord
                        .recv_device_message(from, msg)
                        .expect("coordinator rejected a device message");
                    self.queue.extend(out.into_iter().map(to_msg));
                }
                Msg::ToUser(m) => self.on_user(m),
            }
        }
    }

    /// ONE loop iteration of the shipped device: wire bytes in, decoded body to
    /// `Session::recv`, prompts auto-acked, mutations drained, outbox drained.
    /// Returns what the coordinator would have read off the wire.
    fn drive_session(&mut self, msg: &CoordinatorToDeviceMessage) -> Vec<DeviceToCoordinatorMessage> {
        // The coordinator's frame, built on `System`: on a real device these bytes
        // arrive over USB and cost the device nothing but the `Link` buffer, which
        // is a fixed `[u8; FRAME_LIMIT]` and not heap.
        let mut dests = BTreeSet::new();
        dests.insert(self.id);
        let mut frame = [0u8; FRAME_LIMIT];
        let len = encode_frame(
            &ReceiveSerial::<Upstream>::Message(CoordinatorSendMessage {
                target_destinations: Destination::Particular(dests),
                message_body: WireCoordinatorSendBody::from(CoordinatorSendBody::Core(msg.clone())),
            }),
            &mut frame,
        )
        .expect("a coordinator frame this device could never receive is a finding, not a knob");

        let Hep {
            link,
            session,
            rng,
            outbox_peak,
            outbox_frames,
            refusals,
            ..
        } = self;
        let mut out = Outbox::new(session.device_id());
        let mut prompts: VecDeque<DeviceToUserMessage> = VecDeque::new();
        {
            // THE SPAN. Both decode legs, the dispatch, the consent acks and the
            // mutation drain, with `out` undrained the whole time.
            let _on = Dev::on(true);
            link.poll::<ReceiveSerial<Upstream>, _>(&frame[..len], |f| {
                if let ReceiveSerial::Message(m) = f {
                    // `decode_body`, not the vendored `.decode()`: the bounded leg.
                    match decode_body(m.message_body) {
                        Ok(body) => match session.recv(body, rng, &mut out) {
                            Ok(p) => prompts.extend(p),
                            // A refusal is policy, not failure.
                            Err(Fault::Refused(_)) => *refusals += 1,
                            Err(e) => panic!("Session::recv: {e:?}"),
                        },
                        Err(e) => panic!("the device could not decode a real frame: {e:?}"),
                    }
                }
            })
            .expect("Link::poll on a frame this harness just encoded");

            // AUTO-ACK, and it is a harness affordance: a real device asks a human.
            while let Some(p) = prompts.pop_front() {
                if matches!(
                    p,
                    DeviceToUserMessage::CheckKeyGen { .. } | DeviceToUserMessage::SignatureRequest { .. }
                ) {
                    match session.confirm(p, rng, &mut out) {
                        Ok(more) => prompts.extend(more),
                        Err(e) => panic!("Session::confirm: {e:?}"),
                    }
                }
            }

            // Firmware's flash write: draining and dropping is what "persisted"
            // means for the share here (there is no FS region for shares yet).
            session.signer.staged_mutations().drain(..).count();

            *outbox_peak = (*outbox_peak).max(out.bytes().len());
            *outbox_frames = (*outbox_frames).max(out.frames());
        }

        // `take` moves the Vec, it does not allocate; the arena copy is freed at
        // the `drop` below, by pointer range.
        let bytes = out.take();
        let mut replies = Vec::new();
        self.back
            .poll::<ReceiveSerial<Downstream>, _>(&bytes, |f| {
                if let ReceiveSerial::Message(m) = f {
                    match m.body.decode() {
                        Ok(DeviceSendBody::Core(core)) => replies.push(core),
                        Ok(_) => {}
                        Err(e) => panic!("undecodable device frame: {e}"),
                    }
                }
            })
            .expect("the device's own frames must parse");
        drop(bytes);
        replies
    }

    /// A scaffolding signer. `FrostSigner::new_random` + `MemoryNonceSlot`, on
    /// `System`, never measured.
    fn drive_peer(&mut self, id: DeviceId, msg: &CoordinatorToDeviceMessage) {
        let mut outbox: Vec<DeviceToCoordinatorMessage> = Vec::new();
        let out = self
            .peers
            .get_mut(&id)
            .expect("checked by caller")
            .recv_coordinator_message(msg.clone(), &mut self.rng);
        let mut work: VecDeque<DeviceSend> = match out {
            Ok(v) => v.into(),
            Err(e) => panic!("recv_coordinator_message({id}): {e}"),
        };
        while let Some(send) = work.pop_front() {
            match send {
                DeviceSend::ToCoordinator(m) => outbox.push(*m),
                DeviceSend::ToUser(m) => match *m {
                    DeviceToUserMessage::CheckKeyGen { phase, .. } => {
                        let r = self.peers.get_mut(&id).expect("still there").keygen_ack(
                            *phase,
                            &mut Secrets,
                            &mut self.rng,
                        );
                        work.extend(r.expect("keygen_ack"));
                    }
                    DeviceToUserMessage::NonceJobs(mut batch) => {
                        batch.run_until_finished(&mut Secrets);
                        for segment in batch.into_segments() {
                            outbox.push(DeviceToCoordinatorMessage::Signing(
                                DeviceSigning::NonceResponse {
                                    segments: vec![segment],
                                },
                            ));
                        }
                    }
                    DeviceToUserMessage::SignatureRequest { phase } => {
                        let r = self
                            .peers
                            .get_mut(&id)
                            .expect("still there")
                            .sign_ack(*phase, &mut Secrets);
                        work.extend(r.expect("sign_ack"));
                    }
                    _ => {}
                },
            }
        }
        self.peers
            .get_mut(&id)
            .expect("still there")
            .staged_mutations()
            .drain(..)
            .count();
        for m in outbox {
            self.queue.push_back(Msg::ToCoord { from: id, msg: m });
        }
    }

    fn on_user(&mut self, m: CoordinatorToUserMessage) {
        match m {
            CoordinatorToUserMessage::KeyGen {
                keygen_id,
                inner:
                    CoordinatorToUserKeyGenMessage::KeyGenAck {
                        all_acks_received: true,
                        ..
                    },
            } => {
                let sends = self
                    .coord
                    .finalize_keygen(keygen_id, TEST_KEY, &mut self.rng)
                    .expect("finalize_keygen");
                self.queue.extend(sends.into_iter().map(to_msg));
            }
            CoordinatorToUserMessage::Signing(CoordinatorToUserSigningMessage::Signed {
                signatures,
                ..
            }) => {
                self.sigs.extend(
                    signatures
                        .into_iter()
                        .map(|s| s.into_decoded().expect("valid encoded signature")),
                );
            }
            _ => {}
        }
    }
}

fn knob(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn main() {
    let n = knob("HEAP_N", 12).max(1);
    let rounds = knob("HEAP_ROUNDS", 3);
    let arena = knob("HEAP_ARENA", HEAP_BYTES);
    let slots = NONCE_SLOTS as usize;
    assert!(arena <= ARENA_CAP, "HEAP_ARENA must fit the backing store");

    // SAFETY: `BACK` is a live `static` of `ARENA_CAP` bytes, aligned 16, and
    // nothing else hands out any part of it.
    unsafe { lll().init(base() as *mut u8, arena) };

    eprintln!(
        "=== heap_session: Session::open + NonceAbSlot over FakeFlash, n={n} t={n} \
         rounds={rounds} slots={slots} ==="
    );
    eprintln!(
        "  arena {arena} B (heap::HEAP_BYTES = {HEAP_BYTES}), linked_list_allocator 0.10.6, \
         host 64-bit"
    );
    eprintln!(
        "  min block {} B, round to {} B (device: 8 B / 4 B, so device rounding waste is half)",
        2 * size_of::<usize>(),
        align_of::<usize>()
    );
    eprintln!(
        "  arena holds ONE device: the flash-backed `Session`. The coordinator and the other \
         {} signer(s) are scaffolding on System.",
        n - 1
    );
    hdr();

    // The flash is NOT heap: on device it is 1 MiB of internal NOR. Built before
    // the span so its backing `Vec` stays on `System`.
    let sectors = memmap::FS_FREE_OFFSET as usize / ERASE_SIZE;
    let flash: RefCell<Flash> = RefCell::new(DebugFlash(FakeFlash::new(sectors)));

    phase(0);
    let mut rng = entropy(0x5a);
    // THE SHIPPED CONSTRUCTION, measured: durable identity, then flash-backed
    // nonce slots. `load_or_create` wants `&mut Flash` and the session takes a
    // shared borrow of the same `RefCell` for its whole life, so identity first.
    let secret = {
        let _on = Dev::on(true);
        identity::load_or_create(&mut *flash.borrow_mut(), &mut rng).expect("identity")
    };
    snap("identity::load_or_create");
    let mut session = {
        let _on = Dev::on(true);
        Session::open(&flash, &secret).expect("Session::open")
    };
    session.signer.keygen_fingerprint = TEST_FINGERPRINT;
    let id = session.device_id();
    snap("Session::open (flash-backed slots)");

    let mut coord = FrostCoordinator::new();
    coord.keygen_fingerprint = TEST_FINGERPRINT;
    let mut peers: BTreeMap<DeviceId, FrostSigner> = BTreeMap::new();
    for _ in 1..n {
        let mut s = FrostSigner::new_random(&mut rng, slots);
        s.keygen_fingerprint = TEST_FINGERPRINT;
        peers.insert(s.device_id(), s);
    }
    let mut ids: Vec<DeviceId> = peers.keys().copied().collect();
    ids.push(id);
    let id_set: BTreeSet<DeviceId> = ids.iter().copied().collect();

    let mut p = Hep {
        coord,
        session,
        id,
        peers,
        queue: VecDeque::new(),
        rng,
        sigs: Vec::new(),
        link: {
            let _on = Dev::on(true);
            linked_link()
        },
        back: linked_link(),
        outbox_peak: 0,
        outbox_frames: 0,
        refusals: 0,
    };

    // --- keygen at the declared envelope, t = n
    phase(1);
    let begin = BeginKeygen::new(
        ids.clone(),
        n as u16,
        "heap session".to_string(),
        KeyPurpose::Test,
        &mut p.rng,
    );
    let sends = p
        .coord
        .begin_keygen(begin, &mut entropy(0x77))
        .expect("begin_keygen");
    p.queue.extend(sends.into_iter().map(to_msg));
    p.pump();
    snap("keygen");

    // --- nonce replenishment
    phase(2);
    let req = p
        .coord
        .maybe_request_nonce_replenishment(&id_set, 1, &mut entropy(0x88));
    p.queue.extend(req.into_iter().map(to_msg));
    p.pump();
    snap("nonce replenishment");

    // The slots are on FLASH, not in RAM. This is what fails if `NonceAbSlot` is
    // ever swapped back for `MemoryNonceSlot`.
    let mut probe = [0u8; 256];
    flash
        .borrow_mut()
        .read(memmap::FS_NONCE_OFFSET, &mut probe)
        .expect("read the nonce partition");
    assert!(
        probe.iter().any(|b| *b != 0xff),
        "the nonce partition is blank: the slots are NOT flash-backed, so this run \
         measured the wrong construction"
    );

    // --- signing. A leak shows up as growth PER ROUND, which is why this is a loop.
    let key_data = p.coord.iter_keys().next().expect("a key exists").clone();
    let as_ref = key_data
        .access_structures()
        .next()
        .expect("an access structure")
        .access_structure_ref();
    let master_appkey = key_data.complete_key.master_appkey;
    let schnorr = Schnorr::<Sha256>::verify_only();
    let mut per_round: Vec<(usize, usize, usize, usize)> = Vec::new();
    for round in 0..rounds {
        phase(3);
        if round > 0 {
            let req = p.coord.maybe_request_nonce_replenishment(
                &id_set,
                1,
                &mut entropy(0xa0 + round as u8),
            );
            p.queue.extend(req.into_iter().map(to_msg));
            p.pump();
        }
        let task = WireSignTask::Test {
            message: format!("cold-snap heap_session round {round}"),
        };
        let checked = task
            .clone()
            .check(master_appkey, KeyPurpose::Test)
            .expect("task checks");
        let sign_session = p
            .coord
            .start_sign(as_ref, task, &id_set, &mut entropy(0x99))
            .expect("start_sign");
        for d in &ids {
            let rds = p.coord.request_device_sign(sign_session, *d, TEST_KEY);
            p.queue.push_back(to_msg(CoordinatorSend::from(rds)));
        }
        p.sigs.clear();
        p.pump();
        // The runnable check: a signature this process produced but did not bless.
        assert!(
            checked.verify_final_signatures(&schnorr, &p.sigs),
            "round={round}: the aggregated signature must verify, else the workload was not real"
        );
        snap(&format!("sign round {}", round + 1));
        per_round.push(now());
    }

    // --- the restoration read: `RequestHeldShares` -> `HeldShares2`, cap (b)'s path
    phase(4);
    let held = p.drive_session(&CoordinatorToDeviceMessage::Restoration(
        CoordinatorRestoration::RequestHeldShares,
    ));
    let shares = held
        .iter()
        .filter_map(|m| match m {
            DeviceToCoordinatorMessage::Restoration(DeviceRestoration::HeldShares2(v)) => {
                Some(v.len())
            }
            _ => None,
        })
        .sum::<usize>();
    assert!(
        shares > 0,
        "RequestHeldShares must answer with a non-empty HeldShares2: the device kept no share, \
         so keygen did not really complete"
    );
    snap(&format!("HeldShares2 ({shares} share(s))"));

    // --- what firmware can reclaim. THE ASSERT USES THE FIGURE BEFORE THIS CALL:
    // the shipped dispatch does not make it (`firmware/src/lib.rs` calls
    // `clear_tmp_data` on `Cancel` and nothing else), so what the device really
    // holds between frames is the pre-clear figure. Using the post-clear one would
    // be crediting the budget with a call that is not in the image.
    phase(5);
    let (_, _, live_held, _) = now();
    {
        let _on = Dev::on(true);
        p.session.signer.clear_unfinished_keygens();
    }
    snap("clear_unfinished_keygens");
    let (_, _, live_cleared, _) = now();
    {
        let _on = Dev::on(true);
        drop(p.session);
    }
    snap("drop the Session");

    // ------------------------------------------------------------ the verdict
    let (foot, _, live, maxfree) = now();
    let live_peak = LIVE_PEAK.load(Relaxed);
    let used_peak = USED_PEAK.load(Relaxed);
    let maxone = MAXONE.load(Relaxed);
    let nulls = NULLS.load(Relaxed);
    eprintln!();
    eprintln!("  refusals (policy, expected 0 here): {}", p.refusals);
    eprintln!(
        "  arena FOOTPRINT high-water : {foot} B of {arena} B  ({} B spare)  <- the fit number",
        arena.saturating_sub(foot)
    );
    eprintln!(
        "  PEAK requested (live)      : {live_peak} B in at most {} simultaneous blocks; \
         largest single allocation {maxone} B",
        BLOCKS_PEAK.load(Relaxed)
    );
    eprintln!(
        "  peak consumed (used)       : {used_peak} B  -> per-block rounding overhead {} B \
         (halves on the 32-bit device)",
        used_peak.saturating_sub(live_peak)
    );
    eprintln!(
        "  LIVE held between frames   : {live_held} B  <- what the shipped dispatch holds \
         (it never calls the clear)"
    );
    eprintln!(
        "  LIVE if the clear were called: {live_cleared} B; {live} B after dropping the Session"
    );
    eprintln!("  per signing round          : {per_round:?}  (foot, used, live, maxfree)");
    eprintln!(
        "  largest free block after the drop: {maxfree} B of {arena} B  <- coalescing check"
    );
    eprintln!(
        "  outbox parked at most      : {} B in {} frame(s)   (OUTBOX_CEILING = {OUTBOX_CEILING})",
        p.outbox_peak, p.outbox_frames
    );
    if nulls == 0 {
        eprintln!("  NULLS: 0. Nothing was refused by the allocator.");
    } else {
        eprintln!(
            "  NULLS: {nulls}. FIRST in phase `{}` requesting {} B. ON DEVICE EACH ONE IS \
             handle_alloc_error -> panic -> reset -> PERMANENT BRICK AT RDP=2.",
            PHASES[NULL_PHASE.load(Relaxed)],
            NULL_REQ.load(Relaxed)
        );
    }

    // The binding assert, with the MEASURED live figure in place of the constant.
    let terms = live_held + DECODE_ALLOC_LIMIT + ENCAPS_ALLOC_CEILING + OUTBOX_CEILING;
    eprintln!();
    eprintln!("  heap.rs's binding assert, re-evaluated with what was just measured:");
    eprintln!(
        "    live {live_held} + DECODE_ALLOC_LIMIT {DECODE_ALLOC_LIMIT} + \
         ENCAPS_ALLOC_CEILING {ENCAPS_ALLOC_CEILING} + OUTBOX_CEILING {OUTBOX_CEILING} = {terms} \
         vs HEAP_BYTES {HEAP_BYTES}"
    );
    if terms <= HEAP_BYTES {
        eprintln!("    FITS, slack {} B", HEAP_BYTES - terms);
    } else {
        eprintln!(
            "    DOES NOT FIT, over by {} B  <- RAISE THE FINDING, NOT THE CONSTANT",
            terms - HEAP_BYTES
        );
    }
    eprintln!(
        "    superseded figures, measured with FrostSigner::new_random + MemoryNonceSlot: \
         MEASURED_LIVE_BYTES {MEASURED_LIVE_BYTES}, MEASURED_PEAK_BYTES {MEASURED_PEAK_BYTES}"
    );
    // Three runnable gates, so a regression is a non-zero exit rather than a number
    // in a table nobody reads. The flatness one is load-bearing: both leak
    // mutations this file was verified against (a 512 B `mem::forget` per device
    // call, and never freeing the drained outbox) pass the null check and the
    // assert at n = 12, and fail ONLY here.
    if let Some((_, _, first, _)) = per_round.first() {
        assert!(
            per_round.iter().all(|(_, _, l, _)| l == first),
            "live grew across signing rounds: {per_round:?} -- something is retained per frame, \
             and no arena size fixes that"
        );
    }
    assert_eq!(nulls, 0, "the allocator refused an allocation at {arena} B");
    assert!(
        terms <= HEAP_BYTES,
        "the measured live set no longer fits the binding assert"
    );
}

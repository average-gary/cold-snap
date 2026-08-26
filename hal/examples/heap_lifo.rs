//! ATTACK 2: does a LIFO-rollback bump allocator survive the real workload?
//!
//! Same flow as `heap_profile.rs` (real `FrostCoordinator` against real vendored
//! `FrostSigner`s: keygen -> nonce replenishment -> N signing rounds, each round's
//! aggregate signature asserted to verify) but the allocator under test is a
//! ~40-line LIFO-rollback bump written inline here, and ONLY device 0's
//! allocations go through it.
//!
//! ROUTING, which is the only part that can make the number a lie. A bump that
//! backs the whole process would also be paying for the coordinator, `tracing`,
//! `rusqlite` and every `format!` -- an instant, meaningless OOM. So:
//!
//!   * `alloc` routes to the arena only while `IN_DEV` is set, and `IN_DEV` is set
//!     only around device 0's own calls (its construction,
//!     `recv_coordinator_message`, `keygen_ack`, `NonceJobs::run_until_finished`,
//!     `sign_ack`, `staged_mutations().drain`, the outbound encapsulate+encode).
//!     Devices 1..n and the coordinator stay on `System`.
//!   * `dealloc`/`realloc` route by POINTER RANGE, not by the flag, so a device
//!     allocation freed later -- outside any window -- still hits the arena. That
//!     is what makes long-lived `FrostSigner` state visible as arena residency.
//!   * Outbound messages are cloned to `System` and the arena originals dropped
//!     before the harness queue takes them, so the queue's dwell time does not
//!     show up as device retention.
//!
//! `realloc` is implemented, not defaulted, so the pool routing is right. By
//! default it is the NAIVE version -- alloc-new, copy, free-old -- which is what a
//! plain bump does and is where `Vec` growth turns into retained shadows. Set
//! `LIFO_GROW=1` to add the 4-line grow-the-top-block-in-place case and measure
//! what that one special case is worth.
//!
//! Deliberately NOT modelled: the `0xdeadbeef` guard word. On the host the arena
//! is a zero-init `static`, so the guard would be vacuously true and prove
//! nothing; it is a bring-up concern, not a survival one.
//!
//! Run (one configuration per process, because arena state is global):
//!   cargo run --release --target aarch64-apple-darwin -p coldsnap_hal \
//!       --features test-seam,heap-profile --example heap_lifo
//!
//! Knobs: argv[1] = device count (default 3, threshold = n), `LIFO_LIMIT` = arena
//! bytes the allocator may hand out before it counts an OOM (default 65536),
//! `LIFO_ROUNDS` = signing rounds (default 3), `LIFO_SLOTS` = nonce slots
//! (default 4, as `stub.rs`), `LIFO_GROW` = 1 to enable grow-in-place at the top.
//!
//! # `LIFO_MODE=lll`: the same measurement against `linked_list_allocator` 0.10.6
//!
//! Everything above is unchanged in the default mode -- the bump numbers cited in
//! `hal/src/heap.rs` must stay reproducible, so the bump is still what runs unless
//! `LIFO_MODE=lll` is set. In `lll` mode the backing store is
//! `linked_list_allocator::Heap` (dev-dependency, `default-features = false`, so no
//! `spinning_top`), given `LLL_ARENA` bytes at the base of the same `BACK` static
//! (default `LIFO_LIMIT`, i.e. 64 KiB). Two ways to run it, and both are wanted:
//!
//!   * `LLL_ARENA` = 65536 -- the verdict run. A null from `allocate_first_fit` is a
//!     real OOM at the shipped size, counted in the `nulls` line. (Served from
//!     `System` afterwards so one run reports the whole trajectory; the arena
//!     counters are left untouched for such a block, so `live`/`blocks` stay
//!     consistent.)
//!   * `LLL_ARENA` = 4194304 -- the *footprint* run. First-fit always reuses the
//!     lowest hole, so the high-water offset (`foot`) is exactly how much arena the
//!     workload needs including fragmentation, and it is measurable without the run
//!     ending at the first failure.
//!
//! `foot`/`used`/`live`/`maxfree` are the four numbers that answer the question:
//! `live` is bytes *requested*, `used` is `Heap::used()` = bytes *consumed* (each
//! request floored at `2 * size_of::<usize>()` and rounded up to
//! `align_of::<usize>()`), `foot` is the high-water offset reached, and `maxfree` is
//! the largest single block the arena could still serve at that instant, probed.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::UnsafeCell;
use std::mem::{align_of, size_of};
use std::ptr::NonNull;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed};

use coldsnap_hal::comms::{encode_frame, FRAME_LIMIT};
use coldsnap_hal::rng::{mix_sources, Entropy, ProvenSeed, SE1_BYTES, SE2_BYTES, TRNG_BYTES};
use frostsnap_comms::{DeviceSendBody, DeviceSendMessage, Downstream, ReceiveSerial};
use frostsnap_core::coordinator::{
    BeginKeygen, CoordinatorSend, CoordinatorToUserKeyGenMessage, CoordinatorToUserMessage,
    CoordinatorToUserSigningMessage, FrostCoordinator,
};
use frostsnap_core::device::{
    DeviceSecretDerivation, DeviceToUserMessage, FrostSigner, KeyPurpose,
};
use frostsnap_core::message::signing::DeviceSigning;
use frostsnap_core::message::{CoordinatorToDeviceMessage, DeviceSend, DeviceToCoordinatorMessage};
use frostsnap_core::schnorr_fun::frost::{Fingerprint, ShareIndex};
use frostsnap_core::schnorr_fun::{Schnorr, Signature};
use frostsnap_core::{
    AccessStructureRef, CoordShareDecryptionContrib, DeviceId, SymmetricKey, WireSignTask,
};
use sha2::{Digest, Sha256};

// ---------------------------------------------- the LIFO-rollback bump arena

/// Physical backing. Much larger than any `LIFO_LIMIT` on purpose: an over-limit
/// request is COUNTED and then served anyway, so one run reports the whole
/// trajectory instead of aborting at the first failure and telling us nothing
/// about what came after.
const ARENA_CAP: usize = 4 << 20;

#[repr(C, align(16))]
struct Backing(UnsafeCell<[u8; ARENA_CAP]>);
// SAFETY: this program is single threaded; every access goes through the
// functions below, which are only reached from the global allocator.
unsafe impl Sync for Backing {}
static BACK: Backing = Backing(UnsafeCell::new([0; ARENA_CAP]));

static HEAD: AtomicUsize = AtomicUsize::new(0);
static HIGH: AtomicUsize = AtomicUsize::new(0);
static LIVE: AtomicUsize = AtomicUsize::new(0);
static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static FREES_LIFO: AtomicUsize = AtomicUsize::new(0);
static FREES_STUCK: AtomicUsize = AtomicUsize::new(0);
static BYTES_STUCK: AtomicUsize = AtomicUsize::new(0);
static GROWS: AtomicUsize = AtomicUsize::new(0);
/// What a NON-bump allocator would actually have to hold: the true simultaneous
/// peak of live device bytes and of live device blocks, over the whole flow.
static LIVE_PEAK: AtomicUsize = AtomicUsize::new(0);
static BLOCKS: AtomicUsize = AtomicUsize::new(0);
static BLOCKS_PEAK: AtomicUsize = AtomicUsize::new(0);
static MAXONE: AtomicUsize = AtomicUsize::new(0);
static LIMIT: AtomicUsize = AtomicUsize::new(usize::MAX);
static GROW_ON: AtomicBool = AtomicBool::new(false);
static OVER: AtomicUsize = AtomicUsize::new(0);
static OVER_PHASE: AtomicUsize = AtomicUsize::new(0);
static OVER_HEAD: AtomicUsize = AtomicUsize::new(0);
static OVER_REQ: AtomicUsize = AtomicUsize::new(0);
static PHASE: AtomicUsize = AtomicUsize::new(0);
static IN_DEV: AtomicBool = AtomicBool::new(false);

fn base() -> usize {
    BACK.0.get() as usize
}

fn in_arena(p: *mut u8) -> bool {
    let b = base();
    (p as usize) >= b && (p as usize) < b + ARENA_CAP
}

fn note_over(want: usize) {
    if OVER.fetch_add(1, Relaxed) == 0 {
        OVER_PHASE.store(PHASE.load(Relaxed), Relaxed);
        // The bump's "how far had it got" is the head; the linked list's is the
        // high-water offset, since it has no head.
        OVER_HEAD.store(
            if MODE_LLL.load(Relaxed) {
                HIGH.load(Relaxed)
            } else {
                HEAD.load(Relaxed)
            },
            Relaxed,
        );
        OVER_REQ.store(want, Relaxed);
    }
}

fn bump_alloc(l: Layout) -> *mut u8 {
    let b = base();
    let start = (b + HEAD.load(Relaxed) + l.align() - 1) & !(l.align() - 1);
    let end = start + l.size() - b;
    if end > LIMIT.load(Relaxed) {
        note_over(l.size());
    }
    if end > ARENA_CAP {
        return std::ptr::null_mut();
    }
    HEAD.store(end, Relaxed);
    HIGH.fetch_max(end, Relaxed);
    LIVE_PEAK.fetch_max(LIVE.fetch_add(l.size(), Relaxed) + l.size(), Relaxed);
    BLOCKS_PEAK.fetch_max(BLOCKS.fetch_add(1, Relaxed) + 1, Relaxed);
    MAXONE.fetch_max(l.size(), Relaxed);
    ALLOCS.fetch_add(1, Relaxed);
    start as *mut u8
}

/// The whole allocator, and the whole doubt: the bump pointer can only retreat
/// when the block being freed IS the top block. Anything else is retained.
fn bump_dealloc(p: *mut u8, l: Layout) {
    let off = p as usize - base();
    if HEAD
        .compare_exchange(off + l.size(), off, Relaxed, Relaxed)
        .is_ok()
    {
        FREES_LIFO.fetch_add(1, Relaxed);
    } else {
        FREES_STUCK.fetch_add(1, Relaxed);
        BYTES_STUCK.fetch_add(l.size(), Relaxed);
    }
    LIVE.fetch_sub(l.size(), Relaxed);
    BLOCKS.fetch_sub(1, Relaxed);
}

// ------------------------------- candidate 2: linked_list_allocator 0.10.6

/// Same routing, same counters, different backing store. Selected by `LIFO_MODE=lll`.
struct Lll(UnsafeCell<linked_list_allocator::Heap>);
// SAFETY: same argument as `Backing` -- single threaded, and every access goes
// through `lll()` below, reached only from the global allocator and from `snap`.
unsafe impl Sync for Lll {}
static LLL: Lll = Lll(UnsafeCell::new(linked_list_allocator::Heap::empty()));

static MODE_LLL: AtomicBool = AtomicBool::new(false);
/// High-water of `Heap::used()`: the sum of *aligned* live block sizes. The gap
/// between this and `LIVE` is the measured per-block overhead.
static USED_PEAK: AtomicUsize = AtomicUsize::new(0);
/// `allocate_first_fit` returning `Err` -- on the device this is
/// `handle_alloc_error` -> panic -> reset, so a nonzero count at 64 KiB is fatal.
static NULLS: AtomicUsize = AtomicUsize::new(0);

#[allow(clippy::mut_from_ref)]
fn lll() -> &'static mut linked_list_allocator::Heap {
    // SAFETY: single threaded, and nothing reached from here allocates.
    unsafe { &mut *LLL.0.get() }
}

/// What the allocator actually consumes for one request: `size` floored at
/// `HoleList::min_size()` = `2 * size_of::<usize>()` and rounded up to
/// `align_of::<Hole>()` = `align_of::<usize>()` (`hole.rs:362-374,428`). There is no
/// per-block header -- the links live in the *free* holes -- so this is the whole of
/// the per-block cost. 16-floor/8-round on this 64-bit host, 8-floor/4-round on the
/// 32-bit device, i.e. the device's rounding waste is half of what is measured here.
fn consumed(l: Layout) -> usize {
    let w = size_of::<usize>();
    (l.size().max(2 * w) + w - 1) & !(w - 1)
}

fn lll_alloc(l: Layout) -> *mut u8 {
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
            NULLS.fetch_add(1, Relaxed);
            note_over(l.size());
            // Served off `System` so one run shows the whole trajectory. The arena
            // counters are deliberately NOT touched, so the later `dealloc` (which
            // routes by pointer range, i.e. to `System`) stays balanced.
            unsafe { System.alloc(l) }
        }
    }
}

fn lll_dealloc(p: *mut u8, l: Layout) {
    // SAFETY: routed by pointer range, so `p` came from `lll_alloc` with this layout.
    unsafe { lll().deallocate(NonNull::new_unchecked(p), l) };
    LIVE.fetch_sub(l.size(), Relaxed);
    BLOCKS.fetch_sub(1, Relaxed);
}

/// The largest single block the arena can still serve, by probing. This is the
/// fragmentation number: `free()` is a *sum* of holes, this is the biggest one.
/// Allocate-then-free restores the list (coalescing is what is being tested), and it
/// is only called from `snap`, never mid-phase.
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

fn pool_alloc(l: Layout) -> *mut u8 {
    if MODE_LLL.load(Relaxed) {
        lll_alloc(l)
    } else {
        bump_alloc(l)
    }
}

fn pool_dealloc(p: *mut u8, l: Layout) {
    if MODE_LLL.load(Relaxed) {
        lll_dealloc(p, l)
    } else {
        bump_dealloc(p, l)
    }
}

struct Route;

// SAFETY: `alloc` picks a pool by the `IN_DEV` flag; `dealloc`/`realloc` pick by
// pointer range, so a block always goes back to the pool it came from. Single
// threaded, so `Relaxed` is sufficient.
unsafe impl GlobalAlloc for Route {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        if IN_DEV.load(Relaxed) {
            pool_alloc(l)
        } else {
            System.alloc(l)
        }
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        if in_arena(p) {
            pool_dealloc(p, l)
        } else {
            System.dealloc(p, l)
        }
    }

    unsafe fn realloc(&self, p: *mut u8, l: Layout, new_size: usize) -> *mut u8 {
        if !in_arena(p) {
            return System.realloc(p, l, new_size);
        }
        if MODE_LLL.load(Relaxed) {
            // Naive grow: the linked list has no top block to extend, and a
            // realloc that lands in a bigger hole is the case under test.
            let np = pool_alloc(Layout::from_size_align_unchecked(new_size, l.align()));
            if !np.is_null() {
                std::ptr::copy_nonoverlapping(p, np, l.size().min(new_size));
                pool_dealloc(p, l);
            }
            return np;
        }
        let off = p as usize - base();
        if GROW_ON.load(Relaxed) && off + l.size() == HEAD.load(Relaxed) {
            let end = off + new_size;
            if end > LIMIT.load(Relaxed) {
                note_over(new_size);
            }
            if end <= ARENA_CAP {
                HEAD.store(end, Relaxed);
                HIGH.fetch_max(end, Relaxed);
                if new_size >= l.size() {
                    LIVE_PEAK.fetch_max(
                        LIVE.fetch_add(new_size - l.size(), Relaxed) + new_size - l.size(),
                        Relaxed,
                    );
                    MAXONE.fetch_max(new_size, Relaxed);
                } else {
                    LIVE.fetch_sub(l.size() - new_size, Relaxed);
                }
                GROWS.fetch_add(1, Relaxed);
                return p;
            }
        }
        let np = bump_alloc(Layout::from_size_align_unchecked(new_size, l.align()));
        if !np.is_null() {
            std::ptr::copy_nonoverlapping(p, np, l.size().min(new_size));
            bump_dealloc(p, l);
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
    "setup", "keygen", "nonces", "sign 1", "sign 2", "sign 3", "sign 4", "sign 5", "sign 6",
    "sign 7", "sign 8", "teardown",
];

fn phase(i: usize) {
    PHASE.store(i.min(PHASES.len() - 1), Relaxed);
}

fn hdr() {
    if MODE_LLL.load(Relaxed) {
        eprintln!(
            "  {:<22} {:>8} {:>8} {:>8} {:>7} {:>7} {:>8} {:>7}",
            "after", "foot", "used", "live", "pad", "blocks", "maxfree", "allocs"
        );
        return;
    }
    eprintln!(
        "  {:<22} {:>8} {:>8} {:>8} {:>8} {:>7} {:>7} {:>7} {:>6}",
        "after", "head", "high", "live", "dead", "allocs", "lifo", "stuck", "grow"
    );
}

/// `(foot, used, live, maxfree)` -- the four numbers the lll mode reports.
fn lll_now() -> (usize, usize, usize, usize) {
    (
        HIGH.load(Relaxed),
        lll().used(),
        LIVE.load(Relaxed),
        largest_fit(),
    )
}

fn snap(tag: &str) {
    let _off = Dev::on(false);
    if MODE_LLL.load(Relaxed) {
        let (foot, used, live, maxfree) = lll_now();
        eprintln!(
            "  {:<22} {:>8} {:>8} {:>8} {:>7} {:>7} {:>8} {:>7}",
            tag,
            foot,
            used,
            live,
            used.saturating_sub(live),
            BLOCKS.load(Relaxed),
            maxfree,
            ALLOCS.load(Relaxed),
        );
        return;
    }
    let head = HEAD.load(Relaxed);
    let live = LIVE.load(Relaxed);
    eprintln!(
        "  {:<22} {:>8} {:>8} {:>8} {:>8} {:>7} {:>7} {:>7} {:>6}",
        tag,
        head,
        HIGH.load(Relaxed),
        live,
        head.saturating_sub(live),
        ALLOCS.load(Relaxed),
        FREES_LIFO.load(Relaxed),
        FREES_STUCK.load(Relaxed),
        GROWS.load(Relaxed),
    );
}

// ---------------------------------------------- device secrets (from heap_profile)

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

// ---------------------------------------------- the driver

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

struct Prof {
    coord: FrostCoordinator,
    devices: BTreeMap<DeviceId, FrostSigner>,
    queue: VecDeque<Msg>,
    rng: Entropy,
    sigs: Vec<Signature>,
    /// The one device whose heap lives in the arena.
    arena_dev: DeviceId,
}

impl Prof {
    fn pump(&mut self) {
        while let Some(m) = self.queue.pop_front() {
            match m {
                Msg::ToDevice { dests, msg } => {
                    for d in dests {
                        if self.devices.contains_key(&d) {
                            self.drive(d, &msg);
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

    fn drive(&mut self, id: DeviceId, msg: &CoordinatorToDeviceMessage) {
        let mine = id == self.arena_dev;
        let mut outbox: Vec<DeviceToCoordinatorMessage> = Vec::new();
        let dev = Dev::on(mine);

        // Clone INSIDE the span: on a real device the inbound message is what
        // bincode just allocated, and it is consumed here.
        let cloned = msg.clone();
        let out = self
            .devices
            .get_mut(&id)
            .expect("checked by caller")
            .recv_coordinator_message(cloned, &mut self.rng);

        let mut work: VecDeque<DeviceSend> = match out {
            Ok(v) => v.into(),
            Err(e) => panic!("recv_coordinator_message({id}): {e}"),
        };

        while let Some(send) = work.pop_front() {
            match send {
                DeviceSend::ToCoordinator(m) => outbox.push(*m),
                DeviceSend::ToUser(m) => match *m {
                    DeviceToUserMessage::CheckKeyGen { phase, .. } => {
                        let r = self.devices.get_mut(&id).expect("still there").keygen_ack(
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
                            .devices
                            .get_mut(&id)
                            .expect("still there")
                            .sign_ack(*phase, &mut Secrets);
                        work.extend(r.expect("sign_ack"));
                    }
                    _ => {}
                },
            }
        }

        // Firmware's flash write: draining and dropping is what "persisted" means.
        self.devices
            .get_mut(&id)
            .expect("still there")
            .staged_mutations()
            .drain(..)
            .count();

        // Outbound: encapsulate + encode into the fixed frame buffer, which is a
        // real second copy of the body on the device's own heap.
        for m in &outbox {
            let mut buf = [0u8; FRAME_LIMIT];
            let frame = ReceiveSerial::<Downstream>::Message(DeviceSendMessage {
                from: id,
                body: DeviceSendBody::Core(m.clone()).into(),
            });
            let len = encode_frame(&frame, &mut buf);
            drop(frame);
            len.expect("device frame must fit FRAME_LIMIT");
        }

        // Hand the messages to the harness as SYSTEM copies, then free the arena
        // originals -- otherwise the queue's dwell time reads as device retention.
        drop(dev);
        let copies: Vec<DeviceToCoordinatorMessage> = outbox.iter().cloned().collect();
        {
            let _on = Dev::on(mine);
            drop(outbox);
        }
        for m in copies {
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
    let n = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(3usize);
    let limit = knob("LIFO_LIMIT", 64 * 1024);
    let rounds = knob("LIFO_ROUNDS", 3);
    let slots = knob("LIFO_SLOTS", 4);
    let grow = knob("LIFO_GROW", 0) != 0;
    LIMIT.store(limit, Relaxed);
    GROW_ON.store(grow, Relaxed);
    let lll_mode = std::env::var("LIFO_MODE").as_deref() == Ok("lll");
    MODE_LLL.store(lll_mode, Relaxed);
    let arena = knob("LLL_ARENA", limit);

    if lll_mode {
        assert!(arena <= ARENA_CAP, "LLL_ARENA must fit the backing store");
        // SAFETY: `BACK` is a live `static` of `ARENA_CAP` bytes, aligned 16, and
        // nothing else hands out any part of it in this mode.
        unsafe { lll().init(base() as *mut u8, arena) };
        eprintln!(
            "=== linked_list_allocator 0.10.6: n={n} t={n} arena={arena} B \
             limit={limit} B rounds={rounds} slots={slots} ==="
        );
        eprintln!(
            "  min block {} B, round to {} B (host, 64-bit; device is {} B / {} B)",
            2 * size_of::<usize>(),
            align_of::<usize>(),
            8,
            4
        );
    } else {
        eprintln!(
            "=== LIFO-rollback bump: n={n} t={n} limit={limit} B rounds={rounds} \
             slots={slots} grow_in_place={grow} ==="
        );
    }
    eprintln!("  arena holds ONE device's heap (device 0); coordinator and the other {} signer(s) are on System.", n - 1);
    hdr();

    let mut rng = entropy(0x5a);
    let mut coord = FrostCoordinator::new();
    coord.keygen_fingerprint = TEST_FINGERPRINT;

    phase(0);
    // Device 0 is built INSIDE the arena, so its long-lived state is arena state.
    let mut devices: BTreeMap<DeviceId, FrostSigner> = BTreeMap::new();
    let arena_dev = {
        let mut s = {
            let _on = Dev::on(true);
            FrostSigner::new_random(&mut rng, slots)
        };
        s.keygen_fingerprint = TEST_FINGERPRINT;
        let id = s.device_id();
        devices.insert(id, s);
        id
    };
    snap("fresh signer");
    for _ in 1..n {
        let mut s = FrostSigner::new_random(&mut rng, slots);
        s.keygen_fingerprint = TEST_FINGERPRINT;
        devices.insert(s.device_id(), s);
    }
    let ids: Vec<DeviceId> = devices.keys().copied().collect();
    let id_set: BTreeSet<DeviceId> = devices.keys().copied().collect();

    let mut p = Prof {
        coord,
        devices,
        queue: VecDeque::new(),
        rng,
        sigs: Vec::new(),
        arena_dev,
    };

    // --- keygen
    phase(1);
    let begin = BeginKeygen::new(
        ids.clone(),
        n as u16,
        "lifo probe".to_string(),
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

    // --- signing rounds. A leak shows up as growth PER ROUND, which is why this
    // loop is the point of the whole example.
    let key_data = p.coord.iter_keys().next().expect("a key exists").clone();
    let as_ref = key_data
        .access_structures()
        .next()
        .expect("an access structure")
        .access_structure_ref();
    let master_appkey = key_data.complete_key.master_appkey;
    let schnorr = Schnorr::<Sha256>::verify_only();
    let mut per_round: Vec<(usize, usize)> = Vec::new();
    let mut per_round_lll: Vec<(usize, usize, usize, usize)> = Vec::new();
    for round in 0..rounds {
        phase(3 + round);
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
            message: format!("cold-snap lifo probe round {round}"),
        };
        let checked = task
            .clone()
            .check(master_appkey, KeyPurpose::Test)
            .expect("task checks");
        let session = p
            .coord
            .start_sign(as_ref, task, &id_set, &mut entropy(0x99))
            .expect("start_sign");
        for d in &ids {
            let rds = p.coord.request_device_sign(session, *d, TEST_KEY);
            p.queue.push_back(to_msg(CoordinatorSend::from(rds)));
        }
        p.sigs.clear();
        p.pump();
        // The runnable check: a signature this process produced but did not bless.
        assert!(
            checked.verify_final_signatures(&schnorr, &p.sigs),
            "round={round}: aggregated signature must verify, else the workload was not real"
        );
        snap(&format!("sign round {}", round + 1));
        if lll_mode {
            per_round_lll.push(lll_now());
        } else {
            per_round.push((HEAD.load(Relaxed), LIVE.load(Relaxed)));
        }
    }

    // --- what firmware can reclaim, and what the bump can give back at all
    phase(PHASES.len() - 1);
    {
        let _on = Dev::on(true);
        p.devices
            .get_mut(&arena_dev)
            .expect("device 0")
            .clear_unfinished_keygens();
    }
    snap("clear_unfinished_keygens");
    {
        let _on = Dev::on(true);
        drop(p.devices.remove(&arena_dev));
    }
    snap("drop the signer");

    let head = HEAD.load(Relaxed);
    let high = HIGH.load(Relaxed);
    let lifo = FREES_LIFO.load(Relaxed);
    let stuck = FREES_STUCK.load(Relaxed);
    eprintln!();
    eprintln!("  arena high-water     : {high} B  (limit {limit} B)");
    if lll_mode {
        let (_, used, live, maxfree) = lll_now();
        eprintln!(
            "  after dropping the signer: used {used} B, live {live} B, largest \
             single free block {maxfree} B of a {arena} B arena  <- coalescing check"
        );
        eprintln!(
            "  per signing round     : {per_round_lll:?}  (foot, used, live, maxfree)"
        );
        eprintln!(
            "  peak consumed (used)  : {} B vs peak requested (live) {} B  -> \
             per-block rounding overhead {} B",
            USED_PEAK.load(Relaxed),
            LIVE_PEAK.load(Relaxed),
            USED_PEAK
                .load(Relaxed)
                .saturating_sub(LIVE_PEAK.load(Relaxed)),
        );
        eprintln!(
            "  nulls from allocate_first_fit: {}  (each one is \
             handle_alloc_error -> panic -> reset on device)",
            NULLS.load(Relaxed)
        );
    } else {
        eprintln!(
            "  head after everything: {head} B  <- what the bump can NEVER give back \
             while the process lives"
        );
        eprintln!(
            "  LIFO hit rate        : {lifo}/{} = {:.1}%   stuck bytes (sum of \
             non-LIFO frees): {} B",
            lifo + stuck,
            100.0 * lifo as f64 / (lifo + stuck).max(1) as f64,
            BYTES_STUCK.load(Relaxed)
        );
        eprintln!("  head growth per signing round: {per_round:?}  (head, live)");
    }
    // What an allocator that can actually reuse a hole would have to hold. This is
    // a true simultaneous peak over the whole flow, not a sum of two maxima.
    eprintln!(
        "  LIVE-BYTES peak      : {} B in at most {} simultaneous blocks; largest \
         single block {} B",
        LIVE_PEAK.load(Relaxed),
        BLOCKS_PEAK.load(Relaxed),
        MAXONE.load(Relaxed),
    );
    let over = OVER.load(Relaxed);
    if over == 0 {
        eprintln!("  OOM: none. {high} B high-water fits under {limit} B.");
    } else {
        eprintln!(
            "  OOM: {over} allocation(s) exceeded {limit} B. FIRST at phase \
             `{}`, head {} B, requesting {} B. (Served anyway so the run \
             continues; on device this is `handle_alloc_error` -> panic -> reset.)",
            PHASES[OVER_PHASE.load(Relaxed)],
            OVER_HEAD.load(Relaxed),
            OVER_REQ.load(Relaxed),
        );
    }
}

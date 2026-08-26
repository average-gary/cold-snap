//! Heap profiler for the real device workload: keygen -> nonce replenishment ->
//! signing, driven through the vendored `frostsnap_core` state machines.
//!
//! Answers one question: how much heap does ONE Mk4 need, and does every
//! allocation die inside the frame that made it (so a bump-reset arena is
//! enough) or do some live across frames (so it is not)?
//!
//! HOW PER-DEVICE ATTRIBUTION WORKS, because this is the only part that can make
//! the number wrong. A process-wide peak here would be ~N x a real device --
//! `stub.rs` runs nine signers in one process and its peak means nothing for one
//! Mk4. So nothing is read off the process peak. Instead:
//!
//!   * TRANSIENT is measured in WINDOWS around single device calls
//!     (`recv_coordinator_message`, `keygen_ack`, `NonceJobs::run_until_finished`,
//!     `sign_ack`, `staged_mutations().drain`, and the outbound encode). The loop
//!     is single threaded, so during a window nothing else in the process
//!     allocates: the window number IS one device's heap at the real group size.
//!     No division by N, no slope.
//!   * LIVE is measured DESTRUCTIVELY at the end: pop one `FrostSigner` out of
//!     the map and watch `CUR` fall. That delta is exactly what that one signer
//!     held. The coordinator is dropped the same way, so the gap between "device
//!     heap" and "process heap" is printed rather than assumed.
//!
//! The device count is still swept because a device's OWN state could grow with
//! the group size (share images, party indices, agg nonces from every signer),
//! which would be a real effect and not an artifact of co-hosting. MEASURED: live
//! state does not move with n at all, transient does (roughly doubling from n=1
//! to n=9). The sweep is what establishes that, so it stays.
//!
//! CAVEATS, and they mostly push one way:
//!   * Host is 64-bit (`aarch64-apple-darwin`), device is 32-bit thumbv7em.
//!     Payload arrays (`[u8; 32]`, scalars, points) are identical, but every
//!     pointer, `usize` length and capacity halves, and a `BTreeMap`/`BTreeSet`
//!     node is mostly pointers: `alloc::collections::btree` uses B=6, i.e. 11
//!     K/V slots + 12 child pointers + 2 u16 per internal node. So for small
//!     keys the ARM node is roughly 40-50% smaller, and for a 33-byte `DeviceId`
//!     key roughly 20% smaller. THE ARM NUMBER IS LOWER THAN WHAT IS PRINTED.
//!     Treat the host figure as an upper bound, not as a target to shave.
//!   * `realloc` is deliberately NOT overridden, so `Vec` growth shows up as
//!     alloc-new + copy + free-old with both live at once. That is exactly what a
//!     bump arena does; the system allocator's in-place grow would flatter the
//!     peak and hide the very cost we are sizing for.
//!   * AUTO-ACK collapses a human. On a real device the keygen/sign `phase` sits
//!     in RAM while a person reads the screen -- live ACROSS frames. That is why
//!     each window's `held` (net retained) is printed next to its `peak`: the
//!     `recv:` rows' `held` IS the awaiting-user state.
//!   * `panic = "abort"` on device means an allocation failure is a reset, so the
//!     figure that matters is the worst case, not the average. Only maxima are
//!     reported per class.
//!
//! Run (release; `heap-profile` is what pulls in the real `FrostCoordinator`):
//!   cargo run --release --target aarch64-apple-darwin -p coldsnap_hal \
//!       --features test-seam,heap-profile --example heap_profile
//!
//! Knobs, all optional: argv[1] = comma-separated device counts (default
//! `1,2,3,5,9`), `HEAP_SLOTS` = nonce slots per signer (default 4, as `stub.rs`),
//! `HEAP_SIGNS` = signing sessions (default 1), `HEAP_STAGE` = 1 keygen only /
//! 2 + nonces / 3 + signing (default 3), `HEAP_VERBOSE` = print outbound frame
//! sizes next to their encode windows.

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

use coldsnap_hal::comms::{encode_frame, Link, FRAME_LIMIT};
use coldsnap_hal::rng::{mix_sources, Entropy, ProvenSeed, SE1_BYTES, SE2_BYTES, TRNG_BYTES};
use frostsnap_comms::{
    CoordinatorSendBody, CoordinatorSendMessage, Destination, DeviceSendBody, DeviceSendMessage,
    Downstream, MagicBytes, ReceiveSerial, Upstream, WireCoordinatorSendBody, BINCODE_CONFIG,
};
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

// ------------------------------------------------------------ the allocator

static CUR: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static COUNT: AtomicUsize = AtomicUsize::new(0);
static MAXONE: AtomicUsize = AtomicUsize::new(0);
static TOTAL: AtomicUsize = AtomicUsize::new(0);
/// Window-local mirrors of the four above; reset by `win_open`.
static WPEAK: AtomicUsize = AtomicUsize::new(0);
static WCOUNT: AtomicUsize = AtomicUsize::new(0);
static WMAXONE: AtomicUsize = AtomicUsize::new(0);
static WTOTAL: AtomicUsize = AtomicUsize::new(0);

struct Track;

// SAFETY: every method forwards to `System` unchanged and the atomics touch no
// allocator state. `Relaxed` is enough because this program is single threaded
// and the counters are only read at quiescent points between device calls.
unsafe impl GlobalAlloc for Track {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = System.alloc(l);
        if !p.is_null() {
            let n = l.size();
            let c = CUR.fetch_add(n, Relaxed) + n;
            PEAK.fetch_max(c, Relaxed);
            WPEAK.fetch_max(c, Relaxed);
            COUNT.fetch_add(1, Relaxed);
            WCOUNT.fetch_add(1, Relaxed);
            MAXONE.fetch_max(n, Relaxed);
            WMAXONE.fetch_max(n, Relaxed);
            TOTAL.fetch_add(n, Relaxed);
            WTOTAL.fetch_add(n, Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        CUR.fetch_sub(l.size(), Relaxed);
        System.dealloc(p, l);
    }
}

#[global_allocator]
static ALLOC: Track = Track;

#[derive(Clone, Copy)]
struct Win {
    base: usize,
}

/// Open a window. Everything allocated until `win_close` is attributed to what
/// happens in between -- which must be ONE device call and nothing else, or the
/// number is a lie. In particular: no `eprintln!`, no `format!`, no queue pushes.
fn win_open() -> Win {
    let base = CUR.load(Relaxed);
    WPEAK.store(base, Relaxed);
    WCOUNT.store(0, Relaxed);
    WMAXONE.store(0, Relaxed);
    WTOTAL.store(0, Relaxed);
    Win { base }
}

#[derive(Clone, Copy, Default)]
struct Sample {
    /// High-water mark above the window's starting `CUR`: simultaneous bytes.
    peak: usize,
    /// Net bytes still allocated when the window closed. Positive = held on to.
    held: isize,
    allocs: usize,
    max_single: usize,
    churn: usize,
}

fn win_close(w: Win) -> Sample {
    let cur = CUR.load(Relaxed);
    Sample {
        peak: WPEAK.load(Relaxed).saturating_sub(w.base),
        held: cur as isize - w.base as isize,
        allocs: WCOUNT.load(Relaxed),
        max_single: WMAXONE.load(Relaxed),
        churn: WTOTAL.load(Relaxed),
    }
}

/// Worst window of a class, plus the sum of what those windows held on to.
struct Class {
    label: String,
    n: usize,
    worst: Sample,
    held_sum: isize,
}

fn note(classes: &mut Vec<Class>, label: String, s: Sample) {
    let c = match classes.iter_mut().find(|c| c.label == label) {
        Some(c) => c,
        None => {
            classes.push(Class {
                label,
                n: 0,
                worst: Sample::default(),
                held_sum: 0,
            });
            classes.last_mut().expect("just pushed")
        }
    };
    c.n += 1;
    c.held_sum += s.held;
    if s.peak > c.worst.peak {
        c.worst = s;
    }
}

/// First identifier of a `Debug` rendering: `Signing(RequestSign(..))` -> "Signing".
fn kind<T: std::fmt::Debug>(v: &T) -> String {
    let s = format!("{v:?}");
    let head: String = s
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    if head.is_empty() {
        "anon".to_string()
    } else {
        head
    }
}

// ------------------------------------------------------------ device secrets

/// The tier-2 test fingerprint, as `stub.rs` and `hostcheck` use. It selects
/// WHICH coefficients get chosen, never how much heap anything takes;
/// `Fingerprint::FROST_V0` would add a coordinator-side grind and not one byte.
const TEST_FINGERPRINT: Fingerprint = Fingerprint {
    bits_per_coeff: 2,
    max_bits_total: 6,
    tag: "test",
};

const TEST_KEY: SymmetricKey = SymmetricKey([42u8; 32]);

/// Copied from `stub.rs`: a `ProvenSeed` through the REAL mixer from fixed
/// bytes, so a bad run replays exactly.
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

/// Same shape as `stub.rs`'s `StubSecrets`. A REAL DEVICE MUST NOT return a
/// constant share encryption key -- irrelevant to heap, load-bearing elsewhere.
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

struct Prof {
    coord: FrostCoordinator,
    devices: BTreeMap<DeviceId, FrostSigner>,
    queue: VecDeque<Msg>,
    rng: Entropy,
    classes: Vec<Class>,
    /// Real coordinator->device frames, exactly as they would arrive on the wire.
    frames: Vec<(String, Vec<u8>)>,
    sigs: Vec<Signature>,
    verbose: bool,
}

impl Prof {
    fn pump(&mut self) {
        while let Some(m) = self.queue.pop_front() {
            match m {
                Msg::ToDevice { dests, msg } => {
                    self.capture(&dests, &msg);
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

    /// One inbound frame for one device, driven to quiescence -- the same shape as
    /// `stub.rs`'s `drive`, but every device call is individually windowed.
    fn drive(&mut self, id: DeviceId, msg: &CoordinatorToDeviceMessage) {
        let label = kind(msg);
        let mut outbox: Vec<DeviceToCoordinatorMessage> = Vec::new();

        // The `clone` is INSIDE the window on purpose: on a real device the
        // inbound message is allocated by the bincode decode and then consumed
        // here, so decode+process is the honest per-frame unit. The pure decode
        // cost is also measured separately, on real frames, further down.
        let w = win_open();
        let cloned = msg.clone();
        let out = self
            .devices
            .get_mut(&id)
            .expect("checked by caller")
            .recv_coordinator_message(cloned, &mut self.rng);
        let s = win_close(w);
        note(&mut self.classes, format!("recv:{label}"), s);

        let mut work: VecDeque<DeviceSend> = match out {
            Ok(v) => v.into(),
            Err(e) => panic!("recv_coordinator_message({id}): {e}"),
        };

        while let Some(send) = work.pop_front() {
            match send {
                DeviceSend::ToCoordinator(m) => outbox.push(*m),
                DeviceSend::ToUser(m) => match *m {
                    // AUTO-ACK. A REAL DEVICE MUST NOT: this is a human comparing
                    // a session hash. Heap-wise it means the `phase` above was
                    // held for microseconds instead of seconds.
                    DeviceToUserMessage::CheckKeyGen { phase, .. } => {
                        let w = win_open();
                        let r = self.devices.get_mut(&id).expect("still there").keygen_ack(
                            *phase,
                            &mut Secrets,
                            &mut self.rng,
                        );
                        let s = win_close(w);
                        note(&mut self.classes, "keygen_ack".to_string(), s);
                        work.extend(r.expect("keygen_ack"));
                    }
                    DeviceToUserMessage::NonceJobs(mut batch) => {
                        // The device's nonce PRF work: NONCE_BATCH_SIZE derivations
                        // and their EC points. Firmware would spread this over idle
                        // time, which does not change the heap it needs.
                        let w = win_open();
                        batch.run_until_finished(&mut Secrets);
                        let segments = batch.into_segments();
                        let s = win_close(w);
                        note(&mut self.classes, "nonce_jobs".to_string(), s);
                        for segment in segments {
                            outbox.push(DeviceToCoordinatorMessage::Signing(
                                DeviceSigning::NonceResponse {
                                    segments: vec![segment],
                                },
                            ));
                        }
                    }
                    // AUTO-ACK AGAIN, and worse: this is the screen where a human
                    // reads the transaction. A REAL DEVICE MUST NOT.
                    DeviceToUserMessage::SignatureRequest { phase } => {
                        let w = win_open();
                        let r = self
                            .devices
                            .get_mut(&id)
                            .expect("still there")
                            .sign_ack(*phase, &mut Secrets);
                        let s = win_close(w);
                        note(&mut self.classes, "sign_ack".to_string(), s);
                        work.extend(r.expect("sign_ack"));
                    }
                    _ => {}
                },
            }
        }

        // Firmware's flash write. Draining and dropping is what "persisted" means
        // here; NOT draining would let staged mutations grow without bound and
        // make the live figure a fiction.
        let w = win_open();
        let n_mut = self
            .devices
            .get_mut(&id)
            .expect("still there")
            .staged_mutations()
            .drain(..)
            .count();
        let s = win_close(w);
        if n_mut > 0 {
            note(&mut self.classes, "drain_mutations".to_string(), s);
        }

        // Outbound: encapsulate + encode into the fixed frame buffer. The
        // encapsulation is a real device-side allocation (`EncapsBody(Vec<u8>)`
        // is a whole second copy of the body) and it is on the critical path for
        // the 2 KB `NonceResponse`.
        for m in outbox {
            let mlabel = kind(&m);
            let mut out = [0u8; FRAME_LIMIT];
            let w = win_open();
            let frame = ReceiveSerial::<Downstream>::Message(DeviceSendMessage {
                from: id,
                body: DeviceSendBody::Core(m.clone()).into(),
            });
            let len = encode_frame(&frame, &mut out);
            drop(frame);
            let s = win_close(w);
            note(&mut self.classes, format!("encode:{mlabel}"), s);
            let len = len.expect("device frame must fit FRAME_LIMIT");
            if self.verbose {
                eprintln!("    encode:{mlabel} -> {len} B on the wire");
            }
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

    /// Store the frame the coordinator would actually put on the wire, so decode
    /// cost is measured on real bytes rather than on a hand-built approximation.
    fn capture(&mut self, dests: &BTreeSet<DeviceId>, msg: &CoordinatorToDeviceMessage) {
        let label = kind(msg);
        let frame = ReceiveSerial::<Upstream>::Message(CoordinatorSendMessage {
            target_destinations: Destination::Particular(dests.clone()),
            message_body: WireCoordinatorSendBody::from(CoordinatorSendBody::Core(msg.clone())),
        });
        let mut out = [0u8; FRAME_LIMIT];
        match encode_frame(&frame, &mut out) {
            Ok(n) => self.frames.push((label, out[..n].to_vec())),
            // A coordinator frame over FRAME_LIMIT is a real finding, not a
            // measurement problem: this device could never receive it.
            Err(e) => eprintln!("  !! coordinator frame {label} does not fit: {e:?}"),
        }
    }
}

// ------------------------------------------------------------ decode cost

fn linked_link() -> Link {
    let magic = bincode::encode_to_vec(
        ReceiveSerial::<Upstream>::MagicBytes(MagicBytes::default()),
        BINCODE_CONFIG,
    )
    .expect("magic encodes");
    let mut link = Link::new();
    link.poll::<ReceiveSerial<Upstream>, _>(&magic, |_| {})
        .expect("handshake");
    assert!(link.is_linked(), "magic bytes must link");
    link
}

/// `(outer frame only, outer + the EncapsBody inner decode)`. The second is what
/// a device really pays, because `message_body.decode()` is how the core message
/// comes out of the encapsulation.
fn decode_cost(frame: &[u8]) -> (Sample, Sample) {
    let mut a = linked_link();
    let w = win_open();
    a.poll::<ReceiveSerial<Upstream>, _>(frame, |f| drop(f))
        .expect("decode");
    let outer = win_close(w);

    let mut b = linked_link();
    let w = win_open();
    b.poll::<ReceiveSerial<Upstream>, _>(frame, |f| {
        if let ReceiveSerial::Message(m) = f {
            let body = m.message_body.decode();
            drop(body);
        }
    })
    .expect("decode");
    let full = win_close(w);
    (outer, full)
}

/// The biggest frame `FRAME_LIMIT` permits, built by padding the one field an
/// attacker fully controls for free: `Destination::Particular(BTreeSet<DeviceId>)`.
/// Grown one `DeviceId` at a time until `encode_frame` refuses, then backed off,
/// so the result is the true largest decodable frame rather than a guess.
fn max_frame(core: &CoordinatorToDeviceMessage, seed: &BTreeSet<DeviceId>) -> Vec<u8> {
    let mut rng = entropy(0x11);
    let mut dests = seed.clone();
    let mut best = Vec::new();
    loop {
        let frame = ReceiveSerial::<Upstream>::Message(CoordinatorSendMessage {
            target_destinations: Destination::Particular(dests.clone()),
            message_body: WireCoordinatorSendBody::from(CoordinatorSendBody::Core(core.clone())),
        });
        let mut out = [0u8; FRAME_LIMIT];
        match encode_frame(&frame, &mut out) {
            Ok(n) => best = out[..n].to_vec(),
            Err(_) => return best,
        }
        dests.insert(FrostSigner::new_random(&mut rng, 1).device_id());
    }
}

// ------------------------------------------------------------ one sweep point

struct RunOut {
    frames: Vec<(String, Vec<u8>)>,
    ids: BTreeSet<DeviceId>,
}

/// Env knobs, so the composition of the live figure is measurable instead of
/// assumed: `HEAP_SLOTS` = nonce slots per signer (4 = `stub.rs`), `HEAP_SIGNS` =
/// how many signing sessions to run (the growth-per-session question).
fn knob(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn run(n: usize, verbose: bool) -> RunOut {
    let base = CUR.load(Relaxed);
    PEAK.store(base, Relaxed);
    COUNT.store(0, Relaxed);
    MAXONE.store(0, Relaxed);
    TOTAL.store(0, Relaxed);

    let threshold = n as u16; // t = n maximises per-device signing work
    let slots = knob("HEAP_SLOTS", 4);
    let signs = knob("HEAP_SIGNS", 1);
    // 1 = stop after keygen, 2 = + nonce replenishment, 3 = + signing. Only for
    // splitting the live figure by phase; 3 is the whole workload.
    let stage = knob("HEAP_STAGE", 3);
    let mut rng = entropy(0x5a);
    let mut coord = FrostCoordinator::new();
    coord.keygen_fingerprint = TEST_FINGERPRINT;
    let devices: BTreeMap<DeviceId, FrostSigner> = (0..n)
        .map(|_| {
            // 4 nonce slots, matching `stub.rs`; the batch size is the shipped
            // default, which is what makes a `NonceResponse` 2,040 B.
            let mut s = FrostSigner::new_random(&mut rng, slots);
            s.keygen_fingerprint = TEST_FINGERPRINT;
            (s.device_id(), s)
        })
        .collect();
    let ids: Vec<DeviceId> = devices.keys().copied().collect();
    let id_set: BTreeSet<DeviceId> = devices.keys().copied().collect();

    // Where the end-state live figure COMES FROM: a signer that has never seen a
    // keygen. If this equals the post-signing per-device live below, then keygen
    // adds nothing durable to RAM -- the share left via `staged_mutations` (i.e.
    // to flash) and the signer's own heap is fixed-size. That is a different
    // design conclusion from "the share lives in the heap", so it is measured
    // rather than argued.
    let fresh_live = {
        let before = CUR.load(Relaxed);
        let s = FrostSigner::new_random(&mut rng, slots);
        let mid = CUR.load(Relaxed);
        drop(s);
        mid - before
    };

    let mut p = Prof {
        coord,
        devices,
        queue: VecDeque::new(),
        rng,
        classes: Vec::new(),
        frames: Vec::new(),
        sigs: Vec::new(),
        verbose,
    };

    // --- keygen
    let begin = BeginKeygen::new(
        ids.clone(),
        threshold,
        "heap profile".to_string(),
        KeyPurpose::Test,
        &mut p.rng,
    );
    let sends = p
        .coord
        .begin_keygen(begin, &mut entropy(0x77))
        .expect("begin_keygen");
    p.queue.extend(sends.into_iter().map(to_msg));
    p.pump();
    let live_keygen = CUR.load(Relaxed) as isize - base as isize;

    // --- nonce replenishment (one stream, as the real coordinator asks for)
    if stage >= 2 {
        let req = p
            .coord
            .maybe_request_nonce_replenishment(&id_set, 1, &mut entropy(0x88));
        p.queue.extend(req.into_iter().map(to_msg));
        p.pump();
    }
    let live_nonces = CUR.load(Relaxed) as isize - base as isize;

    // --- signing
    let mut live_signed = 0isize;
    let mut live_per_round: Vec<isize> = Vec::new();
    if stage >= 3 {
        let key_data = p.coord.iter_keys().next().expect("a key exists").clone();
        let as_ref = key_data
            .access_structures()
            .next()
            .expect("an access structure")
            .access_structure_ref();
        let master_appkey = key_data.complete_key.master_appkey;
        // GROWTH PER SESSION is the arena question restated: if live state climbs with
        // every signature the device ever makes, no fixed arena can be sized. Each
        // round signs a DIFFERENT message, as it must -- reusing a nonce across two
        // messages leaks the share.
        let schnorr = Schnorr::<Sha256>::verify_only();
        for round in 0..signs {
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
                message: format!("cold-snap heap profile round {round}"),
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
            // The one runnable check: a signature this process produced but did NOT
            // bless -- verified against the group key with `schnorr_fun`.
            assert!(
                checked.verify_final_signatures(&schnorr, &p.sigs),
                "n={n} round={round}: aggregated signature must verify, else the \
             workload was not real"
            );
            live_signed = CUR.load(Relaxed) as isize - base as isize;
            live_per_round.push(live_signed);
        }
    }

    let proc_peak = PEAK.load(Relaxed) as isize - base as isize;
    eprintln!("\n=== n={n} t={threshold} ===========================================");
    eprintln!(
        "  PROCESS peak {proc_peak} B  (NOT a device: {n} signer(s) + coordinator \
         + queue + captured frames)"
    );
    eprintln!(
        "  process allocs {}  churn {} B  largest single {} B",
        COUNT.load(Relaxed),
        TOTAL.load(Relaxed),
        MAXONE.load(Relaxed)
    );
    eprintln!("  live in process: after keygen {live_keygen} B, after nonces {live_nonces} B, after signing {live_signed} B");
    if signs > 1 {
        eprintln!("  live in process per signing round: {live_per_round:?}");
    }

    eprintln!("  per-device windows (worst of each class):");
    eprintln!(
        "    {:<26} {:>4} {:>10} {:>10} {:>8} {:>10} {:>10}",
        "class", "n", "peak B", "held B", "allocs", "maxone B", "churn B"
    );
    p.classes.sort_by_key(|c| std::cmp::Reverse(c.worst.peak));
    let mut worst_transient = 0usize;
    let mut worst_label = String::new();
    for c in &p.classes {
        if c.worst.peak > worst_transient {
            worst_transient = c.worst.peak;
            worst_label = c.label.clone();
        }
        eprintln!(
            "    {:<26} {:>4} {:>10} {:>10} {:>8} {:>10} {:>10}",
            c.label,
            c.n,
            c.worst.peak,
            c.worst.held,
            c.worst.allocs,
            c.worst.max_single,
            c.worst.churn
        );
    }
    let held_total: isize = p.classes.iter().map(|c| c.held_sum).sum();
    eprintln!(
        "  sum of all window `held` = {held_total} B  (per-device retention as \
         seen from inside the calls, includes outputs the harness still owns)"
    );

    // --- destructive per-device live measurement
    let Prof {
        coord,
        mut devices,
        classes,
        frames,
        queue,
        sigs,
        ..
    } = p;
    drop(classes);
    drop(queue);
    drop(sigs);
    // How much of a device's live heap is state it could simply throw away?
    // `clear_tmp_data` is the vendored crate's own answer to that question, and
    // firmware that never calls it pays the difference for the whole session.
    let tmp_freed = {
        let id = ids[0];
        let before = CUR.load(Relaxed);
        devices.get_mut(&id).expect("device 0").clear_tmp_data();
        before - CUR.load(Relaxed)
    };
    let mut per_device = Vec::new();
    for id in &ids {
        let before = CUR.load(Relaxed);
        drop(devices.remove(id));
        per_device.push(before - CUR.load(Relaxed));
    }
    let before = CUR.load(Relaxed);
    drop(coord);
    let coord_live = before - CUR.load(Relaxed);
    // Device 0 is the one `clear_tmp_data` was called on, so its drop delta is the
    // DURABLE live figure and every other device's is the as-shipped one. Stated
    // this way so n=1 and n=9 report the same two numbers rather than whichever
    // one happened to sort last.
    let durable = per_device[0];
    let as_left = durable + tmp_freed;
    per_device.sort_unstable();
    eprintln!("  fresh signer live, before any keygen: {fresh_live} B  (slots={slots}, signing rounds={signs})");
    eprintln!(
        "  LIVE-ACROSS-FRAMES per device (destructive drop): {as_left} B as the \
         vendored code leaves it, {durable} B durable (after clear_tmp_data). \
         Raw drop deltas: {per_device:?}"
    );
    eprintln!("  coordinator live (NOT on the device): {coord_live} B");
    eprintln!("  of one device's live heap, clear_tmp_data() frees: {tmp_freed} B");
    eprintln!(
        "  => ONE DEVICE at n={n}: peak {} B (live {as_left} + worst transient \
         {worst_transient} in {worst_label}), or {} B if firmware calls \
         clear_tmp_data",
        as_left + worst_transient,
        durable + worst_transient
    );

    RunOut {
        frames,
        ids: id_set,
    }
}

fn main() {
    let sweep: Vec<usize> = std::env::args()
        .nth(1)
        .map(|s| {
            s.split(',')
                .filter_map(|v| v.parse().ok())
                .filter(|&v| v > 0)
                .collect()
        })
        .unwrap_or_else(|| vec![1, 2, 3, 5, 9]);
    let verbose = std::env::var("HEAP_VERBOSE").is_ok();

    let mut last: Option<RunOut> = None;
    for &n in &sweep {
        // Only the final run's frames are kept: leftovers from an earlier run
        // would sit in `CUR` and inflate the next run's process peak.
        drop(last.take());
        last = Some(run(n, verbose));
    }
    let RunOut { mut frames, ids } = last.expect("sweep was non-empty");

    eprintln!("\n=== INBOUND FRAME DECODE (what an attacker's bytes cost) ===========");
    eprintln!(
        "  {:<24} {:>7} {:>10} {:>10} {:>10} {:>8}",
        "frame", "wire B", "outer B", "full B", "held B", "allocs"
    );
    // Biggest real frame of each kind, plus the FRAME_LIMIT worst case.
    frames.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.len().cmp(&a.1.len())));
    frames.dedup_by(|a, b| a.0 == b.0);
    let biggest_core = frames
        .iter()
        .max_by_key(|f| f.1.len())
        .map(|f| f.1.clone())
        .expect("some frames were captured");
    for (label, bytes) in &frames {
        let (outer, full) = decode_cost(bytes);
        eprintln!(
            "  {:<24} {:>7} {:>10} {:>10} {:>10} {:>8}",
            label,
            bytes.len(),
            outer.peak,
            full.peak,
            full.held,
            full.allocs
        );
    }
    // Rebuild a max-size frame from the largest captured body.
    let (decoded, _): (ReceiveSerial<Upstream>, usize) =
        bincode::decode_from_slice(&biggest_core, BINCODE_CONFIG).expect("re-decode");
    if let ReceiveSerial::Message(m) = decoded {
        if let Some(CoordinatorSendBody::Core(core)) = m.message_body.decode() {
            let big = max_frame(&core, &ids);
            let (outer, full) = decode_cost(&big);
            eprintln!(
                "  {:<24} {:>7} {:>10} {:>10} {:>10} {:>8}",
                "MAX (padded dests)",
                big.len(),
                outer.peak,
                full.peak,
                full.held,
                full.allocs
            );
            assert_eq!(full.held, 0, "a decoded frame must not leak");
        }
    }
    eprintln!(
        "\n  outer = ReceiveSerial only; full = + message_body.decode(), which is\n  \
         what firmware pays. `held` 0 means the whole decode is LIFO-clean."
    );
}

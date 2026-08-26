// MEASUREMENT A, SECOND LEG: what does decoding a DEVICE -> COORDINATOR inner
// body claim and allocate, and can the vendored `MAX_MESSAGE_ALLOC_SIZE = 1 << 15`
// come down to ONE number that serves both directions?
//
// `inner_alloc_measure.rs` measured the coordinator -> device inner leg
// (`WireCoordinatorSendBody::decode` -> `CoordinatorSendBody`) and concluded the
// inner limit could come down. It deliberately did NOT touch the vendored const,
// because `MAX_MESSAGE_ALLOC_SIZE` also governs `WireDeviceSendBody::decode`
// (`frostsnap_comms/src/lib.rs:553` — 522 is that impl's *encode* side, the
// `From<DeviceSendBody>` conversion) and nobody had measured that direction.
// This file is that measurement. Same allocator, same ladder, other direction.
//
// PROVENANCE. Read this before quoting a number.
//   * b2 rows are TRANSCRIPT-REAL: `Run` with `nonce_batch_size = 30` (the
//     production `NONCE_BATCH_SIZE`, device.rs:32) driven through keygen, nonce
//     replenishment and a real Bitcoin signing session; every blob is taken off
//     `run.transcript`'s `Send::DeviceToCoordinator` arm and re-encoded exactly
//     as `From<DeviceSendBody> for WireDeviceSendBody` does.
//   * b3 rows are REAL ELEMENT, SYNTHETIC COUNT: one genuine `HeldShare2` from a
//     real keygen, cloned k times. A device holding 26 keys is not something
//     `Run` can produce cheaply. Labelled in the output, not just here.
//   * b4 is a hostile hand-crafted blob, by construction.
//
// HOW TO RUN — needs `mod common` and `mod env` from the vendored tests dir, so
// it must be copied there for the duration and DELETED afterwards, or the
// unresolved imports break `cargo test -p frostsnap_core` wholesale
// (vendor/README.md):
//
//   cp tools/research-scratch/device_send_alloc_measure.rs \
//      vendor/frostsnap/frostsnap_core/tests/
//   cargo test --target aarch64-apple-darwin -p frostsnap_core \
//     --features coordinator --test device_send_alloc_measure -- --nocapture --test-threads=1
//   rm vendor/frostsnap/frostsnap_core/tests/device_send_alloc_measure.rs
//
// Run it BOTH profiles (`--release` too): `size_of::<Point>()` is 144 B with
// debug_assertions and 120 without, on host AND on thumbv7em, so every claim
// figure is ~17% smaller in the profile the device actually ships.
//
// RESULTS, 2026-08-19. Columns are `release / debug`; the device ships release,
// but the DEBUG column governs any bound we set, because a refusal boundary that
// moves with `debug_assertions` is PLAN.md §8.1's profile-divergence class.
//
//   amplification, worst container element in THIS direction
//     binonce::Nonce  [segment.nonces]   240 / 288 B mem vs 66 wire = 3.64x / 4.36x
//     NonceStreamSegment [.segments]      56 /  56 B mem vs 18 wire = 3.11x / 3.11x
//     HeldShare2                         248 / 272 B mem vs ~148 wire = 1.68x / 1.84x
//     frost::SignatureShare               32 /  32 B mem vs 32 wire = 1.00x (none)
//   Same 3.64x / 4.36x ceiling as the C2D leg, and for the same reason: both are
//   dominated by `Point`, 33 wire bytes against 120 / 144 in memory.
//
//   worst LEGITIMATE claim, TRANSCRIPT-REAL (b2), smallest LIMIT that decodes:
//     NonceResponse 1 seg x 30 (production batch)  blob 2002 -> 7424 / 8704  <== BINDING
//     SignatureShare + 30-nonce replenish          blob 2099 -> 7424 / 8704
//     NonceResponse 2 seg x 30 (envelope max)      blob 4000 -> 7424 / 8960
//     KeyGenResponse n=12 t=12                     blob  898 -> 1536 / 1792
//     Certify / Ack                                blob <=116 ->  256 /  256
//   Note the 2-segment row needs no more LIMIT than the 1-segment one: bincode
//   un-claims each element as it decodes, so the LIMIT is set by the single widest
//   container, not the sum. The HEAP is not: 2 seg = 14,556 / 17,436 B live,
//   3 seg = 26,132 B, 4 seg = 34,828 B. The LIMIT does not bound that; FRAME_LIMIT
//   does (3 seg = 6,036 B frame, refused).
//
//   worst claim any frame the transport ALREADY ADMITS can make (b5): 61 nonces in
//   one segment is the largest whose full frame (4,086 B) fits FRAME_LIMIT = 4096,
//   and it demands 15360 / 17664. 62 nonces = 4,152 B frame, refused by the
//   transport. So 17,664 is the number a shared constant has to clear.
//
//   HOSTILE maximum (b4): a 21-byte blob reaches 32,544 B in ONE allocation under
//   the vendored 32768, and the ceiling tracks the LIMIT 1:1 (20,448 / 16,128 /
//   8,064 / 4,032). Identical shape to the C2D leg.
//
//   VERDICT: `MAX_MESSAGE_ALLOC_SIZE` can drop from 32768 to **20480**, and ONE
//   number then serves both directions, because 20480 is already
//   `coldsnap_hal::comms::ENCAPS_DECODE_LIMIT`. Effective budget 20,472 (bincode's
//   `Limit` charges the 8-byte length claim) > 17,664, so it refuses NOTHING a
//   FRAME_LIMIT-bounded frame can carry in either direction, in either profile.
//   16384 does NOT clear 17,664. 8192 is worse than wrong: it refuses the REAL
//   production 30-nonce NonceResponse in debug (needs 8,704) while admitting it in
//   release (7,424) — measured, and exactly the divergence class §8.1 forbids.
//   inner_alloc_measure.rs's "8192 is enough" conclusion was C2D-only and must not
//   be applied to a shared constant.
//
//   BUT SEE THE SCOPE NOTE: nothing in this tree decodes this direction on the
//   device. `hal/src/comms.rs` decodes `ReceiveSerial<Upstream>` only; every
//   mention of `WireDeviceSendBody` in `hal/src` is below the `#[cfg(test)]` at
//   comms.rs:646; `frostsnap_comms/src/lib.rs` is the only non-test file in
//   `vendor/frostsnap` that names the type at all; and `hostcheck`'s real
//   coordinator decodes with the SIBLING checkout's `frostsnap_comms`, not ours.
//   Lowering the vendored const therefore protects no device-side allocation
//   today. It is a correct pre-emptive bound for the day a device relays a
//   downstream device's body, not a fix for a live exposure.
//
// `--test-threads=1` is REQUIRED: the allocator counters are global.
mod common;
mod env;

use crate::common::Run;
use crate::env::TestEnv;
use common::TestDeviceKeyGen;
use frostsnap_comms::{DeviceSendBody, DeviceSendMessage, Downstream, ReceiveSerial, BINCODE_CONFIG};
use frostsnap_core::bitcoin_transaction::{LocalSpk, TransactionTemplate};
use frostsnap_core::device::KeyPurpose;
use frostsnap_core::device_nonces::{NonceJobBatch, RatchetSeedMaterial, SecretNonceSlot};
use frostsnap_core::message::signing::DeviceSigning;
use frostsnap_core::message::{DeviceRestoration, DeviceToCoordinatorMessage, HeldShare2};
use frostsnap_core::nonce_stream::{NonceStreamId, NonceStreamSegment};
use frostsnap_core::tweak::BitcoinBip32Path;
use frostsnap_core::{DeviceId, WireSignTask};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use schnorr_fun::binonce;
use schnorr_fun::fun::prelude::*;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

// ---------------------------------------------------------------------------
// Counting allocator. Identical to inner_alloc_measure.rs's.
// ---------------------------------------------------------------------------
static CUR: AtomicUsize = AtomicUsize::new(0);
static WPEAK: AtomicUsize = AtomicUsize::new(0);
static WMAXONE: AtomicUsize = AtomicUsize::new(0);

struct Track;

// SAFETY: every method forwards to `System` unchanged; the atomics touch no
// allocator state. Relaxed is enough with --test-threads=1.
unsafe impl GlobalAlloc for Track {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = System.alloc(l);
        if !p.is_null() {
            let n = l.size();
            let c = CUR.fetch_add(n, Relaxed) + n;
            WPEAK.fetch_max(c, Relaxed);
            WMAXONE.fetch_max(n, Relaxed);
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

fn enc<T: bincode::Encode>(v: &T) -> Vec<u8> {
    bincode::encode_to_vec(v, BINCODE_CONFIG).expect("encode works")
}

/// EXACTLY the bytes `From<DeviceSendBody> for WireDeviceSendBody` puts inside
/// `EncapsBody`, i.e. exactly what `WireDeviceSendBody::decode`'s inner
/// `decode_from_slice` is handed.
fn encaps_blob(m: &DeviceToCoordinatorMessage) -> Vec<u8> {
    enc(&DeviceSendBody::Core(m.clone()))
}

/// The full `ReceiveSerial<Downstream>` frame `coldsnap_hal::comms::encode_frame`
/// must fit, for the same body. Context only; FRAME_LIMIT is 4,096.
fn frame_len(m: &DeviceToCoordinatorMessage) -> usize {
    let body: frostsnap_comms::WireDeviceSendBody = DeviceSendBody::Core(m.clone()).into();
    enc(&ReceiveSerial::<Downstream>::Message(DeviceSendMessage {
        from: DeviceId::new((*schnorr_fun::fun::G).normalize()),
        body,
    }))
    .len()
}

/// Peak simultaneous bytes above entry, and largest single allocation, for one
/// inner decode. Nothing else may allocate inside: no println!, no format!.
fn measure_decode(blob: &[u8]) -> (usize, usize, bool) {
    let base = CUR.load(Relaxed);
    WPEAK.store(base, Relaxed);
    WMAXONE.store(0, Relaxed);
    let ok = bincode::decode_from_slice::<DeviceSendBody, _>(blob, BINCODE_CONFIG).is_ok();
    let peak = WPEAK.load(Relaxed).saturating_sub(base);
    (peak, WMAXONE.load(Relaxed), ok)
}

fn ok_at<const N: usize>(blob: &[u8]) -> bool {
    let cfg = bincode::config::standard().with_limit::<N>();
    bincode::decode_from_slice::<DeviceSendBody, _>(blob, cfg).is_ok()
}

/// Smallest bincode `Limit` under which the blob still decodes = the peak of
/// bincode's `bytes_read` counter, to ladder granularity (256 B below 4,096,
/// 512 B to 8,192, then coarser).
fn min_limit(blob: &[u8]) -> Option<usize> {
    macro_rules! probe {
        ($($n:literal),*) => {{
            let mut best: Option<usize> = None;
            $( if best.is_none() && ok_at::<$n>(blob) { best = Some($n); } )*
            best
        }};
    }
    probe!(
        256, 512, 768, 1024, 1280, 1536, 1792, 2048, 2304, 2560, 2816, 3072, 3328, 3584, 3840,
        4096, 4352, 4608, 4864, 5120, 5376, 5632, 5888, 6144, 6400, 6656, 6912, 7168, 7424, 7680,
        7936, 8192, 8448, 8704, 8960, 9216, 9472, 9728, 9984, 10240, 10752, 11264, 11776, 12288,
        13312, 14336, 15360, 16384, 17408, 17664, 17920, 18432, 19456, 20480, 24576, 32768
    )
}

fn row(label: &str, blob: &[u8], frame: usize, extra: &str) {
    let lim = min_limit(blob);
    let (peak, maxone, ok) = measure_decode(blob);
    println!(
        "{:<44} {:>7} {:>7} {:>9} {:>9} {:>9} {:>4} {}",
        label,
        blob.len(),
        frame,
        lim.map(|l| l.to_string()).unwrap_or("＞32768".into()),
        peak,
        maxone,
        if ok { "ok" } else { "ERR" },
        extra
    );
}

fn header() {
    println!(
        "{:<44} {:>7} {:>7} {:>9} {:>9} {:>9} {:>4}",
        "message", "blob B", "frame B", "minLIMIT", "heapPeak", "maxSingle", ""
    );
}

// ---------------------------------------------------------------------------
// 1. Amplification, for the containers THIS direction carries.
// ---------------------------------------------------------------------------
#[test]
fn b1_size_of_vs_wire() {
    use core::mem::size_of;
    let g = (*schnorr_fun::fun::G).normalize();
    let nonce = binonce::Nonce([g, g]);

    println!("\n=== B1: in-memory size vs wire size, device -> coordinator containers ===");
    println!(
        "{:<52} {:>8} {:>6} {:>7}",
        "container element type", "size_of", "wire", "ratio"
    );
    let r = |name: &str, mem: usize, wire: usize| {
        println!(
            "{:<52} {:>8} {:>6} {:>6.2}x",
            name,
            mem,
            wire,
            mem as f64 / wire as f64
        );
    };
    r(
        "binonce::Nonce  [NonceStreamSegment.nonces VecDeque]",
        size_of::<binonce::Nonce>(),
        enc(&nonce).len(),
    );
    r(
        "NonceStreamSegment  [NonceResponse.segments Vec]",
        size_of::<NonceStreamSegment>(),
        enc(&NonceStreamSegment {
            stream_id: NonceStreamId([0u8; 16]),
            nonces: Default::default(),
            index: 0,
        })
        .len(),
    );
    r(
        "schnorr_fun::frost::SignatureShare  [Vec]",
        size_of::<schnorr_fun::frost::SignatureShare>(),
        enc(&Scalar::<Public, Zero>::zero()).len(),
    );
    println!(
        "\nsize_of::<HeldShare2>() = {}   size_of::<DeviceSendBody>() = {}\n\
         size_of::<DeviceToCoordinatorMessage>() = {}",
        size_of::<HeldShare2>(),
        size_of::<DeviceSendBody>(),
        size_of::<DeviceToCoordinatorMessage>(),
    );
    println!(
        "\nbincode claims `len * size_of::<ELEMENT>()` up front and un-claims each\n\
         element as it decodes (de/mod.rs:182-191 + impl_alloc.rs), so the LIMIT a\n\
         message needs is set by its single widest container, NOT by the sum.\n\
         32-BIT/RELEASE: Point is 120 B without debug_assertions and 144 B with, on\n\
         host AND thumbv7em (secp256kfun k256 FieldElement is 40 B on both widths,\n\
         48 B with the debug magnitude/normalized tag). VecDeque/Vec node overhead\n\
         halves on 32-bit but bincode's claim is len*size_of::<ELEMENT>(), so the\n\
         claim column carries over unchanged."
    );
}

// ---------------------------------------------------------------------------
// 2. Real transcript, production nonce batch size.
// ---------------------------------------------------------------------------
/// `Run::start_after_keygen` hardcodes `nonce_batch_size = 10`
/// (`common/mod.rs:226`), one third of the production `NONCE_BATCH_SIZE = 30`.
/// This is that function's body with the batch size and slot count opened up, so
/// the `NonceResponse` rows below are production-sized and still transcript-real.
fn run_after_keygen_with_batch(
    n: usize,
    t: u16,
    slots: usize,
    batch: u32,
    env: &mut TestEnv,
    rng: &mut ChaCha20Rng,
) -> Run {
    use frostsnap_core::coordinator::BeginKeygen;
    let mut run = Run::generate_with_nonce_slots_and_batch_size(n, rng, slots, batch);
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let mut coordinator_rng = ChaCha20Rng::from_seed(seed);
    let init = run
        .coordinator
        .begin_keygen(
            BeginKeygen::new(
                run.devices.keys().cloned().collect::<Vec<_>>(),
                t,
                "my new key".to_string(),
                KeyPurpose::Bitcoin(bitcoin::Network::Bitcoin),
                rng,
            ),
            &mut coordinator_rng,
        )
        .unwrap();
    run.extend(init);
    run.run_until_finished(env, rng).unwrap();
    run
}

/// Keygen -> `n_streams` nonce streams -> one real 2-input Bitcoin signing
/// session. Returns the largest device -> coordinator blob per message kind.
fn real_d2c_blobs(
    n: usize,
    t: u16,
    n_streams: usize,
    batch: u32,
) -> Vec<(String, Vec<u8>, usize, String)> {
    let mut env = TestEnv::default();
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let mut run = run_after_keygen_with_batch(n, t, 8, batch, &mut env, &mut rng);

    run.extend(run.coordinator.maybe_request_nonce_replenishment(
        &run.device_set(),
        n_streams,
        &mut rng,
    ));
    run.run_until_finished(&mut env, &mut rng).unwrap();

    // A real signing session over a real Bitcoin transaction template.
    let asr = run
        .coordinator
        .iter_access_structures()
        .next()
        .unwrap()
        .access_structure_ref();
    let master_appkey = run
        .coordinator
        .get_frost_key(asr.key_id)
        .unwrap()
        .complete_key
        .master_appkey;
    let mut tx = TransactionTemplate::new();
    tx.push_owned_output(
        bitcoin::Amount::from_sat(150_000),
        LocalSpk {
            master_appkey,
            bip32_path: BitcoinBip32Path::external(0),
        },
    );
    for i in 0..2u32 {
        tx.push_imaginary_owned_input(
            LocalSpk {
                master_appkey,
                bip32_path: BitcoinBip32Path::external(i),
            },
            bitcoin::Amount::from_sat(100_000 + i as u64),
        );
    }
    let set = run.device_set().into_iter().take(t as usize).collect();
    let session_id = run
        .coordinator
        .start_sign(asr, WireSignTask::BitcoinTransaction(tx), &set, &mut rng)
        .unwrap();
    for &device_id in &set {
        let req = run.coordinator.request_device_sign(
            session_id,
            device_id,
            common::TEST_ENCRYPTION_KEY,
        );
        run.extend(req);
    }
    run.run_until_finished(&mut env, &mut rng).unwrap();

    let mut out: Vec<(String, Vec<u8>, usize, String)> = Vec::new();
    for send in &run.transcript {
        if let common::Send::DeviceToCoordinator { message, .. } = send {
            let (label, extra) = match message {
                DeviceToCoordinatorMessage::KeyGen(k) => (
                    format!("KeyGen::{}", variant_name(&format!("{k:?}"))),
                    String::new(),
                ),
                DeviceToCoordinatorMessage::Signing(DeviceSigning::NonceResponse { segments }) => (
                    "Signing::NonceResponse".to_string(),
                    format!(
                        "{} seg x {} nonces",
                        segments.len(),
                        segments.first().map(|s| s.nonces.len()).unwrap_or(0)
                    ),
                ),
                DeviceToCoordinatorMessage::Signing(DeviceSigning::SignatureShare {
                    signature_shares,
                    replenish_nonces,
                    ..
                }) => (
                    "Signing::SignatureShare".to_string(),
                    format!(
                        "{} share(s), replenish={}",
                        signature_shares.len(),
                        replenish_nonces
                            .as_ref()
                            .map(|s| s.nonces.len())
                            .unwrap_or(0)
                    ),
                ),
                DeviceToCoordinatorMessage::Restoration(r) => (
                    format!("Restoration::{}", variant_name(&format!("{r:?}"))),
                    String::new(),
                ),
            };
            let blob = encaps_blob(message);
            let frame = frame_len(message);
            match out.iter_mut().find(|(l, _, _, _)| *l == label) {
                Some(slot) if slot.1.len() < blob.len() => *slot = (label, blob, frame, extra),
                Some(_) => {}
                None => out.push((label, blob, frame, extra)),
            }
        }
    }
    out
}

fn variant_name(dbg: &str) -> String {
    dbg.split(|c: char| c == '(' || c == ' ' || c == '{')
        .next()
        .unwrap_or("?")
        .to_string()
}

#[test]
fn b2_real_transcript_peaks() {
    println!(
        "\n=== B2: REAL device -> coordinator inner blobs (transcript), batch = 30 ===\n\
         ENCAPS_DECODE_LIMIT (our C2D inner bound) = 20480, effective 20472"
    );
    for (n, t, streams) in [(3usize, 2u16, 1usize), (3, 2, 2), (12, 12, 1), (12, 12, 2)] {
        println!("\n-- n={n} t={t} streams={streams} --");
        header();
        for (label, blob, frame, extra) in real_d2c_blobs(n, t, streams, 30) {
            row(&label, &blob, frame, &extra);
        }
    }
}

// ---------------------------------------------------------------------------
// 3. HeldShares2. REAL element, SYNTHETIC count.
// ---------------------------------------------------------------------------
fn one_real_held_share() -> HeldShare2 {
    let mut env = TestEnv::default();
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    let mut run = Run::start_after_keygen(
        2,
        2,
        &mut env,
        &mut rng,
        KeyPurpose::Bitcoin(bitcoin::Network::Bitcoin),
    );
    let device = run.device_vec()[0];
    let reqs: Vec<_> = run.coordinator.request_held_shares(device).collect();
    run.extend(reqs);
    run.run_until_finished(&mut env, &mut rng).unwrap();
    for send in &run.transcript {
        if let common::Send::DeviceToCoordinator {
            message: DeviceToCoordinatorMessage::Restoration(DeviceRestoration::HeldShares2(v)),
            ..
        } = send
        {
            if let Some(h) = v.first() {
                return h.clone();
            }
        }
    }
    panic!("no HeldShares2 in transcript");
}

#[test]
fn b3_held_shares2_by_count() {
    println!(
        "\n=== B3: HeldShares2. REAL HeldShare2 (key_name=\"my new key\"), COUNT IS SYNTHETIC ===\n\
         Device-emitted: no coordinator input. Bounded only by how many master\n\
         access structures the device stores; nothing in this tree caps that."
    );
    let held = one_real_held_share();
    header();
    for k in [1usize, 2, 5, 10, 14, 20, 26, 40, 64, 128] {
        let m = DeviceToCoordinatorMessage::Restoration(DeviceRestoration::HeldShares2(
            (0..k).map(|_| held.clone()).collect(),
        ));
        let blob = encaps_blob(&m);
        let frame = frame_len(&m);
        row(
            &format!("HeldShares2 x{k}  [SYNTHETIC COUNT]"),
            &blob,
            frame,
            if frame > 4096 { "frame > FRAME_LIMIT" } else { "" },
        );
    }
}

// ---------------------------------------------------------------------------
// 4. Hostile maximum, given the blob is already bounded by the outer 8192.
// ---------------------------------------------------------------------------
fn varint(n: usize) -> Vec<u8> {
    if n < 251 {
        vec![n as u8]
    } else if n <= u16::MAX as usize {
        let mut v = vec![251u8];
        v.extend_from_slice(&(n as u16).to_le_bytes());
        v
    } else {
        let mut v = vec![252u8];
        v.extend_from_slice(&(n as u32).to_le_bytes());
        v
    }
}

/// Bytes of a real one-segment `NonceResponse` up to and NOT including the
/// `nonces` VecDeque length varint. Built by subtraction from a real encoding
/// (empty segment = `[tags][stream_id][len=0][index=0]`), not hand-counted tags.
fn nonce_vec_prefix() -> Vec<u8> {
    let m = DeviceToCoordinatorMessage::Signing(DeviceSigning::NonceResponse {
        segments: vec![NonceStreamSegment {
            stream_id: NonceStreamId([0xab; 16]),
            nonces: Default::default(),
            index: 0,
        }],
    });
    let whole = encaps_blob(&m);
    assert!(
        whole.ends_with(&[0u8, 0u8]),
        "trailing bytes should be nonces-len=0 then index=0, got {:?}",
        &whole[whole.len() - 4..]
    );
    whole[..whole.len() - 2].to_vec()
}

/// Same, for `HeldShares2`: the `Vec<HeldShare2>` length varint is the first
/// thing after the tags, so an empty vec's encoding minus its trailing `0` is
/// the prefix.
fn held_vec_prefix() -> Vec<u8> {
    let m = DeviceToCoordinatorMessage::Restoration(DeviceRestoration::HeldShares2(vec![]));
    let whole = encaps_blob(&m);
    assert_eq!(*whole.last().unwrap(), 0u8, "empty vec len byte");
    whole[..whole.len() - 1].to_vec()
}

fn hostile_at<const N: usize>(prefix: &[u8], elem: usize) -> (usize, usize, usize, String) {
    let len = N / elem;
    let mut blob = prefix.to_vec();
    blob.extend_from_slice(&varint(len));
    let base = CUR.load(Relaxed);
    WPEAK.store(base, Relaxed);
    WMAXONE.store(0, Relaxed);
    let cfg = bincode::config::standard().with_limit::<N>();
    let err = match bincode::decode_from_slice::<DeviceSendBody, _>(&blob, cfg) {
        Ok(_) => "Ok(!)".to_string(),
        Err(e) => format!("{e:?}"),
    };
    let peak = WPEAK.load(Relaxed).saturating_sub(base);
    (blob.len(), peak, WMAXONE.load(Relaxed), err)
}

#[test]
fn b4_hostile_maximum() {
    use core::mem::size_of;
    println!("\n=== B4: hostile device -> coordinator inner blob ===");
    let cases: [(&str, Vec<u8>, usize); 2] = [
        (
            "NonceResponse.nonces: VecDeque<binonce::Nonce>",
            nonce_vec_prefix(),
            size_of::<binonce::Nonce>(),
        ),
        (
            "HeldShares2: Vec<HeldShare2>",
            held_vec_prefix(),
            size_of::<HeldShare2>(),
        ),
    ];
    for (name, prefix, elem) in cases {
        println!("\n{name}\n  prefix = {} B, size_of::<elem>() = {elem} B", prefix.len());
        println!(
            "{:>8} {:>8} {:>9} {:>10}  {}",
            "LIMIT", "blob B", "heapPeak", "maxSingle", "error"
        );
        macro_rules! at {
            ($($n:literal),*) => {$({
                let (b, p, m, e) = hostile_at::<$n>(&prefix, elem);
                println!("{:>8} {:>8} {:>9} {:>10}  {}", $n, b, p, m, e);
            })*};
        }
        at!(32768, 20480, 16384, 8192, 4096);
    }
    println!(
        "\nThe ceiling tracks the LIMIT: a blob of a few dozen bytes buys ~LIMIT bytes\n\
         in ONE allocation, in whichever direction, because bincode sizes the\n\
         up-front `Vec::with_capacity` off the claimed length alone."
    );
}

// ---------------------------------------------------------------------------
// 5. The nonce-count sweep: where the LIMIT and FRAME_LIMIT boundaries sit.
// Real nonces from the real device generator; slot seed material is synthetic.
// ---------------------------------------------------------------------------
fn real_segment(seed_byte: u8, n: usize) -> NonceStreamSegment {
    let nonce_stream_id = NonceStreamId([seed_byte; 16]);
    let ratchet_prg_seed_material: RatchetSeedMaterial = [seed_byte ^ 0x5a; 32];
    let slot_value = SecretNonceSlot {
        index: 0,
        nonce_stream_id,
        ratchet_prg_seed_material,
        last_used: 0,
        signing_state: None,
    };
    let task = slot_value.nonce_task(None, n);
    let mut batch = NonceJobBatch::new(vec![task]);
    batch.run_until_finished(&mut TestDeviceKeyGen);
    batch.into_segments().pop().unwrap()
}

#[test]
fn b5_nonce_response_sweep() {
    println!(
        "\n=== B5: NonceResponse sweep. REAL nonce generator, SYNTHETIC slot seed ===\n\
         30 nonces/segment is production NONCE_BATCH_SIZE; 4 segments is the app's\n\
         N_NONCE_STREAMS. 1-2 segments is the declared envelope."
    );
    header();
    for segs in 1..=4usize {
        for per in [30usize] {
            let m = DeviceToCoordinatorMessage::Signing(DeviceSigning::NonceResponse {
                segments: (0..segs).map(|i| real_segment(i as u8 + 1, per)).collect(),
            });
            let blob = encaps_blob(&m);
            let frame = frame_len(&m);
            row(
                &format!("NonceResponse {segs} seg x {per}"),
                &blob,
                frame,
                if frame > 4096 {
                    "frame > FRAME_LIMIT 4096"
                } else {
                    ""
                },
            );
        }
    }
    // The number that decides whether ONE shared constant can serve both legs:
    // the largest claim any WELL-FORMED frame the transport already admits
    // (<= FRAME_LIMIT = 4096 B) can make in this direction. Found by walking the
    // nonce count up to the last one whose FULL FRAME still fits 4,096.
    println!("\n-- FRAME_LIMIT-filling worst case: last nonce count whose frame fits 4096 --");
    header();
    let mut last: Option<(usize, usize)> = None;
    for per in 55..=70usize {
        let m = DeviceToCoordinatorMessage::Signing(DeviceSigning::NonceResponse {
            segments: vec![real_segment(1, per)],
        });
        let frame = frame_len(&m);
        if frame > 4096 {
            let blob = encaps_blob(&m);
            row(
                &format!("NonceResponse 1 seg x {per}  [FIRST REFUSED]"),
                &blob,
                frame,
                "frame > FRAME_LIMIT",
            );
            break;
        }
        last = Some((per, frame));
    }
    if let Some((per, _)) = last {
        let m = DeviceToCoordinatorMessage::Signing(DeviceSigning::NonceResponse {
            segments: vec![real_segment(1, per)],
        });
        let blob = encaps_blob(&m);
        row(
            &format!("NonceResponse 1 seg x {per}  [LARGEST ADMITTED]"),
            &blob,
            frame_len(&m),
            "<== the shared constant must clear this",
        );
    }

    println!("\n-- one segment, nonce count sweep (finds the per-nonce claim slope) --");
    header();
    for per in [1usize, 10, 30, 60, 100, 200] {
        let m = DeviceToCoordinatorMessage::Signing(DeviceSigning::NonceResponse {
            segments: vec![real_segment(1, per)],
        });
        let blob = encaps_blob(&m);
        let frame = frame_len(&m);
        row(&format!("NonceResponse 1 seg x {per}"), &blob, frame, "");
    }
}

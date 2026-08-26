// MEASUREMENT A: what does the NESTED (EncapsBody) decode leg actually claim and
// allocate, and can the vendored `MAX_MESSAGE_ALLOC_SIZE = 1 << 15` come down?
//
// STATUS, as of 2026-08-19: this file's question has been ANSWERED and acted on, so
// read the two paragraphs below as the state when it was written, not as current.
// The inner leg is now bounded at `comms::ENCAPS_DECODE_LIMIT = 20,480` via
// `comms::decode_body`, `ENCAPS_ALLOC_CEILING` tracks that constant rather than
// 32 KiB, and the vendored `MAX_MESSAGE_ALLOC_SIZE` itself came down to 20,480 once
// the device->coordinator direction was measured too (see the sibling
// device_send_alloc_measure.rs, and PLAN.md section 9 item 7(d)). NOTE that this
// file's "the inner limit could come down to 8192" conclusion was
// coordinator->device ONLY and MUST NOT be generalised: 8,192 refuses a real
// 30-nonce NonceResponse on the other leg under debug_assertions.
//
// As written: `coldsnap_hal::comms::DECODE_ALLOC_LIMIT = 2 * FRAME_LIMIT = 8192`
// bounds the OUTER leg (`ReceiveSerial<Upstream>`). It did not bound the inner one:
// `WireCoordinatorSendBody::decode` re-enters bincode over the `EncapsBody` bytes
// with the vendored 32 KiB budget (`frostsnap_comms/src/lib.rs:54`) while the
// outer `Vec<u8>` is still live. `hal/src/heap.rs::ENCAPS_ALLOC_CEILING` recorded
// that 32 KiB as a heap-sizing input. This file measures whether it is real.
//
// PROVENANCE, and read this before quoting any number out of this file. The rows
// are NOT uniformly real. The KEYGEN rows (`CertifyPlease`, `Check` at n=12) are
// genuine messages taken off `Run::start_after_keygen`'s transcript. The
// `RequestSign` row -- which is the BINDING one, the 5,120 B peak -- is
// HAND-ASSEMBLED from real vendored types but with a fabricated
// `AccessStructureId`, `rootkey = G` and synthetic `ShareIndex`es. So the safety of
// any proposed inner limit rests on the DECLARED ENVELOPE (DECISIONS.md 7: n <= 12
// devices, <= 20 owned inputs), not on 5,120 alone. An earlier version of this
// header said "all on REAL messages", which was wrong and is exactly the kind of
// overclaim that makes a measured number untrustworthy.
//
// Ladder granularity is 256 B below 4,096 and 512 B above, so "5,120" means the
// true peak lies in (4,608, 5,120].
//
// Three things are measured:
//   1. size_of vs wire size for every container element in the inner type
//      (the amplification factor).
//   2. The smallest bincode LIMIT under which each real inner blob still decodes
//      (= the peak of bincode's `bytes_read` counter, to ladder granularity),
//      plus the true heap peak and largest single allocation, from a counting
//      `#[global_allocator]`.
//   3. The largest allocation a HOSTILE inner blob can provoke, given the blob
//      itself is already bounded by the outer 8192.
//
// HOW TO RUN — same constraint as wire_size_measure.rs: it needs `mod common` and
// `mod env`, which live in the vendored tests dir, so it must be copied there for
// the duration and DELETED afterwards, or 26 unresolved imports break
// `cargo test -p frostsnap_core` wholesale (vendor/README.md):
//
//   cp tools/research-scratch/inner_alloc_measure.rs \
//      vendor/frostsnap/frostsnap_core/tests/
//   cargo test --target aarch64-apple-darwin -p frostsnap_core \
//     --features coordinator --test inner_alloc_measure -- --nocapture --test-threads=1
//   rm vendor/frostsnap/frostsnap_core/tests/inner_alloc_measure.rs
//
// RESULTS, 2026-08-19. Run BOTH profiles: `cargo test` reports Point = 144 B
// (debug_assertions wraps each k256 FieldElement with a magnitude+normalized
// tag), `cargo test --release` reports 120 B. THE DEVICE BUILDS RELEASE, so the
// 120 B column is the firmware one; the 144 B column is the conservative one.
//
//   amplification, worst container element  (release / debug)
//     Point<Normal,Public,*>       120 / 144 B mem vs 33 wire  = 3.64x / 4.36x
//     binonce::Nonce<Zero>         240 / 288 B mem vs 66 wire  = 3.64x / 4.36x
//     (Point, Signature)           272 / 320 B mem vs 97 wire  = 2.80x / 3.30x
//     (Point, CertVrfProof)        304 / 352 B mem vs 130 wire = 2.34x / 2.71x
//     Scalar, DeviceId             1.00x -- no amplification at all
//
//   worst LEGITIMATE inner claim inside the declared envelope (n <= 12, t <= n,
//   <= 20 owned inputs) -- the smallest bincode LIMIT that still decodes:
//     RequestSign, 20 owned inputs, 3 parties  blob 3850 B -> 5120 / 6144 B  <== BINDING
//     Keygen::Check      n=12 (13 map entries) blob 1710 B -> 4096 / 4608 B
//     Keygen::CertifyPlease n=12,t=12          blob 2460 B -> 3584 / 4608 B
//   Legitimate inner HEAP peak is a DIFFERENT and larger number: 10,222 B at
//   Check n=12, because std's BTreeMap allocates a fixed 11-entry node
//   (11 * 304 + header = 3,360 B) even for a 3-entry map. The LIMIT does not
//   bound that; it bounds `Vec::with_capacity`.
//
//   HOSTILE maximum: a 20-byte inner blob (trivially inside the outer
//   DECODE_ALLOC_LIMIT = 8192) reaches 32,640 B in ONE allocation under the
//   vendored 32768, and the ceiling tracks the LIMIT 1:1 (16,320 / 8,160 / refused).
//
//   VERDICT: the inner limit CAN come down to 8192 = 2 * FRAME_LIMIT, matching
//   the outer leg. Margin over the binding legitimate peak: 3,072 B (1.60x) on
//   release, 2,048 B (1.33x) on debug. The refusal boundary it introduces sits at
//   ~33 agg_nonces / ~26 Check entries / ~30 keygen contributors -- all far
//   outside the envelope, and a5 pins the FRAME_LIMIT-filling case that DOES get
//   refused (41 contributors, 11,152 B claim). 16384 = 4 * FRAME_LIMIT is the
//   zero-refusal alternative: the largest claim any FRAME_LIMIT-sized well-formed
//   frame can make is ~14,811 B (= 3.64 * 4,069), so 16384 refuses nothing the
//   transport admits while still halving the hostile ceiling.
//
// `--test-threads=1` is REQUIRED here, not just tidy: the allocator counters are
// global and a second test thread allocating concurrently corrupts every window.
mod common;
mod env;

use crate::common::Run;
use crate::env::TestEnv;
use bitcoin::{Amount, ScriptBuf, TxOut};
use common::TestDeviceKeyGen;
use frostsnap_comms::{CoordinatorSendBody, BINCODE_CONFIG};
use frostsnap_core::bitcoin_transaction::{LocalSpk, TransactionTemplate};
use frostsnap_core::device::KeyPurpose;
use frostsnap_core::device_nonces::{NonceJobBatch, RatchetSeedMaterial, SecretNonceSlot};
use frostsnap_core::message::keygen::Keygen;
use frostsnap_core::message::signing::CoordinatorSigning;
use frostsnap_core::message::{
    CoordinatorToDeviceMessage, DeviceSignReq, GroupSignReq, RequestSign,
};
use frostsnap_core::nonce_stream::{CoordNonceStreamState, NonceStreamId, NonceStreamSegment};
use frostsnap_core::tweak::BitcoinBip32Path;
use frostsnap_core::{MasterAppkey, WireSignTask};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use schnorr_fun::binonce;
use schnorr_fun::frost::ShareIndex;
use schnorr_fun::fun::prelude::*;
use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

// ---------------------------------------------------------------------------
// Counting allocator. Same shape as hal/examples/heap_profile.rs's `Track`.
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

/// Peak simultaneous bytes above entry, and largest single allocation, for one
/// inner decode. Nothing else may allocate inside: no println!, no format!.
fn measure_inner_decode(blob: &[u8]) -> (usize, usize, bool) {
    let base = CUR.load(Relaxed);
    WPEAK.store(base, Relaxed);
    WMAXONE.store(0, Relaxed);
    let ok = bincode::decode_from_slice::<CoordinatorSendBody, _>(blob, BINCODE_CONFIG).is_ok();
    let peak = WPEAK.load(Relaxed).saturating_sub(base);
    (peak, WMAXONE.load(Relaxed), ok)
}

// ---------------------------------------------------------------------------
// The LIMIT ladder. `Limit<N>` is a const generic, so the only way to find the
// peak of bincode's `bytes_read` is to instantiate the decoder at a set of
// candidate limits and take the smallest that passes.
// ---------------------------------------------------------------------------
fn ok_at<const N: usize>(blob: &[u8]) -> bool {
    let cfg = bincode::config::standard().with_limit::<N>();
    bincode::decode_from_slice::<CoordinatorSendBody, _>(blob, cfg).is_ok()
}

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
        4096, 4608, 5120, 5632, 6144, 7168, 8192, 10240, 12288, 16384, 24576, 32768
    )
}

fn enc<T: bincode::Encode>(v: &T) -> Vec<u8> {
    bincode::encode_to_vec(v, BINCODE_CONFIG).expect("encode works")
}

/// EXACTLY the bytes `From<CoordinatorSendBody> for WireCoordinatorSendBody`
/// puts inside `EncapsBody`, i.e. exactly what the inner decode leg is handed.
fn encaps_blob(m: &CoordinatorToDeviceMessage) -> Vec<u8> {
    enc(&CoordinatorSendBody::Core(m.clone()))
}

// ---------------------------------------------------------------------------
// 1. Amplification: in-memory bytes per wire byte, per container element.
// ---------------------------------------------------------------------------
#[test]
fn a1_size_of_vs_wire() {
    use core::mem::size_of;
    use schnorr_fun::frost::chilldkg::certpedpop::vrf_cert::CertVrfProof;
    use schnorr_fun::Signature;

    type PN = Point<Normal, Public, NonZero>;
    type PZ = Point<Normal, Public, Zero>;
    type SZ = Scalar<Public, Zero>;

    let g = (*schnorr_fun::fun::G).normalize();
    let gz: PZ = g.mark_zero();
    let sz = Scalar::<Public, Zero>::zero();
    let sig = Signature {
        R: g.into_point_with_even_y().0,
        s: Scalar::<Public, Zero>::zero(),
    };
    let nonce = binonce::Nonce::<Zero>([gz, gz]);

    println!("\n=== A1: in-memory size vs wire size, host 64-bit ===");
    println!(
        "{:<44} {:>8} {:>6} {:>7}",
        "container element type", "size_of", "wire", "ratio"
    );
    let row = |name: &str, mem: usize, wire: usize| {
        println!(
            "{:<44} {:>8} {:>6} {:>6.2}x",
            name,
            mem,
            wire,
            mem as f64 / wire as f64
        );
    };
    row("Point<Normal,Public,NonZero>", size_of::<PN>(), enc(&g).len());
    row("Point<Normal,Public,Zero>", size_of::<PZ>(), enc(&gz).len());
    row("Scalar<Public,Zero>", size_of::<SZ>(), enc(&sz).len());
    row("Signature", size_of::<Signature>(), enc(&sig).len());
    row(
        "(Point, Signature)  [simplepedpop key_contrib]",
        size_of::<(PN, Signature)>(),
        enc(&(g, sig.clone())).len(),
    );
    // 130 B/entry is the MEASURED slope of the real `Keygen::Check` inner blob:
    // 410/3, 800/6, 1320/10, 1710/13 entries -> (1710-1320)/3 = 130, base 20.
    row(
        "(Point, CertVrfProof)  [Keygen::Check map]",
        size_of::<(PN, CertVrfProof)>(),
        130,
    );
    row(
        "binonce::Nonce<Zero>  [GroupSignReq agg_nonces]",
        size_of::<binonce::Nonce<Zero>>(),
        enc(&nonce).len(),
    );
    row(
        "DeviceId  [OUTER Destination::Particular]",
        size_of::<frostsnap_core::DeviceId>(),
        enc(&frostsnap_core::DeviceId::new(g)).len(),
    );
    println!(
        "\nsize_of::<CertVrfProof>() = {}   size_of::<ShareIndex>() = {}",
        size_of::<CertVrfProof>(),
        size_of::<ShareIndex>()
    );
    println!(
        "NOTE (Point,CertVrfProof) wire = 130 B/entry, MEASURED as the slope of the\n\
         real Check inner blob across n = 2/5/9/12 in a2, not assumed."
    );
    println!(
        "\n32-BIT / RELEASE DIRECTION (read the vendored source, not assumed):\n\
         secp256kfun's `backend::Point` IS k256's `ProjectivePoint` = 3 x `FieldElement`\n\
         (secp256kfun-0.12.1 src/backend/k256_impl.rs:9, src/vendor/k256/projective.rs:20).\n\
         `FieldElement` wraps `FieldElementImpl`, chosen by BOTH cfgs\n\
         (src/vendor/k256/field.rs:2-14):\n\
           * 32-bit -> `FieldElement10x26([u32;10])` = 40 B\n\
           * 64-bit -> `FieldElement5x52([u64;5])`   = 40 B\n\
           * debug_assertions -> `field_impl::FieldElementImpl {{value, magnitude: u32,\n\
             normalized: bool}}` = 48 B, on either width\n\
         So the limb COUNT is target-dependent but the BYTE count is not: Point is\n\
         120 B with debug_assertions off and 144 B with it on, on host AND on\n\
         thumbv7em. `cargo test` (dev/test profile) reports 144; the device builds\n\
         --release, so 120 is the firmware figure and every claim number below is\n\
         ~17% smaller there. RUN THIS BOTH WAYS: `cargo test` gives the 144 rows,\n\
         `cargo test --release` gives the 120 rows that describe the device.\n\
         Only Vec/BTreeMap NODE overhead genuinely halves on 32-bit, and bincode\n\
         claims len*size_of::<ELEMENT>(), so the claim figures carry over."
    );
}

// ---------------------------------------------------------------------------
// 2. Real keygen messages, n x t at the declared envelope maximum.
// ---------------------------------------------------------------------------
fn keygen_inner_blobs(n: usize, t: u16) -> Vec<(&'static str, Vec<u8>, usize)> {
    let mut env = TestEnv::default();
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let run = Run::start_after_keygen(
        n,
        t,
        &mut env,
        &mut rng,
        KeyPurpose::Bitcoin(bitcoin::Network::Bitcoin),
    );
    let mut out: Vec<(&'static str, Vec<u8>, usize)> = Vec::new();
    for send in &run.transcript {
        if let common::Send::CoordinatorToDevice { message, .. } = send {
            let (label, entries) = match message {
                CoordinatorToDeviceMessage::KeyGen(Keygen::Begin(b)) => ("Begin", b.devices.len()),
                CoordinatorToDeviceMessage::KeyGen(Keygen::CertifyPlease { .. }) => {
                    ("CertifyPlease", 0)
                }
                CoordinatorToDeviceMessage::KeyGen(Keygen::Check { certificate, .. }) => {
                    ("Check", certificate.len())
                }
                CoordinatorToDeviceMessage::KeyGen(Keygen::Finalize { .. }) => ("Finalize", 0),
                _ => continue,
            };
            let blob = encaps_blob(message);
            // keep only the largest of each kind
            match out.iter_mut().find(|(l, _, _)| *l == label) {
                Some(slot) if slot.1.len() < blob.len() => *slot = (label, blob, entries),
                Some(_) => {}
                None => out.push((label, blob, entries)),
            }
        }
    }
    out
}

#[test]
fn a2_legitimate_inner_peak_across_n() {
    println!("\n=== A2: REAL keygen inner (EncapsBody) blobs, t = n ===");
    println!(
        "{:>3} {:<14} {:>9} {:>10} {:>10} {:>11} {:>7}",
        "n", "message", "blob B", "minLIMIT", "heapPeak", "maxSingle", "mapLen"
    );
    let mut worst_limit = 0usize;
    let mut worst_label = String::new();
    for n in [2usize, 5, 9, 12] {
        let t = n as u16;
        for (label, blob, entries) in keygen_inner_blobs(n, t) {
            let (peak, maxone, ok) = measure_inner_decode(&blob);
            assert!(ok, "real message must decode: {label} at n={n}");
            let ml = min_limit(&blob).expect("real message decodes at some laddered limit");
            if ml > worst_limit {
                worst_limit = ml;
                worst_label = format!("{label} n={n} t={t}");
            }
            println!(
                "{:>3} {:<14} {:>9} {:>10} {:>10} {:>11} {:>7}",
                n,
                label,
                blob.len(),
                ml,
                peak,
                maxone,
                entries
            );
        }
    }
    println!(
        ">>> worst legitimate inner minLIMIT over the envelope: {worst_limit} B  ({worst_label})"
    );
    println!(
        ">>> vendored MAX_MESSAGE_ALLOC_SIZE = {} -> headroom {}x",
        1usize << 15,
        (1usize << 15) as f64 / worst_limit as f64
    );
}

// ---------------------------------------------------------------------------
// 2b. The other inner messages a device decodes. RequestSign is the only one
// that can rival keygen: agg_nonces is Vec<binonce::Nonce<Zero>>, 192 B in
// memory per 66 wire bytes, one per owned input.
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

fn share_index(i: u8) -> ShareIndex {
    let mut b = [0u8; 32];
    b[31] = i;
    Scalar::<Public, NonZero>::from_bytes(b).unwrap()
}

fn contrib() -> frostsnap_core::CoordShareDecryptionContrib {
    "0101010101010101010101010101010101010101010101010101010101010101"
        .parse()
        .unwrap()
}

#[test]
fn a2b_request_sign_inner_peak() {
    println!("\n=== A2b: RequestSign inner blobs (the other inner candidate) ===");
    println!(
        "{:>6} {:>7} {:>9} {:>8} {:>10} {:>10} {:>11}",
        "inputs", "parties", "blob B", "fits4091", "minLIMIT", "heapPeak", "maxSingle"
    );
    let master_appkey = MasterAppkey::derive_from_rootkey((*schnorr_fun::fun::G).normalize());
    // (owned inputs, signing parties). 12 parties is the n=12 envelope; 3 parties
    // is what a t=3 access structure sends, and it is 288 wire B cheaper, which is
    // what lets 20 owned inputs actually FIT FRAME_LIMIT.
    for (n_in, n_parties) in [
        (1usize, 12u8),
        (11, 12),
        (19, 12),
        (20, 12),
        (20, 3),
        (30, 3),
    ] {
        let mut tx = TransactionTemplate::new();
        for i in 0..n_in {
            tx.push_imaginary_owned_input(
                LocalSpk {
                    master_appkey,
                    bip32_path: BitcoinBip32Path::external(i as u32),
                },
                Amount::from_sat(100_000 + i as u64),
            );
        }
        tx.push_foreign_output(TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0u8; 22]),
        });
        let agg_nonces: Vec<binonce::Nonce<Zero>> = (0..n_in)
            .map(|i| {
                let s = real_segment(0x40u8.wrapping_add(i as u8), 1);
                binonce::Nonce::<Zero>::from_bytes(s.nonces[0].to_bytes()).unwrap()
            })
            .collect();
        let parties: BTreeSet<ShareIndex> = (1u8..=n_parties).map(share_index).collect();
        let req = RequestSign {
            group_sign_req: GroupSignReq {
                parties,
                agg_nonces,
                sign_task: WireSignTask::BitcoinTransaction(tx),
                access_structure_id: frostsnap_core::AccessStructureId([7u8; 32]),
            },
            device_sign_req: DeviceSignReq {
                nonces: CoordNonceStreamState {
                    stream_id: NonceStreamId([9u8; 16]),
                    index: 12345,
                    remaining: 17,
                },
                rootkey: (*schnorr_fun::fun::G).normalize(),
                coord_share_decryption_contrib: contrib(),
            },
        };
        let msg =
            CoordinatorToDeviceMessage::Signing(CoordinatorSigning::RequestSign(Box::new(req)));
        let blob = encaps_blob(&msg);
        let (peak, maxone, ok) = measure_inner_decode(&blob);
        assert!(ok, "real RequestSign must decode");
        let ml = min_limit(&blob).expect("decodes at some laddered limit");
        // The pin: every RequestSign that FRAME_LIMIT actually admits must still
        // decode under the candidate inner limit. 20 owned inputs at 3 parties is
        // the binding row -- it needs 5120, above FRAME_LIMIT itself.
        if blob.len() <= 4091 {
            assert!(
                ok_at::<CANDIDATE>(&blob),
                "reachable RequestSign ({n_in} in, {n_parties} parties, {} B) must \
                 decode under CANDIDATE={CANDIDATE}",
                blob.len()
            );
        }
        println!(
            "{:>6} {:>7} {:>9} {:>8} {:>10} {:>10} {:>11}",
            n_in,
            n_parties,
            blob.len(),
            blob.len() <= 4091,
            ml,
            peak,
            maxone
        );
    }
    println!(
        "NOTE only the rows whose blob fits FRAME_LIMIT-minus-envelope are reachable;\n\
         the rest are printed to show the slope."
    );
}

// ---------------------------------------------------------------------------
// 3. The hostile maximum, given the blob is already bounded by the outer 8192.
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

/// A real CertifyPlease blob truncated to just before `agg_input`, i.e. the
/// bytes `[CoordinatorSendBody::Core][KeyGen][CertifyPlease][keygen_id]`. Built
/// by subtraction from the real encoding rather than by hand-counting tags.
fn certify_prefix() -> Vec<u8> {
    let mut env = TestEnv::default();
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let run = Run::start_after_keygen(
        2,
        2,
        &mut env,
        &mut rng,
        KeyPurpose::Bitcoin(bitcoin::Network::Bitcoin),
    );
    for send in &run.transcript {
        if let common::Send::CoordinatorToDevice { message, .. } = send {
            if let CoordinatorToDeviceMessage::KeyGen(Keygen::CertifyPlease { agg_input, .. }) =
                message
            {
                let whole = encaps_blob(message);
                let agg = enc(agg_input);
                assert!(whole.ends_with(&agg), "agg_input is the trailing field");
                return whole[..whole.len() - agg.len()].to_vec();
            }
        }
    }
    panic!("no CertifyPlease in transcript");
}

fn hostile_at<const N: usize>(prefix: &[u8], elem_size: usize) -> (usize, usize, usize, String) {
    // Largest container length whose claim `len * size_of::<T>()` still fits N.
    let len = N / elem_size;
    let mut blob = prefix.to_vec();
    blob.extend_from_slice(&varint(len));
    let base = CUR.load(Relaxed);
    WPEAK.store(base, Relaxed);
    WMAXONE.store(0, Relaxed);
    let cfg = bincode::config::standard().with_limit::<N>();
    let err = match bincode::decode_from_slice::<CoordinatorSendBody, _>(&blob, cfg) {
        Ok(_) => "Ok(!)".to_string(),
        Err(e) => format!("{e:?}"),
    };
    let peak = WPEAK.load(Relaxed).saturating_sub(base);
    (blob.len(), peak, WMAXONE.load(Relaxed), err)
}

#[test]
fn a3_hostile_inner_maximum() {
    use core::mem::size_of;
    use schnorr_fun::Signature;
    let elem = size_of::<(Point<Normal, Public, NonZero>, Signature)>();
    let prefix = certify_prefix();
    println!("\n=== A3: hostile inner blob, key_contrib: Vec<(Point, Signature)> ===");
    println!(
        "prefix (tags + keygen_id) = {} B; size_of::<(Point,Signature)>() = {elem} B",
        prefix.len()
    );
    println!(
        "{:>9} {:>8} {:>8} {:>10} {:>11}  {}",
        "LIMIT", "claimLen", "blob B", "heapPeak", "maxSingle", "error"
    );
    let rows = [
        hostile_at::<32768>(&prefix, elem),
        hostile_at::<16384>(&prefix, elem),
        hostile_at::<8192>(&prefix, elem),
        hostile_at::<4096>(&prefix, elem),
    ];
    for (limit, (blob, peak, maxone, err)) in [32768usize, 16384, 8192, 4096].iter().zip(rows.iter())
    {
        println!(
            "{:>9} {:>8} {:>8} {:>10} {:>11}  {}",
            limit,
            limit / elem,
            blob,
            peak,
            maxone,
            err
        );
    }
    println!(
        "\n>>> The hostile ceiling tracks the LIMIT, not the wire bytes: a ~{}-byte\n\
         blob (well under the outer DECODE_ALLOC_LIMIT of 8192) reaches it, because\n\
         `Vec<T>` decode does `Vec::with_capacity(len)` right after the claim\n\
         (bincode-2.0.1 impl_alloc.rs:274-276). Lowering the inner LIMIT lowers this\n\
         ceiling 1:1.",
        prefix.len() + 3
    );
}

// ---------------------------------------------------------------------------
// 4. The verdict, as an executable check: the candidate limit must pass every
// real message and must still refuse the hostile blob's amplification.
// ---------------------------------------------------------------------------
const CANDIDATE: usize = 8192;

#[test]
fn a4_candidate_limit_passes_every_real_message() {
    println!("\n=== A4: does CANDIDATE = {CANDIDATE} pass every real inner blob? ===");
    let mut worst = 0usize;
    for n in [2usize, 5, 9, 12] {
        for (label, blob, _) in keygen_inner_blobs(n, n as u16) {
            let ok = ok_at::<CANDIDATE>(&blob);
            println!(
                "  n={n:>2} {label:<14} blob {:>5} B  decodes at {CANDIDATE}: {ok}",
                blob.len()
            );
            assert!(ok, "{label} at n={n} must decode under the candidate limit");
            worst = worst.max(blob.len());
        }
    }
    println!("  largest real keygen inner blob: {worst} B");
    // The structural floor: bincode's counter ends at the total bytes consumed,
    // so ANY candidate must exceed the largest legitimate inner blob length,
    // which is itself bounded by FRAME_LIMIT = 4096.
    assert!(CANDIDATE > worst);
}

// ---------------------------------------------------------------------------
// 5. The discriminating case: a blob that FILLS the transport's FRAME_LIMIT with
// the worst-amplifying container. This is what a candidate limit would refuse,
// and it is the inner-leg analogue of the outer leg's
// `a_limit_sized_frame_of_device_ids_still_decodes_under_the_new_limit`.
//
// The bytes are junk after the length varint, so decoding always fails; the
// question is WHICH error. `LimitExceeded` means the limit refused the claim
// before allocating. Anything else means the claim was allowed through.
// ---------------------------------------------------------------------------
fn fill_at<const N: usize>(prefix: &[u8], wire_per_elem: usize) -> (usize, usize, usize, String) {
    // Longest container that still fits a FRAME_LIMIT-sized frame: 4096 minus
    // the minimum outer envelope (ReceiveSerial tag + Destination::All +
    // WireCoordinatorSendBody tag + EncapsBody length varint = 5 B).
    let room = 4096 - 5 - prefix.len() - 3;
    let len = room / wire_per_elem;
    let mut blob = prefix.to_vec();
    blob.extend_from_slice(&varint(len));
    blob.extend_from_slice(&vec![0x02u8; len * wire_per_elem]);
    let base = CUR.load(Relaxed);
    WPEAK.store(base, Relaxed);
    WMAXONE.store(0, Relaxed);
    let cfg = bincode::config::standard().with_limit::<N>();
    let err = match bincode::decode_from_slice::<CoordinatorSendBody, _>(&blob, cfg) {
        Ok(_) => "Ok(!)".to_string(),
        Err(e) => format!("{e:?}"),
    };
    let peak = WPEAK.load(Relaxed).saturating_sub(base);
    (blob.len(), peak, WMAXONE.load(Relaxed), err)
}

#[test]
fn a5_what_a_lower_limit_would_refuse() {
    use core::mem::size_of;
    use schnorr_fun::Signature;
    let elem = size_of::<(Point<Normal, Public, NonZero>, Signature)>();
    let prefix = certify_prefix();
    let wire_per_elem = 97; // 33 B Point + 64 B Signature, measured in a1
    let room = 4096 - 5 - prefix.len() - 3;
    let len = room / wire_per_elem;
    println!("\n=== A5: a FRAME_LIMIT-filling key_contrib: Vec<(Point, Signature)> ===");
    println!(
        "len = {len} entries ({} wire B), claim = {len} * {elem} = {} B",
        len * wire_per_elem,
        len * elem
    );
    println!(
        "{:>9} {:>8} {:>10} {:>11}  {}",
        "LIMIT", "blob B", "heapPeak", "maxSingle", "error"
    );
    let limits = [32768usize, 24576, 16384, 12288, 8192, 4096];
    let rows = [
        fill_at::<32768>(&prefix, wire_per_elem),
        fill_at::<24576>(&prefix, wire_per_elem),
        fill_at::<16384>(&prefix, wire_per_elem),
        fill_at::<12288>(&prefix, wire_per_elem),
        fill_at::<8192>(&prefix, wire_per_elem),
        fill_at::<4096>(&prefix, wire_per_elem),
    ];
    for (limit, (blob, peak, maxone, err)) in limits.iter().zip(rows.iter()) {
        println!(
            "{:>9} {:>8} {:>10} {:>11}  {}",
            limit, blob, peak, maxone, err
        );
    }
    println!(
        ">>> A {len}-contributor keygen is FAR outside the declared envelope (n <= 12),\n\
         so a limit that refuses this row refuses nothing reachable. The row exists to\n\
         locate the boundary, and to show what the WORST well-formed frame the\n\
         transport admits can claim."
    );
}

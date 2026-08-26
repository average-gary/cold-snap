// Adversarial measurement: how big do real Frostsnap wire messages get, vs Coldcard MAX_MSG_LEN=2060
//
// CORRECTION 2026-08-19: the 2,060 in the title is NO LONGER THE BOUND. DECISIONS.md 7
// reversed FRAME_LIMIT to 4,096 precisely because this file's own numbers showed 2,060
// refusing four real messages, and 2,060's provenance is Coldcard's HID reassembly
// buffer rather than this transport (PLAN.md section 7). The MEASUREMENTS below stand;
// only the comparison target is obsolete. Read every "over by N" against 4,096.
//
// CORRECTION 2026-08-14 (phase 3). Every line this file used to label "FULL
// WIRE" was the message BODY only -- a `WireCoordinatorSendBody` /
// `WireDeviceSendBody`. Nothing ever puts a bare body on the wire: the framing
// is `ReceiveSerial<D>`, which adds a variant tag plus, in each direction, the
// envelope (`Destination` upstream, `DeviceId` downstream). PLAN.md §7's table
// was built from the mislabelled figures and so understated every message. The
// `up`/`down` helpers below wrap the body the way `coldsnap_hal::comms` does, so
// what this prints is what `Link::poll` must buffer and `encode_frame` must fit.
//
// HOW TO RUN. It needs `mod common`, which lives in the vendored tests dir, so
// copy it back in for the duration and delete it afterwards — it must not stay
// there, because 26 unresolved imports would break `cargo test -p frostsnap_core`
// wholesale rather than skipping this one target (see ../../vendor/README.md):
//
//   cp tools/research-scratch/wire_size_measure.rs \
//      vendor/frostsnap/frostsnap_core/tests/
//   cargo test --target aarch64-apple-darwin -p frostsnap_core \
//     --features coordinator --test wire_size_measure -- --nocapture --test-threads=1
//   rm vendor/frostsnap/frostsnap_core/tests/wire_size_measure.rs
//
// There are ELEVEN tests now, TEN of them ungated (four signing/nonce/keygen ones, the phase-3
// sweep: measure_keygen_threshold_grid, measure_restoration_and_screen_verify,
// measure_small_and_string_variants, and the 2026-08-18 nonce-segment-cap pair:
// nonce_response_split_per_segment_is_accepted +
// nonce_response_segment_count_per_replenish).
// All the ones that use `Run`/`TestEnv` need `mod common` and `mod env` from that
// same vendored tests dir, which is the other reason this file cannot live
// outside it. To run one, append its name to the command above.
//
// The eleventh, `measure_nostr_sign_task`, is `#[cfg(feature = "serde_json")]`
// because `UnsignedEvent::new` is feature-gated. Run it with
// `--features coordinator,serde_json`.
//
// `--test-threads=1` matters: the tests interleave their `println!`s
// otherwise, which is how the first reading of this output lost half its rows.
// The `frostsnap_comms` dev-dependency it needs is already declared in
// `frostsnap_core/Cargo.toml` (a dev-dep cycle, which Cargo permits).
mod common;

use bitcoin::{Amount, ScriptBuf, TxOut};
use common::TestDeviceKeyGen;
use frostsnap_comms::{
    CoordinatorSendMessage, Destination, DeviceSendMessage, Downstream, ReceiveSerial, Upstream,
    WireCoordinatorSendBody, WireDeviceSendBody, BINCODE_CONFIG,
};
use frostsnap_core::DeviceId;
use frostsnap_core::bitcoin_transaction::{LocalSpk, TransactionTemplate};
use frostsnap_core::device_nonces::{NonceJobBatch, RatchetSeedMaterial, SecretNonceSlot};
use frostsnap_core::message::signing::{CoordinatorSigning, DeviceSigning, OpenNonceStreams};
use frostsnap_core::message::{
    CoordinatorToDeviceMessage, DeviceSignReq, DeviceToCoordinatorMessage, GroupSignReq,
    RequestSign,
};
use frostsnap_core::nonce_stream::{CoordNonceStreamState, NonceStreamId, NonceStreamSegment};
use frostsnap_core::tweak::BitcoinBip32Path;
use frostsnap_core::{MasterAppkey, WireSignTask};
use schnorr_fun::binonce;
use schnorr_fun::frost::ShareIndex;
use schnorr_fun::fun::prelude::*;
use std::collections::BTreeSet;

const COLDCARD_MAX_MSG_LEN: usize = 2060;

fn enc<T: bincode::Encode>(v: &T) -> usize {
    bincode::encode_to_vec(v, BINCODE_CONFIG)
        .expect("encode works")
        .len()
}

/// The device under test, for the `DeviceId` in every outbound envelope. Any 33
/// bytes measure the same; the value is irrelevant, the 33 bytes are not.
fn this_device() -> DeviceId {
    DeviceId::new((*schnorr_fun::fun::G).normalize())
}

/// Coordinator -> device, as `coldsnap_hal::comms::Link::poll` receives it.
///
/// `Destination::Particular([one device])` rather than `Destination::All`: a
/// targeted RequestSign is what a coordinator actually sends, and it is the
/// larger of the two encodings, so this is the bound rather than the best case.
fn up(body: WireCoordinatorSendBody) -> usize {
    enc(&ReceiveSerial::<Upstream>::Message(CoordinatorSendMessage {
        target_destinations: Destination::Particular([this_device()].into()),
        message_body: body,
    }))
}

/// Device -> coordinator, as `coldsnap_hal::comms::encode_frame` must fit it.
fn down(body: WireDeviceSendBody) -> usize {
    enc(&ReceiveSerial::<Downstream>::Message(DeviceSendMessage {
        from: this_device(),
        body,
    }))
}

fn report(label: &str, n: usize) {
    println!(
        "{:<64} {:>7} B  {}",
        label,
        n,
        if n > COLDCARD_MAX_MSG_LEN {
            format!("*** OVER 2060 by {} ***", n - COLDCARD_MAX_MSG_LEN)
        } else {
            format!("fits ({} spare)", COLDCARD_MAX_MSG_LEN - n)
        }
    );
}

/// Build one real segment of `n` nonces via the actual device nonce generator.
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

#[test]
fn measure_wire_sizes_vs_coldcard_max_msg_len() {
    println!("\n=== Coldcard MAX_MSG_LEN = {COLDCARD_MAX_MSG_LEN} ===\n");

    // ---------- sanity: single nonce ----------
    let one = real_segment(1, 1);
    report("bare binonce::Nonce (1 nonce)", enc(&one.nonces[0]));

    // ---------- (a) OpenNonceStreams, coordinator -> device ----------
    let streams: Vec<CoordNonceStreamState> = (0..4)
        .map(|i| CoordNonceStreamState {
            stream_id: NonceStreamId([i as u8; 16]),
            index: 0,
            remaining: 0,
        })
        .collect();
    let ons4 = OpenNonceStreams {
        streams: streams.clone(),
    };
    report("OpenNonceStreams{4 streams} (raw struct)", enc(&ons4));
    let c2d4 =
        CoordinatorToDeviceMessage::Signing(CoordinatorSigning::OpenNonceStreams(ons4.clone()));
    report("C2D::Signing(OpenNonceStreams x4)", enc(&c2d4));
    let wire4: frostsnap_comms::WireCoordinatorSendBody =
        frostsnap_comms::CoordinatorSendBody::Core(c2d4).into();
    report("FULL WIRE: OpenNonceStreams x4 (EncapsV0)", up(wire4));

    // worst plausible: index/remaining near u32::MAX (varint blowup)
    let big_streams: Vec<CoordNonceStreamState> = (0..4)
        .map(|i| CoordNonceStreamState {
            stream_id: NonceStreamId([i as u8; 16]),
            index: u32::MAX - 1,
            remaining: u32::MAX - 1,
        })
        .collect();
    report(
        "FULL WIRE: OpenNonceStreams x4, max varints",
        up(
            frostsnap_comms::CoordinatorSendBody::Core(CoordinatorToDeviceMessage::Signing(
                CoordinatorSigning::OpenNonceStreams(OpenNonceStreams {
                    streams: big_streams,
                }),
            ))
            .into(),
        ),
    );

    // how many streams would it take to blow 2060 on OpenNonceStreams?
    for n in [4usize, 32, 64, 85, 86, 128] {
        let s: Vec<CoordNonceStreamState> = (0..n)
            .map(|i| CoordNonceStreamState {
                stream_id: NonceStreamId([(i % 256) as u8; 16]),
                index: u32::MAX - 1,
                remaining: u32::MAX - 1,
            })
            .collect();
        report(
            &format!("FULL WIRE: OpenNonceStreams x{n} (max varints)"),
            up(
                frostsnap_comms::CoordinatorSendBody::Core(CoordinatorToDeviceMessage::Signing(
                    CoordinatorSigning::OpenNonceStreams(OpenNonceStreams { streams: s }),
                ))
                .into(),
            ),
        );
    }

    // each element of split()
    for (i, part) in ons4.clone().split().into_iter().enumerate() {
        report(
            &format!("split()[{i}] FULL WIRE"),
            up(
                frostsnap_comms::CoordinatorSendBody::Core(CoordinatorToDeviceMessage::Signing(
                    CoordinatorSigning::OpenNonceStreams(part),
                ))
                .into(),
            ),
        );
    }

    println!();

    // ---------- (b) DeviceSigning::NonceResponse ----------
    for n_streams in [1usize, 2, 3, 4] {
        let segments: Vec<NonceStreamSegment> = (0..n_streams)
            .map(|i| real_segment(0x10 + i as u8, 30))
            .collect();
        let total_nonces: usize = segments.iter().map(|s| s.nonces.len()).sum();
        let msg: DeviceToCoordinatorMessage = DeviceSigning::NonceResponse { segments }.into();
        let raw = enc(&msg);
        let w: frostsnap_comms::WireDeviceSendBody =
            frostsnap_comms::DeviceSendBody::Core(msg).into();
        report(
            &format!("D2C NonceResponse {n_streams}x30 = {total_nonces} nonces (core only)"),
            raw,
        );
        report(
            &format!("  -> FULL WIRE NonceResponse {n_streams}x30"),
            down(w),
        );
    }

    // find the exact nonce count where a 1-segment NonceResponse crosses 2060
    println!();
    let mut crossover = None;
    for n in 1..=40usize {
        let seg = real_segment(0x60, n);
        let msg: DeviceToCoordinatorMessage = DeviceSigning::NonceResponse {
            segments: vec![seg],
        }
        .into();
        let w: frostsnap_comms::WireDeviceSendBody =
            frostsnap_comms::DeviceSendBody::Core(msg).into();
        let sz = down(w);
        if sz > COLDCARD_MAX_MSG_LEN && crossover.is_none() {
            crossover = Some((n, sz));
        }
    }
    match crossover {
        Some((n, sz)) => println!(
            ">>> A SINGLE 1-segment NonceResponse exceeds 2060 at n={n} nonces ({sz} B). \
             NONCE_BATCH_SIZE=30 => a full batch DOES overflow.",
        ),
        None => println!(">>> Even 40 nonces in 1 segment fits under 2060"),
    }
    println!();

    // ---------- (c) GroupSignReq with realistic multi-input tx ----------
    let master_appkey = MasterAppkey::derive_from_rootkey((*schnorr_fun::fun::G).normalize());
    for (n_in, n_out) in [(1usize, 2usize), (5, 2), (10, 3), (20, 3), (50, 3)] {
        let mut tx = TransactionTemplate::new();
        for i in 0..n_in {
            let owner = LocalSpk {
                master_appkey,
                bip32_path: BitcoinBip32Path::external(i as u32),
            };
            tx.push_imaginary_owned_input(owner, Amount::from_sat(100_000 + i as u64));
        }
        for j in 0..n_out {
            let spk = ScriptBuf::from_bytes(vec![j as u8; 22]);
            tx.push_foreign_output(TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: spk,
            });
        }
        let agg_nonces: Vec<binonce::Nonce<Zero>> = (0..n_in)
            .map(|i| {
                let s = real_segment(0x40u8.wrapping_add(i as u8), 1);
                binonce::Nonce::<Zero>::from_bytes(s.nonces[0].to_bytes()).unwrap()
            })
            .collect();
        let parties: BTreeSet<ShareIndex> = (1u8..=3).map(share_index).collect();
        let gsr = GroupSignReq {
            parties,
            agg_nonces,
            sign_task: WireSignTask::BitcoinTransaction(tx),
            access_structure_id: frostsnap_core::AccessStructureId([7u8; 32]),
        };
        report(
            &format!("GroupSignReq: {n_in} owned inputs, {n_out} outputs, 3 parties"),
            enc(&gsr),
        );

        let req = RequestSign {
            group_sign_req: gsr,
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
        let full =
            CoordinatorToDeviceMessage::Signing(CoordinatorSigning::RequestSign(Box::new(req)));
        let wire: frostsnap_comms::WireCoordinatorSendBody =
            frostsnap_comms::CoordinatorSendBody::Core(full).into();
        report(
            &format!("  -> FULL WIRE RequestSign ({n_in} in, {n_out} out)"),
            up(wire),
        );
    }
    println!();

    // ---------- signing_req_sub_segment ----------
    let seg30 = real_segment(0x50, 30);
    for take in [1usize, 5, 10, 20, 30] {
        let sub = seg30.signing_req_sub_segment(take).unwrap();
        report(
            &format!("SigningReqSubSegment take {take} of 30 (raw)"),
            enc(&sub),
        );
    }
    println!();

    // ---------- SignatureShare device -> coordinator ----------
    for (n_sigs, replenish) in [
        (1usize, false),
        (10, false),
        (20, false),
        (1, true),
        (20, true),
    ] {
        let shares: Vec<schnorr_fun::frost::SignatureShare> = (0..n_sigs)
            .map(|i| share_index((i + 1) as u8).mark_zero())
            .collect();
        let msg: DeviceToCoordinatorMessage = DeviceSigning::SignatureShare {
            session_id: frostsnap_core::SignSessionId([3u8; 32]),
            signature_shares: shares,
            replenish_nonces: if replenish {
                Some(real_segment(0x70, 30))
            } else {
                None
            },
        }
        .into();
        let w: frostsnap_comms::WireDeviceSendBody =
            frostsnap_comms::DeviceSendBody::Core(msg).into();
        report(
            &format!(
                "FULL WIRE SignatureShare: {n_sigs} shares, replenish={}",
                if replenish { "Some(30 nonces)" } else { "None" }
            ),
            down(w),
        );
    }
}

fn contrib() -> frostsnap_core::CoordShareDecryptionContrib {
    // parse from hex via the FromStr impl generated by impl_fromstr_deserialize!
    "0101010101010101010101010101010101010101010101010101010101010101"
        .parse()
        .unwrap()
}

#[test]
fn exact_requestsign_crossover() {
    let master_appkey = MasterAppkey::derive_from_rootkey((*schnorr_fun::fun::G).normalize());
    println!("\n=== exact RequestSign crossover (1 output, most generous) vs 2060 ===");
    let mut first_over = None;
    for n_in in 1..=30usize {
        let mut tx = TransactionTemplate::new();
        for i in 0..n_in {
            let owner = LocalSpk {
                master_appkey,
                bip32_path: BitcoinBip32Path::external(i as u32),
            };
            tx.push_imaginary_owned_input(owner, Amount::from_sat(100_000));
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
        let parties: BTreeSet<ShareIndex> = (1u8..=2).map(share_index).collect();
        let gsr = GroupSignReq {
            parties,
            agg_nonces,
            sign_task: WireSignTask::BitcoinTransaction(tx),
            access_structure_id: frostsnap_core::AccessStructureId([7u8; 32]),
        };
        let req = RequestSign {
            group_sign_req: gsr,
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
        let wire: frostsnap_comms::WireCoordinatorSendBody =
            frostsnap_comms::CoordinatorSendBody::Core(CoordinatorToDeviceMessage::Signing(
                CoordinatorSigning::RequestSign(Box::new(req)),
            ))
            .into();
        let sz = up(wire);
        let hid_pkts = (sz + 62) / 63;
        println!(
            "{:>3} inputs, 1 output: {:>6} B  ({:>3} HID pkts)  {}",
            n_in,
            sz,
            hid_pkts,
            if sz > 2060 { "OVER" } else { "fits" }
        );
        if sz > 2060 && first_over.is_none() {
            first_over = Some((n_in, sz));
        }
    }
    match first_over {
        Some((n, sz)) => println!("\n>>> RequestSign EXCEEDS Coldcard MAX_MSG_LEN=2060 at {n} inputs ({sz} B). Device receive buffer cannot hold it."),
        None => println!("\n>>> 30 inputs still fits"),
    }
}

#[test]
fn margin_robustness_1segment() {
    println!("\n=== 1-segment NonceResponse: is the 54-byte margin robust? ===");
    for idx in [0u32, 127, 128, 65535, 1 << 20, u32::MAX - 100] {
        let mut seg = real_segment(0x80, 30);
        seg.index = idx;
        let msg: DeviceToCoordinatorMessage = DeviceSigning::NonceResponse {
            segments: vec![seg],
        }
        .into();
        let w: frostsnap_comms::WireDeviceSendBody =
            frostsnap_comms::DeviceSendBody::Core(msg).into();
        let sz = down(w);
        println!(
            "  index={:>12}  FULL WIRE = {:>5} B   {}",
            idx,
            sz,
            if sz > 2060 {
                "*** OVER 2060 ***"
            } else {
                "fits"
            }
        );
    }
    // and SignatureShare + replenish, which IS a single logical message
    let mut seg = real_segment(0x81, 30);
    seg.index = u32::MAX - 100;
    let msg: DeviceToCoordinatorMessage = DeviceSigning::SignatureShare {
        session_id: frostsnap_core::SignSessionId([3u8; 32]),
        signature_shares: vec![share_index(1).mark_zero()],
        replenish_nonces: Some(seg),
    }
    .into();
    let w: frostsnap_comms::WireDeviceSendBody = frostsnap_comms::DeviceSendBody::Core(msg).into();
    let sz = down(w);
    println!(
        "  SignatureShare{{1 share + Some(30 nonces)}} = {} B  {}",
        sz,
        if sz > 2060 {
            "*** OVER 2060 ***"
        } else {
            "fits"
        }
    );
}

// ---------------------------------------------------------------------------
// KEYGEN. Added 2026-08-18, because every figure above is signing or nonces and
// PLAN.md §7 therefore said nothing about whether keygen fits. If a keygen frame
// exceeds 2,060 then the ceiling bites at phase-4 milestone 4, not milestone 6,
// and the FRAME_LIMIT number has to cover it.
//
// These are not hand-built: `AggKeygenInput` and `KeyGenResponse` are real crypto
// objects whose size is the point, so a fabricated one would measure nothing. This
// drives the vendored Tier-2 harness through a REAL keygen at several (n, t) and
// measures every message it actually put on the queue, wrapped in the real
// `ReceiveSerial` envelope with the REAL destination set.
// ---------------------------------------------------------------------------

mod env;

use crate::common::Run;
use crate::env::TestEnv;
use frostsnap_core::device::KeyPurpose;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// Coordinator -> device carrying the destination set the coordinator really used.
/// This matters: `Destination::Particular` costs 1 + 1 + 33·n, so a keygen
/// broadcast to 7 devices carries 233 bytes of envelope, not the 36 a
/// single-destination signing message carries.
fn up_to(dests: &BTreeSet<DeviceId>, body: WireCoordinatorSendBody) -> usize {
    enc(&ReceiveSerial::<Upstream>::Message(CoordinatorSendMessage {
        target_destinations: Destination::Particular(dests.clone()),
        message_body: body,
    }))
}

#[test]
fn measure_keygen_wire_sizes_vs_coldcard_max_msg_len() {
    println!("\n=== KEYGEN, real messages from a real keygen, vs 2060 ===");
    println!("Crossover is between 9 and 10 devices; 9 fits by only 13 B.\n");

    let mut worst = 0usize;
    let mut worst_label = String::new();

    for (n, t) in [(2usize, 2u16), (3, 2), (5, 3), (7, 4), (9, 5), (10, 5), (11, 6)] {
        let mut env = TestEnv::default();
        let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
        let run = Run::start_after_keygen(n, t, &mut env, &mut rng, KeyPurpose::Bitcoin(bitcoin::Network::Bitcoin));

        println!("--- {n} devices, threshold {t} ---");
        for send in &run.transcript {
            let (label, size) = match send {
                common::Send::CoordinatorToDevice {
                    destinations,
                    message,
                } => {
                    let kind = format!("C2D {message:?}");
                    let wire: WireCoordinatorSendBody =
                        frostsnap_comms::CoordinatorSendBody::Core(message.clone()).into();
                    (
                        format!(
                            "{} -> {} dest",
                            kind.chars().take(46).collect::<String>(),
                            destinations.len()
                        ),
                        up_to(destinations, wire),
                    )
                }
                common::Send::DeviceToCoordinator { from, message } => {
                    let kind = format!("D2C {message:?}");
                    let wire: WireDeviceSendBody =
                        frostsnap_comms::DeviceSendBody::Core(message.clone()).into();
                    (
                        kind.chars().take(58).collect::<String>(),
                        enc(&ReceiveSerial::<Downstream>::Message(DeviceSendMessage {
                            from: *from,
                            body: wire,
                        })),
                    )
                }
                // User-facing messages never touch the wire.
                _ => continue,
            };
            report(&label, size);
            if size > worst {
                worst = size;
                worst_label = format!("{n}-of-{t}: {label}");
            }
        }
        println!();
    }

    println!(">>> WORST KEYGEN FRAME: {worst} B  ({worst_label})");
    if worst > COLDCARD_MAX_MSG_LEN {
        println!(
            ">>> KEYGEN EXCEEDS 2060 by {}. The ceiling bites at phase-4 M4, not M6.",
            worst - COLDCARD_MAX_MSG_LEN
        );
    } else {
        println!(
            ">>> keygen fits with {} B spare at worst.",
            COLDCARD_MAX_MSG_LEN - worst
        );
    }
}

// ===========================================================================
// PHASE-3 FULL SWEEP, added 2026-08-18. Everything below is new; the tests
// above stay as-is. Three jobs:
//   * measure_keygen_threshold_grid          -- isolate n from t (job 1)
//   * measure_restoration_and_screen_verify  -- real SharedKey/ShareImage (job 2)
//   * measure_small_and_string_variants      -- plain structs + crossovers (job 2/3)
//   * measure_nostr_sign_task                -- needs --features serde_json
// Every number is a FULL `ReceiveSerial<D>` frame, and every coordinator->device
// broadcast carries the REAL destination set (Destination::Particular = 33n+2).
// ===========================================================================

use frostsnap_comms::fixed_string::DeviceName;
use frostsnap_comms::{
    CommsMisc, CoordinatorSendBody, CoordinatorUpgradeMessage, DeviceSendBody, GenuineChallenge,
    MagicBytes, NameCommand, Sha256Digest,
};
use frostsnap_core::coordinator::CoordinatorSend;
use frostsnap_core::message::keygen::{DeviceKeygen, Keygen};
use frostsnap_core::message::screen_verify::ScreenVerify;
use frostsnap_core::message::{
    ConsolidateBackup, CoordinatorRestoration, DeviceRestoration, EnteredPhysicalBackup, HeldShare,
    HeldShare2,
};
use common::TEST_ENCRYPTION_KEY;
use frostsnap_core::{AccessStructureId, AccessStructureRef, EnterPhysicalId, KeyId};
use schnorr_fun::frost::ShareImage;
use schnorr_fun::frost::SharedKey;
use std::collections::BTreeMap;

fn dests(n: usize) -> BTreeSet<DeviceId> {
    (1u8..=(n as u8))
        .map(|i| {
            let mut b = [0u8; 32];
            b[31] = i;
            let s = Scalar::<Secret, NonZero>::from_bytes(b).unwrap();
            DeviceId::new(g!(s * G).normalize())
        })
        .collect()
}

fn up_core(d: &BTreeSet<DeviceId>, m: CoordinatorToDeviceMessage) -> usize {
    up_to(d, CoordinatorSendBody::Core(m).into())
}

fn up_body(d: &BTreeSet<DeviceId>, b: CoordinatorSendBody) -> usize {
    up_to(d, b.into())
}

fn down_from(from: DeviceId, body: WireDeviceSendBody) -> usize {
    enc(&ReceiveSerial::<Downstream>::Message(DeviceSendMessage {
        from,
        body,
    }))
}

fn down_body(b: DeviceSendBody) -> usize {
    down(b.into())
}

fn down_core(m: DeviceToCoordinatorMessage) -> usize {
    down(DeviceSendBody::Core(m).into())
}

/// A `SharedKey` whose polynomial has exactly `t` coefficients. The coefficients
/// are real curve points (G repeated); only the COUNT drives the encoding, and
/// the test below cross-checks one of these against a SharedKey from a real
/// keygen at the same t.
fn poly_shared_key(t: usize) -> SharedKey {
    let poly: Vec<Point<Normal, Public, Zero>> = (0..t)
        .map(|_| (*schnorr_fun::fun::G).normalize().mark_zero())
        .collect();
    SharedKey::from_poly(poly).non_zero().unwrap()
}

fn asr_dummy() -> AccessStructureRef {
    AccessStructureRef {
        key_id: KeyId([0xffu8; 32]),
        access_structure_id: AccessStructureId([0xffu8; 32]),
    }
}

// ---------------------------------------------------------------------------
// JOB 1: hold n fixed, sweep t. The old keygen test moved n and t together, so
// t's 33 B/step never showed up separately from n's ~211 B/device.
// ---------------------------------------------------------------------------

/// Run one REAL keygen and return the largest full frame per message kind.
fn keygen_frame_sizes(n: usize, t: u16) -> BTreeMap<&'static str, usize> {
    let mut env = TestEnv::default();
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let run = Run::start_after_keygen(
        n,
        t,
        &mut env,
        &mut rng,
        KeyPurpose::Bitcoin(bitcoin::Network::Bitcoin),
    );
    let mut max: BTreeMap<&'static str, usize> = BTreeMap::new();
    for send in &run.transcript {
        let (label, size) = match send {
            common::Send::CoordinatorToDevice {
                destinations,
                message,
            } => {
                let label = match message {
                    CoordinatorToDeviceMessage::KeyGen(Keygen::Begin(_)) => "Begin",
                    CoordinatorToDeviceMessage::KeyGen(Keygen::CertifyPlease { .. }) => "CertifyPlz",
                    CoordinatorToDeviceMessage::KeyGen(Keygen::Check { .. }) => "Check",
                    CoordinatorToDeviceMessage::KeyGen(Keygen::Finalize { .. }) => "Finalize",
                    _ => continue,
                };
                (label, up_core(destinations, message.clone()))
            }
            common::Send::DeviceToCoordinator { from, message } => {
                let label = match message {
                    DeviceToCoordinatorMessage::KeyGen(DeviceKeygen::Response(_)) => "Response",
                    DeviceToCoordinatorMessage::KeyGen(DeviceKeygen::Certify { .. }) => "Certify",
                    DeviceToCoordinatorMessage::KeyGen(DeviceKeygen::Ack(_)) => "Ack",
                    _ => continue,
                };
                (
                    label,
                    down_from(*from, DeviceSendBody::Core(message.clone()).into()),
                )
            }
            _ => continue,
        };
        let e = max.entry(label).or_default();
        *e = (*e).max(size);
    }
    max
}

#[test]
fn measure_keygen_threshold_grid() {
    println!("\n=== JOB 1: n x t grid, real keygens, FULL frames (real destination sets) ===");
    let mut grid: BTreeMap<(usize, u16), BTreeMap<&'static str, usize>> = BTreeMap::new();
    for n in [5usize, 7, 9] {
        for t in 2..=(n as u16) {
            grid.insert((n, t), keygen_frame_sizes(n, t));
        }
    }
    let get = |g: &BTreeMap<&'static str, usize>, k: &str| g.get(k).copied().unwrap_or(0);

    println!(
        "{:>3} {:>3} | {:>7} {:>8} {:>7} {:>8} | {:>8} {:>7} {:>5}",
        "n", "t", "Begin", "CertifyPlz", "Check", "Finalize", "Response", "Certify", "Ack"
    );
    for ((n, t), m) in &grid {
        println!(
            "{:>3} {:>3} | {:>7} {:>8}{} {:>7} {:>8} | {:>8} {:>7} {:>5}",
            n,
            t,
            get(m, "Begin"),
            get(m, "CertifyPlz"),
            if get(m, "CertifyPlz") > COLDCARD_MAX_MSG_LEN {
                "*"
            } else {
                " "
            },
            get(m, "Check"),
            get(m, "Finalize"),
            get(m, "Response"),
            get(m, "Certify"),
            get(m, "Ack"),
        );
    }

    println!("\n-- t-step at fixed n (bytes added by threshold+1) --");
    for n in [5usize, 7, 9] {
        for t in 2..(n as u16) {
            let a = get(&grid[&(n, t)], "CertifyPlz");
            let b = get(&grid[&(n, t + 1)], "CertifyPlz");
            let ra = get(&grid[&(n, t)], "Response");
            let rb = get(&grid[&(n, t + 1)], "Response");
            println!(
                "  n={n}: t={t}->{}: CertifyPlease {a} -> {b} (+{})   Response {ra} -> {rb} (+{})",
                t + 1,
                b as i64 - a as i64,
                rb as i64 - ra as i64
            );
        }
    }

    println!("\n-- n-step at fixed t (bytes added per extra device, /2 since n goes 5->7->9) --");
    for t in 2..=5u16 {
        let a = get(&grid[&(5, t)], "CertifyPlz");
        let b = get(&grid[&(7, t)], "CertifyPlz");
        let c = get(&grid[&(9, t)], "CertifyPlz");
        println!(
            "  t={t}: CertifyPlease n=5 {a}, n=7 {b}, n=9 {c}  => {:.1} B/device (5->7), {:.1} (7->9)",
            (b as f64 - a as f64) / 2.0,
            (c as f64 - b as f64) / 2.0
        );
        let a = get(&grid[&(5, t)], "Check");
        let b = get(&grid[&(7, t)], "Check");
        let c = get(&grid[&(9, t)], "Check");
        println!(
            "       Check         n=5 {a}, n=7 {b}, n=9 {c}  => {:.1} B/device (5->7), {:.1} (7->9)",
            (b as f64 - a as f64) / 2.0,
            (c as f64 - b as f64) / 2.0
        );
    }

    println!("\n-- worst cell per n, and is it t=n? --");
    for n in [5usize, 7, 9] {
        let (bt, bs) = (2..=(n as u16))
            .map(|t| (t, get(&grid[&(n, t)], "CertifyPlz")))
            .max_by_key(|(_, s)| *s)
            .unwrap();
        println!(
            "  n={n}: worst CertifyPlease {bs} B at t={bt}  (t==n? {})",
            bt as usize == n
        );
    }
    let worst = grid
        .iter()
        .flat_map(|((n, t), m)| m.iter().map(move |(k, v)| (*v, *n, *t, *k)))
        .max()
        .unwrap();
    println!(
        ">>> worst frame in the whole grid: {} B  ({} at n={} t={})",
        worst.0, worst.3, worst.1, worst.2
    );
}

// ---------------------------------------------------------------------------
// JOB 2a: restoration + screen verify. Never measured before, all
// coordinator-controlled. SharedKey/ShareImage/AccessStructureRef here come
// from a REAL keygen; only the enum wrappers are assembled by hand, and each
// assumption is stated in the label.
// ---------------------------------------------------------------------------

#[test]
fn measure_restoration_and_screen_verify() {
    println!("\n=== JOB 2: RESTORATION + SCREEN VERIFY, full frames ===");
    let one = dests(1);

    for (n, t) in [(2usize, 2u16), (5, 5), (9, 9), (13, 13)] {
        println!("\n--- real key: n={n} t={t} ---");
        let mut env = TestEnv::default();
        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        let mut run = Run::start_after_keygen(
            n,
            t,
            &mut env,
            &mut rng,
            KeyPurpose::Bitcoin(bitcoin::Network::Bitcoin),
        );
        let device = *run.devices.keys().next().unwrap();
        let asr = {
            let k = run.coordinator.iter_keys().next().unwrap();
            k.access_structures().next().unwrap().access_structure_ref()
        };

        let mut real_shared_key: Option<SharedKey> = None;
        let mut real_share_index = None;

        let msgs = run
            .coordinator
            .request_device_display_backup(device, asr, TEST_ENCRYPTION_KEY)
            .unwrap();
        for m in &msgs {
            if let CoordinatorSend::ToDevice {
                message,
                destinations,
            } = m
            {
                report(
                    &format!("t={t} C2D DisplayBackup ({} dest)", destinations.len()),
                    up_core(destinations, message.clone()),
                );
                if let CoordinatorToDeviceMessage::Restoration(
                    CoordinatorRestoration::DisplayBackup {
                        root_shared_key,
                        share_index,
                        ..
                    },
                ) = message
                {
                    real_shared_key = Some(root_shared_key.clone());
                    real_share_index = Some(*share_index);
                }
            }
        }

        let msgs = run
            .coordinator
            .request_device_check_backup(device, asr, TEST_ENCRYPTION_KEY)
            .unwrap();
        for m in &msgs {
            if let CoordinatorSend::ToDevice {
                message,
                destinations,
            } = m
            {
                report(
                    &format!("t={t} C2D CheckBackup ({} dest)", destinations.len()),
                    up_core(destinations, message.clone()),
                );
            }
        }

        // RequestHeldShares -> the device's real HeldShares2 reply.
        let mark = run.transcript.len();
        let reqs: Vec<_> = run.coordinator.request_held_shares(device).collect();
        run.extend(reqs);
        run.run_until_finished(&mut env, &mut rng).unwrap();
        let mut real_held: Option<HeldShare2> = None;
        for send in &run.transcript[mark..] {
            match send {
                common::Send::CoordinatorToDevice {
                    destinations,
                    message,
                } => report(
                    &format!(
                        "t={t} C2D {} ({} dest)",
                        frostsnap_core::Kind::kind(message),
                        destinations.len()
                    ),
                    up_core(destinations, message.clone()),
                ),
                common::Send::DeviceToCoordinator { from, message } => {
                    if let DeviceToCoordinatorMessage::Restoration(DeviceRestoration::HeldShares2(
                        v,
                    )) = message
                    {
                        real_held = v.first().cloned();
                        report(
                            &format!("t={t} D2C HeldShares2 ({} real share(s), key_name=\"my new key\")", v.len()),
                            down_from(*from, DeviceSendBody::Core(message.clone()).into()),
                        );
                    } else {
                        report(
                            &format!("t={t} D2C {}", frostsnap_core::Kind::kind(message)),
                            down_from(*from, DeviceSendBody::Core(message.clone()).into()),
                        );
                    }
                }
                _ => {}
            }
        }

        let root = real_shared_key.clone().unwrap();
        let share_index = real_share_index.unwrap();
        let share_image = root.share_image(share_index);
        let held = real_held.clone().unwrap();

        // Hand-assembled wrappers around the real crypto objects above.
        // ASSUMED: key_name lengths 15 (the app's KEY_NAME_MAX_LENGTH) and 1000
        // (hostile; nothing on the wire enforces the 15).
        for (klabel, key_name) in [
            ("key_name=15ch", "x".repeat(15)),
            ("key_name=1000ch", "x".repeat(1000)),
        ] {
            report(
                &format!("t={t} C2D Consolidate ({klabel}, real SharedKey)"),
                up_core(
                    &one,
                    CoordinatorToDeviceMessage::Restoration(CoordinatorRestoration::Consolidate(
                        Box::new(ConsolidateBackup {
                            share_index,
                            root_shared_key: root.clone(),
                            key_name: key_name.clone(),
                            purpose: KeyPurpose::Bitcoin(bitcoin::Network::Bitcoin),
                        }),
                    )),
                ),
            );
            report(
                &format!("t={t} C2D SavePhysicalBackup ({klabel}, real ShareImage)"),
                up_core(
                    &one,
                    CoordinatorToDeviceMessage::Restoration(
                        CoordinatorRestoration::SavePhysicalBackup {
                            share_image,
                            key_name: key_name.clone(),
                            purpose: KeyPurpose::Bitcoin(bitcoin::Network::Bitcoin),
                            threshold: t,
                        },
                    ),
                ),
            );
            let mut h = held.clone();
            h.key_name = Some(key_name.clone());
            report(
                &format!("t={t} C2D SavePhysicalBackup2 ({klabel}, real HeldShare2)"),
                up_core(
                    &one,
                    CoordinatorToDeviceMessage::Restoration(
                        CoordinatorRestoration::SavePhysicalBackup2(Box::new(h)),
                    ),
                ),
            );
        }

        // Device -> coordinator restoration replies (all real objects).
        report(
            &format!("t={t} D2C PhysicalEntered (real ShareImage)"),
            down_core(DeviceToCoordinatorMessage::Restoration(
                DeviceRestoration::PhysicalEntered(EnteredPhysicalBackup {
                    enter_physical_id: EnterPhysicalId([0xffu8; 16]),
                    share_image,
                }),
            )),
        );
        report(
            &format!("t={t} D2C PhysicalSaved (real ShareImage)"),
            down_core(DeviceToCoordinatorMessage::Restoration(
                DeviceRestoration::PhysicalSaved(share_image),
            )),
        );
        report(
            &format!("t={t} D2C FinishedConsolidation"),
            down_core(DeviceToCoordinatorMessage::Restoration(
                DeviceRestoration::FinishedConsolidation {
                    access_structure_ref: asr,
                    share_index,
                },
            )),
        );

        // HeldShares / HeldShares2 with k copies of the real entry.
        for k in [1usize, 2, 5, 10, 15, 16, 20] {
            let v2: Vec<HeldShare2> = (0..k).map(|_| held.clone()).collect();
            let v1: Vec<HeldShare> = (0..k)
                .map(|_| HeldShare {
                    access_structure_ref: held.access_structure_ref,
                    share_image: held.share_image,
                    threshold: held.threshold.unwrap_or(t),
                    key_name: held.key_name.clone().unwrap_or_default(),
                    purpose: held
                        .purpose
                        .unwrap_or(KeyPurpose::Bitcoin(bitcoin::Network::Bitcoin)),
                })
                .collect();
            report(
                &format!("t={t} D2C HeldShares2 x{k} (key_name=\"my new key\")"),
                down_core(DeviceToCoordinatorMessage::Restoration(
                    DeviceRestoration::HeldShares2(v2),
                )),
            );
            report(
                &format!("t={t} D2C HeldShares(legacy) x{k}"),
                down_core(DeviceToCoordinatorMessage::Restoration(
                    DeviceRestoration::HeldShares(v1),
                )),
            );
        }

        // ScreenVerify, with the REAL master appkey for this key.
        let master_appkey = MasterAppkey::derive_from_rootkey(root.public_key());
        report(
            &format!("t={t} C2D ScreenVerify::VerifyAddress (idx=u32::MAX)"),
            up_core(
                &one,
                CoordinatorToDeviceMessage::ScreenVerify(ScreenVerify::VerifyAddress {
                    master_appkey,
                    derivation_index: u32::MAX,
                }),
            ),
        );

        // fixed_small restoration bits
        report(
            &format!("t={t} C2D EnterPhysicalBackup"),
            up_core(
                &one,
                CoordinatorToDeviceMessage::Restoration(
                    CoordinatorRestoration::EnterPhysicalBackup {
                        enter_physical_id: EnterPhysicalId([0xffu8; 16]),
                    },
                ),
            ),
        );
        report(
            &format!("t={t} C2D RequestHeldShares"),
            up_core(
                &one,
                CoordinatorToDeviceMessage::Restoration(CoordinatorRestoration::RequestHeldShares),
            ),
        );

        // cross-check the hand-built polynomial against the real one at this t
        let fake = poly_shared_key(t as usize);
        assert_eq!(
            enc(&fake),
            enc(&root),
            "hand-built SharedKey must encode to the same size as the real one at t={t}"
        );
    }

    // Now the t sweep, using hand-built polynomials (a real keygen at t=60 is
    // not needed: the SharedKey encoding is t 33-byte points and the assert
    // above proves the hand-built one matches a real one byte-for-byte in size).
    println!("\n-- DisplayBackup / CheckBackup vs threshold (SharedKey = t x 33 B) --");
    let mk_display = |t: usize| {
        CoordinatorToDeviceMessage::Restoration(CoordinatorRestoration::DisplayBackup {
            access_structure_ref: asr_dummy(),
            coord_share_decryption_contrib: contrib(),
            share_index: share_index(1),
            root_shared_key: poly_shared_key(t),
        })
    };
    let mk_check = |t: usize| {
        CoordinatorToDeviceMessage::Restoration(CoordinatorRestoration::CheckBackup {
            coord_share_decryption_contrib: contrib(),
            share_index: share_index(1),
            root_shared_key: poly_shared_key(t),
        })
    };
    for t in [1usize, 2, 13, 32, 50, 55, 56, 57, 58, 64, 100] {
        report(&format!("t={t:<4} C2D DisplayBackup"), up_core(&one, mk_display(t)));
        report(&format!("t={t:<4} C2D CheckBackup"), up_core(&one, mk_check(t)));
    }
    for (name, f) in [
        ("DisplayBackup", &mk_display as &dyn Fn(usize) -> CoordinatorToDeviceMessage),
        ("CheckBackup", &mk_check),
    ] {
        let cross = (1..=300usize).find(|t| up_core(&one, f(*t)) > COLDCARD_MAX_MSG_LEN);
        match cross {
            Some(t) => println!(
                ">>> {name} crosses 2060 at threshold t={t} ({} B); 33 B per threshold step",
                up_core(&one, f(t))
            ),
            None => println!(">>> {name} still fits at t=300"),
        }
    }

    // key_name crossover: how long a key_name blows a frame on its own?
    let held_name_cross = (1..=4000usize).find(|len| {
        up_core(
            &one,
            CoordinatorToDeviceMessage::Restoration(
                CoordinatorRestoration::SavePhysicalBackup {
                    share_image: ShareImage {
                        index: share_index(1),
                        image: (*schnorr_fun::fun::G).normalize().mark_zero(),
                    },
                    key_name: "x".repeat(*len),
                    purpose: KeyPurpose::Test,
                    threshold: 2,
                },
            ),
        ) > COLDCARD_MAX_MSG_LEN
    });
    println!(
        ">>> SavePhysicalBackup crosses 2060 at key_name length {:?} chars (String, no wire limit)",
        held_name_cross
    );
    let heldshares_cross = (1..=200usize).find(|k| {
        let v: Vec<HeldShare2> = (0..*k)
            .map(|_| HeldShare2 {
                access_structure_ref: Some(asr_dummy()),
                share_image: ShareImage {
                    index: share_index(1),
                    image: (*schnorr_fun::fun::G).normalize().mark_zero(),
                },
                threshold: Some(2),
                key_name: Some("x".repeat(15)),
                purpose: Some(KeyPurpose::Bitcoin(bitcoin::Network::Bitcoin)),
                needs_consolidation: true,
            })
            .collect();
        down_core(DeviceToCoordinatorMessage::Restoration(
            DeviceRestoration::HeldShares2(v),
        )) > COLDCARD_MAX_MSG_LEN
    });
    println!(
        ">>> HeldShares2 (15-char key_names) crosses 2060 at {:?} held shares -- DEVICE-EMITTED",
        heldshares_cross
    );
}

// ---------------------------------------------------------------------------
// JOB 2b/3: every remaining variant. Plain structs, so these are hand-built;
// the assumption for each field is in the label.
// ---------------------------------------------------------------------------

#[test]
fn measure_small_and_string_variants() {
    println!("\n=== JOB 2b: fixed_small + string-driven variants, FULL frames ===");
    let one = dests(1);

    println!("-- C2D framing level (no envelope) --");
    report(
        "C2D ReceiveSerial::MagicBytes",
        enc(&ReceiveSerial::<Upstream>::MagicBytes(
            MagicBytes::<Upstream>::default(),
        )),
    );
    report("C2D ReceiveSerial::Conch", enc(&ReceiveSerial::<Upstream>::Conch));
    report("C2D ReceiveSerial::Reset", enc(&ReceiveSerial::<Upstream>::Reset));
    for (name, v) in [
        ("Unused8", ReceiveSerial::<Upstream>::Unused8),
        ("Unused0", ReceiveSerial::<Upstream>::Unused0),
    ] {
        report(&format!("C2D ReceiveSerial::{name}"), enc(&v));
    }

    println!("\n-- C2D bare (non-encapsulated) wire bodies, 1 destination --");
    for (name, b) in [
        ("_Core", WireCoordinatorSendBody::_Core),
        ("_Naming", WireCoordinatorSendBody::_Naming),
        ("AnnounceAck", WireCoordinatorSendBody::AnnounceAck),
        ("Cancel", WireCoordinatorSendBody::Cancel),
        (
            "Upgrade(PrepareUpgrade)",
            WireCoordinatorSendBody::Upgrade(CoordinatorUpgradeMessage::PrepareUpgrade {
                size: u32::MAX,
                firmware_digest: Sha256Digest([0xffu8; 32]),
            }),
        ),
        (
            "Upgrade(EnterUpgradeMode)",
            WireCoordinatorSendBody::Upgrade(CoordinatorUpgradeMessage::EnterUpgradeMode),
        ),
        (
            "Upgrade(PrepareUpgrade2)",
            WireCoordinatorSendBody::Upgrade(CoordinatorUpgradeMessage::PrepareUpgrade2 {
                size: u32::MAX,
                firmware_digest: Sha256Digest([0xffu8; 32]),
            }),
        ),
    ] {
        report(&format!("C2D Wire::{name}"), up_to(&one, b));
    }

    println!("\n-- C2D encapsulated small bodies, 1 destination --");
    let long_name = "\u{1D11E}".repeat(14); // 14 chars x 4 UTF-8 bytes = 56 B
    for (name, b) in [
        (
            "Naming(Preview(14x4-byte chars))",
            CoordinatorSendBody::Naming(NameCommand::Preview(
                DeviceName::new(long_name.clone()).unwrap(),
            )),
        ),
        (
            "Naming(_Prompt(14x4-byte chars))",
            CoordinatorSendBody::Naming(NameCommand::_Prompt(
                DeviceName::new(long_name.clone()).unwrap(),
            )),
        ),
        ("DataErase", CoordinatorSendBody::DataErase),
        (
            "Challenge(GenuineChallenge)",
            CoordinatorSendBody::Challenge(Box::new(GenuineChallenge([0xffu8; 32]))),
        ),
        ("AnnounceAck(encaps form)", CoordinatorSendBody::AnnounceAck),
        ("Cancel(encaps form)", CoordinatorSendBody::Cancel),
    ] {
        report(&format!("C2D {name}"), up_body(&one, b));
    }
    report(
        "C2D Keygen::Finalize (encaps)",
        up_core(
            &one,
            CoordinatorToDeviceMessage::KeyGen(Keygen::Finalize {
                keygen_id: frostsnap_core::KeygenId([0xffu8; 16]),
            }),
        ),
    );

    println!("\n-- envelope cost: same tiny body, growing destination set --");
    for n in [1usize, 2, 5, 7, 9, 13, 20, 61, 62] {
        report(
            &format!("C2D Cancel to Particular({n} devices)"),
            up_to(&dests(n), WireCoordinatorSendBody::Cancel),
        );
    }
    report(
        "C2D Cancel to Destination::All",
        enc(&ReceiveSerial::<Upstream>::Message(CoordinatorSendMessage {
            target_destinations: Destination::All,
            message_body: WireCoordinatorSendBody::Cancel,
        })),
    );
    let dest_cross = (1..=200usize)
        .find(|n| up_to(&dests(*n), WireCoordinatorSendBody::Cancel) > COLDCARD_MAX_MSG_LEN);
    println!(">>> a 1-byte body sent to Particular(n) alone crosses 2060 at n={dest_cross:?} devices");

    println!("\n-- Keygen::Begin: hostile key_name and device count (hand-built) --");
    for (n, name_len) in [(5usize, 15usize), (9, 15), (13, 15), (5, 1000), (9, 2000)] {
        let devs = dests(n);
        let begin = Keygen::Begin(frostsnap_core::message::keygen::Begin {
            keygen_id: frostsnap_core::KeygenId([0xffu8; 16]),
            devices: devs.iter().cloned().collect(),
            threshold: n as u16,
            key_name: "x".repeat(name_len),
            purpose: KeyPurpose::Bitcoin(bitcoin::Network::Bitcoin),
            coordinator_public_keys: vec![(*schnorr_fun::fun::G).normalize()],
        });
        report(
            &format!("C2D Keygen::Begin n={n} key_name={name_len}ch (1 coord pubkey)"),
            up_core(&devs, CoordinatorToDeviceMessage::KeyGen(begin)),
        );
    }
    let begin_cross = (1..=200usize).find(|n| {
        let devs = dests(*n);
        up_core(
            &devs,
            CoordinatorToDeviceMessage::KeyGen(Keygen::Begin(
                frostsnap_core::message::keygen::Begin {
                    keygen_id: frostsnap_core::KeygenId([0xffu8; 16]),
                    devices: devs.iter().cloned().collect(),
                    threshold: *n as u16,
                    key_name: "x".repeat(15),
                    purpose: KeyPurpose::Bitcoin(bitcoin::Network::Bitcoin),
                    coordinator_public_keys: vec![(*schnorr_fun::fun::G).normalize()],
                },
            )),
        ) > COLDCARD_MAX_MSG_LEN
    });
    println!(">>> Keygen::Begin (15-char name) crosses 2060 at n={begin_cross:?} devices");

    println!("\n-- KeyPurpose encoding cost (Test vs Bitcoin vs Nostr) --");
    for (name, p) in [
        ("Test", KeyPurpose::Test),
        ("Bitcoin(Bitcoin)", KeyPurpose::Bitcoin(bitcoin::Network::Bitcoin)),
        ("Nostr", KeyPurpose::Nostr),
    ] {
        report(
            &format!("C2D SavePhysicalBackup purpose={name}, key_name=15ch"),
            up_core(
                &one,
                CoordinatorToDeviceMessage::Restoration(
                    CoordinatorRestoration::SavePhysicalBackup {
                        share_image: ShareImage {
                            index: share_index(1),
                            image: (*schnorr_fun::fun::G).normalize().mark_zero(),
                        },
                        key_name: "x".repeat(15),
                        purpose: p,
                        threshold: 2,
                    },
                ),
            ),
        );
    }

    println!("\n-- RequestSign with WireSignTask::Test{{message:String}} --");
    let test_task_frame = |len: usize| {
        let gsr = GroupSignReq {
            parties: (1u8..=2).map(share_index).collect(),
            agg_nonces: vec![binonce::Nonce::<Zero>::from_bytes(
                real_segment(0x90, 1).nonces[0].to_bytes(),
            )
            .unwrap()],
            sign_task: WireSignTask::Test {
                message: "x".repeat(len),
            },
            access_structure_id: frostsnap_core::AccessStructureId([7u8; 32]),
        };
        up_core(
            &one,
            CoordinatorToDeviceMessage::Signing(CoordinatorSigning::RequestSign(Box::new(
                RequestSign {
                    group_sign_req: gsr,
                    device_sign_req: DeviceSignReq {
                        nonces: CoordNonceStreamState {
                            stream_id: NonceStreamId([9u8; 16]),
                            index: u32::MAX - 1,
                            remaining: u32::MAX - 1,
                        },
                        rootkey: (*schnorr_fun::fun::G).normalize(),
                        coord_share_decryption_contrib: contrib(),
                    },
                },
            ))),
        )
    };
    for len in [0usize, 32, 256, 1000, 1900, 2000] {
        report(&format!("C2D RequestSign Test{{{len} chars}}"), test_task_frame(len));
    }
    let t_cross = (0..=3000usize).find(|len| test_task_frame(*len) > COLDCARD_MAX_MSG_LEN);
    println!(">>> RequestSign+Test crosses 2060 at message length {t_cross:?} chars");

    println!("\n-- D2C framing level --");
    report(
        "D2C ReceiveSerial::MagicBytes (MAGIC_REPLY)",
        enc(&ReceiveSerial::<Downstream>::MagicBytes(
            MagicBytes::<Downstream>::default(),
        )),
    );
    report("D2C ReceiveSerial::Conch", enc(&ReceiveSerial::<Downstream>::Conch));
    report("D2C ReceiveSerial::Reset", enc(&ReceiveSerial::<Downstream>::Reset));
    report(
        "D2C ReceiveSerial::Unused8",
        enc(&ReceiveSerial::<Downstream>::Unused8),
    );

    println!("\n-- D2C bare (legacy, decode-only) wire bodies --");
    for (name, b) in [
        ("_Core", WireDeviceSendBody::_Core),
        (
            "Debug{14 chars}",
            WireDeviceSendBody::Debug {
                message: "x".repeat(14),
            },
        ),
        (
            "Announce",
            WireDeviceSendBody::Announce {
                firmware_digest: Sha256Digest([0xffu8; 32]),
            },
        ),
        (
            "SetName(14x4-byte chars)",
            WireDeviceSendBody::SetName {
                name: DeviceName::new(long_name.clone()).unwrap(),
            },
        ),
        ("DisconnectDownstream", WireDeviceSendBody::DisconnectDownstream),
        ("NeedName", WireDeviceSendBody::NeedName),
        ("_LegacyAckUpgradeMode", WireDeviceSendBody::_LegacyAckUpgradeMode),
    ] {
        report(&format!("D2C bare Wire::{name}"), down(b));
    }

    println!("\n-- D2C encapsulated bodies (what a current device actually emits) --");
    for (name, b) in [
        (
            "Announce",
            DeviceSendBody::Announce {
                firmware_digest: Sha256Digest([0xffu8; 32]),
            },
        ),
        (
            "SetName(14 x 4-byte chars = 56 B)",
            DeviceSendBody::SetName {
                name: DeviceName::new(long_name.clone()).unwrap(),
            },
        ),
        ("DisconnectDownstream", DeviceSendBody::DisconnectDownstream),
        ("NeedName", DeviceSendBody::NeedName),
        ("_LegacyAckUpgradeMode", DeviceSendBody::_LegacyAckUpgradeMode),
        ("Misc(AckUpgradeMode)", DeviceSendBody::Misc(CommsMisc::AckUpgradeMode)),
        (
            "Misc(DisplayBackupConfrimed)",
            DeviceSendBody::Misc(CommsMisc::DisplayBackupConfrimed),
        ),
        ("Misc(BackupRecorded)", DeviceSendBody::Misc(CommsMisc::BackupRecorded)),
        ("Misc(EraseConfirmed)", DeviceSendBody::Misc(CommsMisc::EraseConfirmed)),
        (
            "Misc(BackupChecked)",
            DeviceSendBody::Misc(CommsMisc::BackupChecked {
                access_structure_ref: asr_dummy(),
                share_index: share_index(1),
            }),
        ),
    ] {
        report(&format!("D2C {name}"), down_body(b));
    }

    println!("\n-- D2C Debug{{message:String}}: the device's own hazard --");
    for len in [0usize, 32, 100, 1000, 2000, 2020] {
        report(
            &format!("D2C Debug{{{len} chars}}"),
            down_body(DeviceSendBody::Debug {
                message: "x".repeat(len),
            }),
        );
    }
    let d_cross = (0..=3000usize).find(|len| {
        down_body(DeviceSendBody::Debug {
            message: "x".repeat(*len),
        }) > COLDCARD_MAX_MSG_LEN
    });
    println!(">>> D2C Debug crosses 2060 at {d_cross:?} ASCII chars (unbounded String, device-emitted)");

    println!("\n-- D2C keygen small replies (hand-built, sizes cross-checked by the grid) --");
    report(
        "D2C KeyGen::Ack",
        down_core(DeviceToCoordinatorMessage::KeyGen(DeviceKeygen::Ack(
            frostsnap_core::message::KeyGenAck {
                ack_session_hash: frostsnap_core::SessionHash([0xffu8; 32]),
                keygen_id: frostsnap_core::KeygenId([0xffu8; 16]),
            },
        ))),
    );
}

#[cfg(feature = "serde_json")]
#[test]
fn measure_nostr_sign_task() {
    println!("\n=== WireSignTask::Nostr (needs --features serde_json) ===");
    let one = dests(1);
    let frame = |content_len: usize, n_tags: usize| {
        let pubkey = (*schnorr_fun::fun::G).normalize().into_point_with_even_y().0;
        let tags: Vec<Vec<String>> = (0..n_tags)
            .map(|i| vec!["e".to_string(), format!("{i:064}")])
            .collect();
        let event = frostsnap_core::nostr::UnsignedEvent::new(
            pubkey,
            1,
            tags,
            "x".repeat(content_len),
            1_700_000_000,
        );
        let gsr = GroupSignReq {
            parties: (1u8..=2).map(share_index).collect(),
            agg_nonces: vec![binonce::Nonce::<Zero>::from_bytes(
                real_segment(0x91, 1).nonces[0].to_bytes(),
            )
            .unwrap()],
            sign_task: WireSignTask::Nostr {
                event: Box::new(event),
            },
            access_structure_id: frostsnap_core::AccessStructureId([7u8; 32]),
        };
        up_core(
            &one,
            CoordinatorToDeviceMessage::Signing(CoordinatorSigning::RequestSign(Box::new(
                RequestSign {
                    group_sign_req: gsr,
                    device_sign_req: DeviceSignReq {
                        nonces: CoordNonceStreamState {
                            stream_id: NonceStreamId([9u8; 16]),
                            index: u32::MAX - 1,
                            remaining: u32::MAX - 1,
                        },
                        rootkey: (*schnorr_fun::fun::G).normalize(),
                        coord_share_decryption_contrib: contrib(),
                    },
                },
            ))),
        )
    };
    for (c, t) in [(0usize, 0usize), (100, 0), (100, 4), (1000, 4), (1800, 0)] {
        report(&format!("C2D RequestSign Nostr{{content={c}, tags={t}}}"), frame(c, t));
    }
    let cross = (0..=3000usize).find(|c| frame(*c, 0) > COLDCARD_MAX_MSG_LEN);
    println!(">>> RequestSign+Nostr (0 tags) crosses 2060 at content length {cross:?} chars");
}

/// The last unbounded coordinator-controlled driver: `SpkOwner::Foreign(ScriptBuf)`
/// on an output. One output with a big non-standard script blows the frame
/// independently of input count (the existing tests all used 22-byte v0 scripts).
#[test]
fn measure_foreign_script_output() {
    println!("\n=== RequestSign: one foreign output with an arbitrary-length script ===");
    let one = dests(1);
    let master_appkey = MasterAppkey::derive_from_rootkey((*schnorr_fun::fun::G).normalize());
    let frame = |spk_len: usize| {
        let mut tx = TransactionTemplate::new();
        tx.push_imaginary_owned_input(
            LocalSpk {
                master_appkey,
                bip32_path: BitcoinBip32Path::external(0),
            },
            Amount::from_sat(100_000),
        );
        tx.push_foreign_output(TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x6au8; spk_len]),
        });
        let gsr = GroupSignReq {
            parties: (1u8..=2).map(share_index).collect(),
            agg_nonces: vec![binonce::Nonce::<Zero>::from_bytes(
                real_segment(0x92, 1).nonces[0].to_bytes(),
            )
            .unwrap()],
            sign_task: WireSignTask::BitcoinTransaction(tx),
            access_structure_id: frostsnap_core::AccessStructureId([7u8; 32]),
        };
        up_core(
            &one,
            CoordinatorToDeviceMessage::Signing(CoordinatorSigning::RequestSign(Box::new(
                RequestSign {
                    group_sign_req: gsr,
                    device_sign_req: DeviceSignReq {
                        nonces: CoordNonceStreamState {
                            stream_id: NonceStreamId([9u8; 16]),
                            index: u32::MAX - 1,
                            remaining: u32::MAX - 1,
                        },
                        rootkey: (*schnorr_fun::fun::G).normalize(),
                        coord_share_decryption_contrib: contrib(),
                    },
                },
            ))),
        )
    };
    for spk_len in [22usize, 34, 500, 1000, 1800, 2000] {
        report(
            &format!("C2D RequestSign 1 in, 1 foreign out, spk={spk_len} B"),
            frame(spk_len),
        );
    }
    let cross = (1..=3000usize).find(|l| frame(*l) > COLDCARD_MAX_MSG_LEN);
    println!(">>> a SINGLE foreign output crosses 2060 at script length {cross:?} B (1 B/script byte, no cap)");
}

// ===========================================================================
// PHASE-3 JOB, added 2026-08-18: is the "one nonce segment per frame" cap legal?
//
// `NonceResponse { segments }` is unbounded in segment count (1x30 = 2,040 B,
// 2x30 = 4,038 B, 3x30 ~ 6 KB). The proposed device-side cap is: emit one
// `NonceResponse` PER SEGMENT instead of one carrying k. That is only legal if a
// REAL `FrostCoordinator` accepts k separate single-segment replies and lands in
// the same state. This test settles it against the real coordinator, not a model.
// ===========================================================================

use frostsnap_core::coordinator::FrostCoordinator;
use frostsnap_core::message::DeviceSend;

/// Pull the `NonceJobBatch` out of a device's reaction to `OpenNonceStreams`,
/// run it, and return the segments it WOULD have crammed into one frame.
fn segments_for(
    run: &mut Run,
    device_id: DeviceId,
    open: OpenNonceStreams,
    rng: &mut impl rand_core::RngCore,
) -> Vec<NonceStreamSegment> {
    let sends = run
        .device(device_id)
        .recv_coordinator_message(
            CoordinatorToDeviceMessage::Signing(CoordinatorSigning::OpenNonceStreams(open)),
            rng,
        )
        .unwrap();
    let mut batch: NonceJobBatch = sends
        .into_iter()
        .find_map(|s| match s {
            DeviceSend::ToUser(m) => match *m {
                frostsnap_core::device::DeviceToUserMessage::NonceJobs(b) => Some(b),
                _ => None,
            },
            _ => None,
        })
        .expect("device must ask the user side to generate nonces");
    batch.run_until_finished(&mut TestDeviceKeyGen);
    batch.into_segments()
}

fn nonce_response(segments: Vec<NonceStreamSegment>) -> DeviceToCoordinatorMessage {
    DeviceToCoordinatorMessage::Signing(DeviceSigning::NonceResponse { segments })
}

#[test]
fn nonce_response_split_per_segment_is_accepted() {
    const K: usize = 3;
    println!("\n=== Is one NonceResponse PER SEGMENT legal for a real coordinator? ===");

    let mut env = TestEnv::default();
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    let mut run = Run::start_after_keygen(
        3,
        2,
        &mut env,
        &mut rng,
        KeyPurpose::Bitcoin(bitcoin::Network::Bitcoin),
    );
    let device_id = run.device_vec()[0];

    // A real coordinator opens K streams for this device in ONE OpenNonceStreams.
    let open = run
        .coordinator
        .maybe_request_nonce_replenishment(&BTreeSet::from([device_id]), K, &mut rng)
        .into_open_nonce_streams()
        .find(|(d, _)| *d == device_id)
        .expect("request covers the device")
        .1;
    assert_eq!(open.streams.len(), K, "coordinator opened K streams");
    println!("coordinator opened {} streams in one message", open.streams.len());

    let segments = segments_for(&mut run, device_id, open, &mut rng);
    assert_eq!(segments.len(), K, "device wants to answer all K in one frame");

    // NOTE ON SIZES: `Run::generate` builds signers with nonce_batch_size = 10, not
    // the production `NONCE_BATCH_SIZE = 30` (device.rs:32), so these frames are ~1/3
    // of real ones. The production figures are measured elsewhere in this file:
    // 1x30 = 2,040 B, 2x30 = 4,038 B, 3x30 ~ 6 KB. Acceptance does not depend on the
    // nonce count -- only on the segment count -- so the verdict below carries over.
    let combined = down_core(nonce_response(segments.clone()));
    let split = down_core(nonce_response(vec![segments[0].clone()]));
    report(&format!("D2C NonceResponse, {K} segments (today, 10/seg)"), combined);
    report("D2C NonceResponse, 1 segment  (capped, 10/seg)", split);

    // Route A: the one big frame.
    let mut coord_a = run.coordinator.clone();
    let a_out = coord_a
        .recv_device_message(device_id, nonce_response(segments.clone()))
        .expect("combined reply accepted");

    // Route B: K frames, one segment each, in order.
    let mut coord_b = run.coordinator.clone();
    let mut b_out = 0;
    for (i, seg) in segments.iter().enumerate() {
        b_out += coord_b
            .recv_device_message(device_id, nonce_response(vec![seg.clone()]))
            .unwrap_or_else(|e| panic!("split reply {i} REFUSED: {e}"))
            .len();
    }

    // Route C: K frames, one segment each, REVERSE order -- a device with a
    // per-slot work queue has no reason to answer streams in the coordinator's
    // order, so order-independence is part of "legal".
    let mut coord_c = run.coordinator.clone();
    for (i, seg) in segments.iter().rev().enumerate() {
        coord_c
            .recv_device_message(device_id, nonce_response(vec![seg.clone()]))
            .unwrap_or_else(|e| panic!("reverse-order split reply {i} REFUSED: {e}"));
    }

    println!(
        "combined -> {} outgoing msg(s); split -> {} outgoing msg(s) (1 ReplenishedNonces per FRAME)",
        a_out.len(),
        b_out
    );
    println!("nonces_available combined = {:?}", coord_a.nonces_available(device_id));
    println!("nonces_available split    = {:?}", coord_b.nonces_available(device_id));

    assert_eq!(
        coord_a.nonces_available(device_id),
        coord_b.nonces_available(device_id),
        "split route must leave the same nonces available"
    );
    assert_eq!(
        coord_a.nonces_available(device_id),
        coord_c.nonces_available(device_id),
        "reverse-order split route must leave the same nonces available"
    );

    // Strongest checks available: whole-coordinator equality (FrostCoordinator is
    // PartialEq; the harness's own check_mutations relies on it), plus mutation
    // replay -- what actually gets persisted.
    //
    // The staged-mutation QUEUE is part of the struct and is order-sensitive, so
    // drain it first and replay it onto a fresh baseline: identical live state AND
    // identical replayed state is the real "equivalent" claim. A bare `==` on the
    // undrained clones fails on the reverse-order route for queue order alone.
    let baseline = run.start_coordinator.clone();
    let settle = |c: &mut FrostCoordinator| {
        let mut replay = baseline.clone();
        for m in c.take_staged_mutations() {
            replay.apply_mutation(m);
        }
        c.clear_tmp_data();
        replay
    };
    let replay_a = settle(&mut coord_a);
    for (label, mut c) in [("split", coord_b), ("reverse-order split", coord_c)] {
        let replay_c = settle(&mut c);
        assert_eq!(coord_a, c, "{label} route must leave an identical coordinator");
        assert_eq!(
            replay_a, replay_c,
            "{label} route must persist to an identical coordinator"
        );
    }
    println!(">>> LEGAL: K single-segment NonceResponses == one K-segment NonceResponse, any order,");
    println!(">>> identical live state AND identical mutation replay.");
    println!(">>> Cost of the cap: {K} frames of {split} B instead of 1 of {combined} B.");
}

/// How many streams does a real coordinator actually open per device? The count
/// is the CALLER's `desired_nonce_streams`, and the real app
/// (frostsnapp/rust/src/coordinator.rs) passes `N_NONCE_STREAMS = 4`. Worse:
/// `generate_nonce_stream_opening_requests` re-lists EVERY existing stream on
/// each replenish, so steady-state k does not decay. This prints the segment
/// count and frame size a device would emit uncapped, for k = 1..=4.
#[test]
fn nonce_response_segment_count_per_replenish() {
    println!("\n=== Segments per NonceResponse vs streams the coordinator opens ===");
    for k in 1usize..=4 {
        let mut env = TestEnv::default();
        let mut rng = ChaCha20Rng::from_seed([11u8; 32]);
        let mut run = Run::start_after_keygen(
            2,
            2,
            &mut env,
            &mut rng,
            KeyPurpose::Bitcoin(bitcoin::Network::Bitcoin),
        );
        let device_id = run.device_vec()[0];
        let open = run
            .coordinator
            .maybe_request_nonce_replenishment(&BTreeSet::from([device_id]), k, &mut rng)
            .into_open_nonce_streams()
            .find(|(d, _)| *d == device_id)
            .unwrap()
            .1;
        let n_streams = open.streams.len();
        let segments = segments_for(&mut run, device_id, open, &mut rng);
        let uncapped = down_core(nonce_response(segments.clone()));
        let capped = segments
            .iter()
            .map(|s| down_core(nonce_response(vec![s.clone()])))
            .max()
            .unwrap_or(0);
        println!(
            "desired k={k}: OpenNonceStreams.streams.len()={n_streams}, \
             segments={}, uncapped frame={uncapped} B, worst capped frame={capped} B",
            segments.len()
        );
        // Uncapped is unbounded in k; capped never is.
        assert!(capped <= 2_100, "a single-segment frame must stay small");
    }
    println!(">>> The real app asks for N_NONCE_STREAMS = 4 (frostsnapp/rust/src/coordinator.rs:50).");
    println!(">>> BUT frostsnap_coordinator::nonce_replenish::NonceReplenishProtocol::new");
    println!(">>> calls OpenNonceStreams::split() and sends ONE stream per device at a time,");
    println!(">>> waiting for ReplenishedNonces before the next -- so on the REAL wire the");
    println!(">>> device is only ever asked for one segment at a time anyway.");
}

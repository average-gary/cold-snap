//! Regression tests for the coordinator-controlled nonce-index panics in
//! `device_nonces.rs`. Each of these was a reachable halt under
//! `panic = "abort"`, i.e. a reset loop under the DECISIONS.md decision-6 panic
//! handler. They are split by where in the protocol they sit, because that
//! determines how bad each one is:
//!
//! - `OpenNonceStreams` is **pre-consent**: no user interaction whatsoever, so
//!   anything reachable from it is a remote brick with no prompt to refuse.
//! - `sign_ack` is post-consent but pre-flash-write.
use common::TEST_ENCRYPTION_KEY;
use env::TestEnv;
use frostsnap_core::device::{FrostSigner, KeyPurpose};
use frostsnap_core::device_nonces::{NonceStreamSlot, SecretNonceSlot, MAX_NONCE_SKIP_BATCHES};
use frostsnap_core::message::{signing, CoordinatorToDeviceMessage};
use frostsnap_core::nonce_stream::{CoordNonceStreamState, NonceStreamId};
use frostsnap_core::WireSignTask;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

use crate::common::Run;
mod common;
mod env;

// ---------------------------------------------------------------------------
// Pre-consent: OpenNonceStreams
// ---------------------------------------------------------------------------

/// Drive a device through a normal `OpenNonceStreams`, then a second one with a
/// coordinator-chosen `index`/`remaining`. Returns Ok if the device survived.
fn open_streams(index: u32, remaining: u32) -> Result<(), String> {
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    let mut signer = FrostSigner::new_random(&mut rng, 8);
    let stream_id = NonceStreamId::random(&mut rng);

    let open = |index, remaining| {
        CoordinatorToDeviceMessage::Signing(signing::CoordinatorSigning::OpenNonceStreams(
            signing::OpenNonceStreams {
                streams: vec![CoordNonceStreamState {
                    stream_id,
                    index,
                    remaining,
                }],
            },
        ))
    };

    // Establish the slot at index 0 first.
    signer
        .recv_coordinator_message(open(0, 100), &mut rng)
        .map_err(|e| e.to_string())?;
    signer
        .recv_coordinator_message(open(index, remaining), &mut rng)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// The pre-consent one. `index = u32::MAX` used to hit
/// `panic!("cannot have an index at u32::MAX")` in `nonce_task` with no user
/// interaction at all.
#[test]
fn max_index_in_open_nonce_streams_does_not_panic() {
    let res = open_streams(u32::MAX, u32::MAX);
    println!("index=u32::MAX -> {res:?}");
    assert!(res.is_ok(), "device must survive: {res:?}");
}

#[test]
fn index_just_below_max_in_open_nonce_streams_does_not_panic() {
    assert!(open_streams(u32::MAX - 1, u32::MAX).is_ok());
    assert!(open_streams(u32::MAX - 2, 0).is_ok());
}

/// A large claimed index must not turn into a proportionally large `NonceJob`.
/// This is the no-panic failure mode: unbounded ChaCha20+EC work plus a
/// `Vec::with_capacity(length * 288)`, which never trips the panic handler and so
/// never trips the reboot counter either — only the watchdog escapes.
#[test]
fn large_claimed_index_does_not_request_unbounded_work() {
    let mut rng = ChaCha20Rng::from_seed([11u8; 32]);
    let batch = 30u32;
    let slot_value = SecretNonceSlot {
        index: 0,
        nonce_stream_id: NonceStreamId::random(&mut rng),
        ratchet_prg_seed_material: [3u8; 32],
        last_used: 0,
        signing_state: None,
    };

    for claimed in [batch + 1, 1_000_000, 100_000_000, u32::MAX - 1, u32::MAX] {
        let mut slot = frostsnap_core::device_nonces::MemoryNonceSlot::default();
        slot.write_slot(&slot_value);
        let job = slot.reconcile_coord_nonce_stream_state(
            CoordNonceStreamState {
                stream_id: slot_value.nonce_stream_id,
                index: claimed,
                remaining: u32::MAX,
            },
            batch,
        );
        // Whatever it decides, the work must be bounded by one batch.
        if let Some(job) = job {
            let n = job.n_nonces_to_generate();
            println!("claimed index {claimed} -> job of {n} nonces");
            assert!(
                n <= batch,
                "claimed index {claimed} produced a job of {n} nonces, over the {batch} batch size"
            );
        } else {
            println!("claimed index {claimed} -> no job");
        }
    }
}

// ---------------------------------------------------------------------------
// Post-consent: sign_ack
// ---------------------------------------------------------------------------

/// Drive a 1-of-1 sign as far as the device's own `sign_ack`, having first moved
/// the device's slot index to `device_index` and rewritten the coordinator's
/// claimed index to `claimed_index`.
///
/// This calls `sign_ack` directly rather than going through
/// `Run::run_until_finished`, because the test harness `unwrap()`s the result
/// (`env/test_env.rs:220-223`) and would therefore convert an `ActionError` — the
/// outcome under test — into a test-harness panic that is indistinguishable from
/// the device panic these tests exist to rule out.
fn sign_ack_with_indexes(
    device_index: u32,
    claimed_index: u32,
) -> Result<Vec<frostsnap_core::message::DeviceSend>, frostsnap_core::ActionError> {
    let mut test_rng = ChaCha20Rng::from_seed([42u8; 32]);
    let mut run = Run::start_after_keygen_and_nonces(
        1,
        1,
        &mut TestEnv::default(),
        &mut test_rng,
        1,
        KeyPurpose::Test,
    );
    let device_set = run.device_set();
    let key_data = run.coordinator.iter_keys().next().unwrap();
    let access_structure_ref = key_data
        .access_structures()
        .next()
        .unwrap()
        .access_structure_ref();
    let session_id = run
        .coordinator
        .start_sign(
            access_structure_ref,
            WireSignTask::Test {
                message: "utxo.club!".into(),
            },
            &device_set,
            &mut test_rng,
        )
        .unwrap();

    let device_id = *device_set.iter().next().unwrap();
    let mut sign_req =
        run.coordinator
            .request_device_sign(session_id, device_id, TEST_ENCRYPTION_KEY);
    let stream_id = sign_req.request_sign.device_sign_req.nonces.stream_id;

    {
        let signer = run.devices.get_mut(&device_id).unwrap();
        let slot = signer.nonce_slots().get(stream_id).unwrap();
        let mut v = slot.read_slot().unwrap();
        v.index = device_index;
        v.signing_state = None;
        slot.write_slot(&v);
    }
    sign_req.request_sign.device_sign_req.nonces.index = claimed_index;

    // Feed RequestSign to the device to obtain the SignPhase1 it would prompt on,
    // then ack it directly.
    let msg = CoordinatorToDeviceMessage::Signing(signing::CoordinatorSigning::RequestSign(
        Box::new(sign_req.request_sign),
    ));
    let sends = run
        .devices
        .get_mut(&device_id)
        .unwrap()
        .recv_coordinator_message(msg, &mut test_rng)
        .expect("RequestSign must be accepted so that sign_ack is what is under test");

    let phase = sends
        .into_iter()
        .find_map(|s| match s {
            frostsnap_core::message::DeviceSend::ToUser(m) => match *m {
                frostsnap_core::device::DeviceToUserMessage::SignatureRequest { phase } => {
                    Some(*phase)
                }
                _ => None,
            },
            _ => None,
        })
        .expect("device must have asked the user to confirm signing");

    run.devices
        .get_mut(&device_id)
        .unwrap()
        .sign_ack(phase, &mut common::TestDeviceKeyGen)
}

/// The exhausted-iterator case. `iter_secret_nonces` stops at `u32::MAX`, and the
/// only guard on the coordinator's claimed index was `< slot.index`, so this used
/// to hit `.expect("tried to sign with nonces out of range")`.
#[test]
fn claimed_index_at_end_of_stream_is_an_error_not_a_panic() {
    let res = sign_ack_with_indexes(u32::MAX - 1, u32::MAX);
    println!("device=MAX-1 claimed=MAX -> {:?}", res.as_ref().err());
    assert!(res.is_err(), "must be rejected, not panic");
}

/// The unbounded-skip case: a claimed index far ahead of ours used to make the
/// device derive one nonce per skipped index before signing. No panic, so no
/// reset and no reboot counter — this must be refused up front instead.
#[test]
fn huge_skip_is_refused_rather_than_ground_through() {
    let res = sign_ack_with_indexes(0, 500_000_000);
    let err = res.expect_err("a huge skip must be refused");
    println!("skip=500M -> {err:?}");
    // Refused for being too large, not merely by luck of some other check.
    assert!(
        format!("{err:?}").contains("skip"),
        "expected a skip-limit refusal, got {err:?}"
    );
}

/// The bound must not break legitimate replenishment: a skip inside the allowed
/// window still signs. Without this, one could "fix" the DoS by refusing
/// everything and the tests above would still pass.
#[test]
fn skip_within_the_allowed_window_still_signs() {
    // Harness nonce_batch_size is 10 (`common/mod.rs:238`), so the window is
    // 10 * MAX_NONCE_SKIP_BATCHES. Use a skip comfortably inside it.
    let skip = 10 * MAX_NONCE_SKIP_BATCHES / 2;
    let res = sign_ack_with_indexes(0, skip);
    println!("skip={skip} -> ok={}", res.is_ok());
    assert!(
        res.is_ok(),
        "legitimate skip must still sign: {:?}",
        res.err()
    );
}

/// The plain happy path, so the tests above cannot pass by breaking signing.
#[test]
fn unmodified_indexes_still_sign() {
    let mut test_rng = ChaCha20Rng::from_seed([42u8; 32]);
    let mut run = Run::start_after_keygen_and_nonces(
        1,
        1,
        &mut TestEnv::default(),
        &mut test_rng,
        1,
        KeyPurpose::Test,
    );
    let device_set = run.device_set();
    let key_data = run.coordinator.iter_keys().next().unwrap();
    let access_structure_ref = key_data
        .access_structures()
        .next()
        .unwrap()
        .access_structure_ref();
    let session_id = run
        .coordinator
        .start_sign(
            access_structure_ref,
            WireSignTask::Test {
                message: "utxo.club!".into(),
            },
            &device_set,
            &mut test_rng,
        )
        .unwrap();
    let device_id = *device_set.iter().next().unwrap();
    let sign_req = run
        .coordinator
        .request_device_sign(session_id, device_id, TEST_ENCRYPTION_KEY);
    run.extend(sign_req);
    run.run_until_finished(&mut TestEnv::default(), &mut test_rng)
        .unwrap();
}

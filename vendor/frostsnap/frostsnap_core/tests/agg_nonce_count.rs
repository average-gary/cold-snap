//! Regression tests for the priority-1 reset-loop defect: `device.rs:491` indexed
//! `agg_nonces[signature_index]` while `GroupSignReq::check` never validated
//! `agg_nonces.len()` against the sign_item count, so a coordinator sending the
//! wrong number of aggregated nonces panicked the device post-consent. Under
//! `panic = "abort"` that is a halt, and with a reset-based panic handler a
//! deterministic reset loop. See DECISIONS.md decision 6, priority 1.
use common::TEST_ENCRYPTION_KEY;
use env::TestEnv;
use frostsnap_core::device::KeyPurpose;
use frostsnap_core::WireSignTask;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

use crate::common::Run;
mod common;
mod env;

fn run_with_agg_nonce_count(n: usize) -> frostsnap_core::MessageResult<()> {
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
    let task = WireSignTask::Test {
        message: "utxo.club!".into(),
    };
    let access_structure_ref = key_data
        .access_structures()
        .next()
        .unwrap()
        .access_structure_ref();
    let session_id = run
        .coordinator
        .start_sign(access_structure_ref, task, &device_set, &mut test_rng)
        .unwrap();

    let device_id = *device_set.iter().next().unwrap();
    let mut sign_req =
        run.coordinator
            .request_device_sign(session_id, device_id, TEST_ENCRYPTION_KEY);

    // sanity: exactly one agg_nonce for one sign_item
    assert_eq!(sign_req.request_sign.group_sign_req.agg_nonces.len(), 1);
    let nonce = sign_req.request_sign.group_sign_req.agg_nonces[0];
    sign_req.request_sign.group_sign_req.agg_nonces = vec![nonce; n];

    run.extend(sign_req);
    run.run_until_finished(&mut TestEnv::default(), &mut test_rng)
}

#[test]
fn too_few_agg_nonces_is_an_error_not_a_panic() {
    let res = run_with_agg_nonce_count(0);
    println!("0 nonces -> {res:?}");
    assert!(res.is_err(), "must be rejected");
}

#[test]
fn too_many_agg_nonces_is_an_error_not_a_panic() {
    let res = run_with_agg_nonce_count(5);
    println!("5 nonces -> {res:?}");
    assert!(res.is_err(), "must be rejected");
}

#[test]
fn correct_agg_nonce_count_still_signs() {
    let res = run_with_agg_nonce_count(1);
    println!("1 nonce -> {res:?}");
    assert!(res.is_ok());
}

/// n_sign_items must agree with sign_items().len() for multi-input bitcoin txs,
/// including mixed owned/foreign inputs — otherwise the new check is itself wrong.
#[test]
fn n_sign_items_agrees_with_sign_items_len() {
    use bitcoin::{Amount, Network, ScriptBuf, TxOut};
    use frostsnap_core::bitcoin_transaction::{LocalSpk, PushInput, TransactionTemplate};
    use frostsnap_core::tweak::BitcoinBip32Path;
    use frostsnap_core::MasterAppkey;
    use schnorr_fun::fun::prelude::*;

    let appkey = MasterAppkey::derive_from_rootkey(g!(2 * G).normalize());

    for n_owned in 0..4usize {
        for n_foreign in 0..3usize {
            let mut t = TransactionTemplate::new();
            for i in 0..n_owned {
                t.push_imaginary_owned_input(
                    LocalSpk {
                        master_appkey: appkey,
                        bip32_path: BitcoinBip32Path::external(i as u32),
                    },
                    Amount::from_sat(100_000),
                );
            }
            for _ in 0..n_foreign {
                let txout = TxOut {
                    value: Amount::from_sat(50_000),
                    script_pubkey: ScriptBuf::new(),
                };
                t.push_foreign_input(PushInput::spend_outpoint(&txout, bitcoin::OutPoint::null()));
            }
            t.push_foreign_output(TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            });

            let checked = match WireSignTask::BitcoinTransaction(t)
                .check(appkey, KeyPurpose::Bitcoin(Network::Bitcoin))
            {
                Ok(c) => c,
                Err(e) => {
                    println!("owned={n_owned} foreign={n_foreign} rejected: {e}");
                    continue;
                }
            };
            assert_eq!(
                checked.n_sign_items(),
                checked.sign_items().len(),
                "mismatch at owned={n_owned} foreign={n_foreign}"
            );
            println!(
                "owned={n_owned} foreign={n_foreign} -> {}",
                checked.n_sign_items()
            );
        }
    }
}

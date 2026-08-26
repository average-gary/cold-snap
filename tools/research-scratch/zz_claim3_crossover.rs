// SUPERSEDED 2026-08-19. This file measures the inbound crossover against
// `MAX = 2060`, which DECISIONS.md 7 reversed to 4,096, and against Coldcard's HID
// reassembly cap (shared/usb.py:190) which ../../PLAN.md section 7 establishes is NOT
// this transport at all. Both of its premises are gone. Kept only as the provenance
// of section 7's early inbound figures. DO NOT CITE ITS NUMBERS as current.
//
// Same copy-in/delete constraint as its siblings in this directory: it must be
// COPIED into vendor/frostsnap/frostsnap_core/tests/ to run and DELETED afterwards,
// or it breaks `cargo test -p frostsnap_core` wholesale (26x E0432).
//
// CLAIM #3 part 2: exact crossover of the INBOUND (coordinator -> device) direction,
// which was believed to be the only direction Coldcard caps (shared/usb.py:190).
use frostsnap_comms::BINCODE_CONFIG;
use frostsnap_core::bitcoin_transaction::{LocalSpk, TransactionTemplate};
use frostsnap_core::message::signing::{CoordinatorSigning, OpenNonceStreams};
use frostsnap_core::message::{
    CoordinatorToDeviceMessage, DeviceSignReq, GroupSignReq, RequestSign,
};
use frostsnap_core::nonce_stream::{CoordNonceStreamState, NonceStreamId};
use frostsnap_core::tweak::BitcoinBip32Path;
use frostsnap_core::{MasterAppkey, WireSignTask};
use schnorr_fun::binonce;
use schnorr_fun::fun::prelude::*;
use std::collections::BTreeSet;

const MAX: usize = 2060;
// the 4-byte command prefix is consumed before args (usb.py:223 `self.msg[0:4]`)
const MAX_PAYLOAD: usize = MAX - 4;

fn enc<T: bincode::Encode>(v: &T) -> usize {
    bincode::encode_to_vec(v, BINCODE_CONFIG).unwrap().len()
}

fn scalar_from_u32(v: u32) -> Scalar<Public, NonZero> {
    let mut b = [0u8; 32];
    b[28..].copy_from_slice(&v.to_be_bytes());
    Scalar::<Public, NonZero>::from_bytes(b).unwrap()
}
fn nonce(i: u32) -> binonce::Nonce {
    binonce::Nonce([
        g!(scalar_from_u32(i * 2 + 3) * G).normalize(),
        g!(scalar_from_u32(i * 2 + 4) * G).normalize(),
    ])
}
fn share_index(i: u8) -> schnorr_fun::frost::ShareIndex {
    let mut b = [0u8; 32];
    b[31] = i;
    Scalar::<Public, NonZero>::from_bytes(b).unwrap()
}

fn request_sign_wire_len(n_in: usize, n_out: usize) -> usize {
    let master_appkey = MasterAppkey::derive_from_rootkey((*G).normalize());
    let mut tx = TransactionTemplate::new();
    for i in 0..n_in {
        tx.push_imaginary_owned_input(
            LocalSpk {
                master_appkey,
                bip32_path: BitcoinBip32Path::external(i as u32),
            },
            bitcoin::Amount::from_sat(100_000 + i as u64),
        );
    }
    for j in 0..n_out {
        // realistic p2tr spk = OP_1 <32-byte> = 34 bytes
        let mut spk = vec![0x51u8, 0x20];
        spk.extend(std::iter::repeat(j as u8).take(32));
        tx.push_foreign_output(bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(10_000),
            script_pubkey: bitcoin::ScriptBuf::from_bytes(spk),
        });
    }
    let agg_nonces: Vec<binonce::Nonce<Zero>> = (0..n_in)
        .map(|i| binonce::Nonce::<Zero>::from_bytes(nonce(200 + i as u32).to_bytes()).unwrap())
        .collect();
    let gsr = GroupSignReq {
        parties: (1u8..=3).map(share_index).collect::<BTreeSet<_>>(),
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
            rootkey: (*G).normalize(),
            coord_share_decryption_contrib:
                "0101010101010101010101010101010101010101010101010101010101010101"
                    .parse()
                    .unwrap(),
        },
    };
    let w: frostsnap_comms::WireCoordinatorSendBody = frostsnap_comms::CoordinatorSendBody::Core(
        CoordinatorToDeviceMessage::Signing(CoordinatorSigning::RequestSign(Box::new(req))),
    )
    .into();
    enc(&w)
}

#[test]
fn inbound_crossover() {
    println!("\nInbound cap MAX_MSG_LEN={MAX}, usable payload after 4-byte cmd = {MAX_PAYLOAD}\n");
    let mut first_over = None;
    for n in 1..=30usize {
        let sz = request_sign_wire_len(n, 2);
        let over = sz > MAX_PAYLOAD;
        if over && first_over.is_none() {
            first_over = Some((n, sz));
        }
        println!(
            "RequestSign {n:>2} p2tr inputs / 2 p2tr outputs -> {sz:>5} B  {}",
            if over { "OVER" } else { "fits" }
        );
    }
    println!("\n>>> first input count that exceeds usable payload: {first_over:?}");

    // and confirm inbound OpenNonceStreams is never a problem even unsplit
    for n in [4usize, 8, 16] {
        let streams: Vec<CoordNonceStreamState> = (0..n)
            .map(|i| CoordNonceStreamState {
                stream_id: NonceStreamId([i as u8; 16]),
                index: u32::MAX - 1,
                remaining: u32::MAX - 1,
            })
            .collect();
        let w: frostsnap_comms::WireCoordinatorSendBody =
            frostsnap_comms::CoordinatorSendBody::Core(CoordinatorToDeviceMessage::Signing(
                CoordinatorSigning::OpenNonceStreams(OpenNonceStreams { streams }),
            ))
            .into();
        println!("OpenNonceStreams x{n} unsplit max-varint -> {} B", enc(&w));
    }
}

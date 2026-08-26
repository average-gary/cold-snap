use alloc::vec::Vec;
use alloc::{boxed::Box, collections::BTreeMap};
use bitcoin::{
    consensus::Encodable,
    hashes::{sha256d, Hash},
    key::TweakedPublicKey,
    sighash::SighashCache,
    OutPoint, Script, ScriptBuf, TapSighash, TxOut, Txid,
};

use crate::{
    tweak::{AppTweak, BitcoinBip32Path},
    MasterAppkey,
};

/// Invalid state free representation of a transaction
#[derive(Clone, Debug, bincode::Encode, bincode::Decode, Eq, PartialEq, Hash)]
pub struct TransactionTemplate {
    #[bincode(with_serde)]
    version: bitcoin::blockdata::transaction::Version,
    #[bincode(with_serde)]
    lock_time: bitcoin::absolute::LockTime,
    inputs: Vec<Input>,
    outputs: Vec<Output>,
}

pub struct PushInput<'a> {
    pub prev_txout: PrevTxOut<'a>,
    pub sequence: bitcoin::Sequence,
}

impl<'a> PushInput<'a> {
    pub fn spend_tx_output(transaction: &'a bitcoin::Transaction, vout: u32) -> Self {
        Self {
            prev_txout: PrevTxOut::Full { transaction, vout },
            sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
        }
    }

    pub fn spend_outpoint(txout: &'a TxOut, outpoint: OutPoint) -> Self {
        Self {
            prev_txout: PrevTxOut::Partial { txout, outpoint },
            sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
        }
    }

    pub fn with_sequence(mut self, sequence: bitcoin::Sequence) -> Self {
        self.sequence = sequence;
        self
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrevTxOut<'a> {
    Full {
        transaction: &'a bitcoin::Transaction,
        vout: u32,
    },
    Partial {
        txout: &'a TxOut,
        outpoint: OutPoint,
    },
}

impl<'a> PrevTxOut<'a> {
    pub fn txout(&self) -> &'a TxOut {
        match self {
            PrevTxOut::Full { transaction, vout } => &transaction.output[*vout as usize],
            PrevTxOut::Partial { txout, .. } => txout,
        }
    }

    pub fn outpoint(&self) -> OutPoint {
        match self {
            PrevTxOut::Full { transaction, vout } => OutPoint {
                txid: transaction.compute_txid(),
                vout: *vout,
            },
            PrevTxOut::Partial { outpoint, .. } => *outpoint,
        }
    }
}

impl Default for TransactionTemplate {
    fn default() -> Self {
        Self::new()
    }
}

impl TransactionTemplate {
    pub fn new() -> Self {
        Self {
            version: bitcoin::blockdata::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            inputs: Default::default(),
            outputs: Default::default(),
        }
    }

    pub fn set_version(&mut self, version: bitcoin::blockdata::transaction::Version) {
        self.version = version;
    }

    pub fn set_lock_time(&mut self, lock_time: bitcoin::absolute::LockTime) {
        self.lock_time = lock_time;
    }

    pub fn txid(&self) -> Txid {
        self.to_rust_bitcoin_tx().compute_txid()
    }

    pub fn push_foreign_input(&mut self, input: PushInput) {
        let txout = input.prev_txout.txout();

        self.inputs.push(Input {
            outpoint: input.prev_txout.outpoint(),
            owner: SpkOwner::Foreign(txout.script_pubkey.clone()),
            value: txout.value.to_sat(),
            sequence: input.sequence,
        })
    }
    pub fn push_owned_input(
        &mut self,
        input: PushInput<'_>,
        owner: LocalSpk,
    ) -> Result<(), Box<SpkDoesntMatchPathError>> {
        let txout = input.prev_txout.txout();
        let expected_spk = owner.spk();

        if txout.script_pubkey != expected_spk {
            return Err(Box::new(SpkDoesntMatchPathError {
                got: txout.script_pubkey.clone(),
                expected: expected_spk,
                path: owner
                    .bip32_path
                    .path_segments_from_bitcoin_appkey()
                    .collect(),
                master_appkey: owner.master_appkey,
            }));
        }

        self.inputs.push(Input {
            outpoint: input.prev_txout.outpoint(),
            owner: SpkOwner::Local(owner),
            value: txout.value.to_sat(),
            sequence: input.sequence,
        });
        Ok(())
    }

    pub fn push_imaginary_owned_input(&mut self, owner: LocalSpk, value: bitcoin::Amount) {
        let txout = TxOut {
            value,
            script_pubkey: owner.spk(),
        };
        let mut engine = sha256d::Hash::engine();
        txout.consensus_encode(&mut engine).unwrap();
        let txid = Txid::from_engine(engine);
        let outpoint = OutPoint { txid, vout: 0 };
        self.push_owned_input(PushInput::spend_outpoint(&txout, outpoint), owner)
            .expect("unreachable");
    }

    pub fn push_foreign_output(&mut self, txout: TxOut) {
        self.outputs.push(Output {
            owner: SpkOwner::Foreign(txout.script_pubkey),
            value: txout.value.to_sat(),
        });
    }

    pub fn push_owned_output(&mut self, value: bitcoin::Amount, owner: LocalSpk) {
        self.outputs.push(Output {
            owner: SpkOwner::Local(owner),
            value: value.to_sat(),
        });
    }

    pub fn to_rust_bitcoin_tx(&self) -> bitcoin::Transaction {
        bitcoin::Transaction {
            version: self.version,
            lock_time: self.lock_time,
            input: self
                .inputs
                .iter()
                .map(|input| bitcoin::TxIn {
                    previous_output: input.outpoint,
                    sequence: input.sequence,
                    ..Default::default()
                })
                .collect(),
            output: self.outputs.iter().map(|output| output.txout()).collect(),
        }
    }

    pub fn inputs(&self) -> &[Input] {
        &self.inputs
    }

    pub fn outputs(&self) -> &[Output] {
        &self.outputs
    }

    pub fn iter_sighash(&self) -> impl Iterator<Item = TapSighash> {
        let tx = self.to_rust_bitcoin_tx();
        let mut sighash_cache = SighashCache::new(tx);
        let schnorr_sighashty = bitcoin::sighash::TapSighashType::Default;
        let prevouts = self.inputs.iter().map(Input::txout).collect::<Vec<_>>();
        (0..self.inputs.len()).map(move |i| {
            sighash_cache
                .taproot_key_spend_signature_hash(
                    i,
                    &bitcoin::sighash::Prevouts::All(&prevouts),
                    schnorr_sighashty,
                )
                .expect("inputs are right length")
        })
    }

    pub fn iter_sighashes_of_locally_owned_inputs(
        &self,
    ) -> impl Iterator<Item = (LocalSpk, TapSighash)> + '_ {
        self.inputs
            .iter()
            .zip(self.iter_sighash())
            .filter_map(|(input, sighash)| {
                let owner = input.owner.local_owner()?.clone();
                Some((owner, sighash))
            })
    }

    pub fn iter_locally_owned_inputs(&self) -> impl Iterator<Item = (usize, &Input, &LocalSpk)> {
        self.inputs
            .iter()
            .enumerate()
            .filter_map(|(i, input)| Some((i, input, input.owner.local_owner()?)))
    }

    pub fn iter_locally_owned_outputs(&self) -> impl Iterator<Item = (usize, &Output, &LocalSpk)> {
        self.outputs
            .iter()
            .enumerate()
            .filter_map(|(i, output)| Some((i, output, output.owner.local_owner()?)))
    }

    /// Returns true if this transaction has any inputs that need signing by this wallet.
    pub fn has_any_inputs_to_sign(&self) -> bool {
        self.inputs
            .iter()
            .any(|input| input.owner.local_owner().is_some())
    }

    /// Total input value minus total output value, or `None` if the template is
    /// not arithmetically valid.
    ///
    /// cold-snap change: both sums were `.sum::<u64>()`, which overflows on
    /// wire-supplied values. This is the device's *only* arithmetic validation of
    /// a sign request — `WireSignTask::check` rejects `fee().is_none()`
    /// (`sign_task.rs:88-90`) before the user is ever prompted — so an overflow
    /// here is not merely a panic risk, it is a validation **bypass**: under
    /// `overflow-checks = false` (`Cargo.toml:82`, the shipped release profile)
    /// the wrap is silent, so a coordinator sending inputs that sum past
    /// `u64::MAX` gets `Some(<wrapped garbage>)` and the check whose whole job is
    /// to reject an invalid transaction passes it. Note the dev profile leaves
    /// `overflow-checks` at its `true` default, so the same message panicked
    /// under `cargo test` and wrapped in firmware — the two profiles disagreed
    /// about what the bug even was.
    ///
    /// `checked_add` makes both profiles behave identically and turns the
    /// overflow into the `InvalidBitcoinTransaction` refusal the caller already
    /// handles. It does **not** bound the individual values: see `net_value`.
    pub fn fee(&self) -> Option<u64> {
        let inputs = self
            .inputs
            .iter()
            .try_fold(0u64, |acc, input| acc.checked_add(input.value))?;
        let outputs = self
            .outputs
            .iter()
            .try_fold(0u64, |acc, output| acc.checked_add(output.value))?;
        inputs.checked_sub(outputs)
    }

    pub fn feerate(&self) -> Option<f64> {
        let mut tx = self.to_rust_bitcoin_tx();

        for (i, input) in self.inputs.iter().enumerate() {
            if input.owner().local_owner().is_some() {
                tx.input[i].witness.push([0u8; 64]);
            } else {
                return None;
            }
        }

        let vbytes = tx.weight().to_vbytes_ceil() as f64;
        Some(self.fee()? as f64 / vbytes)
    }

    /// Per-owner net value change, or `None` if any value does not fit an `i64`
    /// or the running total would overflow.
    ///
    /// cold-snap change: this was infallible and used
    /// `i64::try_from(..).expect("input ridiciously large")` on both loops, plus
    /// bare `-=`/`+=`. Every one of those is a panic on wire-supplied `u64`
    /// values, and under `panic = "abort"` a panic is a reset loop.
    ///
    /// The `fee()` guard at `sign_task.rs:88-90` does **not** protect this, and
    /// that is worth being precise about: `fee()` bounds only the *difference*
    /// between the sums, never the individual magnitudes. One input of `2^63` and
    /// one output of `2^63` gives `fee() == Some(0)`, so the template is accepted
    /// as valid — and then `i64::try_from(2^63)` fails here. Fixing `fee()` to use
    /// `checked_add` does not close this; the two are independent.
    ///
    /// Returning `Option` rather than saturating is deliberate: this feeds the
    /// amounts shown to the user for approval, and a saturated total is a
    /// *plausible-looking wrong number* on a consent screen. Refusing to display
    /// is the fail-closed direction.
    pub fn net_value(&self) -> Option<BTreeMap<RootOwner, i64>> {
        let mut spk_to_value: BTreeMap<RootOwner, i64> = Default::default();

        for input in &self.inputs {
            let delta = i64::try_from(input.value).ok()?;
            let value = spk_to_value.entry(input.owner.root_owner()).or_default();
            *value = value.checked_sub(delta)?;
        }

        for output in &self.outputs {
            let delta = i64::try_from(output.value).ok()?;
            let value = spk_to_value.entry(output.owner.root_owner()).or_default();
            *value = value.checked_add(delta)?;
        }

        Some(spk_to_value)
    }

    pub fn foreign_recipients(&self) -> impl Iterator<Item = (&Script, u64)> {
        self.outputs
            .iter()
            .filter_map(|output| match &output.owner {
                SpkOwner::Foreign(spk) => Some((spk.as_script(), output.value)),
                _ => None,
            })
    }

    /// Render the approval screen's contents, or `None` if this template is not
    /// displayable.
    ///
    /// cold-snap change: this was infallible and held two `expect`s on
    /// coordinator-supplied data. The `Address::from_script` one was live —
    /// `Address::from_script` returns `Err(FromScriptError::UnrecognizedScript)`
    /// for any script that is not p2pkh/p2sh/witness-program (bitcoin 0.32.8
    /// `address/mod.rs:567-590`), which includes OP_RETURN, bare/P2PK, bare
    /// multisig and the empty script, and **nothing** validates a foreign output's
    /// script before this point. `WireSignTask::check` (`sign_task.rs:58-96`)
    /// checks owner keys, that something is ours to sign, and `fee()`; it does not
    /// look at foreign spks, and its own test asserts a `ScriptBuf::new()` output
    /// is accepted (`sign_task.rs:343-350`). An OP_RETURN output is an ordinary
    /// thing for a coordinator to send.
    ///
    /// It is unreachable *today* only because nothing calls this yet — the
    /// upstream callers are the non-vendored display crates, and our replacement
    /// is PLAN.md phase 5. The device currently hands the UI the raw
    /// `TransactionTemplate` (`device.rs:377-381`), so this becomes reachable the
    /// moment a sign-approval screen exists. Under `panic = "abort"` that is a
    /// reset loop triggered by a wire message.
    ///
    /// Returning `Option` is the fail-closed direction: a device that cannot
    /// render what it is being asked to authorise must refuse to ask, not display
    /// a partial list. A caller must treat `None` as "reject this request".
    pub fn user_prompt(&self, network: bitcoin::Network) -> Option<PromptSignBitcoinTx> {
        let fee = bitcoin::Amount::from_sat(self.fee()?);
        let foreign_recipients = self
            .foreign_recipients()
            .map(|(spk, value)| {
                Some((
                    bitcoin::Address::from_script(spk, network).ok()?,
                    bitcoin::Amount::from_sat(value),
                ))
            })
            .collect::<Option<Vec<_>>>()?;

        // Calculate fee rate in sats/vB
        let fee_rate_sats_per_vbyte = self.feerate();

        Some(PromptSignBitcoinTx {
            foreign_recipients,
            fee,
            fee_rate_sats_per_vbyte,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct PromptSignBitcoinTx {
    pub foreign_recipients: Vec<(bitcoin::Address, bitcoin::Amount)>,
    pub fee: bitcoin::Amount,
    /// Fee rate in sats/vB
    pub fee_rate_sats_per_vbyte: Option<f64>,
}

impl PromptSignBitcoinTx {
    /// Calculate the total amount being sent to foreign recipients
    pub fn total_sent(&self) -> bitcoin::Amount {
        self.foreign_recipients
            .iter()
            .map(|(_, amount)| *amount)
            .sum()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum RootOwner {
    Local(MasterAppkey),
    Foreign(ScriptBuf),
}

/// The provided spk doesn't match what was derived from the derivation path
#[derive(Debug, Clone)]
pub struct SpkDoesntMatchPathError {
    pub got: ScriptBuf,
    pub expected: ScriptBuf,
    pub path: Vec<u32>,
    pub master_appkey: MasterAppkey,
}

impl core::fmt::Display for SpkDoesntMatchPathError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "the script pubkey {:?} didn't match what we expected {:?} at derivation path {:?} from {}", self.got, self.expected, self.path, self.master_appkey)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SpkDoesntMatchPathError {}

#[derive(bincode::Decode, bincode::Encode, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Input {
    #[bincode(with_serde)]
    outpoint: OutPoint,
    value: u64,
    owner: SpkOwner,
    #[bincode(with_serde)]
    sequence: bitcoin::Sequence,
}

impl Input {
    pub fn outpoint(&self) -> OutPoint {
        self.outpoint
    }
    pub fn txout(&self) -> TxOut {
        TxOut {
            value: bitcoin::Amount::from_sat(self.value),
            script_pubkey: self.owner.spk(),
        }
    }

    pub fn raw_spk(&self) -> ScriptBuf {
        self.owner.spk()
    }

    pub fn owner(&self) -> &SpkOwner {
        &self.owner
    }
}

#[derive(bincode::Encode, bincode::Decode, Clone, Debug, PartialEq, Eq, Hash)]
pub struct LocalSpk {
    pub master_appkey: MasterAppkey,
    pub bip32_path: BitcoinBip32Path,
}

impl LocalSpk {
    pub fn spk(&self) -> ScriptBuf {
        let expected_external_xonly =
            AppTweak::Bitcoin(self.bip32_path).derive_xonly_key(&self.master_appkey.to_xpub());
        // cold-snap change (decision 3): was `expected_external_xonly.into()`, which
        // needed `secp256kfun`'s `libsecp_compat_0_29` feature. That `From` impl was
        // itself only `XOnlyPublicKey::from_slice(point.to_xonly_bytes())`, so this is
        // the same 32-byte serialize/reparse with the feature dropped. The key is
        // already BIP-341 tweaked by `derive_xonly_key`, hence
        // `dangerous_assume_tweaked`.
        let xonly = bitcoin::secp256k1::XOnlyPublicKey::from_slice(
            &expected_external_xonly.to_xonly_bytes(),
        )
        .expect("a secp256kfun Point<EvenY> is always a valid x-only public key");
        ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(xonly))
    }
}

#[derive(bincode::Encode, bincode::Decode, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Output {
    pub value: u64,
    pub owner: SpkOwner,
}

impl Output {
    pub fn txout(&self) -> TxOut {
        TxOut {
            value: bitcoin::Amount::from_sat(self.value),
            script_pubkey: self.owner.spk(),
        }
    }

    pub fn local_owner(&self) -> Option<&LocalSpk> {
        self.owner.local_owner()
    }

    pub fn owner(&self) -> &SpkOwner {
        &self.owner
    }
}

#[derive(bincode::Encode, bincode::Decode, Clone, Debug, PartialEq, Eq, Hash)]
pub enum SpkOwner {
    Foreign(#[bincode(with_serde)] ScriptBuf),
    Local(LocalSpk),
}

impl SpkOwner {
    pub fn root_owner(&self) -> RootOwner {
        match self {
            SpkOwner::Foreign(spk) => RootOwner::Foreign(spk.clone()),
            SpkOwner::Local(local) => RootOwner::Local(local.master_appkey),
        }
    }
    pub fn spk(&self) -> ScriptBuf {
        match self {
            SpkOwner::Foreign(spk) => spk.clone(),
            SpkOwner::Local(owner) => owner.spk(),
        }
    }

    pub fn local_owner_key(&self) -> Option<MasterAppkey> {
        match self {
            SpkOwner::Foreign(_) => None,
            SpkOwner::Local(owner) => Some(owner.master_appkey),
        }
    }

    pub fn local_owner(&self) -> Option<&LocalSpk> {
        match self {
            SpkOwner::Foreign(_) => None,
            SpkOwner::Local(owner) => Some(owner),
        }
    }
}

/// cold-snap addition (decision 3). `LocalSpk::spk` is the end of the address
/// derivation pipeline — master appkey -> BIP-32 -> BIP-341 tweak -> scriptPubKey —
/// and nothing upstream covered it, so an error anywhere in that chain (including in
/// the hand-rolled tagged hash, or in the x-only serialize/reparse just above) would
/// silently change every receive address rather than fail a test.
///
/// The expected scriptPubKeys were computed independently of this codebase, with a
/// from-scratch Python secp256k1 + BIP-32 + BIP-341 implementation, from the
/// generator point as rootkey.
#[cfg(test)]
mod local_spk_regression {
    use super::*;
    use crate::tweak::{BitcoinBip32Path, Xpub};
    use schnorr_fun::fun::prelude::*;

    #[test]
    fn spk_matches_independently_computed_vectors() {
        // MasterAppkey::derive_from_rootkey(G) — a fixed, reproducible starting point.
        let master_appkey = MasterAppkey::derive_from_rootkey(G.normalize());
        assert_eq!(
            master_appkey.to_xpub().key.to_bytes(),
            Xpub::<Point>::from_rootkey(G.normalize())
                .rootkey_to_master_appkey()
                .key
                .to_bytes()
        );

        for (bip32_path, expected_spk_hex) in [
            (
                BitcoinBip32Path::external(0),
                "51206bc8a5389a5f073608c28771846967ce313d4d3e0c55b0534cc651a0237705a0",
            ),
            (
                BitcoinBip32Path::internal(7),
                "5120e5b21e4ba6978778574694f32205688d83a7b8433397481ebdb9e1a2dce2b042",
            ),
        ] {
            let spk = LocalSpk {
                master_appkey,
                bip32_path,
            }
            .spk();

            assert_eq!(
                alloc::format!("{spk:x}"),
                expected_spk_hex,
                "scriptPubKey mismatch for {bip32_path:?}"
            );
            // A v1 witness program, i.e. actually spendable as taproot.
            assert!(spk.is_p2tr(), "not a p2tr spk for {bip32_path:?}");
        }
    }
}

/// cold-snap addition. Every test here is a panic or a validation bypass that a
/// coordinator can trigger with one wire message, on values that arrive as plain
/// derived `bincode::Decode` with no bounds anywhere in the pipeline
/// (`frostsnap_comms/src/lib.rs:211-214` decodes straight into these types).
///
/// These deliberately assert on `TransactionTemplate` directly rather than through
/// `WireSignTask::check`: `user_prompt` and `net_value` are methods on the
/// *template*, not on `CheckedSignTask`, so a phase-5 UI author can reach them
/// without a check having run. The type is the only thing that can hold the
/// invariant, which is why these return `Option`.
#[cfg(test)]
mod wire_value_bounds {
    use super::*;
    use crate::tweak::BitcoinBip32Path;
    use bitcoin::{Amount, Network, ScriptBuf};
    use schnorr_fun::fun::prelude::*;

    fn owner() -> LocalSpk {
        LocalSpk {
            master_appkey: MasterAppkey::derive_from_rootkey(g!(2 * G).normalize()),
            bip32_path: BitcoinBip32Path::external(0),
        }
    }

    /// Build a template from raw wire values, bypassing the builder API. The
    /// builder cannot express these (it derives `value` from a real `TxOut`), but
    /// the wire format can, and the wire format is what an attacker controls.
    fn from_wire(inputs: &[u64], outputs: &[u64]) -> TransactionTemplate {
        let mut tx = TransactionTemplate::new();
        for (i, value) in inputs.iter().enumerate() {
            tx.inputs.push(Input {
                outpoint: OutPoint::new(Txid::from_byte_array([i as u8; 32]), 0),
                value: *value,
                owner: SpkOwner::Local(owner()),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            });
        }
        for value in outputs {
            tx.outputs.push(Output {
                value: *value,
                owner: SpkOwner::Foreign(ScriptBuf::new_op_return([])),
            });
        }
        tx
    }

    /// THE VALIDATION BYPASS. `fee()` is the device's only arithmetic check on a
    /// sign request — `WireSignTask::check` rejects `fee().is_none()`
    /// (`sign_task.rs:88-90`) before the user sees anything. With `.sum::<u64>()`
    /// these inputs wrapped, so `fee()` returned `Some(garbage)` and the check
    /// passed a transaction it exists to reject. Silently, in release:
    /// `overflow-checks = false` (`Cargo.toml:82`).
    #[test]
    fn input_sum_overflow_is_refused_rather_than_wrapped() {
        let tx = from_wire(&[u64::MAX, 2], &[1]);
        assert_eq!(
            tx.fee(),
            None,
            "wrapped instead of refusing: this is what let an invalid tx past check()"
        );

        // The wrapped value the old code produced, spelled out so the test states
        // what the bug actually was rather than only that it is gone.
        let wrapped = u64::MAX.wrapping_add(2).wrapping_sub(1);
        assert_eq!(wrapped, 0, "the wrap made a bogus tx look like a zero-fee tx");
    }

    /// Same bypass from the output side.
    #[test]
    fn output_sum_overflow_is_refused() {
        let tx = from_wire(&[10], &[u64::MAX, 5]);
        assert_eq!(tx.fee(), None);
    }

    /// A legitimate template must still price normally — a refusal that refuses
    /// everything would be worse than the bug.
    #[test]
    fn ordinary_values_still_produce_a_fee() {
        let tx = from_wire(&[100_000], &[90_000]);
        assert_eq!(tx.fee(), Some(10_000));
        assert_eq!(from_wire(&[100_000], &[100_001]).fee(), None, "outputs > inputs");
        assert_eq!(from_wire(&[], &[]).fee(), Some(0));
    }

    /// `net_value` used `i64::try_from(..).expect("input ridiciously large")`.
    /// Critically, `fee()`'s guard does NOT protect it: `fee()` bounds only the
    /// *difference* between the sums, never the magnitudes. This template is
    /// accepted as valid by `check` and still overflows an `i64`, so fixing
    /// `fee()` alone would have left the panic reachable.
    #[test]
    fn net_value_refuses_values_that_do_not_fit_i64_even_when_the_fee_is_valid() {
        let huge = 1u64 << 63;
        let tx = from_wire(&[huge], &[huge]);

        assert_eq!(
            tx.fee(),
            Some(0),
            "precondition: check() accepts this, so net_value cannot rely on fee()"
        );
        assert!(i64::try_from(huge).is_err(), "precondition: 2^63 overflows i64");
        assert_eq!(tx.net_value(), None, "this expect() was a reset loop");
    }

    /// Two inputs that each fit an `i64` but whose running total does not. The
    /// old `*value -= ..` was a bare subtraction, so this wrapped in release and
    /// panicked in dev.
    #[test]
    fn net_value_refuses_when_the_running_total_overflows() {
        let big = i64::MAX as u64;
        let tx = from_wire(&[big, big], &[]);
        assert!(i64::try_from(big).is_ok(), "precondition: each value fits alone");
        assert_eq!(tx.net_value(), None);
    }

    #[test]
    fn net_value_still_works_on_ordinary_values() {
        let tx = from_wire(&[100_000], &[90_000]);
        let net = tx.net_value().expect("ordinary values must render");
        assert_eq!(net.get(&RootOwner::Local(owner().master_appkey)), Some(&-100_000));
        assert_eq!(
            net.get(&RootOwner::Foreign(ScriptBuf::new_op_return([]))),
            Some(&90_000)
        );
    }

    /// THE PANIC PHASE 5 WOULD HAVE SHIPPED. An OP_RETURN output has no address
    /// representation (`Address::from_script` gives `UnrecognizedScript`), nothing
    /// validates foreign spks — `sign_task.rs:332-352` asserts an unaddressable
    /// output is *accepted* — and the device hands the UI this raw template
    /// (`device.rs:377-381`). So the first sign-approval screen would have
    /// reset-looped on a legal transaction.
    #[test]
    fn unaddressable_foreign_output_refuses_to_render_instead_of_panicking() {
        let tx = from_wire(&[100_000], &[90_000]);
        assert!(
            bitcoin::Address::from_script(&ScriptBuf::new_op_return([]), Network::Bitcoin).is_err(),
            "precondition: OP_RETURN has no address form"
        );
        assert_eq!(tx.user_prompt(Network::Bitcoin), None);
    }

    /// The empty script is the same class and is what `sign_task.rs:345` sends.
    #[test]
    fn empty_foreign_script_refuses_to_render() {
        let mut tx = from_wire(&[100_000], &[]);
        tx.outputs.push(Output {
            value: 90_000,
            owner: SpkOwner::Foreign(ScriptBuf::new()),
        });
        assert_eq!(tx.user_prompt(Network::Bitcoin), None);
    }

    /// An addressable recipient must still render, with the right fee and amount.
    #[test]
    fn addressable_foreign_output_still_renders() {
        let mut tx = from_wire(&[100_000], &[]);
        let recipient = LocalSpk {
            master_appkey: MasterAppkey::derive_from_rootkey(g!(3 * G).normalize()),
            bip32_path: BitcoinBip32Path::external(1),
        }
        .spk();
        assert!(recipient.is_p2tr());
        tx.outputs.push(Output {
            value: 90_000,
            owner: SpkOwner::Foreign(recipient.clone()),
        });

        let prompt = tx
            .user_prompt(Network::Bitcoin)
            .expect("a p2tr recipient must render");
        assert_eq!(prompt.fee, Amount::from_sat(10_000));
        assert_eq!(prompt.total_sent(), Amount::from_sat(90_000));
        assert_eq!(prompt.foreign_recipients.len(), 1);
        assert_eq!(
            prompt.foreign_recipients[0].0,
            bitcoin::Address::from_script(&recipient, Network::Bitcoin).unwrap()
        );
    }

    /// One unaddressable output among several must fail the WHOLE prompt, not be
    /// silently dropped from the recipient list. A consent screen that omits a
    /// recipient is worse than one that refuses to appear.
    #[test]
    fn one_unrenderable_recipient_fails_the_whole_prompt() {
        let mut tx = from_wire(&[100_000], &[]);
        tx.outputs.push(Output {
            value: 40_000,
            owner: SpkOwner::Foreign(
                LocalSpk {
                    master_appkey: MasterAppkey::derive_from_rootkey(g!(3 * G).normalize()),
                    bip32_path: BitcoinBip32Path::external(1),
                }
                .spk(),
            ),
        });
        tx.outputs.push(Output {
            value: 50_000,
            owner: SpkOwner::Foreign(ScriptBuf::new_op_return([])),
        });

        assert_eq!(
            tx.user_prompt(Network::Bitcoin),
            None,
            "dropped a recipient from the approval screen instead of refusing"
        );
    }

    /// `user_prompt` must not be able to reach `fee()`'s own failure either: an
    /// overflowing template refuses at the fee step rather than displaying one.
    #[test]
    fn a_template_with_an_overflowing_fee_does_not_render() {
        let mut tx = from_wire(&[u64::MAX, 2], &[]);
        tx.outputs.push(Output {
            value: 1,
            owner: SpkOwner::Foreign(
                LocalSpk {
                    master_appkey: MasterAppkey::derive_from_rootkey(g!(3 * G).normalize()),
                    bip32_path: BitcoinBip32Path::external(1),
                }
                .spk(),
            ),
        });
        assert_eq!(tx.fee(), None);
        assert_eq!(tx.user_prompt(Network::Bitcoin), None);
    }

    /// The device's own validation must reject the overflowing template, since
    /// that is the seam that actually protects the signing path today.
    #[test]
    fn check_rejects_a_template_whose_fee_overflows() {
        use crate::device::KeyPurpose;
        use crate::sign_task::{SignTaskError, WireSignTask};

        let signing = owner().master_appkey;
        let tx = from_wire(&[u64::MAX, 2], &[1]);

        let result = WireSignTask::BitcoinTransaction(tx).check(signing, KeyPurpose::Bitcoin(Network::Bitcoin));
        assert!(
            matches!(result, Err(SignTaskError::InvalidBitcoinTransaction)),
            "an overflowing fee reached the user: {result:?}"
        );
    }
}

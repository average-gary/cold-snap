use bitcoin::{
    bip32::*,
    hashes::{sha512, Hash, HashEngine, Hmac, HmacEngine},
    secp256k1, NetworkKind,
};
use schnorr_fun::{
    frost::{PairedSecretShare, SharedKey},
    fun::{g, marker::*, Point, Scalar, G},
};

/// The BIP-341 `TapTweak` for the key-path-only case (`merkle_root == None`):
///
/// ```text
/// t = H_TapTweak(P_x)
/// H_TapTweak(m) = SHA256(SHA256("TapTweak") || SHA256("TapTweak") || m)
/// ```
///
/// `P_x` is the 32-byte big-endian x-coordinate of the internal key, and nothing
/// else is hashed — no length prefix, no merkle bytes (BIP-341: "If the spending
/// conditions do not require a script path, the output key should commit to an
/// unspendable script path").
///
/// cold-snap change (`../../../PLAN.md` §2.2, decision 3): upstream called
/// `bitcoin::taproot::TapTweakHash::from_key_and_tweak(k.to_libsecp_xonly(), None)`,
/// which round-tripped the point through the C libsecp256k1 `XOnlyPublicKey` type
/// to reach a hash that does no EC math at all. `secp256kfun`'s `Tag` builds the
/// identical BIP-340 midstate (it feeds `SHA256(tag)` into the outer hash
/// `BlockSize / OutputSize == 2` times), so this is byte-for-byte equivalent with
/// no C dependency — the same construction `schnorr_fun` already uses for the
/// consensus-critical `BIP0340/challenge` hash.
///
/// Proven against the published BIP-341 and BIP-86 vectors in
/// `bip341_taptweak_vectors` below, and differentially against rust-bitcoin for as
/// long as that crate is still in the graph.
fn bip341_taptweak_key_only(internal_key_xonly: [u8; 32]) -> [u8; 32] {
    use schnorr_fun::fun::hash::Tag as _;
    use sha2::Digest as _;

    let mut hash = sha2::Sha256::default().tag(b"TapTweak");
    hash.update(internal_key_xonly);
    hash.finalize().into()
}

#[derive(
    Clone, Copy, Debug, PartialEq, bincode::Encode, bincode::Decode, Eq, Hash, PartialOrd, Ord,
)]
pub enum AccountKind {
    Segwitv1 = 0,
}

impl AccountKind {
    pub fn path_segments_from_bitcoin_appkey(&self) -> impl Iterator<Item = u32> {
        core::iter::once(*self as u32)
    }
}

#[derive(
    Clone, Copy, Debug, PartialEq, bincode::Encode, bincode::Decode, Eq, Hash, PartialOrd, Ord,
)]
pub enum Keychain {
    External = 0,
    Internal = 1,
}

#[derive(Clone, Debug, PartialEq, bincode::Encode, bincode::Decode, Eq, PartialOrd, Ord)]
pub enum AppTweak {
    TestMessage,
    Bitcoin(BitcoinBip32Path),
    Nostr,
}

#[derive(
    Clone, Copy, Debug, PartialEq, bincode::Encode, bincode::Decode, Eq, Hash, PartialOrd, Ord,
)]
pub struct BitcoinBip32Path {
    pub account_keychain: BitcoinAccountKeychain,
    pub index: u32,
}

impl BitcoinBip32Path {
    pub fn external(index: u32) -> Self {
        Self {
            account_keychain: BitcoinAccountKeychain::external(),
            index,
        }
    }

    pub fn internal(index: u32) -> Self {
        Self {
            account_keychain: BitcoinAccountKeychain::internal(),
            index,
        }
    }
}

impl From<BitcoinBip32Path> for DerivationPath {
    fn from(bip32_path: BitcoinBip32Path) -> Self {
        DerivationPath::from_normal_path_segments(
            bip32_path
                .account_keychain
                .account
                .path_segments_from_bitcoin_appkey()
                .chain(core::iter::once(bip32_path.index)),
        )
    }
}

#[derive(
    Clone, Copy, Debug, PartialEq, bincode::Encode, bincode::Decode, Eq, Hash, PartialOrd, Ord,
)]
pub struct BitcoinAccount {
    pub kind: AccountKind,
    pub index: u32,
}

impl BitcoinAccount {
    pub fn path_segments_from_bitcoin_appkey(&self) -> impl Iterator<Item = u32> {
        self.kind
            .path_segments_from_bitcoin_appkey()
            .chain(core::iter::once(self.index))
    }
}

impl Default for BitcoinAccount {
    fn default() -> Self {
        Self {
            kind: AccountKind::Segwitv1,
            index: 0,
        }
    }
}

#[derive(
    Clone, Copy, Debug, PartialEq, bincode::Encode, bincode::Decode, Eq, Hash, PartialOrd, Ord,
)]
pub struct BitcoinAccountKeychain {
    pub account: BitcoinAccount,
    pub keychain: Keychain,
}

impl BitcoinAccountKeychain {
    pub fn external() -> Self {
        Self {
            account: BitcoinAccount::default(),
            keychain: Keychain::External,
        }
    }

    pub fn internal() -> Self {
        Self {
            account: BitcoinAccount::default(),
            keychain: Keychain::Internal,
        }
    }

    pub fn path_segments_from_bitcoin_appkey(&self) -> impl Iterator<Item = u32> {
        self.account
            .path_segments_from_bitcoin_appkey()
            .chain(core::iter::once(self.keychain as u32))
    }
}

impl BitcoinBip32Path {
    pub fn path_segments_from_bitcoin_appkey(&self) -> impl Iterator<Item = u32> {
        self.account_keychain
            .path_segments_from_bitcoin_appkey()
            .chain(core::iter::once(self.index))
    }

    pub fn from_u32_slice(path: &[u32]) -> Option<Self> {
        if path.len() != 4 {
            return None;
        }

        let account_kind = match path[0] {
            0 => AccountKind::Segwitv1,
            _ => return None,
        };

        let account_index = path[1];
        let account = BitcoinAccount {
            kind: account_kind,
            index: account_index,
        };

        let keychain = match path[2] {
            0 => Keychain::External,
            1 => Keychain::Internal,
            _ => return None,
        };

        let _check_it = ChildNumber::from_normal_idx(path[2]).ok()?;
        let index = path[3];

        Some(BitcoinBip32Path {
            account_keychain: BitcoinAccountKeychain { account, keychain },
            index,
        })
    }
}

impl AppTweak {
    pub fn kind(&self) -> AppTweakKind {
        match self {
            AppTweak::Bitcoin { .. } => AppTweakKind::Bitcoin,
            AppTweak::Nostr => AppTweakKind::Nostr,
            AppTweak::TestMessage => AppTweakKind::TestMessage,
        }
    }

    pub fn derive_xonly_key<K: TweakableKey>(&self, master_appkey: &Xpub<K>) -> K::XOnly {
        let appkey = master_appkey.derive_bip32([self.kind() as u32]);

        match &self {
            AppTweak::Bitcoin(bip32_path) => {
                let concrete_internal_key =
                    appkey.derive_bip32(bip32_path.path_segments_from_bitcoin_appkey());
                let derived_key = concrete_internal_key.into_key();
                // `to_key().to_xonly_bytes()` drops the parity byte, matching BIP-341's
                // `lift_x(P)`: the tweak commits to the even-y interpretation, which is
                // also what `into_xonly_with_tweak` then adds `t*G` to.
                let tweak = bip341_taptweak_key_only(derived_key.to_key().to_xonly_bytes());
                derived_key.into_xonly_with_tweak(
                    Scalar::<Public, _>::from_bytes_mod_order(tweak)
                        .non_zero()
                        .expect("computationally unreachable"),
                )
            }
            AppTweak::Nostr => appkey.into_key().into_xonly(),
            AppTweak::TestMessage => appkey.into_key().into_xonly(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Ord, Eq)]
pub enum AppTweakKind {
    Bitcoin = 0,
    TestMessage = 1,
    Nostr = 2,
}

impl AppTweakKind {
    pub fn derivation_path(&self) -> DerivationPath {
        DerivationPath::master().child(ChildNumber::Normal {
            index: *self as u32,
        })
    }
}

pub trait TweakableKey: Clone + core::fmt::Debug {
    type XOnly;
    fn to_key(&self) -> Point;
    /// cold-snap change (decision 3): was `self.to_key().into()`, which needed
    /// `secp256kfun`'s `libsecp_compat_0_29` feature. That `From` impl was itself
    /// only `PublicKey::from_slice(pk.to_bytes())`, so spelling it out here is
    /// identical — a 33-byte SEC1 serialize/reparse — and lets the feature be
    /// dropped. Still returns a C libsecp type because `bitcoin::bip32::Xpub`
    /// demands one; see `to_bitcoin_xpub_with_lies`.
    fn to_libsecp_key(&self) -> secp256k1::PublicKey {
        secp256k1::PublicKey::from_slice(&self.to_key().to_bytes())
            .expect("a secp256kfun Point is always a valid public key")
    }
    /// Unused since cold-snap moved the BIP-341 tweak off rust-bitcoin (decision 3);
    /// its only caller was `AppTweak::derive_xonly_key`. Kept because it is part of a
    /// `pub trait` upstream still uses, and because dropping it would be a wider
    /// rebase conflict than it is worth. Delete along with the `bitcoin` dependency.
    fn to_libsecp_xonly(&self) -> secp256k1::XOnlyPublicKey {
        self.to_key().to_libsecp_xonly()
    }
    fn tweak(self, tweak: Scalar<Public, Zero>) -> Self;
    fn into_xonly_with_tweak(self, tweak: Scalar<Public>) -> Self::XOnly;
    fn into_xonly(self) -> Self::XOnly;
}

impl TweakableKey for SharedKey<Normal> {
    type XOnly = SharedKey<EvenY>;

    fn to_key(&self) -> Point {
        self.public_key()
    }

    fn tweak(self, tweak: Scalar<Public, Zero>) -> Self {
        self.homomorphic_add(tweak)
            .non_zero()
            .expect("computationally unreachable")
    }

    fn into_xonly_with_tweak(self, tweak: Scalar<Public>) -> Self::XOnly {
        self.into_xonly()
            .homomorphic_add(tweak)
            .non_zero()
            .expect("computationally unreachable")
            .into_xonly()
    }

    fn into_xonly(self) -> Self::XOnly {
        SharedKey::into_xonly(self)
    }
}

impl TweakableKey for PairedSecretShare {
    type XOnly = PairedSecretShare<EvenY>;

    fn to_key(&self) -> Point {
        self.public_key().to_key()
    }

    fn tweak(self, tweak: Scalar<Public, Zero>) -> Self {
        self.homomorphic_add(tweak)
            .non_zero()
            .expect("computationally unreachable")
    }

    fn into_xonly_with_tweak(self, tweak: Scalar<Public>) -> Self::XOnly {
        self.into_xonly()
            .homomorphic_add(tweak)
            .non_zero()
            .expect("computationally unreachable")
            .into_xonly()
    }

    fn into_xonly(self) -> Self::XOnly {
        PairedSecretShare::into_xonly(self)
    }
}

impl TweakableKey for Point {
    type XOnly = Point<EvenY>;

    fn to_key(&self) -> Point {
        *self
    }

    fn tweak(self, tweak: Scalar<Public, Zero>) -> Self {
        g!(self + tweak * G)
            .normalize()
            .non_zero()
            .expect("if tweak is a hash this should be unreachable")
    }

    fn into_xonly_with_tweak(self, tweak: Scalar<Public>) -> Self::XOnly {
        let (even_y, _) = self.into_point_with_even_y();
        let (tweaked_even_y, _) = g!(even_y + tweak * G)
            .normalize()
            .non_zero()
            .expect("if tweak is a hash this should be unreachable")
            .into_point_with_even_y();
        tweaked_even_y
    }

    fn to_libsecp_xonly(&self) -> secp256k1::XOnlyPublicKey {
        secp256k1::XOnlyPublicKey::from_slice(self.to_xonly_bytes().as_ref()).unwrap()
    }

    fn into_xonly(self) -> Self::XOnly {
        let (even_y, _) = self.into_point_with_even_y();
        even_y
    }
}

impl<T: TweakableKey> Xpub<T> {
    pub fn from_rootkey(rootkey: T) -> Self {
        Xpub {
            chaincode: [0u8; 32],
            key: rootkey,
        }
    }

    pub fn rootkey_to_master_appkey(&self) -> Xpub<T> {
        let mut master_appkey = self.clone();
        master_appkey.derive_bip32_in_place([0]);
        master_appkey
    }

    pub fn new(key: T, chaincode: [u8; 32]) -> Self {
        Xpub { chaincode, key }
    }

    /// Does non-hardened derivation in place
    pub fn derive_bip32_in_place(&mut self, segments: impl IntoIterator<Item = u32>) {
        for child in segments.into_iter() {
            let mut hmac_engine: HmacEngine<sha512::Hash> = HmacEngine::new(&self.chaincode[..]);
            hmac_engine.input(&self.key().to_key().to_bytes());
            hmac_engine.input(&child.to_be_bytes());
            let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);

            self.key = self.key.clone().tweak(
                Scalar::<Public, _>::from_slice_mod_order(&hmac_result[..32]).expect("32 bytes"),
            );
            self.chaincode.copy_from_slice(&hmac_result[32..]);
        }
    }

    pub fn derive_bip32(&self, segments: impl IntoIterator<Item = u32>) -> Xpub<T> {
        let mut ret = self.clone();
        ret.derive_bip32_in_place(segments);
        ret
    }

    pub fn key(&self) -> &T {
        &self.key
    }

    pub fn into_key(self) -> T {
        self.key
    }

    pub fn fingerprint(&self) -> bitcoin::bip32::Fingerprint {
        self.to_bitcoin_xpub_with_lies(NetworkKind::Main)
            .fingerprint()
    }

    /// Create a rust bitcoin xpub lying about the fields we don't care about
    pub fn to_bitcoin_xpub_with_lies(
        &self,
        network_kind: bitcoin::NetworkKind,
    ) -> bitcoin::bip32::Xpub {
        bitcoin::bip32::Xpub {
            network: network_kind,
            // note below this is a lie and shouldn't matter VVV
            depth: 0,
            parent_fingerprint: Fingerprint::default(),
            child_number: ChildNumber::from_normal_idx(0).unwrap(),
            // ^^^ above is a lie and shouldn't matter
            public_key: self.key.to_libsecp_key(),
            chain_code: ChainCode::from(self.chaincode),
        }
    }
}

/// Xpub to do bip32 deriviation without all the nonsense.
#[derive(
    Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Hash, bincode::Encode, bincode::Decode, Debug,
)]
pub struct Xpub<T> {
    pub key: T,
    pub chaincode: [u8; 32],
}

impl Xpub<SharedKey> {
    pub fn public_key(&self) -> Xpub<Point> {
        Xpub {
            key: self.key.public_key(),
            chaincode: self.chaincode,
        }
    }
}

pub trait DerivationPathExt {
    fn from_normal_path_segments(path_segments: impl IntoIterator<Item = u32>) -> Self;
}

impl DerivationPathExt for DerivationPath {
    fn from_normal_path_segments(path_segments: impl IntoIterator<Item = u32>) -> Self {
        DerivationPath::from_iter(path_segments.into_iter().map(|path_segment| {
            ChildNumber::from_normal_idx(path_segment).expect("valid normal derivation index")
        }))
    }
}

/// cold-snap addition (decision 3). Validates [`bip341_taptweak_key_only`] against
/// the *published* BIP-341/BIP-86 vectors rather than against rust-bitcoin, so these
/// assertions keep their meaning once `bitcoin` is dropped from the graph.
///
/// A wrong tweak here yields wrong addresses and permanently unspendable funds, so
/// each vector pins the whole chain: internal key -> tweak -> output x-only key.
#[cfg(test)]
mod bip341_taptweak_vectors {
    use super::*;

    /// `(internal_key_x, expected_tweak, expected_output_key_x)`, all big-endian.
    ///
    /// Row 0 is BIP-341 `scriptPubKey[0]` — the **only** official vector with
    /// `scriptTree: null`, i.e. the only one exercising the `merkle_root == None`
    /// path frostsnap uses. Source: Bitcoin Core
    /// `src/test/data/bip341_wallet_vectors.json`, byte-identical to rust-bitcoin's
    /// `bitcoin/tests/data/bip341_tests.json`
    /// (sha256 `403e19fb81dd1f31e745699216308f61fb403774b2aafa87b631b8f7c042d37f`).
    ///
    /// Rows 1-3 are BIP-86, which is key-path-only by construction, from the
    /// spec's `m/86'/0'/0'/{0/0, 0/1, 1/0}` test vectors. They exist because one
    /// official vector is thin coverage for a fund-losing code path. Row 1 is the
    /// pair rust-bitcoin itself asserts in its BIP-86 address test.
    const KEY_PATH_ONLY_VECTORS: [([u8; 32], [u8; 32], [u8; 32]); 4] = [
        // BIP-341 scriptPubKey[0]
        (
            hex32("d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d"),
            hex32("b86e7be8f39bab32a6f2c0443abbc210f0edac0e2c53d501b36b64437d9c6c70"),
            hex32("53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343"),
        ),
        // BIP-86 m/86'/0'/0'/0/0 -> bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr
        (
            hex32("cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"),
            hex32("2ca01ed85cf6b6526f73d39a1111cd80333bfdc00ce98992859848a90a6f0258"),
            hex32("a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"),
        ),
        // BIP-86 m/86'/0'/0'/0/1 -> bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh
        (
            hex32("83dfe85a3151d2517290da461fe2815591ef69f2b18a2ce63f01697a8b313145"),
            hex32("84a88d9651f7cbc831e3b2a7800f2e572b6a719c3352dd9e6d3125cd21827237"),
            hex32("a82f29944d65b86ae6b5e5cc75e294ead6c59391a1edc5e016e3498c67fc7bbb"),
        ),
        // BIP-86 m/86'/0'/0'/1/0 -> bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7
        (
            hex32("399f1b2f4393f29a18c937859c5dd8a77350103157eb880f02e8c08214277cef"),
            hex32("563b7c38f218e910fefc744150ed5d5597e4f6dabff583ec56cfac08a9a70235"),
            hex32("882d74e5d0572d5a816cef0041a96b6c1de832f6f9676d9605c44d5e9a97d3dc"),
        ),
    ];

    /// `const fn` so the vectors above stay readable as hex without pulling in a
    /// runtime hex decoder. Panics at compile time on malformed input.
    const fn hex32(s: &str) -> [u8; 32] {
        const fn nibble(c: u8) -> u8 {
            match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                _ => panic!("hex32: not a lowercase hex digit"),
            }
        }
        let s = s.as_bytes();
        assert!(s.len() == 64, "hex32: need exactly 32 bytes of hex");
        let mut out = [0u8; 32];
        let mut i = 0;
        while i < 32 {
            out[i] = (nibble(s[2 * i]) << 4) | nibble(s[2 * i + 1]);
            i += 1;
        }
        out
    }

    /// The tagged hash itself, against the published `tweak` field of each vector.
    #[test]
    fn tagged_hash_matches_published_tweaks() {
        for (internal, expected_tweak, _) in KEY_PATH_ONLY_VECTORS {
            assert_eq!(
                bip341_taptweak_key_only(internal),
                expected_tweak,
                "TapTweak mismatch for internal key {internal:?}"
            );
        }
    }

    /// The full derivation `Q = lift_x(P) + H_TapTweak(P_x)*G`, against the published
    /// output keys. This is the value that ends up in the scriptPubKey, so it is the
    /// assertion that actually protects funds.
    #[test]
    fn output_keys_match_published_vectors() {
        for (internal, expected_tweak, expected_output) in KEY_PATH_ONLY_VECTORS {
            let tweak = bip341_taptweak_key_only(internal);
            assert_eq!(tweak, expected_tweak);

            // `lift_x` per BIP-341, then `.normalize()` to a `Point<Normal>` so the
            // derivation goes through the exact `TweakableKey for Point` impl that
            // production uses rather than a reimplementation of it.
            let internal_point = Point::<EvenY, Public, NonZero>::from_xonly_bytes(internal)
                .expect("vector internal key is on the curve")
                .normalize();
            let output = internal_point.into_xonly_with_tweak(
                Scalar::<Public, _>::from_bytes_mod_order(tweak)
                    .non_zero()
                    .expect("vector tweak is non-zero"),
            );

            assert_eq!(
                output.to_xonly_bytes(),
                expected_output,
                "output key mismatch for internal key {internal:?}"
            );
        }
    }

    /// Pins BIP-341's `lift_x` step, which the two tests above cannot see.
    ///
    /// Every published vector's internal key is *given* as 32 x-only bytes, so
    /// feeding it in already-even-y makes `into_point_with_even_y()` a no-op — the
    /// tests above still pass with the lift deleted outright, and the only tests
    /// that catch that are the two which die with `bitcoin` (decision 4). This one
    /// survives, because it asserts the property rather than a fixture: `P` and
    /// `-P` share an x coordinate, so BIP-341 must tweak them to the *same* output
    /// key. Delete the lift and the odd-y half of each pair diverges.
    #[test]
    fn odd_y_internal_keys_tweak_to_the_same_output() {
        for (internal, tweak, expected_output) in KEY_PATH_ONLY_VECTORS {
            let even_y = Point::<EvenY, Public, NonZero>::from_xonly_bytes(internal)
                .expect("vector internal key is on the curve")
                .normalize();
            let odd_y = -even_y;
            assert!(
                even_y.is_y_even() && !odd_y.is_y_even(),
                "negation is a no-op"
            );

            let tweak = Scalar::<Public, _>::from_bytes_mod_order(tweak)
                .non_zero()
                .expect("vector tweak is non-zero");

            for (parity, key) in [("even", even_y), ("odd", odd_y)] {
                assert_eq!(
                    key.into_xonly_with_tweak(tweak).to_xonly_bytes(),
                    expected_output,
                    "{parity}-y internal key {internal:?} did not lift to the published output"
                );
            }
        }
    }

    /// Belt-and-braces cross-check against rust-bitcoin's `TapTweakHash` while that
    /// crate is still in the graph (decision 4). Unlike the tests above this one is
    /// expected to be deleted along with the `bitcoin` dependency; it catches drift
    /// over a far wider input range than four vectors can.
    #[test]
    fn matches_rust_bitcoin_over_many_keys() {
        use bitcoin::key::TapTweak as _;

        let secp = bitcoin::secp256k1::Secp256k1::verification_only();
        let mut point = G.normalize();
        for _ in 0..256 {
            let xonly = point.to_xonly_bytes();

            let theirs = bitcoin::taproot::TapTweakHash::from_key_and_tweak(
                bitcoin::secp256k1::XOnlyPublicKey::from_slice(&xonly).unwrap(),
                None,
            )
            .to_scalar()
            .to_be_bytes();

            assert_eq!(bip341_taptweak_key_only(xonly), theirs);

            // ...and that the derived output key agrees too, not just the hash.
            let ours = TweakableKey::into_xonly_with_tweak(
                point,
                Scalar::<Public, _>::from_bytes_mod_order(theirs)
                    .non_zero()
                    .unwrap(),
            )
            .to_xonly_bytes();
            let (theirs_key, _) = bitcoin::secp256k1::XOnlyPublicKey::from_slice(&xonly)
                .unwrap()
                .tap_tweak(&secp, None);
            assert_eq!(ours, theirs_key.to_x_only_public_key().serialize());

            point = g!(point + G).normalize().non_zero().unwrap();
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::vec::Vec;
    use bitcoin::secp256k1::Secp256k1;
    use schnorr_fun::frost::chilldkg::certpedpop;

    #[test]
    pub fn bip32_derivation_matches_rust_bitcoin() {
        let schnorr = schnorr_fun::new_with_deterministic_nonces::<sha2::Sha256>();
        let cert_scheme = certpedpop::vrf_cert::VrfCertScheme::<sha2::Sha256>::new("chilldkg-vrf");
        let output = certpedpop::simulate_keygen(
            &schnorr,
            &cert_scheme,
            3,
            5,
            5,
            schnorr_fun::frost::Fingerprint {
                tag: "frostsnap-v0",
                bits_per_coeff: 10,
                max_bits_total: 20,
            },
            &mut rand::thread_rng(),
        );

        let frost_key = output.certified_keygen.verified_agg_input().shared_key();
        let root_xpub = Xpub::from_rootkey(frost_key);
        let secp = Secp256k1::verification_only();
        let xpub = bitcoin::bip32::Xpub {
            network: bitcoin::Network::Bitcoin.into(),
            depth: 0,
            parent_fingerprint: Fingerprint::default(),
            child_number: ChildNumber::from_normal_idx(0).unwrap(),
            // cold-snap change (decision 3): `.into()` here needed
            // `libsecp_compat_0_29`; these two conversions are the same byte
            // round-trips the dropped `From` impls performed.
            public_key: secp256k1::PublicKey::from_slice(&root_xpub.key.public_key().to_bytes())
                .unwrap(),
            chain_code: ChainCode::from(root_xpub.chaincode),
        };
        let path = [1337u32, 42, 0];
        let child_path = path
            .iter()
            .map(|i| ChildNumber::Normal { index: *i })
            .collect::<Vec<_>>();
        let derived_xpub = xpub.derive_pub(&secp, &child_path).unwrap();
        let our_derived_xpub = root_xpub.derive_bip32(path);

        assert_eq!(
            our_derived_xpub.chaincode,
            *derived_xpub.chain_code.as_bytes()
        );
        assert_eq!(
            our_derived_xpub.key.public_key(),
            Point::<Normal, Public, NonZero>::from_bytes(derived_xpub.public_key.serialize())
                .unwrap()
        );
    }
}

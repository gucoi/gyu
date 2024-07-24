use gyu_model::{derivation_path::ChildIndex, extended_private_key::ExtendedPrivateKey};

use crate::{
    address::BitcoinAddress, format::BitcoinFormat, network::BitcoinNetwork,
    private_key::BitcoinPrivateKey, public_key::BitcoinPublicKey,
};

use hmac::{Hmac, Mac};
use secp256k1::{PublicKey, SecretKey};
use sha2::Sha512;
type HmacSha512 = Hmac<Sha512>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoinExtendedPrivateKey<N: BitcoinNetwork> {
    pub(super) format: BitcoinFormat,
    pub(super) depth: u8,
    pub(super) parent_fingerprint: [u8; 4],
    pub(super) child_index: ChildIndex,
    pub(super) chain_code: [u8; 32],
    private_key: BitcoinPrivateKey<N>,
}

impl<N: BitcoinNetwork> ExtendedPrivateKey for BitcoinExtendedPrivateKey<N> {
    type Address = BitcoinAddress<N>;
    type DerivationPath = BitcoinDerivationPath<N>;
    type ExtendedPublicKey = BitcoinExtendedPublicKey<N>;
    type Format = BitcoinFormat;
    type PrivateKey = BitcoinPrivateKey<N>;
    type PublicKey = BitcoinPublicKey<N>;

    fn new(
        seed: &[u8],
        format: &Self::Format,
    ) -> Result<Self, gyu_model::extended_private_key::ExtendedPrivateKeyError> {
        Ok(Self::new_master(seed, format)?.derive(path)?)
    }

    fn new_master(
        seed: &[u8],
        format: &Self::Format,
    ) -> Result<Self, gyu_model::extended_private_key::ExtendedPrivateKeyError> {
        let mut mac = HmacSha512::new_varkey(b"Bitcoin seed")?;
        mac.input(seed);
        let hmac = mac.result().code();
        let private_key = Self::PrivateKey::from_secp256k1_secret_key(
            &SecretKey::parse_slice(&hmac[0..32])?,
            true,
        );

        let mut chain_code = [0u8; 32];
        chain_code[0..32].copy_from_slice(&hmac[32..]);

        Ok(Self {
            format: format.clone(),
            depth: 0,
            parent_fingerprint: [0u8; 4],
            child_index: ChildIndex::Normal(0),
            chain_code,
            private_key,
        })
    }
}

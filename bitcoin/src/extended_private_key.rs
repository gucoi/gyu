use gyu_model::{
    derivation_path::ChildIndex,
    extended_private_key::{self, ExtendedPrivateKey, ExtendedPrivateKeyError},
    private_key::PrivateKey,
};

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

    fn derive(
        &self,
        path: &Self::DerivationPath,
    ) -> Result<Self, gyu_model::extended_private_key::ExtendedPrivateKeyError> {
        if self.depth == 255 {
            return Err(ExtendedPrivateKeyError::MaximumChildDepthReached(
                self.depth,
            ));
        }

        let mut extended_private_key = self.clone();

        for index in path.to_vec()?.into_iter() {
            let public_key = &PublicKey::from_secret_key(
                &extended_private_key.private_key.to_secp256k1_secret_key(),
            )
            .serialize_compressed()[..];
            let mut mac = HmacSha512::new_varkey(&extended_private_key.chain_code)?;
            match index {
                ChildIndex::Normal(_) => mac.input(public_key),
                ChildIndex::Hardened(_) => {
                    mac.input(&[0u8]);
                    mac.input(
                        &extended_private_key
                            .private_key
                            .to_secp256k1_secret_key()
                            .serialize(),
                    );
                }
            }
            mac.input(&u32::from(index).to_be_bytes());
            let hmac = mac.result().code();

            let mut secret_key = SecretKey::parse_slice(&hmac[0..32])?;
            secret_key
                .tweak_add_assign(&extended_private_key.private_key.to_secp256k1_secret_key())?;
            let private_key = Self::PrivateKey::from_secp256k1_secret_key(&secret_key, true);

            let mut chain_code = [0u8; 32];
            chain_code[0..32].copy_from_slice(&hmac[32..]);

            let mut parent_fingerprint = [0u8; 4];
            parent_fingerprint.copy_from_slice(&hash160(public_key)[0..4]);

            let format = match path {
                BitcoinDerivationPath::BIP49(_) => BitcoinFormat::P2SH_P2WPKH,
                _ => extended_private_key.format.clone(),
            };

            extended_private_key = Self {
                format,
                depth: extended_private_key.depth + 1,
                parent_fingerprint,
                child_index: index,
                chain_code,
                private_key,
            }
        }
        Ok(extended_private_key)
    }

    fn to_extended_public_key(&self) -> Self::ExtendedPublicKey {
        Self::ExtendedPublicKey::from_extended_private_key(&self)
    }

    fn to_private_key(&self) -> Self::PrivateKey {
        self.private_key.clone()
    }

    fn to_public_key(&self) -> Self::PublicKey {
        self.private_key.to_public_key()
    }

    fn to_address(
        &self,
        format: &Self::Format,
    ) -> Result<Self::Address, gyu_model::address::AddressError> {
        self.private_key.to_address(format)
    }
}

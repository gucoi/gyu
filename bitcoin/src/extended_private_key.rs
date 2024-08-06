use gyu_model::{
    derivation_path::{ChildIndex, DerivationPath},
    extended_private_key::{ExtendedPrivateKey, ExtendedPrivateKeyError},
    extended_public_key::ExtendedPublicKey,
    private_key::PrivateKey,
    utilities::crypto::checksum,
    utilities::crypto::hash160,
};

use std::str::FromStr;

use crate::{
    address::BitcoinAddress, derivation_path::BitcoinDerivationPath,
    extended_public_key::BitcoinExtendedPublicKey, format::BitcoinFormat, network::BitcoinNetwork,
    private_key::BitcoinPrivateKey, public_key::BitcoinPublicKey,
};

use base58::{FromBase58, ToBase58};

use hmac::{Hmac, Mac};
use secp256k1::{PublicKey, SecretKey};
use sha2::Sha512;
use std::fmt::{self, Display};

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
        path: &Self::DerivationPath,
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

impl<N: BitcoinNetwork> FromStr for BitcoinExtendedPrivateKey<N> {
    type Err = ExtendedPrivateKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = s.from_base58()?;
        if data.len() != 82 {
            return Err(ExtendedPrivateKeyError::InvalidByteLength(data.len()));
        }

        // Check that the version bytes correspond with the correct network.
        let _ = N::from_extended_private_key_version_bytes(&data[0..4])?;
        let format = BitcoinFormat::from_extended_private_key_version_bytes(&data[0..4])?;

        let depth = data[4];

        let mut parent_fingerprint = [0u8; 4];
        parent_fingerprint.copy_from_slice(&data[5..9]);

        let child_index = ChildIndex::from(u32::from_be_bytes(<[u8; 4]>::try_from(&data[9..13])?));

        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&data[13..45]);

        let private_key = BitcoinPrivateKey::from_secp256k1_secret_key(
            &SecretKey::parse_slice(&data[46..78])?,
            true,
        );

        let expected = &data[78..82];
        let checksum = &checksum(&data[0..78])[0..4];
        if *expected != *checksum {
            let expected = expected.to_base58();
            let found = checksum.to_base58();
            return Err(ExtendedPrivateKeyError::InvalidChecksum(expected, found));
        }

        Ok(Self {
            format,
            depth,
            parent_fingerprint,
            child_index,
            chain_code,
            private_key,
        })
    }
}

impl<N: BitcoinNetwork> Display for BitcoinExtendedPrivateKey<N> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let mut result = [0u8; 82];
        result[0..4].copy_from_slice(
            match &N::to_extended_private_key_version_bytes(&self.format) {
                Ok(version) => version,
                Err(_) => return Err(fmt::Error),
            },
        );
        result[4] = self.depth;
        result[5..9].copy_from_slice(&self.parent_fingerprint[..]);
        result[9..13].copy_from_slice(&u32::from(self.child_index).to_be_bytes());
        result[13..45].copy_from_slice(&self.chain_code[..]);
        result[45] = 0;
        result[46..78].copy_from_slice(&self.private_key.to_secp256k1_secret_key().serialize());

        let checksum = &checksum(&result[0..78])[0..4];
        result[78..82].copy_from_slice(&checksum);

        fmt.write_str(&result.to_base58())
    }
}

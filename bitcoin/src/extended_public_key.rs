use std::str::FromStr;

use base58::{FromBase58, ToBase58};
use gyu_model::{
    derivation_path::ChildIndex,
    extended_private_key::ExtendedPrivateKey,
    extended_public_key::{ExtendedPublicKey, ExtendedPublicKeyError},
    public_key::PublicKey,
    utilities::crypto::{checksum, hash160},
};

use hmac::{Hmac, Mac};
use secp256k1::{PublicKey as Secp256k1_PublicKey, SecretKey};
use sha2::Sha512;

use crate::{
    address::BitcoinAddress, derivation_path::BitcoinDerivationPath,
    extended_private_key::BitcoinExtendedPrivateKey, format::BitcoinFormat,
    network::BitcoinNetwork, public_key::BitcoinPublicKey,
};

type HmacSha512 = Hmac<Sha512>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoinExtendedPublicKey<N: BitcoinNetwork> {
    format: BitcoinFormat,
    depth: u8,
    parent_fingerprint: [u8; 4],
    child_index: ChildIndex,
    chain_code: [u8; 32],
    public_key: BitcoinPublicKey<N>,
}

impl<N: BitcoinNetwork> ExtendedPublicKey for BitcoinExtendedPublicKey<N> {
    type Address = BitcoinAddress<N>;
    type DerivationPath = BitcoinDerivationPath<N>;
    type ExtendedPrivateKey = BitcoinExtendedPrivateKey<N>;
    type Format = BitcoinFormat;
    type PublicKey = BitcoinPublicKey<N>;

    fn from_extended_private_key(extended_private_key: &Self::ExtendedPrivateKey) -> Self {
        Self {
            format: extended_private_key.format.clone(),
            depth: extended_private_key.depth,
            parent_fingerprint: extended_private_key.parent_fingerprint,
            child_index: extended_private_key.child_index,
            chain_code: extended_private_key.chain_code,
            public_key: extended_private_key.to_public_key(),
        }
    }

    fn derive(
        &self,
        path: &Self::DerivatingPath,
    ) -> Result<Self, gyu_model::extended_public_key::ExtendedPublicKeyError> {
        if self.depth == 255 {
            return Err(ExtendedPublicKeyError::MaximumChildDepthReached(self.depth));
        }
        let mut extended_public_key = self.clone();

        for index in path.to_vec()?.into_iter() {
            let public_key_serialized = &self
                .public_key
                .to_secp256k1_public_key()
                .serialize_compressed()[..];

            let mut mac = HmacSha512::new_varkey(&self.chain_code)?;
            match index {
                // HMAC-SHA512(Key = cpar, Data = serP(Kpar) || ser32(i))
                ChildIndex::Normal(_) => mac.input(public_key_serialized),
                // Return failure
                ChildIndex::Hardened(_) => {
                    return Err(ExtendedPublicKeyError::InvalidChildNumber(
                        1 << 31,
                        u32::from(index),
                    ))
                }
            }
            // Append the child index in big-endian format
            mac.input(&u32::from(index).to_be_bytes());
            let hmac = mac.result().code();

            let mut chain_code = [0u8; 32];
            chain_code[0..32].copy_from_slice(&hmac[32..]);

            let mut public_key = self.public_key.to_secp256k1_public_key();
            public_key.tweak_add_assign(&SecretKey::parse_slice(&hmac[..32])?)?;
            let public_key = Self::PublicKey::from_secp256k1_public_key(public_key, true);

            let mut parent_fingerprint = [0u8; 4];
            parent_fingerprint.copy_from_slice(&hash160(public_key_serialized)[0..4]);

            extended_public_key = Self {
                format: extended_public_key.format.clone(),
                depth: extended_public_key.depth + 1,
                parent_fingerprint,
                child_index: index,
                chain_code,
                public_key,
            };
        }

        Ok(extended_public_key)
    }

    fn to_public_key(&self) -> Self::PublicKey {
        self.public_key.clone()
    }

    fn to_address(
        &self,
        format: &Self::Format,
    ) -> Result<Self::Address, gyu_model::address::AddressError> {
        self.public_key.to_address(format)
    }
}

impl<N: BitcoinNetwork> BitcoinExtendedPublicKey<N> {
    pub fn format(&self) -> BitcoinFormat {
        self.format.clone()
    }
}

impl<N: BitcoinNetwork> FromStr for BitcoinExtendedPublicKey<N> {
    type Err = ExtendedPublicKeyError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = s.from_base58()?;
        if data.len() != 82 {
            return Err(ExtendedPublicKeyError::InvalidByteLength(data.len()));
        }

        let _ = N::from_extended_public_key_version_bytes(&data[0..4])?;
        let format = BitcoinFormat::from_exteded_private_key_version_bytes(&data[0..4])?;

        let mut version = [0u8; 4];
        version.copy_from_slice(&data[0..4]);
        let depth = data[4];
        let mut parent_fingerprint = [0u8; 4];
        parent_fingerprint.copy_from_slice(&data[5..9]);

        let child_index = ChildIndex::from(u32::from_be_bytes(<[u8; 4]>::try_from(&data[9..13])?));

        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&data[13..45]);

        let secp256k1_public_key = Secp256k1_PublicKey::parse_slice(&data[45..78], None)?;
        let public_key = BitcoinPublicKey::from_secp256k1_public_key(secp256k1_public_key, true);

        let expected = &data[78..82];
        let checksum = &checksum(&data[0..78])[0..4];
        if *expected != *checksum {
            let expected = expected.to_base58();
            let found = checksum.to_base58();
            return Err(ExtendedPublicKeyError::InvalidChecksum(expected, found));
        }

        Ok(Self {
            format,
            depth,
            parent_fingerprint,
            child_index,
            chain_code,
            public_key,
        })
    }
}

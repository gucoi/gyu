use gyu_model::{
    address::AddressError,
    public_key::{PublicKey, PublicKeyError},
};
use std::{fmt::Display, marker::PhantomData, str::FromStr};

use crate::{
    address::BitcoinAddress, format::BitcoinFormat, network::BitcoinNetwork,
    private_key::BitcoinPrivateKey,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoinPublicKey<N: BitcoinNetwork> {
    public_key: secp256k1::PublicKey,
    compressed: bool,
    _network: PhantomData<N>,
}

impl<N: BitcoinNetwork> PublicKey for BitcoinPublicKey<N> {
    type Address = BitcoinAddress<N>;
    type Format = BitcoinFormat;
    type PrivateKey = BitcoinPrivateKey<N>;

    fn from_private_key(private_key: &Self::PrivateKey) -> Self {
        Self {
            public_key: secp256k1::PublicKey::from_secret_key(
                &private_key.to_secp256k1_secret_key(),
            ),
            compressed: private_key.is_compressed(),
            _network: PhantomData,
        }
    }

    fn to_address(&self, format: &Self::Format) -> Result<Self::Address, AddressError> {
        Self::Address::from_public_key(self, format)
    }
}

impl<N: BitcoinNetwork> BitcoinPublicKey<N> {
    pub fn from_secp256k1_public_key(public_key: secp256k1::PublicKey, compressed: bool) -> Self {
        Self {
            public_key,
            compressed,
            _network: PhantomData,
        }
    }

    pub fn to_secp256k1_public_key(&self) -> secp256k1::PublicKey {
        self.public_key.clone()
    }

    pub fn is_compressed(&self) -> bool {
        self.compressed
    }
}

impl<N: BitcoinNetwork> FromStr for BitcoinPublicKey<N> {
    type Err = PublicKeyError;
    fn from_str(public_key: &str) -> Result<Self, Self::Err> {
        Ok(Self {
            public_key: secp256k1::PublicKey::parse_slice(&hex::decode(public_key)?, None)?,
            compressed: public_key.len() == 66,
            _network: PhantomData,
        })
    }
}

impl<N: BitcoinNetwork> Display for BitcoinPublicKey<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.compressed {
            for s in &self.public_key.serialize_compressed()[..] {
                write!(f, "{:02x}", s)?;
            }
        } else {
            for s in &self.public_key.serialize()[..] {
                write!(f, "{:02x}", s)?;
            }
        }
        Ok(())
    }
}

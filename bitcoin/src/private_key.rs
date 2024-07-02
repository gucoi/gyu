use core::{fmt, fmt::Display};
use std::{marker::PhantomData, str::FromStr};

use base58::{FromBase58, ToBase58};
use gyu_model::{
    address::{Address, AddressError},
    private_key::{PrivateKey, PrivateKeyError},
    public_key::PublicKey,
    utilities::crypto::checksum,
};

use crate::{
    address::BitcoinAddress, format::BitcoinFormat, network::BitcoinNetwork,
    public_key::BitcoinPublicKey,
};

use rand::Rng;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoinPrivateKey<N: BitcoinNetwork> {
    secret_key: secp256k1::SecretKey,
    compressed: bool,
    _network: PhantomData<N>,
}

impl<N: BitcoinNetwork> PrivateKey for BitcoinPrivateKey<N> {
    type Address = BitcoinAddress<N>;
    type Format = BitcoinFormat;
    type PublicKey = BitcoinPublicKey<N>;

    fn new<R: Rng>(rng: &mut R) -> Result<Self, PrivateKeyError> {
        Ok(Self {
            secret_key: secp256k1::SecretKey::random(rng),
            compressed: true,
            _network: PhantomData,
        })
    }

    fn to_public_key(&self) -> Self::PublicKey {
        Self::PublicKey::from_private_key(self)
    }

    fn to_address(&self, format: &Self::Format) -> Result<Self::Address, AddressError> {
        Self::Address::from_private_key(self, format)
    }
}

impl<N: BitcoinNetwork> BitcoinPrivateKey<N> {
    pub fn from_secp256k1_secret_key(secret_key: &secp256k1::SecretKey, compressed: bool) -> Self {
        Self {
            secret_key: secret_key.clone(),
            compressed,
            _network: PhantomData,
        }
    }

    pub fn to_secp256k1_secret_key(&self) -> secp256k1::SecretKey {
        self.secret_key.clone()
    }

    pub fn is_compressed(&self) -> bool {
        self.compressed
    }
}

impl<N: BitcoinNetwork> FromStr for BitcoinPrivateKey<N> {
    type Err = PrivateKeyError;

    fn from_str(wif: &str) -> Result<Self, Self::Err> {
        let data = wif.from_base58()?;
        let len = data.len();
        if len != 37 && len != 38 {
            return Err(PrivateKeyError::InvalidByteLength(len));
        }
        let expected = &data[len - 4..len];
        let checksum = &checksum(&data[0..len - 4])[0..4];
        if *expected != *checksum {
            let expected = expected.to_base58();
            let found = checksum.to_base58();
            return Err(PrivateKeyError::InvalidChecksum(expected, found));
        }

        let _ = N::from_private_key_prefix(data[0])?;

        Ok(Self {
            secret_key: secp256k1::SecretKey::parse_slice(&data[1..33])?,
            compressed: len == 38,
            _network: PhantomData,
        })
    }
}

impl<N: BitcoinNetwork> Display for BitcoinPrivateKey<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut wif = [0u8; 38];
        wif[0] = N::to_private_key_prefix();
        wif[1..33].copy_from_slice(&self.secret_key.serialize());

        let output = if self.compressed {
            wif[33] = 0x01;
            let sum = &checksum(&wif[0..34])[0..4];
            wif[34..].copy_from_slice(sum);
            wif.to_base58()
        } else {
            let sum = &checksum(&wif[0..33])[0..4];
            wif[33..37].copy_from_slice(sum);
            wif[..37].to_base58()
        };
        write!(f, "{}", output)
    }
}

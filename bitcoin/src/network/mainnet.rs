use core::fmt;
use core::str::FromStr;
use gyu_model::no_std::*;

use crate::format::BitcoinFormat;
use crate::network::BitcoinNetwork;

use gyu_model::{
    address::AddressError,
    derivation_path::ChildIndex,
    extended_private_key::ExtendedPrivateKeyError,
    extended_public_key::ExtendedPublicKeyError,
    network::{Network, NetworkError},
    private_key::PrivateKeyError,
};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Mainnet;

impl Network for Mainnet {
    const NAME: &'static str = "mainnet";
}

impl BitcoinNetwork for Mainnet {
    const HD_COIN_TYPE: ChildIndex = ChildIndex::Hardened(0);

    fn to_address_prefix(format: &crate::format::BitcoinFormat) -> Vec<u8> {
        match format {
            BitcoinFormat::P2PKH => vec![0x00],
            BitcoinFormat::P2WSH => vec![0x00],
            BitcoinFormat::P2SH_P2WPKH => vec![0x05],
            BitcoinFormat::Bech32 => vec![0x62, 0x63],
        }
    }

    fn from_address_prefix(prefix: &[u8]) -> Result<Self, gyu_model::address::AddressError> {
        match (prefix[0], prefix[1]) {
            (0x00, _) | (0x05, _) | (0x62, 0x63) => Ok(Self),
            _ => Err(AddressError::InvalidPrefix(prefix.to_owned())),
        }
    }

    fn to_private_key_prefix() -> u8 {
        0x80
    }

    fn from_private_key_prefix(
        prefix: u8,
    ) -> Result<Self, gyu_model::private_key::PrivateKeyError> {
        match prefix {
            0x80 => Ok(Self),
            _ => Err(PrivateKeyError::InvalidPrefix(vec![prefix])),
        }
    }

    fn to_extended_private_key_version_bytes(
        format: &BitcoinFormat,
    ) -> Result<Vec<u8>, ExtendedPrivateKeyError> {
        match format {
            BitcoinFormat::P2PKH => Ok(vec![0x04, 0x88, 0xAD, 0xE4]),
            BitcoinFormat::P2SH_P2WPKH => Ok(vec![0x04, 0x9D, 0x78, 0x78]),
            _ => Err(ExtendedPrivateKeyError::UnsupportedFormat(
                format.to_string(),
            )),
        }
    }

    fn from_extended_private_key_version_bytes(
        prefix: &[u8],
    ) -> Result<Self, ExtendedPrivateKeyError> {
        match prefix[0..4] {
            [0x04, 0x88, 0xAD, 0xE4] | [0x04, 0x9D, 0x78, 0x78] => Ok(Self),
            _ => Err(ExtendedPrivateKeyError::InvalidVersionBytes(
                prefix.to_vec(),
            )),
        }
    }

    fn to_extended_public_key_version_bytes(
        format: &BitcoinFormat,
    ) -> Result<Vec<u8>, ExtendedPublicKeyError> {
        match format {
            BitcoinFormat::P2PKH => Ok(vec![0x04, 0x88, 0xB2, 0x1E]),
            BitcoinFormat::P2SH_P2WPKH => Ok(vec![0x04, 0x9D, 0x7C, 0xB2]),
            _ => Err(ExtendedPublicKeyError::UnsupportedFormat(
                format.to_string(),
            )),
        }
    }

    fn from_extended_public_key_version_bytes(
        prefix: &[u8],
    ) -> Result<Self, ExtendedPublicKeyError> {
        match prefix[0..4] {
            [0x04, 0x88, 0xB2, 0x1E] | [0x04, 0x9D, 0x7C, 0xB2] => Ok(Self),
            _ => Err(ExtendedPublicKeyError::InvalidVersionBytes(prefix.to_vec())),
        }
    }
}

impl FromStr for Mainnet {
    type Err = NetworkError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            Self::NAME => Ok(Self),
            _ => Err(NetworkError::InvalidNetwork(s.into())),
        }
    }
}

impl fmt::Display for Mainnet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Self::NAME)
    }
}

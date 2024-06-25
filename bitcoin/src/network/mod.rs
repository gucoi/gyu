pub mod mainnet;

use gyu_model::{
    address::AddressError, derivation_path::ChildIndex,
    extended_private_key::ExtendedPrivateKeyError, extended_public_key::ExtendedPublicKeyError,
    network::Network, private_key::PrivateKeyError,
};

use crate::format::BitcoinFormat;

pub use self::mainnet::*;

pub trait BitcoinNetwork: Network {
    const HD_COIN_TYPE: ChildIndex;
    fn to_address_prefix(format: &BitcoinFormat) -> Vec<u8>;

    fn from_address_prefix(prefix: &[u8]) -> Result<Self, AddressError>;

    fn to_private_key_prefix() -> u8;

    fn from_private_key_prefix(prefix: u8) -> Result<Self, PrivateKeyError>;

    fn to_extended_private_key_version_bytes(
        format: &BitcoinFormat,
    ) -> Result<Vec<u8>, ExtendedPrivateKeyError>;

    fn from_extended_private_key_version_bytes(
        prefix: &[u8],
    ) -> Result<Self, ExtendedPrivateKeyError>;

    fn to_extended_public_key_version_bytes(
        format: &BitcoinFormat,
    ) -> Result<Vec<u8>, ExtendedPublicKeyError>;

    fn from_extended_public_key_version_bytes(
        prefix: &[u8],
    ) -> Result<Self, ExtendedPublicKeyError>;
}

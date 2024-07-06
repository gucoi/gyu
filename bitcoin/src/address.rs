use base58::{FromBase58, ToBase58};
use bech32::{u5, Bech32, FromBase32, ToBase32};
use gyu_model::{
    address::{Address, AddressError},
    private_key::PrivateKey,
    utilities::crypto::{checksum, hash160},
};
use sha2::Sha256;

use crate::{
    format::BitcoinFormat, network::BitcoinNetwork, private_key::BitcoinPrivateKey,
    public_key::BitcoinPublicKey, witness_program::WitnessProgram,
};

use std::{fmt::Display, marker::PhantomData, str::FromStr};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BitcoinAddress<N: BitcoinNetwork> {
    address: String,
    format: BitcoinFormat,
    _network: PhantomData<N>,
}

impl<N: BitcoinNetwork> Address for BitcoinAddress<N> {
    type Format = BitcoinFormat;
    type PrivateKey = BitcoinPrivateKey<N>;
    type PublicKey = BitcoinPublicKey<N>;

    fn from_private_key(
        private_key: &Self::PrivateKey,
        format: &Self::Format,
    ) -> Result<Self, gyu_model::address::AddressError> {
        let public_key = private_key.to_public_key();
        match format {
            BitcoinFormat::P2PKH => Self::p2pkh(&public_key),
            BitcoinFormat::P2WSH => {
                return Err(AddressError::IncompatibleFormats(
                    String::from("non-script"),
                    String::from("p2wsh address"),
                ))
            }
            BitcoinFormat::P2SH_P2WPKH => Self::p2sh_p2wpkh(&public_key),
            BitcoinFormat::Bech32 => Self::bech32(&public_key),
        }
    }

    fn from_public_key(
        public_key: &Self::PublicKey,
        format: &Self::Format,
    ) -> Result<Self, gyu_model::address::AddressError> {
        match format {
            BitcoinFormat::P2PKH => Self::p2pkh(public_key),
            BitcoinFormat::P2WSH => {
                return Err(AddressError::IncompatibleFormats(
                    String::from("non-script"),
                    String::from("p2wsh address"),
                ))
            }
            BitcoinFormat::P2SH_P2WPKH => Self::p2sh_p2wpkh(public_key),
            BitcoinFormat::Bech32 => Self::bech32(public_key),
        }
    }
}

impl<N: BitcoinNetwork> BitcoinAddress<N> {
    pub fn p2pkh(public_key: &<Self as Address>::PublicKey) -> Result<Self, AddressError> {
        let public_key = match public_key.is_compressed() {
            true => public_key
                .to_secp256k1_public_key()
                .serialize_compressed()
                .to_vec(),
            false => public_key.to_secp256k1_public_key().serialize().to_vec(),
        };

        let mut address = [0u8; 25];
        address[0] = N::to_address_prefix(&BitcoinFormat::P2PKH)[0];
        address[1..21].copy_from_slice(&hash160(&public_key));

        let sum = &checksum(&address[0..21])[0..4];
        address[21..25].copy_from_slice(sum);

        Ok(Self {
            address: address.to_base58(),
            format: BitcoinFormat::P2PKH,
            _network: PhantomData,
        })
    }

    // Returns a P2WSH address in Bech32 format from a given Bitcoin script
    pub fn p2wsh(original_script: &Vec<u8>) -> Result<Self, AddressError> {
        let script = Sha256::digest(&original_script).to_vec();

        // Organize as a hash
        let v = N::to_address_prefix(&BitcoinFormat::P2WSH)[0];
        let version = u5::try_from_u8(v)?;

        let mut data = vec![version];
        // Get the SHA256 hash of the script
        data.extend_from_slice(&script.to_vec().to_base32());

        let bech32 = Bech32::new(
            String::from_utf8(N::to_address_prefix(&BitcoinFormat::Bech32))?,
            data,
        )?;

        Ok(Self {
            address: bech32.to_string(),
            format: BitcoinFormat::P2WSH,
            _network: PhantomData,
        })
    }

    /// Returns a P2SH_P2WPKH address from a given Bitcoin public key.
    pub fn p2sh_p2wpkh(public_key: &<Self as Address>::PublicKey) -> Result<Self, AddressError> {
        let mut address = [0u8; 25];
        address[0] = N::to_address_prefix(&BitcoinFormat::P2SH_P2WPKH)[0];
        address[1..21].copy_from_slice(&hash160(&Self::create_redeem_script(public_key)));

        let sum = &checksum(&address[0..21])[0..4];
        address[21..25].copy_from_slice(sum);

        Ok(Self {
            address: address.to_base58(),
            format: BitcoinFormat::P2SH_P2WPKH,
            _network: PhantomData,
        })
    }

    /// Returns a Bech32 address from a given Bitcoin public key.
    pub fn bech32(public_key: &<Self as Address>::PublicKey) -> Result<Self, AddressError> {
        let redeem_script = Self::create_redeem_script(public_key);
        let version = u5::try_from_u8(redeem_script[0])?;

        let mut data = vec![version];
        data.extend_from_slice(&redeem_script[2..].to_vec().to_base32());

        let bech32 = Bech32::new(
            String::from_utf8(N::to_address_prefix(&BitcoinFormat::Bech32))?,
            data,
        )?;

        Ok(Self {
            address: bech32.to_string(),
            format: BitcoinFormat::Bech32,
            _network: PhantomData,
        })
    }

    /// Returns the format of the Bitcoin address.
    pub fn format(&self) -> BitcoinFormat {
        self.format.clone()
    }

    /// Returns a redeem script for a given Bitcoin public key.
    fn create_redeem_script(public_key: &<Self as Address>::PublicKey) -> [u8; 22] {
        let mut redeem = [0u8; 22];
        redeem[1] = 0x14;
        redeem[2..].copy_from_slice(&hash160(
            &public_key.to_secp256k1_public_key().serialize_compressed(),
        ));
        redeem
    }
}

impl<'a, N: BitcoinNetwork> TryFrom<&'a str> for BitcoinAddress<N> {
    type Error = AddressError;
    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        Self::from_str(value)
    }
}

impl<N: BitcoinNetwork> FromStr for BitcoinAddress<N> {
    type Err = AddressError;

    fn from_str(address: &str) -> Result<Self, Self::Err> {
        if address.len() < 14 || address.len() > 74 {
            return Err(AddressError::InvalidCharacterLength(address.len()));
        }
        let prefix = &address.to_lowercase()[0..2];

        if let Ok(format) = BitcoinFormat::from_address_prefix(prefix.as_bytes()) {
            if BitcoinFormat::Bech32 == format {
                let bech32 = Bech32::from_str(&address)?;
                if bech32.data().is_empty() {
                    return Err(AddressError::InvalidAddress(address.to_owned()));
                }

                let data = bech32.data();
                let version = data[0].to_u8();
                let mut program = Vec::from_base32(&data[1..])?;
                let mut data = vec![version, program.len() as u8];
                data.append(&mut program);

                let _ = WitnessProgram::new(data.as_slice())?;
                let _ = N::from_address_prefix(prefix.as_bytes())?;

                return Ok(Self {
                    address: address.to_owned(),
                    format: BitcoinFormat::Bech32,
                    _network: PhantomData,
                });
            }
        }

        let data = address.from_base58()?;
        if data.len() != 25 {
            return Err(AddressError::InvalidByteLength(data.len()));
        }

        let _ = N::from_address_prefix(&data[0..2])?;
        let format = BitcoinFormat::from_address_prefix(&data[0..2])?;

        Ok(Self {
            address: address.into(),
            format,
            _network: PhantomData,
        })
    }
}

impl<N: BitcoinNetwork> Display for BitcoinAddress<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.address)
    }
}

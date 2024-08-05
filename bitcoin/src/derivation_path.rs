use crate::network::BitcoinNetwork;
use gyu_model::derivation_path::{ChildIndex, DerivationPath, DerivationPathError};
use gyu_model::no_std::*;

use core::{convert::TryFrom, fmt, marker::PhantomData, str::FromStr};

/// Represents a Bitcoin derivation path
#[derive(Clone, PartialEq, Eq)]
pub enum BitcoinDerivationPath<N: BitcoinNetwork> {
    /// BIP32 - Pay-to-Pubkey Hash
    /// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
    BIP32(Vec<ChildIndex>, PhantomData<N>),
    /// BIP44 - m/44'/{0', 1'}/{account}'/{change}/{index} - Pay-to-Pubkey Hash
    /// https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
    BIP44([ChildIndex; 3]),
    /// BIP49 - m/49'/{0', 1'}/{account}'/{change}/{index} - SegWit Pay-to-Witness-Public-Key Hash
    /// https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki
    BIP49([ChildIndex; 3]),
}

impl<N: BitcoinNetwork> DerivationPath for BitcoinDerivationPath<N> {
    /// Returns a child index vector given the derivation path.
    fn to_vec(&self) -> Result<Vec<ChildIndex>, DerivationPathError> {
        match self {
            BitcoinDerivationPath::BIP32(path, _) => match path.len() < 256 {
                true => Ok(path.clone()),
                false => Err(DerivationPathError::ExpectedBIP32Path),
            },
            BitcoinDerivationPath::BIP44(path) => {
                match path[0].is_hardened() && path[1].is_normal() && path[2].is_normal() {
                    true => Ok(vec![
                        ChildIndex::Hardened(44),
                        N::HD_COIN_TYPE,
                        path[0],
                        path[1],
                        path[2],
                    ]),
                    false => Err(DerivationPathError::ExpectedBIP44Path),
                }
            }
            BitcoinDerivationPath::BIP49(path) => {
                match path[0].is_hardened() && path[1].is_normal() && path[2].is_normal() {
                    true => Ok(vec![
                        ChildIndex::Hardened(49),
                        N::HD_COIN_TYPE,
                        path[0],
                        path[1],
                        path[2],
                    ]),
                    false => Err(DerivationPathError::ExpectedBIP49Path),
                }
            }
        }
    }

    /// Returns a derivation path given the child index vector.
    fn from_vec(path: &Vec<ChildIndex>) -> Result<Self, DerivationPathError> {
        if path.len() == 5 {
            // Path length 5 - BIP44
            if path[0] == ChildIndex::Hardened(44)
                && path[1] == N::HD_COIN_TYPE
                && path[2].is_hardened()
                && path[3].is_normal()
                && path[4].is_normal()
            {
                return Ok(BitcoinDerivationPath::BIP44([path[2], path[3], path[4]]));
            }
            // Path length 5 - BIP49
            if path[0] == ChildIndex::Hardened(49)
                && path[1] == N::HD_COIN_TYPE
                && path[2].is_hardened()
                && path[3].is_normal()
                && path[4].is_normal()
            {
                return Ok(BitcoinDerivationPath::BIP49([path[2], path[3], path[4]]));
            }
            // Path length 5 - BIP32 (non-BIP44 & non-BIP49 compliant)
            return Ok(BitcoinDerivationPath::BIP32(path.to_vec(), PhantomData));
        } else {
            // Path length 0 - BIP32 root key
            // Path length i - BIP32
            Ok(BitcoinDerivationPath::BIP32(path.to_vec(), PhantomData))
        }
    }
}

impl<N: BitcoinNetwork> FromStr for BitcoinDerivationPath<N> {
    type Err = DerivationPathError;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        let mut parts = path.split("/");

        if parts.next().unwrap() != "m" {
            return Err(DerivationPathError::InvalidDerivationPath(path.to_string()));
        }

        let path: Result<Vec<ChildIndex>, Self::Err> = parts.map(str::parse).collect();
        Self::from_vec(&path?)
    }
}

impl<N: BitcoinNetwork> TryFrom<Vec<ChildIndex>> for BitcoinDerivationPath<N> {
    type Error = DerivationPathError;

    fn try_from(path: Vec<ChildIndex>) -> Result<Self, Self::Error> {
        Self::from_vec(&path)
    }
}

impl<'a, N: BitcoinNetwork> TryFrom<&'a [ChildIndex]> for BitcoinDerivationPath<N> {
    type Error = DerivationPathError;

    fn try_from(path: &'a [ChildIndex]) -> Result<Self, Self::Error> {
        Self::try_from(path.to_vec())
    }
}

impl<N: BitcoinNetwork> fmt::Debug for BitcoinDerivationPath<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self, f)
    }
}

impl<N: BitcoinNetwork> fmt::Display for BitcoinDerivationPath<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.to_vec() {
            Ok(path) => {
                f.write_str("m")?;
                for index in path.iter() {
                    f.write_str("/")?;
                    fmt::Display::fmt(index, f)?;
                }
                Ok(())
            }
            Err(_) => Err(fmt::Error),
        }
    }
}

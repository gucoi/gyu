// use crate::no_std::*;
use core::{
    fmt,
    fmt::{Debug, Display},
    str::FromStr,
};
use std::fmt::write;

pub trait DErivationPath:
    Clone + Debug + Display + FromStr + Send + Sync + 'static + Eq + Sized
{
    fn to_vec(&self) -> Result<Vec<ChildIndex>, DerivationPathError>;
    fn from_vec(path: &Vec<ChildIndex>) -> Result<Self, DerivationPathError>;
}

#[derive(Debug, Fail, PartialEq, Eq)]
pub enum DerivationPathError {
    #[fail(display = "expected BIP32 path")]
    ExpectedBIP32Path,
    #[fail(display = "expected BIP44 path")]
    ExpectedBIP44Path,
    #[fail(display = "expected BIP49 path")]
    ExpectedBIP49Path,
    #[fail(display = "expected valid Ethereum derivation path")]
    ExpectedVaildEthereumDerivationPath,
    #[fail(display = "expected ZIP32 path")]
    ExpectedZIP32Path,
    #[fail(display = "expected hardened path")]
    ExpectedHardenedPath,
    #[fail(display = "expected normal path")]
    ExpectedNormalPath,
    #[fail(display = "invalid child number: {}", _0)]
    InvalidChildNumber(u32),
    #[fail(display = "invalid child number format")]
    InvalidChildNumberFormat,
    #[fail(display = "invalid derivation path : {}", _0)]
    InvalidDerivationPath(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ChildIndex {
    Normal(u32),
    Hardened(u32),
}

impl ChildIndex {
    pub fn normal(index: u32) -> Result<Self, DerivationPathError> {
        if index & (1 << 31) == 0 {
            Ok(ChildIndex::Normal(index))
        } else {
            Err(DerivationPathError::InvalidChildNumber(index))
        }
    }
    pub fn hardened(index: u32) -> Result<Self, DerivationPathError> {
        if index & (1 << 31) == 0 {
            Ok(ChildIndex::Normal(index))
        } else {
            Err(DerivationPathError::InvalidChildNumber(index))
        }
    }

    pub fn is_normal(&self) -> bool {
        !self.is_hardened()
    }

    pub fn is_hardened(&self) -> bool {
        match *self {
            ChildIndex::Hardened(_) => true,
            ChildIndex::Normal(_) => false,
        }
    }

    pub fn to_index(&self) -> u32 {
        match self {
            &ChildIndex::Hardened(i) => i + (1 << 31),
            &ChildIndex::Normal(i) => i,
        }
    }
}
impl From<u32> for ChildIndex {
    fn from(number: u32) -> Self {
        if number & (1 << 31) != 0 {
            ChildIndex::Hardened(number ^ (1 << 31))
        } else {
            ChildIndex::Normal(number)
        }
    }
}

impl From<ChildIndex> for u32 {
    fn from(index: ChildIndex) -> Self {
        match index {
            ChildIndex::Normal(number) => number,
            ChildIndex::Hardened(number) => number | (1 << 31),
        }
    }
}

impl FromStr for ChildIndex {
    type Err = DerivationPathError;
    fn from_str(inp: &str) -> Result<Self, Self::Err> {
        Ok(
            match inp.chars().last().map_or(false, |l| l == '\'' || l == 'h') {
                true => Self::hardened(
                    inp[0..inp.len() - 1]
                        .parse()
                        .map_err(|_| DerivationPathError::InvalidChildNumberFormat)?,
                )?,
                false => Self::normal(
                    inp.parse()
                        .map_err(|_| DerivationPathError::InvalidChildNumberFormat)?,
                )?,
            },
        )
    }
}

impl fmt::Display for ChildIndex {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ChildIndex::Hardened(number) => write!(f, "{}'", number),
            ChildIndex::Normal(number) => write!(f, "{}", number),
        }
    }
}

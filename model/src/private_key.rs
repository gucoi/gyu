use crate::format::Format;

use crate::no_std::*;
use core::{
    fmt::{Debug, Display},
    str::FromStr,
};
use std::{fmt::format, hash::Hash, str::pattern::Pattern};

use rand::Rng;

pub trait PrivateKey:
    Clone + Debug + Display + FromStr + Send + Sync + 'static + Eq + Sized
{
    fn new<R: Rng>(rng: &mut R) -> Result<Self, PrivateKeyError>;

    fn to_public_key(&self) -> Self::PublicKey;

    fn to_address(&self, format: &Self::Format) -> Result<Self::Address, AddressError>;
}

#[derive(Debug, Fail)]
pub enum PrivateKeyError {
    #[fail(display = "{} : {}", _0, _1)]
    Crate(&'static str, String),

    #[fail(display = "invalid byte length {}", _0)]
    InvalidByteLength(usize),

    #[fail(display = "invalid character length: {}", _0)]
    InvalidCharacterLength(usize),

    #[fail(
        display = "invalid private key checksum: {{ expected: {:?}, found: {:?} }}",
        _0, _1
    )]
    InvalidChecksum(String, String),

    #[fail(display = "invalid network: {{ expected: {:?}, found: {:?} }}", _0, _1)]
    InvalidNetwork(String, String),

    #[fail(display = "invalid private key prefix: {:?}", _0)]
    InvalidPrefix(Vec<u8>),

    #[fail(display = "{}", _0)]
    Message(String),

    #[fail(display = "unsupported format")]
    UnsupportedFormat,
}

impl From<crate::no_std::io::Error> for PrivateKeyError {
    fn from(error: crate::no_std::io::Error) -> Self {
        PrivateKeyError::Crate("crate::no_std::io", format!("{:?}", error))
    }
}

impl From<&'static str> for PrivateKeyError {
    fn from(msg: &'static str) -> Self {
        PrivateKeyError::Message(msg.into())
    }
}

impl From<base58::FromBase58Error> for PrivateKeyError {
    fn from(error: base58::FromBase58Error) -> Self {
        PrivateKeyError::Crate("base58", format!("{:?}", error))
    }
}

impl From<secp256k1::Error> for PrivateKeyError {
    fn from(error: secp256k1::Error) -> Self {
        PrivateKeyError::Crate("libsecp256k1", format!("{:?}", error))
    }
}

use std::{
    fmt::{Debug, Display},
    str::FromStr,
};

use rand::Rng;

use crate::{
    address::{Address, AddressError},
    extended_private_key::{ExtendedPrivateKey, ExtendedPrivateKeyError},
    extended_public_key::ExtendedPublicKey,
    private_key::PrivateKeyError,
    wordlist::WordlistError,
};
use crate::{format::Format, private_key::PrivateKey, public_key::PublicKey};

pub trait Mnemonic: Clone + Debug + Display + FromStr + Send + Sync + 'static + Eq + Sized {
    type Address: Address;
    type Format: Format;
    type PrivateKey: PrivateKey;
    type PublicKey: PublicKey;

    fn new<R: Rng>(rng: &mut R) -> Result<Self, MnemonicError>;

    fn from_phrase(phrase: &str) -> Result<Self, MnemonicError>;

    fn to_phrase(&self) -> Result<String, MnemonicError>;

    fn to_private_key(&self, password: Option<&str>) -> Result<Self::PrivateKey, MnemonicError>;

    fn to_public_key(&self, password: Option<&str>) -> Result<Self::PublicKey, MnemonicError>;

    fn to_address(
        &self,
        password: Option<&str>,
        format: &Self::Format,
    ) -> Result<Self::Address, MnemonicError>;
}

pub trait MnemonicCount: Mnemonic {
    fn new_with_count<R: Rng>(rng: &mut R, word_count: u8) -> Result<Self, MnemonicError>;
}

pub trait MnemonicExtend: Mnemonic {
    type ExtendPulicKey: ExtendedPublicKey;
    type ExtendPrivateKey: ExtendedPrivateKey;

    fn to_extend_public_key(
        &self,
        password: Option<&str>,
    ) -> Result<Self::ExtendPulicKey, MnemonicError>;

    fn to_extend_private_key(
        &self,
        password: Option<&str>,
    ) -> Result<Self::ExtendPulicKey, MnemonicError>;
}

#[derive(Debug, Fail)]
pub enum MnemonicError {
    #[fail(display = "{}", _0)]
    AddressError(AddressError),

    #[fail(display = "{}: {}", _0, _1)]
    Crate(&'static str, String),

    #[fail(display = "{}", _0)]
    ExtendedPrivateKeyError(ExtendedPrivateKeyError),

    #[fail(
        display = "Invalid checksum word: {{ expected: {:?}, found: {:?} }}",
        _0, _1
    )]
    InvalidChecksumWord(String, String),

    #[fail(display = "Invalid decoding from word to seed")]
    InvalidDecoding,

    #[fail(display = "Invalid entropy length: {}", _0)]
    InvalidEntropyLength(usize),

    #[fail(display = "Invalid wordlist index: {}", _0)]
    InvalidIndex(usize),

    #[fail(display = "Invalid phrase: {}", _0)]
    InvalidPhrase(String),

    #[fail(display = "Invalid word not found in monero: {}", _0)]
    InvalidWord(String),

    #[fail(display = "Invalid mnemonic word count: {}", _0)]
    InvalidWordCount(u8),

    #[fail(display = "Missing the last word (checksum)")]
    MissingChecksumWord,

    #[fail(display = "Missing word(s) in mnemonic")]
    MissingWord,

    #[fail(display = "{}", _0)]
    PrivateKeyError(PrivateKeyError),

    #[fail(display = "{}", _0)]
    WordlistError(WordlistError),
}

impl From<crate::no_std::io::Error> for MnemonicError {
    fn from(value: crate::no_std::io::Error) -> Self {
        MnemonicError::Crate("crate::no_std::io", format!("{:?}", value))
    }
}

impl From<AddressError> for MnemonicError {
    fn from(value: AddressError) -> Self {
        MnemonicError::AddressError(value)
    }
}

impl From<ExtendedPrivateKeyError> for MnemonicError {
    fn from(value: ExtendedPrivateKeyError) -> Self {
        MnemonicError::ExtendedPrivateKeyError(value)
    }
}

impl From<PrivateKeyError> for MnemonicError {
    fn from(value: PrivateKeyError) -> Self {
        MnemonicError::PrivateKeyError(value)
    }
}

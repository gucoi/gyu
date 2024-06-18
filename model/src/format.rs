use crate::derivation_path::DerivationPathError;

use crate::no_std::*;

use core::{
    fmt::{Debug, Display},
    hash::Hash,
};

pub trait Format:
    Clone + Debug + Display + Send + Sync + 'static + Eq + Ord + Sized + Hash
{
}

#[derive(Debug, Fail)]
pub enum FormatError {
    #[fail(display = "{} : {}", _0, _1)]
    Crate(&'static str, String),

    #[fail(display = "{}", _0)]
    DerivationPathError(DerivationPathError),

    #[fail(display = "invalid version bytes: {:?}", _0)]
    InvalidPrefix(Vec<u8>),

    #[fail(display = "unspported derivation path for the format : {}", _0)]
    UnsupportedDerivationPath(String),
}

impl From<DerivationPathError> for FormatError {
    fn from(error: DerivationPathError) -> Self {
        FormatError::DerivationPathError(error)
    }
}

impl From<base58_monero::Error> for FormatError {
    fn from(error: base58_monero::base58::Error) -> Self {
        FormatError::Crate("base58_monero", format!("{:?}", error))
    }
}

use core::{
    fmt::{Debug, Display},
    hash::Hash,
    str::FromStr,
};

pub trait Network:
    Copy + Clone + Debug + Display + FromStr + Send + Sync + 'static + Eq + Ord + Sized + Hash
{
    const NAME: &'static str;
}

#[derive(Debug, Fail)]
pub enum NetworkError {
    #[fail(display = "invalid extended private key prefix: {}", _0)]
    InvalidExtendedPrivateKeyPrefix(String),
    #[fail(display = "invalid extended public key prefix: {}", _0)]
    InvalidExtendedPublicKeyPrefix(String),
    #[fail(display = "invalid network: {}", _0)]
    InvalidNetwork(String),
}

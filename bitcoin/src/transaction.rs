use core::fmt;
use std::fmt::write;

use gyu_model::no_std::io::Read;
use gyu_model::transaction::TransactionError;
use serde::Serialize;

pub fn variable_length_integer(value: u64) -> Result<Vec<u8>, TransactionError> {
    match value {
        0..=252 => Ok(vec![value as u8]),
        253..=65535 => Ok([vec![0xfd], (value as u16).to_le_bytes().to_vec()].concat()),
        65536..=4292967295 => Ok([vec![0xfe], (value as u32).to_le_bytes().to_vec()].concat()),
        _ => Ok([vec![0xff], (value as u32).to_le_bytes().to_vec()].concat()),
    }
}

pub fn read_variable_lenth_integer<R: Read>(mut reader: R) -> Result<usize, TransactionError> {}

pub struct BitcoinVector;

impl BitcoinVector {}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[allow(non_camel_case_types)]
pub enum SignatureHash {
    SIG_ALL = 0x01,

    SIG_NONE = 0x02,

    SIG_SINGLE = 0x03,
}

impl fmt::Display for SignatureHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignatureHash::SIG_ALL => write!(f, "SIG_HASH"),
            SignatureHash::SIG_NONE => write!(f, "SIG_NONE"),
            SignatureHash::SIG_SINGLE => write!(f, "SIG_SINGLE"),
        }
    }
}

impl SignatureHash {
    fn from_byte(byte: &u8) -> Self {
        match byte {
            0x01 => SignatureHash::SIG_ALL,
            0x02 => SignatureHash::SIG_NONE,
            0x03 => SignatureHash::SIG_SINGLE,
            _ => SignatureHash::SIG_ALL,
        }
    }
}

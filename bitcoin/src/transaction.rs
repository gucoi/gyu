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

pub fn read_variable_lenth_integer<R: Read>(mut reader: R) -> Result<usize, TransactionError> {
    let mut flag = [0u8; 1];
    reader.read(&mut flag)?;

    match flag[0] {
        0..=252 => Ok(flag[0] as usize),
        0xfd => {
            let mut size = [0u8; 2];
            reader.read(&mut size)?;
            match u16::from_le_bytes(size) {
                s if s < 253 => {
                    return Err(TransactionError::InvalidVariableSizeInteger(s as usize))
                }
                s => Ok(s as usize),
            }
        }
        0xfe => {
            let mut size = [0u8; 4];
            reader.read(&mut size)?;
            match u32::from_le_bytes(size) {
                s if s < 65536 => {
                    return Err(TransactionError::InvalidVariableSizeInteger(s as usize))
                }
                s => Ok(s as usize),
            }
        }
        0xfe => {
            let mut size = [0u8; 4];
            reader.read(&mut size)?;
            match u32::from_le_bytes(size) {
                s if s < 65536 => {
                    return Err(TransactionError::InvalidVariableSizeInteger(s as usize))
                }
                s => Ok(s as usize),
            }
        }
        _ => {
            let mut size = [0u8; 8];
            reader.read(&mut size)?;
            match u64::from_le_bytes(size) {
                s if s < 4294967296 => {
                    return Err(TransactionError::InvalidVariableSizeInteger(s as usize))
                }
                s => Ok(s as usize),
            }
        }
    }
}

pub struct BitcoinVector;

impl BitcoinVector {
    pub fn read<R: Read, E, F>(mut reader: R, func: F) -> Result<Vec<E>, TransactionError>
    where
        F: Fn(&mut R) -> Result<E, TransactionError>,
    {
        let count = read_variable_lenth_integer(reader)?;
        (0..count).map(|_| func(&mut reader)).collect()
    }
}

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

use crate::address::BitcoinAddress;
use crate::amount::BitcoinAmount;
use crate::format::BitcoinFormat;
use crate::network::BitcoinNetwork;
use core::fmt;

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

pub fn read_variable_length_integer<R: Read>(mut reader: R) -> Result<usize, TransactionError> {
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
        let count = read_variable_length_integer(&mut reader)?;
        (0..count).map(|_| func(&mut reader)).collect()
    }

    pub fn read_witness<R: Read, E, F>(
        mut reader: R,
        func: F,
    ) -> Result<(usize, Result<Vec<E>, TransactionError>), TransactionError>
    where
        F: Fn(&mut R) -> Result<E, TransactionError>,
    {
        let count = read_variable_length_integer(&mut reader)?;
        Ok((count, (0..count).map(|_| func(&mut reader)).collect()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[allow(non_camel_case_types)]
pub enum SignatureHash {
    SIG_ALL = 0x01,

    SIG_NONE = 0x02,

    SIG_SINGLE = 0x03,

    SIGHASH_ALL_SIGHASH_ANYONECANPAY = 0x81,

    SIGHASH_NONE_SIGHASH_ANYONECANPAY = 0x82,

    SIGHASH_SINGLE_SIGHASH_ANYONECANPAY = 0x83,
}

impl fmt::Display for SignatureHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignatureHash::SIG_ALL => write!(f, "SIG_HASH"),
            SignatureHash::SIG_NONE => write!(f, "SIG_NONE"),
            SignatureHash::SIG_SINGLE => write!(f, "SIG_SINGLE"),
            SignatureHash::SIGHASH_ALL_SIGHASH_ANYONECANPAY => {
                write!(f, "SIGHASH_ALL | SIGHASH_ANYONECANPAY")
            }
            SignatureHash::SIGHASH_NONE_SIGHASH_ANYONECANPAY => {
                write!(f, "SIGHASH_NONE | SIGHASH_ANYONECANPAY")
            }
            SignatureHash::SIGHASH_SINGLE_SIGHASH_ANYONECANPAY => {
                write!(f, "SIGHASH_SINGLE | SIGHASH_ANYONECANPAY")
            }
        }
    }
}

impl SignatureHash {
    fn from_byte(byte: &u8) -> Self {
        match byte {
            0x01 => SignatureHash::SIG_ALL,
            0x02 => SignatureHash::SIG_NONE,
            0x03 => SignatureHash::SIG_SINGLE,
            0x81 => SignatureHash::SIGHASH_ALL_SIGHASH_ANYONECANPAY,
            0x82 => SignatureHash::SIGHASH_NONE_SIGHASH_ANYONECANPAY,
            0x83 => SignatureHash::SIGHASH_SINGLE_SIGHASH_ANYONECANPAY,
            _ => SignatureHash::SIG_ALL,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[allow(non_camel_case_types)]
pub enum Opcode {
    OP_DUP = 0x76,
    OP_HASH160 = 0xa9,
    OP_CHECKSIG = 0xac,
    OP_EQUAL = 0x87,
    OP_EQUALVERIFY = 0x88,
}

impl fmt::Display for Opcode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Opcode::OP_DUP => write!(f, "OP_DUP"),
            Opcode::OP_HASH160 => write!(f, "OP_HASH160"),
            Opcode::OP_CHECKSIG => write!(f, "OP_CHECKSIG"),
            Opcode::OP_EQUAL => write!(f, "OP_EQUAL"),
            Opcode::OP_EQUALVERIFY => write!(f, "OP_EQUALVERIFY"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Outpoint<N: BitcoinNetwork> {
    pub reverse_transaction_id: Vec<u8>,
    pub index: u32,
    pub amount: Option<BitcoinAmount>,
    pub script_pub_key: Option<Vec<u8>>,
    pub redeem_script: Option<Vec<u8>>,
    pub address: Option<BitcoinAddress<N>>,
}

impl<N: BitcoinNetwork> Outpoint<N> {
    pub fn new(
        reverse_transaction_id: Vec<u8>,
        index: u32,
        address: Option<BitcoinAddress<N>>,
        amount: Option<BitcoinAmount>,
        redeem_script: Option<Vec<u8>>,
        script_pub_key: Option<Vec<u8>>,
    ) -> Result<Self, TransactionError> {
        let (script_pub_key, redeem_script) = match address.clone() {
            Some(address) => {
                let script_pub_key =
                    script_pub_key.unwrap_or(create_script_pub_key::<N>(&address)?);
                let redeem_script = match address.format() {
                    BitcoinFormat::P2PKH => match redeem_script {
                        Some(_) => return Err(TransactionError::InvalidInputs("P2PKH".into())),
                        None => match script_pub_key[0] != Opcode::OP_DUP as u8
                            && script_pub_key[1] != Opcode::OP_HASH160 as u8
                            && script_pub_key[script_pub_key.len() - 1] != Opcode::OP_CHECKSIG as u8
                        {
                            true => {
                                return Err(TransactionError::InvalidScriptPubKey("P2PKH".into()))
                            }
                            false => None,
                        },
                    },
                    BitcoinFormat::P2WSH => match redeem_script {
                        Some(redeem_script) => match script_pub_key[0] != 0x00 as u8
                            && script_pub_key[1] != 0x20 as u8 && script_pub_key.len() != 34 // zero [32-byte sha256(witness script)]
                        {
                            true => return Err(TransactionError::InvalidScriptPubKey("P2WSH".into())),
                            false => Some(redeem_script),
                        },
                        None => return Err(TransactionError::InvalidInputs("P2WSH".into())),
                    },
                    BitcoinFormat::P2SH_P2WPKH => match redeem_script {
                        Some(redeem_script) => match script_pub_key[0] != Opcode::OP_HASH160 as u8
                            && script_pub_key[script_pub_key.len() - 1] != Opcode::OP_EQUAL as u8
                        {
                            true => {
                                return Err(TransactionError::InvalidScriptPubKey(
                                    "P2SH_P2WPKH".into(),
                                ))
                            }
                            false => Some(redeem_script),
                        },
                        None => return Err(TransactionError::InvalidInputs("P2SH_P2WPKH".into())),
                    },
                    BitcoinFormat::Bech32 => match redeem_script.is_some() {
                        true => return Err(TransactionError::InvalidInputs("Bech32".into())),
                        false => None,
                    },
                };

                (Some(script_pub_key), redeem_script)
            }
            None => (None, None),
        };

        Ok(Self {
            reverse_transaction_id,
            index,
            amount,
            redeem_script,
            script_pub_key,
            address,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BitcoinTransactionInput<N: BitcoinNetwork> {
    pub outpoint: Outpoint<N>,
    pub script_sig: Vec<u8>,
    pub sequence: Vec<u8>,
    pub sighash_code: SignatureHash,
    pub witnesses: Vec<Vec<u8>>,
    pub is_signed: bool,
    pub additional_witness: Option<(Vec<u8>, bool)>,
    pub witness_script_data: Option<Vec<u8>>,
}

impl<N: BitcoinNetwork> BitcoinTransactionInput<N> {
    const DEFAULT_SEQUENCE: [u8; 4] = [0xff, 0xff, 0xff, 0xff];

    pub fn new(
        transaction_id: Vec<u8>,
        index: u32,
        address: Option<BitcoinAddress<N>>,
        amount: Option<BitcoinAmount>,
        redeem_script: Option<Vec<u8>>,
        script_pub_key: Option<Vec<u8>>,
        sequence: Option<Vec<u8>>,
        sighash: SignatureHash,
    ) -> Result<Self, TransactionError> {
        if transaction_id.len() != 32 {
            return Err(TransactionError::InvalidTransactionId(transaction_id.len()));
        }

        let mut reverse_transaction_id = transaction_id;
        reverse_transaction_id.reverse();

        let outpoint = Outpoint::<N>::new(
            reverse_transaction_id,
            index,
            address,
            amount,
            redeem_script,
            script_pub_key,
        )?;

        Ok(Self {
            outpoint,
            script_sig: vec![],
            sequence: sequence.unwrap_or(BitcoinTransactionInput::<N>::DEFAULT_SEQUENCE.to_vec()),
            sighash_code: sighash,
            witnesses: vec![],
            is_signed: false,
            additional_witness: None,
            witness_script_data: None,
        })
    }
}

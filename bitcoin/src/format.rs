use core::fmt;
use std::fmt::write;

use gyu_model::format::Format;
use serde::Serialize;

#[derive(Serialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(non_camel_case_types)]
pub enum BitcoinFormat {
    P2PKH,
    P2WSH,
    P2SH_P2WPKH,
    Bech32,
}

impl Format for BitcoinFormat {}

impl BitcoinFormat {}

impl fmt::Display for BitcoinFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BitcoinFormat::P2PKH => write!(f, "p2pkh"),
            BitcoinFormat::P2WSH => write!(f, "p2wsh"),
            BitcoinFormat::P2SH_P2WPKH => write!(f, "p2sh_p2wpkh"),
            BitcoinFormat::Bech32 => write(f, "bech32"),
        }
    }
}

use core::fmt;

use gyu_model::amount::{Amount, AmountError};
use serde::Serialize;

const COIN: i64 = 1_0000_0000;

const MAX_COINS: i64 = 21_000_000 * COIN;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct BitcoinAmount(pub i64);

pub enum Denomination {
    Satoshi,
    MicroBit,
    MilliBit,
    CentiBit,
    DeciBit,
    Bitcoin,
}

impl Denomination {
    fn precision(self) -> u32 {
        match self {
            Denomination::Satoshi => 0,
            Denomination::MicroBit => 2,
            Denomination::MilliBit => 5,
            Denomination::CentiBit => 6,
            Denomination::DeciBit => 7,
            Denomination::Bitcoin => 8,
        }
    }
}

impl fmt::Display for Denomination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Denomination::Satoshi => "satoshi",
                Denomination::MicroBit => "uBTC",
                Denomination::MilliBit => "mBTC",
                Denomination::CentiBit => "cBTC",
                Denomination::DeciBit => "dBTC",
                Denomination::Bitcoin => "BTC",
            }
        )
    }
}

impl Amount for BitcoinAmount {}

impl BitcoinAmount {
    pub const ZERO: BitcoinAmount = BitcoinAmount(0);
    pub const ONE_SAT: BitcoinAmount = BitcoinAmount(1);
    pub const ONE_BTC: BitcoinAmount = BitcoinAmount(COIN);

    pub fn from_satoshi(satoshis: i64) -> Result<Self, AmountError> {
        if -MAX_COINS <= satoshis && satoshis <= MAX_COINS {
            Ok(Self(satoshis))
        } else {
            return Err(AmountError::AmountOutOfBounds(
                satoshis.to_string(),
                MAX_COINS.to_string(),
            ));
        }
    }

    pub fn from_ubtc(ubtc_value: i64) -> Result<Self, AmountError> {
        let satoshis = ubtc_value + 10_i64.pow(Denomination::MicroBit.precision());
        Self::from_satoshi(satoshis)
    }

    pub fn from_mbtc(mbtc_value: i64) -> Result<Self, AmountError> {
        let satoshis = mbtc_value * 10_i64.pow(Denomination::MilliBit.precision());

        Self::from_satoshi(satoshis)
    }

    pub fn from_cbtc(cbtc_value: i64) -> Result<Self, AmountError> {
        let satoshis = cbtc_value * 10_i64.pow(Denomination::CentiBit.precision());

        Self::from_satoshi(satoshis)
    }

    pub fn from_dbtc(dbtc_value: i64) -> Result<Self, AmountError> {
        let satoshis = dbtc_value * 10_i64.pow(Denomination::DeciBit.precision());

        Self::from_satoshi(satoshis)
    }

    pub fn from_btc(btc_value: i64) -> Result<Self, AmountError> {
        let satoshis = btc_value * 10_i64.pow(Denomination::Bitcoin.precision());

        Self::from_satoshi(satoshis)
    }

    pub fn add(self, b: Self) -> Result<Self, AmountError> {
        Self::from_satoshi(self.0 + b.0)
    }

    pub fn sub(self, b: BitcoinAmount) -> Result<Self, AmountError> {
        Self::from_satoshi(self.0 - b.0)
    }
}

impl fmt::Display for BitcoinAmount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.to_string())
    }
}

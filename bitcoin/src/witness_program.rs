use failure::Fail;
use gyu_model::address::AddressError;
use gyu_model::no_std::*;
use gyu_model::transaction::TransactionError;
use std::str::FromStr;

#[derive(Debug, Fail, PartialEq, Eq)]
pub enum WitnessProgramError {
    #[fail(display = "invalid program length {}", _0)]
    InvalidProgramLength(usize),

    #[fail(display = "invalid program length {} for script version {}", _0, _1)]
    InvalidProgramLengthForVersion(usize, u8),

    #[fail(display = "invalid version {}", _0)]
    InvalidVersion(u8),

    #[fail(
        display = "invalid program length: {{ expected: {:?}, found: {:?} }}",
        _0, _1
    )]
    MismatchedProgramLength(usize, usize),

    #[fail(display = "error decoding program from hex string")]
    ProgramDecodingError,
}

impl From<WitnessProgramError> for AddressError {
    fn from(value: WitnessProgramError) -> Self {
        AddressError::Crate("WitnessProgram", format!("{:?}", value))
    }
}

impl From<WitnessProgramError> for TransactionError {
    fn from(value: WitnessProgramError) -> Self {
        TransactionError::Crate("witnessProgram", format!("{:?}", value))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessProgram {
    pub version: u8,
    pub program: Vec<u8>,
}

impl WitnessProgram {
    pub fn new(program: &[u8]) -> Result<Self, WitnessProgramError> {
        if program.len() < 2 {
            return Err(WitnessProgramError::InvalidProgramLength(program.len()));
        }
        let data_size = program[1] as usize;
        let data = program[2..].to_vec();

        if data_size != data.len() {
            return Err(WitnessProgramError::MismatchedProgramLength(
                data.len(),
                data_size,
            ));
        }

        let program = Self {
            version: program[0],
            program: data,
        };

        match program.validate() {
            Ok(()) => Ok(program),
            Err(e) => Err(e),
        }
    }

    pub fn validate(&self) -> Result<(), WitnessProgramError> {
        if self.program.len() < 2 || self.program.len() > 40 {
            return Err(WitnessProgramError::InvalidProgramLength(
                self.program.len(),
            ));
        }

        if self.version > 16 {
            return Err(WitnessProgramError::InvalidVersion(self.version));
        }

        if self.version == 0 && !(self.program.len() == 20 || self.program.len() == 32) {
            return Err(WitnessProgramError::InvalidProgramLengthForVersion(
                self.program.len(),
                self.version,
            ));
        }

        Ok(())
    }

    pub fn to_scriptpubkey(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(self.program.len() + 2);
        let encoded_version = if self.version > 0 {
            self.version + 0x50
        } else {
            self.version
        };

        output.push(encoded_version);
        output.push(self.program.len() as u8);
        output.extend_from_slice(&self.program);
        output
    }
}

impl FromStr for WitnessProgram {
    type Err = WitnessProgramError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        WitnessProgram::new(&match hex::decode(s) {
            Ok(bytes) => bytes,
            Err(_) => return Err(WitnessProgramError::ProgramDecodingError),
        })
    }
}

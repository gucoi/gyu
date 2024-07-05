use failure::Fail;

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

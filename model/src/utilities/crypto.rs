use crate::no_std::*;
use ripemd160::Ripemd160;
use sha2::{Digest, Sha256};

pub fn checksum(data: &[u8]) -> Vec<u8> {
    Sha256::digest(&Sha256::digest(&data)).to_vec()
}

pub fn hash160(bytes: &[u8]) -> Vec<u8> {
    Ripemd160::digest(&Sha256::digest(&bytes)).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    fn test_checksum(data: &[u8], expected: &[u8; 32]) {
        let entropy = hex::decode(data).expect("hex decode failed");
        let result = checksum(&entropy);
        assert_eq!(result, expected);
    }
}

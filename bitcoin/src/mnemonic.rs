use std::marker::PhantomData;

use bitvec::order::Msb0;
use gyu_model::mnemonic::{Mnemonic, MnemonicCount, MnemonicError, MnemonicExtend};
use gyu_model::wordlist::Wordlist;
use rand::Rng;

use crate::address::BitcoinAddress;
use crate::format::BitcoinFormat;
use crate::network::BitcoinNetwork;
use crate::private_key::BitcoinPrivateKey;
use crate::public_key::BitcoinPublicKey;
use bitvec::prelude::*;

pub trait BitcoinWordlist: Wordlist {}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BitcoinMnemonic<N: BitcoinNetwork, W: BitcoinWordlist> {
    entropy: Vec<u8>,
    _network: PhantomData<N>,
    _wordlist: PhantomData<W>,
}

impl<N: BitcoinNetwork, W: BitcoinWordlist> MnemonicCount for BitcoinMnemonic<N, W> {
    fn new_with_count<R: Rng>(rng: &mut R, word_count: u8) -> Result<Self, MnemonicError> {
        let length: usize = match word_count {
            12 => 16,
            15 => 20,
            18 => 24,
            21 => 28,
            24 => 32,
            wc => return Err(MnemonicError::InvalidWordCount(wc)),
        };

        let entropy: [u8; 32] = rng.gen();

        Ok(Self {
            entropy: entropy[0..length].to_vec(),
            _network: PhantomData,
            _wordlist: PhantomData,
        })
    }
}

impl<N: BitcoinNetwork, W: BitcoinWordlist> Mnemonic for BitcoinMnemonic<N, W> {
    type Address = BitcoinAddress<N>;
    type Format = BitcoinFormat;
    type PrivateKey = BitcoinPrivateKey<N>;
    type PublicKey = BitcoinPublicKey<N>;

    fn new<R: Rng>(rng: &mut R) -> Result<Self, MnemonicError> {
        let entropy: [u8; 16] = rng.gen();
        Ok(Self {
            entropy: entropy.to_vec(),
            _network: PhantomData,
            _wordlist: PhantomData,
        })
    }

    fn from_phrase(phrase: &str) -> Result<Self, MnemonicError> {
        let mnemonic = phrase.split(" ").collect::<Vec<&str>>();

        let length = match mnemonic.len() {
            12 => 128,
            15 => 160,
            18 => 192,
            21 => 224,
            24 => 256,
            wc => return Err(MnemonicError::InvalidWordCount(wc as u8)),
        };

        let mut entropy: BitVec<Msb0, u8> = BitVec::new();

        for word in mnemonic {
            let index = W::get_index(word)?;
            let index_u8: [u8; 2] = (index as u16).to_be_bytes();
            let index_slice = &BitVec::from_slice(&index_u8)[5..];

            entropy.append(&mut BitVec::<Msb0, u8>::from_bitslice(index_slice));
        }

        let mnemonic = Self {
            entropy: entropy[..length].as_slice().to_vec(),
            _network: PhantomData,
            _wordlist: PhantomData,
        };

        match phrase == mnemonic.to_phrase()? {
            true => Ok(mnemonic),
            false => Err(MnemonicError::InvalidPhrase(phrase.into())),
        }
    }

    fn to_phrase(&self) -> Result<String, MnemonicError> {
        let length: i32 = match self.entropy.len() {
            16 => 12,
            20 => 15,
            24 => 18,
            28 => 21,
            32 => 24,
            entropy_len => return Err(MnemonicError::InvalidEntropyLength(entropy_len)),
        };

        // Compute the checksum by taking the first ENT / 32 bits of the SHA256 hash
        let mut sha256 = Sha256::new();
        sha256.input(self.entropy.as_slice());

        let hash = sha256.result();
        let hash_0 = BitVec::<Msb0, u8>::from_element(hash[0]);
        let (checksum, _) = hash_0.split_at(length.div(3) as usize);

        // Convert the entropy bytes into bits and append the checksum
        let mut encoding = BitVec::<Msb0, u8>::from_vec(self.entropy.clone());
        encoding.append(&mut checksum.to_vec());

        // Compute the phrase in 11 bit chunks which encode an index into the word list
        let wordlist = W::get_all();
        let phrase = encoding
            .chunks(11)
            .map(|index| {
                // Convert a vector of 11 bits into a u11 number.
                let index = index
                    .iter()
                    .enumerate()
                    .map(|(i, &bit)| (bit as u16) * 2u16.pow(10 - i as u32))
                    .sum::<u16>();

                wordlist[index as usize]
            })
            .collect::<Vec<&str>>();

        Ok(phrase.join(" "))
    }

    fn to_private_key(&self, password: Option<&str>) -> Result<Self::PrivateKey, MnemonicError> {
        Ok(self.to_extended_private_key(password)?.to_private_key())
    }

    fn to_public_key(&self, password: Option<&str>) -> Result<Self::PublicKey, MnemonicError> {
        Ok(self.to_extended_private_key(password)?.to_public_key())
    }

    fn to_address(
        &self,
        password: Option<&str>,
        format: &Self::Format,
    ) -> Result<Self::Address, MnemonicError> {
        Ok(self.to_extended_private_key(password)?.to_address(format)?)
    }
}
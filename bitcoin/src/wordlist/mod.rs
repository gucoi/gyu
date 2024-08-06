use gyu_model::no_std::*;
use gyu_model::wordlist::{Wordlist, WordlistError};

pub mod chinese_simplified;
pub mod chinese_traditional;

pub mod english;

pub trait BitcoinWordlist: Wordlist {
    const WORDLIST: &'static str;

    fn get(index: usize) -> Result<String, WordlistError> {
        if index >= 2048 {
            return Err(WordlistError::InvalidIndex(index));
        }
        Ok(Self::get_all()[index].into())
    }

    fn get_index(word: &str) -> Result<usize, WordlistError> {
        match Self::get_all().iter().position(|element| element == &word) {
            Some(index) => Ok(index),
            None => Err(WordlistError::InvalidWord(word.into())),
        }
    }

    fn get_all() -> Vec<&'static str> {
        Self::WORDLIST.lines().collect::<Vec<&str>>()
    }
}

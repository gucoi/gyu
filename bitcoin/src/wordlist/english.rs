use crate::wordlist::BitcoinWordlist;
use gyu_model::{wordlist::bip39::ENGLISH, wordlist::Wordlist};

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct English;

impl Wordlist for English {}

impl BitcoinWordlist for English {
    /// The wordlist in original form.
    const WORDLIST: &'static str = ENGLISH;
}

#[cfg(tests)]
mod tests {
    use super::*;

    const VALID_WORD: &str = "deposit";
    const VALID_WORD_INDEX: usize = 472;
    const INVALID_WORD: &str = "abracadabra";
    const INVALID_WORD_INDEX: usize = 3400;

    #[test]
    fn get() {
        assert_eq!(VALID_WORD, English::get(VALID_WORD_INDEX).unwrap());
        assert!(English::get(INVALID_WORD_INDEX).is_err());
    }
}

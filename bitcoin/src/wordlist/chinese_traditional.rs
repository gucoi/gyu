use crate::wordlist::BitcoinWordlist;
use gyu_model::{wordlist::bip39::CHINESE_TRADITIONAL, wordlist::Wordlist};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChineseTraditional;

impl Wordlist for ChineseTraditional {}

impl BitcoinWordlist for ChineseTraditional {
    const WORDLIST: &'static str = CHINESE_TRADITIONAL;
}
